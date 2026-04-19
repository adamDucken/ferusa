use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, AeadCore, OsRng as AeadOsRng},
    KeyInit, XChaCha20Poly1305,
};
use hkdf::Hkdf;
use rand::{Rng, RngCore};
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::auth::{AuthRequest, AuthResponse};
use crate::error::{FerusaError, Result};

// —— Key material ——————————————————————————————————————————————

/// Password-derived material for v2 unlock.
///
/// `local_secret` is not a vault AEAD key. It must be combined with the
/// phone-held share before any vault plaintext can be decrypted.
#[derive(ZeroizeOnDrop)]
pub struct DerivedKeys {
    pub local_secret: [u8; 32],
}

// —— On-disk blob ——————————————————————————————————————————————

const VAULT_BLOB_MAGIC_V2: &[u8; 8] = b"FERUSA2\0";
const VAULT_BLOB_V2_HEADER_LEN: usize = VAULT_BLOB_MAGIC_V2.len() + 16 + 24;
const AEAD_TAG_LEN: usize = 16;
const LEGACY_V1_MIN_LEN: usize = 16 + 24 + AEAD_TAG_LEN;

/// On-disk layout: ["FERUSA2\0"][salt 16b][nonce 24b][ciphertext + 16b tag]
pub struct EncryptedBlob {
    salt: [u8; 16],
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

impl EncryptedBlob {
    /// Salt embedded in this vault blob.
    pub fn salt(&self) -> [u8; 16] {
        self.salt
    }

    /// Serialise to the v2 byte layout stored in vault.enc.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(VAULT_BLOB_V2_HEADER_LEN + self.ciphertext.len());
        out.extend_from_slice(VAULT_BLOB_MAGIC_V2);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Deserialise from the v2 byte layout.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if !bytes.starts_with(VAULT_BLOB_MAGIC_V2) {
            if bytes.len() >= LEGACY_V1_MIN_LEN {
                return Err(FerusaError::UnsupportedVaultBlob {
                    details: "missing FERUSA2 header; legacy v1 blobs are unsupported".into(),
                });
            }
            return Err(FerusaError::BlobTooShort { len: bytes.len() });
        }
        if bytes.len() < VAULT_BLOB_V2_HEADER_LEN + AEAD_TAG_LEN {
            return Err(FerusaError::BlobTooShort { len: bytes.len() });
        }

        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 24];
        salt.copy_from_slice(&bytes[VAULT_BLOB_MAGIC_V2.len()..VAULT_BLOB_MAGIC_V2.len() + 16]);
        nonce.copy_from_slice(&bytes[VAULT_BLOB_MAGIC_V2.len() + 16..VAULT_BLOB_V2_HEADER_LEN]);
        Ok(Self {
            salt,
            nonce,
            ciphertext: bytes[VAULT_BLOB_V2_HEADER_LEN..].to_vec(),
        })
    }
}

// —— Key derivation ————————————————————————————————————————————

/// Derive the local secret from master password + salt.
///
/// This is intentionally not enough to decrypt the vault. Call
/// `combine_vault_key` with the phone-held share to reconstruct the AEAD key.
pub fn derive_local_secret(password: &[u8], salt: &[u8; 16]) -> Result<[u8; 32]> {
    let params = match Params::new(65536, 3, 1, Some(64)) {
        Ok(params) => params,
        Err(e) => {
            return Err(FerusaError::Argon2Params {
                details: e.to_string(),
            })
        }
    };
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut okm = Zeroizing::new([0u8; 64]);
    if let Err(e) = argon2.hash_password_into(password, salt, &mut *okm) {
        return Err(FerusaError::Argon2Hash {
            details: e.to_string(),
        });
    }

    let mut local_secret = [0u8; 32];

    {
        // hkdf 0.12 does not advertise zeroizing drop for its PRK/HMAC state.
        // Keep it scoped tightly; okm and returned key material are zeroizing.
        let hk = Hkdf::<Sha256>::new(None, &*okm);
        if let Err(e) = hk.expand(b"ferusa-local-secret-v2", &mut local_secret) {
            local_secret.zeroize();
            return Err(FerusaError::HkdfExpandVaultKey {
                details: e.to_string(),
            });
        }
    }

    Ok(local_secret)
}

/// Combine password-derived and phone-held factors into the vault AEAD key.
pub fn combine_vault_key(local_secret: &[u8; 32], phone_share: &[u8; 32]) -> Result<[u8; 32]> {
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(local_secret);
    ikm[32..].copy_from_slice(phone_share);

    let mut vault_key = [0u8; 32];
    {
        let hk = Hkdf::<Sha256>::new(None, &*ikm);
        if let Err(e) = hk.expand(b"ferusa-vault-aead-v2", &mut vault_key) {
            vault_key.zeroize();
            return Err(FerusaError::HkdfExpandVaultKey {
                details: e.to_string(),
            });
        }
    }

    Ok(vault_key)
}

/// Derive password-local material used by callers that need both local secret
/// and phone-backed approval. This no longer returns a vault AEAD key.
pub fn derive_keys(password: &[u8], salt: &[u8; 16]) -> Result<DerivedKeys> {
    let local_secret = derive_local_secret(password, salt)?;

    Ok(DerivedKeys { local_secret })
}

// —— Vault encrypt / decrypt ———————————————————————————————————

/// Encrypt plaintext with XChaCha20-Poly1305. Random nonce each call.
pub fn encrypt_vault(key: &[u8; 32], salt: [u8; 16], plaintext: &[u8]) -> Result<EncryptedBlob> {
    let cipher = match XChaCha20Poly1305::new_from_slice(key) {
        Ok(cipher) => cipher,
        Err(e) => {
            return Err(FerusaError::BuildCipher {
                details: e.to_string(),
            })
        }
    };
    let nonce_generic = XChaCha20Poly1305::generate_nonce(&mut AeadOsRng);
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&nonce_generic);

    let ciphertext = match cipher.encrypt(&nonce_generic, plaintext) {
        Ok(ciphertext) => ciphertext,
        Err(e) => {
            return Err(FerusaError::Encrypt {
                details: e.to_string(),
            })
        }
    };

    Ok(EncryptedBlob {
        salt,
        nonce,
        ciphertext,
    })
}

/// Decrypt. Returns Err on AEAD tag mismatch (wrong key or tampered data).
pub fn decrypt_vault(key: &[u8; 32], blob: &EncryptedBlob) -> Result<Vec<u8>> {
    use chacha20poly1305::XNonce;
    let cipher = match XChaCha20Poly1305::new_from_slice(key) {
        Ok(cipher) => cipher,
        Err(e) => {
            return Err(FerusaError::BuildCipher {
                details: e.to_string(),
            })
        }
    };
    let nonce = XNonce::from_slice(&blob.nonce);
    match cipher.decrypt(nonce, blob.ciphertext.as_slice()) {
        Ok(plaintext) => Ok(plaintext),
        Err(e) => Err(FerusaError::Decrypt {
            details: e.to_string(),
        }),
    }
}

// —— Approval signature verification ———————————————————————————

#[derive(serde::Serialize)]
struct ApprovalPayload<'a> {
    domain: &'static str,
    version: u8,
    request: &'a AuthRequest,
    response: AuthResponseForSigning<'a>,
}

#[derive(serde::Serialize)]
struct AuthResponseForSigning<'a> {
    pairing_id: uuid::Uuid,
    request_id: uuid::Uuid,
    correlation_code: u16,
    action: crate::types::VaultAction,
    approved: bool,
    unlock_share: &'a Option<[u8; 32]>,
    timestamp: u64,
}

pub fn canonical_approval_payload(
    req: &AuthRequest,
    resp: &AuthResponse,
) -> Result<Zeroizing<Vec<u8>>> {
    let payload = ApprovalPayload {
        domain: "ferusa-approval",
        version: 3,
        request: req,
        response: AuthResponseForSigning {
            pairing_id: resp.pairing_id,
            request_id: resp.request_id,
            correlation_code: resp.correlation_code,
            action: resp.action,
            approved: resp.approved,
            unlock_share: &resp.unlock_share,
            timestamp: resp.timestamp,
        },
    };
    serde_json::to_vec(&payload)
        .map(Zeroizing::new)
        .map_err(|e| FerusaError::Json {
            details: e.to_string(),
        })
}

pub fn verify_approval_signature(
    public_key_der: &[u8],
    req: &AuthRequest,
    resp: &AuthResponse,
) -> bool {
    let Ok(payload) = canonical_approval_payload(req, resp) else {
        return false;
    };
    let key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key_der);
    key.verify(&payload, &resp.signature).is_ok()
}

pub fn canonical_pairing_ready_payload(pairing_id: uuid::Uuid) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(format!("ferusa-pairing-ready/v4/{pairing_id}").into_bytes())
}

pub fn verify_pairing_ready_signature(
    public_key_der: &[u8],
    pairing_id: uuid::Uuid,
    signature: &[u8],
) -> bool {
    let payload = canonical_pairing_ready_payload(pairing_id);
    let key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key_der);
    key.verify(&payload, signature).is_ok()
}

// —— Utilities —————————————————————————————————————————————————

/// Cryptographically random 4-digit code in range [1000, 9999].
pub fn random_correlation_code() -> u16 {
    rand::rng().random_range(1000..=9999)
}

/// Random 16-byte salt. Used on vault creation and password change.
pub fn new_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    rand::rng().fill_bytes(&mut salt);
    salt
}
