use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use log::{debug, info, warn};
use tokio::sync::Mutex;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use ferusa_core::crypto::{combine_vault_key, decrypt_vault, derive_keys, encrypt_vault};
use ferusa_core::types::{Vault, VaultAction, MAX_VAULT_PLAINTEXT_BYTES};

use crate::interface::ui;
use crate::net::cli_peer::CliPeer;
use crate::net::phone_connection::PhoneConnection;
use crate::storage::paths::{write_private_file, PairingData, Paths, VaultLock};

/// Shared mutable session for single CLI process.
pub type SharedState = Arc<Mutex<Option<SessionState>>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockStatus {
    AlreadyUnlocked,
    NewlyUnlocked,
}

/// A pending 2FA request waiting for phone approval.
#[derive(Debug, Clone)]
pub struct PendingRequest {
    pub correlation_code: u16,
    pub action: VaultAction,
    pub created_at: Instant,
}

/// In-memory session for current command run only.
#[derive(ZeroizeOnDrop)]
pub struct SessionState {
    pub vault: Vault,
    pub local_secret: [u8; 32],
    pub vault_key: [u8; 32],
    pub phone_share: [u8; 32],
    pub vault_salt: [u8; 16],
    #[zeroize(skip)]
    pub pairing: Option<PairingData>,
    #[zeroize(skip)]
    pub pending_requests: HashMap<Uuid, PendingRequest>,
    #[zeroize(skip)]
    pub endpoint: Option<Arc<iroh::Endpoint>>,
    #[zeroize(skip)]
    pub phone_conn: Option<PhoneConnection>,
    #[zeroize(skip)]
    pub vault_lock: Option<VaultLock>,
}

fn load_vault_blob(paths: &Paths) -> Result<ferusa_core::crypto::EncryptedBlob> {
    let metadata = std::fs::metadata(&paths.vault_enc).context("stat vault.enc")?;
    if metadata.len() > MAX_VAULT_PLAINTEXT_BYTES as u64 {
        bail!(
            "vault.enc exceeds the {} MiB size limit",
            MAX_VAULT_PLAINTEXT_BYTES / (1024 * 1024)
        );
    }
    let blob_bytes = std::fs::read(&paths.vault_enc).context("read vault.enc")?;
    ferusa_core::crypto::EncryptedBlob::from_bytes(&blob_bytes).context("parse vault.enc")
}

fn decrypt_vault_blob(
    blob: &ferusa_core::crypto::EncryptedBlob,
    vault_key: &[u8; 32],
) -> Result<Vault> {
    let plaintext = Zeroizing::new(decrypt_vault(vault_key, &blob).map_err(|e| {
        ui::failed("wrong password or vault is corrupt");
        e
    })?);
    if plaintext.len() > MAX_VAULT_PLAINTEXT_BYTES {
        bail!(
            "decrypted vault exceeds the {} MiB size limit",
            MAX_VAULT_PLAINTEXT_BYTES / (1024 * 1024)
        );
    }

    let vault: Vault = match serde_json::from_slice(&plaintext) {
        Ok(vault) => vault,
        Err(e) => {
            ui::failed("vault data is corrupt");
            return Err(e.into());
        }
    };

    vault.validate().map_err(anyhow::Error::msg)?;
    Ok(vault)
}

async fn build_session(
    endpoint: Option<Arc<iroh::Endpoint>>,
    vault: Vault,
    local_secret: [u8; 32],
    vault_key: [u8; 32],
    phone_share: [u8; 32],
    vault_salt: [u8; 16],
    pairing: Option<PairingData>,
    vault_lock: VaultLock,
) -> Result<SessionState> {
    Ok(SessionState {
        vault,
        local_secret,
        vault_key,
        phone_share,
        vault_salt,
        pairing,
        pending_requests: HashMap::new(),
        endpoint,
        phone_conn: None,
        vault_lock: Some(vault_lock),
    })
}

pub async fn ensure_unlocked(state: &SharedState, paths: &Paths) -> Result<UnlockStatus> {
    ensure_unlocked_for(state, paths, VaultAction::Unlock, None).await
}

/// Prompt for master password, obtain phone share, then decrypt vault.
pub async fn ensure_unlocked_for(
    state: &SharedState,
    paths: &Paths,
    action: VaultAction,
    entry_title: Option<&str>,
) -> Result<UnlockStatus> {
    debug!("[ferusa:cli]: ensure_unlocked: acquiring state lock");
    let guard = state.lock().await;
    if guard.is_some() {
        debug!("[ferusa:cli]: ensure_unlocked: already unlocked in this process");
        return Ok(UnlockStatus::AlreadyUnlocked);
    }
    drop(guard);

    paths.ensure_data_dir().context("secure data dir")?;

    let vault_lock = paths.acquire_vault_lock().context("lock vault")?;
    crate::commands::pair::reconcile_pairing_transaction(paths)
        .await
        .context("recover pairing transaction")?;

    #[cfg(not(feature = "dev-2fa-stub"))]
    paths.ensure_not_dev_2fa_stub_vault().map_err(|e| {
        ui::failed("dev 2FA stub vaults are not production-compatible");
        e
    })?;

    if !paths.vault_exists() {
        warn!("[ferusa:cli]: ensure_unlocked: vault not initialised");
        bail!("vault not initialised — run `ferusa init` first");
    }

    debug!("[ferusa:cli]: ensure_unlocked: prompting for password");
    ui::input("provide master password");
    let password = Zeroizing::new(
        rpassword::prompt_password("master password: ").context("failed to read password")?,
    );

    ui::execute("deriving local password factor");

    let blob = load_vault_blob(paths)?;
    let salt = blob.salt();
    debug!("[ferusa:cli]: ensure_unlocked: salt loaded from vault.enc");

    let keys = derive_keys(password.as_bytes(), &salt).context("key derivation failed")?;
    drop(password);
    debug!("[ferusa:cli]: ensure_unlocked: keys derived");

    let pairing_status = paths.pairing_status();
    let (endpoint, pairing, phone_share) =
        if matches!(pairing_status, crate::storage::paths::PairingStatus::Ready) {
            debug!("[ferusa:cli]: ensure_unlocked: initialising iroh endpoint");
            let peer = CliPeer::init(&paths.peer_id).await.map_err(|e| {
                ui::failed("could not initialise p2p identity");
                e
            })?;
            let endpoint = Arc::new(peer.into_endpoint());

            let pairing = paths.read_pairing_data().context("read pairing data")?;
            debug!("[ferusa:cli]: ensure_unlocked: loaded approval public key from pairing data");
            ui::execute("requesting phone unlock approval");
            let phone_share = crate::twofa::request_unlock_share(
                Arc::clone(&endpoint),
                pairing.clone(),
                action,
                entry_title,
            )
            .await?;
            (Some(endpoint), Some(pairing), phone_share)
        } else {
            #[cfg(feature = "dev-2fa-stub")]
            {
                debug!("[ferusa:cli]: ensure_unlocked: no pairing file — using dev 2FA stub");
                ui::warn("DEV 2FA STUB ENABLED — using deterministic test phone share");
                crate::twofa::stub::ensure_allowed()?;
                paths.ensure_dev_2fa_stub_marker()?;
                crate::twofa::stub::request_approval(action, entry_title).await?;
                (None, None, crate::twofa::stub::dev_phone_share()?)
            }

            #[cfg(not(feature = "dev-2fa-stub"))]
            {
                ui::failed(&format!("2FA unavailable — {pairing_status}"));
                ui::info(
                "run `ferusa init` with the phone app to create a cryptographically gated vault",
            );
                anyhow::bail!("2FA required before vault decryption: {pairing_status}");
            }
        };

    let vault_key =
        combine_vault_key(&keys.local_secret, &phone_share).context("combine vault key")?;

    let vault = decrypt_vault_blob(&blob, &vault_key)?;
    debug!(
        "[ferusa:cli]: ensure_unlocked: vault deserialised ({} entries)",
        vault.entries.len()
    );

    let session = build_session(
        endpoint,
        vault,
        keys.local_secret,
        vault_key,
        phone_share,
        salt,
        pairing,
        vault_lock,
    )
    .await?;

    let mut guard = state.lock().await;
    *guard = Some(session);
    drop(guard);

    info!("[ferusa:cli]: ensure_unlocked: vault unlocked successfully");
    Ok(UnlockStatus::NewlyUnlocked)
}

/// Serialize vault → encrypt → atomic write (temp + rename).
pub async fn save_vault(state: &SharedState, paths: &Paths) -> Result<()> {
    debug!("[ferusa:cli]: save_vault: start");
    let (vault, vault_key, vault_salt) = {
        let guard = state.lock().await;
        let s = guard.as_ref().context("session not unlocked")?;
        (s.vault.clone(), s.vault_key, s.vault_salt)
    };

    save_vault_with_key(paths, vault, vault_key, vault_salt).await
}

/// Persist a candidate vault before replacing the live in-memory session vault.
pub async fn save_vault_candidate(state: &SharedState, paths: &Paths, vault: Vault) -> Result<()> {
    debug!("[ferusa:cli]: save_vault_candidate: start");
    let (vault_key, vault_salt) = {
        let guard = state.lock().await;
        let s = guard.as_ref().context("session not unlocked")?;
        (s.vault_key, s.vault_salt)
    };

    save_vault_with_key(paths, vault.clone(), vault_key, vault_salt).await?;

    let mut guard = state.lock().await;
    let s = guard.as_mut().context("session not unlocked")?;
    s.vault = vault;
    debug!("[ferusa:cli]: save_vault_candidate: session vault replaced");
    Ok(())
}

pub(crate) async fn save_vault_with_key(
    paths: &Paths,
    vault: Vault,
    vault_key: [u8; 32],
    vault_salt: [u8; 16],
) -> Result<()> {
    save_vault_with_key_to(paths.vault_enc.clone(), vault, vault_key, vault_salt).await
}

pub(crate) async fn save_vault_with_key_to(
    vault_enc: std::path::PathBuf,
    vault: Vault,
    vault_key: [u8; 32],
    vault_salt: [u8; 16],
) -> Result<()> {
    let bytes_len = tokio::task::spawn_blocking(move || {
        save_vault_snapshot(vault, Zeroizing::new(vault_key), vault_salt, vault_enc)
    })
    .await
    .context("save vault task panicked")??;

    info!(
        "[ferusa:cli]: save_vault: vault written ({} bytes encrypted)",
        bytes_len
    );
    Ok(())
}

fn save_vault_snapshot(
    vault: Vault,
    vault_key: Zeroizing<[u8; 32]>,
    vault_salt: [u8; 16],
    vault_enc: std::path::PathBuf,
) -> Result<usize> {
    let vault = Zeroizing::new(vault);
    vault.validate().map_err(anyhow::Error::msg)?;
    let mut plaintext = serde_json::to_vec(&*vault).context("serialize vault")?;
    if plaintext.len() > MAX_VAULT_PLAINTEXT_BYTES {
        plaintext.zeroize();
        bail!(
            "serialized vault exceeds the {} MiB size limit",
            MAX_VAULT_PLAINTEXT_BYTES / (1024 * 1024)
        );
    }
    debug!(
        "[ferusa:cli]: save_vault: serialised ({} bytes)",
        plaintext.len()
    );

    let blob = encrypt_vault(&*vault_key, vault_salt, &plaintext)
        .map_err(|e| {
            plaintext.zeroize();
            e
        })
        .context("encrypt vault")?;
    plaintext.zeroize();

    let bytes = blob.to_bytes();
    let bytes_len = bytes.len();

    write_private_file(&vault_enc, &bytes).context("write vault.enc")?;

    Ok(bytes_len)
}

/// Drop session state; key material zeroed on drop.
pub async fn lock_session(state: &SharedState) {
    debug!("[ferusa:cli]: lock_session: zeroing session");
    let mut guard = state.lock().await;
    *guard = None;
    info!("[ferusa:cli]: lock_session: session cleared");
}
