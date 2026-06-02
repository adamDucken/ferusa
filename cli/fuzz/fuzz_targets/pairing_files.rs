#![no_main]

use cli::storage::paths::{PairingStatus, Paths};
use iroh::SecretKey;
use libfuzzer_sys::fuzz_target;

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn paths(dir: &tempfile::TempDir) -> Paths {
    let p = dir.path().to_path_buf();
    Paths {
        data_dir: p.clone(),
        vault_enc: p.join("vault.enc"),
        vault_salt: p.join("vault.salt"),
        peer_id: p.join("peer.id"),
        phone_id: p.join("phone.id"),
        hmac_key: p.join("hmac.key"),
        clipboard_cmd: p.join("clipboard.cmd"),
    }
}

fn write_valid_pairing_state(p: &Paths, data: &[u8]) {
    let mut key_bytes = [0u8; 32];
    let n = data.len().min(key_bytes.len());
    key_bytes[..n].copy_from_slice(&data[..n]);
    let phone = SecretKey::from_bytes(&key_bytes).public();

    let pairing_id = format!(
        "00000000-0000-4000-8000-{:012x}",
        data.iter()
            .skip(32)
            .take(6)
            .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte))
    );
    let approval = if data.len() > 38 {
        hex_encode(&data[38..data.len().min(103)])
    } else {
        "01".to_owned()
    };

    let json = serde_json::json!({
        "version": 3,
        "pairing_id": pairing_id,
        "phone_node_id": hex_encode(phone.as_bytes()),
        "approval_public_key_der": approval,
        "created_at_ms": data.len() as u64,
    });
    std::fs::write(
        p.pairing_state(),
        serde_json::to_vec(&json).expect("serialize pairing state"),
    )
    .expect("write pairing.json");
}

fuzz_target!(|data: &[u8]| {
    let dir = tempfile::TempDir::new().expect("temp dir");
    let p = paths(&dir);
    std::fs::create_dir_all(&p.data_dir).expect("create data dir");

    let control = data.first().copied().unwrap_or(0);
    let split = data.get(1).copied().unwrap_or(0) as usize % (data.len() + 1);
    let (phone, hmac) = data.split_at(split);
    let phone = &phone[..phone.len().min(256)];
    let hmac = &hmac[..hmac.len().min(256)];

    if control & 0b0000_0001 != 0 {
        std::fs::write(&p.phone_id, phone).expect("write phone.id");
    }
    if control & 0b0000_0010 != 0 {
        std::fs::write(&p.hmac_key, hmac).expect("write hmac.key");
    }
    if control & 0b0000_0100 != 0 {
        std::fs::write(p.pending_pairing_state(), data).expect("write pending_pairing.json");
    }
    if control & 0b0000_1000 != 0 {
        std::fs::write(p.pairing_transaction_state(), data).expect("write pairing_txn.json");
    }
    if control & 0b0001_0000 != 0 {
        if control & 0b0010_0000 != 0 {
            write_valid_pairing_state(&p, data);
        } else {
            std::fs::write(p.pairing_state(), data).expect("write pairing.json");
        }
    }

    match p.pairing_status() {
        PairingStatus::Ready => {
            assert!(p.pairing_state().exists());
            assert!(!p.pending_pairing_state().exists());
            assert!(!p.pairing_transaction_state().exists());
            assert!(p.read_pairing_data().is_ok());
        }
        PairingStatus::Pending => {
            assert!(p.pending_pairing_state().exists() || p.pairing_transaction_state().exists());
        }
        PairingStatus::MissingPhoneId => {
            assert!(!p.pairing_state().exists());
            assert!(!p.pending_pairing_state().exists());
            assert!(!p.pairing_transaction_state().exists());
            assert!(!p.phone_id.exists());
            assert!(!p.hmac_key.exists());
        }
        PairingStatus::InvalidPhoneId(_) => {
            assert!(p.pairing_state().exists());
            assert!(!p.pending_pairing_state().exists());
            assert!(!p.pairing_transaction_state().exists());
            assert!(p.read_pairing_data().is_err());
        }
        PairingStatus::InvalidPairing(_) => {
            assert!(!p.pending_pairing_state().exists());
            assert!(!p.pairing_transaction_state().exists());
            assert!(
                p.pairing_state().exists() || p.phone_id.exists() || p.hmac_key.exists(),
                "invalid pairing requires pairing.json or legacy split files"
            );
        }
    }
});
