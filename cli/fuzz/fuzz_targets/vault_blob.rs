#![no_main]

use ferusa_core::crypto::EncryptedBlob;
use ferusa_core::types::Vault;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = EncryptedBlob::from_bytes(data);

    if let Ok(vault) = serde_json::from_slice::<Vault>(&data[..data.len().min(4096)]) {
        let encoded = serde_json::to_vec(&vault).expect("vault serializes");
        let _roundtrip: Vault = serde_json::from_slice(&encoded).expect("vault roundtrips");
    }
});
