#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use tempfile::TempDir;
    use tokio::sync::Mutex;

    use ferusa_core::crypto::{
        combine_vault_key, decrypt_vault, derive_keys, encrypt_vault, new_salt,
    };
    use ferusa_core::transport::FERUSA_ALPN;
    use ferusa_core::types::{Entry, Vault};

    use crate::session::{
        lock_session, save_vault, save_vault_candidate, SessionState, SharedState,
    };
    use crate::storage::paths::Paths;

    const PHONE_SHARE: [u8; 32] = [0xD3; 32];

    fn vault_key(local_secret: &[u8; 32]) -> [u8; 32] {
        combine_vault_key(local_secret, &PHONE_SHARE).unwrap()
    }

    fn temp_paths() -> (TempDir, Paths) {
        let dir = TempDir::new().unwrap();
        let p = dir.path();
        let paths = Paths {
            data_dir: p.to_path_buf(),
            vault_enc: p.join("vault.enc"),
            vault_salt: p.join("vault.salt"),
            peer_id: p.join("peer.id"),
            phone_id: p.join("phone.id"),
            hmac_key: p.join("hmac.key"),
            clipboard_cmd: p.join("clipboard.cmd"),
        };
        (dir, paths)
    }

    /// Bind a throw-away iroh endpoint for tests that need one.
    async fn test_endpoint() -> Arc<iroh::Endpoint> {
        Arc::new(
            iroh::Endpoint::builder(iroh::endpoint::presets::N0)
                .alpns(vec![FERUSA_ALPN.to_vec()])
                .bind()
                .await
                .expect("bind test endpoint"),
        )
    }

    async fn init_vault(paths: &Paths, password: &[u8]) -> SharedState {
        let salt = new_salt();
        let keys = derive_keys(password, &salt).unwrap();
        let vault = Vault::default();
        let plaintext = serde_json::to_vec(&vault).unwrap();
        let blob = encrypt_vault(&vault_key(&keys.local_secret), salt, &plaintext).unwrap();

        std::fs::write(&paths.vault_salt, &salt).unwrap();
        std::fs::write(&paths.vault_enc, blob.to_bytes()).unwrap();

        Arc::new(Mutex::new(Some(SessionState {
            vault,
            local_secret: keys.local_secret,
            vault_key: vault_key(&keys.local_secret),
            phone_share: PHONE_SHARE,
            vault_salt: salt,
            pairing: None,
            pending_requests: HashMap::new(),
            endpoint: Some(test_endpoint().await),
            phone_conn: None,
            vault_lock: None,
        })))
    }

    fn sample_entry(title: &str) -> Entry {
        Entry {
            id: uuid::Uuid::new_v4(),
            title: title.into(),
            username: Some("alice".into()),
            password: "hunter2".into(),
            url: Some("https://example.com".into()),
            notes: None,
            tags: vec!["work".into()],
            created_at: 1_700_000_000_000,
            updated_at: 1_700_000_000_000,
        }
    }

    #[tokio::test]
    async fn init_creates_vault_files() {
        let (dir, paths) = temp_paths();
        let _ = init_vault(&paths, b"correct_horse").await;
        assert!(paths.vault_enc.exists());
        assert!(paths.vault_salt.exists());
        let salt_bytes = std::fs::read(&paths.vault_salt).unwrap();
        assert_eq!(salt_bytes.len(), 16);
        drop(dir);
    }

    #[tokio::test]
    async fn save_and_reload_vault() {
        let (dir, paths) = temp_paths();
        let state = init_vault(&paths, b"my_master_pw").await;
        {
            let mut guard = state.lock().await;
            guard
                .as_mut()
                .unwrap()
                .vault
                .entries
                .push(sample_entry("GitHub"));
        }
        save_vault(&state, &paths).await.unwrap();

        let salt_bytes = std::fs::read(&paths.vault_salt).unwrap();
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&salt_bytes);
        let keys = derive_keys(b"my_master_pw", &salt).unwrap();
        let blob_bytes = std::fs::read(&paths.vault_enc).unwrap();
        let blob = ferusa_core::crypto::EncryptedBlob::from_bytes(&blob_bytes).unwrap();
        let plaintext = decrypt_vault(&vault_key(&keys.local_secret), &blob).unwrap();
        let vault: Vault = serde_json::from_slice(&plaintext).unwrap();
        assert_eq!(vault.entries.len(), 1);
        assert_eq!(vault.entries[0].title, "GitHub");
        drop(dir);
    }

    #[tokio::test]
    async fn multiple_entries_persist() {
        let (dir, paths) = temp_paths();
        let state = init_vault(&paths, b"password123").await;
        {
            let mut guard = state.lock().await;
            let s = guard.as_mut().unwrap();
            s.vault.entries.push(sample_entry("GitHub"));
            s.vault.entries.push(sample_entry("AWS"));
            s.vault.entries.push(sample_entry("Cloudflare"));
        }
        save_vault(&state, &paths).await.unwrap();

        let salt_bytes = std::fs::read(&paths.vault_salt).unwrap();
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&salt_bytes);
        let keys = derive_keys(b"password123", &salt).unwrap();
        let blob = ferusa_core::crypto::EncryptedBlob::from_bytes(
            &std::fs::read(&paths.vault_enc).unwrap(),
        )
        .unwrap();
        let vault: Vault =
            serde_json::from_slice(&decrypt_vault(&vault_key(&keys.local_secret), &blob).unwrap())
                .unwrap();
        assert_eq!(vault.entries.len(), 3);
        drop(dir);
    }

    #[tokio::test]
    async fn wrong_password_fails_decryption() {
        let (dir, paths) = temp_paths();
        let state = init_vault(&paths, b"correct_password").await;
        {
            let mut guard = state.lock().await;
            guard
                .as_mut()
                .unwrap()
                .vault
                .entries
                .push(sample_entry("Secret"));
        }
        save_vault(&state, &paths).await.unwrap();

        let salt_bytes = std::fs::read(&paths.vault_salt).unwrap();
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&salt_bytes);
        let wrong_keys = derive_keys(b"wrong_password", &salt).unwrap();
        let blob = ferusa_core::crypto::EncryptedBlob::from_bytes(
            &std::fs::read(&paths.vault_enc).unwrap(),
        )
        .unwrap();
        assert!(decrypt_vault(&vault_key(&wrong_keys.local_secret), &blob).is_err());
        drop(dir);
    }

    #[tokio::test]
    async fn remove_entry_persists() {
        let (dir, paths) = temp_paths();
        let state = init_vault(&paths, b"pw").await;
        {
            let mut guard = state.lock().await;
            let s = guard.as_mut().unwrap();
            s.vault.entries.push(sample_entry("GitHub"));
            s.vault.entries.push(sample_entry("AWS"));
        }
        save_vault(&state, &paths).await.unwrap();
        {
            let mut guard = state.lock().await;
            guard
                .as_mut()
                .unwrap()
                .vault
                .entries
                .retain(|e| e.title != "GitHub");
        }
        save_vault(&state, &paths).await.unwrap();

        let salt_bytes = std::fs::read(&paths.vault_salt).unwrap();
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&salt_bytes);
        let keys = derive_keys(b"pw", &salt).unwrap();
        let blob = ferusa_core::crypto::EncryptedBlob::from_bytes(
            &std::fs::read(&paths.vault_enc).unwrap(),
        )
        .unwrap();
        let vault: Vault =
            serde_json::from_slice(&decrypt_vault(&vault_key(&keys.local_secret), &blob).unwrap())
                .unwrap();
        assert_eq!(vault.entries.len(), 1);
        assert_eq!(vault.entries[0].title, "AWS");
        drop(dir);
    }

    #[tokio::test]
    async fn passwd_re_encrypts_with_new_key() {
        let (dir, paths) = temp_paths();
        let state = init_vault(&paths, b"old_password").await;
        {
            let mut guard = state.lock().await;
            guard
                .as_mut()
                .unwrap()
                .vault
                .entries
                .push(sample_entry("Secret"));
        }
        save_vault(&state, &paths).await.unwrap();

        let new_salt = new_salt();
        let new_keys = derive_keys(b"new_password_long", &new_salt).unwrap();
        let new_vault_key = vault_key(&new_keys.local_secret);
        {
            let mut guard = state.lock().await;
            let s = guard.as_mut().unwrap();
            let plaintext = serde_json::to_vec(&s.vault).unwrap();
            let blob = encrypt_vault(&new_vault_key, new_salt, &plaintext).unwrap();
            std::fs::write(&paths.vault_salt, &new_salt).unwrap();
            std::fs::write(&paths.vault_enc, blob.to_bytes()).unwrap();
            s.local_secret = new_keys.local_secret;
            s.vault_key = new_vault_key;
        }
        lock_session(&state).await;

        let salt_bytes = std::fs::read(&paths.vault_salt).unwrap();
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&salt_bytes);
        let old_keys = derive_keys(b"old_password", &salt).unwrap();
        let blob = ferusa_core::crypto::EncryptedBlob::from_bytes(
            &std::fs::read(&paths.vault_enc).unwrap(),
        )
        .unwrap();
        assert!(
            decrypt_vault(&vault_key(&old_keys.local_secret), &blob).is_err(),
            "old password should no longer work"
        );

        let new_keys2 = derive_keys(b"new_password_long", &salt).unwrap();
        let vault: Vault = serde_json::from_slice(
            &decrypt_vault(&vault_key(&new_keys2.local_secret), &blob).unwrap(),
        )
        .unwrap();
        assert_eq!(vault.entries.len(), 1);
        assert_eq!(vault.entries[0].title, "Secret");
        drop(dir);
    }

    #[tokio::test]
    async fn vault_exists_false_without_files() {
        let (dir, paths) = temp_paths();
        assert!(!paths.vault_exists());
        drop(dir);
    }

    #[tokio::test]
    async fn vault_exists_true_after_init() {
        let (dir, paths) = temp_paths();
        let _ = init_vault(&paths, b"hunter2").await;
        assert!(paths.vault_exists());
        drop(dir);
    }

    #[tokio::test]
    async fn atomic_write_does_not_leave_tmp_file() {
        let (dir, paths) = temp_paths();
        let state = init_vault(&paths, b"pw").await;
        {
            let mut guard = state.lock().await;
            guard
                .as_mut()
                .unwrap()
                .vault
                .entries
                .push(sample_entry("Test"));
        }
        save_vault(&state, &paths).await.unwrap();
        let temp_prefix = ".vault.enc.tmp-";
        let leftover_temp_files: Vec<_> = std::fs::read_dir(&paths.data_dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name())
            .filter(|name| name.to_string_lossy().starts_with(temp_prefix))
            .collect();
        assert!(
            leftover_temp_files.is_empty(),
            "atomic write left temporary files: {leftover_temp_files:?}"
        );
        drop(dir);
    }

    #[tokio::test]
    async fn failed_candidate_save_keeps_live_session_vault_unchanged() {
        let (dir, paths) = temp_paths();
        let state = init_vault(&paths, b"pw").await;
        let mut candidate = {
            let guard = state.lock().await;
            guard.as_ref().unwrap().vault.clone()
        };
        candidate.entries.push(sample_entry("Rejected"));

        let mut failing_paths = paths.clone();
        failing_paths.vault_enc = paths.data_dir.clone();

        assert!(save_vault_candidate(&state, &failing_paths, candidate)
            .await
            .is_err());

        let guard = state.lock().await;
        assert!(guard.as_ref().unwrap().vault.entries.is_empty());
        drop(dir);
    }
}
