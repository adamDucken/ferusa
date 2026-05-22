/// Tests for session helpers that don't need a real vault on disk.
/// We test the lock helper and the SharedState type contract.
#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use tokio::sync::Mutex;

    use ferusa_core::transport::FERUSA_ALPN;
    use ferusa_core::types::Vault;

    use crate::session::{lock_session, SessionState, SharedState};

    fn make_state() -> SharedState {
        Arc::new(Mutex::new(None))
    }

    async fn fake_session() -> SessionState {
        // We need a real (but ephemeral) endpoint so that SessionState can be
        // constructed. This is cheap in tests because the endpoint is dropped
        // together with the SessionState.
        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .alpns(vec![FERUSA_ALPN.to_vec()])
            .bind()
            .await
            .expect("bind test endpoint");

        SessionState {
            vault: Vault::default(),
            local_secret: [0x11; 32],
            vault_key: [0xAA; 32],
            phone_share: [0x22; 32],
            vault_salt: [0xCC; 16],
            pairing: None,
            pending_requests: HashMap::new(),
            endpoint: Some(Arc::new(endpoint)),
            phone_conn: None,
            vault_lock: None,
        }
    }

    #[tokio::test]
    async fn state_starts_locked() {
        let state = make_state();
        let guard = state.lock().await;
        assert!(guard.is_none());
    }

    #[tokio::test]
    async fn manual_unlock_and_lock() {
        let state = make_state();

        {
            let mut guard = state.lock().await;
            *guard = Some(fake_session().await);
        }

        {
            let guard = state.lock().await;
            assert!(guard.is_some(), "state should be unlocked");
        }

        lock_session(&state).await;

        {
            let guard = state.lock().await;
            assert!(guard.is_none(), "state should be locked after lock_session");
        }
    }

    #[tokio::test]
    async fn lock_idempotent_when_already_locked() {
        let state = make_state();
        lock_session(&state).await; // lock an already-locked state
        let guard = state.lock().await;
        assert!(guard.is_none());
    }

    #[tokio::test]
    async fn session_stores_vault_entries() {
        let state = make_state();
        let mut sess = fake_session().await;
        sess.vault.entries.push(ferusa_core::types::Entry {
            id: uuid::Uuid::new_v4(),
            title: "TestEntry".into(),
            username: Some("user".into()),
            password: "s3cr3t".into(),
            url: None,
            notes: None,
            tags: vec![],
            created_at: 0,
            updated_at: 0,
        });

        {
            let mut guard = state.lock().await;
            *guard = Some(sess);
        }

        let guard = state.lock().await;
        let s = guard.as_ref().unwrap();
        assert_eq!(s.vault.entries.len(), 1);
        assert_eq!(s.vault.entries[0].title, "TestEntry");
        assert_eq!(s.vault.entries[0].password, "s3cr3t");
    }
}
