#[cfg(test)]
mod tests {
    use std::time::Duration;
    use tempfile::TempDir;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use uuid::Uuid;

    use ferusa_core::auth::{AuthRequest, AuthResponse};
    use ferusa_core::transport::{FerusaMessage, FERUSA_ALPN};
    use ferusa_core::types::VaultAction;

    use crate::net::cli_peer::CliPeer;
    use crate::storage::paths::{PairingStatus, Paths};

    fn tmp_paths(dir: &TempDir) -> Paths {
        let p = dir.path();
        Paths {
            data_dir: p.to_path_buf(),
            vault_enc: p.join("vault.enc"),
            vault_salt: p.join("vault.salt"),
            peer_id: p.join("peer.id"),
            phone_id: p.join("phone.id"),
            hmac_key: p.join("hmac.key"),
            clipboard_cmd: p.join("clipboard.cmd"),
        }
    }

    // —— secret key persistence ————————————————————————————————————————————

    #[tokio::test]
    async fn peer_id_is_created_on_first_init() {
        let dir = TempDir::new().unwrap();
        let paths = tmp_paths(&dir);
        assert!(!paths.peer_id.exists());

        let peer = CliPeer::init(&paths.peer_id).await.unwrap();
        peer.endpoint.close().await;

        assert!(
            paths.peer_id.exists(),
            "peer.id should be written on first init"
        );
        let raw = std::fs::read(&paths.peer_id).unwrap();
        assert_eq!(raw.len(), 32, "peer.id should be 32 bytes");

        #[cfg(unix)]
        {
            let mode = std::fs::metadata(&paths.peer_id)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "peer.id should be private");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn existing_peer_id_permissions_are_restricted_on_init() {
        let dir = TempDir::new().unwrap();
        let paths = tmp_paths(&dir);

        let peer1 = CliPeer::init(&paths.peer_id).await.unwrap();
        peer1.endpoint.close().await;

        std::fs::set_permissions(&paths.peer_id, std::fs::Permissions::from_mode(0o644)).unwrap();

        let peer2 = CliPeer::init(&paths.peer_id).await.unwrap();
        peer2.endpoint.close().await;

        let mode = std::fs::metadata(&paths.peer_id)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "existing peer.id should be re-locked");
    }

    #[tokio::test]
    async fn peer_id_is_stable_across_reinit() {
        let dir = TempDir::new().unwrap();
        let paths = tmp_paths(&dir);

        let peer1 = CliPeer::init(&paths.peer_id).await.unwrap();
        let id1 = peer1.endpoint.id();
        peer1.endpoint.close().await;

        let peer2 = CliPeer::init(&paths.peer_id).await.unwrap();
        let id2 = peer2.endpoint.id();
        peer2.endpoint.close().await;

        assert_eq!(id1, id2, "node id must be stable across re-inits");
    }

    // —— phone_id loading ——————————————————————————————————————————————————

    #[tokio::test]
    async fn load_phone_node_id_fails_when_absent() {
        let dir = TempDir::new().unwrap();
        let paths = tmp_paths(&dir);

        let mut peer = CliPeer::init(&paths.peer_id).await.unwrap();
        let result = peer.load_phone_node_id(&paths.phone_id);
        peer.endpoint.close().await;

        assert!(result.is_err(), "should fail when phone.id does not exist");
    }

    #[tokio::test]
    async fn load_phone_node_id_succeeds_with_valid_file() {
        let dir = TempDir::new().unwrap();
        let paths = tmp_paths(&dir);

        let peer_tmp = CliPeer::init(&paths.peer_id).await.unwrap();
        let own_id = *peer_tmp.endpoint.id().as_bytes();
        peer_tmp.endpoint.close().await;

        std::fs::write(&paths.phone_id, hex::encode(own_id)).unwrap();

        let mut peer2 = CliPeer::init(&paths.peer_id).await.unwrap();
        let result = peer2.load_phone_node_id(&paths.phone_id);
        peer2.endpoint.close().await;

        assert!(
            result.is_ok(),
            "should succeed with a valid phone.id: {:?}",
            result
        );
        assert!(peer2.phone_node_id.is_some());
    }

    // —— loopback message exchange ——————————————————————————————————————————

    #[tokio::test]
    async fn loopback_auth_request_roundtrip() {
        use iroh::endpoint::presets;

        let sender = iroh::Endpoint::builder(presets::N0)
            .alpns(vec![FERUSA_ALPN.to_vec()])
            .bind()
            .await
            .unwrap();

        let receiver = iroh::Endpoint::builder(presets::N0)
            .alpns(vec![FERUSA_ALPN.to_vec()])
            .bind()
            .await
            .unwrap();

        let receiver_addr = receiver.addr();

        // Oneshot so the receiver task signals it has finished writing the
        // response. We must not close the receiver endpoint until the sender
        // has fully drained the stream — closing early tears the connection.
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

        let receiver_task = tokio::spawn(async move {
            let incoming = receiver.accept().await.unwrap();
            let conn = incoming.accept().unwrap().await.unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();

            let data = recv.read_to_end(1024 * 1024).await.unwrap();
            let req = match FerusaMessage::decode(&data).unwrap() {
                FerusaMessage::Request(r) => r,
                _ => panic!("expected Request"),
            };

            let resp = AuthResponse {
                pairing_id: req.pairing_id,
                request_id: req.request_id,
                correlation_code: req.correlation_code,
                action: req.action,
                approved: true,
                unlock_share: None,
                timestamp: req.timestamp + 1,
                signature: vec![0xAB; 64],
            };
            let bytes = FerusaMessage::Response(resp).encode().unwrap();
            send.write_all(&bytes).await.unwrap();
            send.finish().unwrap();

            // Signal that the response bytes are in flight.
            let _ = done_tx.send(());

            // Keep the endpoint alive until the sender is done reading;
            // a short sleep is enough since we wait on done_rx before reading.
            tokio::time::sleep(Duration::from_millis(500)).await;
            receiver.close().await;
        });

        let req = AuthRequest {
            pairing_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            correlation_code: 4242,
            action: VaultAction::Read,
            entry_title: Some("GitHub".into()),
            unlock_share_requested: false,
            timestamp: 1_700_000_000_000,
        };

        let conn = sender.connect(receiver_addr, FERUSA_ALPN).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();

        send.write_all(&FerusaMessage::Request(req.clone()).encode().unwrap())
            .await
            .unwrap();
        send.finish().unwrap();

        // Wait until the receiver has written the response before reading,
        // so we don't race with the endpoint being closed.
        let _ = done_rx.await;

        let data = recv.read_to_end(1024 * 1024).await.unwrap();
        let reply = FerusaMessage::decode(&data).unwrap();

        match reply {
            FerusaMessage::Response(r) => {
                assert_eq!(r.request_id, req.request_id);
                assert_eq!(r.correlation_code, 4242);
                assert!(r.approved);
            }
            _ => panic!("expected Response"),
        }

        sender.close().await;
        tokio::time::timeout(Duration::from_secs(10), receiver_task)
            .await
            .unwrap()
            .unwrap();
    }

    // —— pairing status helper ——————————————————————————————————————————————

    #[test]
    fn pairing_status_missing_phone_id_without_files() {
        let dir = TempDir::new().unwrap();
        let paths = tmp_paths(&dir);
        assert_eq!(paths.pairing_status(), PairingStatus::MissingPhoneId);
    }

    #[test]
    fn pairing_status_rejects_invalid_phone_id() {
        let dir = TempDir::new().unwrap();
        let paths = tmp_paths(&dir);
        std::fs::write(&paths.phone_id, "aabbcc").unwrap();
        std::fs::write(&paths.hmac_key, &[0u8; 32]).unwrap();
        assert!(matches!(
            paths.pairing_status(),
            PairingStatus::InvalidPairing(_)
        ));
    }
}
