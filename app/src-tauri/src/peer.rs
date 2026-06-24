use anyhow::{bail, Context, Result};
use ferusa_core::auth::{
    AuthRequest, AuthResponse, PairingActivate, PairingActivateAck, PairingCommit,
    PairingCommitAck, PairingHello, PairingPrepared, PairingReady,
};
use ferusa_core::transport::{
    FerusaMessage, FERUSA_ALPN, PAIRING_COMPLETE_CLOSE_CODE, PAIRING_COMPLETE_CLOSE_REASON,
};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::Endpoint;
#[cfg(target_os = "android")]
use iroh::{endpoint::IncomingAddr, PublicKey};
use log::{debug, info};
#[cfg(any(target_os = "android", test))]
use std::collections::HashMap;
use std::future::Future;
#[cfg(any(target_os = "android", test))]
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::Zeroizing;

pub const INBOUND_FRAME_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(target_os = "android")]
pub const INBOUND_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);
pub const INBOUND_IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
pub const UNAUTHENTICATED_INBOUND_IDLE_TIMEOUT: Duration = Duration::from_secs(3);
#[cfg(target_os = "android")]
pub const MAX_INBOUND_HANDSHAKES: usize = 8;
#[cfg(target_os = "android")]
pub const MAX_UNTRUSTED_CONNECTION_HANDLERS: usize = 8;
#[cfg(target_os = "android")]
pub const MAX_PAIRED_CONNECTION_HANDLERS: usize = 4;
#[cfg(target_os = "android")]
pub const MAX_INBOUND_CONNECTIONS_PER_PEER: usize = 4;
#[cfg(target_os = "android")]
pub const MAX_INBOUND_CONNECTIONS_PER_SOURCE: usize = 4;
const PAIRING_STEP_TIMEOUT: Duration = Duration::from_secs(120);

#[cfg(target_os = "android")]
pub fn inbound_source_key(addr: &IncomingAddr) -> String {
    match addr {
        IncomingAddr::Ip(socket) => format!("ip:{}", socket.ip()),
        IncomingAddr::Relay { url, .. } => format!("relay:{url:?}"),
        IncomingAddr::Custom(custom) => format!("custom:{custom:?}"),
        _ => format!("other:{addr:?}"),
    }
}

#[cfg(target_os = "android")]
pub fn inbound_claimed_endpoint_id(addr: &IncomingAddr) -> Option<PublicKey> {
    match addr {
        IncomingAddr::Relay { endpoint_id, .. } => Some(*endpoint_id),
        _ => None,
    }
}

#[cfg(any(target_os = "android", test))]
pub struct SourceAdmissionLimiter {
    max_per_source: usize,
    counts: Mutex<HashMap<String, usize>>,
}

#[cfg(any(target_os = "android", test))]
impl SourceAdmissionLimiter {
    pub fn new(max_per_source: usize) -> Arc<Self> {
        Arc::new(Self {
            max_per_source,
            counts: Mutex::new(HashMap::new()),
        })
    }

    pub fn try_acquire(self: &Arc<Self>, source: String) -> Option<SourceAdmissionPermit> {
        let mut counts = self
            .counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let count = counts.entry(source.clone()).or_insert(0);
        if *count >= self.max_per_source {
            return None;
        }
        *count += 1;
        Some(SourceAdmissionPermit {
            limiter: self.clone(),
            source,
        })
    }
}

#[cfg(any(target_os = "android", test))]
pub struct SourceAdmissionPermit {
    limiter: Arc<SourceAdmissionLimiter>,
    source: String,
}

#[cfg(any(target_os = "android", test))]
impl Drop for SourceAdmissionPermit {
    fn drop(&mut self) {
        let mut counts = self
            .limiter
            .counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(count) = counts.get_mut(&self.source) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.source);
            }
        }
    }
}

pub struct AppPeer {
    pub endpoint: Endpoint,
}

fn encode_secret_message(message: &FerusaMessage) -> Result<Zeroizing<Vec<u8>>> {
    let json = Zeroizing::new(serde_json::to_vec(message).context("encode secret message JSON")?);
    let len = json.len() as u32;
    let mut out = Zeroizing::new(Vec::with_capacity(4 + json.len()));
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&json);
    Ok(out)
}

async fn finish_pairing_connection(
    send: &mut SendStream,
    recv: &mut RecvStream,
    conn: &Connection,
) -> Result<()> {
    send.finish().context("finish pairing send")?;

    tokio::time::timeout(PAIRING_STEP_TIMEOUT, recv.read_to_end(0))
        .await
        .context("timed out waiting for CLI pairing completion")?
        .context("read CLI pairing completion")?;
    debug!("[ferusa:app]: CLI pairing completion observed");

    conn.close(
        PAIRING_COMPLETE_CLOSE_CODE.into(),
        PAIRING_COMPLETE_CLOSE_REASON,
    );
    Ok(())
}

pub fn build_response_for_signing(
    req: &AuthRequest,
    approved: bool,
    unlock_share: Option<&[u8; 32]>,
    timestamp: u64,
) -> Result<AuthResponse> {
    Ok(AuthResponse {
        pairing_id: req.pairing_id,
        request_id: req.request_id,
        correlation_code: req.correlation_code,
        action: req.action,
        approved,
        unlock_share: match (approved, req.unlock_share_requested) {
            (true, true) => {
                Some(*unlock_share.context("approved unlock response missing phone share")?)
            }
            _ => None,
        },
        timestamp,
        signature: Vec::new(),
    })
}

impl AppPeer {
    /// Wrap an already-bound endpoint.
    ///
    /// This is the preferred constructor for production code. The caller owns
    /// the endpoint lifetime; `AppPeer` is just a thin helper around it. In
    /// particular, do NOT call `close()` on an `AppPeer` built this way — the
    /// endpoint belongs to the listener loop in `lib.rs`.
    pub fn from_endpoint(endpoint: Endpoint) -> Self {
        info!("[ferusa:app]: AppPeer::from_endpoint");
        Self { endpoint }
    }

    pub async fn pair_with_cli<F, Fut, A, AFut>(
        &self,
        cli_node_id_bytes: &[u8; 32],
        pairing_id: uuid::Uuid,
        approval_public_key_der: Vec<u8>,
        phone_share: &[u8; 32],
        ready_signature: Vec<u8>,
        verification_code: u16,
        on_committed: F,
        on_activated: A,
    ) -> Result<()>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<()>>,
        A: FnOnce() -> AFut,
        AFut: Future<Output = Result<()>>,
    {
        info!("[ferusa:app]: pair_with_cli start");

        debug!("[ferusa:app]: parsing CLI public key from bytes");
        let cli_pk = iroh::PublicKey::from_bytes(cli_node_id_bytes).context("parse CLI node id")?;
        debug!("[ferusa:app]: parsed CLI public key");

        let cli_addr = iroh::EndpointAddr::new(cli_pk);
        debug!("[ferusa:app]: built CLI EndpointAddr");

        info!("[ferusa:app]: connecting to CLI...");
        let conn: Connection = tokio::time::timeout(
            PAIRING_STEP_TIMEOUT,
            self.endpoint.connect(cli_addr, FERUSA_ALPN),
        )
        .await
        .context("timed out connecting to CLI for pairing")?
        .context("connect to CLI for pairing")?;
        info!("[ferusa:app]: connected to CLI");

        debug!("[ferusa:app]: opening bidi stream for pairing");
        let (mut send, mut recv) = tokio::time::timeout(PAIRING_STEP_TIMEOUT, conn.open_bi())
            .await
            .context("timed out opening pairing stream")?
            .context("open bidi stream")?;
        debug!("[ferusa:app]: bidi stream opened");

        let message = FerusaMessage::PairingHello(PairingHello {
            pairing_id,
            approval_public_key_der,
            phone_share: *phone_share,
            verification_code,
        });
        let hello = encode_secret_message(&message).context("encode PairingHello")?;
        drop(message);
        tokio::time::timeout(PAIRING_STEP_TIMEOUT, send.write_all(&hello))
            .await
            .context("timed out sending pairing hello")?
            .context("send pairing hello")?;
        drop(hello);
        debug!("[ferusa:app]: pairing hello written");

        debug!("[ferusa:app]: waiting for CLI prepared ACK...");
        match read_ferusa_message(&mut recv, PAIRING_STEP_TIMEOUT)
            .await
            .context("read prepared")?
        {
            FerusaMessage::PairingPrepared(PairingPrepared { pairing_id: got })
                if got == pairing_id => {}
            other => bail!("unexpected pairing prepared message: {:?}", other),
        }

        let ready = FerusaMessage::PairingReady(PairingReady {
            pairing_id,
            signature: ready_signature,
        })
        .encode()
        .context("encode PairingReady")?;
        tokio::time::timeout(PAIRING_STEP_TIMEOUT, send.write_all(&ready))
            .await
            .context("timed out sending pairing ready")?
            .context("send pairing ready")?;

        info!("[ferusa:app]: pairing ready sent");

        debug!("[ferusa:app]: waiting for CLI commit request...");
        match read_ferusa_message(&mut recv, PAIRING_STEP_TIMEOUT)
            .await
            .context("read commit")?
        {
            FerusaMessage::PairingCommit(PairingCommit { pairing_id: got })
                if got == pairing_id => {}
            other => bail!("unexpected pairing commit message: {:?}", other),
        }
        info!("[ferusa:app]: CLI requested pairing commit");

        on_committed().await.context("record committed pairing")?;
        debug!("[ferusa:app]: committed pairing marker recorded");
        let commit_ack = FerusaMessage::PairingCommitAck(PairingCommitAck { pairing_id })
            .encode()
            .context("encode PairingCommitAck")?;
        tokio::time::timeout(PAIRING_STEP_TIMEOUT, send.write_all(&commit_ack))
            .await
            .context("timed out sending pairing commit acknowledgement")?
            .context("send pairing commit acknowledgement")?;

        match read_ferusa_message(&mut recv, PAIRING_STEP_TIMEOUT)
            .await
            .context("read activate")?
        {
            FerusaMessage::PairingActivate(PairingActivate { pairing_id: got })
                if got == pairing_id => {}
            other => bail!("unexpected pairing activate message: {:?}", other),
        }
        on_activated().await.context("activate committed pairing")?;
        let activate_ack = FerusaMessage::PairingActivateAck(PairingActivateAck { pairing_id })
            .encode()
            .context("encode PairingActivateAck")?;
        tokio::time::timeout(PAIRING_STEP_TIMEOUT, send.write_all(&activate_ack))
            .await
            .context("timed out sending pairing activate acknowledgement")?
            .context("send pairing activate acknowledgement")?;
        finish_pairing_connection(&mut send, &mut recv, &conn).await?;
        info!("[ferusa:app]: pairing connection closed");

        Ok(())
    }

    pub async fn send_response(
        send: &mut iroh::endpoint::SendStream,
        resp: AuthResponse,
    ) -> Result<()> {
        info!(
            "[ferusa:app]: send_response: request_id={} approved={}",
            resp.request_id, resp.approved
        );

        debug!("[ferusa:app]: send_response: timestamp={}", resp.timestamp);

        let message = FerusaMessage::Response(resp);
        let bytes = encode_secret_message(&message).context("encode response")?;
        drop(message);
        debug!(
            "[ferusa:app]: send_response: encoded response ({} bytes)",
            bytes.len()
        );

        // Write back on the same stream the CLI opened and is waiting on.
        tokio::time::timeout(INBOUND_FRAME_TIMEOUT, send.write_all(&bytes))
            .await
            .context("timed out sending response")?
            .context("send response")?;
        drop(bytes);
        debug!("[ferusa:app]: send_response: bytes written");

        send.finish().context("finish response")?;
        debug!("[ferusa:app]: send_response: stream finished");

        info!("[ferusa:app]: send_response: response sent successfully");

        Ok(())
    }
}

pub async fn read_ferusa_message(
    recv: &mut iroh::endpoint::RecvStream,
    timeout: Duration,
) -> Result<FerusaMessage> {
    tokio::time::timeout(timeout, read_ferusa_message_unbounded(recv))
        .await
        .context("timed out reading message")?
}

async fn read_ferusa_message_unbounded(
    recv: &mut iroh::endpoint::RecvStream,
) -> Result<FerusaMessage> {
    let mut header = [0u8; 4];
    recv.read_exact(&mut header)
        .await
        .context("read message header")?;
    let len = u32::from_le_bytes(header) as usize;
    if len > 1024 * 1024 {
        bail!("message too large: {len}");
    }
    let mut bytes = Zeroizing::new(vec![0u8; 4 + len]);
    bytes[..4].copy_from_slice(&header);
    recv.read_exact(&mut bytes[4..])
        .await
        .context("read message payload")?;
    FerusaMessage::decode(&bytes).context("decode message")
}

#[cfg(test)]
mod tests {
    use super::{build_response_for_signing, finish_pairing_connection, SourceAdmissionLimiter};
    use ferusa_core::auth::AuthRequest;
    use ferusa_core::transport::{
        FERUSA_ALPN, PAIRING_COMPLETE_CLOSE_CODE, PAIRING_COMPLETE_CLOSE_REASON,
    };
    use ferusa_core::types::VaultAction;
    use iroh::endpoint::{presets, ConnectionError};
    use std::time::Duration;
    use uuid::Uuid;

    fn request(unlock_share_requested: bool) -> AuthRequest {
        AuthRequest {
            pairing_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            correlation_code: 1234,
            action: VaultAction::Unlock,
            entry_title: None,
            unlock_share_requested,
            timestamp: 42,
        }
    }

    #[test]
    fn source_admission_cannot_be_bypassed_by_fresh_peer_identities() {
        let limiter = SourceAdmissionLimiter::new(2);
        let first = limiter.try_acquire("relay:https://relay.example".into());
        let second = limiter.try_acquire("relay:https://relay.example".into());
        let fresh_identity_same_relay = limiter.try_acquire("relay:https://relay.example".into());

        assert!(first.is_some());
        assert!(second.is_some());
        assert!(fresh_identity_same_relay.is_none());

        drop(first);
        assert!(limiter
            .try_acquire("relay:https://relay.example".into())
            .is_some());
    }

    #[test]
    fn approved_response_includes_requested_phone_share() {
        let phone_share = [0x22; 32];
        let req = request(true);

        let resp = build_response_for_signing(&req, true, Some(&phone_share), 100).unwrap();

        assert_eq!(resp.unlock_share, Some(phone_share));
        assert_eq!(resp.signature, Vec::<u8>::new());
    }

    #[test]
    fn approved_response_omits_unrequested_phone_share() {
        let phone_share = [0x22; 32];
        let req = request(false);

        let resp = build_response_for_signing(&req, true, Some(&phone_share), 100).unwrap();

        assert_eq!(resp.unlock_share, None);
        assert_eq!(resp.signature, Vec::<u8>::new());
    }

    #[test]
    fn denial_response_never_includes_phone_share() {
        let phone_share = [0x22; 32];
        let req = request(true);

        let resp = build_response_for_signing(&req, false, Some(&phone_share), 100).unwrap();

        assert_eq!(resp.unlock_share, None);
        assert_eq!(resp.signature, Vec::<u8>::new());
    }

    #[test]
    fn approved_requested_share_requires_phone_share() {
        let req = request(true);

        assert!(build_response_for_signing(&req, true, None, 100).is_err());
    }

    #[tokio::test]
    async fn pairing_close_waits_for_cli_completion_eof() {
        let phone = iroh::Endpoint::builder(presets::N0)
            .alpns(vec![FERUSA_ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let cli = iroh::Endpoint::builder(presets::N0)
            .alpns(vec![FERUSA_ALPN.to_vec()])
            .bind()
            .await
            .unwrap();

        let phone_accept = phone.clone();
        let phone_task = tokio::spawn(async move {
            let incoming = phone_accept.accept().await.unwrap();
            let conn = incoming.accept().unwrap().await.unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            let mut request = [0u8; 1];
            recv.read_exact(&mut request).await.unwrap();
            assert_eq!(request, [0xAA]);
            send.write_all(&[0xBB]).await.unwrap();
            finish_pairing_connection(&mut send, &mut recv, &conn)
                .await
                .unwrap();
            phone_accept.close().await;
        });

        let conn = cli.connect(phone.addr(), FERUSA_ALPN).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(&[0xAA]).await.unwrap();
        let mut response = [0u8; 1];
        recv.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [0xBB]);

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!phone_task.is_finished());

        send.finish().unwrap();
        let close_reason = conn.closed().await;
        match close_reason {
            ConnectionError::ApplicationClosed(close) => {
                assert_eq!(close.error_code, PAIRING_COMPLETE_CLOSE_CODE.into());
                assert_eq!(close.reason.as_ref(), PAIRING_COMPLETE_CLOSE_REASON);
            }
            other => panic!("unexpected close reason: {other}"),
        }

        cli.close().await;
        tokio::time::timeout(Duration::from_secs(10), phone_task)
            .await
            .unwrap()
            .unwrap();
    }
}
