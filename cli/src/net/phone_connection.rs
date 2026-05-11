use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use ferusa_core::auth::{AuthRequest, AuthResponse};
use ferusa_core::transport::FerusaMessage;
use iroh::endpoint::Connection;
use log::debug;

use super::iroh_path::{iroh_path_report, IrohPathReport};
use super::recv_all;

const STREAM_PHASE_TIMEOUT: Duration = Duration::from_secs(10);
const PING_TOTAL_TIMEOUT: Duration = Duration::from_secs(20);
const APPROVAL_TOTAL_TIMEOUT: Duration = Duration::from_secs(70);

#[derive(Clone)]
pub struct PhoneConnection {
    pub conn: Arc<Connection>,
    pub endpoint: Arc<iroh::Endpoint>,
}

#[derive(Debug, thiserror::Error)]
pub enum PersistentApprovalError {
    #[error("persistent approval failed before request delivery: {source:#}")]
    BeforeDelivery {
        #[source]
        source: anyhow::Error,
    },
    #[error("persistent approval failed after request delivery may have started: {source:#}")]
    DeliveryUncertain {
        #[source]
        source: anyhow::Error,
    },
}

impl PersistentApprovalError {
    pub fn retry_is_safe(&self) -> bool {
        matches!(self, Self::BeforeDelivery { .. })
    }

    fn from_delivery_state(delivery_started: bool, source: anyhow::Error) -> Self {
        if delivery_started {
            Self::DeliveryUncertain { source }
        } else {
            Self::BeforeDelivery { source }
        }
    }
}

impl PhoneConnection {
    pub fn new(conn: Connection, endpoint: Arc<iroh::Endpoint>) -> Self {
        Self {
            conn: Arc::new(conn),
            endpoint,
        }
    }

    pub fn is_same_connection(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.conn, &other.conn)
    }

    pub async fn ping(&self) -> Result<IrohPathReport> {
        tokio::time::timeout(PING_TOTAL_TIMEOUT, async {
            debug!("[ferusa:cli]: PhoneConnection::ping opening stream");
            let (mut send, mut recv) =
                tokio::time::timeout(STREAM_PHASE_TIMEOUT, self.conn.open_bi())
                    .await
                    .context("timed out opening ping stream (10s)")??;
            let bytes = FerusaMessage::Ping.encode().context("encode ping")?;
            tokio::time::timeout(STREAM_PHASE_TIMEOUT, send.write_all(&bytes))
                .await
                .context("timed out sending ping (10s)")??;
            send.finish().context("finish ping send")?;

            let response_bytes = tokio::time::timeout(Duration::from_secs(10), recv_all(&mut recv))
                .await
                .context("timed out waiting for pong (10s)")??;

            match FerusaMessage::decode(&response_bytes).context("decode pong")? {
                FerusaMessage::Pong { .. } => Ok(iroh_path_report("ping", &self.conn)),
                _ => bail!("phone replied with non-pong message"),
            }
        })
        .await
        .context("ping exceeded the total 20s deadline")?
    }

    pub async fn request_approval(
        &self,
        req: &AuthRequest,
    ) -> std::result::Result<(AuthResponse, IrohPathReport), PersistentApprovalError> {
        let delivery_started = AtomicBool::new(false);
        let result = tokio::time::timeout(APPROVAL_TOTAL_TIMEOUT, async {
            debug!("[ferusa:cli]: PhoneConnection::request_approval opening stream");
            let (mut send, mut recv) =
                tokio::time::timeout(STREAM_PHASE_TIMEOUT, self.conn.open_bi())
                    .await
                    .context("timed out opening auth stream (10s)")??;
            let bytes = FerusaMessage::Request(req.clone())
                .encode()
                .context("encode AuthRequest")?;
            delivery_started.store(true, Ordering::Release);
            tokio::time::timeout(STREAM_PHASE_TIMEOUT, send.write_all(&bytes))
                .await
                .context("timed out sending AuthRequest (10s)")??;
            send.finish().context("finish auth send")?;

            let response_bytes = tokio::time::timeout(Duration::from_secs(60), recv_all(&mut recv))
                .await
                .context("timed out waiting for phone response (60s)")??;

            match FerusaMessage::decode(&response_bytes).context("decode AuthResponse")? {
                FerusaMessage::Response(r) => Ok((
                    r,
                    iroh_path_report(
                        format!("2fa {:?} {}", req.action, req.request_id),
                        &self.conn,
                    ),
                )),
                _ => bail!("phone sent a non-response message"),
            }
        })
        .await;

        match result {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(source)) => Err(PersistentApprovalError::from_delivery_state(
                delivery_started.load(Ordering::Acquire),
                source,
            )),
            Err(elapsed) => Err(PersistentApprovalError::from_delivery_state(
                delivery_started.load(Ordering::Acquire),
                anyhow::Error::new(elapsed)
                    .context("approval request exceeded the total 70s deadline"),
            )),
        }
    }

    pub async fn close(self) {
        self.conn.close(0u32.into(), b"session ended");
    }
}

#[cfg(test)]
mod tests {
    use super::{PersistentApprovalError, PhoneConnection};
    use ferusa_core::auth::{AuthRequest, AuthResponse};
    use ferusa_core::transport::{FerusaMessage, FERUSA_ALPN};
    use ferusa_core::types::VaultAction;
    use std::sync::Arc;

    #[test]
    fn only_pre_delivery_failures_are_retryable() {
        let before = PersistentApprovalError::from_delivery_state(
            false,
            anyhow::anyhow!("open stream failed"),
        );
        let uncertain =
            PersistentApprovalError::from_delivery_state(true, anyhow::anyhow!("write failed"));

        assert!(before.retry_is_safe());
        assert!(!uncertain.retry_is_safe());
    }

    #[tokio::test]
    async fn phone_connection_reuses_one_quic_session_for_ping_and_approval() {
        let phone_endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .alpns(vec![FERUSA_ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let cli_endpoint = Arc::new(
            iroh::Endpoint::builder(iroh::endpoint::presets::N0)
                .alpns(vec![FERUSA_ALPN.to_vec()])
                .bind()
                .await
                .unwrap(),
        );

        let server_endpoint = phone_endpoint.clone();
        let server = tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.unwrap();
            let conn = incoming.accept().unwrap().await.unwrap();

            let (mut ping_send, mut ping_recv) = conn.accept_bi().await.unwrap();
            let ping = ping_recv.read_to_end(1024 * 1024).await.unwrap();
            assert!(matches!(
                FerusaMessage::decode(&ping).unwrap(),
                FerusaMessage::Ping
            ));
            ping_send
                .write_all(&FerusaMessage::Pong { path_info: None }.encode().unwrap())
                .await
                .unwrap();
            ping_send.finish().unwrap();

            let (mut approval_send, mut approval_recv) = conn.accept_bi().await.unwrap();
            let request = approval_recv.read_to_end(1024 * 1024).await.unwrap();
            let request = match FerusaMessage::decode(&request).unwrap() {
                FerusaMessage::Request(request) => request,
                other => panic!("expected approval request, got {other:?}"),
            };
            approval_send
                .write_all(
                    &FerusaMessage::Response(AuthResponse {
                        pairing_id: request.pairing_id,
                        request_id: request.request_id,
                        correlation_code: request.correlation_code,
                        action: request.action,
                        unlock_share: None,
                        approved: false,
                        timestamp: request.timestamp,
                        signature: Vec::new(),
                    })
                    .encode()
                    .unwrap(),
                )
                .await
                .unwrap();
            approval_send.finish().unwrap();
            let _ = conn.closed().await;
        });

        let conn = cli_endpoint
            .connect(phone_endpoint.addr(), FERUSA_ALPN)
            .await
            .unwrap();
        let phone = PhoneConnection::new(conn, cli_endpoint.clone());
        phone.ping().await.unwrap();

        let request = AuthRequest {
            pairing_id: uuid::Uuid::new_v4(),
            request_id: uuid::Uuid::new_v4(),
            correlation_code: 1234,
            action: VaultAction::Read,
            entry_title: Some("example".into()),
            unlock_share_requested: false,
            timestamp: 42,
        };
        let (response, _) = phone.request_approval(&request).await.unwrap();
        assert_eq!(response.request_id, request.request_id);

        phone.close().await;
        server.await.unwrap();
        cli_endpoint.close().await;
        phone_endpoint.close().await;
    }
}
