use std::time::Duration;

use anyhow::{Context, Result};
use ferusa_core::transport::FERUSA_ALPN;
use iroh::EndpointAddr;
use log::info;

use crate::interface::ui;
use crate::net::phone_connection::PhoneConnection;
use crate::session::SharedState;
use crate::storage::paths::Paths;

pub async fn dial_phone(
    endpoint: std::sync::Arc<iroh::Endpoint>,
    phone_node_id: iroh::PublicKey,
    timeout: Duration,
) -> Result<PhoneConnection> {
    let conn = tokio::time::timeout(
        timeout,
        endpoint.connect(EndpointAddr::new(phone_node_id), FERUSA_ALPN),
    )
    .await
    .context("timed out connecting to phone")?
    .context("connect to phone")?;

    Ok(PhoneConnection::new(conn, endpoint))
}

pub async fn connect_to_phone(
    state: &SharedState,
    _paths: &Paths,
    timeout: Duration,
) -> Result<PhoneConnection> {
    let (endpoint, phone_node_id) = {
        let guard = state.lock().await;
        let s = guard.as_ref().context("session not unlocked")?;
        let pairing = s.pairing.as_ref().context("session missing pairing data")?;
        (
            s.endpoint
                .as_ref()
                .context("real 2FA endpoint unavailable")?
                .clone(),
            pairing.phone_node_id,
        )
    };

    info!(
        "[ferusa:cli]: connecting persistent phone session phone_node_id={}",
        phone_node_id
    );
    let phone = dial_phone(endpoint, phone_node_id, timeout).await?;
    let report = phone.ping().await.context("initial ping")?;
    ui::info(&format!("pong — {}", report.human_summary()));

    {
        let mut guard = state.lock().await;
        if let Some(s) = guard.as_mut() {
            s.phone_conn = Some(phone.clone());
        }
    }

    Ok(phone)
}
