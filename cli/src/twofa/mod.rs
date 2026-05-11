//! Real 2FA request flow via iroh.
//!
//! The iroh `Endpoint` is created once per session in `ensure_unlocked` and
//! stored in `SessionState`.  We clone the `Arc<Endpoint>` out of the lock,
//! release the lock, perform the async network call, then re-acquire for
//! validation.  This means:
//!
//!  - No 8-9 s per-request endpoint teardown.
//!  - The mutex is never held across an await.

pub mod dispatch;
pub mod render;
#[cfg(feature = "dev-2fa-stub")]
pub mod stub;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use log::{debug, error, info, warn};
use uuid::Uuid;

use ferusa_core::auth::{validate_auth_exchange_timestamps, AuthRequest, AuthResponse};
use ferusa_core::crypto::{random_correlation_code, verify_approval_signature};
use ferusa_core::types::VaultAction;

use crate::interface::ui;
use crate::net::cli_peer::CliPeer;
use crate::session::SharedState;
use crate::storage::paths::{PairingData, Paths};

/// All the ways a 2FA request can fail.
#[derive(Debug, thiserror::Error)]
pub enum TwofaError {
    #[error("signature mismatch — response may be forged or replayed")]
    SignatureMismatch,
    #[error("pairing generation mismatch — request or response is stale")]
    PairingGenerationMismatch,
    #[error("unknown request_id in response")]
    UnknownRequest,
    #[error("action mismatch — response action differs from request")]
    ActionMismatch,
    #[error("correlation code mismatch — response code differs from request")]
    CorrelationCodeMismatch,
    #[error("request was denied by the phone")]
    Denied,
    #[error("approved response did not include required phone unlock share")]
    MissingUnlockShare,
    #[error("auth timestamp outside the accepted freshness window")]
    TimestampSkew,
}

pub struct ApprovalResult {
    pub unlock_share: Option<[u8; 32]>,
}

pub fn action_label(action: VaultAction) -> &'static str {
    match action {
        VaultAction::Unlock => "UNLOCK",
        VaultAction::List => "LIST",
        VaultAction::Read => "READ",
        VaultAction::Create => "CREATE",
        VaultAction::Update => "UPDATE",
        VaultAction::Delete => "DELETE",
        // NOTE: protocol action is `Passwd` to match the CLI command; UI expands it for clarity.
        VaultAction::Passwd => "CHANGE_PASSWORD",
        VaultAction::Pair => "REPLACE_PAIRING",
    }
}

/// Send an `AuthRequest` to the phone, verify the signed `AuthResponse`,
/// and return `Ok(())` only if the request was approved and valid.
pub async fn request_approval(
    state: &SharedState,
    paths: &Paths,
    action: VaultAction,
    entry_title: Option<&str>,
) -> Result<()> {
    request_approval_for_session(state, paths, action, entry_title, false)
        .await
        .map(|_| ())
}

pub async fn request_unlock_share(
    endpoint: Arc<iroh::Endpoint>,
    pairing: PairingData,
    action: VaultAction,
    entry_title: Option<&str>,
) -> Result<[u8; 32]> {
    let result =
        request_approval_over_endpoint(&endpoint, pairing, action, entry_title, true).await?;

    result.unlock_share.ok_or_else(|| {
        ui::failed("phone approved but did not return the vault unlock share");
        TwofaError::MissingUnlockShare.into()
    })
}

pub async fn request_approval_for_session(
    state: &SharedState,
    _paths: &Paths,
    action: VaultAction,
    entry_title: Option<&str>,
    unlock_share_requested: bool,
) -> Result<ApprovalResult> {
    info!(
        "[ferusa:cli]: twofa::request_approval action={:?} entry={:?}",
        action, entry_title
    );

    // —— 1. Generate request metadata ————————————————————————————————————
    let request_id = Uuid::new_v4();
    let correlation_code = random_correlation_code();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    debug!(
        "[ferusa:cli]: twofa::request_approval request_id={} correlation_code={}",
        request_id, correlation_code
    );

    let pairing_id = {
        let guard = state.lock().await;
        let s = guard.as_ref().context("session not unlocked")?;
        s.pairing
            .as_ref()
            .context("session missing pairing data")?
            .pairing_id
    };

    let req = AuthRequest {
        pairing_id,
        request_id,
        correlation_code,
        action,
        entry_title: entry_title.map(str::to_owned),
        unlock_share_requested,
        timestamp,
    };

    // —— 2. Register in pending map ——————————————————————————————————————
    {
        use crate::session::PendingRequest;
        let mut guard = state.lock().await;
        let s = guard.as_mut().context("session not unlocked")?;
        s.pending_requests.insert(
            request_id,
            PendingRequest {
                correlation_code,
                action,
                created_at: std::time::Instant::now(),
            },
        );
        debug!(
            "[ferusa:cli]: twofa::request_approval registered in pending map (size={})",
            s.pending_requests.len()
        );
    }

    let result = async {
        // —— 3. Display 2FA prompt ———————————————————————————————————————————
        let action_label = action_label(action);

        match entry_title {
            Some(t) => ui::info(&format!(
                "approve 2FA request for {} \"{}\"",
                action_label, t
            )),
            None => ui::info(&format!("approve 2FA request for {}", action_label)),
        }

        render::render_code(correlation_code.into());
        // ui::info(&format!("2FA code is {}", correlation_code));
        ui::info("waiting for approval");

        // —— 4. Borrow endpoint + phone_node_id from session ——————————————————
        let (phone_conn, endpoint, pairing) = {
            let guard = state.lock().await;
            let s = guard.as_ref().context("session not unlocked")?;
            let pairing = s
                .pairing
                .as_ref()
                .context("session missing pairing data")?
                .clone();
            (
                s.phone_conn.clone(),
                s.endpoint
                    .as_ref()
                    .context("real 2FA endpoint unavailable")?
                    .clone(),
                pairing,
            )
        };
        debug!(
            "[ferusa:cli]: twofa::request_approval sending request to phone phone_node_id={}",
            pairing.phone_node_id
        );

        // —— 5. Send request over persistent connection when available, else fall back to one-shot dial ———
        let (resp, path_report) = if let Some(phone_conn) = phone_conn {
            match phone_conn.request_approval(&req).await {
                Ok(response) => response,
                Err(error) if error.retry_is_safe() => {
                    warn!(
                        "[ferusa:cli]: stale persistent connection failed before delivery; redialing: {:#}",
                        error
                    );
                    {
                        let mut guard = state.lock().await;
                        if let Some(session) = guard.as_mut() {
                            if session
                                .phone_conn
                                .as_ref()
                                .is_some_and(|stored| stored.is_same_connection(&phone_conn))
                            {
                                session.phone_conn = None;
                            }
                        }
                    }

                    let replacement = crate::session_conn::dial_phone(
                        endpoint.clone(),
                        pairing.phone_node_id,
                        std::time::Duration::from_secs(10),
                    )
                    .await
                    .context("redial phone after stale persistent connection")?;
                    let response = replacement
                        .request_approval(&req)
                        .await
                        .context("iroh redialed persistent request_approval")?;
                    {
                        let mut guard = state.lock().await;
                        let session = guard.as_mut().context("session not unlocked")?;
                        session.phone_conn = Some(replacement);
                    }
                    response
                }
                Err(error) => {
                    return Err(anyhow::Error::new(error))
                        .context("iroh persistent request_approval");
                }
            }
        } else {
            CliPeer::send_auth_request_on_with_path_report(&endpoint, &req, pairing.phone_node_id)
                .await
                .context("iroh send_auth_request")?
        };
        ui::info(&path_report.human_summary());
        debug!(
            "[ferusa:cli]: twofa::request_approval got response approved={}",
            resp.approved
        );

        ensure_pairing_generation(pairing.pairing_id, req.pairing_id, resp.pairing_id)?;

        // —— 7. Remove from pending map ——————————————————————————————————————
        let pending = {
            let mut guard = state.lock().await;
            let s = guard.as_mut().context("session not unlocked")?;
            let pending = match s.pending_requests.remove(&resp.request_id) {
                Some(pending) => pending,
                None => {
                    warn!(
                        "[ferusa:cli]: twofa::request_approval unknown request_id={}",
                        resp.request_id
                    );
                    Err(TwofaError::UnknownRequest)?
                }
            };
            debug!("[ferusa:cli]: twofa::request_approval removed from pending map");
            pending
        };

        // —— 8. Verify phone signature ————————————————————————————————————————
        if !verify_approval_signature(&pairing.approval_public_key_der, &req, &resp) {
            error!(
                "[ferusa:cli]: twofa::request_approval signature mismatch request_id={}",
                resp.request_id
            );
            Err(TwofaError::SignatureMismatch)?;
        }
        debug!("[ferusa:cli]: twofa::request_approval signature verified");

        validate_auth_exchange(&req, &resp)?;
        debug!("[ferusa:cli]: twofa::request_approval timestamps fresh");

        // —— 9. Verify correlation code matches pending request ——————————————
        if resp.correlation_code != pending.correlation_code {
            warn!(
                "[ferusa:cli]: twofa::request_approval correlation code mismatch expected={} got={}",
                pending.correlation_code, resp.correlation_code
            );
            Err(TwofaError::CorrelationCodeMismatch)?;
        }
        debug!("[ferusa:cli]: twofa::request_approval correlation code matched");

        // —— 10. Verify action matches pending request ————————————————————————
        if resp.action != pending.action {
            warn!(
                "[ferusa:cli]: twofa::request_approval action mismatch expected={:?} got={:?}",
                pending.action, resp.action
            );
            Err(TwofaError::ActionMismatch)?;
        }
        debug!("[ferusa:cli]: twofa::request_approval action matched");

        // —— 11. Check approved flag —————————————————————————————————————————
        if !resp.approved {
            warn!("[ferusa:cli]: twofa::request_approval denied by phone");
            Err(TwofaError::Denied)?;
        }

        info!(
            "[ferusa:cli]: twofa::request_approval approved request_id={}",
            request_id
        );
        Ok(ApprovalResult {
            unlock_share: resp.unlock_share,
        })
    }
    .await;

    {
        let mut guard = state.lock().await;
        if let Some(s) = guard.as_mut() {
            if s.pending_requests.remove(&request_id).is_some() {
                debug!(
                    "[ferusa:cli]: twofa::request_approval cleaned pending request_id={}",
                    request_id
                );
            }
        }
    }

    result
}

async fn request_approval_over_endpoint(
    endpoint: &iroh::Endpoint,
    pairing: PairingData,
    action: VaultAction,
    entry_title: Option<&str>,
    unlock_share_requested: bool,
) -> Result<ApprovalResult> {
    let request_id = Uuid::new_v4();
    let correlation_code = random_correlation_code();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let req = AuthRequest {
        pairing_id: pairing.pairing_id,
        request_id,
        correlation_code,
        action,
        entry_title: entry_title.map(str::to_owned),
        unlock_share_requested,
        timestamp,
    };

    let label = action_label(action);
    match entry_title {
        Some(t) => ui::info(&format!("approve 2FA request for {} \"{}\"", label, t)),
        None => ui::info(&format!("approve 2FA request for {}", label)),
    }
    render::render_code(correlation_code.into());
    ui::info("waiting for approval");

    let (resp, path_report) =
        CliPeer::send_auth_request_on_with_path_report(endpoint, &req, pairing.phone_node_id)
            .await
            .context("iroh send_auth_request")?;
    ui::info(&path_report.human_summary());

    validate_response(&req, &pairing, &resp)?;

    Ok(ApprovalResult {
        unlock_share: resp.unlock_share,
    })
}

fn validate_response(req: &AuthRequest, pairing: &PairingData, resp: &AuthResponse) -> Result<()> {
    ensure_pairing_generation(pairing.pairing_id, req.pairing_id, resp.pairing_id)?;
    if resp.request_id != req.request_id {
        warn!(
            "[ferusa:cli]: twofa::validate_response request_id mismatch expected={} got={}",
            req.request_id, resp.request_id
        );
        Err(TwofaError::UnknownRequest)?;
    }
    if !verify_approval_signature(&pairing.approval_public_key_der, req, resp) {
        error!(
            "[ferusa:cli]: twofa::validate_response signature mismatch request_id={}",
            resp.request_id
        );
        Err(TwofaError::SignatureMismatch)?;
    }
    validate_auth_exchange(req, resp)?;
    if resp.correlation_code != req.correlation_code {
        Err(TwofaError::CorrelationCodeMismatch)?;
    }
    if resp.action != req.action {
        Err(TwofaError::ActionMismatch)?;
    }
    if !resp.approved {
        Err(TwofaError::Denied)?;
    }
    Ok(())
}

pub(crate) fn validate_auth_exchange(
    req: &AuthRequest,
    resp: &AuthResponse,
) -> std::result::Result<(), TwofaError> {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    validate_auth_exchange_timestamps(req, resp, now_ms).map_err(|err| {
        warn!(
            "[ferusa:cli]: twofa::validate_auth_exchange stale timestamp request_id={} error={}",
            resp.request_id, err
        );
        TwofaError::TimestampSkew
    })
}

pub(crate) fn ensure_pairing_generation(
    active_pairing_id: Uuid,
    request_pairing_id: Uuid,
    response_pairing_id: Uuid,
) -> std::result::Result<(), TwofaError> {
    if request_pairing_id != active_pairing_id || response_pairing_id != active_pairing_id {
        Err(TwofaError::PairingGenerationMismatch)
    } else {
        Ok(())
    }
}
