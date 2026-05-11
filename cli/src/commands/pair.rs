use std::io::{self, Write};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use ferusa_core::auth::{
    PairingActivate, PairingActivateAck, PairingCommit, PairingCommitAck, PairingPrepared,
    PairingReady,
};
use ferusa_core::crypto::{combine_vault_key, verify_pairing_ready_signature};
use ferusa_core::transport::{
    FerusaMessage, FERUSA_ALPN, PAIRING_COMPLETE_CLOSE_CODE, PAIRING_COMPLETE_CLOSE_REASON,
};
use ferusa_core::types::VaultAction;
use iroh::endpoint::ConnectionError;
use iroh::EndpointAddr;
use log::{debug, info};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::interface::ui;
use crate::net::iroh_path::iroh_path_report;
use crate::net::{cli_peer::CliPeer, recv_all};
use crate::session::{
    ensure_unlocked_for, lock_session, save_vault_with_key_to, SharedState, UnlockStatus,
};
use crate::storage::paths::{PairingData, PairingStatus, PairingTxnPhase, Paths};
use crate::twofa::dispatch::request_approval;
use crate::twofa::render;

const PAIRING_ACCEPT_TIMEOUT: Duration = Duration::from_secs(120);
const PAIRING_STEP_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, PartialEq, Eq)]
enum PairingGate {
    NewPairing,
    ReplaceRequiresApproval,
    InvalidExistingPairing,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PairingSecrets {
    #[zeroize(skip)]
    pub pairing_id: uuid::Uuid,
    #[zeroize(skip)]
    pub phone_node_id: iroh::PublicKey,
    #[zeroize(skip)]
    pub approval_public_key_der: Vec<u8>,
    pub phone_share: [u8; 32],
}

pub struct PairingExchange {
    pub secrets: PairingSecrets,
    pub transport: PairingTransport,
}

pub struct PairingTransport {
    endpoint: Arc<iroh::Endpoint>,
    conn: iroh::endpoint::Connection,
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
}

pub struct PairingCommitTransport {
    endpoint: Arc<iroh::Endpoint>,
    conn: iroh::endpoint::Connection,
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
}

fn pairing_gate(status: &PairingStatus, has_pairing_files: bool) -> PairingGate {
    match status {
        PairingStatus::Ready => PairingGate::ReplaceRequiresApproval,
        PairingStatus::MissingPhoneId if !has_pairing_files => PairingGate::NewPairing,
        _ => PairingGate::InvalidExistingPairing,
    }
}

pub(crate) fn has_pairing_files(paths: &Paths) -> bool {
    paths.pairing_state().exists()
        || paths.pending_pairing_state().exists()
        || paths.pairing_transaction_state().exists()
        || paths.phone_id.exists()
        || paths.hmac_key.exists()
}

pub async fn cmd_pair(state: SharedState) -> Result<()> {
    info!("[ferusa:cli]: cmd_pair start");

    let paths = Paths::load()?;
    paths.ensure_data_dir().map_err(|e| {
        ui::failed("could not create data directory");
        e
    })?;
    debug!("[ferusa:cli]: cmd_pair data dir ensured");

    let unlock_status = ensure_unlocked_for(&state, &paths, VaultAction::Pair, None)
        .await
        .map_err(|e| {
            ui::failed("could not unlock vault");
            e
        })?;

    let pairing_status = paths.pairing_status();
    let has_pairing_files = has_pairing_files(&paths);
    match pairing_gate(&pairing_status, has_pairing_files) {
        PairingGate::ReplaceRequiresApproval => {
            if matches!(unlock_status, UnlockStatus::AlreadyUnlocked) {
                ui::info("already paired with a phone");
                ui::info("replacing pairing requires 2FA approval from the current phone");
                ui::execute("requesting 2FA approval for REPLACE_PAIRING");
                request_approval(&state, VaultAction::Pair, None)
                    .await
                    .map_err(|e| {
                        ui::failed("2FA approval failed or was denied");
                        e
                    })?;
                ui::success("2FA approved");
            }
        }
        PairingGate::NewPairing => {
            debug!("[ferusa:cli]: cmd_pair no existing pairing data");
        }
        PairingGate::InvalidExistingPairing => {
            ui::failed("pairing data exists but is incomplete or invalid");
            ui::info("refusing to overwrite pairing data without 2FA approval");
            anyhow::bail!("refusing to overwrite pairing data: {pairing_status}");
        }
    }

    let endpoint = {
        let guard = state.lock().await;
        guard
            .as_ref()
            .context("session not unlocked")?
            .endpoint
            .as_ref()
            .context("real 2FA endpoint unavailable")?
            .clone()
    };

    let exchange = begin_pair_with_phone(&paths, endpoint.clone()).await?;
    let mut secrets = exchange.secrets;

    let (vault_snapshot, local_secret, vault_salt) = {
        let guard = state.lock().await;
        let s = guard.as_ref().context("session not unlocked")?;
        (s.vault.clone(), s.local_secret, s.vault_salt)
    };
    let new_vault_key =
        combine_vault_key(&local_secret, &secrets.phone_share).context("combine vault key")?;

    let pairing_data = PairingData {
        pairing_id: secrets.pairing_id,
        phone_node_id: secrets.phone_node_id,
        approval_public_key_der: std::mem::take(&mut secrets.approval_public_key_der),
        created_at_ms: now_ms(),
    };

    let persist_result = async {
        save_vault_with_key_to(
            paths.pending_vault_enc(),
            vault_snapshot,
            new_vault_key,
            vault_salt,
        )
        .await
        .context("save pending vault with new phone share")?;
        paths
            .write_pending_pairing_data(&pairing_data)
            .map_err(|e| {
                ui::failed("could not write pending pairing data");
                e
            })?;
        debug!("[ferusa:cli]: cmd_pair pending_pairing.json written to disk");
        let commit_transport = confirm_pairing_ready(exchange.transport, &pairing_data).await?;
        commit_and_activate_pairing(&paths, commit_transport, pairing_data.pairing_id).await?;
        Ok::<(), anyhow::Error>(())
    }
    .await;

    if let Err(e) = persist_result {
        if paths.pairing_transaction_state().exists() {
            lock_session(&state).await;
            return Err(e).context("pairing transaction retained for automatic recovery");
        }
        paths
            .clear_pending_pairing()
            .context("clear aborted pending pairing")?;
        return Err(e);
    }

    let stale_conn = {
        let mut guard = state.lock().await;
        let s = guard.as_mut().context("session not unlocked")?;
        s.vault_key.zeroize();
        s.phone_share.zeroize();
        s.vault_key = new_vault_key;
        s.phone_share = std::mem::take(&mut secrets.phone_share);
        s.pairing = Some(pairing_data);
        s.phone_conn.take()
    };
    if let Some(conn) = stale_conn {
        conn.close().await;
        debug!("[ferusa:cli]: cmd_pair stale phone connection closed");
    }

    ui::success("pairing data committed");
    ui::success("paired successfully");
    ui::info(&format!("saved to {:?}", paths.data_dir));

    info!(
        "[ferusa:cli]: cmd_pair done phone_node_id={}",
        secrets.phone_node_id
    );
    Ok(())
}

pub async fn begin_pair_with_phone(
    paths: &Paths,
    endpoint: Arc<iroh::Endpoint>,
) -> Result<PairingExchange> {
    let node_addr = endpoint.addr();
    let node_id_hex = hex::encode(node_addr.id.as_bytes());
    info!("[ferusa:cli]: cmd_pair node_id={}", node_id_hex);
    ui::success("p2p identity ready");

    // — print QR and node ID for the user to scan —
    println!();
    ui::info("scan this QR code with the ferusa android app,");
    ui::info("or you can also enter the node ID manually:");
    println!();
    qr2term::print_qr(&node_id_hex).context("render QR code")?;
    println!();
    ui::info(&format!("node ID  {}", node_id_hex));

    // — wait for phone to connect —
    ui::info("waiting for phone to connect (timeout 120s)");
    let incoming = tokio::time::timeout(PAIRING_ACCEPT_TIMEOUT, endpoint.accept())
        .await
        .map_err(|_| {
            ui::failed("timed out after 120s — no phone connected");
            anyhow::anyhow!("timed out waiting for phone (120s)")
        })?
        .context("endpoint closed")?;
    debug!("[ferusa:cli]: cmd_pair incoming connection detected");

    // — complete the connection handshake —
    ui::execute("completing connection handshake");
    let accepting = incoming.accept().context("accept incoming")?;
    let conn = tokio::time::timeout(PAIRING_STEP_TIMEOUT, accepting)
        .await
        .context("timed out completing phone handshake")?
        .map_err(|e| {
            ui::failed("handshake failed");
            e
        })?;

    let phone_node_id = conn.remote_id();
    let phone_id_hex = hex::encode(phone_node_id.as_bytes());
    info!(
        "[ferusa:cli]: cmd_pair phone connected phone_node_id={}",
        phone_id_hex
    );
    ui::success("phone connected");
    ui::info(&format!("phone node ID  {}", phone_id_hex));

    // — open communication channel —
    ui::execute("opening secure channel");
    let (send, mut recv) = tokio::time::timeout(PAIRING_STEP_TIMEOUT, conn.accept_bi())
        .await
        .context("timed out waiting for phone pairing stream")?
        .map_err(|e| {
            ui::failed("could not open secure channel");
            anyhow::Error::from(e)
        })?;
    debug!("[ferusa:cli]: cmd_pair bidi stream opened");

    ui::execute("receiving pairing hello from phone");
    let mut hello = match tokio::time::timeout(PAIRING_STEP_TIMEOUT, read_ferusa_message(&mut recv))
        .await
        .context("timed out waiting for PairingHello")?
        .context("read PairingHello")?
    {
        FerusaMessage::PairingHello(hello) => hello,
        _ => anyhow::bail!("phone sent non-pairing hello"),
    };
    debug!("[ferusa:cli]: cmd_pair pairing hello received");

    require_pairing_code_confirmation(hello.verification_code)?;

    let path_report = iroh_path_report("pair", &conn);
    ui::info(&path_report.human_summary());

    ui::info(&format!("phone node ID  {}", phone_id_hex));
    ui::info(&format!("saved to {:?}", paths.data_dir));

    Ok(PairingExchange {
        secrets: PairingSecrets {
            pairing_id: hello.pairing_id,
            phone_node_id,
            approval_public_key_der: std::mem::take(&mut hello.approval_public_key_der),
            phone_share: std::mem::take(&mut hello.phone_share),
        },
        transport: PairingTransport {
            endpoint,
            conn,
            send,
            recv,
        },
    })
}

fn format_pairing_verification_code(code: u16) -> String {
    format!("{:04}", code)
}

fn require_pairing_code_confirmation(code: u16) -> Result<()> {
    let code = format_pairing_verification_code(code);
    ui::info("verify this pairing code matches the ferusa android app");
    render::render_code_str(&code);
    print!("\x1b[1minput:\x1b[0m codes match? [y/N]: ");
    io::stdout()
        .flush()
        .context("flush pairing confirmation prompt")?;

    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .context("read pairing confirmation")?;
    if pairing_confirmation_accepted(&answer) {
        Ok(())
    } else {
        ui::failed("pairing verification cancelled");
        anyhow::bail!("pairing verification cancelled")
    }
}

fn pairing_confirmation_accepted(answer: &str) -> bool {
    answer.trim().eq_ignore_ascii_case("y")
}

pub async fn confirm_pairing_ready(
    transport: PairingTransport,
    pairing: &PairingData,
) -> Result<PairingCommitTransport> {
    let PairingTransport {
        endpoint,
        conn,
        mut send,
        mut recv,
    } = transport;

    ui::execute("confirming pairing data was prepared");
    let prepared = FerusaMessage::PairingPrepared(PairingPrepared {
        pairing_id: pairing.pairing_id,
    })
    .encode()
    .context("encode PairingPrepared")?;
    tokio::time::timeout(PAIRING_STEP_TIMEOUT, send.write_all(&prepared))
        .await
        .context("timed out sending pairing prepared acknowledgement")?
        .map_err(|e| {
            ui::failed("failed to send pairing prepared acknowledgement");
            anyhow::Error::from(e)
        })?;
    debug!("[ferusa:cli]: cmd_pair prepared ack sent");

    ui::execute("waiting for phone activation confirmation");
    let ready_msg = tokio::time::timeout(PAIRING_STEP_TIMEOUT, read_ferusa_message(&mut recv))
        .await
        .context("timed out waiting for phone activation")?
        .context("read phone activation")?;
    let ready_signature = match ready_msg {
        FerusaMessage::PairingReady(PairingReady {
            pairing_id,
            signature,
        }) => {
            if pairing_id != pairing.pairing_id {
                anyhow::bail!("pairing ready id mismatch");
            }
            signature
        }
        _ => anyhow::bail!("phone sent non-ready message"),
    };
    if !verify_pairing_ready_signature(
        &pairing.approval_public_key_der,
        pairing.pairing_id,
        &ready_signature,
    ) {
        anyhow::bail!("phone ready signature verification failed");
    }

    ui::success("phone activated pairing");
    debug!("[ferusa:cli]: cmd_pair phone activation verified");

    Ok(PairingCommitTransport {
        endpoint,
        conn,
        send,
        recv,
    })
}

pub async fn commit_and_activate_pairing(
    paths: &Paths,
    mut transport: PairingCommitTransport,
    pairing_id: uuid::Uuid,
) -> Result<()> {
    paths
        .write_pairing_transaction_prepared(pairing_id)
        .context("write prepared pairing transaction")?;
    send_pairing_transition(
        &mut transport.send,
        &mut transport.recv,
        FerusaMessage::PairingCommit(PairingCommit { pairing_id }),
        |message| matches!(message, FerusaMessage::PairingCommitAck(PairingCommitAck { pairing_id: got }) if got == pairing_id),
        "pairing commit",
    )
    .await?;
    paths
        .write_pairing_transaction_phone_committed(pairing_id)
        .context("mark phone committed pairing")?;
    paths
        .recover_pairing_transaction()
        .context("activate phone-committed local pairing")?;
    send_pairing_transition(
        &mut transport.send,
        &mut transport.recv,
        FerusaMessage::PairingActivate(PairingActivate { pairing_id }),
        |message| matches!(message, FerusaMessage::PairingActivateAck(PairingActivateAck { pairing_id: got }) if got == pairing_id),
        "pairing activation",
    )
    .await?;

    transport.send.finish().context("finish pairing send")?;
    let close_reason = tokio::time::timeout(PAIRING_STEP_TIMEOUT, transport.conn.closed())
        .await
        .context("timed out waiting for phone pairing completion")?;
    if !is_pairing_complete_close(&close_reason) {
        anyhow::bail!("unexpected phone pairing completion: {close_reason}");
    }

    paths
        .write_pairing_transaction_fully_activated(pairing_id)
        .context("mark fully activated pairing")?;
    paths
        .recover_pairing_transaction()
        .context("clean fully activated pairing transaction")?;

    drop(transport.conn);
    drop(transport.endpoint);

    Ok(())
}

fn is_pairing_complete_close(close_reason: &ConnectionError) -> bool {
    matches!(
        close_reason,
        ConnectionError::ApplicationClosed(close)
            if close.error_code == PAIRING_COMPLETE_CLOSE_CODE.into()
                && close.reason.as_ref() == PAIRING_COMPLETE_CLOSE_REASON
    )
}

async fn send_pairing_transition(
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
    request: FerusaMessage,
    expected: impl FnOnce(FerusaMessage) -> bool,
    step: &str,
) -> Result<()> {
    let bytes = request.encode().with_context(|| format!("encode {step}"))?;
    tokio::time::timeout(PAIRING_STEP_TIMEOUT, send.write_all(&bytes))
        .await
        .with_context(|| format!("timed out sending {step}"))?
        .with_context(|| format!("send {step}"))?;
    let response = tokio::time::timeout(PAIRING_STEP_TIMEOUT, read_ferusa_message(recv))
        .await
        .with_context(|| format!("timed out waiting for {step} acknowledgement"))??;
    if !expected(response) {
        anyhow::bail!("unexpected {step} acknowledgement");
    }
    Ok(())
}

pub async fn reconcile_pairing_transaction(paths: &Paths) -> Result<()> {
    paths
        .recover_pairing_transaction()
        .context("recover local pairing transaction")?;
    while paths.pairing_transaction_state().exists() {
        let txn = paths.read_pairing_transaction()?;
        match txn.phase {
            PairingTxnPhase::Prepared => {
                send_recovery_transition(
                    paths,
                    FerusaMessage::PairingCommit(PairingCommit {
                        pairing_id: txn.pairing_id,
                    }),
                    |message| matches!(message, FerusaMessage::PairingCommitAck(PairingCommitAck { pairing_id }) if pairing_id == txn.pairing_id),
                )
                .await
                .context("resume phone commit")?;
                paths.write_pairing_transaction_phone_committed(txn.pairing_id)?;
            }
            PairingTxnPhase::PhoneCommitted => {}
            PairingTxnPhase::LocallyActivated => {
                send_recovery_transition(
                    paths,
                    FerusaMessage::PairingActivate(PairingActivate {
                        pairing_id: txn.pairing_id,
                    }),
                    |message| matches!(message, FerusaMessage::PairingActivateAck(PairingActivateAck { pairing_id }) if pairing_id == txn.pairing_id),
                )
                .await
                .context("resume phone activation")?;
                paths.write_pairing_transaction_fully_activated(txn.pairing_id)?;
            }
            PairingTxnPhase::FullyActivated => {}
        }
        paths.recover_pairing_transaction()?;
    }
    Ok(())
}

async fn send_recovery_transition(
    paths: &Paths,
    request: FerusaMessage,
    expected: impl FnOnce(FerusaMessage) -> bool,
) -> Result<()> {
    let pairing = if paths.pending_pairing_state().exists() {
        paths.read_pending_pairing_data()?
    } else {
        paths.read_pairing_data()?
    };
    let peer = CliPeer::init(&paths.peer_id).await?;
    let endpoint = peer.into_endpoint();
    let conn = tokio::time::timeout(
        PAIRING_STEP_TIMEOUT,
        endpoint.connect(EndpointAddr::new(pairing.phone_node_id), FERUSA_ALPN),
    )
    .await
    .context("timed out connecting to phone for pairing recovery")?
    .context("connect to phone for pairing recovery")?;
    let (mut send, mut recv) = conn.open_bi().await.context("open recovery stream")?;
    send.write_all(&request.encode().context("encode recovery request")?)
        .await
        .context("send recovery request")?;
    send.finish().context("finish recovery request")?;
    let bytes = tokio::time::timeout(PAIRING_STEP_TIMEOUT, recv_all(&mut recv))
        .await
        .context("timed out waiting for recovery acknowledgement")??;
    let response = FerusaMessage::decode(&bytes).context("decode recovery acknowledgement")?;
    if !expected(response) {
        anyhow::bail!("unexpected pairing recovery acknowledgement");
    }
    conn.close(0u32.into(), b"pairing recovery complete");
    endpoint.close().await;
    Ok(())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

async fn read_ferusa_message(recv: &mut iroh::endpoint::RecvStream) -> Result<FerusaMessage> {
    let mut header = [0u8; 4];
    recv.read_exact(&mut header)
        .await
        .context("read message header")?;
    let len = u32::from_le_bytes(header) as usize;
    if len > 1024 * 1024 {
        anyhow::bail!("pairing message too large: {len}");
    }
    let mut bytes = Zeroizing::new(vec![0u8; 4 + len]);
    bytes[..4].copy_from_slice(&header);
    recv.read_exact(&mut bytes[4..])
        .await
        .context("read message payload")?;
    FerusaMessage::decode(&bytes).context("decode pairing message")
}

#[cfg(test)]
mod tests {
    use super::{
        format_pairing_verification_code, has_pairing_files, is_pairing_complete_close,
        pairing_confirmation_accepted, pairing_gate, PairingGate,
    };
    use crate::storage::paths::PairingStatus;
    use ferusa_core::transport::{PAIRING_COMPLETE_CLOSE_CODE, PAIRING_COMPLETE_CLOSE_REASON};
    use iroh::endpoint::{ApplicationClose, ConnectionError};

    #[test]
    fn ready_pairing_requires_approval_before_replacement() {
        assert_eq!(
            pairing_gate(&PairingStatus::Ready, true),
            PairingGate::ReplaceRequiresApproval
        );
    }

    #[test]
    fn no_pairing_files_can_start_new_pairing_without_approval() {
        assert_eq!(
            pairing_gate(&PairingStatus::MissingPhoneId, false),
            PairingGate::NewPairing
        );
    }

    #[test]
    fn incomplete_or_invalid_pairing_files_are_not_silently_replaced() {
        assert_eq!(
            pairing_gate(&PairingStatus::MissingPhoneId, true),
            PairingGate::InvalidExistingPairing
        );
        assert_eq!(
            pairing_gate(&PairingStatus::InvalidPhoneId("bad".into()), true),
            PairingGate::InvalidExistingPairing
        );
        assert_eq!(
            pairing_gate(&PairingStatus::InvalidPairing("bad".into()), true),
            PairingGate::InvalidExistingPairing
        );
    }

    #[test]
    fn legacy_partial_pairing_files_are_detected() {
        let temp = tempfile::tempdir().expect("temp dir");
        let paths = crate::storage::paths::Paths {
            data_dir: temp.path().to_path_buf(),
            vault_enc: temp.path().join("vault.enc"),
            vault_salt: temp.path().join("vault.salt"),
            peer_id: temp.path().join("peer.id"),
            phone_id: temp.path().join("phone.id"),
            hmac_key: temp.path().join("hmac.key"),
            clipboard_cmd: temp.path().join("clipboard.cmd"),
        };

        std::fs::write(&paths.hmac_key, [0x11; 32]).expect("write hmac");

        assert!(has_pairing_files(&paths));
        assert_eq!(
            pairing_gate(&paths.pairing_status(), has_pairing_files(&paths)),
            PairingGate::InvalidExistingPairing
        );
    }

    #[test]
    fn pairing_verification_code_is_zero_padded() {
        assert_eq!(format_pairing_verification_code(7), "0007");
        assert_eq!(format_pairing_verification_code(1234), "1234");
    }

    #[test]
    fn pairing_verification_requires_explicit_yes() {
        assert!(pairing_confirmation_accepted("y\n"));
        assert!(pairing_confirmation_accepted("Y"));
        assert!(!pairing_confirmation_accepted(""));
        assert!(!pairing_confirmation_accepted("yes"));
        assert!(!pairing_confirmation_accepted("n"));
    }

    #[test]
    fn pairing_completion_requires_expected_phone_close() {
        let expected = ConnectionError::ApplicationClosed(ApplicationClose {
            error_code: PAIRING_COMPLETE_CLOSE_CODE.into(),
            reason: PAIRING_COMPLETE_CLOSE_REASON.into(),
        });
        let wrong_reason = ConnectionError::ApplicationClosed(ApplicationClose {
            error_code: PAIRING_COMPLETE_CLOSE_CODE.into(),
            reason: b"wrong".as_slice().into(),
        });

        assert!(is_pairing_complete_close(&expected));
        assert!(!is_pairing_complete_close(&wrong_reason));
        assert!(!is_pairing_complete_close(&ConnectionError::LocallyClosed));
    }
}
