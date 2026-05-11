//! Development-only 2FA stub: prints local correlation code and auto-approves.

use anyhow::Result;
use ferusa_core::crypto::random_correlation_code;
use ferusa_core::types::VaultAction;
use log::{debug, info};

use crate::interface::ui;
use crate::twofa::{action_label, render};

pub const ALLOW_DEV_2FA_STUB_ENV: &str = "FERUSA_ALLOW_DEV_2FA_STUB";

pub fn ensure_allowed() -> Result<()> {
    if std::env::var(ALLOW_DEV_2FA_STUB_ENV).as_deref() == Ok("1") {
        return Ok(());
    }

    ui::failed("dev 2FA stub is disabled");
    anyhow::bail!("dev 2FA stub requires {ALLOW_DEV_2FA_STUB_ENV}=1");
}

pub fn dev_phone_share() -> Result<[u8; 32]> {
    ensure_allowed()?;
    Ok([0xD3; 32])
}

/// Print correlation code to terminal, then auto-approve.
pub async fn request_approval(action: VaultAction, entry_title: Option<&str>) -> Result<()> {
    ensure_allowed()?;

    info!(
        "[ferusa:cli]: twofa::stub::request_approval action={:?} entry={:?}",
        action, entry_title
    );

    let code = random_correlation_code();
    debug!(
        "[ferusa:cli]: twofa::stub::request_approval correlation_code={}",
        code
    );

    let label = action_label(action);

    match entry_title {
        Some(title) => ui::info(&format!("approve 2FA request for {label} \"{title}\"")),
        None => ui::info(&format!("approve 2FA request for {label}")),
    }
    ui::info(&format!("2FA code {code}"));
    render::render_code(code.into());
    ui::warn("auto-approved by dev 2FA stub — non-production only");

    info!("[ferusa:cli]: twofa::stub::request_approval auto-approved");
    Ok(())
}
