//! Single import point for all commands that need 2FA approval.

use anyhow::Result;
use ferusa_core::types::VaultAction;
use log::{debug, info, warn};

use crate::interface::ui;
use crate::session::SharedState;
use crate::storage::paths::{PairingStatus, Paths};

pub async fn request_approval(
    state: &SharedState,
    action: VaultAction,
    entry_title: Option<&str>,
) -> Result<()> {
    debug!(
        "[ferusa:cli]: twofa::dispatch::request_approval action={:?} entry={:?}",
        action, entry_title
    );

    let paths = Paths::load()?;

    match paths.pairing_status() {
        PairingStatus::Ready => {
            info!("[ferusa:cli]: twofa::dispatch: paired — using real iroh 2FA");
            crate::twofa::request_approval(state, &paths, action, entry_title).await
        }
        status => {
            #[cfg(feature = "dev-2fa-stub")]
            {
                warn!(
                    "[ferusa:cli]: twofa::dispatch: {status} — DEV 2FA stub feature active; auto-approving"
                );
                ui::warn("DEV 2FA STUB ENABLED — protected action will be auto-approved");
                ui::warn(&format!("{status}. Run `ferusa pair` to enable real 2FA"));
                return crate::twofa::stub::request_approval(action, entry_title).await;
            }

            #[cfg(not(feature = "dev-2fa-stub"))]
            {
                warn!("[ferusa:cli]: twofa::dispatch: {status} — refusing protected action");
                ui::failed(&format!("2FA unavailable — {status}"));
                ui::info("run `ferusa pair` to enable 2FA");
                anyhow::bail!("2FA required but unavailable: {status}");
            }
        }
    }
}
