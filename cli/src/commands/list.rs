use anyhow::{Context, Result};
use ferusa_core::types::VaultAction;
use log::{debug, info};

use crate::interface::ui;
use crate::session::{ensure_unlocked_for, SharedState, UnlockStatus};
use crate::storage::paths::Paths;
use crate::twofa::dispatch::request_approval;

pub async fn cmd_list(state: SharedState) -> Result<()> {
    info!("[ferusa:cli]: cmd_list start");

    let paths = Paths::load()?;
    debug!("[ferusa:cli]: cmd_list paths loaded");

    let unlock_status = ensure_unlocked_for(&state, &paths, VaultAction::List, None)
        .await
        .map_err(|e| {
            ui::failed("could not unlock vault");
            e
        })?;
    debug!("[ferusa:cli]: cmd_list vault unlocked");

    if matches!(unlock_status, UnlockStatus::AlreadyUnlocked) {
        ui::execute("requesting 2FA approval for LIST");
        request_approval(&state, VaultAction::List, None)
            .await
            .map_err(|e| {
                ui::failed("2FA approval failed or was denied");
                e
            })?;

        ui::success("2FA approved");
        info!("[ferusa:cli]: cmd_list 2FA approved");
    }

    let guard = state.lock().await;
    let s = guard.as_ref().context("session not unlocked")?;

    let count = s.vault.entries.len();
    debug!("[ferusa:cli]: cmd_list vault has {} entries", count);

    if s.vault.entries.is_empty() {
        info!("[ferusa:cli]: cmd_list vault is empty");
        ui::info("vault is empty — use `ferusa add` to add an entry");
        return Ok(());
    }

    println!();
    println!("{:<30}  {}", "title", "url");
    for e in &s.vault.entries {
        let url = e.url.as_deref().unwrap_or("—");
        println!("{:<30}  {}", e.title, url);
    }
    println!();
    ui::info(&format!(
        "{} entr{}.",
        count,
        if count == 1 { "y" } else { "ies" }
    ));

    info!("[ferusa:cli]: cmd_list done — listed {} entries", count);
    Ok(())
}
