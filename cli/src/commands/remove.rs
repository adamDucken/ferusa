use std::io::{self, Write};

use anyhow::{bail, Context, Result};
use log::{debug, info, warn};

use ferusa_core::types::VaultAction;

use crate::interface::ui;
use crate::session::{ensure_unlocked_for, save_vault_candidate, SharedState, UnlockStatus};
use crate::storage::paths::Paths;
use crate::twofa::dispatch::request_approval;

pub async fn cmd_remove(state: SharedState, title: &str) -> Result<()> {
    info!("[ferusa:cli]: cmd_remove start title={:?}", title);

    let paths = Paths::load()?;
    debug!("[ferusa:cli]: cmd_remove paths loaded");

    let unlock_status = ensure_unlocked_for(&state, &paths, VaultAction::Delete, Some(title))
        .await
        .map_err(|e| {
            ui::failed("could not unlock vault");
            e
        })?;
    debug!("[ferusa:cli]: cmd_remove vault unlocked");

    // — confirm entry exists —
    ui::execute(&format!("looking up entry \"{}\"", title));
    {
        let guard = state.lock().await;
        let s = guard.as_ref().context("session not unlocked")?;
        if !s
            .vault
            .entries
            .iter()
            .any(|e| e.title.eq_ignore_ascii_case(title))
        {
            ui::failed(&format!("no entry found with title \"{}\"", title));
            warn!("[ferusa:cli]: cmd_remove entry not found: {:?}", title);
            bail!("no entry found with title \"{}\"", title);
        }
    }
    ui::success("entry found");
    debug!("[ferusa:cli]: cmd_remove entry existence confirmed");

    // — confirm with user —
    println!();
    ui::input(&format!("confirm removal of entry \"{}\"", title));
    print!("remove entry \"{}\"? [y/N]: ", title);
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    let answer = buf.trim().to_lowercase();
    debug!("[ferusa:cli]: cmd_remove user answered {:?}", answer);

    if !matches!(answer.as_str(), "y" | "yes") {
        info!("[ferusa:cli]: cmd_remove aborted by user");
        println!();
        ui::info("removal aborted");
        return Ok(());
    }

    // — 2FA approval —
    if matches!(unlock_status, UnlockStatus::AlreadyUnlocked) {
        ui::execute(&format!("requesting 2FA approval for DELETE \"{}\"", title));
        request_approval(&state, VaultAction::Delete, Some(title))
            .await
            .map_err(|e| {
                ui::failed("2FA approval failed or was denied");
                e
            })?;
        ui::success("2FA approved");
        info!("[ferusa:cli]: cmd_remove 2FA approved");
    }

    // — build candidate vault —
    ui::execute("removing entry from vault");
    let candidate = {
        let guard = state.lock().await;
        let s = guard.as_ref().context("session not unlocked")?;
        let mut vault = s.vault.clone();
        let before = vault.entries.len();
        vault
            .entries
            .retain(|e| !e.title.eq_ignore_ascii_case(title));
        let after = vault.entries.len();
        if after == before {
            ui::failed("entry vanished before removal");
            warn!("[ferusa:cli]: cmd_remove entry vanished before removal");
            bail!("entry vanished before removal");
        }
        debug!(
            "[ferusa:cli]: cmd_remove entry removed from candidate; vault size {} → {}",
            before, after
        );
        vault
    };

    ui::execute("saving vault to disk");
    save_vault_candidate(&state, &paths, candidate)
        .await
        .map_err(|e| {
            ui::failed("failed to save vault");
            e
        })?;

    println!();
    ui::success(&format!("entry \"{}\" removed", title));
    info!(
        "[ferusa:cli]: cmd_remove vault saved — entry {:?} removed",
        title
    );
    Ok(())
}
