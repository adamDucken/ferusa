use anyhow::{bail, Context, Result};
use log::{debug, info, warn};

use crate::clipboard;
use crate::interface::ui;
use crate::session::{ensure_unlocked_for, SharedState, UnlockStatus};
use crate::storage::paths::Paths;
use crate::twofa::dispatch::request_approval;
use ferusa_core::types::VaultAction;

pub async fn cmd_get(state: SharedState, title: &str) -> Result<()> {
    info!("[ferusa:cli]: cmd_get start title={:?}", title);

    let paths = Paths::load()?;
    debug!("[ferusa:cli]: cmd_get paths loaded");

    let unlock_status = ensure_unlocked_for(&state, &paths, VaultAction::Read, Some(title))
        .await
        .map_err(|e| {
            ui::failed("could not unlock vault");
            e
        })?;
    debug!("[ferusa:cli]: cmd_get vault unlocked");

    // — confirm entry exists before bothering with 2FA —
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
            warn!("[ferusa:cli]: cmd_get entry not found: {:?}", title);
            bail!("no entry found with title \"{}\"", title);
        }
    }
    ui::success("entry found");
    debug!("[ferusa:cli]: cmd_get entry existence confirmed");

    // — 2FA approval —
    if matches!(unlock_status, UnlockStatus::AlreadyUnlocked) {
        ui::execute(&format!("requesting 2FA approval for READ \"{}\"", title));
        request_approval(&state, VaultAction::Read, Some(title))
            .await
            .map_err(|e| {
                ui::failed("2FA approval failed or was denied");
                e
            })?;

        ui::success("2FA approved");
        info!("[ferusa:cli]: cmd_get 2FA approved");
    }

    // — print entry —
    ui::info("entry details");
    println!();

    let guard = state.lock().await;
    let s = guard.as_ref().context("session not unlocked")?;
    let entry = s
        .vault
        .entries
        .iter()
        .find(|e| e.title.eq_ignore_ascii_case(title))
        .context("entry vanished after approval")?;

    debug!(
        "[ferusa:cli]: cmd_get copying password for entry id={} to clipboard",
        entry.id
    );
    let clear_status = clipboard::copy_password(&entry.password)?;
    match clear_status {
        clipboard::ClipboardClearStatus::Scheduled(seconds) => ui::success(&format!(
            "password copied to clipboard; it will clear in {seconds} seconds if unchanged"
        )),
        clipboard::ClipboardClearStatus::Disabled => {
            ui::info("password copied; automatic clipboard clearing is disabled")
        }
        clipboard::ClipboardClearStatus::Unsupported(program) => ui::info(&format!(
            "password copied; {program} cannot be cleared safely, so overwrite it manually"
        )),
    }

    // Using {:<10} to keep the values neatly aligned after the colons
    println!("{:<10} {}", "title:", entry.title);
    if let Some(u) = &entry.username {
        println!("{:<10} {}", "username:", u);
    }
    if let Some(url) = &entry.url {
        println!("{:<10} {}", "url:", url);
    }
    if let Some(n) = &entry.notes {
        println!("{:<10} {}", "notes:", n);
    }
    if !entry.tags.is_empty() {
        println!("{:<10} {}", "tags:", entry.tags.join(", "));
    }

    println!();

    info!("[ferusa:cli]: cmd_get done");
    Ok(())
}
