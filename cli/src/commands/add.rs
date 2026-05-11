use std::io::{self, Write};

use anyhow::{bail, Context, Result};
use log::{debug, info, warn};
use uuid::Uuid;

use ferusa_core::types::{Entry, SecretString, VaultAction};

use crate::interface::password_gen;
use crate::interface::ui;
use crate::session::{ensure_unlocked_for, save_vault_candidate, SharedState, UnlockStatus};
use crate::storage::paths::Paths;
use crate::twofa::dispatch::request_approval;

/// Optional field — prints `input: <label> [None] : ` on one line and reads input.
/// Returns None if the user submits an empty string.
fn prompt_optional(label: &str) -> Result<Option<String>> {
    print!("\x1b[1minput:\x1b[0m {} [None] : ", label);
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    let val = buf.trim().to_owned();
    Ok(if val.is_empty() { None } else { Some(val) })
}

pub async fn cmd_add(state: SharedState, title: &str) -> Result<()> {
    info!("[ferusa:cli]: cmd_add start title={:?}", title);

    let paths = Paths::load()?;
    debug!("[ferusa:cli]: cmd_add paths loaded");

    let unlock_status = ensure_unlocked_for(&state, &paths, VaultAction::Create, Some(title))
        .await
        .map_err(|e| {
            ui::failed("could not unlock vault");
            e
        })?;
    debug!("[ferusa:cli]: cmd_add vault unlocked");

    let title = title.trim();
    if title.is_empty() {
        ui::failed("title cannot be empty");
        warn!("[ferusa:cli]: cmd_add rejected — empty title");
        bail!("title is required");
    }
    let title = title.to_owned();
    debug!("[ferusa:cli]: cmd_add title={:?}", title);

    // — duplicate check —
    ui::execute("checking for duplicate title");
    {
        let guard = state.lock().await;
        let s = guard.as_ref().context("session not unlocked")?;
        if s.vault
            .entries
            .iter()
            .any(|e| e.title.eq_ignore_ascii_case(&title))
        {
            ui::failed(&format!("entry \"{}\" already exists", title));
            warn!("[ferusa:cli]: cmd_add duplicate title {:?}", title);
            bail!(
                "entry \"{}\" already exists — use `ferusa edit` to update it",
                title
            );
        }
    }
    ui::success("title is unique");
    debug!("[ferusa:cli]: cmd_add duplicate check passed");

    // — 2FA approval —
    if matches!(unlock_status, UnlockStatus::AlreadyUnlocked) {
        ui::info("2FA approval is required before any vault mutation");
        ui::execute(&format!("requesting 2FA approval for CREATE \"{}\"", title));
        request_approval(&state, VaultAction::Create, Some(&title))
            .await
            .map_err(|e| {
                ui::failed("2FA approval failed or was denied");
                e
            })?;
        ui::success("2FA approved");
        info!("[ferusa:cli]: cmd_add 2FA approved");
    }

    // — username —
    println!();
    ui::info("entry details — leave any optional field blank to skip it");
    let username = prompt_optional("provide username or email")?;
    debug!("[ferusa:cli]: cmd_add username={}", username.is_some());

    // — password —
    ui::info("you can let ferusa generate a strong password or type your own");
    let mut password = password_gen::prompt_password_field()?;
    debug!("[ferusa:cli]: cmd_add password collected");

    // — url —
    ui::info("the URL helps to identify where this credential is used");
    let url = prompt_optional("provide url")?;
    debug!("[ferusa:cli]: cmd_add url={}", url.is_some());

    // — notes —
    ui::info("notes are stored encrypted alongside the entry");
    let notes = prompt_optional("provide notes")?;
    debug!("[ferusa:cli]: cmd_add notes={}", notes.is_some());

    // — tags —
    ui::info("tags let you filter and group entries (e.g. \"work, social\")");
    let tags_raw = prompt_optional("provide tags (comma-separated)")?;
    let tags: Vec<String> = match tags_raw {
        None => vec![],
        Some(raw) => raw
            .split(',')
            .map(|t| t.trim().to_owned())
            .filter(|t| !t.is_empty())
            .collect(),
    };
    debug!("[ferusa:cli]: cmd_add tags={}", tags.len());

    // — build entry —
    ui::execute("building entry");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let entry = Entry {
        id: Uuid::new_v4(),
        title: title.clone(),
        username,
        password: SecretString::from(std::mem::take(&mut *password)),
        url,
        notes,
        tags,
        created_at: now,
        updated_at: now,
    };
    ui::success(&format!("entry built with id {}", entry.id));
    debug!("[ferusa:cli]: cmd_add entry built id={}", entry.id);

    // — build candidate vault —
    ui::execute("adding entry to vault");
    let candidate = {
        let guard = state.lock().await;
        let s = guard.as_ref().context("session not unlocked")?;
        let mut vault = s.vault.clone();
        vault.entries.push(entry);
        debug!(
            "[ferusa:cli]: cmd_add entry pushed to candidate; vault size={}",
            vault.entries.len()
        );
        vault
    };

    // — persist —
    ui::execute("saving vault to disk");
    save_vault_candidate(&state, &paths, candidate)
        .await
        .map_err(|e| {
            ui::failed("failed to save vault");
            e
        })?;
    ui::success("entry added to vault");
    ui::success("vault saved to disk");

    println!();
    ui::success(&format!("entry \"{}\" added", title));
    info!(
        "[ferusa:cli]: cmd_add vault saved — entry {:?} added",
        title
    );
    Ok(())
}
