use std::io::{self, Write};

use anyhow::{bail, Context, Result};
use log::{debug, info, warn};
use zeroize::{Zeroize, Zeroizing};

use ferusa_core::types::{SecretString, VaultAction};

use crate::interface::password_gen;
use crate::interface::ui;
use crate::session::{ensure_unlocked_for, save_vault_candidate, SharedState, UnlockStatus};
use crate::storage::paths::Paths;
use crate::twofa::dispatch::request_approval;

fn prompt_with_default(label: &str, default: &str) -> Result<String> {
    print!("\x1b[1minput:\x1b[0m {} [{}]: ", label, default);
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    let trimmed = buf.trim();
    Ok(if trimmed.is_empty() {
        default.to_owned()
    } else {
        trimmed.to_owned()
    })
}

fn prompt_optional_with_default(label: &str, default: Option<&str>) -> Result<Option<String>> {
    let shown = default.unwrap_or("");
    print!("\x1b[1minput:\x1b[0m {} [{}]: ", label, shown);
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    let trimmed = buf.trim();
    if trimmed.is_empty() {
        Ok(default.map(|s| s.to_owned()))
    } else if trimmed == "-" {
        Ok(None)
    } else {
        Ok(Some(trimmed.to_owned()))
    }
}

fn replace_option_zeroize(target: &mut Option<String>, value: Option<String>) {
    if let Some(old) = target {
        old.zeroize();
    }
    *target = value;
}

pub async fn cmd_edit(state: SharedState, title: &str) -> Result<()> {
    info!("[ferusa:cli]: cmd_edit start title={:?}", title);

    let paths = Paths::load()?;
    debug!("[ferusa:cli]: cmd_edit paths loaded");

    let unlock_status = ensure_unlocked_for(&state, &paths, VaultAction::Update, Some(title))
        .await
        .map_err(|e| {
            ui::failed("could not unlock vault");
            e
        })?;
    debug!("[ferusa:cli]: cmd_edit vault unlocked");

    // — confirm entry exists —
    ui::info("check target entry");
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
            warn!("[ferusa:cli]: cmd_edit entry not found: {:?}", title);
            bail!("no entry found with title \"{}\"", title);
        }
    }
    ui::success("entry found");
    debug!("[ferusa:cli]: cmd_edit entry existence confirmed");

    // — 2FA approval —
    if matches!(unlock_status, UnlockStatus::AlreadyUnlocked) {
        ui::info("2FA required for update");
        ui::execute(&format!("requesting 2FA approval for UPDATE \"{}\"", title));
        request_approval(&state, VaultAction::Update, Some(title))
            .await
            .map_err(|e| {
                ui::failed("2FA approval failed or was denied");
                e
            })?;
        ui::success("2FA approved");
        info!("[ferusa:cli]: cmd_edit 2FA approved");
    }

    // — collect updated fields —
    println!();
    ui::info("edit fields");
    ui::input("leave blank to keep, - to clear optional fields");
    let (new_title, new_username, new_password, new_url, new_notes, new_tags) = {
        let guard = state.lock().await;
        let s = guard.as_ref().context("session not unlocked")?;
        let e = s
            .vault
            .entries
            .iter()
            .find(|e| e.title.eq_ignore_ascii_case(title))
            .context("entry vanished after approval")?;

        debug!("[ferusa:cli]: cmd_edit prompting for new field values");
        let nt = prompt_with_default("title", &e.title)?;
        let nu = prompt_optional_with_default("username (- to clear)", e.username.as_deref())?;

        // — password: keep / generate / type —
        ui::info("password action");
        ui::input("[enter] keep  [g] generate  [t] type new");
        print!("\x1b[1minput:\x1b[0m choice: ");
        io::stdout().flush()?;
        let mut pw_choice = String::new();
        io::stdin().read_line(&mut pw_choice)?;

        let np: Option<Zeroizing<String>> = match pw_choice.trim().to_lowercase().as_str() {
            "g" => {
                debug!("[ferusa:cli]: cmd_edit launching password generator");
                Some(password_gen::prompt_password_field()?)
            }
            "t" => {
                debug!("[ferusa:cli]: cmd_edit user will type password");
                ui::input("type new password");
                let typed = Zeroizing::new(
                    rpassword::prompt_password("new password: ").context("read password")?,
                );
                if typed.as_str() == "-" {
                    warn!("[ferusa:cli]: cmd_edit attempted to clear password — rejected");
                    bail!("password cannot be cleared");
                }
                if typed.is_empty() {
                    debug!("[ferusa:cli]: cmd_edit password unchanged (empty typed)");
                    None
                } else {
                    Some(typed)
                }
            }
            _ => {
                debug!("[ferusa:cli]: cmd_edit password unchanged");
                None
            }
        };

        let nurl = prompt_optional_with_default("url (- to clear)", e.url.as_deref())?;
        let nnotes = prompt_optional_with_default("notes (- to clear)", e.notes.as_deref())?;
        let tags_default = e.tags.join(", ");
        let tags_raw = prompt_with_default("tags (comma-separated, - to clear)", &tags_default)?;
        let ntags: Vec<String> = if tags_raw == "-" || tags_raw.is_empty() {
            vec![]
        } else {
            tags_raw.split(',').map(|t| t.trim().to_owned()).collect()
        };

        debug!(
            "[ferusa:cli]: cmd_edit new_title={:?} username={} url={} tags={}",
            nt,
            nu.is_some(),
            nurl.is_some(),
            ntags.len()
        );

        (nt, nu, np, nurl, nnotes, ntags)
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    // — reject duplicate title on rename —
    ui::info("validate new title");
    ui::execute("checking for duplicate title");
    {
        let guard = state.lock().await;
        let s = guard.as_ref().context("session not unlocked")?;
        if s.vault.entries.iter().any(|e| {
            !e.title.eq_ignore_ascii_case(title) && e.title.eq_ignore_ascii_case(&new_title)
        }) {
            ui::failed(&format!("entry \"{}\" already exists", new_title));
            warn!(
                "[ferusa:cli]: cmd_edit duplicate rename rejected old={:?} new={:?}",
                title, new_title
            );
            bail!(
                "entry \"{}\" already exists — choose a different title",
                new_title
            );
        }
    }
    ui::success("title is unique");

    // — build candidate vault —
    ui::info("write changes");
    ui::execute("applying changes to vault");
    let candidate = {
        let guard = state.lock().await;
        let s = guard.as_ref().context("session not unlocked")?;
        let mut vault = s.vault.clone();
        let entry = vault
            .entries
            .iter_mut()
            .find(|e| e.title.eq_ignore_ascii_case(title))
            .context("entry vanished")?;

        entry.title.zeroize();
        entry.title = new_title.clone();
        replace_option_zeroize(&mut entry.username, new_username);
        if let Some(mut new_password) = new_password {
            entry.password.zeroize();
            entry.password = SecretString::from(std::mem::take(&mut *new_password));
        }
        replace_option_zeroize(&mut entry.url, new_url);
        replace_option_zeroize(&mut entry.notes, new_notes);
        for tag in &mut entry.tags {
            tag.zeroize();
        }
        entry.tags = new_tags;
        entry.updated_at = now;
        debug!("[ferusa:cli]: cmd_edit entry mutated in candidate");
        vault
    };

    ui::info("persist vault");
    ui::execute("saving vault to disk");
    save_vault_candidate(&state, &paths, candidate)
        .await
        .map_err(|e| {
            ui::failed("failed to save vault");
            e
        })?;
    ui::success("changes applied");
    ui::success("vault saved");

    println!();
    ui::success(&format!("entry \"{}\" updated", new_title));
    info!(
        "[ferusa:cli]: cmd_edit vault saved — entry {:?} updated",
        new_title
    );
    Ok(())
}
