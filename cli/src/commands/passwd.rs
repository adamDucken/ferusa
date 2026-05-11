use std::io::ErrorKind;

use anyhow::{bail, Context, Result};
use log::{debug, info, warn};

use ferusa_core::crypto::{combine_vault_key, derive_keys, encrypt_vault, new_salt};
use ferusa_core::types::VaultAction;
use zeroize::{Zeroize, Zeroizing};

use crate::interface::ui;
use crate::password::validate_master_password;
use crate::session::{ensure_unlocked_for, lock_session, SharedState, UnlockStatus};
use crate::storage::paths::{write_private_file, Paths};
use crate::twofa::dispatch::request_approval;

fn remove_legacy_vault_salt(paths: &Paths) -> Result<()> {
    match std::fs::remove_file(&paths.vault_salt) {
        Ok(()) => debug!("[ferusa:cli]: cmd_passwd removed legacy vault.salt"),
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) if e.kind() == ErrorKind::IsADirectory => {
            warn!(
                "[ferusa:cli]: cmd_passwd legacy vault.salt path is not a file; leaving it in place"
            );
        }
        Err(e) => return Err(e).with_context(|| format!("remove {:?}", paths.vault_salt)),
    }
    Ok(())
}

pub async fn cmd_passwd(state: SharedState) -> Result<()> {
    info!("[ferusa:cli]: cmd_passwd start");

    let paths = Paths::load()?;
    debug!("[ferusa:cli]: cmd_passwd paths loaded");

    let unlock_status = ensure_unlocked_for(&state, &paths, VaultAction::Passwd, None)
        .await
        .map_err(|e| {
            ui::failed("could not unlock vault");
            e
        })?;
    debug!("[ferusa:cli]: cmd_passwd vault unlocked");

    println!();
    ui::info("changing master password requires 2FA approval");
    if matches!(unlock_status, UnlockStatus::AlreadyUnlocked) {
        ui::execute("requesting 2FA approval for CHANGE_PASSWORD");
        request_approval(&state, VaultAction::Passwd, None)
            .await
            .map_err(|e| {
                ui::failed("2FA approval failed or was denied");
                e
            })?;
        ui::success("2FA approved");
    }
    println!();

    // — collect and validate new password —
    ui::input("provide new master password");
    let pw1 = Zeroizing::new(
        rpassword::prompt_password("new master password: ").context("read new password")?,
    );

    if let Err(e) = validate_master_password(&pw1) {
        ui::failed(&e.to_string());
        warn!(
            "[ferusa:cli]: cmd_passwd new password rejected ({}) characters",
            pw1.chars().count()
        );
        return Err(e);
    }

    let pw2 = Zeroizing::new(
        rpassword::prompt_password("confirm new master password: ")
            .context("confirm new password")?,
    );

    if pw1.as_str() != pw2.as_str() {
        ui::failed("passwords do not match");
        warn!("[ferusa:cli]: cmd_passwd confirmation mismatch");
        bail!("passwords do not match");
    }
    debug!("[ferusa:cli]: cmd_passwd new password confirmed");

    // — derive new keys —
    ui::execute("deriving new keys");
    let new_salt = new_salt();
    let new_keys = derive_keys(pw1.as_bytes(), &new_salt).context("key derivation")?;
    drop(pw1);
    drop(pw2);
    debug!("[ferusa:cli]: cmd_passwd new keys derived");

    // — re-encrypt and write vault —
    ui::execute("re-encrypting vault with new key");
    {
        let mut guard = state.lock().await;
        let s = guard.as_mut().context("session not unlocked")?;
        let new_vault_key = combine_vault_key(&new_keys.local_secret, &s.phone_share)
            .context("combine vault key")?;

        let plaintext = Zeroizing::new(serde_json::to_vec(&s.vault).context("serialize vault")?);
        let blob = encrypt_vault(&new_vault_key, new_salt, plaintext.as_slice())
            .context("encrypt vault")?;
        debug!("[ferusa:cli]: cmd_passwd vault re-encrypted");

        write_private_file(&paths.vault_enc, &blob.to_bytes()).context("write vault.enc")?;
        remove_legacy_vault_salt(&paths).context("remove legacy vault.salt")?;
        debug!("[ferusa:cli]: cmd_passwd atomic write complete");

        s.local_secret.zeroize();
        s.vault_key.zeroize();
        s.local_secret = new_keys.local_secret;
        s.vault_key = new_vault_key;
        s.vault_salt = new_salt;
        debug!("[ferusa:cli]: cmd_passwd session keys rotated in memory");
    }
    ui::success("vault re-encrypted and saved");

    let stale_conn = {
        let mut guard = state.lock().await;
        guard.as_mut().and_then(|s| s.phone_conn.take())
    };
    if let Some(conn) = stale_conn {
        conn.close().await;
        debug!("[ferusa:cli]: cmd_passwd stale phone connection closed");
    }

    // — lock session —
    ui::execute("locking session");
    lock_session(&state).await;
    info!("[ferusa:cli]: cmd_passwd password changed, session locked");

    println!();
    ui::success("password changed — vault re-encrypted");
    ui::info("phone pairing preserved");

    Ok(())
}
