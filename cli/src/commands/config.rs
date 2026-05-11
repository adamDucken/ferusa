use std::io::{self, Write};

use anyhow::{bail, Result};
use log::{debug, info};

use crate::clipboard;
use crate::interface::ui;
use crate::storage::paths::Paths;

const SAMPLE_PASSWORD: &str = "generated-password";

pub fn cmd_config_get() -> Result<()> {
    let paths = Paths::load()?;
    match clipboard::read_clipboard_command(&paths) {
        Ok(command) => {
            println!("{command}");
            println!(
                "clear after: {} seconds",
                clipboard::read_clear_timeout(&paths)?
            );
            Ok(())
        }
        Err(e) if !paths.clipboard_cmd.exists() => {
            ui::info("clipboard command is not configured");
            ui::info("example: ferusa config set wl-copy");
            ui::info("example: ferusa config set xclip -selection clipboard");
            Err(e)
        }
        Err(e) => Err(e),
    }
}

pub fn cmd_config_set(command: &str, clear_after: u64) -> Result<()> {
    let paths = Paths::load()?;
    let command = command.trim();
    clipboard::validate_clipboard_command(command)?;
    clipboard::validate_clear_timeout(clear_after)?;

    ui::info("clipboard command preview");
    println!("{SAMPLE_PASSWORD} | {command}");
    print!("\x1b[1minput:\x1b[0m save this clipboard command? [y/N]: ");
    io::stdout().flush()?;

    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
        ui::failed("clipboard command not saved");
        bail!("clipboard command not saved");
    }

    clipboard::write_clipboard_command(&paths, command)?;
    clipboard::write_clear_timeout(&paths, clear_after)?;
    ui::success("clipboard command saved");
    info!("[ferusa:cli]: clipboard command configured");
    debug!(
        "[ferusa:cli]: clipboard command path={:?}",
        paths.clipboard_cmd
    );
    ui::info(&format!("clipboard clear timeout: {clear_after} seconds"));
    Ok(())
}
