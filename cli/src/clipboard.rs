use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;

use crate::storage::paths::Paths;

const ALLOWED_CLIPBOARD_PROGRAMS: &[&str] = &[
    "wl-copy",
    "xclip",
    "xsel",
    "pbcopy",
    "clip",
    "clip.exe",
    "termux-clipboard-set",
];
const DEFAULT_CLEAR_TIMEOUT_SECS: u64 = 30;
const MAX_CLEAR_TIMEOUT_SECS: u64 = 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardClearStatus {
    Scheduled(u64),
    Disabled,
    Unsupported(String),
}

pub fn copy_password(password: &str) -> Result<ClipboardClearStatus> {
    let paths = Paths::load()?;
    let command = read_clipboard_command(&paths)?;
    pipe_to_command(password, &command)?;

    let timeout = read_clear_timeout(&paths)?;
    if timeout == 0 {
        return Ok(ClipboardClearStatus::Disabled);
    }
    let argv = parse_clipboard_command(&command)?;
    if !supports_ownership_check(&argv) {
        return Ok(ClipboardClearStatus::Unsupported(argv[0].clone()));
    }
    let reader = ownership_reader_program(&argv);
    if reader != argv[0] && !executable_is_available(reader) {
        return Ok(ClipboardClearStatus::Unsupported(format!(
            "{} (missing {reader})",
            argv[0]
        )));
    }
    if spawn_clear_helper(password, timeout).is_err() {
        return Ok(ClipboardClearStatus::Unsupported(
            "the automatic clipboard clear helper".into(),
        ));
    }
    Ok(ClipboardClearStatus::Scheduled(timeout))
}

fn clear_timeout_path(paths: &Paths) -> PathBuf {
    paths.data_dir.join("clipboard.clear-seconds")
}

pub fn validate_clear_timeout(seconds: u64) -> Result<()> {
    if seconds > MAX_CLEAR_TIMEOUT_SECS {
        bail!("clipboard clear timeout must be between 0 and {MAX_CLEAR_TIMEOUT_SECS} seconds");
    }
    Ok(())
}

pub fn read_clear_timeout(paths: &Paths) -> Result<u64> {
    let path = clear_timeout_path(paths);
    if !path.exists() {
        return Ok(DEFAULT_CLEAR_TIMEOUT_SECS);
    }
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("read clipboard clear timeout at {path:?}"))?;
    let seconds = raw
        .trim()
        .parse::<u64>()
        .context("parse clipboard clear timeout")?;
    validate_clear_timeout(seconds)?;
    Ok(seconds)
}

pub fn write_clear_timeout(paths: &Paths, seconds: u64) -> Result<()> {
    validate_clear_timeout(seconds)?;
    paths.ensure_data_dir()?;
    crate::storage::paths::write_private_file(
        &clear_timeout_path(paths),
        seconds.to_string().as_bytes(),
    )
    .context("write clipboard clear timeout")
}

fn supports_ownership_check(argv: &[String]) -> bool {
    argv.first().is_some_and(|program| {
        matches!(
            program.as_str(),
            "wl-copy" | "xclip" | "xsel" | "pbcopy" | "termux-clipboard-set"
        )
    })
}

fn ownership_reader_program(argv: &[String]) -> &str {
    match argv[0].as_str() {
        "wl-copy" => "wl-paste",
        "pbcopy" => "pbpaste",
        "termux-clipboard-set" => "termux-clipboard-get",
        program => program,
    }
}

fn executable_is_available(program: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path).any(|directory| directory.join(program).is_file())
    })
}

fn spawn_clear_helper(password: &str, after_secs: u64) -> Result<()> {
    let executable =
        std::env::current_exe().context("resolve clipboard clear helper executable")?;
    let mut child = Command::new(executable)
        .arg("clipboard-clear-helper")
        .arg("--after-secs")
        .arg(after_secs.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("start clipboard clear helper")?;
    child
        .stdin
        .take()
        .context("open clipboard clear helper stdin")?
        .write_all(password.as_bytes())
        .context("send clipboard ownership value to clear helper")?;
    Ok(())
}

pub fn run_clear_helper(after_secs: u64) -> Result<()> {
    validate_clear_timeout(after_secs)?;
    let mut expected = Zeroizing::new(Vec::new());
    std::io::stdin()
        .take(1024 * 1024 + 1)
        .read_to_end(&mut expected)
        .context("read clipboard ownership value")?;
    if expected.len() > 1024 * 1024 {
        bail!("clipboard ownership value is too large");
    }
    std::thread::sleep(Duration::from_secs(after_secs));

    let paths = Paths::load()?;
    let command = read_clipboard_command(&paths)?;
    let argv = parse_clipboard_command(&command)?;
    let current = Zeroizing::new(read_clipboard_value(&argv, expected.len() + 1)?);
    if clipboard_is_still_owned(&current, &expected) {
        clear_clipboard(&argv)?;
    }
    Ok(())
}

fn clipboard_is_still_owned(current: &[u8], expected: &[u8]) -> bool {
    current == expected
}

fn read_clipboard_value(argv: &[String], limit: usize) -> Result<Vec<u8>> {
    let (program, args): (&str, Vec<String>) = match argv[0].as_str() {
        "wl-copy" => ("wl-paste", vec!["--no-newline".into()]),
        "pbcopy" => ("pbpaste", Vec::new()),
        "termux-clipboard-set" => ("termux-clipboard-get", Vec::new()),
        "xclip" => (
            "xclip",
            argv[1..].iter().cloned().chain(["-o".into()]).collect(),
        ),
        "xsel" => (
            "xsel",
            argv[1..]
                .iter()
                .cloned()
                .chain(["--output".into()])
                .collect(),
        ),
        other => bail!("clipboard ownership check is unsupported for {other}"),
    };
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("read clipboard with {program}"))?;
    let mut value = Vec::new();
    child
        .stdout
        .take()
        .context("open clipboard reader stdout")?
        .take(limit as u64)
        .read_to_end(&mut value)
        .context("read clipboard value")?;
    let status = child.wait().context("wait for clipboard reader")?;
    if !status.success() {
        bail!("clipboard reader exited with {status}");
    }
    Ok(value)
}

fn clear_clipboard(argv: &[String]) -> Result<()> {
    if argv[0] == "wl-copy" {
        let status = Command::new("wl-copy")
            .arg("--clear")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("clear Wayland clipboard")?;
        if !status.success() {
            bail!("clipboard clear command exited with {status}");
        }
        Ok(())
    } else {
        pipe_to_argv("", argv)
    }
}

pub fn read_clipboard_command(paths: &Paths) -> Result<String> {
    let command = std::fs::read_to_string(&paths.clipboard_cmd)
        .with_context(|| format!("read clipboard command at {:?}", paths.clipboard_cmd))?;
    let command = command.trim().to_owned();
    validate_clipboard_command(&command)?;
    Ok(command)
}

pub fn write_clipboard_command(paths: &Paths, command: &str) -> Result<()> {
    validate_clipboard_command(command)?;
    paths.ensure_data_dir()?;
    crate::storage::paths::write_private_file(&paths.clipboard_cmd, command.as_bytes())
        .with_context(|| format!("write clipboard command at {:?}", paths.clipboard_cmd))
}

pub fn validate_clipboard_command(command: &str) -> Result<()> {
    if command.trim().is_empty() {
        bail!("clipboard command cannot be empty");
    }
    if command.contains('\0') || command.contains('\n') || command.contains('\r') {
        bail!("clipboard command must be a single line");
    }
    parse_clipboard_command(command)?;
    Ok(())
}

fn pipe_to_command(password: &str, command: &str) -> Result<()> {
    let argv = parse_clipboard_command(command)?;
    pipe_to_argv(password, &argv)
}

fn pipe_to_argv(password: &str, argv: &[String]) -> Result<()> {
    let (program, args) = argv
        .split_first()
        .context("clipboard command cannot be empty")?;

    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("start clipboard command `{program}`"))?;

    {
        let mut stdin = child.stdin.take().context("open clipboard command stdin")?;
        stdin
            .write_all(password.as_bytes())
            .context("write password to clipboard command")?;
    }

    let status = child
        .wait()
        .with_context(|| format!("wait for clipboard command `{program}`"))?;
    if !status.success() {
        bail!("clipboard command exited with {status}");
    }

    Ok(())
}

pub fn parse_clipboard_command(command: &str) -> Result<Vec<String>> {
    if let Some(c) = command.chars().find(|c| {
        c.is_control() || matches!(c, ';' | '&' | '|' | '<' | '>' | '`' | '$' | '(' | ')')
    }) {
        bail!("clipboard command contains unsupported shell metacharacter {c:?}");
    }

    let command = command.trim();
    if command.is_empty() {
        bail!("clipboard command cannot be empty");
    }

    let argv: Vec<String> = command
        .split_whitespace()
        .map(str::to_owned)
        .filter(|part| !part.is_empty())
        .collect();
    if argv.is_empty() {
        bail!("clipboard command cannot be empty");
    }

    if argv[0].contains('/') || argv[0].contains('\\') {
        bail!("clipboard program must be a bare executable name");
    }

    if !ALLOWED_CLIPBOARD_PROGRAMS.contains(&argv[0].as_str()) {
        bail!(
            "unsupported clipboard command `{}`; use one of: {}",
            argv[0],
            ALLOWED_CLIPBOARD_PROGRAMS.join(", ")
        );
    }

    Ok(argv)
}

#[cfg(test)]
mod tests {
    use super::{clipboard_is_still_owned, validate_clear_timeout, MAX_CLEAR_TIMEOUT_SECS};

    #[test]
    fn clear_helper_only_clears_unchanged_secret() {
        assert!(clipboard_is_still_owned(b"secret", b"secret"));
        assert!(!clipboard_is_still_owned(b"new clipboard value", b"secret"));
    }

    #[test]
    fn clear_timeout_is_bounded() {
        assert!(validate_clear_timeout(0).is_ok());
        assert!(validate_clear_timeout(MAX_CLEAR_TIMEOUT_SECS).is_ok());
        assert!(validate_clear_timeout(MAX_CLEAR_TIMEOUT_SECS + 1).is_err());
    }
}
