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
const MAX_COMMAND_BYTES: usize = 4096;
const MAX_PASSWORD_BYTES: usize = 1024 * 1024;

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
    if expiry_commands(&argv).is_err() {
        return Ok(ClipboardClearStatus::Unsupported(format!(
            "{} with its configured options",
            argv[0]
        )));
    }
    let reader = ownership_reader_program(&argv);
    if reader != argv[0] && !executable_is_available(reader) {
        return Ok(ClipboardClearStatus::Unsupported(format!(
            "{} (missing {reader})",
            argv[0]
        )));
    }
    if spawn_clear_helper(password, &command, timeout).is_err() {
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

// Only accept options whose target can be preserved for both reading and clearing.
fn expiry_commands(argv: &[String]) -> Result<(Vec<String>, Vec<String>)> {
    let program = argv.first().context("empty clipboard command")?.as_str();
    let mut target = Vec::new();
    let mut args = argv[1..].iter();
    while let Some(arg) = args.next() {
        match (program, arg.as_str()) {
            ("wl-copy", "-p" | "--primary") => target.push("--primary".into()),
            ("wl-copy", "-s" | "--seat") => {
                target.push("--seat".into());
                target.push(args.next().context("missing clipboard seat")?.clone());
            }
            ("wl-copy", option) if option.starts_with("--seat=") => {
                if option == "--seat=" {
                    bail!("missing clipboard seat");
                }
                target.push(arg.clone());
            }
            ("xclip", "-selection") => {
                let selection = args.next().context("missing clipboard selection")?;
                if !matches!(selection.as_str(), "primary" | "secondary" | "clipboard") {
                    bail!("unsupported clipboard selection");
                }
                target.extend([arg.clone(), selection.clone()]);
            }
            ("xclip", "-display") => {
                target.extend([arg.clone(), args.next().context("missing display")?.clone()]);
            }
            ("xclip", "-i" | "-in") | ("xsel", "-i" | "--input") => {}
            ("xsel", "-p" | "--primary" | "-s" | "--secondary" | "-b" | "--clipboard") => {
                target.push(arg.clone());
            }
            ("xsel", "--display") => {
                target.extend([arg.clone(), args.next().context("missing display")?.clone()]);
            }
            ("pbcopy", "-pboard") => {
                let board = args.next().context("missing pasteboard")?;
                if !matches!(board.as_str(), "general" | "ruler" | "find" | "font") {
                    bail!("unsupported pasteboard");
                }
                target.extend([arg.clone(), board.clone()]);
            }
            _ => bail!("unsupported clipboard expiry option"),
        }
    }
    let (reader, read_option, clear_option) = match program {
        "wl-copy" => ("wl-paste", Some("--no-newline"), Some("--clear")),
        "xclip" => ("xclip", Some("-o"), None),
        "xsel" => ("xsel", Some("--output"), None),
        "pbcopy" => ("pbpaste", None, None),
        "termux-clipboard-set" => ("termux-clipboard-get", None, None),
        _ => bail!("unsupported clipboard expiry program"),
    };
    let read = std::iter::once(reader.to_owned())
        .chain(target.clone())
        .chain(read_option.map(str::to_owned))
        .collect();
    let clear = std::iter::once(program.to_owned())
        .chain(target)
        .chain(clear_option.map(str::to_owned))
        .collect();
    Ok((read, clear))
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

fn helper_payload(password: &str, command: &str) -> Result<Zeroizing<Vec<u8>>> {
    if command.len() > MAX_COMMAND_BYTES || password.len() > MAX_PASSWORD_BYTES {
        bail!("clipboard helper input is too large");
    }
    let mut payload = Zeroizing::new(Vec::new());
    payload.extend_from_slice(&(command.len() as u32).to_le_bytes());
    payload.extend_from_slice(command.as_bytes());
    payload.extend_from_slice(password.as_bytes());
    Ok(payload)
}

fn helper_snapshot(payload: &[u8]) -> Result<(Vec<String>, &[u8])> {
    let header: [u8; 4] = payload
        .get(..4)
        .context("missing helper header")?
        .try_into()?;
    let len = u32::from_le_bytes(header) as usize;
    if len > MAX_COMMAND_BYTES {
        bail!("clipboard command is too large");
    }
    let command = std::str::from_utf8(
        payload
            .get(4..4 + len)
            .context("truncated helper command")?,
    )?;
    let expected = &payload[4 + len..];
    if expected.len() > MAX_PASSWORD_BYTES {
        bail!("clipboard ownership value is too large");
    }
    let argv = parse_clipboard_command(command)?;
    expiry_commands(&argv)?;
    Ok((argv, expected))
}

fn spawn_clear_helper(password: &str, command: &str, after_secs: u64) -> Result<()> {
    let payload = helper_payload(password, command)?;
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
        .write_all(&payload)
        .context("send clipboard ownership value to clear helper")?;
    Ok(())
}

pub fn run_clear_helper(after_secs: u64) -> Result<()> {
    validate_clear_timeout(after_secs)?;
    let mut payload = Zeroizing::new(Vec::new());
    std::io::stdin()
        .take((4 + MAX_COMMAND_BYTES + MAX_PASSWORD_BYTES + 1) as u64)
        .read_to_end(&mut payload)
        .context("read clipboard ownership value")?;
    let (argv, expected) = helper_snapshot(&payload)?;
    std::thread::sleep(Duration::from_secs(after_secs));

    let current = Zeroizing::new(read_clipboard_value(&argv, expected.len() + 1)?);
    if clipboard_is_still_owned(&current, expected) {
        clear_clipboard(&argv)?;
    }
    Ok(())
}

fn clipboard_is_still_owned(current: &[u8], expected: &[u8]) -> bool {
    current == expected
}

fn read_clipboard_value(argv: &[String], limit: usize) -> Result<Vec<u8>> {
    let (reader, _) = expiry_commands(argv)?;
    let (program, args) = reader.split_first().context("empty clipboard reader")?;
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
    let (_, clear) = expiry_commands(argv)?;
    if argv[0] == "wl-copy" {
        let status = Command::new("wl-copy")
            .args(&clear[1..])
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
        pipe_to_argv("", &clear)
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
    use super::*;

    #[test]
    fn expiry_preserves_supported_targets() {
        for (copy, read, clear) in [
            ("wl-copy", "wl-paste --no-newline", "wl-copy --clear"),
            (
                "wl-copy -p -s seat0",
                "wl-paste --primary --seat seat0 --no-newline",
                "wl-copy --primary --seat seat0 --clear",
            ),
            (
                "wl-copy --primary --seat=seat1",
                "wl-paste --primary --seat=seat1 --no-newline",
                "wl-copy --primary --seat=seat1 --clear",
            ),
            (
                "xclip -selection clipboard -display :1 -i",
                "xclip -selection clipboard -display :1 -o",
                "xclip -selection clipboard -display :1",
            ),
            (
                "xsel --secondary --display :2 --input",
                "xsel --secondary --display :2 --output",
                "xsel --secondary --display :2",
            ),
            (
                "pbcopy -pboard find",
                "pbpaste -pboard find",
                "pbcopy -pboard find",
            ),
            (
                "termux-clipboard-set",
                "termux-clipboard-get",
                "termux-clipboard-set",
            ),
        ] {
            let (reader, clearer) =
                expiry_commands(&parse_clipboard_command(copy).unwrap()).unwrap();
            assert_eq!(reader.join(" "), read);
            assert_eq!(clearer.join(" "), clear);
        }
        for command in [
            "wl-copy --type text/html",
            "wl-copy --seat",
            "wl-copy --seat=",
            "xclip -selection unknown",
            "xclip -display",
            "xclip -o",
            "xsel --display",
            "xsel --keep",
            "pbcopy -pboard unknown",
            "clip",
        ] {
            assert!(
                expiry_commands(&parse_clipboard_command(command).unwrap()).is_err(),
                "{command}"
            );
        }
    }

    #[test]
    fn helper_protocol_is_bounded_and_preserves_secret_bytes() {
        let payload = helper_payload("secret\n\0", "wl-copy --primary").unwrap();
        let (argv, expected) = helper_snapshot(&payload).unwrap();
        assert_eq!(argv, ["wl-copy", "--primary"]);
        assert_eq!(expected, b"secret\n\0");
        assert!(helper_snapshot(&[0, 0, 0]).is_err());
        assert!(helper_snapshot(&u32::MAX.to_le_bytes()).is_err());
        assert!(helper_snapshot(&[5, 0, 0, 0, b'x']).is_err());
        assert!(helper_payload("", &"x".repeat(MAX_COMMAND_BYTES + 1)).is_err());
        assert!(helper_payload(&"x".repeat(MAX_PASSWORD_BYTES + 1), "wl-copy").is_err());
    }

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
