use std::io::{self, Write};

use anyhow::{Context, Result};
use rand::Rng;
use zeroize::Zeroizing;

use crate::interface::error::CliError;
use crate::interface::ui;

const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*-_=+?";

pub struct PasswordGenConfig {
    pub length: usize,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
}

impl Default for PasswordGenConfig {
    fn default() -> Self {
        Self {
            length: 20,
            uppercase: true,
            digits: true,
            symbols: true,
        }
    }
}

/// Generate a random password from `config`.
/// Always includes at least one character from each enabled class so that
/// the result actually satisfies the chosen policy.
pub fn generate(cfg: &PasswordGenConfig) -> std::result::Result<String, CliError> {
    let required_classes =
        1 + usize::from(cfg.uppercase) + usize::from(cfg.digits) + usize::from(cfg.symbols);
    if cfg.length < required_classes {
        return Err(CliError::PasswordGeneration {
            details: format!(
                "requested length {} is shorter than enabled required class count {}",
                cfg.length, required_classes
            ),
        });
    }

    let mut charset: Vec<u8> = Vec::new();
    charset.extend_from_slice(LOWER); // lowercase is always on

    if cfg.uppercase {
        charset.extend_from_slice(UPPER);
    }
    if cfg.digits {
        charset.extend_from_slice(DIGITS);
    }
    if cfg.symbols {
        charset.extend_from_slice(SYMBOLS);
    }

    let mut rng = rand::rng();

    // Guarantee at least one char from every enabled class.
    let mut guaranteed: Vec<u8> = Vec::new();
    guaranteed.push(LOWER[rng.random_range(0..LOWER.len())]);
    if cfg.uppercase {
        guaranteed.push(UPPER[rng.random_range(0..UPPER.len())]);
    }
    if cfg.digits {
        guaranteed.push(DIGITS[rng.random_range(0..DIGITS.len())]);
    }
    if cfg.symbols {
        guaranteed.push(SYMBOLS[rng.random_range(0..SYMBOLS.len())]);
    }

    // Fill the rest randomly from the full charset.
    let fill = cfg.length - guaranteed.len();
    let mut pw: Vec<u8> = (0..fill)
        .map(|_| charset[rng.random_range(0..charset.len())])
        .collect();

    pw.extend_from_slice(&guaranteed);

    // Fisher-Yates shuffle so guaranteed chars aren't always at the end.
    let n = pw.len();
    for i in (1..n).rev() {
        let j = rng.random_range(0..=i);
        pw.swap(i, j);
    }

    Ok(String::from_utf8(pw).expect("charset is ASCII"))
}

pub(crate) enum GeneratedPasswordChoice {
    Accept(Zeroizing<String>),
    Regenerate,
    TypeOwn,
}

pub(crate) fn resolve_generated_choice(
    choice: &str,
    pw: Zeroizing<String>,
) -> Result<GeneratedPasswordChoice> {
    match choice.trim().to_lowercase().as_str() {
        "r" => Ok(GeneratedPasswordChoice::Regenerate),
        "m" => Ok(GeneratedPasswordChoice::TypeOwn),
        _ => Ok(GeneratedPasswordChoice::Accept(pw)),
    }
}

// ── interactive helpers ───────────────────────────────────────────────────────

fn prompt_yn(label: &str, default_yes: bool) -> Result<bool> {
    let hint = if default_yes { "Y/n" } else { "y/N" };
    print!("\x1b[1minput:\x1b[0m {} [{}]: ", label, hint);
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    let s = buf.trim().to_lowercase();
    Ok(match s.as_str() {
        "y" | "yes" => true,
        "n" | "no" => false,
        _ => default_yes,
    })
}

fn prompt_usize(label: &str, default: usize) -> Result<usize> {
    print!("\x1b[1minput:\x1b[0m {} [{}]: ", label, default);
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    let s = buf.trim();
    if s.is_empty() {
        return Ok(default);
    }
    s.parse::<usize>().context("not a valid number")
}

fn ask_config() -> Result<PasswordGenConfig> {
    let length = prompt_usize("length", 20)?;
    let uppercase = prompt_yn("include uppercase?", true)?;
    let digits = prompt_yn("include digits?", true)?;
    let symbols = prompt_yn("include symbols?", true)?;

    let length = length.clamp(8, 128);
    Ok(PasswordGenConfig {
        length,
        uppercase,
        digits,
        symbols,
    })
}

/// Full interactive password field: offer to generate, regenerate, or let the
/// user type their own.  Returns the final password string.
///
/// Drop-in replacement for the inline `rpassword` block in `cmd_add` / `cmd_edit`.
pub fn prompt_password_field() -> Result<Zeroizing<String>> {
    print!("\x1b[1minput:\x1b[0m generate password? [Y/n]: ");
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    let want_gen = !matches!(buf.trim().to_lowercase().as_str(), "n" | "no");

    if !want_gen {
        // Fall back to the same hidden prompt used before.
        return rpassword::prompt_password("\x1b[1minput:\x1b[0m password: ")
            .map(Zeroizing::new)
            .context("read password");
    }

    let cfg = ask_config()?;

    loop {
        let pw = Zeroizing::new(generate(&cfg)?);

        ui::success("generated password ready");

        print!("\x1b[1minput:\x1b[0m [enter] accept   [r] regenerate   [m] type my own: ");
        io::stdout().flush()?;
        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;

        match resolve_generated_choice(&choice, pw)? {
            GeneratedPasswordChoice::Accept(pw) => return Ok(pw),
            GeneratedPasswordChoice::Regenerate => continue,
            GeneratedPasswordChoice::TypeOwn => {
                return rpassword::prompt_password("\x1b[1minput:\x1b[0m password: ")
                    .map(Zeroizing::new)
                    .context("read password");
            }
        }
    }
}

#[cfg(test)]
mod choice_tests {
    use super::{resolve_generated_choice, GeneratedPasswordChoice};
    use zeroize::Zeroizing;

    #[test]
    fn regenerate_does_not_copy_candidate() {
        let result = resolve_generated_choice("r", Zeroizing::new("candidate".to_owned())).unwrap();

        assert!(matches!(result, GeneratedPasswordChoice::Regenerate));
    }

    #[test]
    fn type_own_does_not_copy_candidate() {
        let result = resolve_generated_choice("m", Zeroizing::new("candidate".to_owned())).unwrap();

        assert!(matches!(result, GeneratedPasswordChoice::TypeOwn));
    }

    #[test]
    fn accept_keeps_candidate_in_memory_without_copying_it() {
        let result = resolve_generated_choice("", Zeroizing::new("candidate".to_owned())).unwrap();

        match result {
            GeneratedPasswordChoice::Accept(password) => assert_eq!(&*password, "candidate"),
            _ => panic!("expected generated password to be accepted"),
        }
    }
}
