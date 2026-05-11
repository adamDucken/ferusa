use anyhow::{bail, Result};

pub const MIN_MASTER_PASSWORD_CHARS: usize = 12;

// This deliberately blocks only the most common choices. It is not a substitute
// for a password-strength estimator, but prevents the weak defaults users are
// most likely to choose when creating a security factor.
const COMMON_MASTER_PASSWORDS: &[&str] = &[
    "password",
    "password1",
    "password123",
    "passwordpassword",
    "passw0rd",
    "12345678",
    "123456789",
    "qwerty",
    "qwerty123",
    "letmein",
    "welcome",
    "admin",
    "iloveyou",
    "monkey",
    "dragon",
    "football",
    "baseball",
    "abc123",
];

pub fn validate_master_password(password: &str) -> Result<()> {
    let char_count = password.chars().count();
    if char_count < MIN_MASTER_PASSWORD_CHARS {
        bail!("master password must be at least {MIN_MASTER_PASSWORD_CHARS} characters");
    }

    let normalized = password.to_lowercase();
    if COMMON_MASTER_PASSWORDS.contains(&normalized.as_str()) {
        bail!("master password is too common; choose a unique passphrase");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_short_passwords_by_unicode_character_count() {
        assert!(validate_master_password("12345678901").is_err());
        assert!(validate_master_password("pässwörd1234").is_ok());
    }

    #[test]
    fn rejects_common_passwords() {
        assert!(validate_master_password("PASSWORDPASSWORD").is_err());
    }
}
