use anyhow::{bail, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use log::{debug, error, info};

/// Hash a PIN string with Argon2id. Returns a PHC string (includes salt).
pub fn hash_pin(pin: &str) -> Result<String> {
    debug!("[ferusa:app]: hash_pin start");
    if pin.is_empty() {
        error!("[ferusa:app]: hash_pin called with empty PIN");
        bail!("PIN must not be empty");
    }
    debug!("[ferusa:app]: hash_pin building Argon2id params");
    let params =
        Params::new(65536, 3, 1, None).map_err(|e| anyhow::anyhow!("argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    debug!("[ferusa:app]: hash_pin generating salt");
    let salt = SaltString::generate(&mut OsRng);
    debug!("[ferusa:app]: hash_pin hashing password");
    let hash = argon2
        .hash_password(pin.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hash_password: {e}"))?;
    info!("[ferusa:app]: hash_pin complete");
    Ok(hash.to_string())
}

/// Verify a PIN against its stored hash. Returns Ok(true) on match.
pub fn verify_pin(pin: &str, hash_str: &str) -> Result<bool> {
    debug!("[ferusa:app]: verify_pin start");
    let params =
        Params::new(65536, 3, 1, None).map_err(|e| anyhow::anyhow!("argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    debug!("[ferusa:app]: verify_pin parsing stored hash");
    let hash = PasswordHash::new(hash_str).map_err(|e| anyhow::anyhow!("parse hash: {e}"))?;
    debug!("[ferusa:app]: verify_pin verifying password");
    let result = argon2.verify_password(pin.as_bytes(), &hash).is_ok();
    debug!("[ferusa:app]: verify_pin result: {}", result);
    Ok(result)
}

/// Returns Ok if pin contains only ASCII digits and has the expected length.
pub fn validate_pin(pin: &str, expected_len: usize) -> Result<()> {
    debug!(
        "[ferusa:app]: validate_pin start (expected_len={})",
        expected_len
    );
    if pin.len() != expected_len {
        error!(
            "[ferusa:app]: validate_pin length mismatch: got={} expected={}",
            pin.len(),
            expected_len
        );
        bail!("PIN must be exactly {} digits", expected_len);
    }
    if !pin.chars().all(|c| c.is_ascii_digit()) {
        error!("[ferusa:app]: validate_pin non-digit characters found");
        bail!("PIN must contain only digits 0-9");
    }
    if is_trivial_pin(pin) {
        error!("[ferusa:app]: validate_pin rejected trivial PIN");
        bail!("choose a PIN that is not common, repeated, or sequential");
    }
    debug!("[ferusa:app]: validate_pin ok");
    Ok(())
}

fn is_trivial_pin(pin: &str) -> bool {
    let digits = pin.as_bytes();
    let repeated = digits.windows(2).all(|pair| pair[0] == pair[1]);
    let ascending = digits
        .windows(2)
        .all(|pair| pair[1] == pair[0].saturating_add(1));
    let descending = digits
        .windows(2)
        .all(|pair| pair[1].saturating_add(1) == pair[0]);
    let known_common = matches!(
        pin,
        "1212" | "1122" | "2580" | "121212" | "112233" | "258025"
    );

    repeated || ascending || descending || known_common
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_pin_roundtrip() {
        let hash = hash_pin("1234").unwrap();
        assert!(verify_pin("1234", &hash).unwrap());
        assert!(!verify_pin("9999", &hash).unwrap());
    }

    #[test]
    fn validate_pin_rejects_wrong_length() {
        assert!(validate_pin("123", 4).is_err());
        assert!(validate_pin("12345", 4).is_err());
        assert!(validate_pin("4829", 4).is_ok());
    }

    #[test]
    fn validate_pin_rejects_non_digits() {
        assert!(validate_pin("12ab", 4).is_err());
        assert!(validate_pin("12 4", 4).is_err());
    }

    #[test]
    fn hash_pin_is_non_empty() {
        let h = hash_pin("5678").unwrap();
        assert!(!h.is_empty());
        assert!(h.starts_with("$argon2id"));
    }

    #[test]
    fn different_pins_give_different_hashes() {
        let h1 = hash_pin("1111").unwrap();
        let h2 = hash_pin("2222").unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn same_pin_gives_different_hash_due_to_salt() {
        let h1 = hash_pin("1234").unwrap();
        let h2 = hash_pin("1234").unwrap();
        assert_ne!(h1, h2);
        assert!(verify_pin("1234", &h1).unwrap());
        assert!(verify_pin("1234", &h2).unwrap());
    }

    #[test]
    fn empty_pin_is_rejected() {
        assert!(hash_pin("").is_err());
    }

    #[test]
    fn six_digit_pin_validates() {
        assert!(validate_pin("482916", 6).is_ok());
        assert!(validate_pin("00000", 6).is_err());
        assert!(validate_pin("1234567", 6).is_err());
    }

    #[test]
    fn trivial_pins_are_rejected() {
        for pin in ["0000", "1234", "4321", "1212", "000000", "123456"] {
            assert!(
                validate_pin(pin, pin.len()).is_err(),
                "{pin} should be rejected"
            );
        }
    }
}
