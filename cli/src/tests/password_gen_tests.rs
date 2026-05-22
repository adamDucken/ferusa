#[cfg(test)]
mod tests {
    use crate::interface::error::CliError;
    use crate::interface::password_gen::{generate, PasswordGenConfig};

    const SYMBOLS: &str = "!@#$%^&*-_=+?";

    #[test]
    fn test_length() {
        for length in 8..=128 {
            let cfg = PasswordGenConfig {
                length,
                uppercase: true,
                digits: true,
                symbols: true,
            };
            assert_eq!(generate(&cfg).unwrap().len(), length);
        }
    }

    #[test]
    fn test_shortest_valid_lengths() {
        for (length, uppercase, digits, symbols) in [
            (1, false, false, false),
            (2, true, false, false),
            (3, true, true, false),
            (4, true, true, true),
        ] {
            let cfg = PasswordGenConfig {
                length,
                uppercase,
                digits,
                symbols,
            };
            assert_eq!(generate(&cfg).unwrap().len(), length);
        }
    }

    #[test]
    fn test_rejects_length_below_required_class_count() {
        for (length, uppercase, digits, symbols) in [
            (0, false, false, false),
            (1, true, false, false),
            (2, true, true, false),
            (3, true, true, true),
        ] {
            let cfg = PasswordGenConfig {
                length,
                uppercase,
                digits,
                symbols,
            };
            assert!(matches!(
                generate(&cfg),
                Err(CliError::PasswordGeneration { .. })
            ));
        }
    }

    #[test]
    fn test_guarantees() {
        let cfg = PasswordGenConfig {
            length: 32,
            uppercase: true,
            digits: true,
            symbols: true,
        };

        for _ in 0..100 {
            let password = generate(&cfg).unwrap();
            assert!(password.chars().any(|ch| ch.is_ascii_lowercase()));
            assert!(password.chars().any(|ch| ch.is_ascii_uppercase()));
            assert!(password.chars().any(|ch| ch.is_ascii_digit()));
            assert!(password.chars().any(|ch| SYMBOLS.contains(ch)));
        }
    }

    #[test]
    fn test_no_symbols() {
        let cfg = PasswordGenConfig {
            length: 32,
            uppercase: true,
            digits: true,
            symbols: false,
        };

        for _ in 0..100 {
            let password = generate(&cfg).unwrap();
            assert!(!password.chars().any(|ch| SYMBOLS.contains(ch)));
        }
    }
}
