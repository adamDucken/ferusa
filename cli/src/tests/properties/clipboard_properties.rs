#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use tempfile::TempDir;

    use crate::clipboard::{
        parse_clipboard_command, read_clipboard_command, validate_clipboard_command,
        write_clipboard_command,
    };
    use crate::storage::paths::Paths;

    fn paths(dir: &TempDir) -> Paths {
        let p = dir.path().to_path_buf();
        Paths {
            data_dir: p.clone(),
            vault_enc: p.join("vault.enc"),
            vault_salt: p.join("vault.salt"),
            peer_id: p.join("peer.id"),
            phone_id: p.join("phone.id"),
            hmac_key: p.join("hmac.key"),
            clipboard_cmd: p.join("clipboard.cmd"),
        }
    }

    fn shellish_string() -> impl Strategy<Value = String> {
        prop::collection::vec(any::<u8>(), 0..=256)
            .prop_map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
    }

    fn safe_arg() -> impl Strategy<Value = String> {
        prop::collection::vec(any::<u8>(), 0..=160).prop_map(|bytes| {
            let arg = String::from_utf8_lossy(&bytes)
                .chars()
                .map(|c| {
                    if c.is_control()
                        || c.is_whitespace()
                        || matches!(c, ';' | '&' | '|' | '<' | '>' | '`' | '$' | '(' | ')')
                    {
                        '_'
                    } else {
                        c
                    }
                })
                .collect::<String>()
                .trim_matches('_')
                .to_owned();
            if arg.is_empty() {
                "fuzz-value".to_owned()
            } else {
                arg
            }
        })
    }

    fn has_shell_metachar_or_control(command: &str) -> bool {
        command.chars().any(|c| {
            c.is_control() || matches!(c, ';' | '&' | '|' | '<' | '>' | '`' | '$' | '(' | ')')
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn validated_clipboard_commands_are_parseable(command in shellish_string()) {
            let parsed = parse_clipboard_command(&command);
            let validated = validate_clipboard_command(&command);

            prop_assert!(
                !(validated.is_ok() && parsed.is_err()),
                "validated command did not parse: {command:?}"
            );
        }

        #[test]
        fn parsed_clipboard_commands_use_allowlisted_programs(command in shellish_string()) {
            if let Ok(argv) = parse_clipboard_command(&command) {
                prop_assert!(matches!(
                    argv[0].as_str(),
                    "wl-copy" | "xclip" | "xsel" | "pbcopy" | "clip" | "clip.exe" | "termux-clipboard-set"
                ));
                prop_assert!(!argv[0].contains('/'));
                prop_assert!(!argv[0].contains('\\'));
                prop_assert!(!has_shell_metachar_or_control(command.trim()));
            }
        }

        #[test]
        fn shell_metacharacters_are_rejected(prefix in ".{0,32}", suffix in ".{0,32}", metachar in prop::sample::select(vec![';', '&', '|', '<', '>', '`', '$', '(', ')'])) {
            let command = format!("{prefix}{metachar}{suffix}");
            prop_assert!(validate_clipboard_command(&command).is_err());
        }

        #[test]
        fn clipboard_command_file_roundtrip_trims_loaded_command(arg in safe_arg()) {
            let command = format!("wl-copy --type {arg}");
            let dir = TempDir::new().unwrap();
            let p = paths(&dir);

            write_clipboard_command(&p, &command).unwrap();
            prop_assert_eq!(read_clipboard_command(&p).unwrap(), command.trim());
        }
    }

    #[test]
    fn rejects_known_shell_injection_and_non_clipboard_programs() {
        for command in [
            "wl-copy; rm -rf ~",
            "wl-copy && rm -rf ~",
            "wl-copy | sh",
            "wl-copy > /tmp/out",
            "sh -c wl-copy",
            "rm -rf ~",
            "rm -rf /",
            "cat",
            "/tmp/wl-copy",
            "./wl-copy",
            "bin/wl-copy",
            r"C:\tools\clip.exe",
        ] {
            assert!(
                validate_clipboard_command(command).is_err(),
                "{command:?} must be rejected"
            );
        }
    }
}
