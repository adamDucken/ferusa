use assert_cmd::Command;
use proptest::prelude::*;
use tempfile::TempDir;

fn arg_strategy(max_len: usize) -> impl Strategy<Value = String> {
    prop::collection::vec(any::<u8>(), 1..=max_len).prop_map(|bytes| {
        String::from_utf8_lossy(&bytes)
            .chars()
            .map(|c| if c == '\0' { '_' } else { c })
            .collect()
    })
}

fn safe_clipboard_arg(max_len: usize) -> impl Strategy<Value = String> {
    arg_strategy(max_len).prop_map(|value| {
        let value = value
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
            .collect::<String>();
        if value.is_empty() {
            "fuzz-value".to_owned()
        } else {
            value
        }
    })
}

fn ferusa(temp: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("ferusa").unwrap();
    cmd.env("XDG_DATA_HOME", temp.path());
    cmd
}

fn output_text(output: &std::process::Output) -> String {
    let mut text = String::new();
    text.push_str(&String::from_utf8_lossy(&output.stdout));
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    text
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn cli_rejects_unknown_outer_args_without_panic(arg in arg_strategy(80)) {
        let temp = TempDir::new().unwrap();
        let output = ferusa(&temp).arg(format!("fuzz-{arg}")).output().unwrap();
        let text = output_text(&output);

        prop_assert!(!output.status.success());
        prop_assert!(!text.contains("panicked"), "text={text}");
        prop_assert!(!text.contains("thread 'main'"), "text={text}");
    }

    #[test]
    fn get_title_arg_hits_fs_unlock_boundary_without_panic(title in arg_strategy(160)) {
        let temp = TempDir::new().unwrap();
        let output = ferusa(&temp).args(["get", "--", &title]).output().unwrap();
        let text = output_text(&output);

        prop_assert!(!output.status.success());
        prop_assert!(
            text.contains("vault not initialised") || text.contains("vault not initialized"),
            "text={text}"
        );
        prop_assert!(!text.contains("panicked"), "text={text}");
    }

    #[test]
    fn config_set_negative_confirmation_fails_cleanly(arg in safe_clipboard_arg(64)) {
        let temp = TempDir::new().unwrap();
        let output = ferusa(&temp)
            .args(["config", "set", "wl-copy", "--type", &arg])
            .write_stdin("n\n")
            .output()
            .unwrap();
        let text = output_text(&output);

        prop_assert!(!output.status.success());
        prop_assert!(
            text.contains("clipboard command not saved"),
            "text={text}"
        );
        prop_assert!(!text.contains("panicked"), "text={text}");
    }
}
