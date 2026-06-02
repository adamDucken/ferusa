#![no_main]

use cli::clipboard::{parse_clipboard_command, validate_clipboard_command};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let command = String::from_utf8_lossy(data);
    let parsed = parse_clipboard_command(&command);
    let validated = validate_clipboard_command(&command);

    assert_eq!(parsed.is_ok(), validated.is_ok());

    if let Ok(argv) = parsed {
        assert!(matches!(
            argv[0].as_str(),
            "wl-copy" | "xclip" | "xsel" | "pbcopy" | "clip" | "clip.exe" | "termux-clipboard-set"
        ));
        assert!(!argv[0].contains('/'));
        assert!(!argv[0].contains('\\'));
        let trimmed = command.trim();
        assert!(!trimmed.chars().any(|c| {
            c.is_control() || matches!(c, ';' | '&' | '|' | '<' | '>' | '`' | '$' | '(' | ')')
        }));
    }
});
