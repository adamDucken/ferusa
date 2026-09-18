#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

#[test]
fn helper_keeps_original_target_after_configuration_changes() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("ferusa");
    fs::create_dir(&data).unwrap();
    let config = data.join("clipboard.cmd");
    fs::write(&config, "wl-copy --primary --seat seat0").unwrap();
    fs::write(dir.path().join("A"), "secret").unwrap();
    fs::write(dir.path().join("B"), "other value").unwrap();
    for (name, operation) in [("wl-paste", "/bin/cat"), ("wl-copy", ": >")] {
        let path = dir.path().join(name);
        fs::write(&path, format!(
            "#!/bin/sh\n[ \"$1\" = --primary ] && [ \"$2\" = --seat ] && [ \"$3\" = seat0 ] || exit 7\n{operation} \"$CLIPBOARD_TEST_DIR/A\"\n"
        )).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut helper = Command::new(env!("CARGO_BIN_EXE_ferusa"))
        .args(["clipboard-clear-helper", "--after-secs", "1"])
        .env("PATH", dir.path())
        .env("XDG_DATA_HOME", dir.path())
        .env("CLIPBOARD_TEST_DIR", dir.path())
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let command = fs::read(&config).unwrap();
    let mut stdin = helper.stdin.take().unwrap();
    stdin
        .write_all(&(command.len() as u32).to_le_bytes())
        .unwrap();
    stdin.write_all(&command).unwrap();
    stdin.write_all(b"secret").unwrap();
    drop(stdin);
    fs::write(&config, "wl-copy --seat seat1").unwrap();
    assert!(helper.wait().unwrap().success());
    assert_eq!(fs::read(dir.path().join("A")).unwrap(), b"");
    assert_eq!(fs::read(dir.path().join("B")).unwrap(), b"other value");
}
