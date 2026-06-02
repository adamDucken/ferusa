#![no_main]

use cli::storage::paths::write_private_file;
use libfuzzer_sys::fuzz_target;

#[cfg(unix)]
fn file_name(data: &[u8]) -> std::ffi::OsString {
    use std::os::unix::ffi::OsStringExt;

    let mut bytes: Vec<u8> = data
        .iter()
        .copied()
        .take(64)
        .map(|b| if b == 0 || b == b'/' { b'_' } else { b })
        .collect();
    if bytes.is_empty() || bytes == b"." || bytes == b".." {
        bytes = b"fuzz-file".to_vec();
    }
    std::ffi::OsString::from_vec(bytes)
}

#[cfg(not(unix))]
fn file_name(data: &[u8]) -> std::ffi::OsString {
    let mut name: String = String::from_utf8_lossy(data)
        .chars()
        .take(64)
        .map(|c| match c {
            '\0' | '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect();
    if name.is_empty() || name == "." || name == ".." {
        name = "fuzz-file".to_owned();
    }
    name.into()
}

fuzz_target!(|data: &[u8]| {
    let dir = tempfile::TempDir::new().expect("temp dir");
    let split = data.first().copied().unwrap_or(0) as usize % (data.len() + 1);
    let (name_bytes, contents) = data.split_at(split);
    let path = dir.path().join(file_name(name_bytes));
    let contents = &contents[..contents.len().min(4096)];

    write_private_file(&path, contents).expect("write private file");
    assert_eq!(std::fs::read(&path).expect("read private file"), contents);
});
