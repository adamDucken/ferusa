#![no_main]

use libfuzzer_sys::fuzz_target;

fn fuzz_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .filter(|c| *c != '\0')
        .take(256)
        .collect()
}

fn chunks(data: &[u8]) -> Vec<String> {
    data.chunks(17).take(8).map(fuzz_string).collect()
}

fuzz_target!(|data: &[u8]| {
    let args = chunks(data);

    let mut raw = vec!["ferusa".to_owned()];
    raw.extend(args.clone());
    let _ = cli::args::parse_from(raw);

    if let Some(title) = args.first() {
        let _ = cli::args::parse_from(["ferusa", "get", "--", title.as_str()]);
        let _ = cli::args::parse_from(["ferusa", "edit", "--", title.as_str()]);
        let _ = cli::args::parse_from(["ferusa", "remove", "--", title.as_str()]);
    }

    let mut config = vec!["ferusa".to_owned(), "config".to_owned(), "set".to_owned()];
    config.extend(args);
    let _ = cli::args::parse_from(config);
});
