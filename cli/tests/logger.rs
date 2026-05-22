mod common;

use common::TestContext;

#[cfg(unix)]
#[test]
fn logger_creates_private_directory_and_file() {
    use std::os::unix::fs::PermissionsExt;

    let ctx = TestContext::new();

    ctx.cmd(&["config", "get"]).assert().failure();

    let data_mode = std::fs::metadata(ctx.data_dir())
        .expect("stat data dir")
        .permissions()
        .mode()
        & 0o777;
    let log_mode = std::fs::metadata(ctx.data_dir().join("ferusa.log"))
        .expect("stat log file")
        .permissions()
        .mode()
        & 0o777;

    assert_eq!(data_mode, 0o700);
    assert_eq!(log_mode, 0o600);
}

#[cfg(unix)]
#[test]
fn logger_repairs_permissions_and_redacts_sensitive_metadata() {
    use std::os::unix::fs::PermissionsExt;

    const SENSITIVE_TITLE: &str = "private-entry-title";

    let ctx = TestContext::new();
    std::fs::create_dir_all(ctx.data_dir()).expect("create data dir");
    std::fs::set_permissions(ctx.data_dir(), std::fs::Permissions::from_mode(0o755))
        .expect("set ambient data dir permissions");

    let log_path = ctx.data_dir().join("ferusa.log");
    std::fs::write(&log_path, b"existing log\n").expect("write log");
    std::fs::set_permissions(&log_path, std::fs::Permissions::from_mode(0o644))
        .expect("set ambient log permissions");

    ctx.cmd(&["get", SENSITIVE_TITLE]).assert().failure();

    let data_mode = std::fs::metadata(ctx.data_dir())
        .expect("stat data dir")
        .permissions()
        .mode()
        & 0o777;
    let log_mode = std::fs::metadata(&log_path)
        .expect("stat log file")
        .permissions()
        .mode()
        & 0o777;
    let log = std::fs::read_to_string(log_path).expect("read log");

    assert_eq!(data_mode, 0o700);
    assert_eq!(log_mode, 0o600);
    assert!(log.contains("dispatching Get"));
    assert!(!log.contains(SENSITIVE_TITLE));
}
