mod common;

use common::{exists, TestContext};
use predicates::str::contains;

#[cfg(feature = "dev-2fa-stub")]
#[test]
fn test_init_success() {
    let ctx = TestContext::new();

    assert!(!exists(&ctx.vault_enc()));

    ctx.cmd(&["init"])
        .write_stdin("my_password123\nmy_password123\n")
        .assert()
        .success();

    assert!(exists(&ctx.vault_enc()));
    assert!(exists(&ctx.vault_salt()));
    assert!(exists(&ctx.dev_2fa_stub_marker()));

    let vault = ctx.read_vault("my_password123").expect("decrypt new vault");
    assert_eq!(vault.version, 1);
    assert!(vault.entries.is_empty());
}

#[cfg(feature = "dev-2fa-stub")]
#[test]
fn test_init_dev_stub_requires_explicit_env() {
    let ctx = TestContext::new();
    let mut cmd = ctx.cmd(&["init"]);
    cmd.env_remove("FERUSA_ALLOW_DEV_2FA_STUB");

    cmd.write_stdin("my_password123\nmy_password123\n")
        .assert()
        .failure()
        .stdout(contains("FERUSA_ALLOW_DEV_2FA_STUB=1"));

    assert!(!exists(&ctx.vault_enc()));
    assert!(!exists(&ctx.dev_2fa_stub_marker()));
}

#[cfg(not(feature = "dev-2fa-stub"))]
#[test]
fn test_init_rejects_dev_stub_marker() {
    let ctx = TestContext::new();
    std::fs::create_dir_all(ctx.data_dir()).expect("create data dir");
    std::fs::write(
        ctx.dev_2fa_stub_marker(),
        br#"{
  "version": 1,
  "warning": "This vault was created with the deterministic dev 2FA stub and is not production-compatible."
}"#,
    )
    .expect("write dev marker");

    ctx.cmd(&["init"])
        .write_stdin("my_password123\nmy_password123\n")
        .assert()
        .failure()
        .stdout(contains("not production-compatible"));

    assert!(!exists(&ctx.vault_enc()));
}

#[test]
fn test_init_mismatch() {
    let ctx = TestContext::new();

    ctx.cmd(&["init"])
        .write_stdin("pass1234\npass5678\n")
        .assert()
        .failure();

    assert!(!exists(&ctx.vault_enc()));
    assert!(!exists(&ctx.vault_salt()));
}

#[test]
fn test_init_already_exists() {
    let ctx = TestContext::new();
    ctx.init_vault("old_password");

    let before = std::fs::read(ctx.vault_enc()).expect("read original vault");

    ctx.cmd(&["init"]).assert().failure();

    let after = std::fs::read(ctx.vault_enc()).expect("read vault after failed init");
    assert_eq!(before, after);

    let vault = ctx
        .read_vault("old_password")
        .expect("decrypt original vault");
    assert!(vault.entries.is_empty());
}
