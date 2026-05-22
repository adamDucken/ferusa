mod common;

use common::{sample_entry, vault_with_entries, TestContext};

#[cfg(feature = "dev-2fa-stub")]
#[test]
fn test_add_success_manual_password() {
    let ctx = TestContext::new();
    ctx.init_vault("master_pw");
    ctx.configure_fake_clipboard();
    assert!(ctx.read_vault("master_pw").unwrap().entries.is_empty());

    ctx.cmd(&["add", "GitHub"])
        .write_stdin("master_pw\nalice\n\n\n\n\n\n\n\n\nwork, social\n")
        .assert()
        .success();

    let vault = ctx.read_vault("master_pw").expect("read updated vault");
    assert_eq!(vault.entries.len(), 1);
    let entry = &vault.entries[0];
    assert_eq!(entry.title, "GitHub");
    assert_eq!(entry.username.as_deref(), Some("alice"));
    assert!(!entry.password.as_str().is_empty());
    assert_eq!(entry.tags, vec!["work", "social"]);
}

#[cfg(not(feature = "dev-2fa-stub"))]
#[test]
fn test_add_fails_when_unpaired() {
    let ctx = TestContext::new();
    ctx.init_vault("master_pw");

    ctx.cmd(&["add", "GitHub"])
        .write_stdin("master_pw\n")
        .assert()
        .failure();

    let vault = ctx
        .read_vault("master_pw")
        .expect("read vault after failed add");
    assert!(vault.entries.is_empty());
}

#[test]
fn test_add_duplicate_title() {
    let ctx = TestContext::new();
    ctx.write_vault(
        "master_pw",
        vault_with_entries(vec![sample_entry("GitHub", Some("alice"), "secret123")]),
    );

    ctx.cmd(&["add", "GitHub"])
        .write_stdin("master_pw\n")
        .assert()
        .failure();

    let vault = ctx
        .read_vault("master_pw")
        .expect("read vault after rejected add");
    assert_eq!(vault.entries.len(), 1);
    assert_eq!(vault.entries[0].title, "GitHub");
}
