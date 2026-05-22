mod common;

use common::{sample_entry, vault_with_entries, TestContext};

#[cfg(feature = "dev-2fa-stub")]
#[test]
fn test_remove_success() {
    let ctx = TestContext::new();
    ctx.write_vault(
        "master_pw",
        vault_with_entries(vec![
            sample_entry("AWS", Some("root"), "aws-pass"),
            sample_entry("GitHub", Some("alice"), "gh-pass"),
        ]),
    );

    ctx.cmd(&["remove", "AWS"])
        .write_stdin("master_pw\ny\n")
        .assert()
        .success();

    let vault = ctx
        .read_vault("master_pw")
        .expect("read vault after remove");
    assert_eq!(vault.entries.len(), 1);
    assert!(vault.entries.iter().all(|entry| entry.title != "AWS"));
    assert!(vault.entries.iter().any(|entry| entry.title == "GitHub"));
}

#[cfg(not(feature = "dev-2fa-stub"))]
#[test]
fn test_remove_fails_when_unpaired() {
    let ctx = TestContext::new();
    ctx.write_vault(
        "master_pw",
        vault_with_entries(vec![
            sample_entry("AWS", Some("root"), "aws-pass"),
            sample_entry("GitHub", Some("alice"), "gh-pass"),
        ]),
    );

    ctx.cmd(&["remove", "AWS"])
        .write_stdin("master_pw\ny\n")
        .assert()
        .failure();

    let vault = ctx
        .read_vault("master_pw")
        .expect("read vault after failed remove");
    assert_eq!(vault.entries.len(), 2);
    assert!(vault.entries.iter().any(|entry| entry.title == "AWS"));
    assert!(vault.entries.iter().any(|entry| entry.title == "GitHub"));
}

#[cfg(feature = "dev-2fa-stub")]
#[test]
fn test_remove_abort() {
    let ctx = TestContext::new();
    ctx.write_vault(
        "master_pw",
        vault_with_entries(vec![
            sample_entry("AWS", Some("root"), "aws-pass"),
            sample_entry("GitHub", Some("alice"), "gh-pass"),
        ]),
    );

    ctx.cmd(&["remove", "AWS"])
        .write_stdin("master_pw\nn\n")
        .assert()
        .success();

    let vault = ctx.read_vault("master_pw").expect("read vault after abort");
    assert_eq!(vault.entries.len(), 2);
    assert!(vault.entries.iter().any(|entry| entry.title == "AWS"));
    assert!(vault.entries.iter().any(|entry| entry.title == "GitHub"));
}
