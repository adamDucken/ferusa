mod common;

use common::{sample_entry_full, vault_with_entries, TestContext};

#[cfg(feature = "dev-2fa-stub")]
#[test]
fn test_edit_success_keep_and_change() {
    let ctx = TestContext::new();
    ctx.write_vault(
        "master_pw",
        vault_with_entries(vec![sample_entry_full(
            "GitHub",
            Some("alice"),
            "p1",
            Some("https://github.com"),
            Some("old note"),
            vec!["work"],
        )]),
    );
    ctx.configure_fake_clipboard();

    ctx.cmd(&["edit", "GitHub"])
        .write_stdin("master_pw\n\nbob\ng\n\n\n\n\n\n\n\n\n-\n")
        .assert()
        .success();

    let vault = ctx.read_vault("master_pw").expect("read edited vault");
    let entry = vault
        .entries
        .iter()
        .find(|entry| entry.title == "GitHub")
        .expect("find GitHub entry");

    assert_eq!(entry.username.as_deref(), Some("bob"));
    assert_ne!(entry.password, "p1");
    assert!(!entry.password.as_str().is_empty());
    assert_eq!(entry.url.as_deref(), Some("https://github.com"));
    assert_eq!(entry.notes.as_deref(), Some("old note"));
    assert!(entry.tags.is_empty());
}

#[cfg(not(feature = "dev-2fa-stub"))]
#[test]
fn test_edit_fails_when_unpaired() {
    let ctx = TestContext::new();
    ctx.write_vault(
        "master_pw",
        vault_with_entries(vec![sample_entry_full(
            "GitHub",
            Some("alice"),
            "p1",
            Some("https://github.com"),
            Some("old note"),
            vec!["work"],
        )]),
    );

    ctx.cmd(&["edit", "GitHub"])
        .write_stdin("master_pw\n")
        .assert()
        .failure();

    let vault = ctx
        .read_vault("master_pw")
        .expect("read vault after failed edit");
    let entry = vault
        .entries
        .iter()
        .find(|entry| entry.title == "GitHub")
        .expect("find GitHub entry");

    assert_eq!(entry.username.as_deref(), Some("alice"));
    assert_eq!(entry.password, "p1");
}
