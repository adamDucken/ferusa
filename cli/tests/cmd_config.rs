mod common;

use common::TestContext;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;

#[test]
fn test_config_set_and_get_clipboard_command() {
    let ctx = TestContext::new();

    ctx.cmd(&["config", "set", "--clear-after", "45", "wl-copy"])
        .write_stdin("y\n")
        .assert()
        .success()
        .stdout(contains("generated-password | wl-copy"));

    ctx.cmd(&["config", "get"])
        .assert()
        .success()
        .stdout(contains("wl-copy").and(contains("clear after: 45 seconds")));
}

#[test]
fn test_config_set_rejects_shell_injection() {
    let ctx = TestContext::new();

    ctx.cmd(&["config", "set", "wl-copy; rm -rf ~"])
        .assert()
        .failure()
        .stdout(contains("unsupported shell metacharacter"));

    ctx.cmd(&["config", "set", "rm", "-rf", "~"])
        .assert()
        .failure()
        .stdout(contains("unsupported clipboard command"));

    ctx.cmd(&["config", "set", "rm", "-rf", "/"])
        .assert()
        .failure()
        .stdout(contains("unsupported clipboard command"));

    ctx.cmd(&["config", "set", "/tmp/wl-copy"])
        .assert()
        .failure()
        .stdout(contains("bare executable name"));
}

#[test]
fn test_config_set_rejects_empty_confirmation() {
    let ctx = TestContext::new();

    ctx.cmd(&["config", "set", "wl-copy"])
        .write_stdin("\n")
        .assert()
        .failure()
        .stdout(contains("clipboard command not saved"));

    ctx.cmd(&["config", "get"]).assert().failure().stdout(
        contains("clipboard command is not configured").and(contains("ferusa config set wl-copy")),
    );
}
