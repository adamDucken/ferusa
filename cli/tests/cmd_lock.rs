mod common;

use common::TestContext;
use predicates::prelude::*;

#[test]
fn standalone_lock_is_rejected_instead_of_claiming_to_lock_another_process() {
    let ctx = TestContext::new();
    ctx.init_vault("master_pw");

    ctx.cmd(&["lock"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("unrecognized subcommand 'lock'"));
}
