#![cfg(feature = "dev-2fa-stub")]

mod common;

use std::io::{Read, Write};
use std::process::{Child, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use common::TestContext;

#[cfg(feature = "dev-2fa-stub")]
#[test]
fn test_repl_holds_vault_lock_against_one_shot_command() {
    let ctx = TestContext::new();
    ctx.init_vault("master_pw");

    let mut repl = spawn_cli(&ctx, &[]);
    let repl_stdout = repl.stdout.take().expect("repl stdout");
    let repl_rx = read_output(repl_stdout);
    let mut repl_stdin = repl.stdin.take().expect("repl stdin");

    repl_stdin.write_all(b"master_pw\n").expect("unlock repl");
    wait_for(&repl_rx, "ferusa:", Duration::from_secs(15));

    let mut one_shot = spawn_cli(&ctx, &["list"]);
    let one_shot_stdout = one_shot.stdout.take().expect("one-shot stdout");
    let one_shot_rx = read_output(one_shot_stdout);
    let mut one_shot_stdin = one_shot.stdin.take().expect("one-shot stdin");

    assert_not_seen(
        &one_shot_rx,
        "provide master password",
        Duration::from_millis(500),
    );

    repl_stdin.write_all(b"exit\n").expect("exit repl");
    let repl_status = repl.wait().expect("wait repl");
    assert!(repl_status.success(), "REPL process should exit cleanly");

    wait_for(
        &one_shot_rx,
        "provide master password",
        Duration::from_secs(15),
    );
    one_shot_stdin
        .write_all(b"master_pw\n")
        .expect("unlock one-shot list");
    let one_shot_status = one_shot.wait().expect("wait one-shot");
    assert!(
        one_shot_status.success(),
        "one-shot list should exit cleanly"
    );
}

#[cfg(feature = "dev-2fa-stub")]
#[test]
fn test_repl_list_requires_fresh_approval_after_unlock() {
    let ctx = TestContext::new();
    ctx.init_vault("master_pw");

    let mut repl = spawn_cli(&ctx, &[]);
    let repl_stdout = repl.stdout.take().expect("repl stdout");
    let repl_rx = read_output(repl_stdout);
    let mut repl_stdin = repl.stdin.take().expect("repl stdin");

    repl_stdin.write_all(b"master_pw\n").expect("unlock repl");
    wait_for(&repl_rx, "ferusa:", Duration::from_secs(15));

    repl_stdin.write_all(b"list\n").expect("list vault");
    wait_for(
        &repl_rx,
        "approve 2FA request for LIST",
        Duration::from_secs(15),
    );

    repl_stdin.write_all(b"exit\n").expect("exit repl");
    let repl_status = repl.wait().expect("wait repl");
    assert!(repl_status.success(), "REPL process should exit cleanly");
}

#[cfg(feature = "dev-2fa-stub")]
#[test]
fn test_two_mutating_processes_do_not_lose_updates() {
    let ctx = TestContext::new();
    ctx.init_vault("master_pw");
    ctx.configure_fake_clipboard();

    let mut add_alpha = spawn_cli(&ctx, &["add", "Alpha"]);
    let mut add_beta = spawn_cli(&ctx, &["add", "Beta"]);

    add_alpha
        .stdin
        .as_mut()
        .expect("alpha stdin")
        .write_all(b"master_pw\nalice\n\n\n\n\n\n\n\n\nwork\n")
        .expect("write alpha input");
    add_beta
        .stdin
        .as_mut()
        .expect("beta stdin")
        .write_all(b"master_pw\nbob\n\n\n\n\n\n\n\n\npersonal\n")
        .expect("write beta input");

    let alpha_status = add_alpha.wait().expect("wait alpha add");
    let beta_status = add_beta.wait().expect("wait beta add");
    assert!(alpha_status.success(), "alpha add should succeed");
    assert!(beta_status.success(), "beta add should succeed");

    let vault = ctx.read_vault("master_pw").expect("read vault");
    let mut titles = vault
        .entries
        .iter()
        .map(|entry| entry.title.as_str())
        .collect::<Vec<_>>();
    titles.sort_unstable();
    assert_eq!(titles, ["Alpha", "Beta"]);
}

fn spawn_cli(ctx: &TestContext, args: &[&str]) -> Child {
    let mut cmd = ctx.process_cmd(args);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ferusa under script pty")
}

fn read_output(mut stdout: impl Read + Send + 'static) -> Receiver<String> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match stdout.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if tx
                        .send(String::from_utf8_lossy(&buf[..n]).to_string())
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    rx
}

fn wait_for(rx: &Receiver<String>, needle: &str, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    let mut output = String::new();

    while !output.contains(needle) {
        let now = Instant::now();
        assert!(
            now < deadline,
            "timed out waiting for {needle:?}; output so far:\n{output}"
        );

        let remaining = deadline.saturating_duration_since(now);
        match rx.recv_timeout(remaining.min(Duration::from_millis(250))) {
            Ok(chunk) => output.push_str(&chunk),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("process output ended before {needle:?}; output:\n{output}");
            }
        }
    }

    output
}

fn assert_not_seen(rx: &Receiver<String>, needle: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    let mut output = String::new();

    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(50))) {
            Ok(chunk) => {
                output.push_str(&chunk);
                assert!(
                    !output.contains(needle),
                    "unexpectedly saw {needle:?}; output:\n{output}"
                );
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
}
