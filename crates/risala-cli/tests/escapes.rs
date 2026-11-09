//! Labels with terminal escapes, against a whole `risalad` with its key
//! log and a witness (risala-dev's world).
//!
//! Whoever saw a new device's QR code can answer it with an identity of
//! their own (4.8, step 5). Its device labels must not be able to rewrite
//! what the new device prints before it asks the user to confirm.

use std::io::{BufRead as _, Read as _, Write as _};
use std::path::Path;
use std::process::{Command, Stdio};

use risala_dev::{HOST, World};

/// Moves the cursor up two lines, clears that line, writes another uid
/// there, then reverses what follows.
const EVIL: &str = "x\u{1b}[2A\u{1b}[2K\ralice@example.org\u{9b}K\u{202e}";
const EVIL_SHOWN: &str = "x\\u{1b}[2A\\u{1b}[2K\\u{d}alice@example.org\\u{9b}K\\u{202e}";

fn risala(world: &World, state: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_risala"));
    cmd.arg("--state")
        .arg(state)
        .args(world.cli_args())
        .arg("--short-waits")
        .args(args)
        // No logs: their colours would hide what the CLI itself prints.
        .env("RISALA_LOG", "off");
    cmd
}

/// Runs to the end; its status and output.
async fn run(mut cmd: Command) -> (bool, String, String) {
    tokio::task::spawn_blocking(move || {
        let out = cmd.stdin(Stdio::null()).output().expect("running risala");
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    })
    .await
    .unwrap()
}

fn no_controls(out: &str) {
    assert!(
        !out.contains(['\u{1b}', '\r', '\u{9b}', '\u{202e}']),
        "{out:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn labels_with_escapes_are_printed_escaped() {
    let world = World::start().await;
    let root = tempfile::tempdir().unwrap();
    let mallory = root.path().join("mallory");
    let phone = root.path().join("phone");

    let (ok, out, err) = run(risala(&world, &mallory, &["create", HOST, "mallory", EVIL])).await;
    assert!(ok, "create failed: {err}");
    assert!(out.starts_with("mallory@example.org\n"), "{out}");

    let (ok, out, err) = run(risala(&world, &mallory, &["whoami"])).await;
    assert!(ok, "whoami failed: {err}");
    assert!(out.contains(EVIL_SHOWN), "{out}");
    no_controls(&out);

    // The new device asks; mallory answers its QR code with mallory's
    // identity; the user, shown it, declines.
    let mut pairing = risala(&world, &phone, &["pair", "new", HOST, "phone"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(pairing.stdin.take().unwrap(), "n").unwrap();
    let mut stdout = std::io::BufReader::new(pairing.stdout.take().unwrap());
    let (qr, mut stdout) = tokio::task::spawn_blocking(move || {
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        (line.trim().to_owned(), stdout)
    })
    .await
    .unwrap();
    assert!(qr.starts_with("RISALA-PAIR:"), "{qr}");
    let (ok, _, err) = run(risala(&world, &mallory, &["pair", "accept", &qr])).await;
    assert!(ok, "pair accept failed: {err}");
    let (status, out, err) = tokio::task::spawn_blocking(move || {
        let mut out = String::new();
        stdout.read_to_string(&mut out).unwrap();
        let mut err = String::new();
        pairing
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut err)
            .unwrap();
        (pairing.wait().unwrap(), out, err)
    })
    .await
    .unwrap();
    assert!(!status.success(), "pairing was declined: {out}\n{err}");
    assert!(out.starts_with("mallory@example.org\n"), "{out}");
    assert!(out.contains(&format!("\t{EVIL_SHOWN}\n")), "{out}");
    no_controls(&out);
    assert!(
        err.contains("join mallory@example.org? [y/N] "),
        "the question repeats the uid: {err}"
    );
    assert!(err.contains("risala: declined"), "{err}");
    no_controls(&err);
}
