//! The room and ADMIN subcommands of the `risala` binary against a real
//! server (`risala_server::testing`): deleting, reports, settings,
//! moderation and administration (5.4, 5.8, 6.2-6.4, Section 10).
//!
//! The operator signs in as `op@example.org`, whose key file the test key
//! server serves. Identities sign the server's hostname (4.5), so the
//! binary connects to `localhost`, the test server's name, rather than to
//! 127.0.0.1.

use std::path::Path;
use std::process::{Command, Output};

use risala_proto::auth::PublicKey;
use risala_proto::names::Identity;
use risala_server::testing::{TestClient, TestServer};

/// Runs `risala --state <dir> <args>`.
async fn risala(state: &Path, args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_risala"));
    cmd.arg("--state").arg(state).args(args);
    tokio::task::spawn_blocking(move || cmd.output().expect("running risala"))
        .await
        .unwrap()
}

/// Runs risala and expects exit code `code`; returns standard output and
/// standard error.
async fn run(state: &Path, args: &[&str], code: i32) -> (String, String) {
    let out = risala(state, args).await;
    let (stdout, stderr) = (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    );
    assert_eq!(
        out.status.code(),
        Some(code),
        "risala {args:?}:\n{stdout}\n{stderr}"
    );
    (stdout, stderr)
}

/// Runs risala and expects it to succeed; returns its standard output.
async fn ok(state: &Path, args: &[&str]) -> String {
    run(state, args, 0).await.0
}

/// Reads a test client's lines until one contains `needle`.
async fn wait_line(c: &mut TestClient, needle: &str) -> String {
    let wait = async {
        loop {
            let line = c.expect_line().await.unwrap();
            if line.contains(needle) {
                return line;
            }
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(30), wait)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {needle:?}"))
}

#[tokio::test]
async fn an_operator_reviews_moderates_and_administers() {
    let server = TestServer::builder()
        .room("#general")
        .key_domains(&["example.org"])
        .configure(|c| c.operators = vec!["op@example.org".into()])
        .start()
        .await;
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path();
    let addr = format!("localhost:{}", server.addr().port());
    ok(state, &["trust", &addr, &server.fingerprint().to_string()]).await;

    // A new device key, published, then signed in.
    let (line, _) = run(state, &["login", &addr, "op@example.org"], 3).await;
    let key: PublicKey = line.split_whitespace().nth(1).unwrap().parse().unwrap();
    let op: Identity = "op@example.org".parse().unwrap();
    server.key_server().add_key(&op, &key, Some("laptop"));
    let out = ok(state, &["login", &addr, "op@example.org"]).await;
    assert!(out.contains("as op@example.org"), "{out}");

    // A guest posts something to report.
    let mut ann = server.guest("ann").await;
    ann.send("JOIN #general").await.unwrap();
    wait_line(&mut ann, "OK id=").await;
    ann.send("MSG #general cheap pills").await.unwrap();
    let ok_line = wait_line(&mut ann, "OK seq=").await;
    let spam = ok_line.rsplit('=').next().unwrap().to_owned();
    ok(state, &["join", &addr, "#general"]).await;

    // Reports (5.8): the operator sees who reported.
    let id = ok(state, &["report", &addr, "#general", &spam, "spam"]).await;
    let id = id.trim();
    let listed = ok(state, &["admin", "reports", &addr]).await;
    assert!(listed.contains(id), "{listed}");
    assert!(listed.contains("by op@example.org: spam"), "{listed}");
    assert!(listed.contains("<~ann> cheap pills"), "{listed}");
    let listed = ok(state, &["reports", &addr, "#general"]).await;
    assert!(listed.contains(id), "{listed}");
    let out = ok(state, &["resolve", &addr, id]).await;
    assert!(out.contains("resolved"), "{out}");
    assert!(ok(state, &["admin", "reports", &addr]).await.is_empty());

    // Deleting someone else's message, with owner rights (5.4, 10).
    let out = ok(state, &["delete", &addr, "#general", &spam]).await;
    assert!(out.contains(&format!("deleted {spam}")), "{out}");
    wait_line(&mut ann, &format!("DELETE #general {spam}")).await;

    // Settings and moderation (6.2, 6.4).
    ok(state, &["topic", &addr, "#general", "be", "nice"]).await;
    wait_line(&mut ann, "SET #general topic be nice").await;
    let info = ok(state, &["info", &addr, "#general"]).await;
    assert!(info.contains("topic be nice"), "{info}");
    let out = ok(state, &["kick", &addr, "#general", "~ann", "calm", "down"]).await;
    assert!(out.contains("kicked ~ann"), "{out}");
    wait_line(&mut ann, "KICK #general ~ann calm down").await;
    let out = ok(
        state,
        &["ban", &addr, "#general", "spam@example.org", "spam"],
    )
    .await;
    assert!(out.contains("banned"), "{out}");
    let bans = ok(state, &["bans", &addr, "#general"]).await;
    assert_eq!(bans.trim(), "spam@example.org spam");
    // A refusal is reported with the server's code.
    let (_, err) = run(
        state,
        &["unban", &addr, "#general", "nobody@example.org"],
        1,
    )
    .await;
    assert!(err.contains("not-found"), "{err}");

    // Administration (Section 10).
    let ops = ok(state, &["admin", "ops", &addr]).await;
    assert_eq!(ops.trim(), "op@example.org");
    ok(state, &["admin", "notice", &addr, "back", "at", "noon"]).await;
    wait_line(&mut ann, "NOTICE back at noon").await;
    let who = ok(state, &["admin", "who", &addr]).await;
    assert!(who.contains("~ann 127.0.0.1:"), "{who}");
    let rooms = ok(state, &["admin", "rooms", &addr]).await;
    assert!(rooms.contains("#general (1 member): be nice"), "{rooms}");
    ok(state, &["admin", "set", &addr, "welcome", "hello", "again"]).await;
    let out = ok(state, &["admin", "drop", &addr, "#general", "closing"]).await;
    assert!(out.contains("dropped #general"), "{out}");
    server.stop().await;
}
