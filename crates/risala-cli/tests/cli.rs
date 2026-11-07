//! The `risala` binary against a real server (`risala_server::testing`).

use std::io::{BufRead as _, BufReader, Write as _};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use risala_server::testing::{TestClient, TestServer};

/// Runs `risala --state <dir> <args>` and returns its output.
async fn risala(state: &Path, args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_risala"));
    cmd.arg("--state").arg(state).args(args);
    tokio::task::spawn_blocking(move || cmd.output().expect("running risala"))
        .await
        .unwrap()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Runs risala and expects it to succeed; returns its standard output.
async fn ok(state: &Path, args: &[&str]) -> String {
    let out = risala(state, args).await;
    assert!(
        out.status.success(),
        "risala {args:?} failed:\n{}\n{}",
        stdout(&out),
        stderr(&out)
    );
    stdout(&out)
}

/// Reads a test client's lines until one contains `needle`.
async fn wait_line(c: &mut TestClient, needle: &str) -> String {
    loop {
        let line = c.expect_line().await.unwrap();
        if line.contains(needle) {
            return line;
        }
    }
}

async fn ann_in(server: &TestServer, room: &str) -> TestClient {
    let mut ann = server.guest("ann").await;
    ann.send(&format!("JOIN {room}")).await.unwrap();
    wait_line(&mut ann, "OK id=").await;
    ann
}

#[tokio::test]
async fn trust_guest_join_send_log_sync_and_export() {
    let server = TestServer::builder()
        .room("#general")
        .welcome("hello there")
        .start()
        .await;
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path();
    let addr = format!("127.0.0.1:{}", server.addr().port());
    let fp = server.fingerprint().to_string();

    // First use: the fingerprint, and how to trust it (2.2).
    let out = risala(state, &["connect", &addr]).await;
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(err.contains(&fp), "{err}");
    assert!(err.contains(&format!("risala trust {addr} {fp}")), "{err}");
    // Accounts need trust too.
    assert!(
        !risala(state, &["guest", &addr, "sam"])
            .await
            .status
            .success()
    );

    let out = ok(state, &["trust", &addr, &fp]).await;
    assert!(out.contains(&fp));
    let out = ok(state, &["connect", &addr]).await;
    assert!(out.contains(&fp), "{out}");
    assert!(out.contains("hello there"), "{out}");
    assert!(out.contains("trusted on first use"), "{out}");

    let out = ok(state, &["guest", &addr, "sam"]).await;
    assert!(out.contains("as ~sam"), "{out}");
    let out = ok(state, &["list", &addr]).await;
    assert!(out.contains("#general"), "{out}");

    let mut ann = ann_in(&server, "#general").await;
    ok(state, &["join", &addr, "#general"]).await;
    let mut seq_line = String::new();
    let send = async { ok(state, &["send", &addr, "#general", "hi", "there;", "ann"]).await };
    let watch = async { seq_line = wait_line(&mut ann, "MSG #general hi there; ann").await };
    let (out, ()) = tokio::join!(send, watch);
    assert!(seq_line.contains("from=~sam"), "{seq_line}");
    let seq = out.trim().rsplit(' ').next().unwrap();
    assert!(
        seq_line.starts_with(&format!("@seq={seq};")),
        "{out} {seq_line}"
    );

    // ann writes while sam is offline; sync fetches it.
    ann.send("MSG #general welcome back\\nsam").await.unwrap();
    wait_line(&mut ann, "OK seq=").await;
    let out = ok(state, &["sync"]).await;
    assert!(out.contains("#general"), "{out}");
    let log = ok(state, &["log", &addr, "#general"]).await;
    assert!(log.contains("<~sam> hi there; ann"), "{log}");
    assert!(log.contains("<~ann> welcome back\n    sam"), "{log}");

    // Offline: log and export read the cache.
    let online_export = ok(state, &["export", &addr, "#general"]).await;
    let log = ok(state, &["log", &addr, "#general"]).await;
    server.stop().await;
    let offline_log = ok(state, &["log", &addr, "#general"]).await;
    assert_eq!(offline_log, log);
    let file = dir.path().join("general.txt");
    let out = risala(
        state,
        &["export", &addr, "#general", "-o", file.to_str().unwrap()],
    )
    .await;
    assert!(out.status.success());
    assert!(stderr(&out).contains("offline"), "{}", stderr(&out));
    let exported = std::fs::read_to_string(&file).unwrap();
    assert_eq!(exported, online_export);
    assert!(exported.lines().all(|l| l.starts_with("@seq=")));
    assert!(exported.contains(" MSG #general welcome back\\nsam\n"));

    // Sending offline queues the message, and says so.
    let out = risala(state, &["send", &addr, "#general", "later"]).await;
    assert!(!out.status.success());
    assert!(stderr(&out).contains("queued"), "{}", stderr(&out));
    let log = ok(state, &["log", &addr, "#general", "-n", "1"]).await;
    assert!(log.contains("(waiting to be sent) later"), "{log}");
}

#[tokio::test]
async fn chat_shows_live_messages_and_sends_lines() {
    let server = TestServer::builder().room("#general").start().await;
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path();
    let addr = format!("127.0.0.1:{}", server.addr().port());
    ok(state, &["trust", &addr, &server.fingerprint().to_string()]).await;
    ok(state, &["guest", &addr, "sam"]).await;
    let mut ann = ann_in(&server, "#general").await;
    ann.send("MSG #general before").await.unwrap();
    wait_line(&mut ann, "OK seq=").await;

    let mut child = Command::new(env!("CARGO_BIN_EXE_risala"))
        .arg("--state")
        .arg(state)
        .args(["chat", &addr, "#general"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // The child's output, read on a thread, waited for without blocking
    // the runtime the test server runs on.
    let (tx, mut lines) = tokio::sync::mpsc::unbounded_channel();
    let out = child.stdout.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(out).lines() {
            if tx.send(line.unwrap()).is_err() {
                break;
            }
        }
    });
    // Waits until every needle has been in a line, in any order.
    let mut expect = async |needles: &[&str]| {
        let mut left: Vec<&str> = needles.to_vec();
        let found = tokio::time::timeout(Duration::from_secs(30), async {
            while let Some(line) = lines.recv().await {
                left.retain(|n| !line.contains(n));
                if left.is_empty() {
                    return true;
                }
            }
            false
        })
        .await;
        assert!(matches!(found, Ok(true)), "waiting for {needles:?}");
    };
    // History, then live messages.
    expect(&["<~ann> before", "~sam joined"]).await;
    ann.send("MSG #general live one").await.unwrap();
    expect(&["<~ann> live one"]).await;
    // Typed lines are sent.
    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin, "typed by sam").unwrap();
    wait_line(&mut ann, "MSG #general typed by sam").await;
    expect(&["<~sam> typed by sam"]).await;
    writeln!(stdin, "/quit").unwrap();
    let status = tokio::task::spawn_blocking(move || child.wait().unwrap())
        .await
        .unwrap();
    assert!(status.success());
    // sam's connection is gone, but its session waits to be resumed
    // (4.2), so no PART is recorded.
    let history = sam_events(&mut ann, "#general").await;
    assert_eq!(history, ["JOIN", "MSG"]);
    server.stop().await;
}

/// The verbs of ~sam's events in `room`, from HISTORY.
async fn sam_events(c: &mut TestClient, room: &str) -> Vec<String> {
    c.send(&format!("@ref=h HISTORY {room} limit=500"))
        .await
        .unwrap();
    let mut verbs = Vec::new();
    loop {
        let line = c.expect_line().await.unwrap();
        if line.starts_with("@ref=h OK") {
            return verbs;
        }
        let by_sam = line.contains(";from=~sam ") || line.contains(";from=~sam;");
        if line.starts_with("@ref=h;") && by_sam {
            verbs.push(line.split(' ').nth(1).unwrap().to_owned());
        }
    }
}

/// Each command is a new connection, but the guest resumes its session
/// each time (4.2), so running `risala send` again and again adds only the
/// messages to the room: no JOIN and PART pairs.
#[tokio::test]
async fn sending_twice_resumes_the_guest_session() {
    let server = TestServer::builder().room("#general").start().await;
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path();
    let addr = format!("127.0.0.1:{}", server.addr().port());
    ok(state, &["trust", &addr, &server.fingerprint().to_string()]).await;
    ok(state, &["guest", &addr, "sam"]).await;
    ok(state, &["join", &addr, "#general"]).await;
    for text in ["one", "two", "three"] {
        let out = ok(state, &["send", &addr, "#general", text]).await;
        assert!(out.contains("sent"), "{out}");
    }
    let mut ann = ann_in(&server, "#general").await;
    let history = sam_events(&mut ann, "#general").await;
    assert_eq!(history, ["JOIN", "MSG", "MSG", "MSG"]);
    // Parting reaches the server, where the session is still in the room.
    let out = ok(state, &["part", &addr, "#general"]).await;
    assert!(out.contains("left #general"), "{out}");
    let history = sam_events(&mut ann, "#general").await;
    assert_eq!(history, ["JOIN", "MSG", "MSG", "MSG", "PART"]);
    server.stop().await;
}

#[tokio::test]
async fn keygen_and_keyline() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path();
    let line = ok(state, &["keygen", "alice@example.org", "--label", "laptop"]).await;
    let line = line.trim();
    assert!(line.starts_with("mldsa44 "), "{line}");
    assert!(line.ends_with(" laptop"), "{line}");
    let key = line.split(' ').nth(1).unwrap();
    assert_eq!(
        ok(state, &["keyline", "alice@example.org"]).await.trim(),
        format!("mldsa44 {key}")
    );
    // An existing key is kept unless asked.
    let out = risala(state, &["keygen", "alice@example.org"]).await;
    assert!(!out.status.success());
    assert!(stderr(&out).contains("--force"));
    let again = ok(state, &["keygen", "alice@example.org", "--force"]).await;
    assert_ne!(again.split(' ').nth(1).unwrap(), key);
    // The key file is private.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(state.join("keys/alice@example.org.pem"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    assert!(
        !risala(state, &["keyline", "bob@example.org"])
            .await
            .status
            .success()
    );
    assert!(
        !risala(state, &["keygen", "not-an-identity"])
            .await
            .status
            .success()
    );
}

#[tokio::test]
async fn several_accounts_need_as() {
    let server = TestServer::builder().room("#general").start().await;
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path();
    let addr = format!("127.0.0.1:{}", server.addr().port());
    ok(state, &["trust", &addr, &server.fingerprint().to_string()]).await;
    ok(state, &["guest", &addr, "sam"]).await;
    ok(state, &["guest", &addr, "kim"]).await;
    let out = risala(state, &["join", &addr, "#general"]).await;
    assert!(!out.status.success());
    assert!(stderr(&out).contains("--as"), "{}", stderr(&out));
    ok(state, &["--as", "~kim", "join", &addr, "#general"]).await;
    let log = ok(state, &["--as", "~kim", "log", &addr, "#general"]).await;
    assert!(log.contains("~kim joined"), "{log}");
    assert!(
        !risala(state, &["--as", "~sam", "log", &addr, "#general"])
            .await
            .status
            .success()
    );
    server.stop().await;
}

/// Posts `n` messages as `c`, and waits for every OK.
async fn post_many(c: &mut TestClient, room: &str, n: usize) {
    let lines: String = (0..n).map(|i| format!("MSG {room} m{i}\n")).collect();
    c.send_raw(lines.as_bytes()).await.unwrap();
    for _ in 0..n {
        wait_line(c, "OK seq=").await;
    }
}

#[tokio::test]
async fn trust_conflicts_permanent_failures_and_large_rooms() {
    use risala_server::store::{EventKind, NewEvent, Store as _};
    let server = TestServer::builder()
        .room("#general")
        .prepare(|store| {
            let key = store
                .room(&"#general".parse().unwrap())
                .unwrap()
                .unwrap()
                .key;
            for i in 0..450 {
                let event = NewEvent {
                    t: librisala::proto::time::Timestamp::now(),
                    from: "carol@example.org".parse().unwrap(),
                    kind: EventKind::Msg {
                        relation: None,
                        file: None,
                        text: format!("old {i}"),
                    },
                    cid: None,
                };
                store.append(key, &event).unwrap();
            }
        })
        .start()
        .await;
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path();
    let addr = format!("127.0.0.1:{}", server.addr().port());
    let fp = server.fingerprint().to_string();
    ok(state, &["trust", &addr, &fp]).await;
    ok(state, &["guest", &addr, "sam"]).await;
    ok(state, &["join", &addr, "#general"]).await;

    // More than 1000 events stored: join counts them all.
    let mut ann = ann_in(&server, "#general").await;
    post_many(&mut ann, "#general", 450).await;
    ok(state, &["sync"]).await;
    post_many(&mut ann, "#general", 150).await;
    ok(state, &["sync"]).await;
    let stored = ok(state, &["export", &addr, "#general"])
        .await
        .lines()
        .count();
    assert!(stored > 1000, "{stored}");
    let out = ok(state, &["join", &addr, "#general"]).await;
    assert!(
        out.contains(&format!("({stored} events stored)")),
        "{out}, {stored}"
    );

    // Trusting a fingerprint over another record: not an attack, just a
    // record in the way.
    ok(state, &["untrust", &addr]).await;
    let other = format!("sha256:{}", "0".repeat(64));
    ok(state, &["trust", &addr, &other]).await;
    let out = risala(state, &["trust", &addr, &fp]).await;
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(err.contains("already trusted"), "{err}");
    assert!(err.contains(&format!("risala untrust {addr}")), "{err}");
    assert!(
        !err.contains("attack") && !err.contains("Presented"),
        "{err}"
    );

    // A send that cannot connect for good does not promise the next
    // connection will do.
    let out = risala(state, &["send", &addr, "#general", "stuck"]).await;
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(err.contains("does not match"), "{err}");
    assert!(err.contains("cannot be sent until that is fixed"), "{err}");
    assert!(!err.contains("next connection"), "{err}");
}
