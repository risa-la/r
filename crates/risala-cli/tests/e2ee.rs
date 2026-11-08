//! End-to-end encryption with the `risala` binary against a real server
//! (`risala_server::testing`): M5a's definition of done (PLAN.md section
//! 4). Each device is a state directory of its own, and each command a
//! process of its own, so everything between commands goes through the
//! cache.
//!
//! The server hosts identities under `chat.test`. The binary reaches it,
//! and the key files it publishes, through the test hooks of debug builds
//! (`RISALA_TEST_CONNECT`, `RISALA_TEST_KEY_HOST`, `RISALA_TEST_KEY_CA`).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use risala_server::testing::TestServer;

const HOST: &str = "chat.test";

/// A server hosting identities under `chat.test`, and how the binary
/// reaches it.
struct Net {
    server: TestServer,
    /// The server as the binary names it: `chat.test:<port>`.
    addr: String,
    /// The test CA, in DER, for the key file host.
    ca: PathBuf,
    _dir: tempfile::TempDir,
}

impl Net {
    async fn start(operators: &[&str]) -> Net {
        let ops: Vec<String> = operators.iter().map(|s| (*s).to_owned()).collect();
        let server = TestServer::builder()
            .hostname(HOST)
            .configure(move |c| {
                c.identity_domain = Some(HOST.to_owned());
                c.server.registration = true;
                c.limits.registrations_per_hour = 0;
                c.operators.extend(ops);
            })
            .start()
            .await;
        let dir = tempfile::tempdir().unwrap();
        let ca = dir.path().join("ca.der");
        std::fs::write(&ca, server.key_server().ca().as_ref()).unwrap();
        let addr = format!("{HOST}:{}", server.addr().port());
        Net {
            server,
            addr,
            ca,
            _dir: dir,
        }
    }

    /// A new device: an empty state directory that trusts the server.
    async fn device(&self) -> Device {
        let dir = tempfile::tempdir().unwrap();
        let device = Device { dir };
        let fp = self.server.fingerprint().to_string();
        self.ok(&device, &["trust", &self.addr, &fp]).await;
        device
    }

    /// Runs `risala --state <device> <args>`, with `server` reached at
    /// `at`.
    async fn run_at(&self, device: &Device, at: &str, args: &[&str]) -> Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_risala"));
        cmd.arg("--state")
            .arg(device.path())
            .args(args)
            .env("RISALA_TEST_CONNECT", at)
            .env(
                "RISALA_TEST_KEY_HOST",
                format!("{HOST}={}", self.server.key_server().addr(HOST)),
            )
            .env("RISALA_TEST_KEY_CA", &self.ca);
        tokio::task::spawn_blocking(move || cmd.output().expect("running risala"))
            .await
            .unwrap()
    }

    async fn run(&self, device: &Device, args: &[&str]) -> Output {
        let at = self.server.addr().to_string();
        self.run_at(device, &at, args).await
    }

    /// Runs risala and expects it to succeed; returns its standard output.
    async fn ok(&self, device: &Device, args: &[&str]) -> String {
        let out = self.run(device, args).await;
        assert!(
            out.status.success(),
            "risala {args:?} failed:\n{}\n{}",
            stdout(&out),
            stderr(&out)
        );
        stdout(&out)
    }

    /// Syncs once, then runs `log` and expects every one of `want` in it:
    /// each command finishes what its connection started, so one `sync`
    /// brings everything the others sent.
    async fn log_until(&self, device: &Device, conv: &str, want: &[&str]) -> String {
        self.ok(device, &["sync", &self.addr]).await;
        let log = self.ok(device, &["log", &self.addr, conv]).await;
        for w in want {
            assert!(log.contains(w), "{conv} does not show {w:?}:\n{log}");
        }
        assert!(!log.contains("waiting for its key"), "{log}");
        log
    }

    /// Registers `<name>@chat.test` on a new device.
    async fn registered(&self, name: &str) -> Device {
        let device = self.device().await;
        let out = self.ok(&device, &["register", &self.addr, name]).await;
        assert!(out.starts_with(&format!("{name}@{HOST}\n")), "{out}");
        device
    }

    /// A new device of `uid`, whose key `of` adds (4.7), signed in.
    async fn second_device(&self, of: &Device, uid: &str) -> Device {
        let device = self.device().await;
        let line = self.ok(&device, &["keygen", uid]).await;
        let line = line
            .lines()
            .find(|l| l.contains("ML-DSA-44"))
            .unwrap_or(&line);
        let mut args = vec!["keys", "add", &self.addr];
        args.extend(line.split_whitespace());
        self.ok(of, &args).await;
        self.ok(&device, &["login", &self.addr, uid]).await;
        device
    }
}

struct Device {
    dir: tempfile::TempDir,
}

impl Device {
    fn path(&self) -> &Path {
        self.dir.path()
    }
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// The fingerprint `devices` marks as waiting for confirmation.
fn new_device(devices: &str) -> Option<String> {
    devices
        .lines()
        .find(|l| l.contains("new: confirm it"))
        .map(|l| l.split_whitespace().next().unwrap().to_owned())
}

/// The recovery key that `recovery create` printed.
fn recovery_key(out: &str) -> String {
    out.lines()
        .find(|l| l.starts_with("    "))
        .expect("the recovery key")
        .trim()
        .to_owned()
}

/// The seq of the message with `text` in a `log`.
fn seq_of(log: &str, text: &str) -> String {
    let line = log.lines().find(|l| l.ends_with(text)).expect(text);
    line[1..line.find(']').unwrap()].to_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_devices_talk_encrypted_and_new_devices_read_the_history() {
    let net = Net::start(&[]).await;
    let alice = net.registered("alice").await;
    let bob = net.registered("bob").await;
    let addr = net.addr.clone();

    // A direct conversation is always encrypted (12.3).
    net.ok(&alice, &["send", &addr, "bob@chat.test", "hello", "bob"])
        .await;
    net.log_until(&bob, "alice@chat.test", &["<alice@chat.test> hello bob"])
        .await;
    net.ok(&bob, &["send", &addr, "alice@chat.test", "hi", "alice"])
        .await;
    net.log_until(&alice, "bob@chat.test", &["<bob@chat.test> hi alice"])
        .await;

    // An encrypted room: Alice makes it, encrypts it, writes, and invites
    // Bob, who reads what came before him (12.6, 12.9).
    net.ok(&alice, &["join", &addr, "#secret"]).await;
    let out = net.ok(&alice, &["encrypt", &addr, "#secret"]).await;
    assert!(out.contains("#secret is end-to-end encrypted"), "{out}");
    net.ok(&alice, &["send", &addr, "#secret", "before", "bob"])
        .await;
    let out = net
        .ok(&alice, &["invite", &addr, "#secret", "bob@chat.test"])
        .await;
    assert!(out.contains("invited bob@chat.test"), "{out}");
    net.ok(&bob, &["join", &addr, "#secret"]).await;
    net.log_until(&bob, "#secret", &["<alice@chat.test> before bob"])
        .await;
    net.ok(&bob, &["send", &addr, "#secret", "hi", "all"]).await;
    net.log_until(&alice, "#secret", &["<bob@chat.test> hi all"])
        .await;

    // The server never had the text.
    let export = net.ok(&alice, &["export", &addr, "#secret"]).await;
    assert!(!export.contains("before bob"), "{export}");
    assert!(export.contains(" ENC #secret "), "{export}");

    // A new device of Alice's joins her conversations, and reads nothing
    // from before it until she confirms it on her first device (12.9).
    let alice2 = net.second_device(&alice, "alice@chat.test").await;
    net.ok(&alice2, &["sync", &addr]).await;
    let log = net.ok(&alice2, &["log", &addr, "bob@chat.test"]).await;
    assert!(log.contains("(encrypted; waiting for its key)"), "{log}");
    let devices = net.ok(&alice, &["devices", &addr]).await;
    let fingerprint = new_device(&devices).expect(&devices);
    let out = net.ok(&alice, &["confirm", &addr, &fingerprint]).await;
    assert!(out.contains("gets the history keys"), "{out}");
    net.ok(&alice2, &["sync", &addr]).await;

    // Offline, it reads the whole history: nothing listens where the
    // server was said to be.
    let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let nowhere = dead.local_addr().unwrap().to_string();
    drop(dead);
    for (conv, want) in [
        (
            "bob@chat.test",
            ["<alice@chat.test> hello bob", "<bob@chat.test> hi alice"],
        ),
        (
            "#secret",
            ["<alice@chat.test> before bob", "<bob@chat.test> hi all"],
        ),
    ] {
        let out = net.run_at(&alice2, &nowhere, &["log", &addr, conv]).await;
        assert!(out.status.success(), "{}", stderr(&out));
        let log = stdout(&out);
        for w in want {
            assert!(log.contains(w), "{conv}: {w}:\n{log}");
        }
        assert!(!log.contains("waiting for its key"), "{log}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recovery_key_restores_the_history_and_the_identity() {
    let net = Net::start(&[]).await;
    let alice = net.registered("alice").await;
    let bob = net.registered("bob").await;
    let addr = net.addr.clone();
    net.ok(&alice, &["send", &addr, "bob@chat.test", "one"])
        .await;
    net.ok(&alice, &["join", &addr, "#secret"]).await;
    net.ok(&alice, &["encrypt", &addr, "#secret"]).await;
    net.ok(&alice, &["send", &addr, "#secret", "in", "the", "room"])
        .await;

    // A recovery key, shown once; its key goes in the key file (12.10).
    let out = net.ok(&alice, &["recovery", "create", &addr]).await;
    let key = recovery_key(&out);
    assert_eq!(key.len(), 64, "{key}");
    let keys = net.ok(&alice, &["keys", "list", &addr]).await;
    assert!(keys.contains("recovery"), "{keys}");
    net.ok(&bob, &["send", &addr, "alice@chat.test", "two"])
        .await;
    net.log_until(&alice, "bob@chat.test", &["<bob@chat.test> two"])
        .await;

    // A new device, never confirmed, restores the history keys from the
    // backup.
    let alice2 = net.second_device(&alice, "alice@chat.test").await;
    let mut args = vec!["recovery", "restore", addr.as_str()];
    args.extend(key.split_whitespace());
    let out = net.ok(&alice2, &args).await;
    assert!(out.starts_with("restored "), "{out}");
    net.log_until(
        &alice2,
        "bob@chat.test",
        &["<alice@chat.test> one", "<bob@chat.test> two"],
    )
    .await;

    // A wrong key restores nothing.
    let wrong = "aaaa ".repeat(13);
    let mut args = vec!["recovery", "restore", addr.as_str()];
    args.extend(wrong.split_whitespace());
    assert!(!net.run(&alice2, &args).await.status.success());

    // Every device is lost. On a new one, the recovery key gets the
    // identity back: this device's key replaces the lost ones, and the
    // history comes from the backup.
    drop((alice, alice2));
    let alice3 = net.device().await;
    let mut args = vec!["recover", addr.as_str(), "alice@chat.test"];
    args.extend(key.split_whitespace());
    let out = net.ok(&alice3, &args).await;
    assert!(
        out.contains("alice@chat.test is back on this device"),
        "{out}"
    );
    let keys = net.ok(&alice3, &["keys", "list", &addr]).await;
    assert_eq!(
        keys.lines().count(),
        2,
        "this device and the recovery key:\n{keys}"
    );
    net.log_until(
        &alice3,
        "bob@chat.test",
        &["<alice@chat.test> one", "<bob@chat.test> two"],
    )
    .await;
    // The rooms come back too, and she writes again.
    net.log_until(&alice3, "#secret", &["<alice@chat.test> in the room"])
        .await;
    net.ok(&alice3, &["send", &addr, "bob@chat.test", "back"])
        .await;
    net.log_until(&bob, "alice@chat.test", &["<alice@chat.test> back"])
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_report_of_an_encrypted_message_verifies_for_the_operator() {
    let net = Net::start(&["olga@chat.test"]).await;
    let olga = net.registered("olga").await;
    let alice = net.registered("alice").await;
    let bob = net.registered("bob").await;
    let addr = net.addr.clone();
    net.ok(
        &alice,
        &["send", &addr, "bob@chat.test", "something", "awful"],
    )
    .await;
    let log = net
        .log_until(&bob, "alice@chat.test", &["something awful"])
        .await;
    let seq = seq_of(&log, "something awful");

    // Bob reports it: REPORTENC reveals the content (5.8).
    let out = net
        .ok(
            &bob,
            &["report", &addr, "alice@chat.test", &seq, "harassment"],
        )
        .await;
    assert!(!out.trim().is_empty());

    // The operator reads it, checked against the franking commitment.
    let reports = net.ok(&olga, &["admin", "reports", &addr]).await;
    assert!(
        reports.contains("(encrypted, content verified)"),
        "{reports}"
    );
    assert!(
        reports.contains("<alice@chat.test> something awful"),
        "{reports}"
    );
    assert!(reports.contains("harassment"), "{reports}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encrypt_needs_an_owner_alone_in_the_room() {
    let net = Net::start(&[]).await;
    let alice = net.registered("alice").await;
    let bob = net.registered("bob").await;
    let addr = net.addr.clone();
    net.ok(&alice, &["join", &addr, "#busy"]).await;
    net.ok(&bob, &["join", &addr, "#busy"]).await;

    // Bob does not own it, and Alice is not alone in it (12.5).
    for who in [&bob, &alice] {
        let out = net.run(who, &["encrypt", &addr, "#busy"]).await;
        assert!(!out.status.success(), "{}", stdout(&out));
        assert!(
            stderr(&out).contains("#busy was not encrypted"),
            "{}",
            stderr(&out)
        );
    }

    // Alone in a room of her own, with announcements and joined history.
    net.ok(&alice, &["join", &addr, "#news"]).await;
    let out = net
        .ok(
            &alice,
            &["encrypt", &addr, "#news", "--joined", "--announcements"],
        )
        .await;
    assert!(out.contains("#news is end-to-end encrypted"), "{out}");
    let info = net.ok(&alice, &["info", &addr, "#news"]).await;
    for setting in ["e2ee yes", "public no", "history joined", "send mods"] {
        assert!(info.contains(setting), "{setting}:\n{info}");
    }
    // It is encrypted for good: no going public (12.3).
    assert!(
        !net.run(&alice, &["set", &addr, "#news", "public", "yes"])
            .await
            .status
            .success()
    );
    // Messages there go encrypted.
    net.ok(&alice, &["send", &addr, "#news", "first"]).await;
    let export = net.ok(&alice, &["export", &addr, "#news"]).await;
    assert!(export.contains(" ENC #news "), "{export}");
    assert!(!export.contains("first"), "{export}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn devices_lists_and_declines() {
    let net = Net::start(&[]).await;
    let alice = net.registered("alice").await;
    let bob = net.registered("bob").await;
    let addr = net.addr.clone();
    net.ok(&alice, &["send", &addr, "bob@chat.test", "hi"])
        .await;

    // Alice's own devices: just this one, checked against her key file.
    let mine = net.ok(&alice, &["devices", &addr]).await;
    assert_eq!(mine.lines().count(), 1, "{mine}");
    assert!(mine.contains("(this device)"), "{mine}");
    // Bob's device, as Alice's device knows it from their group.
    let theirs = net.ok(&alice, &["devices", &addr, "bob@chat.test"]).await;
    assert_eq!(theirs.lines().count(), 1, "{theirs}");
    assert!(theirs.starts_with("sha256:"), "{theirs}");
    assert!(!theirs.contains("this device"), "{theirs}");
    let whoami = net.ok(&bob, &["whoami", &addr]).await;
    let bob_key = theirs.split_whitespace().next().unwrap();
    assert!(whoami.contains(bob_key), "{whoami}\n{theirs}");

    // A device Alice does not recognise: she declines it, and it gets no
    // history keys (12.9).
    let other = net.second_device(&alice, "alice@chat.test").await;
    let devices = net.ok(&alice, &["devices", &addr]).await;
    let fingerprint = new_device(&devices).expect(&devices);
    let out = net
        .ok(&alice, &["confirm", &addr, &fingerprint, "--decline"])
        .await;
    assert!(out.contains("gets no history keys"), "{out}");
    let devices = net.ok(&alice, &["devices", &addr]).await;
    assert!(
        devices
            .lines()
            .any(|l| l.starts_with(&fingerprint) && l.contains("declined")),
        "{devices}"
    );
    net.ok(&other, &["sync", &addr]).await;
    let log = net.ok(&other, &["log", &addr, "bob@chat.test"]).await;
    assert!(log.contains("waiting for its key"), "{log}");

    // A fingerprint that names no device of hers is refused.
    let out = net.run(&alice, &["confirm", &addr, "sha256:00"]).await;
    assert!(!out.status.success());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_recovery_key_replaces_the_old_one() {
    let net = Net::start(&[]).await;
    let alice = net.registered("alice").await;
    let bob = net.registered("bob").await;
    let addr = net.addr.clone();
    net.ok(&alice, &["send", &addr, "bob@chat.test", "one"])
        .await;
    let first = recovery_key(&net.ok(&alice, &["recovery", "create", &addr]).await);
    let second = recovery_key(&net.ok(&alice, &["recovery", "create", &addr]).await);
    assert_ne!(first, second);

    // One recovery key in the key file, and it is the shown recovery key,
    // not a device (12.12).
    let keys = net.ok(&alice, &["keys", "list", &addr]).await;
    assert_eq!(
        keys.lines().filter(|l| l.contains("recovery")).count(),
        1,
        "{keys}"
    );
    let devices = net.ok(&alice, &["devices", &addr]).await;
    assert!(devices.contains("(recovery key)"), "{devices}");

    // The old key no longer restores anything; the new one does (12.10).
    let alice2 = net.second_device(&alice, "alice@chat.test").await;
    net.ok(&alice2, &["sync", &addr]).await;
    for (key, works) in [(&first, false), (&second, true)] {
        let mut args = vec!["recovery", "restore", addr.as_str()];
        args.extend(key.split_whitespace());
        let out = net.run(&alice2, &args).await;
        assert_eq!(out.status.success(), works, "{}", stderr(&out));
    }
    net.log_until(&alice2, "bob@chat.test", &["<alice@chat.test> one"])
        .await;

    // Nor does the old key sign in as her.
    let lost = net.device().await;
    let mut args = vec!["recover", addr.as_str(), "alice@chat.test"];
    args.extend(first.split_whitespace());
    let out = net.run(&lost, &args).await;
    assert!(!out.status.success(), "{}", stdout(&out));
    let _ = bob;
}
