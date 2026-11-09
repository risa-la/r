//! M5b's goal with the `risala` binary, against a whole `risalad` with its
//! key log and a witness (risala-dev's world): each device is a state
//! directory, and each step one run of `risala`.
//!
//! Two devices talk in an encrypted direct conversation and a private room
//! over anonymous connections; a third device is paired by QR text and
//! gets the history by transfer; an identity is recovered from its
//! recovery key; and every key file record a device accepts has a
//! witnessed inclusion proof. A public room is tried, and the test says so
//! if librisala does not build them yet.
//!
//! The log witnesses each record within about 10 seconds, and a device
//! acts only while a run of `risala` is connected, so the test takes a
//! few minutes.

use std::io::{BufRead as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use risala_dev::{HOST, World};

/// One device: a state directory.
struct Device {
    dir: PathBuf,
    args: Vec<String>,
}

impl Device {
    fn new(world: &World, root: &Path, name: &str) -> Device {
        let mut args = world.cli_args();
        args.push("--short-waits".into());
        Device {
            dir: root.join(name),
            args,
        }
    }

    /// `risala` with this device's state and the world's options. With
    /// `RISALA_TEST_LOGS=<dir>`, each device's log goes to `<dir>/<device>.log`
    /// at the level `RISALA_LOG` gives.
    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_risala"));
        cmd.arg("--state")
            .arg(&self.dir)
            .args(&self.args)
            .args(args);
        if std::env::var_os("RISALA_TEST_LOGS").is_none() {
            cmd.env("RISALA_LOG", "warn");
        }
        cmd
    }

    fn log(&self, err: &str) {
        if let Some(dir) = std::env::var_os("RISALA_TEST_LOGS") {
            let name = self.dir.file_name().unwrap().to_string_lossy().into_owned();
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(PathBuf::from(dir).join(format!("{name}.log")))
                .unwrap();
            let _ = f.write_all(err.as_bytes());
        }
    }

    /// Runs `risala`, with `stdin` if given; its output and whether it
    /// succeeded.
    async fn try_run(&self, args: &[&str], stdin: Option<&str>) -> (bool, String, String) {
        let mut cmd = self.command(args);
        let stdin = stdin.map(str::to_owned);
        tokio::task::spawn_blocking(move || {
            cmd.stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
            let mut child = cmd.spawn().expect("running risala");
            if let Some(input) = stdin {
                let mut pipe = child.stdin.take().expect("stdin");
                writeln!(pipe, "{input}").expect("writing stdin");
            }
            let out = child.wait_with_output().expect("risala's output");
            (
                out.status.success(),
                String::from_utf8_lossy(&out.stdout).into_owned(),
                String::from_utf8_lossy(&out.stderr).into_owned(),
            )
        })
        .await
        .map(|(ok, out, err)| {
            self.log(&format!("=== risala {args:?}\n{err}"));
            (ok, out, err)
        })
        .expect("the blocking task")
    }

    /// Runs `risala` and returns its standard output; panics if it fails.
    async fn run(&self, args: &[&str]) -> String {
        let (ok, out, err) = self.try_run(args, None).await;
        assert!(ok, "risala {args:?} failed: {err}\n{out}");
        out
    }

    /// Runs `risala` until it succeeds, up to `tries` times.
    async fn retry(&self, args: &[&str], tries: usize) -> String {
        let mut last = String::new();
        for _ in 0..tries {
            let (ok, out, err) = self.try_run(args, None).await;
            if ok {
                return out;
            }
            last = err;
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        panic!("risala {args:?} kept failing: {last}");
    }

    /// The texts of a conversation, after receiving for a few seconds.
    async fn texts(&self, conversation: &str) -> Vec<String> {
        let (ok, out, _) = self
            .try_run(&["--wait", "5", "read", conversation, "--sync"], None)
            .await;
        if !ok {
            return Vec::new();
        }
        out.lines()
            .filter_map(|l| l.splitn(5, '\t').nth(4).map(str::to_owned))
            .collect()
    }

    /// Waits until a conversation has `text`, letting `others` run
    /// meanwhile (each `sync` once a round), for up to `rounds` rounds.
    async fn until_text(&self, conversation: &str, text: &str, others: &[&Device], rounds: usize) {
        for _ in 0..rounds {
            if self.texts(conversation).await.iter().any(|t| t == text) {
                return;
            }
            for other in others {
                other.run(&["--wait", "5", "sync"]).await;
            }
        }
        panic!(
            "{}: {text:?} never arrived in {conversation}: {:?}",
            self.dir.display(),
            self.texts(conversation).await
        );
    }

    /// The device's cache, read directly, for the records it accepted.
    fn store(&self) -> librisala::store::Store {
        let key: [u8; 32] = std::fs::read(self.dir.join("cache.key"))
            .unwrap()
            .try_into()
            .unwrap();
        librisala::store::Store::open(
            self.dir.join("cache.db"),
            &librisala::store::DatabaseKey::from_bytes(key),
        )
        .unwrap()
    }
}

/// Checks every record a device accepted of `uid` against the log and the
/// witness (4.5); returns how many.
async fn witnessed(world: &World, device: &Device, uid: &str) -> usize {
    let records = device.store().records(uid).unwrap();
    let mut n = 0;
    for r in records.iter().filter(|r| r.accepted) {
        assert!(r.witnessed.is_some(), "{uid}: accepted but not witnessed");
        let index = r.log_index.expect("an index");
        world
            .check_witnessed(&r.log.0, &r.log.1, index, &r.record)
            .await
            .unwrap_or_else(|e| panic!("{uid} record {index}: {e}"));
        n += 1;
    }
    n
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_goal_with_the_cli() {
    let world = World::start().await;
    let root = tempfile::tempdir().unwrap();
    let alice = Device::new(&world, root.path(), "alice-laptop");
    let bob = Device::new(&world, root.path(), "bob-laptop");
    let phone = Device::new(&world, root.path(), "alice-phone");
    let spare = Device::new(&world, root.path(), "bob-spare");

    // Identities, with their recovery keys (4.7, 4.8).
    let out = alice.run(&["create", HOST, "alice", "laptop"]).await;
    let mut lines = out.lines();
    assert_eq!(lines.next(), Some("alice@example.org"));
    let alice_key = lines.next().unwrap().to_owned();
    assert!(!alice_key.is_empty());
    let out = bob.run(&["create", HOST, "bob", "laptop"]).await;
    let mut lines = out.lines();
    assert_eq!(lines.next(), Some("bob@example.org"));
    let bob_key = lines.next().unwrap().to_owned();

    // Safety numbers (12.14): bob's, as alice sees it and as bob does.
    let theirs = bob.run(&["safety", "bob@example.org"]).await;
    let ours = alice.run(&["safety", "bob@example.org"]).await;
    assert_eq!(theirs, ours);
    let qr = theirs.lines().nth(1).unwrap();
    alice.run(&["verify", "bob@example.org", qr]).await;

    // A direct conversation.
    alice.retry(&["direct", "bob@example.org"], 15).await;
    alice
        .run(&["send", "bob@example.org", "hello", "bob"])
        .await;
    bob.until_text("alice@example.org", "hello bob", &[&alice], 10)
        .await;
    bob.run(&["send", "alice@example.org", "hello alice"]).await;
    alice
        .until_text("bob@example.org", "hello alice", &[&bob], 10)
        .await;

    // A private room.
    alice.run(&["room", "create", "garden"]).await;
    alice
        .run(&["room", "invite", "garden", "bob@example.org"])
        .await;
    alice.run(&["send", "garden", "welcome"]).await;
    bob.until_text("garden", "welcome", &[&alice], 10).await;
    bob.run(&["send", "garden", "thanks"]).await;
    alice.until_text("garden", "thanks", &[&bob], 10).await;
    let members = alice.run(&["room", "members", "garden"]).await;
    assert!(members.contains("bob@example.org"), "{members}");

    // A file in the direct conversation (5.6, 12.11).
    let file = root.path().join("note.txt");
    std::fs::write(&file, b"a small file").unwrap();
    let id = alice
        .run(&["send-file", "bob@example.org", file.to_str().unwrap()])
        .await
        .trim()
        .to_owned();
    let mut fetched = None;
    for _ in 0..10 {
        bob.run(&["--wait", "5", "sync"]).await;
        let (ok, out, _) = bob
            .try_run(&["fetch", "alice@example.org", &id], None)
            .await;
        if ok {
            fetched = Some(out);
            break;
        }
    }
    let fetched = fetched.expect("bob fetches the file");
    let path = fetched.split('\t').next().unwrap();
    assert_eq!(std::fs::read(path).unwrap(), b"a small file");

    // A third device, paired by QR text (4.8): `pair new` prints the QR
    // text and waits; `pair accept` on alice's laptop answers it.
    let mut pairing = phone
        .command(&["pair", "new", HOST, "phone", "--yes"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = std::io::BufReader::new(pairing.stdout.take().unwrap());
    let qr = tokio::task::spawn_blocking(move || {
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        (line.trim().to_owned(), stdout)
    })
    .await
    .unwrap();
    let (qr, mut stdout) = qr;
    assert!(qr.starts_with("RISALA-PAIR:"), "{qr}");
    let accepted = alice.run(&["pair", "accept", &qr]).await;
    assert!(accepted.contains("phone"), "{accepted}");
    let status = tokio::task::spawn_blocking(move || {
        let mut rest = String::new();
        std::io::Read::read_to_string(&mut stdout, &mut rest).unwrap();
        (pairing.wait().unwrap(), rest)
    })
    .await
    .unwrap();
    assert!(status.0.success(), "pair new failed: {}", status.1);
    assert!(status.1.contains("alice@example.org"));

    // Alice's laptop adds the phone to her groups (12.7, 12.14), and the
    // phone applies the history it was sent (12.13).
    phone
        .until_text("bob@example.org", "hello bob", &[&alice], 15)
        .await;
    phone.until_text("garden", "welcome", &[&alice], 10).await;
    phone
        .run(&["send", "bob@example.org", "from the phone"])
        .await;
    bob.until_text("alice@example.org", "from the phone", &[&phone], 10)
        .await;

    // Bob names himself (8.2), a commit in each group: alice's devices
    // made the last ones, and 12.7's streak rule would hold a fourth in a
    // row for 10 minutes.
    bob.run(&["name", "Bob"]).await;
    for _ in 0..10 {
        alice.run(&["--wait", "5", "sync"]).await;
        let members = alice.run(&["room", "members", "garden"]).await;
        if members
            .lines()
            .any(|l| l.starts_with("bob@example.org") && l.ends_with("\tBob"))
        {
            break;
        }
        bob.run(&["--wait", "3", "sync"]).await;
    }

    // Bob recovers on a new device (4.8): alice's devices remove the old
    // laptop's leaf and add the new device.
    let out = spare
        .try_run(
            &["recover", HOST, "bob@example.org", "spare"],
            Some(&bob_key),
        )
        .await;
    assert!(out.0, "recover failed: {}", out.2);
    let mut seen = false;
    for _ in 0..30 {
        let out = alice
            .run(&["identity", "bob@example.org", "--refresh"])
            .await;
        if out.contains("removed") && out.matches("current").count() == 1 {
            seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    assert!(seen, "alice never saw bob's recovery");
    let mut joined = false;
    for _ in 0..40 {
        alice.run(&["--wait", "5", "sync"]).await;
        let list = spare.run(&["--wait", "5", "sync"]).await;
        if list
            .lines()
            .any(|l| l.contains("\tdirect\talice@example.org"))
        {
            joined = true;
            break;
        }
    }
    assert!(
        joined,
        "the recovered device never joined the direct conversation"
    );
    spare
        .run(&["send", "alice@example.org", "back again"])
        .await;
    alice
        .until_text("bob@example.org", "back again", &[&spare], 10)
        .await;

    // Every record each device accepted is in a witnessed checkpoint.
    let mut n = 0;
    for device in [&alice, &bob, &phone, &spare] {
        for uid in ["alice@example.org", "bob@example.org"] {
            n += witnessed(&world, device, uid).await;
        }
    }
    assert!(n >= 10, "only {n} records checked");

    // A public room (6.1): alice creates it; bob's new device joins by
    // proposal while alice's laptop is online to commit it; they talk once
    // their ATTESTs pin their pseudonyms (7.3, 12.10).
    alice.retry(&["public", "create", "#plaza"], 5).await;
    let rooms = spare.run(&["public", "list"]).await;
    assert!(rooms.contains("#plaza"), "{rooms}");
    let (joined, _) = tokio::join!(
        spare.try_run(&["--wait", "30", "public", "join", "#plaza"], None),
        alice.try_run(&["--wait", "40", "sync"], None),
    );
    assert!(joined.0, "joining the public room failed: {}", joined.2);
    alice.run(&["send", "#plaza", "hello plaza"]).await;
    spare
        .until_text("#plaza", "hello plaza", &[&alice], 15)
        .await;
    spare.run(&["send", "#plaza", "hi from bob"]).await;
    alice
        .until_text("#plaza", "hi from bob", &[&spare], 15)
        .await;
}
