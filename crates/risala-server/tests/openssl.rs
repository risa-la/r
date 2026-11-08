//! risala by hand, with `openssl` (Appendix A): M2's goal, two
//! `openssl s_client` sessions chatting as guests through the real
//! `risalad` binary, and M3's, an identity made and signed in with openssl
//! alone. Skipped when `openssl` is not on PATH, or is older than 3.5 and
//! so lacks X25519MLKEM768 (2.1) and ML-DSA (4.5).

#![cfg(unix)]

use std::io::{BufRead as _, BufReader, Write as _};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// How long to wait for any one line.
const TIMEOUT: Duration = Duration::from_secs(15);

fn have_openssl() -> bool {
    risala_server::net::testing::openssl_has_x25519mlkem768()
}

/// A child process whose output is read line by line in the background.
struct Proc {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: mpsc::Receiver<String>,
}

impl Proc {
    /// Starts `cmd`, reading lines from its stdout, or from its stderr
    /// with `stderr`. The other one is discarded.
    fn spawn(mut cmd: Command, stderr: bool) -> Proc {
        cmd.stdin(Stdio::piped());
        if stderr {
            cmd.stdout(Stdio::null()).stderr(Stdio::piped());
        } else {
            cmd.stdout(Stdio::piped()).stderr(Stdio::null());
        }
        let mut child = cmd.spawn().expect("starting a process");
        let stdin = child.stdin.take();
        let (tx, lines) = mpsc::channel();
        let out: Box<dyn std::io::Read + Send> = if stderr {
            Box::new(child.stderr.take().unwrap())
        } else {
            Box::new(child.stdout.take().unwrap())
        };
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Proc {
            child,
            stdin,
            lines,
        }
    }

    fn line(&self) -> Option<String> {
        match self.lines.recv_timeout(TIMEOUT) {
            Ok(line) => Some(line),
            Err(mpsc::RecvTimeoutError::Disconnected) => None,
            Err(mpsc::RecvTimeoutError::Timeout) => panic!("no line within {TIMEOUT:?}"),
        }
    }

    fn expect(&self, want: &str) {
        let got = self.line().expect("a line");
        assert_eq!(got, want);
    }

    fn expect_prefix(&self, prefix: &str) -> String {
        let got = self.line().expect("a line");
        assert!(got.starts_with(prefix), "expected {prefix}..., got {got}");
        got
    }

    /// Reads lines until one contains `needle`, and returns it.
    fn find(&self, needle: &str) -> String {
        loop {
            let line = self
                .line()
                .unwrap_or_else(|| panic!("the output ended before {needle:?}"));
            if line.contains(needle) {
                return line;
            }
        }
    }

    fn type_line(&mut self, line: &str) {
        let stdin = self.stdin.as_mut().expect("stdin is open");
        writeln!(stdin, "{line}").unwrap();
        stdin.flush().unwrap();
    }

    /// Waits for the process to exit, killing it after [`TIMEOUT`].
    fn wait(&mut self) -> std::process::ExitStatus {
        self.stdin.take();
        let deadline = std::time::Instant::now() + TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            if std::time::Instant::now() > deadline {
                let _ = self.child.kill();
                panic!("the process did not exit");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `openssl s_client -connect <addr> -quiet`, as Appendix A says.
fn s_client(addr: &str) -> Proc {
    let mut cmd = Command::new("openssl");
    cmd.args(["s_client", "-connect", addr, "-quiet"]);
    Proc::spawn(cmd, false)
}

#[test]
fn two_openssl_sessions_chat_through_risalad() {
    if !have_openssl() {
        eprintln!("OpenSSL 3.5 or later not found, skipping");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("risalad.toml");
    std::fs::write(
        &config,
        format!(
            "hostname = \"chat.example.org\"\n\
             listen = [\"127.0.0.1:0\"]\n\
             state_dir = {:?}\n\
             rooms = [\"#general\"]\n\
             [server]\n\
             welcome = \"Welcome!\"\n",
            dir.path().join("state").to_str().unwrap()
        ),
    )
    .unwrap();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_risalad"));
    cmd.arg("--config")
        .arg(&config)
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1");
    let mut server = Proc::spawn(cmd, true);
    // risalad logs where it listens and its fingerprint (2.2).
    let listening = server.find("listening addr=");
    let addr = listening
        .split("listening addr=")
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned();
    let logged = server.find("certificate fingerprint=");
    let fingerprint = logged
        .split("fingerprint=")
        .nth(1)
        .unwrap()
        .trim()
        .to_owned();

    // Appendix A's pipeline prints the same fingerprint.
    let pipeline = format!(
        "openssl s_client -connect {addr} </dev/null 2>/dev/null \
         | openssl x509 -pubkey -noout \
         | openssl pkey -pubin -outform der \
         | openssl dgst -sha256"
    );
    let out = Command::new("sh").args(["-c", &pipeline]).output().unwrap();
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let hex = stdout.split_whitespace().last().unwrap();
    assert_eq!(format!("sha256:{hex}"), fingerprint);

    // A client without X25519MLKEM768 is refused, and the log says why
    // (2.1).
    let classic = Command::new("openssl")
        .args(["s_client", "-connect", &addr, "-groups", "X25519"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!classic.status.success(), "{classic:?}");
    let refused = server.find("TLS handshake refused");
    assert!(refused.contains("X25519MLKEM768"), "{refused}");

    let mut alice = s_client(&addr);
    alice.expect_prefix("RISALA 1 chat.example.org ");
    alice.type_line("guest alice");
    alice.expect_prefix("OK uid=~alice token=");
    alice.type_line("join #general");
    let join = alice.expect_prefix("@seq=1;");
    assert!(join.contains(";from=~alice;id=") && join.ends_with(" JOIN #general"));
    // topic, public, guests, retention and e2ee (6.2).
    for _ in 0..6 {
        alice.expect_prefix("SET #general ");
    }
    alice.expect_prefix("OK id=");

    let mut bob = s_client(&addr);
    bob.expect_prefix("RISALA 1 chat.example.org ");
    bob.type_line("guest bob");
    bob.expect_prefix("OK uid=~bob token=");
    bob.type_line("join #general");
    bob.expect_prefix("@seq=2;");
    for _ in 0..6 {
        bob.expect_prefix("SET #general ");
    }
    bob.expect_prefix("OK id=");
    assert!(alice.expect_prefix("@seq=2;").ends_with(" JOIN #general"));

    bob.type_line("msg #general hi alice!");
    let event = bob.expect_prefix("@seq=3;");
    assert!(
        event.ends_with(";from=~bob MSG #general hi alice!"),
        "{event}"
    );
    bob.expect("OK seq=3");
    assert_eq!(alice.expect_prefix("@seq=3;"), event);

    // Typed by hand: no ALPN, upper and lower case, an empty line.
    alice.type_line("");
    alice.type_line("MSG #general hello bob");
    let event = alice.expect_prefix("@seq=4;");
    assert!(
        event.ends_with(";from=~alice MSG #general hello bob"),
        "{event}"
    );
    alice.expect("OK seq=4");
    assert_eq!(bob.expect_prefix("@seq=4;"), event);

    // QUIT closes the connection. Alice's session waits to be resumed
    // (4.2), so bob sees no PART: his next line is the answer to PING.
    alice.type_line("quit");
    alice.expect("OK");
    assert_eq!(alice.line(), None);
    alice.wait();
    bob.type_line("ping");
    bob.expect("OK");

    // SIGTERM shuts the server down cleanly: bob gets BYE.
    let pid = server.child.id().to_string();
    let killed = Command::new("sh")
        .args(["-c", &format!("kill -TERM {pid}")])
        .status()
        .unwrap();
    assert!(killed.success());
    bob.expect("BYE server shutting down");
    assert_eq!(bob.line(), None);
    server.find("SIGTERM: shutting down");
    let status = server.wait();
    assert!(status.success(), "risalad exited with {status}");
}

/// Runs `script` with `sh -c` in `dir`, and returns its standard output.
fn sh(dir: &std::path::Path, script: &str) -> String {
    let out = Command::new("sh")
        .args(["-c", script])
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(out.status.success(), "{script}: {out:?}");
    String::from_utf8(out.stdout).unwrap()
}

/// M3 by hand: an identity made and signed in with nothing but openssl,
/// following Appendix A word for word: `genpkey` makes the key, the
/// `printf` pipeline prints its key file line, and `pkeyutl` signs the
/// challenge. The server fetches the key file from a test HTTPS server.
#[test]
fn an_identity_signs_in_by_hand() {
    if !have_openssl() {
        eprintln!("OpenSSL 3.5 or later not found, skipping");
        return;
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let server = rt.block_on(
        risala_server::testing::TestServer::builder()
            .key_domains(&["example.net"])
            .room("#general")
            .start(),
    );
    let dir = tempfile::tempdir().unwrap();

    // Make a key, and print the line for your key file.
    sh(
        dir.path(),
        "openssl genpkey -algorithm ML-DSA-44 -out alice.pem",
    );
    let line = sh(
        dir.path(),
        "printf 'mldsa44 %s laptop\\n' \
           \"$(openssl pkey -in alice.pem -pubout -outform der | tail -c 1312 | openssl base64 -A)\"",
    );
    let entry: risala_proto::keyfile::KeyEntry = line.trim_end().parse().unwrap();
    assert_eq!(entry.label(), Some("laptop"));
    let alice: risala_proto::names::Identity = "alice@example.net".parse().unwrap();
    server.key_server().publish(&alice, &[entry]);

    // Connect. `-servername` sends the name the server is known by in SNI,
    // as connecting to it by name would.
    let mut cmd = Command::new("openssl");
    cmd.args([
        "s_client",
        "-connect",
        &server.addr().to_string(),
        "-servername",
        server.hostname(),
        "-quiet",
    ]);
    let mut c = Proc::spawn(cmd, false);
    let greeting = c.expect_prefix(&format!("RISALA 1 {} ", server.hostname()));
    let nonce = greeting.split(' ').nth(3).unwrap().to_owned();

    // Sign in: the challenge goes in a file, and pkeyutl signs it.
    sh(
        dir.path(),
        &format!(
            "printf 'risala-auth-1\\n%s\\n%s\\n%s\\n' {} {nonce} alice@example.net > chal",
            server.hostname()
        ),
    );
    let signature = sh(
        dir.path(),
        "openssl pkeyutl -sign -rawin -inkey alice.pem -in chal | openssl base64 -A",
    );
    c.type_line(&format!("auth alice@example.net {}", signature.trim()));
    c.expect("OK uid=alice@example.net");

    // Signed in as the identity.
    c.type_line("join #general");
    let join = c.expect_prefix("@seq=1;");
    assert!(join.contains(";from=alice@example.net;id="), "{join}");
    for _ in 0..6 {
        c.expect_prefix("SET #general ");
    }
    c.expect_prefix("OK id=");
    c.type_line("name Alice");
    c.expect("OK");
    c.type_line("whois alice@example.net");
    c.expect("USER alice@example.net online Alice");
    c.expect("OK");
    c.type_line("quit");
    c.expect("OK");
    assert_eq!(c.line(), None);
    c.wait();
    rt.block_on(server.stop());
}
