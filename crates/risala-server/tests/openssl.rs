//! M2's goal, by hand: two `openssl s_client` sessions chat as guests
//! through the real `risalad` binary (Appendix A). Skipped when `openssl`
//! is not on PATH.

#![cfg(unix)]

use std::io::{BufRead as _, BufReader, Write as _};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// How long to wait for any one line.
const TIMEOUT: Duration = Duration::from_secs(15);

fn have_openssl() -> bool {
    Command::new("openssl")
        .arg("version")
        .output()
        .is_ok_and(|o| o.status.success())
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
        eprintln!("openssl not found, skipping");
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

    let mut alice = s_client(&addr);
    alice.expect_prefix("RISALA 1 chat.example.org ");
    alice.type_line("guest alice");
    alice.expect("OK uid=~alice");
    alice.type_line("join #general");
    let join = alice.expect_prefix("@seq=1;");
    assert!(join.contains(";from=~alice;id=") && join.ends_with(" JOIN #general"));
    // topic, public, guests, retention and e2ee (6.2).
    for _ in 0..5 {
        alice.expect_prefix("SET #general ");
    }
    alice.expect_prefix("OK id=");

    let mut bob = s_client(&addr);
    bob.expect_prefix("RISALA 1 chat.example.org ");
    bob.type_line("guest bob");
    bob.expect("OK uid=~bob");
    bob.type_line("join #general");
    bob.expect_prefix("@seq=2;");
    for _ in 0..5 {
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

    // QUIT closes the connection, and bob sees alice leave (4.2).
    alice.type_line("quit");
    alice.expect("OK");
    assert_eq!(alice.line(), None);
    alice.wait();
    assert!(
        bob.expect_prefix("@seq=5;")
            .ends_with(";from=~alice PART #general")
    );

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
