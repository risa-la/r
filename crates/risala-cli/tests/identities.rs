//! The identity commands of the `risala` binary (`login`, `register`,
//! `keys`, `unregister`, `whoami`) against a scripted TLS server on
//! `localhost`. Identities need a hostname to sign (2.1, 4.5), so these
//! cannot use the server on 127.0.0.1 that `tests/cli.rs` uses.

use std::path::Path;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use rcgen::PublicKeyData as _;
use risala_proto::auth::{Nonce, PublicKey, SecretKey, Signature};
use risala_proto::fingerprint::Fingerprint;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::TcpListener;

const NONCE: &str = "6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e";

/// The key of Appendix B, seed only.
const PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
    MDQCAQAwCwYJYIZIAWUDBAMRBCKAIMEfrlxZLhO+Z9yW9uhQBNMukoYV968f06bF\n\
    2eoKtsuo\n\
    -----END PRIVATE KEY-----\n";
/// The SHA-256 of its public key, from Appendix B.
const PUBLIC_SHA256: &str = "d9d69ac9b18f42759e43edba0106410c07045a1edab642925b7496ea40baccdf";

/// Answers a command, given the connection's index and the line without
/// its `ref`, with lines to send back. `<close>` closes the connection.
type Handler = dyn Fn(usize, &str) -> Vec<String> + Send + Sync;

/// A TLS server for `localhost` that greets with [`NONCE`], logs every
/// line it receives as `<connection> <line>`, answers QUIT, and answers
/// everything else through a handler.
struct Fake {
    addr: String,
    fingerprint: String,
    log: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Fake {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Fake {
    async fn start(handler: impl Fn(usize, &str) -> Vec<String> + Send + Sync + 'static) -> Fake {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let fingerprint =
            Fingerprint::from_spki_der(&cert.signing_key.subject_public_key_info()).to_string();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert.der().clone()], key)
            .unwrap();
        config.alpn_protocols = vec![risala_proto::ALPN.to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let log = Arc::new(Mutex::new(Vec::new()));
        let handler: Arc<Handler> = Arc::new(handler);
        let task = {
            let log = log.clone();
            tokio::spawn(async move {
                let count = AtomicUsize::new(0);
                loop {
                    let (tcp, _) = listener.accept().await.unwrap();
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        continue;
                    };
                    let i = count.fetch_add(1, Ordering::SeqCst);
                    tokio::spawn(serve(i, tls, handler.clone(), log.clone()));
                }
            })
        };
        Fake {
            addr: format!("localhost:{port}"),
            fingerprint,
            log,
            task,
        }
    }

    /// The lines received so far.
    fn log(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }

    /// Whether a received line, without its connection, is `line`.
    fn received(&self, line: &str) -> bool {
        self.log()
            .iter()
            .any(|l| l.split_once(' ').is_some_and(|(_, l)| l == line))
    }
}

async fn serve(
    i: usize,
    tls: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    handler: Arc<Handler>,
    log: Arc<Mutex<Vec<String>>>,
) {
    let mut stream = BufReader::new(tls);
    send(&mut stream, format!("RISALA 1 localhost {NONCE}")).await;
    loop {
        let mut line = String::new();
        match stream.read_line(&mut line).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        let line = line.trim_end_matches('\n').to_owned();
        log.lock().unwrap().push(format!("{i} {line}"));
        let (r, rest) = match line.strip_prefix("@ref=") {
            Some(tagged) => tagged.split_once(' ').expect("a command after the tags"),
            None => ("", line.as_str()),
        };
        let replies = if rest == "QUIT" {
            vec!["OK".to_owned(), "<close>".to_owned()]
        } else {
            handler(i, rest)
        };
        for reply in replies {
            if reply == "<close>" {
                let _ = stream.get_mut().shutdown().await;
                return;
            }
            let reply = match (r, reply.strip_prefix('@')) {
                ("", _) => reply,
                (r, Some(tags)) => format!("@ref={r};{tags}"),
                (r, None) => format!("@ref={r} {reply}"),
            };
            send(&mut stream, reply).await;
        }
    }
}

async fn send(
    stream: &mut BufReader<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>,
    line: String,
) {
    let _ = stream
        .get_mut()
        .write_all(format!("{line}\n").as_bytes())
        .await;
}

/// Runs `risala --state <dir> <args>`.
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

/// Runs risala and expects exit code `code`; returns standard output and
/// standard error.
async fn run(state: &Path, args: &[&str], code: i32) -> (String, String) {
    let out = risala(state, args).await;
    assert_eq!(
        out.status.code(),
        Some(code),
        "risala {args:?}:\n{}\n{}",
        stdout(&out),
        stderr(&out)
    );
    (stdout(&out), stderr(&out))
}

/// The verb of a command line without its `ref`.
fn verb(line: &str) -> &str {
    line.split(' ').next().unwrap()
}

/// The `n`th word of a line.
fn word(line: &str, n: usize) -> &str {
    line.split(' ').nth(n).unwrap()
}

/// Whether `signature` signs in as `uid` on `localhost` with the
/// greeting's nonce, under `key` (4.5).
fn verifies(key: &PublicKey, uid: &str, signature: &str) -> bool {
    let nonce: Nonce = NONCE.parse().unwrap();
    let signature: Signature = signature.parse().unwrap();
    key.verify_challenge("localhost", &nonce, uid, &signature)
}

#[tokio::test]
async fn login_with_a_pem_key_signs_the_sni_host() {
    let fake = Fake::start(|_, line| match verb(line) {
        "AUTH" => vec![format!("OK uid={}", word(line, 1))],
        "SYNC" => vec!["OK".into()],
        _ => vec!["ERR unknown-command".into()],
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let pem = dir.path().join("alice.pem");
    std::fs::write(&pem, PEM).unwrap();
    run(&state, &["trust", &fake.addr, &fake.fingerprint], 0).await;

    let pem_arg = pem.to_str().unwrap();
    let (out, _) = run(
        &state,
        &["login", &fake.addr, "Alice@Example.org", "--key", pem_arg],
        0,
    )
    .await;
    assert_eq!(
        out.trim(),
        format!("signed in to {} as alice@example.org", fake.addr)
    );
    // Signed with the host sent in SNI and the greeting's nonce (4.5).
    // The deterministic signature of Appendix B's key is exact.
    let key = SecretKey::from_pkcs8_pem(PEM).unwrap();
    let nonce: Nonce = NONCE.parse().unwrap();
    let signature = key.sign_challenge("localhost", &nonce, "alice@example.org");
    let auth = format!("@ref=1 AUTH alice@example.org {signature}");
    assert!(fake.received(&auth), "{:?}", fake.log());
    assert!(verifies(
        &key.public_key(),
        "alice@example.org",
        &signature.to_string()
    ));

    let (out, _) = run(&state, &["whoami"], 0).await;
    assert_eq!(
        out.trim(),
        format!(
            "alice@example.org on {} (key sha256:{PUBLIC_SHA256})",
            fake.addr
        )
    );
    let (out, _) = run(
        &state,
        &["keyline", "alice@example.org", "--label", "laptop"],
        0,
    )
    .await;
    assert_eq!(out.trim(), format!("mldsa44 {} laptop", key.public_key()));

    // Another key is not imported over it unless asked.
    let other = dir.path().join("other.pem");
    std::fs::write(&other, risala_other_pem()).unwrap();
    let other_arg = other.to_str().unwrap();
    let (_, err) = run(
        &state,
        &["login", &fake.addr, "alice@example.org", "--key", other_arg],
        3,
    )
    .await;
    assert!(err.contains("--force"), "{err}");
    // Not a key at all is a usage error.
    let (_, err) = run(
        &state,
        &[
            "login",
            &fake.addr,
            "alice@example.org",
            "--key",
            "/dev/null",
        ],
        2,
    )
    .await;
    assert!(err.contains("PEM"), "{err}");
}

/// A new private key in PEM.
fn risala_other_pem() -> String {
    let key = SecretKey::from_seed([7; 32]);
    key.to_pkcs8_pem().to_string()
}

#[tokio::test]
async fn login_without_a_key_makes_one_to_publish() {
    let auths = Arc::new(AtomicUsize::new(0));
    let fake = {
        let auths = auths.clone();
        Fake::start(move |_, line| match verb(line) {
            // Refused once, then accepted, once the key is published.
            "AUTH" if auths.fetch_add(1, Ordering::SeqCst) < 1 => {
                vec!["ERR auth-failed no key matched".into()]
            }
            "AUTH" => vec![format!("OK uid={}", word(line, 1))],
            "SYNC" => vec!["OK".into()],
            _ => vec!["ERR unknown-command".into()],
        })
        .await
    };
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path();
    run(state, &["trust", &fake.addr, &fake.fingerprint], 0).await;

    // A new key: its line to publish, and how, before any connection.
    let (out, err) = run(
        state,
        &["login", &fake.addr, "bob@example.org", "--label", "laptop"],
        3,
    )
    .await;
    let line = out.trim();
    assert!(
        line.starts_with("mldsa44 ") && line.ends_with(" laptop"),
        "{line}"
    );
    let key: PublicKey = word(line, 1).parse().unwrap();
    assert!(
        err.contains("https://example.org/.well-known/risala/bob"),
        "{err}"
    );
    assert!(
        err.contains(&format!("risala keys add {}", fake.addr)),
        "{err}"
    );
    assert!(fake.log().is_empty());

    // Not published yet: refused, with the line again.
    let (_, err) = run(state, &["login", &fake.addr, "bob@example.org"], 3).await;
    assert!(err.contains("did not accept"), "{err}");
    assert!(err.contains(word(line, 1)), "{err}");
    // auth-failed is not tried again (4.5).
    assert_eq!(auths.load(Ordering::SeqCst), 1);

    // Published: signed in, with that key.
    let (out, _) = run(state, &["login", &fake.addr, "bob@example.org"], 0).await;
    assert!(out.contains("as bob@example.org"), "{out}");
    let auth = fake
        .log()
        .into_iter()
        .rfind(|l| l.contains(" AUTH "))
        .unwrap();
    // "<connection> @ref=<n> AUTH <uid> <signature>"
    assert!(verifies(&key, "bob@example.org", word(&auth, 4)), "{auth}");
}

/// The hosted identity's keys, as the fake server keeps them.
#[derive(Default)]
struct Hosted {
    /// Keys and labels.
    keys: Vec<(String, String)>,
}

#[tokio::test]
async fn register_manage_keys_and_unregister() {
    let hosted = Arc::new(Mutex::new(Hosted::default()));
    let fake = {
        let hosted = hosted.clone();
        Fake::start(move |_, line| {
            let mut h = hosted.lock().unwrap();
            let rest = || line.split_once(' ').map_or("", |(_, r)| r);
            match verb(line) {
                "INFO" => vec!["OK version=1 guests=yes register=example.org".into()],
                "REGISTER" => {
                    assert_eq!(word(line, 1), "carol");
                    let key: PublicKey = word(line, 2).parse().unwrap();
                    assert!(verifies(&key, "carol@example.org", word(line, 3)));
                    h.keys.push((key.to_string(), String::new()));
                    vec!["OK uid=carol@example.org".into()]
                }
                "AUTH" => {
                    let ok = h
                        .keys
                        .iter()
                        .any(|(k, _)| verifies(&k.parse().unwrap(), word(line, 1), word(line, 2)));
                    if ok {
                        vec![format!("OK uid={}", word(line, 1))]
                    } else {
                        vec!["ERR auth-failed".into()]
                    }
                }
                "SYNC" => vec!["OK".into()],
                "KEY" => match word(line, 1) {
                    "LIST" => {
                        let mut out: Vec<String> = h
                            .keys
                            .iter()
                            .map(|(k, l)| format!("KEY {k} {l}").trim_end().to_owned())
                            .collect();
                        out.push("OK".into());
                        out
                    }
                    "ADD" => {
                        let label = rest().splitn(3, ' ').nth(2).unwrap_or("").to_owned();
                        h.keys.push((word(line, 2).to_owned(), label));
                        vec!["OK".into()]
                    }
                    "DEL" if h.keys.len() == 1 => {
                        vec!["ERR forbidden that is the last key".into()]
                    }
                    "DEL" => {
                        h.keys.retain(|(k, _)| k != word(line, 2));
                        vec!["OK".into()]
                    }
                    _ => vec!["ERR bad-syntax".into()],
                },
                "UNREGISTER" => {
                    h.keys.clear();
                    vec!["OK".into(), "<close>".into()]
                }
                _ => vec!["ERR unknown-command".into()],
            }
        })
        .await
    };
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path();
    run(state, &["trust", &fake.addr, &fake.fingerprint], 0).await;

    let (out, err) = run(
        state,
        &["register", &fake.addr, "carol", "--label", "laptop"],
        0,
    )
    .await;
    let mut lines = out.lines();
    assert_eq!(lines.next(), Some("carol@example.org"));
    let line = lines.next().unwrap();
    assert!(line.ends_with(" laptop"), "{line}");
    let carol_key = word(line, 1).to_owned();
    assert_eq!(hosted.lock().unwrap().keys[0].0, carol_key);
    assert!(err.contains("registered carol@example.org"), "{err}");
    assert!(fake.received("@ref=1 INFO"));

    let (out, _) = run(state, &["keys", "list", &fake.addr], 0).await;
    let carol_fp: PublicKey = carol_key.parse().unwrap();
    assert_eq!(
        out.trim(),
        format!("{} (this device)", carol_fp.fingerprint())
    );

    // Another device's line, pasted as it is.
    let other = SecretKey::from_seed([9; 32]).public_key();
    let pasted = format!("mldsa44 {other} phone");
    let words: Vec<&str> = pasted.split(' ').collect();
    let mut args = vec!["keys", "add", &fake.addr];
    args.extend(&words);
    let (out, _) = run(state, &args, 0).await;
    assert_eq!(
        out.trim(),
        format!("added {} phone to carol@example.org", other.fingerprint())
    );
    assert!(
        fake.log()
            .iter()
            .any(|l| l.ends_with(&format!("KEY ADD {other} phone")))
    );
    let (out, _) = run(state, &["keys", "list", &fake.addr, "--lines"], 0).await;
    assert!(out.contains(&format!("mldsa44 {other} phone\n")), "{out}");

    // By fingerprint, then the last key, which the server keeps.
    let fp = other.fingerprint().to_string();
    run(state, &["keys", "del", &fake.addr, &fp], 0).await;
    assert!(
        fake.log()
            .iter()
            .any(|l| l.ends_with(&format!("KEY DEL {other}")))
    );
    let (_, err) = run(state, &["keys", "del", &fake.addr, &carol_key], 3).await;
    assert!(err.contains("at least one key"), "{err}");

    // UNREGISTER needs the uid typed out, and an account for it.
    let (_, err) = run(state, &["unregister", &fake.addr, "dave@example.org"], 1).await;
    assert!(err.contains("no account dave@example.org"), "{err}");
    assert!(!fake.log().iter().any(|l| l.contains("UNREGISTER")));
    let (out, err) = run(
        state,
        &["unregister", &fake.addr, "carol@example.org", "--purge"],
        0,
    )
    .await;
    assert_eq!(
        out.trim(),
        format!("deleted carol@example.org from {}", fake.addr)
    );
    assert!(err.contains("deleted this device's key"), "{err}");
    assert!(fake.received("@ref=3 UNREGISTER carol@example.org purge=yes"));
    assert!(!state.join("keys/carol@example.org.pem").exists());
    let (_, err) = run(state, &["whoami"], 1).await;
    assert!(err.contains("no accounts"), "{err}");
}

#[tokio::test]
async fn register_refusals() {
    let closed = Fake::start(|_, line| match verb(line) {
        "INFO" => vec!["OK version=1 register=no".into()],
        _ => vec!["ERR unknown-command".into()],
    })
    .await;
    let taken = Fake::start(|_, line| match verb(line) {
        "INFO" => vec!["OK version=1 register=example.org".into()],
        "REGISTER" if word(line, 1) == "dave" => {
            vec!["@retry=600 ERR forbidden too many registrations".into()]
        }
        "REGISTER" => vec!["ERR name-taken".into()],
        _ => vec!["ERR unknown-command".into()],
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path();
    for fake in [&closed, &taken] {
        run(state, &["trust", &fake.addr, &fake.fingerprint], 0).await;
    }

    let (_, err) = run(state, &["register", &closed.addr, "carol"], 3).await;
    assert!(err.contains("does not offer registration"), "{err}");
    let (_, err) = run(state, &["register", &taken.addr, "carol"], 3).await;
    assert!(err.contains("name is taken"), "{err}");
    let (_, err) = run(state, &["register", &taken.addr, "dave"], 3).await;
    assert!(err.contains("try again in 600 seconds"), "{err}");
    // No account, and no key left behind.
    run(state, &["whoami"], 1).await;
    assert!(!state.join("keys/carol@example.org.pem").exists());
    // An IP address sends no hostname to sign (2.1).
    let (_, err) = run(state, &["register", "127.0.0.1:9", "carol"], 3).await;
    assert!(err.contains("hostname"), "{err}");
    let (_, err) = run(state, &["register", &taken.addr, "not a name"], 2).await;
    assert!(err.contains("invalid name"), "{err}");
}

/// Whether the fake received `line`, whatever its `ref`.
fn got(fake: &Fake, line: &str) -> bool {
    fake.log().iter().any(|l| {
        let l = l.split_once(' ').map_or("", |(_, l)| l);
        let l = match l.strip_prefix('@') {
            Some(tagged) => tagged.split_once(' ').map_or("", |(_, l)| l),
            None => l,
        };
        l == line
    })
}

#[tokio::test]
async fn read_names_members_and_blocks() {
    // 5.7, 7.4, 8.2, 8.3.
    let fake = Fake::start(|_, line| match verb(line) {
        "AUTH" => vec![format!("OK uid={}", word(line, 1))],
        "SYNC" => vec!["CONV #general k1 3 1".into(), "OK".into()],
        "BLOCKS" => vec!["BLOCK *@evil.example".into(), "OK".into()],
        "HISTORY" => vec![
            "@seq=1;t=2026-11-07T10:00:00.000Z;from=bob@example.net MSG #general one".into(),
            "@seq=2;t=2026-11-07T10:00:01.000Z;from=bob@example.net MSG #general two".into(),
            "@seq=3;t=2026-11-07T10:00:02.000Z;from=bob@example.net MSG #general three".into(),
            "OK id=k1 more=0".into(),
        ],
        "READ" | "NAME" | "BLOCK" | "UNBLOCK" => vec!["OK".into()],
        "MEMBERS" => vec![
            "MEMBER #general alice@example.org owner online Alice".into(),
            "MEMBER #general bob@example.net member offline Bob".into(),
            "MEMBER #general bob@example.org member away Bob".into(),
            "MEMBER #general ~sam member online".into(),
            "OK".into(),
        ],
        "WHOIS" => vec!["USER bob@example.net offline Bob".into(), "OK".into()],
        _ => vec!["ERR unknown-command".into()],
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let pem = dir.path().join("alice.pem");
    std::fs::write(&pem, PEM).unwrap();
    run(&state, &["trust", &fake.addr, &fake.fingerprint], 0).await;
    let pem_arg = pem.to_str().unwrap();
    run(
        &state,
        &["login", &fake.addr, "alice@example.org", "--key", pem_arg],
        0,
    )
    .await;
    let addr = fake.addr.as_str();

    let (out, _) = run(&state, &["read", addr, "#general", "2"], 0).await;
    assert_eq!(out.trim(), "#general: read up to 2, 1 unread");
    assert!(got(&fake, "READ #general 2"), "{:?}", fake.log());
    let (out, _) = run(&state, &["read", addr, "#general"], 0).await;
    assert_eq!(out.trim(), "#general: read up to 3, 0 unread");
    assert!(got(&fake, "READ #general 3"), "{:?}", fake.log());

    let (out, _) = run(&state, &["name", addr, "Alice", "M"], 0).await;
    assert_eq!(out.trim(), "display name set to Alice M");
    assert!(got(&fake, "NAME Alice M"));
    let (out, _) = run(&state, &["name", addr], 0).await;
    assert_eq!(out.trim(), "display name cleared");
    assert!(got(&fake, "NAME"));

    let (out, _) = run(&state, &["members", addr, "#general"], 0).await;
    assert_eq!(
        out.lines().collect::<Vec<_>>(),
        [
            "alice@example.org owner online Alice",
            "bob@example.net member offline Bob",
            "bob@example.org member online Bob",
            "~sam member online",
        ]
    );
    let (out, _) = run(&state, &["whois", addr, "bob@example.net"], 0).await;
    assert_eq!(out.trim(), "bob@example.net offline Bob");

    let (out, _) = run(&state, &["block", addr, "troll@example.com"], 0).await;
    assert_eq!(out.trim(), "blocked troll@example.com");
    assert!(got(&fake, "BLOCK troll@example.com"));
    let (out, _) = run(&state, &["unblock", addr, "troll@example.com"], 0).await;
    assert_eq!(out.trim(), "unblocked troll@example.com");
    let (out, err) = run(&state, &["blocks", addr, "--hide"], 0).await;
    assert_eq!(out.trim(), "*@evil.example");
    assert!(err.contains("hidden in rooms"), "{err}");
    let (_, err) = run(&state, &["blocks", addr, "--show"], 0).await;
    assert!(!err.contains("hidden"), "{err}");
    run(&state, &["block", addr, "~sam"], 2).await;
}
