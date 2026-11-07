//! The HTTPS listener and the key file directory, end to end with the
//! key file fetcher (4.4, 4.6).

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use risala_keyfetch::{FetchError, FetchOptions, KeyFetcher, Roots, StaticResolver};
use risala_proto::auth::{PublicKey, SecretKey};
use risala_proto::keyfile::KeyEntry;
use risala_proto::names::{Identity, Name};
use rustls::pki_types::CertificateDer;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::server::{MAX_REQUEST_HEAD, handle};
use super::{HttpServer, KeyDir, KeyFiles};
use crate::config::{CertPair, Config};
use crate::core::KeyFilePublisher;
use crate::net::Certificates;

/// A test CA. Its certificates are written to a directory as PEM files.
struct TestCa {
    root: CertificateDer<'static>,
    root_pem: String,
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
}

impl TestCa {
    fn new() -> TestCa {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "risala test CA");
        let key = rcgen::KeyPair::generate().unwrap();
        let root = params.self_signed(&key).unwrap();
        TestCa {
            root: root.der().clone(),
            root_pem: root.pem(),
            issuer: rcgen::Issuer::new(params, key),
        }
    }

    /// Issues a certificate for `names` and writes it and its key to `dir`.
    fn issue(&self, dir: &Path, names: &[&str]) -> CertPair {
        let params =
            rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
                .unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &self.issuer).unwrap();
        let pair = CertPair {
            cert: dir.join(format!("{}.pem", names[0])),
            key: dir.join(format!("{}.key", names[0])),
        };
        std::fs::write(&pair.cert, cert.pem()).unwrap();
        std::fs::write(&pair.key, key.serialize_pem()).unwrap();
        pair
    }
}

fn entry(seed: u8, label: &str) -> KeyEntry {
    KeyEntry::new(SecretKey::from_seed([seed; 32]).public_key(), Some(label)).unwrap()
}

fn key(seed: u8) -> PublicKey {
    SecretKey::from_seed([seed; 32]).public_key()
}

fn name(s: &str) -> Name {
    s.parse().unwrap()
}

fn id(s: &str) -> Identity {
    s.parse().unwrap()
}

/// A fetcher that trusts `ca` and sends `example.test` to `addr`.
fn fetcher(ca: &TestCa, addr: SocketAddr) -> KeyFetcher {
    KeyFetcher::new(FetchOptions {
        roots: Roots::Only(vec![ca.root.clone()]),
        allow_private: true,
        resolver: Arc::new(StaticResolver::new().with("example.test", [addr])),
        ..FetchOptions::default()
    })
}

#[tokio::test]
async fn listener_serves_published_key_files() {
    let tmp = tempfile::tempdir().unwrap();
    let ca = TestCa::new();
    let pair = ca.issue(tmp.path(), &["example.test"]);
    let keys = Arc::new(KeyDir::new(tmp.path().join("keys")));
    let certs = Certificates::from_pairs(vec![pair]).unwrap();
    let server =
        HttpServer::bind(&["127.0.0.1:0".parse().unwrap()], certs, true, keys.clone()).unwrap();
    let addr = server.local_addrs()[0];
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let running = tokio::spawn(server.run(async {
        let _ = stopped.await;
    }));

    let fetcher = fetcher(&ca, addr);
    let alice = id("alice@example.test");
    assert_eq!(
        fetcher.fetch(&alice, false).await,
        Err(FetchError::Status(404))
    );

    keys.publish(&name("alice"), &[entry(1, "laptop"), entry(2, "phone")])
        .unwrap();
    fetcher.invalidate(&alice);
    assert_eq!(fetcher.fetch(&alice, false).await, Ok(vec![key(1), key(2)]));
    let entries = fetcher.fetch_entries(&alice, false).await.unwrap();
    assert_eq!(entries[1].label(), Some("phone"));

    // KEY DEL republishes the file.
    keys.publish(&name("alice"), &[entry(2, "phone")]).unwrap();
    fetcher.invalidate(&alice);
    assert_eq!(fetcher.fetch(&alice, false).await, Ok(vec![key(2)]));

    // UNREGISTER removes it.
    keys.remove(&name("alice")).unwrap();
    fetcher.invalidate(&alice);
    assert_eq!(
        fetcher.fetch(&alice, false).await,
        Err(FetchError::Status(404))
    );

    stop.send(()).unwrap();
    running.await.unwrap().unwrap();
}

/// Sends `request` to the listener's request handling and returns the
/// response.
async fn exchange(keys: &Arc<KeyDir>, request: &[u8]) -> String {
    let (mut client, mut server) = tokio::io::duplex(1 << 20);
    let keys: Arc<dyn KeyFiles> = keys.clone();
    let task = tokio::spawn(async move { handle(&mut server, &keys).await });
    client.write_all(request).await.unwrap();
    client.shutdown().await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    task.await.unwrap();
    String::from_utf8(response).unwrap()
}

#[tokio::test]
async fn responses() {
    let tmp = tempfile::tempdir().unwrap();
    let keys = Arc::new(KeyDir::new(tmp.path()));
    keys.publish(&name("alice"), &[entry(1, "laptop")]).unwrap();
    let file = KeyDir::render(&[entry(1, "laptop")]);

    let get = exchange(
        &keys,
        b"GET /.well-known/risala/alice HTTP/1.1\r\nHost: example.test\r\n\r\n",
    )
    .await;
    let (head, body) = get.split_once("\r\n\r\n").unwrap();
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
    assert!(head.contains("\r\nContent-Type: text/plain; charset=utf-8\r\n"));
    assert!(head.contains(&format!("\r\nContent-Length: {}\r\n", file.len())));
    assert!(head.contains("\r\nConnection: close"));
    assert_eq!(body, file);

    // Names are case-insensitive; queries are ignored.
    let upper = exchange(&keys, b"GET /.well-known/risala/ALICE?x=1 HTTP/1.0\r\n\r\n").await;
    assert!(upper.starts_with("HTTP/1.1 200 OK\r\n"));

    let head_only = exchange(&keys, b"HEAD /.well-known/risala/alice HTTP/1.1\r\n\r\n").await;
    let (head, body) = head_only.split_once("\r\n\r\n").unwrap();
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(head.contains(&format!("\r\nContent-Length: {}\r\n", file.len())));
    assert_eq!(body, "");

    for path in [
        "/",
        "/.well-known/risala/",
        "/.well-known/risala/bob",
        "/.well-known/risala/.alice.tmp",
        "/.well-known/risala/../keys/alice",
        "/.well-known/risala/alice/",
    ] {
        let response = exchange(&keys, format!("GET {path} HTTP/1.1\r\n\r\n").as_bytes()).await;
        assert!(response.starts_with("HTTP/1.1 404 "), "{path}: {response}");
    }

    for method in ["POST", "PUT", "DELETE", "OPTIONS"] {
        let response = exchange(
            &keys,
            format!("{method} /.well-known/risala/alice HTTP/1.1\r\n\r\n").as_bytes(),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 405 "), "{method}");
        assert!(response.contains("\r\nAllow: GET, HEAD\r\n"));
    }

    for bad in [
        &b"hello\r\n\r\n"[..],
        b"GET http://a/ HTTP/1.1\r\n\r\n",
        b"GET /",
    ] {
        let response = exchange(&keys, bad).await;
        assert!(response.starts_with("HTTP/1.1 400 "), "{response}");
    }

    let mut long = b"GET / HTTP/1.1\r\n".to_vec();
    long.extend(std::iter::repeat_n(b'a', MAX_REQUEST_HEAD));
    long.extend(b"\r\n\r\n");
    assert!(exchange(&keys, &long).await.starts_with("HTTP/1.1 431 "));
}

/// `risalad`'s listener serves the key files of the identities it hosts,
/// from its records, and nothing else that is in `key_dir` (4.6).
#[tokio::test]
async fn daemon_runs_the_listener() {
    let tmp = tempfile::tempdir().unwrap();
    let ca = TestCa::new();
    let pair = ca.issue(tmp.path(), &["example.test"]);
    let root = tmp.path().join("ca.pem");
    std::fs::write(&root, &ca.root_pem).unwrap();

    let mut config = Config {
        listen: vec!["127.0.0.1:0".parse().unwrap()],
        state_dir: tmp.path().join("state"),
        identity_domain: Some("example.test".into()),
        ..Config::default()
    };
    config.http.listen = vec!["127.0.0.1:0".parse().unwrap()];
    config.http.certs = vec![pair];
    config.keys.allow_private = true;
    config.keys.extra_roots = vec![root];

    // alice is hosted. Files for other names are in the key directory
    // too: one the server wrote for a name it no longer hosts, which it
    // removes when it starts, and others of the operator's.
    std::fs::create_dir_all(config.key_dir()).unwrap();
    {
        use crate::store::Store as _;
        let store = crate::store::SqliteStore::open(&config.database_path()).unwrap();
        let alice: risala_proto::names::Uid = "alice@example.test".parse().unwrap();
        let now = risala_proto::time::Timestamp::now();
        store.register(&alice, &key(7), now).unwrap();
        store
            .add_hosted_key(&alice, &key(7), "laptop", 64, now)
            .unwrap();
    }
    let stale = config.key_dir().join("bob");
    std::fs::write(&stale, KeyDir::render(&[entry(8, "old")])).unwrap();
    let other = config.key_dir().join("carol");
    std::fs::write(&other, "not a key file\n").unwrap();

    let daemon = crate::Daemon::bind(config.clone()).await.unwrap();
    let addr = daemon.http_addrs()[0];
    assert_eq!(daemon.key_dir().dir(), tmp.path().join("state/keys"));
    // Published at startup, and the stale file is gone.
    assert_eq!(
        daemon.key_dir().read(&name("alice")).unwrap(),
        Some(KeyDir::render(&[entry(7, "laptop")]).into_bytes())
    );
    assert!(!stale.exists());
    assert!(other.exists());
    // A file someone writes to the directory is not served.
    std::fs::write(
        config.key_dir().join("dave"),
        KeyDir::render(&[entry(9, "x")]),
    )
    .unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let running = tokio::spawn(daemon.run(async {
        let _ = stopped.await;
    }));

    // The fetcher as the configuration sets it up, with the test CA among
    // its roots, and a resolver that knows the test domain.
    let options = super::fetch::fetch_options(&config.keys).unwrap();
    assert!(options.allow_private);
    let fetcher = KeyFetcher::new(FetchOptions {
        resolver: Arc::new(StaticResolver::new().with("example.test", [addr])),
        ..options
    });
    assert_eq!(
        fetcher.fetch(&id("alice@example.test"), false).await,
        Ok(vec![key(7)])
    );
    for nobody in ["carol", "dave", "bob"] {
        assert_eq!(
            fetcher
                .fetch(&id(&format!("{nobody}@example.test")), false)
                .await,
            Err(FetchError::Status(404)),
            "{nobody}"
        );
    }
    // Through the server's trait, as the hub calls it.
    let fetcher = super::HttpsKeyFetcher(fetcher);
    assert_eq!(
        crate::core::KeyFetcher::fetch(&fetcher, &id("alice@example.test"), true).await,
        Ok(vec![key(7)])
    );

    stop.send(()).unwrap();
    running.await.unwrap().unwrap();
}

#[tokio::test]
async fn http_listener_is_optional_and_shares_certificates() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = Config {
        listen: vec!["127.0.0.1:0".parse().unwrap()],
        state_dir: tmp.path().to_owned(),
        ..Config::default()
    };
    let daemon = crate::Daemon::bind(config.clone()).await.unwrap();
    assert!(daemon.http_addrs().is_empty());
    drop(daemon);

    // Without http.certs, the self-signed certificate of the risala
    // listener is used.
    config.http.listen = vec!["127.0.0.1:0".parse().unwrap()];
    let daemon = crate::Daemon::bind(config).await.unwrap();
    assert_eq!(daemon.http_addrs().len(), 1);

    // A missing extra root fails at startup.
    let mut config = Config {
        listen: vec!["127.0.0.1:0".parse().unwrap()],
        state_dir: tmp.path().to_owned(),
        ..Config::default()
    };
    config.keys.extra_roots = vec![tmp.path().join("missing.pem")];
    assert!(crate::Daemon::bind(config).await.is_err());
}
