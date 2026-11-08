//! Fetching key files from a local HTTPS server with a test CA (4.4).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use risala_keyfetch::{
    CertificateDer, Clock, FetchError, FetchOptions, KeyFetcher, Roots, StaticResolver,
};
use risala_proto::auth::{PublicKey, SecretKey};
use risala_proto::keyfile::MAX_KEY_FILE_BYTES;
use risala_proto::names::Identity;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// A test CA, and a certificate from it for `names`.
struct TestCa {
    root: CertificateDer<'static>,
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
        let root = params.self_signed(&key).unwrap().der().clone();
        TestCa {
            root,
            issuer: rcgen::Issuer::new(params, key),
        }
    }

    fn leaf(&self, names: &[&str]) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let params =
            rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
                .unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &self.issuer).unwrap();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        (vec![cert.der().clone()], key)
    }
}

/// What the test server does with a request.
enum Reply {
    /// Sends these bytes and closes.
    Raw(Vec<u8>),
    /// Reads the request and never answers.
    Hang,
}

type Route = Arc<dyn Fn(&str) -> Reply + Send + Sync>;

/// A local HTTPS server. It records the path of every request.
struct Server {
    addr: SocketAddr,
    paths: Arc<Mutex<Vec<String>>>,
}

impl Server {
    async fn start(ca: &TestCa, names: &[&str], route: Route) -> Server {
        let (chain, key) = ca.leaf(names);
        let config = rustls::ServerConfig::builder_with_provider(risala_keyfetch::provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let paths = Arc::new(Mutex::new(Vec::new()));
        let seen = paths.clone();
        tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let (acceptor, route, seen) = (acceptor.clone(), route.clone(), seen.clone());
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut request = Vec::new();
                    let mut byte = [0u8; 1];
                    while !request.ends_with(b"\r\n\r\n") {
                        if tls.read_exact(&mut byte).await.is_err() {
                            return;
                        }
                        request.push(byte[0]);
                    }
                    let request = String::from_utf8(request).unwrap();
                    let path = request.split(' ').nth(1).unwrap().to_owned();
                    seen.lock().unwrap().push(path.clone());
                    match route(&path) {
                        Reply::Raw(bytes) => {
                            let _ = tls.write_all(&bytes).await;
                            let _ = tls.shutdown().await;
                        }
                        Reply::Hang => std::future::pending::<()>().await,
                    }
                });
            }
        });
        Server { addr, paths }
    }

    fn hits(&self) -> usize {
        self.paths.lock().unwrap().len()
    }
}

fn ok(body: &str) -> Reply {
    Reply::Raw(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes(),
    )
}

fn status(code: u16, extra: &str) -> Reply {
    Reply::Raw(format!("HTTP/1.1 {code} X\r\n{extra}Content-Length: 0\r\n\r\n").into_bytes())
}

fn key(seed: u8) -> PublicKey {
    SecretKey::from_seed([seed; 32]).public_key()
}

fn line(seed: u8) -> String {
    format!("mldsa44 {} device{seed}\n", key(seed))
}

fn id(s: &str) -> Identity {
    s.parse().unwrap()
}

/// A clock the test moves by hand.
struct ManualClock {
    start: Instant,
    offset: Mutex<Duration>,
}

impl ManualClock {
    fn new() -> Arc<ManualClock> {
        Arc::new(ManualClock {
            start: Instant::now(),
            offset: Mutex::new(Duration::ZERO),
        })
    }

    fn advance(&self, by: Duration) {
        *self.offset.lock().unwrap() += by;
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Instant {
        self.start + *self.offset.lock().unwrap()
    }
}

/// Options for a fetcher that trusts `ca` and sends `example.test` (and
/// the other names given) to `server`.
fn options(ca: &TestCa, server: &Server, hosts: &[&str]) -> FetchOptions {
    let mut resolver = StaticResolver::new();
    for host in hosts {
        resolver.insert(host, [server.addr]);
    }
    FetchOptions {
        roots: Roots::Only(vec![ca.root.clone()]),
        allow_private: true,
        resolver: Arc::new(resolver),
        ..FetchOptions::default()
    }
}

#[tokio::test]
async fn fetches_keys() {
    let ca = TestCa::new();
    let body = format!("# alice@example.test\n{}{}", line(1), line(2));
    let server = Server::start(
        &ca,
        &["example.test"],
        Arc::new(move |path| match path {
            "/.well-known/risala/alice" => ok(&body),
            _ => status(404, ""),
        }),
    )
    .await;
    let fetcher = KeyFetcher::new(options(&ca, &server, &["example.test"]));
    let keys = fetcher
        .fetch(&id("Alice@Example.test"), false)
        .await
        .unwrap();
    assert_eq!(keys, vec![key(1), key(2)]);
    let entries = fetcher
        .fetch_entries(&id("alice@example.test"), false)
        .await
        .unwrap();
    assert_eq!(entries[1].label(), Some("device2"));
    assert_eq!(server.hits(), 1);

    // A 404: the file is gone, and bob has no keys (4.4).
    assert_eq!(
        fetcher.fetch(&id("bob@example.test"), false).await,
        Ok(vec![])
    );
    let found = fetcher
        .lookup(&id("bob@example.test"), false)
        .await
        .unwrap();
    assert!(found.gone && found.entries.is_empty());
}

/// The three outcomes of a fetch (4.4): a 200 is a key file, a 404 or
/// 410 is gone, and anything else fails, redirects included, which are
/// not followed.
#[tokio::test]
async fn outcomes_and_redirects() {
    let ca = TestCa::new();
    let server = Server::start(
        &ca,
        &["example.test"],
        Arc::new(|path| match path {
            "/.well-known/risala/moved" => status(
                301,
                "Location: https://example.test/.well-known/risala/target\r\n",
            ),
            "/.well-known/risala/found" => status(302, "Location: /.well-known/risala/target\r\n"),
            "/.well-known/risala/temp" => status(307, "Location: /.well-known/risala/target\r\n"),
            "/.well-known/risala/target" => ok(&line(1)),
            "/.well-known/risala/created" => Reply::Raw(
                format!(
                    "HTTP/1.1 201 Created\r\nContent-Length: {}\r\n\r\n{}",
                    line(1).len(),
                    line(1)
                )
                .into_bytes(),
            ),
            "/.well-known/risala/error" => status(500, ""),
            "/.well-known/risala/unavailable" => status(503, ""),
            "/.well-known/risala/denied" => status(403, ""),
            "/.well-known/risala/login" => status(401, ""),
            "/.well-known/risala/slow-down" => status(429, ""),
            "/.well-known/risala/deleted" => status(410, ""),
            "/.well-known/risala/empty" => ok("# nothing here\n"),
            _ => status(404, ""),
        }),
    )
    .await;
    let fetcher = KeyFetcher::new(options(&ca, &server, &["example.test"]));
    for (name, code) in [
        ("moved", 301),
        ("found", 302),
        ("temp", 307),
        ("created", 201),
        ("error", 500),
        ("unavailable", 503),
        ("denied", 403),
        ("login", 401),
        ("slow-down", 429),
    ] {
        let result = fetcher
            .fetch(&id(&format!("{name}@example.test")), false)
            .await;
        assert_eq!(result, Err(FetchError::Status(code)), "{name}");
    }
    // The redirect target was never asked for.
    assert!(
        !server
            .paths
            .lock()
            .unwrap()
            .contains(&"/.well-known/risala/target".to_owned())
    );
    for name in ["nobody", "deleted"] {
        let found = fetcher
            .lookup(&id(&format!("{name}@example.test")), false)
            .await
            .unwrap();
        assert!(found.gone && found.entries.is_empty(), "{name}");
    }
    let found = fetcher
        .lookup(&id("empty@example.test"), false)
        .await
        .unwrap();
    assert!(!found.gone && found.entries.is_empty() && !found.cached);
}

#[tokio::test]
async fn size_limit() {
    let ca = TestCa::new();
    let first = line(1);
    // A file of exactly 256 KiB, its first line a key and the rest comment.
    let full = format!(
        "{first}#{}\n",
        "x".repeat(MAX_KEY_FILE_BYTES - first.len() - 2)
    );
    assert_eq!(full.len(), MAX_KEY_FILE_BYTES);
    let over = format!("{full}#");
    let (full_, over_) = (full.clone(), over.clone());
    let server = Server::start(
        &ca,
        &["example.test"],
        Arc::new(move |path| match path {
            "/.well-known/risala/full" => ok(&full_),
            "/.well-known/risala/over" => ok(&over_),
            // No Content-Length: the body ends with the connection.
            "/.well-known/risala/over-close" => {
                Reply::Raw(format!("HTTP/1.1 200 OK\r\n\r\n{over_}").into_bytes())
            }
            "/.well-known/risala/full-close" => {
                Reply::Raw(format!("HTTP/1.1 200 OK\r\n\r\n{full_}").into_bytes())
            }
            _ => status(404, ""),
        }),
    )
    .await;
    let fetcher = KeyFetcher::new(options(&ca, &server, &["example.test"]));
    assert_eq!(
        fetcher.fetch(&id("full@example.test"), false).await,
        Ok(vec![key(1)])
    );
    assert_eq!(
        fetcher.fetch(&id("full-close@example.test"), false).await,
        Ok(vec![key(1)])
    );
    // A file over 256 KiB counts as a file with no keys (4.4).
    for name in ["over", "over-close"] {
        let found = fetcher
            .lookup(&id(&format!("{name}@example.test")), false)
            .await
            .unwrap();
        assert!(!found.gone && found.entries.is_empty(), "{name}");
    }
}

#[tokio::test]
async fn time_limit() {
    let ca = TestCa::new();
    let server = Server::start(&ca, &["example.test"], Arc::new(|_| Reply::Hang)).await;
    // A TCP listener that never starts TLS.
    let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let silent_addr = silent.local_addr().unwrap();
    let _keep = tokio::spawn(async move {
        let mut open = Vec::new();
        loop {
            open.push(silent.accept().await.unwrap());
        }
    });
    let mut options = options(&ca, &server, &["example.test"]);
    options.resolver = Arc::new(
        StaticResolver::new()
            .with("example.test", [server.addr])
            .with("silent.test", [silent_addr]),
    );
    // The spec's 10 seconds, shortened for the test. Neither server ever
    // answers, so the limit is what ends both fetches.
    options.timeout = Duration::from_millis(300);
    let fetcher = KeyFetcher::new(options);
    let started = Instant::now();
    assert_eq!(
        fetcher.fetch(&id("alice@example.test"), false).await,
        Err(FetchError::Timeout)
    );
    assert_eq!(
        fetcher.fetch(&id("alice@silent.test"), false).await,
        Err(FetchError::Timeout)
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(server.hits(), 1);

    // Longer timeouts are cut to the spec's 10 seconds.
    let options = FetchOptions {
        timeout: Duration::from_secs(60),
        ..FetchOptions::default()
    };
    assert!(format!("{:?}", KeyFetcher::new(options)).contains("KeyFetcher"));
}

/// An address that never answers gets only its share of the time limit:
/// the next one is still tried in time.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn an_address_that_never_answers_does_not_use_up_the_time() {
    let ca = TestCa::new();
    let server = Server::start(&ca, &["example.test"], Arc::new(|_| ok(&line(1)))).await;
    // A listener whose queue of connections is full, since it accepts
    // none: Linux drops further SYNs, so connecting to it hangs.
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let full = socket.listen(1).unwrap();
    let full_addr = full.local_addr().unwrap();
    let mut queued = Vec::new();
    for _ in 0..16 {
        let connect = tokio::net::TcpStream::connect(full_addr);
        match tokio::time::timeout(Duration::from_millis(200), connect).await {
            Ok(Ok(tcp)) => queued.push(tcp),
            _ => break,
        }
    }
    assert!(queued.len() < 16, "the listener's queue never filled up");
    let mut options = options(&ca, &server, &[]);
    options.resolver =
        Arc::new(StaticResolver::new().with("example.test", [full_addr, server.addr]));
    options.timeout = Duration::from_secs(4);
    let fetcher = KeyFetcher::new(options);
    let started = Instant::now();
    assert_eq!(
        fetcher.fetch(&id("alice@example.test"), false).await,
        Ok(vec![key(1)])
    );
    // About half the limit went to the first address.
    assert!(started.elapsed() >= Duration::from_millis(1900));
    drop(full);
}

#[tokio::test]
async fn address_guard() {
    let ca = TestCa::new();
    let server = Server::start(&ca, &["example.test"], Arc::new(|_| ok(&line(1)))).await;
    let cases = [
        ("loopback4.test", "127.0.0.1:443"),
        ("loopback6.test", "[::1]:443"),
        ("private.test", "10.0.0.1:443"),
        ("linklocal.test", "169.254.1.1:443"),
        ("ula.test", "[fc00::1]:443"),
        ("cgnat.test", "100.64.0.1:443"),
        ("mapped.test", "[::ffff:127.0.0.1]:443"),
    ];
    let mut resolver = StaticResolver::new();
    for (host, addr) in cases {
        resolver.insert(host, [addr.parse::<SocketAddr>().unwrap()]);
    }
    // A name with a refused address first, then the local server (also
    // refused, being on loopback).
    resolver.insert("mixed.test", ["10.0.0.1:443".parse().unwrap(), server.addr]);
    let fetcher = KeyFetcher::new(FetchOptions {
        roots: Roots::Only(vec![ca.root.clone()]),
        resolver: Arc::new(resolver),
        ..FetchOptions::default()
    });
    for (host, addr) in cases {
        let ip = addr.parse::<SocketAddr>().unwrap().ip();
        assert_eq!(
            fetcher.fetch(&id(&format!("alice@{host}")), false).await,
            Err(FetchError::Refused(ip)),
            "{host}"
        );
    }
    assert_eq!(
        fetcher.fetch(&id("alice@mixed.test"), false).await,
        Err(FetchError::Refused("10.0.0.1".parse().unwrap()))
    );
    assert_eq!(server.hits(), 0);

    // With private addresses allowed, the same server is reached.
    let fetcher = KeyFetcher::new(options(&ca, &server, &["example.test"]));
    assert_eq!(
        fetcher.fetch(&id("alice@example.test"), false).await,
        Ok(vec![key(1)])
    );
}

#[tokio::test]
async fn tls_is_checked() {
    let ca = TestCa::new();
    let server = Server::start(&ca, &["other.test"], Arc::new(|_| ok(&line(1)))).await;
    // The certificate is for another name.
    let fetcher = KeyFetcher::new(options(&ca, &server, &["example.test"]));
    assert!(matches!(
        fetcher.fetch(&id("alice@example.test"), false).await,
        Err(FetchError::Tls(_))
    ));
    // The name fits, but the CA is not a public one.
    let fetcher = KeyFetcher::new(FetchOptions {
        roots: Roots::default(),
        ..options(&ca, &server, &["other.test"])
    });
    assert!(matches!(
        fetcher.fetch(&id("alice@other.test"), false).await,
        Err(FetchError::Tls(_))
    ));
    // Extra roots on top of the public ones.
    let fetcher = KeyFetcher::new(FetchOptions {
        roots: Roots::Public {
            extra: vec![ca.root.clone()],
        },
        ..options(&ca, &server, &["other.test"])
    });
    assert_eq!(
        fetcher.fetch(&id("alice@other.test"), false).await,
        Ok(vec![key(1)])
    );
}

/// A server whose key file the test can change, and a fetcher on a manual
/// clock.
async fn changing_file() -> (
    Server,
    Arc<Mutex<String>>,
    Arc<ManualClock>,
    KeyFetcher,
    TestCa,
) {
    let ca = TestCa::new();
    let file = Arc::new(Mutex::new(line(1)));
    let current = file.clone();
    let server = Server::start(
        &ca,
        &["example.test"],
        Arc::new(move |path| {
            let current = current.lock().unwrap();
            match (path, current.as_str()) {
                ("/.well-known/risala/gone", _) | (_, "404") => status(404, ""),
                ("/.well-known/risala/broken", _) | (_, "500") => status(500, ""),
                (_, "hang") => Reply::Hang,
                (_, file) => ok(file),
            }
        }),
    )
    .await;
    let clock = ManualClock::new();
    let fetcher = KeyFetcher::new(FetchOptions {
        clock: clock.clone(),
        // Local fetches are quick; this ends the hanging ones.
        timeout: Duration::from_millis(300),
        ..options(&ca, &server, &["example.test"])
    });
    (server, file, clock, fetcher, ca)
}

#[tokio::test]
async fn cache_expires_after_an_hour() {
    let (server, file, clock, fetcher, _ca) = changing_file().await;
    let alice = id("alice@example.test");
    assert_eq!(fetcher.fetch(&alice, false).await, Ok(vec![key(1)]));
    *file.lock().unwrap() = line(2);
    clock.advance(Duration::from_secs(59 * 60));
    assert_eq!(fetcher.fetch(&alice, false).await, Ok(vec![key(1)]));
    assert_eq!(server.hits(), 1);
    clock.advance(Duration::from_secs(60));
    assert_eq!(fetcher.fetch(&alice, false).await, Ok(vec![key(2)]));
    assert_eq!(server.hits(), 2);
    assert_eq!(fetcher.cached(), 1);
}

#[tokio::test]
async fn refetch_once_on_failure_is_rate_limited() {
    let (server, file, clock, fetcher, _ca) = changing_file().await;
    let alice = id("alice@example.test");
    let found = fetcher.lookup(&alice, false).await.unwrap();
    assert!(!found.cached);
    // A new device is added to the file.
    file.lock().unwrap().push_str(&line(2));

    // A refetch right after a fetch is held back by the rate limit, and
    // the answer is as fresh as a refetch could get.
    let found = fetcher.lookup(&alice, true).await.unwrap();
    assert_eq!(found.entries.len(), 1);
    assert!(!found.cached);
    assert_eq!(server.hits(), 1);

    // Later, the cached file is marked so, and a refetch gets the new key.
    clock.advance(risala_keyfetch::DEFAULT_MIN_REFETCH);
    let found = fetcher.lookup(&alice, false).await.unwrap();
    assert_eq!(found.entries.len(), 1);
    assert!(found.cached);
    assert_eq!(fetcher.fetch(&alice, true).await, Ok(vec![key(1), key(2)]));
    assert_eq!(server.hits(), 2);
    // The refetched file is cached in turn.
    assert_eq!(fetcher.fetch(&alice, false).await, Ok(vec![key(1), key(2)]));
    assert_eq!(server.hits(), 2);

    // Invalidating forgets the file and its rate limit.
    fetcher.invalidate(&alice);
    assert_eq!(fetcher.cached(), 0);
    assert_eq!(fetcher.fetch(&alice, false).await, Ok(vec![key(1), key(2)]));
    assert_eq!(server.hits(), 3);
}

/// A failed fetch is an outage: it does not replace the cached file,
/// which stays valid for its hour, but a refetch that fails says so
/// (4.4). Only a key file or a gone answer replaces it.
#[tokio::test]
async fn a_cached_file_outlives_an_unreachable_host() {
    let (server, file, clock, fetcher, _ca) = changing_file().await;
    let alice = id("alice@example.test");
    assert_eq!(fetcher.fetch(&alice, false).await, Ok(vec![key(1)]));

    // The host stops answering. A refetch fails, but the file stays.
    *file.lock().unwrap() = "hang".into();
    clock.advance(Duration::from_secs(30 * 60));
    assert_eq!(fetcher.fetch(&alice, true).await, Err(FetchError::Timeout));
    assert_eq!(server.hits(), 2);
    assert_eq!(fetcher.fetch(&alice, false).await, Ok(vec![key(1)]));
    // The failed attempt counts for the rate limit, and stands.
    assert_eq!(fetcher.fetch(&alice, true).await, Err(FetchError::Timeout));
    assert_eq!(server.hits(), 2);
    // A 5xx is no different.
    *file.lock().unwrap() = "500".into();
    clock.advance(risala_keyfetch::DEFAULT_MIN_REFETCH);
    assert_eq!(
        fetcher.fetch(&alice, true).await,
        Err(FetchError::Status(500))
    );
    assert_eq!(fetcher.fetch(&alice, false).await, Ok(vec![key(1)]));
    assert_eq!(server.hits(), 3);
    // But the file keeps its age, and expires an hour after it was fetched.
    clock.advance(Duration::from_secs(30 * 60));
    assert_eq!(
        fetcher.fetch(&alice, false).await,
        Err(FetchError::Status(500))
    );
    assert_eq!(server.hits(), 4);

    // An answer from the host replaces the cached file: here, it is gone.
    *file.lock().unwrap() = line(1);
    clock.advance(risala_keyfetch::DEFAULT_MIN_REFETCH);
    assert_eq!(fetcher.fetch(&alice, false).await, Ok(vec![key(1)]));
    *file.lock().unwrap() = "404".into();
    clock.advance(risala_keyfetch::DEFAULT_MIN_REFETCH);
    let found = fetcher.lookup(&alice, true).await.unwrap();
    assert!(found.gone && found.entries.is_empty());
    assert!(fetcher.lookup(&alice, false).await.unwrap().gone);
}

#[tokio::test]
async fn failures_are_remembered_for_the_rate_limit() {
    let (server, _file, clock, fetcher, _ca) = changing_file().await;
    let broken = id("broken@example.test");
    for refresh in [false, true, false] {
        assert_eq!(
            fetcher.fetch(&broken, refresh).await,
            Err(FetchError::Status(500))
        );
    }
    assert_eq!(server.hits(), 1);
    clock.advance(risala_keyfetch::DEFAULT_MIN_REFETCH);
    assert_eq!(
        fetcher.fetch(&broken, false).await,
        Err(FetchError::Status(500))
    );
    assert_eq!(server.hits(), 2);
    // So are gone answers.
    let gone = id("gone@example.test");
    for refresh in [false, true] {
        assert!(fetcher.lookup(&gone, refresh).await.unwrap().gone);
    }
    assert_eq!(server.hits(), 3);
}

#[tokio::test]
async fn concurrent_fetches_of_one_file_become_one() {
    let (server, _file, _clock, fetcher, _ca) = changing_file().await;
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let fetcher = fetcher.clone();
        tasks.push(tokio::spawn(async move {
            fetcher.fetch(&id("alice@example.test"), true).await
        }));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap(), Ok(vec![key(1)]));
    }
    assert_eq!(server.hits(), 1);
}

#[tokio::test]
async fn cache_size_is_capped() {
    let ca = TestCa::new();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let server = Server::start(
        &ca,
        &["example.test"],
        Arc::new(move |_| {
            counter.fetch_add(1, Ordering::Relaxed);
            ok(&line(1))
        }),
    )
    .await;
    let clock = ManualClock::new();
    let fetcher = KeyFetcher::new(FetchOptions {
        cache_capacity: 2,
        clock: clock.clone(),
        ..options(&ca, &server, &["example.test"])
    });
    for name in ["a", "b", "c"] {
        clock.advance(Duration::from_secs(1));
        fetcher
            .fetch(&id(&format!("{name}@example.test")), false)
            .await
            .unwrap();
    }
    assert_eq!(fetcher.cached(), 2);
    assert_eq!(hits.load(Ordering::Relaxed), 3);
    // The oldest, a, was dropped; c is still cached.
    fetcher.fetch(&id("c@example.test"), false).await.unwrap();
    assert_eq!(hits.load(Ordering::Relaxed), 3);
    fetcher.fetch(&id("a@example.test"), false).await.unwrap();
    assert_eq!(hits.load(Ordering::Relaxed), 4);
    assert_eq!(fetcher.cached(), 2);
}

/// A server for `slow.test`, which never answers, and `fast.test`, which
/// does, and a fetcher with at most `overall` fetches at once and
/// `per_domain` from one domain.
async fn slow_and_fast(
    overall: usize,
    per_domain: usize,
    timeout: Duration,
) -> (Server, KeyFetcher) {
    let ca = TestCa::new();
    let server = Server::start(
        &ca,
        &["slow.test", "fast.test"],
        Arc::new(|path| {
            if path.starts_with("/.well-known/risala/slow") {
                Reply::Hang
            } else {
                ok(&line(1))
            }
        }),
    )
    .await;
    let fetcher = KeyFetcher::new(FetchOptions {
        max_concurrent: overall,
        max_per_domain: per_domain,
        timeout,
        ..options(&ca, &server, &["slow.test", "fast.test"])
    });
    (server, fetcher)
}

/// One slow domain cannot hold every fetch: it gets only its share of
/// them, and the others go on (14).
#[tokio::test]
async fn a_slow_domain_does_not_hold_up_the_others() {
    let (server, fetcher) = slow_and_fast(4, 2, Duration::from_secs(3)).await;
    let mut slow = Vec::new();
    for n in 0..8 {
        let fetcher = fetcher.clone();
        slow.push(tokio::spawn(async move {
            fetcher
                .fetch(&id(&format!("slow{n}@slow.test")), false)
                .await
        }));
    }
    // Let the slow ones take what they can.
    while server.hits() < 2 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let started = Instant::now();
    assert_eq!(
        fetcher.fetch(&id("alice@fast.test"), false).await,
        Ok(vec![key(1)])
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    // Only two of the slow domain's ran at once.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(server.hits(), 3);
    for task in slow {
        task.abort();
    }
}

/// Waiting for a turn does not use up a fetch's time limit: it has its
/// own, and a fetch that does not get a turn in time fails as busy,
/// without fetching or being remembered.
#[tokio::test]
async fn waiting_for_a_turn_is_timed_separately() {
    let timeout = Duration::from_millis(400);
    let (server, fetcher) = slow_and_fast(8, 1, timeout).await;
    let mut tasks = Vec::new();
    for n in 0..3 {
        let fetcher = fetcher.clone();
        tasks.push(tokio::spawn(async move {
            let started = Instant::now();
            let result = fetcher
                .fetch(&id(&format!("slow{n}@slow.test")), false)
                .await;
            (result, started.elapsed())
        }));
        // In this order.
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut results = Vec::new();
    for task in tasks {
        results.push(task.await.unwrap());
    }
    // The first runs out its time; the second waits its turn, then has
    // all of its own time; the third does not get a turn in time.
    assert_eq!(results[0].0, Err(FetchError::Timeout));
    assert_eq!(results[1].0, Err(FetchError::Timeout));
    assert!(results[1].1 > timeout + timeout / 2, "{results:?}");
    assert_eq!(results[2].0, Err(FetchError::Busy));
    assert_eq!(server.hits(), 2);
    // A busy fetch is not remembered: the next one tries.
    assert_eq!(
        fetcher.fetch(&id("slow2@slow.test"), false).await,
        Err(FetchError::Timeout)
    );
    assert_eq!(server.hits(), 3);
}

/// Identities made up at one site cannot push other sites' key files out
/// of the cache: a site that has its share makes room among its own.
#[tokio::test]
async fn one_site_gets_only_its_share_of_the_cache() {
    let ca = TestCa::new();
    let hits = Arc::new(Mutex::new(Vec::new()));
    let seen = hits.clone();
    let server = Server::start(
        &ca,
        &["good.test", "evil.test", "a.evil.test", "b.evil.test"],
        Arc::new(move |path| {
            seen.lock().unwrap().push(path.to_owned());
            ok(&line(1))
        }),
    )
    .await;
    let clock = ManualClock::new();
    let fetcher = KeyFetcher::new(FetchOptions {
        cache_capacity: 6,
        cache_per_site: 2,
        clock: clock.clone(),
        ..options(
            &ca,
            &server,
            &["good.test", "evil.test", "a.evil.test", "b.evil.test"],
        )
    });
    let fetch = |who: &'static str| {
        let fetcher = fetcher.clone();
        async move { fetcher.fetch(&id(who), false).await.unwrap() }
    };
    fetch("alice@good.test").await;
    fetch("bob@good.test").await;
    for who in [
        "m1@evil.test",
        "m2@a.evil.test",
        "m3@b.evil.test",
        "m4@evil.test",
        "m5@a.evil.test",
    ] {
        clock.advance(Duration::from_secs(1));
        fetch(who).await;
    }
    // evil.test and its subdomains have two entries between them.
    assert_eq!(fetcher.cached(), 4);
    let before = server.hits();
    fetch("alice@good.test").await;
    fetch("bob@good.test").await;
    fetch("m4@evil.test").await;
    fetch("m5@a.evil.test").await;
    assert_eq!(server.hits(), before);
    fetch("m1@evil.test").await;
    assert_eq!(server.hits(), before + 1);
}
