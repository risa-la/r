//! Helpers for the end-to-end tests of the client against a real server.

#![allow(dead_code)]

use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use librisala::client::{Account, AccountEvent, AccountEvents, Client, ClientOptions};
use librisala::conn::{Backoff, SessionOptions, roots_ca_verifier};
use librisala::proto::server::{ServerLine, ServerMessage};
use librisala::sync::SyncConfig;
use risala_server::testing::{TestClient, TestServer};

/// How long any one wait in these tests may take before the test fails.
pub const LONG: Duration = Duration::from_secs(30);

/// Fails the test instead of hanging.
pub async fn within<T>(what: &str, f: impl Future<Output = T>) -> T {
    match tokio::time::timeout(LONG, f).await {
        Ok(t) => t,
        Err(_) => panic!("timed out: {what}"),
    }
}

/// Client options for tests: a CA check with an unrelated root, so the
/// test server's self-signed certificate goes through trust on first use
/// (2.2); fast reconnects; small pages, so catching up takes many.
pub fn options(page_size: u64) -> ClientOptions {
    let ca = rcgen::generate_simple_self_signed(vec!["unrelated.test".to_owned()]).unwrap();
    ClientOptions {
        session: SessionOptions {
            ca_verifier: Some(roots_ca_verifier([ca.cert.der().clone()]).unwrap()),
            connect_timeout: Duration::from_secs(10),
            ..SessionOptions::default()
        },
        backoff: Backoff {
            initial: Duration::from_millis(5),
            max: Duration::from_millis(30),
            stable_after: Duration::from_secs(60),
        },
        sync: SyncConfig {
            page_size,
            lazy_gap: None,
            ..SyncConfig::default()
        },
        ..ClientOptions::default()
    }
}

/// The address to give the client for a socket address on 127.0.0.1.
pub fn addr_of(addr: SocketAddr) -> String {
    format!("127.0.0.1:{}", addr.port())
}

/// A client in memory that trusts the test server at `addr`.
pub fn trusting_client(server: &TestServer, addr: SocketAddr, page_size: u64) -> (Client, String) {
    let client = Client::open_in_memory(options(page_size)).unwrap();
    let addr = addr_of(addr);
    client
        .accept_fingerprint(&addr, &server.fingerprint().to_string())
        .unwrap();
    (client, addr)
}

/// Reads until the final OK or ERR; returns the lines before it and it.
pub async fn until_final(c: &mut TestClient) -> (Vec<String>, String) {
    let mut lines = Vec::new();
    loop {
        let line = c.expect_line().await.unwrap();
        let bare = match line.strip_prefix('@') {
            Some(rest) => rest.split_once(' ').map_or("", |(_, r)| r),
            None => &line,
        };
        if bare == "OK" || bare.starts_with("OK ") || bare.starts_with("ERR ") {
            return (lines, line);
        }
        lines.push(line);
    }
}

/// Signs in as a guest on the server and joins `room`.
pub async fn guest_in(server: &TestServer, name: &str, room: &str) -> TestClient {
    let mut c = server.guest(name).await;
    c.send(&format!("JOIN {room}")).await.unwrap();
    let (_, ok) = until_final(&mut c).await;
    assert!(ok.starts_with("OK id="), "{ok}");
    c
}

/// Posts a message and returns its seq.
pub async fn post(c: &mut TestClient, room: &str, text: &str) -> u64 {
    c.send(&format!("@ref=p MSG {room} {text}")).await.unwrap();
    loop {
        let line = c.expect_line().await.unwrap();
        if let Some(seq) = line.strip_prefix("@ref=p OK seq=") {
            return seq.parse().unwrap();
        }
        assert!(!line.starts_with("@ref=p ERR"), "{line}");
    }
}

/// Every event the server keeps for `room`, in canonical form, read
/// with HISTORY by a guest that does not join. Each call signs in under a
/// new name, since a guest's name stays taken for a while after it leaves
/// (4.2).
pub async fn server_history(server: &TestServer, room: &str) -> Vec<String> {
    static CHECKERS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let n = CHECKERS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut c = server.guest(&format!("checker{n}")).await;
    let mut out = Vec::new();
    let mut after = 0;
    loop {
        c.send(&format!("HISTORY {room} after={after} limit=500"))
            .await
            .unwrap();
        let (lines, ok) = until_final(&mut c).await;
        for line in lines {
            let msg: ServerMessage = line.parse().unwrap();
            if let ServerLine::Event(e) = &msg.line {
                after = e.meta.as_ref().unwrap().seq.get();
            }
            out.push(msg.to_line().to_string());
        }
        assert!(ok.starts_with("OK id="), "{ok}");
        if ok.ends_with("more=0") {
            break;
        }
    }
    let _ = c.close().await;
    out
}

/// A small deterministic random number generator (xorshift).
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// A number in `lo..hi`.
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next() % (hi - lo)
    }
}

// ---------------------------------------------------------------------------
// Identities the test server hosts

/// The test server's hostname and identity domain. The clients connect to
/// its address on 127.0.0.1 while sending `chat.test` in SNI.
pub const HOST: &str = "chat.test";

/// A server that hosts identities under `chat.test`, with `rooms`, and
/// `f` applied to its configuration.
pub async fn hosted_server(
    rooms: &[&str],
    f: impl FnOnce(&mut risala_server::config::Config),
) -> TestServer {
    let mut builder = TestServer::builder().hostname(HOST);
    for room in rooms {
        builder = builder.room(room);
    }
    builder
        .configure(|c| {
            c.identity_domain = Some(HOST.to_owned());
            c.server.registration = true;
            c.limits.registrations_per_hour = 0;
            f(c);
        })
        .start()
        .await
}

/// A device: a client of its own, with its own key store, that trusts the
/// server and reaches it at `at`. Returns it and the server address to
/// use.
pub fn device_at(server: &TestServer, at: SocketAddr) -> (Client, String) {
    let mut options: ClientOptions = options(50);
    options.session.connect_to = Some(at);
    options.keys = Some(std::sync::Arc::new(
        librisala::conn::keys::MemoryKeyStore::default(),
    ));
    let client = Client::open_in_memory(options).unwrap();
    let addr = format!("{HOST}:{}", server.addr().port());
    client
        .accept_fingerprint(&addr, &server.fingerprint().to_string())
        .unwrap();
    (client, addr)
}

/// A device that reaches the server directly.
pub fn device(server: &TestServer) -> (Client, String) {
    device_at(server, server.addr())
}

/// Registers `<name>@chat.test` on a new device reaching the server at
/// `at`, and signs it in.
pub async fn registered_at(server: &TestServer, at: SocketAddr, name: &str) -> Account {
    let (client, addr) = device_at(server, at);
    let account = within("REGISTER", client.register(&addr, name))
        .await
        .unwrap();
    within("signing in", account.connect()).await.unwrap();
    within("syncing", account.wait_synced()).await.unwrap();
    account
}

/// Registers `<name>@chat.test` on a new device and signs it in.
pub async fn registered(server: &TestServer, name: &str) -> Account {
    registered_at(server, server.addr(), name).await
}

/// Registers `<name>@chat.test` on a new device, signs it in and joins
/// `room`.
pub async fn registered_in(server: &TestServer, name: &str, room: &str) -> Account {
    let account = registered(server, name).await;
    within("joining", account.join(room)).await.unwrap();
    within("syncing", account.wait_synced()).await.unwrap();
    account
}

/// A second device of `account`'s identity: a new key, added from the
/// first device (4.7), signed in.
pub async fn second_device(server: &TestServer, account: &Account) -> Account {
    let (client, addr) = device(server);
    let uid = account.uid();
    client.create_device_key(&uid, false).await.unwrap();
    let line = client.key_line(&uid, "phone").unwrap();
    within("KEY ADD", account.add_key(&line, "")).await.unwrap();
    let other = client.add_identity(&addr, &uid).unwrap();
    within("signing in", other.connect()).await.unwrap();
    within("syncing", other.wait_synced()).await.unwrap();
    other
}

/// Waits until `f` holds, checking after each event.
pub async fn until(what: &str, events: &AccountEvents, f: impl Fn() -> bool) {
    within(what, async {
        while !f() {
            let _ = tokio::time::timeout(Duration::from_millis(200), events.next()).await;
        }
    })
    .await;
}

/// Waits for the first event that `f` picks.
pub async fn event<T>(
    what: &str,
    events: &AccountEvents,
    f: impl Fn(&AccountEvent) -> Option<T>,
) -> T {
    within(what, async {
        loop {
            if let Some(t) = f(&events.next().await.expect("an event")) {
                return t;
            }
        }
    })
    .await
}
