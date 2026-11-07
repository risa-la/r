//! Helpers for the end-to-end tests of the client against a real server.

#![allow(dead_code)]

use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use librisala::client::{Client, ClientOptions};
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
/// with HISTORY by a guest that does not join.
pub async fn server_history(server: &TestServer, room: &str) -> Vec<String> {
    let mut c = server.guest("checker").await;
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
