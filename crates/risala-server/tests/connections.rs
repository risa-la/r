//! Connections over TLS against a whole server (draft-03): the greeting
//! (4.1), anonymous connections and guests (4.2), the line limits of each
//! kind of connection (2.3), and closing (11).
//!
//! The hub's own tests (`src/core/tests/`) cover each rule without
//! sockets. These check that the rules hold end to end, through TLS,
//! framing and the connection tasks.

use std::time::Duration;

use risala_proto::frame::{MAX_CLIENT_LINE, MAX_REGISTER_LINE};
use risala_server::testing::{Proxy, TestClient, TestServer};

/// `n` bytes of zeros in base64 with padding.
fn b64(n: usize) -> String {
    let tail = match n % 3 {
        0 => "",
        1 => "AA==",
        _ => "AAA=",
    };
    format!("{}{tail}", "A".repeat(n / 3 * 4))
}

const BOX: &str = "ujzdegxdncf32epf3dhodzdoci";

#[tokio::test]
async fn greeting_then_anon() {
    let server = TestServer::builder().welcome("Hello\\nthere").start().await;
    let mut client = server.connect().await;
    let greeting = client.expect_line().await.unwrap();
    let words: Vec<&str> = greeting.split(' ').collect();
    assert_eq!(words[..3], ["RISALA", "1", "localhost"], "{greeting}");
    assert_eq!(words[3].len(), 64, "{greeting}");
    assert_eq!(words[4..], ["Hello\\nthere"]);
    client.send("@ref=1 ANON").await.unwrap();
    assert_eq!(client.expect_line().await.unwrap(), "@ref=1 OK");
    client.send("ANON").await.unwrap();
    assert_eq!(
        client.expect_line().await.unwrap(),
        "ERR already-authenticated"
    );
    client.send("QUIT").await.unwrap();
    assert_eq!(client.recv_until_closed().await.unwrap(), ["OK"]);
    server.stop().await;
}

/// The line limits follow the kind (2.3): a new connection may send
/// REGISTER, KEYS and PAIR of up to 64 KiB and nothing else long; an
/// anonymous one may send long POSTs, and REGISTER only within the normal
/// limit.
#[tokio::test]
async fn line_limits_follow_the_kind() {
    let server = TestServer::start().await;
    let mut client = server.connect().await;
    client.expect_line().await.unwrap();

    let post = format!("@ref=p POST {BOX} {} {}", b64(32), b64(3 * MAX_CLIENT_LINE));
    let register = format!(
        "@ref=r REGISTER alice {} {}",
        b64(3 * MAX_CLIENT_LINE),
        b64(2420)
    );
    assert!(register.len() < MAX_REGISTER_LINE);
    client.send(&post).await.unwrap();
    assert_eq!(
        client.expect_line().await.unwrap(),
        "@ref=p ERR too-long too long"
    );
    // REGISTER passes the framing, and reaches the hub (4.7), which hosts
    // no identities here.
    client.send(&register).await.unwrap();
    assert_eq!(
        client.expect_line().await.unwrap(),
        "@ref=r ERR not-supported this server does not offer registration"
    );
    let too_big = format!(
        "@ref=b REGISTER alice {} {}",
        b64(MAX_REGISTER_LINE),
        b64(2420)
    );
    client.send(&too_big).await.unwrap();
    assert_eq!(
        client.expect_line().await.unwrap(),
        "@ref=b ERR too-long too long"
    );

    client.send("ANON").await.unwrap();
    assert_eq!(client.expect_line().await.unwrap(), "OK");
    client.send(&post).await.unwrap();
    assert_eq!(
        client.expect_line().await.unwrap(),
        "@ref=p ERR not-supported"
    );
    client.send(&register).await.unwrap();
    assert_eq!(
        client.expect_line().await.unwrap(),
        "@ref=r ERR too-long too long"
    );
    // The connection still works.
    client.send("@ref=x PING").await.unwrap();
    assert_eq!(client.expect_line().await.unwrap(), "@ref=x OK");
    server.stop().await;
}

/// A guest whose network drops resumes its session on a new connection
/// with its token (4.2), and a clean shutdown ends every session.
#[tokio::test]
async fn a_guest_resumes_after_a_dropped_connection() {
    let server = TestServer::start().await;
    let proxy = Proxy::start(server.addr()).await;
    let options = risala_server::testing::ClientOptions::sni("localhost");
    let mut sam = TestClient::connect_with(proxy.addr(), options.clone())
        .await
        .unwrap();
    sam.expect_line().await.unwrap();
    sam.send("GUEST sam").await.unwrap();
    let ok = sam.expect_line().await.unwrap();
    let token = ok
        .strip_prefix("OK uid=~sam token=")
        .unwrap_or_else(|| panic!("{ok}"))
        .to_owned();

    proxy.cut();
    assert!(sam.recv_until_closed().await.is_ok());
    // Until the server notices, or while it waits, the name is taken.
    let mut other = server.connect().await;
    other.expect_line().await.unwrap();
    other.send("GUEST sam").await.unwrap();
    assert_eq!(other.expect_line().await.unwrap(), "ERR name-taken");

    let (mut back, new_token) = server.guest_session("sam", Some(&token)).await;
    assert_ne!(new_token, token);
    back.send("PING").await.unwrap();
    assert_eq!(back.expect_line().await.unwrap(), "OK");
    assert_eq!(server.hub().guest_sessions().len(), 1);

    // The other connection is still new, and can be a guest of its own.
    other.send("GUEST bea").await.unwrap();
    assert!(
        other
            .expect_line()
            .await
            .unwrap()
            .starts_with("OK uid=~bea token=")
    );

    let hub = server.hub().clone();
    server.stop().await;
    // Sessions do not survive a shutdown (4.2).
    tokio::time::timeout(Duration::from_secs(10), async {
        while !hub.guest_sessions().is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

/// Without guests or anonymous connections allowed, GUEST and ANON are
/// refused (10.6).
#[tokio::test]
async fn kinds_can_be_turned_off() {
    let server = TestServer::builder()
        .guests(false)
        .anon(false)
        .start()
        .await;
    let mut client = server.connect().await;
    client.expect_line().await.unwrap();
    client.send("GUEST sam").await.unwrap();
    assert_eq!(
        client.expect_line().await.unwrap(),
        "ERR forbidden guests are not allowed"
    );
    client.send("ANON").await.unwrap();
    assert_eq!(
        client.expect_line().await.unwrap(),
        "ERR forbidden anonymous connections are off"
    );
    server.stop().await;
}
