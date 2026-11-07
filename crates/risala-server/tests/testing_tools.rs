//! The tools in `risala_server::testing` that other crates use to break
//! things: the cutting proxy and `restart_with`.

use risala_server::testing::{ClientOptions, Proxy, TestClient, TestServer};

async fn guest_via(proxy: &Proxy, name: &str) -> TestClient {
    let mut client = TestClient::connect_with(proxy.addr(), ClientOptions::sni("localhost"))
        .await
        .unwrap();
    assert!(client.expect_line().await.unwrap().starts_with("RISALA 1 "));
    client.send(&format!("GUEST {name}")).await.unwrap();
    let ok = client.expect_line().await.unwrap();
    assert!(ok.starts_with(&format!("OK uid=~{name} token=")), "{ok}");
    client
}

#[tokio::test]
async fn proxy_forwards_and_cuts() {
    let server = TestServer::builder()
        .room("#a")
        .guest_resume(std::time::Duration::from_millis(200))
        .start()
        .await;
    let proxy = Proxy::start(server.addr()).await;
    let mut sam = guest_via(&proxy, "sam").await;
    sam.send("join #a").await.unwrap();
    assert!(sam.expect_line().await.unwrap().ends_with(" JOIN #a"));
    let mut ann = server.guest("ann").await;
    ann.send("join #a").await.unwrap();
    assert!(ann.expect_line().await.unwrap().ends_with(" JOIN #a"));

    proxy.cut();
    // The client sees the end of the stream, with no BYE.
    let rest = sam.recv_until_closed().await.unwrap();
    assert!(rest.iter().all(|l| !l.starts_with("BYE")), "{rest:?}");
    // The server notices too, and records the guest's PART once its
    // session ends (4.2).
    loop {
        let line = ann.expect_line().await.unwrap();
        if line.contains("from=~sam") && line.ends_with(" PART #a") {
            break;
        }
    }
    // New connections still go through.
    let _again = guest_via(&proxy, "sam").await;
    assert_eq!(proxy.connections(), 2);
    server.stop().await;
}

#[tokio::test]
async fn proxy_cuts_after_a_budget() {
    let server = TestServer::start().await;
    let proxy = Proxy::start(server.addr()).await;
    // Enough for the handshake and the greeting, not for much more.
    let mut probe = guest_via(&proxy, "probe").await;
    probe.send("ping").await.unwrap();
    assert_eq!(probe.expect_line().await.unwrap(), "OK");
    proxy.cut_after(Some(10));
    let result = TestClient::connect_with(proxy.addr(), ClientOptions::sni("localhost")).await;
    // The handshake cannot finish in 10 bytes.
    assert!(result.is_err());
    proxy.cut_after(None);
    let _ok = guest_via(&proxy, "late").await;
    server.stop().await;
}

#[tokio::test]
async fn restart_with_recreates_a_dropped_room() {
    let mut server = TestServer::builder().room("#a").start().await;
    let id_of = |line: &str| {
        line.split(' ')
            .find_map(|w| w.strip_prefix("id="))
            .unwrap()
            .to_owned()
    };
    let mut sam = server.guest("sam").await;
    sam.send("info #a").await.unwrap();
    let mut line = sam.expect_line().await.unwrap();
    while !line.starts_with("OK ") {
        line = sam.expect_line().await.unwrap();
    }
    let old = id_of(&line);
    drop(sam);
    server
        .restart_with(|config| {
            let db = rusqlite::Connection::open(config.database_path()).unwrap();
            db.pragma_update(None, "foreign_keys", "ON").unwrap();
            db.execute("DELETE FROM conversations WHERE room = '#a'", [])
                .unwrap();
        })
        .await;
    let mut sam = server.guest("sam").await;
    sam.send("info #a").await.unwrap();
    let mut line = sam.expect_line().await.unwrap();
    while !line.starts_with("OK ") {
        line = sam.expect_line().await.unwrap();
    }
    assert!(line.contains(" head=0"), "{line}");
    assert_ne!(id_of(&line), old);
    server.stop().await;
}

#[tokio::test]
async fn proxy_holds_back_what_the_server_sends() {
    let server = TestServer::builder().room("#a").start().await;
    let proxy = Proxy::start(server.addr()).await;
    let mut sam = guest_via(&proxy, "sam").await;
    let mut ann = server.guest("ann").await;
    ann.send("join #a").await.unwrap();
    assert!(ann.expect_line().await.unwrap().ends_with(" JOIN #a"));

    // Held: the command reaches the server, its answer does not reach sam.
    proxy.hold(true);
    sam.send("join #a").await.unwrap();
    loop {
        let line = ann.expect_line().await.unwrap();
        if line.contains("from=~sam") && line.ends_with(" JOIN #a") {
            break;
        }
    }
    // Released, the answer arrives in order.
    proxy.hold(false);
    assert!(sam.expect_line().await.unwrap().ends_with(" JOIN #a"));

    // A cut while holding drops what was held.
    proxy.hold(true);
    sam.send("msg #a lost answer").await.unwrap();
    loop {
        if ann
            .expect_line()
            .await
            .unwrap()
            .ends_with(" MSG #a lost answer")
        {
            break;
        }
    }
    proxy.cut();
    let rest = sam.recv_until_closed().await.unwrap_or_default();
    assert!(
        rest.iter()
            .all(|l| !l.contains("MSG #a lost answer") && !l.starts_with("OK seq=")),
        "{rest:?}"
    );
    proxy.hold(false);
    server.stop().await;
}
