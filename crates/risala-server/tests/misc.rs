//! Server information and presence over TLS (6.1, 8.3, 8.5): what a
//! client sees end to end. The hub's own tests (`src/core/tests/misc.rs`)
//! cover each rule.

use risala_server::testing::TestServer;

#[tokio::test]
async fn info_before_and_after_choosing_a_kind() {
    let server = TestServer::builder().guests(false).start().await;
    let mut client = server.connect().await;
    client.expect_line().await.unwrap();
    client.send("@ref=1 INFO").await.unwrap();
    assert_eq!(
        client.expect_line().await.unwrap(),
        "@ref=1 OK version=1 anon=yes guests=no register=no log=no retention=30 quota=4294967296 push=yes upload=no"
    );
    client.send("INFO #general").await.unwrap();
    assert_eq!(client.expect_line().await.unwrap(), "ERR not-authenticated");
    server.stop().await;
}

#[tokio::test]
async fn an_anonymous_connection_lists_rooms_and_watches() {
    let server = TestServer::start().await;
    let mut anon = server.anon().await;
    for (line, want) in [
        ("LIST", vec!["OK more=0"]),
        ("INFO #general", vec!["ERR not-found"]),
        ("MEMBERS #general", vec!["ERR not-found"]),
        (
            "WATCH alice@example.org,~sam",
            vec!["USER alice@example.org offline", "USER ~sam offline", "OK"],
        ),
        ("WHOIS alice@example.org", vec!["ERR not-found"]),
        ("PRESENCE ON", vec!["ERR wrong-connection"]),
        ("PUSH LIST", vec!["ERR wrong-connection"]),
    ] {
        anon.send(line).await.unwrap();
        for want in want {
            assert_eq!(anon.expect_line().await.unwrap(), want, "{line}");
        }
    }
    server.stop().await;
}
