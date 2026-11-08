//! Server administration over TLS (Section 10): bans the store holds apply
//! from the start. The hub's own tests (`src/core/tests/admin.rs`) cover
//! each ADMIN command.

use risala_server::store::AdminStore as _;
use risala_server::testing::TestServer;

/// An address ban covers anonymous and guest connections from inside it
/// (10.2), from when the server starts.
#[tokio::test]
async fn stored_address_bans_refuse_anonymous_and_guest_connections() {
    let server = TestServer::builder()
        .prepare(|store| {
            store
                .add_server_ban(
                    &"127.0.0.0/8".parse().unwrap(),
                    "",
                    "2026-11-09T00:00:00.000Z".parse().unwrap(),
                )
                .unwrap();
        })
        .start()
        .await;
    let mut client = server.connect().await;
    client.expect_line().await.unwrap();
    client.send("ANON").await.unwrap();
    client.send("GUEST sam").await.unwrap();
    client.send("INFO").await.unwrap();
    assert_eq!(
        client.expect_line().await.unwrap(),
        "ERR forbidden this network is banned"
    );
    assert_eq!(
        client.expect_line().await.unwrap(),
        "ERR forbidden this network is banned"
    );
    assert!(
        client
            .expect_line()
            .await
            .unwrap()
            .starts_with("OK version=1 ")
    );
    server.stop().await;
}
