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

/// An operator signed in over TLS uses the ADMIN commands (Section 10): a
/// notice reaches every connection, a ban closes the banned identity's
/// connections and refuses its AUTH, and someone who is not an operator
/// is refused.
#[tokio::test]
async fn an_operator_administers_over_tls() {
    let server = TestServer::builder()
        .identity_domain("example.org")
        .operator("op@example.org")
        .start()
        .await;
    let (mut op, _, _) = server.register("op").await;
    let (mut alice, _, alice_device) = server.register("alice").await;
    let mut anon = server.anon().await;

    alice.send("ADMIN OPS").await.unwrap();
    assert_eq!(alice.expect_line().await.unwrap(), "ERR forbidden");

    op.send("@ref=1 ADMIN OPS").await.unwrap();
    assert_eq!(op.expect_line().await.unwrap(), "@ref=1 OP op@example.org");
    assert_eq!(op.expect_line().await.unwrap(), "@ref=1 OK");

    op.send("ADMIN NOTICE Back in 5").await.unwrap();
    assert_eq!(op.expect_line().await.unwrap(), "NOTICE Back in 5");
    assert_eq!(op.expect_line().await.unwrap(), "OK");
    assert_eq!(anon.expect_line().await.unwrap(), "NOTICE Back in 5");
    assert_eq!(alice.expect_line().await.unwrap(), "NOTICE Back in 5");

    op.send("ADMIN BAN alice@example.org spam").await.unwrap();
    assert_eq!(op.expect_line().await.unwrap(), "OK");
    assert_eq!(alice.recv_until_closed().await.unwrap(), ["BYE spam"]);
    let (_, answer) = server.auth(&alice_device).await;
    assert_eq!(answer, "ERR forbidden");

    op.send("ADMIN WHO").await.unwrap();
    let mut who = Vec::new();
    loop {
        let line = op.expect_line().await.unwrap();
        if line == "OK" {
            break;
        }
        who.push(line);
    }
    assert!(
        who.iter()
            .any(|l| l.starts_with("CONNECTION op@example.org 127.0.0.1:")),
        "{who:?}"
    );
    assert!(
        who.iter().any(|l| l.starts_with("CONNECTION - 127.0.0.1:")),
        "{who:?}"
    );
    server.stop().await;
}
