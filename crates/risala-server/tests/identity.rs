//! Identities over TLS against a whole server (4.4-4.9): REGISTER, AUTH,
//! KEYS PUT, hosted key files served over HTTPS, AUTH with a key file
//! fetched over HTTPS, and UNREGISTER.
//!
//! The hub's own tests (`src/core/tests/identity.rs`) cover each rule
//! without sockets. These check that the rules hold end to end.

use risala_keyfetch::{Body, KeyFetcher};
use risala_proto::keyfile::KeyFile;
use risala_server::testing::{ClientOptions, TestClient, TestServer};

/// A server that hosts `example.org` with registration open, and fetches
/// key files of `example.net` from its test key server.
async fn server() -> TestServer {
    TestServer::builder()
        .identity_domain("example.org")
        .key_domains(&["example.net"])
        .configure(|c| c.server.registration = true)
        .start()
        .await
}

/// REGISTER over TLS signs in, AUTH then signs in other connections, and
/// KEYS PUT adds a device that can sign in too; the key file is served
/// over HTTPS at the identity's URL (4.3, 4.6, 4.7).
#[tokio::test]
async fn register_auth_and_keys_put() {
    let server = server().await;
    let (mut alice, mut chain, device) = server.register("alice").await;
    let mut again = server.sign_in(&device).await;
    again.send("PING").await.unwrap();
    let ok = again.expect_line().await.unwrap();
    assert!(ok.starts_with("@t=") && ok.ends_with(" OK"), "{ok}");

    let phone = chain.add_device("phone");
    alice.send(&chain.keys_put_line(2)).await.unwrap();
    assert_eq!(
        alice.expect_line().await.unwrap(),
        format!("RECORD 2 {}", chain.head().hash())
    );
    assert_eq!(alice.expect_line().await.unwrap(), "OK");
    server.sign_in(&phone).await;

    // The key file, as anyone fetches it (4.4).
    let fetcher = KeyFetcher::new(server.key_server().fetch_options());
    let found = fetcher.lookup(chain.identity(), true).await.unwrap();
    let Body::File(bytes) = found.body else {
        panic!("{:?}", found.body)
    };
    let file = KeyFile::parse(&bytes).unwrap();
    assert_eq!(file.len(), 3);
    assert_eq!(&file.last_log().log, &server.hub().key_log().unwrap().log);
    assert!(chain.records().iter().all(|r| file.lists(&r.hash())));

    // A key the chain does not list does not sign in.
    let stranger = risala_server::testing::TestIdentity::new("alice@example.org");
    let (_, answer) = server.auth(&stranger).await;
    assert_eq!(answer, "ERR auth-failed");

    // UNREGISTER: OK, then every connection of the identity closes, and
    // the key file is gone (4.9).
    alice.send("UNREGISTER alice@example.org").await.unwrap();
    let closed = alice.recv_until_closed().await.unwrap();
    assert_eq!(closed[0], "OK");
    assert!(closed[1].starts_with("BYE "), "{closed:?}");
    assert!(again.recv_until_closed().await.unwrap()[0].starts_with("BYE "));
    let (_, answer) = server.auth(&phone).await;
    assert_eq!(answer, "ERR auth-failed");
    let found = fetcher.lookup(chain.identity(), true).await.unwrap();
    assert_eq!(found.body, Body::Gone(404));
    server.stop().await;
}

/// AUTH for an identity of another domain fetches its key file over
/// HTTPS (4.4, 4.6), and fetches it again once for a new device (4.4).
#[tokio::test]
async fn auth_with_a_key_file_over_https() {
    let server = server().await;
    let bob = server.identity("bob@example.net");
    server.sign_in(&bob).await;
    let phone = server.key_server().new_device(&bob);
    server.sign_in(&phone).await;
    // A device the key file does not list.
    let (_, answer) = server
        .auth(&risala_server::testing::TestIdentity::new(
            "bob@example.net",
        ))
        .await;
    assert_eq!(answer, "ERR auth-failed");
    server.stop().await;
}

/// AUTH and REGISTER on a connection whose SNI the server does not serve
/// are refused, saying so (4.6 step 1).
#[tokio::test]
async fn auth_needs_a_served_host_name() {
    let server = server().await;
    let bob = server.identity("bob@example.net");
    let mut client =
        TestClient::connect_with(server.addr(), ClientOptions::sni("chat.example.com"))
            .await
            .unwrap();
    let greeting = client.expect_line().await.unwrap();
    let nonce = greeting.split(' ').nth(3).unwrap().parse().unwrap();
    client
        .send(&bob.auth_line("chat.example.com", &nonce))
        .await
        .unwrap();
    let answer = client.expect_line().await.unwrap();
    assert!(
        answer.starts_with("ERR auth-failed wrong host name"),
        "{answer}"
    );
    server.stop().await;
}
