//! Every M3 behaviour, over TLS against a whole server: identities signing
//! in with key files fetched over HTTPS (4.4, 4.5), registration (4.6),
//! keys (4.7), several devices of one identity (6.1, 7.1), read markers
//! (7.4), typing (8.1), display names (8.2), MEMBERS, WHOIS and PRESENCE
//! (8.3), and blocks (5.7).
//!
//! The hub's own tests (`src/core/*tests.rs`) cover each rule at every
//! edge, without sockets. These check that the rules hold end to end,
//! through TLS, the key file fetcher and a real HTTPS key server.

mod common;

use std::time::Duration;

use std::collections::BTreeSet;

use common::{command, recv, settled, until_closed};
use risala_server::testing::{TestClient, TestIdentity, TestServer};

/// Presence changes held for an hour, so that no PRESENCE line turns up in
/// a test that is not about presence.
const NO_PRESENCE: (Duration, Duration) = (Duration::from_secs(30), Duration::from_secs(3600));

/// A server that hosts `example.org`, with registration open, and lets
/// identities at `example.net` and `example.com` sign in. It has no rooms:
/// the first identity to join one creates it and owns it (6.1).
async fn server() -> TestServer {
    TestServer::builder()
        .identity_domain("example.org")
        .key_domains(&["example.net", "example.com"])
        .presence(NO_PRESENCE.0, NO_PRESENCE.1)
        .start()
        .await
}

/// `client` joins `room`, and its own JOIN, the settings and the OK are
/// read.
async fn join(client: &mut TestClient, room: &str) {
    let lines = command(client, &format!("join {room}")).await;
    assert!(lines.last().unwrap().starts_with("OK id="), "{lines:?}");
}

// ---------------------------------------------------------------------------
// Signing in (4.4-4.6)

/// The relay attack of 4.5: a malicious server connects here with its own
/// name in SNI, passes this server's nonce on to one of its users, and
/// tries to sign in with the signature it gets back. The server refuses
/// AUTH and REGISTER on a connection whose SNI does not name it.
#[tokio::test]
async fn sign_ins_are_refused_under_another_servers_name() {
    use risala_server::testing::ClientOptions;

    let server = server().await;
    let bob = server.identity("bob@example.net");
    let alice = TestIdentity::new("alice@example.org");
    for register in [false, true] {
        for who in [&bob, &alice] {
            let mut conn = server
                .connect_with(ClientOptions::sni("evil.example"))
                .await;
            let greeting = conn.expect_line().await.unwrap();
            let nonce = greeting.split(' ').nth(3).unwrap().parse().unwrap();
            let line = if register {
                who.register_line("evil.example", &nonce)
            } else {
                who.auth_line("evil.example", &nonce)
            };
            conn.send(&line).await.unwrap();
            let answer = conn.expect_line().await.unwrap();
            assert!(answer.starts_with("ERR auth-failed"), "{answer}");
        }
    }
    // The same signatures, made for this server's name, work.
    let _bob = server.sign_in(&bob).await;
    server.stop().await;
}

#[tokio::test]
async fn auth_with_a_fetched_key_file() {
    let server = server().await;
    let bob = server.identity("bob@example.net");
    let mut conn = server.sign_in(&bob).await;
    assert_eq!(command(&mut conn, "sync").await, ["OK"]);
    // Signing in again on the same connection is refused.
    assert_eq!(
        command(&mut conn, "guest sam").await,
        ["ERR already-authenticated already signed in"]
    );

    // A second device, added to the key file after the server cached it:
    // the signature fails against the cached file, so the server fetches
    // it again (4.4).
    let phone = server.new_device(&bob).await;
    let _phone = server.sign_in(&phone).await;

    // A key the file does not list, and an identity with no key file.
    let stranger = bob.new_key();
    let (_c, answer) = server.auth(&stranger).await;
    assert!(answer.starts_with("ERR auth-failed"), "{answer}");
    let carol = TestIdentity::new("carol@example.com");
    let (_c, answer) = server.auth(&carol).await;
    assert!(answer.starts_with("ERR auth-failed"), "{answer}");
    // A domain the key server does not serve at all.
    let dave = TestIdentity::new("dave@example.invalid");
    let (_c, answer) = server.auth(&dave).await;
    assert!(answer.starts_with("ERR auth-failed"), "{answer}");

    // Once carol publishes her key, she may sign in.
    server
        .key_server()
        .publish(carol.identity(), &[carol.key_entry(Some("laptop"))]);
    let _carol = server.sign_in(&carol).await;
    server.stop().await;
}

#[tokio::test]
async fn register_publishes_a_key_file() {
    let server = server().await;
    let mut anon = server.connect().await;
    recv(&mut anon).await;
    let info = command(&mut anon, "info").await;
    assert!(info[0].contains(" register=example.org "), "{info:?}");

    let (alice, mut conn) = server.register("alice").await;
    assert_eq!(alice.uid().as_str(), "alice@example.org");
    let keys = command(&mut conn, "key list").await;
    assert_eq!(keys, [format!("KEY {}", alice.public_key()), "OK".into()]);

    // The key file is served at the identity domain (4.3, 4.6), where the
    // key server's fetch options find it, as a device would (12.12).
    let fetcher = risala_keyfetch::KeyFetcher::new(server.key_server().fetch_options());
    let fetched = fetcher.fetch(alice.identity(), false).await.unwrap();
    assert_eq!(fetched, [alice.public_key()]);

    // The name is taken now, and alice signs in with AUTH like anyone.
    let again = TestIdentity::new("alice@example.org");
    let (mut c, nonce) = connect(&server).await;
    c.send(&again.register_line(server.hostname(), &nonce))
        .await
        .unwrap();
    assert_eq!(recv(&mut c).await, "ERR name-taken that name is registered");
    let _second = server.sign_in(&alice).await;
    server.stop().await;
}

/// Connects and reads the greeting. Returns the client and the nonce.
async fn connect(server: &TestServer) -> (TestClient, risala_proto::auth::Nonce) {
    let mut c = server.connect().await;
    let greeting = recv(&mut c).await;
    let nonce = greeting.split(' ').nth(3).unwrap().parse().unwrap();
    (c, nonce)
}

// ---------------------------------------------------------------------------
// Several devices (6.1, 7.1, 7.4)

#[tokio::test]
async fn every_device_gets_live_events_and_read_markers() {
    let server = server().await;
    let (alice, mut laptop) = server.register("alice").await;
    join(&mut laptop, "#general").await;
    let phone_key = server.new_device(&alice).await;
    let mut phone = server.sign_in(&phone_key).await;
    // The phone is a member at once, with no JOIN (7.1).
    let sync = command(&mut phone, "sync").await;
    assert!(sync[0].starts_with("CONV #general "), "{sync:?}");
    assert!(sync[0].ends_with(" 1 0"), "{sync:?}");

    let bob = server.identity("bob@example.net");
    let mut bob_conn = server.sign_in(&bob).await;
    join(&mut bob_conn, "#general").await;
    let lines = command(&mut bob_conn, "msg #general hi alice").await;
    assert_eq!(lines.last().unwrap(), "OK seq=3");
    for device in [&mut laptop, &mut phone] {
        let join = recv(device).await;
        assert!(join.contains(";from=bob@example.net;id="), "{join}");
        assert!(join.ends_with(" JOIN #general"), "{join}");
        assert!(
            recv(device)
                .await
                .ends_with(";from=bob@example.net MSG #general hi alice")
        );
    }

    // The phone reads up to 3: the laptop hears of it, bob does not.
    assert_eq!(
        command(&mut phone, "@ref=r read #general 3").await,
        ["@ref=r OK"]
    );
    assert_eq!(recv(&mut laptop).await, "READ #general 3");
    settled(&mut phone).await;
    settled(&mut bob_conn).await;
    // An older marker changes nothing.
    assert_eq!(command(&mut laptop, "read #general 1").await, ["OK"]);
    settled(&mut phone).await;
    let sync = command(&mut laptop, "sync").await;
    assert!(sync[0].ends_with(" 3 3"), "{sync:?}");
    server.stop().await;
}

#[tokio::test]
async fn key_del_closes_the_device_that_used_the_key() {
    let server = server().await;
    let (alice, mut laptop) = server.register("alice").await;
    let phone_key = server.new_device(&alice).await;
    let mut phone = server.sign_in(&phone_key).await;
    let keys = command(&mut laptop, "key list").await;
    assert_eq!(keys.len(), 3, "{keys:?}");
    // A label is at most 64 bytes (4.7).
    let spare = TestIdentity::new("alice@example.org");
    let long = format!("key add {} {}", spare.public_key(), "x".repeat(65));
    let lines = command(&mut laptop, &long).await;
    assert!(lines[0].starts_with("ERR too-long"), "{lines:?}");

    let lines = command(&mut laptop, &format!("key del {}", phone_key.public_key())).await;
    assert_eq!(lines, ["OK"]);
    assert_eq!(
        until_closed(&mut phone).await,
        ["BYE this device's key was removed"]
    );
    // The laptop stays, and the phone's key no longer signs in.
    settled(&mut laptop).await;
    let (_c, answer) = server.auth(&phone_key).await;
    assert!(answer.starts_with("ERR auth-failed"), "{answer}");
    // The published key file lost it too.
    let fetcher = risala_keyfetch::KeyFetcher::new(server.key_server().fetch_options());
    assert_eq!(
        fetcher.fetch(alice.identity(), false).await.unwrap(),
        [alice.public_key()]
    );
    server.stop().await;
}

// ---------------------------------------------------------------------------
// TYPING (8.1), NAME (8.2), MEMBERS and WHOIS (8.3)

#[tokio::test]
async fn typing_reaches_the_other_members() {
    let server = server().await;
    let (_alice, mut alice) = server.register("alice").await;
    join(&mut alice, "#general").await;
    let bob = server.identity("bob@example.net");
    let mut bob = server.sign_in(&bob).await;
    join(&mut bob, "#general").await;
    recv(&mut alice).await;
    let mut sam = server.guest("sam").await;
    join(&mut sam, "#general").await;
    recv(&mut alice).await;
    recv(&mut bob).await;

    assert_eq!(command(&mut alice, "typing #general").await, ["OK"]);
    assert_eq!(
        recv(&mut bob).await,
        "@from=alice@example.org TYPING #general"
    );
    assert_eq!(
        recv(&mut sam).await,
        "@from=alice@example.org TYPING #general"
    );
    settled(&mut alice).await;
    assert_eq!(command(&mut sam, "typing #general").await, ["OK"]);
    assert_eq!(recv(&mut bob).await, "@from=~sam TYPING #general");
    server.stop().await;
}

#[tokio::test]
async fn names_members_and_whois() {
    let server = server().await;
    let (alice_id, mut alice) = server.register("alice").await;
    join(&mut alice, "#general").await;
    let phone = server.new_device(&alice_id).await;
    let mut phone = server.sign_in(&phone).await;
    let bob = server.identity("bob@example.net");
    let mut bob = server.sign_in(&bob).await;
    join(&mut bob, "#general").await;
    recv(&mut alice).await;
    recv(&mut phone).await;
    let carol = server.identity("carol@example.com");
    let mut carol = server.sign_in(&carol).await;

    assert_eq!(command(&mut alice, "name عائشة Martin").await, ["OK"]);
    let line = "@from=alice@example.org NAME عائشة Martin";
    assert_eq!(recv(&mut bob).await, line);
    assert_eq!(recv(&mut phone).await, line);
    settled(&mut alice).await;
    settled(&mut carol).await;

    let mut sam = server.guest("sam").await;
    join(&mut sam, "#general").await;
    assert_eq!(command(&mut sam, "name Sam").await, ["OK"]);
    assert_eq!(
        command(&mut carol, "@ref=m members #general").await,
        [
            "@ref=m MEMBER #general alice@example.org owner online عائشة Martin",
            "@ref=m MEMBER #general bob@example.net member online",
            "@ref=m MEMBER #general ~sam member online Sam",
            "@ref=m OK",
        ]
    );
    assert_eq!(
        command(&mut carol, "whois alice@example.org").await,
        ["USER alice@example.org online عائشة Martin", "OK"]
    );
    assert_eq!(
        command(&mut carol, "whois ~sam").await,
        ["USER ~sam online Sam", "OK"]
    );
    assert_eq!(
        command(&mut carol, "whois nobody@example.org").await,
        ["ERR not-found no such user"]
    );

    // The name is the account's, and stored.
    let mut laptop = server.sign_in(&alice_id).await;
    assert_eq!(
        command(&mut laptop, "whois alice@example.org").await,
        ["USER alice@example.org online عائشة Martin", "OK"]
    );
    server.stop().await;
}

// ---------------------------------------------------------------------------
// PRESENCE (8.3)

/// Reads lines until PRESENCE has reported every one of `uids` as
/// `presence`, skipping other lines, such as events. Returns how many
/// PRESENCE lines that took.
async fn presence_of(client: &mut TestClient, presence: &str, uids: &[&str]) -> usize {
    let want: BTreeSet<String> = uids.iter().map(|u| (*u).to_owned()).collect();
    let mut seen = BTreeSet::new();
    let mut lines = 0;
    let prefix = format!("PRESENCE {presence} ");
    while seen != want {
        let line = recv(client).await;
        if let Some(list) = line.strip_prefix(&prefix) {
            lines += 1;
            seen.extend(list.split(',').map(str::to_owned));
            assert!(seen.is_subset(&want), "{line}");
        } else {
            assert!(!line.starts_with("PRESENCE "), "{line}");
        }
    }
    lines
}

#[tokio::test]
async fn presence_is_batched_and_waits_before_offline() {
    // Shorter than the spec's 30 seconds and 1 second, but long enough
    // that the sign-ins below fit in one batch, and a reconnect in the
    // offline delay.
    let offline = Duration::from_secs(4);
    let batch = Duration::from_secs(2);
    let server = TestServer::builder()
        .identity_domain("example.org")
        .key_domains(&["example.net"])
        .presence(offline, batch)
        .start()
        .await;
    let bob = server.identity("bob@example.net");
    let mut bob = server.sign_in(&bob).await;
    join(&mut bob, "#general").await;
    let (alice_id, mut alice) = server.register("alice").await;
    join(&mut alice, "#general").await;
    let (_carol_id, mut carol) = server.register("carol").await;
    join(&mut carol, "#general").await;
    // Each hears of the other two, but not of themselves, in one line.
    let bob_lines = presence_of(
        &mut bob,
        "online",
        &["alice@example.org", "carol@example.org"],
    );
    assert_eq!(bob_lines.await, 1);
    let alice_lines = presence_of(
        &mut alice,
        "online",
        &["bob@example.net", "carol@example.org"],
    );
    assert_eq!(alice_lines.await, 1);
    let carol_lines = presence_of(
        &mut carol,
        "online",
        &["alice@example.org", "bob@example.net"],
    );
    assert_eq!(carol_lines.await, 1);
    settled(&mut bob).await;
    settled(&mut alice).await;
    settled(&mut carol).await;

    // Alice drops off and comes back within the offline delay: nobody
    // hears of it.
    drop(alice);
    let mut alice = server.sign_in(&alice_id).await;
    tokio::time::sleep(offline + batch * 2).await;
    settled(&mut bob).await;
    settled(&mut carol).await;
    settled(&mut alice).await;
    assert_eq!(
        command(&mut bob, "whois alice@example.org").await,
        ["USER alice@example.org online", "OK"]
    );

    // Carol goes for good: after the delay and the batch, the others hear.
    assert_eq!(command(&mut carol, "quit").await, ["OK"]);
    until_closed(&mut carol).await;
    assert_eq!(recv(&mut bob).await, "PRESENCE offline carol@example.org");
    assert_eq!(recv(&mut alice).await, "PRESENCE offline carol@example.org");
    assert_eq!(
        command(&mut bob, "whois carol@example.org").await,
        ["USER carol@example.org offline", "OK"]
    );
    server.stop().await;
}

// ---------------------------------------------------------------------------
// BLOCK, UNBLOCK and BLOCKS (5.7)

#[tokio::test]
async fn blocks_are_kept_for_the_account() {
    let server = server().await;
    let (alice_id, mut alice) = server.register("alice").await;
    for target in ["spam@example.net", "*@bad.example"] {
        assert_eq!(
            command(&mut alice, &format!("block {target}")).await,
            ["OK"]
        );
    }
    let mut phone = server.sign_in(&server.new_device(&alice_id).await).await;
    assert_eq!(
        command(&mut phone, "blocks").await,
        ["BLOCK *@bad.example", "BLOCK spam@example.net", "OK"]
    );
    assert_eq!(
        command(&mut phone, "unblock spam@example.net").await,
        ["OK"]
    );
    assert_eq!(
        command(&mut alice, "blocks").await,
        ["BLOCK *@bad.example", "OK"]
    );
    let mut sam = server.guest("sam").await;
    assert_eq!(
        command(&mut sam, "blocks").await,
        ["ERR forbidden not for guests"]
    );
    // A guest cannot be blocked: `~sam` is not a target (5.7).
    let lines = command(&mut alice, "block ~sam").await;
    assert!(lines[0].starts_with("ERR bad-syntax"), "{lines:?}");
    server.stop().await;
}
