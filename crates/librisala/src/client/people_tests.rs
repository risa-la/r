//! People against a scripted TLS server: read markers, typing, display
//! names, members, presence and blocks (5.7, 7.4, 8.1-8.3), through the
//! client API and its events.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::conn::keys::MemoryKeyStore;
use crate::conn::keys::tests::{PEM, SIGNATURE};
use crate::conn::tests::server::{Peer, ScriptServer, ServerCert, TestCa};
use crate::conn::{SessionOptions, roots_ca_verifier};

const HOST: &str = "chat.example.org";
const NONCE: &str = "6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e";
const ALICE: &str = "alice@example.org";
const WAIT: Duration = Duration::from_secs(30);

/// A client that trusts a self-signed server for `chat.example.org`,
/// which runs `script` on its one connection, with alice's key.
async fn setup<F, Fut>(script: F) -> (Client, ScriptServer)
where
    F: Fn(usize, Peer) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let cert = ServerCert::self_signed(HOST);
    let fingerprint = cert.fingerprint.to_string();
    let server = ScriptServer::start(cert, 1, script).await;
    let unrelated = TestCa::new();
    let client = Client::open_in_memory(ClientOptions {
        session: SessionOptions {
            ca_verifier: Some(roots_ca_verifier([unrelated.cert.clone()]).unwrap()),
            connect_to: Some(server.addr),
            ..SessionOptions::default()
        },
        keys: Some(Arc::new(MemoryKeyStore::default())),
        ..ClientOptions::default()
    })
    .unwrap();
    client.accept_fingerprint(HOST, &fingerprint).unwrap();
    client.import_device_key(ALICE, PEM, false).await.unwrap();
    (client, server)
}

async fn within<T>(f: impl Future<Output = T>) -> T {
    tokio::time::timeout(WAIT, f).await.expect("timed out")
}

/// Greets and accepts alice's AUTH (the signature of Appendix B).
async fn sign_in(peer: &mut Peer) {
    peer.send(&format!("RISALA 1 {HOST} {NONCE}")).await;
    peer.expect(&format!("@ref=1 AUTH {ALICE} {SIGNATURE}"))
        .await;
    peer.send(&format!("@ref=1 OK uid={ALICE}")).await;
}

/// Answers QUIT and closes.
async fn quit(mut peer: Peer) {
    let line = peer.recv().await.expect("QUIT");
    let r = line.strip_suffix(" QUIT").expect("QUIT");
    peer.send(&format!("{r} OK")).await;
    peer.close().await;
}

/// An event line for #general.
fn ev(seq: u64, rest: &str) -> String {
    let t = risala_proto::time::Timestamp::from_unix_millis(1_800_000_000_000 + seq).unwrap();
    format!("@seq={seq};t={t};{rest}")
}

/// Waits for the first event that `f` picks.
async fn until<T>(events: &AccountEvents, f: impl Fn(&AccountEvent) -> Option<T>) -> T {
    within(async {
        loop {
            let event = events.next().await.expect("an event");
            if let Some(t) = f(&event) {
                return t;
            }
        }
    })
    .await
}

fn typing_in(conversation: &str) -> impl Fn(&AccountEvent) -> Option<Vec<String>> + '_ {
    move |e| match e {
        AccountEvent::Typing {
            conversation: c,
            uids,
        } if c == conversation => Some(uids.clone()),
        _ => None,
    }
}

#[tokio::test]
async fn people_from_end_to_end() {
    let (client, server) = setup(|_, mut peer| async move {
        sign_in(&mut peer).await;
        // SYNC with the account's marker from another device (7.1), and
        // BLOCKS (5.7).
        peer.expect("@ref=2 SYNC").await;
        peer.expect("@ref=3 BLOCKS").await;
        peer.send("@ref=2 CONV #general k1 3 1").await;
        peer.send("@ref=2 OK").await;
        peer.send("@ref=3 BLOCK troll@example.com").await;
        peer.send("@ref=3 OK").await;
        peer.expect("@ref=4 HISTORY #general after=0 limit=50")
            .await;
        for (n, rest) in [
            (1, "from=bob@example.net MSG #general one"),
            (2, "from=troll@example.com MSG #general boo"),
            (3, "from=bob@example.net MSG #general three"),
        ] {
            peer.send(&format!("@ref=4;{}", &ev(n, rest)[1..])).await;
        }
        peer.send("@ref=4 OK id=k1 more=0").await;

        // 7.4: this device reads; then another one does.
        peer.expect("@ref=5 READ #general 3").await;
        peer.send("@ref=5 OK").await;
        peer.send(&ev(4, "from=bob@example.net MSG #general four"))
            .await;
        peer.send(&ev(5, "from=bob@example.net MSG #general five"))
            .await;
        peer.send("READ #general 4").await;

        // 8.1: Bob types, the hidden troll types, Bob's message ends it.
        peer.send("@from=bob@example.net TYPING #general").await;
        peer.send("@from=troll@example.com TYPING #general").await;
        peer.send(&ev(6, "from=bob@example.net MSG #general six"))
            .await;
        // Alice types twice in a row: one TYPING.
        peer.expect("@ref=6 TYPING #general").await;
        peer.send("@ref=6 OK").await;

        // 8.3: members, then presence.
        peer.expect("@ref=7 MEMBERS #general").await;
        for line in [
            r"MEMBER #general alice@example.org owner online Alice",
            r"MEMBER #general bob@example.net member online Bob",
            r"MEMBER #general bob@example.org mod offline bob",
            r"MEMBER #general ~sam member online",
        ] {
            peer.send(&format!("@ref=7 {line}")).await;
        }
        peer.send("@ref=7 OK").await;
        peer.send("PRESENCE offline bob@example.net").await;
        peer.expect("@ref=8 WHOIS carol@example.com").await;
        peer.send(r"@ref=8 USER carol@example.com away Carol C")
            .await;
        peer.send("@ref=8 OK").await;
        peer.expect("@ref=9 WHOIS nobody@example.com").await;
        peer.send("@ref=9 ERR not-found").await;

        // 8.2: Alice's own name; Bob renames himself.
        peer.expect(r"@ref=10 NAME Alice M").await;
        peer.send("@ref=10 OK").await;
        peer.send(r"@from=bob@example.net NAME Robert").await;

        // 5.7: block, then the list from another device.
        peer.expect("@ref=11 BLOCK *@evil.example").await;
        peer.send("@ref=11 OK").await;
        peer.expect("@ref=12 UNBLOCK troll@example.com").await;
        peer.send("@ref=12 OK").await;
        peer.expect("@ref=13 BLOCKS").await;
        peer.send("@ref=13 BLOCK *@evil.example").await;
        peer.send("@ref=13 BLOCK zed@example.org").await;
        peer.send("@ref=13 OK").await;
        quit(peer).await;
    })
    .await;
    let alice = client.add_identity(HOST, ALICE).unwrap();
    let events = alice.subscribe();
    within(alice.connect()).await.unwrap();
    within(alice.wait_synced()).await.unwrap();
    let general = alice.conversation("#general").unwrap();
    let info = || general.info().unwrap().unwrap();
    // SYNC's marker: read up to 1, so 2 and 3 are unread.
    assert_eq!((info().read, info().unread), (1, 2));
    assert_eq!(alice.cached_blocks().unwrap(), ["troll@example.com"]);
    assert!(alice.is_blocked("troll@example.com").unwrap());

    // Hiding the blocked troll hides its message, which is no longer
    // unread, and resets timelines.
    let timeline = general.timeline(50).unwrap();
    assert_eq!(timeline.items().len(), 3);
    alice.set_hide_blocked(true).unwrap();
    assert!(alice.hides_blocked().unwrap());
    until(&events, |e| {
        (*e == AccountEvent::BlocksChanged).then_some(())
    })
    .await;
    match within(timeline.next()).await.unwrap().as_slice() {
        [TimelineDiff::Reset { items }] => {
            let seqs: Vec<u64> = items.iter().map(|m| m.seq).collect();
            assert_eq!(seqs, [1, 3]);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(info().unread, 1);

    // 7.4: reading moves the marker here and on the server.
    // Beyond the newest seq known, it stops there, as the server's does.
    general.mark_read(9).await.unwrap();
    assert!(info().read >= 3);
    // Another device read up to 4: one unread is left.
    within(async {
        while info().read != 4 {
            events.next().await;
        }
    })
    .await;
    // Bob's next message may be here already.
    let now = info();
    assert_eq!(now.unread, now.newest - 4);

    // 8.1.
    let bob_typing = until(&events, typing_in("#general")).await;
    assert_eq!(bob_typing, ["bob@example.net"]);
    let after = until(&events, typing_in("#general")).await;
    assert!(after.is_empty(), "{after:?}");
    assert!(general.typing_users().is_empty());
    general.set_typing(true);
    general.set_typing(true);

    // 8.3.
    let members = within(general.members()).await.unwrap();
    let shown: Vec<(&str, &str, &str, Presence)> = members
        .iter()
        .map(|m| {
            (
                m.uid.as_str(),
                m.role.as_str(),
                m.label.as_str(),
                m.presence,
            )
        })
        .collect();
    assert_eq!(
        shown,
        [
            ("alice@example.org", "owner", "Alice", Presence::Online),
            (
                "bob@example.net",
                "member",
                "Bob (bob@example.net)",
                Presence::Online
            ),
            (
                "bob@example.org",
                "mod",
                "bob (bob@example.org)",
                Presence::Offline
            ),
            ("~sam", "member", "~sam", Presence::Online),
        ]
    );
    let cached: Vec<String> = general
        .cached_members()
        .unwrap()
        .iter()
        .map(|m| format!("{} {} {}", m.uid, m.role, m.label))
        .collect();
    assert_eq!(
        cached,
        [
            "alice@example.org owner Alice",
            "bob@example.net member Bob (bob@example.net)",
            "bob@example.org mod bob (bob@example.org)",
            "~sam member ~sam",
        ]
    );
    let bob = until(&events, |e| match e {
        AccountEvent::UserChanged { user }
            if user.uid == "bob@example.net" && user.presence == Presence::Offline =>
        {
            Some(user.clone())
        }
        _ => None,
    })
    .await;
    assert_eq!(bob.uid, "bob@example.net");
    assert_eq!(bob.display_name.as_deref(), Some("Bob"));
    assert_eq!(alice.user("bob@example.net").unwrap(), bob);
    // An unknown presence shows as online (8.3).
    let carol = within(alice.whois("carol@example.com")).await.unwrap();
    assert_eq!(
        carol,
        UserInfo {
            uid: "carol@example.com".into(),
            display_name: Some("Carol C".into()),
            presence: Presence::Online,
        }
    );
    assert_eq!(
        within(alice.whois("nobody@example.com"))
            .await
            .unwrap_err()
            .code(),
        Some("not-found")
    );

    // 8.2.
    within(alice.set_display_name(" Alice M ")).await.unwrap();
    assert_eq!(
        alice.display_name(ALICE).unwrap().as_deref(),
        Some("Alice M")
    );
    let robert = until(&events, |e| match e {
        AccountEvent::UserChanged { user } if user.uid == "bob@example.net" => {
            user.display_name.clone()
        }
        _ => None,
    })
    .await;
    assert_eq!(robert, "Robert");
    assert_eq!(
        general
            .labels(vec!["bob@example.net".into(), "~sam".into(), ALICE.into()])
            .unwrap(),
        ["Robert", "~sam", "Alice M"]
    );
    assert!(matches!(
        alice.set_display_name(&"x".repeat(129)).await,
        Err(ClientError::Invalid(_))
    ));

    // 5.7.
    within(alice.block("*@evil.example")).await.unwrap();
    assert!(alice.is_blocked("spam@mail.evil.example").unwrap());
    within(alice.unblock("troll@example.com")).await.unwrap();
    assert!(!alice.is_blocked("troll@example.com").unwrap());
    assert_eq!(
        within(alice.blocks()).await.unwrap(),
        ["*@evil.example", "zed@example.org"]
    );
    assert_eq!(
        alice.cached_blocks().unwrap(),
        ["*@evil.example", "zed@example.org"]
    );
    assert!(matches!(
        alice.block("~sam").await,
        Err(ClientError::Invalid(_))
    ));

    // Closing forgets presence and typing.
    alice.disconnect().await;
    until(&events, |e| {
        (*e == AccountEvent::PresenceLost).then_some(())
    })
    .await;
    assert_eq!(alice.user(ALICE).unwrap().presence, Presence::NotKnown);
    // Offline, what needs the server says so; the cache still answers.
    assert_eq!(
        general.members().await.unwrap_err(),
        ClientError::NotConnected
    );
    assert_eq!(general.cached_members().unwrap().len(), 4);
    general.set_typing(true);
    server.done().await;
}

#[tokio::test]
async fn typing_runs_out_after_six_seconds() {
    let (client, server) = setup(|_, mut peer| async move {
        sign_in(&mut peer).await;
        peer.expect("@ref=2 SYNC").await;
        peer.expect("@ref=3 BLOCKS").await;
        peer.send("@ref=2 OK").await;
        peer.send("@ref=3 OK").await;
        peer.send("@from=bob@example.net TYPING #general").await;
        quit(peer).await;
    })
    .await;
    let alice = client.add_identity(HOST, ALICE).unwrap();
    let events = alice.subscribe();
    within(alice.connect()).await.unwrap();
    let general = alice.conversation("#general").unwrap();
    assert_eq!(
        until(&events, typing_in("#general")).await,
        ["bob@example.net"]
    );
    let started = std::time::Instant::now();
    assert_eq!(general.typing_users(), ["bob@example.net"]);
    assert!(until(&events, typing_in("#general")).await.is_empty());
    let lasted = started.elapsed();
    assert!(lasted > Duration::from_secs(5), "{lasted:?}");
    alice.disconnect().await;
    server.done().await;
}

#[tokio::test]
async fn guests_cannot_block() {
    let client = Client::open_in_memory(ClientOptions::default()).unwrap();
    let sam = client.add_guest(HOST, "sam").unwrap();
    let err = sam.block("spam@example.net").await.unwrap_err();
    assert!(matches!(
        err,
        ClientError::Refused {
            kind: RefusedKind::Guest,
            ..
        }
    ));
    assert!(!sam.is_blocked("spam@example.net").unwrap());
    assert!(sam.cached_blocks().unwrap().is_empty());
    assert!(matches!(
        sam.conversation("bob@example.net").unwrap().members().await,
        Err(ClientError::Invalid(_))
    ));
}
