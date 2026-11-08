//! The client's C0 parts: accounts, trust, and running a guest account.

use std::time::Duration;

use risala_proto::fingerprint::Fingerprint;

use super::*;
use crate::addr::TrustRecord;
use crate::conn::tests::server::{Peer, ScriptServer, TestCa};
use crate::conn::{Slot, roots_ca_verifier};
use crate::store::AccountKind;

fn client() -> Client {
    Client::open_in_memory(ClientOptions::default()).unwrap()
}

#[test]
fn accounts() {
    let c = client();
    let sam = c.add_guest("Chat.Example.org", "sam").unwrap();
    assert_eq!(sam.kind, AccountKind::Guest);
    assert_eq!(sam.uid.as_str(), "~sam");
    assert_eq!(sam.server.to_string(), "chat.example.org");
    assert_eq!(c.add_guest("chat.example.org", "sam").unwrap(), sam);
    let alice = c
        .add_identity_account("chat.example.org:7000", "alice@example.org")
        .unwrap();
    assert_eq!(alice.kind, AccountKind::Identity);
    assert_eq!(c.accounts().unwrap(), [sam.clone(), alice.clone()]);
    assert_eq!(c.account(alice.id).unwrap(), alice);

    for (server, name) in [("", "sam"), ("chat.example.org", "~sam"), ("a b", "x")] {
        assert!(
            matches!(c.add_guest(server, name), Err(Error::Invalid { .. })),
            "{server} {name}"
        );
    }
    assert!(matches!(
        c.add_identity_account("chat.example.org", "~sam"),
        Err(Error::Invalid { .. })
    ));
}

#[tokio::test]
async fn removing_an_account() {
    let c = client();
    let sam = c.add_guest("chat.example.org", "sam").unwrap();
    c.remove_account(sam.id).await.unwrap();
    assert!(c.accounts().unwrap().is_empty());
    assert!(matches!(c.account(sam.id), Err(Error::NoAccount)));
}

#[test]
fn trust_decisions() {
    let c = client();
    let server = "chat.example.org";
    let (a, b) = (
        Fingerprint::from_bytes([1; 32]),
        Fingerprint::from_bytes([2; 32]),
    );
    let mut events = c.subscribe();
    assert_eq!(c.trust_record(server).unwrap(), None);
    c.accept_fingerprint(server, &a.to_string()).unwrap();
    assert!(matches!(events.try_recv(), Ok(Event::Changed(_))));
    assert_eq!(
        c.trust_record(server).unwrap(),
        Some(TrustRecord::Pinned(a))
    );
    assert!(c.accept_fingerprint(server, &b.to_string()).is_err());
    assert!(matches!(
        c.accept_fingerprint(server, "sha256:xyz"),
        Err(Error::Invalid { .. })
    ));

    c.set_strict_pin(server, &a.to_string()).unwrap();
    assert_eq!(
        c.trust_record(server).unwrap(),
        Some(TrustRecord::Strict(a))
    );
    c.approve_new_pin(server, &a.to_string(), &b.to_string())
        .unwrap();
    assert_eq!(
        c.trust_record(server).unwrap(),
        Some(TrustRecord::Strict(b))
    );
    c.clear_strict_pin(server).unwrap();
    assert_eq!(
        c.trust_record(server).unwrap(),
        Some(TrustRecord::Pinned(b))
    );
    assert!(c.pin_notices().unwrap().is_empty());
    c.forget_trust(server).unwrap();
    assert_eq!(c.trust_record(server).unwrap(), None);
}

#[tokio::test]
async fn area_methods_say_they_are_not_implemented() {
    let c = client();
    let account = c.add_guest("chat.example.org", "sam").unwrap().id;
    let conv = crate::store::conversations::ConversationId(1);
    let message = types::MessageId([0; 16]);
    let not_implemented = |r: Result<()>, name: &str| match r {
        Err(Error::NotImplemented(n)) => assert_eq!(n, name),
        other => panic!("{name}: {other:?}"),
    };
    not_implemented(
        c.join_public_room(account, "#general").await.map(drop),
        "join_public_room",
    );
    not_implemented(c.fetch_file(conv, message).await.map(drop), "fetch_file");
    not_implemented(c.backup_now(account).await.map(drop), "backup_now");
    not_implemented(c.handle_push(b"").await.map(drop), "handle_push");
    not_implemented(c.report_recipients(conv).map(drop), "report_recipients");
}

#[tokio::test]
async fn an_identity_this_device_does_not_hold_cannot_connect() {
    let c = client();
    let alice = c
        .add_identity_account("chat.example.org", "alice@example.org")
        .unwrap();
    // Task C1: signing in needs the identity's keys on this device.
    assert!(matches!(
        c.connect(alice.id).await,
        Err(Error::Identity(identity::IdentityError::NotHeld(_)))
    ));
}

/// The next connection event of `account`, skipping others.
async fn next_state(
    events: &mut tokio::sync::broadcast::Receiver<Event>,
    account: crate::store::AccountId,
) -> (Slot, ConnectionState) {
    loop {
        let event = tokio::time::timeout(Duration::from_secs(10), events.recv())
            .await
            .expect("an event in time")
            .expect("events");
        if let Event::Connection(e) = event
            && e.account == account
        {
            return (e.slot, e.state);
        }
    }
}

#[tokio::test]
async fn a_guest_connects_and_keeps_its_session() {
    let ca = TestCa::new();
    let server = ScriptServer::start(ca.issue("chat.test"), 2, |i, mut peer: Peer| async move {
        peer.greet().await;
        match i {
            0 => {
                peer.expect("@ref=1 GUEST sam").await;
                peer.send("@ref=1 OK uid=~sam token=tok1aaaaaaaaaaaaaaaa")
                    .await;
                peer.close().await;
            }
            _ => {
                // The next connection resumes the session (4.2).
                peer.expect("@ref=1 GUEST sam token=tok1aaaaaaaaaaaaaaaa")
                    .await;
                peer.send("@ref=1 OK uid=~sam token=tok2aaaaaaaaaaaaaaaa resumed=yes")
                    .await;
                peer.expect_eof().await;
            }
        }
    })
    .await;
    let options = ClientOptions {
        ca_verifier: Some(roots_ca_verifier([ca.cert.clone()]).unwrap()),
        session: crate::conn::SessionOptions {
            connect_to: Some(server.addr),
            ..Default::default()
        },
        backoff: crate::conn::Backoff {
            initial: Duration::from_millis(10),
            max: Duration::from_millis(20),
            stable_after: Duration::from_secs(3600),
        },
        ..ClientOptions::default()
    };
    let c = Client::open_in_memory(options).unwrap();
    let sam = c.add_guest("chat.test", "sam").unwrap();
    let mut events = c.subscribe();
    c.connect(sam.id).await.unwrap();
    // Connecting again does nothing.
    c.connect(sam.id).await.unwrap();

    let mut ready = 0;
    while ready < 2 {
        let (slot, state) = next_state(&mut events, sam.id).await;
        assert_eq!(slot, Slot::Guest);
        if state == ConnectionState::Ready {
            ready += 1;
        }
    }
    // Ready comes after the session is saved: the resumed one's token.
    let (name, token) = c.store().guest_session(sam.id).unwrap().unwrap();
    assert_eq!(name.as_str(), "sam");
    assert_eq!(token.to_string(), "tok2aaaaaaaaaaaaaaaa");
    // The trust record is CA (2.2).
    assert_eq!(c.trust_record("chat.test").unwrap(), Some(TrustRecord::Ca));
    c.disconnect(sam.id).await.unwrap();
    server.done().await;
}
