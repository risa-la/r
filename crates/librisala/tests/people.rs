//! Identities with two devices against a real server: read markers,
//! typing, names, members, presence and blocks (5.7, 7.4, 8.1-8.3).
//!
//! The identities are hosted by the test server: device A registers them
//! (4.6), and adds device B's key with KEY ADD (4.7), as in `common`.

mod common;

use std::time::Duration;

use common::*;
use librisala::client::{Account, AccountEvent, Presence, TimelineDiff};
use risala_server::testing::TestServer;

/// A server hosting identities under `chat.test`, with #general.
async fn server() -> TestServer {
    hosted_server(&["#general"], |_| {}).await
}

/// Registers `<name>@chat.test` on a new device, signs it in and joins
/// #general.
async fn registered(server: &TestServer, name: &str) -> Account {
    registered_in(server, name, "#general").await
}

fn unread(account: &Account) -> u64 {
    account
        .conversation("#general")
        .unwrap()
        .info()
        .unwrap()
        .map_or(0, |c| c.unread)
}

#[tokio::test]
async fn read_markers_follow_the_account_across_devices() {
    let server = server().await;
    let alice_a = registered(&server, "alice").await;
    let alice_b = second_device(&server, &alice_a).await;
    let bob = registered(&server, "bob").await;
    let events_b = alice_b.subscribe();

    // Live events reach both devices, with no JOIN on the second.
    let general = bob.conversation("#general").unwrap();
    for text in ["one", "two", "three"] {
        let sent = general.send(text).await.unwrap();
        within("sending", bob.wait_outbox(sent.id)).await.unwrap();
    }
    until("A sees 3 unread", &alice_a.subscribe(), || {
        unread(&alice_a) == 3
    })
    .await;
    until("B sees 3 unread", &events_b, || unread(&alice_b) == 3).await;

    // A reads; B's unread count drops through READ (7.4).
    let a_general = alice_a.conversation("#general").unwrap();
    a_general.mark_all_read().await.unwrap();
    assert_eq!(unread(&alice_a), 0);
    until("B hears A's READ", &events_b, || unread(&alice_b) == 0).await;
    let read = a_general.info().unwrap().unwrap().read;
    assert_eq!(
        alice_b
            .conversation("#general")
            .unwrap()
            .info()
            .unwrap()
            .unwrap()
            .read,
        read
    );

    // A third device learns the marker from SYNC (7.1).
    let alice_c = second_device(&server, &alice_a).await;
    assert_eq!(unread(&alice_c), 0);

    // A marker set while offline reaches the server on the next
    // connection, and from there the other devices.
    let sent = general.send("four").await.unwrap();
    within("sending", bob.wait_outbox(sent.id)).await.unwrap();
    until("B sees 1 unread", &events_b, || unread(&alice_b) == 1).await;
    alice_a.disconnect().await;
    let newest = a_general.info().unwrap().unwrap();
    assert!(newest.newest > read || newest.head > read);
    a_general.mark_all_read().await.unwrap();
    alice_a.connect().await.unwrap();
    until("B hears the marker set offline", &events_b, || {
        unread(&alice_b) == 0
    })
    .await;
    server.stop().await;
}

#[tokio::test]
async fn typing_shows_on_the_other_account() {
    let server = server().await;
    let alice = registered(&server, "alice").await;
    let bob = registered(&server, "bob").await;
    let events = alice.subscribe();
    let general = bob.conversation("#general").unwrap();
    let typing = |e: &AccountEvent| match e {
        AccountEvent::Typing { conversation, uids } if conversation == "#general" => {
            Some(uids.clone())
        }
        _ => None,
    };

    general.set_typing(true);
    assert_eq!(
        event("Alice sees Bob type", &events, typing).await,
        ["bob@chat.test"]
    );
    assert_eq!(
        alice.conversation("#general").unwrap().typing_users(),
        ["bob@chat.test"]
    );
    // Bob's message ends it (8.1).
    general.send("done").await.unwrap();
    assert!(
        event("Bob's message ends it", &events, typing)
            .await
            .is_empty()
    );
    // A notice that is not repeated runs out after 6 seconds.
    general.set_typing(true);
    assert_eq!(event("typing again", &events, typing).await.len(), 1);
    let started = std::time::Instant::now();
    assert!(event("it runs out", &events, typing).await.is_empty());
    assert!(started.elapsed() >= Duration::from_secs(5));
    server.stop().await;
}

#[tokio::test]
async fn names_members_and_presence() {
    let server = server().await;
    let alice = registered(&server, "alice").await;
    let alice_b = second_device(&server, &alice).await;
    let events = alice.subscribe();

    // Bob comes online after Alice: PRESENCE says so (8.3).
    let bob = registered(&server, "bob").await;
    let online = event("PRESENCE online", &events, |e| match e {
        AccountEvent::UserChanged { user } if user.uid == "bob@chat.test" => {
            (user.presence == Presence::Online).then_some(())
        }
        _ => None,
    });
    online.await;

    // NAME reaches those who share a conversation (8.2).
    bob.set_display_name("Bob").await.unwrap();
    until("Alice learns Bob's name", &events, || {
        alice.display_name("bob@chat.test").unwrap().as_deref() == Some("Bob")
    })
    .await;
    alice.set_display_name("Bob").await.unwrap();

    // MEMBERS, with the uid shown where names clash (8.2).
    let general = alice.conversation("#general").unwrap();
    let members = general.members().await.unwrap();
    let mut shown: Vec<(String, String, Option<String>, Presence)> = members
        .iter()
        .map(|m| {
            (
                m.uid.clone(),
                m.label.name.clone(),
                m.label.uid.clone(),
                m.presence,
            )
        })
        .collect();
    shown.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        shown,
        [
            (
                "alice@chat.test".to_owned(),
                "Bob".to_owned(),
                Some("alice@chat.test".to_owned()),
                Presence::Online
            ),
            (
                "bob@chat.test".to_owned(),
                "Bob".to_owned(),
                Some("bob@chat.test".to_owned()),
                Presence::Online
            ),
        ]
    );
    assert_eq!(general.cached_members().unwrap().len(), 2);
    // The other device hears its own account's name too.
    until("B learns the account's name", &alice_b.subscribe(), || {
        alice_b.display_name("alice@chat.test").unwrap().as_deref() == Some("Bob")
    })
    .await;

    // WHOIS (8.3).
    let who = alice.whois("bob@chat.test").await.unwrap();
    assert_eq!(who.display_name.as_deref(), Some("Bob"));
    assert_eq!(who.presence, Presence::Online);
    assert_eq!(
        alice.whois("nobody@chat.test").await.unwrap_err().code(),
        Some("not-found")
    );
    server.stop().await;
}

#[tokio::test]
async fn blocks_reach_every_device_and_hide_messages() {
    let server = server().await;
    let alice = registered(&server, "alice").await;
    let alice_b = second_device(&server, &alice).await;
    let bob = registered(&server, "bob").await;

    let sent = bob
        .conversation("#general")
        .unwrap()
        .send("spam")
        .await
        .unwrap();
    within("sending", bob.wait_outbox(sent.id)).await.unwrap();
    until("Alice has it", &alice.subscribe(), || unread(&alice) == 1).await;

    alice.block("bob@chat.test").await.unwrap();
    assert!(alice.is_blocked("bob@chat.test").unwrap());
    assert_eq!(alice.blocks().await.unwrap(), ["bob@chat.test"]);
    // The other device asks BLOCKS on its next connection (5.7).
    alice_b.disconnect().await;
    alice_b.connect().await.unwrap();
    alice_b.wait_synced().await.unwrap();
    assert!(alice_b.is_blocked("bob@chat.test").unwrap());

    // Hidden in rooms on the client, kept in the cache (5.7).
    let general = alice.conversation("#general").unwrap();
    let timeline = general.timeline(50).unwrap();
    let texts = |items: &[librisala::client::Message]| -> Vec<String> {
        items.iter().filter_map(|m| m.text.clone()).collect()
    };
    assert_eq!(texts(&timeline.items()), ["spam"]);
    alice.set_hide_blocked(true).unwrap();
    match within("reset", timeline.next()).await.unwrap().as_slice() {
        [TimelineDiff::Reset { items }] => assert!(texts(items).is_empty()),
        other => panic!("{other:?}"),
    }
    assert_eq!(unread(&alice), 0);
    alice.unblock("bob@chat.test").await.unwrap();
    match within("reset", timeline.next()).await.unwrap().as_slice() {
        [TimelineDiff::Reset { items }] => assert_eq!(texts(items), ["spam"]),
        other => panic!("{other:?}"),
    }
    assert_eq!(unread(&alice), 1);

    // Blocking a domain covers its identities.
    alice.block("*@chat.test").await.unwrap();
    assert!(alice.is_blocked("bob@chat.test").unwrap());
    server.stop().await;
}
