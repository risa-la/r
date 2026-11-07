//! Transcript tests of read markers (7.4), typing (8.1), display names
//! (8.2), MEMBERS, WHOIS and PRESENCE (8.3), and blocks (5.7), through the
//! [`Handler`] trait.
//!
//! Identities sign in with [`Harness::signed_in_as`], without AUTH, which
//! the identity tests cover. Tests of timers run on tokio's paused clock.

use std::sync::Arc;
use std::time::Duration;

use risala_proto::names::Uid;
use risala_proto::types::{GuestAccess, Role, RoomSetting};

use super::tests::{Harness, config, put, set, start, strings, timers};
use super::*;
use crate::store::{EventKind, SqliteStore};

const ALICE: &str = "alice@example.org";
const BOB: &str = "bob@example.org";
const CAROL: &str = "carol@example.net";
const DAVE: &str = "dave@example.net";

fn uid(s: &str) -> Uid {
    s.parse().unwrap()
}

/// A hub with these rooms, each with its members stored:
///
/// - `#general`: alice (its owner), bob and carol
/// - `#other`: alice and dave
/// - `#private` (not public): bob
/// - `#quiet` (`guests read`): alice
///
/// Every identity is known to the server (5.1). Unless `timers` says
/// otherwise, presence changes are held for a day.
fn harness(timers: Timers) -> Harness {
    harness_with(timers, |_| {})
}

/// [`harness`], after `prepare` has had a go at the store.
fn harness_with(timers: Timers, prepare: impl FnOnce(&SqliteStore)) -> Harness {
    let mut c = config();
    c.rooms = strings(&["#general", "#other", "#private", "#quiet"]);
    let store = SqliteStore::open_in_memory().unwrap();
    for room in &c.rooms {
        store.ensure_room(&room.parse().unwrap(), start()).unwrap();
    }
    set(&store, "#private", RoomSetting::Public(false));
    set(&store, "#quiet", RoomSetting::Guests(GuestAccess::Read));
    for (room, who) in [
        ("#general", ALICE),
        ("#general", BOB),
        ("#general", CAROL),
        ("#other", ALICE),
        ("#other", DAVE),
        ("#private", BOB),
        ("#quiet", ALICE),
    ] {
        put(&store, room, who, EventKind::Join);
    }
    put(
        &store,
        "#general",
        ALICE,
        EventKind::Role {
            uid: uid(ALICE),
            role: Role::Owner,
        },
    );
    for who in [ALICE, BOB, CAROL, DAVE] {
        store.touch_identity(&uid(who), start()).unwrap();
    }
    prepare(&store);
    Harness::on(c, Arc::new(store), timers)
}

/// Presence after 30 seconds, sent in batches of 1 second (8.3).
fn presence_timers() -> Timers {
    Timers {
        presence_offline: Duration::from_secs(30),
        presence_batch: Duration::from_secs(1),
        ..timers()
    }
}

/// Waits on the paused clock.
async fn wait(ms: u64) {
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

fn none() -> Vec<String> {
    Vec::new()
}

// ---------------------------------------------------------------------------
// READ (7.4)

#[tokio::test]
async fn read_markers_move_forward_and_reach_the_other_devices() {
    let mut h = harness(timers());
    let mut a1 = h.signed_in_as(ALICE);
    let mut a2 = h.signed_in_as(ALICE);
    let mut bob = h.signed_in_as(BOB);
    // #general has events 1-4: three JOINs and a ROLE.
    h.send(&a1, "@ref=r read #general 3").await;
    assert_eq!(a1.lines(), ["@ref=r OK"]);
    assert_eq!(a2.lines(), ["READ #general 3"]);
    assert_eq!(bob.lines(), none());

    // Lower, or the same: nothing changes, and nobody is told.
    h.send(&a1, "read #general 2").await;
    h.send(&a2, "read #general 3").await;
    assert_eq!(a1.lines(), ["OK"]);
    assert_eq!(a2.lines(), ["OK"]);

    // Beyond the head: the head.
    h.send(&a2, "read #general 99").await;
    assert_eq!(a2.lines(), ["OK"]);
    assert_eq!(a1.lines(), ["READ #general 4"]);

    // SYNC reports it (7.1), to every device; bob has none.
    h.send(&a1, "sync").await;
    let sync = a1.lines();
    assert!(sync[0].starts_with("CONV #general ") && sync[0].ends_with(" 4 4"));
    assert!(sync[1].starts_with("CONV #other ") && sync[1].ends_with(" 0"));
    h.send(&bob, "sync").await;
    assert!(bob.lines()[0].ends_with(" 4 0"));
    // Stored for the account.
    let markers = h.store.read_markers(&uid(ALICE)).unwrap();
    assert_eq!(markers.len(), 1);
    assert_eq!(markers[0].1.get(), 4);
}

/// The `<read>` on a CONV line covers the READ lines sent to the
/// connection before it (3.6, 7.1): a READ from another device while SYNC
/// is answering never arrives before a CONV line with an older marker.
#[tokio::test]
async fn sync_agrees_with_read_lines() {
    let store = Arc::new(super::tests::Flaky::new());
    store
        .inner
        .ensure_room(&"#general".parse().unwrap(), start())
        .unwrap();
    for (room, who) in [("#general", ALICE), ("#general", BOB), ("#general", CAROL)] {
        put(&store.inner, room, who, EventKind::Join);
    }
    let mut h = Harness::on(config(), store.clone(), timers());
    let mut a1 = h.signed_in_as(ALICE);
    let mut a2 = h.signed_in_as(ALICE);
    h.send(&a1, "read #general 1").await;
    a1.lines();
    a2.lines();

    store.pause.arm("read_markers");
    let (hub, id) = (h.hub.clone(), a2.id);
    let syncing = tokio::spawn(async move { hub.command(id, "sync".parse().unwrap()).await });
    store.pause.reached().await;
    // SYNC has read the markers, with 1 for #general.
    h.send(&a1, "read #general 2").await;
    assert_eq!(a1.lines(), ["OK"]);
    store.pause.release();
    syncing.await.unwrap();
    let lines = a2.lines();
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert_eq!(lines[0], "READ #general 2");
    assert!(
        lines[1].starts_with("CONV #general ") && lines[1].ends_with(" 3 2"),
        "{lines:?}"
    );
    assert_eq!(lines[2], "OK");
}

#[tokio::test]
async fn read_markers_need_a_room_one_may_read() {
    let mut h = harness(timers());
    let mut alice = h.signed_in_as(ALICE);
    // A private room she is not in, or no room at all.
    h.send(&alice, "read #private 1").await;
    assert_eq!(alice.lines(), ["ERR not-found no such room"]);
    h.send(&alice, "read #nowhere 1").await;
    assert_eq!(alice.lines(), ["ERR not-found no such room"]);
    h.send(&alice, "read #other 1").await;
    assert_eq!(alice.lines(), ["OK"]);
    // A public room bob is not in: he may read it, so it may have a
    // marker.
    let mut bob = h.signed_in_as(BOB);
    h.send(&bob, "read #other 1").await;
    assert_eq!(bob.lines(), ["OK"]);
    // M5a: direct conversations.
    h.send(&alice, "read bob@example.org 1").await;
    assert_eq!(alice.lines(), ["ERR not-supported not supported yet"]);
    // Guests have no read markers (7.4).
    let mut sam = h.guest("sam").await;
    h.send(&sam, "read #general 1").await;
    assert_eq!(sam.lines(), ["ERR forbidden not for guests"]);
}

// ---------------------------------------------------------------------------
// TYPING (8.1)

#[tokio::test(start_paused = true)]
async fn typing_reaches_the_other_members() {
    let mut h = harness(timers());
    let mut a1 = h.signed_in_as(ALICE);
    let mut a2 = h.signed_in_as(ALICE);
    let mut bob = h.signed_in_as(BOB);
    let mut dave = h.signed_in_as(DAVE);
    let (mut sam, _) = h.joined("sam", "#general").await;
    bob.lines();
    a1.lines();
    a2.lines();

    h.send(&a1, "@ref=t typing #General").await;
    assert_eq!(a1.lines(), ["@ref=t OK"]);
    let line = "@from=alice@example.org TYPING #general";
    assert_eq!(bob.lines(), [line]);
    assert_eq!(sam.lines(), [line]);
    // Not to the typist's other devices, nor to people not in the room.
    assert_eq!(a2.lines(), none());
    assert_eq!(dave.lines(), none());

    // At most one a second per connection and conversation; the others
    // still get OK.
    h.send(&a1, "typing #general").await;
    assert_eq!(a1.lines(), ["OK"]);
    assert_eq!(bob.lines(), none());
    // Another connection, or another room, is counted apart.
    h.send(&a2, "typing #general").await;
    h.send(&a1, "typing #other").await;
    assert_eq!(bob.lines(), [line]);
    assert_eq!(dave.lines(), ["@from=alice@example.org TYPING #other"]);
    wait(1000).await;
    h.send(&a1, "typing #general").await;
    assert_eq!(bob.lines(), [line]);

    assert_eq!(sam.lines(), [line, line]);

    // Guests may type where they may write.
    h.send(&sam, "typing #general").await;
    assert_eq!(sam.lines(), ["OK"]);
    assert_eq!(bob.lines(), ["@from=~sam TYPING #general"]);
}

#[tokio::test(start_paused = true)]
async fn a_message_lets_the_next_typing_through() {
    let mut h = harness(timers());
    let mut a1 = h.signed_in_as(ALICE);
    let mut a2 = h.signed_in_as(ALICE);
    let mut bob = h.signed_in_as(BOB);
    bob.lines();
    a1.lines();
    a2.lines();
    let line = "@from=alice@example.org TYPING #general";
    h.send(&a1, "typing #general").await;
    h.send(&a2, "typing #general").await;
    assert_eq!(bob.lines(), [line, line]);
    // The message ends the notification on every device (8.1), so typing
    // again within the rate limit's second is passed on at once.
    h.send(&a1, "msg #general done").await;
    bob.lines();
    h.send(&a1, "typing #general").await;
    h.send(&a2, "typing #general").await;
    assert_eq!(bob.lines(), [line, line]);
}

#[tokio::test]
async fn typing_needs_membership_and_write_access() {
    let mut h = harness(timers());
    let mut bob = h.signed_in_as(BOB);
    h.send(&bob, "typing #other").await;
    assert_eq!(bob.lines(), ["ERR forbidden join the room first"]);
    h.send(&bob, "typing #nowhere").await;
    assert_eq!(bob.lines(), ["ERR not-found no such room"]);
    let mut dave = h.signed_in_as(DAVE);
    h.send(&dave, "typing #private").await;
    assert_eq!(dave.lines(), ["ERR not-found no such room"]);
    // M5a: direct conversations.
    h.send(&bob, "typing alice@example.org").await;
    assert_eq!(bob.lines(), ["ERR not-supported not supported yet"]);

    let (mut sam, _) = h.joined("sam", "#quiet").await;
    h.send(&sam, "typing #quiet").await;
    assert_eq!(sam.lines(), ["ERR forbidden guests may not send here"]);
    h.send(&sam, "typing alice@example.org").await;
    assert_eq!(sam.lines(), ["ERR not-found no such conversation"]);
}

#[tokio::test]
async fn typing_may_have_no_limit() {
    let mut h = harness(Timers {
        typing_interval: Duration::ZERO,
        ..timers()
    });
    let alice = h.signed_in_as(ALICE);
    let mut bob = h.signed_in_as(BOB);
    for _ in 0..3 {
        h.send(&alice, "typing #general").await;
    }
    assert_eq!(bob.lines().len(), 3);
}

// ---------------------------------------------------------------------------
// NAME (8.2)

#[tokio::test]
async fn names_reach_everyone_who_shares_a_conversation() {
    let mut h = harness(timers());
    let mut a1 = h.signed_in_as(ALICE);
    let mut a2 = h.signed_in_as(ALICE);
    let mut bob = h.signed_in_as(BOB);
    let mut dave = h.signed_in_as(DAVE);
    let mut eve = h.signed_in_as("eve@example.com");
    bob.lines();

    h.send(&a1, "@ref=n name Alice Martin").await;
    assert_eq!(a1.lines(), ["@ref=n OK"]);
    let line = "@from=alice@example.org NAME Alice Martin";
    // Her other device, bob (#general) and dave (#other), each once.
    assert_eq!(a2.lines(), [line]);
    assert_eq!(bob.lines(), [line]);
    assert_eq!(dave.lines(), [line]);
    // Nobody who shares nothing with her.
    assert_eq!(eve.lines(), none());
    assert_eq!(
        h.store.identity(&uid(ALICE)).unwrap().unwrap().display_name,
        "Alice Martin"
    );

    // Empty clears it.
    h.send(&a2, "name").await;
    assert_eq!(a2.lines(), ["OK"]);
    assert_eq!(a1.lines(), ["@from=alice@example.org NAME"]);
    assert_eq!(bob.lines(), ["@from=alice@example.org NAME"]);
    assert_eq!(
        h.store.identity(&uid(ALICE)).unwrap().unwrap().display_name,
        ""
    );

    // Someone in no conversation reaches only their own devices.
    let mut eve2 = h.signed_in_as("eve@example.com");
    h.send(&eve, "name Eve").await;
    assert_eq!(eve.lines(), ["OK"]);
    assert_eq!(eve2.lines(), ["@from=eve@example.com NAME Eve"]);
    assert_eq!(a1.lines(), none());
}

/// A display name may not hold bidirectional text controls, which can
/// make one name look like another (8.2, 14). Other text is fine.
#[tokio::test]
async fn names_with_bidi_controls_are_refused() {
    let mut h = harness(timers());
    let mut alice = h.signed_in_as(ALICE);
    let mut bob = h.signed_in_as(BOB);
    h.send(&alice, "name عائشة").await;
    assert_eq!(alice.lines(), ["OK"]);
    bob.lines();
    for c in [
        '\u{061C}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{202E}', '\u{2066}', '\u{2069}',
    ] {
        h.send(&alice, &format!("name bob{c}")).await;
        assert_eq!(
            alice.lines(),
            ["ERR forbidden a display name may not hold bidirectional text controls"],
            "{:04X}",
            c as u32
        );
    }
    assert_eq!(bob.lines(), none());
    assert_eq!(
        h.store.identity(&uid(ALICE)).unwrap().unwrap().display_name,
        "عائشة"
    );
    // Guests too.
    let mut sam = h.guest("sam").await;
    h.send(&sam, "name \u{202E}mas").await;
    assert_eq!(
        sam.lines(),
        ["ERR forbidden a display name may not hold bidirectional text controls"]
    );
}

#[tokio::test]
async fn guest_names_last_as_long_as_the_session() {
    let mut h = harness(timers());
    let mut bob = h.signed_in_as(BOB);
    let (mut sam, _) = h.joined("sam", "#general").await;
    bob.lines();
    h.send(&sam, "name Sam the Guest").await;
    assert_eq!(sam.lines(), ["OK"]);
    assert_eq!(bob.lines(), ["@from=~sam NAME Sam the Guest"]);
    h.send(&bob, "whois ~sam").await;
    assert_eq!(bob.lines(), ["USER ~sam online Sam the Guest", "OK"]);

    h.leave(sam, "sam").await;
    bob.lines();
    h.send(&bob, "whois ~sam").await;
    assert_eq!(bob.lines(), ["ERR not-found no such user"]);
    // A new guest of the same name starts with none.
    let mut sam = h.guest("sam").await;
    h.send(&sam, "whois ~sam").await;
    assert_eq!(sam.lines(), ["USER ~sam online", "OK"]);
}

// ---------------------------------------------------------------------------
// MEMBERS and WHOIS (8.3)

#[tokio::test]
async fn members_lists_roles_presence_and_names() {
    let mut h = harness(timers());
    let mut alice = h.signed_in_as(ALICE);
    h.send(&alice, "name Alice").await;
    let (mut sam, _) = h.joined("sam", "#general").await;
    h.send(&sam, "name Sam").await;
    alice.lines();
    sam.lines();

    h.send(&sam, "@ref=m members #GENERAL").await;
    assert_eq!(
        sam.lines(),
        [
            "@ref=m MEMBER #general alice@example.org owner online Alice",
            "@ref=m MEMBER #general bob@example.org member offline",
            "@ref=m MEMBER #general carol@example.net member offline",
            "@ref=m MEMBER #general ~sam member online Sam",
            "@ref=m OK",
        ]
    );
    // Anyone who may read the room may ask, members or not (7.2).
    let mut dave = h.signed_in_as(DAVE);
    h.send(&dave, "members #quiet").await;
    assert_eq!(
        dave.lines(),
        ["MEMBER #quiet alice@example.org member online Alice", "OK"]
    );
    h.send(&dave, "members #private").await;
    assert_eq!(dave.lines(), ["ERR not-found no such room"]);
    let mut bob = h.signed_in_as(BOB);
    h.send(&bob, "members #private").await;
    assert_eq!(
        bob.lines(),
        ["MEMBER #private bob@example.org member online", "OK"]
    );
}

#[tokio::test]
async fn members_follows_the_guest_rules() {
    let mut h = harness_with(timers(), |s| {
        set(s, "#other", RoomSetting::Guests(GuestAccess::None));
    });
    let mut sam = h.guest("sam").await;
    h.send(&sam, "members #other").await;
    assert_eq!(
        sam.lines(),
        ["ERR forbidden guests may not enter this room"]
    );
}

#[tokio::test]
async fn whois_knows_identities_and_current_guests() {
    let mut h = harness(timers());
    let mut alice = h.signed_in_as(ALICE);
    h.send(&alice, "name Alice Martin").await;
    alice.lines();
    h.send(&alice, "@ref=w whois alice@example.org").await;
    assert_eq!(
        alice.lines(),
        [
            "@ref=w USER alice@example.org online Alice Martin",
            "@ref=w OK"
        ]
    );
    h.send(&alice, "whois bob@example.org").await;
    assert_eq!(alice.lines(), ["USER bob@example.org offline", "OK"]);
    // Never signed in here.
    h.send(&alice, "whois nobody@example.org").await;
    assert_eq!(alice.lines(), ["ERR not-found no such user"]);
    h.send(&alice, "whois ~nobody").await;
    assert_eq!(alice.lines(), ["ERR not-found no such user"]);
    // A guest whose connection closed is still around while its session
    // waits to be resumed (4.2).
    let sam = h.guest("sam").await;
    h.close(sam).await;
    h.send(&alice, "whois ~sam").await;
    assert_eq!(alice.lines(), ["USER ~sam online", "OK"]);
    h.end("sam").await;
    h.send(&alice, "whois ~sam").await;
    assert_eq!(alice.lines(), ["ERR not-found no such user"]);
}

// ---------------------------------------------------------------------------
// PRESENCE (8.3)

#[tokio::test(start_paused = true)]
async fn presence_is_batched_and_sent_to_those_who_share_a_conversation() {
    let mut h = harness(presence_timers());
    let (mut sam, _) = h.joined("sam", "#general").await;
    let mut alice = h.signed_in_as(ALICE);
    let mut bob = h.signed_in_as(BOB);
    sam.lines();
    // Nothing until the batch is sent, one line for both.
    wait(900).await;
    assert_eq!(sam.lines(), none());
    wait(200).await;
    assert_eq!(
        sam.lines(),
        ["PRESENCE online alice@example.org,bob@example.org"]
    );
    // Nobody hears about themselves.
    assert_eq!(alice.lines(), ["PRESENCE online bob@example.org"]);
    assert_eq!(bob.lines(), ["PRESENCE online alice@example.org"]);

    // Dave shares only #other with alice; carol only #general with alice
    // and bob. Each hears only of those.
    let mut dave = h.signed_in_as(DAVE);
    let mut carol = h.signed_in_as(CAROL);
    wait(1100).await;
    assert_eq!(
        alice.lines(),
        ["PRESENCE online carol@example.net,dave@example.net"]
    );
    assert_eq!(bob.lines(), ["PRESENCE online carol@example.net"]);
    assert_eq!(sam.lines(), ["PRESENCE online carol@example.net"]);
    assert_eq!(dave.lines(), none());
    assert_eq!(carol.lines(), none());

    // Someone who shares nothing is nobody's news.
    let _eve = h.signed_in_as("eve@example.com");
    wait(1100).await;
    for c in [&mut alice, &mut bob, &mut carol, &mut dave, &mut sam] {
        assert_eq!(c.lines(), none());
    }
}

#[tokio::test(start_paused = true)]
async fn offline_waits_30_seconds_and_a_reconnect_says_nothing() {
    let mut h = harness(presence_timers());
    let mut bob = h.signed_in_as(BOB);
    let a1 = h.signed_in_as(ALICE);
    wait(1100).await;
    assert_eq!(bob.lines(), ["PRESENCE online alice@example.org"]);

    // A second device, and closing one of two, change nothing.
    let a2 = h.signed_in_as(ALICE);
    h.close(a1).await;
    wait(1100).await;
    assert_eq!(bob.lines(), none());

    // The last one closes; alice comes back within 30 seconds.
    h.close(a2).await;
    wait(29_000).await;
    h.send(&bob, "whois alice@example.org").await;
    assert_eq!(bob.lines(), ["USER alice@example.org online", "OK"]);
    let a3 = h.signed_in_as(ALICE);
    wait(60_000).await;
    assert_eq!(bob.lines(), none());

    // She goes for good: 30 seconds, then the batch.
    h.close(a3).await;
    wait(30_500).await;
    assert_eq!(bob.lines(), none());
    wait(1000).await;
    assert_eq!(bob.lines(), ["PRESENCE offline alice@example.org"]);
    h.send(&bob, "whois alice@example.org").await;
    assert_eq!(bob.lines(), ["USER alice@example.org offline", "OK"]);
    h.send(&bob, "members #general").await;
    assert!(
        bob.lines()
            .contains(&"MEMBER #general alice@example.org owner offline".to_string())
    );

    // Back again: online at once, after the batch.
    let _a4 = h.signed_in_as(ALICE);
    wait(1100).await;
    assert_eq!(bob.lines(), ["PRESENCE online alice@example.org"]);
}

#[tokio::test(start_paused = true)]
async fn one_batch_may_carry_both_online_and_offline() {
    let mut h = harness(presence_timers());
    let mut bob = h.signed_in_as(BOB);
    let alice = h.signed_in_as(ALICE);
    wait(1100).await;
    bob.lines();
    h.close(alice).await;
    wait(30_000).await;
    // Carol comes online in the same batch as alice goes offline.
    let _carol = h.signed_in_as(CAROL);
    wait(1100).await;
    assert_eq!(
        bob.lines(),
        [
            "PRESENCE online carol@example.net",
            "PRESENCE offline alice@example.org"
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn a_visit_shorter_than_a_batch_goes_unreported() {
    let mut h = harness(presence_timers());
    let mut bob = h.signed_in_as(BOB);
    wait(1100).await;
    let alice = h.signed_in_as(ALICE);
    wait(500).await;
    h.close(alice).await;
    wait(60_000).await;
    assert_eq!(bob.lines(), none());
}

#[tokio::test(start_paused = true)]
async fn offline_may_be_reported_at_once() {
    let mut h = harness(Timers {
        presence_offline: Duration::ZERO,
        ..presence_timers()
    });
    let mut bob = h.signed_in_as(BOB);
    let alice = h.signed_in_as(ALICE);
    wait(1100).await;
    assert_eq!(bob.lines(), ["PRESENCE online alice@example.org"]);
    h.close(alice).await;
    wait(1100).await;
    assert_eq!(bob.lines(), ["PRESENCE offline alice@example.org"]);
}

#[tokio::test(start_paused = true)]
async fn presence_follows_membership() {
    let mut h = harness(presence_timers());
    let mut dave = h.signed_in_as(DAVE);
    let mut bob = h.signed_in_as(BOB);
    wait(1100).await;
    assert_eq!(dave.lines(), none());
    // Once they share a room, they hear of each other.
    h.send(&dave, "join #general").await;
    dave.lines();
    bob.lines();
    let carol = h.signed_in_as(CAROL);
    wait(1100).await;
    assert_eq!(dave.lines(), ["PRESENCE online carol@example.net"]);
    h.send(&dave, "part #general").await;
    dave.lines();
    h.close(carol).await;
    wait(31_100).await;
    assert_eq!(dave.lines(), none());
    assert_eq!(
        bob.lines().last().unwrap(),
        "PRESENCE offline carol@example.net"
    );
}

// ---------------------------------------------------------------------------
// BLOCK, UNBLOCK and BLOCKS (5.7)

#[tokio::test]
async fn blocks_are_stored_listed_and_removed() {
    let mut h = harness(timers());
    let mut a1 = h.signed_in_as(ALICE);
    let mut a2 = h.signed_in_as(ALICE);
    h.send(&a1, "@ref=b blocks").await;
    assert_eq!(a1.lines(), ["@ref=b OK"]);
    for target in ["spam@example.net", "*@Bad.Example", "spam@example.net"] {
        h.send(&a1, &format!("@ref=x block {target}")).await;
        assert_eq!(a1.lines(), ["@ref=x OK"]);
    }
    // The account's other connections hear of it, line by line (5.7).
    assert_eq!(
        a2.lines(),
        [
            "BLOCK spam@example.net",
            "BLOCK *@bad.example",
            "BLOCK spam@example.net"
        ]
    );
    // A block belongs to the account, and applies to all its devices.
    h.send(&a2, "@ref=l blocks").await;
    assert_eq!(
        a2.lines(),
        [
            "@ref=l BLOCK *@bad.example",
            "@ref=l BLOCK spam@example.net",
            "@ref=l OK"
        ]
    );
    let alice = uid(ALICE);
    for (who, blocked) in [
        ("spam@example.net", true),
        ("x@bad.example", true),
        ("x@sub.bad.example", true),
        ("x@notbad.example", false),
        ("spam@example.org", false),
        ("~spam", false),
    ] {
        assert_eq!(
            h.hub.is_blocked(&alice, &uid(who)).await.unwrap(),
            blocked,
            "{who}"
        );
    }
    // Nobody else's.
    assert!(
        !h.hub
            .is_blocked(&uid(BOB), &uid("spam@example.net"))
            .await
            .unwrap()
    );

    h.send(&a2, "unblock *@bad.example").await;
    h.send(&a2, "unblock nobody@example.com").await;
    assert_eq!(a2.lines(), ["OK", "OK"]);
    assert_eq!(
        a1.lines(),
        ["UNBLOCK *@bad.example", "UNBLOCK nobody@example.com"]
    );
    h.send(&a1, "blocks").await;
    assert_eq!(a1.lines(), ["BLOCK spam@example.net", "OK"]);
    // Nobody else hears of them.
    let mut bob = h.signed_in_as(BOB);
    h.send(&a1, "block x@example.net").await;
    a1.lines();
    assert_eq!(bob.lines(), Vec::<String>::new());

    // Blocks change nothing in rooms (5.7).
    let mut spam = h.signed_in_as("spam@example.net");
    h.send(&spam, "join #general").await;
    spam.lines();
    a1.lines();
    h.send(&spam, "msg #general hello").await;
    assert!(a1.lines()[0].ends_with(" MSG #general hello"));

    // Guests cannot block (5.7, 13).
    let mut sam = h.guest("sam").await;
    for cmd in [
        "block spam@example.net",
        "unblock spam@example.net",
        "blocks",
    ] {
        h.send(&sam, cmd).await;
        assert_eq!(sam.lines(), ["ERR forbidden not for guests"]);
    }
}

/// A BLOCKS reply covers every BLOCK and UNBLOCK line sent to the
/// connection before it (5.7, 3.6): an UNBLOCK from another device while
/// BLOCKS is answering comes after the whole reply, so the client never
/// puts back a block that was lifted.
#[tokio::test]
async fn blocks_replies_agree_with_block_lines() {
    let store = Arc::new(super::tests::Flaky::new());
    let mut h = Harness::on(config(), store.clone(), timers());
    let mut a1 = h.signed_in_as(ALICE);
    let mut a2 = h.signed_in_as(ALICE);
    h.send(&a1, "block spam@example.net").await;
    a1.lines();
    a2.lines();

    store.pause.arm("blocks");
    let (hub, id) = (h.hub.clone(), a2.id);
    let listing = tokio::spawn(async move { hub.command(id, "blocks".parse().unwrap()).await });
    store.pause.reached().await;
    let (hub, id) = (h.hub.clone(), a1.id);
    let lifting = tokio::spawn(async move {
        hub.command(id, "unblock spam@example.net".parse().unwrap())
            .await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    store.pause.release();
    listing.await.unwrap();
    lifting.await.unwrap();
    assert_eq!(a1.lines(), ["OK"]);
    assert_eq!(
        a2.lines(),
        ["BLOCK spam@example.net", "OK", "UNBLOCK spam@example.net"]
    );
}

#[tokio::test]
async fn an_account_has_at_most_max_blocks() {
    let mut c = config();
    c.limits.max_blocks = 2;
    let mut h = Harness::on(
        c,
        Arc::new(SqliteStore::open_in_memory().unwrap()),
        timers(),
    );
    let mut alice = h.signed_in_as(ALICE);
    h.send(&alice, "block a@example.net").await;
    h.send(&alice, "block b@example.net").await;
    h.send(&alice, "block c@example.net").await;
    h.send(&alice, "block a@example.net").await;
    assert_eq!(
        alice.lines(),
        ["OK", "OK", "ERR forbidden too many blocks", "OK"]
    );
}
