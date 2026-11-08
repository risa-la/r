//! Tests of edits and reactions (5.3), DELETE (5.4), RELATED (7.3),
//! retention (7.5), ADMIN PURGE (10.4) and UNREGISTER `purge=yes` (4.8).

use std::time::Duration;

use risala_proto::time::Timestamp;
use risala_proto::types::{Relation, Role, RoomRetention, RoomSetting};

use super::tests::{Client, Flaky, Harness, T, config, put, seq, set, start, timers, value};
use crate::config::Config;
use crate::store::{
    ConvKey, EventKind, HistoryQuery, MessageStore, NewEvent, PurgeQuery, RelatedQuery,
    SqliteStore, Store,
};

const ALICE: &str = "alice@example.org";
const BOB: &str = "bob@example.net";
const CAROL: &str = "carol@example.net";
const OP: &str = "op@example.net";

const DAY: Duration = Duration::from_secs(24 * 60 * 60);

fn msg(text: &str) -> EventKind {
    EventKind::Msg {
        relation: None,
        file: None,
        text: text.into(),
    }
}

fn related(relation: Relation, text: &str) -> EventKind {
    EventKind::Msg {
        relation: Some(relation),
        file: None,
        text: text.into(),
    }
}

/// Appends an event straight to the store, at time `t`.
fn put_at(store: &SqliteStore, room: &str, from: &str, kind: EventKind, t: Timestamp) {
    let key = store.room(&room.parse().unwrap()).unwrap().unwrap().key;
    let event = NewEvent {
        t,
        from: from.parse().unwrap(),
        kind,
        cid: None,
    };
    store.append(key, &event).unwrap();
}

fn with_operator() -> Config {
    let mut c = config();
    c.operators = vec![OP.into()];
    c
}

fn key(h: &Harness, room: &str) -> ConvKey {
    h.store.room(&room.parse().unwrap()).unwrap().unwrap().key
}

/// Every stored event of `room`, as `<seq> <from> <verb>[ deleted]`.
fn stored(h: &Harness, room: &str) -> Vec<String> {
    let all = HistoryQuery {
        after: Some(0),
        before: None,
        limit: 1000,
    };
    h.store
        .history(key(h, room), all)
        .unwrap()
        .events
        .iter()
        .map(|e| {
            let deleted = if e.deleted { " deleted" } else { "" };
            format!("{} {} {}{deleted}", e.seq, e.from, e.kind.verb())
        })
        .collect()
}

/// An identity signed in and a member of `room`, with its lines read.
async fn member(h: &mut Harness, uid: &str, room: &str) -> Client {
    let mut c = h.signed_in_as(uid);
    h.send(&c, &format!("join {room}")).await;
    c.lines();
    c
}

// ---------------------------------------------------------------------------
// Edits (5.3)

#[tokio::test]
async fn only_the_author_edits_a_message() {
    let mut h = Harness::new();
    let (mut sam, _) = h.joined("sam", "#general").await;
    let (mut bob, _) = h.joined("bob", "#general").await;
    sam.lines();
    h.send(&sam, "msg #general lunch?").await; // 3
    h.send(&sam, "@edit=3 msg #general lunch at 12?").await; // 4
    let edit = format!("@seq=4;t={T};from=~sam;edit=3 MSG #general lunch at 12?");
    assert_eq!(sam.lines()[2..], [edit.clone(), "OK seq=4".into()]);
    assert_eq!(bob.lines()[1..], [edit]);

    h.send(&bob, "@edit=3 msg #general lunch at 1?").await;
    // An edit of an edit, of a JOIN, of nothing.
    h.send(&sam, "@edit=4 msg #general no").await;
    h.send(&sam, "@edit=1 msg #general no").await;
    h.send(&sam, "@edit=99 msg #general no").await;
    assert_eq!(
        bob.lines(),
        ["ERR forbidden only the author may edit a message"]
    );
    assert_eq!(sam.lines(), ["ERR not-found no such message"; 3]);
    // Edits and replies target messages, not edits; a second edit goes to
    // the original too.
    h.send(&sam, "@edit=3 msg #general lunch at 12:30?").await;
    assert_eq!(sam.lines().last().unwrap(), "OK seq=5");
}

#[tokio::test]
async fn edits_and_reactions_of_a_deleted_message_are_refused() {
    let mut h = Harness::new();
    let (mut sam, _) = h.joined("sam", "#general").await;
    h.send(&sam, "msg #general oops").await; // 2
    h.send(&sam, "delete #general 2").await; // 3
    sam.lines();
    h.send(&sam, "@edit=2 msg #general fixed").await;
    h.send(&sam, "@react=2 msg #general 👍").await;
    h.send(&sam, "@react=3 msg #general 👍").await;
    assert_eq!(sam.lines(), ["ERR not-found no such message"; 3]);
}

// ---------------------------------------------------------------------------
// Reactions (5.3)

#[tokio::test]
async fn the_same_reaction_twice_is_one_event() {
    let mut h = Harness::new();
    let (mut sam, _) = h.joined("sam", "#general").await;
    let (mut bob, _) = h.joined("bob", "#general").await;
    h.send(&sam, "msg #general lunch?").await; // 3
    sam.lines();
    bob.lines();

    h.send(&bob, "@react=3 msg #general 🍕").await; // 4
    let reaction = format!("@seq=4;t={T};from=~bob;react=3 MSG #general 🍕");
    assert_eq!(bob.lines(), [reaction.clone(), "OK seq=4".into()]);
    assert_eq!(sam.lines(), [reaction]);

    // Again: the same seq, and nothing new for anyone.
    h.send(&bob, "@react=3 msg #general 🍕").await;
    assert_eq!(bob.lines(), ["OK seq=4"]);
    assert_eq!(sam.lines(), Vec::<String>::new());

    // Another reaction, the same one from someone else, a reaction to a
    // reaction.
    h.send(&bob, "@react=3 msg #general 🍣").await; // 5
    h.send(&sam, "@react=3 msg #general 🍕").await; // 6
    h.send(&sam, "@react=4 msg #general 🍕").await;
    assert_eq!(bob.lines()[1], "OK seq=5");
    assert_eq!(
        sam.lines()[2..],
        ["OK seq=6", "ERR not-found no such message"]
    );

    // Taken back and given again: a new event.
    h.send(&bob, "delete #general 4").await; // 7
    h.send(&bob, "@react=3 msg #general 🍕").await; // 8
    let lines = bob.lines();
    assert_eq!(lines.last().unwrap(), "OK seq=8");
    assert_eq!(stored(&h, "#general")[3], "4 ~bob MSG deleted");
}

#[tokio::test]
async fn guests_who_may_only_read_cannot_react() {
    let mut h = Harness::with(config(), |s| {
        put(s, "#general", ALICE, msg("hi")); // 1
        set(
            s,
            "#general",
            RoomSetting::Guests(risala_proto::types::GuestAccess::Read),
        );
    });
    let (mut sam, _) = h.joined("sam", "#general").await;
    h.send(&sam, "@react=1 msg #general 👋").await;
    assert_eq!(sam.lines(), ["ERR forbidden guests may not send here"]);
}

#[tokio::test]
async fn a_resent_reaction_gets_its_seq_before_any_other_check() {
    let mut h = Harness::new();
    let (mut sam, _) = h.joined("sam", "#general").await;
    let mut alice = member(&mut h, ALICE, "#general").await;
    h.send(&sam, "msg #general lunch?").await; // 3
    h.send(&alice, "@cid=0123456789abcdef;react=3 msg #general 🍕")
        .await; // 4
    h.send(&sam, "delete #general 3").await; // 5
    h.send(&alice, "part #general").await; // 6
    alice.lines();
    sam.lines();
    h.send(&alice, "@cid=0123456789abcdef;react=3 msg #general 🍕")
        .await;
    assert_eq!(alice.lines(), ["OK seq=4"]);
}

// ---------------------------------------------------------------------------
// DELETE (5.4)

#[tokio::test]
async fn delete_erases_a_message_with_its_edits_and_reactions() {
    let mut h = Harness::new();
    let (mut sam, id) = h.joined("sam", "#general").await;
    let (mut bob, _) = h.joined("bob", "#general").await;
    h.send(&sam, "msg #general lunch?").await; // 3
    h.send(&sam, "@edit=3 msg #general lunch at 12?").await; // 4
    h.send(&bob, "@react=3 msg #general 🍕").await; // 5
    h.send(&bob, "@reply=3 msg #general sure").await; // 6
    sam.lines();
    bob.lines();

    h.send(&sam, "@ref=d delete #general 3").await; // 7
    let event = format!("@seq=7;t={T};from=~sam DELETE #general 3");
    assert_eq!(sam.lines(), [event.clone(), "@ref=d OK seq=7".into()]);
    assert_eq!(bob.lines(), [event]);

    // Again, it records nothing and names the DELETE that did it, also
    // for an edit that went with its message (5.4).
    h.send(&sam, "delete #general 3").await;
    h.send(&sam, "delete #general 4").await;
    assert_eq!(sam.lines(), ["OK seq=7"; 2]);
    assert!(bob.lines().is_empty());

    h.send(&sam, "history #general after=2").await;
    assert_eq!(
        sam.lines(),
        [
            format!("@seq=3;t={T};from=~sam;deleted MSG #general"),
            format!("@seq=4;t={T};from=~sam;edit=3;deleted MSG #general"),
            format!("@seq=5;t={T};from=~bob;react=3;deleted MSG #general"),
            format!("@seq=6;t={T};from=~bob;reply=3 MSG #general sure"),
            format!("@seq=7;t={T};from=~sam DELETE #general 3"),
            format!("OK id={id} more=0"),
        ]
    );
}

#[tokio::test]
async fn deleting_an_edit_or_reaction_leaves_the_message() {
    let mut h = Harness::new();
    let (mut sam, _) = h.joined("sam", "#general").await;
    h.send(&sam, "msg #general lunch?").await; // 2
    h.send(&sam, "@edit=2 msg #general lunch at 12?").await; // 3
    h.send(&sam, "@react=2 msg #general 🍕").await; // 4
    h.send(&sam, "delete #general 3").await; // 5
    h.send(&sam, "delete #general 4").await; // 6
    assert_eq!(sam.lines().last().unwrap(), "OK seq=6");
    assert_eq!(
        stored(&h, "#general")[1..4],
        ["2 ~sam MSG", "3 ~sam MSG deleted", "4 ~sam MSG deleted"]
    );
}

#[tokio::test]
async fn only_messages_can_be_deleted() {
    let mut h = Harness::new();
    let (mut sam, _) = h.joined("sam", "#general").await;
    h.send(&sam, "msg #general hi").await; // 2
    h.send(&sam, "delete #general 2").await; // 3
    sam.lines();
    // A JOIN, a DELETE, nothing.
    for target in [1, 3, 99] {
        h.send(&sam, &format!("delete #general {target}")).await;
        assert_eq!(sam.lines(), ["ERR not-found no such message"], "{target}");
    }
    h.send(&sam, "delete #nowhere 1").await;
    assert_eq!(sam.lines(), ["ERR not-found no such room"]);
}

#[tokio::test]
async fn moderators_owners_and_operators_delete_anyones_messages() {
    let mut h = Harness::with(with_operator(), |s| {
        for n in 1..=4 {
            put(s, "#general", "~old", msg(&format!("spam {n}")));
        }
        put(
            s,
            "#general",
            ALICE,
            EventKind::Role {
                uid: BOB.parse().unwrap(),
                role: Role::Mod,
            },
        ); // 5
        put(
            s,
            "#general",
            ALICE,
            EventKind::Role {
                uid: ALICE.parse().unwrap(),
                role: Role::Owner,
            },
        ); // 6
    });
    let (mut sam, _) = h.joined("sam", "#general").await; // 7
    let mut carol = member(&mut h, CAROL, "#general").await; // 8
    sam.lines();

    // Plain members and guests may not.
    h.send(&sam, "delete #general 1").await;
    h.send(&carol, "delete #general 1").await;
    let no = "ERR forbidden only moderators may delete others' messages";
    assert_eq!(sam.lines(), [no]);
    assert_eq!(carol.lines(), [no]);

    // A moderator and an owner who are not members, and an operator.
    let mut bob = h.signed_in_as(BOB);
    let mut alice = h.signed_in_as(ALICE);
    let mut op = h.signed_in_as(OP);
    h.send(&bob, "delete #general 1").await;
    h.send(&alice, "delete #general 2").await;
    h.send(&op, "delete #general 3").await;
    assert_eq!(bob.lines(), ["OK seq=9"]);
    assert_eq!(alice.lines(), ["OK seq=10"]);
    assert_eq!(op.lines(), ["OK seq=11"]);
    assert_eq!(
        sam.lines(),
        [
            format!("@seq=9;t={T};from={BOB} DELETE #general 1"),
            format!("@seq=10;t={T};from={ALICE} DELETE #general 2"),
            format!("@seq=11;t={T};from={OP} DELETE #general 3"),
        ]
    );
}

#[tokio::test]
async fn authors_delete_where_they_can_no_longer_read() {
    let mut h = Harness::with(config(), |s| {
        put(s, "#general", ALICE, msg("mine")); // 1
        put(s, "#general", BOB, msg("bob's")); // 2
        put(
            s,
            "#general",
            CAROL,
            EventKind::Ban {
                uid: ALICE.parse().unwrap(),
                reason: String::new(),
            },
        ); // 3
        set(s, "#general", RoomSetting::Public(false)); // 4
    });
    // Banned, and the room is private: alice cannot see it.
    let mut alice = h.signed_in_as(ALICE);
    h.send(&alice, "history #general").await;
    h.send(&alice, "delete #general 2").await;
    h.send(&alice, "delete #general 99").await;
    h.send(&alice, "delete #general 1").await;
    assert_eq!(
        alice.lines(),
        [
            "ERR not-found no such room",
            "ERR not-found no such room",
            "ERR not-found no such room",
            "OK seq=5",
        ]
    );
    // Again, it is safe to resend: the same seq, nothing recorded.
    h.send(&alice, "delete #general 1").await;
    assert_eq!(alice.lines(), ["OK seq=5"]);
    assert_eq!(stored(&h, "#general")[0], format!("1 {ALICE} MSG deleted"));
    assert_eq!(stored(&h, "#general").len(), 5);
    // With the id of an older room of the same name, nothing (5.4).
    h.send(&alice, "@id=k3f9q2abcdef delete #general 1").await;
    assert_eq!(alice.lines(), ["ERR not-found no such message"]);
}

#[tokio::test]
async fn a_guest_name_taken_again_is_not_the_author() {
    let mut h = Harness::new();
    let (sam, _) = h.joined("sam", "#general").await;
    h.send(&sam, "msg #general lunch?").await; // 2
    h.send(&sam, "@react=2 msg #general 🍕").await; // 3
    h.leave(sam, "sam").await; // 4
    h.clock.advance(Duration::from_secs(1));

    let (mut sam, _) = h.joined("sam", "#general").await; // 5
    h.send(&sam, "@edit=2 msg #general dinner?").await;
    h.send(&sam, "delete #general 2").await;
    h.send(&sam, "@react=2 msg #general 🍕").await; // 6
    assert_eq!(
        sam.lines(),
        [
            "ERR forbidden only the author may edit a message".to_owned(),
            "ERR forbidden only moderators may delete others' messages".to_owned(),
            "@seq=6;t=2026-11-06T15:40:59.120Z;from=~sam;react=2 MSG #general 🍕".to_owned(),
            "OK seq=6".to_owned(),
        ]
    );
    // What it sent itself is its own.
    h.send(&sam, "delete #general 6").await;
    assert_eq!(sam.lines().last().unwrap(), "OK seq=7");
}

#[tokio::test]
async fn delete_in_a_direct_conversation_waits_for_m5a() {
    let mut h = Harness::new();
    let mut alice = h.signed_in_as(ALICE);
    h.send(&alice, &format!("delete {BOB} 1")).await;
    h.send(&alice, &format!("related {BOB} 1 2")).await;
    assert_eq!(alice.lines(), ["ERR not-supported not supported yet"; 2]);
}

#[tokio::test]
async fn a_failed_delete_records_nothing() {
    let flaky = std::sync::Arc::new(Flaky::new());
    flaky
        .inner
        .ensure_room(&"#general".parse().unwrap(), start())
        .unwrap();
    let mut h = Harness::on(config(), flaky.clone(), timers());
    let (mut sam, _) = h.joined("sam", "#general").await;
    h.send(&sam, "msg #general hi").await; // 2
    sam.lines();
    flaky
        .broken
        .store(true, std::sync::atomic::Ordering::SeqCst);
    h.send(&sam, "delete #general 2").await;
    assert_eq!(sam.lines(), ["ERR internal internal error"]);
    flaky
        .broken
        .store(false, std::sync::atomic::Ordering::SeqCst);
    h.send(&sam, "delete #general 2").await;
    assert_eq!(sam.lines().last().unwrap(), "OK seq=3");
}

// ---------------------------------------------------------------------------
// RELATED (7.3)

/// 1 and 2 are messages, 3 edits 2, 4 reacts to 1, 5 is a message, 6
/// reacts to 2 and 7 deletes it, 8 edits 5.
fn related_events() -> Harness {
    let mut c = config();
    c.limits.max_page = 3;
    Harness::with(c, |s| {
        put(s, "#general", ALICE, msg("lunch?"));
        put(s, "#general", BOB, msg("sure, at 12"));
        put(
            s,
            "#general",
            BOB,
            related(Relation::Edit(seq(2)), "sure, at 12:30"),
        );
        put(
            s,
            "#general",
            "~sam",
            related(Relation::React(seq(1)), "🍕"),
        );
        put(s, "#general", ALICE, msg("great"));
        put(
            s,
            "#general",
            "~sam",
            related(Relation::React(seq(2)), "👍"),
        );
        put(s, "#general", "~sam", EventKind::Delete { target: seq(6) });
        put(
            s,
            "#general",
            ALICE,
            related(Relation::Edit(seq(5)), "great!"),
        );
    })
}

#[tokio::test]
async fn related_returns_edits_and_reactions_of_a_range() {
    let mut h = related_events();
    let id = h
        .store
        .room(&"#general".parse().unwrap())
        .unwrap()
        .unwrap()
        .id;
    let mut sam = h.guest("sam").await;
    let edit3 = format!("@seq=3;t={T};from={BOB};edit=2 MSG #general sure, at 12:30");
    let react4 = format!("@seq=4;t={T};from=~sam;react=1 MSG #general 🍕");
    let react6 = format!("@seq=6;t={T};from=~sam;react=2;deleted MSG #general");
    let edit8 = format!("@seq=8;t={T};from={ALICE};edit=5 MSG #general great!");
    let ok = |more: u8| format!("OK id={id} more={more}");

    h.send(&sam, "related #general 1 2").await;
    assert_eq!(
        sam.lines(),
        [edit3.clone(), react4.clone(), react6.clone(), ok(0)]
    );
    h.send(&sam, "related #general 1 5 limit=2").await;
    assert_eq!(sam.lines(), [edit3.clone(), react4.clone(), ok(1)]);
    h.send(&sam, "related #general 1 5 after=4 limit=2").await;
    assert_eq!(sam.lines(), [react6.clone(), edit8.clone(), ok(0)]);
    // The server's page size caps the limit.
    h.send(&sam, "related #general 1 99 limit=10").await;
    assert_eq!(sam.lines(), [edit3, react4, react6, ok(1)]);
    h.send(&sam, "related #general 5 5 after=0").await;
    assert_eq!(sam.lines(), [edit8, ok(0)]);
    // Nothing: an empty range, a message nobody edited.
    h.send(&sam, "related #general 5 1").await;
    h.send(&sam, "related #general 3 4").await;
    assert_eq!(sam.lines(), [ok(0), ok(0)]);
}

#[tokio::test]
async fn related_follows_the_reading_rules() {
    let mut h = Harness::with(config(), |s| {
        put(s, "#general", ALICE, msg("lunch?"));
        set(
            s,
            "#general",
            RoomSetting::Guests(risala_proto::types::GuestAccess::None),
        );
    });
    let mut sam = h.guest("sam").await;
    let mut bob = h.signed_in_as(BOB);
    h.send(&sam, "related #general 1 1").await;
    h.send(&sam, "related #nowhere 1 1").await;
    h.send(&bob, "related #general 1 1").await;
    assert_eq!(
        sam.lines(),
        [
            "ERR forbidden guests may not enter this room",
            "ERR not-found no such room"
        ]
    );
    assert_eq!(value(&bob.lines()[0], "more"), "0");
}

// ---------------------------------------------------------------------------
// Retention (7.5)

fn with_retention(server: &str) -> Config {
    let mut c = config();
    c.server.retention = server.into();
    c.rooms.push("#short".into());
    c
}

#[tokio::test]
async fn old_events_expire_in_seq_order() {
    let day = |n: u32| start().checked_sub(DAY * n).unwrap();
    let mut h = Harness::with(with_retention("30"), |s| {
        put_at(s, "#general", ALICE, msg("1"), day(40));
        put_at(s, "#general", ALICE, msg("2"), day(31));
        // Not old enough: it stops here, though 4 is older (7.5).
        put_at(s, "#general", ALICE, msg("3"), day(29));
        put_at(s, "#general", ALICE, msg("4"), day(35));
        put_at(s, "#general", ALICE, msg("5"), day(1));
    });
    assert_eq!(h.hub.expire_now().await.unwrap(), 2);
    assert_eq!(
        stored(&h, "#general"),
        [
            format!("3 {ALICE} MSG"),
            format!("4 {ALICE} MSG"),
            format!("5 {ALICE} MSG")
        ]
    );
    // Nothing more yet.
    assert_eq!(h.hub.expire_now().await.unwrap(), 0);

    // Seqs go on from the head.
    let (mut sam, id) = h.joined("sam", "#general").await;
    h.send(&sam, "history #general after=0").await;
    let lines = sam.lines();
    assert!(lines[0].starts_with("@seq=3;"), "{lines:?}");
    assert_eq!(lines.last().unwrap(), &format!("OK id={id} more=0"));
    assert_eq!(value(&lines[3], "seq"), "6");

    // A day later, 3 and 4 have expired.
    h.clock.advance(DAY * 2);
    assert_eq!(h.hub.expire_now().await.unwrap(), 2);
    assert_eq!(stored(&h, "#general")[0], format!("5 {ALICE} MSG"));
}

#[tokio::test]
async fn the_shorter_period_applies() {
    let day = |n: u32| start().checked_sub(DAY * n).unwrap();
    let days = |n: u32| RoomRetention::Days(std::num::NonZeroU32::new(n).unwrap());
    let prepare = |s: &SqliteStore| {
        for room in ["#general", "#short"] {
            put_at(s, room, ALICE, msg("old"), day(20));
            put_at(s, room, ALICE, msg("older"), day(8));
            put_at(s, room, ALICE, msg("new"), day(1));
        }
        put_at(
            s,
            "#short",
            ALICE,
            EventKind::Set(RoomSetting::Retention(days(7))),
            day(1),
        );
        put_at(
            s,
            "#general",
            ALICE,
            EventKind::Set(RoomSetting::Retention(days(60))),
            day(1),
        );
    };
    // The server keeps 10 days: #short keeps 7, #general 10.
    let h = Harness::with(with_retention("10"), prepare);
    assert_eq!(h.hub.expire_now().await.unwrap(), 3);
    assert_eq!(stored(&h, "#general").len(), 3);
    assert_eq!(stored(&h, "#short").len(), 2);

    // Forever: only the room's own period applies.
    let h = Harness::with(with_retention("forever"), prepare);
    assert_eq!(h.hub.expire_now().await.unwrap(), 2);
    assert_eq!(stored(&h, "#general").len(), 4);
    assert_eq!(stored(&h, "#short").len(), 2);
}

#[tokio::test]
async fn nothing_expires_forever() {
    let h = Harness::with(with_retention("forever"), |s| {
        put_at(
            s,
            "#general",
            ALICE,
            msg("old"),
            Timestamp::from_unix_millis(0).unwrap(),
        );
    });
    assert_eq!(h.hub.expire_now().await.unwrap(), 0);
    assert_eq!(stored(&h, "#general").len(), 1);
}

#[tokio::test]
async fn a_shortened_period_applies_at_the_next_run() {
    let h = Harness::with(with_retention("30"), |s| {
        put(s, "#general", ALICE, msg("hi"));
    });
    h.clock.advance(DAY * 2);
    assert_eq!(h.hub.expire_now().await.unwrap(), 0);
    // As ADMIN SET retention 1 (10.6) would.
    let one = risala_proto::types::ServerRetention::Days(std::num::NonZeroU32::new(1).unwrap());
    h.hub.inner.settings.write().unwrap().retention = one;
    assert_eq!(h.hub.expire_now().await.unwrap(), 1);

    // And SET of a room's retention, under the room's lock (6.2).
    let h = Harness::with(with_retention("30"), |s| {
        put(s, "#general", ALICE, msg("hi"));
    });
    h.clock.advance(DAY * 2);
    let entry = h
        .hub
        .inner
        .room_entry(&"#general".parse().unwrap())
        .unwrap();
    let mut st = entry.lock().await;
    st.room_info_mut().unwrap().settings.retention =
        RoomRetention::Days(std::num::NonZeroU32::new(1).unwrap());
    assert_eq!(h.hub.inner.expire_conv(&st).await.unwrap(), 1);
}

#[tokio::test]
async fn expiry_comes_in_batches() {
    let h = Harness::with(with_retention("1"), |s| {
        s.set_durable(false).unwrap();
        for n in 0..1200 {
            put(s, "#general", ALICE, msg(&n.to_string()));
        }
        put_at(
            s,
            "#general",
            ALICE,
            msg("new"),
            start().checked_add(DAY * 2).unwrap(),
        );
    });
    h.clock.advance(DAY + Duration::from_millis(1));
    assert_eq!(h.hub.expire_now().await.unwrap(), 1200);
    assert_eq!(stored(&h, "#general"), [format!("1201 {ALICE} MSG")]);
}

// ---------------------------------------------------------------------------
// ADMIN PURGE (10.4)

#[tokio::test]
async fn purge_is_for_operators() {
    let mut h = Harness::with(with_operator(), |_| {});
    let mut alice = h.signed_in_as(ALICE);
    let mut sam = h.guest("sam").await;
    h.send(&alice, "admin purge ~spam").await;
    h.send(&sam, "admin purge ~spam").await;
    assert_eq!(alice.lines(), ["ERR forbidden operators only"]);
    assert_eq!(sam.lines(), ["ERR forbidden not for guests"]);
}

#[tokio::test]
async fn purge_deletes_everything_sent_under_a_name() {
    let mut c = with_operator();
    c.rooms.push("#other".into());
    let mut h = Harness::with(c, |s| {
        put(s, "#general", "~spam", msg("buy")); // 1
        put(
            s,
            "#general",
            "~spam",
            related(Relation::Edit(seq(1)), "buy now"),
        ); // 2
        put(s, "#general", ALICE, msg("no")); // 3
        put(
            s,
            "#general",
            "~spam",
            related(Relation::React(seq(3)), "😈"),
        ); // 4
        put(s, "#general", "~spam", msg("gone")); // 5
        put(s, "#general", "~spam", EventKind::Delete { target: seq(5) }); // 6
        put(s, "#other", "~spam", msg("buy")); // 1
        put(s, "#other", "~spam", EventKind::Part { reason: "x".into() }); // 2
    });
    let (mut sam, _) = h.joined("sam", "#general").await; // 7
    let mut op = h.signed_in_as(OP);
    sam.lines();
    h.send(&op, "@ref=p admin purge ~spam").await;
    assert_eq!(op.lines(), ["@ref=p OK deleted=3"]);
    // The edit went with its message.
    assert_eq!(
        sam.lines(),
        [
            format!("@seq=8;t={T};from={OP} DELETE #general 1"),
            format!("@seq=9;t={T};from={OP} DELETE #general 4"),
        ]
    );
    assert_eq!(
        stored(&h, "#general")[..5],
        [
            "1 ~spam MSG deleted",
            "2 ~spam MSG deleted",
            &format!("3 {ALICE} MSG"),
            "4 ~spam MSG deleted",
            "5 ~spam MSG deleted",
        ]
    );
    assert_eq!(
        stored(&h, "#other"),
        [
            "1 ~spam MSG deleted".to_owned(),
            "2 ~spam PART".to_owned(),
            format!("3 {OP} DELETE")
        ]
    );
    // Nothing left.
    h.send(&op, "admin purge ~spam").await;
    h.send(&op, "admin purge ~nobody").await;
    assert_eq!(op.lines(), ["OK deleted=0", "OK deleted=0"]);
}

#[tokio::test]
async fn purge_with_hours_deletes_only_the_last_ones() {
    let mut h = Harness::with(with_operator(), |s| {
        let hours = |n: u64| start().checked_sub(Duration::from_secs(n * 3600)).unwrap();
        put_at(s, "#general", BOB, msg("old"), hours(3));
        put_at(s, "#general", BOB, msg("recent"), hours(2));
        put_at(s, "#general", BOB, msg("new"), hours(0));
    });
    let mut op = h.signed_in_as(OP);
    h.send(&op, "admin purge bob@example.net hours=2").await;
    assert_eq!(op.lines(), ["OK deleted=2"]);
    assert_eq!(
        stored(&h, "#general")[..3],
        [
            format!("1 {BOB} MSG"),
            format!("2 {BOB} MSG deleted"),
            format!("3 {BOB} MSG deleted"),
        ]
    );
}

#[tokio::test]
async fn purge_stops_at_what_was_there() {
    let h = Harness::with(config(), |s| {
        s.set_durable(false).unwrap();
        for n in 0..1100 {
            put(s, "#general", "~spam", msg(&n.to_string()));
        }
    });
    let spam = "~spam".parse().unwrap();
    let op = OP.parse().unwrap();
    assert_eq!(h.hub.inner.purge(&spam, &op, None).await.unwrap(), 1100);
    let head = h
        .store
        .room(&"#general".parse().unwrap())
        .unwrap()
        .unwrap()
        .head;
    assert_eq!(head, Some(seq(2200)));
    // The store deletes no message past `upto`.
    let query = PurgeQuery {
        author: spam,
        since: None,
        upto: seq(1),
        by: op,
        now: start(),
        max: 10,
    };
    assert!(
        h.store
            .purge(key(&h, "#general"), &query)
            .unwrap()
            .is_empty()
    );
}

// ---------------------------------------------------------------------------
// UNREGISTER purge=yes (4.8)

#[tokio::test]
async fn unregister_with_purge_deletes_every_message() {
    let mut h = Harness::with(config(), |s| {
        put(s, "#general", ALICE, msg("before")); // 1
    });
    let mut alice = member(&mut h, ALICE, "#general").await; // 2
    let (mut sam, _) = h.joined("sam", "#general").await; // 3
    h.send(&alice, "msg #general bye").await; // 4
    h.send(&sam, "@reply=4 msg #general bye!").await; // 5
    alice.lines();
    sam.lines();
    h.send(&alice, "unregister alice@example.org purge=yes")
        .await;
    assert_eq!(
        alice.lines(),
        [
            format!("@seq=6;t={T};from={ALICE} PART #general"),
            "OK".into(),
            "<close> BYE identity deleted".into(),
        ]
    );
    assert_eq!(
        sam.lines(),
        [
            format!("@seq=6;t={T};from={ALICE} PART #general"),
            format!("@seq=7;t={T};from={ALICE} DELETE #general 1"),
            format!("@seq=8;t={T};from={ALICE} DELETE #general 4"),
        ]
    );
    // The reply stays.
    assert_eq!(stored(&h, "#general")[4], "5 ~sam MSG");
}

// ---------------------------------------------------------------------------
// The store

#[test]
fn the_store_finds_reactions_and_authored_rooms() {
    let s = SqliteStore::open_in_memory().unwrap();
    for room in ["#a", "#b", "#c"] {
        s.ensure_room(&room.parse().unwrap(), start()).unwrap();
    }
    put(&s, "#a", "~sam", msg("hi")); // 1
    put(&s, "#a", "~sam", related(Relation::React(seq(1)), "👍")); // 2
    put(&s, "#b", "~sam", msg("hi")); // 1
    put(&s, "#b", "~sam", EventKind::Delete { target: seq(1) }); // 2
    put(&s, "#c", BOB, msg("hi"));
    let key = |room: &str| s.room(&room.parse().unwrap()).unwrap().unwrap().key;
    let sam = "~sam".parse().unwrap();
    let rooms: Vec<String> = s
        .authored_rooms(&sam, None)
        .unwrap()
        .into_iter()
        .map(|(k, room)| {
            assert_eq!(k, key(room.as_str()));
            room.to_string()
        })
        .collect();
    assert_eq!(rooms, ["#a"]);
    let later = start().checked_add(Duration::from_millis(1)).unwrap();
    assert!(s.authored_rooms(&sam, Some(later)).unwrap().is_empty());

    let a = key("#a");
    assert_eq!(
        s.reaction(a, &sam, seq(1), "👍", None).unwrap(),
        Some(seq(2))
    );
    assert_eq!(s.reaction(a, &sam, seq(1), "👎", None).unwrap(), None);
    assert_eq!(
        s.reaction(a, &sam, seq(1), "👍", Some(later)).unwrap(),
        None
    );
    let bob = BOB.parse().unwrap();
    assert_eq!(s.reaction(a, &bob, seq(1), "👍", None).unwrap(), None);

    let all = RelatedQuery {
        first: seq(1),
        last: seq(1),
        after: 0,
        limit: 10,
    };
    assert_eq!(s.related(a, all).unwrap().events.len(), 1);
    assert_eq!(s.related(key("#b"), all).unwrap().events.len(), 0);
}

#[tokio::test]
async fn shortening_retention_expires_stored_events_at_once() {
    let day = |n: u32| start().checked_sub(DAY * n).unwrap();
    let mut c = with_retention("30");
    c.operators = vec![OP.into()];
    let mut h = Harness::with(c, |s| {
        for room in ["#general", "#short"] {
            put_at(s, room, ALICE, msg("old"), day(20));
            put_at(s, room, ALICE, msg("new"), day(1));
        }
        put(
            s,
            "#short",
            ALICE,
            EventKind::Role {
                uid: ALICE.parse().unwrap(),
                role: Role::Owner,
            },
        );
    });
    // SET of a room's retention (6.2): only that room.
    let mut alice = h.signed_in_as(ALICE);
    alice.lines();
    h.send(&alice, "set #short retention 7").await;
    assert_eq!(alice.lines().last().unwrap(), "OK seq=4");
    assert_eq!(stored(&h, "#short").len(), 3);
    assert_eq!(stored(&h, "#general").len(), 2);
    // ADMIN SET of the server's (10.6): every room.
    let mut op = h.signed_in_as(OP);
    op.lines();
    h.send(&op, "admin set retention 10").await;
    assert_eq!(op.lines(), ["OK"]);
    assert_eq!(stored(&h, "#general"), [format!("2 {ALICE} MSG")]);
}
