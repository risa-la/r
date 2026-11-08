//! Transcript tests of room settings (6.2), roles (6.3) and moderation
//! (6.4), through the [`Handler`](crate::handler::Handler) trait.
//!
//! Identities sign in with [`Harness::signed_in_as`], without AUTH, which
//! the identity tests cover.

use risala_proto::types::{GuestAccess, Role, RoomSetting};

use crate::core::tests::{Client, Harness, T, config, put, set, stored, strings};
use crate::store::{EventKind, SqliteStore, Store};

const ALICE: &str = "alice@example.org";
const BOB: &str = "bob@example.org";
const CAROL: &str = "carol@example.net";
const DAVE: &str = "dave@example.net";
const ERIN: &str = "erin@example.net";
const OP: &str = "op@example.net";

/// A hub with a server retention of 30 days, `op@example.net` as an
/// operator, and these rooms, with their members stored:
///
/// - `#general`: alice (owner), bob (mod) and carol; erin is a mod who
///   has left. Its next seq is 9.
/// - `#private` (not public): alice (owner). Its next seq is 4.
///
/// Dave is in no room.
fn harness() -> Harness {
    harness_with(|_| {})
}

/// [`harness`], after `prepare` has had a go at the store.
fn harness_with(prepare: impl FnOnce(&SqliteStore)) -> Harness {
    let mut c = config();
    c.rooms = strings(&["#general", "#private"]);
    c.operators = vec![OP.into()];
    c.server.retention = "30".into();
    Harness::with(c, |store| {
        let role = |room, who: &str, role| {
            let uid = who.parse().unwrap();
            put(store, room, ALICE, EventKind::Role { uid, role });
        };
        for who in [ALICE, BOB, CAROL] {
            put(store, "#general", who, EventKind::Join);
        }
        role("#general", ALICE, Role::Owner);
        role("#general", BOB, Role::Mod);
        put(store, "#general", ERIN, EventKind::Join);
        role("#general", ERIN, Role::Mod);
        put(
            store,
            "#general",
            ERIN,
            EventKind::Part {
                reason: String::new(),
            },
        );
        set(store, "#private", RoomSetting::Public(false));
        put(store, "#private", ALICE, EventKind::Join);
        role("#private", ALICE, Role::Owner);
        prepare(store);
    })
}

/// An event line as sent live.
fn ev(seq: u64, from: &str, rest: &str) -> String {
    format!("@seq={seq};t={T};from={from} {rest}")
}

fn none() -> Vec<String> {
    Vec::new()
}

/// Signs in each of `uids`, and reads what they got so far.
fn sign_in<const N: usize>(h: &mut Harness, uids: [&str; N]) -> [Client; N] {
    uids.map(|uid| {
        let mut c = h.signed_in_as(uid);
        c.lines();
        c
    })
}

/// The last line `c` got after sending `line`.
async fn last(h: &Harness, c: &mut Client, line: &str) -> String {
    h.send(c, line).await;
    c.lines().pop().unwrap()
}

// ---------------------------------------------------------------------------
// SET (6.2)

#[tokio::test]
async fn set_topic_reaches_everyone_and_shows_in_info() {
    let mut h = harness();
    let [mut alice, mut bob, mut carol] = sign_in(&mut h, [ALICE, BOB, CAROL]);
    h.send(&bob, "set #general topic Welcome,  all  ").await;
    // A topic keeps its spaces.
    let line = ev(9, BOB, "SET #general topic Welcome,  all  ");
    assert_eq!(bob.lines(), [line.clone(), "OK seq=9".into()]);
    assert_eq!(alice.lines(), std::slice::from_ref(&line));
    assert_eq!(carol.lines(), [line]);
    h.send(&carol, "info #general").await;
    assert_eq!(carol.lines()[0], "SET #general topic Welcome,  all  ");
    // An empty topic clears it.
    h.send(&alice, "set #general topic").await;
    assert_eq!(
        alice.lines(),
        [ev(10, ALICE, "SET #general topic"), "OK seq=10".into()]
    );
}

#[tokio::test]
async fn keyword_and_number_values_ignore_trailing_spaces() {
    let mut h = harness();
    let [mut alice] = sign_in(&mut h, [ALICE]);
    h.send(&alice, "set #general public no  ").await;
    h.send(&alice, "set #general retention 7 ").await;
    assert_eq!(
        alice.lines(),
        [
            ev(9, ALICE, "SET #general public no"),
            "OK seq=9".into(),
            ev(10, ALICE, "SET #general retention 7"),
            "OK seq=10".into(),
        ]
    );
    let room = h.store.room(&"#general".parse().unwrap()).unwrap().unwrap();
    assert!(!room.settings.public);
    assert_eq!(room.settings.retention.to_string(), "7");
}

#[tokio::test]
async fn who_may_set_what() {
    let mut h = harness();
    let [mut bob, mut carol, mut erin, mut op] = sign_in(&mut h, [BOB, CAROL, ERIN, OP]);
    // Members may set nothing.
    for line in [
        "set #general topic hi",
        "set #general public no",
        "set #general guests read",
        "set #general retention 1",
    ] {
        assert!(
            last(&h, &mut carol, line)
                .await
                .starts_with("ERR forbidden ")
        );
    }
    // Moderators may set the topic only, even after leaving (6.3).
    assert_eq!(
        last(&h, &mut bob, "set #general topic hi").await,
        "OK seq=9"
    );
    assert_eq!(
        last(&h, &mut erin, "set #general topic ho").await,
        "OK seq=10"
    );
    for line in [
        "set #general public no",
        "set #general guests read",
        "set #general retention 1",
    ] {
        assert!(last(&h, &mut bob, line).await.starts_with("ERR forbidden "));
    }
    // Operators have owner rights in every room, without being members.
    assert_eq!(
        last(&h, &mut op, "set #general guests read").await,
        "OK seq=11"
    );
    assert_eq!(last(&h, &mut op, "set #private topic x").await, "OK seq=4");
}

#[tokio::test]
async fn keys_nobody_may_set() {
    let mut h = harness();
    let [mut alice, mut op, mut dave] = sign_in(&mut h, [ALICE, OP, DAVE]);
    for c in [&mut alice, &mut op] {
        h.send(c, "set #general e2ee yes").await;
        h.send(c, "set #general e2ee no").await;
        h.send(c, "set #general history joined").await;
        h.send(c, "set #general colour blue").await;
        let lines = c.lines();
        assert_eq!(lines.len(), 4, "{lines:?}");
        assert!(lines[0].starts_with("ERR forbidden "));
        assert!(lines[1].starts_with("ERR forbidden "));
        assert!(lines[2].starts_with("ERR forbidden "));
        assert!(lines[3].starts_with("ERR not-supported "));
    }
    // A private room you cannot see does not exist, whatever the key.
    for line in ["set #private topic x", "set #private colour blue"] {
        assert_eq!(
            last(&h, &mut dave, line).await,
            "ERR not-found no such room"
        );
    }
    assert_eq!(stored(&h, "#general").len(), 8);
}

#[tokio::test]
async fn retention_is_at_most_the_servers() {
    let mut h = harness();
    let [mut alice] = sign_in(&mut h, [ALICE]);
    assert!(
        last(&h, &mut alice, "set #general retention 31")
            .await
            .starts_with("ERR forbidden ")
    );
    assert_eq!(
        last(&h, &mut alice, "set #general retention 30").await,
        "OK seq=9"
    );
    assert_eq!(
        last(&h, &mut alice, "set #general retention server").await,
        "OK seq=10"
    );
}

#[tokio::test]
async fn retention_is_not_limited_when_the_server_keeps_everything() {
    let mut c = config();
    c.server.retention = "forever".into();
    let mut h = Harness::with(c, |store| {
        put(store, "#general", ALICE, EventKind::Join);
        put(
            store,
            "#general",
            ALICE,
            EventKind::Role {
                uid: ALICE.parse().unwrap(),
                role: Role::Owner,
            },
        );
    });
    let [mut alice] = sign_in(&mut h, [ALICE]);
    assert_eq!(
        last(&h, &mut alice, "set #general retention 36500").await,
        "OK seq=3"
    );
}

#[tokio::test]
async fn guests_read_stops_guests_sending() {
    let mut h = harness();
    let [mut alice] = sign_in(&mut h, [ALICE]);
    let (mut sam, _) = h.joined("sam", "#general").await;
    alice.lines();
    h.send(&alice, "set #general guests read").await;
    let set = ev(10, ALICE, "SET #general guests read");
    assert_eq!(alice.lines(), [set.clone(), "OK seq=10".into()]);
    assert_eq!(sam.lines(), [set]);
    h.send(&sam, "msg #general hi").await;
    h.send(&sam, "typing #general").await;
    assert_eq!(
        sam.lines(),
        [
            "ERR forbidden guests may not send here",
            "ERR forbidden guests may not send here"
        ]
    );
    // They stay, and still read.
    h.send(&alice, "msg #general still there?").await;
    assert_eq!(sam.lines(), [ev(11, ALICE, "MSG #general still there?")]);
}

#[tokio::test]
async fn guests_none_removes_guests_with_a_part_each() {
    let mut c = config();
    c.rooms = strings(&["#general", "#other"]);
    let mut h = Harness::with(c, |store| {
        put(store, "#general", ALICE, EventKind::Join);
        put(
            store,
            "#general",
            ALICE,
            EventKind::Role {
                uid: ALICE.parse().unwrap(),
                role: Role::Owner,
            },
        );
    });
    let [mut alice] = sign_in(&mut h, [ALICE]);
    let (mut sam, _) = h.joined("sam", "#general").await;
    let (mut kim, _) = h.joined("kim", "#general").await;
    h.send(&sam, "join #other").await;
    alice.lines();
    sam.lines();
    kim.lines();
    h.send(&alice, "set #general guests none").await;
    let set = ev(5, ALICE, "SET #general guests none");
    let parts = [
        ev(6, "~kim", "PART #general"),
        ev(7, "~sam", "PART #general"),
    ];
    assert_eq!(
        alice.lines(),
        [
            set.clone(),
            parts[0].clone(),
            parts[1].clone(),
            "OK seq=5".into()
        ]
    );
    // Each guest gets the SET, then the PARTs until its own.
    assert_eq!(
        sam.lines(),
        [set.clone(), parts[0].clone(), parts[1].clone()]
    );
    assert_eq!(kim.lines(), [set, parts[0].clone()]);
    assert_eq!(
        stored(&h, "#general")[4..],
        strings(&["alice@example.org SET", "~kim PART", "~sam PART"])
    );
    // Their sessions and other rooms are untouched.
    h.send(&sam, "msg #other still here").await;
    assert_eq!(sam.lines().last().unwrap(), "OK seq=2");
    h.send(&alice, "msg #general gone?").await;
    assert_eq!(sam.lines(), none());
    assert_eq!(kim.lines(), none());
    h.send(&sam, "join #general").await;
    assert_eq!(
        sam.lines(),
        ["ERR forbidden guests may not enter this room"]
    );
}

// ---------------------------------------------------------------------------
// ROLE and ROLES (6.3)

#[tokio::test]
async fn role_reaches_everyone_and_changes_rights() {
    let mut h = harness();
    let [mut alice, mut bob, mut carol] = sign_in(&mut h, [ALICE, BOB, CAROL]);
    h.send(&alice, "role #general carol@example.net mod").await;
    let line = ev(9, ALICE, "ROLE #general carol@example.net mod");
    assert_eq!(alice.lines(), [line.clone(), "OK seq=9".into()]);
    assert_eq!(bob.lines(), std::slice::from_ref(&line));
    assert_eq!(carol.lines(), [line]);
    assert_eq!(
        last(&h, &mut carol, "set #general topic mine").await,
        "OK seq=10"
    );
    // Back to member.
    h.send(&alice, "role #general carol@example.net member")
        .await;
    assert!(
        last(&h, &mut carol, "set #general topic again")
            .await
            .starts_with("ERR forbidden ")
    );
    bob.lines();
    h.send(&bob, "info #general").await;
    assert!(bob.lines().last().unwrap().contains(" role=mod "));
    h.send(&carol, "info #general").await;
    assert!(carol.lines().last().unwrap().contains(" role=member "));
}

#[tokio::test]
async fn role_targets_members_and_role_holders() {
    let mut h = harness();
    let [mut alice] = sign_in(&mut h, [ALICE]);
    // Dave is neither.
    assert_eq!(
        last(&h, &mut alice, "role #general dave@example.net mod").await,
        "ERR not-found not a member and holds no role here"
    );
    // Erin has left, but is a mod: making her a member takes the role.
    assert_eq!(
        last(&h, &mut alice, "role #general erin@example.net member").await,
        "OK seq=9"
    );
    assert_eq!(
        last(&h, &mut alice, "role #general erin@example.net owner").await,
        "ERR not-found not a member and holds no role here"
    );
    let mut erin = h.signed_in_as(ERIN);
    erin.lines();
    h.send(&erin, "info #general").await;
    assert!(erin.lines().last().unwrap().contains(" role=none "));
    // Guests cannot hold roles.
    let (_sam, _) = h.joined("sam", "#general").await;
    alice.lines();
    assert_eq!(
        last(&h, &mut alice, "role #general ~sam mod").await,
        "ERR forbidden guests cannot hold roles"
    );
}

#[tokio::test]
async fn the_only_owner_cannot_change_their_own_role() {
    let mut h = harness();
    let [mut alice, mut bob] = sign_in(&mut h, [ALICE, BOB]);
    for role in ["mod", "member"] {
        assert_eq!(
            last(
                &h,
                &mut alice,
                &format!("role #general alice@example.org {role}")
            )
            .await,
            "ERR last-owner you are the only owner"
        );
    }
    // Setting it to owner again changes nothing, and is allowed.
    assert_eq!(
        last(&h, &mut alice, "role #general alice@example.org owner").await,
        "OK"
    );
    // With a second owner, either may step down.
    h.send(&alice, "role #general bob@example.org owner").await;
    alice.lines();
    assert_eq!(
        last(&h, &mut alice, "role #general alice@example.org mod").await,
        "OK seq=10"
    );
    bob.lines();
    assert_eq!(
        last(&h, &mut bob, "role #general bob@example.org member").await,
        "ERR last-owner you are the only owner"
    );
}

#[tokio::test]
async fn an_operator_may_take_the_only_owners_role() {
    let mut h = harness();
    let [mut op] = sign_in(&mut h, [OP]);
    assert_eq!(
        last(&h, &mut op, "role #general alice@example.org member").await,
        "OK seq=9"
    );
    h.send(&op, "roles #general").await;
    assert_eq!(
        op.lines(),
        [
            "ROLE #general bob@example.org mod",
            "ROLE #general erin@example.net mod",
            "OK"
        ]
    );
}

#[tokio::test]
async fn roles_lists_owners_and_mods_members_or_not() {
    let mut h = harness();
    let [mut carol, mut dave] = sign_in(&mut h, [CAROL, DAVE]);
    let roles = [
        "ROLE #general alice@example.org owner",
        "ROLE #general bob@example.org mod",
        "ROLE #general erin@example.net mod",
        "OK",
    ];
    h.send(&carol, "@ref=r roles #general").await;
    assert_eq!(carol.lines(), roles.map(|l| format!("@ref=r {l}")));
    // Anyone who may read the room: here, a public one.
    h.send(&dave, "roles #general").await;
    assert_eq!(dave.lines(), roles);
    let (mut sam, _) = h.joined("sam", "#general").await;
    h.send(&sam, "roles #general").await;
    assert_eq!(sam.lines(), roles);
    // A private room you cannot see does not exist.
    h.send(&dave, "roles #private").await;
    assert_eq!(dave.lines(), ["ERR not-found no such room"]);
    h.send(&sam, "roles #private").await;
    assert_eq!(sam.lines(), ["ERR not-found no such room"]);
}

// ---------------------------------------------------------------------------
// INVITE (6.4)

#[tokio::test]
async fn invite_reaches_the_invitee_and_lets_them_join() {
    let mut h = harness();
    let [mut alice, mut dave] = sign_in(&mut h, [ALICE, DAVE]);
    let mut dave2 = h.signed_in_as(DAVE);
    dave2.lines();
    h.send(&dave, "info #private").await;
    assert_eq!(dave.lines(), ["ERR not-found no such room"]);
    h.send(&alice, "invite #private dave@example.net").await;
    let line = ev(4, ALICE, "INVITE #private dave@example.net");
    assert_eq!(alice.lines(), [line.clone(), "OK seq=4".into()]);
    // Every connection of the invitee gets it, as a notification.
    assert_eq!(dave.lines(), std::slice::from_ref(&line));
    assert_eq!(dave2.lines(), [line]);
    h.send(&dave, "info #private").await;
    assert!(
        dave.lines()
            .last()
            .unwrap()
            .ends_with(" role=none joined=no")
    );
    h.send(&dave, "join #private").await;
    assert!(dave.lines().last().unwrap().starts_with("OK id="));
    // The invitation was used up: after leaving, the room is hidden again.
    h.send(&dave, "part #private").await;
    dave.lines();
    h.send(&dave, "join #private").await;
    assert_eq!(dave.lines(), ["ERR not-found no such room"]);
}

#[tokio::test]
async fn inviting_a_member_records_nothing() {
    let mut h = harness();
    let [mut bob] = sign_in(&mut h, [BOB]);
    assert_eq!(
        last(&h, &mut bob, "invite #general carol@example.net").await,
        "OK"
    );
    assert_eq!(stored(&h, "#general").len(), 8);
}

#[tokio::test]
async fn inviting_someone_invited_already_records_nothing() {
    let mut h = harness();
    let [mut alice, mut dave] = sign_in(&mut h, [ALICE, DAVE]);
    h.send(&alice, "invite #private dave@example.net").await;
    assert_eq!(alice.lines().last().unwrap(), "OK seq=4");
    dave.lines();
    let before = stored(&h, "#private").len();
    assert_eq!(
        last(&h, &mut alice, "invite #private dave@example.net").await,
        "OK"
    );
    assert_eq!(stored(&h, "#private").len(), before);
    assert_eq!(dave.lines(), Vec::<String>::new());
    // The invitation still lets them in.
    h.send(&dave, "join #private").await;
    assert!(dave.lines().last().unwrap().starts_with("OK id="));
}

#[tokio::test]
async fn who_may_invite_whom() {
    let mut h = harness();
    let [mut carol, mut op, mut dave] = sign_in(&mut h, [CAROL, OP, DAVE]);
    assert_eq!(
        last(&h, &mut carol, "invite #general dave@example.net").await,
        "ERR forbidden only moderators and owners may do that"
    );
    assert_eq!(
        last(&h, &mut op, "invite #general ~sam").await,
        "ERR forbidden guests cannot be invited"
    );
    assert_eq!(
        last(&h, &mut op, "invite #private dave@example.net").await,
        "OK seq=4"
    );
    dave.lines();
    // An invitee can see the room, but may not invite others into it.
    assert_eq!(
        last(&h, &mut dave, "invite #private carol@example.net").await,
        "ERR forbidden only moderators and owners may do that"
    );
    // Guests may not use INVITE at all (13).
    let (mut sam, _) = h.joined("sam", "#general").await;
    assert_eq!(
        last(&h, &mut sam, "invite #general dave@example.net").await,
        "ERR forbidden not for guests"
    );
}

// ---------------------------------------------------------------------------
// KICK (6.4)

#[tokio::test]
async fn kick_reaches_the_target_before_it_stops_receiving() {
    let mut h = harness();
    let [mut alice, mut bob, mut carol] = sign_in(&mut h, [ALICE, BOB, CAROL]);
    h.send(&bob, "kick #general carol@example.net be nice")
        .await;
    let line = ev(9, BOB, "KICK #general carol@example.net be nice");
    assert_eq!(bob.lines(), [line.clone(), "OK seq=9".into()]);
    assert_eq!(alice.lines(), std::slice::from_ref(&line));
    assert_eq!(carol.lines(), [line]);
    h.send(&alice, "msg #general bye carol").await;
    assert_eq!(carol.lines(), none());
    h.send(&carol, "info #general").await;
    assert!(carol.lines().last().unwrap().ends_with(" joined=no"));
    // She may join again.
    h.send(&carol, "join #general").await;
    assert!(carol.lines().last().unwrap().starts_with("OK id="));
}

#[tokio::test]
async fn kick_of_a_non_member_is_not_found_even_with_a_role() {
    let mut h = harness();
    let [mut alice] = sign_in(&mut h, [ALICE]);
    for target in [DAVE, ERIN] {
        assert_eq!(
            last(&h, &mut alice, &format!("kick #general {target}")).await,
            "ERR not-found not a member"
        );
    }
}

#[tokio::test]
async fn kick_takes_the_role_away() {
    let mut h = harness();
    let [mut alice, mut bob] = sign_in(&mut h, [ALICE, BOB]);
    assert_eq!(
        last(&h, &mut alice, "kick #general bob@example.org").await,
        "OK seq=9"
    );
    bob.lines();
    h.send(&bob, "join #general").await;
    bob.lines();
    h.send(&bob, "info #general").await;
    assert!(bob.lines().last().unwrap().contains(" role=member "));
}

#[tokio::test]
async fn moderators_kick_only_plain_members() {
    let mut h = harness_with(|store| {
        let uid = DAVE.parse().unwrap();
        put(store, "#general", DAVE, EventKind::Join);
        put(
            store,
            "#general",
            ALICE,
            EventKind::Role {
                uid,
                role: Role::Mod,
            },
        );
        put(store, "#general", OP, EventKind::Join);
    });
    let [mut alice, mut bob, mut op] = sign_in(&mut h, [ALICE, BOB, OP]);
    for target in [ALICE, DAVE, OP] {
        assert_eq!(
            last(&h, &mut bob, &format!("kick #general {target}")).await,
            "ERR forbidden moderators may act only on plain members"
        );
    }
    // A moderator cannot kick themselves either: they are not a plain
    // member.
    assert_eq!(
        last(&h, &mut bob, "kick #general bob@example.org").await,
        "ERR forbidden moderators may act only on plain members"
    );
    // Owners and operators act on anyone, owners included.
    assert_eq!(
        last(&h, &mut alice, "kick #general dave@example.net").await,
        "OK seq=12"
    );
    assert_eq!(
        last(&h, &mut op, "kick #general alice@example.org").await,
        "OK seq=13"
    );
}

// ---------------------------------------------------------------------------
// BAN, UNBAN and BANS (6.4)

#[tokio::test]
async fn ban_removes_a_member_and_keeps_them_out() {
    let mut h = harness();
    let [mut alice, mut bob, mut carol] = sign_in(&mut h, [ALICE, BOB, CAROL]);
    h.send(&bob, "ban #general carol@example.net spam").await;
    let line = ev(9, BOB, "BAN #general carol@example.net spam");
    assert_eq!(bob.lines(), [line.clone(), "OK seq=9".into()]);
    assert_eq!(alice.lines(), std::slice::from_ref(&line));
    assert_eq!(carol.lines(), [line]);
    h.send(&alice, "msg #general gone").await;
    assert_eq!(carol.lines(), none());
    h.send(&carol, "join #general").await;
    assert_eq!(
        carol.lines(),
        ["ERR forbidden you are banned from this room"]
    );
    h.send(&carol, "history #general").await;
    assert_eq!(
        carol.lines(),
        ["ERR forbidden you are banned from this room"]
    );
    // UNBAN lets her back.
    assert_eq!(
        last(&h, &mut bob, "unban #general carol@example.net").await,
        "OK seq=11"
    );
    h.send(&carol, "join #general").await;
    assert!(carol.lines().last().unwrap().starts_with("OK id="));
}

#[tokio::test]
async fn ban_of_a_non_member_takes_role_and_invitation() {
    let mut h = harness();
    let [mut alice, mut dave, mut erin] = sign_in(&mut h, [ALICE, DAVE, ERIN]);
    h.send(&alice, "invite #private dave@example.net").await;
    alice.lines();
    dave.lines();
    // The target gets it too, as a notification.
    h.send(&alice, "ban #private dave@example.net").await;
    let line = ev(5, ALICE, "BAN #private dave@example.net");
    assert_eq!(alice.lines(), [line.clone(), "OK seq=5".into()]);
    assert_eq!(dave.lines(), [line]);
    let room = h.store.room(&"#private".parse().unwrap()).unwrap().unwrap();
    assert!(room.invites.is_empty());
    // The room is hidden again: no invitation, no role.
    h.send(&dave, "join #private").await;
    assert_eq!(dave.lines(), ["ERR not-found no such room"]);
    // Erin, a mod who left, loses her role.
    assert_eq!(
        last(&h, &mut alice, "ban #general erin@example.net").await,
        "OK seq=9"
    );
    erin.lines();
    h.send(&alice, "roles #general").await;
    assert_eq!(
        alice.lines(),
        [
            "ROLE #general alice@example.org owner",
            "ROLE #general bob@example.org mod",
            "OK"
        ]
    );
    // Unbanned, she is a plain identity and needs nothing to join.
    h.send(&alice, "unban #general erin@example.net").await;
    h.send(&erin, "join #general").await;
    h.send(&erin, "info #general").await;
    assert!(erin.lines().last().unwrap().contains(" role=member "));
}

#[tokio::test]
async fn moderators_ban_only_plain_members() {
    let mut h = harness();
    let [mut bob, mut op] = sign_in(&mut h, [BOB, OP]);
    for target in [ALICE, ERIN, OP] {
        assert_eq!(
            last(&h, &mut bob, &format!("ban #general {target}")).await,
            "ERR forbidden moderators may act only on plain members"
        );
    }
    assert_eq!(
        last(&h, &mut bob, "ban #general dave@example.net").await,
        "OK seq=9"
    );
    // Operators may ban owners. A banned operator may still join (6.3).
    assert_eq!(
        last(&h, &mut op, "ban #general alice@example.org").await,
        "OK seq=10"
    );
    let mut alice = h.signed_in_as(ALICE);
    alice.lines();
    assert_eq!(
        last(&h, &mut alice, "set #general topic x").await,
        "ERR forbidden only moderators and owners may do that"
    );
    assert_eq!(
        last(&h, &mut bob, "ban #general op@example.net").await,
        "ERR forbidden moderators may act only on plain members"
    );
    // The operator bans itself: it may join all the same.
    assert_eq!(
        last(&h, &mut op, "ban #general op@example.net").await,
        "OK seq=11"
    );
    h.send(&op, "join #general").await;
    assert!(op.lines().last().unwrap().starts_with("OK id="));
}

#[tokio::test]
async fn ban_of_a_guest_bans_its_uid() {
    let mut h = harness();
    let [mut bob] = sign_in(&mut h, [BOB]);
    let mut sam = h.guest("sam").await;
    h.send(&sam, "join #general").await;
    sam.lines();
    bob.lines();
    h.send(&bob, "ban #general ~sam").await;
    let line = ev(10, BOB, "BAN #general ~sam");
    assert_eq!(bob.lines(), [line.clone(), "OK seq=10".into()]);
    assert_eq!(sam.lines(), [line]);
    h.send(&sam, "join #general").await;
    assert_eq!(sam.lines(), ["ERR forbidden you are banned from this room"]);
    // The next guest of that name is banned too.
    h.leave(sam, "sam").await;
    let mut sam = h.guest("sam").await;
    h.send(&sam, "join #general").await;
    assert_eq!(sam.lines(), ["ERR forbidden you are banned from this room"]);
}

#[tokio::test]
async fn bans_lists_bans_with_reasons() {
    let mut h = harness();
    let [alice, mut bob, mut carol] = sign_in(&mut h, [ALICE, BOB, CAROL]);
    h.send(&bob, "ban #general dave@example.net too much spam")
        .await;
    h.send(&bob, "ban #general ~sam").await;
    h.send(&alice, "ban #general carol@example.net").await;
    h.send(&alice, "unban #general carol@example.net").await;
    bob.lines();
    h.send(&bob, "@ref=b bans #general").await;
    assert_eq!(
        bob.lines(),
        [
            "@ref=b BAN #general dave@example.net too much spam",
            "@ref=b BAN #general ~sam",
            "@ref=b OK",
        ]
    );
    // Members may not see them; a private room you cannot see does not
    // exist.
    carol.lines();
    h.send(&carol, "join #general").await;
    carol.lines();
    assert_eq!(
        last(&h, &mut carol, "bans #general").await,
        "ERR forbidden only moderators and owners may do that"
    );
    assert_eq!(
        last(&h, &mut carol, "bans #private").await,
        "ERR not-found no such room"
    );
    // An operator may.
    let [mut op] = sign_in(&mut h, [OP]);
    h.send(&op, "bans #private").await;
    assert_eq!(op.lines(), ["OK"]);
}

#[tokio::test]
async fn unban_of_someone_not_banned_is_not_found() {
    let mut h = harness();
    let [mut bob, mut carol] = sign_in(&mut h, [BOB, CAROL]);
    assert_eq!(
        last(&h, &mut bob, "unban #general dave@example.net").await,
        "ERR not-found not banned"
    );
    h.send(&bob, "ban #general dave@example.net").await;
    assert_eq!(
        last(&h, &mut carol, "unban #general dave@example.net").await,
        "ERR forbidden only moderators and owners may do that"
    );
}

// ---------------------------------------------------------------------------
// The table of 6.3

/// Who sends the command in the permission table's tests.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Who {
    Member,
    Mod,
    Owner,
    Operator,
}

/// Every row of the table in 6.3 that this area implements, for each kind
/// of actor: whether the action is allowed. A fresh hub for each try, so
/// that the rows do not affect each other. Sending messages and deleting
/// them are DELETE's (5.4), and `history` exists only in encrypted rooms.
#[tokio::test]
async fn the_permission_table_of_6_3() {
    let rows: [(&str, [bool; 4]); 9] = [
        ("set #general topic t", [false, true, true, true]),
        (
            "invite #general dave@example.net",
            [false, true, true, true],
        ),
        ("kick #general carol@example.net", [false, true, true, true]),
        ("ban #general carol@example.net", [false, true, true, true]),
        ("bans #general", [false, true, true, true]),
        ("set #general public no", [false, false, true, true]),
        ("set #general guests read", [false, false, true, true]),
        ("set #general retention 3", [false, false, true, true]),
        (
            "role #general carol@example.net mod",
            [false, false, true, true],
        ),
    ];
    for (line, allowed) in rows {
        for (who, allowed) in [Who::Member, Who::Mod, Who::Owner, Who::Operator]
            .into_iter()
            .zip(allowed)
        {
            let mut h = harness_with(|store| {
                // Dave is the member who acts; carol is the target.
                put(store, "#general", DAVE, EventKind::Join);
            });
            let uid = match who {
                Who::Member => DAVE,
                Who::Mod => BOB,
                Who::Owner => ALICE,
                Who::Operator => OP,
            };
            let [mut c] = sign_in(&mut h, [uid]);
            let got = last(&h, &mut c, line).await;
            assert_eq!(
                got.starts_with("OK"),
                allowed,
                "{who:?} sent {line:?} and got {got:?}"
            );
            if !allowed {
                assert!(got.starts_with("ERR forbidden "), "{who:?}: {got:?}");
            }
        }
    }
    // UNBAN, with a ban to lift.
    for (who, uid, allowed) in [
        (Who::Member, CAROL, false),
        (Who::Mod, BOB, true),
        (Who::Owner, ALICE, true),
        (Who::Operator, OP, true),
    ] {
        let mut h = harness_with(|store| {
            let uid = DAVE.parse().unwrap();
            put(
                store,
                "#general",
                ALICE,
                EventKind::Ban {
                    uid,
                    reason: String::new(),
                },
            );
        });
        let [mut c] = sign_in(&mut h, [uid]);
        let got = last(&h, &mut c, "unban #general dave@example.net").await;
        assert_eq!(got.starts_with("OK"), allowed, "{who:?}: {got:?}");
    }
}

// ---------------------------------------------------------------------------
// Restarts and failures

#[tokio::test]
async fn changes_survive_a_restart() {
    let mut h = harness();
    let [mut alice] = sign_in(&mut h, [ALICE]);
    for line in [
        "set #general guests read",
        "role #general carol@example.net mod",
        "ban #general dave@example.net",
        "invite #private bob@example.org",
    ] {
        assert!(last(&h, &mut alice, line).await.starts_with("OK seq="));
    }
    let mut c = config();
    c.rooms = strings(&["#general", "#private"]);
    let mut h = Harness::on(c, h.store.clone(), crate::core::tests::timers());
    let [mut bob, mut carol, mut dave] = sign_in(&mut h, [BOB, CAROL, DAVE]);
    h.send(&carol, "info #general").await;
    assert!(carol.lines().last().unwrap().contains(" role=mod "));
    assert_eq!(
        last(&h, &mut dave, "join #general").await,
        "ERR forbidden you are banned from this room"
    );
    h.send(&bob, "join #private").await;
    assert!(bob.lines().last().unwrap().starts_with("OK id="));
    let (mut sam, _) = h.joined("sam", "#general").await;
    assert_eq!(
        last(&h, &mut sam, "msg #general hi").await,
        "ERR forbidden guests may not send here"
    );
}

#[tokio::test]
async fn a_failed_store_changes_nothing() {
    use std::sync::atomic::Ordering;

    let flaky = std::sync::Arc::new(crate::core::tests::Flaky::new());
    let general = "#general".parse().unwrap();
    flaky
        .inner
        .ensure_room(&general, crate::core::tests::start())
        .unwrap();
    for who in [ALICE, CAROL] {
        put(&flaky.inner, "#general", who, EventKind::Join);
    }
    put(
        &flaky.inner,
        "#general",
        ALICE,
        EventKind::Role {
            uid: ALICE.parse().unwrap(),
            role: Role::Owner,
        },
    );
    let mut h = Harness::on(config(), flaky.clone(), crate::core::tests::timers());
    let [mut alice, mut carol] = sign_in(&mut h, [ALICE, CAROL]);
    flaky.broken.store(true, Ordering::SeqCst);
    for line in [
        "set #general guests none",
        "role #general carol@example.net mod",
        "kick #general carol@example.net",
        "ban #general carol@example.net",
        "invite #general dave@example.net",
    ] {
        assert_eq!(
            last(&h, &mut alice, line).await,
            "ERR internal internal error"
        );
    }
    assert_eq!(carol.lines(), none());
    flaky.broken.store(false, Ordering::SeqCst);
    // Carol is still a plain member, not banned, and dave not invited.
    h.send(&alice, "roles #general").await;
    assert_eq!(
        alice.lines(),
        ["ROLE #general alice@example.org owner", "OK"]
    );
    h.send(&alice, "bans #general").await;
    assert_eq!(alice.lines(), ["OK"]);
    h.send(&alice, "msg #general still here?").await;
    assert_eq!(carol.lines(), [ev(4, ALICE, "MSG #general still here?")]);
    let room = h.store.room(&general).unwrap().unwrap();
    assert!(room.invites.is_empty());
    assert_eq!(room.settings.guests, GuestAccess::Write);
}

// ---------------------------------------------------------------------------
// Decided while building M4 (PLAN.md 5, item 31)

#[tokio::test]
async fn changes_that_change_nothing_record_nothing() {
    let mut h = harness();
    let [mut alice, mut bob] = sign_in(&mut h, [ALICE, BOB]);
    assert_eq!(
        last(&h, &mut alice, "set #general topic hello").await,
        "OK seq=9"
    );
    bob.lines();
    // The same value, a role already held, and a ban again: plain OK, and
    // no event reaches anyone.
    for cmd in [
        "set #general topic hello",
        "set #general public yes",
        "role #general bob@example.org mod",
        "role #general carol@example.net member",
    ] {
        h.send(&alice, cmd).await;
        assert_eq!(alice.lines(), ["OK"], "{cmd}");
        assert_eq!(bob.lines(), none(), "{cmd}");
    }
    assert_eq!(
        last(&h, &mut alice, "ban #general dave@example.net spam").await,
        "OK seq=10"
    );
    bob.lines();
    // BAN again only replaces the reason.
    h.send(&alice, "ban #general dave@example.net lots of spam")
        .await;
    assert_eq!(alice.lines(), ["OK"]);
    assert_eq!(bob.lines(), none());
    h.send(&alice, "bans #general").await;
    assert_eq!(
        alice.lines(),
        ["BAN #general dave@example.net lots of spam", "OK"]
    );
    // The next event takes the next seq: none was used up.
    assert_eq!(
        last(&h, &mut alice, "set #general topic bye").await,
        "OK seq=11"
    );
}

#[tokio::test]
async fn a_banned_identity_cannot_be_invited() {
    let mut h = harness();
    let [mut alice] = sign_in(&mut h, [ALICE]);
    h.send(&alice, "ban #private dave@example.net").await;
    alice.lines();
    assert_eq!(
        last(&h, &mut alice, "invite #private dave@example.net").await,
        "ERR forbidden banned; unban first"
    );
    h.send(&alice, "unban #private dave@example.net").await;
    alice.lines();
    assert_eq!(
        last(&h, &mut alice, "invite #private dave@example.net").await,
        "OK seq=6"
    );
}

#[tokio::test]
async fn the_only_owner_cannot_kick_or_ban_themselves() {
    let mut h = harness();
    let [mut alice] = sign_in(&mut h, [ALICE]);
    for cmd in [
        "kick #general alice@example.org",
        "ban #general alice@example.org",
    ] {
        assert_eq!(
            last(&h, &mut alice, cmd).await,
            "ERR last-owner you are the only owner",
            "{cmd}"
        );
    }
    // With a second owner, they may.
    h.send(&alice, "role #general bob@example.org owner").await;
    alice.lines();
    assert_eq!(
        last(&h, &mut alice, "kick #general alice@example.org").await,
        "OK seq=10"
    );
}

#[tokio::test]
async fn a_ban_reaches_its_target_only_if_they_could_see_the_room() {
    let mut h = harness();
    let [mut alice, mut dave] = sign_in(&mut h, [ALICE, DAVE]);
    // Dave has never been able to see #private: the ban is silent.
    h.send(&alice, "ban #private dave@example.net").await;
    assert_eq!(alice.lines().last().unwrap(), "OK seq=4");
    assert_eq!(dave.lines(), none());
    // #general is public, so he hears of that one.
    h.send(&alice, "ban #general dave@example.net").await;
    alice.lines();
    assert_eq!(
        dave.lines(),
        [ev(9, ALICE, "BAN #general dave@example.net")]
    );
}
