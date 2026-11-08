//! Transcript tests of reports (5.8), `ADMIN ROOMS` and `ADMIN DROP`
//! (10.4).

use std::sync::Arc;

use risala_proto::names::{Room, Seq, Uid};
use risala_proto::types::{Relation, Role, RoomSetting};

use crate::core::tests::{
    Client, Flaky, Harness, T, config, put, set, start, strings, timers, value,
};
use crate::handler::Handler as _;
use crate::store::{EventKind, SqliteStore, Store};

const ALICE: &str = "alice@example.org";
const BOB: &str = "bob@example.net";
const DAVE: &str = "dave@example.org";
const OP: &str = "op@example.net";

fn uid(s: &str) -> Uid {
    s.parse().unwrap()
}

fn seq(n: u64) -> Seq {
    Seq::new(n).unwrap()
}

fn msg(relation: Option<Relation>, text: &str) -> EventKind {
    EventKind::Msg {
        relation,
        file: None,
        text: text.into(),
    }
}

fn none() -> Vec<String> {
    Vec::new()
}

/// `#general` (from the configuration) has, as events:
///
/// 1. alice's JOIN, 2. alice made owner, 3. dave (not a member) made
///    moderator, 4. bob's JOIN, 5. and 6. messages from `~spammer`, 7. a
///    reaction from `~spammer` to 5.
///
/// `#private` is private, with alice as its owner and a message from her
/// as event 4. `#temp` is a room someone created, which is not in the
/// configuration. `op@example.net` is an operator.
fn prepare(store: &SqliteStore) {
    put(store, "#general", ALICE, EventKind::Join);
    for (who, role) in [(ALICE, Role::Owner), (DAVE, Role::Mod)] {
        put(
            store,
            "#general",
            ALICE,
            EventKind::Role {
                uid: uid(who),
                role,
            },
        );
    }
    put(store, "#general", BOB, EventKind::Join);
    put(store, "#general", "~spammer", msg(None, "cheap pills"));
    put(store, "#general", "~spammer", msg(None, "more pills"));
    put(
        store,
        "#general",
        "~spammer",
        msg(Some(Relation::React(seq(5))), "ok"),
    );

    set(store, "#private", RoomSetting::Public(false));
    put(store, "#private", ALICE, EventKind::Join);
    put(
        store,
        "#private",
        ALICE,
        EventKind::Role {
            uid: uid(ALICE),
            role: Role::Owner,
        },
    );
    put(store, "#private", ALICE, msg(None, "secret"));

    store
        .create_room(&"#temp".parse().unwrap(), &uid(BOB), start())
        .unwrap();
    put(store, "#temp", BOB, msg(None, "temporary"));
}

fn harness() -> Harness {
    let mut c = config();
    c.rooms = strings(&["#general", "#private"]);
    c.operators = strings(&[OP]);
    Harness::with(c, prepare)
}

/// The two lines a reviewer gets for report `id` of event 5 of
/// `#general`, whose id is `conv`, by `~sam` with the reason `spam`, with
/// `from` for operators.
fn report_5(id: &str, conv: &str, operator: bool) -> Vec<String> {
    let from = if operator { ";from=~sam" } else { "" };
    vec![
        format!("@report={id};id={conv};t={T}{from} REPORT #general 5 spam"),
        format!("@report={id};id={conv};seq=5;t={T};from=~spammer MSG #general cheap pills"),
    ]
}

/// The id of `#general` (5.1).
fn general_id(h: &Harness) -> String {
    h.store
        .room(&"#general".parse().unwrap())
        .unwrap()
        .unwrap()
        .id
        .to_string()
}

/// Sends `line` on `c` and returns the id in its `OK id=`.
async fn report(h: &Harness, c: &mut Client, line: &str) -> String {
    h.send(c, line).await;
    let lines = c.lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].starts_with("OK id="), "{lines:?}");
    value(&lines[0], "id")
}

// ---------------------------------------------------------------------------
// REPORT (5.8)

#[tokio::test]
async fn a_report_reaches_every_reviewer() {
    let mut h = harness();
    let mut alice = h.signed_in_as(ALICE);
    let mut dave = h.signed_in_as(DAVE);
    let mut op = h.signed_in_as(OP);
    let mut bob = h.signed_in_as(BOB);
    // A guest who can read #general, without joining it.
    let mut sam = h.guest("sam").await;

    let id = report(&h, &mut sam, "report #general 5 spam").await;
    assert_eq!(id.len(), crate::store::ID_LEN);
    // Owners and moderators, members or not, get it without the reporter;
    // operators with it. Members who are not reviewers get nothing.
    let conv = general_id(&h);
    assert_eq!(alice.lines(), report_5(&id, &conv, false));
    assert_eq!(dave.lines(), report_5(&id, &conv, false));
    assert_eq!(op.lines(), report_5(&id, &conv, true));
    assert_eq!(bob.lines(), none());

    // Again: the same id, and nobody is told again.
    h.send(&sam, "@ref=a report #general 5 again").await;
    assert_eq!(sam.lines(), [format!("@ref=a OK id={id}")]);
    for c in [&mut alice, &mut dave, &mut op] {
        assert_eq!(c.lines(), none());
    }

    // Another reporter, of a reaction, with no reason. Edits and reactions
    // are messages too.
    let other = report(&h, &mut bob, "report #general 7").await;
    assert_ne!(other, id);
    assert_eq!(
        op.lines(),
        [
            format!("@report={other};id={conv};t={T};from={BOB} REPORT #general 7"),
            format!("@report={other};id={conv};seq=7;t={T};from=~spammer;react=5 MSG #general ok"),
        ]
    );
    assert_eq!(alice.lines().len(), 2);
}

#[tokio::test]
async fn what_may_be_reported() {
    let mut h = harness();
    put_deleted(&h);
    let mut sam = h.guest("sam").await;
    let mut alice = h.signed_in_as(ALICE);
    let mut bob = h.signed_in_as(BOB);
    let mut spammer = h.guest("spammer").await;
    let enc = "g6310tyvzbFYtF+zfJzNGwhM3CbuWJ83hbt4OL35Zb4= VEVYVA== x";
    // Not a message, no such event, or a deleted one.
    for n in [1, 99, 9] {
        expect(
            &h,
            &mut sam,
            &format!("report #general {n}"),
            "ERR not-found no such message",
        )
        .await;
    }
    // Your own.
    let own = "ERR forbidden you cannot report your own message";
    expect(&h, &mut spammer, "report #general 5", own).await;
    expect(&h, &mut alice, "report #private 4", own).await;
    // A room you cannot see, or that does not exist.
    expect(
        &h,
        &mut bob,
        "report #private 3",
        "ERR not-found no such room",
    )
    .await;
    expect(
        &h,
        &mut bob,
        "report #nowhere 3",
        "ERR not-found no such room",
    )
    .await;
    // REPORTENC and direct conversations wait for M5a.
    let later = "ERR not-supported not supported yet";
    expect(&h, &mut bob, &format!("reportenc #general 5 {enc}"), later).await;
    expect(&h, &mut bob, "report alice@example.org 1", later).await;
    // Guests have no direct conversations, and cannot use REPORTENC.
    let direct = "ERR not-found no such conversation";
    expect(&h, &mut sam, "report alice@example.org 1", direct).await;
    let enc_line = format!("reportenc #general 5 {enc}");
    expect(&h, &mut sam, &enc_line, "ERR forbidden not for guests").await;
    // Event 8 may be reported.
    report(&h, &mut sam, "report #general 8").await;
}

/// A guest may report a message sent under its name before its session
/// started: another guest's (5.3).
#[tokio::test]
async fn a_guest_may_report_an_earlier_guests_message_under_its_name() {
    let mut h = harness();
    h.clock.advance(std::time::Duration::from_secs(1));
    let mut spammer = h.guest("spammer").await;
    report(&h, &mut spammer, "report #general 5").await;
    h.send(&spammer, "join #general").await;
    h.send(&spammer, "msg #general mine").await;
    spammer.lines();
    expect(
        &h,
        &mut spammer,
        "report #general 9",
        "ERR forbidden you cannot report your own message",
    )
    .await;
}

async fn expect(h: &Harness, c: &mut Client, cmd: &str, want: &str) {
    h.send(c, cmd).await;
    assert_eq!(c.lines(), [want], "{cmd}");
}

/// Event 8 of `#general` is a message from `~spammer`, and 9 another,
/// deleted by event 10.
fn put_deleted(h: &Harness) {
    let key = h
        .store
        .room(&"#general".parse().unwrap())
        .unwrap()
        .unwrap()
        .key;
    for kind in [
        msg(None, "kept"),
        msg(None, "gone"),
        EventKind::Delete { target: seq(9) },
    ] {
        h.store
            .append(
                key,
                &crate::store::NewEvent {
                    t: start(),
                    from: uid("~spammer"),
                    kind,
                    cid: None,
                },
            )
            .unwrap();
    }
}

#[tokio::test]
async fn guests_report_only_where_they_may_read() {
    let mut h = harness();
    let mut sam = h.guest("sam").await;
    // `guests none`, in the hub only: SET is another area's.
    let room: Room = "#general".parse().unwrap();
    let entry = h.hub.inner.room_entry(&room).unwrap();
    entry.lock().await.room_info_mut().unwrap().settings.guests =
        risala_proto::types::GuestAccess::None;
    h.send(&sam, "report #general 5").await;
    assert_eq!(
        sam.lines(),
        ["ERR forbidden guests may not enter this room"]
    );
}

/// A report sent again gets its id again, even once the reporter can no
/// longer read the room (5.8).
#[tokio::test]
async fn a_resent_report_gets_its_id_after_the_reporter_lost_access() {
    let mut h = harness();
    let mut sam = h.guest("sam").await;
    let id = report(&h, &mut sam, "report #general 5 spam").await;
    let room: Room = "#general".parse().unwrap();
    let entry = h.hub.inner.room_entry(&room).unwrap();
    entry.lock().await.room_info_mut().unwrap().settings.guests =
        risala_proto::types::GuestAccess::None;
    expect(
        &h,
        &mut sam,
        "report #general 5 spam",
        &format!("OK id={id}"),
    )
    .await;
    // Another message is refused.
    expect(
        &h,
        &mut sam,
        "report #general 6",
        "ERR forbidden guests may not enter this room",
    )
    .await;
}

#[tokio::test]
async fn reports_are_rate_limited() {
    let mut h = harness();
    let key = h
        .store
        .room(&"#general".parse().unwrap())
        .unwrap()
        .unwrap()
        .key;
    for n in 0..30 {
        h.store
            .append(
                key,
                &crate::store::NewEvent {
                    t: start(),
                    from: uid("~spammer"),
                    kind: msg(None, &format!("spam {n}")),
                    cid: None,
                },
            )
            .unwrap();
    }
    let mut sam = h.guest("sam").await;
    // Events 5 to 7, and the 30 just added: 33 messages.
    for n in 5..5 + 30u64 {
        report(&h, &mut sam, &format!("report #general {n}")).await;
    }
    // Repeating one is not a new report.
    report(&h, &mut sam, "report #general 5").await;
    h.send(&sam, "@ref=x report #general 36").await;
    assert_eq!(
        sam.lines(),
        ["@ref=x;retry=3600 ERR rate-limited you have made too many reports"]
    );
    // Others are not limited by it.
    let mut bob = h.signed_in_as(BOB);
    report(&h, &mut bob, "report #general 36").await;
    // An hour later, sam may report again.
    h.clock.advance(super::REPORT_WINDOW);
    report(&h, &mut sam, "report #general 36").await;
}

#[tokio::test]
async fn guests_count_reports_by_network() {
    let mut c = config();
    c.rooms = strings(&["#general", "#private"]);
    c.limits.reports_per_hour = 2;
    let mut h = Harness::with(c, prepare);
    let mut sam = h.guest_from("sam", "[2001:db8:1:2::5]:4000").await;
    report(&h, &mut sam, "report #general 5").await;
    report(&h, &mut sam, "report #general 6").await;
    // A new name in the same /64 does not get around the limit.
    h.close(sam).await;
    h.end("sam").await;
    let mut tom = h.guest_from("tom", "[2001:db8:1:2:ffff::9]:4000").await;
    h.send(&tom, "report #general 7").await;
    assert_eq!(
        tom.lines(),
        ["@retry=3600 ERR rate-limited you have made too many reports"]
    );
    // Another network has its own reports.
    let mut far = h.guest_from("far", "[2001:db8:1:3::5]:4000").await;
    report(&h, &mut far, "report #general 7").await;
    // Identities count by uid, wherever they connect from.
    let mut bob = h.signed_in_as(BOB);
    report(&h, &mut bob, "report #general 5").await;
}

// ---------------------------------------------------------------------------
// REPORTS, RESOLVE and ADMIN REPORTS (5.8)

#[tokio::test]
async fn reports_lists_a_rooms_open_reports() {
    let mut h = harness();
    let mut sam = h.guest("sam").await;
    let first = report(&h, &mut sam, "report #general 5 spam").await;
    let mut bob = h.signed_in_as(BOB);
    let second = report(&h, &mut bob, "report #general 6").await;
    let mut alice = h.signed_in_as(ALICE);
    alice.lines();
    // Tags in one list, the ref first.
    let conv = general_id(&h);
    let want = [
        format!("@ref=r;report={first};id={conv};t={T} REPORT #general 5 spam"),
        format!(
            "@ref=r;report={first};id={conv};seq=5;t={T};from=~spammer MSG #general cheap pills"
        ),
        format!("@ref=r;report={second};id={conv};t={T} REPORT #general 6"),
        format!(
            "@ref=r;report={second};id={conv};seq=6;t={T};from=~spammer MSG #general more pills"
        ),
        "@ref=r OK".to_owned(),
    ];
    h.send(&alice, "@ref=r reports #general").await;
    assert_eq!(alice.lines(), want);

    // Operators see the reporters.
    let mut op = h.signed_in_as(OP);
    h.send(&op, "reports #general").await;
    assert_eq!(
        op.lines()[0],
        format!("@report={first};id={conv};t={T};from=~sam REPORT #general 5 spam")
    );
    // A room with no open reports.
    h.send(&alice, "reports #private").await;
    assert_eq!(alice.lines(), ["OK"]);

    // Others may not.
    h.send(&bob, "reports #general").await;
    assert_eq!(
        bob.lines(),
        ["ERR forbidden only the room's owners and moderators may see its reports"]
    );
    h.send(&bob, "reports #private").await;
    assert_eq!(bob.lines(), ["ERR not-found no such room"]);
    h.send(&sam, "reports #general").await;
    assert_eq!(sam.lines(), ["ERR forbidden not for guests"]);
}

#[tokio::test]
async fn a_report_keeps_the_message_as_it_was() {
    let mut h = harness();
    let mut sam = h.guest("sam").await;
    let id = report(&h, &mut sam, "report #general 5 spam").await;
    // The message is deleted and edited away; the report keeps it.
    let key = h
        .store
        .room(&"#general".parse().unwrap())
        .unwrap()
        .unwrap()
        .key;
    h.store
        .append(
            key,
            &crate::store::NewEvent {
                t: start(),
                from: uid("~spammer"),
                kind: EventKind::Delete { target: seq(5) },
                cid: None,
            },
        )
        .unwrap();
    let mut op = h.signed_in_as(OP);
    h.send(&op, "admin reports").await;
    let mut want = report_5(&id, &general_id(&h), true);
    want.push("OK".into());
    assert_eq!(op.lines(), want);
    // And it can be reported no more.
    let mut bob = h.signed_in_as(BOB);
    h.send(&bob, "report #general 5").await;
    assert_eq!(bob.lines(), ["ERR not-found no such message"]);
    // But sam's report is found again.
    h.send(&sam, "report #general 5").await;
    assert_eq!(sam.lines(), [format!("OK id={id}")]);
}

#[tokio::test]
async fn resolving_tells_the_other_reviewers() {
    let mut h = harness();
    let mut sam = h.guest("sam").await;
    let id = report(&h, &mut sam, "report #general 5 spam").await;
    let mut alice = h.signed_in_as(ALICE);
    let mut alice2 = h.signed_in_as(ALICE);
    let mut dave = h.signed_in_as(DAVE);
    let mut op = h.signed_in_as(OP);
    let mut bob = h.signed_in_as(BOB);

    // Not a reviewer: as if there were no such report.
    h.send(&bob, &format!("resolve {id}")).await;
    assert_eq!(bob.lines(), ["ERR not-found no such report"]);
    h.send(&sam, &format!("resolve {id}")).await;
    assert_eq!(sam.lines(), ["ERR forbidden not for guests"]);

    h.send(&alice, &format!("@ref=z resolve {id}")).await;
    assert_eq!(alice.lines(), ["@ref=z OK"]);
    let resolved = [format!("RESOLVED {id}")];
    assert_eq!(alice2.lines(), resolved);
    assert_eq!(dave.lines(), resolved);
    assert_eq!(op.lines(), resolved);
    assert_eq!(bob.lines(), none());

    // It is gone.
    h.send(&op, &format!("resolve {id}")).await;
    assert_eq!(op.lines(), ["ERR not-found no such report"]);
    h.send(&op, "admin reports").await;
    assert_eq!(op.lines(), ["OK"]);
    h.send(&op, "resolve nosuchreport").await;
    assert_eq!(op.lines(), ["ERR not-found no such report"]);
    // A new report of the same message gets a new id.
    let again = report(&h, &mut sam, "report #general 5 spam").await;
    assert_ne!(again, id);
}

#[tokio::test]
async fn reports_come_in_chunks() {
    let mut c = config();
    c.rooms = strings(&["#general", "#private"]);
    c.operators = strings(&[OP]);
    // Room for 17 lines in a response: chunks of 8 reports.
    c.limits.max_page = 1;
    c.limits.max_list = 1;
    let mut h = Harness::with(c, prepare);
    let key = h
        .store
        .room(&"#general".parse().unwrap())
        .unwrap()
        .unwrap()
        .key;
    for n in 0..20 {
        h.store
            .append(
                key,
                &crate::store::NewEvent {
                    t: start(),
                    from: uid("~spammer"),
                    kind: msg(None, &format!("spam {n}")),
                    cid: None,
                },
            )
            .unwrap();
    }
    let mut sam = h.guest("sam").await;
    let mut ids = Vec::new();
    for n in 8..28 {
        ids.push(report(&h, &mut sam, &format!("report #general {n}")).await);
    }
    let mut op = h.signed_in_as(OP);
    for cmd in ["reports #general", "admin reports"] {
        h.send(&op, cmd).await;
        let lines = op.lines();
        assert_eq!(lines.len(), 41, "{cmd}");
        for (n, id) in ids.iter().enumerate() {
            assert!(
                lines[2 * n].starts_with(&format!("@report={id};")),
                "{cmd}: {}",
                lines[2 * n]
            );
        }
        assert_eq!(lines[40], "OK");
    }
}

// ---------------------------------------------------------------------------
// ADMIN ROOMS and ADMIN DROP (10.4)

#[tokio::test]
async fn admin_rooms_lists_every_room() {
    let mut h = harness();
    let mut op = h.signed_in_as(OP);
    h.send(&op, "admin rooms").await;
    assert_eq!(
        op.lines(),
        [
            "ROOM #general 2",
            "ROOM #private 1",
            "ROOM #temp 1",
            "OK more=0",
        ]
    );
    h.send(&op, "admin rooms after=#general limit=1").await;
    assert_eq!(op.lines(), ["ROOM #private 1", "OK more=1"]);
    h.send(&op, "admin rooms after=#private limit=1").await;
    assert_eq!(op.lines(), ["ROOM #temp 1", "OK more=0"]);

    let mut alice = h.signed_in_as(ALICE);
    for cmd in ["admin rooms", "admin drop #general", "admin reports"] {
        h.send(&alice, cmd).await;
        assert_eq!(alice.lines(), ["ERR forbidden for operators only"], "{cmd}");
    }
    let mut sam = h.guest("sam").await;
    h.send(&sam, "admin rooms").await;
    assert_eq!(sam.lines(), ["ERR forbidden not for guests"]);
}

#[tokio::test]
async fn dropping_a_room_removes_everyone_and_keeps_reports() {
    let mut h = harness();
    let (mut sam, _) = h.joined("sam", "#general").await;
    let id = report(&h, &mut sam, "report #general 5 spam").await;
    let mut alice = h.signed_in_as(ALICE);
    let mut bob = h.signed_in_as(BOB);
    let mut dave = h.signed_in_as(DAVE);
    let mut op = h.signed_in_as(OP);
    let old = value(
        &{
            h.send(&alice, "info #general").await;
            alice.lines().pop().unwrap()
        },
        "id",
    );

    h.send(&op, "@ref=d admin drop #general enough").await;
    assert_eq!(op.lines(), ["@ref=d OK"]);
    let dropped = [format!("@id={old} DROP #general enough")];
    assert_eq!(alice.lines(), dropped);
    assert_eq!(bob.lines(), dropped);
    assert_eq!(sam.lines(), dropped);
    // Dave holds a role, but is not a member: he hears of it too (PLAN.md
    // 5, item 33).
    assert_eq!(dave.lines(), dropped);

    // The room is gone from everyone's SYNC.
    h.send(&sam, "sync").await;
    assert_eq!(sam.lines(), ["OK"]);
    h.send(&alice, "sync").await;
    let lines = alice.lines();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].starts_with("CONV #private "), "{lines:?}");
    // It is in the configuration, so it is there again, empty, with a new
    // id, and with nobody's role.
    h.send(&op, "admin rooms limit=1").await;
    assert_eq!(op.lines(), ["ROOM #general 0", "OK more=1"]);
    h.send(&alice, "info #general").await;
    let lines = alice.lines();
    let new = value(lines.last().unwrap(), "id");
    assert_ne!(new, old);
    assert_eq!(
        lines.last().unwrap(),
        &format!("OK id={new} members=0 head=0 role=none joined=no")
    );
    assert!(
        h.store
            .room(&"#general".parse().unwrap())
            .unwrap()
            .unwrap()
            .roles
            .is_empty()
    );
    h.send(&bob, "join #general").await;
    assert_eq!(
        bob.lines()[0],
        format!("@seq=1;t={T};from={BOB};id={new} JOIN #general")
    );

    // The open report stays, for the operators alone, with the old room's
    // id (5.8).
    h.send(&op, "admin reports").await;
    let mut want = report_5(&id, &old, true);
    want.push("OK".into());
    assert_eq!(op.lines(), want);
    h.send(&alice, "reports #general").await;
    assert_eq!(
        alice.lines(),
        ["ERR forbidden only the room's owners and moderators may see its reports"]
    );
    h.send(&dave, &format!("resolve {id}")).await;
    assert_eq!(dave.lines(), ["ERR not-found no such report"]);
    let mut op2 = h.signed_in_as(OP);
    h.send(&op, &format!("resolve {id}")).await;
    assert_eq!(op.lines(), ["OK"]);
    assert_eq!(op2.lines(), [format!("RESOLVED {id}")]);
    assert_eq!(alice.lines(), none());
    assert_eq!(dave.lines(), none());
}

#[tokio::test]
async fn a_dropped_room_not_in_the_configuration_is_gone() {
    let mut h = harness();
    let mut bob = h.signed_in_as(BOB);
    let mut op = h.signed_in_as(OP);
    h.send(&op, "admin drop #temp").await;
    assert_eq!(op.lines(), ["OK"]);
    let line = bob.lines();
    assert_eq!(line.len(), 1);
    assert!(
        line[0].starts_with("@id=") && line[0].ends_with(" DROP #temp"),
        "{line:?}"
    );
    h.send(&op, "admin rooms after=#private").await;
    assert_eq!(op.lines(), ["OK more=0"]);
    for cmd in ["info #temp", "history #temp", "admin drop #temp"] {
        h.send(&op, cmd).await;
        assert_eq!(op.lines(), ["ERR not-found no such room"], "{cmd}");
    }
    assert_eq!(h.store.room(&"#temp".parse().unwrap()).unwrap(), None);
    // The name is free: joining creates a new room.
    h.send(&bob, "join #temp").await;
    let lines = bob.lines();
    assert!(lines[0].starts_with(&format!("@seq=1;t={T};from={BOB};id=")));
    assert_ne!(value(&lines[0], "id"), value(&line[0], "id"));
    h.send(&bob, "history #temp").await;
    assert_eq!(bob.lines().len(), 2);
}

#[tokio::test]
async fn commands_waiting_on_a_dropped_room_get_not_found() {
    let flaky = Arc::new(Flaky::new());
    let mut c = config();
    c.rooms = strings(&["#general", "#private"]);
    c.operators = strings(&[OP]);
    for room in &c.rooms {
        flaky
            .inner
            .ensure_room(&room.parse().unwrap(), start())
            .unwrap();
    }
    prepare(&flaky.inner);
    let mut h = Harness::on(c, flaky.clone(), timers());
    let mut bob = h.signed_in_as(BOB);
    let op = h.signed_in_as(OP);

    flaky.pause.arm("drop_room");
    let hub = h.hub.clone();
    let id = op.id;
    let drop =
        tokio::spawn(async move { hub.command(id, "admin drop #temp".parse().unwrap()).await });
    flaky.pause.reached().await;
    let hub = h.hub.clone();
    let id = bob.id;
    let msg = tokio::spawn(async move {
        hub.command(id, "@ref=m msg #temp hi".parse().unwrap())
            .await
    });
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    flaky.pause.release();
    drop.await.unwrap();
    msg.await.unwrap();
    let lines = bob.lines();
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(lines[0].ends_with(" DROP #temp"));
    assert_eq!(lines[1], "@ref=m ERR not-found no such room");
}

/// Commands waiting on a room from the configuration while it is dropped
/// go to the room made again in its place, as if they had come a moment
/// later.
#[tokio::test]
async fn commands_waiting_on_a_dropped_configured_room_go_to_the_new_one() {
    let flaky = Arc::new(Flaky::new());
    let mut c = config();
    c.rooms = strings(&["#general", "#private"]);
    c.operators = strings(&[OP]);
    for room in &c.rooms {
        flaky
            .inner
            .ensure_room(&room.parse().unwrap(), start())
            .unwrap();
    }
    prepare(&flaky.inner);
    let mut h = Harness::on(c, flaky.clone(), timers());
    let mut bob = h.signed_in_as(BOB);
    let op = h.signed_in_as(OP);
    let old = h
        .store
        .room(&"#general".parse().unwrap())
        .unwrap()
        .unwrap()
        .id;

    flaky.pause.arm("drop_room");
    let (hub, id) = (h.hub.clone(), op.id);
    let drop = tokio::spawn(async move {
        hub.command(id, "admin drop #general".parse().unwrap())
            .await
    });
    flaky.pause.reached().await;
    let (hub, id) = (h.hub.clone(), bob.id);
    let join = tokio::spawn(async move {
        hub.command(id, "@ref=j join #general".parse().unwrap())
            .await
    });
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    flaky.pause.release();
    drop.await.unwrap();
    join.await.unwrap();
    let new = h
        .store
        .room(&"#general".parse().unwrap())
        .unwrap()
        .unwrap()
        .id;
    assert_ne!(new, old);
    let lines = bob.lines();
    assert_eq!(lines[0], format!("@id={old} DROP #general"), "{lines:?}");
    assert_eq!(
        lines.last().unwrap(),
        &format!("@ref=j OK id={new} head=1 role=member"),
        "{lines:?}"
    );
}

/// HISTORY and RELATED whose query comes after a DROP that went through
/// once they had checked the room: `not-found`, not an empty page with the
/// old room's id.
#[tokio::test]
async fn history_and_related_racing_a_drop_get_not_found() {
    for (method, line) in [
        ("history", "@ref=q history #temp"),
        ("related", "@ref=q related #temp 1 2"),
    ] {
        let flaky = Arc::new(Flaky::new());
        let mut c = config();
        c.rooms = strings(&["#general", "#private"]);
        c.operators = strings(&[OP]);
        for room in &c.rooms {
            flaky
                .inner
                .ensure_room(&room.parse().unwrap(), start())
                .unwrap();
        }
        prepare(&flaky.inner);
        let mut h = Harness::on(c, flaky.clone(), timers());
        let mut bob = h.signed_in_as(BOB);
        let mut op = h.signed_in_as(OP);

        flaky.pause.arm(method);
        let (hub, id, req) = (h.hub.clone(), bob.id, line.parse().unwrap());
        let query = tokio::spawn(async move { hub.command(id, req).await });
        flaky.pause.reached().await;
        h.send(&op, "admin drop #temp").await;
        assert_eq!(op.lines(), ["OK"], "{method}");
        flaky.pause.release();
        query.await.unwrap();
        let lines = bob.lines();
        assert_eq!(lines.len(), 2, "{method}: {lines:?}");
        assert!(lines[0].ends_with(" DROP #temp"), "{method}: {lines:?}");
        assert_eq!(lines[1], "@ref=q ERR not-found no such room", "{method}");
    }
}

#[tokio::test]
async fn a_drop_that_fails_changes_nothing() {
    let flaky = Arc::new(Flaky::new());
    let mut c = config();
    c.rooms = strings(&["#general", "#private"]);
    c.operators = strings(&[OP]);
    for room in &c.rooms {
        flaky
            .inner
            .ensure_room(&room.parse().unwrap(), start())
            .unwrap();
    }
    prepare(&flaky.inner);
    let mut h = Harness::on(c, flaky.clone(), timers());
    let mut bob = h.signed_in_as(BOB);
    let mut op = h.signed_in_as(OP);
    flaky
        .broken
        .store(true, std::sync::atomic::Ordering::SeqCst);
    h.send(&op, "admin drop #temp").await;
    assert_eq!(op.lines(), ["ERR internal internal error"]);
    assert_eq!(bob.lines(), none());
    flaky
        .broken
        .store(false, std::sync::atomic::Ordering::SeqCst);
    h.send(&op, "admin rooms after=#private").await;
    assert_eq!(op.lines(), ["ROOM #temp 1", "OK more=0"]);
    h.send(&bob, "sync").await;
    let lines = bob.lines();
    assert_eq!(lines.len(), 3);
    assert!(lines[1].starts_with("CONV #temp "), "{lines:?}");
}

/// Nobody reviews a report about their own message: a moderator whose
/// message is reported gets no lines for it, does not see it in REPORTS,
/// and cannot RESOLVE it (PLAN.md 5, item 35).
#[tokio::test]
async fn the_author_is_not_a_reviewer() {
    let mut h = harness();
    let mut alice = h.signed_in_as(ALICE);
    let mut dave = h.signed_in_as(DAVE);
    let mut op = h.signed_in_as(OP);
    let mut bob = h.signed_in_as(BOB);
    h.send(&dave, "join #general").await;
    h.send(&dave, "msg #general mods rule").await;
    assert_eq!(dave.lines().last().unwrap(), "OK seq=9");
    alice.lines();
    bob.lines();
    op.lines();

    let id = report(&h, &mut bob, "report #general 9 rude").await;
    assert_eq!(alice.lines().len(), 2);
    assert_eq!(op.lines().len(), 2);
    assert_eq!(dave.lines(), none());

    h.send(&dave, "reports #general").await;
    assert_eq!(dave.lines(), ["OK"]);
    h.send(&dave, &format!("resolve {id}")).await;
    assert_eq!(dave.lines(), ["ERR not-found no such report"]);
    // The others still may, and dave hears nothing of it.
    h.send(&alice, &format!("resolve {id}")).await;
    assert_eq!(alice.lines(), ["OK"]);
    assert_eq!(op.lines(), [format!("RESOLVED {id}")]);
    assert_eq!(dave.lines(), none());
}
