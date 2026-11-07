//! Unit tests of the sync engine: one or more per rule, and the scenarios
//! TLC found in `proofs/sync` (proofs/README.md, Results).

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use risala_proto::command::{Command, Request};
use risala_proto::error::ErrorCode;
use risala_proto::names::{Conv, Seq};
use risala_proto::server::{ServerLine, ServerMessage};
use risala_proto::time::Timestamp;
use risala_proto::types::RoomSetting;

use super::*;
use crate::addr::ServerAddr;
use crate::store::{AccountId, Change, ConversationSummary, Draft, FailReason, OutboxState, Store};

const ALICE: &str = "alice@example.org";
const T0: u64 = 1_800_000_000_000;

fn conv(s: &str) -> Conv {
    s.parse().unwrap()
}

fn seq(n: u64) -> Seq {
    Seq::new(n).unwrap()
}

fn msg(s: &str) -> ServerMessage {
    s.parse().unwrap_or_else(|e| panic!("{s}: {e}"))
}

/// An event line: `seq` and `t`, then the rest.
fn ev(seq: u64, rest: &str) -> String {
    let t = Timestamp::from_unix_millis(T0 + seq).unwrap();
    format!("@seq={seq};t={t};{rest}")
}

/// A test harness: one account, one engine, and the commands it sent.
struct H {
    store: Store,
    account: AccountId,
    engine: SyncEngine,
    config: SyncConfig,
    clock: Arc<AtomicU64>,
    queue: VecDeque<Outgoing>,
    notes: Vec<Notification>,
    changes: Vec<Change>,
    last: Output,
}

impl H {
    fn new(me: &str) -> H {
        H::with(me, None, 50)
    }

    fn with(me: &str, lazy_gap: Option<u64>, page_size: u64) -> H {
        let store = Store::open_in_memory().unwrap();
        let server: ServerAddr = "chat.example.org".parse().unwrap();
        let account = store.account(&server, &me.parse().unwrap()).unwrap();
        let clock = Arc::new(AtomicU64::new(T0));
        let c = clock.clone();
        let config = SyncConfig {
            page_size,
            lazy_gap,
            resend_window: Duration::from_secs(23 * 3600),
            clock: Clock::new(move || {
                Timestamp::from_unix_millis(c.load(Ordering::SeqCst)).unwrap()
            }),
        };
        let engine = SyncEngine::new(store.clone(), account, config.clone()).unwrap();
        H {
            store,
            account,
            engine,
            config,
            clock,
            queue: VecDeque::new(),
            notes: Vec::new(),
            changes: Vec::new(),
            last: Output::default(),
        }
    }

    /// Signs in, and expects SYNC.
    fn start(&mut self) -> ReqId {
        let out = self.engine.start().unwrap();
        self.absorb(out);
        self.expect("SYNC")
    }

    /// A new connection: a new engine, and SYNC.
    fn reconnect(&mut self) -> ReqId {
        self.queue.clear();
        self.engine =
            SyncEngine::new(self.store.clone(), self.account, self.config.clone()).unwrap();
        self.start()
    }

    fn absorb(&mut self, out: Output) {
        self.queue.extend(out.send.iter().cloned());
        self.notes.extend(out.notifications.iter().cloned());
        self.changes.extend(out.changes.iter().cloned());
        self.last = out;
    }

    fn next(&mut self) -> Outgoing {
        self.queue.pop_front().expect("a command to send")
    }

    /// The next command, which must be `wire`.
    fn expect(&mut self, wire: &str) -> ReqId {
        let o = self.next();
        assert_eq!(Request::new(o.command).to_line().to_string(), wire);
        o.req
    }

    /// The next command, which must be a MSG; returns its request and cid.
    fn expect_msg(&mut self, text: &str) -> (ReqId, String) {
        let o = self.next();
        match o.command {
            Command::Msg { text: t, cid, .. } => {
                assert_eq!(t, text);
                (o.req, cid.expect("a cid").to_string())
            }
            other => panic!("expected MSG, got {other:?}"),
        }
    }

    fn idle(&self) {
        assert!(
            self.queue.is_empty(),
            "unexpected commands: {:?}",
            self.queue
        );
    }

    fn line(&mut self, s: &str) {
        let out = self.engine.handle_line(&msg(s)).unwrap();
        self.absorb(out);
    }

    fn reply(&mut self, req: ReqId, lines: &[&str], last: &str) {
        let lines = lines.iter().map(|l| msg(l)).collect();
        let out = self
            .engine
            .handle_reply(req, Reply::new(lines, msg(last).line))
            .unwrap();
        self.absorb(out);
    }

    fn reply_s(&mut self, req: ReqId, lines: &[String], last: &str) {
        let lines: Vec<&str> = lines.iter().map(String::as_str).collect();
        self.reply(req, &lines, last);
    }

    fn conv(&self, c: &str) -> ConversationSummary {
        self.store
            .conversation(self.account, &conv(c))
            .unwrap()
            .unwrap_or_else(|| panic!("no {c}"))
    }

    fn has_conv(&self, c: &str) -> bool {
        self.store
            .conversation(self.account, &conv(c))
            .unwrap()
            .is_some()
    }

    /// The stored seqs of `c`.
    fn seqs(&self, c: &str) -> Vec<u64> {
        let Some(summary) = self.store.conversation(self.account, &conv(c)).unwrap() else {
            return Vec::new();
        };
        self.store
            .export(summary.id)
            .unwrap()
            .iter()
            .map(|l| match msg(l).line {
                ServerLine::Event(e) => e.meta.unwrap().seq.get(),
                _ => unreachable!(),
            })
            .collect()
    }

    /// Signs in and catches #general up to `head`, from a server with
    /// messages 1..=head and the given id.
    fn joined(&mut self, id: &str, head: u64) {
        let r = self.start();
        self.reply(r, &[&format!("CONV #general {id} {head} 0")], "OK");
        if head > 0 {
            let r = self.expect(&format!(
                "HISTORY #general after=0 limit={}",
                self.config.page_size
            ));
            let page: Vec<String> = (1..=head)
                .map(|n| ev(n, &format!("from=bob@example.net MSG #general m{n}")))
                .collect();
            self.reply_s(r, &page, &format!("OK id={id} more=0"));
        }
        self.idle();
        assert_eq!(self.conv("#general").sync_point, head);
    }

    fn advance_clock(&self, d: Duration) {
        self.clock.fetch_add(d.as_millis() as u64, Ordering::SeqCst);
    }
}

fn bob(n: u64) -> String {
    ev(n, &format!("from=bob@example.net MSG #general m{n}"))
}

// ---------------------------------------------------------------------------
// 7.1: SYNC and catching up

#[test]
fn catches_up_page_by_page() {
    let mut h = H::with(ALICE, None, 2);
    let r = h.start();
    h.reply(r, &["CONV #general k1 3 1"], "OK");
    let r = h.expect("HISTORY #general after=0 limit=2");
    h.reply_s(r, &[bob(1), bob(2)], "OK id=k1 more=1");
    let r = h.expect("HISTORY #general after=2 limit=2");
    h.reply_s(r, &[bob(3)], "OK id=k1 more=0");
    h.idle();
    let c = h.conv("#general");
    assert_eq!((c.sync_point, c.head, c.read, c.joined), (3, 3, 1, true));
    assert!(c.caught_up());
    assert_eq!(c.unread, 2);
    assert!(h.engine.is_live(&conv("#general")));
}

#[test]
fn a_new_id_starts_afresh() {
    let mut h = H::new(ALICE);
    h.joined("k1", 3);
    let r = h.reconnect();
    // A head above what is stored, so only the id tells.
    h.reply(r, &["CONV #general k2 4 0"], "OK");
    assert_eq!(h.seqs("#general"), Vec::<u64>::new());
    assert!(h.changes.contains(&Change::Cleared {
        conv: h.conv("#general").id
    }));
    let r = h.expect("HISTORY #general after=0 limit=50");
    let page: Vec<String> = (1..=4).map(bob).collect();
    h.reply_s(r, &page, "OK id=k2 more=0");
    assert_eq!(h.seqs("#general"), [1, 2, 3, 4]);
    assert_eq!(h.conv("#general").conv_id, Some("k2".parse().unwrap()));
}

#[test]
fn a_lower_head_starts_afresh() {
    let mut h = H::new(ALICE);
    h.joined("k1", 3);
    let r = h.reconnect();
    h.reply(r, &["CONV #general k1 2 0"], "OK");
    assert_eq!(h.seqs("#general"), Vec::<u64>::new());
    h.expect("HISTORY #general after=0 limit=50");
}

#[test]
fn nothing_to_fetch_when_caught_up() {
    let mut h = H::new(ALICE);
    h.joined("k1", 3);
    let r = h.reconnect();
    h.reply(r, &["CONV #general k1 3 0"], "OK");
    h.idle();
}

#[test]
fn a_page_from_another_room_is_discarded() {
    // 7.2: the room was dropped and created again while HISTORY was on
    // its way.
    let mut h = H::new(ALICE);
    h.joined("k1", 2);
    let r = h.reconnect();
    h.reply(r, &["CONV #general k1 4 0"], "OK");
    let r = h.expect("HISTORY #general after=2 limit=50");
    h.reply_s(
        r,
        &[ev(1, "from=carol@example.com;id=k2 JOIN #general")],
        "OK id=k2 more=0",
    );
    assert_eq!(h.seqs("#general"), Vec::<u64>::new());
    assert_eq!(h.conv("#general").conv_id, None);
    assert!(!h.engine.is_live(&conv("#general")));
    let r = h.expect("SYNC");
    h.reply(r, &[], "OK");
    assert!(!h.conv("#general").joined);
}

#[test]
fn live_events_wait_for_the_id() {
    // 7.1 step 6.
    let mut h = H::new(ALICE);
    let r = h.start();
    h.line(&bob(4));
    assert!(!h.has_conv("#general"));
    h.reply(r, &["CONV #general k1 4 0"], "OK");
    let r = h.expect("HISTORY #general after=0 limit=50");
    h.reply_s(r, &[bob(1), bob(2), bob(3), bob(4)], "OK id=k1 more=0");
    assert_eq!(h.seqs("#general"), [1, 2, 3, 4]);
}

#[test]
fn a_dropped_event_past_the_head_is_fetched() {
    // A server can compute SYNC's reply, then queue a live event before
    // it. The event's seq is then above the head SYNC reports.
    let mut h = H::new(ALICE);
    let r = h.start();
    h.line(&bob(5));
    h.reply(r, &["CONV #general k1 4 0"], "OK");
    let r = h.expect("HISTORY #general after=0 limit=50");
    h.reply_s(
        r,
        &[bob(1), bob(2), bob(3), bob(4), bob(5)],
        "OK id=k1 more=0",
    );
    assert_eq!(h.conv("#general").sync_point, 5);
}

#[test]
fn a_new_conversation_seen_live_asks_sync() {
    // A direct conversation that starts after SYNC was answered.
    let mut h = H::new(ALICE);
    let r = h.start();
    h.reply(r, &[], "OK");
    h.idle();
    h.line(&ev(1, "from=bob@example.net MSG alice@example.org hi"));
    let r = h.expect("SYNC");
    h.reply(r, &["CONV bob@example.net d1 1 0"], "OK");
    let r = h.expect("HISTORY bob@example.net after=0 limit=50");
    h.reply_s(
        r,
        &[ev(1, "from=bob@example.net MSG bob@example.net hi")],
        "OK id=d1 more=0",
    );
    assert_eq!(h.seqs("bob@example.net"), [1]);
}

#[test]
fn duplicates_and_gaps() {
    // 7.1 step 5.
    let mut h = H::new(ALICE);
    h.joined("k1", 3);
    h.line(&bob(4));
    h.line(&bob(4));
    assert_eq!(h.seqs("#general"), [1, 2, 3, 4]);
    assert_eq!(h.conv("#general").sync_point, 4);
    h.idle();
    // A gap: stored, but the sync point stays, and the gap is fetched.
    h.line(&bob(6));
    assert_eq!(h.conv("#general").sync_point, 4);
    let r = h.expect("HISTORY #general after=4 limit=50");
    h.reply_s(r, &[bob(5), bob(6)], "OK id=k1 more=0");
    assert_eq!(h.conv("#general").sync_point, 6);
    h.idle();
}

#[test]
fn expired_events_are_skipped() {
    // 7.2: if the first event is later than after + 1, the rest expired.
    let mut h = H::new(ALICE);
    let r = h.start();
    h.reply(r, &["CONV #general k1 10 0"], "OK");
    let r = h.expect("HISTORY #general after=0 limit=50");
    h.reply_s(r, &[bob(9), bob(10)], "OK id=k1 more=0");
    assert_eq!(h.conv("#general").sync_point, 10);
    // Everything expired.
    let r = h.reconnect();
    h.reply(r, &["CONV #general k1 15 0"], "OK");
    let r = h.expect("HISTORY #general after=10 limit=50");
    h.reply(r, &[], "OK id=k1 more=0");
    assert_eq!(h.conv("#general").sync_point, 15);
    h.idle();
}

#[test]
fn missing_from_sync_means_left() {
    let mut h = H::new(ALICE);
    h.joined("k1", 2);
    let r = h.reconnect();
    h.reply(r, &[], "OK");
    assert!(h.notes.contains(&Notification::Left {
        conv: conv("#general")
    }));
    let c = h.conv("#general");
    assert!(!c.joined);
    assert_eq!(h.seqs("#general"), [1, 2]);
    // Live events are no longer stored.
    h.line(&bob(3));
    assert_eq!(h.seqs("#general"), [1, 2]);
}

#[test]
fn a_stale_sync_does_not_undo_a_join() {
    // SYNC computed before a JOIN on another device, answered after its
    // event.
    let mut h = H::new(ALICE);
    let r = h.start();
    h.line(&ev(1, "from=alice@example.org;id=k1 JOIN #general"));
    h.reply(r, &[], "OK");
    assert!(h.conv("#general").joined);
    assert!(h.engine.is_live(&conv("#general")));
    let r = h.expect("SYNC");
    h.reply(r, &["CONV #general k1 1 0"], "OK");
    h.idle();
    assert!(h.conv("#general").joined);
}

#[test]
fn a_server_that_refuses_history_is_not_asked_forever() {
    let mut h = H::new(ALICE);
    let r = h.start();
    h.reply(r, &["CONV #general k1 3 0"], "OK");
    for _ in 0..2 {
        let r = h.expect("HISTORY #general after=0 limit=50");
        h.reply(r, &[], "ERR not-found");
        let r = h.expect("SYNC");
        h.reply(r, &["CONV #general k1 3 0"], "OK");
    }
    // The third failure is the last.
    let r = h.expect("HISTORY #general after=0 limit=50");
    h.reply(r, &[], "ERR not-found");
    h.idle();
    // A new id is a new conversation, and is tried again.
    h.line(&ev(4, "from=alice@example.org;id=k2 JOIN #general"));
    h.expect("HISTORY #general after=0 limit=50");
}

// ---------------------------------------------------------------------------
// 6.1, 6.4, 10.4: joins, notifications, DROP

#[test]
fn joining() {
    let mut h = H::new(ALICE);
    let r = h.start();
    h.reply(r, &[], "OK");
    let out = h.engine.join(&"#general".parse().unwrap());
    h.absorb(out);
    let r = h.expect("JOIN #general");
    h.line(&ev(5, "from=alice@example.org;id=k1 JOIN #general"));
    // Catching up starts at once.
    let fill = h.expect("HISTORY #general after=0 limit=50");
    h.reply(
        r,
        &["SET #general topic hello", "SET #general public yes"],
        "OK id=k1 head=5",
    );
    assert_eq!(h.last.completed[0].req, r);
    let c = h.conv("#general");
    assert_eq!((c.joined, c.head), (true, 5));
    let settings = h.store.room_settings(c.id).unwrap();
    assert!(settings.contains(&RoomSetting::Topic("hello".into())));
    let page: Vec<String> = (1..=4).map(bob).collect();
    h.reply_s(fill, &page, "OK id=k1 more=0");
    assert_eq!(h.conv("#general").sync_point, 5);
    h.idle();
}

#[test]
fn own_join_from_another_device() {
    // 6.1: the JOIN's id differs from the stored one.
    let mut h = H::new(ALICE);
    h.joined("k1", 3);
    h.line(&ev(
        4,
        "from=bob@example.net KICK #general alice@example.org",
    ));
    assert!(!h.engine.is_live(&conv("#general")));
    // The room is dropped and created again; we are not told. Our other
    // device joins the new room.
    h.line(&ev(2, "from=alice@example.org;id=k2 JOIN #general"));
    assert_eq!(h.seqs("#general"), [2]);
    assert_eq!(h.conv("#general").conv_id, Some("k2".parse().unwrap()));
    let r = h.expect("HISTORY #general after=0 limit=50");
    h.reply_s(
        r,
        &[
            ev(1, "from=carol@example.com;id=k2 JOIN #general"),
            ev(2, "from=alice@example.org;id=k2 JOIN #general"),
        ],
        "OK id=k2 more=0",
    );
    assert_eq!(h.seqs("#general"), [1, 2]);
}

#[test]
fn own_join_of_the_same_room_catches_up() {
    let mut h = H::new(ALICE);
    h.joined("k1", 3);
    h.line(&ev(4, "from=alice@example.org PART #general"));
    assert!(!h.conv("#general").joined);
    h.line(&ev(9, "from=alice@example.org;id=k1 JOIN #general"));
    assert!(h.conv("#general").joined);
    h.expect("HISTORY #general after=4 limit=50");
}

#[test]
fn someone_elses_join_with_a_new_id() {
    let mut h = H::new(ALICE);
    h.joined("k1", 3);
    h.line(&ev(4, "from=carol@example.com;id=k2 JOIN #general"));
    assert_eq!(h.seqs("#general"), Vec::<u64>::new());
    assert!(!h.engine.is_live(&conv("#general")));
    h.expect("SYNC");
}

#[test]
fn notifications_are_not_history() {
    // 6.4.
    let mut h = H::new(ALICE);
    h.joined("k1", 3);
    h.line(&ev(
        4,
        "from=bob@example.net KICK #general alice@example.org bye",
    ));
    assert_eq!(h.seqs("#general"), [1, 2, 3]);
    assert!(!h.conv("#general").joined);
    assert!(h.notes.contains(&Notification::Kicked {
        room: "#general".parse().unwrap(),
        by: "bob@example.net".parse().unwrap(),
        reason: "bye".into(),
    }));
    h.line(&ev(
        9,
        "from=bob@example.net INVITE #general alice@example.org",
    ));
    assert!(matches!(h.notes.last(), Some(Notification::Invited { .. })));
    h.line(&ev(
        10,
        "from=bob@example.net BAN #general alice@example.org",
    ));
    assert!(matches!(h.notes.last(), Some(Notification::Banned { .. })));
    assert_eq!(h.seqs("#general"), [1, 2, 3]);
    // Someone else's kick is history.
    let mut h = H::new(ALICE);
    h.joined("k1", 3);
    h.line(&ev(
        4,
        "from=bob@example.net KICK #general carol@example.com",
    ));
    assert_eq!(h.seqs("#general"), [1, 2, 3, 4]);
}

#[test]
fn drop_removes_the_room() {
    // 10.4.
    let mut h = H::new(ALICE);
    h.joined("k1", 3);
    let (id, out) = h
        .engine
        .send(&conv("#general"), &Draft::text("hi"))
        .unwrap();
    h.absorb(out);
    h.expect_msg("hi");
    h.line("DROP #general spam");
    assert!(!h.has_conv("#general"));
    assert!(h.notes.contains(&Notification::Dropped {
        room: "#general".parse().unwrap(),
        reason: "spam".into(),
    }));
    let item = h.store.outbox_item(id).unwrap().unwrap();
    assert_eq!(item.state, OutboxState::Failed(FailReason::Dropped));
}

#[test]
fn a_page_after_starting_afresh_is_ignored() {
    // The model's note for client authors: remember what HISTORY was asked
    // for.
    let mut h = H::new(ALICE);
    let r = h.start();
    h.reply(r, &["CONV #general k1 3 0"], "OK");
    let old = h.expect("HISTORY #general after=0 limit=50");
    h.line("DROP #general");
    h.line(&ev(1, "from=alice@example.org;id=k2 JOIN #general"));
    // The old request's page arrives, from the new room.
    h.reply_s(
        old,
        &[ev(1, "from=alice@example.org;id=k2 JOIN #general")],
        "OK id=k2 more=0",
    );
    assert_eq!(h.seqs("#general"), [1]);
    assert_eq!(h.conv("#general").sync_point, 1);
}

#[test]
fn reported_copies_are_not_events() {
    let mut h = H::new(ALICE);
    h.joined("k1", 3);
    h.line("@report=p4x8n2;seq=4;t=2026-11-06T15:43:58.019Z;from=~spammer MSG #general pills");
    assert_eq!(h.seqs("#general"), [1, 2, 3]);
}

// ---------------------------------------------------------------------------
// 7.1 step 4, 7.3: lazy loading, RELATED

#[test]
fn lazy_loading() {
    let mut h = H::with(ALICE, Some(10), 3);
    let r = h.start();
    h.reply(r, &["CONV #general k1 100 0"], "OK");
    // Only the newest page.
    let r = h.expect("HISTORY #general limit=3");
    h.reply_s(r, &[bob(98), bob(99), bob(100)], "OK id=k1 more=1");
    h.idle();
    let c = h.conv("#general");
    assert_eq!((c.sync_point, c.newest), (0, Some(seq(100))));
    assert!(!c.caught_up());

    // Scrolling back. Every later event is stored, so no RELATED.
    let out = h.engine.load_older(&conv("#general")).unwrap();
    h.absorb(out);
    let r = h.expect("HISTORY #general before=98 limit=3");
    h.reply_s(r, &[bob(95), bob(96), bob(97)], "OK id=k1 more=1");
    h.idle();

    // A reply's target far back, with an edit in the gap (7.3).
    let out = h.engine.fetch(&conv("#general"), seq(50)).unwrap();
    h.absorb(out);
    let r = h.expect("HISTORY #general before=51 limit=1");
    h.reply_s(r, &[bob(50)], "OK id=k1 more=1");
    let r = h.expect("RELATED #general 50 50 after=50 limit=3");
    h.reply_s(
        r,
        &[ev(60, "from=bob@example.net;edit=50 MSG #general fixed")],
        "OK id=k1 more=0",
    );
    let item = h
        .store
        .message(h.conv("#general").id, seq(50))
        .unwrap()
        .unwrap();
    assert_eq!(item.text.as_deref(), Some("fixed"));

    // Downloading fills the rest, forward from the sync point.
    let out = h.engine.download(&conv("#general")).unwrap();
    h.absorb(out);
    let mut after = 0;
    loop {
        let r = h.expect(&format!("HISTORY #general after={after} limit=3"));
        let page: Vec<String> = (after + 1..=(after + 3).min(100)).map(bob).collect();
        let more = after + 3 < 100;
        h.reply_s(r, &page, &format!("OK id=k1 more={}", u8::from(more)));
        after = h.conv("#general").sync_point;
        if !more {
            break;
        }
    }
    h.idle();
    assert!(h.conv("#general").caught_up());
    assert_eq!(h.seqs("#general"), (1..=100).collect::<Vec<_>>());
}

#[test]
fn loading_older_reaches_the_sync_point() {
    let mut h = H::with(ALICE, Some(3), 3);
    h.joined("k1", 2);
    let r = h.reconnect();
    h.reply(r, &["CONV #general k1 9 0"], "OK");
    let r = h.expect("HISTORY #general limit=3");
    h.reply_s(r, &[bob(7), bob(8), bob(9)], "OK id=k1 more=1");
    let out = h.engine.load_older(&conv("#general")).unwrap();
    h.absorb(out);
    let r = h.expect("HISTORY #general before=7 limit=3");
    h.reply_s(r, &[bob(4), bob(5), bob(6)], "OK id=k1 more=1");
    assert_eq!(h.conv("#general").sync_point, 2);
    let out = h.engine.load_older(&conv("#general")).unwrap();
    h.absorb(out);
    let r = h.expect("HISTORY #general before=4 limit=3");
    // Event 3 is reached: the page joins the sync point.
    h.reply_s(r, &[bob(1), bob(2), bob(3)], "OK id=k1 more=0");
    assert_eq!(h.conv("#general").sync_point, 9);
    let out = h.engine.load_older(&conv("#general")).unwrap();
    assert!(out.send.is_empty());
}

// ---------------------------------------------------------------------------
// 7.6: the outbox

#[test]
fn sending() {
    let mut h = H::new(ALICE);
    h.joined("k1", 3);
    let (id, out) = h
        .engine
        .send(&conv("#general"), &Draft::text("hello"))
        .unwrap();
    h.absorb(out);
    let (r, cid) = h.expect_msg("hello");
    assert!(cid.len() >= 16);
    let item = h.store.outbox_item(id).unwrap().unwrap();
    assert_eq!(item.state, OutboxState::Sending);
    assert_eq!(item.conv_id, Some("k1".parse().unwrap()));
    // The event comes before the OK (5.3).
    h.line(&ev(4, "from=alice@example.org MSG #general hello"));
    h.reply(r, &[], "OK seq=4");
    assert_eq!(
        h.store.outbox_item(id).unwrap().unwrap().state,
        OutboxState::Sent(seq(4))
    );
}

#[test]
fn sending_waits_for_the_id() {
    let mut h = H::new(ALICE);
    h.joined("k1", 3);
    let r = h.reconnect();
    // Not confirmed on this connection yet.
    let (_, out) = h
        .engine
        .send(&conv("#general"), &Draft::text("early"))
        .unwrap();
    assert!(out.send.is_empty());
    h.reply(r, &["CONV #general k1 3 0"], "OK");
    h.expect_msg("early");
}

#[test]
fn resending_after_a_reconnect() {
    let mut h = H::new(ALICE);
    h.joined("k1", 3);
    let (id, out) = h
        .engine
        .send(&conv("#general"), &Draft::text("again"))
        .unwrap();
    h.absorb(out);
    let (_, cid) = h.expect_msg("again");
    // The connection drops before the OK.
    let r = h.reconnect();
    h.reply(r, &["CONV #general k1 4 0"], "OK");
    let fill = h.expect("HISTORY #general after=3 limit=50");
    let (r, cid2) = h.expect_msg("again");
    assert_eq!(cid, cid2, "the same cid");
    h.reply_s(
        fill,
        &[ev(4, "from=alice@example.org MSG #general again")],
        "OK id=k1 more=0",
    );
    h.reply(r, &[], "OK seq=4");
    assert_eq!(
        h.store.outbox_item(id).unwrap().unwrap().state,
        OutboxState::Sent(seq(4))
    );
}

#[test]
fn no_resending_into_a_new_room() {
    let mut h = H::new(ALICE);
    h.joined("k1", 3);
    let (id, out) = h
        .engine
        .send(&conv("#general"), &Draft::text("old"))
        .unwrap();
    h.absorb(out);
    h.expect_msg("old");
    let r = h.reconnect();
    h.reply(r, &["CONV #general k2 1 0"], "OK");
    h.expect("HISTORY #general after=0 limit=50");
    h.idle();
    assert_eq!(
        h.store.outbox_item(id).unwrap().unwrap().state,
        OutboxState::Failed(FailReason::RoomChanged)
    );
}

#[test]
fn guests_do_not_resend() {
    // 7.6: a guest's cids count only within one connection.
    let mut h = H::new("~sam");
    h.joined("k1", 3);
    let (queued, out) = h
        .engine
        .send(&conv("#general"), &Draft::text("one"))
        .unwrap();
    h.absorb(out);
    h.expect_msg("one");
    let r = h.reconnect();
    // Still in the room, as far as this test's server says.
    h.reply(r, &["CONV #general k1 3 0"], "OK");
    h.idle();
    assert_eq!(
        h.store.outbox_item(queued).unwrap().unwrap().state,
        OutboxState::Failed(FailReason::Unconfirmed)
    );
}

#[test]
fn no_resending_after_a_day() {
    let mut h = H::new(ALICE);
    h.joined("k1", 3);
    let (id, out) = h
        .engine
        .send(&conv("#general"), &Draft::text("late"))
        .unwrap();
    h.absorb(out);
    h.expect_msg("late");
    h.advance_clock(Duration::from_secs(24 * 3600));
    let r = h.reconnect();
    h.reply(r, &["CONV #general k1 3 0"], "OK");
    h.idle();
    assert_eq!(
        h.store.outbox_item(id).unwrap().unwrap().state,
        OutboxState::Failed(FailReason::Unconfirmed)
    );
}

#[test]
fn rate_limits_and_errors() {
    let mut h = H::new(ALICE);
    h.joined("k1", 3);
    let (id, out) = h
        .engine
        .send(&conv("#general"), &Draft::text("slow"))
        .unwrap();
    h.absorb(out);
    let (r, cid) = h.expect_msg("slow");
    h.reply(r, &[], "@retry=3 ERR rate-limited");
    assert_eq!(h.last.retry_after, Some(Duration::from_secs(3)));
    assert_eq!(
        h.store.outbox_item(id).unwrap().unwrap().state,
        OutboxState::Queued
    );
    let out = h.engine.resume_outbox().unwrap();
    h.absorb(out);
    let (r, cid2) = h.expect_msg("slow");
    assert_eq!(cid, cid2);
    h.reply(r, &[], "ERR forbidden read only");
    assert_eq!(
        h.store.outbox_item(id).unwrap().unwrap().state,
        OutboxState::Failed(FailReason::Rejected(ErrorCode::Forbidden))
    );
}

#[test]
fn bad_drafts() {
    let mut h = H::new(ALICE);
    h.joined("k1", 3);
    assert!(matches!(
        h.engine.send(&conv("#general"), &Draft::text("  ")),
        Err(SyncError::Invalid(_))
    ));
    assert!(matches!(
        h.engine.send(&conv("#elsewhere"), &Draft::text("hi")),
        Err(SyncError::NotJoined(_))
    ));
    // A direct conversation with no id starts with its first message.
    let (_, out) = h
        .engine
        .send(&conv("bob@example.net"), &Draft::text("hi"))
        .unwrap();
    h.absorb(out);
    h.expect_msg("hi");
}

// ---------------------------------------------------------------------------
// 7.4: read markers

#[test]
fn read_markers() {
    let mut h = H::new(ALICE);
    h.joined("k1", 3);
    let out = h.engine.mark_read(&conv("#general"), seq(2)).unwrap();
    h.absorb(out);
    h.expect("READ #general 2");
    // Backwards is ignored.
    let out = h.engine.mark_read(&conv("#general"), seq(1)).unwrap();
    assert!(out.send.is_empty());
    h.line("READ #general 3");
    assert_eq!(h.conv("#general").read, 3);
    assert_eq!(h.conv("#general").unread, 0);

    let mut g = H::new("~sam");
    g.joined("k1", 3);
    let out = g.engine.mark_read(&conv("#general"), seq(2)).unwrap();
    assert!(out.send.is_empty(), "guests keep markers locally");
    assert_eq!(g.conv("#general").read, 2);
}

// ---------------------------------------------------------------------------
// The scenarios TLC found (proofs/README.md, Results)

#[test]
fn tlc_1_history_page_from_a_different_room() {
    // Joined and catching up; kicked, the room dropped and created again
    // before HISTORY is handled. The page comes from the new room.
    let mut h = H::new(ALICE);
    let r = h.start();
    h.reply(r, &["CONV #general k1 3 0"], "OK");
    let r = h.expect("HISTORY #general after=0 limit=50");
    h.line(&ev(
        4,
        "from=bob@example.net KICK #general alice@example.org",
    ));
    h.reply_s(
        r,
        &[ev(1, "from=bob@example.net;id=k2 JOIN #general")],
        "OK id=k2 more=0",
    );
    assert_eq!(h.seqs("#general"), Vec::<u64>::new());
}

#[test]
fn tlc_2_a_gap_that_is_never_filled() {
    // Catching up, a live event is stored; the connection drops before
    // the page arrives.
    let mut h = H::new(ALICE);
    let r = h.start();
    h.reply(r, &["CONV #general k1 3 0"], "OK");
    h.expect("HISTORY #general after=0 limit=50");
    h.line(&bob(4));
    assert_eq!(h.seqs("#general"), [4]);
    let r = h.reconnect();
    h.reply(r, &["CONV #general k1 4 0"], "OK");
    // From the sync point, not from the newest stored seq.
    let r = h.expect("HISTORY #general after=0 limit=50");
    h.reply_s(r, &[bob(1), bob(2), bob(3), bob(4)], "OK id=k1 more=0");
    assert_eq!(h.seqs("#general"), [1, 2, 3, 4]);
    assert_eq!(h.conv("#general").sync_point, 4);
}

#[test]
fn tlc_3_another_devices_join_lands_in_old_history() {
    // Kicked with history kept; the room is dropped (not told) and created
    // again; the identity joins from another device.
    let mut h = H::new(ALICE);
    h.joined("k1", 3);
    h.line(&ev(
        4,
        "from=bob@example.net KICK #general alice@example.org",
    ));
    h.line(&ev(2, "from=alice@example.org;id=k2 JOIN #general"));
    h.line(&ev(3, "from=carol@example.com MSG #general new room"));
    // Seq 2 and 3 of the new room are not dropped as duplicates of the
    // old room's, and the old events are gone.
    assert_eq!(h.seqs("#general"), [2, 3]);
    let lines = h.store.export(h.conv("#general").id).unwrap();
    assert!(lines[1].ends_with("new room"));
}

#[test]
fn tlc_4_live_events_before_sync_answers() {
    // Signed in with the old room stored; the identity is in the new room;
    // before SYNC answers, it is kicked from the new room.
    let mut h = H::new(ALICE);
    h.joined("k1", 3);
    let r = h.reconnect();
    h.line(&ev(5, "from=bob@example.net MSG #general new room"));
    h.line(&ev(
        6,
        "from=bob@example.net KICK #general alice@example.org",
    ));
    h.reply(r, &[], "OK");
    // Nothing filed under the old room.
    assert_eq!(h.seqs("#general"), [1, 2, 3]);
    assert!(!h.conv("#general").joined);
}

#[test]
fn tlc_5_a_resent_cid_gets_someone_elses_seq() {
    // Sent, the connection drops before the OK, the room is dropped, and
    // the device creates it again by joining.
    let mut h = H::new(ALICE);
    h.joined("k1", 3);
    let (id, out) = h
        .engine
        .send(&conv("#general"), &Draft::text("mine"))
        .unwrap();
    h.absorb(out);
    h.expect_msg("mine");
    let r = h.reconnect();
    h.reply(r, &[], "OK");
    let out = h.engine.join(&"#general".parse().unwrap());
    h.absorb(out);
    let r = h.expect("JOIN #general");
    h.line(&ev(1, "from=alice@example.org;id=k2 JOIN #general"));
    h.reply(r, &[], "OK id=k2 head=1");
    h.idle();
    assert_eq!(
        h.store.outbox_item(id).unwrap().unwrap().state,
        OutboxState::Failed(FailReason::RoomChanged)
    );
}
