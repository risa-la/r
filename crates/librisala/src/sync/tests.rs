//! Unit tests of the sync engine: one or more per rule, and the scenarios
//! TLC found in `proofs/sync` (proofs/README.md, Results).

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use risala_proto::command::{Command, Request};
use risala_proto::error::ErrorCode;
use risala_proto::names::{Conv, Seq, Uid};
use risala_proto::server::{ServerLine, ServerMessage};
use risala_proto::time::Timestamp;
use risala_proto::types::{Presence, RoomSetting};

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
    signals: Vec<Signal>,
    last: Output,
    /// The cache's file, for [`H::on_disk`].
    file: Option<Arc<tempfile::TempDir>>,
}

impl H {
    fn new(me: &str) -> H {
        H::with(me, None, 50)
    }

    /// A harness whose cache is a file, so that [`H::sharing`] opens it
    /// as another process would.
    fn on_disk(me: &str) -> H {
        let dir = Arc::new(tempfile::tempdir().unwrap());
        let store = Store::open(dir.path().join("cache.db")).unwrap();
        let mut h = H::on(store, me, None, 50);
        h.file = Some(dir);
        h
    }

    fn with(me: &str, lazy_gap: Option<u64>, page_size: u64) -> H {
        H::on(Store::open_in_memory().unwrap(), me, lazy_gap, page_size)
    }

    fn on(store: Store, me: &str, lazy_gap: Option<u64>, page_size: u64) -> H {
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
            // Tested on its own, in `blocks`.
            fetch_blocks: false,
            ..SyncConfig::default()
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
            signals: Vec::new(),
            last: Output::default(),
            file: None,
        }
    }

    /// Another process on the same cache and account, with its own engine
    /// and connection, such as a notification extension (PLAN.md 3.3). It
    /// opens the cache again if it is a file.
    fn sharing(other: &H) -> H {
        let store = match &other.file {
            Some(dir) => Store::open(dir.path().join("cache.db")).unwrap(),
            None => other.store.clone(),
        };
        let engine = SyncEngine::new(store.clone(), other.account, other.config.clone()).unwrap();
        H {
            file: other.file.clone(),
            store,
            account: other.account,
            engine,
            config: other.config.clone(),
            clock: other.clock.clone(),
            queue: VecDeque::new(),
            notes: Vec::new(),
            changes: Vec::new(),
            signals: Vec::new(),
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
        self.signals.extend(out.signals.iter().cloned());
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
fn a_stale_head_from_another_process_keeps_history() {
    // Two processes share the cache (7.1). A sends SYNC, and the server
    // computes #general's head as 1. Before A reads the reply, B, on its
    // own connection, stores seq 2 and moves the sync point to 2.
    let mut a = H::new(ALICE);
    a.joined("k1", 1);
    let ra = a.reconnect();

    let mut b = H::sharing(&a);
    let rb = b.start();
    b.reply(rb, &["CONV #general k1 2 0"], "OK");
    let r = b.expect("HISTORY #general after=1 limit=50");
    b.reply_s(r, &[bob(2)], "OK id=k1 more=0");
    assert_eq!(b.conv("#general").sync_point, 2);
    b.idle();
    // A message the user wrote meanwhile, bound to the room.
    let (queued, _) = a
        .store
        .write(|tx| {
            tx.queue(
                a.account,
                &conv("#general"),
                Some(&"k1".parse().unwrap()),
                &Draft::text("hello"),
                Timestamp::MIN,
            )
        })
        .unwrap();

    // A's SYNC reply arrives, with the head it computed before seq 2.
    a.reply(ra, &["CONV #general k1 1 0"], "OK");
    assert_eq!(a.seqs("#general"), [1, 2]);
    let c = a.conv("#general");
    assert_eq!((c.sync_point, c.head), (2, 2));
    assert!(
        !a.changes
            .iter()
            .any(|c| matches!(c, Change::Cleared { .. }))
    );
    a.expect_msg("hello");
    a.idle();
    let item = a.store.outbox_item(queued).unwrap().unwrap();
    assert_eq!(item.state, OutboxState::Sending);
}

#[test]
fn a_head_below_the_sync_point_keeps_the_outbox() {
    // A head below the sync point with the same id discards the history
    // (7.1), but the room is the same, so its outbox entries stay.
    let mut h = H::new(ALICE);
    h.joined("k1", 3);
    let (queued, _) = h
        .store
        .write(|tx| {
            tx.queue(
                h.account,
                &conv("#general"),
                Some(&"k1".parse().unwrap()),
                &Draft::text("hello"),
                Timestamp::MIN,
            )
        })
        .unwrap();
    let r = h.reconnect();
    h.reply(r, &["CONV #general k1 2 0"], "OK");
    assert_eq!(h.seqs("#general"), Vec::<u64>::new());
    h.expect("HISTORY #general after=0 limit=50");
    h.expect_msg("hello");
    let item = h.store.outbox_item(queued).unwrap().unwrap();
    assert_eq!(item.state, OutboxState::Sending);
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
fn a_live_event_past_a_stale_head_asks_sync_again() {
    // Found by the simulation. The SYNC reply was computed at head 1, then
    // event 2 arrived first and could not be stored (7.1 step 6). If
    // events 1 and 2 expire before HISTORY asks, nothing but a new SYNC
    // says that the head is 2.
    let mut h = H::new(ALICE);
    let r = h.start();
    h.line(&bob(2));
    h.reply(r, &["CONV #general k1 1 0"], "OK");
    h.expect("HISTORY #general after=0 limit=50");
    h.expect("SYNC");
    h.idle();
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
fn a_head_learned_during_an_empty_page_is_fetched() {
    // Found by the simulation. Event 3 arrives before SYNC's reply, which
    // was computed at head 2, so it cannot be stored and SYNC is asked
    // again. Everything expires. The second SYNC says head 3 while
    // HISTORY after=2 is in flight, and that page was asked for knowing
    // only head 2, so its empty reply proves nothing about 3. One more
    // request does.
    let mut h = H::new(ALICE);
    let r = h.start();
    h.line(&bob(3));
    h.reply(r, &["CONV #general k1 2 0"], "OK");
    let h1 = h.expect("HISTORY #general after=0 limit=50");
    let s2 = h.expect("SYNC");
    h.reply(h1, &[], "OK id=k1 more=0");
    assert_eq!(h.conv("#general").sync_point, 2);
    let h3 = h.expect("HISTORY #general after=2 limit=50");
    h.reply(s2, &["CONV #general k1 3 0"], "OK");
    h.idle();
    h.reply(h3, &[], "OK id=k1 more=0");
    let r = h.expect("HISTORY #general after=2 limit=50");
    h.reply(r, &[], "OK id=k1 more=0");
    assert_eq!(h.conv("#general").sync_point, 3);
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
fn a_stale_head_does_not_discard() {
    // JOIN's OK was computed at head 5, but the server queued event 6
    // before it. The head check of 7.1 must not discard on that.
    let mut h = H::new(ALICE);
    let r = h.start();
    h.reply(r, &[], "OK");
    let out = h.engine.join(&"#general".parse().unwrap());
    h.absorb(out);
    let r = h.expect("JOIN #general");
    h.line(&ev(5, "from=alice@example.org;id=k1 JOIN #general"));
    h.line(&bob(6));
    h.reply(r, &[], "OK id=k1 head=5");
    assert_eq!(h.seqs("#general"), [5, 6]);
    h.expect("HISTORY #general after=0 limit=50");
    h.idle();
}

#[test]
fn info_checks_the_id() {
    // 6.2: INFO reports the room's id, compared like the others (5.1).
    let mut h = H::new(ALICE);
    h.joined("k1", 3);
    let room = "#general".parse().unwrap();
    let out = h.engine.info(&room);
    h.absorb(out);
    let r = h.expect("INFO #general");
    h.reply(
        r,
        &["SET #general topic now"],
        "OK id=k1 members=2 head=3 role=member joined=yes",
    );
    assert_eq!(h.seqs("#general"), [1, 2, 3]);
    h.idle();
    // Not in the room, and it is another room by now.
    let out = h.engine.info(&room);
    h.absorb(out);
    let r = h.expect("INFO #general");
    h.reply(r, &[], "OK id=k2 members=1 head=1 role=none joined=no");
    assert_eq!(h.seqs("#general"), Vec::<u64>::new());
    assert!(!h.conv("#general").joined);
    assert!(!h.engine.is_live(&conv("#general")));
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
    // An INVITE of someone else is history too.
    h.line(&ev(
        5,
        "from=bob@example.net INVITE #general carol@example.com",
    ));
    assert_eq!(h.seqs("#general"), [1, 2, 3, 4, 5]);
    assert!(h.notes.is_empty());
}

#[test]
fn an_invite_of_a_member_is_never_history() {
    // 6.4: inviting a member records nothing, so an INVITE of the account
    // means the server takes it not to be in the room, even if this
    // connection thought it was. It is a notification, and SYNC settles
    // the membership.
    let mut h = H::new(ALICE);
    h.joined("k1", 3);
    h.line(&ev(
        4,
        "from=bob@example.net INVITE #general alice@example.org",
    ));
    assert_eq!(h.seqs("#general"), [1, 2, 3]);
    assert_eq!(
        h.notes,
        [Notification::Invited {
            room: "#general".parse().unwrap(),
            by: "bob@example.net".parse().unwrap(),
        }]
    );
    assert!(!h.engine.is_live(&conv("#general")));
    assert!(!h.conv("#general").joined);
    let r = h.expect("SYNC");
    h.reply(r, &[], "OK");
    h.idle();
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
    // A DROP for another id is about an older room of the same name.
    h.line("@id=k0 DROP #general spam");
    assert!(h.has_conv("#general"));
    assert!(h.notes.is_empty());
    h.line("@id=k1 DROP #general spam");
    assert!(!h.has_conv("#general"));
    assert!(h.notes.contains(&Notification::Dropped {
        room: "#general".parse().unwrap(),
        reason: "spam".into(),
    }));
    let item = h.store.outbox_item(id).unwrap().unwrap();
    assert_eq!(item.state, OutboxState::Failed(FailReason::Dropped));
}

#[test]
fn a_drop_for_another_id_is_ignored() {
    // 10.4: a DROP whose id is not the stored one is about an older room
    // of the same name.
    let mut h = H::new(ALICE);
    h.joined("k2", 3);
    h.line("@id=k1 DROP #general spam");
    assert_eq!(h.seqs("#general"), [1, 2, 3]);
    assert!(h.notes.is_empty());
    assert!(h.engine.is_live(&conv("#general")));
    // Live events are still stored.
    h.line(&bob(4));
    assert_eq!(h.seqs("#general"), [1, 2, 3, 4]);

    // The DROP of the stored room removes it.
    h.line("@id=k2 DROP #general spam");
    assert!(!h.has_conv("#general"));
    assert!(h.notes.contains(&Notification::Dropped {
        room: "#general".parse().unwrap(),
        reason: "spam".into(),
    }));
}

#[test]
fn a_drop_for_an_older_id_still_ends_it_on_this_connection() {
    // Found by the simulation. A sends JOIN #general; the server creates
    // the room as k1. The room is dropped, and another device of the same
    // identity creates it again as k2, which B, sharing the cache, stores.
    // A's DROP of k1 leaves the stored k2 alone, but A must forget k1 and
    // not trust its JOIN reply, computed before the DROP, which names k1.
    let mut a = H::new(ALICE);
    let r = a.start();
    a.reply(r, &[], "OK");
    let out = a.engine.join(&"#general".parse().unwrap());
    a.absorb(out);
    let join = a.expect("JOIN #general");
    a.line(&ev(1, "from=alice@example.org;id=k1 JOIN #general"));
    assert_eq!(a.conv("#general").conv_id, Some("k1".parse().unwrap()));

    let mut b = H::sharing(&a);
    let rb = b.start();
    b.reply(rb, &[], "OK");
    b.line(&ev(1, "from=alice@example.org;id=k2 JOIN #general"));
    assert_eq!(a.conv("#general").conv_id, Some("k2".parse().unwrap()));

    a.line("@id=k1 DROP #general");
    assert!(!a.engine.is_live(&conv("#general")));
    assert!(a.notes.is_empty());
    a.line(&ev(1, "from=alice@example.org;id=k2 JOIN #general"));
    a.reply(join, &[], "OK id=k1 head=1");
    // The stale reply changed nothing; SYNC settles it.
    assert_eq!(a.conv("#general").conv_id, Some("k2".parse().unwrap()));
    a.expect("SYNC");
    a.line(&ev(2, "from=alice@example.org PART #general"));
    assert_eq!(a.conv("#general").conv_id, Some("k2".parse().unwrap()));
}

#[test]
fn a_page_after_starting_afresh_is_ignored() {
    // The model's note for client authors: remember what HISTORY was asked
    // for.
    let mut h = H::new(ALICE);
    let r = h.start();
    h.reply(r, &["CONV #general k1 3 0"], "OK");
    let old = h.expect("HISTORY #general after=0 limit=50");
    h.line("@id=k1 DROP #general");
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
    // 7.6: a guest's cids count only within one session, and a client cannot
    // tell whether its session was resumed.
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
fn two_processes_never_send_the_same_entry() {
    // 7.6: two processes share the cache, both signed in and in the room.
    // Picking an entry and marking it sent is one transaction, so only one
    // of them sends it, and the other leaves it alone while it waits.
    let mut a = H::on_disk(ALICE);
    a.joined("k1", 3);
    let mut b = H::sharing(&a);
    let r = b.start();
    b.reply(r, &["CONV #general k1 3 0"], "OK");
    b.idle();
    let (queued, _) = a
        .store
        .write(|tx| {
            tx.queue(
                a.account,
                &conv("#general"),
                Some(&"k1".parse().unwrap()),
                &Draft::text("hello"),
                Timestamp::MIN,
            )
        })
        .unwrap();
    let out = b.engine.resume_outbox().unwrap();
    b.absorb(out);
    let out = a.engine.resume_outbox().unwrap();
    a.absorb(out);
    let (sent, _) = b.expect_msg("hello");
    b.idle();
    a.idle();

    // A new connection of A's does not take it over either.
    let r = a.reconnect();
    a.reply(r, &["CONV #general k1 3 0"], "OK");
    a.idle();
    let state = |h: &H| h.store.outbox_item(queued).unwrap().unwrap().state;
    assert_eq!(state(&a), OutboxState::Sending);

    // B's answer settles it.
    b.reply(sent, &[], "OK seq=4");
    assert_eq!(state(&a), OutboxState::Sent(seq(4)));
}

#[test]
fn another_process_does_not_fail_a_guest_message_in_flight() {
    // A guest cannot resend after a reconnect (7.6), but a message another
    // process sent on its own live connection is not that process's to
    // fail.
    let mut a = H::on_disk("~sam");
    a.joined("k1", 3);
    let mut b = H::sharing(&a);
    let r = b.start();
    b.reply(r, &["CONV #general k1 3 0"], "OK");
    let (queued, out) = b
        .engine
        .send(&conv("#general"), &Draft::text("hello"))
        .unwrap();
    b.absorb(out);
    let (sent, _) = b.expect_msg("hello");

    let r = a.reconnect();
    a.reply(r, &["CONV #general k1 3 0"], "OK");
    a.idle();
    let state = |h: &H| h.store.outbox_item(queued).unwrap().unwrap().state;
    assert_eq!(state(&a), OutboxState::Sending);
    b.reply(sent, &[], "OK seq=4");
    assert_eq!(state(&a), OutboxState::Sent(seq(4)));
}

#[test]
fn a_claim_lapses_after_its_lease() {
    // A process that sent an entry and went away without its answer: once
    // the lease runs out, the entry is settled as if this process had sent
    // it on an earlier connection. An identity sends it again (7.6).
    let mut a = H::on_disk(ALICE);
    a.joined("k1", 3);
    let mut b = H::sharing(&a);
    let r = b.start();
    b.reply(r, &["CONV #general k1 3 0"], "OK");
    let (queued, out) = b
        .engine
        .send(&conv("#general"), &Draft::text("hello"))
        .unwrap();
    b.absorb(out);
    b.expect_msg("hello");
    drop(b);

    a.advance_clock(a.config.claim_lease - Duration::from_secs(1));
    let out = a.engine.resume_outbox().unwrap();
    a.absorb(out);
    a.idle();
    a.advance_clock(Duration::from_secs(1));
    let out = a.engine.resume_outbox().unwrap();
    a.absorb(out);
    a.expect_msg("hello");
    assert_eq!(
        a.store.outbox_item(queued).unwrap().unwrap().state,
        OutboxState::Sending
    );
}

#[test]
fn a_message_that_could_not_be_written_is_not_maybe_sent() {
    // The session refused to write the MSG line, for example because it
    // was too long: the server never saw it.
    let mut h = H::new(ALICE);
    h.joined("k1", 3);
    let (queued, out) = h
        .engine
        .send(&conv("#general"), &Draft::text("hello"))
        .unwrap();
    h.absorb(out);
    let (r, _) = h.expect_msg("hello");
    let out = h
        .engine
        .handle_reply(
            r,
            Reply {
                lines: Vec::new(),
                outcome: Outcome::NotSent,
            },
        )
        .unwrap();
    h.absorb(out);
    assert_eq!(
        h.store.outbox_item(queued).unwrap().unwrap().state,
        OutboxState::Failed(FailReason::Invalid)
    );
    // Nor is it sent again on the next connection.
    let r = h.reconnect();
    h.reply(r, &["CONV #general k1 3 0"], "OK");
    h.idle();
}

#[test]
fn a_resumed_guest_resends_with_its_cid() {
    // 4.2, 7.6: GUEST's OK said resumed=yes, so the session's cids carry
    // over, and a message with no OK goes again with the same cid.
    let mut h = H::new("~sam");
    h.joined("k1", 3);
    let (queued, out) = h
        .engine
        .send(&conv("#general"), &Draft::text("one"))
        .unwrap();
    h.absorb(out);
    let (_, cid) = h.expect_msg("one");
    h.queue.clear();
    h.engine = SyncEngine::new(h.store.clone(), h.account, h.config.clone()).unwrap();
    h.engine.set_resumed(true);
    let r = h.start();
    h.reply(r, &["CONV #general k1 3 0"], "OK");
    let (r, again) = h.expect_msg("one");
    assert_eq!(again, cid);
    h.reply(r, &[], "OK seq=4");
    assert_eq!(
        h.store.outbox_item(queued).unwrap().unwrap().state,
        OutboxState::Sent(seq(4))
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

#[test]
fn a_read_marker_stops_at_the_newest_seq_known() {
    // The server sets a marker beyond the head to the head (7.4).
    let mut h = H::new(ALICE);
    h.joined("k1", 3);
    let out = h.engine.mark_read(&conv("#general"), seq(9)).unwrap();
    h.absorb(out);
    h.expect("READ #general 3");
    assert_eq!(h.conv("#general").read, 3);
    assert!(h.changes.contains(&Change::Conversation {
        conv: h.conv("#general").id
    }));
    // A READ from another device moves it, and the unread count, and is
    // reported (7.4).
    h.line(&bob(4));
    h.line(&bob(5));
    assert_eq!(h.conv("#general").unread, 2);
    h.changes.clear();
    h.line("READ #general 4");
    assert_eq!((h.conv("#general").read, h.conv("#general").unread), (4, 1));
    assert_eq!(
        h.changes,
        [Change::Conversation {
            conv: h.conv("#general").id
        }]
    );
    // Not backwards, and nothing for a conversation not in the cache.
    h.changes.clear();
    h.line("READ #general 2");
    h.line("READ #other 2");
    assert_eq!(h.conv("#general").read, 4);
    assert!(h.changes.is_empty());
    h.idle();
}

#[test]
fn sync_initialises_read_markers_and_sends_the_ones_it_missed() {
    let mut h = H::new(ALICE);
    h.joined("k1", 5);
    // Read offline: the marker moved here only.
    h.store
        .write(|tx| {
            let mut row = tx.conv_by_name(h.account, &conv("#general"))?.unwrap();
            tx.mark_read(&mut row, 4)
        })
        .unwrap();
    let r = h.reconnect();
    // Another device read up to 2: ours is newer, so the server hears it.
    h.reply(r, &["CONV #general k1 5 2"], "OK");
    h.expect("READ #general 4");
    assert_eq!(h.conv("#general").read, 4);
    h.idle();
    // SYNC's marker moves ours forward, with nothing to send back.
    let r = h.reconnect();
    h.reply(r, &["CONV #general k1 5 5"], "OK");
    assert_eq!((h.conv("#general").read, h.conv("#general").unread), (5, 0));
    h.idle();

    // Guests have no markers on the server (7.1): theirs stay here.
    let mut g = H::new("~sam");
    g.joined("k1", 3);
    let out = g.engine.mark_read(&conv("#general"), seq(3)).unwrap();
    g.absorb(out);
    let r = g.reconnect();
    g.reply(r, &["CONV #general k1 3 0"], "OK");
    assert_eq!(g.conv("#general").read, 3);
    g.idle();
}

#[test]
fn the_higher_of_conv_and_read_lines_wins() {
    // 3.6, 7.4: CONV's <read> covers the READ lines sent before it, and
    // the client takes the higher of the two, whichever comes first.
    let mut h = H::new(ALICE);
    h.joined("k1", 6);
    let r = h.reconnect();
    // A READ line before the SYNC reply, then a CONV line lower than it.
    h.line("READ #general 4");
    assert_eq!(h.conv("#general").read, 4);
    h.reply(r, &["CONV #general k1 6 3"], "OK");
    assert_eq!(h.conv("#general").read, 4);
    // The server heard of less than this device knows: it hears again.
    h.expect("READ #general 4");
    // A READ line after the CONV line, lower then higher.
    h.line("READ #general 2");
    assert_eq!(h.conv("#general").read, 4);
    h.line("READ #general 5");
    assert_eq!(h.conv("#general").read, 5);
    // And a CONV line higher than every READ line.
    let r = h.reconnect();
    h.reply(r, &["CONV #general k1 6 6"], "OK");
    assert_eq!((h.conv("#general").read, h.conv("#general").unread), (6, 0));
    h.idle();
}

// ---------------------------------------------------------------------------
// 8.1-8.3: typing, names, members and presence

#[test]
fn typing_repeats_every_four_seconds_while_the_user_types() {
    let mut h = H::new(ALICE);
    h.joined("k1", 1);
    let general = conv("#general");
    let out = h.engine.typing(&general);
    h.absorb(out);
    let r = h.expect("TYPING #general");
    h.reply(r, &[], "OK");
    // Calls in the next 4 seconds send nothing.
    h.advance_clock(Duration::from_millis(3900));
    let out = h.engine.typing(&general);
    assert!(out.send.is_empty());
    h.advance_clock(Duration::from_millis(100));
    let out = h.engine.typing(&general);
    h.absorb(out);
    h.expect("TYPING #general");
    // Sending a message ends it: the next keystroke says so at once.
    let out = h.engine.send(&general, &Draft::text("hi")).unwrap().1;
    h.absorb(out);
    h.expect_msg("hi");
    let out = h.engine.typing(&general);
    h.absorb(out);
    h.expect("TYPING #general");
    // So does stopping.
    h.engine.stop_typing(&general);
    let out = h.engine.typing(&general);
    h.absorb(out);
    h.expect("TYPING #general");
    // Nothing for a conversation that is not live here.
    let out = h.engine.typing(&conv("#elsewhere"));
    assert!(out.send.is_empty());
}

#[test]
fn typing_and_presence_are_signals() {
    let mut h = H::new(ALICE);
    h.joined("k1", 1);
    h.line("@from=bob@example.net TYPING #general");
    // The account's own other devices are not "someone typing".
    h.line("@from=alice@example.org TYPING #general");
    h.line(&ev(2, "from=bob@example.net MSG #general done"));
    // Edits, reactions and our own messages do not end anyone's typing.
    h.line(&ev(3, "from=bob@example.net;react=2 MSG #general 👍"));
    h.line(&ev(4, "from=alice@example.org MSG #general me too"));
    h.line("PRESENCE offline bob@example.net,carol@example.com");
    h.line("PRESENCE away dave@example.com");
    let bob: Uid = "bob@example.net".parse().unwrap();
    assert_eq!(
        h.signals,
        [
            Signal::Typing {
                conv: conv("#general"),
                from: bob.clone()
            },
            Signal::Spoke {
                conv: conv("#general"),
                from: bob.clone()
            },
            Signal::Presence {
                uid: bob,
                presence: Presence::Offline
            },
            Signal::Presence {
                uid: "carol@example.com".parse().unwrap(),
                presence: Presence::Offline
            },
            Signal::Presence {
                uid: "dave@example.com".parse().unwrap(),
                presence: Presence::Other("away".into())
            },
        ]
    );
    h.idle();
}

#[test]
fn display_names_are_stored() {
    let mut h = H::new(ALICE);
    h.joined("k1", 1);
    let bob: Uid = "bob@example.net".parse().unwrap();
    let carol: Uid = "carol@example.com".parse().unwrap();
    let name = |h: &H, u: &Uid| h.store.user_name(h.account, u).unwrap();
    assert_eq!(name(&h, &bob), None);
    h.line(r"@from=bob@example.net NAME Bob the Builder");
    assert_eq!(name(&h, &bob).as_deref(), Some("Bob the Builder"));
    assert!(h.changes.contains(&Change::User {
        account: h.account,
        uid: bob.clone()
    }));
    // Cleared: known to have none.
    h.changes.clear();
    h.line("@from=bob@example.net NAME");
    assert_eq!(name(&h, &bob).as_deref(), Some(""));
    // The same again changes nothing.
    h.line("@from=bob@example.net NAME");
    assert_eq!(h.changes.len(), 1);

    // WHOIS (8.3).
    let out = h.engine.whois(&carol);
    h.absorb(out);
    let r = h.expect("WHOIS carol@example.com");
    h.reply(r, &["USER carol@example.com online Carol"], "OK");
    assert_eq!(name(&h, &carol).as_deref(), Some("Carol"));
    assert_eq!(h.last.completed[0].req, r);
    assert!(h.signals.contains(&Signal::Presence {
        uid: carol,
        presence: Presence::Online
    }));

    // The account's own, once the server accepts it (8.2).
    let alice: Uid = ALICE.parse().unwrap();
    let out = h.engine.set_name("Alice M");
    h.absorb(out);
    let r = h.expect("NAME Alice M");
    h.reply(r, &[], "ERR invalid");
    assert_eq!(name(&h, &alice), None);
    let out = h.engine.set_name("Alice");
    h.absorb(out);
    let r = h.expect("NAME Alice");
    h.reply(r, &[], "OK");
    assert_eq!(name(&h, &alice).as_deref(), Some("Alice"));
    h.idle();
}

#[test]
fn members_are_stored_as_listed() {
    let mut h = H::new(ALICE);
    let r = h.start();
    h.reply(r, &["CONV #general k1 2 0"], "OK");
    let r = h.expect("HISTORY #general after=0 limit=50");
    h.reply(
        r,
        &[
            &ev(1, "from=carol@example.com;id=k1 JOIN #general"),
            &ev(2, "from=dave@example.com;id=k1 JOIN #general"),
        ],
        "OK id=k1 more=0",
    );
    let row = h.conv("#general").id;
    let joined = |h: &H| -> Vec<String> {
        h.store
            .room_members(row)
            .unwrap()
            .into_iter()
            .filter(|m| m.joined == Some(true))
            .map(|m| format!("{} {}", m.uid, m.role.map_or("-", |r| r.as_str())))
            .collect()
    };
    assert_eq!(joined(&h), ["carol@example.com -", "dave@example.com -"]);

    let out = h.engine.members(&"#general".parse().unwrap()).unwrap();
    h.absorb(out);
    let r = h.expect("MEMBERS #general");
    // Before the answer, Erin joins live, after the server computed it.
    h.line(&ev(3, "from=erin@example.org;id=k1 JOIN #general"));
    h.changes.clear();
    h.reply(
        r,
        &[
            "MEMBER #general alice@example.org owner online Alice",
            "MEMBER #general carol@example.com member offline",
            "MEMBER #general ~guest member online",
            "MEMBER #other zed@example.org owner online Zed",
        ],
        "OK",
    );
    // Dave is not listed, so he left; Erin's JOIN is newer than the list.
    assert_eq!(
        joined(&h),
        [
            "alice@example.org owner",
            "carol@example.com member",
            "erin@example.org -",
            "~guest member",
        ]
    );
    assert!(h.changes.contains(&Change::Members { conv: row }));
    let alice: Uid = ALICE.parse().unwrap();
    assert_eq!(
        h.store.user_name(h.account, &alice).unwrap().as_deref(),
        Some("Alice")
    );
    // Lines for another room count for nothing.
    let zed: Uid = "zed@example.org".parse().unwrap();
    assert_eq!(h.store.user_name(h.account, &zed).unwrap(), None);
    assert!(h.signals.contains(&Signal::Presence {
        uid: "carol@example.com".parse().unwrap(),
        presence: Presence::Offline
    }));
    // Events after the list count over it.
    h.line(&ev(4, "from=carol@example.com PART #general"));
    assert!(!joined(&h).contains(&"carol@example.com member".to_owned()));
    h.idle();
}

#[test]
fn members_of_a_room_started_afresh_are_not_mixed_in() {
    let mut h = H::new(ALICE);
    h.joined("k1", 1);
    let out = h.engine.members(&"#general".parse().unwrap()).unwrap();
    h.absorb(out);
    let r = h.expect("MEMBERS #general");
    // The room is dropped and created again before the answer.
    h.line(&ev(1, "from=bob@example.net;id=k2 JOIN #general"));
    h.reply(r, &["MEMBER #general bob@example.net owner online"], "OK");
    let row = h.conv("#general").id;
    assert!(h.store.room_members(row).unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// 5.7: blocks

#[test]
fn blocks() {
    // An identity asks BLOCKS on each connection; a guest cannot block.
    let mut h = H::new(ALICE);
    h.config.fetch_blocks = true;
    let r = h.reconnect();
    let b = h.expect("BLOCKS");
    h.reply(r, &[], "OK");
    h.reply(b, &["BLOCK spam@example.net", "BLOCK *@evil.example"], "OK");
    let targets = |h: &H| -> Vec<String> {
        h.store
            .blocks(h.account)
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect()
    };
    assert_eq!(targets(&h), ["*@evil.example", "spam@example.net"]);
    assert!(h.changes.contains(&Change::Blocks { account: h.account }));
    let blocked = |h: &H, u: &str| h.store.is_blocked(h.account, &u.parse().unwrap()).unwrap();
    assert!(blocked(&h, "spam@example.net"));
    assert!(blocked(&h, "x@mail.evil.example"));
    assert!(!blocked(&h, "x@notevil.example"));
    assert!(!blocked(&h, "~spam"));

    // BLOCK and UNBLOCK count once the server accepts them.
    let out = h.engine.block(&"troll@example.com".parse().unwrap());
    h.absorb(out);
    let r = h.expect("BLOCK troll@example.com");
    h.reply(r, &[], "OK");
    let out = h.engine.unblock(&"spam@example.net".parse().unwrap());
    h.absorb(out);
    let r = h.expect("UNBLOCK spam@example.net");
    h.reply(r, &[], "ERR rate-limited");
    assert_eq!(
        targets(&h),
        ["*@evil.example", "spam@example.net", "troll@example.com"]
    );
    let out = h.engine.unblock(&"spam@example.net".parse().unwrap());
    h.absorb(out);
    let r = h.expect("UNBLOCK spam@example.net");
    h.reply(r, &[], "OK");
    assert_eq!(targets(&h), ["*@evil.example", "troll@example.com"]);
    // BLOCKS replaces the list: here, blocks removed on another device.
    h.changes.clear();
    let out = h.engine.blocks().unwrap();
    h.absorb(out);
    let r = h.expect("BLOCKS");
    h.reply(r, &["BLOCK troll@example.com"], "OK");
    assert_eq!(targets(&h), ["troll@example.com"]);
    // The same list again is no change.
    h.changes.clear();
    let out = h.engine.blocks().unwrap();
    h.absorb(out);
    let r = h.expect("BLOCKS");
    h.reply(r, &["BLOCK troll@example.com"], "OK");
    assert!(h.changes.is_empty());
    h.idle();

    let mut g = H::new("~sam");
    g.config.fetch_blocks = true;
    g.reconnect();
    g.idle();
}

fn blocks_of(h: &H) -> Vec<String> {
    h.store
        .blocks(h.account)
        .unwrap()
        .iter()
        .map(ToString::to_string)
        .collect()
}

#[test]
fn block_lines_from_other_devices_change_one_target() {
    // 5.7: BLOCK and UNBLOCK lines change one target each, never the
    // whole list.
    let mut h = H::new(ALICE);
    let r = h.start();
    h.reply(r, &[], "OK");
    let out = h.engine.blocks().unwrap();
    h.absorb(out);
    let r = h.expect("BLOCKS");
    h.reply(r, &["BLOCK a@example.net", "BLOCK b@example.net"], "OK");
    h.changes.clear();
    h.line("BLOCK c@example.net");
    assert_eq!(
        blocks_of(&h),
        ["a@example.net", "b@example.net", "c@example.net"]
    );
    assert!(h.changes.contains(&Change::Blocks { account: h.account }));
    h.line("UNBLOCK a@example.net");
    assert_eq!(blocks_of(&h), ["b@example.net", "c@example.net"]);
    // Lifting a block that is not there changes nothing.
    h.changes.clear();
    h.line("UNBLOCK z@example.net");
    assert!(h.changes.is_empty());
    // A response line is part of a reply, not a change.
    h.line("@ref=9 BLOCK d@example.net");
    assert_eq!(blocks_of(&h), ["b@example.net", "c@example.net"]);
    h.idle();
}

#[test]
fn a_blocks_reply_does_not_undo_a_newer_change() {
    // Two processes share the cache, each with its connection (PLAN.md
    // 3.3). A's BLOCKS is in flight while B blocks x and lifts y. The
    // server computed A's reply before, so it lacks x and still has y.
    // It must undo neither, though it still drops z, which another
    // device lifted before the reply.
    let mut a = H::new(ALICE);
    let r = a.start();
    a.reply(r, &[], "OK");
    let out = a.engine.blocks().unwrap();
    a.absorb(out);
    let r = a.expect("BLOCKS");
    a.reply(r, &["BLOCK y@example.net", "BLOCK z@example.net"], "OK");
    assert_eq!(blocks_of(&a), ["y@example.net", "z@example.net"]);

    let mut b = H::sharing(&a);
    let r = b.start();
    b.reply(r, &[], "OK");

    let out = a.engine.blocks().unwrap();
    a.absorb(out);
    let stale = a.expect("BLOCKS");

    let out = b.engine.block(&"x@example.net".parse().unwrap());
    b.absorb(out);
    let r = b.expect("BLOCK x@example.net");
    b.reply(r, &[], "OK");
    let out = b.engine.unblock(&"y@example.net".parse().unwrap());
    b.absorb(out);
    let r = b.expect("UNBLOCK y@example.net");
    b.reply(r, &[], "OK");
    assert_eq!(blocks_of(&a), ["x@example.net", "z@example.net"]);

    a.reply(stale, &["BLOCK y@example.net"], "OK");
    assert_eq!(blocks_of(&a), ["x@example.net"]);
    // Then the server's lines for B's changes reach A, after its reply,
    // and change nothing more.
    a.line("BLOCK x@example.net");
    a.line("UNBLOCK y@example.net");
    assert_eq!(blocks_of(&a), ["x@example.net"]);

    // A later BLOCKS, sent after both changes, settles everything.
    let out = a.engine.blocks().unwrap();
    a.absorb(out);
    let r = a.expect("BLOCKS");
    a.reply(r, &["BLOCK w@example.net", "BLOCK x@example.net"], "OK");
    assert_eq!(blocks_of(&a), ["w@example.net", "x@example.net"]);
    a.idle();
    b.idle();
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

// ---------------------------------------------------------------------------
// A connection signed in under another uid than the account's

#[test]
fn a_guest_signed_in_under_a_numbered_name_knows_its_own_join() {
    let store = Store::open_in_memory().unwrap();
    let server: ServerAddr = "chat.example.org".parse().unwrap();
    let account = store.account(&server, &"~sam".parse().unwrap()).unwrap();
    let mut engine = SyncEngine::signed_in_as(
        store.clone(),
        account,
        "~sam2".parse().unwrap(),
        SyncConfig::default(),
    );
    assert_eq!(engine.uid().as_str(), "~sam2");
    let out = engine.join(&"#general".parse().unwrap());
    let join = out.send[0].req;
    // Its own JOIN event confirms the id at once, and is stored (6.1).
    let out = engine
        .handle_line(&msg(&ev(1, "from=~sam2;id=k1 JOIN #general")))
        .unwrap();
    assert!(engine.is_live(&conv("#general")));
    assert!(out.send.is_empty(), "{:?}", out.send);
    engine
        .handle_reply(join, Reply::new(vec![], msg("OK id=k1 head=1").line))
        .unwrap();
    let c = store
        .conversation(account, &conv("#general"))
        .unwrap()
        .unwrap();
    assert_eq!((c.sync_point, c.head, c.joined), (1, 1, true));
    // Its own PART leaves.
    engine
        .handle_line(&msg(&ev(2, "from=~sam2 PART #general")))
        .unwrap();
    assert!(!engine.is_live(&conv("#general")));
}

#[test]
fn deleting_goes_through_the_outbox() {
    // 5.4: DELETE is bound to the room's id and sent once it is confirmed.
    let mut h = H::new(ALICE);
    h.joined("k1", 3);
    let r = h.reconnect();
    let (id, out) = h.engine.delete(&conv("#general"), seq(2)).unwrap();
    h.absorb(out);
    h.idle();
    let item = h.store.outbox_item(id).unwrap().unwrap();
    assert_eq!(item.delete, Some(seq(2)));
    assert_eq!(item.conv_id, Some("k1".parse().unwrap()));
    h.reply(r, &["CONV #general k1 3 0"], "OK");
    let d = h.expect("@id=k1 DELETE #general 2");
    h.line(&ev(4, "from=alice@example.org DELETE #general 2"));
    h.reply(d, &[], "OK seq=4");
    assert_eq!(
        h.store.outbox_item(id).unwrap().unwrap().state,
        OutboxState::Sent(seq(4))
    );
    // Nothing is queued for a conversation with no id.
    assert!(matches!(
        h.engine.delete(&conv("#nowhere"), seq(1)),
        Err(SyncError::NotJoined(_))
    ));
}

#[test]
fn a_delete_is_sent_again_after_a_reconnect() {
    // DELETE has no cid (7.6), but sending it twice is safe: the second
    // gets OK with the first one's seq (5.4). A guest sends it again too.
    for me in [ALICE, "~sam"] {
        let mut h = H::new(me);
        h.joined("k1", 3);
        let (id, out) = h.engine.delete(&conv("#general"), seq(3)).unwrap();
        h.absorb(out);
        h.expect("@id=k1 DELETE #general 3");
        // The connection drops before the OK; the DELETE went through.
        let r = h.reconnect();
        h.reply(r, &["CONV #general k1 4 0"], "OK");
        let fill = h.expect("HISTORY #general after=3 limit=50");
        let d = h.expect("@id=k1 DELETE #general 3");
        h.reply_s(
            fill,
            &[ev(4, &format!("from={me} DELETE #general 3"))],
            "OK id=k1 more=0",
        );
        h.reply(d, &[], "OK seq=4");
        assert_eq!(
            h.store.outbox_item(id).unwrap().unwrap().state,
            OutboxState::Sent(seq(4)),
            "{me}"
        );
    }
}

#[test]
fn a_delete_that_is_not_found_fails() {
    // A message deleted already gets OK (5.4), so not-found means the
    // server deleted nothing: no such message, or another room by now.
    // That holds even if the cache has a DELETE of it, from the old room.
    let mut h = H::new(ALICE);
    h.joined("k1", 3);
    h.line(&ev(4, "from=alice@example.org DELETE #general 3"));
    for target in [9, 3] {
        let (id, out) = h.engine.delete(&conv("#general"), seq(target)).unwrap();
        h.absorb(out);
        let d = h.expect(&format!("@id=k1 DELETE #general {target}"));
        h.reply(d, &[], "ERR not-found");
        assert_eq!(
            h.store.outbox_item(id).unwrap().unwrap().state,
            OutboxState::Failed(FailReason::Rejected(ErrorCode::NotFound)),
            "{target}"
        );
    }
}

#[test]
fn a_delete_of_a_message_someone_else_deleted_ends_as_sent() {
    // 5.4: a moderator deleted it first; the OK names their DELETE.
    let mut h = H::new(ALICE);
    h.joined("k1", 3);
    let (id, out) = h.engine.delete(&conv("#general"), seq(3)).unwrap();
    h.absorb(out);
    let d = h.expect("@id=k1 DELETE #general 3");
    h.line(&ev(4, "from=bob@example.net DELETE #general 3"));
    h.reply(d, &[], "OK seq=4");
    assert_eq!(
        h.store.outbox_item(id).unwrap().unwrap().state,
        OutboxState::Sent(seq(4))
    );
}

#[test]
fn authors_delete_in_rooms_they_left() {
    // 5.4: an author may delete their own messages after leaving. The
    // room is not confirmed on the connection, but the cache says the
    // account left it, and the DELETE carries the id it is bound to.
    let mut h = H::new(ALICE);
    h.joined("k1", 3);
    let r = h.reconnect();
    h.reply(r, &[], "OK");
    assert!(!h.conv("#general").joined);
    let (id, out) = h.engine.delete(&conv("#general"), seq(2)).unwrap();
    h.absorb(out);
    let d = h.expect("@id=k1 DELETE #general 2");
    h.reply(d, &[], "OK seq=7");
    assert_eq!(
        h.store.outbox_item(id).unwrap().unwrap().state,
        OutboxState::Sent(seq(7))
    );

    // Known to have left, it goes out at once, before SYNC answers: the
    // server deletes nothing if the room has another id by now.
    let r = h.reconnect();
    let (id, out) = h.engine.delete(&conv("#general"), seq(1)).unwrap();
    h.absorb(out);
    h.expect("@id=k1 DELETE #general 1");
    assert_eq!(
        h.store.outbox_item(id).unwrap().unwrap().state,
        OutboxState::Sending
    );
    h.reply(r, &[], "OK");
    h.idle();
}

#[test]
fn a_delete_in_a_room_thought_joined_waits_for_sync() {
    // Queued while the cache still counts the account as in the room, it
    // waits for the id to be confirmed, or for SYNC to show it left.
    let mut h = H::new(ALICE);
    h.joined("k1", 3);
    let r = h.reconnect();
    let (id, out) = h.engine.delete(&conv("#general"), seq(1)).unwrap();
    h.absorb(out);
    h.idle();
    assert_eq!(
        h.store.outbox_item(id).unwrap().unwrap().state,
        OutboxState::Queued
    );
    h.reply(r, &[], "OK");
    h.expect("@id=k1 DELETE #general 1");
}

#[test]
fn a_delete_for_a_dropped_room_is_never_sent() {
    let mut h = H::new(ALICE);
    h.joined("k1", 3);
    let r = h.reconnect();
    let (gone, out) = h.engine.delete(&conv("#general"), seq(2)).unwrap();
    h.absorb(out);
    // The room was dropped and created again: seq 2 is another message.
    h.reply(r, &["CONV #general k2 1 0"], "OK");
    h.expect("HISTORY #general after=0 limit=50");
    h.idle();
    assert_eq!(
        h.store.outbox_item(gone).unwrap().unwrap().state,
        OutboxState::Failed(FailReason::RoomChanged)
    );
}

#[test]
fn messages_for_a_room_an_identity_left_fail() {
    // PLAN.md 5, item 34: an identity's queued messages for a room it has
    // left fail, and new ones are refused. DELETEs still go out (5.4).
    let mut h = H::new(ALICE);
    h.joined("k1", 3);
    let r = h.reconnect();
    let (msg, out) = h
        .engine
        .send(&conv("#general"), &Draft::text("hi"))
        .unwrap();
    h.absorb(out);
    let (delete, out) = h.engine.delete(&conv("#general"), seq(2)).unwrap();
    h.absorb(out);
    h.idle();
    // SYNC does not list the room: kicked meanwhile.
    h.reply(r, &[], "OK");
    assert!(!h.conv("#general").joined);
    assert_eq!(
        h.store.outbox_item(msg).unwrap().unwrap().state,
        OutboxState::Failed(FailReason::NotInRoom)
    );
    h.expect("@id=k1 DELETE #general 2");
    assert_eq!(
        h.store.outbox_item(delete).unwrap().unwrap().state,
        OutboxState::Sending
    );
    assert!(matches!(
        h.engine.send(&conv("#general"), &Draft::text("again")),
        Err(SyncError::NotJoined(_))
    ));
}

#[test]
fn a_guests_messages_wait_for_its_rooms() {
    // A guest rejoins its rooms by itself after a reconnect (4.2), so its
    // messages wait rather than fail.
    let mut h = H::new("~sam");
    h.joined("k1", 3);
    let r = h.reconnect();
    let (msg, out) = h
        .engine
        .send(&conv("#general"), &Draft::text("hi"))
        .unwrap();
    h.absorb(out);
    h.reply(r, &[], "OK");
    assert_eq!(
        h.store.outbox_item(msg).unwrap().unwrap().state,
        OutboxState::Queued
    );
    assert!(
        h.engine
            .send(&conv("#general"), &Draft::text("again"))
            .is_ok()
    );
}
