//! A simulated server for testing the sync engine, and the property test
//! that runs it.
//!
//! The server keeps every incarnation of each room (a room dropped and
//! created again is a new incarnation with a new id, 10.4), so the checks
//! can compare what a client stored with the incarnation it claims to have.
//! One identity, `alice`, is observed from three engines: devices 0 and 1
//! have their own stores, and device 2 shares device 0's store, as an iOS
//! notification extension shares the app's (PLAN.md 3.3). Everyone else
//! (`bob`, moderators, operators, retention) is the environment, and acts
//! at any time.
//!
//! A connection's replies can be staged: computed, but sent later, so live
//! events from other connections get ahead of them, as on a real server
//! that reads a page and then queues it.
//!
//! Each store also has a chat list, as an app shows it, fed every change
//! the engines on that store report. Device 0's store also holds a guest
//! account on another server, so the list spans servers. After every
//! step, applying the list's diffs must give the rows and counts of a
//! fresh list with the same filter and window.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use proptest::prelude::*;
use risala_proto::command::Command;
use risala_proto::error::ErrorCode;
use risala_proto::names::{Conv, Id, Room, Seq, Uid};
use risala_proto::server::{
    ErrResponse, Event, EventBody, EventMeta, Message, OkResponse, ServerLine, ServerMessage,
};
use risala_proto::time::Timestamp;
use risala_proto::types::{Relation, RoomSetting};

use super::{Clock, Outcome, Reply, ReqId, SyncConfig, SyncEngine};
use crate::addr::ServerAddr;
use crate::client::chats::{ChatListDiff, ChatState};
use crate::client::{ChatCounts, ChatSummary};
use crate::store::{AccountId, Change, ChatQuery, Draft, OutboxState, Store};

pub(super) const ME: &str = "alice@example.org";
const BOB: &str = "bob@example.org";
pub(super) const ROOMS: [&str; 2] = ["#a", "#b"];
const DEVICES: usize = 3;

fn uid(s: &str) -> Uid {
    s.parse().unwrap()
}

fn room(i: u8) -> Room {
    ROOMS[usize::from(i) % ROOMS.len()].parse().unwrap()
}

/// Prints what happens if `RISALA_SIM_TRACE` is set, to follow a failing
/// case: `RISALA_SIM_TRACE=1 cargo test <test> -- --nocapture`.
fn trace(f: impl FnOnce() -> String) {
    if std::env::var_os("RISALA_SIM_TRACE").is_some() {
        eprintln!("{}", f());
    }
}

// ---------------------------------------------------------------------------
// The server

#[derive(Debug, Clone)]
struct SimEvent {
    from: Uid,
    t: Timestamp,
    /// The event as first sent; MSG keeps its text.
    body: EventBody,
    deleted: bool,
    expired: bool,
}

impl SimEvent {
    fn msg(&self) -> Option<&Message> {
        match &self.body {
            EventBody::Msg(m) => Some(m),
            _ => None,
        }
    }

    fn is_base(&self) -> bool {
        self.msg()
            .is_some_and(|m| matches!(m.relation, None | Some(Relation::Reply(_))))
    }
}

#[derive(Debug)]
struct Inc {
    id: Id,
    room: Room,
    log: Vec<SimEvent>,
    members: BTreeSet<Uid>,
    alive: bool,
    read: u64,
}

impl Inc {
    fn head(&self) -> u64 {
        self.log.len() as u64
    }

    fn wire(&self, seq: u64) -> Event {
        let e = &self.log[(seq - 1) as usize];
        let mut body = e.body.clone();
        if e.deleted
            && let EventBody::Msg(m) = &mut body
        {
            m.deleted = true;
            m.text.clear();
            m.file = None;
        }
        Event::new(
            EventMeta {
                seq: Seq::new(seq).unwrap(),
                t: e.t,
                from: e.from.clone(),
            },
            body,
        )
    }

    fn kept(&self) -> impl Iterator<Item = u64> + '_ {
        (1..=self.head()).filter(|&s| !self.log[(s - 1) as usize].expired)
    }

    /// The text a client should show for base message `seq` (5.3).
    fn current_text(&self, seq: u64) -> String {
        let base = &self.log[(seq - 1) as usize];
        if base.deleted {
            return String::new();
        }
        let mut text = base.msg().unwrap().text.clone();
        for e in &self.log {
            if let Some(m) = e.msg()
                && m.relation == Some(Relation::Edit(Seq::new(seq).unwrap()))
                && !e.deleted
                && e.from == base.from
            {
                text = m.text.clone();
            }
        }
        text
    }
}

/// A line or a reply, in the order a connection receives them.
#[derive(Debug)]
enum Item {
    Line(ServerMessage),
    Reply(ReqId, Reply),
}

struct Conn {
    engine: SyncEngine,
    /// Commands sent, not yet handled by the server.
    requests: VecDeque<(ReqId, Command)>,
    /// A reply computed but not yet sent.
    staged: Option<(ReqId, Reply)>,
    inbox: VecDeque<Item>,
}

struct Device {
    store: Store,
    account: AccountId,
    conn: Option<Conn>,
}

/// A chat list on one store, with the rows its diffs give.
struct List {
    state: ChatState,
    /// The rows and counts as an app applying the diffs has them.
    shown: Vec<ChatSummary>,
    counts: ChatCounts,
}

impl List {
    fn new(store: &Store) -> List {
        let state = ChatState::new(store.clone(), ChatQuery::default(), 1).unwrap();
        List {
            shown: state.items(),
            counts: state.counts(),
            state,
        }
    }

    fn show(&mut self, diffs: Vec<ChatListDiff>) {
        for diff in diffs {
            match diff {
                ChatListDiff::Reset { items } => self.shown = items,
                ChatListDiff::Insert { index, item } => self.shown.insert(index as usize, item),
                ChatListDiff::Update { index, item } => self.shown[index as usize] = item,
                ChatListDiff::Remove { index } => {
                    self.shown.remove(index as usize);
                }
            }
        }
        self.counts = self.state.counts();
    }

    fn apply(&mut self, changes: &[Change]) {
        let diffs = self.state.apply(changes).unwrap();
        self.show(diffs);
    }
}

/// One action of the simulation. Numbers are taken modulo what they
/// choose from.
#[derive(Debug, Clone)]
pub(super) enum Action {
    // The environment.
    Post(u8),
    Edit(u8, u8),
    React(u8, u8),
    Delete(u8, u8),
    KickMe(u8),
    BobJoin(u8),
    Expire(u8),
    Drop(u8),
    Create(u8),
    TimePasses,
    // Connections.
    Connect(u8),
    Disconnect(u8),
    /// The connection drops, and the device connects again at once.
    Reconnect(u8),
    Handle(u8, bool),
    Flush(u8),
    Deliver(u8),
    // The user.
    Join(u8, u8),
    Part(u8, u8),
    Send(u8, u8),
    LoadOlder(u8, u8),
    Fetch(u8, u8, u8),
    Download(u8, u8),
    MarkRead(u8, u8),
    // The user, in the chat list.
    Favourite(u8, u8),
    ListFilter(u8, u8),
    ListMore(u8),
}

pub(super) struct World {
    incs: Vec<Inc>,
    clock: Arc<AtomicU64>,
    max_page: u64,
    /// (cid, incarnation) to seq: cids match within one id (7.6).
    cids: HashMap<(String, usize), u64>,
    devices: Vec<Device>,
    /// The chat lists of devices 0 (whose store device 2 shares) and 1.
    lists: [List; 2],
    config: SyncConfig,
    sends: u32,
    /// Engine calls that failed.
    errors: Vec<String>,
}

impl World {
    pub(super) fn new(page_size: u64, max_page: u64, lazy_gap: Option<u64>) -> World {
        let clock = Arc::new(AtomicU64::new(1_800_000_000_000));
        let c = clock.clone();
        let config = SyncConfig {
            page_size,
            lazy_gap,
            resend_window: Duration::from_secs(23 * 3600),
            clock: Clock::new(move || {
                Timestamp::from_unix_millis(c.load(Ordering::SeqCst)).unwrap()
            }),
            fetch_blocks: false,
            ..SyncConfig::default()
        };
        let server: ServerAddr = "chat.example.org".parse().unwrap();
        let shared = Store::open_in_memory().unwrap();
        let mut devices = Vec::new();
        for d in 0..DEVICES {
            let store = if d == 2 {
                devices.first().map(|d: &Device| d.store.clone()).unwrap()
            } else if d == 0 {
                shared.clone()
            } else {
                Store::open_in_memory().unwrap()
            };
            let account = store.account(&server, &uid(ME)).unwrap();
            devices.push(Device {
                store,
                account,
                conn: None,
            });
        }
        // Another account on another server, with one room, in the middle
        // of the chat list until alice's rooms move past it.
        let other: ServerAddr = "other.example".parse().unwrap();
        let sam = shared.account(&other, &uid("~sam")).unwrap();
        shared
            .write(|tx| {
                tx.at(Timestamp::from_unix_millis(1_799_999_999_000).unwrap());
                let mut row = tx.conv_or_create(sam, &"#z".parse().unwrap())?;
                tx.learn_id(&mut row, &"z1".parse().unwrap(), Some(1))?;
                tx.set_joined(&mut row, true)?;
                let line: ServerMessage = "@seq=1;t=2027-01-15T08:00:00.010Z;from=~kim MSG #z hi"
                    .parse()
                    .unwrap();
                let ServerLine::Event(e) = line.line else {
                    unreachable!()
                };
                tx.store_event(&row, &e)?;
                tx.raise_sync_point(&mut row, 1)
            })
            .unwrap();
        let lists = [List::new(&devices[0].store), List::new(&devices[1].store)];
        let mut w = World {
            incs: Vec::new(),
            clock,
            max_page,
            cids: HashMap::new(),
            devices,
            lists,
            config,
            sends: 0,
            errors: Vec::new(),
        };
        for i in 0..ROOMS.len() as u8 {
            w.create(i);
        }
        w
    }

    fn now(&self) -> Timestamp {
        let ms = self.clock.fetch_add(1, Ordering::SeqCst) + 1;
        Timestamp::from_unix_millis(ms).unwrap()
    }

    fn alive(&self, r: &Room) -> Option<usize> {
        self.incs.iter().position(|i| i.alive && i.room == *r)
    }

    fn inc_by_id(&self, id: &Id) -> Option<usize> {
        self.incs.iter().position(|i| i.id == *id)
    }

    /// Sends a line to every connection of the observed identity, if it is
    /// in incarnation `inc` (5.2).
    fn send_to_me(&mut self, inc: usize, msg: &ServerMessage) {
        if !self.incs[inc].members.contains(&uid(ME)) {
            return;
        }
        for d in &mut self.devices {
            if let Some(c) = &mut d.conn {
                c.inbox.push_back(Item::Line(msg.clone()));
            }
        }
    }

    /// Appends an event and sends it to the members' connections.
    fn append(&mut self, inc: usize, from: &str, body: EventBody) -> u64 {
        let t = self.now();
        let i = &mut self.incs[inc];
        i.log.push(SimEvent {
            from: uid(from),
            t,
            body,
            deleted: false,
            expired: false,
        });
        let seq = i.head();
        let msg = ServerMessage::new(ServerLine::Event(i.wire(seq)));
        self.send_to_me(inc, &msg);
        seq
    }

    fn create(&mut self, r: u8) {
        let room = room(r);
        if self.alive(&room).is_some() {
            return;
        }
        let id: Id = format!("i{}", self.incs.len()).parse().unwrap();
        self.incs.push(Inc {
            id: id.clone(),
            room: room.clone(),
            log: Vec::new(),
            members: BTreeSet::from([uid(BOB)]),
            alive: true,
            read: 0,
        });
        let inc = self.incs.len() - 1;
        self.append(inc, BOB, EventBody::Join { room, id });
    }

    fn bob_in(&self, r: u8) -> Option<usize> {
        self.alive(&room(r))
            .filter(|&i| self.incs[i].members.contains(&uid(BOB)))
    }

    /// The `k`th seq among those of `inc` that pass `f`.
    fn pick(&self, inc: usize, k: u8, f: impl Fn(&SimEvent) -> bool) -> Option<u64> {
        let seqs: Vec<u64> = self.incs[inc]
            .kept()
            .filter(|&s| f(&self.incs[inc].log[(s - 1) as usize]))
            .collect();
        (!seqs.is_empty()).then(|| seqs[usize::from(k) % seqs.len()])
    }

    fn post(&mut self, inc: usize, from: &str, relation: Option<Relation>, text: String) -> u64 {
        let conv = Conv::Room(self.incs[inc].room.clone());
        let msg = Message {
            conv,
            relation,
            file: None,
            deleted: false,
            text,
        };
        self.append(inc, from, EventBody::Msg(msg))
    }

    /// Deletes message `seq` and, for a message, its edits and reactions
    /// (5.4).
    fn delete(&mut self, inc: usize, seq: u64) {
        let i = &mut self.incs[inc];
        let base = i.log[(seq - 1) as usize].is_base();
        let target = Seq::new(seq).unwrap();
        for e in &mut i.log {
            let related = base
                && e.msg().is_some_and(|m| {
                    matches!(m.relation, Some(Relation::Edit(t) | Relation::React(t)) if t == target)
                });
            if related {
                e.deleted = true;
            }
        }
        i.log[(seq - 1) as usize].deleted = true;
        let conv = Conv::Room(i.room.clone());
        self.append(inc, BOB, EventBody::Delete { conv, seq: target });
    }

    // -----------------------------------------------------------------------
    // Requests

    /// Runs one command for device `d` and returns its reply. Live events
    /// it causes go out first (3.6).
    fn exec(&mut self, d: usize, command: Command) -> Reply {
        let me = uid(ME);
        let ok = |o: OkResponse| Outcome::Ok(o);
        let err = |c: ErrorCode| Outcome::Err(ErrResponse::new(c));
        let mut lines = Vec::new();
        let outcome = match command {
            Command::Sync => {
                for i in self
                    .incs
                    .iter()
                    .filter(|i| i.alive && i.members.contains(&me))
                {
                    lines.push(ServerMessage::new(ServerLine::Conv {
                        conv: Conv::Room(i.room.clone()),
                        id: i.id.clone(),
                        head: Seq::new(i.head()).unwrap(),
                        read: Seq::new(i.read),
                    }));
                }
                ok(OkResponse::new())
            }
            Command::Join { room } => {
                let inc = match self.alive(&room) {
                    Some(inc) => inc,
                    None => {
                        // 6.1: an identity may create the room.
                        let id: Id = format!("i{}", self.incs.len()).parse().unwrap();
                        self.incs.push(Inc {
                            id,
                            room: room.clone(),
                            log: Vec::new(),
                            members: BTreeSet::new(),
                            alive: true,
                            read: 0,
                        });
                        self.incs.len() - 1
                    }
                };
                if !self.incs[inc].members.contains(&me) {
                    self.incs[inc].members.insert(me.clone());
                    let id = self.incs[inc].id.clone();
                    self.append(
                        inc,
                        ME,
                        EventBody::Join {
                            room: room.clone(),
                            id,
                        },
                    );
                }
                lines.push(ServerMessage::new(ServerLine::Event(Event::snapshot(
                    EventBody::Set {
                        room: room.clone(),
                        setting: RoomSetting::Topic(format!("topic of {}", self.incs[inc].id)),
                    },
                ))));
                let i = &self.incs[inc];
                ok(OkResponse::new()
                    .with_id(&i.id)
                    .with_head(Seq::new(i.head()).unwrap()))
            }
            Command::Part { room, reason } => match self.alive(&room) {
                Some(inc) if self.incs[inc].members.contains(&me) => {
                    self.append(inc, ME, EventBody::Part { room, reason });
                    self.incs[inc].members.remove(&me);
                    ok(OkResponse::new())
                }
                _ => err(ErrorCode::NotFound),
            },
            Command::Msg {
                conv,
                text,
                relation,
                cid,
                ..
            } => match conv.room().and_then(|r| self.alive(r)) {
                Some(inc) if self.incs[inc].members.contains(&me) => {
                    let cid = cid.expect("the outbox always sets a cid").to_string();
                    let seq = match self.cids.get(&(cid.clone(), inc)) {
                        Some(&seq) => seq,
                        None => {
                            let seq = self.post(inc, ME, relation, text);
                            self.cids.insert((cid, inc), seq);
                            seq
                        }
                    };
                    ok(OkResponse::new().with_seq(Seq::new(seq).unwrap()))
                }
                Some(_) => err(ErrorCode::Forbidden),
                None => err(ErrorCode::NotFound),
            },
            Command::History {
                conv,
                after,
                before,
                limit,
                ..
            } => match conv.room().and_then(|r| self.alive(r)) {
                Some(inc) => {
                    let i = &self.incs[inc];
                    let lim = limit.map_or(50, |l| l.get()).min(self.max_page) as usize;
                    let below = |s: u64| before.is_none_or(|b| s < b.get());
                    let (page, more) = match after {
                        Some(a) => {
                            let all: Vec<u64> = i.kept().filter(|&s| s > a && below(s)).collect();
                            let more = all.len() > lim;
                            (all.into_iter().take(lim).collect::<Vec<_>>(), more)
                        }
                        None => {
                            let all: Vec<u64> = i.kept().filter(|&s| below(s)).collect();
                            let more = all.len() > lim;
                            (all[all.len().saturating_sub(lim)..].to_vec(), more)
                        }
                    };
                    for s in page {
                        lines.push(ServerMessage::new(ServerLine::Event(i.wire(s))));
                    }
                    ok(OkResponse::new().with_id(&i.id).with_more(more))
                }
                None => err(ErrorCode::NotFound),
            },
            Command::Related {
                conv,
                first,
                last,
                after,
                limit,
            } => match conv.room().and_then(|r| self.alive(r)) {
                Some(inc) => {
                    let i = &self.incs[inc];
                    let lim = limit.map_or(50, |l| l.get()).min(self.max_page) as usize;
                    let all: Vec<u64> = i
                        .kept()
                        .filter(|&s| s > after.unwrap_or(0))
                        .filter(|&s| {
                            i.log[(s - 1) as usize].msg().is_some_and(|m| {
                                matches!(m.relation,
                                    Some(Relation::Edit(t) | Relation::React(t))
                                        if first <= t && t <= last)
                            })
                        })
                        .collect();
                    let more = all.len() > lim;
                    for &s in all.iter().take(lim) {
                        lines.push(ServerMessage::new(ServerLine::Event(i.wire(s))));
                    }
                    ok(OkResponse::new().with_id(&i.id).with_more(more))
                }
                None => err(ErrorCode::NotFound),
            },
            Command::Read { conv, seq } => match conv.room().and_then(|r| self.alive(r)) {
                Some(inc) => {
                    let i = &mut self.incs[inc];
                    let new = seq.get().min(i.head());
                    if new > i.read {
                        i.read = new;
                        let line = ServerMessage::new(ServerLine::Read {
                            conv,
                            seq: Seq::new(new).unwrap(),
                        });
                        for (n, dev) in self.devices.iter_mut().enumerate() {
                            if n != d
                                && let Some(c) = &mut dev.conn
                            {
                                c.inbox.push_back(Item::Line(line.clone()));
                            }
                        }
                    }
                    ok(OkResponse::new())
                }
                None => err(ErrorCode::NotFound),
            },
            _ => err(ErrorCode::NotSupported),
        };
        Reply { lines, outcome }
    }

    // -----------------------------------------------------------------------
    // Running

    /// Hands an engine's commands to its connection, checking each MSG
    /// against the outbox as it is sent.
    fn take_output(&mut self, d: usize, out: Result<super::Output, super::SyncError>) {
        let out = match out {
            Ok(out) => out,
            Err(e) => {
                self.errors.push(e.to_string());
                return;
            }
        };
        self.lists[list_of(d)].apply(&out.changes);
        let now = Timestamp::from_unix_millis(self.clock.load(Ordering::SeqCst)).unwrap();
        let dev = &self.devices[d];
        for o in &out.send {
            if let Command::Msg { conv, cid, .. } = &o.command {
                let cid = cid.as_ref().unwrap();
                let item = dev
                    .store
                    .outbox(dev.account)
                    .unwrap()
                    .into_iter()
                    .find(|i| i.cid == *cid)
                    .expect("a MSG comes from the outbox");
                // 7.6: never into a conversation other than the one it is
                // bound to, as far as the store knows.
                let stored = dev
                    .store
                    .conversation(dev.account, conv)
                    .unwrap()
                    .and_then(|c| c.conv_id);
                assert_eq!(
                    item.conv_id, stored,
                    "MSG bound to {:?} sent while the store has {stored:?}",
                    item.conv_id
                );
                // And not after the server may have forgotten the cid.
                if let Some(first) = item.first_sent {
                    assert!(
                        now.saturating_duration_since(first) < Duration::from_secs(24 * 3600),
                        "resent after 24 hours"
                    );
                }
            }
        }
        let conn = self.devices[d].conn.as_mut().unwrap();
        for o in out.send {
            trace(|| format!("  d{d} sends #{}: {:?}", o.req.get(), o.command));
            conn.requests.push_back((o.req, o.command));
        }
    }

    fn device(&self, d: u8) -> usize {
        usize::from(d) % DEVICES
    }

    /// The chat filter numbered `n`: a server or none, and each toggle.
    fn filter(n: u8) -> ChatQuery {
        ChatQuery {
            server: match n % 3 {
                0 => None,
                1 => Some("chat.example.org".into()),
                _ => Some("other.example".into()),
            },
            unread: n & 4 != 0,
            favourites: n & 8 != 0,
            rooms: n & 16 != 0,
        }
    }

    pub(super) fn step(&mut self, action: &Action) {
        if !matches!(
            action,
            Action::Flush(_) | Action::Handle(..) | Action::Deliver(_)
        ) {
            trace(|| format!("{action:?}"));
        }
        match *action {
            Action::Post(r) => {
                if let Some(inc) = self.bob_in(r) {
                    let text = format!("m{inc}x{}", self.incs[inc].head() + 1);
                    self.post(inc, BOB, None, text);
                }
            }
            Action::Edit(r, k) => {
                if let Some(inc) = self.bob_in(r)
                    && let Some(t) =
                        self.pick(inc, k, |e| e.is_base() && !e.deleted && e.from == uid(BOB))
                {
                    let text = format!("e{inc}x{}", self.incs[inc].head() + 1);
                    self.post(inc, BOB, Some(Relation::Edit(Seq::new(t).unwrap())), text);
                }
            }
            Action::React(r, k) => {
                if let Some(inc) = self.bob_in(r)
                    && let Some(t) = self.pick(inc, k, |e| e.is_base() && !e.deleted)
                {
                    let text = format!("r{}", k % 3);
                    self.post(inc, BOB, Some(Relation::React(Seq::new(t).unwrap())), text);
                }
            }
            Action::Delete(r, k) => {
                if let Some(inc) = self.bob_in(r)
                    && let Some(t) = self.pick(inc, k, |e| e.msg().is_some() && !e.deleted)
                {
                    self.delete(inc, t);
                }
            }
            Action::KickMe(r) => {
                if let Some(inc) = self.bob_in(r)
                    && self.incs[inc].members.contains(&uid(ME))
                {
                    let room = self.incs[inc].room.clone();
                    let body = EventBody::Kick {
                        room,
                        uid: uid(ME),
                        reason: "out".into(),
                    };
                    self.append(inc, BOB, body);
                    self.incs[inc].members.remove(&uid(ME));
                }
            }
            Action::BobJoin(r) => {
                if let Some(inc) = self.alive(&room(r))
                    && !self.incs[inc].members.contains(&uid(BOB))
                {
                    self.incs[inc].members.insert(uid(BOB));
                    let id = self.incs[inc].id.clone();
                    self.append(inc, BOB, EventBody::Join { room: room(r), id });
                }
            }
            Action::Expire(r) => {
                let first = self
                    .alive(&room(r))
                    .and_then(|i| Some((i, self.incs[i].kept().next()?)));
                if let Some((inc, s)) = first {
                    self.incs[inc].log[(s - 1) as usize].expired = true;
                }
            }
            Action::Drop(r) => {
                if let Some(inc) = self.alive(&room(r)) {
                    let line = ServerMessage::new(ServerLine::Drop {
                        room: room(r),
                        id: self.incs[inc].id.clone(),
                        reason: String::new(),
                    });
                    self.send_to_me(inc, &line);
                    let i = &mut self.incs[inc];
                    i.alive = false;
                    i.members.clear();
                }
            }
            Action::Create(r) => self.create(r),
            Action::TimePasses => {
                self.clock.fetch_add(25 * 3600 * 1000, Ordering::SeqCst);
            }
            Action::Connect(d) => {
                let d = self.device(d);
                if self.devices[d].conn.is_none() {
                    let dev = &self.devices[d];
                    let mut engine =
                        SyncEngine::new(dev.store.clone(), dev.account, self.config.clone())
                            .unwrap();
                    let out = engine.start();
                    self.devices[d].conn = Some(Conn {
                        engine,
                        requests: VecDeque::new(),
                        staged: None,
                        inbox: VecDeque::new(),
                    });
                    self.take_output(d, out);
                }
            }
            Action::Disconnect(d) => {
                let d = self.device(d);
                self.devices[d].conn = None;
            }
            Action::Reconnect(d) => {
                self.step(&Action::Disconnect(d));
                self.step(&Action::Connect(d));
            }
            Action::Handle(d, stage) => {
                let d = self.device(d);
                let Some(conn) = &mut self.devices[d].conn else {
                    return;
                };
                if conn.staged.is_some() {
                    return;
                }
                let Some((req, command)) = conn.requests.pop_front() else {
                    return;
                };
                trace(|| format!("  server runs d{d} #{}: {command:?}", req.get()));
                let reply = self.exec(d, command);
                trace(|| format!("    -> {reply:?}"));
                let conn = self.devices[d].conn.as_mut().unwrap();
                if stage {
                    conn.staged = Some((req, reply));
                } else {
                    conn.inbox.push_back(Item::Reply(req, reply));
                }
            }
            Action::Flush(d) => {
                let d = self.device(d);
                if let Some(conn) = &mut self.devices[d].conn
                    && let Some((req, reply)) = conn.staged.take()
                {
                    conn.inbox.push_back(Item::Reply(req, reply));
                }
            }
            Action::Deliver(d) => {
                let d = self.device(d);
                let Some(conn) = &mut self.devices[d].conn else {
                    return;
                };
                let Some(item) = conn.inbox.pop_front() else {
                    return;
                };
                trace(|| format!("  d{d} handles {item:?}"));
                let out = match item {
                    Item::Line(line) => conn.engine.handle_line(&line),
                    Item::Reply(req, reply) => conn.engine.handle_reply(req, reply),
                };
                self.take_output(d, out);
            }
            Action::Join(d, r) => self.user(d, |e| Ok(e.join(&room(r)))),
            Action::Part(d, r) => self.user(d, |e| Ok(e.part(&room(r), ""))),
            Action::Send(d, r) => {
                self.sends += 1;
                let text = format!("s{}", self.sends);
                self.user(d, |e| {
                    match e.send(&Conv::Room(room(r)), &Draft::text(text)) {
                        Ok((_, out)) => Ok(out),
                        Err(super::SyncError::NotJoined(_)) => Ok(super::Output::default()),
                        Err(e) => Err(e),
                    }
                });
            }
            Action::LoadOlder(d, r) => self.user(d, |e| e.load_older(&Conv::Room(room(r)))),
            Action::Fetch(d, r, s) => {
                let seq = Seq::new(u64::from(s % 12) + 1).unwrap();
                self.user(d, |e| e.fetch(&Conv::Room(room(r)), seq));
            }
            Action::Download(d, r) => self.user(d, |e| e.download(&Conv::Room(room(r)))),
            Action::MarkRead(d, r) => {
                let d2 = self.device(d);
                let conv = Conv::Room(room(r));
                let dev = &self.devices[d2];
                let newest = dev
                    .store
                    .conversation(dev.account, &conv)
                    .unwrap()
                    .and_then(|c| c.newest);
                if let Some(seq) = newest {
                    self.user(d, |e| e.mark_read(&conv, seq));
                }
            }
            Action::Favourite(d, r) => {
                let d = self.device(d);
                let dev = &self.devices[d];
                let conv = Conv::Room(room(r));
                if let Some(c) = dev.store.conversation(dev.account, &conv).unwrap() {
                    let on = !dev
                        .store
                        .chat_row(c.id)
                        .unwrap()
                        .is_some_and(|row| row.favourite);
                    let changes = dev.store.set_favourite(c.id, on).unwrap();
                    self.lists[list_of(d)].apply(&changes);
                }
            }
            Action::ListFilter(d, n) => {
                let list = &mut self.lists[list_of(self.device(d))];
                let diffs = list.state.set_query(World::filter(n)).unwrap();
                list.show(diffs);
            }
            Action::ListMore(d) => {
                let list = &mut self.lists[list_of(self.device(d))];
                let diffs = list.state.widen(1).unwrap();
                list.show(diffs);
            }
        }
    }

    fn user(
        &mut self,
        d: u8,
        f: impl FnOnce(&mut SyncEngine) -> Result<super::Output, super::SyncError>,
    ) {
        let d = self.device(d);
        if let Some(conn) = &mut self.devices[d].conn {
            let out = f(&mut conn.engine);
            self.take_output(d, out);
        }
    }

    /// Runs every connection until nothing is left to do, with every
    /// device connected and the environment quiet. With `download`, also
    /// asks every engine to fill its gaps.
    pub(super) fn settle(&mut self, download: bool) {
        for d in 0..DEVICES as u8 {
            self.step(&Action::Connect(d));
        }
        let mut downloaded = false;
        for _ in 0..3_000 {
            let mut busy = false;
            for d in 0..DEVICES {
                let conn = self.devices[d].conn.as_ref().unwrap();
                let work =
                    conn.staged.is_some() || !conn.requests.is_empty() || !conn.inbox.is_empty();
                if work {
                    busy = true;
                    self.step(&Action::Flush(d as u8));
                    self.step(&Action::Handle(d as u8, false));
                    self.step(&Action::Deliver(d as u8));
                }
            }
            if busy {
                continue;
            }
            if download && !downloaded {
                downloaded = true;
                for d in 0..DEVICES as u8 {
                    for r in 0..ROOMS.len() as u8 {
                        self.step(&Action::Download(d, r));
                    }
                }
                continue;
            }
            return;
        }
        panic!("the simulation did not settle");
    }

    // -----------------------------------------------------------------------
    // Checks

    /// Checks what must hold after every step.
    pub(super) fn check(&self) {
        assert!(self.errors.is_empty(), "engine errors: {:?}", self.errors);
        // A chat list's diffs give what reading it afresh gives.
        for (n, list) in self.lists.iter().enumerate() {
            let fresh = ChatState::new(
                self.devices[n].store.clone(),
                list.state.query().clone(),
                list.state.limit(),
            )
            .unwrap();
            assert_eq!(list.shown, fresh.items(), "chat list {n}: rows");
            assert_eq!(list.counts, fresh.counts(), "chat list {n}: counts");
        }
        // At most one event per outbox message per conversation id (7.6).
        for i in &self.incs {
            let mut seen = BTreeSet::new();
            for e in &i.log {
                if e.from == uid(ME)
                    && let Some(m) = e.msg()
                {
                    assert!(
                        seen.insert(m.text.clone()),
                        "{} sent twice in {}",
                        m.text,
                        i.id
                    );
                }
            }
        }
        for (n, dev) in self.devices.iter().enumerate() {
            if n == 2 {
                continue; // shares device 0's store
            }
            for c in dev.store.conversations(dev.account).unwrap() {
                let lines = dev.store.export(c.id).unwrap();
                let Some(id) = &c.conv_id else {
                    assert!(lines.is_empty(), "events stored without an id");
                    continue;
                };
                let inc = &self.incs[self.inc_by_id(id).expect("ids come from the server")];
                let mut stored = BTreeSet::new();
                for line in &lines {
                    let msg: ServerMessage = line.parse().unwrap();
                    let ServerLine::Event(e) = msg.line else {
                        panic!("{line}")
                    };
                    let meta = e.meta.unwrap();
                    let s = meta.seq.get();
                    stored.insert(s);
                    // No mixed history: the event is incarnation inc's.
                    let orig = inc
                        .log
                        .get((s - 1) as usize)
                        .unwrap_or_else(|| panic!("device {n} has {s} beyond {}'s head", inc.id));
                    assert_eq!(
                        (meta.t, &meta.from),
                        (orig.t, &orig.from),
                        "device {n} mixed {}",
                        inc.id
                    );
                    assert_eq!(e.body.verb(), orig.body.verb());
                    if let (EventBody::Msg(m), Some(o)) = (&e.body, orig.msg()) {
                        if m.deleted {
                            assert!(orig.deleted, "deleted on the client only");
                            assert!(m.text.is_empty());
                        } else {
                            assert_eq!(m.text, o.text);
                        }
                    }
                    if let (EventBody::Join { id: a, .. }, EventBody::Join { id: b, .. }) =
                        (&e.body, &orig.body)
                    {
                        assert_eq!(a, b);
                    }
                }
                // The sync point is truthful (7.1).
                assert!(
                    c.sync_point <= inc.head(),
                    "device {n}: sync point {} beyond {}'s head {}: {c:?}, {lines:?}",
                    c.sync_point,
                    inc.id,
                    inc.head()
                );
                for s in 1..=c.sync_point {
                    assert!(
                        stored.contains(&s) || inc.log[(s - 1) as usize].expired,
                        "device {n}: sync point {} of {} passes missing {s}",
                        c.sync_point,
                        inc.id
                    );
                }
            }
            // 7.6: an OK names our own message.
            for item in dev.store.outbox(dev.account).unwrap() {
                if let OutboxState::Sent(seq) = item.state {
                    let ours = self.incs.iter().any(|i| {
                        i.log.get((seq.get() - 1) as usize).is_some_and(|e| {
                            e.from == uid(ME) && e.msg().is_some_and(|m| m.text == item.draft.text)
                        })
                    });
                    assert!(
                        ours,
                        "{} acknowledged as someone else's {seq}",
                        item.draft.text
                    );
                }
            }
        }
    }

    /// Checks what must hold once settled: every engine has caught up.
    pub(super) fn check_settled(&self) {
        self.check();
        for (n, dev) in self.devices.iter().enumerate() {
            let conn = dev.conn.as_ref().unwrap();
            for inc in self.incs.iter().filter(|i| i.alive) {
                let conv = Conv::Room(inc.room.clone());
                let c = dev.store.conversation(dev.account, &conv).unwrap();
                if !inc.members.contains(&uid(ME)) {
                    if let Some(c) = c {
                        assert!(!c.joined, "device {n} thinks it is in {}", inc.room);
                    }
                    continue;
                }
                let c = c.unwrap_or_else(|| panic!("device {n} lacks {}", inc.room));
                assert_eq!(
                    c.conv_id.as_ref(),
                    Some(&inc.id),
                    "device {n}, {}",
                    inc.room
                );
                assert!(c.joined);
                assert!(conn.engine.is_live(&conv));
                assert_eq!(
                    c.sync_point,
                    inc.head(),
                    "device {n} has not caught up in {}",
                    inc.id
                );
                for s in inc.kept() {
                    let e = &inc.log[(s - 1) as usize];
                    let seq = Seq::new(s).unwrap();
                    let lines = dev.store.export(c.id).unwrap();
                    let line = lines
                        .iter()
                        .find(|l| l.starts_with(&format!("@seq={s};")))
                        .unwrap_or_else(|| panic!("device {n} lacks {s} of {}", inc.id));
                    let msg: ServerMessage = line.parse().unwrap();
                    let ServerLine::Event(stored) = msg.line else {
                        panic!()
                    };
                    if let EventBody::Msg(m) = &stored.body {
                        assert_eq!(m.deleted, e.deleted, "device {n}: deleted state of {s}");
                    }
                    if e.is_base() {
                        let item = dev.store.message(c.id, seq).unwrap().unwrap();
                        assert_eq!(item.text.unwrap(), inc.current_text(s), "text of {s}");
                        assert_eq!(item.deleted, e.deleted);
                        let mut want: HashMap<String, BTreeSet<Uid>> = HashMap::new();
                        for r in &inc.log {
                            if let Some(m) = r.msg()
                                && m.relation == Some(Relation::React(seq))
                                && !r.deleted
                            {
                                want.entry(m.text.clone())
                                    .or_default()
                                    .insert(r.from.clone());
                            }
                        }
                        let want_n: HashMap<String, u64> =
                            want.into_iter().map(|(k, v)| (k, v.len() as u64)).collect();
                        let got_n: HashMap<String, u64> = item
                            .reactions
                            .iter()
                            .map(|r| (r.reaction.clone(), r.count))
                            .collect();
                        assert_eq!(got_n, want_n, "reactions of {s}");
                    }
                }
            }
            if n != 2 {
                for item in dev.store.outbox(dev.account).unwrap() {
                    // Waiting is fine only where the account is not in the
                    // room: an unanswered message is resent if it rejoins.
                    if matches!(item.state, OutboxState::Sending | OutboxState::Queued) {
                        assert!(
                            !conn.engine.is_live(&item.conv),
                            "{} stuck in {:?}",
                            item.draft.text,
                            item.state
                        );
                    }
                }
            }
        }
    }
}

/// The chat list of device `d`'s store.
fn list_of(d: usize) -> usize {
    if d == 2 { 0 } else { d }
}

fn action() -> impl Strategy<Value = Action> {
    let b = any::<u8>;
    prop_oneof![
        3 => b().prop_map(Action::Post),
        1 => (b(), b()).prop_map(|(r, k)| Action::Edit(r, k)),
        1 => (b(), b()).prop_map(|(r, k)| Action::React(r, k)),
        1 => (b(), b()).prop_map(|(r, k)| Action::Delete(r, k)),
        1 => b().prop_map(Action::KickMe),
        1 => b().prop_map(Action::BobJoin),
        2 => b().prop_map(Action::Expire),
        1 => b().prop_map(Action::Drop),
        2 => b().prop_map(Action::Create),
        1 => Just(Action::TimePasses),
        2 => b().prop_map(Action::Connect),
        2 => b().prop_map(Action::Disconnect),
        2 => b().prop_map(Action::Reconnect),
        8 => (b(), any::<bool>()).prop_map(|(d, s)| Action::Handle(d, s)),
        3 => b().prop_map(Action::Flush),
        12 => b().prop_map(Action::Deliver),
        2 => (b(), b()).prop_map(|(d, r)| Action::Join(d, r)),
        1 => (b(), b()).prop_map(|(d, r)| Action::Part(d, r)),
        3 => (b(), b()).prop_map(|(d, r)| Action::Send(d, r)),
        1 => (b(), b()).prop_map(|(d, r)| Action::LoadOlder(d, r)),
        1 => (b(), b(), b()).prop_map(|(d, r, s)| Action::Fetch(d, r, s)),
        1 => (b(), b()).prop_map(|(d, r)| Action::Download(d, r)),
        1 => (b(), b()).prop_map(|(d, r)| Action::MarkRead(d, r)),
        1 => (b(), b()).prop_map(|(d, r)| Action::Favourite(d, r)),
        1 => (b(), b()).prop_map(|(d, n)| Action::ListFilter(d, n)),
        1 => b().prop_map(Action::ListMore),
    ]
}

/// Runs `actions`, checking after every step, then settles and checks
/// that every engine caught up.
pub(super) fn run(page_size: u64, max_page: u64, lazy: Option<u64>, actions: &[Action]) {
    let mut w = World::new(page_size, max_page, lazy);
    for a in actions {
        w.step(a);
        w.check();
    }
    w.settle(lazy.is_some());
    w.check_settled();
}

proptest! {
    // PROPTEST_CASES=10000 runs more.
    #![proptest_config(ProptestConfig {
        cases: std::env::var("PROPTEST_CASES").ok().and_then(|s| s.parse().ok()).unwrap_or(200),
        ..ProptestConfig::default()
    })]

    /// Full catch-up (7.1 step 3).
    #[test]
    fn sync_converges(
        page in 1u64..4,
        max_page in 1u64..4,
        actions in proptest::collection::vec(action(), 0..300),
    ) {
        run(page, max_page, None, &actions);
    }

    /// The newest page first, then the rest on demand (7.1 step 4, 7.3).
    #[test]
    fn lazy_sync_converges(
        page in 1u64..4,
        max_page in 1u64..4,
        gap in 1u64..4,
        actions in proptest::collection::vec(action(), 0..300),
    ) {
        run(page, max_page, Some(gap), &actions);
    }
}

/// A seq seen live in a dropped room must not move the sync point of the
/// room created again under the same name.
#[test]
fn regression_seq_from_a_dropped_room() {
    use Action::*;
    let actions = [
        Connect(2),
        Join(2, 0),
        Connect(0),
        Handle(2, false),
        Join(2, 0),
        Post(0),
        Handle(2, false),
        Drop(0),
    ];
    run(1, 1, None, &actions);
}

/// Device 0 is offline while its room is dropped, created again and
/// joined from device 1, and the new room grows past what device 0 has.
/// Only SYNC's id tells the rooms apart (7.1 step 2).
#[test]
fn offline_while_the_room_is_recreated() {
    use Action::*;
    let actions = [
        Connect(0),
        Join(0, 0),
        Handle(0, false),
        Handle(0, false),
        Deliver(0),
        Deliver(0),
        Deliver(0),
        Handle(0, false),
        Deliver(0),
        Disconnect(0),
        Drop(0),
        Create(0),
        Post(0),
        Post(0),
        Post(0),
        Post(0),
        Connect(1),
        Join(1, 0),
        Handle(1, false),
        Handle(1, false),
        Post(0),
        Connect(0),
    ];
    let mut w = World::new(5, 5, None);
    for a in &actions[..9] {
        w.step(a);
    }
    // Device 0 has caught up with the first room.
    let dev = &w.devices[0];
    let c = dev
        .store
        .conversation(dev.account, &Conv::Room(room(0)))
        .unwrap()
        .unwrap();
    assert_eq!((c.conv_id.unwrap().as_str(), c.sync_point), ("i0", 2));
    run(5, 5, None, &actions);
}
