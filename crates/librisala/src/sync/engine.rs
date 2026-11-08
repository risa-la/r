//! The [`SyncEngine`] state machine.

use std::collections::{HashMap, HashSet};
use std::num::NonZeroU64;
use std::time::Duration;

use risala_proto::command::{Command, Request};
use risala_proto::error::ErrorCode;
use risala_proto::names::{BlockTarget, Conv, Id, Room, Seq, Uid};
use risala_proto::server::{Event, EventBody, ServerLine, ServerMessage};
use risala_proto::time::Timestamp;
use risala_proto::types::Relation;
use tracing::{debug, warn};

use super::{
    Completed, Notification, Outcome, Outgoing, Output, Reply, ReqId, Signal, SyncConfig, SyncError,
};
use crate::store::{
    AccountId, Claim, ConvId, ConvRow, Draft, FailReason, OutboxId, OutboxState, Store, StoreError,
    Tx,
};

/// After this many failed HISTORY or RELATED requests for one
/// conversation, the engine stops trying on this connection.
const MAX_FAILURES: u32 = 3;

/// How often TYPING is repeated while the user types (8.1). A notice lasts
/// 6 seconds.
pub const TYPING_REPEAT: Duration = Duration::from_secs(4);

/// What this connection knows about one conversation, by name. Everything
/// lasting is in the store.
#[derive(Debug, Default)]
struct Live {
    /// The id learned on this connection from SYNC, JOIN or INFO (7.1 step
    /// 6). Live events are stored only while it matches the stored id.
    confirmed: Option<Id>,
    /// The highest seq of a live event that was not stored because the id
    /// was not confirmed. It says to catch up, but may belong to another
    /// conversation with the same name, so it never moves the sync point.
    dropped: u64,
    /// An automatic HISTORY request (catching up) is in flight.
    filling: bool,
    /// A [`SyncEngine::load_older`] request is in flight.
    loading_older: bool,
    /// Catch up to the end, even across a large gap.
    download: bool,
    /// HISTORY or RELATED failures on this connection, for the id in
    /// `failed_for`.
    failures: u32,
    /// The id the failures were counted for. Confirming the same id again
    /// does not clear them, so a server that lists a conversation in SYNC
    /// but refuses its HISTORY is not asked forever.
    failed_for: Option<Id>,
    /// Catching up made no progress toward a goal, knowing the
    /// conversation reached a seq: `(known, goal)`. The events in between
    /// expired, or the goal is a dropped live event's seq that no head
    /// has covered yet. Do not ask again until either moves: a head
    /// learned while the request was in flight is not covered by its
    /// reply, so it needs a request of its own.
    stuck: Option<(u64, u64)>,
    /// The goal for which the newest page was fetched (7.1 step 4).
    newest_for: Option<u64>,
    /// A live event was dropped while a SYNC was in flight: if the SYNC
    /// does not list the conversation, ask again.
    recheck: bool,
    /// When a live line last showed the account joining, in
    /// [`SyncEngine::ticks`].
    joined_at: u64,
    /// When a live event of the conversation was last handled, in
    /// [`SyncEngine::ticks`]. A head in a reply to a command sent before
    /// then may be older than the events stored.
    event_at: u64,
    /// When a live line last showed the account leaving, or the
    /// conversation changing its id, in [`SyncEngine::ticks`].
    left_at: u64,
}

/// Which slot a HISTORY request occupies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    /// Catching up, from [`SyncEngine::check_fill`].
    Auto,
    /// [`SyncEngine::load_older`].
    Older,
    /// [`SyncEngine::fetch`], which may run alongside the others.
    Extra,
}

/// The shape of a HISTORY request, which says what its page proves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Page {
    /// `after=<after>`: forward from the sync point (7.1 step 3).
    Forward { after: u64 },
    /// No bounds: the newest page (7.1 step 4).
    Newest,
    /// `before=<before>`: the page below `before` (7.3).
    Backward { before: u64 },
}

/// A request in flight, and what to do with its reply.
#[derive(Debug, Clone)]
enum Pending {
    Sync {
        /// [`SyncEngine::ticks`] when it was sent.
        sent: u64,
        /// The sync points when it was sent, for the head check.
        floors: HashMap<Conv, u64>,
    },
    Join {
        room: Room,
        /// [`SyncEngine::ticks`] when it was sent.
        sent: u64,
        /// The room's sync point when it was sent, for the head check.
        floor: Option<u64>,
    },
    Part,
    Info {
        room: Room,
        /// [`SyncEngine::ticks`] when it was sent.
        sent: u64,
        /// The room's sync point when it was sent, for the head check.
        floor: Option<u64>,
    },
    Read,
    Msg {
        outbox: OutboxId,
    },
    Typing,
    Name {
        /// The display name set, escaped.
        name: String,
    },
    Members {
        room: Room,
        /// The stored room, its epoch and the newest seq known when MEMBERS
        /// was sent, to record the list against (8.3).
        roster: Option<(ConvId, i64, u64)>,
    },
    Whois,
    /// A command the engine keeps nothing from ([`SyncEngine::request`]).
    Plain,
    Block {
        target: BlockTarget,
        on: bool,
    },
    Blocks {
        /// The account's block clock when BLOCKS was sent: the reply
        /// covers the blocks as they were then (5.7).
        since: u64,
    },
    History {
        conv: Conv,
        row: ConvId,
        epoch: i64,
        page: Page,
        slot: Slot,
        /// The highest seq known to exist in the stored conversation when
        /// the request was made: its reported head or newest stored event.
        known: u64,
        /// What catching up aimed for: `known`, or a dropped live event.
        goal: u64,
    },
    Related {
        conv: Conv,
        row: ConvId,
        epoch: i64,
        first: Seq,
        last: Seq,
    },
}

/// What a page did to the store.
enum PageResult {
    /// The conversation was discarded or removed since the request: the
    /// page does not continue from where the client now is.
    Stale,
    /// The page came from a different conversation with the same name
    /// (7.2). The history was discarded.
    OtherConversation,
    /// The page was stored.
    Stored {
        progress: bool,
        sync_point: u64,
        /// A range of messages whose edits and reactions may be missing
        /// (7.3).
        related: Option<(Seq, Seq)>,
        /// The newest seq in the page.
        last: Option<Seq>,
    },
}

/// The sync engine for one signed-in connection. See the [module
/// docs](super).
#[derive(Debug)]
pub struct SyncEngine {
    store: Store,
    account: AccountId,
    me: Uid,
    guest: bool,
    /// A guest's session was resumed on this connection (4.2), so its
    /// cids carry over (7.6).
    resumed: bool,
    config: SyncConfig,
    next_req: u64,
    pending: HashMap<ReqId, Pending>,
    convs: HashMap<Conv, Live>,
    /// The SYNC in flight, if any.
    syncing: Option<ReqId>,
    /// Send SYNC again once the one in flight is answered.
    want_sync: bool,
    /// Outbox entries sent on this connection and not answered yet.
    sending: HashSet<OutboxId>,
    /// This connection's claim on the outbox entries it sends (7.6).
    claim: Claim,
    /// Counts the lines and replies handled, to order them.
    ticks: u64,
    /// When TYPING was last sent for each conversation (8.1).
    typing_sent: HashMap<Conv, Timestamp>,
    out: Output,
}

impl SyncEngine {
    /// An engine for `account`, after signing in on a new connection.
    pub fn new(
        store: Store,
        account: AccountId,
        config: SyncConfig,
    ) -> Result<SyncEngine, SyncError> {
        let me = store.account_uid(account)?;
        Ok(SyncEngine::signed_in_as(store, account, me, config))
    }

    /// An engine for `account` on a connection signed in as `me`, which
    /// may differ from the account's uid: a guest whose name was still
    /// taken signs in as `<name>2` and so on (4.2). The engine uses `me`
    /// to recognise the connection's own JOIN, PART, KICK and BAN events.
    pub fn signed_in_as(
        store: Store,
        account: AccountId,
        me: Uid,
        config: SyncConfig,
    ) -> SyncEngine {
        SyncEngine {
            claim: store.new_claim(),
            store,
            account,
            guest: me.is_guest(),
            resumed: false,
            me,
            config,
            next_req: 1,
            pending: HashMap::new(),
            convs: HashMap::new(),
            syncing: None,
            want_sync: false,
            sending: HashSet::new(),
            ticks: 0,
            typing_sent: HashMap::new(),
            out: Output::default(),
        }
    }

    /// Says that this connection's guest resumed its session: GUEST's
    /// `OK` carried `resumed=yes` (4.2). The session's cids carry over, so
    /// messages sent on an earlier connection of the session with no `OK`
    /// are sent again with their cids (7.6), as an identity's are. Without
    /// it, a guest marks them as possibly not sent. Call it before
    /// [`start`](Self::start). Identities need not.
    pub fn set_resumed(&mut self, resumed: bool) {
        self.resumed = resumed;
    }

    /// The account this engine syncs.
    pub fn account(&self) -> AccountId {
        self.account
    }

    /// The account's uid.
    pub fn uid(&self) -> &Uid {
        &self.me
    }

    /// Whether `conv`'s id has been confirmed on this connection, so that
    /// its live events are being stored (7.1 step 6).
    pub fn is_live(&self, conv: &Conv) -> bool {
        self.convs.get(conv).is_some_and(|l| l.confirmed.is_some())
    }

    /// Whether any request is still waiting for its reply.
    pub fn is_busy(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Starts syncing: sends SYNC (7.1 step 1), and settles outbox entries
    /// left from the previous connection. An identity also asks BLOCKS
    /// (5.7), unless [`SyncConfig::fetch_blocks`] is off.
    pub fn start(&mut self) -> Result<Output, SyncError> {
        self.request_sync();
        if !self.guest && self.config.fetch_blocks {
            self.request_blocks()?;
        }
        self.flush_outbox()?;
        Ok(self.finish())
    }

    /// Handles a line that is not part of a reply: a live event, READ,
    /// DROP and so on. Lines this engine has no use for are ignored.
    pub fn handle_line(&mut self, msg: &ServerMessage) -> Result<Output, SyncError> {
        self.ticks += 1;
        if msg.ref_.is_some() || msg.is_report_copy() {
            // A response line belongs in a Reply. A reported event is a
            // copy for review, not a new event (5.8).
            return Ok(self.finish());
        }
        match &msg.line {
            ServerLine::Event(event) if event.meta.is_some() => self.on_event(event)?,
            // Another device of the account read up to here (7.4).
            ServerLine::Read { conv, seq } => {
                let (account, conv, seq) = (self.account, conv.clone(), seq.get());
                self.write(|tx| {
                    if let Some(mut row) = tx.conv_by_name(account, &conv)? {
                        tx.set_read(&mut row, seq)?;
                    }
                    Ok(())
                })?;
            }
            ServerLine::Typing { from, conv } if *from != self.me => {
                self.out.signals.push(Signal::Typing {
                    conv: conv.clone(),
                    from: from.clone(),
                });
            }
            ServerLine::Name { from, name } => {
                let account = self.account;
                self.write(|tx| tx.set_user_name(account, from, name))?;
            }
            ServerLine::Presence { presence, uids } => {
                for uid in uids {
                    self.out.signals.push(Signal::Presence {
                        uid: uid.clone(),
                        presence: presence.clone(),
                    });
                }
            }
            ServerLine::Drop { id, room, reason } => self.on_drop(Some(id), room, reason)?,
            // A block made or lifted on another device of the account
            // (5.7): one target at a time, never the whole list.
            ServerLine::Block { target } | ServerLine::Unblock { target } if !self.guest => {
                let on = matches!(msg.line, ServerLine::Block { .. });
                let account = self.account;
                self.write(|tx| tx.change_block(account, target, on))?;
            }
            _ => {}
        }
        Ok(self.finish())
    }

    /// Handles the reply to a command from [`Output::send`]. A `req` this
    /// engine does not know is ignored.
    pub fn handle_reply(&mut self, req: ReqId, reply: Reply) -> Result<Output, SyncError> {
        self.ticks += 1;
        let Some(pending) = self.pending.remove(&req) else {
            debug!(req = req.get(), "reply to an unknown request");
            return Ok(self.finish());
        };
        match pending {
            Pending::Sync { sent, floors } => self.on_sync(req, sent, &floors, &reply)?,
            Pending::Join { room, sent, floor } => {
                self.on_join(req, &room, (sent, floor), reply)?
            }
            // The PART event, which comes first, did the work (6.1).
            Pending::Part => self.completed(req, reply.outcome),
            Pending::Info { room, sent, floor } => {
                self.on_info(req, &room, (sent, floor), reply)?
            }
            Pending::Read | Pending::Typing | Pending::Plain => self.completed(req, reply.outcome),
            Pending::Msg { outbox } => self.on_msg(outbox, reply)?,
            Pending::Name { name } => self.on_name(req, &name, reply)?,
            Pending::Members { room, roster } => self.on_members(req, &room, roster, reply)?,
            Pending::Whois => self.on_whois(req, reply)?,
            Pending::Block { target, on } => self.on_block(req, &target, on, reply)?,
            Pending::Blocks { since } => self.on_blocks(req, since, reply)?,
            Pending::History {
                conv,
                row,
                epoch,
                page,
                slot,
                known,
                goal,
            } => self.on_history(&conv, row, epoch, page, slot, (known, goal), &reply)?,
            Pending::Related {
                conv,
                row,
                epoch,
                first,
                last,
            } => self.on_related(&conv, row, epoch, first, last, &reply)?,
        }
        Ok(self.finish())
    }

    /// Joins a room (6.1).
    pub fn join(&mut self, room: &Room) -> Output {
        let command = Command::Join { room: room.clone() };
        let sent = self.ticks;
        let floor = self.floor(&Conv::Room(room.clone()));
        self.issue(
            command,
            Pending::Join {
                room: room.clone(),
                sent,
                floor,
            },
        );
        self.finish()
    }

    /// Leaves a room (6.1). Its history is kept.
    pub fn part(&mut self, room: &Room, reason: &str) -> Output {
        let command = Command::Part {
            room: room.clone(),
            reason: reason.to_owned(),
        };
        self.issue(command, Pending::Part);
        self.finish()
    }

    /// Asks for a room's information (6.2), which also checks its id.
    pub fn info(&mut self, room: &Room) -> Output {
        let command = Command::Info {
            room: Some(room.clone()),
        };
        let sent = self.ticks;
        let floor = self.floor(&Conv::Room(room.clone()));
        self.issue(
            command,
            Pending::Info {
                room: room.clone(),
                sent,
                floor,
            },
        );
        self.finish()
    }

    /// Sends a command the engine keeps nothing from, such as ROLE, KICK,
    /// REPORT or an ADMIN command, in order with the engine's own, and
    /// reports how it ended in [`Output::completed`]. The events it causes
    /// arrive as live lines before its reply (5.2), and are handled like
    /// any others, so they are stored by the time it completes.
    pub fn request(&mut self, command: Command) -> Output {
        self.issue(command, Pending::Plain);
        self.finish()
    }

    /// Queues a message, bound to the conversation's stored id (7.6), and
    /// sends it if the id is confirmed on this connection. Returns the
    /// outbox entry.
    ///
    /// A room must have a stored id. A direct conversation without one is
    /// new, and its first message starts it (5.1).
    pub fn send(&mut self, conv: &Conv, draft: &Draft) -> Result<(OutboxId, Output), SyncError> {
        let check = Request::new(Command::Msg {
            conv: conv.clone(),
            text: draft.text.clone(),
            relation: draft.relation,
            file: draft.file.clone(),
            cid: None,
        });
        check
            .validate()
            .map_err(|e| SyncError::Invalid(e.to_string()))?;
        let (account, now) = (self.account, self.now());
        let id = self.write(|tx| {
            let bound = tx.conv_by_name(account, conv)?.and_then(|r| r.conv_id);
            if bound.is_none() && conv.is_room() {
                return Ok(None);
            }
            tx.queue(account, conv, bound.as_ref(), draft, now)
                .map(Some)
        })?;
        let id = id.ok_or_else(|| SyncError::NotJoined(conv.clone()))?;
        // A message ends typing (8.1): the next keystroke says so again.
        self.typing_sent.remove(conv);
        self.flush_outbox()?;
        Ok((id, self.finish()))
    }

    /// Queues `DELETE <conv> <seq>` (5.4) in the outbox, bound to the
    /// conversation's stored id like a message (7.6), since the seq names
    /// a message of that conversation only. Returns the outbox entry.
    ///
    /// It goes out once the id is confirmed on this connection, or, for a
    /// room the account is no longer in, once SYNC has been answered with
    /// the id still stored: authors may delete their own messages in rooms
    /// they have left (5.4). See [`delete_left`] for that rule.
    pub fn delete(&mut self, conv: &Conv, seq: Seq) -> Result<(OutboxId, Output), SyncError> {
        let (account, now) = (self.account, self.now());
        let id = self.write(|tx| {
            let Some(bound) = tx.conv_by_name(account, conv)?.and_then(|r| r.conv_id) else {
                return Ok(None);
            };
            tx.queue_delete(account, conv, &bound, seq, now).map(Some)
        })?;
        let id = id.ok_or_else(|| SyncError::NotJoined(conv.clone()))?;
        self.flush_outbox()?;
        Ok((id, self.finish()))
    }

    /// Sends queued messages that were waiting, for example after
    /// [`Output::retry_after`].
    pub fn resume_outbox(&mut self) -> Result<Output, SyncError> {
        self.flush_outbox()?;
        Ok(self.finish())
    }

    /// Moves the read marker forward (7.4), in the store and, for an
    /// identity, on the server. A marker beyond the newest seq known stops
    /// there, as the server's stops at the head. Guests have no markers on
    /// the server (7.4), so for a guest it moves only in the store.
    pub fn mark_read(&mut self, conv: &Conv, seq: Seq) -> Result<Output, SyncError> {
        let account = self.account;
        let moved = self.write(|tx| match tx.conv_by_name(account, conv)? {
            Some(mut row) => Ok(tx.mark_read(&mut row, seq.get())?.then_some(row.read)),
            None => Ok(None),
        })?;
        if let Some(read) = moved.and_then(Seq::new)
            && !self.guest
        {
            let command = Command::Read {
                conv: conv.clone(),
                seq: read,
            };
            self.issue(command, Pending::Read);
        }
        Ok(self.finish())
    }

    /// Says that the user is typing in `conv` (8.1). Call it as the user
    /// types: TYPING goes out at once, then at most every
    /// [`TYPING_REPEAT`] while the calls go on. Nothing is sent for a
    /// conversation that is not live on this connection. Sending a
    /// message, or [`stop_typing`](Self::stop_typing), ends it.
    pub fn typing(&mut self, conv: &Conv) -> Output {
        let now = self.now();
        let recent = self
            .typing_sent
            .get(conv)
            .is_some_and(|at| now.saturating_duration_since(*at) < TYPING_REPEAT);
        if !recent && self.is_live(conv) {
            self.typing_sent.insert(conv.clone(), now);
            self.issue(Command::Typing { conv: conv.clone() }, Pending::Typing);
        }
        self.finish()
    }

    /// Says that the user stopped typing in `conv`, for example by
    /// clearing what they wrote. Nothing is sent: the others' notice runs
    /// out (8.1). The next [`typing`](Self::typing) sends at once.
    pub fn stop_typing(&mut self, conv: &Conv) {
        self.typing_sent.remove(conv);
    }

    /// Sets the account's display name, escaped, or clears it if empty
    /// (8.2). Once the server accepts it, it is stored as the account's
    /// own name.
    pub fn set_name(&mut self, name: &str) -> Output {
        let command = Command::Name {
            display_name: name.to_owned(),
        };
        self.issue(
            command,
            Pending::Name {
                name: name.to_owned(),
            },
        );
        self.finish()
    }

    /// Asks for a room's members (8.3). Their names are stored, and for a
    /// room in the store, who is in it and their roles. Their presence
    /// comes as [`Signal::Presence`].
    pub fn members(&mut self, room: &Room) -> Result<Output, SyncError> {
        let account = self.account;
        let conv = Conv::Room(room.clone());
        let roster = self.write(|tx| match tx.conv_by_name(account, &conv)? {
            Some(row) => {
                let at = row.head.max(tx.max_seq(row.id)?);
                Ok(Some((row.id, row.epoch, at)))
            }
            None => Ok(None),
        })?;
        let command = Command::Members { room: room.clone() };
        self.issue(
            command,
            Pending::Members {
                room: room.clone(),
                roster,
            },
        );
        Ok(self.finish())
    }

    /// Asks about a user (8.3). Their name is stored; their presence comes
    /// as [`Signal::Presence`].
    pub fn whois(&mut self, uid: &Uid) -> Output {
        self.issue(Command::Whois { uid: uid.clone() }, Pending::Whois);
        self.finish()
    }

    /// Blocks an identity or a domain (5.7). Stored once the server
    /// accepts it.
    pub fn block(&mut self, target: &BlockTarget) -> Output {
        let command = Command::Block {
            target: target.clone(),
        };
        let pending = Pending::Block {
            target: target.clone(),
            on: true,
        };
        self.issue(command, pending);
        self.finish()
    }

    /// Removes a block (5.7). Stored once the server accepts it.
    pub fn unblock(&mut self, target: &BlockTarget) -> Output {
        let command = Command::Unblock {
            target: target.clone(),
        };
        let pending = Pending::Block {
            target: target.clone(),
            on: false,
        };
        self.issue(command, pending);
        self.finish()
    }

    /// Asks for the account's blocks (5.7). The reply replaces the stored
    /// ones, except those changed since it was sent, which are newer.
    pub fn blocks(&mut self) -> Result<Output, SyncError> {
        self.request_blocks()?;
        Ok(self.finish())
    }

    /// Loads the page of history just below the newest stored run, while
    /// there is a gap between it and the sync point (7.1 step 4, 7.3).
    /// Sends nothing if there is no gap, or a request is in flight.
    pub fn load_older(&mut self, conv: &Conv) -> Result<Output, SyncError> {
        let Some(live) = self.convs.get(conv) else {
            return Ok(self.finish());
        };
        if live.loading_older || live.confirmed.is_none() {
            return Ok(self.finish());
        }
        let account = self.account;
        let found = self.write(|tx| {
            let Some(row) = tx.conv_by_name(account, conv)? else {
                return Ok(None);
            };
            let top = tx.gap_top(&row)?;
            let known = row.head.max(tx.max_seq(row.id)?);
            Ok(top.map(|before| (row, before, known)))
        })?;
        if let Some((row, before, known)) = found
            && self.matches_confirmed(conv, &row)
        {
            let page = self.config.page_size;
            let at = (known, known);
            self.history(conv, &row, Page::Backward { before }, Slot::Older, at, page);
        }
        Ok(self.finish())
    }

    /// Fetches one event that is not stored, such as a reply's target,
    /// with its edits and reactions (7.3). If it has expired, the server
    /// returns an older event instead, or none.
    pub fn fetch(&mut self, conv: &Conv, seq: Seq) -> Result<Output, SyncError> {
        if !self.is_live(conv) {
            return Ok(self.finish());
        }
        let account = self.account;
        let row = self.write(|tx| {
            let Some(row) = tx.conv_by_name(account, conv)? else {
                return Ok(None);
            };
            let have = seq.get() <= row.sync_point || tx.has_event(row.id, seq.get())?;
            let known = row.head.max(tx.max_seq(row.id)?);
            Ok((!have).then_some((row, known)))
        })?;
        if let Some((row, known)) = row
            && self.matches_confirmed(conv, &row)
        {
            let page = Page::Backward {
                before: seq.get() + 1,
            };
            self.history(conv, &row, page, Slot::Extra, (known, known), 1);
        }
        Ok(self.finish())
    }

    /// Catches `conv` up completely, across any gap, for reading offline
    /// (7.1). Watch [`ConversationSummary::caught_up`](crate::store::ConversationSummary::caught_up).
    pub fn download(&mut self, conv: &Conv) -> Result<Output, SyncError> {
        self.convs.entry(conv.clone()).or_default().download = true;
        self.check_fill(conv)?;
        Ok(self.finish())
    }

    // -----------------------------------------------------------------------
    // Plumbing

    fn now(&self) -> Timestamp {
        self.config.clock.now()
    }

    /// Ends a call: sends SYNC if one is wanted, and hands over the output.
    fn finish(&mut self) -> Output {
        if self.want_sync && self.syncing.is_none() {
            self.want_sync = false;
            self.request_sync();
        }
        std::mem::take(&mut self.out)
    }

    fn write<T>(
        &mut self,
        f: impl FnOnce(&mut Tx<'_>) -> Result<T, StoreError>,
    ) -> Result<T, SyncError> {
        let me = &self.me;
        let (t, changes) = self.store.write(|tx| {
            // Events the connection sends are the account's own (4.2).
            tx.signed_in_as(me);
            f(tx)
        })?;
        self.out.changes.extend(changes);
        Ok(t)
    }

    fn issue(&mut self, command: Command, pending: Pending) -> ReqId {
        let req = ReqId(self.next_req);
        self.next_req += 1;
        self.pending.insert(req, pending);
        self.out.send.push(Outgoing { req, command });
        req
    }

    fn completed(&mut self, req: ReqId, outcome: Outcome) {
        self.out.completed.push(Completed { req, outcome });
    }

    /// Sends BLOCKS, noting the block clock as it is now.
    fn request_blocks(&mut self) -> Result<(), SyncError> {
        let since = self.store.blocks_clock(self.account)?;
        self.issue(Command::Blocks, Pending::Blocks { since });
        Ok(())
    }

    fn request_sync(&mut self) {
        if self.syncing.is_some() {
            self.want_sync = true;
            return;
        }
        let sent = self.ticks;
        // If the cache cannot be read, no head is checked.
        let floors = self.store.sync_points(self.account).unwrap_or_default();
        self.syncing = Some(self.issue(Command::Sync, Pending::Sync { sent, floors }));
    }

    /// The sync point of `conv` now, to check a head in the reply to a
    /// command sent now (7.1). `None` if it is not known.
    fn floor(&self, conv: &Conv) -> Option<u64> {
        self.store
            .sync_points(self.account)
            .ok()
            .and_then(|mut m| m.remove(conv))
    }

    fn live(&mut self, conv: &Conv) -> &mut Live {
        self.convs.entry(conv.clone()).or_default()
    }

    fn matches_confirmed(&self, conv: &Conv, row: &ConvRow) -> bool {
        row.conv_id.is_some()
            && self.convs.get(conv).and_then(|l| l.confirmed.as_ref()) == row.conv_id.as_ref()
    }

    /// The account is no longer in `conv`: stop storing its live events.
    fn left(&mut self, conv: &Conv) -> Result<(), SyncError> {
        self.live(conv).confirmed = None;
        let account = self.account;
        self.write(|tx| {
            if let Some(mut row) = tx.conv_by_name(account, conv)? {
                tx.set_joined(&mut row, false)?;
            }
            Ok(())
        })
    }

    /// A live line showed the account leaving `conv`, or its id changing.
    /// A reply to a command sent before then may not show it: a server can
    /// compute a reply, then queue lines from other connections before it.
    fn touch_left(&mut self, conv: &Conv) {
        let now = self.ticks;
        self.live(conv).left_at = now;
    }

    /// A live line showed the account joining `conv`.
    fn touch_joined(&mut self, conv: &Conv) {
        let now = self.ticks;
        self.live(conv).joined_at = now;
    }

    /// The sync point to check a head against (7.1), in the reply to a
    /// command sent at `sent` when the sync point was `floor`.
    ///
    /// The head is compared with the sync point as it was when the command
    /// was sent, not as it is now: since then, this connection or another
    /// process sharing the cache may have stored newer events, which the
    /// server may not have counted when it computed the head. Events stored
    /// before the command was sent existed on the server before it, so a
    /// correct server's head covers them. A live event of the conversation
    /// since the command was sent skips the check altogether.
    fn head_floor(&self, conv: &Conv, sent: u64, floor: Option<u64>) -> Option<u64> {
        let fresh = self.convs.get(conv).is_none_or(|l| l.event_at <= sent);
        floor.filter(|_| fresh)
    }

    /// The id of `conv` was learned on this connection.
    fn confirm(&mut self, conv: &Conv, id: Id) {
        let live = self.live(conv);
        if live.failed_for.as_ref() != Some(&id) {
            live.failures = 0;
            live.failed_for = None;
        }
        live.confirmed = Some(id);
        live.stuck = None;
        live.newest_for = None;
    }

    // -----------------------------------------------------------------------
    // Live lines

    fn on_event(&mut self, event: &Event) -> Result<(), SyncError> {
        let Some(meta) = &event.meta else {
            return Ok(());
        };
        let conv = event.body.conv();
        let n = meta.seq.get();
        let now = self.ticks;
        self.live(&conv).event_at = now;

        // 8.1: a message ends its author's typing.
        if let EventBody::Msg(m) = &event.body
            && matches!(m.relation, None | Some(Relation::Reply(_)))
            && meta.from != self.me
        {
            self.out.signals.push(Signal::Spoke {
                conv: conv.clone(),
                from: meta.from.clone(),
            });
        }

        // 6.4: notifications, not history.
        match &event.body {
            EventBody::Invite { room, uid } if *uid == self.me => {
                self.out.notifications.push(Notification::Invited {
                    room: room.clone(),
                    by: meta.from.clone(),
                });
                // Inviting a member records nothing (6.4), so the server
                // takes the account not to be in the room. If this
                // connection thought it was, ask SYNC.
                if self.is_live(&conv) {
                    self.touch_left(&conv);
                    self.left(&conv)?;
                    self.want_sync = true;
                }
                return Ok(());
            }
            EventBody::Kick { room, uid, reason } if *uid == self.me => {
                self.out.notifications.push(Notification::Kicked {
                    room: room.clone(),
                    by: meta.from.clone(),
                    reason: reason.clone(),
                });
                self.touch_left(&conv);
                return self.left(&conv);
            }
            EventBody::Ban { room, uid, reason } if *uid == self.me => {
                self.out.notifications.push(Notification::Banned {
                    room: room.clone(),
                    by: meta.from.clone(),
                    reason: reason.clone(),
                });
                self.touch_left(&conv);
                return self.left(&conv);
            }
            _ => {}
        }

        let mut joined_here = false;

        // 6.1: a JOIN carries the room's id. One that differs from the
        // stored id means the stored history is from an older room.
        if let EventBody::Join { id, .. } = &event.body {
            let own = meta.from == self.me;
            let account = self.account;
            let reset = self.write(|tx| {
                let row = if own {
                    Some(tx.conv_or_create(account, &conv)?)
                } else {
                    tx.conv_by_name(account, &conv)?
                };
                let Some(mut row) = row else {
                    return Ok(false);
                };
                let mut reset = false;
                if row.conv_id.as_ref().is_some_and(|old| old != id) {
                    tx.discard(&mut row, None)?;
                    reset = true;
                }
                if own {
                    tx.learn_id(&mut row, id, None)?;
                    tx.set_joined(&mut row, true)?;
                }
                Ok(reset)
            })?;
            if own {
                self.confirm(&conv, id.clone());
                self.touch_joined(&conv);
                joined_here = true;
            } else if reset {
                self.live(&conv).confirmed = None;
                self.touch_left(&conv);
            }
        }

        // 7.1 step 6: store only once the id is known on this connection.
        let stored = match self.convs.get(&conv).and_then(|l| l.confirmed.clone()) {
            Some(id) => {
                let account = self.account;
                self.write(|tx| {
                    let Some(mut row) = tx.conv_by_name(account, &conv)? else {
                        return Ok(false);
                    };
                    if row.conv_id.as_ref() != Some(&id) {
                        return Ok(false);
                    }
                    tx.store_event(&row, event)?;
                    // 7.1 step 5: it moves the sync point only if it
                    // directly follows.
                    tx.raise_sync_point(&mut row, 0)?;
                    Ok(true)
                })?
            }
            None => false,
        };
        if !stored {
            self.dropped(&conv, n);
        }

        if meta.from == self.me && matches!(event.body, EventBody::Part { .. }) {
            self.touch_left(&conv);
            self.left(&conv)?;
        }
        self.check_fill(&conv)?;
        if joined_here {
            self.flush_outbox()?;
        }
        Ok(())
    }

    /// A live event was not stored because the conversation's id is not
    /// confirmed. HISTORY will return it once it is (7.1 step 6), but only
    /// if SYNC lists the conversation, so make sure a SYNC answers after
    /// it: a new direct conversation, or a room joined on another device,
    /// would otherwise be missed.
    fn dropped(&mut self, conv: &Conv, seq: u64) {
        let syncing = self.syncing.is_some();
        let live = self.live(conv);
        live.confirmed = None;
        live.dropped = live.dropped.max(seq);
        if syncing {
            live.recheck = true;
        } else {
            self.want_sync = true;
        }
    }

    /// DROP (10.4). One whose `id` is not the stored id is about an older
    /// room of the same name: the stored history stays, and nothing is
    /// reported. One with no `id` is taken to be about the stored room.
    ///
    /// Either way, this connection forgets the dropped id if it had
    /// confirmed it, and replies to commands sent before the DROP may name
    /// it, so they are out of date. Another process sharing the cache may
    /// have stored the new room's id while this connection still had the
    /// old one.
    fn on_drop(&mut self, id: Option<&Id>, room: &Room, reason: &str) -> Result<(), SyncError> {
        let conv = Conv::Room(room.clone());
        self.touch_left(&conv);
        let live = self.live(&conv);
        if id.is_none_or(|id| live.confirmed.as_ref() == Some(id)) {
            live.confirmed = None;
        }
        let account = self.account;
        let ours = self.write(|tx| {
            let row = tx.conv_by_name(account, &conv)?;
            if let Some(id) = id
                && row.as_ref().and_then(|r| r.conv_id.as_ref()) != Some(id)
            {
                return Ok(false);
            }
            if let Some(row) = row {
                tx.remove(&row)?;
            }
            Ok(true)
        })?;
        if !ours {
            debug!(%room, "DROP for another room of the same name");
            return Ok(());
        }
        self.live(&conv).confirmed = None;
        self.out.notifications.push(Notification::Dropped {
            room: room.clone(),
            reason: reason.to_owned(),
        });
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Replies

    fn on_sync(
        &mut self,
        req: ReqId,
        sent: u64,
        floors: &HashMap<Conv, u64>,
        reply: &Reply,
    ) -> Result<(), SyncError> {
        if self.syncing == Some(req) {
            self.syncing = None;
        }
        if !matches!(reply.outcome, Outcome::Ok(_)) {
            warn!("SYNC failed");
            return Ok(());
        }
        // A live line handled after the SYNC was sent may be newer than
        // what the server listed: a server can compute a reply and queue
        // events from other connections before it. Leave those
        // conversations alone, and ask again.
        let newer: HashSet<Conv> = self
            .convs
            .iter()
            .filter(|(_, l)| l.joined_at.max(l.left_at) > sent)
            .map(|(c, _)| c.clone())
            .collect();
        if !newer.is_empty() {
            self.want_sync = true;
        }
        let account = self.account;
        let guest = self.guest;
        let mut listed = Vec::new();
        let mut heads = HashMap::new();
        // Read markers moved here while the server did not hear (7.4).
        let mut unsent_reads = Vec::new();
        for msg in &reply.lines {
            if let ServerLine::Conv {
                conv,
                id,
                head,
                read,
            } = &msg.line
            {
                listed.push(conv.clone());
                heads.insert(conv.clone(), head.get());
                if newer.contains(conv) {
                    continue;
                }
                let floor = self.head_floor(conv, sent, floors.get(conv).copied());
                let local = self.write(|tx| {
                    let mut row = tx.conv_or_create(account, conv)?;
                    // 7.1 step 2, and the head check.
                    learn(tx, &mut row, id, Some(head.get()), floor)?;
                    tx.set_joined(&mut row, true)?;
                    // 7.4: the account's marker, from its other devices.
                    if let Some(read) = read {
                        tx.set_read(&mut row, read.get())?;
                    }
                    Ok(row.read)
                })?;
                if !guest
                    && local > read.map_or(0, Seq::get)
                    && let Some(local) = Seq::new(local)
                {
                    unsent_reads.push((conv.clone(), local));
                }
                self.confirm(conv, id.clone());
            }
        }

        // A conversation missing from SYNC is one the account left (7.1).
        let missing = self.write(|tx| {
            let mut gone = Vec::new();
            for mut row in tx.convs(account)? {
                if row.joined && !listed.contains(&row.name) && !newer.contains(&row.name) {
                    tx.set_joined(&mut row, false)?;
                    gone.push(row.name);
                }
            }
            Ok(gone)
        })?;
        for conv in missing {
            self.live(&conv).confirmed = None;
            self.out.notifications.push(Notification::Left { conv });
        }
        // A live event dropped while this SYNC was in flight: ask again if
        // the SYNC did not list its conversation, or listed it with a head
        // below the event. The server computed that head before the event,
        // and the event may have expired by the time HISTORY asks for it,
        // so only a new SYNC tells how far to catch up (7.1 step 6).
        for (conv, live) in &mut self.convs {
            if std::mem::take(&mut live.recheck)
                && heads.get(conv).is_none_or(|&head| head < live.dropped)
            {
                self.want_sync = true;
            }
        }
        for (conv, seq) in unsent_reads {
            self.issue(Command::Read { conv, seq }, Pending::Read);
        }
        for conv in &listed {
            if !newer.contains(conv) {
                self.check_fill(conv)?;
            }
        }
        self.flush_outbox()
    }

    fn on_name(&mut self, req: ReqId, name: &str, reply: Reply) -> Result<(), SyncError> {
        if matches!(reply.outcome, Outcome::Ok(_)) {
            let (account, me) = (self.account, self.me.clone());
            self.write(|tx| tx.set_user_name(account, &me, name))?;
        }
        self.completed(req, reply.outcome);
        Ok(())
    }

    fn on_members(
        &mut self,
        req: ReqId,
        room: &Room,
        roster: Option<(ConvId, i64, u64)>,
        reply: Reply,
    ) -> Result<(), SyncError> {
        if matches!(reply.outcome, Outcome::Ok(_)) {
            let mut members = Vec::new();
            for msg in &reply.lines {
                if let ServerLine::Member {
                    room: r,
                    uid,
                    role,
                    presence,
                    name,
                } = &msg.line
                    && r == room
                {
                    members.push((uid.clone(), *role, name.clone()));
                    self.out.signals.push(Signal::Presence {
                        uid: uid.clone(),
                        presence: presence.clone(),
                    });
                }
            }
            let account = self.account;
            self.write(|tx| {
                for (uid, _, name) in &members {
                    tx.set_user_name(account, uid, name)?;
                }
                // Only for the room it was asked for: not one dropped and
                // created again since (7.1).
                if let Some((row, epoch, at)) = roster
                    && tx.conv(row)?.is_some_and(|r| r.epoch == epoch)
                {
                    let list: Vec<_> = members.iter().map(|(u, r, _)| (u.clone(), *r)).collect();
                    tx.set_roster(row, at, &list)?;
                }
                Ok(())
            })?;
        }
        self.completed(req, reply.outcome);
        Ok(())
    }

    fn on_whois(&mut self, req: ReqId, reply: Reply) -> Result<(), SyncError> {
        if matches!(reply.outcome, Outcome::Ok(_)) {
            let account = self.account;
            for msg in &reply.lines {
                if let ServerLine::User {
                    uid,
                    presence,
                    name,
                } = &msg.line
                {
                    self.write(|tx| tx.set_user_name(account, uid, name))?;
                    self.out.signals.push(Signal::Presence {
                        uid: uid.clone(),
                        presence: presence.clone(),
                    });
                }
            }
        }
        self.completed(req, reply.outcome);
        Ok(())
    }

    fn on_block(
        &mut self,
        req: ReqId,
        target: &BlockTarget,
        on: bool,
        reply: Reply,
    ) -> Result<(), SyncError> {
        if matches!(reply.outcome, Outcome::Ok(_)) {
            let account = self.account;
            self.write(|tx| tx.change_block(account, target, on))?;
        }
        self.completed(req, reply.outcome);
        Ok(())
    }

    fn on_blocks(&mut self, req: ReqId, since: u64, reply: Reply) -> Result<(), SyncError> {
        if matches!(reply.outcome, Outcome::Ok(_)) {
            let targets: Vec<BlockTarget> = reply
                .lines
                .iter()
                .filter_map(|m| match &m.line {
                    ServerLine::Block { target } => Some(target.clone()),
                    _ => None,
                })
                .collect();
            let account = self.account;
            // As the blocks were when BLOCKS was sent: a change since,
            // here or in another process sharing the cache, is newer
            // (5.7), as with heads (7.1).
            self.write(|tx| tx.apply_blocks(account, &targets, since))?;
        }
        self.completed(req, reply.outcome);
        Ok(())
    }

    fn on_join(
        &mut self,
        req: ReqId,
        room: &Room,
        (sent, floor): (u64, Option<u64>),
        reply: Reply,
    ) -> Result<(), SyncError> {
        let conv = Conv::Room(room.clone());
        if self.live(&conv).left_at > sent {
            // Left since: this OK is out of date.
            self.want_sync = true;
        } else if let Outcome::Ok(ok) = &reply.outcome
            && let Ok(Some(id)) = ok.id()
        {
            let head = ok.head().ok().flatten();
            let floor = self.head_floor(&conv, sent, floor);
            let account = self.account;
            self.write(|tx| {
                let mut row = tx.conv_or_create(account, &conv)?;
                learn(tx, &mut row, &id, head, floor)?;
                tx.set_joined(&mut row, true)?;
                for msg in &reply.lines {
                    if let ServerLine::Event(e) = &msg.line
                        && e.is_snapshot()
                        && e.body.conv() == conv
                    {
                        tx.apply_snapshot(&row, e)?;
                    }
                }
                Ok(())
            })?;
            self.confirm(&conv, id);
            self.check_fill(&conv)?;
            self.flush_outbox()?;
        }
        self.completed(req, reply.outcome);
        Ok(())
    }

    fn on_info(
        &mut self,
        req: ReqId,
        room: &Room,
        (sent, floor): (u64, Option<u64>),
        reply: Reply,
    ) -> Result<(), SyncError> {
        let conv = Conv::Room(room.clone());
        let live = self.live(&conv);
        if live.joined_at.max(live.left_at) > sent {
            self.want_sync = true;
        } else if let Outcome::Ok(ok) = &reply.outcome
            && let Ok(Some(id)) = ok.id()
        {
            let joined = ok.joined().ok().flatten().unwrap_or(false);
            let head = ok.head().ok().flatten();
            let floor = self.head_floor(&conv, sent, floor);
            let account = self.account;
            self.write(|tx| {
                let row = if joined {
                    Some(tx.conv_or_create(account, &conv)?)
                } else {
                    tx.conv_by_name(account, &conv)?
                };
                let Some(mut row) = row else {
                    return Ok(());
                };
                if joined {
                    learn(tx, &mut row, &id, head, floor)?;
                    tx.set_joined(&mut row, true)?;
                    for msg in &reply.lines {
                        if let ServerLine::Event(e) = &msg.line
                            && e.is_snapshot()
                            && e.body.conv() == conv
                        {
                            tx.apply_snapshot(&row, e)?;
                        }
                    }
                } else {
                    if row.conv_id.as_ref().is_some_and(|old| *old != id) {
                        tx.discard(&mut row, None)?;
                    }
                    tx.set_joined(&mut row, false)?;
                }
                Ok(())
            })?;
            if joined {
                self.confirm(&conv, id);
                self.check_fill(&conv)?;
                self.flush_outbox()?;
            } else {
                self.live(&conv).confirmed = None;
            }
        }
        self.completed(req, reply.outcome);
        Ok(())
    }

    fn on_msg(&mut self, outbox: OutboxId, reply: Reply) -> Result<(), SyncError> {
        self.sending.remove(&outbox);
        let account = self.account;
        let me = self.me.clone();
        let retry = self.write(|tx| {
            let Some(item) = tx.outbox_item(outbox)? else {
                return Ok(None);
            };
            match reply.outcome {
                Outcome::Ok(ok) => match ok.seq().ok().flatten() {
                    Some(seq) => {
                        // 7.6: the OK names our own message. Check it if
                        // the event is stored. A DELETE's OK may name an
                        // earlier DELETE of the same message, by a
                        // moderator for one (5.4).
                        if item.delete.is_none()
                            && let Some(row) = tx.conv_by_name(account, &item.conv)?
                            && let Some(author) = tx.author_of(row.id, seq.get())?
                            && author != me.as_str()
                        {
                            warn!(%seq, "OK for a cid names someone else's event");
                        }
                        tx.outbox_sent(outbox, seq)?;
                    }
                    None => tx.outbox_failed(outbox, FailReason::Unconfirmed)?,
                },
                Outcome::Err(err) if err.code == ErrorCode::RateLimited => {
                    tx.outbox_requeue(outbox)?;
                    return Ok(Some(err.retry.unwrap_or(1)));
                }
                Outcome::Err(err) => tx.outbox_failed(outbox, FailReason::Rejected(err.code))?,
                Outcome::Failed => tx.outbox_failed(outbox, FailReason::Unconfirmed)?,
                // Never sent, so it is not "maybe sent".
                Outcome::NotSent => tx.outbox_failed(outbox, FailReason::Invalid)?,
            }
            Ok(None)
        })?;
        if let Some(secs) = retry {
            let wait = Duration::from_secs(secs);
            self.out.retry_after = Some(self.out.retry_after.map_or(wait, |w| w.max(wait)));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn on_history(
        &mut self,
        conv: &Conv,
        row_id: ConvId,
        epoch: i64,
        page: Page,
        slot: Slot,
        (known, goal): (u64, u64),
        reply: &Reply,
    ) -> Result<(), SyncError> {
        let live = self.live(conv);
        match slot {
            Slot::Auto => live.filling = false,
            Slot::Older => live.loading_older = false,
            Slot::Extra => {}
        }
        let Some(id) = self.reply_id(conv, reply) else {
            return self.check_fill(conv);
        };
        let more = match &reply.outcome {
            Outcome::Ok(ok) => ok.more().ok().flatten().unwrap_or(false),
            _ => false,
        };
        let events = page_events(conv, reply);
        let result = self.write(|tx| {
            let Some(mut row) = tx.conv(row_id)? else {
                return Ok(PageResult::Stale);
            };
            if row.epoch != epoch {
                return Ok(PageResult::Stale);
            }
            if row.conv_id.as_ref() != Some(&id) {
                // 7.2: a page from another conversation with this name.
                tx.discard(&mut row, None)?;
                return Ok(PageResult::OtherConversation);
            }
            for e in &events {
                tx.store_event(&row, e)?;
            }
            let start = row.sync_point;
            let first = events.first().and_then(|e| e.meta.as_ref()).map(|m| m.seq);
            let last = events.last().and_then(|e| e.meta.as_ref()).map(|m| m.seq);
            let first_n = first.map_or(u64::MAX, Seq::get);
            let last_n = last.map_or(0, Seq::get);
            // What the page proves: every event the server keeps in some
            // range is in it (7.2). Expired events are always the oldest
            // (7.5), so a range that starts at or below the sync point
            // moves it.
            let to = match page {
                // Kept events in (after, last] are all here; with more=0,
                // there are none after. An empty last page means the rest
                // up to what was known has expired.
                Page::Forward { after } if after <= start => {
                    if !more && events.is_empty() {
                        known
                    } else {
                        last_n
                    }
                }
                Page::Forward { .. } => 0,
                // more=0: no kept event below the page. Nor between its
                // last event and `before`, since only the oldest expire.
                Page::Newest if !more => last_n.max(if events.is_empty() { known } else { 0 }),
                Page::Backward { before } if !more => {
                    if events.is_empty() {
                        known.min(before - 1)
                    } else {
                        last_n
                    }
                }
                // more=1: kept events from the first to the last are here.
                Page::Newest | Page::Backward { .. } if first_n <= start + 1 => last_n,
                Page::Newest | Page::Backward { .. } => 0,
            };
            tx.raise_sync_point(&mut row, to)?;
            // 7.3: messages loaded below a gap may have edits and reactions
            // in it.
            let related = match (page, first, last) {
                (Page::Backward { .. }, Some(f), Some(l))
                    if tx.first_missing_after(row.id, l.get())? <= known =>
                {
                    Some((f, l))
                }
                _ => None,
            };
            Ok(PageResult::Stored {
                progress: row.sync_point > start,
                sync_point: row.sync_point,
                related,
                last,
            })
        })?;
        match result {
            PageResult::Stale => {}
            PageResult::OtherConversation => {
                self.live(conv).confirmed = None;
                self.want_sync = true;
            }
            PageResult::Stored {
                progress,
                sync_point,
                related,
                last,
            } => {
                if slot == Slot::Auto && matches!(page, Page::Forward { .. }) {
                    if more {
                        // 7.1 step 3: repeat while more=1.
                        let after = sync_point.max(last.map_or(0, Seq::get));
                        self.continue_fill(conv, row_id, epoch, after, (known, goal));
                    } else if !progress {
                        self.live(conv).stuck = Some((known, goal));
                    }
                }
                if slot == Slot::Auto && page == Page::Newest {
                    // One newest page per goal: the rest loads on demand.
                    self.live(conv).newest_for = Some(goal);
                }
                if let Some((first, last)) = related {
                    self.related(conv, row_id, epoch, first, last, None);
                }
            }
        }
        self.check_fill(conv)
    }

    fn on_related(
        &mut self,
        conv: &Conv,
        row_id: ConvId,
        epoch: i64,
        first: Seq,
        last: Seq,
        reply: &Reply,
    ) -> Result<(), SyncError> {
        let Some(id) = self.reply_id(conv, reply) else {
            return Ok(());
        };
        let more = match &reply.outcome {
            Outcome::Ok(ok) => ok.more().ok().flatten().unwrap_or(false),
            _ => false,
        };
        let events = page_events(conv, reply);
        let result = self.write(|tx| {
            let Some(mut row) = tx.conv(row_id)? else {
                return Ok(PageResult::Stale);
            };
            if row.epoch != epoch {
                return Ok(PageResult::Stale);
            }
            if row.conv_id.as_ref() != Some(&id) {
                tx.discard(&mut row, None)?;
                return Ok(PageResult::OtherConversation);
            }
            for e in &events {
                tx.store_event(&row, e)?;
            }
            tx.raise_sync_point(&mut row, 0)?;
            Ok(PageResult::Stored {
                progress: false,
                sync_point: row.sync_point,
                related: None,
                last: events.last().and_then(|e| e.meta.as_ref()).map(|m| m.seq),
            })
        })?;
        match result {
            PageResult::Stale => {}
            PageResult::OtherConversation => {
                self.live(conv).confirmed = None;
                self.want_sync = true;
            }
            PageResult::Stored { last: Some(l), .. } if more => {
                self.related(conv, row_id, epoch, first, last, Some(l.get()));
            }
            PageResult::Stored { .. } => {}
        }
        self.check_fill(conv)
    }

    /// The id in a HISTORY or RELATED reply, or `None` after counting a
    /// failure. `not-found` and `forbidden` mean the account cannot read
    /// the conversation any more, so ask SYNC.
    fn reply_id(&mut self, conv: &Conv, reply: &Reply) -> Option<Id> {
        if let Outcome::Ok(ok) = &reply.outcome
            && let Ok(Some(id)) = ok.id()
        {
            return Some(id);
        }
        let live = self.live(conv);
        if let Some(id) = live.confirmed.clone() {
            live.failed_for = Some(id);
        }
        live.failures += 1;
        if let Outcome::Err(err) = &reply.outcome
            && matches!(err.code, ErrorCode::NotFound | ErrorCode::Forbidden)
        {
            live.confirmed = None;
            if live.failures < MAX_FAILURES {
                self.want_sync = true;
            }
        }
        None
    }

    // -----------------------------------------------------------------------
    // Catching up

    /// Starts catching `conv` up if it is behind and nothing is in flight
    /// (7.1 steps 3 and 4).
    fn check_fill(&mut self, conv: &Conv) -> Result<(), SyncError> {
        let Some(live) = self.convs.get(conv) else {
            return Ok(());
        };
        if live.confirmed.is_none() || live.filling || live.failures >= MAX_FAILURES {
            return Ok(());
        }
        let account = self.account;
        let found = self.write(|tx| match tx.conv_by_name(account, conv)? {
            Some(row) => {
                let newest = tx.max_seq(row.id)?;
                Ok(Some((row, newest)))
            }
            None => Ok(None),
        })?;
        let Some((row, newest)) = found else {
            return Ok(());
        };
        if !self.matches_confirmed(conv, &row) {
            return Ok(());
        }
        let known = row.head.max(newest);
        let lazy_gap = self.config.lazy_gap;
        let live = self.live(conv);
        let top = row.head.max(live.dropped);
        let goal = known.max(live.dropped);
        if row.sync_point >= goal {
            live.download = false;
            return Ok(());
        }
        if live.stuck == Some((known, goal)) {
            live.download = false;
            return Ok(());
        }
        let lazy = !live.download && lazy_gap.is_some_and(|gap| goal - row.sync_point > gap);
        let page = if lazy {
            if newest >= top || live.newest_for == Some(goal) {
                // The newest events are here; the rest loads on demand.
                return Ok(());
            }
            Page::Newest
        } else {
            Page::Forward {
                after: row.sync_point,
            }
        };
        let limit = self.config.page_size;
        self.history(conv, &row, page, Slot::Auto, (known, goal), limit);
        Ok(())
    }

    /// Asks for the next forward page after a page with more=1.
    fn continue_fill(
        &mut self,
        conv: &Conv,
        row: ConvId,
        epoch: i64,
        after: u64,
        (known, goal): (u64, u64),
    ) {
        let live = self.live(conv);
        if live.confirmed.is_none() || live.filling {
            return;
        }
        live.filling = true;
        let command = Command::History {
            conv: conv.clone(),
            after: Some(after),
            before: None,
            limit: NonZeroU64::new(self.config.page_size),
            only: None,
        };
        self.issue(
            command,
            Pending::History {
                conv: conv.clone(),
                row,
                epoch,
                page: Page::Forward { after },
                slot: Slot::Auto,
                known,
                goal,
            },
        );
    }

    fn history(
        &mut self,
        conv: &Conv,
        row: &ConvRow,
        page: Page,
        slot: Slot,
        (known, goal): (u64, u64),
        limit: u64,
    ) {
        let live = self.live(conv);
        match slot {
            Slot::Auto => live.filling = true,
            Slot::Older => live.loading_older = true,
            Slot::Extra => {}
        }
        let (after, before) = match page {
            Page::Forward { after } => (Some(after), None),
            Page::Newest => (None, None),
            Page::Backward { before } => (None, Seq::new(before)),
        };
        let command = Command::History {
            conv: conv.clone(),
            after,
            before,
            limit: NonZeroU64::new(limit),
            only: None,
        };
        self.issue(
            command,
            Pending::History {
                conv: conv.clone(),
                row: row.id,
                epoch: row.epoch,
                page,
                slot,
                known,
                goal,
            },
        );
    }

    fn related(
        &mut self,
        conv: &Conv,
        row: ConvId,
        epoch: i64,
        first: Seq,
        last: Seq,
        after: Option<u64>,
    ) {
        let command = Command::Related {
            conv: conv.clone(),
            first,
            last,
            after: Some(after.unwrap_or(last.get())),
            limit: NonZeroU64::new(self.config.page_size),
        };
        self.issue(
            command,
            Pending::Related {
                conv: conv.clone(),
                row,
                epoch,
                first,
                last,
            },
        );
    }

    // -----------------------------------------------------------------------
    // The outbox (7.6)

    /// Sends every outbox entry that can be sent now, and fails those that
    /// cannot be sent safely any more.
    ///
    /// Picking the entries and marking them as sent is one write
    /// transaction (`BEGIN IMMEDIATE`), so that another process sharing the
    /// cache cannot pick them too. An entry another process's connection
    /// sent is left to it while its claim lasts
    /// ([`SyncConfig::claim_lease`]).
    fn flush_outbox(&mut self) -> Result<(), SyncError> {
        let account = self.account;
        let now = self.now();
        let window = self.config.resend_window;
        let lease = self.config.claim_lease;
        // A guest's cids count only within its session (7.6).
        let cids_hold = !self.guest || self.resumed;
        let claim = self.claim.clone();
        let store = self.store.clone();
        let in_flight = self.sending.clone();
        let confirmed: HashMap<Conv, Id> = self
            .convs
            .iter()
            .filter_map(|(c, l)| Some((c.clone(), l.confirmed.clone()?)))
            .collect();
        // Rooms the account is not in can be told apart from rooms not
        // confirmed yet only once SYNC has answered (7.1).
        let synced = self.syncing.is_none() && !self.want_sync;
        let to_send = self.write(|tx| {
            let mut to_send = Vec::new();
            for item in tx.outbox_pending(account)? {
                if in_flight.contains(&item.id) {
                    continue;
                }
                if item.state == OutboxState::Sending {
                    // Another process may still be waiting for its answer.
                    if let Some((other, at)) = &item.claim
                        && !store.is_own_instance(other)
                        && now.saturating_duration_since(*at) < lease
                    {
                        continue;
                    }
                    // Sent on an earlier connection, with no answer. Only an
                    // identity's cid survives that, or a resumed guest
                    // session's, and only for 24 hours. A DELETE needs no
                    // cid: sent twice, the second gets `OK` with the first
                    // one's seq (5.4).
                    let fresh = item
                        .first_sent
                        .is_some_and(|t| now.saturating_duration_since(t) < window);
                    if item.delete.is_none() && (!cids_hold || !fresh) {
                        tx.outbox_failed(item.id, FailReason::Unconfirmed)?;
                        continue;
                    }
                }
                // The id confirmed on this connection, if the store still
                // has it: another process sharing the store may have
                // learned that the room changed.
                let row = tx.conv_by_name(account, &item.conv)?;
                let left = row.as_ref().is_some_and(|r| !r.joined);
                let stored = row.and_then(|r| r.conv_id);
                let live = confirmed
                    .get(&item.conv)
                    .filter(|id| stored.as_ref() == Some(*id));
                match (&item.conv_id, live) {
                    (Some(bound), Some(id)) if bound == id => {}
                    (Some(bound), None)
                        if item.delete.is_some()
                            && delete_left(synced, left, stored.as_ref(), bound) => {}
                    (Some(_), Some(_)) => {
                        // The room was dropped and created again (7.6).
                        tx.outbox_failed(item.id, FailReason::RoomChanged)?;
                        continue;
                    }
                    (None, Some(id)) => tx.outbox_bind(item.id, id)?,
                    (Some(_), None) => continue,
                    (None, None) => {
                        // A direct conversation that has not started: its
                        // first message starts it (5.1). Wait if it has an
                        // id now.
                        if stored.is_some() || item.conv.is_room() {
                            continue;
                        }
                    }
                }
                tx.outbox_sending(item.id, &claim, now)?;
                to_send.push(item);
            }
            Ok(to_send)
        })?;
        for item in to_send {
            let command = match item.delete {
                // The id the entry is bound to, so that the server deletes
                // nothing in a room created again under the same name
                // (5.4).
                Some(seq) => Command::Delete {
                    conv: item.conv,
                    seq,
                    id: item.conv_id.clone(),
                },
                None => Command::Msg {
                    conv: item.conv,
                    text: item.draft.text,
                    relation: item.draft.relation,
                    file: item.draft.file,
                    cid: Some(item.cid),
                },
            };
            self.sending.insert(item.id);
            self.issue(command, Pending::Msg { outbox: item.id });
        }
        Ok(())
    }
}

/// Whether a DELETE bound to `bound` may be sent for a room that is not
/// confirmed on this connection (5.4): SYNC has answered, the cache says
/// the account is not in the room, and still has the id the DELETE is
/// bound to. Authors may delete their own messages in rooms they have
/// left, but the server cannot confirm the room's id to someone who no
/// longer reads it, so a room dropped and created again since it was last
/// seen cannot be told apart here. The server deletes only the sender's
/// own messages in a room they cannot read.
fn delete_left(synced: bool, left: bool, stored: Option<&Id>, bound: &Id) -> bool {
    synced && left && stored == Some(bound)
}

/// Learns a conversation's id and head from a reply (7.1). The head is
/// checked only against `floor`, the sync point when the command was sent
/// (see [`SyncEngine::head_floor`]), and against the sync point now, which
/// is lower if the history was discarded since.
fn learn(
    tx: &mut Tx<'_>,
    row: &mut ConvRow,
    id: &Id,
    head: Option<u64>,
    floor: Option<u64>,
) -> Result<bool, StoreError> {
    if let (Some(h), Some(f)) = (head, floor)
        && h < f
    {
        return tx.learn_id(row, id, head);
    }
    let reset = tx.learn_id(row, id, None)?;
    if let Some(head) = head {
        tx.note_head(row, head)?;
    }
    Ok(reset)
}

/// The events of a HISTORY or RELATED reply that belong to `conv`.
fn page_events(conv: &Conv, reply: &Reply) -> Vec<Event> {
    let mut events: Vec<Event> = reply
        .lines
        .iter()
        .filter_map(|m| match &m.line {
            ServerLine::Event(e) if e.meta.is_some() && e.body.conv() == *conv => Some(e.clone()),
            _ => None,
        })
        .collect();
    events.sort_by_key(|e| e.meta.as_ref().map(|m| m.seq));
    events
}
