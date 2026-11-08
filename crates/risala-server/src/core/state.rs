//! The hub's state in memory: connections, who is signed in as whom,
//! conversations and their members, and the per-conversation locks that
//! keep events in order.
//!
//! # Locks
//!
//! There are three kinds, always taken in this order, and the two plain
//! mutexes are never held across an `await`:
//!
//! 1. a conversation's async lock ([`ConvEntry`]), held while an event is
//!    assigned its seq, stored and queued, and while its members change
//! 2. the [`Registry`] mutex: connections, users and guest sessions
//! 3. a user's own mutex ([`UserEntry`]): its connections and the
//!    conversations it is in
//!
//! Fan-out takes only 1 and 3: a conversation holds its members'
//! [`UserEntry`]s, so queuing an event for every member's connections
//! never touches the registry.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};

use risala_proto::auth::{Nonce, PublicKey};
use risala_proto::names::{Conv, Id, Room, Seq, Uid};
use risala_proto::time::Timestamp;
use risala_proto::types::{Cid, Role};

use super::presence::PresenceBook;
use crate::handler::{ConnHandle, ConnId, ConnInfo, OutLine};
use crate::store::{CID_WINDOW_MS, ConvKey, RoomRecord, RoomSettings};

/// A conversation the hub knows, behind its async lock. The lock is held
/// while an event is assigned its seq, stored and queued for every
/// member's connection. That is what keeps each connection's view of a
/// conversation in seq order (5.2), however many connections post at once.
/// Membership changes under it too, so fan-out sees a stable set of
/// members.
pub(crate) type ConvEntry = tokio::sync::Mutex<ConvState>;

/// The lock on a conversation, held by its own `Arc`, so that it can be
/// returned from a lookup.
pub(crate) type ConvGuard = tokio::sync::OwnedMutexGuard<ConvState>;

/// What the hub keeps about a conversation. Changed only while its lock is
/// held.
#[derive(Debug)]
pub(crate) struct ConvState {
    /// The store's key for it.
    pub(crate) key: ConvKey,
    /// Its id (5.1). Membership, cids and SYNC go by this, so that a room
    /// dropped and created again under the same name starts afresh.
    pub(crate) id: Id,
    /// The newest seq, or `None` before the first event.
    pub(crate) head: Option<Seq>,
    /// The conversation was deleted (ADMIN DROP, M4) while a command waited
    /// for its lock. It is gone from every index, so such a command answers
    /// `ERR not-found`, as if it had come a moment later.
    pub(crate) dropped: bool,
    /// The members, with their users' entries for fan-out: identities
    /// (also stored) and guests (only here).
    pub(crate) members: BTreeMap<Uid, Arc<UserEntry>>,
    /// What kind of conversation it is.
    pub(crate) kind: ConvKind,
    /// The value of the hub's count of read marker changes at the last
    /// change of a marker in this conversation, or 0. SYNC reads every
    /// marker at once, then reads one again under this lock if it moved
    /// since (3.6, 7.1).
    pub(crate) marker_moved: u64,
}

/// The kinds of conversation (5.1). Direct conversations come with M5a.
#[derive(Debug)]
pub(crate) enum ConvKind {
    /// A room (Section 6).
    Room(RoomInfo),
}

/// What only rooms have.
#[derive(Debug)]
pub(crate) struct RoomInfo {
    pub(crate) room: Room,
    pub(crate) settings: RoomSettings,
    /// Owners and moderators (6.3), members or not.
    pub(crate) roles: BTreeMap<Uid, Role>,
    /// Open invitations (6.4).
    pub(crate) invites: BTreeSet<Uid>,
    /// Room bans (6.4).
    pub(crate) bans: BTreeSet<Uid>,
}

impl ConvState {
    /// The state of a stored room, with no members yet: the caller adds
    /// them, since it needs their [`UserEntry`]s.
    pub(crate) fn room(record: RoomRecord) -> ConvState {
        ConvState {
            key: record.key,
            id: record.id,
            head: record.head,
            dropped: false,
            members: BTreeMap::new(),
            marker_moved: 0,
            kind: ConvKind::Room(RoomInfo {
                room: record.room,
                settings: record.settings,
                roles: record.roles.into_iter().collect(),
                invites: record.invites.into_iter().collect(),
                bans: record.bans.into_iter().collect(),
            }),
        }
    }

    /// The room part, for a conversation that is a room.
    pub(crate) fn room_info(&self) -> Option<&RoomInfo> {
        match &self.kind {
            ConvKind::Room(info) => Some(info),
        }
    }

    /// The room part, for a conversation that is a room.
    pub(crate) fn room_info_mut(&mut self) -> Option<&mut RoomInfo> {
        match &mut self.kind {
            ConvKind::Room(info) => Some(info),
        }
    }

    /// The conversation's name as `uid` sees it (5.2).
    pub(crate) fn name_for(&self, _uid: &Uid) -> Conv {
        match &self.kind {
            ConvKind::Room(info) => Conv::Room(info.room.clone()),
        }
    }

    pub(crate) fn is_member(&self, uid: &Uid) -> bool {
        self.members.contains_key(uid)
    }

    pub(crate) fn member_count(&self) -> u64 {
        self.members.len() as u64
    }

    /// This conversation's place in `uid`'s list of conversations.
    pub(crate) fn conv_ref(&self, uid: &Uid) -> ConvRef {
        ConvRef {
            name: self.name_for(uid),
            id: self.id.clone(),
        }
    }

    /// Makes `user` a member. `entry` is this conversation's own entry,
    /// which the user's list of conversations keeps.
    pub(crate) fn add_member(&mut self, entry: &Arc<ConvEntry>, user: &Arc<UserEntry>) {
        self.members.insert(user.uid.clone(), user.clone());
        let at = self.conv_ref(&user.uid);
        user.lock().convs.insert(at, entry.clone());
    }

    /// Removes `uid` from the members. Returns its entry, if it was one.
    pub(crate) fn remove_member(&mut self, uid: &Uid) -> Option<Arc<UserEntry>> {
        let user = self.members.remove(uid)?;
        user.lock().convs.remove(&self.conv_ref(uid));
        Some(user)
    }

    /// Queues `line` for every connection of every member (5.2). The line
    /// is encoded once and shared.
    pub(crate) fn broadcast(&self, line: &OutLine) {
        for user in self.members.values() {
            user.send(line);
        }
    }
}

/// Where a conversation sits in a user's list: by the name the user knows
/// it by, so that SYNC lists conversations in order, and then by id, which
/// is what membership goes by (5.1).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ConvRef {
    pub(crate) name: Conv,
    pub(crate) id: Id,
}

/// The most cids remembered per guest session (7.6). Older ones are
/// forgotten first, so a guest cannot grow the server's memory without
/// bound.
const GUEST_CIDS: usize = 1024;

/// A guest session's cids (7.6): the cid and conversation id of each
/// message it sent, with the message's seq.
#[derive(Debug, Default)]
pub(crate) struct CidCache {
    map: HashMap<(Id, Cid), (Seq, Timestamp)>,
    order: VecDeque<(Id, Cid)>,
}

impl CidCache {
    /// The seq of the message sent with `cid` to the conversation with id
    /// `id` in the last 24 hours.
    pub(crate) fn get(&self, id: &Id, cid: &Cid, now: Timestamp) -> Option<Seq> {
        let (seq, t) = self.map.get(&(id.clone(), cid.clone()))?;
        (now.saturating_duration_since(*t).as_millis() <= u128::from(CID_WINDOW_MS)).then_some(*seq)
    }

    pub(crate) fn insert(&mut self, id: Id, cid: Cid, seq: Seq, now: Timestamp) {
        let key = (id, cid);
        if self.map.insert(key.clone(), (seq, now)).is_none() {
            self.order.push_back(key);
        }
        while self.order.len() > GUEST_CIDS {
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            }
        }
    }
}

/// One user, guest or identity, as fan-out sees it: the connections signed
/// in as it, and the conversations it is a member of.
///
/// There is at most one entry per uid at a time: [`Registry::user`] makes
/// them, and [`Registry::release`] forgets one only when nothing else holds
/// it.
#[derive(Debug)]
pub(crate) struct UserEntry {
    pub(crate) uid: Uid,
    inner: Mutex<UserState>,
    /// Held while the account's blocks change and the change is sent to
    /// its other connections, and while BLOCKS answers, so that a BLOCKS
    /// reply covers every BLOCK and UNBLOCK line sent before it (5.7).
    pub(crate) blocks: tokio::sync::Mutex<()>,
}

/// See [`UserEntry`].
#[derive(Debug, Default)]
pub(crate) struct UserState {
    /// The connections signed in as the user. A guest has at most one:
    /// none while its session waits to be resumed.
    pub(crate) conns: Vec<UserConn>,
    /// The conversations the user is a member of, in name order.
    pub(crate) convs: BTreeMap<ConvRef, Arc<ConvEntry>>,
    /// The identity is being deleted, or was (4.8): it may not join rooms
    /// or sign in. Once UNREGISTER is done, the registry forgets the entry
    /// for good, and the next sign-in gets a new one, so this stays set
    /// for whatever still holds the old one.
    pub(crate) ending: bool,
}

/// A connection signed in as a user.
#[derive(Debug, Clone)]
pub(crate) struct UserConn {
    pub(crate) handle: ConnHandle,
    /// The device key it signed in with (4.5), for identities.
    pub(crate) key: Option<PublicKey>,
}

impl UserEntry {
    fn new(uid: Uid) -> UserEntry {
        UserEntry {
            uid,
            inner: Mutex::new(UserState::default()),
            blocks: tokio::sync::Mutex::new(()),
        }
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, UserState> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Queues `line` for every connection signed in as the user.
    pub(crate) fn send(&self, line: &OutLine) {
        for conn in &self.lock().conns {
            // A full queue kills only that connection (PLAN.md 3.2).
            conn.handle.send_line(line.clone());
        }
    }

    /// Queues `line` for every connection signed in as the user but
    /// `except`.
    pub(crate) fn send_except(&self, line: &OutLine, except: ConnId) {
        for conn in &self.lock().conns {
            if conn.handle.id() != except {
                conn.handle.send_line(line.clone());
            }
        }
    }

    /// The conversations the user is a member of.
    pub(crate) fn convs(&self) -> Vec<Arc<ConvEntry>> {
        self.lock().convs.values().cloned().collect()
    }

    /// Whether the user has no connections and is in no conversation.
    fn is_idle(&self) -> bool {
        let state = self.lock();
        state.conns.is_empty() && state.convs.is_empty() && !state.ending
    }
}

/// One open connection.
#[derive(Debug)]
pub(crate) struct ConnEntry {
    pub(crate) handle: ConnHandle,
    pub(crate) info: ConnInfo,
    /// The greeting's nonce (4.1), until an AUTH or REGISTER that parses
    /// uses it up (4.5).
    pub(crate) nonce: Option<Nonce>,
    /// Who the connection signed in as.
    pub(crate) uid: Option<Uid>,
    /// The connection was signed out from under itself: its guest session
    /// moved to another connection or ended (4.2), or its identity's key
    /// was removed or the identity deleted (4.7, 4.8). It runs no more
    /// commands, and is closed with BYE.
    pub(crate) detached: bool,
    /// Held by each command while it runs, and by the clean-up after the
    /// connection closes, so that the clean-up never overlaps a command.
    pub(crate) gate: Arc<tokio::sync::Mutex<()>>,
    /// The connection is running an UNREGISTER or ADMIN UNREGISTER (4.8,
    /// 10.5), which waits for the gates of the deleted identity's
    /// connections. Set and read under the registry's lock, so that two
    /// such commands never wait for each other's gates.
    pub(crate) unregistering: bool,
    /// The task that closes the connection if it does not sign in (4.1).
    pub(crate) sign_in_timer: Option<tokio::task::AbortHandle>,
    /// When the connection last had a TYPING passed on, by conversation id
    /// (8.1), for `limits.typing_interval_ms`.
    pub(crate) typing: HashMap<Id, tokio::time::Instant>,
}

/// The most conversations a connection's TYPING times are kept for before
/// the old ones are forgotten.
const TYPING_CONVS: usize = 64;

impl ConnEntry {
    /// Whether a TYPING to the conversation `id` may be passed on now, at
    /// most one per `interval` (8.1, 13). If so, it counts from now.
    pub(crate) fn may_type(&mut self, id: &Id, interval: std::time::Duration) -> bool {
        let now = tokio::time::Instant::now();
        if let Some(last) = self.typing.get(id)
            && now.saturating_duration_since(*last) < interval
        {
            return false;
        }
        if self.typing.len() >= TYPING_CONVS {
            self.typing
                .retain(|_, last| now.saturating_duration_since(*last) < interval);
        }
        self.typing.insert(id.clone(), now);
        true
    }
    /// A message to the conversation `id` ended this connection's typing
    /// notification (8.1), so the next TYPING starts afresh and is passed
    /// on at once.
    pub(crate) fn typing_ended(&mut self, id: &Id) {
        self.typing.remove(id);
    }
}

/// A guest's session (4.2): it starts with GUEST, moves to a new connection
/// when the guest resumes it, and ends a while after its connection
/// closes. While it lasts, it holds the guest's name, rooms and cids.
#[derive(Debug)]
pub(crate) struct GuestSession {
    /// The token that resumes the session. It lives only here, in memory:
    /// sessions do not survive a restart, so it never needs to be stored.
    /// Never logged.
    pub(crate) token: Id,
    /// The connection that has the session, or `None` while it waits to be
    /// resumed.
    pub(crate) conn: Option<ConnId>,
    /// The address of the session's connection, or of its last one while
    /// it waits to be resumed: an address ban covering it ends the session
    /// (10.2).
    pub(crate) address: IpAddr,
    pub(crate) cids: CidCache,
    /// Counts the times the session started waiting, so that a resume
    /// period that has been cut short cannot end a later one.
    pub(crate) epoch: u64,
    /// The task that ends the session when its resume period is over.
    pub(crate) expiry: Option<tokio::task::AbortHandle>,
    /// The session is ending: its PARTs are being recorded. It still holds
    /// its name, but can no longer be resumed or join rooms.
    pub(crate) ending: bool,
    /// The guest's display name (8.2), escaped; empty if none. It lasts as
    /// long as the session.
    pub(crate) display_name: String,
    /// The seq of the first message the session sent in each conversation.
    /// Messages sent there under the name before it were another guest's,
    /// so this one may not edit or delete them (4.2, 5.3, 5.4). The name is
    /// the session's alone while it lasts, so every later one is its own.
    /// Seqs, not times, so that a clock that steps back changes nothing.
    pub(crate) first_sent: HashMap<ConvKey, Seq>,
}

impl GuestSession {
    /// Whether `token` is the session's current token, compared in
    /// constant time.
    pub(crate) fn token_is(&self, token: &Id) -> bool {
        let (a, b) = (self.token.as_str().as_bytes(), token.as_str().as_bytes());
        a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
    }
}

/// Connections, users and guest sessions. Behind one plain mutex that is
/// never held across an await, and that fan-out does not take.
#[derive(Debug, Default)]
pub(crate) struct Registry {
    pub(crate) conns: HashMap<ConnId, ConnEntry>,
    /// Every user that has a connection or is in a conversation, and
    /// perhaps some that no longer do (see [`release`](Self::release)).
    pub(crate) users: HashMap<Uid, Arc<UserEntry>>,
    /// Guest sessions (4.2), connected or waiting, by uid. A guest's name
    /// is taken for as long as it has one.
    pub(crate) sessions: HashMap<Uid, GuestSession>,
    /// The presence of identities (8.3), which changes as their first
    /// connection opens and their last one closes.
    pub(crate) presence: PresenceBook,
}

impl Registry {
    /// The entry of `uid`, made if there is none.
    pub(crate) fn user(&mut self, uid: &Uid) -> Arc<UserEntry> {
        self.users
            .entry(uid.clone())
            .or_insert_with(|| Arc::new(UserEntry::new(uid.clone())))
            .clone()
    }

    /// Forgets the entry of `uid` if it has no connections, is in no
    /// conversation and nobody else holds it. Called whenever one of those
    /// may have become true. Holding the registry lock, nobody can take a
    /// new reference meanwhile, so a later [`user`](Self::user) makes a
    /// fresh entry that nothing else knows.
    pub(crate) fn release(&mut self, uid: &Uid) {
        if let Some(user) = self.users.get(uid)
            && Arc::strong_count(user) == 1
            && user.is_idle()
        {
            self.users.remove(uid);
        }
    }

    /// Whether `uid` is an identity that is not being deleted, or a guest
    /// whose session is neither over nor ending. Only then may it join a
    /// room.
    pub(crate) fn may_join(&self, uid: &Uid) -> bool {
        if uid.is_guest() {
            self.sessions.get(uid).is_some_and(|s| !s.ending)
        } else {
            !self.users.get(uid).is_some_and(|u| u.lock().ending)
        }
    }

    /// Signs connection `id` in as `uid`, with `key` as its device key
    /// (4.5). From now on it gets the live events of the user's
    /// conversations (7.1). Returns `false` if the connection is gone.
    pub(crate) fn attach(&mut self, id: ConnId, uid: &Uid, key: Option<PublicKey>) -> bool {
        let Some(conn) = self.conns.get_mut(&id) else {
            return false;
        };
        conn.uid = Some(uid.clone());
        if let Some(timer) = conn.sign_in_timer.take() {
            timer.abort();
        }
        let handle = conn.handle.clone();
        // Long lines from now on (2.3).
        handle.set_signed_in();
        let user = self.user(uid);
        let first = {
            let mut state = user.lock();
            state.conns.push(UserConn { handle, key });
            state.conns.len() == 1
        };
        if first && uid.is_identity() {
            self.presence.connected(uid);
        }
        true
    }

    /// Takes connection `id` away from its user, if it has one.
    fn unlink(&mut self, id: ConnId, uid: &Uid) {
        if let Some(user) = self.users.get(uid) {
            let last = {
                let mut state = user.lock();
                let before = state.conns.len();
                state.conns.retain(|c| c.handle.id() != id);
                before > 0 && state.conns.is_empty()
            };
            if last && uid.is_identity() {
                self.presence.disconnected(uid);
            }
        }
        self.release(uid);
    }

    /// Signs connection `id` out from under itself: it gets no more live
    /// events, runs no more commands, and is closed with BYE (4.2, 4.7,
    /// 4.8).
    pub(crate) fn detach(&mut self, id: ConnId, bye: &str) {
        let Some(conn) = self.conns.get_mut(&id) else {
            return;
        };
        conn.detached = true;
        conn.handle.close(Some(bye.to_owned()));
        if let Some(uid) = conn.uid.take() {
            self.unlink(id, &uid);
        }
    }

    /// The connection has closed: forgets it. Returns its entry.
    pub(crate) fn remove_conn(&mut self, id: ConnId) -> Option<ConnEntry> {
        let conn = self.conns.remove(&id)?;
        if let Some(uid) = &conn.uid {
            self.unlink(id, uid);
        }
        Some(conn)
    }
}
