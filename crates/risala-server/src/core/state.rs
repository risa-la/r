//! The hub's state in memory: connections, who is signed in as whom, room
//! membership, and the per-room locks that keep events in order.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::Arc;

use risala_proto::auth::Nonce;
use risala_proto::names::{Id, Room, Seq, Uid};
use risala_proto::server::ServerMessage;
use risala_proto::time::Timestamp;
use risala_proto::types::{Cid, Role};

use crate::handler::{ConnHandle, ConnId, ConnInfo};
use crate::store::{CID_WINDOW_MS, ConvKey, RoomRecord, RoomSettings};

/// A room the hub knows. Its state sits behind an async lock, which is
/// held while an event is assigned its seq, stored and queued for every
/// member's connection. That is what keeps each connection's view of a
/// room in seq order (5.2), however many connections post at once.
#[derive(Debug)]
pub(crate) struct RoomEntry {
    pub(crate) state: tokio::sync::Mutex<RoomState>,
}

/// What the hub keeps about a room besides its members. Changed only while
/// the room's lock is held.
#[derive(Debug)]
pub(crate) struct RoomState {
    pub(crate) room: Room,
    pub(crate) key: ConvKey,
    pub(crate) id: Id,
    /// The newest seq, or `None` before the first event.
    pub(crate) head: Option<Seq>,
    pub(crate) settings: RoomSettings,
    /// Owners and moderators (6.3).
    pub(crate) roles: BTreeMap<Uid, Role>,
}

impl RoomEntry {
    pub(crate) fn new(record: RoomRecord) -> RoomEntry {
        RoomEntry {
            state: tokio::sync::Mutex::new(RoomState {
                room: record.room,
                key: record.key,
                id: record.id,
                head: record.head,
                settings: record.settings,
                roles: record.roles.into_iter().collect(),
            }),
        }
    }
}

/// The most cids remembered per guest connection (7.6). Older ones are
/// forgotten first, so a guest cannot grow the server's memory without
/// bound.
const GUEST_CIDS: usize = 1024;

/// A guest connection's cids (7.6): the cid and conversation id of each
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

/// One open connection.
#[derive(Debug)]
pub(crate) struct ConnEntry {
    pub(crate) handle: ConnHandle,
    #[allow(dead_code)] // ADMIN WHO (10.3) and address bans (10.2), M4.
    pub(crate) info: ConnInfo,
    /// The host from the greeting, for checking AUTH signatures (4.5), M3.
    #[allow(dead_code)]
    pub(crate) host: String,
    /// The greeting's nonce (4.1), used up by AUTH or REGISTER (4.5), M3.
    #[allow(dead_code)]
    pub(crate) nonce: Nonce,
    /// Who the connection signed in as.
    pub(crate) uid: Option<Uid>,
    /// Held by each command while it runs, and by the clean-up after the
    /// connection closes, so that the clean-up never overlaps a command.
    pub(crate) gate: Arc<tokio::sync::Mutex<()>>,
    pub(crate) guest_cids: CidCache,
    /// The task that closes the connection if it does not sign in (4.1).
    pub(crate) sign_in_timer: Option<tokio::task::AbortHandle>,
}

/// Connections, users and room membership. Behind one plain mutex that is
/// never held across an await.
///
/// Membership changes only while the room's own lock is held too, so that
/// fan-out under that lock sees a stable set of members.
#[derive(Debug, Default)]
pub(crate) struct Registry {
    pub(crate) conns: HashMap<ConnId, ConnEntry>,
    /// The connections signed in as each uid. A guest has one.
    pub(crate) users: HashMap<Uid, Vec<ConnId>>,
    /// The members of each room: identities (also stored) and guests (only
    /// here).
    pub(crate) members: HashMap<Room, BTreeSet<Uid>>,
    /// The rooms each uid is a member of.
    pub(crate) rooms_of: HashMap<Uid, BTreeSet<Room>>,
}

impl Registry {
    pub(crate) fn is_member(&self, room: &Room, uid: &Uid) -> bool {
        self.members.get(room).is_some_and(|m| m.contains(uid))
    }

    pub(crate) fn member_count(&self, room: &Room) -> u64 {
        self.members.get(room).map_or(0, |m| m.len() as u64)
    }

    pub(crate) fn add_member(&mut self, room: &Room, uid: &Uid) {
        self.members
            .entry(room.clone())
            .or_default()
            .insert(uid.clone());
        self.rooms_of
            .entry(uid.clone())
            .or_default()
            .insert(room.clone());
    }

    pub(crate) fn remove_member(&mut self, room: &Room, uid: &Uid) {
        if let Some(m) = self.members.get_mut(room) {
            m.remove(uid);
            if m.is_empty() {
                self.members.remove(room);
            }
        }
        if let Some(r) = self.rooms_of.get_mut(uid) {
            r.remove(room);
            if r.is_empty() {
                self.rooms_of.remove(uid);
            }
        }
    }

    /// Queues `msg` for every connection of every member of `room` (5.2).
    pub(crate) fn broadcast(&self, room: &Room, msg: &ServerMessage) {
        let Some(members) = self.members.get(room) else {
            return;
        };
        for uid in members {
            self.send_to_user(uid, msg);
        }
    }

    /// Queues `msg` for every connection signed in as `uid`.
    pub(crate) fn send_to_user(&self, uid: &Uid, msg: &ServerMessage) {
        for id in self.users.get(uid).into_iter().flatten() {
            if let Some(conn) = self.conns.get(id) {
                // A full queue kills only that connection (PLAN.md 3.2).
                conn.handle.send(msg.clone());
            }
        }
    }
}
