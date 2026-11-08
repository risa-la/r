//! Mailboxes and delivery (5.2, 6.1, 6.4, 7): CREATE, POST, GROUPINFO,
//! MUTE, UNMUTE, FOLLOW, UNFOLLOW, FETCH and TOKEN, the GONE and DROP
//! lines, moves (7.8), retention and quotas (7.5).
//!
//! Not built yet: every command replies `ERR not-supported`. What is here
//! is the followers of each mailbox, and GONE when a guest's session ends
//! (4.2, 6.1).
//!
//! The store keeps mailboxes, token hashes, posts, cids, public rooms,
//! their members and mutes ([`MailboxStore`](crate::store::MailboxStore)).

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex, MutexGuard};

use risala_proto::command::Command;
use risala_proto::names::{BoxName, Uid};
use risala_proto::server::{ServerLine, ServerMessage};

use super::Inner;
use super::command::{Cx, Reply, misrouted, not_supported};
use super::state::ConnEntry;
use crate::config::Config;
use crate::handler::{ConnId, OutLine};
use crate::store::{Store, StoreError};

/// What the mailbox area keeps in memory.
#[derive(Debug)]
pub(crate) struct State {
    follows: Mutex<Follows>,
}

/// Which connections follow which mailboxes (7.1), both ways.
#[derive(Debug, Default)]
struct Follows {
    by_box: HashMap<BoxName, BTreeSet<ConnId>>,
    by_conn: HashMap<ConnId, BTreeSet<BoxName>>,
}

impl State {
    /// Loads the area's state when the hub starts.
    pub(crate) fn load(_config: &Config, _store: &dyn Store) -> Result<State, StoreError> {
        Ok(State {
            follows: Mutex::default(),
        })
    }

    fn follows(&self) -> MutexGuard<'_, Follows> {
        self.follows.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Connection `conn` follows `mailbox` from now on (7.1).
    #[allow(
        dead_code,
        reason = "used by the areas as they are built (docs/plans/M5b.md, SV1-SV5)"
    )]
    pub(crate) fn follow(&self, mailbox: BoxName, conn: ConnId) {
        let mut follows = self.follows();
        follows.by_box.entry(mailbox).or_default().insert(conn);
        follows.by_conn.entry(conn).or_default().insert(mailbox);
    }

    /// The connections that follow `mailbox`.
    pub(crate) fn followers(&self, mailbox: &BoxName) -> Vec<ConnId> {
        self.follows()
            .by_box
            .get(mailbox)
            .map(|conns| conns.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Connection `conn` follows nothing any more.
    fn forget(&self, conn: ConnId) {
        let mut follows = self.follows();
        for mailbox in follows.by_conn.remove(&conn).unwrap_or_default() {
            if let Some(conns) = follows.by_box.get_mut(&mailbox) {
                conns.remove(&conn);
                if conns.is_empty() {
                    follows.by_box.remove(&mailbox);
                }
            }
        }
    }
}

/// What the mailbox area keeps about one connection.
#[derive(Debug, Default)]
pub(crate) struct ConnState {}

/// Handles CREATE, POST, GROUPINFO, MUTE, UNMUTE, FOLLOW, UNFOLLOW, FETCH
/// and TOKEN.
pub(super) async fn handle(_cx: &Cx, command: Command) -> Reply {
    match command {
        Command::Create { .. } // 5.2
        | Command::Post { .. } // 5.2
        | Command::GroupInfo { .. } // 6.1
        | Command::Mute { .. } // 6.4
        | Command::Unmute { .. } // 6.4
        | Command::Follow { .. } // 7.1
        | Command::Unfollow { .. } // 7.1
        | Command::Fetch { .. } // 7.1
        | Command::Token { .. } /* 7.2 */ => not_supported(),
        other => misrouted("mailbox", &other),
    }
}

/// The session of the guest `uid` has ended (4.2): every connection that
/// follows a public room the guest had a leaf in gets `GONE <box> <uid>`,
/// so that members' devices remove its leaves (6.1).
pub(super) async fn guest_session_ended(inner: &Inner, uid: &Uid) {
    let who = uid.clone();
    let rooms = match inner.db(move |store| store.rooms_with_member(&who)).await {
        Ok(rooms) => rooms,
        Err(e) => {
            tracing::error!("finding a guest's rooms for GONE: {e}");
            return;
        }
    };
    for mailbox in rooms {
        let line = OutLine::new(ServerMessage::new(ServerLine::Gone {
            mailbox,
            uid: uid.clone(),
        }));
        let followers = inner.mailbox.followers(&mailbox);
        let handles: Vec<_> = {
            let reg = inner.reg();
            followers
                .iter()
                .filter_map(|id| reg.conns.get(id))
                .map(|conn| conn.handle.clone())
                .collect()
        };
        for handle in handles {
            handle.send_line(line.clone());
        }
    }
}

/// Connection `id` has closed: it follows nothing any more.
pub(super) fn conn_closed(inner: &Arc<Inner>, id: ConnId, _conn: &ConnEntry) {
    inner.mailbox.forget(id);
}

/// The area's background work: expiring posts (7.5) and cids (7.6),
/// forgetting unused token sets (7.2), and ending mailboxes (7.5).
pub(super) async fn maintain(_inner: Arc<Inner>) {}

/// The most a mailbox may hold at once, for INFO's `quota=` (7.5, 8.5), or
/// `None` while the server sets none.
///
/// TODO(SV3): a stub added by SV5 (INFO) until quotas are built.
pub(crate) fn quota(_inner: &Inner) -> Option<u64> {
    None
}

/// The mailbox was dropped (10.4): nobody follows it any more.
///
/// TODO(SV3): added by SV5 for ADMIN DROP.
pub(crate) fn dropped(inner: &Inner, mailbox: &BoxName) {
    let mut follows = inner.mailbox.follows();
    for conn in follows.by_box.remove(mailbox).unwrap_or_default() {
        if let Some(boxes) = follows.by_conn.get_mut(&conn) {
            boxes.remove(mailbox);
            if boxes.is_empty() {
                follows.by_conn.remove(&conn);
            }
        }
    }
}
