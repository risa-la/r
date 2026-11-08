//! The hub's registry of connections, their kinds (4.1), and guest
//! sessions (4.2).
//!
//! # Locks
//!
//! The [`Registry`] is behind a plain mutex, which is never held across an
//! `await`, and under which no other lock is taken. An area may take it
//! while holding a lock of its own, never the other way round.
//!
//! Each connection also has a gate, an async mutex held while one of its
//! commands runs, and while it is cleaned up after closing. So its
//! commands run one at a time and in order (3.6), and clean-up waits for a
//! command in progress.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::Arc;

use risala_proto::auth::{Nonce, PublicKey};
use risala_proto::connection::ConnectionKind;
use risala_proto::names::Uid;
use tokio::task::AbortHandle;

use super::{admin, identity, keylog, keys, mailbox, misc};
use crate::handler::{ConnHandle, ConnId, ConnInfo};
use crate::secret::SecretHash;

/// Who a connection acts for: its kind (4.1), with what each kind knows.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "used by the areas as they are built (docs/plans/M5b.md, SV1-SV5)"
)]
pub(crate) enum Who {
    /// Not yet anonymous, a guest or signed in.
    New,
    /// Anonymous, after ANON (4.2).
    Anonymous,
    /// A guest, after GUEST (4.2): its uid, `~<name>`.
    Guest(Uid),
    /// Signed in with AUTH or REGISTER (4.6, 4.7).
    SignedIn(Device),
}

impl Who {
    /// The kind of connection (4.1).
    pub(crate) fn kind(&self) -> ConnectionKind {
        match self {
            Who::New => ConnectionKind::New,
            Who::Anonymous => ConnectionKind::Anonymous,
            Who::Guest(_) => ConnectionKind::Guest,
            Who::SignedIn(_) => ConnectionKind::SignedIn,
        }
    }

    /// The guest's or identity's uid, if the connection has one.
    pub(crate) fn uid(&self) -> Option<&Uid> {
        match self {
            Who::Guest(uid) => Some(uid),
            Who::SignedIn(device) => Some(&device.uid),
            Who::New | Who::Anonymous => None,
        }
    }
}

/// The identity and device a connection signed in as (4.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Device {
    /// The identity.
    pub(crate) uid: Uid,
    /// The device key that signed in, the connection's device key (4.6).
    pub(crate) key: PublicKey,
}

/// One open connection.
#[allow(
    dead_code,
    reason = "used by the areas as they are built (docs/plans/M5b.md, SV1-SV5)"
)]
pub(crate) struct ConnEntry {
    /// Where its lines go.
    pub(crate) handle: ConnHandle,
    /// What the network layer knew when it opened.
    pub(crate) info: ConnInfo,
    /// Its kind, and who it acts for.
    pub(crate) who: Who,
    /// The greeting's nonce, until an AUTH or REGISTER that parses uses it
    /// up (4.6).
    pub(crate) nonce: Option<Nonce>,
    /// Held while one of its commands runs, and while it is cleaned up.
    pub(crate) gate: Arc<tokio::sync::Mutex<()>>,
    /// Closes it if it is still new when its time to choose a kind is up
    /// (4.1).
    pub(crate) sign_in_timer: Option<AbortHandle>,
    /// The hub is closing it, for example because its guest session moved
    /// to another connection (4.2): no more of its commands are run.
    pub(crate) detached: bool,
    /// What each area keeps about the connection.
    pub(crate) areas: AreaConns,
}

/// What each area keeps about one connection, in the area's own type.
#[derive(Default)]
#[allow(
    dead_code,
    reason = "used by the areas as they are built (docs/plans/M5b.md, SV1-SV5)"
)]
pub(crate) struct AreaConns {
    pub(crate) identity: identity::ConnState,
    pub(crate) keylog: keylog::ConnState,
    pub(crate) mailbox: mailbox::ConnState,
    pub(crate) keys: keys::ConnState,
    pub(crate) misc: misc::ConnState,
    pub(crate) admin: admin::ConnState,
}

/// A guest's session (4.2). It starts with GUEST and outlasts its
/// connection by the resume period.
#[derive(Debug)]
pub(crate) struct GuestSession {
    /// The hash of its current token, a bearer secret (Section 14).
    pub(crate) token: SecretHash,
    /// Its connection, or `None` while it waits to be resumed.
    pub(crate) conn: Option<ConnId>,
    /// The address of its latest connection, for address bans (10.2).
    pub(crate) address: IpAddr,
    /// Counts the times its connection changed, so that a resume period
    /// that ends after the session was resumed does nothing.
    pub(crate) epoch: u64,
    /// Ends the session when the resume period is over.
    pub(crate) expiry: Option<AbortHandle>,
    /// The session is ending: its name stays taken until GONE has been
    /// sent, and it can no longer be resumed.
    pub(crate) ending: bool,
}

/// Every connection and guest session.
#[derive(Default)]
pub(crate) struct Registry {
    /// Every open connection.
    pub(crate) conns: HashMap<ConnId, ConnEntry>,
    /// The connections of each identity and guest, for lines meant for an
    /// identity's devices (12.8) and for closing them (10.3).
    pub(crate) by_uid: HashMap<Uid, BTreeSet<ConnId>>,
    /// Every guest session, connected or waiting to be resumed.
    pub(crate) sessions: HashMap<Uid, GuestSession>,
}

impl Registry {
    /// Gives connection `id` its kind (4.1), and tells the network layer,
    /// so that the kind's line limits apply from its next line (2.3). Its
    /// time to choose a kind stops. Returns `false` if it is gone.
    pub(crate) fn set_who(&mut self, id: ConnId, who: Who) -> bool {
        let Some(conn) = self.conns.get_mut(&id) else {
            return false;
        };
        if let Some(uid) = conn.who.uid().cloned() {
            unlink(&mut self.by_uid, &uid, id);
        }
        if let Some(uid) = who.uid() {
            self.by_uid.entry(uid.clone()).or_default().insert(id);
        }
        conn.handle.set_kind(who.kind());
        if let Some(timer) = conn.sign_in_timer.take() {
            timer.abort();
        }
        conn.who = who;
        true
    }

    /// Removes connection `id`.
    pub(crate) fn remove(&mut self, id: ConnId) -> Option<ConnEntry> {
        let conn = self.conns.remove(&id)?;
        if let Some(uid) = conn.who.uid() {
            unlink(&mut self.by_uid, uid, id);
        }
        Some(conn)
    }

    /// Closes connection `id` with `BYE <bye>` (11), and runs none of its
    /// commands from now on. It stays registered until the network layer
    /// reports it closed, but no longer counts as a connection of its uid.
    pub(crate) fn detach(&mut self, id: ConnId, bye: &str) {
        let Some(conn) = self.conns.get_mut(&id) else {
            return;
        };
        conn.detached = true;
        conn.handle.close(Some(bye.to_owned()));
        if let Some(uid) = conn.who.uid().cloned() {
            unlink(&mut self.by_uid, &uid, id);
        }
    }

    /// Runs none of connection `id`'s commands from now on, and no longer
    /// counts it as a connection of its uid, without closing it yet: the
    /// command running now closes it after its reply, as UNREGISTER does
    /// (4.9).
    pub(crate) fn stop(&mut self, id: ConnId) {
        let Some(conn) = self.conns.get_mut(&id) else {
            return;
        };
        conn.detached = true;
        if let Some(uid) = conn.who.uid().cloned() {
            unlink(&mut self.by_uid, &uid, id);
        }
    }

    /// The connections of `uid`, signed in or a guest.
    #[allow(
        dead_code,
        reason = "used by the areas as they are built (docs/plans/M5b.md, SV1-SV5)"
    )]
    pub(crate) fn conns_of(&self, uid: &Uid) -> Vec<ConnHandle> {
        self.by_uid
            .get(uid)
            .into_iter()
            .flatten()
            .filter_map(|id| self.conns.get(id))
            .map(|conn| conn.handle.clone())
            .collect()
    }
}

fn unlink(by_uid: &mut HashMap<Uid, BTreeSet<ConnId>>, uid: &Uid, id: ConnId) {
    if let Some(ids) = by_uid.get_mut(uid) {
        ids.remove(&id);
        if ids.is_empty() {
            by_uid.remove(uid);
        }
    }
}
