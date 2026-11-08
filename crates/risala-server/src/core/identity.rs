//! Identities (4.6-4.9, 10.5): AUTH, REGISTER, KEYS PUT, PAIR PUT and
//! PAIR GET, UNREGISTER and ADMIN UNREGISTER, and the key files of the
//! identities the server hosts.
//!
//! Not built yet: every command replies `ERR not-supported`, and the
//! server hosts no key files.
//!
//! What this area builds on:
//!
//! - The greeting's nonce is in [`ConnEntry::nonce`] until an AUTH or
//!   REGISTER that parses uses it up (4.6).
//! - Signing in is `reg.set_who(id, Who::SignedIn(Device { .. }))`
//!   ([`Registry::set_who`](super::state::Registry::set_who)), which also
//!   lifts the connection's line limits (2.3).
//! - Key files are fetched with [`Inner::key_files`](super::Inner) (4.4),
//!   and the store keeps accounts, hosted names, chains of records and
//!   pairing messages ([`IdentityStore`](crate::store::IdentityStore)).
//! - The key log is [`keylog`](super::keylog).

use std::sync::Arc;

use risala_proto::command::Command;
use risala_proto::names::{Name, Uid};

use super::Inner;
use super::command::{Cx, Reply, misrouted, not_supported};
use super::state::ConnEntry;
use crate::config::Config;
use crate::handler::ConnId;
use crate::store::{Store, StoreError};

/// What the identity area keeps in memory.
#[derive(Debug)]
pub(crate) struct State {}

impl State {
    /// Loads the area's state when the hub starts.
    pub(crate) fn load(_config: &Config, _store: &dyn Store) -> Result<State, StoreError> {
        Ok(State {})
    }
}

/// What the identity area keeps about one connection.
#[derive(Debug, Default)]
pub(crate) struct ConnState {}

/// Handles AUTH, REGISTER, KEYS PUT, PAIR and UNREGISTER.
pub(super) async fn handle(_cx: &Cx, command: Command) -> Reply {
    match command {
        Command::Auth { .. } // 4.6
        | Command::Register { .. } // 4.7
        | Command::KeysPut { .. } // 4.7
        | Command::Pair(_) // 4.8
        | Command::Unregister { .. } /* 4.9 */ => not_supported(),
        other => misrouted("identity", &other),
    }
}

/// Handles ADMIN UNREGISTER (10.5), for an operator.
pub(super) async fn admin_unregister(_cx: &Cx, _uid: &Uid) -> Reply {
    not_supported()
}

/// The key file of the hosted identity `<name>@<identity domain>`, as
/// served at its URL (4.3, 4.7), or `None` if there is none. Blocks.
pub(super) fn hosted_key_file(_inner: &Inner, _name: &Name) -> std::io::Result<Option<Vec<u8>>> {
    Ok(None)
}

/// Connection `id` has closed.
pub(super) fn conn_closed(_inner: &Arc<Inner>, _id: ConnId, _conn: &ConnEntry) {}

/// The area's background work, such as expiring pairing messages after
/// 10 minutes (4.8).
pub(super) async fn maintain(_inner: Arc<Inner>) {}
