//! What the server keeps for devices without reading it (5.6, 12.5,
//! 12.8, 12.12, 12.13): KEYPKG, WELCOME, BLOB, BACKUP and UPLOAD, and the
//! HTTPS side of blobs and files.
//!
//! Not built yet: every command replies `ERR not-supported`.
//!
//! The store keeps KeyPackages, Welcomes, blobs, uploads and backups
//! ([`KeysStore`](crate::store::KeysStore)). Upload and blob URLs are
//! bearer secrets, stored as hashes ([`crate::secret`]).

use std::sync::Arc;

use risala_proto::command::Command;

use super::Inner;
use super::command::{Cx, Reply, misrouted, not_supported};
use super::state::ConnEntry;
use crate::config::Config;
use crate::handler::ConnId;
use crate::store::{Store, StoreError};

/// What the keys area keeps in memory.
#[derive(Debug)]
pub(crate) struct State {}

impl State {
    /// Loads the area's state when the hub starts.
    pub(crate) fn load(_config: &Config, _store: &dyn Store) -> Result<State, StoreError> {
        Ok(State {})
    }
}

/// What the keys area keeps about one connection.
#[derive(Debug, Default)]
pub(crate) struct ConnState {}

/// Handles KEYPKG, WELCOME, BLOB, BACKUP and UPLOAD.
pub(super) async fn handle(_cx: &Cx, command: Command) -> Reply {
    match command {
        Command::KeyPkg(_) // 12.5
        | Command::Welcome(_) // 12.8
        | Command::Blob { .. } // 12.12
        | Command::Backup(_) // 12.13
        | Command::Upload { .. } /* 5.6 */ => not_supported(),
        other => misrouted("keys", &other),
    }
}

/// Connection `id` has closed.
pub(super) fn conn_closed(_inner: &Arc<Inner>, _id: ConnId, _conn: &ConnEntry) {}

/// The area's background work: deleting KeyPackages whose lifetime has
/// ended (12.5), and Welcomes, blobs and files past retention (7.5).
pub(super) async fn maintain(_inner: Arc<Inner>) {}
