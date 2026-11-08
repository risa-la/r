//! The key log (4.5): appending the records of hosted identities, and of
//! identities whose key files name the log, signing checkpoints, asking
//! witnesses to cosign them, and serving checkpoints, tiles and entries
//! over HTTPS. It has no commands of its own: KEYS PUT and REGISTER
//! (`identity`) append to it.
//!
//! Not built yet: the server keeps no log, and INFO says `log=no` (8.5).
//!
//! The store keeps the entries, checkpoints and the log's key
//! ([`KeyLogStore`](crate::store::KeyLogStore)).

use std::sync::Arc;

use super::Inner;
use super::state::ConnEntry;
use crate::config::Config;
use crate::handler::ConnId;
use crate::store::{Store, StoreError};

/// What the key log keeps in memory.
#[derive(Debug)]
pub(crate) struct State {}

impl State {
    /// Loads the area's state when the hub starts.
    pub(crate) fn load(_config: &Config, _store: &dyn Store) -> Result<State, StoreError> {
        Ok(State {})
    }
}

/// What the key log keeps about one connection.
#[derive(Debug, Default)]
pub(crate) struct ConnState {}

/// Connection `id` has closed.
pub(super) fn conn_closed(_inner: &Arc<Inner>, _id: ConnId, _conn: &ConnEntry) {}

/// The area's background work: a witnessed checkpoint within an hour of a
/// new record, and at least once a day (4.5).
pub(super) async fn maintain(_inner: Arc<Inner>) {}
