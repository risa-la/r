//! Server information, presence, push and reports (5.8, 6.1, 8, 9): INFO,
//! LIST, PRESENCE, WATCH, WHOIS, MEMBERS, PUSH, REPORT and RESOLVE.
//!
//! Not built yet: every command replies `ERR not-supported`.
//!
//! The store keeps presence settings, push subscriptions and reports
//! ([`MiscStore`](crate::store::MiscStore)); LIST, INFO with a room and
//! MEMBERS read public rooms from the mailbox area's tables
//! ([`MailboxStore`](crate::store::MailboxStore)).

use std::sync::Arc;

use risala_proto::command::Command;

use super::Inner;
use super::command::{Cx, Reply, misrouted, not_supported};
use super::state::ConnEntry;
use crate::config::Config;
use crate::handler::ConnId;
use crate::store::{Store, StoreError};

/// What the misc area keeps in memory.
#[derive(Debug)]
pub(crate) struct State {}

impl State {
    /// Loads the area's state when the hub starts.
    pub(crate) fn load(_config: &Config, _store: &dyn Store) -> Result<State, StoreError> {
        Ok(State {})
    }
}

/// What the misc area keeps about one connection, such as its WATCH list
/// (8.3).
#[derive(Debug, Default)]
pub(crate) struct ConnState {}

/// Handles INFO, LIST, PRESENCE, WATCH, WHOIS, MEMBERS, PUSH, REPORT and
/// RESOLVE.
pub(super) async fn handle(_cx: &Cx, command: Command) -> Reply {
    match command {
        Command::Info { .. } // 8.5, 6.1
        | Command::List { .. } // 6.1
        | Command::Presence { .. } // 8.3
        | Command::Watch { .. } // 8.3
        | Command::Whois { .. } // 8.3
        | Command::Members { .. } // 8.3
        | Command::Push(_) // 9.1
        | Command::Report { .. } // 5.8
        | Command::Resolve { .. } /* 5.8 */ => not_supported(),
        other => misrouted("misc", &other),
    }
}

/// Connection `id` has closed.
pub(super) fn conn_closed(_inner: &Arc<Inner>, _id: ConnId, _conn: &ConnEntry) {}

/// The area's background work: batched presence changes (8.3) and pushes
/// (9.2).
pub(super) async fn maintain(_inner: Arc<Inner>) {}
