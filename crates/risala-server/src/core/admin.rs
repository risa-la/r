//! Server administration (Section 10): the ADMIN commands but ADMIN
//! UNREGISTER (which is `identity`'s), operators and server bans.
//!
//! The routing in [`command`](super::command) lets only operators send
//! ADMIN commands: anyone else gets `ERR forbidden` (Section 10).
//! Operators are those in the configuration and those added with
//! ADMIN OP, which the store keeps ([`AdminStore`](crate::store::AdminStore)).
//!
//! Not built yet: every ADMIN command replies `ERR not-supported`, and no
//! address is banned.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use risala_proto::command::AdminCommand;
use risala_proto::names::Uid;

use super::Inner;
use super::command::{Cx, Reply, misrouted, not_supported};
use super::state::ConnEntry;
use crate::config::Config;
use crate::handler::ConnId;
use crate::store::{Store, StoreError};

/// What the admin area keeps in memory.
#[derive(Debug)]
#[allow(
    dead_code,
    reason = "used by the areas as they are built (docs/plans/M5b.md, SV1-SV5)"
)]
pub(crate) struct State {
    /// The operators named in the configuration, who cannot be removed
    /// with ADMIN DEOP or banned (10.1, 10.2).
    configured: BTreeSet<Uid>,
    /// Every operator: those configured, and those added with ADMIN OP.
    operators: RwLock<BTreeSet<Uid>>,
}

impl State {
    /// Loads the area's state when the hub starts.
    pub(crate) fn load(config: &Config, store: &dyn Store) -> Result<State, StoreError> {
        let configured: BTreeSet<Uid> = config.operators().iter().map(|op| op.to_uid()).collect();
        let mut operators = configured.clone();
        operators.extend(store.operators()?);
        Ok(State {
            configured,
            operators: RwLock::new(operators),
        })
    }
}

/// What the admin area keeps about one connection.
#[derive(Debug, Default)]
pub(crate) struct ConnState {}

/// Whether `uid` is an operator (10.1).
pub(crate) fn is_operator(inner: &Inner, uid: &Uid) -> bool {
    inner
        .admin
        .operators
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .contains(uid)
}

/// Whether `uid` is an operator named in the configuration (10.1).
#[allow(
    dead_code,
    reason = "used by the areas as they are built (docs/plans/M5b.md, SV1-SV5)"
)]
pub(crate) fn is_configured_operator(inner: &Inner, uid: &Uid) -> bool {
    inner.admin.configured.contains(uid)
}

/// Why anonymous and guest connections from `ip` are refused, if they
/// are: an address ban (10.2).
pub(crate) fn refuses_address(_inner: &Inner, _ip: IpAddr) -> Option<&'static str> {
    None
}

/// Handles the ADMIN commands but ADMIN UNREGISTER, from an operator.
pub(super) async fn handle(_cx: &Cx, command: AdminCommand) -> Reply {
    match command {
        AdminCommand::Unregister { .. } => {
            misrouted("admin", &risala_proto::command::Command::Admin(command))
        }
        _ => not_supported(),
    }
}

/// Connection `id` has closed.
pub(super) fn conn_closed(_inner: &Arc<Inner>, _id: ConnId, _conn: &ConnEntry) {}

/// The area's background work.
pub(super) async fn maintain(_inner: Arc<Inner>) {}
