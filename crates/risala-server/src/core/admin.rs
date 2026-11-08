//! Server administration (Section 10): the ADMIN commands, except
//! `ADMIN PURGE`, which is in [`super::messages`], and `ADMIN REPORTS`,
//! `ROOMS` and `DROP`, which are in [`super::reports`].

use std::sync::Arc;

use risala_proto::command::AdminCommand;
use risala_proto::names::Uid;

use super::Inner;
use super::commands::{Outcome, Reply, not_supported};

impl Inner {
    /// Handles the ADMIN commands about operators, bans, connections,
    /// hosted identities and server settings (10.1-10.3, 10.5, 10.6).
    pub(super) async fn admin(
        self: &Arc<Self>,
        uid: &Uid,
        reply: &Reply,
        command: AdminCommand,
    ) -> Outcome {
        let _ = (uid, reply, command);
        Err(not_supported())
    }
}
