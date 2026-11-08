//! Room settings (6.2), roles (6.3) and moderation (6.4): SET, ROLE,
//! ROLES, INVITE, KICK, BAN, UNBAN and BANS.

use std::sync::Arc;

use risala_proto::command::Command;
use risala_proto::names::Uid;

use super::Inner;
use super::commands::{Outcome, Reply, not_supported};

impl Inner {
    /// Handles SET, ROLE, ROLES, INVITE, KICK, BAN, UNBAN and BANS.
    pub(super) async fn moderation(
        self: &Arc<Self>,
        uid: &Uid,
        reply: &Reply,
        command: Command,
    ) -> Outcome {
        let _ = (uid, reply, command);
        Err(not_supported())
    }
}
