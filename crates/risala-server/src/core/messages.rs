//! Edits, reactions and replies (5.3), DELETE (5.4), RELATED (7.3),
//! retention (7.5), ADMIN PURGE (10.4) and UNREGISTER `purge=yes` (4.8).

use std::sync::Arc;

use risala_proto::command::Command;
use risala_proto::names::Uid;

use super::Inner;
use super::commands::{Outcome, Reply, not_supported};

impl Inner {
    /// Handles DELETE, RELATED and `ADMIN PURGE`.
    pub(super) async fn messages(
        self: &Arc<Self>,
        uid: &Uid,
        reply: &Reply,
        command: Command,
    ) -> Outcome {
        let _ = (uid, reply, command);
        Err(not_supported())
    }
}
