//! Reports (5.8): REPORT, REPORTS, RESOLVE and `ADMIN REPORTS`, and the
//! ADMIN commands about rooms (10.4): `ADMIN ROOMS` and `ADMIN DROP`.
//! REPORTENC waits for M5a.

use std::sync::Arc;

use risala_proto::command::Command;
use risala_proto::names::Uid;

use super::Inner;
use super::commands::{Outcome, Reply, not_supported};

impl Inner {
    /// Handles REPORT, REPORTENC, REPORTS, RESOLVE, and `ADMIN REPORTS`,
    /// `ROOMS` and `DROP`.
    pub(super) async fn reports(
        self: &Arc<Self>,
        uid: &Uid,
        reply: &Reply,
        command: Command,
    ) -> Outcome {
        let _ = (uid, reply, command);
        Err(not_supported())
    }
}
