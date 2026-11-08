//! Reports (5.8): to a room's moderators, inside the encryption, or to the
//! server's operators, with franking.
//!
//! Owned by task C4. Every method returns [`Error::NotImplemented`](super::Error::NotImplemented) until
//! C4 builds it; the shapes are a starting point, which C4 may change.

use super::error::not_implemented;
use super::types::{ConversationId, MessageId, Uid};
use super::{Client, Result};

/// Who sees a report (5.8). The reporter is told this before sending.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportTo {
    /// The room's owners and moderators, who can trust who wrote it.
    Moderators(Vec<Uid>),
    /// The server's operators, who see the content, proven by franking,
    /// but not who wrote it.
    Operators,
}

impl Client {
    /// Who would see a report of a message in this conversation, for each
    /// way of reporting.
    pub fn report_recipients(&self, conversation: ConversationId) -> Result<Vec<ReportTo>> {
        let _ = conversation;
        not_implemented("report_recipients")
    }

    /// Reports `message`, with up to 10 earlier messages as `context`
    /// (5.8).
    pub async fn report(
        &self,
        conversation: ConversationId,
        message: MessageId,
        context: &[MessageId],
        to: ReportTo,
        reason: &str,
    ) -> Result<()> {
        let _ = (conversation, message, context, to, reason);
        not_implemented("report")
    }
}
