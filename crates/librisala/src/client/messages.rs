//! Messages (5.3, 5.4, 7.4, 7.7, 8.1, 12.9): reading a conversation's
//! messages, sending, replying, editing, reacting, deleting, typing and
//! read markers.
//!
//! Owned by task C2. Every method returns [`Error::NotImplemented`](super::Error::NotImplemented) until
//! C2 builds it; the shapes are a starting point, which C2 may change.

use super::error::not_implemented;
use super::types::{ConversationId, MessageId, Timestamp, Uid};
use super::{Client, Result};

/// A message, as shown (12.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Its id in the group.
    pub id: MessageId,
    /// The conversation.
    pub conversation: ConversationId,
    /// Its post's seq, if it was posted.
    pub seq: Option<u64>,
    /// The sender.
    pub sender: Uid,
    /// The sender's time (12.9).
    pub sent: Timestamp,
    /// The server's time, if it was posted.
    pub received: Option<Timestamp>,
    /// Whether the two times differ by more than 10 minutes (12.9).
    pub time_mismatch: bool,
    /// Whether the sender's leaf was confirmed (12.10).
    pub verified: bool,
    /// Whether it came from a backup or a transfer (12.13).
    pub restored: bool,
    /// Its text, after edits, escaped as on the wire (3.4); `None` once
    /// deleted.
    pub text: Option<String>,
    /// The message it replies to (5.3).
    pub reply_to: Option<MessageId>,
    /// Whether it was edited (5.3).
    pub edited: bool,
    /// Reactions, with how many of each.
    pub reactions: Vec<(String, u32)>,
}

/// Messages the device did not get (7.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    /// The sender.
    pub sender: Uid,
    /// How many messages are missing.
    pub missing: u64,
    /// Whether retention explains them; otherwise the server held them
    /// back.
    pub expired: bool,
}

impl Client {
    /// Up to `limit` messages of a conversation, newest last, before
    /// `before` (or the newest, without it).
    pub fn messages(
        &self,
        conversation: ConversationId,
        before: Option<MessageId>,
        limit: usize,
    ) -> Result<Vec<Message>> {
        let _ = (conversation, before, limit);
        not_implemented("messages")
    }

    /// Sends a TEXT line, as a reply to `reply_to` if given (5.3).
    pub async fn send_text(
        &self,
        conversation: ConversationId,
        text: &str,
        reply_to: Option<MessageId>,
    ) -> Result<MessageId> {
        let _ = (conversation, text, reply_to);
        not_implemented("send_text")
    }

    /// Edits one of this identity's messages (5.3).
    pub async fn edit(
        &self,
        conversation: ConversationId,
        id: MessageId,
        text: &str,
    ) -> Result<()> {
        let _ = (conversation, id, text);
        not_implemented("edit")
    }

    /// Reacts to a message (5.3).
    pub async fn react(
        &self,
        conversation: ConversationId,
        id: MessageId,
        reaction: &str,
    ) -> Result<()> {
        let _ = (conversation, id, reaction);
        not_implemented("react")
    }

    /// Deletes a message: one's own, or anyone's as a moderator (5.4).
    pub async fn delete(&self, conversation: ConversationId, id: MessageId) -> Result<()> {
        let _ = (conversation, id);
        not_implemented("delete")
    }

    /// Says that this device's user is typing (8.1), as a live post.
    pub async fn typing(&self, conversation: ConversationId) -> Result<()> {
        let _ = conversation;
        not_implemented("typing")
    }

    /// Marks a conversation read up to `id` (7.7), on every device of the
    /// identity.
    pub async fn mark_read(&self, conversation: ConversationId, id: MessageId) -> Result<()> {
        let _ = (conversation, id);
        not_implemented("mark_read")
    }

    /// The gaps in a conversation (7.4).
    pub fn gaps(&self, conversation: ConversationId) -> Result<Vec<Gap>> {
        let _ = conversation;
        not_implemented("gaps")
    }
}
