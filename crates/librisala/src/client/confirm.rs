//! Which leaves are confirmed (12.10): a message shows as verified only if
//! its sender's leaf is confirmed (12.9).
//!
//! Owned by task C3. Every method returns [`Error::NotImplemented`](super::Error::NotImplemented) until
//! C3 builds it; the shapes are a starting point, which C3 may change.

use super::error::not_implemented;
use super::types::{ConversationId, DeviceId, Uid};
use super::{Client, Result};

/// Whether a member's leaf is confirmed (12.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafStatus {
    /// The member.
    pub uid: Uid,
    /// Its device, if it is not a guest.
    pub device: Option<DeviceId>,
    /// Whether its leaf is confirmed, pairwise or by a period key.
    pub confirmed: bool,
}

impl Client {
    /// The leaves of a conversation, and whether each is confirmed.
    pub fn leaf_status(&self, conversation: ConversationId) -> Result<Vec<LeafStatus>> {
        let _ = conversation;
        not_implemented("leaf_status")
    }
}
