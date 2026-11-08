//! Push notifications (Section 9).
//!
//! Owned by task C4. Every method returns [`Error::NotImplemented`](super::Error::NotImplemented) until
//! C4 builds it; the shapes are a starting point, which C4 may change.

use super::error::not_implemented;
use super::types::{AccountId, ConversationId};
use super::{Client, Result};

/// A push gateway the app registers with (9.1, Appendix C): it hands out
/// a subscription URL for each subscription.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushGateway {
    /// The gateway's URL.
    pub url: String,
}

/// What a push says to show (9.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushNotice {
    /// New posts in a conversation.
    Message {
        /// The conversation.
        conversation: ConversationId,
    },
    /// A Welcome for the account: someone added it to a conversation.
    Welcome {
        /// The account.
        account: AccountId,
    },
}

impl Client {
    /// Subscribes the account to pushes through `gateway`: one
    /// subscription per conversation and one for the account (9.1).
    pub async fn enable_push(&self, account: AccountId, gateway: &PushGateway) -> Result<()> {
        let _ = (account, gateway);
        not_implemented("enable_push")
    }

    /// Removes the account's push subscriptions (9.1).
    pub async fn disable_push(&self, account: AccountId) -> Result<()> {
        let _ = account;
        not_implemented("disable_push")
    }

    /// Decrypts a push body (9.3, RFC 8291) and says what to show,
    /// quickly enough for an iOS notification extension (PLAN.md 3.4).
    pub async fn handle_push(&self, body: &[u8]) -> Result<Vec<PushNotice>> {
        let _ = body;
        not_implemented("handle_push")
    }
}
