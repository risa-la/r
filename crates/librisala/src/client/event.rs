//! What the client tells the UI.

use crate::addr::{PinChange, ServerAddr};
use crate::conn::Slot;
use crate::store::{AccountId, Change};

/// Something that happened, from [`Client::subscribe`](super::Client::subscribe).
///
/// Each area has a variant for events that are not changes to the cache,
/// with an enum in the area's module.
#[derive(Debug, Clone)]
pub enum Event {
    /// The cache changed: read the new state with the area's reads.
    Changed(Change),
    /// One of an account's connections changed state.
    Connection(ConnectionEvent),
    /// A pinned server showed a CA-valid certificate with another key,
    /// which replaced the pin (2.2). Tell the user once, then
    /// [`dismiss_pin_notice`](super::Client::dismiss_pin_notice).
    PinReplaced {
        /// The server.
        server: ServerAddr,
        /// The old and new fingerprints.
        change: PinChange,
    },
    /// Identities, devices and key logs (task C1).
    Identity(super::identity::IdentityEvent),
    /// Conversations and messages (task C2).
    Conversation(super::conversations::ConversationEvent),
    /// Files, transfers and backups (task C4).
    Transfer(super::files::TransferEvent),
}

/// A connection of an account changed state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionEvent {
    /// The account.
    pub account: AccountId,
    /// Which of its connections.
    pub slot: Slot,
    /// Its new state.
    pub state: ConnectionState,
}

/// The state of one connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    /// Connecting, after `attempt` failures in a row.
    Connecting {
        /// Failures in a row so far.
        attempt: u32,
    },
    /// Anonymous, a guest or signed in, and ready.
    Ready,
    /// Waiting before trying again.
    Waiting {
        /// Why the last attempt failed, for display.
        error: Option<String>,
        /// How long, in milliseconds.
        delay_ms: u64,
    },
    /// Stopped, after an error that needs the user (a trust error,
    /// `auth-failed` and so on), for display.
    Failed(String),
    /// Stopped on purpose.
    Stopped,
}
