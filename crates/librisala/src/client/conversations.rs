//! Conversations (5, 6, 8): direct conversations, private and public
//! rooms, their members and roles, profiles, topics, blocks and presence.
//!
//! Owned by task C2. Every method returns [`Error::NotImplemented`](super::Error::NotImplemented) until
//! C2 builds it; the shapes are a starting point, which C2 may change.
//! What is shown comes from the group, never from the server (5.1), except
//! what LIST says about public rooms the device has not joined.

use risala_proto::types::Role;

use super::error::not_implemented;
use super::types::{AccountId, ConversationId, Room, Timestamp, Uid};
use super::{Client, Result};

/// The conversation area's errors.
#[derive(Debug, thiserror::Error)]
pub enum ConversationError {
    /// There is no such conversation.
    #[error("no such conversation")]
    NotFound(ConversationId),
    /// Only an owner or moderator may do this (6.3).
    #[error("only an owner or moderator may do this")]
    NotAllowed,
}

/// What the conversation area tells the UI, besides changes to the cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConversationEvent {
    /// Someone is typing (8.1).
    Typing {
        /// The conversation.
        conversation: ConversationId,
        /// Who.
        uid: Uid,
    },
    /// Watched identities came online or went offline (8.3).
    Presence {
        /// The account that watches them.
        account: AccountId,
        /// Who.
        uids: Vec<Uid>,
        /// Whether they are online now.
        online: bool,
    },
}

/// The kind of a conversation (5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConversationKind {
    /// Between two identities, or with yourself.
    Direct,
    /// A private room.
    PrivateRoom,
    /// A public room.
    PublicRoom,
}

/// A conversation, for the chat list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationSummary {
    /// Its id.
    pub id: ConversationId,
    /// The account it belongs to.
    pub account: AccountId,
    /// Its kind.
    pub kind: ConversationKind,
    /// Its name, from the group (12.4), or the other identity of a direct
    /// conversation.
    pub name: String,
    /// A public room's name.
    pub room: Option<Room>,
    /// Its topic (12.4).
    pub topic: Option<String>,
    /// How many messages are unread (7.7).
    pub unread: u64,
    /// When the newest message was sent.
    pub last_activity: Option<Timestamp>,
    /// Whether sending is stopped for someone in it (4.5, 12.14).
    pub sending_stopped: bool,
}

/// A member of a conversation (12.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// The identity, or a guest.
    pub uid: Uid,
    /// Its display name, from its profile (8.2).
    pub display_name: Option<String>,
    /// Its role (6.3).
    pub role: Role,
    /// How many of its devices have a leaf.
    pub devices: usize,
    /// Whether its safety number was checked (12.14).
    pub verified: bool,
}

/// A public room, as LIST shows it (6.1): the server's word until the
/// device joins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicRoom {
    /// Its name.
    pub room: Room,
    /// How many members the server says it has.
    pub members: u64,
    /// The topic the server says it has.
    pub topic: String,
}

impl Client {
    /// The account's conversations, newest activity first.
    pub fn conversations(&self, account: AccountId) -> Result<Vec<ConversationSummary>> {
        let _ = account;
        not_implemented("conversations")
    }

    /// One conversation.
    pub fn conversation(&self, id: ConversationId) -> Result<ConversationSummary> {
        let _ = id;
        not_implemented("conversation")
    }

    /// The direct conversation with `uid` on the account's server,
    /// started if there is none (5.1, 12.7).
    pub async fn direct(&self, account: AccountId, uid: &str) -> Result<ConversationId> {
        let _ = (account, uid);
        not_implemented("direct")
    }

    /// Creates a private room named `name` (5.1).
    pub async fn create_private_room(
        &self,
        account: AccountId,
        name: &str,
    ) -> Result<ConversationId> {
        let _ = (account, name);
        not_implemented("create_private_room")
    }

    /// Creates the public room `room` on the account's server (6.1).
    pub async fn create_public_room(
        &self,
        account: AccountId,
        room: &str,
    ) -> Result<ConversationId> {
        let _ = (account, room);
        not_implemented("create_public_room")
    }

    /// Public rooms on the account's server, after `after` (6.1).
    pub async fn list_public_rooms(
        &self,
        account: AccountId,
        after: Option<&str>,
    ) -> Result<Vec<PublicRoom>> {
        let _ = (account, after);
        not_implemented("list_public_rooms")
    }

    /// Joins the public room `room`, as an identity or a guest (6.1).
    pub async fn join_public_room(&self, account: AccountId, room: &str) -> Result<ConversationId> {
        let _ = (account, room);
        not_implemented("join_public_room")
    }

    /// Leaves a conversation (6.1).
    pub async fn leave(&self, conversation: ConversationId) -> Result<()> {
        let _ = conversation;
        not_implemented("leave")
    }

    /// Adds `uid`'s devices to a room (6.1, 12.7).
    pub async fn invite(&self, conversation: ConversationId, uid: &str) -> Result<()> {
        let _ = (conversation, uid);
        not_implemented("invite")
    }

    /// Removes `uid` from a room, and bans it if `ban` (6.4).
    pub async fn remove_member(
        &self,
        conversation: ConversationId,
        uid: &str,
        ban: bool,
    ) -> Result<()> {
        let _ = (conversation, uid, ban);
        not_implemented("remove_member")
    }

    /// Sets `uid`'s role in a room (6.3).
    pub async fn set_role(
        &self,
        conversation: ConversationId,
        uid: &str,
        role: Role,
    ) -> Result<()> {
        let _ = (conversation, uid, role);
        not_implemented("set_role")
    }

    /// Sets a room's topic (12.4).
    pub async fn set_topic(&self, conversation: ConversationId, topic: &str) -> Result<()> {
        let _ = (conversation, topic);
        not_implemented("set_topic")
    }

    /// The members of a conversation, from its group.
    pub fn members(&self, conversation: ConversationId) -> Result<Vec<Member>> {
        let _ = conversation;
        not_implemented("members")
    }

    /// Sets this device's display name in the account's groups (8.2).
    pub async fn set_display_name(&self, account: AccountId, name: &str) -> Result<()> {
        let _ = (account, name);
        not_implemented("set_display_name")
    }

    /// Blocks `uid` (5.7), on every device of the account's identity.
    pub async fn block(&self, account: AccountId, uid: &str) -> Result<()> {
        let _ = (account, uid);
        not_implemented("block")
    }

    /// Unblocks `uid` (5.7).
    pub async fn unblock(&self, account: AccountId, uid: &str) -> Result<()> {
        let _ = (account, uid);
        not_implemented("unblock")
    }

    /// Whether the server reports the account's identity as online (8.3).
    pub async fn set_presence(&self, account: AccountId, on: bool) -> Result<()> {
        let _ = (account, on);
        not_implemented("set_presence")
    }

    /// The identities whose presence the account watches (8.3).
    pub async fn watch(&self, account: AccountId, uids: &[String]) -> Result<()> {
        let _ = (account, uids);
        not_implemented("watch")
    }
}
