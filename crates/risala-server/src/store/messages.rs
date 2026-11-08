//! Storage for M4's message work: edits, reactions, DELETE (5.3, 5.4),
//! RELATED (7.3), retention (7.5), ADMIN PURGE (10.4) and UNREGISTER
//! `purge=yes` (4.8).
//!
//! DELETE itself is an event, stored by [`super::Store::append`], which
//! erases what it deletes in the same transaction.

use risala_proto::names::{Room, Seq, Uid};
use risala_proto::time::Timestamp;

use super::{ConvKey, Page, Result, StoredEvent};

/// Which events [`MessageStore::related`] returns (7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelatedQuery {
    /// The first target seq, inclusive.
    pub first: Seq,
    /// The last target seq, inclusive. Below `first`, nothing matches.
    pub last: Seq,
    /// Only events whose own seq is greater than this; 0 for all.
    pub after: u64,
    /// The most events to return, at least 1.
    pub limit: u64,
}

/// What [`MessageStore::purge`] deletes (4.8, 10.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgeQuery {
    /// Whose messages: those whose `from` is this uid. For a guest uid,
    /// every message sent under the name.
    pub author: Uid,
    /// Only messages sent at or after this time, if given.
    pub since: Option<Timestamp>,
    /// Only messages up to this seq, so that a purge ends even if the
    /// author keeps sending.
    pub upto: Seq,
    /// The `from` of the DELETE events.
    pub by: Uid,
    /// The `t` of the DELETE events.
    pub now: Timestamp,
    /// The most DELETE events to append in one call.
    pub max: usize,
}

/// Part of [`super::Store`]: see the module documentation.
///
/// Every method blocks, like the rest of [`super::Store`].
pub trait MessageStore {
    /// The seq of the oldest DELETE event whose target is `target` (5.4),
    /// if any. For DELETE of a message that is already deleted.
    fn delete_of(&self, conv: ConvKey, target: Seq) -> Result<Option<Seq>>;

    /// The seq of the reaction `from` sent to message `target` with exactly
    /// `text` (escaped), at or after `since` if given, and not deleted
    /// (5.3). The oldest, if there are several.
    fn reaction(
        &self,
        conv: ConvKey,
        from: &Uid,
        target: Seq,
        text: &str,
        since: Option<Timestamp>,
    ) -> Result<Option<Seq>>;

    /// A page of RELATED (7.3): the edits and reactions whose target is in
    /// `first..=last` and whose seq is greater than `after`, deleted ones
    /// included, in ascending seq order. `more` says whether there are
    /// more after the last one returned. [`StoreError::NoConversation`]
    /// if the conversation no longer exists, as for
    /// [`Store::history`](super::Store::history).
    ///
    /// [`StoreError::NoConversation`]: super::StoreError::NoConversation
    fn related(&self, conv: ConvKey, query: RelatedQuery) -> Result<Page>;

    /// The rooms in which `author` has messages that are not deleted, sent
    /// at or after `since` if given, in name order (4.8, 10.4).
    ///
    /// M5a: direct conversations.
    fn authored_rooms(
        &self,
        author: &Uid,
        since: Option<Timestamp>,
    ) -> Result<Vec<(ConvKey, Room)>>;

    /// Deletes messages of `query.author` in one conversation, as DELETE
    /// does (5.4), oldest first: for each, appends a DELETE event and
    /// applies it, all in one transaction. A message that an earlier one
    /// of these deletions took with it, such as an edit of a deleted
    /// message, gets no DELETE of its own.
    ///
    /// Appends at most `query.max` events, and returns them. Call it again
    /// until it returns none.
    fn purge(&self, conv: ConvKey, query: &PurgeQuery) -> Result<Vec<StoredEvent>>;

    /// Expires a conversation's oldest events under its retention period
    /// (7.5): in seq order, every event older than `before`, stopping at
    /// the first that is not. Removes at most `max`, and returns how many
    /// it removed. Seqs are not reused: the head stays.
    fn expire(&self, conv: ConvKey, before: Timestamp, max: usize) -> Result<u64>;
}
