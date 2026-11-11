//! Conversations (5, 6, 8): direct conversations, private and public
//! rooms, their members and roles, profiles, topics, blocks and presence.
//!
//! Owned by task C2. What is shown comes from the group, never from the
//! server (5.1), except what LIST says about public rooms the device has
//! not joined.
//!
//! Operations that change a group queue a commit, which the account's
//! group engine makes and posts once the conversation is caught up
//! ([`crate::sync::conversations`]); they return once it is queued, and
//! the cache's [`Change`](crate::store::Change)s show when it took
//! effect. Starting a conversation waits for its KeyPackages and its
//! mailbox, and so needs the account to be connected.

use std::sync::Arc;

use risala_mls::conversation::{
    ConversationError as ExtensionError, RisalaConversation, Role as GroupRole,
};
use risala_proto::content::ContentLine;
use risala_proto::types::Role;

use super::types::{AccountId, ConversationId, DeviceId, Room, Timestamp, Uid};
use super::{Client, Error, Event, Result};
use crate::keys::KeyStore;
use crate::store::Store;
use crate::store::conversations::{ConvKind, ConvRow, ConvState, Held};
use crate::sync::conversations::wire::Intent;
use crate::sync::conversations::{BlobFetch, EngineError, Hooks, Job, JobId, content, group};

/// The conversation area's errors.
#[derive(Debug, thiserror::Error)]
pub enum ConversationError {
    /// There is no such conversation.
    #[error("no such conversation")]
    NotFound(ConversationId),
    /// Only an owner or moderator may do this (6.3).
    #[error("only an owner or moderator may do this")]
    NotAllowed,
    /// The device is not in this conversation any more.
    #[error("not in this conversation")]
    NotInGroup,
    /// Starting a conversation or inviting failed: an identity has no
    /// devices to add, or the server refused.
    #[error("{0}")]
    Failed(String),
    /// The group engine failed.
    #[error("{0}")]
    Engine(String),
    /// A ban past the cap: a room bans at most 10,000 identities (6.4).
    /// Lift a ban first.
    #[error("a room bans at most 10,000 identities")]
    TooManyBans,
    /// A change past the size limit: a room's owners, moderators, bans
    /// and topic take at most 512 KiB together (12.4), which long uids can
    /// reach before the ban cap. Lift bans, or take roles away, first.
    #[error("a room's owners, moderators, bans and topic take at most 512 KiB")]
    TooLarge,
}

impl From<EngineError> for Error {
    fn from(e: EngineError) -> Error {
        match e {
            EngineError::Store(e) => Error::Store(e),
            other => Error::Conversation(ConversationError::Engine(other.to_string())),
        }
    }
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
    /// A job of the group engine ended: a conversation started, or an
    /// invitation made (see [`crate::sync::conversations::Job`]).
    JobDone {
        /// The job.
        job: JobId,
        /// The conversation, if it worked.
        conversation: Option<ConversationId>,
        /// Why it failed, if it did.
        error: Option<String>,
    },
    /// The device joined a conversation by Welcome (12.8).
    Joined {
        /// The conversation.
        conversation: ConversationId,
    },
    /// The device is no longer in a conversation: removed, or it left
    /// (6.1).
    Left {
        /// The conversation.
        conversation: ConversationId,
    },
    /// The identity left the conversation from another of its devices
    /// (6.1, 12.9): that device left it locally, without removing the
    /// identity's other leaves, and asked its own devices with `LEAVE
    /// <box>` to leave it for the identity. This device acts on it: it
    /// leaves the conversation too, as the user had left it here, and
    /// [`Left`](Self::Left) follows once it has.
    LeftFromOwnDevice {
        /// The conversation.
        conversation: ConversationId,
        /// The device the identity left it from, as its confirmed leaf
        /// named it.
        device: Option<DeviceId>,
    },
    /// An operator dropped the conversation's mailbox (6.1, 10.4).
    Dropped {
        /// The conversation.
        conversation: ConversationId,
        /// The operator's reason, escaped.
        reason: String,
    },
    /// Another device of the identity is in a different branch of the
    /// group: the server may have split it (7.7, 12.7).
    MaybeSplit {
        /// The conversation.
        conversation: ConversationId,
    },
    /// A day after joining, this device has seen nobody else post in its
    /// epoch while posts it cannot read arrive: it may have joined a branch
    /// of the group that nobody follows, and has uploaded fresh KeyPackages
    /// to be added again (12.8).
    MaybeOtherBranch {
        /// The conversation.
        conversation: ConversationId,
    },
    /// Posts that this device had not applied expired on the server, so it
    /// cannot tell whether they held commits, and can no longer follow the
    /// conversation (7.4, 7.5). It applies and posts nothing there until
    /// its leaf is replaced and a Welcome brings it back (12.7), or, in a
    /// public room, until it has joined again (6.1).
    CannotFollow {
        /// The conversation.
        conversation: ConversationId,
    },
    /// The server accepted a commit in a public room that this device holds
    /// invalid (12.7). The device resyncs the room or joins it again.
    InvalidCommitAccepted {
        /// The conversation.
        conversation: ConversationId,
    },
    /// The server changed a public room in a way no commit this device
    /// checked explains (12.7, "Rejoining a public room"). The device joins
    /// it again only if the user accepts, with
    /// [`Client::accept_room_change`].
    RoomChanged {
        /// The conversation.
        conversation: ConversationId,
        /// What changed: `owners`, `mods`, `bans`, `guests`, `send` or
        /// `topic`.
        fields: Vec<String>,
    },
    /// Someone resynced a public room that this device followed without
    /// trouble (12.7): possible abuse, by `by`, whom owners and moderators
    /// can ban.
    Resynced {
        /// The conversation.
        conversation: ConversationId,
        /// Who made the resync commit.
        by: Uid,
    },
    /// The server refused a Welcome this device sent (12.8): it cannot know
    /// who holds the added device's place, and adds it again where it may.
    WelcomeRefused {
        /// The conversation.
        conversation: ConversationId,
        /// The added device's identity, if known.
        uid: Option<Uid>,
    },
    /// A leaf was added that this device could not check yet (12.7): it
    /// sends nothing in the conversation until the check passes or fails,
    /// since that leaf would read it. Queued messages wait.
    SendingHeld {
        /// The conversation.
        conversation: ConversationId,
    },
    /// The key checks that held sending are done: queued messages go.
    SendingResumed {
        /// The conversation.
        conversation: ConversationId,
    },
    /// A key check failed (12.7): an added device's binding does not
    /// verify under a current device of its identity, it was removed by
    /// record, or its record was still pending 2 hours on; or a
    /// committer's device was removed by record. With `repairing`, the
    /// device removes the leaf after a random wait; without, the checks do
    /// not let it, and what the leaf sends is hidden.
    KeyCheckFailed {
        /// The conversation.
        conversation: ConversationId,
        /// The identity of the leaf.
        uid: Uid,
        /// Whether this device removes the leaf.
        repairing: bool,
    },
    /// A key check has waited 2 hours on a key file that this device
    /// cannot read (4.4, 12.7). An outage never fails a check: nothing is
    /// removed for it, and while the leaf is an added one, sending stays
    /// held. The check goes on once the key file can be read.
    KeyFileUnavailable {
        /// The conversation.
        conversation: ConversationId,
        /// The identity whose key file cannot be read.
        uid: Uid,
    },
    /// A public room could not be resynced (12.7): the server took a
    /// commit this device could not apply, its resync failed, as a resync
    /// commit that could not be used or that the server refused, and no
    /// commit has applied its join proposal within 30 minutes. The room
    /// goes on for this device only once a full client that could apply
    /// that commit commits the join proposals; the device keeps waiting.
    CouldNotResync {
        /// The conversation.
        conversation: ConversationId,
    },
    /// A commit removed leaves for a check whose reason this device could
    /// not see (12.7): the removal stands, and the user is told who made
    /// it.
    RemovalUnchecked {
        /// The conversation.
        conversation: ConversationId,
        /// Who made the commit, if a member did.
        by: Option<Uid>,
    },
    /// Another leaf of the own identity removed a leaf of it whose device
    /// is still current, without adding it again: it may be a stolen
    /// device racing its own removal (12.7, 4.8). Told as for ALERT.
    OwnLeafRemoved {
        /// The conversation.
        conversation: ConversationId,
    },
    /// A Welcome named the group of a conversation this device has, but
    /// does not continue it: a later epoch, the same kind and members,
    /// and signed by a leaf this device knew in it. It was refused, and
    /// the conversation is unchanged (12.7, 12.8).
    WelcomeForKnownGroupRefused {
        /// The conversation.
        conversation: ConversationId,
        /// Why.
        reason: String,
    },
    /// A guest wants to report something to this identity, an owner or
    /// moderator of a public room here (5.8, 12.7). Accept with
    /// [`Client::accept_report`], or decline with
    /// [`Client::decline_report`].
    ReportOffered {
        /// The account.
        account: AccountId,
        /// The offer.
        offer: i64,
        /// The guest.
        guest: Uid,
    },
    /// A member invites this device back into a conversation it left for
    /// good, as a device that could no longer follow it or whose leave
    /// failed its checks (6.1). It is held, not joined, until the user
    /// accepts it with [`Client::accept_invitation`] or declines it with
    /// [`Client::decline_invitation`]: from the Welcome alone it cannot be
    /// told from that member's replacement of this device's leaf, and the
    /// user left. [`Client::invitations`] lists those held; one not
    /// answered within the server's retention period expires, as the
    /// server's Welcomes do (12.8).
    Invited {
        /// The account.
        account: AccountId,
        /// The invitation.
        invitation: i64,
        /// The conversation it leads back into.
        conversation: ConversationId,
        /// Who sent it.
        by: Uid,
    },
}

/// The kind of a conversation (5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConversationKind {
    /// Between two identities.
    Direct,
    /// The conversation with yourself (5.1, 12.13).
    WithYourself,
    /// A private room.
    PrivateRoom,
    /// A public room.
    PublicRoom,
}

impl From<ConvKind> for ConversationKind {
    fn from(k: ConvKind) -> ConversationKind {
        match k {
            ConvKind::Direct => ConversationKind::Direct,
            ConvKind::WithYourself => ConversationKind::WithYourself,
            ConvKind::Private => ConversationKind::PrivateRoom,
            ConvKind::Public => ConversationKind::PublicRoom,
        }
    }
}

/// Where this device is in a conversation, for the chat list (6.1, 7.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConversationState {
    /// In the group: it reads and sends there.
    Active,
    /// Joining a public room by proposal, for the first time or again
    /// after it could not follow it (6.1, 12.7).
    Joining,
    /// Leaving (6.1): its leave commit or SelfRemove has not won yet. It
    /// keeps trying while the device is offline.
    Leaving,
    /// It can no longer follow the group: posts expired before it read
    /// them (7.5). A Welcome, or joining a public room again, brings it
    /// back; or the user leaves it.
    Lost,
    /// No longer in the group: it left, was removed, or the operator
    /// dropped its mailbox (6.1, 10.4).
    Left,
}

impl ConversationState {
    /// The state of `row`, given its outbox rows not yet done.
    fn of(row: &ConvRow, pending: &[crate::store::messages::OutboxRow]) -> ConversationState {
        match row.state {
            // 6.1: a leave commit queued is leaving too.
            _ if group::is_leaving(row.state, pending) => ConversationState::Leaving,
            ConvState::Leaving => ConversationState::Leaving,
            ConvState::Creating | ConvState::Active => ConversationState::Active,
            ConvState::Joining => ConversationState::Joining,
            ConvState::Lost => ConversationState::Lost,
            ConvState::Left | ConvState::Dropped | ConvState::Failed => ConversationState::Left,
        }
    }

    /// Whether the device is in the group, leaving it or not.
    pub fn in_group(self) -> bool {
        matches!(self, ConversationState::Active | ConversationState::Leaving)
    }
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
    /// Where the device is in it.
    pub state: ConversationState,
    /// A direct conversation that the peer left (6.1): the device left it
    /// too, by itself. Talking again starts a new one.
    pub left_by_peer: bool,
}

/// An invitation held for the user (6.1): see
/// [`ConversationEvent::Invited`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invitation {
    /// Its id.
    pub id: i64,
    /// The conversation it leads back into.
    pub conversation: ConversationId,
    /// Who sent it.
    pub by: Uid,
    /// When it arrived.
    pub received: Option<Timestamp>,
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

/// The hooks the client gives the group engine (see
/// [`crate::sync::conversations::Hooks`]). For now: this device's device
/// key, from the key store, under the `key_id` the identity area keeps
/// for the identity. Tasks C1 and C3 add key facts and leaf
/// confirmation here.
pub(crate) struct ClientHooks {
    store: Store,
    keys: Arc<dyn KeyStore>,
    /// The blob store (12.12): blobs fetched over HTTPS in the background.
    blobs: Arc<BlobFetcher>,
    /// The device's own blobs stored over HTTPS in the background (12.12).
    puts: Arc<BlobPutter>,
    /// Leaf confirmation (task C3).
    confirm: Arc<crate::sync::confirm::Confirm>,
    /// The time, for C4's lines.
    clock: Arc<dyn crate::clock::Clock>,
    /// Whether the engine acts on the key checks of 12.7 (task R2):
    /// always, except in tests without key files.
    enforce_key_checks: bool,
}

/// The most a blob may hold: the tree of the largest public room (12.12).
const MAX_BLOB: usize = 256 << 20;

/// How many blobs are fetched at once (LR-M5).
const MAX_IN_FLIGHT: usize = 2;

/// How many fetched blobs are kept until asked for again, for a Welcome
/// and its tree, or a GroupInfo and its tree, asked for together (LR-M5).
const MAX_READY: usize = 4;

/// The most bytes of fetched blobs kept at once, besides the newest
/// (LR-M5).
const MAX_HELD: usize = MAX_BLOB;

/// Fetches blobs (12.12) from INFO's `blobs` URL prefix over HTTPS, in the
/// background, for [`Hooks::blob`], which answers `Waiting` until a fetch
/// is done. The engine checks each blob's hash.
///
/// Anyone who can post, or put a Welcome to one of the device's
/// KeyPackages, can name blobs, so what it does is bounded (LR-M5): at
/// most [`MAX_IN_FLIGHT`] fetches at once (a ref asked for beyond that
/// waits for a later ask), each of at most [`MAX_BLOB`] bytes, and at most
/// [`MAX_READY`] fetched blobs, of [`MAX_HELD`] bytes in all, kept, the
/// oldest dropped first.
pub(crate) struct BlobFetcher {
    https: Option<Arc<dyn crate::client::identity::Https>>,
    state: std::sync::Mutex<FetchState>,
}

/// A blob being fetched (`None`), or fetched: its bytes, or `None` if the
/// fetch failed.
type BlobState = Option<Option<Vec<u8>>>;

/// What the fetcher holds.
#[derive(Default)]
pub(crate) struct FetchState {
    blobs: std::collections::HashMap<[u8; 48], BlobState>,
    /// Fetched blobs, oldest first.
    ready: std::collections::VecDeque<[u8; 48]>,
    in_flight: usize,
    held: usize,
}

impl FetchState {
    fn done(&mut self, hash: [u8; 48], got: Option<Vec<u8>>) {
        self.in_flight = self.in_flight.saturating_sub(1);
        if let Some(bytes) = &got {
            self.held += bytes.len();
            self.ready.push_back(hash);
        }
        self.blobs.insert(hash, Some(got));
        while self.ready.len() > MAX_READY || (self.ready.len() > 1 && self.held > MAX_HELD) {
            let Some(old) = self.ready.pop_front() else {
                break;
            };
            if let Some(Some(Some(bytes))) = self.blobs.remove(&old) {
                self.held -= bytes.len();
            }
        }
    }
}

impl BlobFetcher {
    pub(crate) fn new(https: Option<Arc<dyn crate::client::identity::Https>>) -> BlobFetcher {
        BlobFetcher {
            https,
            state: std::sync::Mutex::default(),
        }
    }

    pub(crate) fn get(
        self: &Arc<Self>,
        prefix: Option<&str>,
        blob: &risala_proto::names::BlobRef,
    ) -> BlobFetch {
        let (Some(prefix), Some(https)) = (prefix, self.https.clone()) else {
            return BlobFetch::Unavailable;
        };
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match state.blobs.get(blob.hash()) {
            Some(None) => return BlobFetch::Waiting,
            Some(Some(Some(bytes))) => return BlobFetch::Ready(bytes.clone()),
            Some(Some(None)) => {
                state.blobs.remove(blob.hash());
                return BlobFetch::Unavailable;
            }
            None => {}
        }
        // Asked again later, once a fetch is done.
        if state.in_flight >= MAX_IN_FLIGHT {
            return BlobFetch::Waiting;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return BlobFetch::Unavailable;
        };
        state.blobs.insert(*blob.hash(), None);
        state.in_flight += 1;
        drop(state);
        let url = format!("{prefix}{}", blob.hex());
        let hash = *blob.hash();
        let this = self.clone();
        handle.spawn(async move {
            let got = match https.get(&url, MAX_BLOB).await {
                crate::client::identity::Fetched::Body(body) => Some(body),
                other => {
                    tracing::info!(%url, ?other, "a blob could not be fetched");
                    None
                }
            };
            this.state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .done(hash, got);
        });
        BlobFetch::Waiting
    }

    #[cfg(test)]
    fn counts(&self) -> (usize, usize, usize) {
        let s = self.state.lock().unwrap();
        (s.in_flight, s.ready.len(), s.held)
    }
}

/// Stores the group engine's own blobs (12.12), commits, GroupInfos and
/// Welcomes too long for a line, with an HTTP PUT to the `put` URL that
/// BLOB answered, in the background, for [`Hooks::put_blob`] and
/// [`Hooks::blob_put`]. The engine asks for at most the blobs of one post
/// or Welcome per conversation at a time, and forgets each once it is done.
pub(crate) struct BlobPutter {
    https: Arc<dyn crate::client::files::FileHttps>,
    /// Each PUT: in flight (`None`), or how it went.
    state: std::sync::Mutex<std::collections::HashMap<risala_proto::names::BlobRef, Option<bool>>>,
}

impl BlobPutter {
    pub(crate) fn new(https: Arc<dyn crate::client::files::FileHttps>) -> BlobPutter {
        BlobPutter {
            https,
            state: std::sync::Mutex::default(),
        }
    }

    fn put(self: &Arc<Self>, url: &str, blob: &risala_proto::names::BlobRef, bytes: Arc<Vec<u8>>) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.get(blob) == Some(&None) {
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            state.insert(*blob, Some(false));
            return;
        };
        state.insert(*blob, None);
        drop(state);
        let (url, blob, this) = (url.to_owned(), *blob, self.clone());
        handle.spawn(async move {
            let ok = match this.https.put(&url, &bytes).await {
                Ok(()) => true,
                Err(e) => {
                    tracing::info!(%blob, error = %e, "a blob could not be stored");
                    false
                }
            };
            this.state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(blob, Some(ok));
        });
    }

    fn get(&self, blob: &risala_proto::names::BlobRef) -> crate::sync::conversations::BlobPut {
        use crate::sync::conversations::BlobPut;
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match state.get(blob) {
            Some(None) => BlobPut::Waiting,
            Some(Some(true)) => {
                state.remove(blob);
                BlobPut::Done
            }
            _ => {
                state.remove(blob);
                BlobPut::Failed
            }
        }
    }
}

impl Hooks for ClientHooks {
    fn enforce_key_checks(&self) -> bool {
        self.enforce_key_checks
    }

    /// WANT, TRANSFER and REPORT go to transfers and reports (C4).
    fn content_line(
        &self,
        tx: &mut crate::store::Tx<'_>,
        conv: ConversationId,
        leaf: &crate::store::conversations::LeafRow,
        line: &risala_proto::content::ContentLine,
    ) -> Vec<crate::sync::Action> {
        use risala_proto::content::ContentLine as L;
        match line {
            // The identity area's lines of the conversation with yourself
            // (C1, 12.9), wired by task C5.
            line if super::members::is_identity_line(line) => {
                let now = self.clock.now().unix_millis();
                super::members::self_line(tx, self.keys.as_ref(), conv, leaf, line, now)
            }
            L::Want { .. } | L::Transfer(_) | L::Report(_) => {
                let now = self.clock.now().unix_millis();
                crate::sync::transfer::content_line(tx, conv, leaf, line, now).unwrap_or_else(|e| {
                    tracing::info!(error = %e, "a transfer or report line");
                    Vec::new()
                })
            }
            _ => Vec::new(),
        }
    }

    /// Expired posts are asked for with WANT (C4, 12.13).
    fn posts_expired(
        &self,
        tx: &mut crate::store::Tx<'_>,
        account: AccountId,
        mailbox: &risala_proto::names::BoxName,
        after: u64,
        before: u64,
    ) -> Vec<crate::sync::Action> {
        let now = self.clock.now().unix_millis();
        crate::sync::transfer::posts_expired(tx, account, mailbox, after, Some(before), now)
            .unwrap_or_else(|e| {
                tracing::info!(error = %e, "asking for expired posts");
                Vec::new()
            })
    }

    /// FOLLOW's `quiet`, from push (C4).
    fn follow_quiet(
        &self,
        store: &Store,
        account: AccountId,
        mailbox: &risala_proto::names::BoxName,
    ) -> Option<risala_proto::types::PushTag> {
        crate::sync::push::follow_quiet(store, account, mailbox)
    }

    fn blob(
        &self,
        _: AccountId,
        prefix: Option<&str>,
        blob: &risala_proto::names::BlobRef,
    ) -> BlobFetch {
        self.blobs.get(prefix, blob)
    }

    fn put_blob(&self, url: &str, blob: &risala_proto::names::BlobRef, bytes: Arc<Vec<u8>>) {
        self.puts.put(url, blob, bytes);
    }

    fn blob_put(&self, blob: &risala_proto::names::BlobRef) -> crate::sync::conversations::BlobPut {
        self.puts.get(blob)
    }

    /// Whether a fetched KeyPackage's device is current, from the identity
    /// area's tables (C1, wired by task C5).
    fn device_key_of(
        &self,
        tx: &crate::store::Tx<'_>,
        _: AccountId,
        uid: &Uid,
        device: &risala_mls::identity::DeviceId,
    ) -> Option<Option<Vec<u8>>> {
        super::members::device_key_of(tx, uid, device)
    }

    /// Never read, or an outage at the last fetch (4.4, 12.7).
    fn key_file_unreadable(&self, tx: &crate::store::Tx<'_>, uid: &Uid) -> bool {
        super::members::key_file_unreadable(tx, uid)
    }

    /// Not while another device of the identity is current (task C5).
    fn start_self_conversation(&self, tx: &crate::store::Tx<'_>, uid: &Uid) -> bool {
        super::members::start_self_conversation(tx, uid)
    }

    /// The key facts of 12.7, from the identity area's tables (C1, wired
    /// by task C5).
    fn key_facts<'a>(
        &'a self,
        tx: &'a crate::store::Tx<'_>,
        _: AccountId,
    ) -> Box<dyn risala_mls::checks::KeyFacts + 'a> {
        Box::new(super::members::TxFacts::new(tx))
    }

    fn device_key(&self, _: AccountId, uid: &Uid) -> Option<risala_mls::mldsa::SigningKey> {
        let key_id: Option<String> = self
            .store
            .read(|conn| {
                use rusqlite::OptionalExtension as _;
                Ok(conn
                    .query_row(
                        "SELECT key_id FROM identities WHERE uid = ?1",
                        [uid.as_str()],
                        |r| r.get(0),
                    )
                    .optional()?)
            })
            .ok()
            .flatten();
        let key = self.keys.load(&key_id?).ok()??;
        let seed = crate::keys::key_seed(&key);
        Some(risala_mls::mldsa::SigningKey::from_seed(*seed))
    }

    // Leaf confirmation (task C3): see crate::sync::confirm.

    fn leaf_confirmed(
        &self,
        tx: &crate::store::Tx<'_>,
        conv: ConversationId,
        leaf: &crate::store::conversations::LeafRow,
    ) -> bool {
        self.confirm.leaf_confirmed(tx, conv, leaf)
    }

    fn leaves_changed(
        &self,
        tx: &mut crate::store::Tx<'_>,
        conv: ConversationId,
    ) -> Vec<crate::sync::Action> {
        self.confirm.leaves_changed(tx, conv).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "leaf confirmation failed after a commit");
            Vec::new()
        })
    }

    fn commit_applied(
        &self,
        tx: &mut crate::store::Tx<'_>,
        conv: ConversationId,
        by: crate::sync::confirm::CommitBy,
    ) -> Vec<crate::sync::Action> {
        self.confirm
            .commit_applied(tx, conv, by)
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "leaf confirmation failed after a commit");
                Vec::new()
            })
    }

    fn message_received(
        &self,
        tx: &mut crate::store::Tx<'_>,
        _: &crate::sync::conversations::Ctx<'_>,
        conv: &ConvRow,
        leaf: &crate::store::conversations::LeafRow,
        group: &risala_mls::openmls::group::MlsGroup,
        message: &risala_mls::message::Decrypted,
        t: u64,
    ) -> crate::sync::confirm::Received {
        self.confirm
            .message_received(tx, conv, group, message, t)
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "leaf confirmation failed on a message");
                crate::sync::confirm::Received {
                    confirmed: self.confirm.leaf_confirmed(tx, conv.id, leaf),
                    ..Default::default()
                }
            })
    }

    fn outgoing(
        &self,
        tx: &mut crate::store::Tx<'_>,
        conv: &ConvRow,
        outbox: i64,
        body: &[u8],
    ) -> crate::sync::confirm::Outgoing {
        self.confirm
            .outgoing(tx, conv, outbox, body)
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "leaf confirmation failed on a message to send");
                crate::sync::confirm::Outgoing::Keep
            })
    }
}

/// `new`, an extension this device made by changing the group's, if it
/// is well formed (12.4). Devices refuse a commit whose extension breaks
/// a format rule, so a change that would is refused here, before any
/// commit is made: past the ban cap or the size limit with an error of
/// its own, since the user can make room; anything else is a bug.
fn checked(new: RisalaConversation) -> Result<RisalaConversation> {
    match new.check() {
        Ok(()) => Ok(new),
        Err(ExtensionError::TooManyBans) => {
            Err(Error::Conversation(ConversationError::TooManyBans))
        }
        Err(ExtensionError::TooLong(_)) => Err(Error::Conversation(ConversationError::TooLarge)),
        Err(e) => Err(Error::Internal(format!(
            "a change made the conversation extension malformed: {e}"
        ))),
    }
}

/// The extension after a ban of `uid` (6.4): `uid` added to `bans`, if it
/// is not there yet, and taken out of `owners` and `mods`. A ban past
/// 10,000 uids, or past 512 KiB, is refused ([`checked`]).
fn banned(ext: &RisalaConversation, uid: &Uid) -> Result<RisalaConversation> {
    let mut new = ext.clone();
    new.owners.retain(|u| u != uid);
    new.mods.retain(|u| u != uid);
    if !new.bans.contains(uid) {
        new.bans.push(uid.clone());
    }
    checked(new)
}

/// The extension with `uid`'s role set to `role` (6.3). Leaving no owner
/// is not allowed, and a role past 512 KiB is refused ([`checked`]).
fn with_role(ext: &RisalaConversation, uid: &Uid, role: Role) -> Result<RisalaConversation> {
    let mut new = ext.clone();
    new.owners.retain(|u| u != uid);
    new.mods.retain(|u| u != uid);
    match role {
        Role::Owner => new.owners.push(uid.clone()),
        Role::Mod => new.mods.push(uid.clone()),
        _ => {}
    }
    if new.owners.is_empty() {
        return Err(Error::Conversation(ConversationError::NotAllowed));
    }
    checked(new)
}

/// The extension with the topic `topic` (6.2), which is at most 512
/// bytes. A topic past the extension's 512 KiB is refused ([`checked`]).
fn with_topic(ext: &RisalaConversation, topic: &str) -> Result<RisalaConversation> {
    if topic.len() > risala_mls::conversation::MAX_TOPIC_LEN {
        return Err(Error::invalid("topic", topic));
    }
    let mut new = ext.clone();
    new.topic = topic.to_owned();
    checked(new)
}

fn summary(store: &Store, row: ConvRow) -> Result<ConversationSummary> {
    let unread = store
        .message_rows(row.id)?
        .iter()
        .filter(|m| !m.own && !m.hidden && m.seq.is_some_and(|s| s > row.read_seq))
        .filter(|m| m.edit_of.is_none() && m.react_to.is_none())
        .count() as u64;
    let name = match (&row.kind, &row.peer) {
        (ConvKind::Direct, Some(peer)) => peer.to_string(),
        _ => row.name.clone(),
    };
    let left_by_peer = match (&row.kind, &row.peer) {
        (ConvKind::Direct, Some(peer)) if !row.state.in_group() => store.departed(row.id, peer)?,
        _ => false,
    };
    Ok(ConversationSummary {
        id: row.id,
        account: row.account,
        kind: row.kind.into(),
        name,
        room: row.room.as_deref().and_then(|r| r.parse().ok()),
        topic: (!row.topic.is_empty()).then(|| row.topic.clone()),
        unread,
        last_activity: row.last_activity.and_then(Timestamp::from_unix_millis),
        sending_stopped: false,
        state: ConversationState::of(&row, &store.pending_outbox_rows(row.id)?),
        left_by_peer,
    })
}

fn group_role(r: GroupRole) -> Role {
    match r {
        GroupRole::Owner => Role::Owner,
        GroupRole::Mod => Role::Mod,
        GroupRole::Member => Role::Member,
    }
}

impl Client {
    /// The hooks the group engine runs with.
    pub(crate) fn conversation_hooks(&self) -> Arc<dyn Hooks> {
        Arc::new(ClientHooks {
            store: self.store().clone(),
            keys: self.options().keys.clone(),
            blobs: Arc::new(BlobFetcher::new(self.options().https.clone())),
            puts: Arc::new(BlobPutter::new(self.file_https())),
            confirm: self.confirm_service(),
            clock: self.options().clock.clone(),
            #[cfg(test)]
            enforce_key_checks: !self.options().skip_key_checks,
            #[cfg(not(test))]
            enforce_key_checks: true,
        })
    }

    /// The account's conversations, newest activity first.
    pub fn conversations(&self, account: AccountId) -> Result<Vec<ConversationSummary>> {
        self.store()
            .conversation_rows(account)?
            .into_iter()
            .filter(|r| r.state != ConvState::Failed)
            .map(|r| self.summary(r))
            .collect()
    }

    /// One conversation.
    pub fn conversation(&self, id: ConversationId) -> Result<ConversationSummary> {
        let row = self.conv_row(id)?;
        self.summary(row)
    }

    fn summary(&self, row: ConvRow) -> Result<ConversationSummary> {
        // Task C5: sending stopped by the identity area (12.14).
        let stopped = self.row_sending_stopped(&row)?.is_some();
        let mut s = summary(self.store(), row)?;
        s.sending_stopped = stopped;
        Ok(s)
    }

    pub(crate) fn conv_row(&self, id: ConversationId) -> Result<ConvRow> {
        self.store()
            .conversation_row(id)?
            .ok_or(Error::Conversation(ConversationError::NotFound(id)))
    }

    /// Starts a job on a connected account's group engine, and waits for
    /// it to end.
    pub(crate) async fn run_job(&self, account: AccountId, job: Job) -> Result<ConversationId> {
        let exec = self.exec(account)?;
        let mut events = self.subscribe();
        let id = exec.with_conversations(|e, cx| e.start(cx, job)).await;
        loop {
            match events.recv().await {
                Ok(Event::Conversation(ConversationEvent::JobDone {
                    job,
                    conversation,
                    error,
                })) if job == id => {
                    return match (conversation, error) {
                        (Some(c), None) => Ok(c),
                        (_, e) => Err(Error::Conversation(ConversationError::Failed(
                            e.unwrap_or_else(|| "failed".into()),
                        ))),
                    };
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    return Err(Error::Internal("the client closed".into()));
                }
            }
        }
    }

    /// The direct conversation with `uid` on the account's server, started
    /// if there is none (5.1, 6.1): this device creates the group and the
    /// mailbox, and adds `uid`'s devices and its own other devices.
    pub async fn direct(&self, account: AccountId, uid: &str) -> Result<ConversationId> {
        let peer: Uid = uid.parse().map_err(|_| Error::invalid("uid", uid))?;
        // One that the peer left does not count: this side leaves it too,
        // and a new one is started (5.1, 6.1, 12.7).
        for r in self.store().conversation_rows(account)? {
            if r.kind == ConvKind::Direct
                && r.peer.as_ref() == Some(&peer)
                && r.state.in_group()
                && !self.store().departed(r.id, &peer)?
            {
                return Ok(r.id);
            }
        }
        // Task C5: the peer's key file read and its devices addable (12.7).
        self.prepare_members(account, std::slice::from_ref(&peer))
            .await?;
        self.run_job(account, Job::Direct { peer }).await
    }

    /// The conversation with yourself, started if there is none (5.1).
    pub async fn with_yourself(&self, account: AccountId) -> Result<ConversationId> {
        let existing = self
            .store()
            .conversation_rows(account)?
            .into_iter()
            .find(|r| r.kind == ConvKind::WithYourself && r.state.in_group());
        if let Some(row) = existing {
            return Ok(row.id);
        }
        self.run_job(account, Job::WithYourself).await
    }

    /// Creates a private room named `name` (5.1), with this identity's
    /// other devices.
    pub async fn create_private_room(
        &self,
        account: AccountId,
        name: &str,
    ) -> Result<ConversationId> {
        if name.is_empty() || name.len() > 128 {
            return Err(Error::invalid("room name", name));
        }
        self.run_job(
            account,
            Job::PrivateRoom {
                name: name.to_owned(),
                members: Vec::new(),
            },
        )
        .await
    }

    /// Creates the public room `room` on the account's server (6.1): this
    /// device's identity is its first owner. Other devices, this
    /// identity's included, join it by themselves.
    pub async fn create_public_room(
        &self,
        account: AccountId,
        room: &str,
    ) -> Result<ConversationId> {
        let room: Room = room.parse().map_err(|_| Error::invalid("room", room))?;
        self.run_job(account, Job::PublicRoom { room }).await
    }

    /// Public rooms on the account's server, after `after` (6.1).
    pub async fn list_public_rooms(
        &self,
        account: AccountId,
        after: Option<&str>,
    ) -> Result<Vec<PublicRoom>> {
        let after: Option<Room> = after
            .map(|r| r.parse().map_err(|_| Error::invalid("room", r)))
            .transpose()?;
        let exec = self.exec(account)?;
        // LIST says nothing about the device, so it goes on a connection
        // that is not signed in (4.1).
        let slot = if self.account(account)?.kind == crate::store::AccountKind::Guest {
            crate::conn::Slot::Guest
        } else {
            crate::conn::Slot::Anonymous(0)
        };
        let response = exec
            .request(
                slot,
                risala_proto::command::Command::List { after, limit: None },
            )
            .await?;
        let (lines, _) = response.into_result().map_err(crate::conn::Error::from)?;
        Ok(lines
            .into_iter()
            .filter_map(|l| match l.line {
                risala_proto::server::ServerLine::Room {
                    room,
                    members,
                    topic,
                    ..
                } => Some(PublicRoom {
                    room,
                    members,
                    topic,
                }),
                _ => None,
            })
            .collect())
    }

    /// Joins the public room `room`, as an identity or a guest (6.1), by
    /// external proposal: returns once a member's device has committed it
    /// and the Welcome is in, which can take up to 10 minutes. Fails if the
    /// name now leads to another group than the one this account joined
    /// before; [`join_public_room_anew`](Self::join_public_room_anew) joins
    /// it anyway.
    pub async fn join_public_room(&self, account: AccountId, room: &str) -> Result<ConversationId> {
        let room: Room = room.parse().map_err(|_| Error::invalid("room", room))?;
        self.run_job(
            account,
            Job::JoinPublic {
                room,
                new_group: false,
            },
        )
        .await
    }

    /// Joins the public room `room` even though its name now leads to
    /// another group than the one joined before, once the user chose to
    /// (6.1).
    pub async fn join_public_room_anew(
        &self,
        account: AccountId,
        room: &str,
    ) -> Result<ConversationId> {
        let room: Room = room.parse().map_err(|_| Error::invalid("room", room))?;
        self.run_job(
            account,
            Job::JoinPublic {
                room,
                new_group: true,
            },
        )
        .await
    }

    /// The user accepts that the server changed a public room
    /// ([`ConversationEvent::RoomChanged`]), and the device joins it again
    /// (12.7, "Rejoining a public room").
    pub async fn accept_room_change(&self, conversation: ConversationId) -> Result<()> {
        let row = self.conv_row(conversation)?;
        if row.kind != ConvKind::Public {
            return Err(Error::Conversation(ConversationError::NotAllowed));
        }
        self.store()
            .write_with(|tx| {
                tx.set_accept_change(conversation, true)?;
                Ok::<_, EngineError>(())
            })
            .map_err(Error::from)?;
        let exec = self.exec(row.account)?;
        exec.with_conversations(|e, cx| ((), e.rejoin(cx, conversation)))
            .await;
        Ok(())
    }

    /// As a guest, starts a report conversation with `uid`, an owner or
    /// moderator of a public room here (5.8, 12.7): a direct conversation
    /// in which only REPORT lines from the guest count.
    pub async fn report_conversation(
        &self,
        account: AccountId,
        uid: &str,
    ) -> Result<ConversationId> {
        let peer: Uid = uid.parse().map_err(|_| Error::invalid("uid", uid))?;
        self.run_job(account, Job::Report { peer }).await
    }

    /// Accepts a guest's report conversation
    /// ([`ConversationEvent::ReportOffered`]), and joins it (12.7).
    pub async fn accept_report(&self, account: AccountId, offer: i64) -> Result<ConversationId> {
        self.held(account, offer, false)?;
        let exec = self.exec(account)?;
        exec.with_conversations(|e, cx| e.accept_held(cx, offer))
            .await
            .map_err(|e| Error::Conversation(ConversationError::Failed(e)))
    }

    /// Declines a guest's report conversation (12.7): its Welcome, and the
    /// KeyPackage it is for, are forgotten.
    pub fn decline_report(&self, account: AccountId, offer: i64) -> Result<()> {
        self.forget_held(account, offer, false)
    }

    /// The invitations held for the user, oldest first (6.1): see
    /// [`ConversationEvent::Invited`].
    pub fn invitations(&self, account: AccountId) -> Result<Vec<Invitation>> {
        Ok(self
            .store()
            .held_welcome_rows(account)?
            .into_iter()
            .filter_map(|h| match h.held {
                Held::Invitation { conv, by } => Some(Invitation {
                    id: h.id,
                    conversation: conv,
                    by,
                    received: Timestamp::from_unix_millis(h.received),
                }),
                Held::Report { .. } => None,
            })
            .collect())
    }

    /// Accepts an invitation back into a conversation this device left for
    /// good ([`ConversationEvent::Invited`]), and joins it (6.1).
    pub async fn accept_invitation(
        &self,
        account: AccountId,
        invitation: i64,
    ) -> Result<ConversationId> {
        self.held(account, invitation, true)?;
        let exec = self.exec(account)?;
        exec.with_conversations(|e, cx| e.accept_held(cx, invitation))
            .await
            .map_err(|e| Error::Conversation(ConversationError::Failed(e)))
    }

    /// Declines an invitation back into a conversation this device left
    /// for good (6.1): its Welcome, and the KeyPackage it is for, are
    /// forgotten. The device's leaf, if the invitation added one, does
    /// nothing, and is removed once it is stale (12.7).
    pub fn decline_invitation(&self, account: AccountId, invitation: i64) -> Result<()> {
        self.forget_held(account, invitation, true)
    }

    /// A Welcome held for the user: an invitation, or a report offer.
    fn held(
        &self,
        account: AccountId,
        id: i64,
        invitation: bool,
    ) -> Result<crate::store::conversations::HeldWelcome> {
        self.store()
            .held_welcome_rows(account)?
            .into_iter()
            .find(|h| h.id == id && matches!(h.held, Held::Invitation { .. }) == invitation)
            .ok_or_else(|| {
                let what = if invitation { "invitation" } else { "offer" };
                Error::Conversation(ConversationError::Failed(format!("no such {what}")))
            })
    }

    fn forget_held(&self, account: AccountId, id: i64, invitation: bool) -> Result<()> {
        let held = self.held(account, id, invitation)?;
        self.store()
            .write_with(|tx| group::forget_held(tx, &held))
            .map_err(Error::from)?;
        Ok(())
    }

    /// Queues a commit in a conversation, and lets the engine send it.
    async fn commit(&self, conversation: ConversationId, intent: Intent) -> Result<()> {
        let row = self.conv_row(conversation)?;
        if !row.state.in_group() {
            return Err(Error::Conversation(ConversationError::NotInGroup));
        }
        let now = self.options().clock.now().unix_millis();
        self.store()
            .write_with(|tx| group::queue_intent(tx, conversation, &intent, now))
            .map_err(Error::from)?;
        self.kick(row.account).await;
        Ok(())
    }

    /// The conversation extension of a group (12.4).
    pub(crate) fn extension(&self, row: &ConvRow) -> Result<RisalaConversation> {
        let crypto =
            Arc::new(risala_mls::RisalaCrypto::new().map_err(|e| Error::Internal(e.to_string()))?);
        self.store()
            .read(|conn| {
                let p = crate::store::mls::read_provider(conn, &crypto);
                use risala_mls::openmls_traits::OpenMlsProvider as _;
                let group = risala_mls::openmls::group::MlsGroup::load(
                    p.storage(),
                    &risala_mls::openmls::prelude::GroupId::from_slice(&row.group_id),
                )
                .map_err(|e| crate::store::StoreError::Corrupt(format!("{e:?}")))?;
                Ok(group.and_then(|g| risala_mls::group::conversation(&g)))
            })?
            .ok_or(Error::Conversation(ConversationError::NotInGroup))
    }

    /// The uid of the account.
    fn own_uid(&self, account: AccountId) -> Result<Uid> {
        Ok(self.account(account)?.uid)
    }

    /// Leaves a conversation (6.1): a commit that removes this identity's
    /// other leaves, if it has any, then a SelfRemove. In a direct
    /// conversation nobody commits it: the device forgets the group once
    /// it has posted it, and so do the other participant's. Where no other
    /// identity has a leaf, the device leaves locally, with no SelfRemove:
    /// at once if its identity has no other leaf, and otherwise once its
    /// commit that removes them is applied, so that none of them can
    /// Welcome it back later.
    pub async fn leave(&self, conversation: ConversationId) -> Result<()> {
        let row = self.conv_row(conversation)?;
        let own = self.own_uid(row.account)?;
        let now = self.options().clock.now().unix_millis();
        let (left, changes) = self
            .store()
            .write_with(|tx| group::leave(tx, conversation, &own, now))
            .map_err(Error::from)?;
        self.emit_changes(changes);
        if left {
            self.emit(Event::Conversation(ConversationEvent::Left {
                conversation,
            }));
        }
        self.kick(row.account).await;
        Ok(())
    }

    /// Adds `uid`'s devices to a room (6.1, 12.7): an invitation, which
    /// an owner or moderator makes (6.3).
    pub async fn invite(&self, conversation: ConversationId, uid: &str) -> Result<()> {
        let row = self.conv_row(conversation)?;
        let uid: Uid = uid.parse().map_err(|_| Error::invalid("uid", uid))?;
        if !matches!(row.kind, ConvKind::Private) {
            return Err(Error::Conversation(ConversationError::NotAllowed));
        }
        let ext = self.extension(&row)?;
        let own = self.own_uid(row.account)?;
        let role = ext.role(&own);
        let invitee = ext.role(&uid);
        // 12.7: identities in `owners` or `mods` are invited by owners only.
        if role < GroupRole::Mod || (invitee >= GroupRole::Mod && role < GroupRole::Owner) {
            return Err(Error::Conversation(ConversationError::NotAllowed));
        }
        // Task C5: the invitee's key file read and its devices addable.
        self.prepare_members(row.account, std::slice::from_ref(&uid))
            .await?;
        self.run_job(
            row.account,
            Job::Invite {
                conv: conversation,
                uids: vec![uid],
            },
        )
        .await
        .map(drop)
    }

    /// Removes `uid` from a room, and bans it if `ban` (6.4): a commit that
    /// removes every leaf of the identity, and for a ban, adds it to
    /// `bans` and takes it out of `owners` and `mods`.
    pub async fn remove_member(
        &self,
        conversation: ConversationId,
        uid: &str,
        ban: bool,
    ) -> Result<()> {
        let row = self.conv_row(conversation)?;
        let uid: Uid = uid.parse().map_err(|_| Error::invalid("uid", uid))?;
        let ext = self.extension(&row)?;
        let own = self.own_uid(row.account)?;
        let (role, target) = (ext.role(&own), ext.role(&uid));
        // 6.4: moderators act on plain members only; owners on anyone but
        // the last owner.
        let allowed = match role {
            GroupRole::Owner => !(target == GroupRole::Owner && ext.owners.len() <= 1),
            GroupRole::Mod => target == GroupRole::Member,
            GroupRole::Member => false,
        };
        if !allowed || !matches!(row.kind, ConvKind::Private | ConvKind::Public) {
            return Err(Error::Conversation(ConversationError::NotAllowed));
        }
        let remove = self
            .store()
            .leaf_rows(conversation)?
            .into_iter()
            .filter(|l| l.uid == uid)
            .map(|l| (l.uid.to_string(), l.device_id))
            .collect();
        let conversation_ext = match ban {
            true => Some(banned(&ext, &uid)?.encode()),
            false => None,
        };
        self.commit(
            conversation,
            Intent {
                remove,
                conversation: conversation_ext,
                ..Intent::default()
            },
        )
        .await
    }

    /// Sets `uid`'s role in a room (6.3), by an owner.
    pub async fn set_role(
        &self,
        conversation: ConversationId,
        uid: &str,
        role: Role,
    ) -> Result<()> {
        let row = self.conv_row(conversation)?;
        let uid: Uid = uid.parse().map_err(|_| Error::invalid("uid", uid))?;
        let ext = self.extension(&row)?;
        let own = self.own_uid(row.account)?;
        if ext.role(&own) != GroupRole::Owner || uid.is_guest() {
            return Err(Error::Conversation(ConversationError::NotAllowed));
        }
        let new = with_role(&ext, &uid, role)?;
        self.commit(
            conversation,
            Intent {
                conversation: Some(new.encode()),
                ..Intent::default()
            },
        )
        .await
    }

    /// Sets a room's topic (6.2), by an owner or moderator.
    pub async fn set_topic(&self, conversation: ConversationId, topic: &str) -> Result<()> {
        let row = self.conv_row(conversation)?;
        if topic.len() > risala_mls::conversation::MAX_TOPIC_LEN
            || !matches!(row.kind, ConvKind::Private | ConvKind::Public)
        {
            return Err(Error::invalid("topic", topic));
        }
        let ext = self.extension(&row)?;
        let own = self.own_uid(row.account)?;
        if ext.role(&own) < GroupRole::Mod {
            return Err(Error::Conversation(ConversationError::NotAllowed));
        }
        let new = with_topic(&ext, topic)?;
        self.commit(
            conversation,
            Intent {
                conversation: Some(new.encode()),
                ..Intent::default()
            },
        )
        .await
    }

    /// The members of a conversation, from its group (12.7): each identity
    /// with a leaf, its role from the conversation extension (6.3), and
    /// its display name (8.2).
    pub fn members(&self, conversation: ConversationId) -> Result<Vec<Member>> {
        let row = self.conv_row(conversation)?;
        let ext = self.extension(&row).ok();
        let mut members: Vec<Member> = Vec::new();
        for leaf in self.store().leaf_rows(conversation)? {
            let role = ext
                .as_ref()
                .map_or(Role::Member, |e| group_role(e.role(&leaf.uid)));
            match members.iter_mut().find(|m| m.uid == leaf.uid) {
                Some(m) => {
                    m.devices += 1;
                    if m.display_name.as_deref().unwrap_or("").is_empty() {
                        m.display_name = leaf.display_name.clone();
                    }
                }
                None => members.push(Member {
                    uid: leaf.uid.clone(),
                    display_name: leaf.display_name.clone().filter(|n| !n.is_empty()),
                    role,
                    devices: 1,
                    verified: false,
                }),
            }
        }
        Ok(members)
    }

    /// Sets this device's display name in the account's groups (8.2): kept
    /// for new groups, and committed in each group it is in, with a commit
    /// that updates its own leaf.
    pub async fn set_display_name(&self, account: AccountId, name: &str) -> Result<()> {
        if name.len() > risala_mls::profile::MAX_DISPLAY_NAME_LEN {
            return Err(Error::invalid("display name", name));
        }
        let key = group::display_name_key(account);
        self.store().set_setting(&key, Some(name))?;
        let now = self.options().clock.now().unix_millis();
        let convs: Vec<ConversationId> = self
            .store()
            .conversation_rows(account)?
            .into_iter()
            .filter(|r| r.state == ConvState::Active)
            .map(|r| r.id)
            .collect();
        self.store()
            .write_with(|tx| {
                for conv in convs {
                    group::queue_intent(
                        tx,
                        conv,
                        &Intent {
                            display_name: Some(name.to_owned()),
                            ..Intent::default()
                        },
                        now,
                    )?;
                }
                Ok::<_, EngineError>(())
            })
            .map_err(Error::from)?;
        self.kick(account).await;
        Ok(())
    }

    /// Blocks `uid`, or a whole domain as `*@<domain>` (5.7), on every
    /// device of the account's identity: a BLOCK line in the conversation
    /// with yourself.
    pub async fn block(&self, account: AccountId, uid: &str) -> Result<()> {
        self.set_block(account, uid, true).await
    }

    /// Unblocks `uid` (5.7).
    pub async fn unblock(&self, account: AccountId, uid: &str) -> Result<()> {
        self.set_block(account, uid, false).await
    }

    async fn set_block(&self, account: AccountId, target: &str, blocked: bool) -> Result<()> {
        let target: risala_proto::names::BlockTarget = target
            .parse()
            .map_err(|_| Error::invalid("block target", target))?;
        let own = self.own_uid(account)?;
        let now = self.options().clock.now().unix_millis();
        let self_conv = self
            .store()
            .conversation_rows(account)?
            .into_iter()
            .find(|r| r.kind == ConvKind::WithYourself && r.state.in_group())
            .map(|r| r.id);
        self.store()
            .write_with(|tx| {
                tx.set_block(account, &target.to_string(), blocked, now)?;
                if let Some(conv) = self_conv {
                    let line = if blocked {
                        ContentLine::Block(target.clone())
                    } else {
                        ContentLine::Unblock(target.clone())
                    };
                    content::queue_lines(tx, conv, &own, vec![line], false, now)?;
                }
                Ok::<_, EngineError>(())
            })
            .map_err(Error::from)?;
        self.kick(account).await;
        Ok(())
    }

    /// The account's blocks (5.7).
    pub fn blocks(&self, account: AccountId) -> Result<Vec<String>> {
        Ok(self.store().block_rows(account)?)
    }

    /// Whether the server reports the account's identity as online (8.3).
    pub async fn set_presence(&self, account: AccountId, on: bool) -> Result<()> {
        let exec = self.exec(account)?;
        let response = exec
            .request(
                crate::conn::Slot::SignedIn,
                risala_proto::command::Command::Presence { on },
            )
            .await?;
        response.ok().map_err(crate::conn::Error::from)?;
        Ok(())
    }

    /// The identities whose presence the account watches (8.3), on the
    /// anonymous connection kept apart for WATCH, or the first anonymous
    /// one.
    pub async fn watch(&self, account: AccountId, uids: &[String]) -> Result<()> {
        let uids = uids
            .iter()
            .map(|u| u.parse().map_err(|_| Error::invalid("uid", u.as_str())))
            .collect::<Result<Vec<Uid>>>()?;
        let exec = self.exec(account)?;
        let command = risala_proto::command::Command::Watch { uids };
        let response = match exec
            .request(crate::conn::Slot::Watch, command.clone())
            .await
        {
            Ok(r) => r,
            Err(_) => {
                exec.request(crate::conn::Slot::Anonymous(0), command)
                    .await?
            }
        };
        response.ok().map_err(crate::conn::Error::from)?;
        Ok(())
    }
}

#[cfg(test)]
mod server_tests;
#[cfg(test)]
mod tests;
