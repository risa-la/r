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

use risala_mls::conversation::{RisalaConversation, Role as GroupRole};
use risala_proto::content::ContentLine;
use risala_proto::types::Role;

use super::error::not_implemented;
use super::types::{AccountId, ConversationId, Room, Timestamp, Uid};
use super::{Client, Error, Event, Result};
use crate::keys::KeyStore;
use crate::store::Store;
use crate::store::conversations::{ConvKind, ConvRow, ConvState};
use crate::sync::conversations::wire::Intent;
use crate::sync::conversations::{EngineError, Hooks, Job, JobId, content, group};

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
    /// Whether the device is still in it.
    pub active: bool,
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
}

impl Hooks for ClientHooks {
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
        active: row.state.in_group(),
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
        })
    }

    /// The account's conversations, newest activity first.
    pub fn conversations(&self, account: AccountId) -> Result<Vec<ConversationSummary>> {
        self.store()
            .conversation_rows(account)?
            .into_iter()
            .filter(|r| r.state != ConvState::Failed)
            .map(|r| summary(self.store(), r))
            .collect()
    }

    /// One conversation.
    pub fn conversation(&self, id: ConversationId) -> Result<ConversationSummary> {
        let row = self.conv_row(id)?;
        summary(self.store(), row)
    }

    pub(crate) fn conv_row(&self, id: ConversationId) -> Result<ConvRow> {
        self.store()
            .conversation_row(id)?
            .ok_or(Error::Conversation(ConversationError::NotFound(id)))
    }

    /// Starts a job on a connected account's group engine, and waits for
    /// it to end.
    async fn run_job(&self, account: AccountId, job: Job) -> Result<ConversationId> {
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
        let existing = self
            .store()
            .conversation_rows(account)?
            .into_iter()
            .find(|r| {
                r.kind == ConvKind::Direct && r.peer.as_ref() == Some(&peer) && r.state.in_group()
            });
        if let Some(row) = existing {
            return Ok(row.id);
        }
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

    /// Joins the public room `room`, as an identity or a guest (6.1).
    pub async fn join_public_room(&self, account: AccountId, room: &str) -> Result<ConversationId> {
        let _ = (account, room);
        not_implemented("join_public_room")
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
    fn extension(&self, row: &ConvRow) -> Result<RisalaConversation> {
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
    /// other leaves, if it has any, then a SelfRemove.
    pub async fn leave(&self, conversation: ConversationId) -> Result<()> {
        let row = self.conv_row(conversation)?;
        let own = self.own_uid(row.account)?;
        let now = self.options().clock.now().unix_millis();
        self.store()
            .write_with(|tx| group::leave(tx, conversation, &own, now))
            .map_err(Error::from)?;
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
        let conversation_ext = ban.then(|| {
            let mut new = ext.clone();
            new.owners.retain(|u| *u != uid);
            new.mods.retain(|u| *u != uid);
            if !new.bans.contains(&uid) {
                new.bans.push(uid.clone());
            }
            new.encode()
        });
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
        let mut new = ext.clone();
        new.owners.retain(|u| *u != uid);
        new.mods.retain(|u| *u != uid);
        match role {
            Role::Owner => new.owners.push(uid),
            Role::Mod => new.mods.push(uid),
            _ => {}
        }
        if new.owners.is_empty() {
            return Err(Error::Conversation(ConversationError::NotAllowed));
        }
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
        if topic.len() > 512 || !matches!(row.kind, ConvKind::Private | ConvKind::Public) {
            return Err(Error::invalid("topic", topic));
        }
        let ext = self.extension(&row)?;
        let own = self.own_uid(row.account)?;
        if ext.role(&own) < GroupRole::Mod {
            return Err(Error::Conversation(ConversationError::NotAllowed));
        }
        let mut new = ext;
        new.topic = topic.to_owned();
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
mod tests;
