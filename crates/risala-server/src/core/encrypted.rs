//! Encrypted conversations (Section 12): INIT, COMMIT and GROUPINFO
//! (12.5, 12.6).
//!
//! # Commands
//!
//! Each command locks its conversation for its whole run, so commits are
//! put in order by that lock (12.5): the group is read, checked and
//! written back while nothing else can change it. The checks run in three
//! steps:
//!
//! 1. Under the lock, the rules of the conversation that need no MLS: the
//!    room is visible, encrypted, and the sender may commit at all.
//! 2. On the blocking pool, everything OpenMLS and the command alone can
//!    show (`mls`): epoch, validity, the GroupInfo, the committer, the
//!    kinds of proposals and the size. The group comes back in its new
//!    epoch, not yet stored.
//! 3. Under the lock again, the rules that need membership and key files:
//!    who may be added and removed (12.5, rule 4), and who may join by
//!    external commit (12.6).
//!
//! The new group is then stored with the COMMIT event, the INVITE and SET
//! events it causes, and its Welcome, in one transaction, which also
//! checks that the group is still in the epoch the commit was for. Only
//! then are the events and Welcomes sent.
//!
//! Key files are read while the conversation is locked: for hosted
//! identities from the store, and for others through the fetcher, from its
//! cache when that agrees with what the commit claims, and fetched afresh
//! otherwise. A key file that cannot be had gets `ERR unavailable`, as for
//! KEYPKG GET.
//!
//! # Rooms
//!
//! INIT makes a room encrypted for good: `public no`, `guests none`,
//! `e2ee yes`, and `history` and `send` from the conversation extension.
//! It records a SET event for each of these that changes, and always for
//! `e2ee` and `history`, which did not exist before. The sender must have
//! the rights of an owner (6.3), as for SET of `history`; operators do.

use std::sync::Arc;

use risala_mls::conversation::RisalaConversation;
use risala_proto::auth::PublicKey;
use risala_proto::command::Command;
use risala_proto::error::ErrorCode;
use risala_proto::mls::{CommitMessage, GroupInfo, RatchetTree, Welcome};
use risala_proto::names::{Conv, Room, Seq, Uid};
use risala_proto::server::{OkResponse, ServerLine, ServerMessage};
use risala_proto::types::{GuestAccess, Role, RoomSetting};

use super::commands::{Fail, Outcome, Reply, fail, not_found, not_supported, room_of, visible};
use super::identity::unavailable;
use super::keys::FetchError;
use super::mls::{CheckedCommit, Device, check_commit, check_init, tree_of};
use super::moderation::rights;
use super::state::ConvState;
use super::{Inner, KEY_FETCH_TIMEOUT};
use crate::handler::OutLine;
use crate::store::{
    EventKind, GroupCommit, GroupInit, GroupMeta, NewEvent, NewWelcome, StoreError, StoredEvent,
};

/// Runs `f` on the blocking pool.
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, Fail> + Send + 'static,
) -> Result<T, Fail> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| Fail::Store(StoreError::Task(e.to_string())))?
}

/// An event as stored with `seq`.
fn stored(event: NewEvent, seq: Seq) -> StoredEvent {
    StoredEvent {
        seq,
        t: event.t,
        from: event.from,
        kind: event.kind,
        deleted: false,
    }
}

fn forbidden(message: &str) -> Fail {
    fail(ErrorCode::Forbidden, message)
}

fn stale(message: &str) -> Fail {
    fail(ErrorCode::Stale, message)
}

impl Inner {
    /// INIT, COMMIT and GROUPINFO (12.5), for identities only: guests were
    /// refused before this (13).
    pub(super) async fn encrypted(
        self: &Arc<Self>,
        uid: &Uid,
        reply: &Reply,
        command: Command,
    ) -> Outcome {
        match command {
            Command::Init {
                conv,
                group_info,
                tree,
            } => self.init(uid, reply, conv, group_info, tree).await,
            Command::Commit {
                conv,
                commit,
                group_info,
                welcome,
            } => {
                self.commit(uid, reply, conv, commit, group_info, welcome)
                    .await
            }
            Command::GroupInfo { conv } => self.group_info(uid, reply, conv).await,
            _ => Err(not_supported()),
        }
    }

    /// Whether `key` is in the key file of the identity `uid` (4.4): the
    /// server's own records for a hosted identity, or else the file as the
    /// fetcher has it. A cached copy that disagrees with `claim`, what the
    /// device that sent the command says, is fetched again, since the
    /// device may have seen a newer one. A file that cannot be had is
    /// `ERR unavailable`.
    pub(super) async fn key_listed(
        &self,
        uid: &Uid,
        key: &PublicKey,
        claim: bool,
    ) -> Result<bool, Fail> {
        let Some(identity) = uid.to_identity() else {
            return Ok(false);
        };
        if self.hosts(&identity) {
            let who = uid.clone();
            let keys = self.db(move |s| s.hosted_keys(&who)).await?;
            return Ok(keys.unwrap_or_default().iter().any(|k| k.key == *key));
        }
        for refresh in [false, true] {
            let fetch = self.keys.fetcher.fetch_boxed(&identity, refresh);
            let fetched = match tokio::time::timeout(KEY_FETCH_TIMEOUT, fetch).await {
                Ok(Ok(fetched)) => fetched,
                Ok(Err(e)) => return Err(unavailable(&e)),
                Err(_) => return Err(unavailable(&FetchError::Failed("timed out".into()))),
            };
            let listed = fetched.keys.contains(key);
            if listed == claim || !fetched.cached || refresh {
                return Ok(listed);
            }
        }
        unreachable!("the second pass returns")
    }

    /// INIT (12.5).
    async fn init(
        &self,
        uid: &Uid,
        reply: &Reply,
        conv: Conv,
        group_info: GroupInfo,
        tree: RatchetTree,
    ) -> Outcome {
        let key = self.device_key(uid, reply.handle.id())?;
        match conv {
            Conv::Room(room) => {
                self.init_room(uid, reply, key, &room, group_info, tree)
                    .await
            }
            // Step 5: direct conversations.
            Conv::Uid(_) => Err(not_supported()),
        }
    }

    /// INIT of a room (12.3, 12.5).
    async fn init_room(
        &self,
        uid: &Uid,
        reply: &Reply,
        key: PublicKey,
        room: &Room,
        group_info: GroupInfo,
        tree: RatchetTree,
    ) -> Outcome {
        let mut guard = self.lock_room(room).await?;
        let st = &mut *guard;
        let info = room_of(st)?;
        let a = self.asker(uid, st.is_member(uid));
        if !visible(info, a) {
            return Err(not_found());
        }
        if st.group.is_some() {
            return Err(stale("the room is encrypted already"));
        }
        if rights(info, a) != Role::Owner {
            return Err(forbidden("only owners may encrypt a room"));
        }
        if !st.is_member(uid) || st.member_count() != 1 {
            return Err(forbidden(
                "a room is encrypted while its owner is its only member",
            ));
        }
        let id = st.id.clone();
        let crypto = self.mls.clone();
        let who = uid.clone();
        let new = blocking(move || {
            let device = Device {
                uid: &who,
                key: &key,
            };
            check_init(&crypto, device, &group_info, &tree, |c| c.is_room(&id))
        })
        .await?;

        // The settings INIT sets (12.5), each recorded if it changes, and
        // `e2ee` and `history` always.
        let settings = &info.settings;
        let mut changes = Vec::new();
        if settings.public {
            changes.push(RoomSetting::Public(false));
        }
        if settings.guests != GuestAccess::None {
            changes.push(RoomSetting::Guests(GuestAccess::None));
        }
        changes.push(RoomSetting::E2ee(true));
        changes.push(RoomSetting::History(new.conversation.history));
        if settings.send != new.conversation.send {
            changes.push(RoomSetting::Send(new.conversation.send));
        }
        let now = self.now();
        let events: Vec<NewEvent> = changes
            .iter()
            .map(|setting| NewEvent {
                t: now,
                from: uid.clone(),
                kind: EventKind::Set(setting.clone()),
                cid: None,
            })
            .collect();
        let conv = st.key;
        let (record, leaves, to_store) = (new.record.clone(), new.leaves, events.clone());
        let init = self
            .db(move |s| s.init_group(conv, &record, &leaves, &to_store, true))
            .await?;
        let seqs = match init {
            GroupInit::Done(seqs) => seqs,
            GroupInit::Exists => return Err(stale("the room is encrypted already")),
            GroupInit::IdTaken => {
                return Err(fail(ErrorCode::Invalid, "that group id was used before"));
            }
        };
        st.group = Some(new.record.meta);
        if let Some(last) = seqs.last() {
            st.head = Some(*last);
        }
        if let Some(info) = st.room_info_mut() {
            for setting in &changes {
                info.settings.apply(setting);
            }
            // Made without the group, so they cannot be used (12.5).
            info.invites.clear();
        }
        for (event, seq) in events.into_iter().zip(seqs) {
            Self::broadcast_event(st, &stored(event, seq));
        }
        // Queued under the lock, after the SET events (3.6).
        reply.line(OkResponse::new().with_id(&st.id).with_epoch(0));
        Ok(None)
    }

    /// COMMIT (12.5).
    async fn commit(
        &self,
        uid: &Uid,
        reply: &Reply,
        conv: Conv,
        commit: CommitMessage,
        group_info: GroupInfo,
        welcome: Option<Welcome>,
    ) -> Outcome {
        let key = self.device_key(uid, reply.handle.id())?;
        let room = match conv {
            Conv::Room(room) => room,
            // Step 5: direct conversations.
            Conv::Uid(_) => return Err(not_supported()),
        };
        let mut guard = self.lock_room(&room).await?;
        let st = &mut *guard;
        let info = room_of(st)?;
        let a = self.asker(uid, st.is_member(uid));
        if !visible(info, a) {
            return Err(not_found());
        }
        if st.group.is_none() {
            return Err(forbidden("the room is not encrypted"));
        }
        // Rule 3: a member or invitee.
        if !st.is_member(uid) && !info.invites.contains(uid) {
            return Err(forbidden("only members and invitees change the group"));
        }
        let conv_key = st.key;
        let record = self
            .db(move |s| s.group(conv_key))
            .await?
            .ok_or(StoreError::NoConversation)?;
        let from_epoch = record.meta.epoch;
        let crypto = self.mls.clone();
        let now = self.now().to_system_time();
        let (who, device_key) = (uid.clone(), key.clone());
        let checked = blocking(move || {
            let device = Device {
                uid: &who,
                key: &device_key,
            };
            check_commit(
                &crypto,
                &record,
                device,
                &commit,
                &group_info,
                welcome.as_ref(),
                now,
            )
            .map(|checked| (checked, commit, welcome))
        })
        .await;
        let (checked, commit, welcome) = checked?;
        let invited = self.check_room_commit(st, uid, &key, &checked).await?;
        self.store_commit(
            st, uid, reply, from_epoch, checked, commit, welcome, invited,
        )
        .await
    }

    /// The rules of a commit in a room that need its membership and key
    /// files (12.5, 12.6). Returns the identities the commit invites.
    async fn check_room_commit(
        &self,
        st: &ConvState,
        uid: &Uid,
        key: &PublicKey,
        checked: &CheckedCommit,
    ) -> Result<Vec<Uid>, Fail> {
        let info = room_of(st)?;
        let a = self.asker(uid, st.is_member(uid));
        if checked.external {
            if !checked.had_leaf {
                return Err(forbidden(
                    "an identity joins by external commit only when it has a leaf",
                ));
            }
            if !self.key_listed(uid, key, true).await? {
                return Err(forbidden("the device's key is not in its key file"));
            }
        }
        let mut invited: Vec<Uid> = Vec::new();
        for (target, target_key) in &checked.adds {
            if !self.key_listed(target, target_key, true).await? {
                return Err(forbidden(&format!(
                    "a key of {target} that is not in its key file"
                )));
            }
            if st.is_member(target) || info.invites.contains(target) || invited.contains(target) {
                continue;
            }
            // An invitation (12.6), under the rules of INVITE (6.4).
            if !rights(info, a).can_moderate() {
                return Err(forbidden(&format!(
                    "{target} is neither a member nor invited, and only moderators invite"
                )));
            }
            if info.bans.contains(target) {
                return Err(forbidden(&format!("{target} is banned; unban first")));
            }
            invited.push(target.clone());
        }
        for removed in checked.removes.iter().filter(|r| !r.justified) {
            let leaf = &removed.leaf;
            let gone = !st.is_member(&leaf.uid) && !info.invites.contains(&leaf.uid);
            if gone || !self.key_listed(&leaf.uid, &leaf.key, false).await? {
                continue;
            }
            return Err(forbidden(&format!(
                "no reason to remove a leaf of {}",
                leaf.uid
            )));
        }
        if checked.extensions.is_some() && rights(info, a) != Role::Owner {
            return Err(forbidden("only owners change the group's extensions"));
        }
        invited.sort();
        Ok(invited)
    }

    /// Stores an accepted commit with its events and Welcome, then sends
    /// them, and replies (12.5).
    #[allow(clippy::too_many_arguments)]
    async fn store_commit(
        &self,
        st: &mut ConvState,
        uid: &Uid,
        reply: &Reply,
        from_epoch: u64,
        checked: CheckedCommit,
        commit: CommitMessage,
        welcome: Option<Welcome>,
        invited: Vec<Uid>,
    ) -> Outcome {
        let now = self.now();
        let event = |kind| NewEvent {
            t: now,
            from: uid.clone(),
            kind,
            cid: None,
        };
        let epoch = checked.group.meta.epoch;
        let mut then: Vec<NewEvent> = invited
            .iter()
            .map(|target| {
                event(EventKind::Invite {
                    uid: target.clone(),
                })
            })
            .collect();
        let mut changes = Vec::new();
        if let Some(new) = &checked.extensions {
            changes.extend(settings_changed(&checked.before, new));
        }
        then.extend(changes.iter().map(|s| event(EventKind::Set(s.clone()))));
        let welcome = welcome.map(|welcome| NewWelcome {
            welcome,
            tree: checked.tree.clone(),
            devices: checked.adds.clone(),
        });
        let to_store = GroupCommit {
            from_epoch,
            group: checked.group,
            leaves: checked.leaves,
            event: event(EventKind::Commit { epoch, commit }),
            then,
            welcome,
            removed: checked
                .removes
                .iter()
                .map(|r| (r.leaf.uid.clone(), r.leaf.key.clone()))
                .collect(),
        };
        let conv = st.key;
        let (stored_commit, to_store) = {
            let to_store = Arc::new(to_store);
            let c = to_store.clone();
            (self.db(move |s| s.commit_group(conv, &c)).await?, to_store)
        };
        let Some(done) = stored_commit else {
            return Err(stale("another commit came first"));
        };
        let commit_seq = done.seqs[0];
        st.group = Some(GroupMeta {
            epoch,
            seq: Some(commit_seq),
        });
        st.head = done.seqs.last().copied();
        if let Some(info) = st.room_info_mut() {
            info.invites.extend(invited.iter().cloned());
            for setting in &changes {
                info.settings.apply(setting);
            }
        }
        Self::broadcast_event(st, &stored(to_store.event.clone(), commit_seq));
        for (event, seq) in to_store.then.iter().zip(&done.seqs[1..]) {
            let event = stored(event.clone(), *seq);
            Self::broadcast_event(st, &event);
            if let EventKind::Invite { uid: target } = &event.kind {
                self.notify_room_event(st, &event, target);
            }
        }
        if let Some(welcome) = &to_store.welcome {
            self.send_welcomes(st, commit_seq, welcome, &done.welcome_ids);
        }
        reply.line(OkResponse::new().with_seq(commit_seq).with_epoch(epoch));
        Ok(None)
    }

    /// Sends a room's event to `target` if it is not a member, as INVITE
    /// does for its invitee (6.4).
    fn notify_room_event(&self, st: &ConvState, event: &StoredEvent, target: &Uid) {
        if st.is_member(target) {
            return;
        }
        let Some(info) = st.room_info() else {
            return;
        };
        match event.to_event(info.room.clone(), &st.id) {
            Ok(line) => {
                if let Some(user) = self.reg().users.get(target).cloned() {
                    user.send(&OutLine::new(ServerMessage::new(line)));
                }
            }
            Err(e) => tracing::error!(room = %info.room, "cannot send an event: {e}"),
        }
    }

    /// GROUPINFO (12.5).
    async fn group_info(&self, uid: &Uid, reply: &Reply, conv: Conv) -> Outcome {
        let room = match conv {
            Conv::Room(room) => room,
            // Step 5: direct conversations.
            Conv::Uid(_) => return Err(not_supported()),
        };
        let st = self.lock_room(&room).await?;
        let info = room_of(&st)?;
        if !visible(info, self.asker(uid, st.is_member(uid))) {
            return Err(not_found());
        }
        if st.group.is_none() {
            return Err(fail(ErrorCode::NotFound, "the room has no group"));
        }
        if !st.is_member(uid) && !info.invites.contains(uid) {
            return Err(forbidden("only members and invitees join the group"));
        }
        let conv_key = st.key;
        let (leaf_uids, record) = self
            .db(move |s| Ok((s.leaf_uids(conv_key)?, s.group(conv_key)?)))
            .await?;
        if !leaf_uids.contains(uid) {
            return Err(forbidden(
                "only an identity with a leaf joins by external commit",
            ));
        }
        let record = record.ok_or(StoreError::NoConversation)?;
        let (group_info, meta) = (record.group_info.clone(), record.meta);
        let tree = blocking(move || tree_of(&record)).await?;
        reply.line(ServerLine::GroupInfo {
            conv: st.name_for(uid),
            epoch: meta.epoch,
            seq: meta.seq,
            group_info,
            tree,
        });
        Ok(Some(OkResponse::new()))
    }
}

/// The SET events of an owner's GroupContextExtensions (12.5): one for
/// each of `history` and `send` that changed.
fn settings_changed(before: &RisalaConversation, after: &RisalaConversation) -> Vec<RoomSetting> {
    let mut changes = Vec::new();
    if before.history != after.history {
        changes.push(RoomSetting::History(after.history));
    }
    if before.send != after.send {
        changes.push(RoomSetting::Send(after.send));
    }
    changes
}
