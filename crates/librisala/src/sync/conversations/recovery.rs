//! Recovery paths of the group engine (7.4, 7.5, 7.8, 12.7, 12.8):
//! replacing stale leaves, `RESYNC <box> <seq>` to the identity's other
//! devices, who replaces a leaf that asked with RESYNC, the move by any
//! member after another's removal, groups the device can no longer follow
//! after posts expired unread, and the warning that the device may have
//! joined a branch of the group that nobody follows.

use risala_mls::checks::{EpochState, GroupView, own_leaves_to_replace};
use risala_mls::conversation::Role;
use risala_mls::group as mls_group;
use risala_proto::content::ContentLine;
use risala_proto::names::{Seq, Uid};

use super::{
    ConversationEngine, Ctx, EngineError, Intent, Job, Me, Pending, Target, content, group,
};
use crate::client::Event;
use crate::client::conversations::ConversationEvent;
use crate::store::Tx;
use crate::store::conversations::{ConvKind, ConvRow, ConvState, ConversationId};
use crate::store::messages::{OutboxKind, OutboxState};
use crate::sync::{Action, Context};
use risala_proto::command::{Command, KeyPkgCommand};

/// A day, in ms.
const DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// Whether this device may add devices of `uid` back to `row`'s group by
/// itself (6.1, 12.7): not while it is leaving the group, not while a leaf
/// of `uid` has posted a SelfRemove that no commit has applied, and not
/// once `uid` has left.
pub(crate) fn may_add_back(tx: &Tx<'_>, row: &ConvRow, uid: &Uid) -> Result<bool, EngineError> {
    if group::leaving(tx, row.id)? || tx.departed(row.id, uid)? {
        return Ok(false);
    }
    let leaves = crate::store::conversations::read::leaves(tx.conn(), row.id)?;
    Ok(!leaves.iter().any(|l| l.uid == *uid && l.self_removed))
}

/// Whether this device may remove a leaf of `uid` in `row`'s group and add
/// its device again (12.7): always for its own identity and in a direct
/// conversation; in a private room, an owner's leaf only by an owner, a
/// moderator's by an owner or moderator, and a plain member's by anyone
/// while that identity keeps another leaf, otherwise (an invitation) by an
/// owner or moderator. Never where [`may_add_back`] says no.
pub(crate) fn may_replace(
    tx: &Tx<'_>,
    cx: &Ctx<'_>,
    row: &ConvRow,
    uid: &Uid,
) -> Result<bool, EngineError> {
    if !may_add_back(tx, row, uid)? {
        return Ok(false);
    }
    if uid == cx.uid {
        return Ok(true);
    }
    match row.kind {
        ConvKind::Direct => return Ok(true),
        ConvKind::WithYourself | ConvKind::Public => return Ok(false),
        ConvKind::Private => {}
    }
    let group = group::load(tx, cx, &row.group_id)?;
    let view = GroupView::of(group.public_group(), &EpochState::default());
    let Ok(ext) = &view.conversation else {
        return Ok(false);
    };
    let own = view.effective_role(cx.uid);
    Ok(match ext.role(uid) {
        Role::Owner => own == Role::Owner,
        Role::Mod => own >= Role::Mod,
        Role::Member => own >= Role::Mod || view.leaves_of(uid).count() > 1,
    })
}

/// Marks `conv` as a group the device can no longer follow (7.4, 7.5):
/// posts after its sync point expired before it applied them, and it
/// cannot tell whether they held commits. Its commits made for the epoch
/// it holds are dropped, and their intents queued again for when it is
/// back (7.2). Its group, of no more use, is forgotten with its leaf key,
/// as when it is removed. Until it is back it applies and posts nothing
/// there, and follows none of its mailboxes: in a public room it joins
/// again (6.1); in other conversations its leaf is replaced, by its
/// identity's other devices once the leaf is stale and by other members'
/// after 35 days, and a Welcome brings it back, as for a new device
/// (7.5, 12.7).
pub(super) fn cannot_follow(
    tx: &mut Tx<'_>,
    cx: &Ctx<'_>,
    conv: ConversationId,
) -> Result<(), EngineError> {
    let row = tx.conversation(conv)?;
    for o in tx.pending_outbox(conv)? {
        if o.kind == OutboxKind::Commit
            && o.post.is_some()
            && !matches!(o.state, OutboxState::Lost | OutboxState::Done)
        {
            group::commit_lost(tx, cx, &row, &o)?;
        }
    }
    if let Ok(mut old) = group::load(tx, cx, &row.group_id) {
        mls_group::forget_group(&tx.mls(cx.crypto), &mut old)
            .map_err(|e| EngineError::Mls(e.to_string()))?;
    }
    tx.set_state(conv, ConvState::Lost)?;
    tracing::info!(%conv, "posts expired unread: the device can no longer follow the group");
    Ok(())
}

impl ConversationEngine {
    /// After [`cannot_follow`]: tells the user, and in a public room joins
    /// again by proposal, after a random wait (6.1). It goes the way of a
    /// room it cannot follow (12.7), but never makes a resync commit: the
    /// commits it missed may have been valid.
    pub(super) fn lost(
        &mut self,
        cx: &Context,
        me: &Me,
        conv: ConversationId,
        out: &mut Vec<Action>,
    ) {
        self.move_timers.remove(&conv);
        self.proposal_timers.remove(&conv);
        self.unprocessable.remove(&conv);
        self.resync_since.remove(&conv);
        out.push(Action::Emit(Event::Conversation(
            ConversationEvent::CannotFollow { conversation: conv },
        )));
        let row = self.write(cx, me, out, |tx, _| Ok(tx.conversation(conv)?));
        if let Ok(row) = row
            && row.kind == ConvKind::Public
            && !self.stuck.contains_key(&conv)
        {
            let wait = super::random_below(self.config.max_commit_wait_ms).unwrap_or(0);
            self.stuck.insert(conv, (row.epoch, self.now() + wait));
        }
    }

    /// After a Welcome into `conv`: a mailbox the device already follows
    /// and has caught up in needs no first catch-up, so posts that expire
    /// unread there count from now on (7.4, 12.8).
    pub(super) fn welcomed(
        &mut self,
        cx: &Context,
        me: &Me,
        conv: ConversationId,
        out: &mut Vec<Action>,
    ) -> Result<(), EngineError> {
        let Some(mb) = self.write(cx, me, out, |tx, _| Ok(tx.current_mailbox(conv).ok()))? else {
            return Ok(());
        };
        if mb.head.is_none() && self.caught_up(&mb.mailbox) {
            self.joined_heads.remove(&mb.mailbox);
            self.write(cx, me, out, |tx, _| {
                tx.set_sync(conv, &mb.mailbox, mb.sync_point, Some(mb.sync_point))?;
                Ok(())
            })?;
        }
        Ok(())
    }

    /// 12.8: a day after joining by Welcome, a device that has seen no post
    /// in its epoch from any other leaf, while posts arrive that it cannot
    /// decrypt, tells the user that it may have joined a branch nobody
    /// follows, and uploads fresh KeyPackages to be added again.
    pub(super) fn check_branch(
        &mut self,
        cx: &Context,
        me: &Me,
        conv: ConversationId,
        out: &mut Vec<Action>,
    ) {
        if self.branch_warned.contains(&conv) {
            return;
        }
        let now = self.now();
        let lone = self
            .write(cx, me, out, |tx, _| {
                let state = tx.public_state(conv)?;
                Ok(state
                    .joined_at
                    .is_some_and(|j| now >= j + DAY_MS && !state.branch_seen))
            })
            .unwrap_or(false);
        if !lone {
            return;
        }
        self.branch_warned.insert(conv);
        out.push(Action::Emit(Event::Conversation(
            ConversationEvent::MaybeOtherBranch { conversation: conv },
        )));
        if me.guest || self.device_key(me).is_none() {
            return;
        }
        let n = self.config.key_packages as usize;
        let made = self.write(cx, me, out, |tx, c| {
            group::make_key_packages(tx, c, n, false)
        });
        match made {
            Ok(made) => {
                for bytes in made {
                    if let Ok(key_package) = risala_proto::mls::KeyPackage::from_bytes(&bytes) {
                        self.send(
                            out,
                            Target::SignedIn,
                            Command::KeyPkg(KeyPkgCommand::Add { key_package }),
                            Pending::KeyPkgAdd,
                        );
                    }
                }
            }
            Err(e) => tracing::warn!(error = %e, "could not make fresh KeyPackages"),
        }
    }

    /// The recovery timers, run with the engine's others.
    pub(super) fn recovery_due(
        &mut self,
        cx: &Context,
        me: &Me,
        now: u64,
        out: &mut Vec<Action>,
    ) -> Result<(), EngineError> {
        // 7.8: the move by any member, if none has won since the removal.
        let due: Vec<(ConversationId, risala_proto::names::BoxName)> = self
            .move_timers
            .iter()
            .filter(|(_, (at, _))| *at <= now)
            .map(|(c, (_, b))| (*c, *b))
            .collect();
        for (conv, mailbox) in due {
            self.move_timers.remove(&conv);
            self.write(cx, me, out, |tx, c| {
                let row = tx.conversation(conv)?;
                let moved = tx.current_mailbox(conv)?.mailbox != mailbox;
                let queued = tx.pending_outbox(conv)?.iter().any(|o| {
                    o.kind == crate::store::messages::OutboxKind::Commit && o.move_box.is_some()
                });
                if row.state == ConvState::Active
                    && row.kind != ConvKind::Public
                    && !moved
                    && !queued
                {
                    group::queue_intent(
                        tx,
                        conv,
                        &Intent {
                            move_box: true,
                            ..Intent::default()
                        },
                        c.now,
                    )?;
                }
                Ok(())
            })?;
        }

        // 12.7: a RESYNC nobody acted on within an hour goes to the own
        // devices, as `RESYNC <box> <seq>` in the conversation with
        // yourself.
        let due: Vec<(ConversationId, u64)> = self
            .resync_since
            .iter()
            .filter(|(_, (at, _))| now >= at + self.config.resync_escalate_ms)
            .map(|(c, (_, seq))| (*c, *seq))
            .collect();
        for (conv, seq) in due {
            self.resync_since.remove(&conv);
            let r = self.write(cx, me, out, |tx, c| {
                let mailbox = tx.current_mailbox(conv)?.mailbox;
                let Some(own) = tx
                    .conversations_of(c.account)?
                    .into_iter()
                    .find(|r| r.kind == ConvKind::WithYourself && r.state.in_group())
                else {
                    return Ok(());
                };
                let seq = Seq::new(seq).ok_or(EngineError::Invalid("seq".into()))?;
                content::queue_lines(
                    tx,
                    own.id,
                    c.uid,
                    vec![ContentLine::Resync {
                        mailbox: Some(mailbox),
                        seq,
                    }],
                    false,
                    c.now,
                )?;
                Ok(())
            });
            if let Err(e) = r {
                tracing::warn!(error = %e, "could not ask the own devices to resync");
            }
        }
        Ok(())
    }

    /// 12.7, checked with the weekly fresh-leaf commit: outside public
    /// rooms, the own identity's other leaves whose activity time is older
    /// than retention plus a day are replaced, and stale leaves of others
    /// that this device may add again, within the bulk limit.
    pub(super) fn replace_stale(
        &mut self,
        cx: &Context,
        me: &Me,
        now: u64,
        out: &mut Vec<Action>,
    ) -> Result<(), EngineError> {
        if me.guest {
            return Ok(());
        }
        let retention = self.config.retention_ms;
        let replacing = self.replacing.clone();
        let jobs = self.write(cx, me, out, |tx, c| {
            let mut jobs = Vec::new();
            for row in tx.conversations_of(c.account)? {
                // 6.1: a device that is leaving puts no device back.
                if row.state != ConvState::Active
                    || row.kind == ConvKind::Public
                    || group::leaving(tx, row.id)?
                {
                    continue;
                }
                let Ok(group) = group::load(tx, c, &row.group_id) else {
                    continue;
                };
                let state = tx.group_history(row.id)?;
                let view = mls_group::view(&group, &state, c.crypto.as_ref());
                let own = group.own_leaf_index();
                let mut leaves: Vec<(u32, Uid, [u8; 48])> = Vec::new();
                for index in own_leaves_to_replace(&view, c.uid, own, retention, now) {
                    if let Some(l) = view.leaf(index)
                        && let Some(id) = &l.identity
                        && let Some(device) = id.device_id
                    {
                        leaves.push((index.u32(), id.uid.clone(), *device.as_bytes()));
                    }
                }
                let limit = view.bulk_limit();
                let mut others = 0;
                for index in view.stale_leaves(now) {
                    if others >= limit || index == own {
                        continue;
                    }
                    let Some(l) = view.leaf(index) else { continue };
                    let Some(id) = &l.identity else { continue };
                    let Some(device) = id.device_id else { continue };
                    if leaves.iter().any(|(i, ..)| *i == index.u32())
                        || !may_replace(tx, c, &row, &id.uid)?
                    {
                        continue;
                    }
                    if id.uid != *c.uid {
                        others += 1;
                    }
                    leaves.push((index.u32(), id.uid.clone(), *device.as_bytes()));
                }
                leaves.retain(|(i, ..)| !replacing.contains(&(row.id, *i)));
                if !leaves.is_empty() {
                    jobs.push((row.id, leaves));
                }
            }
            Ok(jobs)
        })?;
        for (conv, leaves) in jobs {
            for (i, ..) in &leaves {
                self.replacing.insert((conv, *i));
            }
            let (_, actions) = self.start(
                cx,
                Job::ReplaceAll {
                    conv,
                    leaves: leaves.into_iter().map(|(_, u, d)| (u, d)).collect(),
                },
            );
            out.extend(actions);
        }
        Ok(())
    }

    /// Whether this device replaces a leaf that asked with RESYNC (12.7):
    /// a device of the same identity; if that identity has no other leaf,
    /// the other participant's in a direct conversation, and an owner's or
    /// moderator's in a room as far as the checks let it. Others warn.
    pub(super) fn answers_resync(
        &mut self,
        cx: &Context,
        me: &Me,
        conv: ConversationId,
        uid: &Uid,
        out: &mut Vec<Action>,
    ) -> bool {
        self.write(cx, me, out, |tx, c| {
            let row = tx.conversation(conv)?;
            if !row.state.in_group() || !may_add_back(tx, &row, uid)? {
                return Ok(false);
            }
            if uid == c.uid {
                return Ok(true);
            }
            let leaves = crate::store::conversations::read::leaves(tx.conn(), conv)?;
            if leaves.iter().filter(|l| l.uid == *uid).count() > 1 {
                return Ok(false);
            }
            match row.kind {
                ConvKind::Direct => Ok(true),
                ConvKind::Private => {
                    let group = group::load(tx, c, &row.group_id)?;
                    let view = GroupView::of(group.public_group(), &EpochState::default());
                    Ok(view.effective_role(c.uid) >= Role::Mod && may_replace(tx, c, &row, uid)?)
                }
                ConvKind::WithYourself | ConvKind::Public => Ok(false),
            }
        })
        .unwrap_or(false)
    }
}
