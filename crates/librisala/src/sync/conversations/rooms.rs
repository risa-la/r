//! The engine's side of public rooms (6.1, 12.6-12.8): creating them,
//! joining by proposal, checking each commit for the join's leaf,
//! fetching the Welcome, GONE, and resyncing a room the device cannot
//! follow. The transactions are [`super::public`]'s.
//!
//! Which connection each command goes on (4.1, 12.6): a join proposal
//! names the identity, so an identity's device posts it, and fetches its
//! Welcome, on a connection of its own; a guest has one connection for
//! everything. Commits, external commits and Updates of an identity's leaf
//! go on the signed-in connection of the device the credential names.

use risala_mls::checks::External;
use risala_mls::conversation::RisalaConversation;
use risala_proto::command::{Command, CreateForm, PublicRoom as PublicRoomForm, WelcomeCommand};
use risala_proto::error::ErrorCode;
use risala_proto::mls::{
    GroupId, GroupInfo as GroupInfoText, KeyPackageRef as RefText, MlsMessage, OrBlob, PostToken,
    RatchetTree as TreeText, TokenHash,
};
use risala_proto::names::{BlobRef, BoxName, Room, Uid};
use risala_proto::server::ServerLine;

use super::public::{self, JoinStep, RoomState, StartJoin};
use super::{
    BlobFetch, ConversationEngine, EngineError, Intent, JobId, Me, Pending, RoomPurpose, Target,
    group, job_done, random_below,
};
use crate::client::Event;
use crate::client::conversations::ConversationEvent;
use crate::conn::{End, Response, SingleUse};
use crate::store::conversations::{ConvKind, ConvState, ConversationId};
use crate::store::messages::OutboxState;
use crate::sync::{Action, Context};

/// What a blob-ref or an inline value comes to (12.12).
pub(crate) enum Got {
    Bytes(Vec<u8>),
    Waiting,
    Unavailable,
}

impl ConversationEngine {
    /// The bytes of an inline value or a blob (12.12), from
    /// [`super::Hooks::blob`], whose hash is checked here.
    pub(super) fn get_blob(&self, me: &Me, blob: &BlobRef) -> Got {
        if !self.info_answered {
            // INFO is asked on the next step, or in flight: wait for it.
            self.need_info
                .store(true, std::sync::atomic::Ordering::Relaxed);
            return Got::Waiting;
        }
        match self
            .hooks
            .blob(me.account, self.blob_prefix.as_deref(), blob)
        {
            BlobFetch::Ready(bytes) => {
                if BlobRef::of(&bytes) == *blob {
                    Got::Bytes(bytes)
                } else {
                    tracing::warn!(%blob, "a blob whose hash is wrong");
                    Got::Unavailable
                }
            }
            BlobFetch::Waiting => Got::Waiting,
            BlobFetch::Unavailable => Got::Unavailable,
        }
    }

    pub(super) fn resolve<T>(
        &self,
        me: &Me,
        value: &OrBlob<T>,
        decode: impl Fn(&T) -> Vec<u8>,
    ) -> Got {
        match value {
            OrBlob::Inline(v) => Got::Bytes(decode(v)),
            OrBlob::Blob(blob) => self.get_blob(me, blob),
        }
    }

    /// The connection a join's proposal and Welcome go on (4.1, 12.8).
    fn join_target(me: &Me) -> Target {
        if me.guest {
            Target::Conversing
        } else {
            Target::Own(SingleUse::Anonymous)
        }
    }

    /// The connection a public room's GROUPINFO goes on: the one that
    /// follows it, if any.
    fn room_target(&self, me: &Me, mailbox: &BoxName) -> Target {
        if me.guest || !self.follows.contains_key(mailbox) {
            Target::Conversing
        } else {
            Target::Mailbox(*mailbox)
        }
    }

    // -----------------------------------------------------------------
    // Creating

    /// Creates a public room (6.1, 12.6): its group, with this device the
    /// only member, and its mailbox with the second form of CREATE on the
    /// signed-in connection, which carries the GroupInfo and the tree of
    /// epoch 0.
    pub(super) fn create_public(
        &mut self,
        cx: &Context,
        me: &Me,
        id: JobId,
        room: Room,
        out: &mut Vec<Action>,
    ) -> Result<(), EngineError> {
        let made = self.write(cx, me, out, |tx, c| {
            if let Some(existing) = tx.conversations_of(c.account)?.into_iter().find(|r| {
                r.kind == ConvKind::Public
                    && r.room.as_deref() == Some(room.as_str())
                    && r.state.in_group()
            }) {
                return Ok(Err(existing.id));
            }
            let made = group::create(
                tx,
                c,
                |b| RisalaConversation::public_room(c.host.clone(), b, &room, c.uid),
                Vec::new(),
            )?;
            let (info, tree) = group::public_create_info(tx, c, &made.group_id)?;
            Ok(Ok((made, info, tree)))
        })?;
        let (made, info, tree) = match made {
            Err(conv) => {
                out.push(job_done(id, Some(conv), None));
                return Ok(());
            }
            Ok(made) => made,
        };
        // 12.12: a new room's GroupInfo and tree hold one leaf, and fit a
        // line. Its mailbox does not exist yet, so no blob could be stored
        // with its box and a send token (12.12) anyway: one too long fails.
        if super::blobs::as_blobs(&[info.len(), tree.len()], self.config.line_limit).contains(&true)
        {
            self.write(cx, me, out, |tx, _| {
                tx.set_state(made.conv, ConvState::Failed)?;
                Ok(())
            })?;
            out.push(job_done(
                id,
                None,
                Some("CREATE: the room's GroupInfo and tree do not fit a line".into()),
            ));
            return Ok(());
        }
        let groupinfo =
            GroupInfoText::from_bytes(&info).map_err(|e| EngineError::Invalid(e.to_string()))?;
        let tree = TreeText::from_bytes(&tree).map_err(|e| EngineError::Invalid(e.to_string()))?;
        self.send(
            out,
            Target::SignedIn,
            Command::Create {
                mailbox: made.mailbox,
                group_id: GroupId::from_bytes(made.group_id),
                token_hash: TokenHash::from_bytes(made.token_hash),
                form: CreateForm::Public(PublicRoomForm {
                    room,
                    groupinfo: OrBlob::Inline(groupinfo),
                    tree: OrBlob::Inline(tree),
                }),
            },
            Pending::Create {
                job: Some(id),
                conv: made.conv,
            },
        );
        Ok(())
    }

    // -----------------------------------------------------------------
    // Joining

    /// INFO answered: ask for the room's GroupInfo.
    pub(super) fn on_room_info(
        &mut self,
        job: JobId,
        room: Room,
        new_group: bool,
        response: &Response,
        out: &mut Vec<Action>,
    ) {
        let mailbox = match &response.end {
            End::Ok(ok) => ok.mailbox().ok().flatten(),
            _ => None,
        };
        let Some(mailbox) = mailbox else {
            tracing::info!(end = ?response.end, %room, "INFO of a room");
            out.push(job_done(
                job,
                None,
                Some(format!("{room} is not a public room here")),
            ));
            return;
        };
        self.send(
            out,
            Target::Conversing,
            Command::GroupInfo { mailbox },
            Pending::GroupInfo {
                purpose: RoomPurpose::Join {
                    job,
                    room,
                    new_group,
                },
            },
        );
    }

    /// The room in a GROUPINFO answer, its blobs fetched: `Ok(Err(box))`
    /// while a blob is being fetched.
    fn room_state(
        &self,
        me: &Me,
        response: &Response,
    ) -> Result<Result<RoomState, BoxName>, String> {
        if let End::Err(e) = &response.end {
            return Err(format!("GROUPINFO: {}", e.code));
        }
        for line in &response.lines {
            if let ServerLine::GroupInfo {
                mailbox,
                epoch,
                seq,
                groupinfo,
                tree,
            } = &line.line
            {
                let info = self.resolve(me, groupinfo, |g| g.decode());
                let tree = self.resolve(me, tree, |t| t.decode());
                return match (info, tree) {
                    (Got::Bytes(group_info), Got::Bytes(tree)) => Ok(Ok(RoomState {
                        mailbox: *mailbox,
                        epoch: *epoch,
                        seq: seq.map_or(0, |s| s.get()),
                        group_info,
                        tree,
                    })),
                    (Got::Unavailable, _) | (_, Got::Unavailable) => {
                        Err("the room's tree is a blob, and there is no blob store".into())
                    }
                    _ => Ok(Err(*mailbox)),
                };
            }
        }
        Err("no GROUPINFO line".into())
    }

    /// A GROUPINFO answer, for one of [`RoomPurpose`].
    pub(super) fn on_group_info(
        &mut self,
        cx: &Context,
        purpose: RoomPurpose,
        response: &Response,
        out: &mut Vec<Action>,
    ) -> Result<(), EngineError> {
        let me = self.me(cx)?;
        let state = match self.room_state(&me, response) {
            // 12.12: asked again once the blob is in, on a later tick.
            Ok(Err(mailbox)) => {
                if let RoomPurpose::Check { conv } = &purpose {
                    self.join_inflight.remove(conv);
                }
                self.groupinfo_waits.push((purpose, mailbox));
                return Ok(());
            }
            Ok(Ok(state)) => Ok(Some(state)),
            Err(e) => Err(e),
        };
        tracing::debug!(?purpose, epoch = ?state.as_ref().ok().and_then(|s| s.as_ref()).map(|s| s.epoch), "GROUPINFO");
        match purpose {
            RoomPurpose::Join {
                job,
                room,
                new_group,
            } => {
                let state = match state {
                    Ok(Some(state)) => state,
                    Ok(None) => {
                        out.push(job_done(
                            job,
                            None,
                            Some("the room's blobs are not in".into()),
                        ));
                        return Ok(());
                    }
                    Err(e) => {
                        out.push(job_done(job, None, Some(e)));
                        return Ok(());
                    }
                };
                let started = self.write(cx, &me, out, |tx, c| {
                    public::start_join(tx, c, room.as_str(), &state, None, new_group)
                });
                match started {
                    Ok(StartJoin::AlreadyIn(conv)) => out.push(job_done(job, Some(conv), None)),
                    Ok(StartJoin::Proposal(started)) => {
                        self.join_jobs.insert(started.conv, job);
                        self.post_join(&me, started.conv, &state.mailbox, &started.proposal, out)?;
                    }
                    Err(e) => {
                        self.room_error(&e, out);
                        out.push(job_done(job, None, Some(e.to_string())));
                    }
                }
            }
            RoomPurpose::Check { conv } => {
                self.join_inflight.remove(&conv);
                let Ok(Some(state)) = state else {
                    return Ok(());
                };
                let step = self.write(cx, &me, out, |tx, c| match tx.join_of(conv)? {
                    Some(join) => public::check_join(tx, c, &join, &state).map(Some),
                    None => Ok(None),
                });
                tracing::debug!(?step, "a join checked");
                match step {
                    Ok(Some(JoinStep::Wait)) | Ok(None) => {}
                    Ok(Some(JoinStep::Fetch(reference))) => {
                        let Ok(reference) = <[u8; 48]>::try_from(reference.as_slice()) else {
                            return Ok(());
                        };
                        self.join_inflight.insert(conv);
                        self.send(
                            out,
                            Self::join_target(&me),
                            Command::Welcome(WelcomeCommand::Get {
                                key_package_ref: RefText::from_bytes(reference),
                                light: false,
                            }),
                            Pending::WelcomeGet { conv },
                        );
                    }
                    Ok(Some(JoinStep::Propose(proposal))) => {
                        self.post_join(&me, conv, &state.mailbox, &proposal, out)?;
                    }
                    Ok(Some(JoinStep::Rejoin)) => {
                        let r = self.write(cx, &me, out, |tx, c| {
                            let (room, _) = public::room_of(tx, conv)?;
                            public::external_join(tx, c, conv, &room, &state, External::Rejoin)
                        });
                        if let Err(e) = r {
                            self.room_error(&e, out);
                            tracing::warn!(error = %e, "could not rejoin a public room");
                        }
                    }
                    Err(e) => {
                        self.room_error(&e, out);
                        tracing::warn!(error = %e, "a join could not be checked");
                    }
                }
            }
            RoomPurpose::Stuck { conv, epoch } => {
                let Ok(Some(state)) = state else {
                    // Try again later.
                    let wait = random_below(self.config.max_commit_wait_ms).unwrap_or(0);
                    self.stuck
                        .insert(conv, (epoch, self.now() + wait.max(60_000)));
                    return Ok(());
                };
                self.stuck.remove(&conv);
                // 6.1: the user left it meanwhile.
                if self.write(cx, &me, out, |tx, c| {
                    group::left_for_good(tx, &tx.conversation(conv)?, c.uid)
                })? {
                    return Ok(());
                }
                // 12.7: a full client of an identity resyncs a room whose
                // bad commit is still the newest; otherwise someone has, or
                // the device is a guest's, and it joins again by proposal.
                let resync = !me.guest && state.epoch == epoch + 1;
                let r = self.write(cx, &me, out, |tx, c| {
                    let (room, _) = public::room_of(tx, conv)?;
                    // 7.5: a room lost to posts that expired unread is
                    // joined again by proposal: the commits it missed may
                    // have been valid, and a resync commit would undo one.
                    let lost = tx.conversation(conv)?.state == ConvState::Lost;
                    if resync && !lost {
                        public::external_join(tx, c, conv, &room, &state, External::Resync)?;
                        Ok(None)
                    } else {
                        match public::start_join(tx, c, &room, &state, Some(conv), false)? {
                            StartJoin::Proposal(started) => Ok(Some(started.proposal)),
                            StartJoin::AlreadyIn(_) => Ok(None),
                        }
                    }
                });
                match r {
                    Ok(Some(proposal)) => {
                        self.post_join(&me, conv, &state.mailbox, &proposal, out)?
                    }
                    Ok(None) => {}
                    Err(e) => {
                        // 12.7: a room it lost (7.5) that the server changed
                        // waits for the user, who may accept the change and
                        // join again, rather than asking again.
                        let lost = self
                            .write(cx, &me, out, |tx, _| Ok(tx.conversation(conv)?.state))
                            .is_ok_and(|s| s == ConvState::Lost);
                        if lost && matches!(e, EngineError::RoomChanged { .. }) {
                            self.stuck.insert(conv, (epoch, u64::MAX));
                        }
                        self.room_error(&e, out);
                        tracing::warn!(error = %e, "could not resync a public room");
                    }
                }
            }
        }
        Ok(())
    }

    /// Tells the user that the server changed a room (12.7).
    fn room_error(&self, e: &EngineError, out: &mut Vec<Action>) {
        if let EngineError::RoomChanged { conv, fields } = e {
            out.push(Action::Emit(Event::Conversation(
                ConversationEvent::RoomChanged {
                    conversation: *conv,
                    fields: fields.clone(),
                },
            )));
        }
    }

    /// Posts a join proposal, with the token `-` (6.1).
    fn post_join(
        &mut self,
        me: &Me,
        conv: ConversationId,
        mailbox: &BoxName,
        proposal: &[u8],
        out: &mut Vec<Action>,
    ) -> Result<(), EngineError> {
        let message =
            MlsMessage::from_bytes(proposal).map_err(|e| EngineError::Invalid(e.to_string()))?;
        self.send(
            out,
            Self::join_target(me),
            Command::Post {
                mailbox: *mailbox,
                token: PostToken::Join,
                message: OrBlob::Inline(message),
                live: false,
                groupinfo: None,
                next: None,
                cid: None,
            },
            Pending::JoinPost { conv },
        );
        Ok(())
    }

    /// The answer to a join proposal.
    pub(super) fn on_join_post(
        &mut self,
        conv: ConversationId,
        response: &Response,
        out: &mut Vec<Action>,
    ) {
        let now = self.now();
        tracing::debug!(end = ?response.end, "a join proposal posted");
        match &response.end {
            End::Ok(_) => {
                self.join_checks
                    .insert(conv, now + self.config.join_poll_ms);
            }
            End::Err(e) if e.code == ErrorCode::Stale => {
                // A commit came first: look again at once.
                self.join_checks.insert(conv, now);
            }
            End::Err(e) => {
                if let Some(job) = self.join_jobs.remove(&conv) {
                    out.push(job_done(job, None, Some(format!("join: {}", e.code))));
                }
                self.join_checks
                    .insert(conv, now + self.config.join_poll_ms);
            }
            End::Unparseable(_) => {
                self.join_checks
                    .insert(conv, now + self.config.retry_ms.max(1_000));
            }
        }
    }

    /// WELCOME GET answered: join by the Welcome, with its tree (12.8).
    pub(super) fn on_welcome_get(
        &mut self,
        cx: &Context,
        conv: ConversationId,
        response: &Response,
        out: &mut Vec<Action>,
    ) -> Result<(), EngineError> {
        self.join_inflight.remove(&conv);
        let me = self.me(cx)?;
        tracing::debug!(end = ?response.end, lines = ?response.lines.iter().map(|l| l.line.verb()).collect::<Vec<_>>(), "WELCOME GET");
        let found = response.lines.iter().find_map(|l| match &l.line {
            ServerLine::Welcome {
                welcome,
                tree: Some(tree),
                ..
            } => Some((welcome.clone(), tree.clone())),
            _ => None,
        });
        let Some((welcome, tree)) = found else {
            tracing::debug!("no Welcome with a tree yet");
            // Not there yet: look again after the next commit or poll.
            self.join_checks
                .insert(conv, self.now() + self.config.join_poll_ms);
            return Ok(());
        };
        self.public_welcome(cx, &me, conv, welcome, tree, out)
    }

    /// Joins by a public room's Welcome and the tree of its epoch, once
    /// their blobs are in (12.8, 12.12).
    fn public_welcome(
        &mut self,
        cx: &Context,
        me: &Me,
        conv: ConversationId,
        welcome: OrBlob<risala_proto::mls::Welcome>,
        tree: OrBlob<TreeText>,
        out: &mut Vec<Action>,
    ) -> Result<(), EngineError> {
        let me = me.clone();
        let (got_welcome, got_tree) = (
            self.resolve(&me, &welcome, |w| w.decode()),
            self.resolve(&me, &tree, |t| t.decode()),
        );
        let (welcome, tree) = match (got_welcome, got_tree) {
            (Got::Bytes(w), Got::Bytes(t)) => (w, t),
            (Got::Unavailable, _) | (_, Got::Unavailable) => {
                tracing::info!("a public room's Welcome or tree is a blob, and no blob store");
                self.join_checks
                    .insert(conv, self.now() + self.config.join_poll_ms);
                return Ok(());
            }
            _ => {
                // Asked again on a later tick.
                self.welcome_waits.insert(conv, (welcome, tree));
                return Ok(());
            }
        };
        let joined = self.write(cx, &me, out, |tx, c| {
            let Some(join) = tx.join_of(conv)? else {
                return Ok(None);
            };
            let conv = public::join_by_welcome(tx, c, &join, &welcome, &tree)?;
            let mb = tx.current_mailbox(conv)?;
            Ok(Some((conv, mb)))
        });
        match joined {
            Ok(Some((conv, mb))) => {
                self.join_checks.remove(&conv);
                out.push(Action::Emit(Event::Conversation(
                    ConversationEvent::Joined { conversation: conv },
                )));
                if let Some(job) = self.join_jobs.remove(&conv) {
                    out.push(job_done(job, Some(conv), None));
                }
                let actions = self.write(cx, &me, out, |tx, _| {
                    Ok(self.hooks.leaves_changed(tx, conv))
                })?;
                out.extend(actions);
                // Fetch again from the commit that started the Welcome's
                // epoch.
                if self.follows.contains_key(&mb.mailbox) {
                    self.fetch(&mb.mailbox, mb.sync_point, out);
                }
            }
            Ok(None) => {}
            Err(e) => {
                self.room_error(&e, out);
                tracing::warn!(error = %e, "a public room's Welcome could not be joined");
                self.join_checks
                    .insert(conv, self.now() + self.config.join_poll_ms);
            }
        }
        Ok(())
    }

    /// Looks at the GroupInfo of joining rooms whose time has come, and
    /// resyncs rooms this device cannot follow (6.1, 12.7).
    pub(super) fn rooms_due(
        &mut self,
        cx: &Context,
        me: &Me,
        now: u64,
        out: &mut Vec<Action>,
    ) -> Result<(), EngineError> {
        // 12.12: Welcomes and GroupInfos whose blobs were being fetched.
        let waits: Vec<_> = self.welcome_waits.drain().collect();
        for (conv, (welcome, tree)) in waits {
            self.public_welcome(cx, me, conv, welcome, tree, out)?;
        }
        let waits: Vec<_> = std::mem::take(&mut self.groupinfo_waits);
        for (purpose, mailbox) in waits {
            if let RoomPurpose::Check { conv } = &purpose {
                self.join_inflight.insert(*conv);
            }
            let target = self.room_target(me, &mailbox);
            self.send(
                out,
                target,
                Command::GroupInfo { mailbox },
                Pending::GroupInfo { purpose },
            );
        }
        let joins = self.write(cx, me, out, |tx, c| Ok(tx.joins(c.account)?))?;
        // 6.1: a join the user gave up by leaving the room ends its job.
        let given_up: Vec<ConversationId> = self
            .join_jobs
            .keys()
            .filter(|conv| !joins.iter().any(|j| j.conv == **conv))
            .copied()
            .collect();
        for conv in given_up {
            let left = self.write(cx, me, out, |tx, _| {
                Ok(tx.conversation(conv)?.state == ConvState::Left)
            })?;
            if left && let Some(job) = self.join_jobs.remove(&conv) {
                self.join_checks.remove(&conv);
                out.push(job_done(job, None, Some("left while joining".into())));
            }
        }
        for join in joins {
            if self.join_inflight.contains(&join.conv) {
                continue;
            }
            let due = self.join_checks.get(&join.conv).copied().unwrap_or(0);
            if due > now {
                continue;
            }
            self.join_checks
                .insert(join.conv, now + self.config.join_poll_ms);
            self.join_inflight.insert(join.conv);
            let target = self.room_target(me, &join.mailbox);
            self.send(
                out,
                target,
                Command::GroupInfo {
                    mailbox: join.mailbox,
                },
                Pending::GroupInfo {
                    purpose: RoomPurpose::Check { conv: join.conv },
                },
            );
        }
        // 6.1, 7.5: a public room this device can no longer follow is
        // joined again, also after the engine started again.
        let lost: Vec<(ConversationId, u64)> = self.write(cx, me, out, |tx, c| {
            Ok(tx
                .conversations_of(c.account)?
                .into_iter()
                .filter(|r| r.kind == ConvKind::Public && r.state == ConvState::Lost)
                .map(|r| (r.id, r.epoch))
                .collect())
        })?;
        for (conv, epoch) in lost {
            if !self.stuck.contains_key(&conv) {
                let wait = random_below(self.config.max_commit_wait_ms).unwrap_or(0);
                self.stuck.insert(conv, (epoch, now + wait));
            }
        }
        let due: Vec<(ConversationId, u64)> = self
            .stuck
            .iter()
            .filter(|(_, (_, at))| *at <= now)
            .map(|(c, (e, _))| (*c, *e))
            .collect();
        for (conv, epoch) in due {
            // 6.1: a room the user left while the device could not follow
            // it is not joined again.
            if self.write(cx, me, out, |tx, c| {
                group::left_for_good(tx, &tx.conversation(conv)?, c.uid)
            })? {
                self.stuck.remove(&conv);
                continue;
            }
            self.stuck.insert(conv, (epoch, u64::MAX));
            let mailbox = self.write(cx, me, out, |tx, _| Ok(tx.current_mailbox(conv).ok()))?;
            let Some(mb) = mailbox else { continue };
            let target = self.room_target(me, &mb.mailbox);
            self.send(
                out,
                target,
                Command::GroupInfo {
                    mailbox: mb.mailbox,
                },
                Pending::GroupInfo {
                    purpose: RoomPurpose::Stuck { conv, epoch },
                },
            );
        }
        Ok(())
    }

    /// A public room the device cannot follow from `epoch` (12.7): tell the
    /// user that the server took an invalid commit, and after a random wait
    /// resync or join again.
    pub(super) fn on_stuck(&mut self, conv: ConversationId, epoch: u64, out: &mut Vec<Action>) {
        if self.stuck.contains_key(&conv) {
            return;
        }
        let wait = random_below(self.config.max_commit_wait_ms).unwrap_or(0);
        self.stuck.insert(conv, (epoch, self.now() + wait));
        out.push(Action::Emit(Event::Conversation(
            ConversationEvent::InvalidCommitAccepted { conversation: conv },
        )));
    }

    /// Joins a public room again that the device could not follow, after
    /// the user accepted the server's change (12.7), or at once.
    pub(crate) fn rejoin(&mut self, cx: &Context, conv: ConversationId) -> Vec<Action> {
        let mut out = Vec::new();
        let epoch = cx
            .store
            .conversation_row(conv)
            .ok()
            .flatten()
            .map_or(0, |r| r.epoch);
        self.stuck.insert(conv, (epoch, 0));
        if let Err(e) = self.pump(cx, &mut out) {
            tracing::warn!(error = %e, "the group engine failed to send");
        }
        out
    }

    /// `GONE <box> <uid>` (6.1): a guest's session ended; a full client
    /// removes its leaf in its next commit, after a random wait.
    pub(super) fn on_gone(
        &mut self,
        cx: &Context,
        mailbox: &BoxName,
        uid: &Uid,
        out: &mut Vec<Action>,
    ) -> Result<(), EngineError> {
        let me = self.me(cx)?;
        if me.guest || !uid.is_guest() {
            return Ok(());
        }
        let wait = random_below(self.config.max_commit_wait_ms)?;
        self.write(cx, &me, out, |tx, c| {
            let Some(mb) = tx.mailbox(c.account, mailbox)? else {
                return Ok(());
            };
            let row = tx.conversation(mb.conv)?;
            if row.kind != ConvKind::Public || row.state != ConvState::Active {
                return Ok(());
            }
            let has_leaf = crate::store::conversations::read::leaves(tx.conn(), row.id)?
                .iter()
                .any(|l| l.uid == *uid);
            if !has_leaf {
                return Ok(());
            }
            let id = group::queue_intent(
                tx,
                row.id,
                &Intent {
                    remove: vec![(uid.to_string(), None)],
                    ..Intent::default()
                },
                c.now,
            )?;
            tx.update_outbox(id, OutboxState::Queued, None, None, Some(c.now + wait))?;
            Ok(())
        })
    }
}

impl ConversationEngine {
    /// Joins a guest's report conversation that the user accepted (12.7),
    /// from its held Welcome.
    pub(crate) fn accept_report(
        &mut self,
        cx: &Context,
        offer: i64,
    ) -> (Result<ConversationId, String>, Vec<Action>) {
        let mut out = Vec::new();
        let result = self.accept_report_inner(cx, offer, &mut out);
        if let Err(e) = self.pump(cx, &mut out) {
            tracing::warn!(error = %e, "the group engine failed to send");
        }
        (result, out)
    }

    fn accept_report_inner(
        &mut self,
        cx: &Context,
        offer: i64,
        out: &mut Vec<Action>,
    ) -> Result<ConversationId, String> {
        let me = self.me(cx).map_err(|e| e.to_string())?;
        let joined = self
            .write(cx, &me, out, |tx, c| {
                let Some(held) = tx.held_welcome(offer)? else {
                    return Ok(Err("no such offer".to_owned()));
                };
                let joined = group::join_welcome(tx, c, &held.welcome, true)?;
                tx.drop_held_welcome(offer)?;
                Ok(match joined {
                    group::Joined::Joined { conv } => Ok(conv),
                    group::Joined::Refused(why) => Err(why),
                })
            })
            .map_err(|e| e.to_string())??;
        out.push(Action::Emit(Event::Conversation(
            ConversationEvent::Joined {
                conversation: joined,
            },
        )));
        let actions = self
            .write(cx, &me, out, |tx, _| {
                Ok(self.hooks.leaves_changed(tx, joined))
            })
            .map_err(|e| e.to_string())?;
        out.extend(actions);
        Ok(joined)
    }
}
