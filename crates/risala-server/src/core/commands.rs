//! One function per command.

use std::collections::HashMap;
use std::num::NonZeroU64;
use std::ops::Bound;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use risala_proto::command::{AdminCommand, Command, Request, RoomPage};
use risala_proto::error::ErrorCode;
use risala_proto::names::{Conv, Id, Name, Room, Seq, Uid};
use risala_proto::server::{
    ErrResponse, Event, EventBody, OkResponse, Register, ServerLine, ServerMessage, Upload,
};
use risala_proto::types::{
    Cid, DEFAULT_LIMIT, DEFAULT_LIST_LIMIT, FileUrl, InfoRole, Ref, Relation, Role,
};

use super::state::{ConvEntry, ConvGuard, ConvState, RoomInfo};
use super::{Inner, SignIn, SignInRefused, TOKEN_LEN};
use crate::config::RoomCreation;
use crate::handler::{ConnHandle, ConnId, OutLine};
use crate::store::{
    self, Appended, ConvKey, Created, EventKind, HistoryQuery, NewEvent, StoreError, StoredEvent,
};

/// Why a command failed.
#[derive(Debug)]
pub(super) enum Fail {
    /// An error for the client (3.7).
    Err(ErrResponse),
    /// The store failed: logged, and `ERR internal` for the client.
    Store(StoreError),
}

impl From<StoreError> for Fail {
    fn from(e: StoreError) -> Fail {
        Fail::Store(e)
    }
}

pub(super) fn fail(code: ErrorCode, message: &str) -> Fail {
    Fail::Err(ErrResponse::new(code).with_message(message))
}

pub(super) fn not_found() -> Fail {
    fail(ErrorCode::NotFound, "no such room")
}

pub(super) fn not_supported() -> Fail {
    fail(ErrorCode::NotSupported, "not supported yet")
}

pub(super) type Outcome = Result<Option<OkResponse>, Fail>;

/// The window of `limits.rooms_per_day` (6.1, 14).
pub(super) const ROOM_CREATION_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

/// Sends the lines of one command's response, each with the command's
/// `ref` (3.6).
pub(super) struct Reply {
    pub(super) handle: ConnHandle,
    pub(super) ref_: Option<Ref>,
}

impl Reply {
    pub(super) fn line(&self, line: impl Into<ServerLine>) {
        self.handle
            .send(ServerMessage::new(line).with_ref_opt(self.ref_.clone()));
    }
}

/// The settings of a room as snapshot SET lines (5.2, 6.1, 6.2).
fn send_settings(reply: &Reply, info: &RoomInfo) {
    for setting in info.settings.to_settings() {
        reply.line(Event::snapshot(EventBody::Set {
            room: info.room.clone(),
            setting,
        }));
    }
}

/// The room part of a conversation found by room name.
pub(super) fn room_of(st: &ConvState) -> Result<&RoomInfo, Fail> {
    st.room_info().ok_or_else(not_found)
}

/// Who is asking about a room, as its access rules see it (6.1, 6.3).
#[derive(Debug, Clone, Copy)]
pub(super) struct Asker<'a> {
    uid: &'a Uid,
    /// A member of the room right now.
    member: bool,
    /// A server operator (10.1).
    operator: bool,
}

/// Whether the asker can know that the room exists (6.1): it is public, or
/// the asker is a member, holds a role or an invitation in it, or is an
/// operator. Guests cannot be invited, hold roles or be operators (4.2).
fn visible(info: &RoomInfo, a: Asker<'_>) -> bool {
    a.member
        || info.settings.public
        || a.operator
        || (a.uid.is_identity() && (info.roles.contains_key(a.uid) || info.invites.contains(a.uid)))
}

/// Checks that the asker may read the room: its history, INFO and
/// RELATED (6.1, 7.2). A room it cannot see is `ERR not-found`, so private
/// rooms stay hidden; one it can see but may not read is `ERR forbidden`.
///
/// Readers are members, owners and moderators even after leaving (6.3),
/// operators (10), and anyone allowed to join a public room. Guests need
/// the room's `guests` setting to let them in.
pub(super) fn check_read(info: &RoomInfo, a: Asker<'_>) -> Result<(), Fail> {
    if !visible(info, a) {
        return Err(not_found());
    }
    if a.uid.is_guest() && !info.settings.guests.allows_read() {
        return Err(fail(ErrorCode::Forbidden, "guests may not enter this room"));
    }
    if a.member || a.operator || info.roles.contains_key(a.uid) {
        return Ok(());
    }
    if info.bans.contains(a.uid) {
        return Err(fail(ErrorCode::Forbidden, "you are banned from this room"));
    }
    if info.settings.public {
        return Ok(());
    }
    Err(fail(ErrorCode::Forbidden, "join the room first"))
}

/// Checks that the asker, not a member, may join the room (6.1): anyone not
/// banned may join a public room; a private room takes an invitation or
/// the role `owner` or `mod`; operators may join any room (6.3). Guests
/// need the room's `guests` setting to let them in.
///
/// M5a: joining an encrypted room always takes an invitation.
fn check_join(info: &RoomInfo, a: Asker<'_>) -> Result<(), Fail> {
    if !visible(info, a) {
        return Err(not_found());
    }
    if a.uid.is_guest() && !info.settings.guests.allows_read() {
        return Err(fail(ErrorCode::Forbidden, "guests may not enter this room"));
    }
    if a.operator {
        return Ok(());
    }
    if info.bans.contains(a.uid) {
        return Err(fail(ErrorCode::Forbidden, "you are banned from this room"));
    }
    if info.settings.public || info.roles.contains_key(a.uid) || info.invites.contains(a.uid) {
        return Ok(());
    }
    Err(fail(
        ErrorCode::Forbidden,
        "joining this room takes an invitation",
    ))
}

/// Checks that the asker may see `INFO <room>` (6.2): anyone who may read
/// the room, and also someone invited to it who is not banned, so their
/// client can show what they are invited to. HISTORY stays closed to them
/// until they join (7.2).
fn check_info(info: &RoomInfo, a: Asker<'_>) -> Result<(), Fail> {
    match check_read(info, a) {
        Err(Fail::Err(e))
            if e.code == ErrorCode::Forbidden
                && a.uid.is_identity()
                && info.invites.contains(a.uid)
                && !info.bans.contains(a.uid) =>
        {
            Ok(())
        }
        other => other,
    }
}

/// What INFO reports as `role` (6.2, 6.3).
fn info_role(st: &RoomInfo, uid: &Uid, member: bool) -> InfoRole {
    match st.roles.get(uid) {
        Some(role) => InfoRole(Some(*role)),
        None if member => InfoRole(Some(Role::Member)),
        None => InfoRole(None),
    }
}

/// Queues a command's final response, if `outcome` has one: its `OK`, its
/// `ERR`, or `ERR internal` for a store failure, which is logged.
pub(super) fn respond(reply: &Reply, verb: &str, outcome: Outcome) {
    match outcome {
        Ok(Some(ok)) => reply.line(ok),
        Ok(None) => {}
        Err(Fail::Err(err)) => reply.line(err),
        Err(Fail::Store(e)) => {
            tracing::error!(conn = reply.handle.id().0, verb, "store failed: {e}");
            reply.line(ErrResponse::new(ErrorCode::Internal).with_message("internal error"));
        }
    }
}

/// Whether `command` is one that guests may use in rooms, naming a uid
/// as its conversation: MSG, DELETE, HISTORY, RELATED, TYPING and REPORT
/// (4.2, 13). Commands that guests may not use at all are not, so they
/// still get `forbidden`.
fn names_direct_for_guests(command: &Command) -> bool {
    match command {
        Command::Msg { conv, .. }
        | Command::Delete { conv, .. }
        | Command::History { conv, .. }
        | Command::Related { conv, .. }
        | Command::Typing { conv }
        | Command::Report {
            conv,
            franking: None,
            ..
        } => !conv.is_room(),
        _ => false,
    }
}

fn page_limit(limit: Option<NonZeroU64>, default: u64, max: u64) -> u64 {
    limit.map_or(default, NonZeroU64::get).min(max).max(1)
}

impl Inner {
    /// Handles one command and queues its final response.
    pub(super) async fn command(self: &Arc<Self>, id: ConnId, req: Request) {
        let Some((handle, uid, detached)) = self
            .reg()
            .conns
            .get(&id)
            .map(|c| (c.handle.clone(), c.uid.clone(), c.detached))
        else {
            return;
        };
        // The connection lost its guest session and has been told BYE
        // (4.2). Nothing it sends now is read: no line after the BYE is
        // sent.
        if detached {
            return;
        }
        let reply = Reply {
            handle,
            ref_: req.ref_,
        };
        let verb = req.command.verb();
        let outcome = self.dispatch(id, uid, &reply, req.command).await;
        respond(&reply, verb, outcome);
    }

    async fn dispatch(
        self: &Arc<Self>,
        id: ConnId,
        uid: Option<Uid>,
        reply: &Reply,
        command: Command,
    ) -> Outcome {
        let uid = match uid {
            None if !command.allowed_before_sign_in() => {
                return Err(fail(ErrorCode::NotAuthenticated, "sign in first"));
            }
            Some(_) if command.signs_in() => {
                return Err(fail(ErrorCode::AlreadyAuthenticated, "already signed in"));
            }
            // Guests have no direct conversations, so one named by a uid
            // does not exist for them (4.2, 13).
            Some(uid) if uid.is_guest() && names_direct_for_guests(&command) => {
                return Err(fail(ErrorCode::NotFound, "no such conversation"));
            }
            Some(uid) if uid.is_guest() && !command.allowed_for_guests() => {
                return Err(fail(ErrorCode::Forbidden, "not for guests"));
            }
            uid => uid,
        };
        match (command, uid) {
            (Command::Info { room: None }, _) => Ok(Some(self.info())),
            (Command::Guest { name, token }, None) => self.guest(id, name, token),
            (
                Command::Auth {
                    identity,
                    signature,
                },
                None,
            ) => self.auth(id, identity, signature).await,
            (
                Command::Register {
                    name,
                    key,
                    signature,
                },
                None,
            ) => self.register(id, name, key, signature).await,
            (Command::Ping { .. }, _) => Ok(Some(OkResponse::new())),
            (Command::Pong { .. }, _) => Ok(None),
            (Command::Quit { .. }, _) => {
                reply.line(OkResponse::new());
                reply.handle.close(None);
                Ok(None)
            }
            (command, Some(uid)) => self.signed_in(&uid, reply, command).await,
            // Every command allowed before sign-in is handled above.
            (_, None) => Err(fail(ErrorCode::NotAuthenticated, "sign in first")),
        }
    }

    async fn signed_in(self: &Arc<Self>, uid: &Uid, reply: &Reply, command: Command) -> Outcome {
        match command {
            Command::Key(sub) => self.key(uid, reply, sub).await,
            Command::Unregister { uid: target, purge } => {
                self.unregister(uid, reply, &target, purge).await
            }
            Command::Info { room: Some(room) } => self.info_room(uid, reply, &room).await,
            Command::List(page) => self.list(uid, reply, page).await,
            Command::Join { room } => self.join(uid, reply, &room).await,
            Command::Part { room, reason } => self.part(uid, &room, reason).await,
            Command::Msg {
                conv,
                text,
                relation,
                file,
                cid,
            } => self.msg(uid, conv, text, relation, file, cid).await,
            Command::Sync => self.sync(uid, reply).await,
            Command::History {
                conv,
                after,
                before,
                limit,
                only: None,
            } => self.history(uid, reply, conv, after, before, limit).await,
            Command::Read { conv, seq } => self.read(uid, reply, conv, seq).await,
            Command::Typing { conv } => self.typing(uid, reply, conv).await,
            Command::Name { display_name } => self.name(uid, reply, display_name).await,
            Command::Members { room } => self.members(uid, reply, &room).await,
            Command::Whois { uid: target } => self.whois(reply, target).await,
            Command::Block { target } => self.block(uid, reply, target).await,
            Command::Unblock { target } => self.unblock(uid, reply, target).await,
            Command::Blocks => self.blocks(uid, reply).await,
            // M4, one arm per area so that they can be built apart.
            command @ (Command::Delete { .. }
            | Command::Related { .. }
            | Command::Admin(AdminCommand::Purge { .. })) => {
                self.messages(uid, reply, command).await
            }
            command @ (Command::Set { .. }
            | Command::Role { .. }
            | Command::Roles { .. }
            | Command::Invite { .. }
            | Command::Kick { .. }
            | Command::Ban { .. }
            | Command::Unban { .. }
            | Command::Bans { .. }) => self.moderation(uid, reply, command).await,
            command @ (Command::Report { .. }
            | Command::Reports { .. }
            | Command::Resolve { .. }
            | Command::Admin(
                AdminCommand::Reports | AdminCommand::Rooms(_) | AdminCommand::Drop { .. },
            )) => self.reports(uid, reply, command).await,
            Command::Admin(command) => self.admin(uid, reply, command).await,
            // Later milestones, including `HISTORY only=commit` and the
            // rest of Section 12.
            _ => Err(not_supported()),
        }
    }

    /// INFO (8.5).
    fn info(&self) -> OkResponse {
        let settings = self.settings();
        OkResponse::new()
            .with_version(risala_proto::PROTOCOL_VERSION)
            .with_guests(settings.guests)
            // `register=no` while registration is closed (8.5), so clients
            // do not offer a sign-up that will fail.
            .with_register(&match &self.identity_domain {
                Some(domain) if settings.registration => Register::Domain(domain.clone()),
                _ => Register::No,
            })
            .with_retention(settings.retention)
            .with_push(false)
            .with_upload(Upload::No)
    }

    /// GUEST (4.2): a new session, or a resumed one when `token` is the
    /// current token of the session that holds the name. A token that
    /// matches nothing is ignored.
    fn guest(&self, id: ConnId, name: Name, token: Option<Id>) -> Outcome {
        if !self.settings().guests {
            return Err(fail(ErrorCode::Forbidden, "guests are not allowed"));
        }
        let uid = Uid::guest(&name);
        let new_token = store::random_id_of(TOKEN_LEN)?;
        match self.sign_in_guest(id, &uid, token.as_ref(), new_token.clone()) {
            Ok(how) => {
                tracing::debug!(
                    conn = id.0,
                    resumed = how == SignIn::Resumed,
                    "signed in as a guest"
                );
                // 4.2: resumed=yes tells the guest its cids carry over,
                // so it may resend what got no OK (7.6).
                Ok(Some(
                    OkResponse::new()
                        .with_uid(&uid)
                        .with_token(&new_token)
                        .with_resumed(how == SignIn::Resumed),
                ))
            }
            Err(SignInRefused::NameTaken) => {
                Err(fail(ErrorCode::NameTaken, "a guest has that name"))
            }
            Err(SignInRefused::Forbidden(why)) => Err(fail(ErrorCode::Forbidden, why)),
            Err(SignInRefused::Gone) => Ok(None),
        }
    }

    /// INFO <room> (6.2).
    async fn info_room(&self, uid: &Uid, reply: &Reply, room: &Room) -> Outcome {
        let st = self.lock_room(room).await?;
        let info = room_of(&st)?;
        let (member, members) = (st.is_member(uid), st.member_count());
        check_info(info, self.asker(uid, member))?;
        send_settings(reply, info);
        // A room from the configuration has no events until someone joins,
        // and then reports `head=0` (6.2).
        let head = st.head.map_or(0, u64::from);
        let ok = OkResponse::new()
            .with_id(&st.id)
            .with_members(members)
            .with_head(head);
        // Queued under the room lock, so the live events this connection
        // gets before it are covered by it, and those after it are newer
        // (3.6).
        reply.line(
            ok.with_role(info_role(info, uid, member))
                .with_joined(member),
        );
        Ok(None)
    }

    /// LIST (6.1). A guest sees only the rooms guests may enter.
    async fn list(&self, uid: &Uid, reply: &Reply, page: RoomPage) -> Outcome {
        let limit = page_limit(page.limit, DEFAULT_LIST_LIMIT, self.config.limits.max_list);
        let entries: Vec<_> = {
            let rooms = self.rooms.read().unwrap_or_else(|e| e.into_inner());
            let start = match &page.after {
                Some(after) => Bound::Excluded(after),
                None => Bound::Unbounded,
            };
            rooms
                .range::<Room, _>((start, Bound::Unbounded))
                .map(|(_, entry)| entry.clone())
                .collect()
        };
        let mut lines = Vec::new();
        let mut more = false;
        for entry in entries {
            let st = entry.lock().await;
            let Some(info) = st.room_info().filter(|_| !st.dropped) else {
                continue;
            };
            if !info.settings.public || (uid.is_guest() && !info.settings.guests.allows_read()) {
                continue;
            }
            if lines.len() as u64 == limit {
                more = true;
                break;
            }
            lines.push(ServerLine::Room {
                room: info.room.clone(),
                members: st.member_count(),
                topic: info.settings.topic.clone(),
            });
        }
        for line in lines {
            reply.line(line);
        }
        Ok(Some(OkResponse::new().with_more(more)))
    }

    /// Appends an event to a room whose lock the caller holds, and records
    /// its seq as the head. Nothing is sent.
    async fn append(
        &self,
        st: &mut ConvState,
        event: NewEvent,
    ) -> Result<(Appended, StoredEvent), StoreError> {
        let key = st.key;
        let stored_event = event.clone();
        let appended = self.db(move |s| s.append(key, &stored_event)).await?;
        let seq = match appended {
            Appended::New(seq) | Appended::Duplicate(seq) => seq,
        };
        if let Appended::New(seq) = appended {
            st.head = Some(seq);
        }
        Ok((
            appended,
            StoredEvent {
                seq,
                t: event.t,
                from: event.from,
                kind: event.kind,
                deleted: false,
            },
        ))
    }

    /// Queues a conversation's event for every connection of every member
    /// (5.2). The event is already stored, so an event that cannot be
    /// shown is only logged.
    ///
    /// M5a: a direct conversation's lines name the other participant, so
    /// they are written once per receiver (5.2).
    pub(super) fn broadcast_event(st: &ConvState, event: &StoredEvent) {
        let Some(info) = st.room_info() else {
            return;
        };
        match event.to_event(info.room.clone(), &st.id) {
            Ok(line) => st.broadcast(&OutLine::new(ServerMessage::new(line))),
            Err(e) => tracing::error!(room = %info.room, "cannot send an event: {e}"),
        }
    }

    /// Locks a room. A room that does not exist, or that was dropped while
    /// this waited for its lock, is `ERR not-found` (6.1, 10.4).
    pub(super) async fn lock_room(&self, room: &Room) -> Result<ConvGuard, Fail> {
        let entry = self.room_entry(room).ok_or_else(not_found)?;
        let st = entry.lock_owned().await;
        if st.dropped {
            return Err(not_found());
        }
        Ok(st)
    }

    /// JOIN (6.1). A room that does not exist is created for an identity
    /// when the server's policy allows it.
    async fn join(&self, uid: &Uid, reply: &Reply, room: &Room) -> Outcome {
        loop {
            let guard = match self.lock_room(room).await {
                Ok(guard) => guard,
                Err(e) if !self.may_create_room(uid) => return Err(e),
                Err(_) => {
                    // Taken now and given back if no room is made (6.1,
                    // 14).
                    let slot = self.room_creation_slot(uid)?;
                    match self.create_room(uid, room).await? {
                        Some(guard) => {
                            if let Some(slot) = slot {
                                slot.keep();
                            }
                            // The creator is its first member, and its JOIN
                            // is event 1 (6.1).
                            send_settings(reply, room_of(&guard)?);
                            let head = guard.head.map_or(0, u64::from);
                            reply.line(OkResponse::new().with_id(&guard.id).with_head(head));
                            return Ok(None);
                        }
                        // Someone else created it meanwhile: join theirs.
                        None => continue,
                    }
                }
            };
            return self.join_existing(uid, reply, guard).await;
        }
    }

    /// JOIN of a room that exists, whose lock is held.
    async fn join_existing(&self, uid: &Uid, reply: &Reply, mut guard: ConvGuard) -> Outcome {
        let entry = ConvGuard::mutex(&guard).clone();
        let st = &mut *guard;
        let member = st.is_member(uid);
        if !member {
            check_join(room_of(st)?, self.asker(uid, false))?;
            // A guest whose session is ending, on a connection that has
            // already been told BYE (4.2).
            if !self.reg().may_join(uid) {
                return Err(fail(ErrorCode::Forbidden, "the session has ended"));
            }
            let event = NewEvent {
                t: self.now(),
                from: uid.clone(),
                kind: EventKind::Join,
                cid: None,
            };
            let (_, event) = self.append(st, event).await?;
            // The invitation is used up (6.4), as in the store.
            if let Some(info) = st.room_info_mut() {
                info.invites.remove(uid);
            }
            let user = self.reg().user(uid);
            st.add_member(&entry, &user);
            Self::broadcast_event(st, &event);
        }
        send_settings(reply, room_of(st)?);
        // A member has joined, so there is an event.
        let head = st.head.map_or(0, u64::from);
        // Queued under the room lock, so no later event of the room can
        // overtake it (3.6).
        reply.line(OkResponse::new().with_id(&st.id).with_head(head));
        Ok(None)
    }

    /// Whether `uid` may create a room by joining it (6.1), under
    /// `room_creation`. Guests never may (4.2).
    fn may_create_room(&self, uid: &Uid) -> bool {
        if uid.is_guest() {
            return false;
        }
        match self.config.room_creation {
            RoomCreation::Identities => true,
            RoomCreation::Hosted => self.hosts_uid(uid) || self.is_operator(uid),
            RoomCreation::Operators => self.is_operator(uid),
            RoomCreation::Nobody => false,
        }
    }

    /// One of the rooms `uid` may create today (6.1, 14), under
    /// `limits.rooms_per_day`, or `ERR rate-limited`. Operators are not
    /// limited, and get no slot.
    fn room_creation_slot(&self, uid: &Uid) -> Result<Option<super::rate::Slot<'_, Uid>>, Fail> {
        if self.is_operator(uid) {
            return Ok(None);
        }
        let limit = self.config.limits.rooms_per_day;
        self.room_creations
            .take(uid.clone(), limit, self.now())
            .map_err(|retry| {
                Fail::Err(
                    ErrResponse::new(ErrorCode::RateLimited)
                        .with_retry(retry)
                        .with_message("you have created too many rooms today"),
                )
            })
    }

    /// `uid` as the access rules of a room see it.
    pub(super) fn asker<'a>(&self, uid: &'a Uid, member: bool) -> Asker<'a> {
        Asker {
            uid,
            member,
            operator: uid.is_identity() && self.is_operator(uid),
        }
    }

    /// Creates `room` for `creator`, with its JOIN as event 1, and adds it
    /// to the hub (6.1). Returns the new room, locked, once the creator's
    /// connections have its JOIN; or `None` if the room exists after all.
    ///
    /// Rooms are added at run time only here, under the creation lock, so
    /// two JOINs cannot both create one. The room is locked before it is
    /// added to the index, so nobody else's event can come before its
    /// first.
    async fn create_room(&self, creator: &Uid, room: &Room) -> Result<Option<ConvGuard>, Fail> {
        let _creating = self.create_lock.lock().await;
        if self.room_entry(room).is_some() {
            return Ok(None);
        }
        // An identity being deleted may not join rooms, nor own new ones
        // (4.8).
        if !self.reg().may_join(creator) {
            return Err(fail(ErrorCode::Forbidden, "the identity is being deleted"));
        }
        let now = self.now();
        let (name, uid) = (room.clone(), creator.clone());
        let created = self.db(move |s| s.create_room(&name, &uid, now)).await?;
        let (mut record, new) = match created {
            Created::New(record) => (record, true),
            // In the store but not in the index: cannot happen, since
            // rooms are added to both here or at startup. Add it, and join
            // it as it is.
            Created::Exists(record) => {
                tracing::warn!(%room, "a stored room was missing from the index");
                (record, false)
            }
        };
        let members = std::mem::take(&mut record.members);
        let entry = Arc::new(ConvEntry::new(ConvState::room(record)));
        let mut guard = entry
            .clone()
            .try_lock_owned()
            .map_err(|_| Fail::Store(StoreError::Task("a new room was locked".into())))?;
        {
            let mut reg = self.reg();
            for uid in &members {
                let user = reg.user(uid);
                guard.add_member(&entry, &user);
            }
        }
        self.rooms
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(room.clone(), entry);
        drop(_creating);
        if !new {
            return Ok(None);
        }
        tracing::info!(%room, "room created");
        let join = StoredEvent {
            seq: guard.head.ok_or(StoreError::NoConversation)?,
            t: now,
            from: creator.clone(),
            kind: EventKind::Join,
            deleted: false,
        };
        Self::broadcast_event(&guard, &join);
        Ok(Some(guard))
    }

    /// PART (6.1).
    async fn part(&self, uid: &Uid, room: &Room, reason: String) -> Outcome {
        let mut st = self.lock_room(room).await?;
        if !st.is_member(uid) {
            return Err(fail(ErrorCode::NotFound, "not a member"));
        }
        let event = NewEvent {
            t: self.now(),
            from: uid.clone(),
            kind: EventKind::Part { reason },
            cid: None,
        };
        let (_, event) = self.append(&mut st, event).await?;
        Self::broadcast_event(&st, &event);
        st.remove_member(uid);
        Ok(Some(OkResponse::new()))
    }

    /// A PART with no reason that nobody sent: a guest's when its session
    /// ends (4.2), or an identity's when it is deleted (4.8). In `conv`,
    /// if `uid` is still a member there.
    pub(super) async fn auto_part(&self, conv: Arc<ConvEntry>, uid: &Uid) {
        let mut st = conv.lock_owned().await;
        if st.dropped || !st.is_member(uid) {
            // Not a member here any more: just make sure the user's list
            // agrees, so that the caller's loop ends.
            if st.remove_member(uid).is_none()
                && let Some(user) = self.reg().users.get(uid).cloned()
            {
                user.lock().convs.remove(&st.conv_ref(uid));
            }
            return;
        }
        let event = NewEvent {
            t: self.now(),
            from: uid.clone(),
            kind: EventKind::Part {
                reason: String::new(),
            },
            cid: None,
        };
        match self.append(&mut st, event).await {
            Ok((_, event)) => Self::broadcast_event(&st, &event),
            // The guest is gone either way. No seq was used.
            Err(e) => tracing::error!(conv = %st.id, "storing a PART failed: {e}"),
        }
        st.remove_member(uid);
    }

    /// MSG (5.3), in rooms.
    async fn msg(
        &self,
        uid: &Uid,
        conv: Conv,
        text: String,
        relation: Option<Relation>,
        file: Option<FileUrl>,
        cid: Option<Cid>,
    ) -> Outcome {
        // M3: direct conversations. M4 and later: edits, reactions, files.
        let Conv::Room(room) = conv else {
            return Err(not_supported());
        };
        if file.is_some() || matches!(relation, Some(Relation::Edit(_) | Relation::React(_))) {
            return Err(not_supported());
        }
        let mut guard = self.lock_room(&room).await?;
        let st = &mut *guard;

        // A message that was already sent gets its seq again (7.6), before
        // any other check: the sender may have left since, or the room may
        // have become private or closed to guests (PLAN.md 5, item 14).
        let now = self.now();
        if let Some(cid) = &cid {
            let earlier = if uid.is_guest() {
                let reg = self.reg();
                reg.sessions
                    .get(uid)
                    .and_then(|s| s.cids.get(&st.id, cid, now))
            } else {
                let (key, from, cid) = (st.key, uid.clone(), cid.clone());
                self.db(move |s| s.cid_seq(key, &from, &cid, now)).await?
            };
            if let Some(seq) = earlier {
                return Ok(Some(OkResponse::new().with_seq(seq)));
            }
        }

        let member = st.is_member(uid);
        let info = room_of(st)?;
        check_read(info, self.asker(uid, member))?;
        if !member {
            return Err(fail(ErrorCode::Forbidden, "join the room first"));
        }
        if uid.is_guest() && !info.settings.guests.allows_write() {
            return Err(fail(ErrorCode::Forbidden, "guests may not send here"));
        }
        if let Some(Relation::Reply(target)) = relation {
            self.check_target(st, target).await?;
        }

        let event = NewEvent {
            t: now,
            from: uid.clone(),
            kind: EventKind::Msg {
                relation,
                file: None,
                text,
            },
            // Guests' cids are kept per session (7.6).
            cid: cid.clone().filter(|_| uid.is_identity()),
        };
        let (appended, event) = self.append(st, event).await?;
        match appended {
            Appended::New(seq) => {
                Self::broadcast_event(st, &event);
                self.typing_ended(uid, &st.id);
                if let Some(cid) = cid
                    && uid.is_guest()
                    && let Some(session) = self.reg().sessions.get_mut(uid)
                {
                    session.cids.insert(st.id.clone(), cid, seq, now);
                }
                Ok(Some(OkResponse::new().with_seq(seq)))
            }
            // Another connection of the same identity sent the same cid
            // between the check above and now.
            Appended::Duplicate(seq) => Ok(Some(OkResponse::new().with_seq(seq))),
        }
    }

    /// A message from `uid` ends its typing notification in the
    /// conversation `id` (8.1), on every device: the next TYPING from any of
    /// them is passed on at once, not held back by the rate limit.
    fn typing_ended(&self, uid: &Uid, id: &Id) {
        // The registry and the user's entry are never locked together here,
        // so no lock order is imposed.
        let Some(user) = self.reg().users.get(uid).cloned() else {
            return;
        };
        let conns: Vec<ConnId> = user.lock().conns.iter().map(|c| c.handle.id()).collect();
        let mut reg = self.reg();
        for conn in conns {
            if let Some(entry) = reg.conns.get_mut(&conn) {
                entry.typing_ended(id);
            }
        }
    }

    /// Checks the target of `reply`, `edit` or `react` (5.3): a message in
    /// the same conversation, not deleted, and not an edit or a reaction.
    async fn check_target(&self, st: &ConvState, target: Seq) -> Result<(), Fail> {
        let key = st.key;
        let event = self.db(move |s| s.event(key, target)).await?;
        match event {
            Some(e) if !e.deleted && e.is_plain_message() => Ok(()),
            _ => Err(fail(ErrorCode::NotFound, "no such message")),
        }
    }

    /// SYNC (7.1).
    ///
    /// SYNC has a CONV line for every conversation, however many, so it is
    /// not bounded by the room the network layer keeps for a response
    /// ([`Limits::command_room`](crate::config::Limits::command_room)). It
    /// queues its lines in chunks small enough to fit that room, and
    /// before each chunk after the first it waits, holding no room lock,
    /// until the connection's queue has that room again. Each CONV line is
    /// still queued under its room's lock (3.6).
    async fn sync(&self, uid: &Uid, reply: &Reply) -> Outcome {
        // Read markers are the account's, and only identities have them
        // (7.4). They are all read at once, first. A CONV line must cover
        // the READ lines sent before it (3.6), so a conversation whose
        // marker moved after this has its marker read again under its
        // lock, as the CONV line is queued.
        let since = self.markers_moved.load(Ordering::SeqCst);
        let markers: HashMap<ConvKey, Seq> = if uid.is_identity() {
            let who = uid.clone();
            self.db(move |s| s.read_markers(&who))
                .await?
                .into_iter()
                .collect()
        } else {
            HashMap::new()
        };
        let convs = self
            .reg()
            .users
            .get(uid)
            .map(|user| user.convs())
            .unwrap_or_default();
        // The network layer left room for this many lines and the OK.
        let chunk = self.config.limits.reply_lines().saturating_sub(1).max(1);
        for (n, conv) in convs.into_iter().enumerate() {
            if n > 0 && n % chunk == 0 && !self.wait_for_reply_room(&reply.handle).await {
                // The connection is gone, so nobody reads the rest.
                return Ok(None);
            }
            let st = conv.lock().await;
            // Checked again under the lock: a PART queued before this line
            // means the conversation is no longer ours (3.6).
            if st.dropped || !st.is_member(uid) {
                continue;
            }
            // A member has joined, so the conversation has an event.
            if let Some(head) = st.head {
                let read = if uid.is_identity() && st.marker_moved > since {
                    let (key, who) = (st.key, uid.clone());
                    self.db(move |s| s.read_marker(key, &who)).await?
                } else {
                    markers.get(&st.key).copied()
                };
                reply.line(ServerLine::Conv {
                    conv: st.name_for(uid),
                    id: st.id.clone(),
                    head,
                    // Always 0 for guests (7.1). A marker is never beyond
                    // the head (7.4).
                    read: read.map(|read| read.min(head)),
                });
            }
        }
        Ok(Some(OkResponse::new()))
    }

    /// Waits until `handle`'s queue has room for a whole response and live
    /// events besides, as the network layer does before each command.
    /// Returns `false` if the connection closed instead. A client that
    /// reads nothing for as long as the keepalive allows (11) is dropped.
    pub(super) async fn wait_for_reply_room(&self, handle: &ConnHandle) -> bool {
        let limits = &self.config.limits;
        let patience = Duration::from_secs(
            limits
                .idle_ping_secs
                .saturating_add(limits.ping_timeout_secs),
        );
        let wait = handle.wait_for_room(limits.command_room(), limits.command_room_bytes());
        if tokio::time::timeout(patience, wait).await.is_err() {
            tracing::debug!(conn = handle.id().0, "not reading SYNC");
            handle.kill();
            return false;
        }
        !handle.is_closed()
    }

    /// HISTORY (7.2).
    async fn history(
        &self,
        uid: &Uid,
        reply: &Reply,
        conv: Conv,
        after: Option<u64>,
        before: Option<Seq>,
        limit: Option<NonZeroU64>,
    ) -> Outcome {
        let room = match conv {
            Conv::Room(room) => room,
            // Guests have no direct conversations (4.2).
            Conv::Uid(_) if uid.is_guest() => {
                return Err(fail(ErrorCode::NotFound, "no such conversation"));
            }
            // M3: direct conversations.
            Conv::Uid(_) => return Err(not_supported()),
        };
        let (key, id) = {
            let st = self.lock_room(&room).await?;
            check_read(room_of(&st)?, self.asker(uid, st.is_member(uid)))?;
            (st.key, st.id.clone())
        };
        let query = HistoryQuery {
            after,
            before,
            limit: page_limit(limit, DEFAULT_LIMIT, self.config.limits.max_page),
        };
        let page = self.db(move |s| s.history(key, query)).await?;
        // Every line is made before any is sent, so that bad data gives
        // only `ERR internal`.
        let lines = page
            .events
            .iter()
            .map(|event| event.to_event(room.clone(), &id))
            .collect::<Result<Vec<_>, _>>()?;
        for line in lines {
            reply.line(line);
        }
        Ok(Some(OkResponse::new().with_id(&id).with_more(page.more)))
    }
}
