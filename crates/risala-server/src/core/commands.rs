//! One function per command.

use std::num::NonZeroU64;
use std::ops::Bound;
use std::sync::Arc;
use std::time::Duration;

use risala_proto::command::{Command, Request, RoomPage};
use risala_proto::error::ErrorCode;
use risala_proto::names::{Conv, Id, Name, Room, Seq, Uid};
use risala_proto::server::{
    ErrResponse, Event, EventBody, OkResponse, Register, ServerLine, ServerMessage, Upload,
};
use risala_proto::types::{
    Cid, DEFAULT_LIMIT, DEFAULT_LIST_LIMIT, FileUrl, InfoRole, Ref, Relation, Role,
};

use super::state::{Registry, RoomState};
use super::{Inner, SignIn, SignInRefused, TOKEN_LEN};
use crate::handler::{ConnHandle, ConnId, OutLine};
use crate::store::{self, Appended, EventKind, HistoryQuery, NewEvent, StoreError, StoredEvent};

/// Why a command failed.
#[derive(Debug)]
enum Fail {
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

fn fail(code: ErrorCode, message: &str) -> Fail {
    Fail::Err(ErrResponse::new(code).with_message(message))
}

fn not_found() -> Fail {
    fail(ErrorCode::NotFound, "no such room")
}

fn not_supported() -> Fail {
    fail(ErrorCode::NotSupported, "not supported yet")
}

type Outcome = Result<Option<OkResponse>, Fail>;

/// Sends the lines of one command's response, each with the command's
/// `ref` (3.6).
struct Reply {
    handle: ConnHandle,
    ref_: Option<Ref>,
}

impl Reply {
    fn line(&self, line: impl Into<ServerLine>) {
        self.handle
            .send(ServerMessage::new(line).with_ref_opt(self.ref_.clone()));
    }
}

/// The settings of a room as snapshot SET lines (5.2, 6.1, 6.2).
fn send_settings(reply: &Reply, st: &RoomState) {
    for setting in st.settings.to_settings() {
        reply.line(Event::snapshot(EventBody::Set {
            room: st.room.clone(),
            setting,
        }));
    }
}

/// Whether `uid` can know that the room exists: it is public, or `uid` is
/// a member or holds a role in it. Guests cannot be invited or hold roles
/// (4.2). M3: invitations and operators.
fn visible(st: &RoomState, uid: &Uid, member: bool) -> bool {
    member || st.settings.public || (!uid.is_guest() && st.roles.contains_key(uid))
}

/// Checks that `uid` may read the room's history and INFO (7.2, 6.2), or
/// join it when `member` is false (6.1). A room it cannot see gets
/// `ERR not-found`, so private rooms stay hidden. A room it can see but
/// may not enter gets `ERR forbidden` (6.1). M3: room bans.
fn check_access(st: &RoomState, uid: &Uid, member: bool) -> Result<(), Fail> {
    if !visible(st, uid, member) {
        return Err(not_found());
    }
    if uid.is_guest() && !st.settings.guests.allows_read() {
        return Err(fail(ErrorCode::Forbidden, "guests may not enter this room"));
    }
    Ok(())
}

/// What INFO reports as `role` (6.2, 6.3).
fn info_role(st: &RoomState, uid: &Uid, member: bool) -> InfoRole {
    match st.roles.get(uid) {
        Some(role) => InfoRole(Some(*role)),
        None if member => InfoRole(Some(Role::Member)),
        None => InfoRole(None),
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
        match self.dispatch(id, uid, &reply, req.command).await {
            Ok(Some(ok)) => reply.line(ok),
            Ok(None) => {}
            Err(Fail::Err(err)) => reply.line(err),
            Err(Fail::Store(e)) => {
                tracing::error!(conn = id.0, verb, "store failed: {e}");
                reply.line(ErrResponse::new(ErrorCode::Internal).with_message("internal error"));
            }
        }
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
            Some(uid) if uid.is_guest() && !command.allowed_for_guests() => {
                return Err(fail(ErrorCode::Forbidden, "not for guests"));
            }
            uid => uid,
        };
        match (command, uid) {
            (Command::Info { room: None }, _) => Ok(Some(self.info())),
            (Command::Guest { name, token }, None) => self.guest(id, name, token),
            // M3.
            (Command::Auth { .. } | Command::Register { .. }, None) => Err(not_supported()),
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
            .with_register(&Register::No)
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
                Ok(Some(
                    OkResponse::new().with_uid(&uid).with_token(&new_token),
                ))
            }
            Err(SignInRefused::NameTaken) => {
                Err(fail(ErrorCode::NameTaken, "a guest has that name"))
            }
            Err(SignInRefused::Gone) => Ok(None),
        }
    }

    /// INFO <room> (6.2).
    async fn info_room(&self, uid: &Uid, reply: &Reply, room: &Room) -> Outcome {
        let entry = self.room_entry(room).ok_or_else(not_found)?;
        let st = entry.state.lock().await;
        let (member, members) = {
            let reg = self.reg();
            (reg.is_member(room, uid), reg.member_count(room))
        };
        check_access(&st, uid, member)?;
        send_settings(reply, &st);
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
            ok.with_role(info_role(&st, uid, member))
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
            let st = entry.state.lock().await;
            if !st.settings.public || (uid.is_guest() && !st.settings.guests.allows_read()) {
                continue;
            }
            if lines.len() as u64 == limit {
                more = true;
                break;
            }
            let members = self.reg().member_count(&st.room);
            lines.push(ServerLine::Room {
                room: st.room.clone(),
                members,
                topic: st.settings.topic.clone(),
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
        st: &mut RoomState,
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

    /// Queues a room's event for every connection of every member (5.2).
    /// The event is already stored, so an event that cannot be shown is
    /// only logged.
    fn broadcast_event(reg: &Registry, st: &RoomState, event: &StoredEvent) {
        match event.to_event(st.room.clone(), &st.id) {
            Ok(line) => reg.broadcast(&st.room, &OutLine::new(ServerMessage::new(line))),
            Err(e) => tracing::error!(room = %st.room, "cannot send an event: {e}"),
        }
    }

    /// JOIN (6.1).
    async fn join(&self, uid: &Uid, reply: &Reply, room: &Room) -> Outcome {
        // M3: identities may create rooms that do not exist.
        let entry = self.room_entry(room).ok_or_else(not_found)?;
        let mut st = entry.state.lock().await;
        let (member, may_join) = {
            let reg = self.reg();
            (reg.is_member(room, uid), reg.may_join(uid))
        };
        if !member {
            check_access(&st, uid, false)?;
            // A guest whose session is ending, on a connection that has
            // already been told BYE (4.2).
            if !may_join {
                return Err(fail(ErrorCode::Forbidden, "the session has ended"));
            }
            let event = NewEvent {
                t: self.now(),
                from: uid.clone(),
                kind: EventKind::Join,
                cid: None,
            };
            let (_, event) = self.append(&mut st, event).await?;
            let mut reg = self.reg();
            reg.add_member(room, uid);
            Self::broadcast_event(&reg, &st, &event);
        }
        send_settings(reply, &st);
        // A member has joined, so there is an event.
        let head = st.head.map_or(0, u64::from);
        // Queued under the room lock, so no later event of the room can
        // overtake it (3.6).
        reply.line(OkResponse::new().with_id(&st.id).with_head(head));
        Ok(None)
    }

    /// PART (6.1).
    async fn part(&self, uid: &Uid, room: &Room, reason: String) -> Outcome {
        let entry = self.room_entry(room).ok_or_else(not_found)?;
        let mut st = entry.state.lock().await;
        if !self.reg().is_member(room, uid) {
            return Err(fail(ErrorCode::NotFound, "not a member"));
        }
        let event = NewEvent {
            t: self.now(),
            from: uid.clone(),
            kind: EventKind::Part { reason },
            cid: None,
        };
        let (_, event) = self.append(&mut st, event).await?;
        let mut reg = self.reg();
        Self::broadcast_event(&reg, &st, &event);
        reg.remove_member(room, uid);
        Ok(Some(OkResponse::new()))
    }

    /// A guest's automatic PART when its session ends (4.2).
    pub(super) async fn guest_part(&self, room: &Room, uid: &Uid) {
        let Some(entry) = self.room_entry(room) else {
            self.reg().remove_member(room, uid);
            return;
        };
        let mut st = entry.state.lock().await;
        let event = NewEvent {
            t: self.now(),
            from: uid.clone(),
            kind: EventKind::Part {
                reason: String::new(),
            },
            cid: None,
        };
        let result = self.append(&mut st, event).await;
        let mut reg = self.reg();
        match result {
            Ok((_, event)) => Self::broadcast_event(&reg, &st, &event),
            // The guest is gone either way. No seq was used.
            Err(e) => tracing::error!(%room, "storing a guest's PART failed: {e}"),
        }
        reg.remove_member(room, uid);
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
        let entry = self.room_entry(&room).ok_or_else(not_found)?;
        let mut st = entry.state.lock().await;

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

        let member = self.reg().is_member(&room, uid);
        check_access(&st, uid, member)?;
        if !member {
            return Err(fail(ErrorCode::Forbidden, "join the room first"));
        }
        if uid.is_guest() && !st.settings.guests.allows_write() {
            return Err(fail(ErrorCode::Forbidden, "guests may not send here"));
        }
        if let Some(Relation::Reply(target)) = relation {
            self.check_target(&st, target).await?;
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
        let (appended, event) = self.append(&mut st, event).await?;
        let mut reg = self.reg();
        match appended {
            Appended::New(seq) => {
                Self::broadcast_event(&reg, &st, &event);
                if let Some(cid) = cid
                    && uid.is_guest()
                    && let Some(session) = reg.sessions.get_mut(uid)
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

    /// Checks the target of `reply`, `edit` or `react` (5.3): a message in
    /// the same conversation, not deleted, and not an edit or a reaction.
    async fn check_target(&self, st: &RoomState, target: Seq) -> Result<(), Fail> {
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
        let rooms: Vec<Room> = self
            .reg()
            .rooms_of
            .get(uid)
            .map(|r| r.iter().cloned().collect())
            .unwrap_or_default();
        // The network layer left room for this many lines and the OK.
        let chunk = self.config.limits.reply_lines().saturating_sub(1).max(1);
        for (n, room) in rooms.into_iter().enumerate() {
            if n > 0 && n % chunk == 0 && !self.wait_for_reply_room(&reply.handle).await {
                // The connection is gone, so nobody reads the rest.
                return Ok(None);
            }
            let Some(entry) = self.room_entry(&room) else {
                continue;
            };
            let st = entry.state.lock().await;
            // Checked again under the room lock: a PART queued before this
            // line means the room is no longer ours (3.6).
            if !self.reg().is_member(&room, uid) {
                continue;
            }
            // A member has joined, so the room has an event.
            if let Some(head) = st.head {
                reply.line(ServerLine::Conv {
                    conv: Conv::Room(room),
                    id: st.id.clone(),
                    head,
                    // M3: read markers for identities. Always 0 for guests.
                    read: None,
                });
            }
        }
        Ok(Some(OkResponse::new()))
    }

    /// Waits until `handle`'s queue has room for a whole response and live
    /// events besides, as the network layer does before each command.
    /// Returns `false` if the connection closed instead. A client that
    /// reads nothing for as long as the keepalive allows (11) is dropped.
    async fn wait_for_reply_room(&self, handle: &ConnHandle) -> bool {
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
        let entry = self.room_entry(&room).ok_or_else(not_found)?;
        let (key, id) = {
            let st = entry.state.lock().await;
            let member = self.reg().is_member(&room, uid);
            check_access(&st, uid, member)?;
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
