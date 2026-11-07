//! One function per command.

use std::num::NonZeroU64;
use std::ops::Bound;
use std::sync::Arc;

use risala_proto::command::{Command, Request, RoomPage};
use risala_proto::error::ErrorCode;
use risala_proto::names::{Conv, Name, Room, Seq, Uid};
use risala_proto::server::{
    ErrResponse, Event, EventBody, OkResponse, Register, ServerLine, ServerMessage, Upload,
};
use risala_proto::types::{
    Cid, DEFAULT_LIMIT, DEFAULT_LIST_LIMIT, FileUrl, InfoRole, Ref, Relation, Role,
};

use super::Inner;
use super::state::RoomState;
use crate::handler::{ConnHandle, ConnId};
use crate::store::{Appended, EventKind, HistoryQuery, NewEvent, StoreError, StoredEvent};

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
        let Some((handle, uid)) = self
            .reg()
            .conns
            .get(&id)
            .map(|c| (c.handle.clone(), c.uid.clone()))
        else {
            return;
        };
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
            (Command::Guest { name }, None) => self.guest(id, name),
            // M3.
            (Command::Auth { .. } | Command::Register { .. }, None) => Err(not_supported()),
            (Command::Ping { .. }, _) => Ok(Some(OkResponse::new())),
            (Command::Pong { .. }, _) => Ok(None),
            (Command::Quit { .. }, _) => {
                reply.line(OkResponse::new());
                reply.handle.close(None);
                Ok(None)
            }
            (command, Some(uid)) => self.signed_in(id, &uid, reply, command).await,
            // Every command allowed before sign-in is handled above.
            (_, None) => Err(fail(ErrorCode::NotAuthenticated, "sign in first")),
        }
    }

    async fn signed_in(
        self: &Arc<Self>,
        id: ConnId,
        uid: &Uid,
        reply: &Reply,
        command: Command,
    ) -> Outcome {
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
            } => self.msg(id, uid, conv, text, relation, file, cid).await,
            Command::Sync => self.sync(uid, reply).await,
            Command::History {
                conv,
                after,
                before,
                limit,
            } => self.history(uid, reply, conv, after, before, limit).await,
            // Later milestones.
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

    /// GUEST (4.2).
    fn guest(&self, id: ConnId, name: Name) -> Outcome {
        if !self.settings().guests {
            return Err(fail(ErrorCode::Forbidden, "guests are not allowed"));
        }
        let uid = Uid::guest(&name);
        let mut reg = self.reg();
        if reg.users.contains_key(&uid) {
            return Err(fail(ErrorCode::NameTaken, "a guest has that name"));
        }
        let Some(conn) = reg.conns.get_mut(&id) else {
            return Ok(None);
        };
        if conn.uid.is_some() {
            return Err(fail(ErrorCode::AlreadyAuthenticated, "already signed in"));
        }
        conn.uid = Some(uid.clone());
        if let Some(timer) = conn.sign_in_timer.take() {
            timer.abort();
        }
        reg.users.insert(uid.clone(), vec![id]);
        tracing::debug!(conn = id.0, "signed in as a guest");
        Ok(Some(OkResponse::new().with_uid(&uid)))
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
        Ok(Some(
            ok.with_role(info_role(&st, uid, member))
                .with_joined(member),
        ))
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

    /// The live line of an event in a room (5.2).
    fn room_line(st: &RoomState, event: &StoredEvent) -> ServerMessage {
        ServerMessage::new(event.to_event(st.room.clone(), &st.id))
    }

    /// JOIN (6.1).
    async fn join(&self, uid: &Uid, reply: &Reply, room: &Room) -> Outcome {
        // M3: identities may create rooms that do not exist.
        let entry = self.room_entry(room).ok_or_else(not_found)?;
        let mut st = entry.state.lock().await;
        let member = self.reg().is_member(room, uid);
        if !member {
            check_access(&st, uid, false)?;
            let event = NewEvent {
                t: self.now(),
                from: uid.clone(),
                kind: EventKind::Join,
                cid: None,
            };
            let (_, event) = self.append(&mut st, event).await?;
            let mut reg = self.reg();
            reg.add_member(room, uid);
            reg.broadcast(room, &Self::room_line(&st, &event));
        }
        send_settings(reply, &st);
        let mut ok = OkResponse::new().with_id(&st.id);
        // A member has joined, so there is an event.
        if let Some(head) = st.head {
            ok = ok.with_head(head);
        }
        Ok(Some(ok))
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
        reg.broadcast(room, &Self::room_line(&st, &event));
        reg.remove_member(room, uid);
        Ok(Some(OkResponse::new()))
    }

    /// A guest's automatic PART when its connection closes (4.2).
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
            Ok((_, event)) => reg.broadcast(room, &Self::room_line(&st, &event)),
            // The guest is gone either way. No seq was used.
            Err(e) => tracing::error!(%room, "storing a guest's PART failed: {e}"),
        }
        reg.remove_member(room, uid);
    }

    /// MSG (5.3), in rooms.
    #[allow(clippy::too_many_arguments)]
    async fn msg(
        &self,
        id: ConnId,
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
        let member = self.reg().is_member(&room, uid);
        check_access(&st, uid, member)?;

        // A message that was already sent gets its seq again (7.6), even if
        // what would be checked below has changed since.
        let now = self.now();
        if let Some(cid) = &cid {
            let earlier = if uid.is_guest() {
                let reg = self.reg();
                reg.conns
                    .get(&id)
                    .and_then(|c| c.guest_cids.get(&st.id, cid, now))
            } else {
                let (key, from, cid) = (st.key, uid.clone(), cid.clone());
                self.db(move |s| s.cid_seq(key, &from, &cid, now)).await?
            };
            if let Some(seq) = earlier {
                return Ok(Some(OkResponse::new().with_seq(seq)));
            }
        }

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
            // Guests' cids are kept per connection (7.6).
            cid: cid.clone().filter(|_| uid.is_identity()),
        };
        let (appended, event) = self.append(&mut st, event).await?;
        let mut reg = self.reg();
        match appended {
            Appended::New(seq) => {
                reg.broadcast(&room, &Self::room_line(&st, &event));
                if let Some(cid) = cid
                    && uid.is_guest()
                    && let Some(conn) = reg.conns.get_mut(&id)
                {
                    conn.guest_cids.insert(st.id.clone(), cid, seq, now);
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
    async fn sync(&self, uid: &Uid, reply: &Reply) -> Outcome {
        let rooms: Vec<Room> = self
            .reg()
            .rooms_of
            .get(uid)
            .map(|r| r.iter().cloned().collect())
            .unwrap_or_default();
        for room in rooms {
            let Some(entry) = self.room_entry(&room) else {
                continue;
            };
            let st = entry.state.lock().await;
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
        for event in &page.events {
            reply.line(event.to_event(room.clone(), &id));
        }
        Ok(Some(OkResponse::new().with_id(&id).with_more(page.more)))
    }
}
