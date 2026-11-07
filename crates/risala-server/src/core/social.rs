//! Read markers (7.4), typing (8.1), display names (8.2), MEMBERS and
//! WHOIS (8.3), and blocks (5.7).
//!
//! None of these is an event: they are not stored in a conversation and
//! have no seq. Read markers, identities' display names and blocks are
//! stored for the account; typing is not stored at all, and a guest's
//! display name lasts as long as its session (4.2).

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use risala_proto::error::ErrorCode;
use risala_proto::names::{BlockTarget, Conv, Room, Seq, Uid};
use risala_proto::server::{OkResponse, ServerLine, ServerMessage};
use risala_proto::types::{Presence, Role};

use super::Inner;
use super::commands::{Fail, Outcome, Reply, check_read, fail, not_supported, room_of};
use super::state::UserEntry;
use crate::handler::OutLine;
use crate::store::StoreError;

impl Inner {
    /// READ (7.4): moves the account's read marker forward, and tells the
    /// account's other connections. Only identities get here (13).
    ///
    /// The marker may be set in any room the account may read (7.2), so
    /// that a public room read without joining can have one too.
    pub(super) async fn read(&self, uid: &Uid, reply: &Reply, conv: Conv, seq: Seq) -> Outcome {
        let Conv::Room(room) = conv else {
            // M5a: direct conversations.
            return Err(not_supported());
        };
        let mut st = self.lock_room(&room).await?;
        check_read(room_of(&st)?, self.asker(uid, st.is_member(uid)))?;
        let (key, who) = (st.key, uid.clone());
        let marker = self.db(move |s| s.set_read_marker(key, &who, seq)).await?;
        // Sent under the room's lock, so that two devices moving the marker
        // at once cannot have their lines overtake each other, and so that
        // a CONV line agrees with them (3.6).
        if let Some(marker) = marker.filter(|m| m.moved) {
            // After the marker is stored: a SYNC that read the markers
            // before this reads this one again.
            st.marker_moved = self.markers_moved.fetch_add(1, Ordering::SeqCst) + 1;
            let line = OutLine::new(ServerMessage::new(ServerLine::Read {
                conv: st.name_for(uid),
                seq: marker.seq,
            }));
            if let Some(user) = self.reg().users.get(uid).cloned() {
                user.send_except(&line, reply.handle.id());
            }
        }
        Ok(Some(OkResponse::new()))
    }

    /// TYPING (8.1): passes `@from=<uid> TYPING <conv>` on to the other
    /// members' connections. Not stored.
    ///
    /// The checks are those of MSG (5.3), since typing announces one. Each
    /// connection has at most one TYPING per conversation passed on every
    /// `limits.typing_interval_ms`; those in between get `OK` too, since a
    /// typing notification lasts 6 seconds anyway.
    ///
    /// Blocks do not apply in rooms (5.7). M5a: in direct conversations,
    /// neither side may send TYPING while one has blocked the other
    /// ([`is_blocked`](Self::is_blocked)).
    pub(super) async fn typing(&self, uid: &Uid, reply: &Reply, conv: Conv) -> Outcome {
        let room = match conv {
            Conv::Room(room) => room,
            // Guests have no direct conversations (4.2).
            Conv::Uid(_) if uid.is_guest() => {
                return Err(fail(ErrorCode::NotFound, "no such conversation"));
            }
            // M5a: direct conversations.
            Conv::Uid(_) => return Err(not_supported()),
        };
        let st = self.lock_room(&room).await?;
        let member = st.is_member(uid);
        let info = room_of(&st)?;
        check_read(info, self.asker(uid, member))?;
        if !member {
            return Err(fail(ErrorCode::Forbidden, "join the room first"));
        }
        if uid.is_guest() && !info.settings.guests.allows_write() {
            return Err(fail(ErrorCode::Forbidden, "guests may not send here"));
        }
        let pass = self
            .reg()
            .conns
            .get_mut(&reply.handle.id())
            .is_some_and(|c| c.may_type(&st.id, self.typing_interval));
        if pass {
            let line = OutLine::new(ServerMessage::new(ServerLine::Typing {
                from: uid.clone(),
                conv: Conv::Room(info.room.clone()),
            }));
            // Under the room's lock, so that it cannot overtake a message
            // from the same user, which ends it (8.1).
            for (who, user) in &st.members {
                if who != uid {
                    user.send(&line);
                }
            }
        }
        Ok(Some(OkResponse::new()))
    }

    /// NAME (8.2): sets or clears the display name, and sends
    /// `@from=<uid> NAME [<name>]` to every connection that shares a
    /// conversation with the user, and to the user's other connections.
    /// An identity's is stored; a guest's lasts as long as its session.
    pub(super) async fn name(&self, uid: &Uid, reply: &Reply, name: String) -> Outcome {
        // One NAME at a time, so that every connection gets the names in
        // the order they were stored.
        let _names = self.names_lock.lock().await;
        if uid.is_guest() {
            if let Some(session) = self.reg().sessions.get_mut(uid) {
                session.display_name = name.clone();
            }
        } else {
            let (who, text) = (uid.clone(), name.clone());
            self.db(move |s| s.set_display_name(&who, &text)).await?;
        }
        let line = OutLine::new(ServerMessage::new(ServerLine::Name {
            from: uid.clone(),
            name,
        }));
        let Some(me) = self.reg().users.get(uid).cloned() else {
            return Ok(Some(OkResponse::new()));
        };
        let mut people: BTreeMap<Uid, Arc<UserEntry>> = BTreeMap::new();
        for conv in me.convs() {
            let st = conv.lock().await;
            if st.dropped || !st.is_member(uid) {
                continue;
            }
            for (who, user) in &st.members {
                people.entry(who.clone()).or_insert_with(|| user.clone());
            }
        }
        people.insert(uid.clone(), me);
        for (who, user) in people {
            if who == *uid {
                user.send_except(&line, reply.handle.id());
            } else {
                user.send(&line);
            }
        }
        Ok(Some(OkResponse::new()))
    }

    /// The display names of those of `uids` that have one (8.2): stored for
    /// identities, in the session for guests.
    async fn display_names(&self, uids: Vec<Uid>) -> Result<HashMap<Uid, String>, Fail> {
        let (guests, identities): (Vec<Uid>, Vec<Uid>) = uids.into_iter().partition(Uid::is_guest);
        let mut names = if identities.is_empty() {
            HashMap::new()
        } else {
            self.db(move |s| s.display_names(&identities)).await?
        };
        let reg = self.reg();
        for guest in guests {
            if let Some(session) = reg.sessions.get(&guest)
                && !session.display_name.is_empty()
            {
                names.insert(guest, session.display_name.clone());
            }
        }
        Ok(names)
    }

    /// MEMBERS (8.3): one `MEMBER` line per member, in uid order. It needs
    /// permission to read the room (7.2).
    pub(super) async fn members(&self, uid: &Uid, reply: &Reply, room: &Room) -> Outcome {
        let (room, rows): (Room, Vec<(Uid, Role)>) = {
            let st = self.lock_room(room).await?;
            let info = room_of(&st)?;
            check_read(info, self.asker(uid, st.is_member(uid)))?;
            let rows = st
                .members
                .keys()
                .map(|m| {
                    (
                        m.clone(),
                        info.roles.get(m).copied().unwrap_or(Role::Member),
                    )
                })
                .collect();
            (info.room.clone(), rows)
        };
        let mut names = self
            .display_names(rows.iter().map(|(m, _)| m.clone()).collect())
            .await?;
        let lines: Vec<ServerLine> = {
            let reg = self.reg();
            rows.into_iter()
                .map(|(member, role)| {
                    let presence = if member.is_guest() || reg.presence.is_online(&member) {
                        Presence::Online
                    } else {
                        Presence::Offline
                    };
                    let name = names.remove(&member).unwrap_or_default();
                    ServerLine::Member {
                        room: room.clone(),
                        uid: member,
                        role,
                        presence,
                        name,
                    }
                })
                .collect()
        };
        if !self.reply_all(reply, lines).await {
            return Ok(None);
        }
        Ok(Some(OkResponse::new()))
    }

    /// WHOIS (8.3). A user the server does not know, and a guest whose
    /// session has ended, get `not-found`.
    pub(super) async fn whois(&self, reply: &Reply, target: Uid) -> Outcome {
        let not_found = || fail(ErrorCode::NotFound, "no such user");
        let name = if target.is_guest() {
            let reg = self.reg();
            match reg.sessions.get(&target) {
                Some(session) if !session.ending => session.display_name.clone(),
                _ => return Err(not_found()),
            }
        } else {
            let who = target.clone();
            match self.db(move |s| s.identity(&who)).await? {
                Some(record) => record.display_name,
                None => return Err(not_found()),
            }
        };
        reply.line(ServerLine::User {
            presence: self.presence_of(&target),
            uid: target,
            name,
        });
        Ok(Some(OkResponse::new()))
    }

    /// BLOCK (5.7). Only identities get here (13). The account's other
    /// connections get `BLOCK <target>`.
    pub(super) async fn block(&self, uid: &Uid, reply: &Reply, target: BlockTarget) -> Outcome {
        let user = self.pin(uid);
        let result = async {
            let _blocks = user.blocks.lock().await;
            let (who, max, now) = (uid.clone(), self.config.limits.max_blocks, self.now());
            let stored = target.clone();
            if !self
                .db(move |s| s.add_block(&who, &stored, max, now))
                .await?
            {
                return Err(fail(ErrorCode::Forbidden, "too many blocks"));
            }
            let line = OutLine::new(ServerMessage::new(ServerLine::Block { target }));
            user.send_except(&line, reply.handle.id());
            Ok(Some(OkResponse::new()))
        }
        .await;
        self.unpin(uid, user);
        result
    }

    /// UNBLOCK (5.7). Removing a block the account does not have is not an
    /// error. The account's other connections get `UNBLOCK <target>`.
    pub(super) async fn unblock(&self, uid: &Uid, reply: &Reply, target: BlockTarget) -> Outcome {
        let user = self.pin(uid);
        let result = async {
            let _blocks = user.blocks.lock().await;
            let (who, stored) = (uid.clone(), target.clone());
            self.db(move |s| s.remove_block(&who, &stored)).await?;
            let line = OutLine::new(ServerMessage::new(ServerLine::Unblock { target }));
            user.send_except(&line, reply.handle.id());
            Ok(Some(OkResponse::new()))
        }
        .await;
        self.unpin(uid, user);
        result
    }

    /// BLOCKS (5.7): one `BLOCK <target>` line per block, then `OK`, all
    /// queued while no BLOCK or UNBLOCK line can be, so that they cover
    /// every one sent to the connection before them.
    pub(super) async fn blocks(&self, uid: &Uid, reply: &Reply) -> Outcome {
        let user = self.pin(uid);
        let result = async {
            let _blocks = user.blocks.lock().await;
            let who = uid.clone();
            let blocks = self.db(move |s| s.blocks(&who)).await?;
            let lines = blocks
                .into_iter()
                .map(|target| ServerLine::Block { target })
                .collect();
            if self.reply_all(reply, lines).await {
                reply.line(OkResponse::new());
            }
            Ok(None)
        }
        .await;
        self.unpin(uid, user);
        result
    }

    /// Whether the identity `by` has blocked `uid` (5.7), by identity or by
    /// domain. Guests are never blocked, and never block.
    ///
    /// Blocks do nothing in rooms. M5a: neither side may send messages or
    /// TYPING in a direct conversation while one has blocked the other,
    /// and the blocked person cannot start one. M8: mentions and replies
    /// from someone blocked are not notable (9.2).
    pub(super) async fn is_blocked(&self, by: &Uid, uid: &Uid) -> Result<bool, StoreError> {
        if !by.is_identity() || !uid.is_identity() {
            return Ok(false);
        }
        let (by, uid) = (by.clone(), uid.clone());
        self.db(move |s| s.is_blocked(&by, &uid)).await
    }

    /// Queues the lines of a response that may be longer than the room the
    /// network layer keeps for one, in chunks, as SYNC does. Returns
    /// `false` if the connection went away meanwhile.
    async fn reply_all(&self, reply: &Reply, lines: Vec<ServerLine>) -> bool {
        let chunk = self.config.limits.reply_lines().saturating_sub(1).max(1);
        for (n, line) in lines.into_iter().enumerate() {
            if n > 0 && n % chunk == 0 && !self.wait_for_reply_room(&reply.handle).await {
                return false;
            }
            reply.line(line);
        }
        true
    }
}
