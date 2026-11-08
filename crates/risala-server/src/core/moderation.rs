//! Room settings (6.2), roles (6.3) and moderation (6.4): SET, ROLE,
//! ROLES, INVITE, KICK, BAN, UNBAN and BANS.
//!
//! # Permissions
//!
//! [`rights`] gives what someone may do in a room as a [`Role`]: the role
//! they hold, or `owner` for a server operator (Section 10). Roles belong
//! to the identity, not to its membership (6.3), so someone who holds
//! `owner` or `mod` keeps its rights after leaving. [`check_rights`] adds
//! the visibility rule of 6.1: a room you cannot see is `ERR not-found`.
//! Other areas may reuse both, for example DELETE (5.4), where moderators,
//! owners and operators may delete anyone's message:
//! `rights(info, asker).can_moderate()`.
//!
//! # Changes
//!
//! Each command appends its event, which applies its effects in the store
//! in one transaction (see [`crate::store::Store::append`]), then changes
//! the room's state in memory to match and sends the event to its members,
//! all under the room's lock. A KICK or BAN reaches its target before the
//! target stops receiving the room (6.4).

use std::ops::Bound;
use std::sync::Arc;

use risala_proto::command::Command;
use risala_proto::error::ErrorCode;
use risala_proto::names::{Room, Uid};
use risala_proto::server::{Event, EventBody, OkResponse, ServerMessage};
use risala_proto::types::{GuestAccess, Role, RoomRetention, RoomSetting};

use super::Inner;
use super::commands::{
    Asker, Fail, Outcome, Reply, check_read, fail, not_found, not_supported, room_of, visible,
};
use super::state::{ConvGuard, ConvState, RoomInfo};
use crate::handler::OutLine;
use crate::store::{EventKind, NewEvent, StoredEvent};

/// What `a` may do in a room (6.3), as a role: `owner` for a server
/// operator (Section 10), else the role it holds there, whether or not it
/// is a member, else `member`. Guests are always `member` (4.2).
pub(super) fn rights(info: &RoomInfo, a: Asker<'_>) -> Role {
    if a.uid.is_guest() {
        return Role::Member;
    }
    if a.operator {
        return Role::Owner;
    }
    info.roles.get(a.uid).copied().unwrap_or(Role::Member)
}

/// Checks that `a` may do what takes `needed` in a room (6.3), and returns
/// its rights. A room it cannot see is `ERR not-found` (6.1), so private
/// rooms stay hidden; one it can see is `ERR forbidden` without the role.
pub(super) fn check_rights(info: &RoomInfo, a: Asker<'_>, needed: Role) -> Result<Role, Fail> {
    if !visible(info, a) {
        return Err(not_found());
    }
    let have = rights(info, a);
    if have < needed {
        let message = match needed {
            Role::Owner => "only owners may do that",
            _ => "only moderators and owners may do that",
        };
        return Err(fail(ErrorCode::Forbidden, message));
    }
    Ok(have)
}

/// Checks that someone with rights `have` may KICK or BAN someone with
/// rights `target` (6.3): moderators act only on plain members, while
/// owners and operators act on anyone. A target who is an operator counts
/// as an owner, since operators have owner rights in every room.
fn check_outranks(have: Role, target: Role) -> Result<(), Fail> {
    if have == Role::Owner || target == Role::Member {
        return Ok(());
    }
    Err(fail(
        ErrorCode::Forbidden,
        "moderators may act only on plain members",
    ))
}

/// The role a SET of `setting` takes (6.2), or the error for a key that
/// nobody may set.
/// Refuses KICK or BAN of yourself as the room's only owner, which would
/// leave it with none (6.3, PLAN.md 5, item 31).
fn check_not_last_owner(info: &RoomInfo, asker: &Uid, target: &Uid) -> Result<(), Fail> {
    let owners = info.roles.values().filter(|r| **r == Role::Owner).count();
    if asker == target && info.roles.get(target) == Some(&Role::Owner) && owners == 1 {
        return Err(fail(ErrorCode::LastOwner, "you are the only owner"));
    }
    Ok(())
}

fn needed_for(setting: &RoomSetting) -> Result<Role, Fail> {
    match setting {
        RoomSetting::Topic(_) => Ok(Role::Mod),
        RoomSetting::Public(_) | RoomSetting::Guests(_) | RoomSetting::Retention(_) => {
            Ok(Role::Owner)
        }
        // Only INIT turns encryption on, and nothing turns it off.
        RoomSetting::E2ee(_) => Err(fail(ErrorCode::Forbidden, "e2ee is set by INIT only")),
        // M5a: `ERR encrypted` in an encrypted room, where a COMMIT
        // changes it. No room is encrypted yet.
        RoomSetting::History(_) => Err(fail(
            ErrorCode::Forbidden,
            "history exists only in encrypted rooms",
        )),
        RoomSetting::Other { .. } => Err(fail(ErrorCode::NotSupported, "unknown setting")),
    }
}

impl Inner {
    /// Handles SET, ROLE, ROLES, INVITE, KICK, BAN, UNBAN and BANS.
    pub(super) async fn moderation(
        self: &Arc<Self>,
        uid: &Uid,
        reply: &Reply,
        command: Command,
    ) -> Outcome {
        match command {
            Command::Set { room, setting } => self.set(uid, &room, setting).await,
            Command::Role {
                room,
                uid: target,
                role,
            } => self.role(uid, &room, target, role).await,
            Command::Roles { room } => self.roles(uid, reply, &room).await,
            Command::Invite { room, uid: target } => self.invite(uid, &room, target).await,
            Command::Kick {
                room,
                uid: target,
                reason,
            } => self.kick(uid, &room, target, reason).await,
            Command::Ban {
                room,
                uid: target,
                reason,
            } => self.ban(uid, &room, target, reason).await,
            Command::Unban { room, uid: target } => self.unban(uid, &room, target).await,
            Command::Bans { room } => self.bans(uid, reply, &room).await,
            _ => Err(not_supported()),
        }
    }

    /// Appends an event from `from` to a room whose lock the caller holds.
    /// Its effects are stored with it; the caller changes the state in
    /// memory to match, and sends it.
    async fn record(
        &self,
        st: &mut ConvState,
        from: &Uid,
        kind: EventKind,
    ) -> Result<StoredEvent, Fail> {
        let event = NewEvent {
            t: self.now(),
            from: from.clone(),
            kind,
            cid: None,
        };
        let (_, event) = self.append(st, event).await?;
        Ok(event)
    }

    /// Sends a room's event to the connections of `target` if it is not a
    /// member, which the room's own fan-out does not reach: the INVITE to
    /// its invitee, the BAN to its target (6.4). For them it is a
    /// notification, and does not make them a member.
    fn notify(&self, st: &ConvState, event: &StoredEvent, target: &Uid) {
        if st.is_member(target) {
            return;
        }
        let Some(info) = st.room_info() else {
            return;
        };
        let line = match event.to_event(info.room.clone(), &st.id) {
            Ok(line) => OutLine::new(ServerMessage::new(line)),
            Err(e) => {
                tracing::error!(room = %info.room, "cannot send an event: {e}");
                return;
            }
        };
        if let Some(user) = self.reg().users.get(target).cloned() {
            user.send(&line);
        }
    }

    /// SET (6.2).
    async fn set(&self, uid: &Uid, room: &Room, setting: RoomSetting) -> Outcome {
        let mut guard = self.lock_room(room).await?;
        let st = &mut *guard;
        let info = room_of(st)?;
        let a = self.asker(uid, st.is_member(uid));
        if !visible(info, a) {
            return Err(not_found());
        }
        let needed = needed_for(&setting)?;
        // M5a: SET of `public` or `guests` in an encrypted room gets
        // `ERR forbidden` (6.2).
        check_rights(info, a, needed)?;
        if let RoomSetting::Retention(RoomRetention::Days(days)) = &setting
            && let Some(server) = self.settings().retention.days()
            && *days > server
        {
            return Err(fail(
                ErrorCode::Forbidden,
                "longer than the server's retention period",
            ));
        }

        // Setting the value a room already has records nothing (PLAN.md 5,
        // item 31).
        if info.settings.to_settings().contains(&setting) {
            return Ok(Some(OkResponse::new()));
        }

        let event = self
            .record(st, uid, EventKind::Set(setting.clone()))
            .await?;
        if let Some(info) = st.room_info_mut() {
            info.settings.apply(&setting);
        }
        Self::broadcast_event(st, &event);
        match setting {
            // Guests already in the room leave it, each with a PART (6.2).
            RoomSetting::Guests(GuestAccess::None) => self.part_guests(st).await,
            // `guests read` needs nothing more: MSG and TYPING check the
            // setting as they come.
            // A shorter period applies to stored events at once (6.2,
            // 7.5). The setting stands even if this fails; the hourly
            // run catches up.
            RoomSetting::Retention(_) => {
                if let Err(e) = self.expire_conv(st).await {
                    tracing::error!(conv = %st.id, "expiring events failed: {e}");
                }
            }
            _ => {}
        }
        Ok(Some(OkResponse::new().with_seq(event.seq)))
    }

    /// Removes every guest from a room whose lock the caller holds,
    /// recording a PART for each (6.2). Their sessions and other rooms are
    /// not affected.
    async fn part_guests(&self, st: &mut ConvState) {
        let guests: Vec<Uid> = st
            .members
            .keys()
            .filter(|m| m.is_guest())
            .cloned()
            .collect();
        for guest in guests {
            let part = NewEvent {
                t: self.now(),
                from: guest.clone(),
                kind: EventKind::Part {
                    reason: String::new(),
                },
                cid: None,
            };
            match self.append(st, part).await {
                Ok((_, event)) => Self::broadcast_event(st, &event),
                // The guest leaves either way, as when its session ends.
                // Its PART is recorded at the next start (4.2).
                Err(e) => tracing::error!(conv = %st.id, "storing a guest's PART failed: {e}"),
            }
            st.remove_member(&guest);
        }
    }

    /// ROLE (6.3).
    async fn role(&self, uid: &Uid, room: &Room, target: Uid, role: Role) -> Outcome {
        let mut guard = self.lock_room(room).await?;
        let st = &mut *guard;
        let info = room_of(st)?;
        check_rights(info, self.asker(uid, st.is_member(uid)), Role::Owner)?;
        let held = info.roles.get(&target).copied();
        if !st.is_member(&target) && held.is_none() {
            return Err(fail(
                ErrorCode::NotFound,
                "not a member and holds no role here",
            ));
        }
        if target.is_guest() {
            return Err(fail(ErrorCode::Forbidden, "guests cannot hold roles"));
        }
        let owners = info.roles.values().filter(|r| **r == Role::Owner).count();
        if target == *uid && held == Some(Role::Owner) && role != Role::Owner && owners == 1 {
            return Err(fail(ErrorCode::LastOwner, "you are the only owner"));
        }
        // The role they already have records nothing (PLAN.md 5, item 31).
        if held.unwrap_or(Role::Member) == role {
            return Ok(Some(OkResponse::new()));
        }

        let kind = EventKind::Role {
            uid: target.clone(),
            role,
        };
        let event = self.record(st, uid, kind).await?;
        if let Some(info) = st.room_info_mut() {
            match role {
                Role::Member => info.roles.remove(&target),
                role => info.roles.insert(target, role),
            };
        }
        Self::broadcast_event(st, &event);
        Ok(Some(OkResponse::new().with_seq(event.seq)))
    }

    /// How many snapshot lines ROLES and BANS queue at a time: as many as
    /// the room the network layer keeps for a response holds, with the
    /// `OK`.
    fn snapshot_chunk(&self) -> usize {
        self.config.limits.reply_lines().saturating_sub(1).max(1)
    }

    /// Waits, without the room's lock, until the connection has room for
    /// the next chunk of ROLES or BANS, then locks the room again. `None`
    /// if the connection went away, `Some(None)` if the room was dropped
    /// meanwhile: it is gone, and so are its roles and bans.
    async fn next_chunk(&self, reply: &Reply, guard: ConvGuard) -> Option<Option<ConvGuard>> {
        let entry = ConvGuard::mutex(&guard).clone();
        drop(guard);
        if !self.wait_for_reply_room(&reply.handle).await {
            return None;
        }
        let guard = entry.lock_owned().await;
        Some((!guard.dropped).then_some(guard))
    }

    /// ROLES (6.3): the owners and moderators, members or not, for anyone
    /// who may read the room (7.2).
    ///
    /// Each chunk of lines is queued under the room's lock, so that they
    /// agree with the ROLE events the connection receives (3.6): a ROLE
    /// event sent before a line is covered by it. A long list goes in
    /// chunks, each read afresh after the one before, in uid order.
    async fn roles(&self, uid: &Uid, reply: &Reply, room: &Room) -> Outcome {
        let chunk = self.snapshot_chunk();
        let mut guard = self.lock_room(room).await?;
        let mut after: Option<Uid> = None;
        loop {
            let info = room_of(&guard)?;
            check_read(info, self.asker(uid, guard.is_member(uid)))?;
            let from = after.as_ref().map_or(Bound::Unbounded, Bound::Excluded);
            let rest: Vec<(Uid, Role)> = info
                .roles
                .range::<Uid, _>((from, Bound::Unbounded))
                .take(chunk + 1)
                .map(|(holder, role)| (holder.clone(), *role))
                .collect();
            let more = rest.len() > chunk;
            for (holder, role) in rest.into_iter().take(chunk) {
                after = Some(holder.clone());
                reply.line(Event::snapshot(EventBody::Role {
                    room: info.room.clone(),
                    uid: holder,
                    role,
                }));
            }
            if !more {
                return Ok(Some(OkResponse::new()));
            }
            guard = match self.next_chunk(reply, guard).await {
                None => return Ok(None),
                Some(None) => return Ok(Some(OkResponse::new())),
                Some(Some(guard)) => guard,
            };
        }
    }

    /// INVITE (6.4).
    async fn invite(&self, uid: &Uid, room: &Room, target: Uid) -> Outcome {
        let mut guard = self.lock_room(room).await?;
        let st = &mut *guard;
        let info = room_of(st)?;
        check_rights(info, self.asker(uid, st.is_member(uid)), Role::Mod)?;
        if target.is_guest() {
            return Err(fail(ErrorCode::Forbidden, "guests cannot be invited"));
        }
        // An invitation and a ban never coexist (6.4).
        if info.bans.contains(&target) {
            return Err(fail(ErrorCode::Forbidden, "banned; unban first"));
        }
        // M5a: `ERR encrypted` in an encrypted room, where a COMMIT invites.
        // A member needs no invitation, and someone invited already needs
        // no second one: nothing is recorded (6.4).
        if st.is_member(&target) || info.invites.contains(&target) {
            return Ok(Some(OkResponse::new()));
        }

        let kind = EventKind::Invite {
            uid: target.clone(),
        };
        let event = self.record(st, uid, kind).await?;
        if let Some(info) = st.room_info_mut() {
            info.invites.insert(target.clone());
        }
        Self::broadcast_event(st, &event);
        self.notify(st, &event, &target);
        Ok(Some(OkResponse::new().with_seq(event.seq)))
    }

    /// KICK (6.4).
    async fn kick(&self, uid: &Uid, room: &Room, target: Uid, reason: String) -> Outcome {
        let mut guard = self.lock_room(room).await?;
        let st = &mut *guard;
        let info = room_of(st)?;
        let have = check_rights(info, self.asker(uid, st.is_member(uid)), Role::Mod)?;
        // Even if they hold a role: ROLE or BAN takes that (6.4).
        if !st.is_member(&target) {
            return Err(fail(ErrorCode::NotFound, "not a member"));
        }
        check_outranks(have, rights(info, self.asker(&target, true)))?;
        check_not_last_owner(info, uid, &target)?;

        let kind = EventKind::Kick {
            uid: target.clone(),
            reason,
        };
        let event = self.record(st, uid, kind).await?;
        if let Some(info) = st.room_info_mut() {
            info.roles.remove(&target);
        }
        // The target is still a member, so this reaches it too.
        Self::broadcast_event(st, &event);
        st.remove_member(&target);
        Ok(Some(OkResponse::new().with_seq(event.seq)))
    }

    /// BAN (6.4). Works on non-members too. A guest's uid is banned, not
    /// its address (PLAN.md 5, item 30).
    async fn ban(&self, uid: &Uid, room: &Room, target: Uid, reason: String) -> Outcome {
        let mut guard = self.lock_room(room).await?;
        let st = &mut *guard;
        let info = room_of(st)?;
        let member = st.is_member(&target);
        let have = check_rights(info, self.asker(uid, st.is_member(uid)), Role::Mod)?;
        check_outranks(have, rights(info, self.asker(&target, member)))?;
        check_not_last_owner(info, uid, &target)?;
        // BAN of someone already banned, and gone, records nothing and only
        // replaces the reason (PLAN.md 5, item 31). An operator may be in a
        // room they are banned from (6.3), so a member is banned again.
        if info.bans.contains(&target) && !member {
            let conv = st.key;
            self.db(move |s| s.set_room_ban_reason(conv, &target, &reason))
                .await?;
            return Ok(Some(OkResponse::new()));
        }
        // Only someone who could see the room hears of the ban, so that a
        // ban made in advance does not reveal a private room (PLAN.md 5,
        // item 31).
        let could_see = visible(info, self.asker(&target, member));

        let kind = EventKind::Ban {
            uid: target.clone(),
            reason,
        };
        let event = self.record(st, uid, kind).await?;
        if let Some(info) = st.room_info_mut() {
            info.bans.insert(target.clone());
            info.roles.remove(&target);
            info.invites.remove(&target);
        }
        Self::broadcast_event(st, &event);
        if could_see {
            self.notify(st, &event, &target);
        }
        st.remove_member(&target);
        Ok(Some(OkResponse::new().with_seq(event.seq)))
    }

    /// UNBAN (6.4).
    async fn unban(&self, uid: &Uid, room: &Room, target: Uid) -> Outcome {
        let mut guard = self.lock_room(room).await?;
        let st = &mut *guard;
        let info = room_of(st)?;
        check_rights(info, self.asker(uid, st.is_member(uid)), Role::Mod)?;
        if !info.bans.contains(&target) {
            return Err(fail(ErrorCode::NotFound, "not banned"));
        }

        let kind = EventKind::Unban {
            uid: target.clone(),
        };
        let event = self.record(st, uid, kind).await?;
        if let Some(info) = st.room_info_mut() {
            info.bans.remove(&target);
        }
        Self::broadcast_event(st, &event);
        Ok(Some(OkResponse::new().with_seq(event.seq)))
    }

    /// BANS (6.4): the room's bans as snapshot BAN lines.
    ///
    /// Read and queued under the room's lock, a chunk at a time, as ROLES
    /// does, so that the list agrees with the BAN and UNBAN events the
    /// connection receives (3.6).
    async fn bans(&self, uid: &Uid, reply: &Reply, room: &Room) -> Outcome {
        let chunk = self.snapshot_chunk();
        let mut guard = self.lock_room(room).await?;
        let mut after: Option<Uid> = None;
        loop {
            let info = room_of(&guard)?;
            check_rights(info, self.asker(uid, guard.is_member(uid)), Role::Mod)?;
            let key = guard.key;
            let bans = self.db(move |s| s.room_bans(key)).await?;
            let rest: Vec<(Uid, String)> = bans
                .into_iter()
                .filter(|(banned, _)| after.as_ref().is_none_or(|last| banned > last))
                .take(chunk + 1)
                .collect();
            let more = rest.len() > chunk;
            for (banned, reason) in rest.into_iter().take(chunk) {
                after = Some(banned.clone());
                reply.line(Event::snapshot(EventBody::Ban {
                    room: info.room.clone(),
                    uid: banned,
                    reason,
                }));
            }
            if !more {
                return Ok(Some(OkResponse::new()));
            }
            guard = match self.next_chunk(reply, guard).await {
                None => return Ok(None),
                Some(None) => return Ok(Some(OkResponse::new())),
                Some(Some(guard)) => guard,
            };
        }
    }
}

#[cfg(test)]
#[path = "moderation_tests.rs"]
mod tests;
