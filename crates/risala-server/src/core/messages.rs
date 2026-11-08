//! Messages with replies, edits and reactions (5.3), DELETE (5.4),
//! RELATED (7.3), retention (7.5), ADMIN PURGE (10.4) and UNREGISTER
//! `purge=yes` (4.8).
//!
//! # Whose message it is
//!
//! Only the author may edit a message, and the author may delete it even
//! where they can no longer read (5.3, 5.4). An identity is the author of
//! every message whose `from` it is. A guest uid says nothing about who
//! someone is over time (4.2), so a guest is the author only of what it
//! sent in its current session: see [`Inner::is_author`]. ADMIN PURGE of a
//! guest uid still covers everything sent under the name (10.4).

use std::num::NonZeroU64;
use std::sync::Arc;

use risala_proto::command::Command;
use risala_proto::error::ErrorCode;
use risala_proto::names::{Conv, Id, Seq, Uid};
use risala_proto::server::OkResponse;
use risala_proto::time::Timestamp;
use risala_proto::types::{Cid, DEFAULT_LIMIT, FileUrl, MAX_REACTION, Relation, Role};

use super::Inner;
use super::commands::{Fail, Outcome, Reply, check_read, fail, not_supported, room_of};
use super::state::{ConvState, RoomInfo};
use crate::handler::ConnId;
use crate::store::{Appended, EventKind, NewEvent, RelatedQuery, StoredEvent};

fn no_message() -> Fail {
    fail(ErrorCode::NotFound, "no such message")
}

/// Whether `uid` may delete anyone's messages in the room (6.3): its
/// owners and moderators, members or not, and operators (10).
fn moderates(info: &RoomInfo, uid: &Uid, operator: bool) -> bool {
    operator || matches!(info.roles.get(uid), Some(Role::Owner | Role::Mod))
}

impl Inner {
    /// Handles DELETE, RELATED and `ADMIN PURGE`.
    pub(super) async fn messages(
        self: &Arc<Self>,
        uid: &Uid,
        reply: &Reply,
        command: Command,
    ) -> Outcome {
        match command {
            Command::Delete { conv, seq } => self.delete(uid, conv, seq).await,
            Command::Related {
                conv,
                first,
                last,
                after,
                limit,
            } => {
                let query = RelatedQuery {
                    first,
                    last,
                    after: after.unwrap_or(0),
                    limit: limit.map_or(DEFAULT_LIMIT, NonZeroU64::get),
                };
                self.related(uid, reply, conv, query).await
            }
            _ => Err(not_supported()),
        }
    }

    /// Since when `uid`'s messages count as its own, or `None` for all of
    /// them. The one place that decides whose message it is: see the
    /// module documentation.
    fn own_since(&self, uid: &Uid) -> Option<Timestamp> {
        if uid.is_identity() {
            return None;
        }
        // A guest with no session sends nothing: nothing is its own.
        Some(
            self.reg()
                .sessions
                .get(uid)
                .map_or(Timestamp::MAX, |s| s.started),
        )
    }

    /// Whether `uid` wrote `event` (5.3, 5.4).
    pub(super) fn is_author(&self, uid: &Uid, event: &StoredEvent) -> bool {
        event.from == *uid && self.own_since(uid).is_none_or(|since| event.t >= since)
    }

    /// MSG (5.3), in rooms, with a `reply`, `edit` or `react` tag.
    pub(super) async fn msg(
        &self,
        uid: &Uid,
        conv: Conv,
        text: String,
        relation: Option<Relation>,
        file: Option<FileUrl>,
        cid: Option<Cid>,
    ) -> Outcome {
        // M5a: direct conversations. M8: files.
        let Conv::Room(room) = conv else {
            return Err(not_supported());
        };
        if file.is_some() {
            return Err(not_supported());
        }
        let mut guard = self.lock_room(&room).await?;
        let st = &mut *guard;

        // A message that was already sent gets its seq again (7.6), before
        // any other check: the sender may have left since, or the room may
        // have become private or closed to guests, or the target may have
        // been deleted (PLAN.md 5, item 14).
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
        // Reactions too (6.3).
        if uid.is_guest() && !info.settings.guests.allows_write() {
            return Err(fail(ErrorCode::Forbidden, "guests may not send here"));
        }
        match relation {
            None => {}
            Some(Relation::Reply(target)) => {
                self.check_target(st, target).await?;
            }
            Some(Relation::Edit(target)) => {
                let target = self.check_target(st, target).await?;
                if !self.is_author(uid, &target) {
                    return Err(fail(
                        ErrorCode::Forbidden,
                        "only the author may edit a message",
                    ));
                }
            }
            Some(Relation::React(target)) => {
                self.check_target(st, target).await?;
                // The parser refuses longer ones already.
                if text.len() > MAX_REACTION {
                    return Err(fail(ErrorCode::TooLong, "a reaction is at most 64 bytes"));
                }
                // The same reaction again is the same event (5.3).
                let (key, from, reaction) = (st.key, uid.clone(), text.clone());
                let since = self.own_since(uid);
                let earlier = self
                    .db(move |s| s.reaction(key, &from, target, &reaction, since))
                    .await?;
                if let Some(seq) = earlier {
                    return Ok(Some(OkResponse::new().with_seq(seq)));
                }
            }
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
    /// Returns it.
    async fn check_target(&self, st: &ConvState, target: Seq) -> Result<StoredEvent, Fail> {
        let key = st.key;
        let event = self.db(move |s| s.event(key, target)).await?;
        match event {
            Some(e) if !e.deleted && e.is_plain_message() => Ok(e),
            _ => Err(no_message()),
        }
    }

    /// DELETE (5.4), in rooms.
    async fn delete(&self, uid: &Uid, conv: Conv, target: Seq) -> Outcome {
        // M5a: direct conversations. Guests never get here with one (4.2).
        let Conv::Room(room) = conv else {
            return Err(not_supported());
        };
        let mut guard = self.lock_room(&room).await?;
        let st = &mut *guard;
        let key = st.key;
        // M5a: ENC events too.
        let event = self
            .db(move |s| s.event(key, target))
            .await?
            .filter(|e| matches!(e.kind, EventKind::Msg { .. }) && !e.deleted);
        // Authors may delete their own messages even where they can no
        // longer read, so this comes before the reading rules (5.4).
        let own = event.as_ref().is_some_and(|e| self.is_author(uid, e));
        if !own {
            let info = room_of(st)?;
            check_read(info, self.asker(uid, st.is_member(uid)))?;
            if event.is_none() {
                return Err(no_message());
            }
            let operator = uid.is_identity() && self.is_operator(uid);
            if !moderates(info, uid, operator) {
                return Err(fail(
                    ErrorCode::Forbidden,
                    "only moderators may delete others' messages",
                ));
            }
        }
        let event = NewEvent {
            t: self.now(),
            from: uid.clone(),
            kind: EventKind::Delete { target },
            cid: None,
        };
        let (_, event) = self.append(st, event).await?;
        Self::broadcast_event(st, &event);
        Ok(Some(OkResponse::new().with_seq(event.seq)))
    }

    /// RELATED (7.3), in rooms.
    async fn related(
        &self,
        uid: &Uid,
        reply: &Reply,
        conv: Conv,
        mut query: RelatedQuery,
    ) -> Outcome {
        // M5a: direct conversations. Guests never get here with one (4.2).
        let Conv::Room(room) = conv else {
            return Err(not_supported());
        };
        let (key, id) = {
            let st = self.lock_room(&room).await?;
            check_read(room_of(&st)?, self.asker(uid, st.is_member(uid)))?;
            (st.key, st.id.clone())
        };
        query.limit = query.limit.min(self.config.limits.max_page).max(1);
        let page = self.db(move |s| s.related(key, query)).await?;
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
