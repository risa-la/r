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
//!
//! # Retention
//!
//! [`Hub::expire_every`] expires old events in the background, and
//! [`Hub::expire_now`] and [`Inner::expire_all`] run it at once, as after a
//! change to the server's period (10.6). SET of a room's `retention` holds
//! the room's lock, and calls [`Inner::expire_conv`] instead (6.2).
//! Expiry takes each room's lock while it removes events, a batch at a
//! time, so that a DELETE or reply never meets a target that vanishes
//! between its check and its event.

use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::Duration;

use risala_proto::command::{AdminCommand, Command};
use risala_proto::error::ErrorCode;
use risala_proto::names::{Conv, Id, Seq, Uid};
use risala_proto::server::OkResponse;
use risala_proto::time::Timestamp;
use risala_proto::types::{Cid, DEFAULT_LIMIT, FileUrl, MAX_REACTION, Relation, Role};

use super::commands::{
    Fail, Outcome, Reply, check_read, fail, gone_is_not_found, not_supported, room_of,
};
use super::moderation::{may_send_messages, only_moderators_send};
use super::state::{ConvState, RoomInfo};
use super::{Hub, Inner};
use crate::handler::ConnId;
use crate::store::{
    Appended, EventKind, NewEvent, PurgeQuery, RelatedQuery, RoomSettings, StoreError, StoredEvent,
};

/// How often [`Hub::expire_every`] runs in `risalad` (7.5). Periods are
/// whole days, so an event outlives its period by at most this.
pub const EXPIRE_PERIOD: Duration = Duration::from_secs(60 * 60);

/// The most events one store transaction expires, or deletes in a purge,
/// so that transactions stay short and other commands get the room's lock
/// in between.
const BATCH: usize = 500;

const DAY: Duration = Duration::from_secs(24 * 60 * 60);

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
            Command::Delete { conv, seq, id } => self.delete(uid, conv, seq, id).await,
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
            Command::Admin(AdminCommand::Purge { uid: target, hours }) => {
                self.admin_purge(uid, &target, hours).await
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
        // An announcement room: plain members may only react (6.2).
        if !matches!(relation, Some(Relation::React(_)))
            && !may_send_messages(info, self.asker(uid, member))
        {
            return Err(only_moderators_send());
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
    async fn delete(&self, uid: &Uid, conv: Conv, target: Seq, id: Option<Id>) -> Outcome {
        // M5a: direct conversations. Guests never get here with one (4.2).
        let Conv::Room(room) = conv else {
            return Err(not_supported());
        };
        let mut guard = self.lock_room(&room).await?;
        let st = &mut *guard;
        // A seq meant for an older room of the same name names nothing
        // here (5.4).
        if id.is_some_and(|id| id != st.id) {
            return Err(no_message());
        }
        let key = st.key;
        // M5a: ENC events too.
        let event = self
            .db(move |s| s.event(key, target))
            .await?
            .filter(|e| matches!(e.kind, EventKind::Msg { .. }));
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
        // Already deleted: the DELETE that did it, so that resending is safe
        // (5.4). An edit or reaction may have gone with its message.
        if let Some(event) = event.filter(|e| e.deleted) {
            let parent = match &event.kind {
                EventKind::Msg {
                    relation: Some(Relation::Edit(p) | Relation::React(p)),
                    ..
                } => Some(*p),
                _ => None,
            };
            let found = self
                .db(move |s| match s.delete_of(key, target)? {
                    Some(seq) => Ok(Some(seq)),
                    None => parent.map_or(Ok(None), |p| s.delete_of(key, p)),
                })
                .await?;
            return match found {
                Some(seq) => Ok(Some(OkResponse::new().with_seq(seq))),
                // Deleted with no DELETE left to name, for example one that
                // expired since (7.5).
                None => Err(no_message()),
            };
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
        let page = self
            .db(move |s| s.related(key, query))
            .await
            .map_err(gone_is_not_found)?;
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

    /// `ADMIN PURGE` (10.4).
    async fn admin_purge(&self, uid: &Uid, target: &Uid, hours: Option<NonZeroU64>) -> Outcome {
        if !self.is_operator(uid) {
            return Err(fail(ErrorCode::Forbidden, "operators only"));
        }
        let since = hours.and_then(|h| {
            let secs = h.get().saturating_mul(60 * 60);
            self.now().checked_sub(Duration::from_secs(secs))
        });
        let deleted = self.purge(target, uid, since).await?;
        tracing::info!(operator = %uid, %target, deleted, "purged messages");
        Ok(Some(OkResponse::new().with_deleted(deleted)))
    }

    /// Deletes the messages `author` sent, in every conversation, as DELETE
    /// does (5.4), with `by` as the `from` of each DELETE event: all of
    /// them, or with `since`, those sent at or after it. Returns how many
    /// DELETE events were recorded. For ADMIN PURGE (10.4), and UNREGISTER
    /// `purge=yes` (4.8), where `by` is `author`.
    ///
    /// Takes each room's lock in turn, a batch at a time, so the caller
    /// must hold none. In each room, it deletes only what was there when it
    /// started, so it ends even if the author keeps sending.
    ///
    /// M5a: direct conversations.
    pub(super) async fn purge(
        &self,
        author: &Uid,
        by: &Uid,
        since: Option<Timestamp>,
    ) -> Result<u64, StoreError> {
        let who = author.clone();
        let rooms = self.db(move |s| s.authored_rooms(&who, since)).await?;
        let mut count = 0;
        for (key, room) in rooms {
            let Some(entry) = self.room_entry(&room) else {
                continue;
            };
            let mut upto = None;
            loop {
                let mut st = entry.lock().await;
                // Dropped meanwhile, perhaps created again (10.4): its
                // messages are gone already.
                if st.dropped || st.key != key {
                    break;
                }
                let Some(upto) = *upto.get_or_insert(st.head) else {
                    break;
                };
                let query = PurgeQuery {
                    author: author.clone(),
                    since,
                    upto,
                    by: by.clone(),
                    now: self.now(),
                    max: BATCH,
                };
                let deletes = self.db(move |s| s.purge(key, &query)).await?;
                let Some(last) = deletes.last() else {
                    break;
                };
                st.head = Some(last.seq);
                count += deletes.len() as u64;
                for event in &deletes {
                    Self::broadcast_event(&st, event);
                }
            }
        }
        Ok(count)
    }

    /// The time before which a room's events expire (7.5), or `None` if
    /// they never do: the shorter of the server's period and the room's.
    fn expiry_cutoff(&self, settings: &RoomSettings) -> Option<Timestamp> {
        let days = settings.retention.effective(self.settings().retention)?;
        let period = DAY.checked_mul(days.get())?;
        self.now().checked_sub(period)
    }

    /// Expires one batch of a conversation's events whose lock the caller
    /// holds. Returns how many.
    async fn expire_batch(&self, st: &ConvState) -> Result<u64, StoreError> {
        let Some(info) = st.room_info() else {
            return Ok(0);
        };
        if st.dropped || st.head.is_none() {
            return Ok(0);
        }
        let Some(before) = self.expiry_cutoff(&info.settings) else {
            return Ok(0);
        };
        let key = st.key;
        self.db(move |s| s.expire(key, before, BATCH)).await
    }

    /// Expires a conversation's old events now (7.5), holding the lock the
    /// caller holds. For SET of a room's `retention` (6.2), which applies
    /// to events already stored. Returns how many expired.
    pub(super) async fn expire_conv(&self, st: &ConvState) -> Result<u64, StoreError> {
        let mut total = 0;
        loop {
            let n = self.expire_batch(st).await?;
            total += n;
            if n < BATCH as u64 {
                return Ok(total);
            }
        }
    }

    /// Expires old events in every conversation now (7.5): what the
    /// background task does, and what a change to the server's period
    /// calls for (10.6). The caller must hold no conversation's lock: each
    /// is taken in turn, a batch at a time. Returns how many expired. A
    /// conversation that fails is logged, the others still expire, and
    /// the first error is returned.
    pub(super) async fn expire_all(&self) -> Result<u64, StoreError> {
        let entries: Vec<_> = self
            .rooms
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect();
        let (mut total, mut first_error) = (0, None);
        for entry in entries {
            loop {
                let st = entry.lock().await;
                match self.expire_batch(&st).await {
                    Ok(n) => {
                        total += n;
                        if n < BATCH as u64 {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::error!(conv = %st.id, "expiring events failed: {e}");
                        first_error.get_or_insert(e);
                        break;
                    }
                }
            }
        }
        match first_error {
            Some(e) => Err(e),
            None => Ok(total),
        }
    }
}

impl Hub {
    /// Expires old events in every conversation now (7.5), under the
    /// server's retention period and each room's, and returns how many.
    /// [`expire_every`](Self::expire_every) does this in the background.
    pub async fn expire_now(&self) -> Result<u64, StoreError> {
        self.inner.expire_all().await
    }

    /// Runs [`expire_now`](Self::expire_now) at once and then every
    /// `period`, until the future is dropped. Failures are logged.
    pub async fn expire_every(self, period: Duration) {
        let mut tick = tokio::time::interval(period);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            match self.expire_now().await {
                Ok(0) => {}
                Ok(n) => tracing::info!(events = n, "expired old events"),
                // Logged per conversation already.
                Err(_) => {}
            }
        }
    }
}
