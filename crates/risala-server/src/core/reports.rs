//! Reports (5.8): REPORT, REPORTS, RESOLVE and `ADMIN REPORTS`, and the
//! ADMIN commands about rooms (10.4): `ADMIN ROOMS` and `ADMIN DROP`.
//! REPORTENC and reports in direct conversations wait for M5a.
//!
//! # Reviewers
//!
//! A report in a room goes to its **reviewers** (5.8): the room's owners
//! and moderators, members or not, and the server's operators
//! ([`Inner::reviewers`]). A report outlives its room (10.4): once the
//! room is dropped, or dropped and created again under the same name with
//! a new id, its operators are its only reviewers.
//!
//! # Order
//!
//! A report is stored and sent, and resolved and RESOLVED sent, holding
//! the [`ReportBook`]'s lock, after the room's lock when the room still
//! exists. REPORTS and ADMIN REPORTS read and queue each chunk of their
//! answer holding it too, so each chunk agrees with the live lines sent
//! before and after it (3.6). Between chunks they hold no lock while they
//! wait for room in the connection's queue, as SYNC does, so a report made
//! meanwhile may come both live and in a later chunk. Reviewers tell
//! reports apart by id.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::num::NonZeroU64;
use std::ops::Bound;
use std::sync::Arc;
use std::time::Duration;

use risala_proto::command::{AdminCommand, Command, RoomPage};
use risala_proto::error::ErrorCode;
use risala_proto::mls::Franking;
use risala_proto::names::{Conv, Id, Room, Seq, Uid};
use risala_proto::server::{ErrResponse, OkResponse, Report, ServerLine, ServerMessage};
use risala_proto::types::DEFAULT_LIST_LIMIT;

use super::Inner;
use super::commands::{Fail, Outcome, Reply, check_read, fail, not_found, not_supported, room_of};
use super::messages::BATCH;
use super::rate::{WindowLimit, network};
use super::state::{ConvEntry, ConvState, RoomInfo};
use crate::handler::OutLine;
use crate::store::{EventKind, NewReport, ReportAdded, ReportRecord, StoreError};

/// The window of `limits.reports_per_hour` (5.8).
pub(super) const REPORT_WINDOW: Duration = Duration::from_secs(60 * 60);

/// What the hub keeps in memory for reports.
#[derive(Debug)]
pub(crate) struct ReportBook {
    /// See the module documentation, "Order". Taken after a room's lock,
    /// never before one.
    lock: tokio::sync::Mutex<()>,
    /// The reports each reporter made in the last [`REPORT_WINDOW`].
    made: WindowLimit<Reporter>,
}

/// Who a report counts against for `limits.reports_per_hour`: an
/// identity by its uid, a guest by the network of its session's address
/// (see [`network`]), since a guest can take a new name at will.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Reporter {
    Identity(Uid),
    Network(IpAddr),
}

impl ReportBook {
    /// No reports made yet.
    pub(crate) fn new() -> ReportBook {
        ReportBook {
            lock: tokio::sync::Mutex::new(()),
            made: WindowLimit::new(REPORT_WINDOW),
        }
    }
}

fn no_report() -> Fail {
    fail(ErrorCode::NotFound, "no such report")
}

fn operators_only() -> Fail {
    fail(ErrorCode::Forbidden, "for operators only")
}

/// The two lines of a report (5.8): the REPORT line, with `from` if
/// `with_from`, and the copy of the reported event. Both carry the
/// `report` tag, and the `id` tag with the conversation's id. A room is named by its name; a direct conversation (M5a)
/// by the author, as the reporter sees it.
fn report_lines(
    id: &Id,
    report: &NewReport,
    with_from: bool,
) -> Result<[ServerMessage; 2], StoreError> {
    let conv = match &report.room {
        Some(room) => Conv::Room(room.clone()),
        None => Conv::Uid(report.event.from.clone()),
    };
    let copy = report.event.to_event(conv.clone(), &report.conv_id)?;
    let line = Report {
        t: report.t,
        from: with_from.then(|| report.reporter.clone()),
        conv,
        seq: report.event.seq,
        franking: None,
        reason: report.reason.clone(),
    };
    // Both carry the conversation's id, so that a report from a room that
    // was dropped and made again is not taken for one about the new room
    // (5.8, 10.4).
    let conv_id = report.conv_id.clone();
    Ok([
        ServerMessage::report_line(id.clone(), line).with_report_conv(conv_id.clone()),
        ServerMessage::report_copy(id.clone(), copy).with_report_conv(conv_id),
    ])
}

impl Inner {
    /// Handles REPORT, REPORTENC, REPORTS, RESOLVE, and `ADMIN REPORTS`,
    /// `ROOMS` and `DROP`.
    pub(super) async fn reports(
        self: &Arc<Self>,
        uid: &Uid,
        reply: &Reply,
        command: Command,
    ) -> Outcome {
        match command {
            Command::Report {
                conv,
                seq,
                franking,
                reason,
            } => self.report(uid, conv, seq, franking, reason).await,
            Command::Reports { room } => self.room_reports(uid, reply, &room).await,
            Command::Resolve { id } => self.resolve(uid, reply, &id).await,
            Command::Admin(command) => {
                if !self.is_operator(uid) {
                    return Err(operators_only());
                }
                match command {
                    AdminCommand::Reports => self.all_reports(uid, reply).await,
                    AdminCommand::Rooms(page) => self.all_rooms(reply, page).await,
                    AdminCommand::Drop { room, reason } => self.drop_room(&room, reason).await,
                    _ => Err(not_supported()),
                }
            }
            _ => Err(not_supported()),
        }
    }

    /// The reviewers of a report in a room (5.8), each with whether it is
    /// an operator, who alone see the reporter: the room's owners and
    /// moderators, members or not, and the operators. With `None`, for a
    /// report whose room is gone, the operators only. Never `author`, who
    /// wrote the reported message, so that nobody reviews reports against
    /// themselves (PLAN.md 5, item 35).
    pub(super) fn reviewers(&self, info: Option<&RoomInfo>, author: &Uid) -> BTreeMap<Uid, bool> {
        let mut reviewers: BTreeMap<Uid, bool> = info
            .map(|info| info.roles.keys().map(|uid| (uid.clone(), false)).collect())
            .unwrap_or_default();
        let operators = self.operators.read().unwrap_or_else(|e| e.into_inner());
        for op in operators.iter() {
            reviewers.insert(op.clone(), true);
        }
        reviewers.remove(author);
        reviewers
    }

    /// Whether `uid` is a reviewer of reports in the room `info`, or of a
    /// report whose room is gone if `None` (5.8), leaving aside who wrote
    /// the reported message.
    fn reviews_room(&self, uid: &Uid, info: Option<&RoomInfo>) -> bool {
        uid.is_identity()
            && (self.is_operator(uid) || info.is_some_and(|info| info.roles.contains_key(uid)))
    }

    /// Whether `uid` is a reviewer of a report about a message by `author`
    /// (PLAN.md 5, item 35).
    fn is_reviewer(&self, uid: &Uid, info: Option<&RoomInfo>, author: &Uid) -> bool {
        uid != author && self.reviews_room(uid, info)
    }

    /// Sends a report's two lines to every connection of every reviewer
    /// (5.8). Each connection gets the two together, with nothing between
    /// them.
    fn send_report(
        &self,
        reviewers: &BTreeMap<Uid, bool>,
        id: &Id,
        report: &NewReport,
    ) -> Result<(), StoreError> {
        let [with_from, copy] = report_lines(id, report, true)?;
        let [without_from, _] = report_lines(id, report, false)?;
        let (with_from, without_from, copy) = (
            OutLine::new(with_from),
            OutLine::new(without_from),
            OutLine::new(copy),
        );
        for (uid, operator) in reviewers {
            let Some(user) = self.reg().users.get(uid).cloned() else {
                continue;
            };
            let first = if *operator { &with_from } else { &without_from };
            let state = user.lock();
            for conn in &state.conns {
                conn.handle.send_line(first.clone());
                conn.handle.send_line(copy.clone());
            }
        }
        Ok(())
    }

    /// REPORT (5.8), of a MSG event in a room.
    async fn report(
        &self,
        uid: &Uid,
        conv: Conv,
        seq: Seq,
        franking: Option<Franking>,
        reason: String,
    ) -> Outcome {
        // M5a: REPORTENC, and direct conversations. Guests naming a uid were
        // answered `not-found` before this (4.2).
        if franking.is_some() {
            return Err(not_supported());
        }
        let Conv::Room(room) = conv else {
            return Err(not_supported());
        };
        let st = self.lock_room(&room).await?;
        let info = room_of(&st)?;
        let (key, conv_id) = (st.key, st.id.clone());
        // A report made before gets its id again, before every other check,
        // so that a client may resend it safely: even if the message was
        // deleted, or the reporter can no longer read the room, since (5.8).
        let (c, who) = (conv_id.clone(), uid.clone());
        if let Some(id) = self.db(move |s| s.report_of(&c, seq, &who)).await? {
            return Ok(Some(OkResponse::new().with_id(&id)));
        }
        // Anyone who can read the message may report it (5.8, 7.2).
        check_read(info, self.asker(uid, st.is_member(uid)))?;
        let event = self.db(move |s| s.event(key, seq)).await?;
        let Some(event) = event.filter(|e| !e.deleted && matches!(e.kind, EventKind::Msg { .. }))
        else {
            return Err(fail(ErrorCode::NotFound, "no such message"));
        };
        // A guest's name may have been someone else's before its session
        // (5.3): their messages are not its own.
        if self.is_author(uid, &event) {
            return Err(fail(
                ErrorCode::Forbidden,
                "you cannot report your own message",
            ));
        }
        let slot = self
            .report_book
            .made
            .take(
                self.reporter(uid),
                self.config.limits.reports_per_hour,
                self.now(),
            )
            .map_err(|retry| {
                Fail::Err(
                    ErrResponse::new(ErrorCode::RateLimited)
                        .with_retry(retry)
                        .with_message("you have made too many reports"),
                )
            })?;

        let report = NewReport {
            conv_id,
            room: Some(info.room.clone()),
            reporter: uid.clone(),
            reason,
            t: self.now(),
            event,
        };
        let reviewers = self.reviewers(Some(info), &report.event.from);
        let _book = self.report_book.lock.lock().await;
        let stored = report.clone();
        let id = match self.db(move |s| s.add_report(&stored)).await? {
            ReportAdded::New(id) => id,
            // Cannot happen under the room's lock, but is harmless.
            ReportAdded::Existing(id) => return Ok(Some(OkResponse::new().with_id(&id))),
        };
        if let Some(slot) = slot {
            slot.keep();
        }
        tracing::info!(%room, report = %id, "message reported");
        self.send_report(&reviewers, &id, &report)?;
        Ok(Some(OkResponse::new().with_id(&id)))
    }

    /// Who a report by `uid` counts against (see [`Reporter`]).
    fn reporter(&self, uid: &Uid) -> Reporter {
        if !uid.is_identity()
            && let Some(session) = self.reg().sessions.get(uid)
        {
            return Reporter::Network(network(session.address));
        }
        Reporter::Identity(uid.clone())
    }

    /// Checks that `uid` may see the reports of the room (5.8): the room
    /// is one it may read, and it is a reviewer there.
    fn check_room_reviewer(&self, st: &ConvState, uid: &Uid) -> Result<(), Fail> {
        let info = room_of(st)?;
        check_read(info, self.asker(uid, st.is_member(uid)))?;
        if !self.reviews_room(uid, Some(info)) {
            return Err(fail(
                ErrorCode::Forbidden,
                "only the room's owners and moderators may see its reports",
            ));
        }
        Ok(())
    }

    /// How many reports a chunk of REPORTS or ADMIN REPORTS holds: as
    /// many as fit, two lines each, in the room the network layer keeps
    /// for a response, with the `OK`.
    fn report_chunk(&self) -> u64 {
        (self.config.limits.reply_lines().saturating_sub(1) / 2).max(1) as u64
    }

    /// `REPORTS <room>` (5.8): the two lines of each open report in the
    /// room, oldest first, then `OK`.
    async fn room_reports(&self, uid: &Uid, reply: &Reply, room: &Room) -> Outcome {
        let entry = self.room_entry(room).ok_or_else(not_found)?;
        let operator = self.is_operator(uid);
        let mut after = 0;
        loop {
            let st = entry.clone().lock_owned().await;
            if st.dropped {
                // Dropped while this waited for the lock: as if it came a
                // moment later. Dropped after the first chunk: the room is
                // gone, and only operators still see its reports.
                return if after == 0 {
                    Err(not_found())
                } else {
                    Ok(Some(OkResponse::new()))
                };
            }
            self.check_room_reviewer(&st, uid)?;
            let _book = self.report_book.lock.lock().await;
            let conv_id = st.id.clone();
            let (records, more) = self.report_page(Some(conv_id), after).await?;
            self.send_reports(reply, uid, &records, operator)?;
            if !more {
                return Ok(Some(OkResponse::new()));
            }
            after = records.last().map_or(after, |r| r.n);
            drop(_book);
            drop(st);
            if !self.wait_for_reply_room(&reply.handle).await {
                return Ok(None);
            }
        }
    }

    /// `ADMIN REPORTS` (5.8, 10.4): the two lines of every open report on
    /// the server, oldest first, then `OK`. Operators only.
    async fn all_reports(&self, uid: &Uid, reply: &Reply) -> Outcome {
        let mut after = 0;
        loop {
            let _book = self.report_book.lock.lock().await;
            let (records, more) = self.report_page(None, after).await?;
            self.send_reports(reply, uid, &records, true)?;
            if !more {
                return Ok(Some(OkResponse::new()));
            }
            after = records.last().map_or(after, |r| r.n);
            drop(_book);
            if !self.wait_for_reply_room(&reply.handle).await {
                return Ok(None);
            }
        }
    }

    /// One chunk of open reports after the one numbered `after`, and
    /// whether there are more.
    async fn report_page(
        &self,
        conv_id: Option<Id>,
        after: u64,
    ) -> Result<(Vec<ReportRecord>, bool), StoreError> {
        let chunk = self.report_chunk();
        let mut records = self
            .db(move |s| s.reports(conv_id.as_ref(), after, chunk + 1))
            .await?;
        let more = records.len() as u64 > chunk;
        records.truncate(chunk as usize);
        Ok((records, more))
    }

    /// Queues the lines of `records` as part of a response to `uid`,
    /// leaving out reports about its own messages (PLAN.md 5, item 35).
    /// Every line is made before any is sent, so that bad data gives only
    /// `ERR internal`.
    fn send_reports(
        &self,
        reply: &Reply,
        uid: &Uid,
        records: &[ReportRecord],
        with_from: bool,
    ) -> Result<(), StoreError> {
        let mut lines = Vec::with_capacity(records.len() * 2);
        for record in records.iter().filter(|r| r.report.event.from != *uid) {
            lines.extend(report_lines(&record.id, &record.report, with_from)?);
        }
        for line in lines {
            reply.handle.send(line.with_ref_opt(reply.ref_.clone()));
        }
        Ok(())
    }

    /// `RESOLVE <id>` (5.8): closes a report, and sends `RESOLVED <id>` to
    /// the other reviewers.
    ///
    /// Someone who is not one of the report's reviewers gets `not-found`,
    /// as for a report that does not exist, so that report ids reveal
    /// nothing.
    async fn resolve(&self, uid: &Uid, reply: &Reply, id: &Id) -> Outcome {
        let key = id.clone();
        let record = self
            .db(move |s| s.report(&key))
            .await?
            .ok_or_else(no_report)?;
        // The room, locked, if it is still the report's room: its owners
        // and moderators are reviewers too.
        let st = match &record.report.room {
            Some(room) => match self.room_entry(room) {
                Some(entry) => {
                    let st = entry.lock_owned().await;
                    (!st.dropped && st.id == record.report.conv_id).then_some(st)
                }
                None => None,
            },
            None => None,
        };
        let info = st.as_deref().and_then(ConvState::room_info);
        let author = &record.report.event.from;
        if !self.is_reviewer(uid, info, author) {
            return Err(no_report());
        }
        let reviewers = self.reviewers(info, author);
        let _book = self.report_book.lock.lock().await;
        let key = id.clone();
        if !self.db(move |s| s.resolve_report(&key)).await? {
            // Another reviewer resolved it meanwhile.
            return Err(no_report());
        }
        tracing::info!(report = %id, "report resolved");
        let line = OutLine::new(ServerMessage::new(ServerLine::Resolved { id: id.clone() }));
        let me = reply.handle.id();
        for uid in reviewers.keys() {
            if let Some(user) = self.reg().users.get(uid).cloned() {
                user.send_except(&line, me);
            }
        }
        Ok(Some(OkResponse::new()))
    }

    /// `ADMIN ROOMS` (10.4): every room, private ones too, a page at a
    /// time, as LIST does (6.1).
    async fn all_rooms(&self, reply: &Reply, page: RoomPage) -> Outcome {
        let limit = page
            .limit
            .map_or(DEFAULT_LIST_LIMIT, NonZeroU64::get)
            .min(self.config.limits.max_list)
            .max(1);
        let entries: Vec<Arc<ConvEntry>> = {
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

    /// Whether `room` is one of the configuration's `rooms`.
    fn configured(&self, room: &Room) -> bool {
        self.config
            .rooms
            .iter()
            .any(|name| name.parse::<Room>().is_ok_and(|r| r == *room))
    }

    /// `ADMIN DROP` (10.4): deletes a room with everything in it but its
    /// open reports. Operators only.
    ///
    /// Under the room's lock, so that commands waiting for it then find it
    /// dropped (`not-found`), and under the creation lock, so that a JOIN
    /// cannot create the room again until it is gone. Every connection of
    /// every member gets `@id=<id> DROP <room> [<reason>]`, and the members
    /// are removed, as if kicked. A room from the configuration is created
    /// again at once, empty and with a new id (PLAN.md section 6).
    ///
    /// A large room's events go first, oldest first, a batch at a time, so
    /// that other rooms get the store in between. The room's lock is held
    /// throughout, so commands that need it find the room whole or gone.
    /// A HISTORY or RELATED already past the lock may find the oldest
    /// events gone, as if they had expired (7.5). If this fails, or the
    /// server stops, in between, the room stays in that state and no DROP
    /// was sent: the operator drops it again.
    async fn drop_room(&self, room: &Room, reason: String) -> Outcome {
        let mut st = self.lock_room(room).await?;
        let key = st.key;
        while self.db(move |s| s.trim_room(key, BATCH)).await? == BATCH as u64 {}
        let creating = self.create_lock.lock().await;
        let recreate = self.configured(room);
        let now = self.now();
        let new = self.db(move |s| s.drop_room(key, recreate, now)).await?;

        st.dropped = true;
        let line = OutLine::new(ServerMessage::new(ServerLine::Drop {
            room: room.clone(),
            id: st.id.clone(),
            reason,
        }));
        st.broadcast(&line);
        // Owners and moderators who have left hear of it too, so that their
        // clients forget the room (PLAN.md 5, item 33).
        if let Some(info) = st.room_info() {
            let reg = self.reg();
            for holder in info.roles.keys().filter(|u| !st.is_member(u)) {
                if let Some(user) = reg.users.get(holder) {
                    user.send(&line);
                }
            }
        }
        let members: Vec<Uid> = st.members.keys().cloned().collect();
        for uid in &members {
            st.remove_member(uid);
        }
        {
            let mut rooms = self.rooms.write().unwrap_or_else(|e| e.into_inner());
            match new {
                Some(record) => {
                    rooms.insert(
                        room.clone(),
                        Arc::new(ConvEntry::new(ConvState::room(record))),
                    );
                }
                None => {
                    rooms.remove(room);
                }
            }
        }
        drop(creating);
        drop(st);
        let mut reg = self.reg();
        for uid in &members {
            reg.release(uid);
        }
        drop(reg);
        tracing::info!(%room, recreated = recreate, "room dropped");
        Ok(Some(OkResponse::new()))
    }
}

#[cfg(test)]
mod tests;
