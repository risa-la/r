//! Storage for reports (5.8), `ADMIN ROOMS` and `ADMIN DROP` (10.4).
//!
//! A report keeps a copy of the reported event, and names its
//! conversation by id and, for a room, by name, rather than by the
//! store's key. So a report outlives the message (5.4), its expiry (7.5)
//! and the room itself (10.4), until it is resolved.

use risala_proto::names::{Id, Room, Seq, Uid};
use risala_proto::time::Timestamp;

use super::{ConvKey, Result, RoomRecord, StoredEvent};

/// What a report says (5.8): stored by [`ReportStore::add_report`], and
/// part of each [`ReportRecord`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewReport {
    /// The id (5.1) of the reported event's conversation, which may since
    /// have been dropped (10.4).
    pub conv_id: Id,
    /// The room's name, or `None` in a direct conversation (M5a).
    pub room: Option<Room>,
    /// Who made the report.
    pub reporter: Uid,
    /// Why, escaped; empty if no reason was given.
    pub reason: String,
    /// When the report was made.
    pub t: Timestamp,
    /// The copy of the reported event, as it was when it was reported: a
    /// MSG that was not deleted. Its seq is the reported seq.
    pub event: StoredEvent,
}

/// An open report, as stored (5.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportRecord {
    /// The order reports were made in: larger is newer. For paging.
    pub n: u64,
    /// The report's id.
    pub id: Id,
    /// What it says.
    pub report: NewReport,
}

/// The result of [`ReportStore::add_report`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportAdded {
    /// The report was stored with this new id.
    New(Id),
    /// The reporter had already reported this event: this is that open
    /// report's id. Nothing was stored.
    Existing(Id),
}

/// Part of [`super::Store`]: see the module documentation.
///
/// Every method blocks, like the rest of [`super::Store`].
pub trait ReportStore {
    /// The id of the open report `reporter` made of event `seq` in the
    /// conversation with id `conv_id`, if there is one (5.8).
    fn report_of(&self, conv_id: &Id, seq: Seq, reporter: &Uid) -> Result<Option<Id>>;

    /// Stores a report with a new id, in one transaction with the check
    /// that the reporter has no open report of the same event (5.8).
    fn add_report(&self, report: &NewReport) -> Result<ReportAdded>;

    /// One open report, or `None`.
    fn report(&self, id: &Id) -> Result<Option<ReportRecord>>;

    /// Open reports made after the one numbered `after` (0 for all), oldest
    /// first, at most `limit`: of the conversation with id `conv_id`, or of
    /// every conversation if `None` (5.8, 10.4).
    fn reports(&self, conv_id: Option<&Id>, after: u64, limit: u64) -> Result<Vec<ReportRecord>>;

    /// Resolves a report: deletes it and its copy of the event (5.8).
    /// Returns whether it was open.
    fn resolve_report(&self, id: &Id) -> Result<bool>;

    /// Drops the room `key` (10.4), in one transaction: from then on the
    /// store treats `key` as gone, as if the room had been deleted, and
    /// its name is free. Its settings, memberships, roles, invitations,
    /// bans, read markers and cids are deleted. Reports stay. Its id is
    /// never used again. Its events are left for
    /// [`clear_dropped`](Self::clear_dropped), so that no one transaction
    /// deletes a large room's events; nothing can read them meanwhile.
    ///
    /// With `recreate`, a room of the same name is created again in the
    /// same transaction, empty and with a new id, as [`ensure_room`] does,
    /// and returned (PLAN.md section 6, "Rooms from the configuration").
    ///
    /// [`ensure_room`]: super::Store::ensure_room
    fn drop_room(&self, key: ConvKey, recreate: bool, now: Timestamp)
    -> Result<Option<RoomRecord>>;

    /// Deletes up to `max` of the oldest events of the room `key`, which
    /// [`drop_room`](Self::drop_room) dropped, and returns how many it
    /// deleted. If that is fewer than `max`, none are left, and what
    /// remains of the room goes too, in the same transaction. Called until
    /// it deletes fewer than `max`. Does nothing to a room that was not
    /// dropped.
    fn clear_dropped(&self, key: ConvKey, max: usize) -> Result<u64>;

    /// The rooms that were dropped, but whose events
    /// [`clear_dropped`](Self::clear_dropped) has not finished deleting:
    /// a drop that failed, or that the server stopped in.
    fn dropped_rooms(&self) -> Result<Vec<ConvKey>>;
}
