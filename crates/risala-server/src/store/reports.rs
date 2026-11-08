//! Storage for reports (5.8), `ADMIN ROOMS` and `ADMIN DROP` (10.4).
//!
//! A report keeps a copy of the reported event, and names its
//! conversation by id and, for a room, by name, rather than by the
//! store's key. So a report outlives the message (5.4), its expiry (7.5)
//! and the room itself (10.4), until it is resolved.

use risala_proto::names::{Id, Room, Seq, Uid};
use risala_proto::time::Timestamp;

use super::{ConvKey, Result, RoomRecord, StoredEvent};

/// A report to store (5.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewReport {
    /// The id (5.1) of the reported event's conversation.
    pub conv_id: Id,
    /// The room's name, or `None` in a direct conversation (M5a).
    pub room: Option<Room>,
    /// Who made the report.
    pub reporter: Uid,
    /// Why, escaped; empty if no reason was given.
    pub reason: String,
    /// When the report was made.
    pub t: Timestamp,
    /// The reported event as it is now: a MSG that is not deleted. Its seq
    /// is the reported seq.
    pub event: StoredEvent,
}

/// An open report, as stored (5.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportRecord {
    /// The order reports were made in: larger is newer. For paging.
    pub n: u64,
    /// The report's id.
    pub id: Id,
    /// The id (5.1) of the reported event's conversation, which may since
    /// have been dropped (10.4).
    pub conv_id: Id,
    /// The room's name, or `None` in a direct conversation (M5a).
    pub room: Option<Room>,
    /// Who made the report.
    pub reporter: Uid,
    /// Why, escaped; empty if none.
    pub reason: String,
    /// When the report was made.
    pub t: Timestamp,
    /// The copy of the reported event, as it was when it was reported.
    pub event: StoredEvent,
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

    /// Deletes the room `key` with everything in it (10.4): its events,
    /// settings, memberships, roles, invitations, bans, read markers and
    /// cids. Reports stay. Its id is never used again.
    ///
    /// With `recreate`, a room of the same name is created again in the
    /// same transaction, empty and with a new id, as [`ensure_room`] does,
    /// and returned (PLAN.md section 6, "Rooms from the configuration").
    ///
    /// [`ensure_room`]: super::Store::ensure_room
    fn drop_room(&self, key: ConvKey, recreate: bool, now: Timestamp)
    -> Result<Option<RoomRecord>>;
}
