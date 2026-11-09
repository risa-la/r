//! Presence settings (8.3), push subscriptions (9) and reports to the
//! operators (5.8).
//!
//! Tables (`sqlite/misc.rs`):
//!
//! - `presence`: the identities that turned presence on (8.3). Off is the
//!   default, and has no row.
//! - `push_subscriptions`: mailbox subscriptions, by box, until they
//!   expire, and account subscriptions, by device id (9.1). The server
//!   must send to the URL, so it keeps it, and looks it up by its hash.
//!   Nothing links a mailbox subscription to an identity (9.1).
//! - `reports`: reports to the operators, open until resolved (5.8).
//! - `report_posts`: the copies of the posts a report names, kept until it
//!   is resolved even if they expire (5.8).

use risala_proto::binary::{PushAuth, PushKey, ReportData};
use risala_proto::mls::Pseudonym;
use risala_proto::names::{BoxName, Id, Uid};
use risala_proto::record::DeviceId;
use risala_proto::time::Timestamp;
use risala_proto::types::{PushTag, PushUrl};

use super::Result;

/// What a push subscription wakes (9.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushTarget {
    /// A mailbox subscription: a new kept post in the mailbox.
    Mailbox(BoxName),
    /// An account subscription: a new Welcome for the device.
    Device {
        /// The device's identity.
        uid: Uid,
        /// The device.
        device: DeviceId,
    },
}

/// A push subscription, as PUSH ADD gives it (9.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPushSubscription {
    /// What it wakes.
    pub target: PushTarget,
    /// The URL to POST to.
    pub url: PushUrl,
    /// The tag that goes in every push.
    pub tag: PushTag,
    /// The subscription's P-256 public key.
    pub key: PushKey,
    /// Its authentication secret.
    pub auth: PushAuth,
    /// When a mailbox subscription expires: one retention period after the
    /// PUSH ADD that made or renewed it (9.1). `None` for an account
    /// subscription.
    pub expires: Option<Timestamp>,
}

/// A stored push subscription.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushSubscription {
    /// Its row id, which the pusher uses to find it again.
    pub id: i64,
    /// What it wakes.
    pub target: PushTarget,
    /// The URL to POST to.
    pub url: PushUrl,
    /// The tag that goes in every push.
    pub tag: PushTag,
    /// The subscription's P-256 public key.
    pub key: PushKey,
    /// Its authentication secret.
    pub auth: PushAuth,
    /// When the current run of failed pushes began (9.3), if the last one
    /// failed.
    pub failing_since: Option<Timestamp>,
}

/// What [`MiscStore::add_push`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushAdded {
    /// A new subscription.
    Added,
    /// The URL was registered for the same mailbox or device: its tag and
    /// keys were replaced, and it was renewed (9.1).
    Replaced,
    /// The mailbox or device has as many subscriptions as `max` allows
    /// (`ERR rate-limited`, 9.1).
    TooMany,
}

/// A report to the operators, as made (5.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewReport {
    /// Its id.
    pub id: Id,
    /// The mailbox the posts are in.
    pub mailbox: BoxName,
    /// The RisalaReport, as received.
    pub report: ReportData,
    /// When it was made.
    pub t: Timestamp,
    /// The pseudonym in the target post's RisalaAAD.
    pub pseudonym: Pseudonym,
    /// The reporter, if signed in.
    pub from: Option<Uid>,
    /// Copies of the posts it names: seq, time and MLSMessage. A post
    /// whose message is a blob is kept by its hash: the blob then stays
    /// until the report is resolved (12.12).
    pub posts: Vec<(u64, Timestamp, super::PostBody)>,
}

/// An open report, as the operators see it (5.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredReport {
    /// Its id.
    pub id: Id,
    /// The mailbox the posts are in.
    pub mailbox: BoxName,
    /// The RisalaReport, as received.
    pub report: ReportData,
    /// When it was made.
    pub t: Timestamp,
    /// The pseudonym in the target post's RisalaAAD.
    pub pseudonym: Pseudonym,
    /// The reporter, if signed in.
    pub from: Option<Uid>,
}

/// Presence, push and reports (5.8, 8.3, 9).
pub trait MiscStore {
    /// Whether `uid` turned presence on (8.3). Off by default.
    fn presence_on(&self, uid: &Uid) -> Result<bool>;

    /// Turns presence on or off for `uid` (8.3).
    fn set_presence(&self, uid: &Uid, on: bool) -> Result<()>;

    /// Adds a push subscription, or replaces the tag and keys of the one
    /// with the same URL and target and renews it (9.1). A new one is
    /// refused if the target has `max` subscriptions already.
    fn add_push(&self, sub: &NewPushSubscription, max: usize) -> Result<PushAdded>;

    /// Deletes the subscription with this URL and target. Returns whether
    /// there was one.
    fn delete_push(&self, target: &PushTarget, url: &PushUrl) -> Result<bool>;

    /// Deletes a subscription by its id.
    fn delete_push_id(&self, id: i64) -> Result<()>;

    /// The subscriptions of a target that have not expired at `now`, in
    /// the order they were made.
    fn push_subscriptions(
        &self,
        target: &PushTarget,
        now: Timestamp,
    ) -> Result<Vec<PushSubscription>>;

    /// The subscription with this id, if it is still there.
    fn push_subscription(&self, id: i64) -> Result<Option<PushSubscription>>;

    /// Notes how a push to subscription `id` went (9.3): a failure at
    /// `now` starts a run of failures if none is running, and a success
    /// ends it.
    fn note_push(&self, id: i64, ok: bool, now: Timestamp) -> Result<()>;

    /// Deletes every subscription of the mailbox, as ADMIN DROP does
    /// (10.4).
    fn delete_mailbox_pushes(&self, mailbox: &BoxName) -> Result<u64>;

    /// Deletes every account subscription of the device, when it is
    /// removed (9.1).
    fn delete_device_pushes(&self, device: &DeviceId) -> Result<u64>;

    /// Deletes every account subscription of the identity's devices, and
    /// its presence setting, as UNREGISTER does (4.9).
    fn forget_identity_misc(&self, uid: &Uid) -> Result<()>;

    /// Deletes the mailbox subscriptions that expired before `now` (9.1).
    fn expire_pushes(&self, now: Timestamp) -> Result<u64>;

    /// Stores a report, with copies of its posts (5.8). The blobs of posts
    /// that are blobs are kept until it is resolved, those that no report
    /// keeps yet only while the bytes reports keep stay within
    /// `max_reported` (0: no limit). Returns how many were not kept.
    fn add_report(&self, report: &NewReport, max_reported: u64) -> Result<usize>;

    /// Every open report, oldest first (5.8).
    fn open_reports(&self) -> Result<Vec<StoredReport>>;

    /// Resolves a report, and discards it and its copies (5.8). Returns
    /// whether it was open.
    fn resolve_report(&self, id: &Id) -> Result<bool>;
}
