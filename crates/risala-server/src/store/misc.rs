//! Presence settings (8.3), push subscriptions (9) and reports to the
//! operators (5.8).
//!
//! Tables (`sqlite/misc.rs`):
//!
//! - `presence`: the identities that turned presence on (8.3). Off is the
//!   default, and has no row.
//! - `push_subscriptions`: mailbox subscriptions, by box, and account
//!   subscriptions, by device key (9.1). The server must send to the URL,
//!   so it keeps it, and looks it up by its hash.
//! - `reports`: reports to the operators, open until resolved (5.8).
//! - `report_posts`: the copies of the posts a report names, kept until it
//!   is resolved even if they expire (5.8).

use risala_proto::names::Uid;

use super::Result;

/// Presence, push and reports (5.8, 8.3, 9).
pub trait MiscStore {
    /// Whether `uid` turned presence on (8.3). Off by default.
    fn presence_on(&self, uid: &Uid) -> Result<bool>;

    /// Turns presence on or off for `uid` (8.3).
    fn set_presence(&self, uid: &Uid, on: bool) -> Result<()>;
}
