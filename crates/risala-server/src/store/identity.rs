//! What the server keeps about identities (4.6-4.9, 10.5): the identities
//! that have signed in here, the identities it hosts with their chains of
//! records, and pairing messages.
//!
//! Tables (`sqlite/identity.rs`):
//!
//! - `accounts`: every identity that has signed in here and not
//!   unregistered since (4.9). KEYPKG GET (12.5) and WHOIS (8.3) answer
//!   `not-found` for one that is not here.
//! - `hosted`: the names the server hosts under its identity domain (4.7),
//!   kept once retired so that the name is never registered again and
//!   its key file answers 410 (4.9, 10.5).
//! - `records`: the chains of records the server keeps, for hosted
//!   identities and identities whose key files name its log (4.4, 4.7),
//!   in chain order, each with its index in the key log once logged.
//! - `pairing`: PAIR PUT's messages, for 10 minutes (4.8), by the hash of
//!   their id, which is a bearer secret (Section 14).

use risala_proto::names::Uid;
use risala_proto::time::Timestamp;

use super::Result;

/// Identities on this server (4.6-4.9, 10.5).
pub trait IdentityStore {
    /// Notes that `uid` signed in at `now` (4.6), and returns whether the
    /// server did not know it before.
    fn note_sign_in(&self, uid: &Uid, now: Timestamp) -> Result<bool>;

    /// Whether `uid` has signed in here and not unregistered since (4.9).
    fn knows(&self, uid: &Uid) -> Result<bool>;

    /// Forgets that `uid` signed in here, as UNREGISTER does (4.9).
    /// Returns whether it was known.
    fn forget(&self, uid: &Uid) -> Result<bool>;
}
