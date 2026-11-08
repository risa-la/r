//! The key log (4.5): an append-only Merkle tree of the records of the
//! identities the server hosts, and of others whose chains name it, with
//! its signed checkpoints and the log's ML-DSA-44 key.
//!
//! Tables (`sqlite/keylog.rs`):
//!
//! - `log_entries`: the entries, by index from 0, each an encoded
//!   LogEntry (4.5): a record, with its uid and the SHA-384 hash of its
//!   Record, or a hand-off to the next log. A log never removes an entry.
//! - `log_checkpoints`: checkpoints the log signed, with the cosignatures
//!   witnesses returned, as served (C2SP tlog-checkpoint).
//! - `log_key`: each log the server has run, by its number in the origin
//!   `<host>/risala-log/<number>`, with its key's seed. The newest is the
//!   current one (4.5, 4.10).

use risala_proto::names::{BlobRef, Uid};
use risala_proto::time::Timestamp;

use super::Result;

/// One entry of the key log (4.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    /// The encoded LogEntry.
    pub entry: Vec<u8>,
    /// For a record entry, the identity and the SHA-384 hash of its
    /// Record, as key files name it (4.4); `None` for a hand-off.
    pub record: Option<(Uid, BlobRef)>,
}

/// The key log (4.5).
pub trait KeyLogStore {
    /// The number of entries in the log: the size of its tree.
    fn log_size(&self) -> Result<u64>;

    /// Appends `entries`, in order, at `now`, and returns the index of the
    /// first. A record the log already holds fails, and nothing is
    /// appended; checking chains is for the caller (4.5).
    fn append_entries(&self, entries: &[LogEntry], now: Timestamp) -> Result<u64>;

    /// At most `count` entries from index `start` on, in order.
    fn log_entries(&self, start: u64, count: u64) -> Result<Vec<LogEntry>>;
}
