//! The key log (4.5): an append-only Merkle tree of the records of the
//! identities the server hosts, and of others whose key files name it,
//! with its signed checkpoints and the log's ML-DSA-44 key.
//!
//! Tables (`sqlite/keylog.rs`):
//!
//! - `log_entries`: the entries, by index from 0, each an encoded Record
//!   (4.4) with its uid. A log never removes an entry (4.5).
//! - `log_checkpoints`: checkpoints the log signed, with the cosignatures
//!   witnesses returned, as served (C2SP tlog-checkpoint).
//! - `log_key`: the log's number in its origin
//!   (`<host>/risala-log/<number>`) and its key's seed.

use risala_proto::names::Uid;
use risala_proto::time::Timestamp;

use super::Result;

/// One entry of the key log (4.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    /// The identity the record is for.
    pub uid: Uid,
    /// The encoded Record (4.4).
    pub record: Vec<u8>,
}

/// The key log (4.5).
pub trait KeyLogStore {
    /// The number of entries in the log: the size of its tree.
    fn log_size(&self) -> Result<u64>;

    /// Appends `entries`, in order, at `now`, and returns the index of the
    /// first. A record the log already holds fails, since the log never
    /// holds one twice; checking chains is for the caller (4.5).
    fn append_entries(&self, entries: &[LogEntry], now: Timestamp) -> Result<u64>;

    /// At most `count` entries from index `start` on, in order.
    fn log_entries(&self, start: u64, count: u64) -> Result<Vec<LogEntry>>;
}
