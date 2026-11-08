//! The key log (4.5): append-only Merkle trees of the records of the
//! identities the server hosts, and of others whose chains name it, with
//! their signed checkpoints and the logs' ML-DSA-44 keys; and, when the
//! server is a witness (4.10), what it knows of the logs it witnesses.
//!
//! A host runs one log at a time, `<host>/risala-log/<n>`; after a
//! hand-off (4.5) it keeps serving the old ones, which append nothing
//! more. Entries are numbered from 0 within each log.
//!
//! Tables (`sqlite/keylog.rs`):
//!
//! - `log_key`: each log the server has run, by its number in the origin,
//!   with its key's seed. The newest is the current one (4.5, 4.10).
//! - `log_entries`: each log's entries, by index, each an encoded
//!   LogEntry (4.5): a record, with its uid and the SHA-384 hash of its
//!   Record, or a hand-off to the next log. A log never removes an entry.
//! - `log_checkpoints`: checkpoints the logs signed, with the
//!   cosignatures witnesses returned, as served (C2SP tlog-checkpoint).
//! - `witness_key`: the seed of the server's witness key (4.10).
//! - `witness_logs`: each log the server's witness has enrolled (4.10).

use risala_proto::names::{BlobRef, Uid};
use risala_proto::time::Timestamp;

use sha2::{Digest as _, Sha256};

use super::Result;

/// The SHA-256 hash of a uid, as `risala/uid/<hash>` names it (4.5).
pub fn uid_hash(uid: &str) -> [u8; 32] {
    Sha256::digest(uid.as_bytes()).into()
}

/// A record entry's uid and hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggedRecord {
    /// The identity whose chain the record is in.
    pub uid: Uid,
    /// The SHA-384 hash of its Record, as key files name it (4.4).
    pub hash: BlobRef,
}

/// One entry of a key log (4.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    /// The encoded LogEntry.
    pub entry: Vec<u8>,
    /// For a record entry, its uid and hash; `None` for a hand-off.
    pub record: Option<LoggedRecord>,
}

/// A log the server has run (4.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogKeyRow {
    /// Its number, `<n>` in `<host>/risala-log/<n>`.
    pub number: u64,
    /// The seed of its ML-DSA-44 key. A secret.
    pub seed: [u8; 32],
}

/// A checkpoint a log signed, as served (4.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointRow {
    /// The tree size.
    pub size: u64,
    /// The signed note, with every cosignature it got.
    pub note: String,
    /// Whether it got the cosignatures the log asks for (k).
    pub witnessed: bool,
    /// When the log signed it.
    pub signed: Timestamp,
}

/// What the server's witness knows of one log it has enrolled (4.10), in
/// the store's terms. Times are seconds since 1970, as cosignatures carry
/// them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessLogRow {
    /// The log's origin.
    pub origin: String,
    /// The log's signed-note verifier key, fixed at enrolment.
    pub vkey: String,
    /// The size of the newest checkpoint the witness cosigned.
    pub size: u64,
    /// Its root.
    pub root: [u8; 32],
    /// The registered domain of the log's host.
    pub domain: String,
    /// When the witness enrolled the log.
    pub enrolled_at: u64,
    /// When it last cosigned a checkpoint of the log; 0 if never.
    pub last_cosigned: u64,
    /// The hand-off it took from the log: the entry's index, and the next
    /// log's verifier key.
    pub handoff: Option<(u64, String)>,
}

/// The key log (4.5), and the witness's state (4.10).
pub trait KeyLogStore {
    /// Every log the server has run, by number, oldest first.
    fn log_keys(&self) -> Result<Vec<LogKeyRow>>;

    /// Starts log 1 with `seed` if the server has run no log yet, and
    /// returns every log, as [`log_keys`](Self::log_keys) does.
    fn first_log_key(&self, seed: [u8; 32], now: Timestamp) -> Result<Vec<LogKeyRow>>;

    /// Hands log `log` off (4.5): appends `handoff`, its hand-off entry,
    /// and starts log `log + 1` with `seed`, at once. Returns the hand-off
    /// entry's index. Fails if log `log` is not the newest.
    fn hand_off(&self, log: u64, handoff: &[u8], seed: [u8; 32], now: Timestamp) -> Result<u64>;

    /// The number of entries in log `log`: the size of its tree.
    fn log_size(&self, log: u64) -> Result<u64>;

    /// Appends `entries` to log `log`, in order, at `now`, and returns the
    /// index of the first. A record any log already holds fails, and
    /// nothing is appended; checking chains is for the caller (4.5).
    fn append_entries(&self, log: u64, entries: &[LogEntry], now: Timestamp) -> Result<u64>;

    /// At most `count` entries of log `log` from index `start` on, in
    /// order.
    fn log_entries(&self, log: u64, start: u64, count: u64) -> Result<Vec<LogEntry>>;

    /// The indices of the entries of log `log` whose uid has the SHA-256
    /// hash `uid_hash`, in increasing order (4.5, `risala/uid/`).
    fn log_uid_indices(&self, log: u64, uid_hash: &[u8; 32]) -> Result<Vec<u64>>;

    /// The hash of the newest record of `uid` in any log the server has
    /// run, if it holds one.
    fn log_newest_record(&self, uid: &Uid) -> Result<Option<BlobRef>>;

    /// Where a record is logged: the log's number and the entry's index.
    fn log_record_index(&self, hash: &BlobRef) -> Result<Option<(u64, u64)>>;

    /// Keeps a checkpoint of log `log`, replacing any of the same size.
    fn put_log_checkpoint(&self, log: u64, checkpoint: &CheckpointRow) -> Result<()>;

    /// The newest checkpoint of log `log`, or the newest witnessed one.
    fn log_checkpoint(&self, log: u64, witnessed_only: bool) -> Result<Option<CheckpointRow>>;

    /// The seed of the server's witness key: the stored one, or else
    /// `fresh`, which is then stored.
    fn witness_seed(&self, fresh: [u8; 32], now: Timestamp) -> Result<[u8; 32]>;

    /// What the witness knows of the log `origin`, if it enrolled it.
    fn witness_log(&self, origin: &str) -> Result<Option<WitnessLogRow>>;

    /// Stores what the witness knows of a log, under its origin.
    fn put_witness_log(&self, row: &WitnessLogRow) -> Result<()>;

    /// How many hosts under `domain` the witness enrolled a log 1 of at or
    /// after `since`, in seconds.
    fn witness_hosts_enrolled_since(&self, domain: &str, since: u64) -> Result<u64>;
}
