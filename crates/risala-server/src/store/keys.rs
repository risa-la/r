//! What the server keeps for devices and identities without reading it:
//! KeyPackages (12.5), Welcomes (12.8), blobs (12.12), uploaded files
//! (5.6) and backups (12.13).
//!
//! Tables (`sqlite/keys.rs`):
//!
//! - `key_packages`: each device's KeyPackages, ordinary and last resort,
//!   until handed out or their lifetime ends (12.5).
//! - `handed_out`: each handing out of a KeyPackage by KEYPKG GET, and
//!   each KeyPackage of an external Add proposal in a public room: what a
//!   Welcome may be put for, once each (12.8).
//! - `welcomes`: Welcomes waiting for their device, or for WELCOME GET,
//!   until fetched or retention ends (12.8).
//! - `blobs`: the blobs the server holds, by hash, with when they expire
//!   or whether something keeps them (12.12, 12.13). Their bytes live in
//!   files.
//! - `blob_puts`: `put` URLs BLOB handed out, for 10 minutes (12.12).
//! - `uploads`: uploaded files and their `put`, `get` and `del` URLs, by
//!   the hashes of their secret parts (5.6, Section 14).
//! - `backups`: each identity's current backup, whose blobs are kept
//!   while it is current (12.13).
//!
//! Nothing here says which connection or address stored a Welcome, blob
//! or upload (4.2).

use risala_proto::binary::WrappedKey;
use risala_proto::names::{BlobRef, Uid};
use risala_proto::time::Timestamp;

use super::Result;

/// An identity's backup (12.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupRecord {
    /// The generation of the backup key that wraps `key`.
    pub generation: u32,
    /// The blob that holds the encrypted archive.
    pub hash: BlobRef,
    /// The archives' key, a WrappedKey.
    pub key: WrappedKey,
    /// The blob of the list of the backup's other blobs, if it has any.
    pub files: Option<BlobRef>,
}

/// KeyPackages, Welcomes, blobs, files and backups (5.6, 12).
pub trait KeysStore {
    /// The backup of `uid`, if it has one (12.13).
    fn backup(&self, uid: &Uid) -> Result<Option<BackupRecord>>;

    /// Stores `backup` as the backup of `uid` at `now`, replacing any
    /// other, and returns the one it replaced, whose blobs the new one
    /// does not name the server deletes (12.13).
    fn put_backup(
        &self,
        uid: &Uid,
        backup: &BackupRecord,
        now: Timestamp,
    ) -> Result<Option<BackupRecord>>;

    /// Deletes the backup of `uid`, and returns it, if it had one, so
    /// that its blobs can be deleted (12.13).
    fn delete_backup(&self, uid: &Uid) -> Result<Option<BackupRecord>>;
}
