//! What the server keeps for devices and identities without reading it:
//! KeyPackages (12.5), Welcomes (12.8), blobs (12.12), uploaded files
//! (5.6) and backups (12.13).
//!
//! Tables (`sqlite/keys.rs`):
//!
//! - `key_packages`: each device's KeyPackages, ordinary and last resort,
//!   until handed out or their lifetime ends (12.5).
//! - `handed_out`: the KeyPackageRefs a Welcome may be put for: those
//!   KEYPKG GET handed out, and those of external Add proposals in public
//!   rooms (12.8).
//! - `welcomes`: Welcomes waiting for their device, or for WELCOME GET,
//!   until fetched or retention ends (12.8).
//! - `blobs`: the blobs the server holds, by hash, with when they expire
//!   or whether something keeps them (12.12, 12.13). Their bytes live in
//!   files.
//! - `blob_puts`: `put` URLs BLOB handed out, for 10 minutes (12.12).
//! - `uploads`: uploaded files and their `put`, `get` and `del` URLs, by
//!   the hashes of their secret parts (5.6, Section 14).
//! - `backups`: each identity's current backup (12.13).

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
    /// The archive's key, wrapped.
    pub key: WrappedKey,
}

/// KeyPackages, Welcomes, blobs, files and backups (5.6, 12).
pub trait KeysStore {
    /// The backup of `uid`, if it has one (12.13).
    fn backup(&self, uid: &Uid) -> Result<Option<BackupRecord>>;

    /// Stores `backup` as the backup of `uid` at `now`, replacing any
    /// other, and returns the blob of the backup it replaced, which the
    /// server deletes (12.13).
    fn put_backup(
        &self,
        uid: &Uid,
        backup: &BackupRecord,
        now: Timestamp,
    ) -> Result<Option<BlobRef>>;

    /// Deletes the backup of `uid`, and returns its blob, if it had one.
    fn delete_backup(&self, uid: &Uid) -> Result<Option<BlobRef>>;
}
