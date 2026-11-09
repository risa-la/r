//! What the server keeps for devices and identities without reading it:
//! KeyPackages (12.5), Welcomes (12.8), blobs (12.12), uploaded files
//! (5.6) and backups (12.13).
//!
//! Tables (`sqlite/keys.rs`):
//!
//! - `key_packages`: each device's KeyPackages, ordinary and last resort,
//!   until handed out or their lifetime ends (12.5).
//! - `key_package_uids`: the identities that have uploaded KeyPackages,
//!   so that KEYPKG GET can tell a uid it does not know (12.5).
//! - `handed_out`: each handing out of a KeyPackage by KEYPKG GET, with
//!   the hash of its put secret (12.5), and each KeyPackage of an external
//!   Add proposal that a public room's commit applied, with the device
//!   that committed it: what a Welcome may be put for, once each (12.8).
//! - `room_trees`: the ratchet tree of each public-room epoch that such a
//!   commit started, for WELCOME GET's `tree`, kept 24 hours (12.6, 12.8).
//! - `welcomes`: Welcomes waiting for their device, or for WELCOME GET,
//!   until fetched or retention ends (12.8).
//! - `blobs`: the blobs the server holds, by hash, with when retention
//!   counts from (12.12). Their bytes live in files.
//! - `blob_keeps`: what keeps a blob whatever the retention: a current
//!   backup, the tree of a public room's current epoch, or the tree of an
//!   epoch with Welcomes (12.6, 12.12, 12.13).
//! - `blob_puts`: `put` URLs BLOB handed out, for 10 minutes (12.12).
//! - `uploads`: uploaded files and their `put`, `get` and `del` URLs, by
//!   the hashes of their secret parts (5.6, Section 14).
//! - `report_holds`: the uploads each open report keeps (5.8).
//! - `backups`: each identity's current backup, whose blobs are kept
//!   while it is current (12.13).
//!
//! Nothing here says which connection or address stored a Welcome, blob
//! or upload (4.2). A blob stored on a signed-in connection names its
//! identity, which BLOB already told the server (12.12).

use risala_proto::binary::WrappedKey;
use risala_proto::mls::OrBlob;
use risala_proto::names::{BlobRef, BoxName, Uid};
use risala_proto::time::Timestamp;

use super::Result;
use crate::secret::SecretHash;

/// A device id (4.4), as stored: SHA-384 of the device key.
pub type DeviceBytes = [u8; 48];

/// A KeyPackageRef (12.8), as stored.
pub type RefBytes = [u8; 48];

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

/// A KeyPackage that passed the checks of KEYPKG ADD (12.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewKeyPackage {
    /// The device's identity.
    pub uid: Uid,
    /// Its device id.
    pub device: DeviceBytes,
    /// Its KeyPackageRef.
    pub key_package_ref: RefBytes,
    /// The MLSMessage that holds it.
    pub key_package: Vec<u8>,
    /// Whether it is of last resort.
    pub last_resort: bool,
    /// When its lifetime ends.
    pub not_after: Timestamp,
}

/// What [`KeysStore::add_key_package`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddedKeyPackage {
    /// It is stored, replacing the device's last-resort one if it is one.
    Added,
    /// The server already holds it.
    Again,
    /// The device has as many ordinary KeyPackages as the server keeps
    /// (`ERR forbidden`).
    Full,
}

/// What KEYPKG COUNT reports (12.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeyPackageCount {
    /// Ordinary KeyPackages whose lifetime has not ended.
    pub ordinary: u64,
    /// Whether a last-resort one is held.
    pub last_resort: bool,
}

/// A KeyPackage KEYPKG GET hands out (12.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandedKeyPackage {
    /// The device it belongs to.
    pub device: DeviceBytes,
    /// The MLSMessage that holds it.
    pub key_package: Vec<u8>,
}

/// What a Welcome may be put for (12.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Handout {
    /// A KeyPackage KEYPKG GET handed out: the Welcome goes to its device,
    /// and is kept until WELCOME DEL.
    Device {
        /// Its identity.
        uid: Uid,
        /// Its device id.
        device: DeviceBytes,
        /// The hash of the handout's put secret (12.5).
        secret: SecretHash,
    },
    /// The KeyPackage of an external Add proposal that a public room's
    /// commit applied: the Welcome waits for WELCOME GET.
    Room {
        /// The room's mailbox.
        mailbox: BoxName,
        /// The epoch the commit started, the Welcome's.
        epoch: u64,
        /// The identity of the device that made the commit.
        committer_uid: Uid,
        /// Its device id.
        committer: DeviceBytes,
    },
}

/// A [`Handout`] as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoutRow {
    /// Its row, for [`KeysStore::put_welcome`].
    pub id: i64,
    /// What it is.
    pub handout: Handout,
}

/// What [`KeysStore::put_welcome`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PutWelcome {
    /// Stored, with this id.
    Stored(String),
    /// It replaced the Welcome with this id, which its device had not
    /// deleted.
    Replaced(String),
    /// The handout already has this very Welcome: nothing changed.
    Same,
    /// The handout's Welcome has been deleted by its device (WELCOME DEL)
    /// or expired, and this is another one.
    Taken,
    /// The handout is gone (`ERR not-found`).
    NotFound,
    /// The device has too many pending Welcomes (`ERR rate-limited`).
    TooMany,
}

/// A public room's commit applied external Add proposals (12.6, 12.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomJoins {
    /// The room's mailbox.
    pub mailbox: BoxName,
    /// The epoch the commit started.
    pub epoch: u64,
    /// The identity of the device that made the commit.
    pub committer_uid: Uid,
    /// Its device id.
    pub committer: DeviceBytes,
    /// The KeyPackageRefs of the proposals' KeyPackages.
    pub refs: Vec<RefBytes>,
    /// The ratchet tree of `epoch`, or the blob the server made of it.
    pub tree: OrBlob<Vec<u8>>,
    /// The tree's size in bytes.
    pub tree_size: u64,
}

/// A Welcome for an external proposal's KeyPackage, with the tree of its
/// epoch (12.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomWelcome {
    /// The Welcome.
    pub welcome: StoredWelcome,
    /// The ratchet tree, or the blob that holds it.
    pub tree: OrBlob<Vec<u8>>,
}

/// A pending Welcome (12.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredWelcome {
    /// The id the server gave it (3.5).
    pub id: String,
    /// Its bytes, or the blob that holds them.
    pub welcome: OrBlob<Vec<u8>>,
}

/// The owner in `blob_keeps` of the tree blob of the public room of
/// `mailbox` (12.12), which keeps it while the room's epoch is current.
pub fn room_tree_owner(mailbox: &BoxName) -> String {
    let hex: String = mailbox.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
    format!("room {hex}")
}

/// What the server stores, from [`KeysStore::stored_total`] (7.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StoredBytes {
    /// Blobs, `put` URLs not yet used, uploaded files and kept posts.
    pub stored: u64,
    /// The blobs and uploaded files that open reports keep (5.8), which
    /// nothing else counts.
    pub reported: u64,
}

/// A blob the server holds (12.12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobRecord {
    /// Its hash.
    pub hash: BlobRef,
    /// Its size in bytes.
    pub size: u64,
    /// The last BLOB command that named it, from which retention counts.
    pub stored: Timestamp,
    /// Whether something keeps it whatever the retention: a current
    /// backup or a public room's current tree.
    pub kept: bool,
    /// The mailbox whose quota it counts against, if any.
    pub mailbox: Option<BoxName>,
    /// The identity that stored it on a signed-in connection, if any.
    pub uid: Option<Uid>,
}

/// A `put` URL BLOB handed out (12.12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobPut {
    /// The URL's public part.
    pub id: String,
    /// The hash of its secret part.
    pub secret: SecretHash,
    /// The blob it is for.
    pub hash: BlobRef,
    /// The blob's size.
    pub size: u64,
    /// The mailbox whose quota it counts against, if any.
    pub mailbox: Option<BoxName>,
    /// The identity it counts against, if any.
    pub uid: Option<Uid>,
    /// When the URL stops working.
    pub expires: Timestamp,
}

/// An uploaded file, or one waiting for its upload (5.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadRecord {
    /// The URLs' public part.
    pub id: String,
    /// The mailbox it was uploaded for.
    pub mailbox: BoxName,
    /// The hashes of the secret parts of the `put`, `get` and `del` URLs.
    pub put: SecretHash,
    /// See `put`.
    pub get: SecretHash,
    /// See `put`.
    pub del: SecretHash,
    /// The size UPLOAD named.
    pub size: u64,
    /// When UPLOAD made it: the `put` URL works for 10 minutes from here.
    pub created: Timestamp,
    /// Whether an upload to the `put` URL has started.
    pub claimed: bool,
    /// When the upload finished, from which retention counts.
    pub stored: Option<Timestamp>,
    /// How many open reports keep it (5.8).
    pub held: u32,
    /// Its uploader deleted it while reports kept it.
    pub deleted: bool,
}

/// What [`KeysStore::expire_keys`] deleted, whose bytes are to be removed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Expired {
    /// Blobs.
    pub blobs: Vec<BlobRef>,
    /// Uploads, by id.
    pub uploads: Vec<String>,
}

/// What [`KeysStore::expire_keys`] counts from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpiryTimes {
    /// Now: KeyPackages whose lifetime ended and `put` URLs past their
    /// time go.
    pub now: Timestamp,
    /// Now less the retention period (7.5): Welcomes, blobs and files
    /// stored before it go.
    pub retention: Timestamp,
    /// Public rooms' trees kept for Welcomes, of commits before this, go
    /// with their Welcomes (12.6).
    pub room_trees: Timestamp,
    /// Uploads that UPLOAD made before this and that never started go.
    pub unclaimed: Timestamp,
    /// Uploads that UPLOAD made before this and that never finished go.
    pub unfinished: Timestamp,
}

/// KeyPackages, Welcomes, blobs, files and backups (5.6, 12).
pub trait KeysStore {
    // ---- KeyPackages (12.5)

    /// Stores a KeyPackage at `now`, unless the device already has
    /// `max_ordinary` ordinary ones whose lifetime has not ended. A
    /// last-resort one replaces the device's last.
    fn add_key_package(
        &self,
        key_package: &NewKeyPackage,
        max_ordinary: u64,
        now: Timestamp,
    ) -> Result<AddedKeyPackage>;

    /// How many KeyPackages the server holds for a device at `now`.
    fn count_key_packages(
        &self,
        uid: &Uid,
        device: &DeviceBytes,
        now: Timestamp,
    ) -> Result<KeyPackageCount>;

    /// Whether `uid` has uploaded KeyPackages within the retention period
    /// (`since`).
    fn knows_key_package_uid(&self, uid: &Uid, since: Timestamp) -> Result<bool>;

    /// Hands out one KeyPackage of each of `devices` of `uid`, at `now`:
    /// its oldest ordinary one whose lifetime has not ended, which is
    /// deleted, or else its last-resort one, which is kept. Each one is
    /// recorded as handed out, with the hash of the put secret paired
    /// with its device, for one Welcome (12.5, 12.8).
    fn take_key_packages(
        &self,
        uid: &Uid,
        devices: &[(DeviceBytes, SecretHash)],
        now: Timestamp,
    ) -> Result<Vec<HandedKeyPackage>>;

    /// A device has been removed (4.8, 12.8): its KeyPackages and pending
    /// Welcomes go.
    fn forget_device(&self, uid: &Uid, device: &DeviceBytes) -> Result<()>;

    // ---- Welcomes (12.8)

    /// Records the KeyPackages of a public room's commit that applied
    /// external Add proposals, each for one Welcome from the committing
    /// device, and keeps the tree of the epoch it started; a blob tree is
    /// recorded as a blob, with no mailbox or identity, if it is new.
    fn add_room_joins(&self, joins: &RoomJoins, now: Timestamp) -> Result<()>;

    /// What a Welcome may be put for under `key_package_ref`, newest
    /// first.
    fn handouts(&self, key_package_ref: &RefBytes) -> Result<Vec<HandoutRow>>;

    /// Puts a Welcome for the handout `handout`, whose hash (12.12) is
    /// `digest`: stored with id `id` unless its device already has
    /// `max_pending` Welcomes pending, or replacing the one it has if that
    /// has not been fetched (12.8).
    fn put_welcome(
        &self,
        handout: i64,
        id: &str,
        welcome: &OrBlob<Vec<u8>>,
        digest: &[u8; 48],
        max_pending: u64,
        now: Timestamp,
    ) -> Result<PutWelcome>;

    /// The Welcomes pending for a device, oldest first.
    fn device_welcomes(&self, uid: &Uid, device: &DeviceBytes) -> Result<Vec<StoredWelcome>>;

    /// Deletes the Welcome `id` if it is pending for the device.
    fn delete_welcome(&self, uid: &Uid, device: &DeviceBytes, id: &str) -> Result<()>;

    /// The Welcome for the KeyPackage of an external proposal, with its
    /// epoch's tree, if it has arrived. Reading it changes nothing: anyone
    /// may ask, since the KeyPackageRefs of external proposals are public.
    fn room_welcome(&self, key_package_ref: &RefBytes) -> Result<Option<RoomWelcome>>;

    // ---- Blobs (12.12)

    /// The blob `hash`, if the server holds it.
    fn blob(&self, hash: &BlobRef) -> Result<Option<BlobRecord>>;

    /// A BLOB command named `hash` at `now`: retention counts from now.
    /// Returns whether the server holds it.
    fn touch_blob(&self, hash: &BlobRef, now: Timestamp) -> Result<bool>;

    /// Records a `put` URL.
    fn add_blob_put(&self, put: &BlobPut) -> Result<()>;

    /// The `put` URL whose public part is `id`.
    fn blob_put(&self, id: &str) -> Result<Option<BlobPut>>;

    /// Uses the `put` URL `id` up. Returns `false` if it was already used.
    fn claim_blob_put(&self, id: &str) -> Result<bool>;

    /// A blob's bytes are stored, at `now`. If the server already held it,
    /// retention counts from now.
    fn blob_stored(&self, put: &BlobPut, now: Timestamp) -> Result<()>;

    /// The bytes the server stores for everyone (7.5), for its own caps:
    /// blobs, `put` URLs not yet used, uploaded files and kept posts, apart
    /// from the blobs and files open reports keep, which count on their own
    /// (5.8).
    fn stored_total(&self) -> Result<StoredBytes>;

    /// The bytes of files and blobs kept for `mailbox`, and of `put` URLs
    /// for it that are not yet used (7.5).
    fn mailbox_file_bytes(&self, mailbox: &BoxName) -> Result<u64>;

    /// Keeps `hashes` for `owner` whatever the retention, replacing what
    /// `owner` kept before. Returns the blobs `owner` kept before that
    /// nothing keeps now.
    fn set_blob_keeps(&self, owner: &str, hashes: &[BlobRef]) -> Result<Vec<BlobRef>>;

    /// Records the blob `hash` of `size` bytes, which the server wrote
    /// itself, as stored at `now`, counted against nobody. If the server
    /// held it already, retention counts from now.
    fn store_own_blob(&self, hash: &BlobRef, size: u64, now: Timestamp) -> Result<()>;

    /// Deletes the blob `hash` now, unless something keeps it. Returns
    /// whether it was deleted.
    fn delete_blob(&self, hash: &BlobRef) -> Result<bool>;

    // ---- Uploads (5.6)

    /// Records a new upload.
    fn add_upload(&self, upload: &UploadRecord) -> Result<()>;

    /// The upload whose public part is `id`.
    fn upload(&self, id: &str) -> Result<Option<UploadRecord>>;

    /// Starts the one upload the `put` URL allows. Returns `false` if one
    /// has started.
    fn claim_upload(&self, id: &str) -> Result<bool>;

    /// The upload `id` finished at `now`. Returns `false` if it is gone.
    fn upload_stored(&self, id: &str, now: Timestamp) -> Result<bool>;

    /// Its uploader deletes the upload `id`. Returns whether its bytes are
    /// to be removed now; if reports keep it, it stays until they are
    /// resolved (5.8).
    fn delete_upload(&self, id: &str) -> Result<bool>;

    /// The report `report` keeps the upload `id` until it is resolved
    /// (5.8). Keeping it twice changes nothing. An upload no report keeps
    /// yet is kept only if the bytes reports keep stay within
    /// `max_reported` (0: no limit); returns whether it is kept.
    fn hold_upload(&self, report: &str, id: &str, max_reported: u64) -> Result<bool>;

    /// The report `report` was resolved: the uploads it kept stop being
    /// kept by it (5.8). Returns those whose bytes are to be removed now:
    /// deleted, or stored before `retention`, and kept by no other report.
    fn release_uploads(&self, report: &str, retention: Timestamp) -> Result<Vec<String>>;

    // ---- Backups (12.13)

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

    // ---- Expiry (7.5, 12.5)

    /// Deletes what has expired at `times`: KeyPackages whose lifetime has
    /// ended, unused `put` URLs, and Welcomes, records of handing out,
    /// blobs and files past retention, and public rooms' trees past their
    /// 24 hours with their Welcomes, and the blobs the server made of
    /// them. Returns the blobs and files whose bytes are to be removed.
    fn expire_keys(&self, times: &ExpiryTimes) -> Result<Expired>;
}
