//! Storage for what the server keeps of encrypted conversations without
//! reading it (Section 12): KeyPackages (12.4), pending Welcomes (12.7)
//! and key backups (12.10).
//!
//! A **device** is an identity together with one of its device keys, the
//! key it signed in with (4.5). KeyPackages and Welcomes belong to a
//! device, backups to the identity.
//!
//! The store does not look inside MLS data. Whoever stores a KeyPackage
//! has checked it, and passes on what the store needs from it: its ref,
//! the end of its lifetime, and whether it is a last-resort one.

use risala_proto::auth::PublicKey;
use risala_proto::mls::{BackupBlob, KeyPackage, RatchetTree, Welcome};
use risala_proto::names::{Conv, Id, Seq, Uid};
use risala_proto::time::Timestamp;

use super::{ConvKey, Result};

/// A KeyPackage to store (12.4), with what was learned from it when it
/// was checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewKeyPackage {
    /// The KeyPackage, as received.
    pub key_package: KeyPackage,
    /// Its ref [RFC9420]. Storing a KeyPackage with the same ref again for
    /// the same device stores nothing.
    pub kp_ref: Vec<u8>,
    /// The end of its lifetime: it is not handed out from then on.
    pub not_after: Timestamp,
    /// Whether it has the `last_resort` extension.
    pub last_resort: bool,
}

/// The result of [`E2eeStore::add_key_package`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPackageAdded {
    /// It was stored. A last-resort KeyPackage replaced the device's
    /// earlier one, if it had one.
    Added,
    /// The device has a KeyPackage with the same ref already: nothing
    /// changed.
    Already,
    /// The device has as many ordinary KeyPackages as it may: nothing was
    /// stored.
    Full,
}

/// What [`E2eeStore::key_package_count`] reports (12.4): the device's
/// KeyPackages whose lifetimes have not ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyPackageCount {
    /// Its ordinary KeyPackages.
    pub ordinary: u64,
    /// Whether it has a last-resort one.
    pub last_resort: bool,
}

/// A Welcome pending for a device (12.7), as its WELCOME line needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingWelcome {
    /// Its id.
    pub id: Id,
    /// The conversation, named as the device's identity sees it (5.2).
    pub conv: Conv,
    /// The store's key for the conversation.
    pub conv_key: ConvKey,
    /// The seq of the COMMIT event that added the device.
    pub seq: Seq,
    /// The Welcome.
    pub welcome: Welcome,
    /// The ratchet tree of the epoch the commit started.
    pub tree: RatchetTree,
}

/// The result of [`E2eeStore::add_backup`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupAdded {
    /// The blob was stored.
    Added,
    /// The epoch has a blob with the same key id already, which was kept
    /// (12.10).
    Kept,
    /// The epoch has as many blobs, each with another key id, as it may:
    /// nothing was stored.
    Full,
}

/// A page of backup blobs (12.10), oldest epoch first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupPage {
    /// Each blob with its epoch. Every blob of an epoch is in the page, or
    /// none of them.
    pub blobs: Vec<(u64, BackupBlob)>,
    /// Whether there are blobs of later epochs than the last one returned.
    pub more: bool,
}

/// Part of [`super::Store`]: see the module documentation.
///
/// Every method blocks, like the rest of [`super::Store`].
pub trait E2eeStore {
    // ---- KeyPackages (12.4) ----

    /// Stores a KeyPackage for the device `uid` and `key`, unless the
    /// device has `max` ordinary ones already. A last-resort KeyPackage
    /// replaces the device's earlier one, and does not count against
    /// `max`. The device's KeyPackages whose lifetimes ended by `now` are
    /// deleted first.
    fn add_key_package(
        &self,
        uid: &Uid,
        key: &PublicKey,
        key_package: &NewKeyPackage,
        max: usize,
        now: Timestamp,
    ) -> Result<KeyPackageAdded>;

    /// How many KeyPackages the device `uid` and `key` has whose lifetimes
    /// have not ended by `now` (12.4).
    fn key_package_count(
        &self,
        uid: &Uid,
        key: &PublicKey,
        now: Timestamp,
    ) -> Result<KeyPackageCount>;

    /// The device keys of `uid` that have a KeyPackage whose lifetime has
    /// not ended by `now`, in the byte order of their base64.
    fn key_package_devices(&self, uid: &Uid, now: Timestamp) -> Result<Vec<PublicKey>>;

    /// Takes one KeyPackage for each device of `uid` whose key is in
    /// `listed` and is not `except`, in one transaction (12.4): the oldest
    /// ordinary one, which is deleted, or else the last-resort one, which
    /// is kept. Only KeyPackages whose lifetimes have not ended by `now`
    /// count. In the byte order of the device keys' base64.
    fn take_key_packages(
        &self,
        uid: &Uid,
        except: Option<&PublicKey>,
        listed: &[PublicKey],
        now: Timestamp,
    ) -> Result<Vec<(PublicKey, KeyPackage)>>;

    /// Deletes every KeyPackage whose lifetime ended by `now` (12.4), and
    /// returns how many.
    fn prune_key_packages(&self, now: Timestamp) -> Result<u64>;

    // ---- Welcomes (12.7) ----

    /// Stores the Welcome of the commit whose COMMIT event is `seq` in the
    /// conversation `conv`, with the ratchet tree of the epoch it started,
    /// as pending for each of `devices` (12.5, 12.7). Returns each
    /// device's Welcome id, in the order of `devices`. A device listed
    /// twice gets one Welcome. Nothing is stored for no devices.
    fn add_welcomes(
        &self,
        conv: ConvKey,
        seq: Seq,
        welcome: &Welcome,
        tree: &RatchetTree,
        devices: &[(Uid, PublicKey)],
    ) -> Result<Vec<Id>>;

    /// The ids of the Welcomes pending for the device `uid` and `key`, in
    /// the order their commits were stored. Those of conversations that
    /// are being dropped (10.4) are left out.
    fn pending_welcomes(&self, uid: &Uid, key: &PublicKey) -> Result<Vec<Id>>;

    /// The Welcome `id`, if it is pending for the device `uid` and `key`
    /// and its conversation is not being dropped (10.4).
    fn pending_welcome(
        &self,
        uid: &Uid,
        key: &PublicKey,
        id: &Id,
    ) -> Result<Option<PendingWelcome>>;

    /// Deletes the Welcome `id` of the device `uid` and `key` (12.7), and
    /// with the last pending one of its commit, the commit's Welcome and
    /// tree. Returns whether there was one.
    fn delete_welcome(&self, uid: &Uid, key: &PublicKey, id: &Id) -> Result<bool>;

    // ---- Devices (4.4, 4.7) ----

    /// The device keys of `uid` that have KeyPackages, pending Welcomes, or
    /// leaves in groups not yet known to be removed, whatever their
    /// lifetimes, in the byte order of their base64.
    fn stored_devices(&self, uid: &Uid) -> Result<Vec<PublicKey>>;

    /// Deletes the KeyPackages and pending Welcomes of the device `uid`
    /// and `key`, whose key left the identity's key file (4.7, 12.7), and
    /// notes that its leaves must be removed (12.6).
    fn forget_device(&self, uid: &Uid, key: &PublicKey) -> Result<()>;

    /// Notes that the keys `keys` of `uid` are in its key file again, as
    /// one fetched just now lists them (4.4): their leaves need not be
    /// removed after all (12.6).
    fn relist_keys(&self, uid: &Uid, keys: &[PublicKey]) -> Result<()>;

    // ---- Backups (12.10) ----

    /// Stores the blob of epoch `epoch` of the conversation with id
    /// `conv_id` for the identity `uid` (12.10). If the epoch has a blob
    /// with the same key id, that one is kept. A blob with another key id
    /// is refused once the epoch has `max_per_epoch`.
    fn add_backup(
        &self,
        uid: &Uid,
        conv_id: &Id,
        epoch: u64,
        blob: &BackupBlob,
        max_per_epoch: usize,
    ) -> Result<BackupAdded>;

    /// A page of the identity's blobs of the conversation `conv_id`
    /// (12.10): those of epochs after `after`, or from the oldest without
    /// it, oldest epoch first, for at most `max_epochs` epochs and
    /// `max_blobs` blobs. A page holds every blob of each epoch in it, so
    /// it stops before an epoch whose blobs do not all fit; but it always
    /// holds the first epoch whole.
    fn backups(
        &self,
        uid: &Uid,
        conv_id: &Id,
        after: Option<u64>,
        max_epochs: u64,
        max_blobs: usize,
    ) -> Result<BackupPage>;

    /// Deletes the identity's blobs of the conversation `conv_id`, or all
    /// of them (12.10). Returns how many.
    fn delete_backups(&self, uid: &Uid, conv_id: Option<&Id>) -> Result<u64>;
}
