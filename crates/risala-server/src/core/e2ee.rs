//! What the server keeps of encrypted conversations without reading it
//! (Section 12): KeyPackages (KEYPKG, 12.4), pending Welcomes (WELCOME,
//! 12.7) and key backups (BACKUP, 12.10). Groups themselves, INIT,
//! COMMIT, GROUPINFO and ENC, are not here.
//!
//! # Devices
//!
//! A device is an identity and the key its connection signed in with
//! (4.5). KeyPackages and Welcomes belong to devices, so KEYPKG ADD and
//! COUNT and both WELCOME commands act for the connection's device. When
//! a key leaves its identity's key file, the server deletes the device's
//! KeyPackages and Welcomes (4.7, 12.7): at KEY DEL and ADMIN DELKEY, and
//! when a key file fetched for AUTH, KEYPKG GET or COMMIT no longer lists
//! it. It does so holding `keys_lock`, and KEYPKG ADD stores a KeyPackage
//! under the same lock, after checking that its connection is still signed
//! in, so none is stored for a key just removed.
//!
//! # KeyPackages
//!
//! KEYPKG ADD checks a KeyPackage with [`check_key_package`] (12.4).
//! KEYPKG GET hands out each ordinary
//! KeyPackage once, then the last-resort one (12.4). It leaves out devices
//! whose keys are not in the identity's key file: the server's own records
//! for a hosted identity, or else the file as the fetcher has it, fetched
//! again if a device with KeyPackages is missing from a cached copy, as
//! AUTH does (4.4). If the file cannot be had, KEYPKG GET fails with
//! `ERR unavailable`, rather than hand out KeyPackages of keys that may
//! have been removed. KeyPackages whose lifetimes have ended are never
//! handed out, and [`Hub::prune_key_packages`] deletes them.
//!
//! # Welcomes
//!
//! COMMIT stores the Welcome of a commit that adds devices, with the tree
//! of the new epoch, as pending for each device, in the transaction of the
//! commit (12.5), then sends it to the devices' connections with
//! [`Inner::send_welcomes`]. The store keeps the commit's Welcome and tree
//! while any of its devices has it pending (12.7; PLAN.md 5, item 22,
//! change P), and a device deletes its Welcome only once it has joined.
//! COMMIT also deletes the pending Welcomes of the conversation for each
//! device whose leaf it removes (12.7).
//!
//! WELCOME LIST sends the pending Welcomes one at a time, waiting for room
//! in the connection's queue before each after the first, since each may
//! be a long line (2.3). A Welcome stored meanwhile may come both live and
//! in the list; devices tell them apart by id.
//!
//! # Backups
//!
//! Backups belong to the identity, by conversation id (12.10). The server
//! keeps them until the identity deletes them with BACKUP DEL, or is
//! deleted itself (4.8). It does not delete them when the identity leaves
//! the conversation, or when the conversation is dropped (10.4), though
//! 12.10 would let it: the identity may still read the conversation's
//! history, and keeping them needs no bookkeeping. An epoch keeps at most
//! [`MAX_BACKUP_KEYS_PER_EPOCH`] blobs, one per key id, so that a page,
//! which always holds every blob of an epoch, stays small. BACKUP ADD is
//! refused for a conversation the identity has never been in, or an epoch
//! its group has not reached (12.10; see
//! [`E2eeStore::may_back_up`](crate::store::E2eeStore::may_back_up)), so
//! that nobody stores blobs for anything else.
//!
//! KEYPKG ADD refuses KeyPackages larger than
//! [`Limits::max_key_package_bytes`](crate::config::Limits::max_key_package_bytes)
//! (12.4). ENC and COMMIT have no byte budget yet beyond the line limit:
//! that comes with the rate limits of M10.

use std::num::NonZeroU64;
use std::time::Duration;

use risala_mls::RisalaCrypto;
use risala_proto::auth::PublicKey;
use risala_proto::command::{BackupCommand, Command, KeyPkgCommand, WelcomeCommand};
use risala_proto::error::ErrorCode;
use risala_proto::mls::{BackupBlob, DEFAULT_BACKUP_LIMIT, KeyPackage};
use risala_proto::names::{Id, Identity, Seq, Uid};
use risala_proto::server::{ErrResponse, OkResponse, ServerLine, ServerMessage};
use risala_proto::time::Timestamp;

use super::commands::{Fail, Outcome, Reply, fail, not_supported};
use super::identity::unavailable;
use super::keys::FetchError;
use super::state::ConvState;
use super::{Hub, Inner, KEY_FETCH_TIMEOUT};
use crate::handler::{ConnId, OutLine};
use crate::store::{
    BackupAdded, BackupCheck, KeyPackageAdded, NewKeyPackage, NewWelcome, StoreError,
};

/// The window of `limits.key_package_gets_per_hour` (12.4).
pub(super) const KEYPKG_GET_WINDOW: Duration = Duration::from_secs(60 * 60);

/// The most blobs one epoch of a conversation keeps for an identity, each
/// with another key id (12.10). A recovery key is replaced by deleting
/// every blob and backing up again (12.10), so an epoch normally has one,
/// and briefly two while devices learn of a new recovery key. BACKUP ADD
/// of a further one gets `ERR forbidden`.
pub const MAX_BACKUP_KEYS_PER_EPOCH: usize = 8;

/// The most seconds a KeyPackage's lifetime may span: 12 weeks and one
/// hour (12.4).
pub const MAX_KEY_PACKAGE_LIFETIME: u64 = 7_261_200;

/// How often [`Hub::prune_key_packages_every`] runs in `risalad`.
pub const KEY_PACKAGE_PRUNE_PERIOD: Duration = Duration::from_secs(60 * 60);

/// What KEYPKG ADD learns from a KeyPackage that passes its checks (12.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CheckedKeyPackage {
    /// The KeyPackage's ref [RFC9420], computed with the suite's hash,
    /// SHA-384.
    pub(super) kp_ref: Vec<u8>,
    /// The end of its lifetime.
    pub(super) not_after: Timestamp,
    /// Whether it has the `last_resort` extension [MLS-EXT].
    pub(super) last_resort: bool,
}

/// The checks of KEYPKG ADD (12.4), for a KeyPackage uploaded by the
/// device `uid` and `device_key` at `now`. Runs on the blocking pool,
/// since it verifies ML-DSA signatures.
///
/// [`risala_mls::check_key_package`] decodes `key_package` as an
/// MLSMessage holding a KeyPackage, and checks that:
///
/// - its protocol version is `mls10`, and its cipher suite is `0x0052`
///   (12.2)
/// - its leaf's credential is a `basic` credential whose identity is
///   `uid`, in lower case, in UTF-8 (12.2)
/// - its leaf's signature key is `device_key`, the raw 1312-byte ML-DSA-44
///   key the connection signed in with (4.5, 12.2)
/// - its leaf's capabilities list the cipher suite, `basic` credentials,
///   the conversation extension `0xF2A1` and `last_resort` `0x000A` (12.2)
/// - its lifetime is acceptable at `now`: `not_before <= now <=
///   not_after`, spanning at most [`MAX_KEY_PACKAGE_LIFETIME`] seconds
///   (12.4)
/// - its signatures verify, and the rest of the checks of RFC 9420,
///   section 10.1 hold, such as `init_key` differing from the leaf's
///   `encryption_key`
///
/// It then returns the KeyPackage's ref, the end of its lifetime, and
/// whether it carries the `last_resort` extension. A KeyPackage that fails
/// any check gets `ERR invalid`.
pub(super) fn check_key_package(
    crypto: &RisalaCrypto,
    key_package: &KeyPackage,
    uid: &Uid,
    device_key: &PublicKey,
    now: Timestamp,
) -> Result<CheckedKeyPackage, Fail> {
    let checked =
        risala_mls::check_key_package(crypto, key_package, uid, device_key, now.to_system_time())
            .map_err(|e| fail(ErrorCode::Invalid, &e.to_string()))?;
    let kp_ref = checked
        .key_package
        .hash_ref(crypto)
        .map_err(|_| fail(ErrorCode::Invalid, "the KeyPackage has no ref"))?;
    // A lifetime past the end of time cannot be acceptable now.
    let not_after = checked
        .not_after
        .checked_mul(1000)
        .and_then(Timestamp::from_unix_millis)
        .ok_or_else(|| fail(ErrorCode::Invalid, "the KeyPackage's lifetime is too long"))?;
    Ok(CheckedKeyPackage {
        kp_ref: kp_ref.as_slice().to_vec(),
        not_after,
        last_resort: checked.last_resort,
    })
}

fn rate_limited(retry: u64) -> Fail {
    Fail::Err(
        ErrResponse::new(ErrorCode::RateLimited)
            .with_retry(retry)
            .with_message("too many KEYPKG GET; try again later"),
    )
}

impl Hub {
    /// Deletes the KeyPackages whose lifetimes have ended (12.4), and
    /// returns how many. Ended ones are never handed out or counted
    /// meanwhile; this frees their room.
    pub async fn prune_key_packages(&self) -> Result<u64, StoreError> {
        let now = self.inner.now();
        self.inner.db(move |s| s.prune_key_packages(now)).await
    }

    /// Runs [`prune_key_packages`](Self::prune_key_packages) at once and
    /// then every `period`, until the future is dropped. Failures are
    /// logged.
    pub async fn prune_key_packages_every(self, period: Duration) {
        let mut tick = tokio::time::interval(period);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            match self.prune_key_packages().await {
                Ok(0) => {}
                Ok(n) => tracing::debug!(key_packages = n, "deleted ended KeyPackages"),
                Err(e) => tracing::error!("deleting ended KeyPackages failed: {e}"),
            }
        }
    }
}

impl Inner {
    /// KEYPKG (12.4), WELCOME (12.7) and BACKUP (12.10), for identities
    /// only: guests were refused before this (13).
    pub(super) async fn e2ee(&self, uid: &Uid, reply: &Reply, command: Command) -> Outcome {
        match command {
            Command::KeyPkg(KeyPkgCommand::Add { key_package }) => {
                self.keypkg_add(uid, reply, key_package).await
            }
            Command::KeyPkg(KeyPkgCommand::Count) => self.keypkg_count(uid, reply).await,
            Command::KeyPkg(KeyPkgCommand::Get { uid: target }) => {
                self.keypkg_get(uid, reply, target).await
            }
            Command::Welcome(WelcomeCommand::List) => self.welcome_list(uid, reply).await,
            Command::Welcome(WelcomeCommand::Del { id }) => self.welcome_del(uid, reply, id).await,
            Command::Backup(BackupCommand::Add { id, epoch, blob }) => {
                self.backup_add(uid, id, epoch, blob).await
            }
            Command::Backup(BackupCommand::Get { id, after, limit }) => {
                self.backup_get(uid, reply, id, after, limit).await
            }
            Command::Backup(BackupCommand::Del { id }) => self.backup_del(uid, id).await,
            _ => Err(not_supported()),
        }
    }

    /// The key connection `id` of `uid` signed in with (4.5).
    pub(super) fn device_key(&self, uid: &Uid, id: ConnId) -> Result<PublicKey, Fail> {
        let user = self.reg().users.get(uid).cloned();
        user.and_then(|user| {
            user.lock()
                .conns
                .iter()
                .find(|c| c.handle.id() == id)
                .and_then(|c| c.key.clone())
        })
        .ok_or_else(|| fail(ErrorCode::Forbidden, "this connection has no device key"))
    }

    /// Whether connection `id` is still signed in and reading commands: its
    /// key was not removed, nor its identity deleted (4.7, 4.8).
    fn still_signed_in(&self, id: ConnId) -> bool {
        self.reg().conns.get(&id).is_some_and(|c| !c.detached)
    }

    /// KEYPKG ADD (12.4).
    async fn keypkg_add(&self, uid: &Uid, reply: &Reply, key_package: KeyPackage) -> Outcome {
        let id = reply.handle.id();
        let key = self.device_key(uid, id)?;
        let max = self.config.limits.max_key_package_bytes;
        if key_package.decoded_len() > max {
            return Err(fail(
                ErrorCode::TooLong,
                &format!("a KeyPackage is at most {max} bytes"),
            ));
        }
        let now = self.now();
        let checked = {
            let (kp, who, k) = (key_package.clone(), uid.clone(), key.clone());
            let crypto = self.mls.clone();
            tokio::task::spawn_blocking(move || check_key_package(&crypto, &kp, &who, &k, now))
                .await
                .map_err(|e| Fail::Store(StoreError::Task(e.to_string())))??
        };
        let new = NewKeyPackage {
            key_package,
            kp_ref: checked.kp_ref,
            not_after: checked.not_after,
            last_resort: checked.last_resort,
        };
        let max = self.config.limits.max_key_packages;
        // See the module documentation, "Devices".
        let _keys = self.keys_lock.lock().await;
        if !self.still_signed_in(id) {
            return Ok(None);
        }
        let who = uid.clone();
        match self
            .db(move |s| s.add_key_package(&who, &key, &new, max, now))
            .await?
        {
            KeyPackageAdded::Added | KeyPackageAdded::Already => Ok(Some(OkResponse::new())),
            KeyPackageAdded::Full => Err(fail(
                ErrorCode::Forbidden,
                "the server keeps no more KeyPackages for this device",
            )),
        }
    }

    /// KEYPKG COUNT (12.4).
    async fn keypkg_count(&self, uid: &Uid, reply: &Reply) -> Outcome {
        let key = self.device_key(uid, reply.handle.id())?;
        let (who, now) = (uid.clone(), self.now());
        let count = self
            .db(move |s| s.key_package_count(&who, &key, now))
            .await?;
        Ok(Some(
            OkResponse::new()
                .with_count(count.ordinary)
                .with_last_resort(count.last_resort),
        ))
    }

    /// KEYPKG GET (12.4).
    async fn keypkg_get(&self, uid: &Uid, reply: &Reply, target: Uid) -> Outcome {
        let unknown = || fail(ErrorCode::NotFound, "no such identity");
        // Guests have no devices, and the server does not know them as
        // identities.
        let identity = target.to_identity().ok_or_else(unknown)?;
        let who = target.clone();
        if self.db(move |s| s.identity(&who)).await?.is_none() {
            return Err(unknown());
        }
        let now = self.now();
        let limit = self.config.limits.key_package_gets_per_hour;
        let slot = self
            .key_package_gets
            .take(uid.clone(), limit, now)
            .map_err(rate_limited)?;
        // The asking device is left out: it is a device of `target` only
        // if `target` is its own identity.
        let except = if target == *uid {
            Some(self.device_key(uid, reply.handle.id())?)
        } else {
            None
        };
        let listed = self.listed_keys(&identity, &target).await?;
        let who = target.clone();
        let taken = self
            .db(move |s| s.take_key_packages(&who, except.as_ref(), &listed, now))
            .await?;
        if let Some(slot) = slot {
            slot.keep();
        }
        for (n, (_, key_package)) in taken.into_iter().enumerate() {
            // Each may be a long line (2.3): wait for room for the next.
            if n > 0 && !self.wait_for_reply_room(&reply.handle).await {
                return Ok(None);
            }
            reply.line(ServerLine::KeyPkg {
                uid: target.clone(),
                key_package,
            });
        }
        Ok(Some(OkResponse::new()))
    }

    /// The keys in the key file of `identity`, whose uid is `uid`, for
    /// KEYPKG GET (12.4): see the module documentation, "KeyPackages".
    async fn listed_keys(&self, identity: &Identity, uid: &Uid) -> Result<Vec<PublicKey>, Fail> {
        if self.hosts(identity) {
            let who = uid.clone();
            let keys = self.db(move |s| s.hosted_keys(&who)).await?;
            return Ok(keys
                .unwrap_or_default()
                .into_iter()
                .map(|k| k.key)
                .collect());
        }
        let (who, now) = (uid.clone(), self.now());
        let devices = self.db(move |s| s.key_package_devices(&who, now)).await?;
        if devices.is_empty() {
            // Nothing to hand out: no need for the key file.
            return Ok(Vec::new());
        }
        for refresh in [false, true] {
            let fetch = self.keys.fetcher.fetch_boxed(identity, refresh);
            let fetched = match tokio::time::timeout(KEY_FETCH_TIMEOUT, fetch).await {
                Ok(Ok(fetched)) => fetched,
                Ok(Err(e)) => return Err(unavailable(&e)),
                Err(_) => return Err(unavailable(&FetchError::Failed("timed out".into()))),
            };
            if !fetched.cached {
                // Fetched just now: the keys it does not list are gone.
                self.close_removed_keys(uid, &fetched.keys);
                self.forget_unlisted_devices(uid, &fetched.keys).await;
            }
            // A copy from the cache may be older than a device (4.4).
            let stale = fetched.cached && devices.iter().any(|d| !fetched.keys.contains(d));
            if !stale || refresh {
                return Ok(fetched.keys);
            }
        }
        unreachable!("the second pass returns")
    }

    /// Deletes the KeyPackages and pending Welcomes of the device `uid`
    /// and `key`, whose key left the identity's key file (4.7, 12.7). The
    /// caller holds `keys_lock`. A failure is logged: the key is gone
    /// either way, and its KeyPackages are not handed out.
    pub(super) async fn forget_device(&self, uid: &Uid, key: &PublicKey) {
        let (who, gone) = (uid.clone(), key.clone());
        if let Err(e) = self.db(move |s| s.forget_device(&who, &gone)).await {
            tracing::error!(%uid, "deleting a removed key's KeyPackages and Welcomes failed: {e}");
        }
    }

    /// [`forget_device`](Self::forget_device) for each device of `uid`
    /// with KeyPackages, Welcomes or leaves whose key is not in `keys`, the
    /// keys of a key file fetched just now (4.4). The keys it lists are
    /// taken off the list of removed keys, so that a key that left the
    /// file and came back does not leave its leaves marked for good
    /// (12.6). Takes `keys_lock`.
    pub(super) async fn forget_unlisted_devices(&self, uid: &Uid, keys: &[PublicKey]) {
        let _keys = self.keys_lock.lock().await;
        let (who, listed) = (uid.clone(), keys.to_vec());
        if let Err(e) = self.db(move |s| s.relist_keys(&who, &listed)).await {
            tracing::error!(%uid, "taking listed keys off the removed keys failed: {e}");
        }
        let who = uid.clone();
        let stored = match self.db(move |s| s.stored_devices(&who)).await {
            Ok(stored) => stored,
            Err(e) => {
                tracing::error!(%uid, "listing an identity's devices failed: {e}");
                return;
            }
        };
        for key in stored.iter().filter(|k| !keys.contains(k)) {
            self.forget_device(uid, key).await;
        }
    }

    /// Sends the WELCOME line of an accepted commit, whose COMMIT event is
    /// `seq` in the conversation `st`, to the connections of each device
    /// it adds (12.5, 12.7). `ids` are the ids the store gave each device's
    /// Welcome, in the order of `welcome.devices`; COMMIT stores them in
    /// the transaction of the commit, so a Welcome is never lost after the
    /// commit is accepted.
    ///
    /// For COMMIT, which calls it holding the conversation's lock, after it
    /// has queued the COMMIT event. A connection whose queue has no room
    /// for the line is dropped, as for any live line; the device gets the
    /// Welcome from WELCOME LIST when it connects again.
    pub(super) fn send_welcomes(&self, st: &ConvState, seq: Seq, welcome: &NewWelcome, ids: &[Id]) {
        for ((uid, device), id) in welcome.devices.iter().zip(ids) {
            let Some(user) = self.reg().users.get(uid).cloned() else {
                continue;
            };
            let line = OutLine::new(ServerMessage::new(ServerLine::Welcome {
                conv: st.name_for(uid),
                id: id.clone(),
                seq,
                welcome: welcome.welcome.clone(),
                tree: welcome.tree.clone(),
            }));
            for conn in &user.lock().conns {
                if conn.key.as_ref() == Some(device) {
                    conn.handle.send_line(line.clone());
                }
            }
        }
    }

    /// WELCOME LIST (12.7).
    async fn welcome_list(&self, uid: &Uid, reply: &Reply) -> Outcome {
        let key = self.device_key(uid, reply.handle.id())?;
        let (who, k) = (uid.clone(), key.clone());
        let ids = self.db(move |s| s.pending_welcomes(&who, &k)).await?;
        let mut sent = false;
        for id in ids {
            // Each may be a long line (2.3): wait for room for the next.
            if sent && !self.wait_for_reply_room(&reply.handle).await {
                return Ok(None);
            }
            let (who, k) = (uid.clone(), key.clone());
            // Read one at a time, since each may be large.
            let Some(w) = self.db(move |s| s.pending_welcome(&who, &k, &id)).await? else {
                // Deleted meanwhile.
                continue;
            };
            reply.line(ServerLine::Welcome {
                conv: w.conv,
                id: w.id,
                seq: w.seq,
                welcome: w.welcome,
                tree: w.tree,
            });
            sent = true;
        }
        Ok(Some(OkResponse::new()))
    }

    /// WELCOME DEL (12.7). A Welcome that is not pending for this device,
    /// for example one deleted before, is not an error: a device that
    /// lost the `OK` sends WELCOME DEL again.
    async fn welcome_del(&self, uid: &Uid, reply: &Reply, id: Id) -> Outcome {
        let key = self.device_key(uid, reply.handle.id())?;
        let who = uid.clone();
        self.db(move |s| s.delete_welcome(&who, &key, &id)).await?;
        Ok(Some(OkResponse::new()))
    }

    /// BACKUP ADD (12.10).
    async fn backup_add(&self, uid: &Uid, id: Id, epoch: u64, blob: BackupBlob) -> Outcome {
        // Checked before storing: an identity that has been in a
        // conversation stays so, and a group's epoch only grows.
        let (who, conv) = (uid.clone(), id.clone());
        match self.db(move |s| s.may_back_up(&who, &conv, epoch)).await? {
            BackupCheck::Allowed => {}
            BackupCheck::NotIn => {
                return Err(fail(
                    ErrorCode::Forbidden,
                    "you have never been in that conversation",
                ));
            }
            BackupCheck::LaterEpoch => {
                return Err(fail(
                    ErrorCode::Forbidden,
                    "the conversation's group has not reached that epoch",
                ));
            }
        }
        let who = uid.clone();
        let added = self
            .db(move |s| s.add_backup(&who, &id, epoch, &blob, MAX_BACKUP_KEYS_PER_EPOCH))
            .await?;
        match added {
            BackupAdded::Added | BackupAdded::Kept => Ok(Some(OkResponse::new())),
            BackupAdded::Full => Err(fail(
                ErrorCode::Forbidden,
                "this epoch has backups under too many recovery keys; delete the old ones",
            )),
        }
    }

    /// BACKUP GET (12.10). A page holds at most `limit` epochs, and no more
    /// blobs than a response may have lines, but always every blob of each
    /// epoch in it.
    async fn backup_get(
        &self,
        uid: &Uid,
        reply: &Reply,
        id: Id,
        after: Option<u64>,
        limit: Option<NonZeroU64>,
    ) -> Outcome {
        let epochs = limit.map_or(DEFAULT_BACKUP_LIMIT, NonZeroU64::get);
        let blobs = self
            .config
            .limits
            .reply_lines()
            .saturating_sub(1)
            .max(MAX_BACKUP_KEYS_PER_EPOCH);
        let (who, conv) = (uid.clone(), id.clone());
        let page = self
            .db(move |s| s.backups(&who, &conv, after, epochs, blobs))
            .await?;
        for (epoch, blob) in page.blobs {
            reply.line(ServerLine::Backup {
                id: id.clone(),
                epoch,
                blob,
            });
        }
        Ok(Some(OkResponse::new().with_more(page.more)))
    }

    /// BACKUP DEL (12.10).
    async fn backup_del(&self, uid: &Uid, id: Option<Id>) -> Outcome {
        let who = uid.clone();
        self.db(move |s| s.delete_backups(&who, id.as_ref()))
            .await?;
        Ok(Some(OkResponse::new()))
    }
}
