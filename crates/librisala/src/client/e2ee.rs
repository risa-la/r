//! End-to-end encryption for apps (Section 12).
//!
//! Encrypted conversations look like any other: messages go through the
//! outbox and arrive in timelines. The differences an app sees are
//! [`ConversationInfo::encrypted`](super::ConversationInfo::encrypted)
//! and [`Message::encryption`](super::Message::encryption). Everything
//! else here is about the identity's devices and its recovery key:
//!
//! - **Encrypted rooms.** [`Conversation::encrypt`] makes a room the
//!   account owns, and is the only member of, encrypted for good (12.3).
//!   [`Conversation::invite`] then adds the invitee's devices to the room's
//!   group (12.6).
//! - **New devices.** When a new device of the identity appears, the app
//!   gets [`Notice::NewDevice`](super::Notice::NewDevice). Once the user
//!   says it is theirs, [`Account::confirm_device`] sends it the history
//!   keys, so that it reads the whole history offline (12.9).
//! - **Checking devices** (12.12). [`Account::devices`] lists an
//!   identity's device keys, with fingerprints to compare through another
//!   channel.
//! - **The recovery key** (12.10). [`Account::create_recovery_key`] makes
//!   one, shows it once, adds its key to the identity's key file, and backs
//!   up every history key under it. [`Account::restore_backup`] restores
//!   them on a device that lost them. [`Client::recover_identity`] gets the
//!   identity back after every device is lost.
//! - **Key files** (4.4, 12.12). Devices check every leaf of their groups
//!   against its identity's key file, fetched with
//!   [`ClientOptions::key_files`](super::ClientOptions::key_files), by
//!   default over HTTPS ([`HttpsKeyFiles`]).

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use risala_keyfetch::{FetchOptions, KeyFetcher};
use risala_mls::RecoveryKey;
use risala_proto::auth::PublicKey;
use risala_proto::command::{BackupCommand, Command};
use risala_proto::names::{Id, Identity, Uid};
use risala_proto::server::ServerLine;
use risala_proto::types::{HistoryMode, SendMode};
use tokio::sync::oneshot;

use super::account::{Cmd, E2eeOp, wait};
use super::{Account, Client, ClientError, Conversation, blocking, parse_server};
use crate::addr::TrustStore;
use crate::conn::Session;
use crate::conn::keys::{self, KeyStore};
use crate::store::{AccountId, Store, StoreError};
use crate::sync::OwnDeviceState;

/// A future that a [`KeyFiles`] returns.
pub type KeyFileFuture = Pin<Box<dyn Future<Output = Option<Vec<KeyFileEntry>>> + Send>>;

/// A key in a key file, with its label (4.4).
pub type KeyFileEntry = (PublicKey, Option<String>);

/// Where a device gets identities' key files, to check the leaves of its
/// groups (4.4, 12.12).
pub trait KeyFiles: Send + Sync {
    /// The keys `identity`'s key file lists, with their labels: none if it
    /// is gone (404 or 410). `None` if it could not be fetched, which says
    /// nothing about its keys (4.4).
    fn fetch(&self, identity: Identity) -> KeyFileFuture;
}

/// Key files fetched over HTTPS, under the rules of 4.4.
pub struct HttpsKeyFiles(Arc<KeyFetcher>);

impl HttpsKeyFiles {
    /// A fetcher with a cache of up to an hour (12.12). A device may
    /// reach key files on private addresses, unlike a server.
    pub fn new() -> HttpsKeyFiles {
        HttpsKeyFiles(Arc::new(KeyFetcher::new(FetchOptions {
            allow_private: true,
            ..FetchOptions::default()
        })))
    }

    /// A fetcher with options of its own: other roots or a resolver, as
    /// tests and tools need.
    pub fn with_options(options: FetchOptions) -> HttpsKeyFiles {
        HttpsKeyFiles(Arc::new(KeyFetcher::new(options)))
    }
}

impl Default for HttpsKeyFiles {
    fn default() -> HttpsKeyFiles {
        HttpsKeyFiles::new()
    }
}

impl KeyFiles for HttpsKeyFiles {
    fn fetch(&self, identity: Identity) -> KeyFileFuture {
        let fetcher = self.0.clone();
        Box::pin(async move {
            // The engine asks only when it needs a newer answer than it has.
            let entries = fetcher.fetch_entries(&identity, true).await.ok()?;
            Some(
                entries
                    .iter()
                    .map(|e| (e.key().clone(), e.label().map(str::to_owned)))
                    .collect(),
            )
        })
    }
}

/// Key files from memory, for tests and tools: what was set for each
/// identity, or a failed fetch for one never set.
#[derive(Default)]
pub struct MemoryKeyFiles(Mutex<HashMap<String, Vec<PublicKey>>>);

impl MemoryKeyFiles {
    /// Sets the keys `identity`'s key file lists.
    pub fn set(&self, identity: &str, keys: Vec<PublicKey>) {
        self.0
            .lock()
            .expect("poisoned")
            .insert(identity.to_lowercase(), keys);
    }

    /// Adds a key to `identity`'s key file.
    pub fn add(&self, identity: &str, key: PublicKey) {
        self.0
            .lock()
            .expect("poisoned")
            .entry(identity.to_lowercase())
            .or_default()
            .push(key);
    }

    /// Removes a key from `identity`'s key file.
    pub fn remove(&self, identity: &str, key: &PublicKey) {
        if let Some(keys) = self
            .0
            .lock()
            .expect("poisoned")
            .get_mut(&identity.to_lowercase())
        {
            keys.retain(|k| k != key);
        }
    }
}

impl KeyFiles for MemoryKeyFiles {
    fn fetch(&self, identity: Identity) -> KeyFileFuture {
        let keys = self
            .0
            .lock()
            .expect("poisoned")
            .get(identity.as_str())
            .cloned();
        Box::pin(async move { keys.map(|k| k.into_iter().map(|k| (k, None)).collect()) })
    }
}

/// A room's `history` setting for [`Conversation::encrypt`] (12.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum History {
    /// New members get the keys to read what was sent before them.
    Shared,
    /// New members read only what is sent after they are added.
    Joined,
}

/// A device of an identity, as this device knows it (12.12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    /// The key's fingerprint, to compare through another channel.
    pub fingerprint: String,
    /// The key file's label for it, unescaped; empty if none.
    pub label: String,
    /// Whether the identity's key file listed it when last fetched: `None`
    /// if no fetch has told yet.
    pub listed: Option<bool>,
    /// Whether it is the identity's recovery key rather than a device: its
    /// label is `recovery`, and no group has a leaf with it (12.12).
    pub recovery: bool,
    /// For the account's own identity, where the device is: new and
    /// waiting for the user, confirmed, or declined (12.9). `None` for
    /// others, and for this device.
    pub state: Option<OwnDeviceState>,
    /// Whether it is this device.
    pub this_device: bool,
}

/// A device of the identity the user declined ([`Account::confirm_device`]).
/// Its leaves are removed, but its key can still sign in and join groups
/// until it leaves the key file (12.9): offer to remove it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclinedDevice {
    /// The key's fingerprint.
    pub fingerprint: String,
    /// Its key file line, for [`Account::remove_key`] or to remove from a
    /// key file the server does not host (4.4).
    pub key_file_line: String,
}

/// A recovery key just made ([`Account::create_recovery_key`]), to show
/// the user once, and then keep with [`Account::finish_recovery_key`].
#[derive(Clone, PartialEq)]
pub struct NewRecoveryKey {
    /// The key, to show the user once: 52 characters in groups of four
    /// (12.10). The app does not keep it.
    pub key: String,
    /// For an identity the server does not host, the line the user adds
    /// to the key file (4.4); `None` when KEY ADD added it.
    pub key_file_line: Option<String>,
    /// For an identity the server does not host, the line of the previous
    /// recovery key, which the user removes from the key file; `None` if
    /// there was none, or KEY DEL removes it.
    pub old_key_file_line: Option<String>,
    /// When this device does not hold the previous recovery key, the key
    /// file lines of every other key labelled `recovery` (12.10). Offer to
    /// remove each, with [`Account::remove_key`] or by editing the key
    /// file, and warn about any that stays: it can still sign in.
    pub other_recovery_lines: Vec<String>,
    recovery: RecoveryKey,
    old: Option<RecoveryKey>,
    hosted: bool,
}

impl std::fmt::Debug for NewRecoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewRecoveryKey")
            .field("key", &"…")
            .field("key_file_line", &self.key_file_line)
            .field("old_key_file_line", &self.old_key_file_line)
            .field("other_recovery_lines", &self.other_recovery_lines)
            .finish_non_exhaustive()
    }
}

/// What [`Client::recover_identity`] did (12.10).
pub struct Recovered {
    /// The account, connected.
    pub account: Account,
    /// How many history keys were restored from the backups.
    pub restored: u64,
    /// Encrypted conversations the device could not join yet. While there
    /// are any, the lost devices' keys stay in the key file, since in a
    /// room a device may join only while its identity still has a leaf
    /// there: remove them later with [`Account::remove_key`].
    pub not_joined: Vec<String>,
    /// The key file lines of the lost keys that were removed.
    pub removed: Vec<String>,
}

impl std::fmt::Debug for Recovered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recovered")
            .field("account", &self.account.uid())
            .field("restored", &self.restored)
            .field("not_joined", &self.not_joined)
            .field("removed", &self.removed)
            .finish()
    }
}

/// The id a recovery key is kept under in the key store, beside the
/// identity's device key (PLAN.md 43). It starts with `~`, as no identity
/// does, so that it never names a device key, and uses only characters
/// every key store takes.
fn recovery_id(identity: &Identity) -> String {
    format!("~recovery-{identity}")
}

/// Keeps `identity`'s recovery key in the key store. It is 32 random bytes,
/// stored as a key's seed is.
pub(crate) fn save_recovery_key(
    keys: &dyn KeyStore,
    identity: &Identity,
    key: &RecoveryKey,
) -> Result<(), ClientError> {
    let as_seed = risala_proto::auth::SecretKey::from_seed(*key.as_bytes());
    keys.save(&recovery_id(identity), &as_seed)
        .map_err(|e| ClientError::from_key_store(&e))
}

/// `identity`'s recovery key from the key store, if this device holds it.
pub(crate) fn load_recovery_key(
    keys: &dyn KeyStore,
    identity: &Identity,
) -> Result<Option<RecoveryKey>, ClientError> {
    let key = keys
        .load(&recovery_id(identity))
        .map_err(|e| ClientError::from_key_store(&e))?;
    Ok(key.map(|k| RecoveryKey::from_bytes(*keys::key_seed(&k))))
}

/// A recovery key's key file line, labelled `recovery` (12.10).
fn recovery_line(public: &PublicKey) -> Result<String, ClientError> {
    keys::key_line(public, Some("recovery"))
        .map_err(|_| ClientError::Invalid("recovery key line".into()))
}

fn parse_recovery(typed: &str) -> Result<RecoveryKey, ClientError> {
    RecoveryKey::parse(typed).map_err(|_| ClientError::Invalid("recovery key".into()))
}

fn store_err(e: StoreError) -> ClientError {
    ClientError::from(e)
}

impl Conversation {
    /// The franking key and content of stored ENC event `seq`, to report
    /// it with REPORTENC (5.8): `None` for any other event. A message this
    /// device could not read cannot be reported.
    pub(crate) fn franking(
        &self,
        seq: risala_proto::names::Seq,
    ) -> Result<Option<risala_proto::mls::Franking>, ClientError> {
        let account = self.account().id();
        let conv = self.conv().clone();
        let (found, _) = self
            .account()
            .shared()
            .store
            .write(|tx| {
                let Some(row) = tx.conv_by_name(account, &conv)? else {
                    return Ok((false, None));
                };
                let encrypted =
                    tx.author_of(row.id, seq.get())?.is_some() && tx.is_enc(row.id, seq.get())?;
                Ok((encrypted, tx.franking(row.id, seq.get())?))
            })
            .map_err(store_err)?;
        match found {
            (false, _) => Ok(None),
            (true, None) => Err(ClientError::Invalid(
                "a message this device could not read".into(),
            )),
            (true, Some((content, key))) => {
                let key: [u8; 32] = key
                    .try_into()
                    .map_err(|_| ClientError::Store("a franking key is not 32 bytes".into()))?;
                Ok(Some(risala_proto::mls::Franking {
                    key: risala_proto::mls::FrankKey::from_bytes(key),
                    content: risala_proto::mls::Content::from_bytes(&content)
                        .map_err(|_| ClientError::Invalid("content too long to report".into()))?,
                }))
            }
        }
    }

    /// Makes this room end-to-end encrypted (12.3, 12.5): the account must
    /// own it and be its only member. The room is private for good, and
    /// joining it takes an invitation that adds the invitee's devices.
    /// `announcements` turns on `send mods` (6.2).
    pub async fn encrypt(&self, history: History, announcements: bool) -> Result<(), ClientError> {
        let room = self.room()?;
        let history = match history {
            History::Shared => HistoryMode::Shared,
            History::Joined => HistoryMode::Joined,
        };
        let send = if announcements {
            SendMode::Mods
        } else {
            SendMode::All
        };
        self.account()
            .e2ee(E2eeOp::EncryptRoom {
                room,
                history,
                send,
            })
            .await
    }
}

impl Conversation {
    /// Starts over with a conversation whose encryption stopped
    /// ([`Notice::EncryptionStopped`](super::Notice::EncryptionStopped)):
    /// the device joins, or starts, its group again (12.6). Only when the
    /// user asks: the change the device refused may be an attack, and
    /// joining again accepts it. Does nothing for a conversation whose
    /// encryption did not stop. Needs a connection.
    pub async fn reset_encryption(&self) -> Result<(), ClientError> {
        self.account()
            .e2ee(E2eeOp::ResetEncryption(self.conv().clone()))
            .await
    }
}

impl Account {
    pub(crate) async fn e2ee(&self, op: E2eeOp) -> Result<(), ClientError> {
        let (reply, rx) = oneshot::channel();
        self.shared().command(Cmd::E2ee { op, reply });
        wait(rx).await
    }

    fn e2ee_identity(&self) -> Result<Identity, ClientError> {
        self.shared()
            .uid
            .to_identity()
            .ok_or_else(|| ClientError::Invalid("a guest has no encryption".into()))
    }

    fn keys_store(&self) -> Result<Arc<dyn KeyStore>, ClientError> {
        self.client().key_store()
    }

    /// The devices of `uid` this device knows, from the groups it shares
    /// with it and its key file (12.12), oldest first. For the account's
    /// own identity, with whether the user confirmed each one.
    pub fn devices(&self, uid: &str) -> Result<Vec<DeviceInfo>, ClientError> {
        let uid: Uid = uid
            .trim()
            .parse()
            .map_err(|_| ClientError::Invalid(format!("uid {uid:?}")))?;
        let own = uid == self.shared().uid;
        let mine = self.device_key().ok().flatten().map(|k| k.fingerprint);
        let rows = self
            .shared()
            .store
            .device_keys(self.id(), &uid)
            .map_err(store_err)?;
        Ok(rows
            .into_iter()
            .map(|d| {
                let this_device = mine.as_deref() == Some(&*d.key.fingerprint().to_string());
                DeviceInfo {
                    fingerprint: d.key.fingerprint().to_string(),
                    label: d.label.clone().unwrap_or_default(),
                    listed: d.listed,
                    recovery: d.label.as_deref() == Some("recovery") && !d.in_group,
                    state: if own && !this_device { d.state } else { None },
                    this_device,
                }
            })
            .collect())
    }

    /// Fetches `uid`'s key file now (4.4, 12.12), so that
    /// [`devices`](Self::devices) shows what it lists, as when a key was
    /// just added or removed. The device acts on it as on its own fetches:
    /// leaves of keys it no longer lists are removed (12.6). Returns
    /// whether it could be fetched; a failed fetch changes nothing. Needs
    /// a connection.
    pub async fn refresh_devices(&self, uid: &str) -> Result<bool, ClientError> {
        let uid: Uid = uid
            .trim()
            .parse()
            .map_err(|_| ClientError::Invalid(format!("uid {uid:?}")))?;
        let identity = uid
            .to_identity()
            .ok_or_else(|| ClientError::Invalid(format!("{uid} is a guest")))?;
        let files: Arc<dyn KeyFiles> = self
            .shared()
            .options
            .key_files
            .clone()
            .unwrap_or_else(|| Arc::new(HttpsKeyFiles::new()));
        let keys = files.fetch(identity).await;
        let fetched = keys.is_some();
        self.e2ee(E2eeOp::KeyFile(uid, keys)).await?;
        Ok(fetched)
    }

    /// Says whether the new device with key fingerprint `fingerprint` is
    /// the user's (12.9). Ask the user to compare the fingerprint with the
    /// one the new device shows.
    ///
    /// A confirmed device gets every history key this device holds, so
    /// that it reads the whole history, and the recovery key if this device
    /// holds one, so that it backs up the keys it gets later (12.10). No
    /// keys go to any device while another device of the identity waits
    /// for this answer, since every one of them would read them.
    ///
    /// A declined device gets nothing, and this device removes its leaves
    /// from every encrypted conversation. Its key stays in the key file
    /// until removed: the answer is a [`DeclinedDevice`] with the key
    /// file line, to offer removing it with
    /// [`remove_key`](Self::remove_key) or by editing the key file.
    pub async fn confirm_device(
        &self,
        fingerprint: &str,
        confirmed: bool,
    ) -> Result<Option<DeclinedDevice>, ClientError> {
        let fingerprint = fingerprint.trim().to_lowercase();
        let key = self
            .shared()
            .store
            .device_keys(self.id(), &self.shared().uid)
            .map_err(store_err)?
            .into_iter()
            .find(|d| d.key.fingerprint().to_string() == fingerprint)
            .ok_or_else(|| ClientError::Invalid(format!("device {fingerprint}")))?
            .key;
        let line = keys::key_line(&key, None)
            .map_err(|_| ClientError::Invalid("a key file line".into()))?;
        self.e2ee(E2eeOp::ConfirmDevice { key, confirmed }).await?;
        Ok((!confirmed).then_some(DeclinedDevice {
            fingerprint,
            key_file_line: line,
        }))
    }

    /// Answers [`Notice::RecoveryKeyOffered`](super::Notice::RecoveryKeyOffered):
    /// with `true`, the recovery key another device of the identity sent
    /// replaces the one this device holds, and the history keys are backed
    /// up under it (12.10); with `false`, it is dropped. Needs a connection.
    pub async fn accept_recovery_key(&self, accept: bool) -> Result<(), ClientError> {
        self.e2ee(E2eeOp::AcceptRecovery(accept)).await
    }

    /// Makes a new recovery key (12.10), and returns it to show the user
    /// once. Its key goes into the identity's key file with the label
    /// `recovery`: by KEY ADD if the server hosts the identity, or else as
    /// a line for the user to add ([`NewRecoveryKey::key_file_line`]).
    ///
    /// Nothing is lost if this is the last step taken: the previous
    /// recovery key, and its backups, stay. Show the key, then call
    /// [`finish_recovery_key`](Self::finish_recovery_key). Needs a
    /// connection.
    pub async fn create_recovery_key(&self) -> Result<NewRecoveryKey, ClientError> {
        let identity = self.e2ee_identity()?;
        let keys = self.keys_store()?;
        let key = RecoveryKey::generate().map_err(|e| ClientError::Keys {
            kind: super::KeyErrorKind::Failed,
            message: format!("no randomness: {e}"),
        })?;
        let public = key.signing_key(&identity).public_key();
        let line = recovery_line(&public)?;
        let (k, id) = (keys.clone(), identity.clone());
        let old = blocking(&self.client().runtime().clone(), move || {
            load_recovery_key(&*k, &id)
        })
        .await?;
        let old_public = old.as_ref().map(|o| o.signing_key(&identity).public_key());
        // 4.7: KEY ADD works only for an identity the server hosts. It only
        // adds a key.
        let hosted = match self.add_key(&line, "recovery").await {
            Ok(_) => true,
            Err(ClientError::Server { .. } | ClientError::Refused { .. }) => false,
            Err(e) => return Err(e),
        };
        let old_key_file_line = match &old_public {
            Some(p) if !hosted && *p != public => Some(recovery_line(p)?),
            _ => None,
        };
        // 12.10: a device that does not hold the previous recovery key
        // cannot tell which line is its, so it offers to remove them all.
        let mut other_recovery_lines = Vec::new();
        if old.is_none() {
            let others: Vec<PublicKey> = if hosted {
                self.keys()
                    .await?
                    .into_iter()
                    .filter(|k| k.label == "recovery")
                    .filter_map(|k| {
                        super::identity::parse_public_key(&k.public_key)
                            .ok()
                            .map(|(k, _)| k)
                    })
                    .collect()
            } else {
                self.shared()
                    .store
                    .device_keys(self.id(), &self.shared().uid)
                    .map_err(store_err)?
                    .into_iter()
                    .filter(|d| d.label.as_deref() == Some("recovery") && d.listed == Some(true))
                    .map(|d| d.key)
                    .collect()
            };
            for other in others.iter().filter(|k| **k != public) {
                other_recovery_lines.push(recovery_line(other)?);
            }
        }
        Ok(NewRecoveryKey {
            key: key.to_display().to_string(),
            key_file_line: (!hosted).then_some(line),
            old_key_file_line,
            other_recovery_lines,
            recovery: key,
            old,
            hosted,
        })
    }

    /// Keeps a recovery key made with
    /// [`create_recovery_key`](Self::create_recovery_key), once it has been
    /// shown (12.10): this device keeps it and backs up every history key
    /// under it. Only once those backups are made are the old backups
    /// deleted, and everything backed up again under it, and the previous
    /// recovery key removed from the key file, if the server hosts the
    /// identity. The identity's other devices get it once the key file
    /// lists it and every device is confirmed. Needs a connection.
    pub async fn finish_recovery_key(&self, made: &NewRecoveryKey) -> Result<(), ClientError> {
        let identity = self.e2ee_identity()?;
        let keys = self.keys_store()?;
        let (k, id, rk) = (keys, identity.clone(), made.recovery.clone());
        blocking(&self.client().runtime().clone(), move || {
            save_recovery_key(&*k, &id, &rk)
        })
        .await?;
        self.e2ee(E2eeOp::SetRecovery(Some(made.recovery.clone())))
            .await?;
        self.wait_backed_up(&made.recovery).await?;
        // The old backups go, and everything is backed up again under the
        // new key (12.10).
        self.request(Command::Backup(BackupCommand::Del { id: None }))
            .await?;
        self.shared()
            .store
            .clear_backed_up(self.id())
            .map_err(store_err)?;
        self.e2ee(E2eeOp::SetRecovery(Some(made.recovery.clone())))
            .await?;
        self.wait_backed_up(&made.recovery).await?;
        if made.hosted
            && let Some(old) = &made.old
        {
            let old_public = old.signing_key(&identity).public_key();
            if old_public != made.recovery.signing_key(&identity).public_key() {
                self.remove_key(&recovery_line(&old_public)?).await?;
            }
        }
        self.e2ee(E2eeOp::ShareRecovery(made.recovery.clone()))
            .await
    }

    /// Waits until every history key is backed up under `recovery`, or
    /// fails if the backups stop making progress.
    async fn wait_backed_up(&self, recovery: &RecoveryKey) -> Result<(), ClientError> {
        let identity = self.e2ee_identity()?;
        let key_id = recovery.backup_key(&identity).key_id().to_vec();
        let mut last = u64::MAX;
        loop {
            self.wait_synced().await?;
            let left = self
                .shared()
                .store
                .keys_not_backed_up(self.id(), &key_id)
                .map_err(store_err)?;
            if left == 0 {
                return Ok(());
            }
            if left >= last {
                return Err(ClientError::Invalid(format!(
                    "{left} history keys could not be backed up under the new recovery key; \
                     the old backups were kept"
                )));
            }
            last = left;
        }
    }

    /// Restores history keys from the backups made under the recovery key
    /// `typed` (12.10), for every conversation the cache knows, and keeps
    /// the key to back up from now on. Returns how many keys were restored.
    /// A key that matches no backup at all is
    /// [`ClientError::Invalid`]. Needs a connection.
    pub async fn restore_backup(&self, typed: &str) -> Result<u64, ClientError> {
        let identity = self.e2ee_identity()?;
        let recovery = parse_recovery(typed)?;
        let backup = recovery.backup_key(&identity);
        let store = self.shared().store.clone();
        let account = self.id();
        let ids: Vec<Id> = store
            .conversations(account)
            .map_err(store_err)?
            .into_iter()
            .filter_map(|c| c.conv_id)
            .collect();
        let mut restored = Vec::new();
        let mut blobs = 0u64;
        for id in ids {
            let mut after = None;
            loop {
                let answer = self
                    .request(Command::Backup(BackupCommand::Get {
                        id: id.clone(),
                        after,
                        limit: None,
                    }))
                    .await?;
                let mut last = None;
                for m in &answer.lines {
                    if let ServerLine::Backup { id: i, epoch, blob } = &m.line
                        && *i == id
                    {
                        blobs += 1;
                        last = Some(*epoch);
                        if let Ok(key) = backup.open(&id, *epoch, blob) {
                            restored.push((id.clone(), *epoch, key));
                        }
                    }
                }
                match (answer.ok.more().ok().flatten(), last) {
                    (Some(true), Some(last)) => after = Some(last),
                    _ => break,
                }
            }
        }
        if blobs > 0 && restored.is_empty() {
            return Err(ClientError::Invalid("recovery key".into()));
        }
        let n = restored.len() as u64;
        let me = self.shared().uid.clone();
        let rt = self.client().runtime().clone();
        let (changes, cascade) =
            blocking(&rt, move || restore_keys(&store, account, &me, restored))
                .await
                .map_err(store_err)?;
        super::driver::publish_changes(self.shared(), changes);
        drop(cascade);
        let keys = self.keys_store()?;
        let (k, id, rk) = (keys, identity, recovery.clone());
        blocking(&rt, move || save_recovery_key(&*k, &id, &rk)).await?;
        self.e2ee(E2eeOp::SetRecovery(Some(recovery))).await?;
        Ok(n)
    }
}

/// Stores restored history keys and decrypts what they open (12.10).
fn restore_keys(
    store: &Store,
    account: AccountId,
    me: &Uid,
    keys: Vec<(Id, u64, risala_mls::HistoryKey)>,
) -> Result<(Vec<crate::store::Change>, crate::store::e2ee::Cascade), StoreError> {
    let (cascade, changes) = store.write(|tx| {
        let mut convs = Vec::new();
        for (id, epoch, key) in &keys {
            tx.put_history_key(
                account,
                id,
                *epoch,
                key,
                crate::store::e2ee::KeySource::Backup,
                None,
                None,
            )?;
            if let Some(row) = tx.conv_by_id(account, id)?
                && !convs.contains(&row.name)
            {
                convs.push(row.name);
            }
        }
        tx.decrypt_cascade(account, me, convs)
    })?;
    Ok((changes, cascade))
}

/// How many times [`Client::recover_identity`] waits for the connection to
/// settle while the device still joins encrypted conversations.
const JOIN_ROUNDS: usize = 5;

impl Client {
    /// Gets an identity back after every device is lost, with its recovery
    /// key (12.10), in the order 12.10 gives:
    ///
    /// 1. signs in to `server` with the recovery key's own key, and adds
    ///    this device's key with KEY ADD;
    /// 2. signs in again with this device's key, and joins the identity's
    ///    encrypted conversations (12.6);
    /// 3. restores the history keys from the backups;
    /// 4. only then removes every other key but the recovery key's, the
    ///    lost devices' and any other `recovery` key, since in a room a
    ///    device may join only while its identity still has a leaf there.
    ///    If a conversation could not be joined, the keys stay
    ///    ([`Recovered::not_joined`]).
    ///
    /// Then make a new recovery key, as the lost devices hold this one:
    /// [`Account::create_recovery_key`], show it, and
    /// [`Account::finish_recovery_key`].
    ///
    /// This works for an identity the server hosts (4.7). For one it does
    /// not host, edit the key file instead, then add the identity as
    /// usual. The device's key must exist already
    /// ([`create_device_key`](Self::create_device_key)).
    pub async fn recover_identity(
        &self,
        server: &str,
        identity: &str,
        recovery: &str,
    ) -> Result<Recovered, ClientError> {
        let addr = parse_server(server)?;
        let identity: Identity = identity
            .trim()
            .parse()
            .map_err(|_| ClientError::Invalid(format!("identity {identity:?}")))?;
        let typed = recovery;
        let recovery = parse_recovery(typed)?;
        let signing = recovery.signing_key(&identity);
        let keys = self.key_store()?;
        let device = keys
            .load(identity.as_str())
            .map_err(|e| ClientError::from_key_store(&e))?
            .ok_or_else(|| ClientError::Keys {
                kind: super::KeyErrorKind::NoKey,
                message: format!("no key for {identity}"),
            })?
            .public_key();
        let server_name = addr.to_string();
        let fail = |e: crate::conn::Error| ClientError::from_sign_in(&server_name, &e);
        let trust: Arc<dyn TrustStore> = Arc::new(self.store().clone());
        let options = self.options().session.clone();
        let session = Session::connect(&addr, trust, options)
            .await
            .map_err(fail)?;
        // 12.10: this connection is signed in with the recovery key, and
        // sends KEY commands only.
        let session = RecoverySession(session);
        let result = async {
            session.auth(&identity, &signing).await.map_err(fail)?;
            let lines = answered(
                &server_name,
                session
                    .key(risala_proto::command::KeyCommand::List)
                    .await
                    .map_err(fail)?,
            )?;
            let listed: Vec<PublicKey> = lines
                .iter()
                .filter_map(|m| match &m.line {
                    ServerLine::Key { key, .. } => Some(key.clone()),
                    _ => None,
                })
                .collect();
            if !listed.contains(&device) {
                answered(
                    &server_name,
                    session
                        .key(risala_proto::command::KeyCommand::Add {
                            key: device.clone(),
                            label: String::new(),
                        })
                        .await
                        .map_err(fail)?,
                )?;
            }
            Ok::<Vec<PublicKey>, ClientError>(listed)
        }
        .await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(3), session.0.quit("")).await;
        let listed = result?;
        let (k, id, rk) = (keys, identity.clone(), recovery);
        blocking(self.runtime(), move || save_recovery_key(&*k, &id, &rk)).await?;
        let account = self.add_identity(server, identity.as_str())?;
        account.connect().await?;

        // 12.6: join every encrypted conversation before anything else.
        let mut pending = Vec::new();
        for _ in 0..JOIN_ROUNDS {
            account.wait_synced().await?;
            let now = account
                .shared()
                .store
                .encryption_pending(account.id())
                .map_err(store_err)?;
            let stuck = now == pending;
            pending = now;
            if pending.is_empty() || stuck {
                break;
            }
        }
        let restored = account.restore_backup(typed).await?;

        // 12.10: only then do the lost keys go.
        let mut removed = Vec::new();
        if pending.is_empty() {
            let recovery_public = signing.public_key();
            for key in listed {
                if key == device || key == recovery_public {
                    continue;
                }
                let line = keys::key_line(&key, None)
                    .map_err(|_| ClientError::Invalid("a key file line".into()))?;
                account.remove_key(&line).await?;
                removed.push(line);
            }
        }
        Ok(Recovered {
            account,
            restored,
            not_joined: pending.iter().map(ToString::to_string).collect(),
            removed,
        })
    }
}

/// A connection signed in with the recovery key (12.10). It can send only
/// KEY commands, so it never uploads KeyPackages, starts or changes a
/// group, or sends ENC: the recovery key never joins a group.
struct RecoverySession(Session);

impl RecoverySession {
    async fn auth(
        &self,
        identity: &Identity,
        key: &risala_proto::auth::SecretKey,
    ) -> Result<(), crate::conn::Error> {
        self.0.auth(identity, key).await.map(|_| ())
    }

    async fn key(
        &self,
        command: risala_proto::command::KeyCommand,
    ) -> Result<crate::conn::Response, crate::conn::Error> {
        self.0.request(Command::Key(command)).await
    }
}

/// The lines of a command's answer, or its error.
fn answered(
    server: &str,
    response: crate::conn::Response,
) -> Result<Vec<risala_proto::server::ServerMessage>, ClientError> {
    match response.into_result() {
        Ok((lines, _)) => Ok(lines),
        Err(crate::conn::CommandError::Server(err)) => Err(ClientError::server(&err)),
        Err(e) => Err(ClientError::from_conn(server, &e.into())),
    }
}
