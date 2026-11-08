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

/// A recovery key just made ([`Account::create_recovery_key`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRecoveryKey {
    /// The key, to show the user once: 52 characters in groups of four
    /// (12.10). The app does not keep it.
    pub key: String,
    /// For an identity the server does not host, the line the user adds
    /// to the key file (4.4); `None` when KEY ADD added it.
    pub key_file_line: Option<String>,
    /// For an identity the server does not host, the line of the previous
    /// recovery key, which the user removes from the key file; `None` if
    /// there was none, or KEY DEL removed it.
    pub old_key_file_line: Option<String>,
}

/// The id a recovery key is kept under in the key store, beside the
/// identity's device key (PLAN.md 42). It starts with `~`, as no identity
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

    /// Says whether the new device with key fingerprint `fingerprint` is
    /// the user's (12.9). A confirmed device gets every history key this
    /// device holds, so that it reads the whole history, and the recovery
    /// key if this device holds one, so that it backs up the keys it gets
    /// later (12.10); one that is not gets none. Ask the user to compare
    /// the fingerprint with the one the new device shows.
    pub async fn confirm_device(
        &self,
        fingerprint: &str,
        confirmed: bool,
    ) -> Result<(), ClientError> {
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
        self.e2ee(E2eeOp::ConfirmDevice { key, confirmed }).await
    }

    /// Makes a new recovery key (12.10), and returns it to show the user
    /// once:
    ///
    /// - its key goes into the identity's key file with the label
    ///   `recovery`: by KEY ADD if the server hosts the identity, or else
    ///   as a line for the user to add ([`NewRecoveryKey::key_file_line`]),
    ///   in place of the previous recovery key's;
    /// - the identity's other devices get it, in its conversation with
    ///   itself;
    /// - every history key is backed up under it, and the old backups go.
    ///
    /// Needs a connection.
    pub async fn create_recovery_key(&self) -> Result<NewRecoveryKey, ClientError> {
        let identity = self.e2ee_identity()?;
        let keys = self.keys_store()?;
        let key = RecoveryKey::generate().map_err(|e| ClientError::Keys {
            kind: super::KeyErrorKind::Failed,
            message: format!("no randomness: {e}"),
        })?;
        let public = key.signing_key(&identity).public_key();
        let line = keys::key_line(&public, Some("recovery"))
            .map_err(|_| ClientError::Invalid("recovery key line".into()))?;
        let (k, id) = (keys.clone(), identity.clone());
        let old = blocking(&self.client().runtime().clone(), move || {
            load_recovery_key(&*k, &id)
        })
        .await?;
        let old_public = old.as_ref().map(|o| o.signing_key(&identity).public_key());
        let old_line = old_public
            .as_ref()
            .map(|p| keys::key_line(p, Some("recovery")))
            .transpose()
            .map_err(|_| ClientError::Invalid("recovery key line".into()))?;
        // 4.7: KEY ADD works only for an identity the server hosts.
        let hosted = match self.add_key(&line, "recovery").await {
            Ok(_) => true,
            Err(ClientError::Server { .. } | ClientError::Refused { .. }) => false,
            Err(e) => return Err(e),
        };
        let mut old_key_file_line = None;
        if let Some(old_line) = old_line
            && old_public.as_ref() != Some(&public)
        {
            if hosted {
                if let Err(e) = self.remove_key(&old_line).await {
                    tracing::warn!(error = %e, "removing the previous recovery key");
                }
            } else {
                old_key_file_line = Some(old_line);
            }
        }
        let (k, id, rk) = (keys.clone(), identity.clone(), key.clone());
        blocking(&self.client().runtime().clone(), move || {
            save_recovery_key(&*k, &id, &rk)
        })
        .await?;
        // The old backups go; everything is backed up again under the new
        // key (12.10).
        if old.is_some() {
            self.request(Command::Backup(BackupCommand::Del { id: None }))
                .await?;
        }
        self.e2ee(E2eeOp::SetRecovery(Some(key.clone()))).await?;
        self.e2ee(E2eeOp::ShareRecovery(key.clone())).await?;
        Ok(NewRecoveryKey {
            key: key.to_display().to_string(),
            key_file_line: (!hosted).then_some(line),
            old_key_file_line,
        })
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

impl Client {
    /// Gets an identity back after every device is lost, with its recovery
    /// key (12.10): signs in to `server` with the recovery key's own key,
    /// adds this device's key to the identity with KEY ADD, removes every
    /// other key but the recovery key's, then signs in again with this
    /// device's key. Returns the account, connected.
    ///
    /// This works for an identity the server hosts (4.7). For one it does
    /// not host, edit the key file instead, then add the identity as
    /// usual. The device's key must exist already
    /// ([`create_device_key`](Self::create_device_key)). The new device
    /// then joins the identity's encrypted conversations (12.6); restore
    /// the history keys with [`Account::restore_backup`].
    pub async fn recover_identity(
        &self,
        server: &str,
        identity: &str,
        recovery: &str,
    ) -> Result<Account, ClientError> {
        let addr = parse_server(server)?;
        let identity: Identity = identity
            .trim()
            .parse()
            .map_err(|_| ClientError::Invalid(format!("identity {identity:?}")))?;
        let recovery = parse_recovery(recovery)?;
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
        // uploads no KeyPackages.
        let result = async {
            session.auth(&identity, &signing).await.map_err(fail)?;
            let lines = answered(
                &server_name,
                session
                    .request(Command::Key(risala_proto::command::KeyCommand::List))
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
                        .request(Command::Key(risala_proto::command::KeyCommand::Add {
                            key: device.clone(),
                            label: String::new(),
                        }))
                        .await
                        .map_err(fail)?,
                )?;
            }
            let recovery_public = signing.public_key();
            for key in listed {
                if key != device && key != recovery_public {
                    answered(
                        &server_name,
                        session
                            .request(Command::Key(risala_proto::command::KeyCommand::Del { key }))
                            .await
                            .map_err(fail)?,
                    )?;
                }
            }
            Ok::<(), ClientError>(())
        }
        .await;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(3), session.quit("")).await;
        result?;
        let (k, id, rk) = (keys, identity.clone(), recovery);
        blocking(self.runtime(), move || save_recovery_key(&*k, &id, &rk)).await?;
        let account = self.add_identity(server, identity.as_str())?;
        account.connect().await?;
        Ok(account)
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
