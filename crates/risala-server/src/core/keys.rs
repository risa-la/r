//! What the server keeps for devices without reading it (5.6, 12.5,
//! 12.8, 12.12, 12.13): KEYPKG, WELCOME, BLOB, BACKUP and UPLOAD, and the
//! HTTPS side of blobs and files ([`disk`]).
//!
//! The store keeps KeyPackages, Welcomes, blobs, uploads and backups
//! ([`KeysStore`](crate::store::KeysStore)); the bytes of blobs and files live in
//! [`Config::files_dir`]. Upload and blob URLs are bearer secrets, stored
//! as hashes and compared in constant time ([`crate::secret`]).
//!
//! # What other areas call
//!
//! - [`room_joins_committed`]: the mailbox area, when it accepts a public
//!   room's commit that applies external Add proposals: their KeyPackages
//!   may then get one Welcome each from the committing device, and the
//!   tree of the new epoch is kept for WELCOME GET (12.6, 12.8).
//! - [`blob_bytes`]: the identity area for KEYS PUT, reports, and the
//!   mailbox area, for the bytes of a blob a line names (12.12).
//! - [`keep_room_tree`]: the mailbox area, when a public room's tree is a
//!   blob, so that it is kept while its epoch is current (12.12).
//! - [`charge_address`] and [`stored_bytes`]: the mailbox area, so that
//!   POST, UPLOAD and BLOB count against one window per network address,
//!   and posts, files and blobs against one quota per mailbox (7.5).
//! - [`device_removed`]: the identity area, when a device leaves an
//!   identity (12.8).
//! - [`hold_file`]: reports, which keep the files they name (5.8).
//! - [`info`]: INFO's `upload`, `blobs` and `files` (8.5).

pub(crate) mod disk;

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use risala_mls::{DeviceId, RisalaCrypto};
use risala_proto::binary::read_blob_list;
use risala_proto::command::{BackupCommand, BlobPermit, Command, KeyPkgCommand, WelcomeCommand};
use risala_proto::error::ErrorCode;
use risala_proto::frame::MAX_SERVER_LINE;
use risala_proto::mls::{
    KeyPackage, KeyPackageRef, OrBlob, PutSecret, RatchetTree, SendToken, Welcome, WelcomeSecret,
};
use risala_proto::names::{BlobRef, BoxName, Identity, Uid};
use risala_proto::server::{
    ErrResponse, FileOrigin, OkResponse, ServerLine, ServerMessage, Upload,
};
use risala_proto::time::Timestamp;

use super::command::{Cx, Reply, err, misrouted};
use super::rate::{WindowLimit, network};
use super::state::{ConnEntry, Who};
use super::{Hub, Inner, identity, mailbox};
use crate::config::Config;
use crate::handler::{ConnHandle, ConnId};
use crate::secret::{SecretHash, random_bytes, random_token};
use crate::store::keys::{
    AddedKeyPackage, BlobPut, DeviceBytes, Handout, NewKeyPackage, PutWelcome, RoomJoins,
    StoredWelcome, UploadRecord,
};
use crate::store::{BackupRecord, Store, StoreError};

/// How long a `put` URL works (5.6, 12.12).
pub const PUT_WINDOW: Duration = Duration::from_secs(10 * 60);

/// How long an upload that started may take before what it left behind is
/// deleted.
pub const UNFINISHED_UPLOAD: Duration = Duration::from_secs(24 * 60 * 60);

/// How often the area's background work runs.
const MAINTAIN_EVERY: Duration = Duration::from_secs(60);

/// The characters of the public part of a URL, and of a Welcome's id.
const ID_LEN: usize = 25;

/// The characters of the secret part of a URL: 32 of `a-z 0-9`, over 165
/// bits, more than the 128 that 5.6 asks for.
const SECRET_LEN: usize = 32;

/// The paths of the HTTPS listener (see [`disk`]).
pub(crate) mod paths {
    /// `GET <prefix><96 hex digits>`: a blob (12.12). INFO's `blobs`.
    pub const BLOBS: &str = "/blobs/";
    /// `PUT /blob/<id>/<secret>`: BLOB's `put` URL (12.12).
    pub const BLOB_PUT: &str = "/blob/";
    /// `PUT /up/<id>/<secret>`: UPLOAD's `put` URL (5.6).
    pub const UPLOAD_PUT: &str = "/up/";
    /// `GET /f/<id>/<secret>`: UPLOAD's `get` URL (5.6).
    pub const UPLOAD_GET: &str = "/f/";
    /// `DELETE /del/<id>/<secret>`: UPLOAD's `del` URL (5.6).
    pub const UPLOAD_DEL: &str = "/del/";
}

/// What the keys area keeps in memory.
#[derive(Debug)]
pub(crate) struct State {
    /// For checking KeyPackages and computing their refs (12.5).
    crypto: Arc<RisalaCrypto>,
    /// Where blobs and files are kept.
    dir: PathBuf,
    /// The origin of the HTTPS listener, as clients reach it: `None` if
    /// there is none, and then no blobs or files.
    url: RwLock<Option<String>>,
    /// Held while blob files are created and deleted, so that a blob that
    /// expires as it is uploaded again keeps its file.
    fs: Mutex<()>,
    /// Held by BACKUP PUT and BACKUP DEL, so that each identity's backup
    /// and the blobs it keeps change together.
    backups: tokio::sync::Mutex<()>,
    /// KEYPKG GET per network address and per uid asked for (12.5).
    gets_by_address: WindowLimit<IpAddr>,
    gets_by_uid: WindowLimit<Uid>,
    /// Bytes asked to be stored per network address, POST, UPLOAD and
    /// BLOB together (7.5), and per identity with BLOB (12.12).
    address_bytes: ByteWindow<IpAddr>,
    identity_bytes: ByteWindow<Uid>,
}

impl State {
    /// Loads the area's state when the hub starts.
    pub(crate) fn load(config: &Config, _store: &dyn Store) -> Result<State, StoreError> {
        let crypto = RisalaCrypto::new()
            .map_err(|e| StoreError::Setup(format!("the MLS crypto provider: {e:?}")))?;
        let hour = Duration::from_secs(60 * 60);
        Ok(State {
            crypto: Arc::new(crypto),
            dir: config.files_dir(),
            url: RwLock::new(config.files.url.clone()),
            fs: Mutex::new(()),
            backups: tokio::sync::Mutex::new(()),
            gets_by_address: WindowLimit::new(hour),
            gets_by_uid: WindowLimit::new(hour),
            address_bytes: ByteWindow::new(hour),
            identity_bytes: ByteWindow::new(24 * hour),
        })
    }

    /// The origin of the HTTPS listener, if there is one.
    fn url(&self) -> Option<String> {
        self.url.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn lock_fs(&self) -> std::sync::MutexGuard<'_, ()> {
        self.fs.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn blob_path(&self, hash: &BlobRef) -> PathBuf {
        self.dir.join("blobs").join(hash.hex())
    }

    fn upload_path(&self, id: &str) -> PathBuf {
        self.dir.join("uploads").join(id)
    }
}

impl Hub {
    /// Sets the origin clients reach the HTTPS listener at, from which the
    /// `put`, `get` and `del` URLs of blobs and files and INFO's `blobs`
    /// are made (5.6, 12.12), unless `files.url` sets one. `risalad` calls
    /// this once its listener is bound.
    pub fn set_files_url(&self, url: &str) {
        let mut current = self
            .inner
            .keys
            .url
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if self.inner.config.files.url.is_none() {
            *current = Some(url.trim_end_matches('/').to_owned());
        }
    }

    /// The HTTPS side of blobs and files, for the listener.
    pub(crate) fn files(&self) -> disk::Files {
        disk::Files::new(self.inner.clone())
    }
}

/// At most some number of bytes per key in any window.
#[derive(Debug)]
pub(crate) struct ByteWindow<K> {
    window: Duration,
    taken: Mutex<HashMap<K, VecDeque<(Timestamp, u64)>>>,
}

impl<K: Eq + Hash + Clone> ByteWindow<K> {
    pub(crate) fn new(window: Duration) -> ByteWindow<K> {
        ByteWindow {
            window,
            taken: Mutex::new(HashMap::new()),
        }
    }

    /// Counts `bytes` against `key` at `now`, unless that would take it
    /// over `max` in the window. Fails with the seconds until enough room
    /// may be free, at least 1. A `max` of 0 means no limit.
    pub(crate) fn charge(&self, key: K, bytes: u64, max: u64, now: Timestamp) -> Result<(), u64> {
        if max == 0 {
            return Ok(());
        }
        let mut all = self.taken.lock().unwrap_or_else(|e| e.into_inner());
        all.retain(|_, taken| {
            while taken
                .front()
                .is_some_and(|(t, _)| now.saturating_duration_since(*t) >= self.window)
            {
                taken.pop_front();
            }
            !taken.is_empty()
        });
        let taken = all.entry(key).or_default();
        let used: u64 = taken.iter().map(|(_, n)| n).sum();
        if used.saturating_add(bytes) > max {
            let oldest = taken.front().map_or(now, |(t, _)| *t);
            let waited = now.saturating_duration_since(oldest);
            return Err(self.window.saturating_sub(waited).as_secs().max(1));
        }
        taken.push_back((now, bytes));
        Ok(())
    }
}

/// What the keys area keeps about one connection.
#[derive(Debug, Default)]
pub(crate) struct ConnState {}

/// Handles KEYPKG, WELCOME, BLOB, BACKUP and UPLOAD.
pub(super) async fn handle(cx: &Cx, command: Command) -> Reply {
    match command {
        Command::KeyPkg(KeyPkgCommand::Add { key_package }) => keypkg_add(cx, key_package).await,
        Command::KeyPkg(KeyPkgCommand::Count) => keypkg_count(cx).await,
        Command::KeyPkg(KeyPkgCommand::Get { uid }) => keypkg_get(cx, uid).await,
        Command::Welcome(WelcomeCommand::Put {
            key_package_ref,
            secret,
            welcome,
        }) => welcome_put(cx, key_package_ref, secret, welcome).await,
        Command::Welcome(WelcomeCommand::List) => welcome_list(cx).await,
        Command::Welcome(WelcomeCommand::Del { id }) => welcome_del(cx, id.to_string()).await,
        Command::Welcome(WelcomeCommand::Get {
            key_package_ref,
            light,
        }) => welcome_get(cx, key_package_ref, light).await,
        Command::Blob { hash, size, permit } => blob(cx, hash, size, permit).await,
        Command::Backup(BackupCommand::Put {
            generation,
            hash,
            key,
            files,
        }) => {
            let backup = BackupRecord {
                generation,
                hash,
                key,
                files,
            };
            backup_put(cx, backup).await
        }
        Command::Backup(BackupCommand::Get) => backup_get(cx).await,
        Command::Backup(BackupCommand::Del) => backup_del(cx).await,
        Command::Upload {
            mailbox,
            token,
            size,
        } => upload(cx, mailbox, token, size).await,
        other => misrouted("keys", &other),
    }
}

/// The signed-in device of `cx`. Section 13 lets only signed-in
/// connections send the commands that call this, so anything else is a
/// bug, and gets `ERR wrong-connection`.
fn signed_in(cx: &Cx) -> Result<(Uid, DeviceBytes, risala_proto::auth::PublicKey), ErrResponse> {
    match cx.device() {
        Some(device) => Ok((
            device.uid.clone(),
            DeviceId::of_device_key(device.key.as_bytes()).0,
            device.key.clone(),
        )),
        None => Err(err(ErrorCode::WrongConnection)),
    }
}

fn rate_limited(retry: u64) -> ErrResponse {
    err(ErrorCode::RateLimited).with_retry(retry)
}

/// A store call failed outside a command.
fn internal(e: impl std::fmt::Display) -> ErrResponse {
    tracing::error!("keys: {e}");
    err(ErrorCode::Internal)
}

/// The time `inner`'s retention period (7.5) before `now`.
fn retention_start(inner: &Inner, now: Timestamp) -> Timestamp {
    let days = u64::from(inner.settings().retention.days());
    now.checked_sub(Duration::from_secs(days * 24 * 60 * 60))
        .unwrap_or(Timestamp::from_unix_millis(0).expect("the epoch"))
}

// ---------------------------------------------------------------------------
// KeyPackages (12.5)

/// `KEYPKG ADD <keypackage>`: checks the KeyPackage with `risala-mls`, and
/// stores it for this device.
async fn keypkg_add(cx: &Cx, key_package: KeyPackage) -> Reply {
    let (uid, device, key) = signed_in(cx)?;
    let limits = &cx.inner.config.limits;
    if key_package.decoded_len() > limits.max_key_package_bytes {
        return Err(err(ErrorCode::TooLong));
    }
    let bytes = key_package.decode();
    let crypto = cx.inner.keys.crypto.clone();
    let now = cx.inner.now();
    let who = uid.clone();
    let checked = tokio::task::spawn_blocking(move || {
        let checked = risala_mls::keypackage::check_key_package(
            &*crypto,
            &bytes,
            &who,
            key.as_bytes(),
            now.to_system_time(),
        )?;
        let kp_ref = checked
            .key_package
            .hash_ref(&*crypto)
            .map_err(|_| risala_mls::keypackage::KeyPackageError::Invalid)?;
        Ok::<_, risala_mls::keypackage::KeyPackageError>((checked, kp_ref, bytes))
    })
    .await
    .map_err(internal)?;
    let (checked, kp_ref, bytes) = match checked {
        Ok(checked) => checked,
        Err(e) => {
            tracing::debug!(conn = cx.conn.0, "KEYPKG ADD: {e}");
            return Err(err(ErrorCode::Invalid));
        }
    };
    let key_package_ref: [u8; 48] = kp_ref
        .as_slice()
        .try_into()
        .map_err(|_| err(ErrorCode::Invalid))?;
    let not_after = checked
        .not_after
        .checked_mul(1000)
        .and_then(Timestamp::from_unix_millis)
        .ok_or_else(|| err(ErrorCode::Invalid))?;
    let new = NewKeyPackage {
        uid,
        device,
        key_package_ref,
        key_package: bytes,
        last_resort: checked.last_resort,
        not_after,
    };
    let max = limits.max_key_packages as u64;
    match cx
        .db(move |store| store.add_key_package(&new, max, now))
        .await?
    {
        AddedKeyPackage::Added | AddedKeyPackage::Again => Ok(OkResponse::new()),
        AddedKeyPackage::Full => Err(err(ErrorCode::Forbidden)),
    }
}

/// `KEYPKG COUNT`.
async fn keypkg_count(cx: &Cx) -> Reply {
    let (uid, device, _) = signed_in(cx)?;
    let now = cx.inner.now();
    let count = cx
        .db(move |store| store.count_key_packages(&uid, &device, now))
        .await?;
    Ok(OkResponse::new()
        .with_count(count.ordinary)
        .with_last_resort(count.last_resort))
}

/// `KEYPKG GET <uid>`: one KeyPackage of each current device of `uid`,
/// each recorded as handed out with a new put secret, for one Welcome
/// (12.5, 12.8).
async fn keypkg_get(cx: &Cx, uid: Uid) -> Reply {
    let inner = &cx.inner;
    let now = inner.now();
    let max = inner.config.limits.key_package_gets_per_hour;
    // Every KEYPKG GET uses KeyPackages up, so each one counts, whatever
    // it finds (12.5).
    let by_address = inner
        .keys
        .gets_by_address
        .take(network(cx.peer.ip()), max, now)
        .map_err(rate_limited)?;
    let by_uid = inner
        .keys
        .gets_by_uid
        .take(uid.clone(), max, now)
        .map_err(rate_limited)?;
    if let Some(slot) = by_address {
        slot.keep();
    }
    if let Some(slot) = by_uid {
        slot.keep();
    }
    let Ok(identity) = Identity::try_from(uid.clone()) else {
        // A guest has no KeyPackages.
        return Err(err(ErrorCode::NotFound));
    };
    // A uid the server does not know: one that has uploaded no KeyPackage
    // within retention. Asking only then also keeps the server from
    // fetching key files from any domain a client names (12.5).
    let since = retention_start(inner, now);
    let who = uid.clone();
    if !cx
        .db(move |store| store.knows_key_package_uid(&who, since))
        .await?
    {
        return Err(err(ErrorCode::NotFound));
    }
    // Keys missing give no devices; an outage, `ERR unavailable` (4.4).
    let Some(devices) = identity::current_devices(inner, &identity).await else {
        return Err(err(ErrorCode::Unavailable));
    };
    let mut secrets = Vec::with_capacity(devices.len());
    let mut handouts = Vec::with_capacity(devices.len());
    for device in devices {
        let secret = PutSecret::from_bytes(random_bytes().map_err(internal)?);
        handouts.push((device, SecretHash::of(secret.as_bytes())));
        secrets.push((device, secret));
    }
    let who = uid.clone();
    let handed = cx
        .db(move |store| store.take_key_packages(&who, &handouts, now))
        .await?;
    for (i, kp) in handed.into_iter().enumerate() {
        if i > 0 {
            cx.wait_for_room().await;
        }
        let key_package = KeyPackage::from_bytes(&kp.key_package).map_err(internal)?;
        let secret = secrets
            .iter()
            .find(|(device, _)| *device == kp.device)
            .map(|(_, secret)| secret.clone())
            .ok_or_else(|| internal("a KeyPackage of a device not asked for"))?;
        cx.send(ServerLine::KeyPkg {
            uid: uid.clone(),
            key_package,
            secret,
        });
    }
    Ok(OkResponse::new())
}

// ---------------------------------------------------------------------------
// Welcomes (12.8)

/// The version of a SealedWelcome (12.8).
pub const SEALED_WELCOME_VERSION: u8 = 1;

/// Reads an MLS variable-length integer [RFC9420, 2.1.2] at the start of
/// `bytes`: the value and the bytes it took. Only minimal encodings.
fn varint(bytes: &[u8]) -> Option<(usize, usize)> {
    let first = *bytes.first()?;
    let (len, value) = match first >> 6 {
        0 => (1, u32::from(first & 0x3f)),
        1 => {
            let b = bytes.get(..2)?;
            (2, u32::from(u16::from_be_bytes([b[0] & 0x3f, b[1]])))
        }
        2 => {
            let b = bytes.get(..4)?;
            (4, u32::from_be_bytes([b[0] & 0x3f, b[1], b[2], b[3]]))
        }
        _ => return None,
    };
    let minimal = match len {
        1 => true,
        2 => value >= 64,
        _ => value >= 16384,
    };
    minimal.then_some((usize::try_from(value).ok()?, len))
}

/// Whether `bytes` are a well-formed SealedWelcome (12.8):
/// `version` 1, then `kem_output<V>` and `ciphertext<V>`, neither empty,
/// and nothing after.
pub(crate) fn is_sealed_welcome(bytes: &[u8]) -> bool {
    let Some((&SEALED_WELCOME_VERSION, mut rest)) = bytes.split_first() else {
        return false;
    };
    for _ in 0..2 {
        let Some((len, took)) = varint(rest) else {
            return false;
        };
        if len == 0 || rest.len() < took + len {
            return false;
        }
        rest = &rest[took + len..];
    }
    rest.is_empty()
}

/// Whether `bytes` are an MLSMessage that holds a Welcome of the suite of
/// 12.2.
fn is_mls_welcome(bytes: &[u8]) -> bool {
    matches!(
        risala_mls::framing::read_message(bytes),
        Ok(risala_mls::framing::MlsMessage::Welcome)
    )
}

/// The signed-in connections of one device of `uid`.
fn device_conns(inner: &Inner, uid: &Uid, device: &DeviceBytes) -> Vec<ConnHandle> {
    let reg = inner.reg();
    reg.by_uid
        .get(uid)
        .into_iter()
        .flatten()
        .filter_map(|id| reg.conns.get(id))
        .filter(|conn| {
            !conn.detached
                && matches!(&conn.who, Who::SignedIn(d)
                    if DeviceId::of_device_key(d.key.as_bytes()).0 == *device)
        })
        .map(|conn| conn.handle.clone())
        .collect()
}

/// A stored Welcome as a WELCOME line, with `tree` for WELCOME GET.
fn welcome_line(
    stored: StoredWelcome,
    tree: Option<OrBlob<Vec<u8>>>,
) -> Result<ServerLine, ErrResponse> {
    let welcome = match stored.welcome {
        OrBlob::Inline(bytes) => OrBlob::Inline(Welcome::from_bytes(&bytes).map_err(internal)?),
        OrBlob::Blob(blob) => OrBlob::Blob(blob),
    };
    let tree = match tree {
        Some(OrBlob::Inline(bytes)) => Some(OrBlob::Inline(
            RatchetTree::from_bytes(&bytes).map_err(internal)?,
        )),
        Some(OrBlob::Blob(blob)) => Some(OrBlob::Blob(blob)),
        None => None,
    };
    Ok(ServerLine::Welcome {
        id: stored.id.parse().map_err(internal)?,
        welcome,
        tree,
    })
}

/// `WELCOME PUT <ref> <secret> <welcome>` (12.8): for a KeyPackage that
/// KEYPKG GET handed out, with the put secret of that handout; or for one
/// of an external Add proposal that a public room's commit applied, with
/// `-`, on a signed-in connection of the device that made the commit.
///
/// The kind of `<welcome>` follows from `<secret>` (12.8): a SealedWelcome
/// with a put secret, an MLSMessage holding a Welcome with `-`; anything
/// else in the line gets `ERR invalid`. A blob is taken for either, once
/// stored, since the server does not read it (12.8 is silent on checking
/// a blob's bytes).
///
/// A ref the server knows, but with a secret that matches none of its
/// handouts, or `-` from another device, gets `ERR forbidden`. A second,
/// different Welcome for a handout replaces the first while it has not
/// been fetched (deleted with WELCOME DEL, or returned by WELCOME GET);
/// after that it gets `ERR forbidden` too, and the same Welcome again gets
/// `OK` (12.8 is silent on both; a choice to confirm).
async fn welcome_put(
    cx: &Cx,
    kp_ref: KeyPackageRef,
    secret: WelcomeSecret,
    welcome: OrBlob<Welcome>,
) -> Reply {
    let inner = &cx.inner;
    let now = inner.now();
    let for_room = matches!(secret, WelcomeSecret::Proposal);
    let (stored, digest) = match welcome {
        OrBlob::Inline(welcome) => {
            let bytes = welcome.decode();
            let fits = if for_room {
                is_mls_welcome(&bytes)
            } else {
                is_sealed_welcome(&bytes)
            };
            if !fits {
                return Err(err(ErrorCode::Invalid));
            }
            let digest = *BlobRef::of(&bytes).hash();
            (OrBlob::Inline(bytes), digest)
        }
        OrBlob::Blob(blob) => {
            let hash = blob;
            if cx.db(move |store| store.blob(&hash)).await?.is_none() {
                return Err(err(ErrorCode::NotFound));
            }
            (OrBlob::Blob(blob), *blob.hash())
        }
    };
    let key = *kp_ref.as_bytes();
    let handouts = cx.db(move |store| store.handouts(&key)).await?;
    if handouts.is_empty() {
        return Err(err(ErrorCode::NotFound));
    }
    let chosen = match &secret {
        // Every handout's hash is compared, each in constant time.
        WelcomeSecret::Put(secret) => handouts
            .iter()
            .filter(|row| match &row.handout {
                Handout::Device { secret: hash, .. } => hash.matches(secret.as_bytes()),
                Handout::Room { .. } => false,
            })
            .fold(None, |found, row| found.or(Some(row))),
        // The newest commit that applied a proposal with this KeyPackage.
        WelcomeSecret::Proposal => handouts
            .iter()
            .find(|row| matches!(row.handout, Handout::Room { .. }))
            .filter(|row| match (&row.handout, cx.device()) {
                (
                    Handout::Room {
                        committer_uid,
                        committer,
                        ..
                    },
                    Some(device),
                ) => {
                    device.uid == *committer_uid
                        && DeviceId::of_device_key(device.key.as_bytes()).0 == *committer
                }
                _ => false,
            }),
    };
    let Some(chosen) = chosen.cloned() else {
        return Err(err(ErrorCode::Forbidden));
    };
    let id = random_token(ID_LEN).map_err(internal)?;
    let max = inner.config.files.max_pending_welcomes;
    let to_store = stored.clone();
    let handout = chosen.id;
    let put = cx
        .db(move |store| store.put_welcome(handout, &id, &to_store, &digest, max, now))
        .await?;
    let id = match put {
        PutWelcome::Stored(id) | PutWelcome::Replaced(id) => id,
        PutWelcome::Same => return Ok(OkResponse::new()),
        PutWelcome::Taken => return Err(err(ErrorCode::Forbidden)),
        PutWelcome::NotFound => return Err(err(ErrorCode::NotFound)),
        PutWelcome::TooMany => return Err(err(ErrorCode::RateLimited)),
    };
    if let Handout::Device { uid, device, .. } = chosen.handout {
        let line = welcome_line(
            StoredWelcome {
                id,
                welcome: stored,
            },
            None,
        )?;
        for handle in device_conns(inner, &uid, &device) {
            handle.send(ServerMessage::new(line.clone()));
        }
        // TODO(SV5): push to the device's account subscriptions (9.2)
        // with the reason `welcome`, once the push area is built.
    }
    Ok(OkResponse::new())
}

/// `WELCOME LIST`: every Welcome pending for this device.
async fn welcome_list(cx: &Cx) -> Reply {
    let (uid, device, _) = signed_in(cx)?;
    let pending = cx
        .db(move |store| store.device_welcomes(&uid, &device))
        .await?;
    for (i, stored) in pending.into_iter().enumerate() {
        if i > 0 {
            cx.wait_for_room().await;
        }
        cx.send(welcome_line(stored, None)?);
    }
    Ok(OkResponse::new())
}

/// `WELCOME DEL <id>`: `OK` whether or not it was pending.
async fn welcome_del(cx: &Cx, id: String) -> Reply {
    let (uid, device, _) = signed_in(cx)?;
    cx.db(move |store| store.delete_welcome(&uid, &device, &id))
        .await?;
    Ok(OkResponse::new())
}

/// `WELCOME GET <ref> [light=yes]`: the Welcome for the KeyPackage of an
/// external proposal, with the tree of its epoch (12.6, 12.8).
///
/// `light=yes` gets `ERR not-supported`: AnnotatedWelcomes are for light
/// clients, which M5b does not build (12.6, docs/plans/M5b.md).
async fn welcome_get(cx: &Cx, kp_ref: KeyPackageRef, light: bool) -> Reply {
    if light {
        return Err(err(ErrorCode::NotSupported));
    }
    let key = *kp_ref.as_bytes();
    match cx.db(move |store| store.room_welcome(&key)).await? {
        Some(found) => {
            cx.send(welcome_line(found.welcome, Some(found.tree))?);
            Ok(OkResponse::new())
        }
        None => Err(err(ErrorCode::NotFound)),
    }
}

/// How long a public room's tree is kept for the Welcomes of its epoch,
/// from the commit that started it (12.6: at least 24 hours). The tree
/// and those Welcomes then go together; their devices join again by a new
/// proposal. Dropping them at 24 hours rather than at retention is a
/// choice to confirm: a large room's trees are large.
pub const ROOM_TREE_KEPT: Duration = Duration::from_secs(24 * 60 * 60);

/// The longest tree, in base64, that a WELCOME line carries inline; a
/// longer one is made a blob. With it, a WELCOME line whose Welcome fits
/// a long client line still fits a long server line (2.3).
const MAX_INLINE_TREE: usize = MAX_SERVER_LINE / 2;

/// A public room's commit applied external Add proposals (12.6, 12.8):
/// one Welcome may be put for each KeyPackage in `added`, with `-`, and
/// only on a signed-in connection of the device that made the commit,
/// whose identity is `committer_uid` and whose device id (4.4) is
/// `committer`. `tree` is the ratchet tree of `epoch`, the epoch the
/// commit started, which WELCOME GET hands out with those Welcomes for
/// [`ROOM_TREE_KEPT`]; a tree too long for a line becomes a blob that the
/// server stores itself and counts against nobody.
///
/// The mailbox area calls this once it has accepted such a commit, with
/// the KeyPackageRefs of the proposals' KeyPackages and the tree it
/// exported after merging the commit (docs/plans/M5b.md, SV3).
#[allow(
    dead_code,
    reason = "called by the mailbox area (docs/plans/M5b.md, SV3)"
)]
pub(crate) async fn room_joins_committed(
    inner: &Arc<Inner>,
    mailbox: BoxName,
    epoch: u64,
    committer_uid: Uid,
    committer: DeviceBytes,
    added: Vec<KeyPackageRef>,
    tree: Vec<u8>,
) -> Result<(), StoreError> {
    if added.is_empty() {
        return Ok(());
    }
    let now = inner.now();
    let tree_size = tree.len() as u64;
    let inner = inner.clone();
    tokio::task::spawn_blocking(move || {
        let keys = &inner.keys;
        // Under the lock that expiry takes, so that a tree's blob is not
        // removed between its file and its row.
        let _guard = keys.lock_fs();
        let tree = if tree.len().div_ceil(3) * 4 <= MAX_INLINE_TREE {
            OrBlob::Inline(tree)
        } else {
            let hash = BlobRef::of(&tree);
            disk::write_blob(keys, &hash, &tree)
                .map_err(|e| StoreError::Setup(format!("storing a tree: {e}")))?;
            OrBlob::Blob(hash)
        };
        let joins = RoomJoins {
            mailbox,
            epoch,
            committer_uid,
            committer,
            refs: added.iter().map(|r| *r.as_bytes()).collect(),
            tree,
            tree_size,
        };
        inner.store.add_room_joins(&joins, now)
    })
    .await
    .map_err(|e| StoreError::Task(e.to_string()))?
}

/// Why [`blob_bytes`] has no bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NoBlob {
    /// The server does not hold the blob, or it has expired.
    NotFound,
    /// It is larger than the caller takes.
    TooLong,
    /// The store or the disk failed.
    Internal,
}

impl From<NoBlob> for ErrResponse {
    fn from(why: NoBlob) -> ErrResponse {
        err(match why {
            NoBlob::NotFound => ErrorCode::NotFound,
            NoBlob::TooLong => ErrorCode::TooLong,
            NoBlob::Internal => ErrorCode::Internal,
        })
    }
}

/// The bytes of the blob `hash` that a line names (12.12), if the server
/// holds it and it has not expired, and it has at most `max` bytes. The
/// identity area calls this for KEYS PUT, reports for a post stored as a
/// blob (5.8), and the mailbox area may for the messages, GroupInfos and
/// trees its lines name.
pub(crate) async fn blob_bytes(inner: &Inner, hash: &BlobRef, max: u64) -> Result<Vec<u8>, NoBlob> {
    let now = inner.now();
    let start = retention_start(inner, now);
    let h = *hash;
    let record = inner
        .db(move |store| store.blob(&h))
        .await
        .map_err(|e| {
            tracing::error!("keys: reading a blob: {e}");
            NoBlob::Internal
        })?
        .ok_or(NoBlob::NotFound)?;
    if !record.kept && record.stored < start {
        return Err(NoBlob::NotFound);
    }
    if record.size > max {
        return Err(NoBlob::TooLong);
    }
    match tokio::fs::read(inner.keys.blob_path(hash)).await {
        Ok(bytes) if BlobRef::of(&bytes) == *hash => Ok(bytes),
        Ok(_) => {
            tracing::error!("keys: the file of blob {hash} does not hold it");
            Err(NoBlob::Internal)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(NoBlob::NotFound),
        Err(e) => {
            tracing::error!("keys: reading blob {hash}: {e}");
            Err(NoBlob::Internal)
        }
    }
}

/// The device whose key is `device_key` has left `uid` (4.8): its
/// KeyPackages and pending Welcomes go (12.8). The identity area calls
/// this.
#[allow(
    dead_code,
    reason = "called by the identity area (docs/plans/M5b.md, SV1)"
)]
pub(crate) async fn device_removed(
    inner: &Inner,
    uid: Uid,
    device_key: &[u8],
) -> Result<(), StoreError> {
    let device = DeviceId::of_device_key(device_key).0;
    inner
        .db(move |store| store.forget_device(&uid, &device))
        .await
}

// ---------------------------------------------------------------------------
// Blobs and uploads (5.6, 7.5, 12.12)

/// Checks `token` for `mailbox` as POST does (5.2), through the mailbox
/// area.
async fn check_token(cx: &Cx, mailbox: &BoxName, token: &SendToken) -> Result<(), ErrResponse> {
    mailbox::check_token(&cx.inner, mailbox, token)
        .await
        .map_err(err)
}

/// Counts `bytes` that the network address `ip` asks to store against its
/// window, which POST, UPLOAD and BLOB share (7.5): `ERR rate-limited`
/// when it is full. The mailbox area calls this for POST.
pub(crate) fn charge_address(inner: &Inner, ip: IpAddr, bytes: u64) -> Result<(), ErrResponse> {
    let max = inner.config.files.address_bytes_per_hour;
    inner
        .keys
        .address_bytes
        .charge(network(ip), bytes, max, inner.now())
        .map_err(rate_limited)
}

/// The bytes of files and blobs kept for `mailbox` (7.5). The mailbox
/// area adds its posts to check the quota on POST.
#[allow(
    dead_code,
    reason = "called by the mailbox area (docs/plans/M5b.md, SV3)"
)]
pub(crate) async fn stored_bytes(inner: &Inner, mailbox: BoxName) -> Result<u64, StoreError> {
    inner.db(move |store| store.mailbox_bytes(&mailbox)).await
}

/// Checks that `mailbox` has room for `size` more bytes (7.5).
///
/// TODO(SV3): the quota counts the mailbox's posts too; add them here
/// once the mailbox area has a way to count them.
async fn check_quota(cx: &Cx, mailbox: BoxName, size: u64) -> Result<(), ErrResponse> {
    let quota = cx.inner.config.files.quota;
    let used = cx.db(move |store| store.mailbox_bytes(&mailbox)).await?;
    if used.saturating_add(size) > quota {
        return Err(err(ErrorCode::RateLimited));
    }
    Ok(())
}

/// `BLOB <hash> <size> [box=<box> token=<token>]` (12.12).
async fn blob(cx: &Cx, hash: BlobRef, size: u64, permit: Option<BlobPermit>) -> Reply {
    let inner = &cx.inner;
    let Some(url) = inner.keys.url() else {
        return Err(err(ErrorCode::NotSupported));
    };
    if size > inner.config.files.max_blob {
        return Err(err(ErrorCode::TooLong));
    }
    let now = inner.now();
    // Anonymous and guest connections show they are members of some
    // group. On a signed-in connection the pair is not needed; if it is
    // sent, it is checked, and the blob counts against the mailbox
    // (12.12 is silent on this).
    let mailbox = match (&permit, cx.device()) {
        (Some(permit), _) => {
            check_token(cx, &permit.mailbox, &permit.token).await?;
            Some(permit.mailbox)
        }
        (None, Some(_)) => None,
        // 12.12: required on anonymous and guest connections. Its absence
        // is a malformed command for this kind of connection.
        (None, None) => return Err(err(ErrorCode::BadSyntax)),
    };
    let touched = hash;
    if cx.db(move |store| store.touch_blob(&touched, now)).await? {
        return Ok(OkResponse::new().with_exists());
    }
    let uid = match (&mailbox, cx.device()) {
        (Some(mailbox), _) => {
            check_quota(cx, *mailbox, size).await?;
            charge_address(inner, cx.peer.ip(), size)?;
            None
        }
        (None, Some(device)) => {
            let max = inner.config.files.identity_bytes_per_day;
            inner
                .keys
                .identity_bytes
                .charge(device.uid.clone(), size, max, now)
                .map_err(rate_limited)?;
            Some(device.uid.clone())
        }
        (None, None) => return Err(err(ErrorCode::BadSyntax)),
    };
    let id = random_token(ID_LEN).map_err(internal)?;
    let secret = random_token(SECRET_LEN).map_err(internal)?;
    let put = BlobPut {
        id: id.clone(),
        secret: SecretHash::of(secret.as_bytes()),
        hash,
        size,
        mailbox,
        uid,
        expires: now.checked_add(PUT_WINDOW).unwrap_or(now),
    };
    cx.db(move |store| store.add_blob_put(&put)).await?;
    let put_url = format!("{url}{}{id}/{secret}", paths::BLOB_PUT);
    OkResponse::new().with_put_url(&put_url).map_err(internal)
}

/// `UPLOAD <box> <token> <size>` (5.6).
async fn upload(cx: &Cx, mailbox: BoxName, token: SendToken, size: u64) -> Reply {
    let inner = &cx.inner;
    let max = inner.config.files.max_upload;
    let Some(url) = inner.keys.url().filter(|_| max > 0) else {
        return Err(err(ErrorCode::NotSupported));
    };
    if size > max {
        return Err(err(ErrorCode::TooLong));
    }
    check_token(cx, &mailbox, &token).await?;
    check_quota(cx, mailbox, size).await?;
    charge_address(inner, cx.peer.ip(), size)?;
    let id = random_token(ID_LEN).map_err(internal)?;
    let [put, get, del] = [(); 3].map(|()| random_token(SECRET_LEN));
    let (put, get, del) = (
        put.map_err(internal)?,
        get.map_err(internal)?,
        del.map_err(internal)?,
    );
    let record = UploadRecord {
        id: id.clone(),
        mailbox,
        put: SecretHash::of(put.as_bytes()),
        get: SecretHash::of(get.as_bytes()),
        del: SecretHash::of(del.as_bytes()),
        size,
        created: inner.now(),
        claimed: false,
        stored: None,
        held: 0,
        deleted: false,
    };
    cx.db(move |store| store.add_upload(&record)).await?;
    let get_url = format!("{url}{}{id}/{get}", paths::UPLOAD_GET)
        .parse()
        .map_err(internal)?;
    OkResponse::new()
        .with_upload_urls(
            &format!("{url}{}{id}/{put}", paths::UPLOAD_PUT),
            &get_url,
            &format!("{url}{}{id}/{del}", paths::UPLOAD_DEL),
        )
        .map_err(internal)
}

/// The public room `mailbox`'s current tree is the blob `tree`, or is in
/// its line (`None`): the blob is kept for as long as the epoch is
/// current, whatever the retention (12.12). Once it is not, retention
/// counts from the last BLOB that named it. The mailbox area calls this
/// for each new epoch, and with `None` when the room ends.
#[allow(
    dead_code,
    reason = "called by the mailbox area (docs/plans/M5b.md, SV3)"
)]
pub(crate) async fn keep_room_tree(
    inner: &Inner,
    mailbox: BoxName,
    tree: Option<BlobRef>,
) -> Result<(), StoreError> {
    let owner = format!("room {}", hex(mailbox.as_bytes()));
    let kept: Vec<BlobRef> = tree.into_iter().collect();
    inner
        .db(move |store| store.set_blob_keeps(&owner, &kept))
        .await
        .map(drop)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A report keeps the file whose `get` URL is `url` (`hold`), or stops
/// keeping it (5.8): while any report keeps it, it neither expires nor
/// goes when its uploader deletes it. Does nothing for a URL that is not
/// one of this server's. Reports call this.
#[allow(dead_code, reason = "called by reports (docs/plans/M5b.md, SV5)")]
pub(crate) async fn hold_file(inner: &Inner, url: &str, hold: bool) -> Result<(), StoreError> {
    let Some(id) = disk::upload_id_of_get_url(inner, url) else {
        return Ok(());
    };
    let retention = retention_start(inner, inner.now());
    let file = id.clone();
    let remove = inner
        .db(move |store| store.hold_upload(&file, hold, retention))
        .await?;
    if remove {
        disk::remove_upload_file(inner, &id).await;
    }
    Ok(())
}

/// What INFO says about files and blobs (8.5): `upload=`, `blobs=` and
/// `files=`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FilesInfo {
    /// The largest upload, or `no`.
    pub(crate) upload: Upload,
    /// The URL prefix blobs are fetched from, if the server stores blobs.
    pub(crate) blobs: Option<String>,
    /// The origins of `get` URLs, only with uploads.
    pub(crate) files: Vec<FileOrigin>,
}

/// INFO's `upload=`, `blobs=` and `files=` (8.5).
pub(crate) fn info(inner: &Inner) -> FilesInfo {
    let url = inner.keys.url();
    let max = inner.config.files.max_upload;
    let upload = (url.is_some() && max > 0).then_some(max);
    FilesInfo {
        upload: upload.map_or(Upload::No, Upload::MaxBytes),
        blobs: url.as_ref().map(|u| format!("{u}{}", paths::BLOBS)),
        files: match (&url, upload) {
            (Some(url), Some(_)) => url.parse().into_iter().collect(),
            _ => Vec::new(),
        },
    }
}

// ---------------------------------------------------------------------------
// Backups (12.13)

/// What keeps the blobs of `uid`'s backup.
fn backup_owner(uid: &Uid) -> String {
    format!("backup {uid}")
}

/// Deletes, now, the blobs in `freed` that `uid` stored and that nothing
/// keeps. Blobs that others stored are left to retention: anyone can name
/// any blob, so a backup could otherwise delete someone else's (12.13).
async fn delete_freed(
    inner: &Arc<Inner>,
    uid: &Uid,
    freed: Vec<BlobRef>,
) -> Result<(), ErrResponse> {
    if freed.is_empty() {
        return Ok(());
    }
    let inner = inner.clone();
    let who = uid.clone();
    tokio::task::spawn_blocking(move || {
        let keys = &inner.keys;
        let _guard = keys.lock_fs();
        for hash in freed {
            let owned = inner
                .store
                .blob(&hash)?
                .is_some_and(|blob| blob.uid.as_ref() == Some(&who));
            if owned && inner.store.delete_blob(&hash)? {
                disk::remove_quietly(&keys.blob_path(&hash));
            }
        }
        Ok::<_, StoreError>(())
    })
    .await
    .map_err(internal)?
    .map_err(internal)
}

/// `BACKUP PUT <generation> <hash> <key> [files=<list>]` (12.13).
async fn backup_put(cx: &Cx, backup: BackupRecord) -> Reply {
    let (uid, _, _) = signed_in(cx)?;
    let inner = &cx.inner;
    backup.key.check().map_err(err)?;
    let files = &inner.config.files;
    let first = backup.hash;
    let Some(first) = cx.db(move |store| store.blob(&first)).await? else {
        return Err(err(ErrorCode::NotFound));
    };
    let mut named = vec![first.hash];
    let mut total = first.size;
    if let Some(list) = &backup.files {
        let hash = *list;
        let Some(record) = cx.db(move |store| store.blob(&hash)).await? else {
            return Err(err(ErrorCode::NotFound));
        };
        if record.size > files.max_backup_blobs.saturating_mul(48) {
            return Err(err(ErrorCode::TooLong));
        }
        let path = inner.keys.blob_path(list);
        let bytes = match tokio::fs::read(&path).await {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(err(ErrorCode::NotFound));
            }
            Err(e) => return Err(internal(e)),
        };
        let listed = read_blob_list(&bytes).map_err(err)?;
        named.push(*list);
        total = total.saturating_add(record.size);
        for hash in listed {
            let h = hash;
            let Some(record) = cx.db(move |store| store.blob(&h)).await? else {
                return Err(err(ErrorCode::NotFound));
            };
            total = total.saturating_add(record.size);
            named.push(hash);
        }
    }
    if total > files.max_backup {
        return Err(err(ErrorCode::TooLong));
    }
    let _serial = inner.keys.backups.lock().await;
    let now = inner.now();
    let owner = backup_owner(&uid);
    let who = uid.clone();
    let freed = cx
        .db(move |store| {
            store.put_backup(&who, &backup, now)?;
            store.set_blob_keeps(&owner, &named)
        })
        .await?;
    delete_freed(inner, &uid, freed).await?;
    Ok(OkResponse::new())
}

/// `BACKUP GET` (12.13).
async fn backup_get(cx: &Cx) -> Reply {
    let (uid, _, _) = signed_in(cx)?;
    match cx.db(move |store| store.backup(&uid)).await? {
        Some(backup) => {
            cx.send(ServerLine::Backup {
                generation: backup.generation,
                hash: backup.hash,
                key: backup.key,
                files: backup.files,
            });
            Ok(OkResponse::new())
        }
        None => Err(err(ErrorCode::NotFound)),
    }
}

/// `BACKUP DEL` (12.13): the backup and its blobs.
async fn backup_del(cx: &Cx) -> Reply {
    let (uid, _, _) = signed_in(cx)?;
    let inner = &cx.inner;
    let _serial = inner.keys.backups.lock().await;
    let owner = backup_owner(&uid);
    let who = uid.clone();
    let freed = cx
        .db(move |store| {
            store.delete_backup(&who)?;
            store.set_blob_keeps(&owner, &[])
        })
        .await?;
    delete_freed(inner, &uid, freed).await?;
    Ok(OkResponse::new())
}

// ---------------------------------------------------------------------------

/// Connection `id` has closed.
pub(super) fn conn_closed(_inner: &Arc<Inner>, _id: ConnId, _conn: &ConnEntry) {}

/// The area's background work, every minute: deleting KeyPackages whose
/// lifetime has ended (12.5), `put` URLs past their 10 minutes, and
/// Welcomes, blobs and files past retention (7.5), with their bytes.
pub(super) async fn maintain(inner: Arc<Inner>) {
    disk::clear_tmp(&inner).await;
    let mut tick = tokio::time::interval(MAINTAIN_EVERY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        if let Err(e) = expire(&inner).await {
            tracing::error!("expiring keys, Welcomes, blobs and files: {e}");
        }
    }
}

/// One round of [`maintain`]'s work.
pub(crate) async fn expire(inner: &Arc<Inner>) -> Result<(), StoreError> {
    let now = inner.now();
    let times = crate::store::keys::ExpiryTimes {
        now,
        retention: retention_start(inner, now),
        room_trees: now.checked_sub(ROOM_TREE_KEPT).unwrap_or(now),
        unclaimed: now.checked_sub(PUT_WINDOW).unwrap_or(now),
        unfinished: now.checked_sub(UNFINISHED_UPLOAD).unwrap_or(now),
    };
    let inner = inner.clone();
    tokio::task::spawn_blocking(move || {
        let keys = &inner.keys;
        // Blob rows and files go together, under the lock that a finishing
        // upload of the same blob also takes.
        let _guard = keys.lock_fs();
        let expired = inner.store.expire(&times)?;
        for hash in &expired.blobs {
            disk::remove_quietly(&keys.blob_path(hash));
        }
        for id in &expired.uploads {
            disk::remove_quietly(&keys.upload_path(id));
        }
        Ok(())
    })
    .await
    .map_err(|e| StoreError::Task(e.to_string()))?
}

/// Keeps the uploaded files behind `urls` that are this server's, even if
/// their uploader deletes them or they expire, until the report `report`
/// is resolved (5.8).
///
/// TODO(SV4): a stub added by SV5 (REPORT) until uploads are built.
pub(crate) async fn keep_files_for_report(
    _inner: &Inner,
    _report: &risala_proto::names::Id,
    _urls: &[risala_proto::content::FileUrl],
) {
}

/// The report `report` was resolved: the files it kept expire as usual
/// again (5.8).
///
/// TODO(SV4): a stub added by SV5 (RESOLVE) until uploads are built.
pub(crate) async fn release_files_for_report(_inner: &Inner, _report: &risala_proto::names::Id) {}
