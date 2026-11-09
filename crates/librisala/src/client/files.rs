//! Files (5.6, 12.11): sending a file in a conversation, fetching one,
//! and deleting the ones this device shared when their message is
//! deleted. This module also holds what task C4's area shares: its errors
//! and events, the HTTPS client for files and blobs ([`FileHttps`]), and
//! `Jobs`, the area's work for one account, which the account's worker
//! ([`super::backups`]) and the API run.
//!
//! Owned by task C4.
//!
//! - **Sending.** The file is encrypted (12.11), uploaded with UPLOAD on
//!   the anonymous connection that follows the conversation's mailbox,
//!   with a send token of the group (5.6), PUT to the `put` URL, and then
//!   shared by a message whose TEXT line carries `file`, `file-key`,
//!   `file-type`, `file-size` and `file-hash` (12.9).
//! - **Fetching.** A file is downloaded without asking only from one of
//!   the `files` origins INFO lists for the conversation's server (8.5,
//!   12.11); any other needs [`Client::fetch_file_anywhere`], after the
//!   user was told that its host will learn their network address. The
//!   hash is checked before anything is decrypted, and nothing is saved
//!   unless every check of 12.11 passes. A file a transfer or backup
//!   listed for the message is read from its blob instead (12.13).
//! - **Deleting.** Once a message this device shared a file in is
//!   deleted, the worker deletes the file with its `del` URL (5.6).

mod http;
#[cfg(test)]
mod server_tests;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use risala_mls::file::{BlobRef as MlsBlobRef, FileKey as MlsFileKey, Label};
use risala_proto::command::Command;
use risala_proto::content::{
    Content, ContentLine, FileHash, FileKey, FileRef, FileUrl, MediaType, Text,
};
use risala_proto::names::BlobRef;
use risala_proto::server::FileOrigin;
use tokio::sync::broadcast;

use super::types::{AccountId, ConversationId, MessageId};
use super::{Client, Error, Event, Result};
use crate::clock::Clock;
use crate::conn::{BoxFuture, Response};
use crate::store::transfer::ServerFiles;
use crate::store::{Change, Store, StoreError, Tx};
use crate::sync::Target;
use crate::sync::conversations::{EngineError, content};

pub use http::TlsFileHttps;

/// How long what INFO said about files is used before asking again.
const INFO_TTL_MS: u64 = 60 * 60 * 1000;

/// The largest blob this device fetches: 256 MiB, the least a server
/// allows (12.12).
pub const MAX_BLOB: usize = 256 * 1024 * 1024;

/// The largest blob this device makes for a transfer or backup archive:
/// 64 MiB. History beyond it is split over several archives (12.13).
pub const ARCHIVE_BLOB: u64 = 64 * 1024 * 1024;

/// The errors of files, transfers, backups, push and reports.
#[derive(Debug, thiserror::Error)]
pub enum TransferError {
    /// The file's bytes do not have the hash its message gives, or do not
    /// decrypt and check as a file (12.11).
    #[error("the file does not match its hash, or does not decrypt")]
    HashMismatch,
    /// The server no longer has it (7.5).
    #[error("the server no longer has it")]
    Expired,
    /// The message shares no file.
    #[error("the message shares no file")]
    NoFile,
    /// The file is on another host than the conversation's server's file
    /// origins: fetching it tells that host the device's network address,
    /// so it needs the user's say (12.11).
    #[error("the file is on another host: {0}")]
    OtherHost(String),
    /// The server takes no uploads (`upload=no`), or not this large (5.6).
    #[error("the server does not take this file")]
    TooLarge,
    /// The message or conversation is not one this works for.
    #[error("{0}")]
    NotPossible(String),
    /// HTTPS failed.
    #[error("HTTPS: {0}")]
    Http(#[from] HttpError),
    /// There is no backup, or none of the generation this device may
    /// restore (12.13).
    #[error("there is no usable backup")]
    NoBackup,
    /// The backup or transfer does not open: wrong recovery key, or a
    /// broken or hostile archive (12.13).
    #[error("the backup or transfer does not open: {0}")]
    Unreadable(String),
    /// Push needs URLs from the app's push gateway (Appendix C).
    #[error("no push URL left: hand over more with add_push_urls")]
    NoPushUrl,
    /// A push body does not decrypt with any subscription (9.3).
    #[error("the push does not decrypt")]
    BadPush,
}

/// Why an HTTPS request failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HttpError {
    /// Not an `https` URL this client can use.
    #[error("bad URL")]
    Url,
    /// 404 or 410.
    #[error("gone ({0})")]
    Gone(u16),
    /// Another status, a redirect included (4.4).
    #[error("status {0}")]
    Status(u16),
    /// The body is larger than allowed.
    #[error("too large")]
    TooLarge,
    /// DNS, TCP, TLS, a timeout or a bad response.
    #[error("{0}")]
    Failed(String),
}

/// HTTPS for files and blobs: one request each (5.6, 12.12).
/// [`TlsFileHttps`] is the client's; tests keep files in memory.
pub trait FileHttps: Send + Sync {
    /// PUTs `body` to `url`, as `application/octet-stream`.
    fn put<'a>(&'a self, url: &'a str, body: &'a [u8]) -> BoxFuture<'a, Result<(), HttpError>>;
    /// GETs `url`, reading at most `max` bytes of body.
    fn get<'a>(&'a self, url: &'a str, max: usize) -> BoxFuture<'a, Result<Vec<u8>, HttpError>>;
    /// DELETEs `url`.
    fn delete<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<(), HttpError>>;
}

/// What C4's area tells the UI, besides changes to the cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferEvent {
    /// Bytes of a file, transfer or backup moved.
    Progress {
        /// The file's message, or `None` for a transfer or backup.
        message: Option<MessageId>,
        /// Bytes done.
        done: u64,
        /// Bytes in all.
        total: u64,
    },
    /// A transfer was applied: `messages` were stored. `missing` archives
    /// could not be fetched or opened, and `ignored` conversations were
    /// out of seq order: if either is not 0, tell the user that part of
    /// the history is missing (12.13).
    TransferApplied {
        /// The account.
        account: AccountId,
        /// Messages stored now.
        messages: usize,
        /// Conversations kept until the device joins them.
        waiting: usize,
        /// Archives missing.
        missing: usize,
        /// Conversations ignored.
        ignored: usize,
    },
    /// A transfer could not be opened at all, or its archives do not
    /// belong together: tell the user (12.13).
    TransferFailed {
        /// The account.
        account: AccountId,
        /// Why.
        error: String,
    },
    /// A backup was made.
    BackupMade {
        /// The account.
        account: AccountId,
        /// Its generation.
        generation: u32,
    },
    /// A REPORT line arrived from a member, for this identity as a room's
    /// owner or moderator (5.8): see [`Client::received_reports`].
    Report {
        /// The account.
        account: AccountId,
        /// The report's row.
        report: i64,
    },
    /// A report to the server's operators, on an operator's connection
    /// (5.8).
    OperatorReport {
        /// The account.
        account: AccountId,
        /// The whole line, as the server sent it.
        line: String,
        /// The mailbox the posts are in.
        mailbox: risala_proto::names::BoxName,
    },
    /// Push needs more URLs from the app's push gateway: hand them over
    /// with [`Client::add_push_urls`] (9.1, Appendix C).
    PushUrlsNeeded {
        /// The account.
        account: AccountId,
        /// How many subscriptions wait for one.
        count: usize,
    },
}

/// A file shared in a conversation (5.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileInfo {
    /// The message that shares it.
    pub message: MessageId,
    /// Its media type, as the message gives it (not to be trusted over
    /// the file's bytes, 12.11).
    pub media_type: Option<String>,
    /// Its size: as the message gives it before the download, the real
    /// one after.
    pub size: u64,
    /// Where it is on this device, once fetched.
    pub path: Option<PathBuf>,
    /// The `get` URL.
    pub url: String,
    /// Whether the URL is on one of the conversation's server's file
    /// origins, so that it is fetched without asking (12.11).
    pub on_server: bool,
}

/// Sends commands on a running account's connections and waits for the
/// response: the driver's executor, or a fake server in tests.
pub(crate) trait Commands: Send + Sync {
    /// Sends `command` on the connection `target` names.
    fn request<'a>(&'a self, target: Target, command: Command) -> BoxFuture<'a, Result<Response>>;
}

impl Commands for super::driver::Exec {
    fn request<'a>(&'a self, target: Target, command: Command) -> BoxFuture<'a, Result<Response>> {
        Box::pin(self.request_on(target, command))
    }
}

/// The work of C4's area for one account, for the API and the worker.
#[derive(Clone)]
pub(crate) struct Jobs {
    pub store: Store,
    pub account: AccountId,
    /// The account's server, as stored.
    pub server: String,
    /// The account's uid.
    pub uid: risala_proto::names::Uid,
    pub commands: Arc<dyn Commands>,
    pub https: Arc<dyn FileHttps>,
    pub clock: Arc<dyn Clock>,
    pub keys: Arc<dyn crate::keys::KeyStore>,
    pub events: broadcast::Sender<Event>,
    /// Where fetched files are saved.
    pub downloads: PathBuf,
    /// The largest archive blob to make.
    pub max_blob: u64,
}

impl std::fmt::Debug for Jobs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Jobs")
            .field("account", &self.account)
            .finish_non_exhaustive()
    }
}

fn engine(e: EngineError) -> Error {
    match e {
        EngineError::Store(s) => Error::Store(s),
        other => Error::Internal(other.to_string()),
    }
}

/// The OK of a response, or the error.
pub(crate) fn ok(response: &Response) -> Result<&risala_proto::server::OkResponse> {
    response
        .ok()
        .map_err(|e| Error::Connection(crate::conn::Error::Rejected(e)))
}

fn mls_ref(r: &BlobRef) -> MlsBlobRef {
    MlsBlobRef::from_bytes(*r.hash())
}

pub(crate) fn proto_ref(r: &MlsBlobRef) -> BlobRef {
    BlobRef::from_hash(*r.as_bytes())
}

impl Jobs {
    pub(crate) fn now(&self) -> u64 {
        self.clock.now().unix_millis()
    }

    pub(crate) fn emit(&self, event: Event) {
        let _ = self.events.send(event);
    }

    /// Runs `f` in a write transaction, and tells the UI what changed.
    pub(crate) fn write<T>(
        &self,
        f: impl FnOnce(&mut Tx<'_>) -> std::result::Result<T, EngineError>,
    ) -> Result<T> {
        let (value, changes) = self.store.write_with(f).map_err(engine)?;
        for change in changes {
            self.emit(Event::Changed(change));
        }
        Ok(value)
    }

    /// Sends a command and checks that it got OK.
    pub(crate) async fn command(&self, target: Target, command: Command) -> Result<Response> {
        let response = self.commands.request(target, command).await?;
        ok(&response)?;
        Ok(response)
    }

    // ---- INFO

    /// What INFO says about the server's files and blobs (8.5), asked
    /// again once an hour.
    pub(crate) async fn info(&self, refresh: bool) -> Result<ServerFiles> {
        if !refresh
            && let Some(info) = self.store.server_files(&self.server)?
            && info.fetched + INFO_TTL_MS > self.now()
        {
            return Ok(info);
        }
        let response = self
            .command(Target::Conversing, Command::Info { room: None })
            .await?;
        let values = ok(&response)?;
        let upload = match values.upload() {
            Ok(Some(risala_proto::server::Upload::MaxBytes(n))) => Some(n),
            _ => None,
        };
        let files = values
            .files()
            .ok()
            .flatten()
            .unwrap_or_default()
            .iter()
            .map(ToString::to_string)
            .collect();
        let info = ServerFiles {
            upload,
            files,
            blobs: values.blobs().map(str::to_owned),
            fetched: self.now(),
        };
        let server = self.server.clone();
        let kept = info.clone();
        self.write(move |tx| Ok(tx.set_server_files(&server, &kept)?))?;
        Ok(info)
    }

    // ---- blobs

    /// Stores a blob that belongs to the account, such as an archive of a
    /// transfer or backup, with BLOB on the signed-in connection and a PUT
    /// (12.12). Returns its blob-ref.
    pub(crate) async fn put_blob(&self, bytes: &[u8]) -> Result<MlsBlobRef> {
        let hash = BlobRef::of(bytes);
        let response = self
            .command(
                Target::SignedIn,
                Command::Blob {
                    hash,
                    size: bytes.len() as u64,
                    permit: None,
                },
            )
            .await?;
        let values = ok(&response)?;
        if values.exists().ok().flatten() != Some(true) {
            let put = values
                .put_url()
                .ok_or(Error::Internal("BLOB without a put URL".into()))?
                .to_owned();
            self.https
                .put(&put, bytes)
                .await
                .map_err(TransferError::from)?;
        }
        Ok(mls_ref(&hash))
    }

    /// Fetches a blob from the server's `blobs` prefix, and checks its
    /// hash before it is used (12.12).
    pub(crate) async fn get_blob(&self, hash: &MlsBlobRef) -> Result<Vec<u8>> {
        let info = self.info(false).await?;
        let prefix = info.blobs.ok_or(TransferError::NotPossible(
            "the server names no blobs URL".into(),
        ))?;
        let url = format!("{prefix}{}", proto_ref(hash).hex());
        let bytes = match self.https.get(&url, MAX_BLOB).await {
            Ok(b) => b,
            Err(HttpError::Gone(_)) => return Err(TransferError::Expired.into()),
            Err(e) => return Err(TransferError::Http(e).into()),
        };
        hash.check(&bytes)
            .map_err(|_| Error::from(TransferError::HashMismatch))?;
        Ok(bytes)
    }

    // ---- files

    /// Uploads an encrypted file for the conversation of `mailbox` (5.6):
    /// UPLOAD with a send token of its group, on the anonymous connection
    /// that follows it, then a PUT. Returns the `get` and `del` URLs.
    pub(crate) async fn upload(
        &self,
        mailbox: risala_proto::names::BoxName,
        token: [u8; 32],
        upload: &[u8],
    ) -> Result<(FileUrl, Option<String>)> {
        let response = self
            .command(
                Target::Mailbox(mailbox),
                Command::Upload {
                    mailbox,
                    token: risala_proto::mls::SendToken::from_bytes(token),
                    size: upload.len() as u64,
                },
            )
            .await?;
        let values = ok(&response)?;
        let put = values
            .put_url()
            .ok_or(Error::Internal("UPLOAD without a put URL".into()))?
            .to_owned();
        let get: FileUrl = values
            .get_url()
            .ok()
            .flatten()
            .and_then(|u| u.as_str().parse().ok())
            .ok_or(Error::Internal("UPLOAD without a valid get URL".into()))?;
        let del = values.del_url().map(str::to_owned);
        self.https
            .put(&put, upload)
            .await
            .map_err(TransferError::from)?;
        Ok((get, del))
    }

    /// Encrypts `file` and shares it in `conv` (5.6, 12.11): UPLOAD on the
    /// mailbox's anonymous connection, PUT, then a message with the file's
    /// tags. Returns the message's id.
    pub(crate) async fn send_file(
        &self,
        conv: ConversationId,
        file: &[u8],
        name: &str,
        caption: Option<&str>,
        media_type: Option<&str>,
    ) -> Result<[u8; 16]> {
        let media_type: Option<MediaType> = match media_type {
            Some(t) => Some(t.parse().map_err(|_| Error::invalid("media type", t))?),
            None => None,
        };
        let text = caption.filter(|c| !c.trim().is_empty()).unwrap_or(name);
        let text = risala_proto::text::escape(text);
        if risala_proto::text::is_blank(&text) {
            return Err(Error::invalid("caption or file name", text));
        }
        let info = self.info(false).await?;
        let encrypted = risala_mls::file::encrypt(Label::File, file)
            .map_err(|e| Error::Internal(format!("random: {e}")))?;
        let size = encrypted.upload.len() as u64;
        if info.upload.is_none_or(|max| size > max) {
            return Err(TransferError::TooLarge.into());
        }
        let (mailbox, token) = self
            .store
            .write_with(|tx| {
                let row = tx.conversation(conv)?;
                if !row.state.in_group() {
                    return Err(EngineError::Invalid("not in this conversation".into()));
                }
                let mailbox = tx.current_mailbox(conv)?.mailbox;
                let token = crate::sync::transfer::send_token(tx, &row.group_id)?;
                Ok::<_, EngineError>((mailbox, token))
            })
            .map_err(engine)?
            .0;
        let (get, del) = self
            .upload(mailbox, *token.as_bytes(), &encrypted.upload)
            .await?;
        self.emit(Event::Transfer(TransferEvent::Progress {
            message: None,
            done: size,
            total: size,
        }));
        let hash = *encrypted.hash.as_bytes();
        let line = ContentLine::Text(Text {
            text,
            target: None,
            file: Some(FileRef {
                url: get.clone(),
                key: FileKey::from_bytes(*encrypted.key.as_bytes()),
                hash: FileHash::from_bytes(hash),
                media_type: media_type.clone(),
                size: Some(encrypted.size),
            }),
        });
        let now = self.now();
        let uid = self.uid.clone();
        let url = get.to_string();
        let media = media_type.map(|m| m.to_string());
        self.write(move |tx| {
            let id = content::queue_lines(tx, conv, &uid, vec![line], false, now)?;
            tx.add_shared_file(
                conv,
                &id,
                &hash,
                &url,
                del.as_deref(),
                encrypted.size,
                media.as_deref(),
                now,
            )?;
            Ok(id)
        })
    }

    /// The file `message` shares in `conv`, and whether its URL is on the
    /// server's file origins.
    pub(crate) async fn file_of(
        &self,
        conv: ConversationId,
        message: &[u8; 16],
    ) -> Result<(FileRef, bool)> {
        let row = self
            .store
            .message_rows(conv)?
            .into_iter()
            .find(|m| m.message_id == *message)
            .ok_or(TransferError::NoFile)?;
        let content = row
            .content
            .as_deref()
            .and_then(|c| Content::parse(c).ok())
            .ok_or(TransferError::NoFile)?;
        let file = content
            .lines()
            .iter()
            .find_map(|l| match l {
                ContentLine::Text(t) => t.file.clone(),
                _ => None,
            })
            .ok_or(TransferError::NoFile)?;
        let info = self.info(false).await?;
        let on_server = on_origins(&info.files, &file.url);
        Ok((file, on_server))
    }

    /// Fetches, checks and decrypts the file `message` shares (12.11), and
    /// saves it in the download directory. `anywhere` allows a URL off the
    /// server's file origins, which the user must have agreed to.
    pub(crate) async fn fetch_file(
        &self,
        conv: ConversationId,
        message: &[u8; 16],
        anywhere: bool,
    ) -> Result<FileInfo> {
        let (file, on_server) = self.file_of(conv, message).await?;
        let hash = *file.hash.as_bytes();
        let row = self.store.file_row(conv, message)?;
        // 12.13: a file a transfer or backup listed for this message is
        // read from its blob, and only for this message.
        let plain = if let Some((blob, key)) = row.as_ref().and_then(|r| r.blob) {
            let blob = MlsBlobRef::from_bytes(blob);
            let bytes = self.get_blob(&blob).await?;
            risala_mls::file::decrypt(&MlsFileKey::from_bytes(key), Label::File, &blob, &bytes)
                .map_err(|_| Error::from(TransferError::HashMismatch))?
        } else {
            if !on_server && !anywhere {
                return Err(TransferError::OtherHost(file.url.to_string()).into());
            }
            // The upload is at most Padmé of 8 + L plus a tag per chunk,
            // and the server's upload limit bounds it too.
            let max = file
                .size
                .and_then(risala_mls::file::encrypted_len)
                .unwrap_or(MAX_BLOB as u64)
                .min(MAX_BLOB as u64) as usize;
            let bytes = match self.https.get(file.url.as_str(), max).await {
                Ok(b) => b,
                Err(HttpError::Gone(_)) => return Err(TransferError::Expired.into()),
                Err(e) => return Err(TransferError::Http(e).into()),
            };
            // The hash first, then every check of 12.11; nothing is saved
            // unless they all pass.
            risala_mls::file::decrypt(
                &MlsFileKey::from_bytes(*file.key.as_bytes()),
                Label::File,
                &MlsBlobRef::from_bytes(hash),
                &bytes,
            )
            .map_err(|_| Error::from(TransferError::HashMismatch))?
        };
        let path = self.save(conv, message, &plain)?;
        let now = self.now();
        let url = file.url.to_string();
        let kept = path.to_string_lossy().into_owned();
        let id = *message;
        self.write(move |tx| Ok(tx.set_file_fetched(conv, &id, &hash, &url, Some(&kept), now)?))?;
        Ok(FileInfo {
            message: MessageId(*message),
            media_type: file.media_type.map(|m| m.to_string()),
            size: plain.len() as u64,
            path: Some(path),
            url: file.url.to_string(),
            on_server,
        })
    }

    /// Writes a fetched file into the account's download directory, under
    /// the conversation and message, readable by this user only (LR-M3).
    fn save(&self, conv: ConversationId, message: &[u8; 16], plain: &[u8]) -> Result<PathBuf> {
        private_dir(&self.downloads).map_err(StoreError::from)?;
        let name = format!("{}-{}", conv.get(), MessageId(*message));
        let path = self.downloads.join(name);
        write_private(&path, plain).map_err(StoreError::from)?;
        Ok(path)
    }

    /// Deletes the saved copies of files whose message was deleted (5.4),
    /// or whose conversation this device is no longer in (LR-M3).
    pub(crate) fn remove_saved_files(&self) -> Result<()> {
        for (conv, message, path) in self.store.saved_files_to_remove(self.account)? {
            let path = PathBuf::from(path);
            // Only what this area saved, in the account's directory.
            if path.parent() == Some(self.downloads.as_path()) {
                match std::fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => {
                        tracing::info!(error = %e, "could not delete a saved file; will retry");
                        continue;
                    }
                }
            }
            self.write(|tx| Ok(tx.forget_saved_file(conv, &message)?))?;
        }
        Ok(())
    }

    /// Deletes, with their `del` URLs, the files this device shared whose
    /// messages are deleted (5.4, 5.6).
    pub(crate) async fn delete_files(&self) -> Result<()> {
        for row in self.store.files_to_delete(self.account)? {
            let Some(del) = &row.del_url else {
                continue;
            };
            match self.https.delete(del).await {
                Ok(()) | Err(HttpError::Gone(_)) => {
                    self.write(|tx| Ok(tx.set_file_deleted(row.conv, &row.message_id)?))?;
                }
                Err(e) => tracing::info!(error = %e, "could not delete a file; will retry"),
            }
        }
        Ok(())
    }
}

/// Whether `url` is on one of `origins`, as INFO lists them (8.5).
pub(crate) fn on_origins(origins: &[String], url: &FileUrl) -> bool {
    let Ok(url) = url.as_str().parse::<risala_proto::types::FileUrl>() else {
        return false;
    };
    let url = &url;
    origins
        .iter()
        .filter_map(|o| o.parse::<FileOrigin>().ok())
        .any(|o| o.contains(url))
}

/// Writes `bytes` to a new file at `path`, mode 0600 on Unix. Whatever is
/// at `path` already, a file saved before or a link someone planted, is
/// removed first, never followed: the file is created anew, with
/// `O_CREAT | O_EXCL`, which fails rather than follow a link put in its
/// place meanwhile (LR-M3).
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut f = options.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

/// Makes `dir` a directory private to this user, mode 0700, with its
/// parent if that is missing; or checks that it is one: a directory, not a
/// link, owned by this user, that nobody else may use (LR-M3).
pub(crate) fn private_dir(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    match builder.create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = dir.parent() {
                private_dir(parent)?;
            }
            match builder.create(dir) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let meta = std::fs::symlink_metadata(dir)?;
    let refuse = |why: &str| {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("{}: {why}", dir.display()),
        ))
    };
    if !meta.file_type().is_dir() {
        return refuse("not a directory of its own");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if meta.mode() & 0o077 != 0 {
            return refuse("others may use it");
        }
        // The process's own user, where the system tells it without
        // unsafe code. Elsewhere, a directory of another user's with mode
        // 0700 lets this one write nothing in it anyway.
        #[cfg(target_os = "linux")]
        if let Ok(me) = std::fs::metadata("/proc/self")
            && meta.uid() != me.uid()
        {
            return refuse("owned by another user");
        }
    }
    Ok(())
}

impl Client {
    /// Where fetched files go, for every account (LR-M3): the options'
    /// directory, or `risala-files` beside the cache's file, or for a cache
    /// in memory a new directory in the system's temporary directory, with
    /// a random name. Each account has a directory of its own in it, made
    /// private when a file is saved.
    pub(crate) fn downloads_base(&self) -> PathBuf {
        self.inner
            .downloads
            .get_or_init(|| {
                if let Some(dir) = &self.options().download_dir {
                    return dir.clone();
                }
                if let Some(cache) = self.store().path()
                    && let Some(parent) = cache.parent()
                {
                    return parent.join("risala-files");
                }
                let name: [u8; 16] = risala_mls::primitives::random().unwrap_or([0; 16]);
                let hex: String = name.iter().map(|b| format!("{b:02x}")).collect();
                std::env::temp_dir().join(format!("risala-files-{hex}"))
            })
            .clone()
    }

    /// The HTTPS client for files and blobs: the options' or one with the
    /// options' CA check, else the platform's.
    pub(crate) fn file_https(&self) -> Arc<dyn FileHttps> {
        if let Some(h) = &self.options().file_https {
            return h.clone();
        }
        let verifier = self
            .options()
            .ca_verifier
            .clone()
            .unwrap_or_else(crate::conn::platform_ca_verifier);
        Arc::new(TlsFileHttps::new(verifier))
    }

    /// The area's work for a running account, on its connections.
    pub(crate) fn jobs_with(
        &self,
        account: AccountId,
        commands: Arc<dyn Commands>,
    ) -> Result<Jobs> {
        let a = self.account(account)?;
        Ok(Jobs {
            store: self.store().clone(),
            account,
            server: a.server.to_string(),
            uid: a.uid,
            commands,
            https: self.file_https(),
            clock: self.options().clock.clone(),
            keys: self.options().keys.clone(),
            events: self.inner.events.clone(),
            downloads: self.downloads_base().join(account.0.to_string()),
            max_blob: ARCHIVE_BLOB,
        })
    }

    /// The area's work for a connected account.
    pub(crate) fn jobs(&self, account: AccountId) -> Result<Jobs> {
        let exec = self.exec(account)?;
        self.jobs_with(account, exec)
    }

    /// Encrypts the file at `path` (12.11), uploads it (5.6) and sends a
    /// message that shares it, with `caption` as its text, or the file's
    /// name. The account must be connected.
    pub async fn send_file(
        &self,
        conversation: ConversationId,
        path: &Path,
        media_type: Option<&str>,
        caption: Option<&str>,
    ) -> Result<MessageId> {
        let row = self.conv_row(conversation)?;
        let jobs = self.jobs(row.account)?;
        let file = tokio::fs::read(path).await.map_err(StoreError::from)?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "file".into());
        let id = jobs
            .send_file(conversation, &file, &name, caption, media_type)
            .await?;
        self.kick(row.account).await;
        Ok(MessageId(id))
    }

    /// The file a message shares, as far as the device knows without
    /// fetching it.
    pub async fn file_info(
        &self,
        conversation: ConversationId,
        message: MessageId,
    ) -> Result<FileInfo> {
        let row = self.conv_row(conversation)?;
        let jobs = self.jobs(row.account)?;
        let (file, on_server) = jobs.file_of(conversation, &message.0).await?;
        let kept = self.store().file_row(conversation, &message.0)?;
        Ok(FileInfo {
            message,
            media_type: file.media_type.map(|m| m.to_string()),
            size: file.size.unwrap_or(0),
            path: kept.and_then(|k| k.path).map(PathBuf::from),
            url: file.url.to_string(),
            on_server,
        })
    }

    /// Fetches the file a message shares, checks its hash and decrypts it
    /// into the download directory (12.11). A file off the conversation's
    /// server's file origins gives [`TransferError::OtherHost`]: ask the
    /// user, telling them that its host will learn their network address,
    /// then use [`fetch_file_anywhere`](Self::fetch_file_anywhere).
    pub async fn fetch_file(
        &self,
        conversation: ConversationId,
        message: MessageId,
    ) -> Result<FileInfo> {
        let row = self.conv_row(conversation)?;
        self.jobs(row.account)?
            .fetch_file(conversation, &message.0, false)
            .await
    }

    /// [`fetch_file`](Self::fetch_file) from any host, once the user has
    /// agreed (12.11).
    pub async fn fetch_file_anywhere(
        &self,
        conversation: ConversationId,
        message: MessageId,
    ) -> Result<FileInfo> {
        let row = self.conv_row(conversation)?;
        self.jobs(row.account)?
            .fetch_file(conversation, &message.0, true)
            .await
    }
}

/// Whether a change is one the area's worker acts on.
pub(crate) fn wakes_worker(change: &Change) -> bool {
    matches!(
        change,
        Change::Transfer(_) | Change::Message(_) | Change::Conversation(_) | Change::Identity(_)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_match_get_urls() {
        let origins = vec!["https://files.example.org".to_owned()];
        let url: FileUrl = "https://files.example.org/f/abc".parse().unwrap();
        assert!(on_origins(&origins, &url));
        let url: FileUrl = "https://FILES.example.org:443/f/abc".parse().unwrap();
        assert!(on_origins(&origins, &url));
        let url: FileUrl = "https://files.example.org:8443/f/abc".parse().unwrap();
        assert!(!on_origins(&origins, &url));
        let url: FileUrl = "https://evil.example/f/abc".parse().unwrap();
        assert!(!on_origins(&origins, &url));
        assert!(!on_origins(&[], &url));
    }
}
