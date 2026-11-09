//! The bytes of blobs and files on disk, and what the HTTPS listener asks
//! of them (5.6, 12.12): [`Files`].
//!
//! Under [`Config::files_dir`](crate::config::Config::files_dir):
//!
//! - `blobs/<96 hex digits>`: each blob, named by its hash;
//! - `uploads/<id>`: each uploaded file, by the public part of its URLs;
//! - `tmp/`: uploads in progress, moved into place once complete and
//!   checked, and cleared when the server starts.
//!
//! Every URL is looked up by its public part, and its secret part checked
//! against the stored hash in constant time (Section 14). A URL whose
//! public part is unknown, and one whose secret is wrong, get the same
//! answer.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use risala_proto::names::BlobRef;
use risala_proto::time::Timestamp;

use super::{Inner, PUT_WINDOW, paths, retention_start};
use crate::store::StoreError;
use crate::store::keys::{BlobPut, UploadRecord};

/// Why a URL does not lead anywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refused {
    /// Unknown, wrong secret, expired, or deleted: 404.
    NotFound,
    /// A `put` URL that has been used, or whose 10 minutes are over: 410.
    Gone,
    /// The store failed: 500.
    Internal,
}

impl From<StoreError> for Refused {
    fn from(e: StoreError) -> Refused {
        tracing::error!("files: {e}");
        Refused::Internal
    }
}

/// A `put` URL claimed for one upload.
#[derive(Debug, Clone)]
pub(crate) enum PutTarget {
    /// A blob (12.12): its body must hash to [`BlobPut::hash`].
    Blob(BlobPut),
    /// A file (5.6).
    Upload(UploadRecord),
}

impl PutTarget {
    /// The size the body must have.
    pub(crate) fn size(&self) -> u64 {
        match self {
            PutTarget::Blob(put) => put.size,
            PutTarget::Upload(upload) => upload.size,
        }
    }
}

/// The HTTPS side of blobs and files, for the listener.
#[derive(Clone)]
pub(crate) struct Files {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Files {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Files").finish_non_exhaustive()
    }
}

/// Splits `<id>/<secret>` into its parts, each of `a-z 0-9` only.
fn id_and_secret(rest: &str) -> Option<(&str, &str)> {
    let (id, secret) = rest.split_once('/')?;
    let ok = |s: &str| {
        !s.is_empty()
            && s.len() <= 64
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    };
    (ok(id) && ok(secret)).then_some((id, secret))
}

/// A blob's hash from the 96 lower-case hex digits after the `blobs`
/// prefix.
pub(crate) fn blob_hash_of(hex: &str) -> Option<BlobRef> {
    if hex.len() != 96 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut hash = [0u8; 48];
    for (i, out) in hash.iter_mut().enumerate() {
        *out = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(BlobRef::from_hash(hash))
}

/// The public and secret parts of a `get` URL of this server, if `url` is
/// one.
pub(crate) fn upload_of_get_url(inner: &Inner, url: &str) -> Option<(String, String)> {
    let base = inner.keys.url()?;
    let rest = url.strip_prefix(&base)?.strip_prefix(paths::UPLOAD_GET)?;
    id_and_secret(rest).map(|(id, secret)| (id.to_owned(), secret.to_owned()))
}

/// Removes a file, logging anything but its being gone already.
pub(crate) fn remove_quietly(path: &Path) {
    if let Err(e) = std::fs::remove_file(path)
        && e.kind() != io::ErrorKind::NotFound
    {
        tracing::warn!(path = %path.display(), "removing a file: {e}");
    }
}

/// Removes an upload's bytes.
pub(crate) async fn remove_upload_file(inner: &Inner, id: &str) {
    let path = inner.keys.upload_path(id);
    let _ = tokio::task::spawn_blocking(move || remove_quietly(&path)).await;
}

/// Clears what uploads in progress left behind when the server stopped.
pub(crate) async fn clear_tmp(inner: &Inner) {
    let tmp = inner.keys.dir.join("tmp");
    let _ = tokio::task::spawn_blocking(move || {
        let Ok(entries) = std::fs::read_dir(&tmp) else {
            return;
        };
        for entry in entries.flatten() {
            remove_quietly(&entry.path());
        }
    })
    .await;
}

/// Writes `bytes` as the file of the blob `hash`, unless it is there
/// already, through `tmp/` so that the file is never seen half written.
/// The caller holds [`State::lock_fs`](super::State) and has checked
/// nothing about `bytes`: the file is named by their hash.
pub(crate) fn write_blob(keys: &super::State, hash: &BlobRef, bytes: &[u8]) -> io::Result<()> {
    let path = keys.blob_path(hash);
    if path.exists() {
        return Ok(());
    }
    let tmp_dir = keys.dir.join("tmp");
    create_dir(&tmp_dir)?;
    let tmp = tmp_dir.join(crate::secret::random_token(32).map_err(io::Error::other)?);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let written = options.open(&tmp).and_then(|mut file| {
        io::Write::write_all(&mut file, bytes)?;
        file.sync_all()
    });
    let moved = written.and_then(|()| {
        create_dir(path.parent().expect("a blob's directory"))?;
        std::fs::rename(&tmp, &path)
    });
    if moved.is_err() {
        remove_quietly(&tmp);
    }
    moved
}

/// Creates `dir` and its parents, private to the server.
fn create_dir(dir: &Path) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir)
}

impl Files {
    pub(super) fn new(inner: Arc<Inner>) -> Files {
        Files { inner }
    }

    fn now(&self) -> Timestamp {
        self.inner.now()
    }

    /// The running minimum rate of transfers over HTTPS, in bytes a
    /// second, and the time it is averaged over (`files.min_rate` and
    /// `files.min_rate_secs`, 10.6).
    pub(crate) fn min_rate(&self) -> (u64, std::time::Duration) {
        let files = &self.inner.config.files;
        (
            files.min_rate,
            std::time::Duration::from_secs(files.min_rate_secs.max(1)),
        )
    }

    /// The most connections that may transfer blobs and files at once
    /// (`files.max_transfers`).
    pub(crate) fn max_transfers(&self) -> usize {
        self.inner.config.files.max_transfers
    }

    async fn db<T: Send + 'static>(
        &self,
        f: impl FnOnce(&dyn crate::store::Store) -> crate::store::Result<T> + Send + 'static,
    ) -> Result<T, Refused> {
        Ok(self.inner.db(f).await?)
    }

    /// The blob `hash`, to download, if the server holds it and it has
    /// not expired: its file and size.
    pub(crate) async fn blob(&self, hash: BlobRef) -> Result<(PathBuf, u64), Refused> {
        let now = self.now();
        let start = retention_start(&self.inner, now);
        let h = hash;
        let record = self
            .db(move |store| store.blob(&h))
            .await?
            .ok_or(Refused::NotFound)?;
        if !record.kept && record.stored < start {
            return Err(Refused::NotFound);
        }
        Ok((self.inner.keys.blob_path(&hash), record.size))
    }

    /// Claims the `put` URL `<id>/<secret>` under `prefix` for one upload.
    pub(crate) async fn claim_put(&self, prefix: &str, rest: &str) -> Result<PutTarget, Refused> {
        let (id, secret) = id_and_secret(rest).ok_or(Refused::NotFound)?;
        let (id, secret) = (id.to_owned(), secret.to_owned());
        let now = self.now();
        if prefix == paths::BLOB_PUT {
            let key = id.clone();
            let put = self
                .db(move |store| store.blob_put(&key))
                .await?
                .ok_or(Refused::NotFound)?;
            if !put.secret.matches(secret.as_bytes()) {
                return Err(Refused::NotFound);
            }
            if put.expires < now {
                return Err(Refused::Gone);
            }
            if !self.db(move |store| store.claim_blob_put(&id)).await? {
                return Err(Refused::Gone);
            }
            Ok(PutTarget::Blob(put))
        } else {
            let key = id.clone();
            let upload = self
                .db(move |store| store.upload(&key))
                .await?
                .ok_or(Refused::NotFound)?;
            if !upload.put.matches(secret.as_bytes()) {
                return Err(Refused::NotFound);
            }
            let ends = upload.created.checked_add(PUT_WINDOW).unwrap_or(now);
            if ends < now || upload.claimed {
                return Err(Refused::Gone);
            }
            if !self.db(move |store| store.claim_upload(&id)).await? {
                return Err(Refused::Gone);
            }
            Ok(PutTarget::Upload(upload))
        }
    }

    /// A new file in `tmp/` for a body to be written to.
    pub(crate) async fn temp_file(&self) -> io::Result<(PathBuf, tokio::fs::File)> {
        let tmp = self.inner.keys.dir.join("tmp");
        let name = crate::secret::random_token(32).map_err(io::Error::other)?;
        let path = tmp.join(name);
        let file = tokio::task::spawn_blocking({
            let path = path.clone();
            move || {
                create_dir(&tmp)?;
                let mut options = std::fs::OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
                options.open(&path)
            }
        })
        .await
        .map_err(io::Error::other)??;
        Ok((path, tokio::fs::File::from_std(file)))
    }

    /// The body of `target` is complete in `tmp`, and checked: moves it
    /// into place and records it. Returns `false` if the upload was
    /// deleted meanwhile, and then removes `tmp`.
    pub(crate) async fn commit(&self, target: PutTarget, tmp: PathBuf) -> Result<bool, Refused> {
        let inner = self.inner.clone();
        let now = self.now();
        let done = tokio::task::spawn_blocking(move || -> Result<bool, StoreError> {
            let keys = &inner.keys;
            match target {
                PutTarget::Blob(put) => {
                    let path = keys.blob_path(&put.hash);
                    let _guard = keys.lock_fs();
                    create_dir(path.parent().expect("a blob's directory"))
                        .and_then(|()| std::fs::rename(&tmp, &path))
                        .map_err(|e| StoreError::Setup(format!("storing a blob: {e}")))?;
                    inner.store.blob_stored(&put, now)?;
                    Ok(true)
                }
                PutTarget::Upload(upload) => {
                    let path = keys.upload_path(&upload.id);
                    create_dir(path.parent().expect("an upload's directory"))
                        .and_then(|()| std::fs::rename(&tmp, &path))
                        .map_err(|e| StoreError::Setup(format!("storing a file: {e}")))?;
                    if inner.store.upload_stored(&upload.id, now)? {
                        Ok(true)
                    } else {
                        remove_quietly(&path);
                        Ok(false)
                    }
                }
            }
        })
        .await
        .map_err(|e| StoreError::Task(e.to_string()))?;
        Ok(done?)
    }

    /// The file whose `get` URL ends in `<id>/<secret>`, to download, if
    /// it is stored and has not expired: its file and size.
    pub(crate) async fn upload(&self, rest: &str) -> Result<(PathBuf, u64), Refused> {
        let (id, secret) = id_and_secret(rest).ok_or(Refused::NotFound)?;
        let (id, secret) = (id.to_owned(), secret.to_owned());
        let start = retention_start(&self.inner, self.now());
        let key = id.clone();
        let upload = self
            .db(move |store| store.upload(&key))
            .await?
            .ok_or(Refused::NotFound)?;
        if !upload.get.matches(secret.as_bytes()) {
            return Err(Refused::NotFound);
        }
        match upload.stored {
            // A file a report keeps stays, even if it has expired or its
            // uploader deleted it (5.8).
            Some(_) if upload.held > 0 => {}
            Some(stored) if stored >= start && !upload.deleted => {}
            _ => return Err(Refused::NotFound),
        }
        Ok((self.inner.keys.upload_path(&id), upload.size))
    }

    /// Deletes the file whose `del` URL ends in `<id>/<secret>` (5.6).
    pub(crate) async fn delete(&self, rest: &str) -> Result<(), Refused> {
        let (id, secret) = id_and_secret(rest).ok_or(Refused::NotFound)?;
        let (id, secret) = (id.to_owned(), secret.to_owned());
        let key = id.clone();
        let upload = self
            .db(move |store| store.upload(&key))
            .await?
            .ok_or(Refused::NotFound)?;
        if !upload.del.matches(secret.as_bytes()) || upload.deleted {
            return Err(Refused::NotFound);
        }
        let key = id.clone();
        if self.db(move |store| store.delete_upload(&key)).await? {
            remove_upload_file(&self.inner, &id).await;
        }
        Ok(())
    }
}
