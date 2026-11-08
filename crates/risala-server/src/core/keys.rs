//! What the server keeps for devices without reading it (5.6, 12.5,
//! 12.8, 12.12, 12.13): KEYPKG, WELCOME, BLOB, BACKUP and UPLOAD, and the
//! HTTPS side of blobs and files.
//!
//! Not built yet: every command replies `ERR not-supported`.
//!
//! The store keeps KeyPackages, Welcomes, blobs, uploads and backups
//! ([`KeysStore`](crate::store::KeysStore)). Upload and blob URLs are
//! bearer secrets, stored as hashes ([`crate::secret`]).

use std::sync::Arc;

use risala_proto::command::Command;

use super::Inner;
use super::command::{Cx, Reply, misrouted, not_supported};
use super::state::ConnEntry;
use crate::config::Config;
use crate::handler::ConnId;
use crate::store::{Store, StoreError};

/// What the keys area keeps in memory.
#[derive(Debug)]
pub(crate) struct State {}

impl State {
    /// Loads the area's state when the hub starts.
    pub(crate) fn load(_config: &Config, _store: &dyn Store) -> Result<State, StoreError> {
        Ok(State {})
    }
}

/// What the keys area keeps about one connection.
#[derive(Debug, Default)]
pub(crate) struct ConnState {}

/// Handles KEYPKG, WELCOME, BLOB, BACKUP and UPLOAD.
pub(super) async fn handle(_cx: &Cx, command: Command) -> Reply {
    match command {
        Command::KeyPkg(_) // 12.5
        | Command::Welcome(_) // 12.8
        | Command::Blob { .. } // 12.12
        | Command::Backup(_) // 12.13
        | Command::Upload { .. } /* 5.6 */ => not_supported(),
        other => misrouted("keys", &other),
    }
}

/// Connection `id` has closed.
pub(super) fn conn_closed(_inner: &Arc<Inner>, _id: ConnId, _conn: &ConnEntry) {}

/// The area's background work: deleting KeyPackages whose lifetime has
/// ended (12.5), and Welcomes, blobs and files past retention (7.5).
pub(super) async fn maintain(_inner: Arc<Inner>) {}

/// What INFO says about files and blobs (8.5): `upload=`, `blobs=` and
/// `files=`.
#[derive(Debug, Clone)]
pub(crate) struct FilesInfo {
    /// The largest upload, or `no`.
    pub(crate) upload: risala_proto::server::Upload,
    /// The URL prefix blobs are fetched from, if the server stores blobs.
    pub(crate) blobs: Option<String>,
    /// The origins of `get` URLs, only with uploads.
    pub(crate) files: Vec<risala_proto::server::FileOrigin>,
}

/// INFO's `upload=`, `blobs=` and `files=` (8.5).
///
/// TODO(SV4): a stub added by SV5 (INFO) until uploads and blobs are
/// built: no uploads, and no blob store.
pub(crate) fn info(_inner: &Inner) -> FilesInfo {
    FilesInfo {
        upload: risala_proto::server::Upload::No,
        blobs: None,
        files: Vec::new(),
    }
}

/// The bytes of the blob `blob`, if the server holds it (12.12), for a
/// report of a post stored as a blob (5.8).
///
/// TODO(SV4): a stub added by SV5 (REPORT) until blobs are built.
pub(crate) async fn blob_bytes(
    _inner: &Inner,
    _blob: &risala_proto::names::BlobRef,
) -> Option<Vec<u8>> {
    None
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
