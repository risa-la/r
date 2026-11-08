//! Files (5.6, 12.11): sending a file in a conversation, and fetching
//! one. This module also holds the errors and events of task C4's area:
//! files, transfers, backups, push and reports.
//!
//! Owned by task C4. Every method returns [`Error::NotImplemented`](super::Error::NotImplemented) until
//! C4 builds it; the shapes are a starting point, which C4 may change.

use std::path::{Path, PathBuf};

use super::error::not_implemented;
use super::types::{ConversationId, MessageId};
use super::{Client, Result};

/// The errors of files, transfers, backups, push and reports.
#[derive(Debug, thiserror::Error)]
pub enum TransferError {
    /// The file's bytes do not have the hash its message gives (12.11).
    #[error("the file does not match its hash")]
    HashMismatch,
    /// The server no longer has it (7.5).
    #[error("the server no longer has it")]
    Expired,
}

/// What C4's area tells the UI, besides changes to the cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferEvent {
    /// Bytes of a file, transfer or backup moved.
    Progress {
        /// The file's row, or 0 for a transfer or backup.
        file: i64,
        /// Bytes done.
        done: u64,
        /// Bytes in all.
        total: u64,
    },
}

/// A file shared in a conversation (5.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileInfo {
    /// The message that shares it.
    pub message: MessageId,
    /// Its media type, if the message gives one.
    pub media_type: Option<String>,
    /// Its size before encryption.
    pub size: u64,
    /// Where it is on this device, once fetched.
    pub path: Option<PathBuf>,
}

impl Client {
    /// Encrypts the file at `path` (12.11), uploads it (5.6) and sends a
    /// message that shares it.
    pub async fn send_file(
        &self,
        conversation: ConversationId,
        path: &Path,
        media_type: Option<&str>,
    ) -> Result<MessageId> {
        let _ = (conversation, path, media_type);
        not_implemented("send_file")
    }

    /// Fetches the file a message shares, checks its hash and decrypts it
    /// into the download cache (12.11).
    pub async fn fetch_file(
        &self,
        conversation: ConversationId,
        message: MessageId,
    ) -> Result<FileInfo> {
        let _ = (conversation, message);
        not_implemented("fetch_file")
    }
}
