//! History on new devices and backups (12.13).
//!
//! Owned by task C4. Every method returns [`Error::NotImplemented`](super::Error::NotImplemented) until
//! C4 builds it; the shapes are a starting point, which C4 may change.
//! Transfers at pairing are started by
//! [`Client::confirm_pairing`](super::Client::confirm_pairing) (C1), and
//! built here.

use super::error::not_implemented;
use super::types::{AccountId, Timestamp};
use super::{Client, Result};

/// A backup on the server (12.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupInfo {
    /// The backup key's generation.
    pub generation: u32,
    /// When this device made or restored it, if it did.
    pub made: Option<Timestamp>,
}

impl Client {
    /// Makes a backup of this device's history now, for the account's
    /// identity on its server (12.13).
    pub async fn backup_now(&self, account: AccountId) -> Result<BackupInfo> {
        let _ = account;
        not_implemented("backup_now")
    }

    /// The account's backup on its server, if there is one.
    pub async fn backup(&self, account: AccountId) -> Result<Option<BackupInfo>> {
        let _ = account;
        not_implemented("backup")
    }

    /// Restores history from the account's backup, with the recovery key
    /// (12.13).
    pub async fn restore_backup(&self, account: AccountId, recovery_key: &str) -> Result<()> {
        let _ = (account, recovery_key);
        not_implemented("restore_backup")
    }

    /// Deletes the account's backup (12.13).
    pub async fn delete_backup(&self, account: AccountId) -> Result<()> {
        let _ = account;
        not_implemented("delete_backup")
    }
}
