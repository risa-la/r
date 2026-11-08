//! History keys between an identity's own devices (12.9), and the
//! recovery key's backups (12.10), as part of the encryption engine.
//!
//! - **New devices.** A device notes the other devices of its identity
//!   that join the conversation with itself. One that was there when this
//!   device first joined is old; a later one is new, and waits for the
//!   user to confirm it on this device ([`SyncEngine::confirm_device`]).
//!   Only then does this device send it every history key it holds, as KEY
//!   lines in ENC in the conversation with itself (12.9), with the
//!   recovery key as a RECOVERY line if this device holds it (12.10).
//! - **Backups.** While the device holds the recovery key
//!   ([`SyncEngine::set_recovery_key`]), it backs up each history key it
//!   gets with BACKUP ADD, encrypted under the backup key (12.10).

use risala_mls::RecoveryKey;
use risala_mls::message::sender_key_id;
use risala_proto::auth::PublicKey;
use risala_proto::command::{BackupCommand, Command};
use risala_proto::error::ErrorCode;
use risala_proto::names::{Conv, Id, Uid};
use rusqlite::{OptionalExtension, params};
use tracing::{debug, warn};

use super::e2ee::E2eePending;
use super::engine::Pending;
use super::{Notification, Outcome, Reply, SyncEngine, SyncError};
use crate::e2ee::content::Control;
use crate::e2ee::group;
use crate::store::{StoreError, Tx};

/// How many BACKUP ADDs one connection has in flight at most.
const BACKUPS_IN_FLIGHT: usize = 64;

/// Where an own device is (`own_devices.state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnDeviceState {
    /// It joined after this device, and the user has not said whether it
    /// is theirs. It gets no history keys until then (12.9).
    New,
    /// The user confirmed it: this device sends it history keys.
    Confirmed,
    /// It has the history keys, or it was there before this device.
    Sent,
    /// The user did not recognise it.
    Declined,
}

impl OwnDeviceState {
    fn as_str(self) -> &'static str {
        match self {
            OwnDeviceState::New => "new",
            OwnDeviceState::Confirmed => "confirmed",
            OwnDeviceState::Sent => "sent",
            OwnDeviceState::Declined => "declined",
        }
    }

    /// Reads `own_devices.state`.
    pub(crate) fn parse(s: &str) -> Option<OwnDeviceState> {
        Some(match s {
            "new" => OwnDeviceState::New,
            "confirmed" => OwnDeviceState::Confirmed,
            "sent" => OwnDeviceState::Sent,
            "declined" => OwnDeviceState::Declined,
            _ => return None,
        })
    }
}

impl Tx<'_> {
    /// Notes the other devices of the identity in the current epoch of
    /// its conversation with itself. The first time, they are all old.
    /// Returns the keys that are new.
    fn note_own_devices(
        &mut self,
        account: crate::store::AccountId,
        me: &Uid,
        own: &PublicKey,
        leaves: &[group::Leaf],
    ) -> Result<Vec<PublicKey>, StoreError> {
        let first = self
            .conn()
            .query_row(
                "SELECT 1 FROM own_devices WHERE account = ?1 AND key_id = ?2",
                params![account.get(), &sender_key_id(own)[..]],
                |_| Ok(()),
            )
            .optional()?
            .is_none();
        let state = if first {
            OwnDeviceState::Sent
        } else {
            OwnDeviceState::New
        };
        if first {
            self.conn().execute(
                "INSERT OR IGNORE INTO own_devices (account, key_id, state) VALUES (?1, ?2, 'sent')",
                params![account.get(), &sender_key_id(own)[..]],
            )?;
        }
        let mut new = Vec::new();
        for leaf in leaves.iter().filter(|l| l.uid == *me && l.key != *own) {
            let added = self.conn().execute(
                "INSERT OR IGNORE INTO own_devices (account, key_id, state) VALUES (?1, ?2, ?3)",
                params![account.get(), &sender_key_id(&leaf.key)[..], state.as_str()],
            )?;
            if added > 0 && state == OwnDeviceState::New {
                new.push(leaf.key.clone());
            }
        }
        Ok(new)
    }

    /// Sets an own device's state.
    pub(crate) fn set_own_device(
        &mut self,
        account: crate::store::AccountId,
        key_id: &[u8],
        state: OwnDeviceState,
    ) -> Result<bool, StoreError> {
        Ok(self.conn().execute(
            "UPDATE own_devices SET state = ?3 WHERE account = ?1 AND key_id = ?2",
            params![account.get(), key_id, state.as_str()],
        )? > 0)
    }
}

impl SyncEngine {
    /// Says what the device holds as the identity's recovery key (12.10):
    /// it then backs up every history key it has and gets. `None` stops
    /// backups.
    pub fn set_recovery_key(
        &mut self,
        key: Option<RecoveryKey>,
    ) -> Result<super::Output, SyncError> {
        self.keep_recovery_key(key);
        self.backup_keys()?;
        Ok(self.finish())
    }

    /// [`set_recovery_key`](Self::set_recovery_key) without sending
    /// anything yet, before [`start`](Self::start).
    pub fn keep_recovery_key(&mut self, key: Option<RecoveryKey>) {
        if let Some(e) = self.e2ee.as_mut() {
            e.recovery = key;
            e.backups_failed.clear();
        }
    }

    /// The user confirmed (`true`) or did not recognise (`false`) a new
    /// device of the identity, by its key (12.9, 12.12). Once confirmed,
    /// this device sends it every history key it holds, and the recovery
    /// key if it holds one (12.10).
    pub fn confirm_device(
        &mut self,
        key: &PublicKey,
        confirmed: bool,
    ) -> Result<super::Output, SyncError> {
        let account = self.account;
        let state = if confirmed {
            OwnDeviceState::Confirmed
        } else {
            OwnDeviceState::Declined
        };
        let id = sender_key_id(key);
        let found = self.write(|tx| tx.set_own_device(account, &id, state))?;
        if !found {
            return Err(SyncError::Invalid("no such device of the identity".into()));
        }
        if confirmed {
            self.share_with_devices()?;
        }
        Ok(self.finish())
    }

    /// Notes new devices of the identity in its conversation with itself,
    /// and sends history keys to those the user confirmed (12.9).
    pub(super) fn own_devices(&mut self, conv: &Conv) -> Result<(), SyncError> {
        let Some(e) = self.e2ee.as_ref() else {
            return Ok(());
        };
        if e.recovery_connection() || *conv != Conv::Uid(self.me.clone()) {
            return Ok(());
        }
        let own = e.dev.key.public_key();
        let (account, me) = (self.account, self.me.clone());
        let new = self.e2ee_write(|tx| {
            let Some(row) = tx.conv_by_name(account, conv)? else {
                return Ok(Vec::new());
            };
            let Some(leaves) = group::current_leaves(tx, &row)? else {
                return Ok(Vec::new());
            };
            Ok(tx.note_own_devices(account, &me, &own, &leaves)?)
        })?;
        match new {
            Ok(keys) => {
                for key in keys {
                    self.out.notifications.push(Notification::NewDevice {
                        fingerprint: key.fingerprint().to_string(),
                    });
                }
            }
            Err(e) => warn!(error = %e, "noting the identity's devices"),
        }
        self.share_with_devices()
    }

    /// Sends every history key the device holds to the devices the user
    /// confirmed, once they are in the conversation with itself (12.9).
    fn share_with_devices(&mut self) -> Result<(), SyncError> {
        if self
            .e2ee
            .as_ref()
            .is_none_or(|e| e.recovery_connection() || e.sharing_keys)
        {
            return Ok(());
        }
        let account = self.account;
        let conv = Conv::Uid(self.me.clone());
        let recovery = self.e2ee.as_ref().and_then(|e| e.recovery.clone());
        let found = self.e2ee_write(|tx| {
            let Some(row) = tx.conv_by_name(account, &conv)? else {
                return Ok(None);
            };
            let Some(leaves) = group::current_leaves(tx, &row)? else {
                return Ok(None);
            };
            let confirmed: Vec<Vec<u8>> = {
                let mut stmt = tx
                    .conn()
                    .prepare_cached(
                        "SELECT key_id FROM own_devices WHERE account = ?1 AND state = 'confirmed'",
                    )
                    .map_err(StoreError::from)?;
                stmt.query_map([account.get()], |r| r.get(0))
                    .map_err(StoreError::from)?
                    .collect::<Result<_, _>>()
                    .map_err(StoreError::from)?
            };
            // Only to devices that are in the group now, so that they can
            // read the message.
            let ready: Vec<Vec<u8>> = confirmed
                .into_iter()
                .filter(|id| leaves.iter().any(|l| sender_key_id(&l.key)[..] == id[..]))
                .collect();
            if ready.is_empty() {
                return Ok(None);
            }
            let mut lines = Vec::new();
            for id in tx.key_conversations(account)? {
                for k in tx.history_keys(account, &id)? {
                    lines.push(Control::Key {
                        id: id.clone(),
                        epoch: k.epoch,
                        key: k.key,
                    });
                }
            }
            // The recovery key too, so that the new device backs up the
            // history keys it gets from now on (12.10, PLAN.md 47).
            if let Some(recovery) = recovery {
                lines.push(Control::Recovery(recovery));
            }
            Ok(Some((row, ready, lines)))
        })?;
        let (row, ready, lines) = match found {
            Ok(Some(found)) => found,
            Ok(None) => return Ok(()),
            Err(e) => {
                warn!(error = %e, "gathering history keys to share");
                return Ok(());
            }
        };
        if lines.is_empty() {
            for id in &ready {
                self.write(|tx| tx.set_own_device(account, id, OwnDeviceState::Sent))?;
            }
            return Ok(());
        }
        let sent = self.send_control_for(&conv, &row, lines, Some(ready))?;
        if sent {
            self.e2().sharing_keys = true;
        }
        Ok(())
    }

    /// Sends the recovery key to the identity's other devices, as a
    /// RECOVERY line in the conversation with itself (12.10).
    pub fn share_recovery_key(&mut self, key: &RecoveryKey) -> Result<super::Output, SyncError> {
        let account = self.account;
        let conv = Conv::Uid(self.me.clone());
        let row = self.write(|tx| tx.conv_by_name(account, &conv))?;
        match row {
            Some(row) => {
                self.send_control_for(&conv, &row, vec![Control::Recovery(key.clone())], None)?;
            }
            None => debug!("no conversation with itself to send the recovery key in"),
        }
        Ok(self.finish())
    }

    /// An ENC of KEY or RECOVERY lines was answered. With `devices`, the
    /// last message to the devices confirmed: they have their keys.
    pub(super) fn on_shared(
        &mut self,
        devices: Option<Vec<Vec<u8>>>,
        reply: &Reply,
    ) -> Result<(), SyncError> {
        let Some(devices) = devices else {
            return Ok(());
        };
        self.e2().sharing_keys = false;
        if !matches!(reply.outcome, Outcome::Ok(_)) {
            debug!("sending history keys to a new device failed; it is tried again");
            return Ok(());
        }
        let account = self.account;
        self.write(|tx| {
            for id in &devices {
                tx.set_own_device(account, id, OwnDeviceState::Sent)?;
            }
            Ok(())
        })?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Backups (12.10)

    /// Backs up the history keys not backed up yet under the current
    /// recovery key, a few at a time.
    pub(super) fn backup_keys(&mut self) -> Result<(), SyncError> {
        let Some(e) = self.e2ee.as_ref() else {
            return Ok(());
        };
        let Some(recovery) = e.recovery.clone() else {
            return Ok(());
        };
        let Some(identity) = self.me.to_identity() else {
            return Ok(());
        };
        let room = BACKUPS_IN_FLIGHT.saturating_sub(e.backing_up.len());
        if room == 0 {
            return Ok(());
        }
        let backup = recovery.backup_key(&identity);
        let key_id = backup.key_id().to_vec();
        let account = self.account;
        let skip: Vec<(Id, u64)> = e
            .backing_up
            .iter()
            .chain(e.backups_failed.iter())
            .cloned()
            .collect();
        let todo: Vec<(Id, u64, risala_mls::HistoryKey)> = self.write(|tx| {
            let mut stmt = tx.conn().prepare_cached(
                "SELECT conv_id, epoch, key FROM history_keys
                 WHERE account = ?1 AND (backed_up IS NULL OR backed_up != ?2)
                 ORDER BY conv_id, epoch",
            )?;
            let rows = stmt.query_map(params![account.get(), key_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            })?;
            let mut out = Vec::new();
            for row in rows {
                let (id, epoch, key) = row?;
                let id: Id = crate::store::parse(&id, "conversation id")?;
                let epoch = epoch.max(0) as u64;
                if skip.iter().any(|(i, e)| *i == id && *e == epoch) {
                    continue;
                }
                let key: [u8; 48] = key
                    .try_into()
                    .map_err(|_| StoreError::Corrupt("a history key is not 48 bytes".into()))?;
                out.push((id, epoch, risala_mls::HistoryKey::from_bytes(key)));
                if out.len() >= room {
                    break;
                }
            }
            Ok(out)
        })?;
        for (id, epoch, key) in todo {
            let Ok(blob) = backup.seal(&id, epoch, &key) else {
                warn!("no randomness for a backup");
                return Ok(());
            };
            self.e2().backing_up.push((id.clone(), epoch));
            self.issue(
                Command::Backup(BackupCommand::Add {
                    id: id.clone(),
                    epoch,
                    blob,
                }),
                Pending::E2ee(E2eePending::BackupAdd {
                    id,
                    epoch,
                    key_id: key_id.clone(),
                }),
            );
        }
        Ok(())
    }

    pub(super) fn on_backup_add(
        &mut self,
        id: Id,
        epoch: u64,
        key_id: Vec<u8>,
        reply: &Reply,
    ) -> Result<(), SyncError> {
        let e = self.e2();
        e.backing_up.retain(|(i, ep)| *i != id || *ep != epoch);
        let account = self.account;
        match &reply.outcome {
            // 12.10: a server may keep blobs of only a few key ids per
            // epoch; this one stays as it is.
            Outcome::Ok(_) => {
                self.write(|tx| tx.set_backed_up(account, &id, epoch, &key_id))?;
            }
            Outcome::Err(err) if err.code == ErrorCode::Forbidden => {
                warn!(%id, epoch, "the server keeps no more backups of this epoch");
                self.write(|tx| tx.set_backed_up(account, &id, epoch, &key_id))?;
            }
            _ => self.e2().backups_failed.push((id, epoch)),
        }
        self.backup_keys()
    }
}
