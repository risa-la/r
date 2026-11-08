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
//!   Every leaf there reads those lines, so none are sent while a device
//!   of the identity there is new or declined. A declined device's leaves
//!   are removed from every group.
//! - **Received keys.** KEY and RECOVERY lines count only from devices the
//!   user confirmed or that were there first. A recovery key counts only
//!   while the key file lists its signing key; one that would replace the
//!   key this device holds waits for the user
//!   ([`SyncEngine::accept_recovery_key`]).
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
use crate::store::{ConvRow, StoreError, Tx};

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

    /// The state of an own device, by key id.
    pub(crate) fn own_device_state(
        &self,
        account: crate::store::AccountId,
        key_id: &[u8],
    ) -> Result<Option<OwnDeviceState>, StoreError> {
        let state: Option<String> = self
            .conn()
            .query_row(
                "SELECT state FROM own_devices WHERE account = ?1 AND key_id = ?2",
                params![account.get(), key_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(state.as_deref().and_then(OwnDeviceState::parse))
    }

    /// Whether KEY and RECOVERY lines from the own device with `key_id`
    /// count: the user confirmed it, or it was there when this device
    /// joined (12.9).
    pub(crate) fn trusted_own_device(
        &self,
        account: crate::store::AccountId,
        key_id: &[u8],
    ) -> Result<bool, StoreError> {
        Ok(matches!(
            self.own_device_state(account, key_id)?,
            Some(OwnDeviceState::Confirmed | OwnDeviceState::Sent)
        ))
    }

    /// The recovery key still to send to the identity's other devices.
    fn recovery_unshared(
        &self,
        account: crate::store::AccountId,
    ) -> Result<Option<RecoveryKey>, StoreError> {
        let raw: Option<Option<Vec<u8>>> = self
            .conn()
            .query_row(
                "SELECT unshared FROM recovery_state WHERE account = ?1",
                [account.get()],
                |r| r.get(0),
            )
            .optional()?;
        raw.flatten().map(|b| recovery_from(&b)).transpose()
    }

    fn set_recovery_unshared(
        &mut self,
        account: crate::store::AccountId,
        key: Option<&RecoveryKey>,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "INSERT INTO recovery_state (account, unshared) VALUES (?1, ?2)
             ON CONFLICT (account) DO UPDATE SET unshared = excluded.unshared",
            params![account.get(), key.map(|k| k.as_bytes().to_vec())],
        )?;
        Ok(())
    }

    /// A recovery key another device sent, since when, and whether the user
    /// was asked about it.
    fn recovery_offered(
        &self,
        account: crate::store::AccountId,
    ) -> Result<Option<(RecoveryKey, i64, bool)>, StoreError> {
        let raw: Option<(Option<Vec<u8>>, Option<i64>, bool)> = self
            .conn()
            .query_row(
                "SELECT offered, offered_at, asked FROM recovery_state WHERE account = ?1",
                [account.get()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        match raw {
            Some((Some(key), at, asked)) => {
                Ok(Some((recovery_from(&key)?, at.unwrap_or(0), asked)))
            }
            _ => Ok(None),
        }
    }

    fn set_recovery_offered(
        &mut self,
        account: crate::store::AccountId,
        offered: Option<(&RecoveryKey, i64)>,
        asked: bool,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "INSERT INTO recovery_state (account, offered, offered_at, asked)
                 VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (account) DO UPDATE SET offered = excluded.offered,
                 offered_at = excluded.offered_at, asked = excluded.asked",
            params![
                account.get(),
                offered.map(|(k, _)| k.as_bytes().to_vec()),
                offered.map(|(_, at)| at),
                asked
            ],
        )?;
        Ok(())
    }

    /// Whether every leaf of the identity in its conversation with itself,
    /// other than `own`, is a device the user confirmed or that was there
    /// first (12.9): only then may KEY or RECOVERY lines go there, since
    /// every leaf reads them.
    fn own_leaves_trusted(
        &self,
        account: crate::store::AccountId,
        me: &Uid,
        own: &PublicKey,
        leaves: &[group::Leaf],
    ) -> Result<bool, StoreError> {
        for leaf in leaves.iter().filter(|l| l.uid == *me && l.key != *own) {
            if !self.trusted_own_device(account, &sender_key_id(&leaf.key))? {
                return Ok(false);
            }
        }
        Ok(true)
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

/// Whether the leaf of `uid` with `key` is one of `me`'s devices that the
/// user declined, which this device removes (12.9).
pub(super) fn declined_leaf(
    tx: &Tx<'_>,
    (account, me): (crate::store::AccountId, &Uid),
    uid: &Uid,
    key: &PublicKey,
) -> Result<bool, StoreError> {
    Ok(uid == me && tx.own_device_state(account, &sender_key_id(key))? == Some(OwnDeviceState::Declined))
}

fn recovery_from(bytes: &[u8]) -> Result<RecoveryKey, StoreError> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| StoreError::Corrupt("a recovery key is not 32 bytes".into()))?;
    Ok(RecoveryKey::from_bytes(bytes))
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
            self.try_share_recovery()?;
        } else {
            // 12.9: its leaves go from every group, which the duties of
            // each conversation commit.
            self.e2ee_all()?;
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
        self.share_with_devices()?;
        self.consider_offered_recovery()?;
        self.try_share_recovery()
    }

    /// The conversation with itself, its leaves, and whether KEY and
    /// RECOVERY lines may go there now (12.9).
    fn self_conversation(&mut self) -> Result<Option<(ConvRow, Vec<group::Leaf>, bool)>, SyncError> {
        let Some(e) = self.e2ee.as_ref() else {
            return Ok(None);
        };
        let own = e.dev.key.public_key();
        let (account, me) = (self.account, self.me.clone());
        let conv = Conv::Uid(me.clone());
        let found = self.e2ee_write(|tx| {
            let Some(row) = tx.conv_by_name(account, &conv)? else {
                return Ok(None);
            };
            let Some(leaves) = group::current_leaves(tx, &row)? else {
                return Ok(None);
            };
            let trusted = tx.own_leaves_trusted(account, &me, &own, &leaves)?;
            Ok(Some((row, leaves, trusted)))
        })?;
        match found {
            Ok(found) => Ok(found),
            Err(e) => {
                warn!(error = %e, "reading the conversation with itself");
                Ok(None)
            }
        }
    }

    /// Whether the identity's key file lists the signing key of `key` now
    /// (12.10): `None` if the device has not fetched it since `since`.
    fn recovery_listed(&mut self, key: &RecoveryKey, since: i64) -> Result<Option<bool>, SyncError> {
        let Some(identity) = self.me.to_identity() else {
            return Ok(Some(false));
        };
        let public = key.signing_key(&identity).public_key();
        let (account, me) = (self.account, self.me.clone());
        self.write(|tx| {
            Ok(match tx.key_listed(account, &me, &public)? {
                Some(listed) => Some(listed),
                // A fetch after `since` that did not list it.
                None => match tx.key_file_times(account, &me)?.0 {
                    Some(fetched) if fetched >= since => Some(false),
                    _ => None,
                },
            })
        })
    }

    /// Fetches the identity's own key file, unless it was tried after
    /// `since` or is on its way, to see whether it lists a recovery key
    /// (12.10).
    fn fetch_own_key_file(&mut self, since: i64) -> Result<(), SyncError> {
        let (account, me) = (self.account, self.me.clone());
        let tried = self.write(|tx| Ok(tx.key_file_times(account, &me)?.1))?;
        if tried.is_none_or(|t| t < since) {
            self.fetch_key_file(&me);
        }
        Ok(())
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
        let Some((row, leaves, trusted)) = self.self_conversation()? else {
            return Ok(());
        };
        // 12.9: not while a device that would read them is new or declined.
        if !trusted {
            return Ok(());
        }
        // 12.10: the recovery key only while the key file lists it.
        let mut recovery = self.e2ee.as_ref().and_then(|e| e.recovery.clone());
        if let Some(key) = recovery.clone()
            && self.recovery_listed(&key, i64::MAX)? != Some(true)
        {
            recovery = None;
        }
        let found = self.e2ee_write(|tx| {
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
            Ok(Some((row.clone(), ready, lines)))
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
    /// RECOVERY line in the conversation with itself (12.10), once every
    /// device there is confirmed and the key file lists the key's signing
    /// key. Until then it waits, also across connections.
    pub fn share_recovery_key(&mut self, key: &RecoveryKey) -> Result<super::Output, SyncError> {
        let account = self.account;
        self.write(|tx| tx.set_recovery_unshared(account, Some(key)))?;
        if let Some(e) = self.e2ee.as_mut() {
            e.sharing_recovery = false;
            e.share_since = group::now_ms();
        }
        self.try_share_recovery()?;
        Ok(self.finish())
    }

    /// Sends the recovery key waiting to go to the identity's other
    /// devices, if it may go now (12.9, 12.10).
    pub(super) fn try_share_recovery(&mut self) -> Result<(), SyncError> {
        if self
            .e2ee
            .as_ref()
            .is_none_or(|e| e.recovery_connection() || e.sharing_recovery)
        {
            return Ok(());
        }
        let account = self.account;
        let Some(key) = self.write(|tx| tx.recovery_unshared(account))? else {
            return Ok(());
        };
        let Some((row, leaves, trusted)) = self.self_conversation()? else {
            return Ok(());
        };
        if !trusted {
            return Ok(());
        }
        let since = self.e2().share_since;
        match self.recovery_listed(&key, since)? {
            Some(true) => {}
            Some(false) => {
                debug!("the recovery key waits until the key file lists it");
                return Ok(());
            }
            None => return self.fetch_own_key_file(since),
        }
        // Nobody else to send it to.
        let own = self.e2().dev.key.public_key();
        if !leaves.iter().any(|l| l.uid == self.me && l.key != own) {
            return Ok(());
        }
        let conv = Conv::Uid(self.me.clone());
        if self.send_control_for(&conv, &row, vec![Control::Recovery(key)], None)? {
            self.e2().sharing_recovery = true;
        }
        Ok(())
    }

    /// A recovery key another device sent (12.10): kept if the key file
    /// lists it and the device holds none, and offered to the user if the
    /// device holds another.
    pub(super) fn recovery_received(&mut self, key: RecoveryKey) -> Result<(), SyncError> {
        if self
            .e2ee
            .as_ref()
            .is_some_and(|e| e.recovery.as_ref() == Some(&key))
        {
            return Ok(());
        }
        let account = self.account;
        let now = group::now_ms();
        self.write(|tx| tx.set_recovery_offered(account, Some((&key, now)), false))?;
        self.consider_offered_recovery()
    }

    /// Decides on the recovery key another device offered, once the key
    /// file says whether it lists it (12.10).
    pub(super) fn consider_offered_recovery(&mut self) -> Result<(), SyncError> {
        if self.e2ee.is_none() {
            return Ok(());
        }
        let account = self.account;
        let Some((key, at, asked)) = self.write(|tx| tx.recovery_offered(account))? else {
            return Ok(());
        };
        let held = self.e2ee.as_ref().and_then(|e| e.recovery.clone());
        if held.as_ref() == Some(&key) {
            self.write(|tx| tx.set_recovery_offered(account, None, false))?;
            return Ok(());
        }
        match self.recovery_listed(&key, at)? {
            None => self.fetch_own_key_file(at)?,
            Some(false) => {
                debug!("a recovery key the key file does not list is ignored");
                self.write(|tx| tx.set_recovery_offered(account, None, false))?;
            }
            Some(true) if held.is_none() => {
                self.write(|tx| tx.set_recovery_offered(account, None, false))?;
                self.keep_recovery_key(Some(key.clone()));
                self.out.recovery = Some(key);
                self.backup_keys()?;
            }
            // 12.10: ask before replacing the one the device holds.
            Some(true) if !asked => {
                self.write(|tx| tx.set_recovery_offered(account, Some((&key, at)), true))?;
                self.out.notifications.push(Notification::RecoveryKeyOffered);
            }
            Some(true) => {}
        }
        Ok(())
    }

    /// The user's answer to [`Notification::RecoveryKeyOffered`]: with
    /// `true` the offered key replaces the one the device holds, and comes
    /// back in [`Output::recovery`](super::Output::recovery) to keep;
    /// with `false` it is dropped.
    pub fn accept_recovery_key(&mut self, accept: bool) -> Result<super::Output, SyncError> {
        let account = self.account;
        let offered = self.write(|tx| {
            let offered = tx.recovery_offered(account)?;
            tx.set_recovery_offered(account, None, false)?;
            Ok(offered)
        })?;
        if accept && let Some((key, at, _)) = offered {
            // Still only while the key file lists it.
            if self.recovery_listed(&key, at)? == Some(true) {
                self.keep_recovery_key(Some(key.clone()));
                self.out.recovery = Some(key);
                self.backup_keys()?;
            }
        }
        Ok(self.finish())
    }

    /// An ENC of KEY or RECOVERY lines in `conv` was answered. With
    /// `devices`, the last message to the devices confirmed: they have
    /// their keys. A room's keys or the recovery key that did not go are
    /// sent again.
    pub(super) fn on_shared(
        &mut self,
        conv: Conv,
        devices: Option<Vec<Vec<u8>>>,
        recovery: bool,
        reply: &Reply,
    ) -> Result<(), SyncError> {
        let ok = matches!(reply.outcome, Outcome::Ok(_));
        let account = self.account;
        if recovery {
            self.e2().sharing_recovery = false;
            if ok {
                self.write(|tx| tx.set_recovery_unshared(account, None))?;
            }
        }
        if !ok && conv.is_room() {
            debug!(%conv, "sharing a room's history keys failed; it is tried again");
            self.e2().to_share.insert(conv.clone());
        }
        let Some(devices) = devices else {
            return Ok(());
        };
        self.e2().sharing_keys = false;
        if !ok {
            debug!("sending history keys to a new device failed; it is tried again");
            return Ok(());
        }
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
