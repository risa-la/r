//! History on new devices and backups (12.13), and the worker that does
//! C4's area's work for each running account.
//!
//! Owned by task C4.
//!
//! - **Transfers.** Another device's WANT (in the conversation with
//!   yourself) is answered with the messages this device holds in that
//!   range, as archives stored in blobs, named by a TRANSFER line. A
//!   TRANSFER line this device asked for, and the IdentityBundle's
//!   transfer at pairing ([`Client::receive_pairing_transfer`]), are
//!   fetched, opened and applied under 12.13's rules
//!   (`crate::sync::transfer::apply`). The old device builds the
//!   pairing transfer with [`Client::pairing_transfer`], for the identity
//!   area (task C1) to put in the IdentityBundle.
//! - **Backups.** Once the user turns them on ([`Client::set_backups`]),
//!   a backup is made at most once a day, and at once when the identity
//!   moves to a new generation (4.8): archives of everything, the
//!   first one's key wrapped under the current backup key, the other
//!   blobs listed, then BACKUP PUT. [`Client::restore_backup`] follows
//!   12.13's steps after recovery.
//! - **The worker.** Each running account has a task that does the work
//!   above when the cache changes, and every 30 seconds.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use risala_mls::archive::{ArchiveError, ArchivedFile, HistoryArchive, TransferRef};
use risala_mls::backup::{Backup, BackupError, BackupKey, RecoveryKey, WrappedKey};
use risala_mls::file::{BlobRef as MlsBlobRef, FileKey as MlsFileKey, Label};
use risala_proto::command::{BackupCommand, Command};
use risala_proto::content::{ContentLine, TransferRef as TransferText};
use risala_proto::error::ErrorCode;
use risala_proto::names::Identity;
use risala_proto::server::ServerLine;
use tokio::sync::broadcast;

use super::files::{Commands, Jobs, TransferError, TransferEvent, ok, proto_ref, wakes_worker};
use super::identity::IdentityEvent;
use super::types::{AccountId, ConversationId, DeviceId, MessageId, Timestamp};
use super::{Client, Error, Event, Result};
use crate::conn::End;
use crate::store::transfer::{BackupRow, Origin, TransferKind, TransferRow};
use crate::store::{StoreError, Tx};
use crate::sync::Target;
use crate::sync::conversations::{EngineError, content};
use crate::sync::transfer::{self as logic, Selection, Source};

/// At most one backup a day (12.13).
pub const BACKUP_EVERY_MS: u64 = 24 * 60 * 60 * 1000;

/// How often the worker looks for work when nothing wakes it.
const WORKER_PERIOD: Duration = Duration::from_secs(30);

/// How many times a transfer is fetched before it is given up.
const TRANSFER_ATTEMPTS: u32 = 5;

/// A backup on the server (12.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupInfo {
    /// The backup key's generation.
    pub generation: u32,
    /// When it was made, if this device made or restored it, or when a
    /// restore read it from its first archive.
    pub made: Option<Timestamp>,
}

/// Where a message came from (12.13), to show with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageOrigin {
    /// From the server, as posted.
    Received,
    /// Copied from another device of the identity: show it as copied from
    /// that device, and `vouched` as that device's verification, never as
    /// this device's own.
    Copied {
        /// The device's label, as this device knows it.
        device: Option<String>,
        /// Whether that device had confirmed the sender's leaf.
        vouched: bool,
    },
    /// Restored from a backup: show it as restored, and `vouched` as the
    /// verification of the user's device at the time.
    Restored {
        /// When the backup was made.
        made: Timestamp,
        /// Whether the device that made it had confirmed the sender.
        vouched: bool,
    },
}

/// What a restore did (12.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Restored {
    /// When the backup was made, from its first archive: show it, so that
    /// the user can notice an older backup than the newest (Section 14).
    pub made: Timestamp,
    /// Messages stored now.
    pub messages: usize,
    /// Conversations kept until the device is added to them again.
    pub waiting: usize,
    /// Archives that could not be fetched or opened, and conversations out
    /// of seq order: if not 0, part of the history is missing.
    pub missing: usize,
}

fn setting(uid: &str) -> String {
    format!("backups.{uid}")
}

fn engine(e: EngineError) -> Error {
    match e {
        EngineError::Store(s) => Error::Store(s),
        other => Error::Internal(other.to_string()),
    }
}

fn archive_error(e: impl std::fmt::Display) -> Error {
    TransferError::Unreadable(e.to_string()).into()
}

/// Archives stored as blobs.
struct Stored {
    /// The first archive's TransferRef.
    first: TransferRef,
}

impl Jobs {
    fn identity(&self) -> Result<Identity> {
        self.uid
            .as_str()
            .parse()
            .map_err(|_| TransferError::NotPossible("a guest has no history to keep".into()).into())
    }

    fn is_guest(&self) -> bool {
        self.uid.is_guest()
    }

    /// The blobs of the files to include, encrypted again under the key
    /// made for each before, or a new one (12.13), and stored.
    async fn store_files(&self, files: Vec<logic::FileToArchive>) -> Result<Vec<ArchivedFile>> {
        let mut out = Vec::new();
        for f in files {
            let Ok(plain) = tokio::fs::read(&f.path).await else {
                continue;
            };
            let file_hash = MlsBlobRef::from_bytes(f.file_hash);
            let (bytes, archived) = match f.blob {
                // The same key and file give the same blob, so a server
                // that still has it answers exists=yes.
                Some((_, key)) => {
                    let key = MlsFileKey::from_bytes(key);
                    let (bytes, hash) =
                        risala_mls::file::encrypt_with_key(&key, Label::File, &plain);
                    (
                        bytes,
                        ArchivedFile {
                            file_hash,
                            blob: hash,
                            key,
                        },
                    )
                }
                None => ArchivedFile::encrypt(file_hash, &plain)
                    .map_err(|e| Error::Internal(format!("random: {e}")))?,
            };
            self.put_blob(&bytes).await?;
            let (account, hash, blob, key) = (
                self.account,
                f.file_hash,
                *archived.blob.as_bytes(),
                *archived.key.as_bytes(),
            );
            self.write(move |tx| Ok(tx.add_file_blob(account, &hash, &blob, &key)?))?;
            out.push(archived);
        }
        Ok(out)
    }

    /// Builds archives of `selection`, stores them as blobs, and gives the
    /// first's TransferRef, or `None` if there is nothing to send.
    async fn store_transfer(
        &self,
        selection: Selection,
        with_files: bool,
    ) -> Result<Option<Stored>> {
        let uid = self.identity()?;
        let account = self.account;
        let collected = self
            .store
            .write_with(|tx| logic::collect(tx, account, &selection, with_files))
            .map_err(engine)?
            .0;
        if collected.conversations.is_empty() {
            return Ok(None);
        }
        let files = self.store_files(collected.files).await?;
        let sealed = risala_mls::archive::seal_transfer(
            &uid,
            self.now(),
            collected.conversations,
            files,
            self.max_blob,
        )
        .map_err(archive_error)?;
        for archive in &sealed {
            self.put_blob(&archive.blob).await?;
        }
        Ok(Some(Stored {
            first: sealed[0].transfer.clone(),
        }))
    }

    /// Fetches the archives of a transfer or backup whose first archive
    /// is `first`, and opens them (12.13).
    async fn open(&self, first: &TransferRef) -> Result<risala_mls::archive::OpenedTransfer> {
        let uid = self.identity()?;
        let mut blobs: HashMap<[u8; 48], Vec<u8>> = HashMap::new();
        let head = self.get_blob(&first.blob).await?;
        let archive = HistoryArchive::open(first, &head, &uid).map_err(archive_error)?;
        blobs.insert(*first.blob.as_bytes(), head);
        for more in &archive.more {
            match self.get_blob(&more.blob).await {
                Ok(bytes) => {
                    blobs.insert(*more.blob.as_bytes(), bytes);
                }
                Err(e) => tracing::info!(error = %e, "an archive of a transfer is missing"),
            }
        }
        risala_mls::archive::open_transfer(first, &uid, |h| blobs.get(h.as_bytes()).cloned())
            .map_err(archive_error)
    }

    /// A transfer of everything, as at pairing: the encoded TransferRef.
    #[cfg(test)]
    pub(crate) async fn store_transfer_for_tests(&self) -> Result<Vec<u8>> {
        let stored = self
            .store_transfer(Selection::All, true)
            .await?
            .ok_or(TransferError::NotPossible("no history".into()))?;
        Ok(stored.first.to_bytes().to_vec())
    }

    // ---- WANT and TRANSFER

    /// Answers other devices' WANTs with the messages this device holds
    /// in their ranges, as a TRANSFER in the conversation with yourself
    /// (12.13).
    pub(crate) async fn answer_wants(&self) -> Result<()> {
        let requests = self
            .store
            .write_with(|tx| tx.want_requests(self.account))?
            .0;
        for request in requests {
            let Ok(mailbox) = request.mailbox.parse() else {
                self.write(|tx| Ok(tx.remove_want_request(request.id)?))?;
                continue;
            };
            let selection = Selection::Range {
                mailbox,
                range: request.range,
            };
            let stored = self.store_transfer(selection, true).await?;
            let (account, uid, now, id) = (self.account, self.uid.clone(), self.now(), request.id);
            self.write(move |tx| {
                if let Some(stored) = &stored
                    && let Some(me) = logic::self_conversation(tx, account)?
                {
                    let line =
                        ContentLine::Transfer(TransferText::from_bytes(*stored.first.to_bytes()));
                    content::queue_lines(tx, me.id, &uid, vec![line], false, now)?;
                }
                tx.remove_want_request(id)?;
                Ok(())
            })?;
        }
        Ok(())
    }

    /// Fetches and applies the transfers that are due: TRANSFER lines,
    /// and the pairing transfer.
    pub(crate) async fn fetch_transfers(&self) -> Result<()> {
        let now = self.now();
        let due = self
            .store
            .write_with(|tx| tx.due_transfers(self.account, now))?
            .0;
        for row in due {
            if let Err(e) = self.fetch_transfer(&row).await {
                tracing::info!(error = %e, "a transfer failed");
            }
        }
        Ok(())
    }

    async fn fetch_transfer(&self, row: &TransferRow) -> Result<()> {
        let first = TransferRef::from_bytes(&row.reference);
        let opened = match first {
            Ok(first) => self.open(&first).await,
            Err(e) => Err(archive_error(e)),
        };
        let opened = match opened {
            Ok(o) => o,
            Err(Error::Transfer(TransferError::Unreadable(why))) => {
                // Only a faulty or dishonest device makes such a transfer
                // (12.13): reject the whole of it, and tell the user.
                self.write(|tx| Ok(tx.set_transfer_state(row.id, "failed", 0, 0, Some(&why))?))?;
                self.emit(Event::Transfer(TransferEvent::TransferFailed {
                    account: self.account,
                    error: why,
                }));
                return Ok(());
            }
            Err(e) => {
                let delay = 60_000u64 << row.attempts.min(10);
                let attempts =
                    self.write(|tx| Ok(tx.retry_transfer(row.id, self.now() + delay)?))?;
                if attempts >= TRANSFER_ATTEMPTS {
                    let why = e.to_string();
                    self.write(|tx| {
                        Ok(tx.set_transfer_state(row.id, "failed", 0, 0, Some(&why))?)
                    })?;
                    self.emit(Event::Transfer(TransferEvent::TransferFailed {
                        account: self.account,
                        error: why,
                    }));
                }
                return Err(e);
            }
        };
        let source = match row.kind {
            TransferKind::Want => Source::Want {
                device: row.from_device,
                label: row.from_label.clone(),
            },
            TransferKind::Pairing => Source::Pairing {
                transfer: row.id,
                device: row.from_device,
                label: row.from_label.clone(),
            },
            TransferKind::Backup => Source::Backup {
                transfer: row.id,
                made: opened.made,
            },
        };
        let (account, now) = (self.account, self.now());
        let applied = self.write(|tx| {
            let applied = logic::apply(
                tx,
                account,
                &opened.conversations,
                &opened.files,
                &source,
                now,
            )?;
            let state = if applied.waiting > 0 {
                "waiting"
            } else {
                "done"
            };
            tx.set_transfer_state(row.id, state, opened.missing, opened.ignored, None)?;
            Ok(applied)
        })?;
        self.emit(Event::Transfer(TransferEvent::TransferApplied {
            account: self.account,
            messages: applied.messages,
            waiting: applied.waiting,
            missing: opened.missing,
            ignored: opened.ignored,
        }));
        Ok(())
    }

    /// Applies kept conversations of pairing transfers and backups whose
    /// groups the device has joined since, and closes WANT ranges that
    /// stayed open a day.
    pub(crate) fn apply_waiting(&self) -> Result<()> {
        let (account, now) = (self.account, self.now());
        let applied = self.write(|tx| {
            for (mailbox, range, asked) in tx.all_wants(account)? {
                if asked + logic::WANT_OPEN_MS <= now {
                    tx.remove_want(account, &mailbox, range.after)?;
                }
            }
            logic::apply_waiting(tx, account, now)
        })?;
        if applied > 0 {
            self.emit(Event::Transfer(TransferEvent::TransferApplied {
                account,
                messages: applied,
                waiting: 0,
                missing: 0,
                ignored: 0,
            }));
        }
        Ok(())
    }

    // ---- backups

    /// The identity's current generation and backup key, as the identity
    /// area (C1) keeps them: the generation in the identity's row, the key
    /// in the key store (12.13).
    fn backup_key(&self) -> Result<Option<BackupKey>> {
        let Some(own) = self.store.own_identity(self.uid.as_str())? else {
            return Ok(None);
        };
        let names = crate::keys::KeyNames::new(&own.key_id);
        let Some(seed) = self.keys.load_seed(&names.backup())? else {
            return Ok(None);
        };
        Ok(Some(BackupKey::from_bytes(own.backup_generation, *seed)))
    }

    /// The generation a recovered identity may restore (12.13, step 1):
    /// the one current just before this device's own recovery record, from
    /// the records this device has accepted, never from the server.
    fn restorable_generation(&self) -> Result<Option<u32>> {
        let identity = self.identity()?;
        let Some(own) = self.store.own_identity(identity.as_str())? else {
            return Ok(None);
        };
        let rows = self.store.records(identity.as_str())?;
        Ok(generation_before_recovery(&identity, &rows, &own.device_id))
    }

    /// Makes a backup now (12.13): archives of everything, with the files
    /// this device fetched, stored as blobs; the first one's key wrapped
    /// under the current backup key; the other blobs listed; BACKUP PUT.
    pub(crate) async fn backup_now(&self) -> Result<BackupRow> {
        let uid = self.identity()?;
        let key = self.backup_key()?.ok_or(TransferError::NotPossible(
            "this device holds no backup key".into(),
        ))?;
        let account = self.account;
        let collected = self
            .store
            .write_with(|tx| logic::collect(tx, account, &Selection::All, true))
            .map_err(engine)?
            .0;
        let files = self.store_files(collected.files).await?;
        let made = self.now();
        let upload = key
            .make_backup(&uid, made, collected.conversations, files, self.max_blob)
            .map_err(archive_error)?;
        for archive in &upload.archives {
            self.put_blob(archive).await?;
        }
        if let Some(list) = &upload.list {
            self.put_blob(list).await?;
        }
        let backup = upload.backup;
        self.command(
            Target::SignedIn,
            Command::Backup(BackupCommand::Put {
                generation: backup.generation,
                hash: proto_ref(&backup.hash),
                key: risala_proto::binary::WrappedKey::from_array(backup.key.as_bytes()),
                files: backup.files.as_ref().map(proto_ref),
            }),
        )
        .await?;
        let row = BackupRow {
            uid: uid.as_str().to_owned(),
            generation: backup.generation,
            blob_hash: *backup.hash.as_bytes(),
            made,
            restored: false,
        };
        let kept = row.clone();
        self.write(move |tx| Ok(tx.set_backup(&kept)?))?;
        self.emit(Event::Transfer(TransferEvent::BackupMade {
            account: self.account,
            generation: backup.generation,
        }));
        Ok(row)
    }

    /// Makes a backup if backups are on and the last is a day old, or the
    /// identity moved to a new generation since (4.8, 12.13).
    pub(crate) async fn backup_if_due(&self) -> Result<()> {
        if self.is_guest()
            || self.store.setting(&setting(self.uid.as_str()))?.as_deref() != Some("on")
        {
            return Ok(());
        }
        let Some(key) = self.backup_key()? else {
            return Ok(());
        };
        let last = self.store.backup_row(self.uid.as_str())?;
        let due = match &last {
            None => true,
            Some(l) => l.generation < key.generation() || l.made + BACKUP_EVERY_MS <= self.now(),
        };
        if due {
            self.backup_now().await?;
        }
        Ok(())
    }

    /// The identity moved to a new generation on this device (4.8): the
    /// device MUST replace the current backup at once with one under it,
    /// if the identity keeps one (12.13): backups are on here, or the
    /// server has one.
    pub(crate) async fn backup_for_new_generation(&self) -> Result<()> {
        let on = self.store.setting(&setting(self.uid.as_str()))?.as_deref() == Some("on");
        if on || self.backup_get().await?.is_some() {
            self.backup_now().await?;
        }
        Ok(())
    }

    /// The identity's backup on the server: BACKUP GET (12.13).
    pub(crate) async fn backup_get(&self) -> Result<Option<Backup>> {
        let response = self
            .commands
            .request(Target::SignedIn, Command::Backup(BackupCommand::Get))
            .await?;
        if let End::Err(e) = &response.end
            && e.code == ErrorCode::NotFound
        {
            return Ok(None);
        }
        ok(&response)?;
        for line in &response.lines {
            if let ServerLine::Backup {
                generation,
                hash,
                key,
                files,
            } = &line.line
            {
                // 12.13: a wrapped key whose version is not 1 is refused.
                let key = WrappedKey::from_bytes(key.as_bytes()).map_err(|e| match e {
                    BackupError::Version(_) | BackupError::Length => archive_error(e),
                    other => archive_error(other),
                })?;
                return Ok(Some(Backup {
                    generation: *generation,
                    hash: MlsBlobRef::from_bytes(*hash.hash()),
                    key,
                    files: files.map(|f| MlsBlobRef::from_bytes(*f.hash())),
                }));
            }
        }
        Ok(None)
    }

    /// Restores the backup after recovery, following 12.13's steps.
    pub(crate) async fn restore(&self, recovery_key: &str) -> Result<Restored> {
        // 1. The generation from the chain, not from the server.
        let generation = self
            .restorable_generation()?
            .ok_or(TransferError::NoBackup)?;
        self.restore_generation(recovery_key, generation).await
    }

    /// Steps 2 to 5 of restoring (12.13), for the generation step 1 gave.
    pub(crate) async fn restore_generation(
        &self,
        recovery_key: &str,
        generation: u32,
    ) -> Result<Restored> {
        let uid = self.identity()?;
        let recovery = RecoveryKey::parse(recovery_key)
            .map_err(|_| Error::invalid("recovery key", "(hidden)"))?;
        // 2. BACKUP GET, refusing any other generation.
        let backup = self.backup_get().await?.ok_or(TransferError::NoBackup)?;
        if backup.generation != generation {
            return Err(TransferError::NoBackup.into());
        }
        // 3. The generation's key, the wrapped key's version (checked when
        // it was read), the unwrap, and the archives.
        let key = recovery.backup_key(&uid, generation);
        let first_key = key
            .unwrap(&uid, &backup.hash, &backup.key)
            .map_err(|_| TransferError::Unreadable("the backup key does not unwrap it".into()))?;
        let first = TransferRef {
            blob: backup.hash,
            key: first_key,
        };
        let opened = self.open(&first).await?;
        // 4. When it was made, from the first archive.
        let made = opened.made;
        // 5. Shown as restored.
        let (account, now) = (self.account, self.now());
        let applied = self.write(|tx| {
            let transfer = tx
                .add_transfer(
                    account,
                    TransferKind::Backup,
                    backup.hash.as_bytes(),
                    None,
                    None,
                    now,
                )?
                .ok_or(EngineError::Invalid(
                    "this backup was restored already".into(),
                ))?;
            tx.set_transfer_made(transfer, made)?;
            let applied = logic::apply(
                tx,
                account,
                &opened.conversations,
                &opened.files,
                &Source::Backup { transfer, made },
                now,
            )?;
            let state = if applied.waiting > 0 {
                "waiting"
            } else {
                "done"
            };
            tx.set_transfer_state(transfer, state, opened.missing, opened.ignored, None)?;
            tx.set_backup(&BackupRow {
                uid: uid.as_str().to_owned(),
                generation,
                blob_hash: *backup.hash.as_bytes(),
                made,
                restored: true,
            })?;
            Ok(applied)
        })?;
        Ok(Restored {
            made: Timestamp::from_unix_millis(made).unwrap_or(Timestamp::MIN),
            messages: applied.messages,
            waiting: applied.waiting,
            missing: opened.missing + opened.ignored,
        })
    }

    /// Everything due, once. Errors are logged; the next run tries again.
    pub(crate) async fn run_due(&self) {
        if let Err(e) = self.remove_saved_files() {
            tracing::info!(error = %e, "removing saved files failed");
        }
        if self.is_guest() {
            return;
        }
        if let Err(e) = self.apply_waiting() {
            tracing::info!(error = %e, "applying kept history failed");
        }
        if let Err(e) = self.answer_wants().await {
            tracing::info!(error = %e, "answering a WANT failed");
        }
        if let Err(e) = self.fetch_transfers().await {
            tracing::info!(error = %e, "fetching a transfer failed");
        }
        if let Err(e) = self.delete_files().await {
            tracing::info!(error = %e, "deleting files failed");
        }
        if let Err(e) = self.backup_if_due().await {
            tracing::info!(error = %e, "making a backup failed");
        }
    }
}

/// The generation current just before this device's recovery record
/// (12.13, step 1; LR-M6), from accepted records only: `recover` makes a
/// `signing` record that removes every device, signed by this device, then
/// this device's `device` record. Records made later, such as a removal
/// or another recovery, do not move it. `None` if this device was not
/// added by a recovery, or its records are not accepted yet.
pub(crate) fn generation_before_recovery(
    uid: &risala_proto::names::Identity,
    rows: &[crate::store::identity::RecordRow],
    device: &[u8; 48],
) -> Option<u32> {
    use risala_proto::record::{Record, RecordBody};
    let mut accepted: Vec<&crate::store::identity::RecordRow> =
        rows.iter().filter(|r| r.accepted).collect();
    accepted.sort_by_key(|r| r.position);
    let own = accepted.iter().position(|r| {
        Record::decode(&r.record).is_ok_and(|rec| {
            matches!(&rec.content().body, RecordBody::Device(k) if k.device_id().as_bytes() == device)
        })
    })?;
    let recovery = own.checked_sub(1)?;
    let row = accepted[recovery];
    let is_signing = Record::decode(&row.record)
        .is_ok_and(|rec| matches!(rec.content().body, RecordBody::Signing { .. }));
    if !row.mine || !is_signing {
        return None;
    }
    let before: Vec<crate::store::identity::RecordRow> =
        accepted[..recovery].iter().map(|r| (*r).clone()).collect();
    crate::sync::identity::kept_chain(uid, &before, true).map(|chain| chain.generation())
}

/// The account's worker: does the area's work when the cache changes, and
/// every 30 seconds, until the account disconnects.
pub(crate) async fn worker(jobs: Jobs, mut events: broadcast::Receiver<Event>) {
    let mut new_generation = false;
    // Task C5: the first run waits for the account's connections, so that
    // what needs one does not fail and wait out its back-off.
    wait_connected(&jobs, &mut events, Duration::from_secs(10)).await;
    loop {
        if std::mem::take(&mut new_generation)
            && let Err(e) = jobs.backup_for_new_generation().await
        {
            tracing::info!(error = %e, "the new generation's backup failed; will retry");
        }
        jobs.run_due().await;
        let wait = tokio::time::sleep(WORKER_PERIOD);
        tokio::pin!(wait);
        loop {
            tokio::select! {
                () = &mut wait => break,
                event = events.recv() => match event {
                    Ok(Event::Changed(change)) if wakes_worker(&change) => break,
                    // Task C5: a connection came up, so what failed for
                    // want of one runs now rather than in 30 seconds.
                    Ok(Event::Connection(e))
                        if e.account == jobs.account
                            && e.state == crate::client::ConnectionState::Ready =>
                    {
                        break;
                    }
                    // 4.8, 12.13: C1 tells this device's account that it
                    // moved the identity to a new generation.
                    Ok(Event::Identity(IdentityEvent::NewGeneration { uid, .. }))
                        if uid == jobs.uid =>
                    {
                        new_generation = true;
                        break;
                    }
                    Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => return,
                },
            }
        }
        // Let a burst of changes settle.
        tokio::time::sleep(Duration::from_millis(200)).await;
        while events.try_recv().is_ok() {}
    }
}

/// Waits until the account's signed-in and anonymous connections (or its
/// guest connection) are up, for at most `max`.
async fn wait_connected(jobs: &Jobs, events: &mut broadcast::Receiver<Event>, max: Duration) {
    use crate::conn::Slot;
    let (mut signed_in, mut anonymous) = (false, false);
    let deadline = tokio::time::Instant::now() + max;
    while !(signed_in && anonymous) {
        match tokio::time::timeout_at(deadline, events.recv()).await {
            Ok(Ok(Event::Connection(e)))
                if e.account == jobs.account
                    && e.state == crate::client::ConnectionState::Ready =>
            {
                match e.slot {
                    Slot::SignedIn => signed_in = true,
                    Slot::Anonymous(_) => anonymous = true,
                    Slot::Guest => (signed_in, anonymous) = (true, true),
                    _ => {}
                }
            }
            Ok(Ok(_)) | Ok(Err(broadcast::error::RecvError::Lagged(_))) => {}
            Ok(Err(broadcast::error::RecvError::Closed)) | Err(_) => return,
        }
    }
}

impl Client {
    /// Starts the area's worker for a running account (called by the
    /// driver when the account connects).
    pub(crate) fn spawn_transfer_worker(
        &self,
        account: AccountId,
        commands: Arc<dyn Commands>,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let jobs = self.jobs_with(account, commands).ok()?;
        Some(tokio::spawn(worker(jobs, self.subscribe())))
    }

    /// Turns backups of the account's identity on or off on this device
    /// (12.13). Once on, a backup is made at most daily, and at once when
    /// the identity moves to a new generation.
    pub fn set_backups(&self, account: AccountId, on: bool) -> Result<()> {
        let a = self.account(account)?;
        self.store()
            .set_setting(&setting(a.uid.as_str()), on.then_some("on"))?;
        Ok(())
    }

    /// Whether backups are on for the account's identity on this device.
    pub fn backups_on(&self, account: AccountId) -> Result<bool> {
        let a = self.account(account)?;
        Ok(self.store().setting(&setting(a.uid.as_str()))?.as_deref() == Some("on"))
    }

    /// Makes a backup of this device's history now, for the account's
    /// identity on its server (12.13), and turns backups on.
    pub async fn backup_now(&self, account: AccountId) -> Result<BackupInfo> {
        let jobs = self.jobs(account)?;
        self.set_backups(account, true)?;
        let row = jobs.backup_now().await?;
        Ok(BackupInfo {
            generation: row.generation,
            made: Timestamp::from_unix_millis(row.made),
        })
    }

    /// The account's backup on its server, if there is one.
    pub async fn backup(&self, account: AccountId) -> Result<Option<BackupInfo>> {
        let jobs = self.jobs(account)?;
        let Some(backup) = jobs.backup_get().await? else {
            return Ok(None);
        };
        let a = self.account(account)?;
        let made = self
            .store()
            .backup_row(a.uid.as_str())?
            .filter(|r| r.blob_hash == *backup.hash.as_bytes())
            .and_then(|r| Timestamp::from_unix_millis(r.made));
        Ok(Some(BackupInfo {
            generation: backup.generation,
            made,
        }))
    }

    /// Restores history from the account's backup with the recovery key,
    /// after recovering the identity (4.8, 12.13). Conversations the
    /// device is not in yet are kept until it is added to them again.
    /// Then a new backup is made in the new generation.
    pub async fn restore_backup(&self, account: AccountId, recovery_key: &str) -> Result<Restored> {
        let jobs = self.jobs(account)?;
        let restored = jobs.restore(recovery_key).await?;
        self.set_backups(account, true)?;
        if let Err(e) = jobs.backup_now().await {
            tracing::info!(error = %e, "the new generation's backup failed; will retry");
        }
        Ok(restored)
    }

    /// Deletes the account's backup (12.13), and turns backups off.
    pub async fn delete_backup(&self, account: AccountId) -> Result<()> {
        let jobs = self.jobs(account)?;
        jobs.command(Target::SignedIn, Command::Backup(BackupCommand::Del))
            .await?;
        self.set_backups(account, false)?;
        let a = self.account(account)?;
        let (_, changes) = self.store().write(|tx| tx.remove_backup(a.uid.as_str()))?;
        for c in changes {
            self.emit(Event::Changed(c));
        }
        Ok(())
    }

    /// Builds the history transfer for a device being paired (4.8, 12.13):
    /// archives of every conversation, with the files this device fetched,
    /// stored as blobs. Gives the encoded TransferRef for the
    /// IdentityBundle's `transfer`, or `None` if there is no history.
    pub async fn pairing_transfer(&self, account: AccountId) -> Result<Option<Vec<u8>>> {
        let jobs = self.jobs(account)?;
        Ok(jobs
            .store_transfer(Selection::All, true)
            .await?
            .map(|s| s.first.to_bytes().to_vec()))
    }

    /// The history transfer for a device being paired (4.8, 12.13), built
    /// on the connected account of `uid` on its home server, where the
    /// blobs are stored. `None` if there is none to send, or the account
    /// is not connected: the pairing goes on without history.
    pub(crate) async fn transfer_for_pairing(
        &self,
        uid: &Identity,
        home: &str,
    ) -> Option<TransferRef> {
        let account = self
            .accounts()
            .ok()?
            .into_iter()
            .find(|a| a.uid.as_str() == uid.as_str() && a.server.to_string() == home)?;
        let jobs = self.jobs(account.id).ok()?;
        match jobs.store_transfer(Selection::All, true).await {
            Ok(stored) => stored.map(|s| s.first),
            Err(e) => {
                tracing::info!(error = %e, "no history transfer for the new device");
                None
            }
        }
    }

    /// Keeps the IdentityBundle's transfer on the new device, on its
    /// account on the home server (4.8, step 5): fetched once it connects,
    /// and applied as the device is added to conversations. The bundle
    /// does not name the device that sent it, so its messages show as
    /// copied from another device of the identity.
    pub(crate) fn keep_pairing_transfer(
        &self,
        uid: &Identity,
        home: &crate::addr::ServerAddr,
        transfer: &TransferRef,
    ) -> Result<()> {
        let Some(account) = self
            .accounts()?
            .into_iter()
            .find(|a| a.uid.as_str() == uid.as_str() && a.server == *home)
        else {
            return Ok(());
        };
        self.receive_pairing_transfer(account.id, &transfer.to_bytes()[..], None, None)
    }

    /// Keeps the IdentityBundle's transfer on the new device (4.8, step
    /// 5), to fetch once the account is connected. Its conversations are
    /// applied as the device is added to them, and shown as copied from
    /// `from_label`.
    pub fn receive_pairing_transfer(
        &self,
        account: AccountId,
        transfer: &[u8],
        from_device: Option<DeviceId>,
        from_label: Option<&str>,
    ) -> Result<()> {
        // 12.13, 2.4: a TransferRef whose version is not 1 is refused.
        TransferRef::from_bytes(transfer).map_err(|e: ArchiveError| archive_error(e))?;
        let now = self.options().clock.now().unix_millis();
        let (_, changes) = self.store().write(|tx: &mut Tx<'_>| {
            tx.add_transfer(
                account,
                TransferKind::Pairing,
                transfer,
                from_device.as_ref().map(|d| &d.0),
                from_label,
                now,
            )
            .map(|_| ())
        })?;
        for c in changes {
            self.emit(Event::Changed(c));
        }
        Ok(())
    }

    /// Where a message came from (12.13): the server, another device of
    /// the identity, or a backup.
    pub fn message_origin(
        &self,
        conversation: ConversationId,
        message: MessageId,
    ) -> Result<MessageOrigin> {
        let meta = self.store().read(|conn| {
            use rusqlite::OptionalExtension as _;
            Ok(conn
                .query_row(
                    "SELECT vouched FROM message_meta WHERE conv = ?1 AND message_id = ?2",
                    rusqlite::params![conversation.get(), &message.0[..]],
                    |r| r.get::<_, bool>(0),
                )
                .optional()?)
        })?;
        let vouched = meta.unwrap_or(false);
        Ok(
            match self.store().message_origin(conversation, &message.0)? {
                Origin::Server => MessageOrigin::Received,
                Origin::Copied { label, .. } => MessageOrigin::Copied {
                    device: label,
                    vouched,
                },
                Origin::Restored { made } => MessageOrigin::Restored {
                    made: Timestamp::from_unix_millis(made).unwrap_or(Timestamp::MIN),
                    vouched,
                },
            },
        )
    }
}

impl From<StoreError> for TransferError {
    fn from(e: StoreError) -> TransferError {
        TransferError::NotPossible(e.to_string())
    }
}
