//! The device's own identities (4.6-4.9): creating one, signing in,
//! publishing records with KEYS PUT, removing a device, recovery,
//! unregistering, and the daily work of watching them (4.5).

use std::sync::Arc;

use risala_proto::auth::SecretKey;
use risala_proto::binary::EncodedRecords;
use risala_proto::chain::Chain;
use risala_proto::command::{Command, KeysPutRecords};
use risala_proto::content::{ContentLine, SigningSeed};
use risala_proto::names::{BlobRef, Identity, Name};
use risala_proto::record::{
    DeviceId as ProtoDeviceId, DeviceKeys, LogKey, Record, RecordBody, RecordContent,
    encode_records,
};
use risala_proto::recovery::RecoveryKey;
use risala_proto::server::{Register, ServerLine};
use zeroize::Zeroizing;

use super::verify::{Applied, DAY_MS};
use super::{IdentityError, IdentityEvent, NewIdentity, OwnIdentity, parse_identity, rnd, to_uid};
use crate::addr::ServerAddr;
use crate::client::servers::server_addr;
use crate::client::types::{AccountId, DeviceId};
use crate::client::{Client, Error, Result};
use crate::conn::{BoxFuture, ConnectionKind, Establish, Session, SingleUse, single_use};
use crate::keys::{KeyNames, attestation_public_key, random_seed};
use crate::store::AccountKind;
use crate::store::identity::{ContactRow, OwnRow, RecordRow};
use crate::sync::identity::{backup_key_line, kept_chain, queue_line};

/// The time for a new record after `head`: now, or just after the head if
/// the clock is behind it, since times increase along a chain (4.4).
pub(crate) fn record_time(now: u64, head: Option<&Record>) -> u64 {
    head.map_or(now, |h| now.max(h.content().time + 1))
}

/// The backup key of `generation` from a recovery key (12.13).
pub(crate) fn backup_key(recovery: &RecoveryKey, uid: &Identity, generation: u32) -> [u8; 32] {
    let key = risala_mls::RecoveryKey::from_bytes(*recovery.as_bytes()).backup_key(uid, generation);
    *key.as_bytes()
}

fn rng_error(e: getrandom::Error) -> Error {
    Error::Internal(format!("random: {e}"))
}

fn invalid_record(e: impl std::fmt::Display) -> Error {
    IdentityError::InvalidRecord(e.to_string()).into()
}

/// The `log` column of a record the device makes: the chain's log for it.
fn log_of(chain: &Chain) -> (String, String) {
    let log = chain.log();
    (log.origin().to_owned(), log.vkey())
}

/// Signs in as an identity with the device key of one of its current
/// devices (4.6), with hedged signatures (PLAN.md 58). `auth-failed` is
/// final; `unavailable` is tried again, as for
/// [`IdentitySignIn`](crate::conn::IdentitySignIn).
#[derive(Debug, Clone)]
pub(crate) struct HedgedSignIn {
    identity: Identity,
    key: SecretKey,
}

fn hedge() -> std::result::Result<[u8; 32], crate::conn::Error> {
    let mut r = [0u8; 32];
    getrandom::fill(&mut r).map_err(|e| crate::conn::Error::Io(std::io::Error::other(e)))?;
    Ok(r)
}

impl Establish for HedgedSignIn {
    fn kind(&self) -> ConnectionKind {
        ConnectionKind::SignedIn
    }

    fn establish<'a>(
        &'a self,
        session: &'a Session,
    ) -> BoxFuture<'a, std::result::Result<(), crate::conn::Error>> {
        Box::pin(async move {
            session
                .auth_hedged(&self.identity, &self.key, hedge()?)
                .await?;
            Ok(())
        })
    }
}

impl Client {
    /// Creates the identity `<name>@<the server's identity domain>` (4.7,
    /// 4.8): a recovery key, the master key derived from it, a
    /// device-signing key and this device's keys, its first two records
    /// (a `master` record naming the server's log, and a `device` record),
    /// and REGISTER, which signs in. Returns the recovery key to show the
    /// user once; the device keeps only the backup key derived from it.
    pub async fn create_identity(
        &self,
        server: &str,
        name: &str,
        device_label: &str,
    ) -> Result<NewIdentity> {
        let addr = server_addr(server)?;
        let name: Name = name.parse().map_err(|_| Error::invalid("name", name))?;
        if device_label.len() > risala_proto::record::MAX_DEVICE_LABEL {
            return Err(Error::invalid("device label", device_label));
        }
        let session = Session::connect(&addr, self.trust(), self.session_options()).await?;
        let result = self.register_on(&session, &addr, &name, device_label).await;
        session.close();
        result
    }

    async fn register_on(
        &self,
        session: &Session,
        addr: &ServerAddr,
        name: &Name,
        label: &str,
    ) -> Result<NewIdentity> {
        let info = session.request_ok(Command::Info { room: None }).await?;
        let Ok(Some(Register::Domain(domain))) = info.register() else {
            return Err(IdentityError::NoRegistration.into());
        };
        // The log's URL is always `https://` and its origin (4.4, 4.5):
        // `log=` must name the same log as `log-key=`.
        let (Ok(Some(info_log)), Ok(Some(log))) = (info.log(), info.log_key()) else {
            return Err(IdentityError::NoRegistration.into());
        };
        if info_log.origin() != Some(log.origin()) {
            return Err(IdentityError::NoRegistration.into());
        }
        let uid = Identity::new(name, &domain);
        if self.store().own_identity(uid.as_str())?.is_some() {
            return Err(Error::invalid(
                "identity, already on this device",
                uid.as_str(),
            ));
        }

        // 4.8, step 1 and 2.
        let recovery = RecoveryKey::from_bytes(*random_seed().map_err(rng_error)?);
        let master = recovery.master_key(&uid);
        let signing_seed = random_seed().map_err(rng_error)?;
        let device_seed = random_seed().map_err(rng_error)?;
        let attest_seed = random_seed().map_err(rng_error)?;
        let signing = SecretKey::from_seed(*signing_seed);
        let device = SecretKey::from_seed(*device_seed);
        let keys = DeviceKeys {
            device_key: device.public_key(),
            attestation_key: attestation_public_key(&attest_seed),
            label: label.to_owned(),
        };

        // Step 3: a master record naming the log, then a device record.
        let now = self.now_ms();
        let first = Record::sign(
            RecordContent {
                uid: uid.clone(),
                previous: None,
                time: now,
                body: RecordBody::Master {
                    master_key: master.public_key(),
                    signing_key: signing.public_key(),
                    log: log.clone(),
                },
            },
            &master,
            rnd()?,
        )
        .map_err(invalid_record)?;
        let second = Record::sign(
            RecordContent {
                uid: uid.clone(),
                previous: Some(first.hash()),
                time: now + 1,
                body: RecordBody::Device(keys.clone()),
            },
            &signing,
            rnd()?,
        )
        .map_err(invalid_record)?;
        let chain =
            Chain::replay(&uid, &[first.clone(), second.clone()]).map_err(invalid_record)?;
        drop(master);

        // Keep the keys and records before REGISTER: after a lost answer
        // the device signs in with the same key, and registers again only
        // with the same records (4.7).
        let names = KeyNames::new(uid.as_str());
        let store_keys = self.options().keys.clone();
        store_keys.save_seed(&names.device(), &device_seed)?;
        store_keys.save_seed(&names.attestation(), &attest_seed)?;
        store_keys.save_seed(&names.signing(), &signing_seed)?;
        store_keys.save_seed(&names.backup(), &backup_key(&recovery, &uid, 0))?;
        let log_col = (log.origin().to_owned(), log.vkey());
        let rows: Vec<RecordRow> = [&first, &second]
            .iter()
            .enumerate()
            .map(|(i, r)| RecordRow {
                hash: r.hash(),
                position: i as u64,
                record: r.encoded().to_vec(),
                log: log_col.clone(),
                log_index: None,
                accepted: false,
                mine: true,
                witnessed: None,
            })
            .collect();
        let own = OwnRow {
            uid: uid.as_str().to_owned(),
            device_id: *keys.device_id().as_bytes(),
            key_id: names.base().to_owned(),
            home: addr.to_string(),
            backup_generation: 0,
            created: now,
            told_full: false,
        };
        let (_, changes) = self.store().write(|tx| {
            tx.add_own(&own)?;
            tx.put_records(uid.as_str(), 0, &rows)?;
            let mut contact = ContactRow::new(uid.as_str());
            // The device made the chain: it pins its own master key and
            // log at once (4.5).
            contact.master_key = Some(chain.master_key().as_bytes().to_vec());
            contact.log_origin = Some(log.origin().to_owned());
            tx.put_contact(&contact)?;
            for r in &rows {
                tx.add_announced(uid.as_str(), &r.hash)?;
            }
            Ok(())
        })?;
        self.emit_changes(changes);

        // Step 4.
        let records = EncodedRecords::from_bytes(&encode_records(&[first, second]))
            .map_err(|e| Error::Internal(format!("records: {e}")))?;
        match session
            .register_hedged(name, &domain, records, &device, rnd()?)
            .await
        {
            Ok(_) => {}
            Err(crate::conn::Error::Rejected(e)) => {
                // Refused: nothing was created. Forget it all.
                self.forget_own(&uid)?;
                return Err(crate::conn::Error::Rejected(e).into());
            }
            Err(crate::conn::Error::NoRegistration) => {
                self.forget_own(&uid)?;
                return Err(IdentityError::NoRegistration.into());
            }
            // The answer was lost: the identity may exist. The device
            // keeps everything and tries AUTH later (4.7).
            Err(e) => return Err(e.into()),
        }
        let account = self
            .store()
            .add_account(addr, AccountKind::Identity, &uid.to_uid())?;
        // Step 5: the recovery key is shown once, then forgotten.
        Ok(NewIdentity {
            uid: uid.to_uid(),
            account,
            recovery_key: recovery.to_text(),
        })
    }

    /// Forgets an identity this device was making, keys and all.
    fn forget_own(&self, uid: &Identity) -> Result<()> {
        for id in KeyNames::new(uid.as_str()).all() {
            self.options().keys.delete(&id)?;
        }
        let (_, changes) = self.store().write(|tx| {
            for table in ["identities", "records", "contacts", "devices", "announced"] {
                tx.conn().execute(
                    &format!("DELETE FROM {table} WHERE uid = ?1"),
                    [uid.as_str()],
                )?;
            }
            Ok(())
        })?;
        self.emit_changes(changes);
        Ok(())
    }

    /// The identity this device holds, or [`IdentityError::NotHeld`].
    pub(crate) fn own_row(&self, uid: &Identity) -> Result<OwnRow> {
        self.store()
            .own_identity(uid.as_str())?
            .ok_or_else(|| IdentityError::NotHeld(to_uid(uid)).into())
    }

    /// The device key of an identity this device holds.
    pub(crate) fn device_key(&self, own: &OwnRow) -> Result<SecretKey> {
        let seed = self
            .options()
            .keys
            .load_seed(&KeyNames::new(&own.key_id).device())?
            .ok_or(IdentityError::MissingKey("device key"))?;
        Ok(SecretKey::from_seed(*seed))
    }

    /// How the account's signed-in connection signs in: AUTH with this
    /// device's key for the identity (4.6), for the driver. The signature
    /// is hedged (4.6, PLAN.md 58).
    pub(crate) async fn identity_sign_in(&self, account: AccountId) -> Result<Arc<dyn Establish>> {
        let a = self.account(account)?;
        if a.kind != AccountKind::Identity {
            return Err(Error::NoAccount);
        }
        let uid = parse_identity(a.uid.as_str())?;
        let own = self.own_row(&uid)?;
        let key = self.blocking(move |c| c.device_key(&own)).await?;
        Ok(Arc::new(HedgedSignIn { identity: uid, key }))
    }

    /// The chain of an identity this device holds, with its records not
    /// yet logged.
    pub(crate) fn own_chain(&self, uid: &Identity) -> Result<(Chain, Vec<RecordRow>)> {
        let rows = self.store().records(uid.as_str())?;
        let chain =
            kept_chain(uid, &rows, false).ok_or_else(|| IdentityError::NotAccepted(to_uid(uid)))?;
        Ok((chain, rows))
    }

    /// Keeps a record this device signed, exactly as encoded, and queues
    /// its RECORD line (4.5, 4.7).
    pub(crate) fn keep_own_record(
        &self,
        uid: &Identity,
        chain: &Chain,
        rows: &[RecordRow],
        record: &Record,
    ) -> Result<()> {
        let row = RecordRow {
            hash: record.hash(),
            position: rows.len() as u64,
            record: record.encoded().to_vec(),
            log: log_of(chain),
            log_index: None,
            accepted: false,
            mine: true,
            witnessed: None,
        };
        let now = self.now_ms();
        let (_, changes) = self.store().write(|tx| {
            tx.put_records(uid.as_str(), row.position, std::slice::from_ref(&row))?;
            tx.add_announced(uid.as_str(), &row.hash)?;
            queue_line(tx, uid.as_str(), &ContentLine::Record(row.hash), now)?;
            Ok(())
        })?;
        self.emit_changes(changes);
        Ok(())
    }

    /// Sends the records of an identity this device holds that its log
    /// does not hold yet, with KEYS PUT on a connection of its own (4.1,
    /// 4.7), to `server`, or its home server. Keeps the indices of the
    /// RECORD lines that answer.
    pub(crate) async fn publish_own(
        &self,
        uid: &Identity,
        server: Option<&ServerAddr>,
    ) -> Result<()> {
        let own = self.own_row(uid)?;
        let rows = self.store().records(uid.as_str())?;
        let Some(first) = rows.iter().position(|r| r.mine && r.log_index.is_none()) else {
            return Ok(());
        };
        let records: Vec<Record> = rows[first..]
            .iter()
            .map(|r| Record::decode(&r.record).map_err(invalid_record))
            .collect::<Result<_>>()?;
        let after = first.checked_sub(1).map(|i| rows[i].hash);
        let addr = match server {
            Some(addr) => addr.clone(),
            None => own
                .home
                .parse()
                .map_err(|_| Error::invalid("server address", own.home.clone()))?,
        };
        let records_arg = EncodedRecords::from_bytes(&encode_records(&records))
            .map_err(|e| Error::Internal(format!("records: {e}")))?;
        let response = single_use(
            &addr,
            self.trust(),
            self.session_options(),
            SingleUse::New,
            Command::KeysPut {
                after,
                records: KeysPutRecords::Inline(records_arg),
            },
        )
        .await?;
        let (lines, _) = response
            .into_result()
            .map_err(|e| Error::Connection(e.into()))?;
        let indices: Vec<(BlobRef, u64)> = lines
            .iter()
            .filter_map(|m| match &m.line {
                ServerLine::Record { index, hash } => Some((*hash, *index)),
                _ => None,
            })
            .collect();
        if indices.is_empty() {
            return Ok(());
        }
        let (_, changes) = self.store().write(|tx| {
            let mut rows = tx.records(uid.as_str())?;
            for row in &mut rows {
                if let Some((_, index)) = indices.iter().find(|(h, _)| *h == row.hash) {
                    row.log_index = Some(*index);
                }
            }
            tx.put_records(uid.as_str(), 0, &rows)
        })?;
        self.emit_changes(changes);
        Ok(())
    }

    /// The chain of an identity, fetched and checked now, with its
    /// records kept; fails unless at least its first records are
    /// accepted.
    async fn checked_chain(&self, uid: &Identity) -> Result<(Chain, Vec<RecordRow>)> {
        self.refresh_uid(uid).await?;
        let rows = self.store().records(uid.as_str())?;
        if !rows.iter().any(|r| r.accepted) {
            return Err(IdentityError::NotAccepted(to_uid(uid)).into());
        }
        let chain =
            kept_chain(uid, &rows, false).ok_or_else(|| IdentityError::NotAccepted(to_uid(uid)))?;
        Ok((chain, rows))
    }

    /// Removes a device of `uid`, which needs the recovery key (4.8): a
    /// `signing` record with a new device-signing key that removes it,
    /// published with KEYS PUT. The new device-signing key and the next
    /// generation's backup key go to the identity's other devices as
    /// SIGNINGKEY and BACKUPKEY lines, and
    /// [`IdentityEvent::NewGeneration`] asks for a new backup at once
    /// (12.13). The conversations area removes the device's leaves once
    /// its device shows as removed, which is once the record is accepted.
    pub async fn remove_device(
        &self,
        uid: &str,
        device: DeviceId,
        recovery_key: &str,
    ) -> Result<()> {
        let identity = parse_identity(uid)?;
        let own = self.own_row(&identity)?;
        let recovery =
            RecoveryKey::parse(recovery_key).map_err(|_| IdentityError::BadRecoveryKey)?;
        let (chain, rows) = self.checked_chain(&identity).await?;
        // Step 1: the master key, checked (4.8).
        let master = recovery
            .master_key_for(&chain)
            .ok_or(IdentityError::WrongRecoveryKey)?;
        let id = ProtoDeviceId::from_bytes(device.0);
        if !chain.devices().contains_key(&id) {
            return Err(IdentityError::NoSuchDevice.into());
        }
        let signing_seed = random_seed().map_err(rng_error)?;
        let signing = SecretKey::from_seed(*signing_seed);
        let record = Record::sign(
            RecordContent {
                uid: identity.clone(),
                previous: Some(chain.head_hash()),
                time: record_time(self.now_ms(), Some(chain.head())),
                body: RecordBody::Signing {
                    signing_key: signing.public_key(),
                    removed: vec![id],
                },
            },
            &master,
            rnd()?,
        )
        .map_err(invalid_record)?;
        drop(master);
        let mut next = chain.clone();
        next.push(&record, None, &|_: &LogKey, _: &LogKey| false)
            .map_err(invalid_record)?;
        self.keep_own_record(&identity, &chain, &rows, &record)?;
        let generation = next.generation();
        let backup = backup_key(&recovery, &identity, generation);
        drop(recovery);
        self.take_generation(&identity, &own, &signing_seed, generation, &backup)?;
        if let Err(e) = self.publish_own(&identity, None).await {
            // Kept, and sent again by the daily work (4.7).
            tracing::info!(%identity, error = %e, "KEYS PUT failed; will retry");
        }
        self.emit_identity(IdentityEvent::NewGeneration {
            uid: to_uid(&identity),
            generation,
        });
        Ok(())
    }

    /// Takes a new device-signing key and generation on this device, and
    /// queues them for the identity's other devices (4.8, step 3).
    fn take_generation(
        &self,
        uid: &Identity,
        own: &OwnRow,
        signing_seed: &[u8; 32],
        generation: u32,
        backup: &[u8; 32],
    ) -> Result<()> {
        let names = KeyNames::new(&own.key_id);
        self.options()
            .keys
            .save_seed(&names.signing(), signing_seed)?;
        self.options().keys.save_seed(&names.backup(), backup)?;
        let now = self.now_ms();
        let (_, changes) = self.store().write(|tx| {
            tx.set_backup_generation(uid.as_str(), generation)?;
            queue_line(
                tx,
                uid.as_str(),
                &ContentLine::SigningKey(SigningSeed::from_bytes(*signing_seed)),
                now,
            )?;
            queue_line(tx, uid.as_str(), &backup_key_line(generation, backup), now)?;
            Ok(())
        })?;
        self.emit_changes(changes);
        Ok(())
    }

    /// Recovers `uid` on this device from its recovery key, after losing
    /// every device (4.8): a `signing` record that removes every current
    /// device and names a new device-signing key, then a `device` record
    /// for this device, sent with KEYS PUT to `server`, which needs no
    /// sign-in. The chain moves to the next generation (12.13); the backup
    /// of the generation before is restored by the backups area.
    pub async fn recover(
        &self,
        server: &str,
        uid: &str,
        recovery_key: &str,
        device_label: &str,
    ) -> Result<OwnIdentity> {
        let addr = server_addr(server)?;
        let identity = parse_identity(uid)?;
        if self.store().own_identity(identity.as_str())?.is_some() {
            return Err(Error::invalid("identity, already on this device", uid));
        }
        let recovery =
            RecoveryKey::parse(recovery_key).map_err(|_| IdentityError::BadRecoveryKey)?;
        let (chain, rows) = self.checked_chain(&identity).await?;
        let master = recovery
            .master_key_for(&chain)
            .ok_or(IdentityError::WrongRecoveryKey)?;
        let removed: Vec<ProtoDeviceId> = chain.devices().keys().copied().collect();
        if removed.is_empty() || chain.is_retired() {
            // A signing record must remove a device (4.4); an identity
            // with none current cannot be recovered this way.
            return Err(IdentityError::InvalidRecord("no current device to remove".into()).into());
        }
        let signing_seed = random_seed().map_err(rng_error)?;
        let device_seed = random_seed().map_err(rng_error)?;
        let attest_seed = random_seed().map_err(rng_error)?;
        let signing = SecretKey::from_seed(*signing_seed);
        let device = SecretKey::from_seed(*device_seed);
        let now = self.now_ms();
        let first = Record::sign(
            RecordContent {
                uid: identity.clone(),
                previous: Some(chain.head_hash()),
                time: record_time(now, Some(chain.head())),
                body: RecordBody::Signing {
                    signing_key: signing.public_key(),
                    removed,
                },
            },
            &master,
            rnd()?,
        )
        .map_err(invalid_record)?;
        drop(master);
        let keys = DeviceKeys {
            device_key: device.public_key(),
            attestation_key: attestation_public_key(&attest_seed),
            label: device_label.to_owned(),
        };
        let second = Record::sign(
            RecordContent {
                uid: identity.clone(),
                previous: Some(first.hash()),
                time: first.content().time + 1,
                body: RecordBody::Device(keys.clone()),
            },
            &signing,
            rnd()?,
        )
        .map_err(invalid_record)?;
        let mut next = chain.clone();
        for r in [&first, &second] {
            next.push(r, None, &|_: &LogKey, _: &LogKey| false)
                .map_err(invalid_record)?;
        }
        let generation = next.generation();
        let backup = backup_key(&recovery, &identity, generation);
        drop(recovery);

        let names = KeyNames::new(identity.as_str());
        let keys_store = self.options().keys.clone();
        keys_store.save_seed(&names.device(), &device_seed)?;
        keys_store.save_seed(&names.attestation(), &attest_seed)?;
        keys_store.save_seed(&names.signing(), &signing_seed)?;
        keys_store.save_seed(&names.backup(), &backup)?;
        let own = OwnRow {
            uid: identity.as_str().to_owned(),
            device_id: *keys.device_id().as_bytes(),
            key_id: names.base().to_owned(),
            home: addr.to_string(),
            backup_generation: generation,
            created: now,
            told_full: false,
        };
        let (_, changes) = self.store().write(|tx| tx.add_own(&own))?;
        self.emit_changes(changes);
        self.keep_own_record(&identity, &chain, &rows, &first)?;
        let mut with_first = chain.clone();
        with_first
            .push(&first, None, &|_: &LogKey, _: &LogKey| false)
            .map_err(invalid_record)?;
        let rows = self.store().records(identity.as_str())?;
        self.keep_own_record(&identity, &with_first, &rows, &second)?;
        self.publish_own(&identity, Some(&addr)).await?;
        self.store()
            .add_account(&addr, AccountKind::Identity, &identity.to_uid())?;
        self.emit_identity(IdentityEvent::NewGeneration {
            uid: to_uid(&identity),
            generation,
        });
        Ok(OwnIdentity {
            uid: to_uid(&identity),
            device: DeviceId(*keys.device_id().as_bytes()),
        })
    }

    /// The generation whose backup a recovered identity may restore: the
    /// one current just before its newest `signing` record, from the
    /// chain the device has accepted, never from the server (12.13).
    pub fn restorable_backup_generation(&self, uid: &str) -> Result<Option<u32>> {
        let identity = parse_identity(uid)?;
        let rows = self.store().records(identity.as_str())?;
        let Some(chain) = kept_chain(&identity, &rows, false) else {
            return Ok(None);
        };
        Ok(chain.generation().checked_sub(1))
    }

    /// Deletes everything the server keeps about the account's identity
    /// (4.9): UNREGISTER on a connection signed in for it. It does not
    /// end the identity for others, which only a `retire` record does.
    pub async fn unregister(&self, account: AccountId) -> Result<()> {
        let a = self.account(account)?;
        let uid = parse_identity(a.uid.as_str())?;
        let own = self.own_row(&uid)?;
        let key = self.device_key(&own)?;
        let session = Session::connect(&a.server, self.trust(), self.session_options()).await?;
        let result = async {
            session.auth_hedged(&uid, &key, hedge()?).await?;
            session
                .request_ok(Command::Unregister { uid: uid.to_uid() })
                .await?;
            Ok::<_, crate::conn::Error>(())
        }
        .await;
        session.close();
        Ok(result?)
    }

    /// The identity area's daily work, for the driver to run every few
    /// minutes; it does each part only when it is due:
    ///
    /// - sends the records of the device's own identities that their log
    ///   does not hold yet (4.7);
    /// - watches each own identity's records at least daily (4.5): fetches
    ///   the key file and the log's newest checkpoint and the uid's hint,
    ///   and alerts for records no device announced within 24 hours of
    ///   being witnessed, and for forks;
    /// - fetches again the key file of every identity due (12.14), at
    ///   random times through the day;
    /// - forgets pairings older than 10 minutes (4.8).
    pub async fn identity_maintenance(&self) -> Result<()> {
        let now = self.now_ms();
        for own in self.store().own_identities()? {
            let Ok(uid) = own.uid.parse::<Identity>() else {
                continue;
            };
            if let Err(e) = self.publish_own(&uid, None).await {
                tracing::debug!(%uid, error = %e, "KEYS PUT failed; will retry");
            }
            self.watch_own(&uid).await?;
        }
        for contact in self.store().contacts()? {
            if self.store().own_identity(&contact.uid)?.is_some() {
                continue;
            }
            if contact.next_check.is_some_and(|t| t <= now)
                && let Ok(uid) = contact.uid.parse::<Identity>()
            {
                self.refresh_uid(&uid).await?;
            }
        }
        self.expire_pairings()?;
        Ok(())
    }

    /// Watches an own identity's records (4.5, "Watching your own
    /// records"): fetches its key file, checkpoint and hint when they are
    /// due, then alerts for records that no device announced within 24
    /// hours of their being witnessed, and for forks. A device back after
    /// more than a day asks its own devices with RECORDS first, and alerts
    /// only from the next run on.
    pub(crate) async fn watch_own(&self, uid: &Identity) -> Result<()> {
        let now = self.now_ms();
        let key = format!("identity.watched.{uid}");
        let last: Option<u64> = self.store().setting(&key)?.and_then(|t| t.parse().ok());
        let due = self
            .store()
            .contact(uid.as_str())?
            .is_none_or(|c| c.next_check.is_none_or(|t| t <= now) || c.pending > 0);
        let mut alert: Option<BlobRef> = None;
        if due
            && let Applied::Keys { new_fork: true, .. } | Applied::Unread { new_fork: true } =
                self.refresh_uid(uid).await?
        {
            alert = self.store().contact(uid.as_str())?.and_then(|c| c.head);
        }
        self.store().set_setting(&key, Some(&now.to_string()))?;
        let back_after_a_day = last.is_some_and(|t| now.saturating_sub(t) > DAY_MS);
        let own = self.own_row(uid)?;
        let rows = self.store().records(uid.as_str())?;
        let (_, changes) = self.store().write(|tx| {
            if back_after_a_day {
                queue_line(tx, uid.as_str(), &ContentLine::Records(None), now)?;
                return Ok(());
            }
            for r in rows.iter().filter(|r| r.accepted && !r.mine) {
                let late = r.witnessed.is_some_and(|w| now.saturating_sub(w) >= DAY_MS);
                if late
                    && !tx.is_announced(uid.as_str(), &r.hash)?
                    && tx.set_alerted(uid.as_str(), &r.hash)?
                {
                    alert = Some(r.hash);
                }
            }
            if let Some(hash) = alert {
                queue_line(tx, uid.as_str(), &ContentLine::Alert(hash), now)?;
            }
            Ok(())
        })?;
        self.emit_changes(changes);
        if alert.is_some() {
            self.emit_identity(IdentityEvent::Alert { uid: to_uid(uid) });
        }
        if !own.told_full && kept_chain(uid, &rows, false).is_some_and(|c| c.is_nearly_full()) {
            self.store().write(|tx| tx.set_told_full(uid.as_str()))?;
            self.emit_identity(IdentityEvent::ChainFilling { uid: to_uid(uid) });
        }
        Ok(())
    }

    /// The recovery key's text, checked: for apps that ask the user to
    /// type it back after creation (4.8, step 5).
    pub fn check_recovery_key(&self, uid: &str, recovery_key: &str) -> Result<bool> {
        let identity = parse_identity(uid)?;
        let recovery =
            RecoveryKey::parse(recovery_key).map_err(|_| IdentityError::BadRecoveryKey)?;
        let rows = self.store().records(identity.as_str())?;
        let chain = kept_chain(&identity, &rows, false)
            .ok_or_else(|| IdentityError::NotAccepted(to_uid(&identity)))?;
        let ok = recovery.master_key_for(&chain).is_some();
        let _ = Zeroizing::new(());
        Ok(ok)
    }
}
