//! Replaying an identity's chain of records (SPEC 4.4), and the checks
//! built on it: heads and "extends" (4.4, 4.5), pins (4.5, 4.6), forks
//! (4.5), REGISTER and KEYS PUT (4.7).
//!
//! [`Chain`] replays records one at a time, under the rules of 4.4's
//! "Replaying" steps 1 to 11, and keeps what they give: the current
//! master key, device-signing key, log, devices and generation. A chain
//! that has been built is valid; [`Chain::push`] leaves it unchanged when
//! a record fails.
//!
//! Step 11 places each record in a log. A key file lists the log of each
//! record ([`keyfile`](crate::keyfile)); records that come without one,
//! as in KEYS PUT, are placed where the chain puts them. A record may be
//! placed in a later log of the same host only after a hand-off (4.5),
//! which the caller vouches for through [`Handoffs`].

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;

use thiserror::Error;

use crate::auth::{PublicKey, SIGNATURE_LEN, SignLabel};
use crate::names::{BlobRef, Identity};
use crate::record::{
    DOUBLE_SIGNATURE_LEN, DeviceId, DeviceKeys, LogKey, MAX_CHAIN_LEN, MAX_CLOCK_AHEAD_MS,
    MAX_DEVICES, Record, RecordBody,
};
use crate::time::Timestamp;

/// Which hand-offs a reader has accepted (4.5): a reader follows a
/// hand-off only once the hand-off entry is the last entry of a witnessed
/// checkpoint of the old log, with an inclusion proof. Checking that is
/// for the key log code; the chain only asks.
pub trait Handoffs {
    /// Whether log `from` has handed off to log `to`, of the same host,
    /// directly or through the logs between them, by hand-offs that the
    /// reader has accepted.
    fn handed_off(&self, from: &LogKey, to: &LogKey) -> bool;
}

/// No hand-offs: every record must be in the log its chain names.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoHandoffs;

impl Handoffs for NoHandoffs {
    fn handed_off(&self, _: &LogKey, _: &LogKey) -> bool {
        false
    }
}

impl<F: Fn(&LogKey, &LogKey) -> bool> Handoffs for F {
    fn handed_off(&self, from: &LogKey, to: &LogKey) -> bool {
        self(from, to)
    }
}

/// The rule of 4.4 that a record broke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// Parsing step 3: more than 4,096 records.
    TooLong,
    /// Replaying step 1: the uid is not the identity's.
    Uid,
    /// Replaying step 2: the first record is not a `master` record with an
    /// empty `previous`, or a later one is.
    First,
    /// Replaying step 2: `previous` is not the hash of the record before.
    Previous,
    /// Replaying step 3: the time is not later than the record before.
    Time,
    /// Replaying step 4: the signature has the wrong length.
    SignatureLength,
    /// Replaying step 4: the signature does not verify.
    Signature,
    /// Replaying step 5: a public key appears twice in the chain.
    RepeatedKey,
    /// Replaying step 6: a later `master` record names another log than
    /// the chain's current one.
    MasterLog,
    /// Replaying step 7: `removed` is empty.
    NothingRemoved,
    /// Replaying step 7: `removed` is not sorted, or repeats an id.
    RemovedOrder,
    /// Replaying step 7: `removed` names a device that is not current.
    RemovedNotCurrent,
    /// Replaying step 8: the device was added before.
    DeviceAgain,
    /// Replaying step 8: more than 64 devices would be current.
    TooManyDevices,
    /// Replaying step 9: a `log` record names the current log.
    SameLog,
    /// Replaying step 10: a record follows a `retire` record.
    AfterRetire,
    /// Replaying step 11: the record is listed under a log that is not
    /// its own.
    WrongLog,
    /// REGISTER (4.7): the records are not one `master` record and one
    /// `device` record, or do not name the server's current log.
    NotRegistration,
}

impl Rule {
    fn describe(self) -> &'static str {
        match self {
            Rule::TooLong => "the chain has more than 4096 records",
            Rule::Uid => "the uid is not the identity's",
            Rule::First => "only the first record is a master record with an empty previous",
            Rule::Previous => "previous is not the hash of the record before",
            Rule::Time => "the time is not later than the record before",
            Rule::SignatureLength => "the signature has the wrong length",
            Rule::Signature => "the signature does not verify",
            Rule::RepeatedKey => "a public key appears twice in the chain",
            Rule::MasterLog => "a later master record names another log",
            Rule::NothingRemoved => "a signing record removes no device",
            Rule::RemovedOrder => "removed is not sorted without repeats",
            Rule::RemovedNotCurrent => "removed names a device that is not current",
            Rule::DeviceAgain => "the device was added before",
            Rule::TooManyDevices => "more than 64 devices would be current",
            Rule::SameLog => "a log record names the current log",
            Rule::AfterRetire => "a record follows a retire record",
            Rule::WrongLog => "the record is listed under another log than its own",
            Rule::NotRegistration => "not a master and a device record for this server's log",
        }
    }
}

/// A record that breaks a rule of 4.4, and its position in the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("record {index}: {}", rule.describe())]
pub struct ChainError {
    /// The record's position, from 0.
    pub index: usize,
    /// The rule it breaks.
    pub rule: Rule,
}

/// A current device (4.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Device {
    /// Its keys and label.
    pub keys: DeviceKeys,
    /// The position of the `device` record that added it.
    pub index: usize,
    /// That record's time, in milliseconds since 1970.
    pub time: u64,
}

/// A valid chain of records, and the state it replays to (4.4).
#[derive(Clone)]
pub struct Chain {
    uid: Identity,
    records: Vec<Record>,
    /// The log each record is in (step 11).
    placements: Vec<LogKey>,
    first_master_key: PublicKey,
    master_key: PublicKey,
    signing_key: PublicKey,
    /// The log the next record goes into, before any hand-off.
    log: LogKey,
    devices: BTreeMap<DeviceId, Device>,
    removed: BTreeSet<DeviceId>,
    keys: HashSet<Box<[u8]>>,
    generation: u32,
    retired: bool,
}

impl Chain {
    /// Replays `records` for `uid`, each in the log its chain puts it in,
    /// with no hand-offs.
    pub fn replay(uid: &Identity, records: &[Record]) -> Result<Chain, ChainError> {
        Chain::replay_placed(uid, records.iter().map(|r| (r, None)), &NoHandoffs)
    }

    /// Replays records for `uid`, each with the log it is listed under, if
    /// any (step 11). Records without one go where the chain puts them.
    pub fn replay_placed<'a>(
        uid: &Identity,
        records: impl IntoIterator<Item = (&'a Record, Option<&'a LogKey>)>,
        handoffs: &dyn Handoffs,
    ) -> Result<Chain, ChainError> {
        let mut records = records.into_iter();
        let Some((first, placed)) = records.next() else {
            return Err(ChainError {
                index: 0,
                rule: Rule::First,
            });
        };
        let mut chain = Chain::start(uid, first, placed)?;
        for (record, placed) in records {
            chain.push(record, placed, handoffs)?;
        }
        Ok(chain)
    }

    /// Starts a chain with its first record, a `master` record with an
    /// empty `previous` (steps 1, 2, 4, 5 and 11).
    pub fn start(
        uid: &Identity,
        record: &Record,
        placed: Option<&LogKey>,
    ) -> Result<Chain, ChainError> {
        let fail = |rule| Err(ChainError { index: 0, rule });
        let content = record.content();
        if content.uid != *uid {
            return fail(Rule::Uid);
        }
        let RecordBody::Master {
            master_key,
            signing_key,
            log,
        } = &content.body
        else {
            return fail(Rule::First);
        };
        if content.previous.is_some() {
            return fail(Rule::First);
        }
        if record.signature().len() != SIGNATURE_LEN {
            return fail(Rule::SignatureLength);
        }
        if !master_key.risala_verify(
            SignLabel::Record,
            record.content_bytes(),
            record.signature(),
        ) {
            return fail(Rule::Signature);
        }
        if master_key == signing_key {
            return fail(Rule::RepeatedKey);
        }
        // A first master record is in the log it names.
        if placed.is_some_and(|p| p != log) {
            return fail(Rule::WrongLog);
        }
        let keys = [master_key, signing_key]
            .into_iter()
            .map(|k| Box::from(&k.as_bytes()[..]))
            .collect();
        Ok(Chain {
            uid: uid.clone(),
            records: vec![record.clone()],
            placements: vec![log.clone()],
            first_master_key: master_key.clone(),
            master_key: master_key.clone(),
            signing_key: signing_key.clone(),
            log: log.clone(),
            devices: BTreeMap::new(),
            removed: BTreeSet::new(),
            keys,
            generation: 0,
            retired: false,
        })
    }

    /// Adds the next record, listed under `placed` if it is listed under a
    /// log (steps 1 to 11). On failure the chain is unchanged.
    pub fn push(
        &mut self,
        record: &Record,
        placed: Option<&LogKey>,
        handoffs: &dyn Handoffs,
    ) -> Result<(), ChainError> {
        let index = self.records.len();
        let fail = |rule| Err(ChainError { index, rule });
        if index >= MAX_CHAIN_LEN {
            return fail(Rule::TooLong);
        }
        let content = record.content();
        // Step 10: nothing follows a retire record.
        if self.retired {
            return fail(Rule::AfterRetire);
        }
        // Step 1.
        if content.uid != self.uid {
            return fail(Rule::Uid);
        }
        // Step 2.
        if content.previous.is_none() {
            return fail(Rule::First);
        }
        if content.previous != Some(self.head_hash()) {
            return fail(Rule::Previous);
        }
        // Step 3.
        if content.time <= self.head().content().time {
            return fail(Rule::Time);
        }
        // Step 11: the record's log is the chain's, or a later log of the
        // same host that the chain's log handed off to.
        let log = match placed {
            None => self.log.clone(),
            Some(p) if *p == self.log => p.clone(),
            Some(p) => {
                let later = p.host() == self.log.host() && p.number() > self.log.number();
                if !later || !handoffs.handed_off(&self.log, p) {
                    return fail(Rule::WrongLog);
                }
                p.clone()
            }
        };
        // Step 4.
        let signature = record.signature();
        let bytes = record.content_bytes();
        let signer = match &content.body {
            RecordBody::Device(_) => &self.signing_key,
            _ => &self.master_key,
        };
        if let RecordBody::Master { master_key, .. } = &content.body {
            if signature.len() != DOUBLE_SIGNATURE_LEN {
                return fail(Rule::SignatureLength);
            }
            let (old, new) = signature.split_at(SIGNATURE_LEN);
            if !signer.risala_verify(SignLabel::Record, bytes, old)
                || !master_key.risala_verify(SignLabel::Record, bytes, new)
            {
                return fail(Rule::Signature);
            }
        } else {
            if signature.len() != SIGNATURE_LEN {
                return fail(Rule::SignatureLength);
            }
            if !signer.risala_verify(SignLabel::Record, bytes, signature) {
                return fail(Rule::Signature);
            }
        }
        // Step 5: no public key twice, in any role.
        let new_keys: Vec<&[u8]> = match &content.body {
            RecordBody::Master {
                master_key,
                signing_key,
                ..
            } => vec![master_key.as_bytes(), signing_key.as_bytes()],
            RecordBody::Signing { signing_key, .. } => vec![signing_key.as_bytes()],
            RecordBody::Device(keys) => {
                vec![keys.device_key.as_bytes(), keys.attestation_key.as_bytes()]
            }
            RecordBody::Log(_) | RecordBody::Retire => vec![],
        };
        let mut seen = HashSet::new();
        if new_keys
            .iter()
            .any(|k| self.keys.contains(*k) || !seen.insert(*k))
        {
            return fail(Rule::RepeatedKey);
        }
        // Steps 6 to 9.
        match &content.body {
            RecordBody::Master { log: named, .. } if *named != log => {
                return fail(Rule::MasterLog);
            }
            RecordBody::Signing { removed, .. } => {
                if removed.is_empty() {
                    return fail(Rule::NothingRemoved);
                }
                if removed.windows(2).any(|w| w[0] >= w[1]) {
                    return fail(Rule::RemovedOrder);
                }
                if removed.iter().any(|id| !self.devices.contains_key(id)) {
                    return fail(Rule::RemovedNotCurrent);
                }
            }
            RecordBody::Device(keys) => {
                let id = keys.device_id();
                if self.devices.contains_key(&id) || self.removed.contains(&id) {
                    return fail(Rule::DeviceAgain);
                }
                if self.devices.len() >= MAX_DEVICES {
                    return fail(Rule::TooManyDevices);
                }
            }
            RecordBody::Log(named) if *named == log => return fail(Rule::SameLog),
            _ => {}
        }

        // Every check passed: apply the record.
        self.keys.extend(new_keys.into_iter().map(Box::from));
        self.log = log.clone();
        match &content.body {
            RecordBody::Master {
                master_key,
                signing_key,
                ..
            } => {
                self.master_key = master_key.clone();
                self.signing_key = signing_key.clone();
                self.generation += 1;
            }
            RecordBody::Signing {
                signing_key,
                removed,
            } => {
                self.signing_key = signing_key.clone();
                for id in removed {
                    self.devices.remove(id);
                    self.removed.insert(*id);
                }
                self.generation += 1;
            }
            RecordBody::Device(keys) => {
                self.devices.insert(
                    keys.device_id(),
                    Device {
                        keys: keys.clone(),
                        index,
                        time: content.time,
                    },
                );
            }
            RecordBody::Log(named) => self.log = named.clone(),
            RecordBody::Retire => {
                self.retired = true;
                let ids: Vec<DeviceId> = self.devices.keys().copied().collect();
                self.removed.extend(ids);
                self.devices.clear();
            }
        }
        self.records.push(record.clone());
        self.placements.push(log);
        Ok(())
    }

    /// The identity.
    pub fn uid(&self) -> &Identity {
        &self.uid
    }

    /// The records, oldest first.
    pub fn records(&self) -> &[Record] {
        &self.records
    }

    /// The log each record is in, in the same order as
    /// [`records`](Chain::records).
    pub fn placements(&self) -> &[LogKey] {
        &self.placements
    }

    /// The number of records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Always false: a chain has at least its first record.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// The newest record.
    pub fn head(&self) -> &Record {
        self.records.last().expect("a chain has a first record")
    }

    /// The newest record's hash.
    pub fn head_hash(&self) -> BlobRef {
        self.head().hash()
    }

    /// The master key of the chain's first record.
    pub fn first_master_key(&self) -> &PublicKey {
        &self.first_master_key
    }

    /// The current master key.
    pub fn master_key(&self) -> &PublicKey {
        &self.master_key
    }

    /// The current device-signing key.
    pub fn signing_key(&self) -> &PublicKey {
        &self.signing_key
    }

    /// The current log: the one the chain's newest `master` or `log`
    /// record names, or the later log of the same host that the newest
    /// record went into after a hand-off. The next record goes there.
    pub fn log(&self) -> &LogKey {
        &self.log
    }

    /// The chain's generation: its `signing` records plus its `master`
    /// records after the first (4.4).
    pub fn generation(&self) -> u32 {
        self.generation
    }

    /// Whether the chain ends with a `retire` record (4.4, 4.9).
    pub fn is_retired(&self) -> bool {
        self.retired
    }

    /// The current devices, by id. None after a `retire` record.
    pub fn devices(&self) -> &BTreeMap<DeviceId, Device> {
        &self.devices
    }

    /// The current device with this device key, if any. Only current
    /// devices may sign in (4.4, 4.6).
    pub fn device_by_key(&self, key: &PublicKey) -> Option<&Device> {
        self.devices.get(&DeviceId::of(key))
    }

    /// The devices removed by record: by `signing` records, and every
    /// device that was current when a `retire` record ended the chain
    /// (4.4).
    pub fn removed(&self) -> &BTreeSet<DeviceId> {
        &self.removed
    }

    /// Whether the chain has more than [`CHAIN_WARN_LEN`] records, so
    /// that the device should tell its user (4.4).
    ///
    /// [`CHAIN_WARN_LEN`]: crate::record::CHAIN_WARN_LEN
    pub fn is_nearly_full(&self) -> bool {
        self.records.len() > crate::record::CHAIN_WARN_LEN
    }

    /// The position of the record with this hash, if the chain holds it.
    pub fn position(&self, hash: &BlobRef) -> Option<usize> {
        self.records.iter().position(|r| r.hash() == *hash)
    }

    /// Whether the chain **extends** the record `head` that a reader
    /// holds: `head` is in it (4.4).
    pub fn extends(&self, head: &BlobRef) -> bool {
        self.position(head).is_some()
    }

    /// The first record whose time is more than 10 minutes ahead of `now`,
    /// if any, which makes a fetch an outage rather than the file invalid
    /// (4.4). Times increase along a chain, so only the newest record can
    /// be the first.
    pub fn ahead_of(&self, now: Timestamp) -> Option<usize> {
        let limit = now.unix_millis().saturating_add(MAX_CLOCK_AHEAD_MS);
        self.records.iter().position(|r| r.content().time > limit)
    }

    /// The record of this chain that `other` forks with (4.5): one with
    /// the same `previous` and a different RecordContent. Records of
    /// other uids fork with nothing.
    pub fn fork_with(&self, other: &Record) -> Option<usize> {
        self.records.iter().position(|r| r.forks_with(other))
    }

    /// Where two chains of one uid first differ in RecordContent, which
    /// is a fork (4.5); `None` if one is a prefix of the other, records
    /// with equal contents counting as the same record.
    pub fn diverges_from(&self, other: &Chain) -> Option<usize> {
        if self.uid != other.uid {
            return None;
        }
        self.records
            .iter()
            .zip(&other.records)
            .position(|(a, b)| !a.same_content(b))
    }

    /// Checks the chain against a reader's pin (4.5, 4.6).
    pub fn check_pin(&self, pin: &Pin) -> PinCheck {
        PinCheck {
            extends: self.extends(&pin.head),
            new_master_key: self.master_key != pin.master_key,
        }
    }

    /// The pin a reader takes from this chain: its current master key and
    /// its newest record (4.5). A server pins the master key of the first
    /// chain it accepts the same way (4.6).
    pub fn pin(&self) -> Pin {
        Pin {
            master_key: self.master_key.clone(),
            head: self.head_hash(),
        }
    }
}

impl fmt::Debug for Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Chain")
            .field("uid", &self.uid)
            .field("len", &self.records.len())
            .field("head", &self.head_hash())
            .field("generation", &self.generation)
            .field("devices", &self.devices.len())
            .field("retired", &self.retired)
            .finish_non_exhaustive()
    }
}

/// What a reader has pinned for an identity (4.5, 4.6): a master key and
/// its **head**, the hash of the newest record of the identity it has
/// accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pin {
    /// The pinned master key.
    pub master_key: PublicKey,
    /// The head.
    pub head: BlobRef,
}

/// How a valid key file's chain stands against a pin (4.4, 4.5, 4.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PinCheck {
    /// The chain holds the head. If not, the file is a **rollback**: a
    /// device treats it as a fork (4.5), a server as keys missing (4.6).
    pub extends: bool,
    /// The chain's current master key is not the pinned one: a chain that
    /// starts with another master key, or a later `master` record. A
    /// device stops sending to the identity until its user acknowledges
    /// the new key (4.5, 12.14). A server, which pins the master key of
    /// the first chain it accepts, uses only [`extends`](PinCheck::extends):
    /// a chain that holds its head starts with that key.
    pub new_master_key: bool,
}

/// Why KEYS PUT failed (4.7), by the error code a server replies with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum KeysPutError {
    /// `ERR not-found`: the server does not hold the record `<after>`
    /// names.
    #[error("the record <after> names is not held")]
    NotFound,
    /// `ERR invalid`: the chain is not valid.
    #[error(transparent)]
    Invalid(ChainError),
    /// `ERR forbidden`: a different record in the place of one the server
    /// holds.
    #[error("a different record in the place of one held")]
    Forbidden,
    /// `ERR too-long`: over the limits of 4.4.
    #[error("over the limits of 4.4")]
    TooLong,
    /// `ERR not-supported`: the newest record does not go into this log.
    #[error("the newest record does not go into this log")]
    NotThisLog,
}

/// What a KEYS PUT that passes the chain checks adds (4.7).
#[derive(Debug, Clone)]
pub struct KeysPut {
    /// The chain the server holds afterwards.
    pub chain: Chain,
    /// The position of the first record the server did not hold. Records
    /// from here on are new; [`to_append`](KeysPut::to_append) says which
    /// of them go into this log.
    pub first_new: usize,
    /// The positions of the new records that go into this log, which the
    /// server appends, in order (4.5, 4.7). Records that belong to earlier
    /// logs of the chain are kept only to check the chain.
    pub to_append: Vec<usize>,
}

/// The chain checks of KEYS PUT (4.7), for a server whose current log is
/// `this_log`.
///
/// `held` is the chain the server holds for the records' uid, if any;
/// `after` is `<after>`, `None` for `-`; `records` the decoded
/// `<records>`. Records go into the log the chain puts them in, or into
/// `this_log` when that is a later log of the same host which the chain's
/// log has handed off to (4.5).
///
/// The rest of 4.7's checks are the server's: whether it hosts the
/// identity or logs others (`ERR not-supported`), and, for an identity
/// it does not host, that the identity's key file names this log in its
/// last `log` line and lists the new records (`ERR forbidden`).
pub fn keys_put(
    held: Option<&Chain>,
    after: Option<&BlobRef>,
    records: &[Record],
    this_log: &LogKey,
    handoffs: &dyn Handoffs,
) -> Result<KeysPut, KeysPutError> {
    let base: &[Record] = match (after, held) {
        (None, _) => &[],
        (Some(after), Some(held)) => {
            let p = held.position(after).ok_or(KeysPutError::NotFound)?;
            &held.records()[..=p]
        }
        (Some(_), None) => return Err(KeysPutError::NotFound),
    };
    let Some(first) = base.first().or(records.first()) else {
        return Err(KeysPutError::Invalid(ChainError {
            index: 0,
            rule: Rule::First,
        }));
    };
    let uid = first.content().uid.clone();
    let invalid = |e: ChainError| match e.rule {
        Rule::TooLong => KeysPutError::TooLong,
        _ => KeysPutError::Invalid(e),
    };
    let all: Vec<&Record> = base.iter().chain(records).collect();
    let mut chain = Chain::start(&uid, all[0], None).map_err(invalid)?;
    for record in &all[1..] {
        let into_this = chain.log() != this_log
            && chain.log().host() == this_log.host()
            && chain.log().number() < this_log.number()
            && handoffs.handed_off(chain.log(), this_log);
        let placed = into_this.then_some(this_log);
        chain.push(record, placed, handoffs).map_err(invalid)?;
    }
    let held_len = held.map_or(0, Chain::len);
    if let Some(held) = held {
        if held.uid() != chain.uid() {
            return Err(KeysPutError::Forbidden);
        }
        let differs = held
            .records()
            .iter()
            .zip(chain.records())
            .any(|(a, b)| a != b);
        if differs {
            return Err(KeysPutError::Forbidden);
        }
    }
    // The newest record goes into this log, or is a `log` record that
    // names it: moving to another log sends the whole chain, ending with
    // that record, to the new log, which appends nothing and answers with
    // no RECORD lines (4.7, 4.8).
    let newest_here = chain.placements().last() == Some(this_log) || chain.log() == this_log;
    if !newest_here && chain.len() > held_len {
        return Err(KeysPutError::NotThisLog);
    }
    let first_new = held_len.min(chain.len());
    let to_append = (first_new..chain.len())
        .filter(|&i| chain.placements()[i] == *this_log)
        .collect();
    Ok(KeysPut {
        chain,
        first_new,
        to_append,
    })
}

/// The chain checks of REGISTER (4.7): `records` are a `master` record
/// that names `server_log`, the server's current log, and one `device`
/// record, for `uid`, forming a valid chain. The server then checks the
/// sign-in signature under the device key, which is the chain's one
/// current device.
pub fn check_register(
    uid: &Identity,
    records: &[Record],
    server_log: &LogKey,
) -> Result<Chain, ChainError> {
    let [master, device] = records else {
        return Err(ChainError {
            index: records.len().min(2),
            rule: Rule::NotRegistration,
        });
    };
    let chain = Chain::replay(uid, records)?;
    let names_log =
        matches!(&master.content().body, RecordBody::Master { log, .. } if log == server_log);
    let is_device = matches!(device.content().body, RecordBody::Device(_));
    if !names_log || !is_device {
        return Err(ChainError {
            index: usize::from(names_log),
            rule: Rule::NotRegistration,
        });
    }
    Ok(chain)
}
