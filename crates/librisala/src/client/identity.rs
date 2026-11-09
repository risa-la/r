//! Identities and devices (4.3-4.9, 12.13, 12.14): creating an identity
//! with its recovery key, signing in, pairing a device by QR text,
//! removing a device, recovery, safety numbers, what the device knows of
//! other identities, and the witness policy of the key logs (4.5).
//!
//! Owned by task C1.
//!
//! # Checking identities
//!
//! A device never takes the server's word for whose keys are whose
//! (12.14). [`Client::refresh_identity`] fetches an identity's key file
//! over HTTPS and checks every record against the key log: witnessed
//! checkpoints under the device's [witness policy](Client::witness_policy),
//! inclusion proofs from the log's tiles, consistency with the newest
//! checkpoint seen, hand-offs, and the uid's hint (4.4, 4.5). What it
//! learns ends in one of the three states of 4.4, with pins on the master
//! key and log, a head that only moves forward, forks and rollbacks, and
//! devices that once removed stay removed. See `verify`.
//!
//! # For the conversations area (task C2)
//!
//! - [`Client::send_check`]: whether a conversation may send to an
//!   identity.
//! - [`Client::identity_devices`] and [`Client::may_add_devices`]: an
//!   identity's devices and their states, for group membership (12.7).
//! - [`Client::take_self_lines`] and [`Client::handle_self_lines`]: the
//!   lines of the conversation with yourself (12.9) that this area sends
//!   and receives.
//! - [`Client::identity_maintenance`]: the daily work (fetches spread
//!   over the day, watching the device's own records, resending records
//!   not logged yet), for the driver to run from time to time.

mod https;
mod own;
mod pairing;
#[cfg(test)]
mod tests;
mod verify;

use std::sync::Arc;

use risala_keylog::witness::WitnessPolicy;
use risala_proto::content::ContentLine;
use risala_proto::names::{BlobRef, Identity};
use risala_proto::safety::SafetyNumber as ProtoSafetyNumber;
use zeroize::Zeroizing;

use super::types::{AccountId, DeviceId, Timestamp, Uid};
use super::{Client, Error, Event, Result};
use crate::store::identity::{ContactRow, DeviceState, KeysState};
use crate::store::{Change, StoreError};
use crate::sync::identity::{
    SelfEffect, handle_self_line, is_stale, queue_pin, send_check, unchecked,
};

pub use crate::sync::identity::{ConversationKind, SendCheck, StopReason};
pub use https::{Fetched, Https, KeyFetcherHttps};
pub use verify::{DAY_MS, STALE_AFTER_MS};

/// The identity area's errors.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// This device does not hold the identity.
    #[error("this device does not hold {0}")]
    NotHeld(Uid),
    /// Sending to the identity is stopped until the user acts: it has a
    /// new master key, or a fork was found (4.5, 12.14).
    #[error("sending to {uid} is stopped: {reason:?}")]
    Stopped {
        /// The identity.
        uid: Uid,
        /// Why.
        reason: StopReason,
    },
    /// The recovery key does not give the identity's current master key
    /// (4.8).
    #[error("the recovery key is not this identity's")]
    WrongRecoveryKey,
    /// The text is not a recovery key (4.8).
    #[error("not a recovery key")]
    BadRecoveryKey,
    /// The server offers no registration, or names no key log (4.7, 8.5).
    #[error("the server does not offer registration")]
    NoRegistration,
    /// The identity's records are not accepted yet, or its key file is
    /// missing, so the operation cannot check them (4.5).
    #[error("the records of {0} are not accepted yet")]
    NotAccepted(Uid),
    /// The device is not a current device of the identity.
    #[error("no such device")]
    NoSuchDevice,
    /// The device does not hold the identity's current device-signing key
    /// or backup key (4.8, 12.13): another device has not sent it yet.
    #[error("this device does not hold the current {0}")]
    MissingKey(&'static str),
    /// The record would break a rule of 4.4.
    #[error("the record is not valid: {0}")]
    InvalidRecord(String),
    /// A pairing failed (4.8): a code that is not a pairing code, data
    /// that does not open or check, or nothing to finish.
    #[error("pairing: {0}")]
    Pairing(String),
    /// The safety number scanned is not this identity's (12.14).
    #[error("the safety number does not match")]
    SafetyNumberMismatch,
    /// The witness policy is not valid: k must be more than half the list
    /// and at most its length, with each witness once (4.5).
    #[error("invalid witness policy")]
    BadWitnessPolicy,
}

/// What the identity area tells the UI, besides changes to the cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityEvent {
    /// A record of one of the device's own identities that no device
    /// announced, a fork of it, or an ALERT from another device (4.5):
    /// someone else may control the identity.
    Alert {
        /// The identity.
        uid: Uid,
    },
    /// A device to pair asks to be confirmed (4.8, step 2).
    PairingRequest(PairingRequest),
    /// This device, being paired, waits until its record is accepted
    /// (4.5, 4.8 step 5) before it shows the identity to confirm.
    PairingWaiting {
        /// The identity the bundle names.
        uid: Uid,
    },
    /// An identity has a new master key, or a new log: sending stops
    /// outside public rooms until the user acknowledges it (12.14).
    NewMasterKey {
        /// The identity.
        uid: Uid,
    },
    /// A fork or rollback of an identity, or of a log that holds its
    /// records (4.5): sending to it stops until the user resolves it.
    Fork {
        /// The identity.
        uid: Uid,
    },
    /// No checkpoint of a log has k cosignatures from the device's witness
    /// list (4.5): the list does not fit the log.
    WitnessListProblem {
        /// The identity whose log it is.
        uid: Uid,
    },
    /// One of the device's own identities moved to a new generation
    /// (4.8): the backups area must replace the current backup at once
    /// (12.13).
    NewGeneration {
        /// The identity.
        uid: Uid,
        /// The new generation.
        generation: u32,
    },
    /// One of the device's own identities' chain passed 3,072 records
    /// (4.4): time to move to a new identity.
    ChainFilling {
        /// The identity.
        uid: Uid,
    },
}

/// An identity just made, with the recovery key to show the user once
/// (4.8). The recovery key is wiped when dropped.
#[derive(Debug)]
pub struct NewIdentity {
    /// The identity.
    pub uid: Uid,
    /// Its account on the server it registered on.
    pub account: AccountId,
    /// The recovery key, as 52 characters of base32 in groups of four
    /// (4.8).
    pub recovery_key: Zeroizing<String>,
}

/// An identity this device holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnIdentity {
    /// The identity.
    pub uid: Uid,
    /// This device's id.
    pub device: DeviceId,
}

/// A device of an identity (4.4, 12.14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// Its id.
    pub id: DeviceId,
    /// Its short id, the first 8 characters of its id in base32, to show
    /// with its label (12.14).
    pub short: String,
    /// Its label, usually its name.
    pub label: String,
    /// When the record that added it was made.
    pub added: Timestamp,
    /// Whether its record is accepted (4.5), not pending.
    pub accepted: bool,
    /// Whether an accepted record removed it.
    pub removed: bool,
    /// Whether it is this device.
    pub this_device: bool,
    /// Its ML-DSA-44 device key, which signs its KeyPackage bindings
    /// (12.5).
    pub device_key: Vec<u8>,
    /// Its X-Wing attestation key (12.10).
    pub attestation_key: Vec<u8>,
}

/// The state of an identity's keys after the last fetch (4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeysStatus {
    /// Never fetched with an answer: an outage so far, or not fetched.
    Unknown,
    /// A valid key file.
    Keys,
    /// Keys missing, with why, for display.
    Missing(String),
}

/// What this device knows of an identity (4.5, 12.14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contact {
    /// The identity.
    pub uid: Uid,
    /// Whether the user checked its safety number.
    pub verified: bool,
    /// Why sending to it is stopped in a direct conversation with it, if
    /// it is (12.14).
    pub stopped: Option<StopReason>,
    /// Whether the device can check it (12.14): not when it is forked or
    /// its keys are missing. Rooms then treat its leaves as unverified.
    pub checkable: bool,
    /// The state of its keys.
    pub keys: KeysStatus,
    /// Whether its view was not refreshed for 7 days (4.5).
    pub stale: bool,
    /// How many records of its key file are pending (4.5).
    pub pending: u64,
    /// Whether the device's witness list does not fit its log (4.5).
    pub witness_problem: bool,
    /// Its devices, current, pending and removed.
    pub devices: Vec<Device>,
}

/// An identity's safety number (12.14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyNumber {
    /// 40 digits in eight groups of five, separated by spaces.
    pub digits: String,
    /// The QR text, `RISALA-FP:` and base32.
    pub qr: String,
}

/// A pairing this device started as the new device (4.8, step 1): the QR
/// text to show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingOffer {
    /// The QR text, `RISALA-PAIR:` and base32.
    pub qr: String,
}

/// The identity a new device is about to take, for the user to confirm
/// (4.8, step 5): whoever saw the QR code could have answered with a
/// bundle of an identity of their own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingIdentity {
    /// The identity.
    pub uid: Uid,
    /// Its current devices, by its accepted records, this one among them.
    pub devices: Vec<PairingDevice>,
}

/// A device of the identity a new device is about to take (4.8, step 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingDevice {
    /// Its id.
    pub id: DeviceId,
    /// Its short id (12.14).
    pub short: String,
    /// Its label.
    pub label: String,
    /// Whether it is this device.
    pub this_device: bool,
}

/// A new device asking to be paired, after scanning its QR code (4.8,
/// step 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingRequest {
    /// The new device's label.
    pub label: String,
    /// The new device's id.
    pub device: DeviceId,
    /// Its short id (12.14).
    pub short: String,
}

/// 32 bytes of randomness for hedged signing (4.3, PLAN.md 58).
pub(crate) fn rnd() -> Result<[u8; 32]> {
    let mut r = [0u8; 32];
    getrandom::fill(&mut r).map_err(|e| Error::Internal(format!("random: {e}")))?;
    Ok(r)
}

pub(crate) fn parse_identity(uid: &str) -> Result<Identity> {
    uid.trim()
        .parse::<Identity>()
        .map_err(|_| Error::invalid("identity", uid))
}

fn to_uid(identity: &Identity) -> Uid {
    identity.to_uid()
}

impl Client {
    /// The HTTPS fetcher for key files and logs.
    pub(crate) fn https(&self) -> Arc<dyn Https> {
        if let Some(https) = &self.options().https {
            return https.clone();
        }
        if let Some(ca) = &self.options().ca_verifier {
            return Arc::new(KeyFetcherHttps::new(ca.clone()));
        }
        https::platform()
    }

    /// The time now, in ms.
    pub(crate) fn now_ms(&self) -> u64 {
        self.options().clock.now().unix_millis()
    }

    /// The witness policy in force, if there is a usable one.
    pub(crate) fn policy(&self) -> Result<Option<WitnessPolicy>> {
        let (vkeys, k) = self.store().witnesses()?;
        Ok(crate::sync::keylog::policy(&vkeys, k))
    }

    /// Emits the cache's changes to the UI.
    pub(crate) fn emit_changes(&self, changes: Vec<Change>) {
        for change in changes {
            self.emit(Event::Changed(change));
        }
    }

    pub(crate) fn emit_identity(&self, event: IdentityEvent) {
        self.emit(Event::Identity(event));
    }

    /// Fetches `uid`'s key file and checks it against its logs, then
    /// takes what it found into the cache (4.4, 4.5).
    pub(crate) async fn refresh_uid(&self, uid: &Identity) -> Result<verify::Applied> {
        let store = self.store().clone();
        let before = store.contact(uid.as_str())?;
        let new_key_before = before.as_ref().and_then(|c| c.new_master_key.clone());
        let head = match &before {
            Some(c) => match c.head {
                Some(head) => store
                    .records(uid.as_str())?
                    .into_iter()
                    .find(|r| r.hash == head)
                    .and_then(|r| Some((r.log.0, r.log_index?))),
                None => None,
            },
            None => None,
        };
        let now = self.now_ms();
        let verified = verify::Verifier::new(self.https(), self.policy()?, store.clone(), now)
            .verify(uid, head)
            .await?;
        let uid2 = uid.clone();
        let (applied, changes) = self
            .blocking(move |c| {
                let own: Vec<String> = c
                    .store()
                    .own_identities()?
                    .into_iter()
                    .map(|o| o.uid)
                    .collect();
                Ok(c.store().write(|tx| {
                    let applied = verify::apply(tx, &uid2, verified, now)?;
                    let after = tx.contact(uid2.as_str())?;
                    if let Some(after) = &after {
                        let moved = before.as_ref().is_none_or(|b| {
                            b.master_key != after.master_key
                                || b.head != after.head
                                || b.log_origin != after.log_origin
                        });
                        if moved {
                            queue_pin(tx, &own, after, now)?;
                        }
                    }
                    Ok((applied, after))
                })?)
            })
            .await?;
        let (applied, after) = applied;
        self.emit_changes(changes);
        if let Some(after) = after {
            let uid = to_uid(uid);
            if matches!(
                applied,
                verify::Applied::Keys { new_fork: true, .. }
                    | verify::Applied::Unread { new_fork: true }
            ) {
                self.emit_identity(IdentityEvent::Fork { uid: uid.clone() });
            }
            if after.new_master_key.is_some() && after.new_master_key != new_key_before {
                self.emit_identity(IdentityEvent::NewMasterKey { uid: uid.clone() });
            }
            if after.witness_problem {
                self.emit_identity(IdentityEvent::WitnessListProblem { uid });
            }
        }
        Ok(applied)
    }

    /// Fetches `uid`'s key file again and checks it (4.4, 4.5, 12.14),
    /// and returns what the device now knows of it. An outage changes
    /// nothing, and is not an error.
    pub async fn refresh_identity(&self, uid: &str) -> Result<Contact> {
        let identity = parse_identity(uid)?;
        self.refresh_uid(&identity).await?;
        self.contact_now(&identity)
    }

    /// What this device knows of `uid`, fetching its key file if it has
    /// never fetched it (4.4, 4.5).
    pub async fn contact(&self, uid: &str) -> Result<Contact> {
        let identity = parse_identity(uid)?;
        if self
            .store()
            .contact(identity.as_str())?
            .is_none_or(|c| c.fetched.is_none())
        {
            self.refresh_uid(&identity).await?;
        }
        self.contact_now(&identity)
    }

    /// What this device knows of `uid`, from the cache only.
    pub fn known_contact(&self, uid: &str) -> Result<Option<Contact>> {
        let identity = parse_identity(uid)?;
        if self.store().contact(identity.as_str())?.is_none() {
            return Ok(None);
        }
        self.contact_now(&identity).map(Some)
    }

    fn contact_now(&self, uid: &Identity) -> Result<Contact> {
        let row = self
            .store()
            .contact(uid.as_str())?
            .unwrap_or_else(|| ContactRow::new(uid.as_str()));
        let stopped = match send_check(Some(&row), ConversationKind::Direct) {
            SendCheck::Stop(r) | SendCheck::Warn(r) => Some(r),
            SendCheck::Send => None,
        };
        Ok(Contact {
            uid: to_uid(uid),
            verified: row.verified,
            stopped,
            checkable: unchecked(&row).is_none(),
            keys: match &row.keys {
                KeysState::Unknown => KeysStatus::Unknown,
                KeysState::Keys => KeysStatus::Keys,
                KeysState::Missing(why) => KeysStatus::Missing(why.clone()),
            },
            stale: is_stale(&row, self.now_ms()),
            pending: row.pending,
            witness_problem: row.witness_problem,
            devices: self.identity_devices(uid.as_str())?,
        })
    }

    /// The devices this device knows of `uid`: current (accepted), pending
    /// and removed (4.4, 4.5). Only current devices' leaves are accepted
    /// in groups (12.7); removed ones are removed from them.
    pub fn identity_devices(&self, uid: &str) -> Result<Vec<Device>> {
        let identity = parse_identity(uid)?;
        let mine = self
            .store()
            .own_identity(identity.as_str())?
            .map(|o| o.device_id);
        Ok(self
            .store()
            .devices(identity.as_str())?
            .into_iter()
            .map(|d| {
                let id = risala_proto::record::DeviceId::from_bytes(d.device_id);
                Device {
                    id: DeviceId(d.device_id),
                    short: id.short(),
                    label: d.label,
                    added: Timestamp::from_unix_millis(d.added).unwrap_or(Timestamp::MAX),
                    accepted: d.state == DeviceState::Current,
                    removed: d.state == DeviceState::Removed,
                    this_device: mine == Some(d.device_id),
                    device_key: d.device_key,
                    attestation_key: d.attestation_key,
                }
            })
            .collect())
    }

    /// Whether a conversation of `kind` may send to `uid` (4.5, 12.14).
    /// An identity the device cannot check stops only direct
    /// conversations; a new master key stops direct conversations and
    /// private rooms, and warns in public rooms (see
    /// [`send_check`]). An identity the
    /// device never fetched is not stopped by this: the conversations area
    /// fetches it first with [`contact`](Self::contact).
    pub fn send_check(&self, uid: &str, kind: ConversationKind) -> Result<SendCheck> {
        let identity = parse_identity(uid)?;
        let contact = self.store().contact(identity.as_str())?;
        Ok(send_check(contact.as_ref(), kind))
    }

    /// Whether the device can check `uid` (12.14). When it cannot, because
    /// the identity is forked or its keys are missing, rooms treat its
    /// leaves as unverified and hide what they send, and rooms that are
    /// not public remove its leaves, until it can again (12.7).
    pub fn can_check(&self, uid: &str) -> Result<bool> {
        let identity = parse_identity(uid)?;
        let contact = self.store().contact(identity.as_str())?;
        Ok(contact.as_ref().is_none_or(|c| unchecked(c).is_none()))
    }

    /// Whether the devices of `uid` may be added to groups now: its keys
    /// are there, nothing stops sending to it, and its view is fresh, not
    /// stale (4.5, 12.7).
    pub fn may_add_devices(&self, uid: &str) -> Result<bool> {
        let identity = parse_identity(uid)?;
        let Some(c) = self.store().contact(identity.as_str())? else {
            return Ok(false);
        };
        // None while it is stale, forked, has its keys missing, or has a
        // new master key not yet acknowledged (12.7).
        Ok(c.keys == KeysState::Keys
            && unchecked(&c).is_none()
            && c.new_master_key.is_none()
            && !is_stale(&c, self.now_ms()))
    }

    /// The identities this device holds.
    pub fn own_identities(&self) -> Result<Vec<OwnIdentity>> {
        Ok(self
            .store()
            .own_identities()?
            .into_iter()
            .filter_map(|o| {
                Some(OwnIdentity {
                    uid: o.uid.parse().ok()?,
                    device: DeviceId(o.device_id),
                })
            })
            .collect())
    }

    /// Takes the lines this area has queued for the conversation with
    /// yourself of `uid` (12.9): RECORD, ALERT, RECORDS, SIGNINGKEY,
    /// BACKUPKEY and PIN. The conversations area sends them. SIGNINGKEY
    /// and BACKUPKEY are returned only while no record of the chain is
    /// pending and every other leaf of the conversation with yourself is a
    /// current, confirmed device of the identity, so never to a device
    /// whose removal has not yet won (12.9, 4.8); until then they stay
    /// queued.
    pub fn take_self_lines(&self, uid: &str) -> Result<Vec<ContentLine>> {
        let identity = parse_identity(uid)?;
        let (lines, changes) = self
            .store()
            .write(|tx| tx.take_self_lines(identity.as_str()))?;
        self.emit_changes(changes);
        Ok(lines
            .iter()
            .filter_map(|l| ContentLine::parse(l).ok())
            .collect())
    }

    /// Handles lines that arrived in the conversation with yourself of
    /// `uid` from a leaf of the identity's own that the device has
    /// confirmed (12.9, 12.10): the conversations area calls this with
    /// the lines of this area (RECORD, ALERT, RECORDS, SIGNINGKEY,
    /// BACKUPKEY and PIN), and ignores the others here.
    pub fn handle_self_lines(&self, uid: &str, lines: &[ContentLine]) -> Result<()> {
        let identity = parse_identity(uid)?;
        let own = self
            .store()
            .own_identity(identity.as_str())?
            .ok_or_else(|| IdentityError::NotHeld(to_uid(&identity)))?;
        let keys = self.options().keys.clone();
        let now = self.now_ms();
        let (effects, changes) = self.store().write_with(|tx| {
            lines
                .iter()
                .map(|line| handle_self_line(tx, &*keys, &own, line, now))
                .collect::<Result<Vec<_>>>()
        })?;
        self.emit_changes(changes);
        for effect in effects {
            if let SelfEffect::Alert(_) = effect {
                self.emit_identity(IdentityEvent::Alert {
                    uid: to_uid(&identity),
                });
            }
        }
        Ok(())
    }

    /// Queues a PIN line for every identity this device has pinned, in the
    /// conversation with yourself of `uid` (12.9): for the conversations
    /// area to call when a new device of the identity joins it.
    pub fn queue_all_pins(&self, uid: &str) -> Result<()> {
        let identity = parse_identity(uid)?;
        let now = self.now_ms();
        let contacts = self.store().contacts()?;
        let (_, changes) = self.store().write(|tx| {
            for c in contacts.iter().filter(|c| c.uid != identity.as_str()) {
                queue_pin(tx, &[identity.as_str().to_owned()], c, now)?;
            }
            Ok(())
        })?;
        self.emit_changes(changes);
        Ok(())
    }

    /// The safety number of `uid` (12.14), over its pinned master key.
    pub fn safety_number(&self, uid: &str) -> Result<SafetyNumber> {
        let identity = parse_identity(uid)?;
        let number = self.proto_safety_number(&identity)?;
        Ok(SafetyNumber {
            digits: number.groups().join(" "),
            qr: number.to_qr_text(),
        })
    }

    fn proto_safety_number(&self, identity: &Identity) -> Result<ProtoSafetyNumber> {
        let contact = self
            .store()
            .contact(identity.as_str())?
            .and_then(|c| c.master_key)
            .ok_or_else(|| IdentityError::NotAccepted(to_uid(identity)))?;
        let key: &[u8; risala_proto::auth::PUBLIC_KEY_LEN] = contact
            .as_slice()
            .try_into()
            .map_err(|_| Error::Store(StoreError::Corrupt("a master key".into())))?;
        Ok(ProtoSafetyNumber::new(
            identity,
            &risala_proto::auth::PublicKey::from_bytes(key),
        ))
    }

    /// Marks `uid` as verified, from the QR text of its safety number
    /// scanned from the other person's device (12.14), or after comparing
    /// the digits when `qr` is `None`. The mark goes to the identity's
    /// other devices with a PIN line (12.9).
    pub fn mark_verified(&self, uid: &str, qr: Option<&str>) -> Result<()> {
        let identity = parse_identity(uid)?;
        let ours = self.proto_safety_number(&identity)?;
        if let Some(qr) = qr {
            let theirs = ProtoSafetyNumber::from_qr_text(qr.trim())
                .map_err(|_| IdentityError::SafetyNumberMismatch)?;
            if theirs != ours {
                return Err(IdentityError::SafetyNumberMismatch.into());
            }
        }
        self.update_contact(&identity, |c| c.verified = true)
    }

    /// Clears the verified mark of `uid`.
    pub fn clear_verified(&self, uid: &str) -> Result<()> {
        let identity = parse_identity(uid)?;
        self.update_contact(&identity, |c| c.verified = false)
    }

    /// Acknowledges a new master key of `uid` (4.5, 12.14), so that
    /// sending starts again: the new key becomes the pin, unverified.
    pub fn acknowledge_new_master_key(&self, uid: &str) -> Result<()> {
        let identity = parse_identity(uid)?;
        self.update_contact(&identity, |c| {
            if let Some(key) = c.new_master_key.take() {
                c.master_key = Some(key);
                c.verified = false;
                // The new chain is taken afresh from the next fetch, which
                // may not hold the old head (4.5).
                c.head = None;
                c.head_index = None;
                c.next_check = Some(0);
            }
        })
    }

    /// Resolves the forks of `uid` once the user has checked with the
    /// person (4.5): the device takes the identity afresh, as at first
    /// contact, from its next fetch. Its devices stay removed if they were.
    pub async fn resolve_fork(&self, uid: &str) -> Result<Contact> {
        let identity = parse_identity(uid)?;
        let now = self.now_ms();
        let (_, changes) = self.store().write(|tx| {
            tx.resolve_forks(identity.as_str(), now)?;
            if let Some(mut c) = tx.contact(identity.as_str())? {
                c.forked = false;
                c.master_key = None;
                c.head = None;
                c.head_index = None;
                c.log_origin = None;
                c.verified = false;
                tx.put_contact(&c)?;
            }
            Ok(())
        })?;
        self.emit_changes(changes);
        self.refresh_identity(uid).await
    }

    fn update_contact(&self, identity: &Identity, f: impl FnOnce(&mut ContactRow)) -> Result<()> {
        let own: Vec<String> = self
            .store()
            .own_identities()?
            .into_iter()
            .map(|o| o.uid)
            .collect();
        let now = self.now_ms();
        let (_, changes) = self.store().write(|tx| {
            let mut c = tx
                .contact(identity.as_str())?
                .unwrap_or_else(|| ContactRow::new(identity.as_str()));
            f(&mut c);
            tx.put_contact(&c)?;
            queue_pin(tx, &own, &c, now)?;
            Ok(())
        })?;
        self.emit_changes(changes);
        Ok(())
    }

    /// The witness policy (4.5): the witnesses' verifier keys, and k.
    pub fn witness_policy(&self) -> Result<(Vec<String>, usize)> {
        let (vkeys, k) = self.store().witnesses()?;
        Ok(match k {
            Some(k) => (vkeys, k),
            None => {
                let (list, k) = crate::sync::keylog::DEFAULT_WITNESSES;
                (list.iter().map(|s| (*s).to_owned()).collect(), k)
            }
        })
    }

    /// Sets the witness policy (4.5): k must be more than half the list
    /// and at most its length, each witness once, all ML-DSA-44 (type
    /// `0x06`) verifier keys.
    pub fn set_witness_policy(&self, witnesses: &[String], k: usize) -> Result<()> {
        WitnessPolicy::from_vkeys(witnesses, k).map_err(|_| IdentityError::BadWitnessPolicy)?;
        let (_, changes) = self.store().write(|tx| tx.set_witnesses(witnesses, k))?;
        self.emit_changes(changes);
        Ok(())
    }

    /// Forgets the witness policy set with
    /// [`set_witness_policy`](Self::set_witness_policy), for the apps'
    /// default list (4.10).
    pub fn clear_witness_policy(&self) -> Result<()> {
        let (_, changes) = self.store().write(|tx| tx.clear_witnesses())?;
        self.emit_changes(changes);
        Ok(())
    }

    /// The forks found and not yet resolved of `uid` (4.5), as hashes of
    /// what shows them, for display.
    pub fn forks(&self, uid: &str) -> Result<Vec<BlobRef>> {
        let identity = parse_identity(uid)?;
        Ok(self
            .store()
            .forks(Some(identity.as_str()))?
            .into_iter()
            .map(|f| BlobRef::of(&f.evidence))
            .collect())
    }
}
