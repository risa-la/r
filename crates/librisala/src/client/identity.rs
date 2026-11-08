//! Identities and devices (4.3-4.9, 12.14): creating an identity with its
//! recovery key, pairing a device by QR text, removing a device,
//! recovery, safety numbers, what the device knows of other identities,
//! and the witness policy of the key logs (4.5).
//!
//! Owned by task C1. Every method returns [`Error::NotImplemented`](super::Error::NotImplemented) until
//! C1 builds it; the shapes are a starting point, which C1 may change.

use std::sync::Arc;

use zeroize::Zeroizing;

use super::error::not_implemented;
use super::types::{AccountId, DeviceId, Timestamp, Uid};
use super::{Client, Result};
use crate::conn::Establish;

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
}

/// Why sending to an identity is stopped (4.5, 12.14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// A new master key or a new log, not yet acknowledged.
    NewMasterKey,
    /// A fork in its records or its log.
    Fork,
}

/// What the identity area tells the UI, besides changes to the cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityEvent {
    /// A record of one of the device's own identities that no device
    /// announced, or an ALERT from another device (4.5): someone else may
    /// control the identity.
    Alert {
        /// The identity.
        uid: Uid,
    },
    /// A device to pair asks to be confirmed (4.8, step 2).
    PairingRequest(PairingRequest),
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

/// A device of an identity (4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// Its id.
    pub id: DeviceId,
    /// Its label, usually its name.
    pub label: String,
    /// When the record that added it was made.
    pub added: Timestamp,
    /// Whether its record is accepted (4.5), not pending.
    pub accepted: bool,
    /// Whether it has been removed.
    pub removed: bool,
    /// Whether it is this device.
    pub this_device: bool,
}

/// What this device knows of an identity (4.5, 12.14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contact {
    /// The identity.
    pub uid: Uid,
    /// Whether the user checked its safety number.
    pub verified: bool,
    /// Why sending to it is stopped, if it is.
    pub stopped: Option<StopReason>,
    /// Its current devices.
    pub devices: Vec<Device>,
}

/// An identity's safety number (12.14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafetyNumber {
    /// 40 digits in eight groups of five.
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

/// A new device asking to be paired, after scanning its QR code (4.8,
/// step 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingRequest {
    /// The new device's label.
    pub label: String,
    /// The new device's id.
    pub device: DeviceId,
}

impl Client {
    /// Creates the identity `<name>@<the server's identity domain>`: a
    /// recovery key, master key, device-signing key and this device's
    /// keys, its first records, and REGISTER (4.7, 4.8).
    pub async fn create_identity(
        &self,
        server: &str,
        name: &str,
        device_label: &str,
    ) -> Result<NewIdentity> {
        let _ = (server, name, device_label);
        not_implemented("create_identity")
    }

    /// The identities this device holds.
    pub fn own_identities(&self) -> Result<Vec<OwnIdentity>> {
        not_implemented("own_identities")
    }

    /// What this device knows of `uid`, fetching its key file if it has
    /// none (4.4, 4.5).
    pub async fn contact(&self, uid: &str) -> Result<Contact> {
        let _ = uid;
        not_implemented("contact")
    }

    /// Starts pairing this device to an identity (4.8, step 1), with
    /// `server` as the relay.
    pub async fn start_pairing(&self, server: &str, device_label: &str) -> Result<PairingOffer> {
        let _ = (server, device_label);
        not_implemented("start_pairing")
    }

    /// Waits for the other device to finish the pairing started with
    /// [`start_pairing`](Self::start_pairing) (4.8, step 5), and returns
    /// the identity this device now holds.
    pub async fn finish_pairing(&self) -> Result<OwnIdentity> {
        not_implemented("finish_pairing")
    }

    /// Reads a new device's QR text on a device of `uid` (4.8, step 2).
    pub async fn scan_pairing(&self, uid: &str, qr: &str) -> Result<PairingRequest> {
        let _ = (uid, qr);
        not_implemented("scan_pairing")
    }

    /// Adds the device the user confirmed, and sends it the identity
    /// (4.8, steps 3 and 4), with a history transfer if `transfer`.
    pub async fn confirm_pairing(&self, uid: &str, transfer: bool) -> Result<()> {
        let _ = (uid, transfer);
        not_implemented("confirm_pairing")
    }

    /// Removes a device of `uid`, which needs the recovery key (4.8).
    pub async fn remove_device(
        &self,
        uid: &str,
        device: DeviceId,
        recovery_key: &str,
    ) -> Result<()> {
        let _ = (uid, device, recovery_key);
        not_implemented("remove_device")
    }

    /// Recovers `uid` on this device from its recovery key, after losing
    /// every device (4.8).
    pub async fn recover(
        &self,
        server: &str,
        uid: &str,
        recovery_key: &str,
        device_label: &str,
    ) -> Result<OwnIdentity> {
        let _ = (server, uid, recovery_key, device_label);
        not_implemented("recover")
    }

    /// The safety number of `uid` (12.14).
    pub fn safety_number(&self, uid: &str) -> Result<SafetyNumber> {
        let _ = uid;
        not_implemented("safety_number")
    }

    /// Marks `uid` as verified, from the QR text of its safety number
    /// scanned from the other person's device (12.14), or after comparing
    /// the digits when `qr` is `None`.
    pub fn mark_verified(&self, uid: &str, qr: Option<&str>) -> Result<()> {
        let _ = (uid, qr);
        not_implemented("mark_verified")
    }

    /// Acknowledges a new master key of `uid` (4.5, 12.14), so that
    /// sending starts again.
    pub fn acknowledge_new_master_key(&self, uid: &str) -> Result<()> {
        let _ = uid;
        not_implemented("acknowledge_new_master_key")
    }

    /// Deletes everything the server keeps about the account's identity
    /// (4.9).
    pub async fn unregister(&self, account: AccountId) -> Result<()> {
        let _ = account;
        not_implemented("unregister")
    }

    /// The witness policy (4.5): the witnesses' verifier keys, and k.
    pub fn witness_policy(&self) -> Result<(Vec<String>, usize)> {
        not_implemented("witness_policy")
    }

    /// Sets the witness policy (4.5).
    pub fn set_witness_policy(&self, witnesses: &[String], k: usize) -> Result<()> {
        let _ = (witnesses, k);
        not_implemented("set_witness_policy")
    }

    /// How the account's signed-in connection signs in: AUTH with this
    /// device's key for the identity (4.6), for the driver.
    pub(crate) async fn identity_sign_in(&self, account: AccountId) -> Result<Arc<dyn Establish>> {
        let _ = account;
        not_implemented("identity_sign_in")
    }
}
