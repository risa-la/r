//! Epochal confirmation (12.10): period keys, their certificates, ATTEST
//! and REVEAL.
//!
//! **This construction is new and has not been reviewed.** It is an
//! instance of Hülsing and Weber's epochal signatures (EPOCHAL, SPEC
//! 16), built simply, by publishing each day's key once the day is over.
//! It needs a review by cryptographers, and a formal model, before it is
//! relied on (PLAN.md item 53, SPEC 12.10 and Section 14). Until then,
//! treat what it confirms as best effort.
//!
//! What it does, in short:
//!
//! - A **period** is a UTC day, numbered from 1970-01-01 as 0
//!   ([`period_of`]).
//! - For each period in which it sends in an epochal group, a device has
//!   an ML-DSA-44 **period key**, certified by its device key:
//!   RisalaSign(device key, "period", [`PeriodCert`]). The certificate
//!   says only that the key is the device's for that period, and names no
//!   group, leaf or message.
//! - The period keys' seeds form a chain of up to [`CHAIN_LEN`] periods,
//!   made in advance: the last period's seed is random, and each earlier
//!   one is [`previous_seed`] of the one after it. [`PeriodKeyring`] holds
//!   a device's chains.
//! - In its first message with a leaf key of the period, a device sends
//!   `ATTEST`, whose attestation is RisalaSign(period key, "attest",
//!   [`AttestContent`]): the group, the period and the hash of the leaf's
//!   signature key. [`check_attest`] says whether one is valid.
//! - From [`REVEAL_DELAY_MS`] after the period ends, the device publishes
//!   the period key's seed with `REVEAL`. From then on anyone could have
//!   made the attestation, so the messages are deniable.
//!   [`RevealRegistry`] remembers the seeds a device has seen, since an
//!   ATTEST whose key has been revealed proves nothing.
//!
//! The state machine that uses these, per group, is
//! [`crate::confirm::Confirmer`].

use std::collections::BTreeMap;

use risala_proto::auth::{PublicKey, Signature};
use risala_proto::content::{ContentLine, PeriodSeed};
use risala_proto::time::Timestamp;
use zeroize::{Zeroize as _, Zeroizing};

use crate::aad::Pseudonym;
use crate::codec::Writer;
use crate::identity::{DeviceId, RisalaIdentity};
use crate::mldsa::{PUBLIC_KEY_LEN, SEED_LEN, SIGNATURE_LEN, SigningKey};
use crate::primitives::{HASH_LEN, hkdf_expand, hkdf_extract, sha384};
use crate::risala_sign::{risala_sign, risala_verify};

/// The length of a period: one UTC day, in milliseconds (12.10).
pub const PERIOD_MS: u64 = 86_400_000;

/// The grace hour after a period, in which its ATTESTs are still valid and
/// accepted (12.10).
pub const GRACE_MS: u64 = 3_600_000;

/// How long after the end of a period its REVEAL may be sent at the
/// earliest: 3 hours, the grace hour and two more for clocks that are off
/// by up to an hour each (12.10, D.4).
pub const REVEAL_DELAY_MS: u64 = 3 * 3_600_000;

/// Within how long of becoming due a REVEAL is sent, in a message of its
/// own if the device sends none in the group (12.10: "within a day").
pub const REVEAL_WITHIN_MS: u64 = 86_400_000;

/// The most periods one chain of seeds covers (12.10).
pub const CHAIN_LEN: u32 = 90;

/// A device that sent in a group in the period before proposes its new
/// leaf at a random time in the first 12 hours of the period (12.10).
pub const ROTATE_WITHIN_MS: u64 = 12 * 3_600_000;

/// The RisalaSign label of a PeriodCert (12.10, 15).
pub const PERIOD_LABEL: &str = "period";

/// The RisalaSign label of an AttestContent (12.10, 15).
pub const ATTEST_LABEL: &str = "attest";

/// The HKDF label of the chain of seeds (12.10, 15).
pub const SEED_LABEL: &[u8] = b"risala/1 period seed";

// ---------------------------------------------------------------------------
// Periods

/// The period of `t`: floor(ms since 1970-01-01T00:00:00Z / 86400000).
pub fn period_of(t: Timestamp) -> u32 {
    period_of_ms(t.unix_millis())
}

/// [`period_of`] for milliseconds. Timestamps end in the year 9999, so the
/// period always fits a `u32`.
pub(crate) fn period_of_ms(ms: u64) -> u32 {
    u32::try_from(ms / PERIOD_MS).unwrap_or(u32::MAX)
}

/// When period `p` starts, in ms since 1970.
pub fn period_start(p: u32) -> u64 {
    u64::from(p) * PERIOD_MS
}

/// When period `p` ends, in ms since 1970: the start of the next one.
pub fn period_end(p: u32) -> u64 {
    period_start(p) + PERIOD_MS
}

/// When the grace hour after period `p` ends.
pub fn grace_end(p: u32) -> u64 {
    period_end(p) + GRACE_MS
}

/// The earliest time a REVEAL of period `p` may be sent (12.10).
pub fn reveal_from(p: u32) -> u64 {
    period_end(p) + REVEAL_DELAY_MS
}

/// Whether `ms` falls within period `p` or its grace hour: the rule for
/// the `t` of a post that carries an ATTEST, and, by the device's own
/// clock, for accepting one (12.10).
pub fn within_period_or_grace(p: u32, ms: u64) -> bool {
    (period_start(p)..grace_end(p)).contains(&ms)
}

// ---------------------------------------------------------------------------
// The chain of seeds

/// The seed of the period before: HKDF-Expand(HKDF-Extract("", seed),
/// "risala/1 period seed", 32) with SHA-384 (12.10).
pub fn previous_seed(seed: &[u8; SEED_LEN]) -> Zeroizing<[u8; SEED_LEN]> {
    let prk = hkdf_extract(b"", seed);
    let mut out = Zeroizing::new([0; SEED_LEN]);
    hkdf_expand(&prk[..], SEED_LABEL, &mut out[..]);
    out
}

/// The seed `steps` periods before the one whose seed is `seed`.
pub fn seed_before(seed: &[u8; SEED_LEN], steps: u32) -> Zeroizing<[u8; SEED_LEN]> {
    let mut current = Zeroizing::new(*seed);
    for _ in 0..steps {
        current = previous_seed(&current);
    }
    current
}

/// Whether `seed`, the seed of period `seed_period`, derives the period
/// key `period_key` of period `period`, directly or through the chain
/// (12.10). A chain covers at most [`CHAIN_LEN`] periods, so a seed never
/// derives a key more than that many periods before it.
pub fn seed_derives(
    seed: &[u8; SEED_LEN],
    seed_period: u32,
    period: u32,
    period_key: &[u8],
) -> bool {
    let Some(steps) = seed_period.checked_sub(period) else {
        return false;
    };
    if steps >= CHAIN_LEN {
        return false;
    }
    let derived = seed_before(seed, steps);
    SigningKey::from_seed(*derived).public_key()[..] == *period_key
}

// ---------------------------------------------------------------------------
// PeriodCert and AttestContent

/// A PeriodCert (12.10): what a device key signs to certify a period key.
///
/// ```text
/// struct {
///     uint8 version;               // 1
///     opaque uid<V>;
///     opaque device_id[48];
///     uint32 period;
///     opaque period_key<V>;        // ML-DSA-44 public key
/// } PeriodCert;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeriodCert<'a> {
    /// The device's uid.
    pub uid: &'a str,
    /// The device's id.
    pub device_id: &'a DeviceId,
    /// The period.
    pub period: u32,
    /// The period key, a raw ML-DSA-44 public key.
    pub period_key: &'a [u8],
}

impl PeriodCert<'_> {
    /// The encoded PeriodCert.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(1)
            .vector(self.uid.as_bytes())
            .fixed(self.device_id.as_bytes())
            .fixed(&self.period.to_be_bytes())
            .vector(self.period_key);
        w.into_bytes()
    }

    /// RisalaSign(device key, "period", PeriodCert).
    pub fn sign(&self, device_key: &SigningKey) -> Box<[u8; SIGNATURE_LEN]> {
        risala_sign(device_key, PERIOD_LABEL, &self.encode())
    }

    /// Whether `signature` is this certificate's, by the device key whose
    /// raw public key is `device_key`.
    pub fn verify(&self, device_key: &[u8], signature: &[u8]) -> bool {
        risala_verify(device_key, PERIOD_LABEL, &self.encode(), signature)
    }
}

/// An AttestContent (12.10): what a period key signs to attest a leaf.
///
/// ```text
/// struct {
///     uint8 version;               // 1
///     opaque group_id<V>;
///     uint32 period;
///     opaque leaf_key_hash[48];    // SHA-384 of the leaf's signature key
/// } AttestContent;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestContent<'a> {
    /// The group's id.
    pub group_id: &'a [u8],
    /// The period.
    pub period: u32,
    /// SHA-384 of the leaf's raw signature key.
    pub leaf_key_hash: [u8; HASH_LEN],
}

impl AttestContent<'_> {
    /// The encoded AttestContent.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(1)
            .vector(self.group_id)
            .fixed(&self.period.to_be_bytes())
            .fixed(&self.leaf_key_hash);
        w.into_bytes()
    }

    /// RisalaSign(period key, "attest", AttestContent).
    pub fn sign(&self, period_key: &SigningKey) -> Box<[u8; SIGNATURE_LEN]> {
        risala_sign(period_key, ATTEST_LABEL, &self.encode())
    }

    /// Whether `signature` is this content's, by the period key whose raw
    /// public key is `period_key`.
    pub fn verify(&self, period_key: &[u8], signature: &[u8]) -> bool {
        risala_verify(period_key, ATTEST_LABEL, &self.encode(), signature)
    }
}

// ---------------------------------------------------------------------------
// Checking an ATTEST

/// The fields of an `ATTEST` line (12.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attest {
    /// The period.
    pub period: u32,
    /// The period key, raw ML-DSA-44.
    pub period_key: Box<[u8; PUBLIC_KEY_LEN]>,
    /// The PeriodCert's signature by the device key.
    pub certificate: Box<[u8; SIGNATURE_LEN]>,
    /// The AttestContent's signature by the period key.
    pub attestation: Box<[u8; SIGNATURE_LEN]>,
    /// The leaf's pseudonym for the period (7.3).
    pub pseudonym: Pseudonym,
}

impl Attest {
    /// The fields of `line`, if it is an ATTEST.
    pub fn from_line(line: &ContentLine) -> Option<Attest> {
        match line {
            ContentLine::Attest {
                period,
                period_key,
                certificate,
                attestation,
                pseudonym,
            } => Some(Attest {
                period: *period,
                period_key: Box::new(*period_key.as_bytes()),
                certificate: Box::new(*certificate.as_bytes()),
                attestation: Box::new(*attestation.as_bytes()),
                pseudonym: Pseudonym(*pseudonym.as_bytes()),
            }),
            _ => None,
        }
    }

    /// The `ATTEST` line.
    pub fn to_line(&self) -> ContentLine {
        ContentLine::Attest {
            period: self.period,
            period_key: PublicKey::from_bytes(&self.period_key),
            certificate: Signature::from_bytes(&self.certificate),
            attestation: Signature::from_bytes(&self.attestation),
            pseudonym: risala_proto::mls::Pseudonym::from_bytes(self.pseudonym.0),
        }
    }
}

/// Why an ATTEST line is not valid, or not accepted (12.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AttestError {
    /// The leaf is a guest's, which has no device to attest it.
    #[error("guests do not attest")]
    Guest,
    /// The certificate does not verify under the device key.
    #[error("the period certificate does not verify")]
    Certificate,
    /// The attestation does not verify under the period key, or names
    /// another group, period or leaf key.
    #[error("the attestation does not verify")]
    Attestation,
    /// The `t` of the post that carries it is outside the period and its
    /// grace hour.
    #[error("the post is outside the period")]
    OutsidePeriod,
    /// Its pseudonym is not the one in the message's RisalaAAD (7.3), or
    /// the message has none.
    #[error("the pseudonym is not the message's")]
    Pseudonym,
    /// A REVEAL by that device has already published the period key.
    #[error("the period key has been revealed")]
    Revealed,
    /// It is valid, but by this device's clock its period is neither the
    /// current one nor the one before within its grace hour, so it no
    /// longer convinces anyone (12.10).
    #[error("the period is over")]
    Late,
    /// The credential names a device that is not a current, logged device
    /// of its identity (4.5).
    #[error("the device is not a current device of the identity")]
    DeviceNotCurrent,
}

/// What [`check_attest`] needs besides the line.
#[derive(Debug, Clone, Copy)]
pub struct AttestCheck<'a> {
    /// The group's id.
    pub group_id: &'a [u8],
    /// The credential of the leaf that sent the line.
    pub identity: &'a RisalaIdentity,
    /// The raw device key of the device that the credential names, a
    /// current, logged device of its identity (4.5).
    pub device_key: &'a [u8],
    /// The leaf's raw signature key.
    pub leaf_key: &'a [u8],
    /// The `t` of the post that carries the line.
    pub post_t: Timestamp,
    /// The pseudonym in the message's RisalaAAD, if it has one.
    pub message_pseudonym: Option<Pseudonym>,
    /// The device's clock, as it processes the line.
    pub now: Timestamp,
}

/// Checks an ATTEST line (12.10): it is **valid** if the certificate
/// verifies under the device key, the attestation under the period key
/// for this group, period and leaf key, the post's `t` is within the
/// period or its grace hour, its pseudonym is the message's, and no REVEAL
/// seen so far derives the period key. A valid line is **accepted** if, by
/// the device's own clock, the period is the current one or the one before
/// within its grace hour.
pub fn check_attest(
    attest: &Attest,
    check: &AttestCheck<'_>,
    reveals: &RevealRegistry,
) -> Result<(), AttestError> {
    let Some(device_id) = &check.identity.device_id else {
        return Err(AttestError::Guest);
    };
    let cert = PeriodCert {
        uid: check.identity.uid.as_str(),
        device_id,
        period: attest.period,
        period_key: &attest.period_key[..],
    };
    if !cert.verify(check.device_key, &attest.certificate[..]) {
        return Err(AttestError::Certificate);
    }
    let content = AttestContent {
        group_id: check.group_id,
        period: attest.period,
        leaf_key_hash: sha384(check.leaf_key),
    };
    if !content.verify(&attest.period_key[..], &attest.attestation[..]) {
        return Err(AttestError::Attestation);
    }
    if !within_period_or_grace(attest.period, check.post_t.unix_millis()) {
        return Err(AttestError::OutsidePeriod);
    }
    if check.message_pseudonym != Some(attest.pseudonym) {
        return Err(AttestError::Pseudonym);
    }
    if reveals.derives(check.identity, attest.period, &attest.period_key[..]) {
        return Err(AttestError::Revealed);
    }
    if !within_period_or_grace(attest.period, check.now.unix_millis()) {
        return Err(AttestError::Late);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// A device's own period keys

/// A 32-byte seed that is wiped when dropped. Serialised as its bytes, for
/// the device's store, which must keep it secret.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct Seed(pub(crate) [u8; SEED_LEN]);

impl Drop for Seed {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for Seed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Seed(…)")
    }
}

/// One chain of seeds: periods `first` to `last`, and the seed of `last`,
/// from which the others derive.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Chain {
    first: u32,
    last: u32,
    last_seed: Seed,
}

impl Chain {
    fn covers(&self, period: u32) -> bool {
        (self.first..=self.last).contains(&period)
    }

    fn seed(&self, period: u32) -> Option<Zeroizing<[u8; SEED_LEN]>> {
        self.covers(period)
            .then(|| seed_before(&self.last_seed.0, self.last - period))
    }
}

/// Why the keyring cannot give a period key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KeyringError {
    /// The period is before every chain the keyring holds, so its key can
    /// no longer be made. Keys are only made for the current period.
    #[error("no chain covers the period")]
    NoChain,
    /// The operating system had no randomness for a new chain.
    #[error("no randomness for a new chain of period seeds")]
    Random,
}

/// A device's period keys (12.10): its chains of seeds, and the
/// certificates it has made, one per period. One keyring serves all of the
/// device's epochal groups, since one period key does.
///
/// It holds secrets: the device stores it as it stores its other keys
/// (serialised with serde), and keeps it on this device only.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct PeriodKeyring {
    chains: Vec<Chain>,
    /// Certificates by period, each a RisalaSign signature.
    certificates: BTreeMap<u32, Vec<u8>>,
}

impl PeriodKeyring {
    /// An empty keyring.
    pub fn new() -> PeriodKeyring {
        PeriodKeyring::default()
    }

    /// The seed of `period`, if a chain covers it.
    pub fn seed(&self, period: u32) -> Option<Zeroizing<[u8; SEED_LEN]>> {
        self.chains.iter().find_map(|c| c.seed(period))
    }

    /// The first period of the chain that covers `period`, which names the
    /// chain.
    pub fn chain_of(&self, period: u32) -> Option<u32> {
        self.chains
            .iter()
            .find(|c| c.covers(period))
            .map(|c| c.first)
    }

    /// Starts a chain at `period`, with the seed of its last period. Only
    /// for test vectors and tests: [`PeriodKeyring::key`] starts chains
    /// with random seeds.
    pub fn start_chain_with(&mut self, period: u32, last_seed: [u8; SEED_LEN]) {
        self.chains.push(Chain {
            first: period,
            last: period.saturating_add(CHAIN_LEN - 1),
            last_seed: Seed(last_seed),
        });
    }

    /// The period key of `period`. If no chain covers it and it is after
    /// every chain, starts a new chain of [`CHAIN_LEN`] periods there, with
    /// a random seed for its last period (12.10).
    pub fn key(&mut self, period: u32) -> Result<SigningKey, KeyringError> {
        if let Some(seed) = self.seed(period) {
            return Ok(SigningKey::from_seed(*seed));
        }
        if self.chains.iter().any(|c| c.last >= period) {
            return Err(KeyringError::NoChain);
        }
        let mut last_seed = Seed([0; SEED_LEN]);
        getrandom::fill(&mut last_seed.0).map_err(|_| KeyringError::Random)?;
        self.chains.push(Chain {
            first: period,
            last: period.saturating_add(CHAIN_LEN - 1),
            last_seed,
        });
        let seed = self.seed(period).expect("the new chain covers the period");
        Ok(SigningKey::from_seed(*seed))
    }

    /// The certificate of `period`'s key, made once with `device_key` and
    /// kept for the period's other groups.
    pub fn certificate(
        &mut self,
        device_key: &SigningKey,
        identity: &RisalaIdentity,
        period: u32,
    ) -> Result<Box<[u8; SIGNATURE_LEN]>, KeyringError> {
        let key = self.key(period)?;
        if let Some(cert) = self.certificates.get(&period)
            && let Ok(cert) = <[u8; SIGNATURE_LEN]>::try_from(&cert[..])
        {
            return Ok(Box::new(cert));
        }
        let device_id = identity.device_id.as_ref().ok_or(KeyringError::NoChain)?;
        let cert = PeriodCert {
            uid: identity.uid.as_str(),
            device_id,
            period,
            period_key: key.public_key(),
        }
        .sign(device_key);
        self.certificates.insert(period, cert.to_vec());
        Ok(cert)
    }

    /// The ATTEST line of `period` for a leaf whose signature key is
    /// `leaf_key` in group `group_id`, under the leaf's pseudonym for the
    /// period (12.10, 7.3). `identity` is the device's own.
    pub fn attest(
        &mut self,
        device_key: &SigningKey,
        identity: &RisalaIdentity,
        group_id: &[u8],
        period: u32,
        leaf_key: &[u8],
        pseudonym: Pseudonym,
    ) -> Result<Attest, KeyringError> {
        let certificate = self.certificate(device_key, identity, period)?;
        let key = self.key(period)?;
        let attestation = AttestContent {
            group_id,
            period,
            leaf_key_hash: sha384(leaf_key),
        }
        .sign(&key);
        Ok(Attest {
            period,
            period_key: Box::new(*key.public_key()),
            certificate,
            attestation,
            pseudonym,
        })
    }

    /// The REVEAL line of `period`, if a chain still covers it.
    pub fn reveal(&self, period: u32) -> Option<ContentLine> {
        let seed = self.seed(period)?;
        Some(ContentLine::Reveal {
            period,
            seed: PeriodSeed::from_bytes(*seed),
        })
    }

    /// Forgets chains whose every period ended more than `keep_days` days
    /// before `now`, and certificates of periods before the oldest chain
    /// left. A device keeps a chain until its REVEALs have gone out in
    /// every group, which is a day and 3 hours after its last period at
    /// most; `keep_days` gives it longer, for devices that were offline.
    pub fn prune(&mut self, now: Timestamp, keep_days: u32) {
        let current = period_of(now);
        self.chains
            .retain(|c| c.last.saturating_add(keep_days) >= current);
        let oldest = self.chains.iter().map(|c| c.first).min();
        self.certificates
            .retain(|&p, _| oldest.is_some_and(|first| p >= first));
    }
}

// ---------------------------------------------------------------------------
// REVEALs seen from others

/// The most REVEALs kept for one device. A device sends at most one per
/// group and period, and they matter only for the current period and the
/// one before (see [`RevealRegistry::prune`]).
pub const MAX_REVEALS_PER_DEVICE: usize = 8;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Revealed {
    period: u32,
    seed: [u8; SEED_LEN],
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct DeviceReveals {
    /// The encoded RisalaIdentity of the device.
    identity: Vec<u8>,
    reveals: Vec<Revealed>,
}

/// The REVEALs a device has seen from other devices, in any group (12.10):
/// an ATTEST whose period key one of them derives is not valid, since one
/// period key serves all of a device's epochal groups.
///
/// One registry serves all of the device's groups. It holds only seeds
/// that are public by design.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct RevealRegistry {
    devices: Vec<DeviceReveals>,
}

impl RevealRegistry {
    /// An empty registry.
    pub fn new() -> RevealRegistry {
        RevealRegistry::default()
    }

    /// Records a REVEAL of `period` with `seed`, sent by a leaf whose
    /// credential is `identity`. Keeps the newest
    /// [`MAX_REVEALS_PER_DEVICE`] periods for each device.
    pub fn record(&mut self, identity: &RisalaIdentity, period: u32, seed: &[u8; SEED_LEN]) {
        if identity.is_guest() {
            return;
        }
        let encoded = identity.encode();
        let index = match self.devices.iter().position(|d| d.identity == encoded) {
            Some(i) => i,
            None => {
                self.devices.push(DeviceReveals {
                    identity: encoded,
                    reveals: Vec::new(),
                });
                self.devices.len() - 1
            }
        };
        let reveals = &mut self.devices[index].reveals;
        if reveals
            .iter()
            .any(|r| r.period == period && r.seed == *seed)
        {
            return;
        }
        reveals.push(Revealed {
            period,
            seed: *seed,
        });
        reveals.sort_by_key(|r| std::cmp::Reverse(r.period));
        reveals.truncate(MAX_REVEALS_PER_DEVICE);
    }

    /// Whether a REVEAL seen from the device of `identity` derives
    /// `period_key` as the key of `period`, directly or through the chain.
    pub fn derives(&self, identity: &RisalaIdentity, period: u32, period_key: &[u8]) -> bool {
        let encoded = identity.encode();
        self.devices
            .iter()
            .filter(|d| d.identity == encoded)
            .flat_map(|d| &d.reveals)
            .any(|r| seed_derives(&r.seed, r.period, period, period_key))
    }

    /// Forgets REVEALs that can no longer matter: an ATTEST is accepted
    /// only for the current period or the one before (12.10), and a seed
    /// derives only its own period and earlier ones, so a REVEAL of a
    /// period before the one before `now` derives no key that could still
    /// be accepted.
    pub fn prune(&mut self, now: Timestamp) {
        let oldest = period_of(now).saturating_sub(1);
        for device in &mut self.devices {
            device.reveals.retain(|r| r.period >= oldest);
        }
        self.devices.retain(|d| !d.reveals.is_empty());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::tests::hex;

    fn uid(s: &str) -> risala_proto::names::Uid {
        s.parse().unwrap()
    }

    fn device(seed: u8) -> (SigningKey, RisalaIdentity) {
        let key = SigningKey::from_seed([seed; 32]);
        let identity = RisalaIdentity::device(
            uid("alice@example.org"),
            DeviceId::of_device_key(key.public_key()),
        );
        (key, identity)
    }

    fn at(ms: u64) -> Timestamp {
        Timestamp::from_unix_millis(ms).unwrap()
    }

    #[test]
    fn periods() {
        assert_eq!(period_of(at(0)), 0);
        assert_eq!(period_of(at(PERIOD_MS - 1)), 0);
        assert_eq!(period_of(at(PERIOD_MS)), 1);
        // 2026-11-09T12:00:00Z is day 20766.
        assert_eq!(period_of(at(1_794_225_600_000)), 20766);
        assert_eq!(period_of(Timestamp::MAX), 2_932_896);
        assert_eq!(period_start(20766), 1_794_182_400_000);
        assert_eq!(period_end(20766), 1_794_268_800_000);
        assert_eq!(grace_end(20766), 1_794_272_400_000);
        assert_eq!(reveal_from(20766), 1_794_279_600_000);
        assert!(!within_period_or_grace(1, PERIOD_MS - 1));
        assert!(within_period_or_grace(1, PERIOD_MS));
        assert!(within_period_or_grace(1, 2 * PERIOD_MS + GRACE_MS - 1));
        assert!(!within_period_or_grace(1, 2 * PERIOD_MS + GRACE_MS));
    }

    #[test]
    fn seed_chain() {
        let last = [7; 32];
        let one = previous_seed(&last);
        // HKDF-Expand for one block is HMAC(PRK, info || 1).
        let prk = hkdf_extract(b"", &last);
        let block = crate::primitives::hmac_sha384(&prk[..], b"risala/1 period seed\x01");
        assert_eq!(one[..], block[..32]);
        assert_eq!(*seed_before(&last, 0), last);
        assert_eq!(*seed_before(&last, 2), *previous_seed(&one));

        let key5 = SigningKey::from_seed(*seed_before(&last, 5));
        assert!(seed_derives(&last, 100, 95, key5.public_key()));
        assert!(!seed_derives(&last, 100, 96, key5.public_key()));
        // A seed does not derive later periods, nor beyond its chain.
        assert!(!seed_derives(
            &one,
            99,
            100,
            SigningKey::from_seed(last).public_key()
        ));
        let far = SigningKey::from_seed(*seed_before(&last, CHAIN_LEN));
        assert!(!seed_derives(&last, 200, 200 - CHAIN_LEN, far.public_key()));
        let edge = SigningKey::from_seed(*seed_before(&last, CHAIN_LEN - 1));
        assert!(seed_derives(&last, 200, 201 - CHAIN_LEN, edge.public_key()));
    }

    #[test]
    fn keyring_chains() {
        let mut ring = PeriodKeyring::new();
        let k10 = ring.key(10).unwrap();
        assert_eq!(ring.chain_of(10), Some(10));
        assert_eq!(ring.chain_of(99), Some(10));
        assert_eq!(ring.chain_of(100), None);
        // Later keys of the chain derive the earlier ones.
        let s50 = ring.seed(50).unwrap();
        assert!(seed_derives(&s50, 50, 10, k10.public_key()));
        // The next chain starts after the last one, independently.
        let k100 = ring.key(100).unwrap();
        assert_eq!(ring.chain_of(100), Some(100));
        assert!(!seed_derives(
            &ring.seed(100).unwrap(),
            100,
            99,
            ring.key(99).unwrap().public_key()
        ));
        assert_eq!(ring.key(100).unwrap().public_key(), k100.public_key());
        // No keys for a past period no chain covers.
        let mut ring2 = PeriodKeyring::new();
        ring2.key(20).unwrap();
        assert_eq!(ring2.key(5).unwrap_err(), KeyringError::NoChain);
        // The keyring survives serialisation, keys and all.
        let json = serde_json::to_string(&ring).unwrap();
        let back: PeriodKeyring = serde_json::from_str(&json).unwrap();
        assert_eq!(back.seed(42).unwrap(), ring.seed(42).unwrap());
        // Pruning forgets old chains.
        ring.prune(at(period_start(100 + CHAIN_LEN + 5)), 7);
        assert_eq!(ring.chain_of(10), None);
        assert_eq!(ring.chain_of(150), Some(100));
        assert_eq!(format!("{:?}", Seed([1; 32])), "Seed(…)");
    }

    #[test]
    fn attest_checks() {
        let (device_key, identity) = device(1);
        let group = b"group id";
        let leaf = SigningKey::from_seed([3; 32]);
        let pseudonym = Pseudonym([9; 16]);
        let period = 20766;
        let mut ring = PeriodKeyring::new();
        let attest = ring
            .attest(
                &device_key,
                &identity,
                group,
                period,
                leaf.public_key(),
                pseudonym,
            )
            .unwrap();
        // The line round-trips through the content line.
        let line = attest.to_line();
        assert_eq!(Attest::from_line(&line).unwrap(), attest);
        let parsed: ContentLine = line.to_line().unwrap().parse().unwrap();
        assert_eq!(Attest::from_line(&parsed).unwrap(), attest);

        let reveals = RevealRegistry::new();
        let noon = at(period_start(period) + PERIOD_MS / 2);
        let check = AttestCheck {
            group_id: group,
            identity: &identity,
            device_key: device_key.public_key(),
            leaf_key: leaf.public_key(),
            post_t: noon,
            message_pseudonym: Some(pseudonym),
            now: noon,
        };
        assert_eq!(check_attest(&attest, &check, &reveals), Ok(()));

        let other_device = SigningKey::from_seed([2; 32]);
        let bad = |c: AttestCheck<'_>| check_attest(&attest, &c, &reveals);
        assert_eq!(
            bad(AttestCheck {
                device_key: other_device.public_key(),
                ..check
            }),
            Err(AttestError::Certificate)
        );
        // Another group or leaf key: the attestation does not verify.
        assert_eq!(
            bad(AttestCheck {
                group_id: b"other",
                ..check
            }),
            Err(AttestError::Attestation)
        );
        let other_leaf = SigningKey::from_seed([4; 32]);
        assert_eq!(
            bad(AttestCheck {
                leaf_key: other_leaf.public_key(),
                ..check
            }),
            Err(AttestError::Attestation)
        );
        // Another uid in the credential: the certificate names this one.
        let bob = RisalaIdentity::device(uid("bob@example.org"), identity.device_id.unwrap());
        assert_eq!(
            bad(AttestCheck {
                identity: &bob,
                ..check
            }),
            Err(AttestError::Certificate)
        );
        let guest = RisalaIdentity::guest("~guest1".parse().unwrap());
        assert_eq!(
            bad(AttestCheck {
                identity: &guest,
                ..check
            }),
            Err(AttestError::Guest)
        );
        // The post's t: within the period or its grace hour.
        let edge = at(grace_end(period) - 1);
        assert_eq!(
            bad(AttestCheck {
                post_t: edge,
                now: edge,
                ..check
            }),
            Ok(())
        );
        let after = at(grace_end(period));
        assert_eq!(
            bad(AttestCheck {
                post_t: after,
                ..check
            }),
            Err(AttestError::OutsidePeriod)
        );
        let before = at(period_start(period) - 1);
        assert_eq!(
            bad(AttestCheck {
                post_t: before,
                ..check
            }),
            Err(AttestError::OutsidePeriod)
        );
        // The pseudonym must be the message's.
        assert_eq!(
            bad(AttestCheck {
                message_pseudonym: Some(Pseudonym([8; 16])),
                ..check
            }),
            Err(AttestError::Pseudonym)
        );
        assert_eq!(
            bad(AttestCheck {
                message_pseudonym: None,
                ..check
            }),
            Err(AttestError::Pseudonym)
        );
        // A late attestation, by this device's clock, is not accepted.
        assert_eq!(
            bad(AttestCheck {
                now: after,
                ..check
            }),
            Err(AttestError::Late)
        );

        // Once the period's key is revealed, directly or by a later seed of
        // the chain, the ATTEST is not valid.
        let mut seen = RevealRegistry::new();
        seen.record(&identity, period + 3, &ring.seed(period + 3).unwrap());
        assert_eq!(
            check_attest(&attest, &check, &seen),
            Err(AttestError::Revealed)
        );
        // A seed of an earlier period does not reveal it.
        let mut seen = RevealRegistry::new();
        seen.record(
            &identity,
            period - 1,
            &previous_seed(&ring.seed(period).unwrap()),
        );
        assert_eq!(check_attest(&attest, &check, &seen), Ok(()));
        // Nor does another device's REVEAL.
        let mut seen = RevealRegistry::new();
        let (_, other) = device(5);
        seen.record(&other, period, &ring.seed(period).unwrap());
        assert_eq!(check_attest(&attest, &check, &seen), Ok(()));
    }

    #[test]
    fn reveal_registry() {
        let (_, identity) = device(1);
        let mut ring = PeriodKeyring::new();
        let key = ring.key(10).unwrap();
        let mut seen = RevealRegistry::new();
        for p in 10..30 {
            seen.record(&identity, p, &[p as u8; 32]);
        }
        seen.record(&identity, 40, &ring.seed(40).unwrap());
        assert!(seen.derives(&identity, 10, key.public_key()));
        // Only the newest are kept.
        assert_eq!(seen.devices[0].reveals.len(), MAX_REVEALS_PER_DEVICE);
        assert_eq!(seen.devices[0].reveals[0].period, 40);
        let json = serde_json::to_string(&seen).unwrap();
        let back: RevealRegistry = serde_json::from_str(&json).unwrap();
        assert!(back.derives(&identity, 10, key.public_key()));
        seen.prune(at(period_start(41)));
        assert!(seen.derives(&identity, 10, key.public_key()));
        seen.prune(at(period_start(42)));
        assert!(seen.devices.is_empty());
    }

    /// Test vectors for Appendix B (task V1): a chain of seeds, a
    /// PeriodCert and an AttestContent with deterministic ML-DSA-44
    /// signatures (randomness of zero bytes), and a REVEAL. Run with
    /// `--nocapture` to print them.
    #[test]
    fn vectors() {
        use crate::risala_sign::sign_content;
        use libcrux_ml_dsa::ml_dsa_44 as mldsa;

        let det_sign = |seed: [u8; 32], label: &str, content: &[u8]| -> Vec<u8> {
            let pair = mldsa::generate_key_pair(seed);
            mldsa::sign(
                &pair.signing_key,
                &sign_content(label, content),
                b"",
                [0; 32],
            )
            .unwrap()
            .as_ref()
            .to_vec()
        };

        let device_seed = [0x11; 32];
        let device_key = SigningKey::from_seed(device_seed);
        let device_id = DeviceId::of_device_key(device_key.public_key());
        let last_seed = [0x22; 32];
        // A chain from period 20766 (2026-11-09) to 20855.
        let mut ring = PeriodKeyring::new();
        ring.start_chain_with(20766, last_seed);
        let period = 20767;
        let seed = ring.seed(period).unwrap();
        let period_key = SigningKey::from_seed(*seed);
        assert_eq!(*seed, *seed_before(&last_seed, 20855 - period));

        let cert = PeriodCert {
            uid: "alice@example.org",
            device_id: &device_id,
            period,
            period_key: period_key.public_key(),
        };
        let cert_bytes = cert.encode();
        let cert_sig = det_sign(device_seed, PERIOD_LABEL, &cert_bytes);
        assert!(cert.verify(device_key.public_key(), &cert_sig));

        let group_id = [0x33; 32];
        let leaf = SigningKey::from_seed([0x44; 32]);
        let content = AttestContent {
            group_id: &group_id,
            period,
            leaf_key_hash: sha384(leaf.public_key()),
        };
        let content_bytes = content.encode();
        let attest_sig = det_sign(*seed, ATTEST_LABEL, &content_bytes);
        assert!(content.verify(period_key.public_key(), &attest_sig));

        // The encodings, byte by byte.
        assert_eq!(cert_bytes[0], 1);
        assert_eq!(&cert_bytes[1..19], b"\x11alice@example.org");
        assert_eq!(&cert_bytes[19..67], device_id.as_bytes());
        assert_eq!(&cert_bytes[67..71], &period.to_be_bytes());
        assert_eq!(&cert_bytes[71..73], &[0x45, 0x20]); // 1312 as a varint
        assert_eq!(&cert_bytes[73..], period_key.public_key());
        assert_eq!(content_bytes.len(), 1 + 1 + 32 + 4 + 48);

        // Pinned, so that a change to any of these shows.
        assert_eq!(
            hex(&previous_seed(&last_seed)[..]),
            "4a7b3211acefd7c6e104a416d9c67c77673ad901f62703191fcbe62f88304252"
        );
        let reveal = ring.reveal(period).unwrap().to_line().unwrap();

        println!("== period seeds (12.10)");
        println!("last period 20855, seed(20855) = {}", hex(&last_seed));
        println!("seed(20854) = {}", hex(&previous_seed(&last_seed)[..]));
        println!("seed({period}) = {}", hex(&seed[..]));
        println!("period key ({period}) = {}", hex(period_key.public_key()));
        println!("period of 2026-11-09T12:00:00Z (1794225600000) = 20766");
        println!("== PeriodCert");
        println!("device key seed = {}", hex(&device_seed));
        println!("device key = {}", hex(device_key.public_key()));
        println!("device id = {}", hex(device_id.as_bytes()));
        println!("PeriodCert = {}", hex(&cert_bytes));
        println!(
            "RisalaSignContent = {}",
            hex(&sign_content(PERIOD_LABEL, &cert_bytes))
        );
        println!("certificate (deterministic) = {}", hex(&cert_sig));
        println!("== AttestContent");
        println!("group id = {}", hex(&group_id));
        println!("leaf key seed = {}", hex(&[0x44; 32]));
        println!("leaf key hash = {}", hex(&sha384(leaf.public_key())));
        println!("AttestContent = {}", hex(&content_bytes));
        println!("attestation (deterministic) = {}", hex(&attest_sig));
        println!("== REVEAL");
        println!("{reveal}");
        println!("sha384(certificate) = {}", hex(&sha384(&cert_sig)));
        println!("sha384(attestation) = {}", hex(&sha384(&attest_sig)));
    }
    /// Appendix B.13: [`vectors`], checked against the appendix.
    #[test]
    fn appendix_b() {
        use crate::risala_sign::sign_content;
        use libcrux_ml_dsa::ml_dsa_44 as mldsa;

        let det_sign = |seed: [u8; 32], label: &str, content: &[u8]| -> Vec<u8> {
            let pair = mldsa::generate_key_pair(seed);
            mldsa::sign(
                &pair.signing_key,
                &sign_content(label, content),
                b"",
                [0; 32],
            )
            .unwrap()
            .as_ref()
            .to_vec()
        };
        let mut ck = crate::appendix::Checker::open("B.13 ");
        let last_seed = [0x22; 32];
        let device_seed = [0x11; 32];
        let group_id = [0x33; 32];
        let period = 20767;
        let noon = 1_794_225_600_000;
        ck.eq("time", noon.to_string());
        ck.eq("last period of the chain", "20855");
        ck.hex("its seed", &last_seed);
        ck.eq("uid", "alice@example.org");
        ck.hex("device key seed", &device_seed);
        ck.eq("period", period.to_string());
        ck.hex("group id", &group_id);
        ck.hex("leaf key seed", &[0x44; 32]);
        ck.gap();
        ck.eq("period of the time", period_of_ms(noon).to_string());
        ck.hex("seed of period 20854", &previous_seed(&last_seed)[..]);
        let seed = seed_before(&last_seed, 20855 - period);
        ck.hex("seed of period 20767", &seed[..]);
        let period_key = SigningKey::from_seed(*seed);
        ck.file("period key", "period-key.bin", period_key.public_key());
        let device_key = SigningKey::from_seed(device_seed);
        let device_id = DeviceId::of_device_key(device_key.public_key());
        ck.hex("device id", device_id.as_bytes());
        let cert = PeriodCert {
            uid: "alice@example.org",
            device_id: &device_id,
            period,
            period_key: period_key.public_key(),
        };
        let cert_bytes = cert.encode();
        ck.file("PeriodCert", "periodcert.bin", &cert_bytes);
        let cert_sig = det_sign(device_seed, PERIOD_LABEL, &cert_bytes);
        assert!(cert.verify(device_key.public_key(), &cert_sig));
        ck.file("certificate", "period-certificate.bin", &cert_sig);
        let leaf = SigningKey::from_seed([0x44; 32]);
        let content = AttestContent {
            group_id: &group_id,
            period,
            leaf_key_hash: sha384(leaf.public_key()),
        };
        let content_bytes = content.encode();
        ck.hex("AttestContent", &content_bytes);
        let attest_sig = det_sign(*seed, ATTEST_LABEL, &content_bytes);
        assert!(content.verify(period_key.public_key(), &attest_sig));
        ck.file("attestation", "attestation.bin", &attest_sig);
        let mut ring = PeriodKeyring::new();
        ring.start_chain_with(20766, last_seed);
        assert_eq!(*ring.seed(period).unwrap(), *seed);
        ck.eq(
            "the REVEAL line",
            ring.reveal(period).unwrap().to_line().unwrap(),
        );
        assert!(seed_derives(&seed, period, period, period_key.public_key()));
        assert!(seed_derives(
            &last_seed,
            20855,
            period,
            period_key.public_key()
        ));
        ck.gap();
        let other_leaf = SigningKey::from_seed([0x45; 32]);
        let wrong = AttestContent {
            leaf_key_hash: sha384(other_leaf.public_key()),
            ..content
        };
        ck.rejected(
            "the attestation checked for a leaf key from the seed 32 bytes of 45",
            !wrong.verify(period_key.public_key(), &attest_sig),
        );
        // Period 20767 runs from 1794268800000, and its grace hour ends at
        // 1794358800000.
        assert_eq!(period_start(period), 1_794_268_800_000);
        assert_eq!(grace_end(period), 1_794_358_800_000);
        assert!(within_period_or_grace(period, 1_794_268_800_000));
        assert!(within_period_or_grace(period, 1_794_358_800_000 - 1));
        ck.rejected(
            "an ATTEST for period 20767 posted at 1794268799999",
            !within_period_or_grace(period, 1_794_268_799_999),
        );
        ck.rejected(
            "an ATTEST for period 20767 posted at 1794358800000",
            !within_period_or_grace(period, 1_794_358_800_000),
        );
        ck.rejected(
            "a REVEAL of period 20767 with the seed 32 bytes of 23",
            !seed_derives(&[0x23; 32], period, period, period_key.public_key()),
        );
        ck.rejected(
            "a REVEAL of period 20767 with the seed of period 20766",
            !seed_derives(
                &previous_seed(&seed),
                period - 1,
                period,
                period_key.public_key(),
            ),
        );
        ck.finish();
    }
}
