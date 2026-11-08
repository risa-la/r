//! Confirming leaves (12.10): the pairwise challenge and answer, and the
//! state machine that confirms a group's leaves either way.
//!
//! Leaf keys are signed by nothing the identity publishes (12.3). A device
//! **confirms** a leaf once it is sure that the leaf belongs to the device
//! that its credential names; until then the leaf's messages show as
//! unverified. The group's `confirm` field (12.4) picks how:
//!
//! - **Pairwise** (direct conversations, and private rooms of up to
//!   [`MAX_PAIRWISE_MEMBERS`] members). Device B encapsulates to device
//!   A's X-Wing attestation key (4.4) and sends `CHALLENGE <a> <ct>`; A
//!   decapsulates and sends `ANSWER <b> <mac>`, an HMAC-SHA-384 over a
//!   [`confirm_content`] under a key from the shared secret
//!   ([`confirm_key`]). B could have made the same MAC, so the exchange
//!   convinces B and nobody else.
//! - **Epochal** (public rooms, and private rooms past 256 members): see
//!   [`crate::epochal`]. That construction still needs an outside review
//!   (PLAN.md item 53).
//!
//! [`Confirmer`] is the state machine for one group, which the client
//! drives: it is told the group's leaves after each commit, the messages
//! it processes, the leaves that use authority, and the clock, and it
//! gives back the lines to send ([`Confirmer::take_lines`]), when to send
//! them on their own ([`Confirmer::send_due`]), events ([`Event`]) and each
//! leaf's state ([`LeafState`]). It keeps no clock and makes no network
//! calls; the device's keys and key files come in through [`OwnDevice`].
//! It is serialisable with serde, and holds open challenges' shared
//! secrets, so the client stores it as a secret.

use std::collections::{BTreeMap, BTreeSet};

use risala_proto::content::{CHALLENGE_LEN, ChallengeCiphertext, ConfirmMac, Content, ContentLine};
use risala_proto::time::Timestamp;
use zeroize::{Zeroize as _, Zeroizing};

use crate::aad::{PSEUDONYM_LEN, Pseudonym};
use crate::codec::Writer;
use crate::conversation::ConfirmMode;
use crate::crypto::{X_WING_PUBLIC_KEY_LEN, x_wing_public_key_ok};
use crate::epochal::{
    self, Attest, AttestCheck, AttestError, CHAIN_LEN, PeriodKeyring, REVEAL_WITHIN_MS,
    ROTATE_WITHIN_MS, RevealRegistry, check_attest, period_of_ms,
};
use crate::identity::RisalaIdentity;
use crate::mldsa::SigningKey;
use crate::primitives::{HASH_LEN, ct_eq, hkdf_expand, hkdf_extract, hmac_sha384, sha384};

pub use crate::checks::MAX_PAIRWISE_MEMBERS;

/// The HKDF label of the confirmation key (12.10, 15).
pub const CONFIRM_LABEL: &[u8] = b"risala/1 confirm";

/// The length of an X-Wing shared secret.
pub const SHARED_SECRET_LEN: usize = 32;

/// The randomness of one X-Wing encapsulation: 32 bytes for ML-KEM-768,
/// then 32 for the ephemeral X25519 key (XWING, draft 06).
pub const ENCAPSULATION_RANDOMNESS_LEN: usize = 64;

/// The length of an attestation key's seed (4.3).
pub const ATTESTATION_SEED_LEN: usize = 32;

/// The length of the MAC in ANSWER.
pub const MAC_LEN: usize = HASH_LEN;

// Timing (12.7, 12.9, 12.10), in milliseconds.

/// Pending CHALLENGE and ANSWER lines that ride in no ordinary message go
/// in one of their own at a random time within 10 minutes.
pub const SEND_WITHIN_MS: u64 = 10 * 60_000;
/// ... or within a minute for a challenge to a leaf that used authority,
/// to a new leaf of the device's own identity, or in the conversation with
/// yourself.
pub const URGENT_WITHIN_MS: u64 = 60_000;
/// A leaf that uses authority, or a new leaf of the device's own identity,
/// that has not answered (or, in an epochal group, attested) within an
/// hour is an impostor (12.7).
pub const IMPOSTOR_AFTER_MS: u64 = 3_600_000;
/// In the conversation with yourself, a leaf that has not answered within
/// 24 hours is reported to the user, who may remove it (12.9).
pub const ASK_USER_AFTER_MS: u64 = 24 * 3_600_000;
/// An unanswered challenge is sent again, unchanged, when its leaf shows
/// that it is active and this long has passed since it was last sent.
pub const RESEND_AFTER_MS: u64 = 15 * 60_000;
/// How many times an unanswered challenge is sent again.
pub const MAX_RESENDS: u8 = 4;
/// At most this many leaves of the device's own identity are challenged at
/// once in one group: an identity has at most 64 devices (4.4).
pub const MAX_OWN_CHALLENGES: usize = 64;
/// A device warns that a leaf has not revealed a period key it attested
/// with once this long has passed since the REVEAL became due: the day the
/// sender has, and a day more for devices that were offline (12.10).
pub const REVEAL_MISSING_AFTER_MS: u64 = REVEAL_WITHIN_MS + 86_400_000;

// ---------------------------------------------------------------------------
// The pairwise construction

/// A device's X-Wing attestation key (4.4): its 32-byte seed, wiped when
/// dropped, and its public key. It answers leaf challenges (12.10) and
/// signs nothing.
pub struct AttestationKey {
    seed: Zeroizing<[u8; ATTESTATION_SEED_LEN]>,
    public: Vec<u8>,
}

impl AttestationKey {
    /// A new random attestation key.
    pub fn generate() -> Result<AttestationKey, getrandom::Error> {
        let mut seed = Zeroizing::new([0; ATTESTATION_SEED_LEN]);
        getrandom::fill(&mut seed[..])?;
        Ok(AttestationKey::from_seed(seed))
    }

    /// The key of `seed`, by X-Wing's key generation from a seed, as for
    /// the pairing key (4.8) and the leaves' HPKE keys (12.2).
    pub fn from_seed(seed: Zeroizing<[u8; ATTESTATION_SEED_LEN]>) -> AttestationKey {
        let (_, public) =
            libcrux_kem::key_gen_derand(libcrux_kem::Algorithm::XWingKemDraft06, &seed[..])
                .expect("X-Wing makes a key pair from any 32-byte seed");
        AttestationKey {
            seed,
            public: public.encode(),
        }
    }

    /// The seed, which is the private key (4.3). Store it as a secret.
    pub fn seed(&self) -> &[u8; ATTESTATION_SEED_LEN] {
        &self.seed
    }

    /// The public key, for the device's record (4.4): 1216 bytes.
    pub fn public_key(&self) -> &[u8] {
        &self.public
    }

    /// Decapsulates a challenge's ciphertext, or `None` if X-Wing refuses
    /// it (its X25519 part gives an all-zero secret).
    pub fn decapsulate(&self, ciphertext: &[u8; CHALLENGE_LEN]) -> Option<SharedSecret> {
        let alg = libcrux_kem::Algorithm::XWingKemDraft06;
        let ct = libcrux_kem::Ct::decode(alg, ciphertext).ok()?;
        let sk = libcrux_kem::PrivateKey::decode(alg, &self.seed[..]).ok()?;
        let ss = ct.decapsulate(&sk).ok()?;
        SharedSecret::from_slice(&Zeroizing::new(ss.encode()))
    }
}

impl std::fmt::Debug for AttestationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AttestationKey(…)")
    }
}

/// An X-Wing shared secret, wiped when dropped.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SharedSecret([u8; SHARED_SECRET_LEN]);

impl SharedSecret {
    fn from_slice(bytes: &[u8]) -> Option<SharedSecret> {
        Some(SharedSecret(bytes.try_into().ok()?))
    }

    /// The secret's bytes.
    pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_LEN] {
        &self.0
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SharedSecret(…)")
    }
}

/// Why a challenge cannot be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConfirmError {
    /// The attestation key fails the check of 12.2 (1216 bytes, and an
    /// ML-KEM-768 part that passes FIPS 203's encapsulation key check).
    #[error("the attestation key fails the X-Wing key check")]
    BadAttestationKey,
    /// The operating system had no randomness.
    #[error("no randomness for the encapsulation")]
    Random,
}

/// Encapsulates to an attestation key with X-Wing (12.10, step 1), after
/// checking the key as 12.2 requires: the ciphertext for CHALLENGE, and
/// the shared secret that the challenger keeps.
pub fn encapsulate(
    attestation_key: &[u8],
) -> Result<(Box<[u8; CHALLENGE_LEN]>, SharedSecret), ConfirmError> {
    let mut randomness = Zeroizing::new([0; ENCAPSULATION_RANDOMNESS_LEN]);
    getrandom::fill(&mut randomness[..]).map_err(|_| ConfirmError::Random)?;
    encapsulate_derand(attestation_key, &randomness)
}

/// [`encapsulate`] with the given randomness, for test vectors.
pub fn encapsulate_derand(
    attestation_key: &[u8],
    randomness: &[u8; ENCAPSULATION_RANDOMNESS_LEN],
) -> Result<(Box<[u8; CHALLENGE_LEN]>, SharedSecret), ConfirmError> {
    // The check comes first: libcrux-kem slices a short key and panics.
    if !x_wing_public_key_ok(attestation_key) {
        return Err(ConfirmError::BadAttestationKey);
    }
    debug_assert_eq!(attestation_key.len(), X_WING_PUBLIC_KEY_LEN);
    let alg = libcrux_kem::Algorithm::XWingKemDraft06;
    let pk = libcrux_kem::PublicKey::decode(alg, attestation_key)
        .map_err(|_| ConfirmError::BadAttestationKey)?;
    let (ss, ct) = pk
        .encapsulate_derand(&randomness[..])
        .map_err(|_| ConfirmError::BadAttestationKey)?;
    let ct: [u8; CHALLENGE_LEN] = ct
        .encode()
        .try_into()
        .expect("an X-Wing ciphertext is 1120 bytes");
    let ss = SharedSecret::from_slice(&Zeroizing::new(ss.encode()))
        .expect("an X-Wing shared secret is 32 bytes");
    Ok((Box::new(ct), ss))
}

/// The encoded ConfirmContent (12.10), where A answers and B challenges:
///
/// ```text
/// struct {
///     uint8 version;                  // 1
///     opaque group_id<V>;
///     opaque challenge_hash[48];      // SHA-384 of ct
///     opaque answerer_key_hash[48];   // SHA-384 of A's leaf signature key
///     opaque challenger_key_hash[48]; // SHA-384 of B's leaf signature key
/// } ConfirmContent;
/// ```
///
/// The keys are the leaves' raw ML-DSA-44 public keys, as in their leaf
/// nodes' `signature_key`.
pub fn confirm_content(
    group_id: &[u8],
    ciphertext: &[u8],
    answerer_key: &[u8],
    challenger_key: &[u8],
) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(1)
        .vector(group_id)
        .fixed(&sha384(ciphertext))
        .fixed(&sha384(answerer_key))
        .fixed(&sha384(challenger_key));
    w.into_bytes()
}

/// K = HKDF-Expand(HKDF-Extract("", ss), "risala/1 confirm", 48), with
/// SHA-384 (12.10).
pub fn confirm_key(ss: &SharedSecret) -> Zeroizing<[u8; HASH_LEN]> {
    let prk = hkdf_extract(b"", &ss.0);
    let mut key = Zeroizing::new([0; HASH_LEN]);
    hkdf_expand(&prk[..], CONFIRM_LABEL, &mut key[..]);
    key
}

/// The MAC of ANSWER: HMAC-SHA-384(K, ConfirmContent) (12.10).
pub fn confirm_mac(
    ss: &SharedSecret,
    group_id: &[u8],
    ciphertext: &[u8],
    answerer_key: &[u8],
    challenger_key: &[u8],
) -> [u8; MAC_LEN] {
    let content = confirm_content(group_id, ciphertext, answerer_key, challenger_key);
    hmac_sha384(&confirm_key(ss)[..], &content)
}

/// Whether `mac` is the right answer, compared in constant time (12.10,
/// step 3).
pub fn check_answer(
    ss: &SharedSecret,
    group_id: &[u8],
    ciphertext: &[u8],
    answerer_key: &[u8],
    challenger_key: &[u8],
    mac: &[u8],
) -> bool {
    let expected = Zeroizing::new(confirm_mac(
        ss,
        group_id,
        ciphertext,
        answerer_key,
        challenger_key,
    ));
    ct_eq(&expected[..], mac)
}

// ---------------------------------------------------------------------------
// What the state machine is given

/// A leaf of the group, as the client reads it from the ratchet tree after
/// each commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafInfo {
    /// The leaf index.
    pub index: u32,
    /// Its credential.
    pub identity: RisalaIdentity,
    /// Its raw ML-DSA-44 signature key.
    pub signature_key: Vec<u8>,
}

/// What the client knows of the device that a credential names, from the
/// identity's key file and log (4.4, 4.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceStatus {
    /// A current, logged device of the identity, with its keys.
    Current {
        /// Its raw ML-DSA-44 device key.
        device_key: Vec<u8>,
        /// Its raw X-Wing attestation key.
        attestation_key: Vec<u8>,
    },
    /// Not known yet: the key file could not be fetched, or a record is
    /// still pending (4.5, 12.7). The state machine waits, and asks again
    /// when it is next driven.
    Unknown,
    /// Not a current device of the identity: never listed, or removed.
    NotCurrent,
}

/// Where the state machine looks up devices.
pub trait DeviceDirectory {
    /// The device that `identity` names. Never called for guests.
    fn device(&self, identity: &RisalaIdentity) -> DeviceStatus;
}

/// The device's own keys and device-wide state, borrowed for one call.
pub struct OwnDevice<'a> {
    /// The device's own credential.
    pub identity: &'a RisalaIdentity,
    /// The device key, which certifies period keys (12.10).
    pub device_key: &'a SigningKey,
    /// The attestation key, which answers challenges.
    pub attestation_key: &'a AttestationKey,
    /// The device's period keys, shared by its epochal groups.
    pub periods: &'a mut PeriodKeyring,
    /// The REVEALs seen from others, in any group.
    pub reveals: &'a mut RevealRegistry,
    /// The other devices' keys.
    pub directory: &'a dyn DeviceDirectory,
}

/// A message the client has decrypted and applied in the group.
#[derive(Debug, Clone, Copy)]
pub struct Incoming<'a> {
    /// The sender's leaf index.
    pub sender: u32,
    /// The `t` of the post that carried it (5.2).
    pub t: Timestamp,
    /// The pseudonym in its RisalaAAD, or `None` for a PublicMessage.
    pub pseudonym: Option<Pseudonym>,
    /// Its content.
    pub content: &'a Content,
}

/// A leaf's state, for showing its messages (12.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeafState {
    /// Not confirmed (yet): its messages show as unverified. Guests are
    /// always unconfirmed.
    Unconfirmed,
    /// Confirmed: it belongs to the device its credential names.
    Confirmed,
    /// It answered wrongly, or not in time: its messages and actions show
    /// as unconfirmed, the user is warned, and a device repairs the group
    /// (12.7).
    Impostor,
}

/// Why a leaf is an impostor (12.7, 12.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ImpostorReason {
    /// Its ANSWER's MAC was wrong.
    WrongAnswer,
    /// It did not answer within an hour of a challenge that had a
    /// deadline: after it used authority, or as a new leaf of the device's
    /// own identity.
    NoAnswer,
    /// In an epochal group, it did not attest within an hour of using
    /// authority.
    NoAttestation,
}

/// Something the client acts on or tells the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The leaf is confirmed, and so are its earlier messages with the
    /// same signature key.
    Confirmed {
        /// The leaf.
        leaf: u32,
    },
    /// The leaf is an impostor: warn the user, and after a random wait of
    /// up to 10 minutes make an impostor repair unless another device has
    /// (12.7).
    Impostor {
        /// The leaf.
        leaf: u32,
        /// Why.
        reason: ImpostorReason,
    },
    /// In the conversation with yourself, the leaf has not answered within
    /// 24 hours: tell the user, and remove it if they agree (12.9).
    Unanswered {
        /// The leaf.
        leaf: u32,
    },
    /// The leaf attested for the period, valid and accepted. Its pseudonym
    /// for the period is pinned (7.3). The client applies bans to the
    /// identity it names (12.10).
    Attested {
        /// The leaf.
        leaf: u32,
        /// The period.
        period: u32,
        /// Its pseudonym for the period.
        pseudonym: Pseudonym,
    },
    /// An ATTEST line from the leaf was not valid, or came too late.
    InvalidAttestation {
        /// The leaf.
        leaf: u32,
        /// Why.
        error: AttestError,
    },
    /// The leaf's REVEAL does not derive the period key it attested with:
    /// warn the user, since the leaf does not give the deniability the
    /// group expects (12.10).
    BadReveal {
        /// The leaf.
        leaf: u32,
        /// The period.
        period: u32,
    },
    /// The leaf has not revealed a period key it attested with, well after
    /// it was due (12.10). Warn as for [`Event::BadReveal`].
    RevealMissing {
        /// The leaf.
        leaf: u32,
        /// The period.
        period: u32,
    },
    /// The leaf's credential names a device that is not a current device
    /// of its identity, so it cannot be confirmed (4.5, 12.7).
    DeviceNotCurrent {
        /// The leaf.
        leaf: u32,
    },
    /// The leaf's device has an attestation key that fails the X-Wing key
    /// check (12.2), so it cannot be challenged.
    BadAttestationKey {
        /// The leaf.
        leaf: u32,
    },
}

// ---------------------------------------------------------------------------
// The state machine's state

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum Mode {
    Pairwise,
    Epochal,
}

impl From<ConfirmMode> for Mode {
    fn from(mode: ConfirmMode) -> Mode {
        match mode {
            ConfirmMode::Pairwise => Mode::Pairwise,
            ConfirmMode::Epochal => Mode::Epochal,
        }
    }
}

/// A challenge to send.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
struct Want {
    /// Send it on its own by then.
    send_by: u64,
}

/// An open challenge (12.10): at most one per leaf, with the leaf's
/// signature key when it was sent.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct Open {
    ciphertext: Vec<u8>,
    ss: SharedSecret,
    /// The challenged leaf's signature key when it was sent.
    answerer_key: Vec<u8>,
    /// This device's leaf key when it was sent.
    challenger_key: Vec<u8>,
    last_sent: u64,
    resends: u8,
    /// Send it again, unchanged, on its own by then.
    resend_by: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum DeadlineKind {
    /// Not confirmed by then: an impostor.
    Impostor,
    /// Not confirmed by then: ask the user (the conversation with
    /// yourself).
    AskUser,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
struct Deadline {
    at: u64,
    kind: DeadlineKind,
}

/// A valid, accepted ATTEST from a leaf.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct Attested {
    period_key: Vec<u8>,
    key_hash: Vec<u8>,
    revealed: bool,
    missing_reported: bool,
}

/// An ATTEST waiting for its device's keys.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PendingAttest {
    period: u32,
    period_key: Vec<u8>,
    certificate: Vec<u8>,
    attestation: Vec<u8>,
    pseudonym: [u8; PSEUDONYM_LEN],
    post_t: u64,
    message_pseudonym: Option<[u8; PSEUDONYM_LEN]>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct Leaf {
    /// The encoded RisalaIdentity.
    identity: Vec<u8>,
    #[serde(skip)]
    decoded: Option<RisalaIdentity>,
    key: Vec<u8>,
    key_hash: Vec<u8>,
    /// Confirmed pairwise, for its current key.
    confirmed: bool,
    impostor: Option<ImpostorReason>,
    want: Option<Want>,
    open: Option<Open>,
    /// The challenge dropped when the leaf's signature key last changed
    /// (12.10). An ANSWER to it may still come, made before the answerer
    /// saw the change or with its new key: it is ignored rather than
    /// checked against the newer challenge, which it would fail, so that a
    /// device that rotates its leaf after a last-resort join is not taken
    /// for an impostor.
    #[serde(default)]
    dropped: Option<Open>,
    deadline: Option<Deadline>,
    /// Challenged as a new leaf of the device's own identity.
    own_identity: bool,
    unanswered_reported: bool,
    attests: BTreeMap<u32, Attested>,
    pending_attest: Option<PendingAttest>,
}

impl Leaf {
    fn new(info: &LeafInfo) -> Leaf {
        Leaf {
            identity: info.identity.encode(),
            decoded: Some(info.identity.clone()),
            key: info.signature_key.clone(),
            key_hash: sha384(&info.signature_key).to_vec(),
            confirmed: false,
            impostor: None,
            want: None,
            open: None,
            dropped: None,
            deadline: None,
            own_identity: false,
            unanswered_reported: false,
            attests: BTreeMap::new(),
            pending_attest: None,
        }
    }

    fn identity(&self) -> RisalaIdentity {
        match &self.decoded {
            Some(identity) => identity.clone(),
            None => RisalaIdentity::decode(&self.identity)
                .expect("stored identities were encoded by this module"),
        }
    }

    fn is_guest(&self) -> bool {
        self.identity().is_guest()
    }

    /// Whether an ATTEST makes it confirmed for period `p` at `now`.
    fn attested_for(&self, p: u32, now: u64) -> bool {
        self.attests
            .get(&p)
            .is_some_and(|a| a.key_hash == self.key_hash && now < epochal::grace_end(p))
    }
}

/// An ANSWER to send.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct Answer {
    mac: Vec<u8>,
    send_by: u64,
}

/// The device's own leaf in the group.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct Own {
    index: u32,
    /// The encoded RisalaIdentity.
    identity: Vec<u8>,
    key: Vec<u8>,
    /// The period in which the current key took effect.
    key_period: u32,
    pseudonym: [u8; PSEUDONYM_LEN],
    /// The last time this device made an authority commit, or sent a line
    /// that only a role allows.
    authority_at: Option<u64>,
}

/// The confirmation state of one group, for the device that holds it: who
/// is confirmed, who is pending, and what to send (12.10).
///
/// Drive it like this:
///
/// - After joining, [`Confirmer::new`] with the group's leaves.
/// - After each commit the client applies, [`Confirmer::set_mode`] if the
///   `confirm` field changed, [`Confirmer::set_leaves`] with the new tree's
///   leaves, [`Confirmer::own_leaf_changed`] if this device's leaf got a
///   new signature key, and [`Confirmer::authority_used`] if the committer
///   used authority (12.7). Call [`Confirmer::own_authority_used`] when
///   this device does.
/// - For each message it applies, [`Confirmer::message`]; then
///   [`Confirmer::message_state`] says how to show it.
/// - When it composes a message to post (not a live one), it adds the
///   lines of [`Confirmer::take_lines`]. If it has none to post by
///   [`Confirmer::send_due`], it posts those lines on their own, unless
///   there are none.
/// - At [`Confirmer::next_wake`], or whenever a key file it waited for
///   arrives, [`Confirmer::poll`].
/// - In an epochal group, it rotates its leaf (12.10) by an Update when
///   [`Confirmer::rotation_due`] says so, and before posting if
///   [`Confirmer::must_rotate_before_sending`] does.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Confirmer {
    group_id: Vec<u8>,
    with_yourself: bool,
    mode: Mode,
    own: Own,
    leaves: BTreeMap<u32, Leaf>,
    answers: BTreeMap<u32, Answer>,
    /// Epochal: the periods this device attested in, here, and when it
    /// sends their REVEAL on its own.
    attested: BTreeMap<u32, u64>,
    /// Epochal: the hash of the leaf key last attested, and its period.
    attested_key: Option<(u32, Vec<u8>)>,
    /// Epochal: an ATTEST owed within an hour of an authority commit.
    attest_send_by: Option<u64>,
    /// Epochal: the periods in which this device sent here.
    sent_periods: BTreeSet<u32>,
    /// Epochal: when to propose this period's new leaf, if it sent in the
    /// period before (period, time).
    rotation: Option<(u32, Option<u64>)>,
}

fn ms(t: Timestamp) -> u64 {
    t.unix_millis()
}

fn timestamp(ms: u64) -> Timestamp {
    Timestamp::from_unix_millis(ms).unwrap_or(Timestamp::MAX)
}

/// A random time in `[0, within)`, from the operating system. Without
/// randomness, the middle of the range.
fn random_below(within: u64) -> u64 {
    if within == 0 {
        return 0;
    }
    let mut bytes = [0; 8];
    match getrandom::fill(&mut bytes) {
        Ok(()) => u64::from_le_bytes(bytes) % within,
        Err(_) => within / 2,
    }
}

impl Confirmer {
    /// The state of a group the device has just joined or created, with
    /// the leaves of its tree (its own among them). `own` is this device's
    /// own leaf, and `pseudonym` its pseudonym (7.3). `with_yourself` says
    /// whether this is the conversation with yourself (12.9).
    pub fn new(
        group_id: &[u8],
        mode: ConfirmMode,
        with_yourself: bool,
        own: &LeafInfo,
        pseudonym: Pseudonym,
        leaves: &[LeafInfo],
        now: Timestamp,
    ) -> Confirmer {
        let mut confirmer = Confirmer {
            group_id: group_id.to_vec(),
            with_yourself,
            mode: mode.into(),
            own: Own {
                index: own.index,
                identity: own.identity.encode(),
                key: own.signature_key.clone(),
                key_period: period_of_ms(ms(now)),
                pseudonym: pseudonym.0,
                authority_at: None,
            },
            leaves: BTreeMap::new(),
            answers: BTreeMap::new(),
            attested: BTreeMap::new(),
            attested_key: None,
            attest_send_by: None,
            sent_periods: BTreeSet::new(),
            rotation: None,
        };
        confirmer.set_leaves(leaves, now);
        confirmer
    }

    /// The group's id.
    pub fn group_id(&self) -> &[u8] {
        &self.group_id
    }

    /// The group's `confirm` mode.
    pub fn mode(&self) -> ConfirmMode {
        match self.mode {
            Mode::Pairwise => ConfirmMode::Pairwise,
            Mode::Epochal => ConfirmMode::Epochal,
        }
    }

    fn own_identity(&self) -> RisalaIdentity {
        RisalaIdentity::decode(&self.own.identity)
            .expect("stored identities were encoded by this module")
    }

    /// The group's `confirm` field changed (12.4, 6.2): a private room
    /// that grew past 256 members moved to `epochal`. Pairwise lines no
    /// longer count there, so open challenges and answers are dropped.
    /// Leaves already confirmed pairwise stay confirmed for their current
    /// signature key, until it changes at their first rotation.
    pub fn set_mode(&mut self, mode: ConfirmMode) {
        let mode = Mode::from(mode);
        if mode == self.mode {
            return;
        }
        self.mode = mode;
        self.answers.clear();
        for leaf in self.leaves.values_mut() {
            leaf.want = None;
            leaf.open = None;
            // Deadlines stay: in an epochal group, an ATTEST meets them.
        }
    }

    /// The group's leaves after a commit, its own among them (12.7). New
    /// leaves are added, missing ones dropped with their challenges, a
    /// leaf whose credential changed is treated as new, and one whose
    /// signature key changed needs confirming again, with its open
    /// challenge dropped (12.10). In a pairwise group, every new leaf of
    /// the conversation with yourself, and every new leaf of the device's
    /// own identity, is challenged at once.
    pub fn set_leaves(&mut self, leaves: &[LeafInfo], now: Timestamp) {
        let now = ms(now);
        let present: BTreeSet<u32> = leaves.iter().map(|l| l.index).collect();
        self.leaves.retain(|index, _| present.contains(index));
        self.answers.retain(|index, _| present.contains(index));
        let own_uid = self.own_identity().uid;
        for info in leaves {
            if info.index == self.own.index {
                continue;
            }
            let encoded = info.identity.encode();
            match self.leaves.get_mut(&info.index) {
                Some(leaf) if leaf.identity == encoded => {
                    if leaf.key != info.signature_key {
                        leaf.key = info.signature_key.clone();
                        leaf.key_hash = sha384(&info.signature_key).to_vec();
                        leaf.confirmed = false;
                        if let Some(open) = leaf.open.take() {
                            leaf.dropped = Some(open);
                        }
                        leaf.pending_attest = None;
                        // Leaves challenged at once are challenged again
                        // at once (a choice: 12.10 does not say).
                        let eager = self.with_yourself || leaf.own_identity;
                        if self.mode == Mode::Pairwise && eager && leaf.impostor.is_none() {
                            leaf.want = Some(Want {
                                send_by: now + random_below(URGENT_WITHIN_MS),
                            });
                        }
                    }
                    continue;
                }
                _ => {}
            }
            // A new leaf, or a new credential at that index.
            self.answers.remove(&info.index);
            let mut leaf = Leaf::new(info);
            if self.mode == Mode::Pairwise && !info.identity.is_guest() {
                if self.with_yourself {
                    leaf.want = Some(Want {
                        send_by: now + random_below(URGENT_WITHIN_MS),
                    });
                    leaf.deadline = Some(Deadline {
                        at: now + ASK_USER_AFTER_MS,
                        kind: DeadlineKind::AskUser,
                    });
                } else if info.identity.uid == own_uid && self.own_challenges() < MAX_OWN_CHALLENGES
                {
                    leaf.own_identity = true;
                    leaf.want = Some(Want {
                        send_by: now + random_below(URGENT_WITHIN_MS),
                    });
                    leaf.deadline = Some(Deadline {
                        at: now + IMPOSTOR_AFTER_MS,
                        kind: DeadlineKind::Impostor,
                    });
                }
            }
            self.leaves.insert(info.index, leaf);
        }
    }

    /// How many leaves of the device's own identity have a challenge
    /// pending or open as such.
    fn own_challenges(&self) -> usize {
        self.leaves
            .values()
            .filter(|l| l.own_identity && !l.confirmed && (l.want.is_some() || l.open.is_some()))
            .count()
    }

    /// This device's leaf has a new pseudonym (7.3), with no new key:
    /// outside public rooms, call it after every commit, with the
    /// pseudonym derived from the new epoch
    /// ([`crate::group::own_pseudonym`]), since ATTEST carries the
    /// pseudonym of the message it is in (12.10).
    pub fn pseudonym_changed(&mut self, pseudonym: Pseudonym) {
        self.own.pseudonym = pseudonym.0;
    }

    /// This device's leaf has a new signature key, and in a public room, a
    /// new pseudonym (12.3, 7.3), now in effect.
    pub fn own_leaf_changed(&mut self, signature_key: &[u8], pseudonym: Pseudonym, now: Timestamp) {
        self.own.key = signature_key.to_vec();
        self.own.pseudonym = pseudonym.0;
        self.own.key_period = period_of_ms(ms(now));
        // An ATTEST still owed for an authority commit goes within the
        // hour (12.7).
        if self.mode == Mode::Epochal
            && self
                .own
                .authority_at
                .is_some_and(|t| ms(now) < t + IMPOSTOR_AFTER_MS)
        {
            self.attest_send_by = Some(ms(now) + random_below(URGENT_WITHIN_MS));
        }
        // Open challenges keep the key they were sent with, which is what
        // the answerer sees as their signer (12.10). Answers not yet sent
        // bind the old key, and challengers drop their challenges when they
        // see the new one: they would only be checked against a newer
        // challenge, and fail it.
        self.answers.clear();
    }

    /// Leaf `leaf` made an authority commit, or sent a line that only a
    /// role allows (12.7). Unless it is confirmed, it is challenged within
    /// a minute (pairwise), or must attest (epochal), within an hour, or it
    /// is an impostor.
    pub fn authority_used(&mut self, leaf: u32, now: Timestamp) {
        let now_ms = ms(now);
        if leaf == self.own.index || self.state(leaf, now) == LeafState::Confirmed {
            return;
        }
        let mode = self.mode;
        let Some(entry) = self.leaves.get_mut(&leaf) else {
            return;
        };
        if entry.impostor.is_some() || entry.is_guest() {
            return;
        }
        let at = now_ms + IMPOSTOR_AFTER_MS;
        match &mut entry.deadline {
            Some(d) if d.kind == DeadlineKind::Impostor && d.at <= at => {}
            d => {
                *d = Some(Deadline {
                    at,
                    kind: DeadlineKind::Impostor,
                })
            }
        }
        if mode == Mode::Pairwise {
            let send_by = now_ms + random_below(URGENT_WITHIN_MS);
            match (&mut entry.open, &mut entry.want) {
                (Some(open), _) => {
                    // Send the open challenge again, unless it just went.
                    if now_ms >= open.last_sent + URGENT_WITHIN_MS {
                        open.resend_by = Some(open.resend_by.map_or(send_by, |t| t.min(send_by)));
                    }
                }
                (None, Some(want)) => want.send_by = want.send_by.min(send_by),
                (None, want) => *want = Some(Want { send_by }),
            }
        }
    }

    /// This device made an authority commit, or sent a line that only a
    /// role allows. Its answers go within a minute for the next hour, and
    /// in an epochal group it owes an ATTEST within the hour if it has not
    /// attested in this period (12.7).
    pub fn own_authority_used(&mut self, now: Timestamp) {
        let now = ms(now);
        self.own.authority_at = Some(now);
        if self.mode == Mode::Epochal && !self.own_attested(period_of_ms(now)) {
            let send_by = now + random_below(SEND_WITHIN_MS);
            self.attest_send_by = Some(self.attest_send_by.map_or(send_by, |t| t.min(send_by)));
        }
    }

    fn own_attested(&self, period: u32) -> bool {
        let hash = sha384(&self.own.key).to_vec();
        self.attested_key
            .as_ref()
            .is_some_and(|(p, h)| *p == period && *h == hash)
    }

    fn answer_within(&self, now: u64) -> u64 {
        let urgent = self.with_yourself
            || self
                .own
                .authority_at
                .is_some_and(|t| now < t + IMPOSTOR_AFTER_MS);
        if urgent {
            URGENT_WITHIN_MS
        } else {
            SEND_WITHIN_MS
        }
    }

    /// Processes a message the client has decrypted and applied: its
    /// CHALLENGE and ANSWER lines in a pairwise group, its ATTEST and
    /// REVEAL lines in an epochal one, and whether its sender now needs a
    /// challenge (12.10).
    pub fn message(
        &mut self,
        device: &mut OwnDevice<'_>,
        message: &Incoming<'_>,
        now: Timestamp,
    ) -> Vec<Event> {
        let now_ms = ms(now);
        let sender = message.sender;
        if sender == self.own.index {
            return Vec::new();
        }
        let Some(leaf) = self.leaves.get(&sender) else {
            return Vec::new();
        };
        // Guests have no attestation key and no logged device: they are
        // never challenged or confirmed, and their lines here never count.
        if leaf.is_guest() {
            return Vec::new();
        }
        let mut events = Vec::new();
        match self.mode {
            Mode::Pairwise => {
                for line in message.content.lines() {
                    match line {
                        ContentLine::Challenge { leaf, ciphertext } if *leaf == self.own.index => {
                            self.on_challenge(device, sender, ciphertext, now_ms);
                        }
                        ContentLine::Answer { leaf, mac } if *leaf == self.own.index => {
                            events.extend(self.on_answer(sender, mac));
                        }
                        _ => {}
                    }
                }
                self.after_pairwise_message(sender, message.content, now_ms);
            }
            Mode::Epochal => {
                for line in message.content.lines() {
                    if let Some(attest) = Attest::from_line(line) {
                        events.extend(self.on_attest(
                            device,
                            sender,
                            &attest,
                            (message.t, message.pseudonym),
                            now,
                        ));
                    } else if let ContentLine::Reveal { period, seed } = line {
                        events.extend(self.on_reveal(
                            device,
                            sender,
                            *period,
                            seed.as_bytes(),
                            now,
                        ));
                    }
                }
            }
        }
        events
    }

    /// A CHALLENGE to this device's leaf: answer it (12.10, step 2). Only
    /// the newest challenge from each leaf is answered.
    fn on_challenge(
        &mut self,
        device: &OwnDevice<'_>,
        sender: u32,
        ciphertext: &ChallengeCiphertext,
        now: u64,
    ) {
        let Some(ss) = device.attestation_key.decapsulate(ciphertext.as_bytes()) else {
            return;
        };
        let challenger_key = &self.leaves[&sender].key;
        let mac = confirm_mac(
            &ss,
            &self.group_id,
            ciphertext.as_bytes(),
            &self.own.key,
            challenger_key,
        );
        let send_by = now + random_below(self.answer_within(now));
        self.answers.insert(
            sender,
            Answer {
                mac: mac.to_vec(),
                send_by,
            },
        );
    }

    /// An ANSWER to this device: check it against the one open challenge
    /// to that leaf, in constant time (12.10, step 3).
    fn on_answer(&mut self, sender: u32, mac: &ConfirmMac) -> Option<Event> {
        let leaf = self.leaves.get_mut(&sender)?;
        if leaf.impostor.is_some() {
            return None;
        }
        // An answer to the challenge dropped when the leaf's key changed,
        // made with its old key or its new one: the answerer had not seen
        // the newer challenge yet. It is ignored, not checked against the
        // newer one (12.10).
        if let Some(dropped) = &leaf.dropped
            && [&dropped.answerer_key, &leaf.key].into_iter().any(|key| {
                check_answer(
                    &dropped.ss,
                    &self.group_id,
                    &dropped.ciphertext,
                    key,
                    &dropped.challenger_key,
                    mac.as_bytes(),
                )
            })
        {
            return None;
        }
        // No open challenge, or one to an older key: nothing to check.
        let open = leaf.open.take_if(|o| o.answerer_key == leaf.key)?;
        if check_answer(
            &open.ss,
            &self.group_id,
            &open.ciphertext,
            &open.answerer_key,
            &open.challenger_key,
            mac.as_bytes(),
        ) {
            leaf.dropped = None;
            leaf.confirmed = true;
            leaf.want = None;
            leaf.deadline = None;
            Some(Event::Confirmed { leaf: sender })
        } else {
            leaf.want = None;
            leaf.deadline = None;
            leaf.impostor = Some(ImpostorReason::WrongAnswer);
            Some(Event::Impostor {
                leaf: sender,
                reason: ImpostorReason::WrongAnswer,
            })
        }
    }

    /// After a message from `sender` in a pairwise group: challenge it if
    /// it showed something (or anything, in the conversation with
    /// yourself) and is not confirmed, or send its open challenge again if
    /// it has gone unanswered for a while.
    fn after_pairwise_message(&mut self, sender: u32, content: &Content, now: u64) {
        let with_yourself = self.with_yourself;
        let Some(leaf) = self.leaves.get_mut(&sender) else {
            return;
        };
        if leaf.confirmed || leaf.impostor.is_some() {
            return;
        }
        let within = if with_yourself || leaf.deadline.is_some() {
            URGENT_WITHIN_MS
        } else {
            SEND_WITHIN_MS
        };
        if let Some(open) = &mut leaf.open {
            // The leaf is active but has not answered: perhaps it never
            // saw the challenge (7.5). Send the same one again.
            if open.resend_by.is_none()
                && open.resends < MAX_RESENDS
                && now >= open.last_sent + RESEND_AFTER_MS
            {
                open.resend_by = Some(now + random_below(within));
            }
            return;
        }
        if leaf.want.is_none() && (with_yourself || content.shows_something()) {
            leaf.want = Some(Want {
                send_by: now + random_below(within),
            });
        }
    }

    fn on_attest(
        &mut self,
        device: &mut OwnDevice<'_>,
        sender: u32,
        attest: &Attest,
        (post_t, message_pseudonym): (Timestamp, Option<Pseudonym>),
        now: Timestamp,
    ) -> Option<Event> {
        let leaf = self.leaves.get(&sender)?;
        let identity = leaf.identity();
        match device.directory.device(&identity) {
            DeviceStatus::Current { device_key, .. } => {
                let check = AttestCheck {
                    group_id: &self.group_id,
                    identity: &identity,
                    device_key: &device_key,
                    leaf_key: &leaf.key,
                    post_t,
                    message_pseudonym,
                    now,
                };
                let result = check_attest(attest, &check, device.reveals);
                // A certificate that verified under the device key: REVEALs
                // whose seeds derive its key are then never pushed out by
                // forged ones (12.10).
                if !matches!(result, Err(AttestError::Guest | AttestError::Certificate)) {
                    device
                        .reveals
                        .note_certified(&identity, attest.period, &attest.period_key[..]);
                }
                Some(self.attest_checked(sender, attest, result, now))
            }
            DeviceStatus::Unknown => {
                let leaf = self.leaves.get_mut(&sender)?;
                leaf.pending_attest = Some(PendingAttest {
                    period: attest.period,
                    period_key: attest.period_key.to_vec(),
                    certificate: attest.certificate.to_vec(),
                    attestation: attest.attestation.to_vec(),
                    pseudonym: attest.pseudonym.0,
                    post_t: ms(post_t),
                    message_pseudonym: message_pseudonym.map(|p| p.0),
                });
                None
            }
            DeviceStatus::NotCurrent => Some(Event::InvalidAttestation {
                leaf: sender,
                error: AttestError::DeviceNotCurrent,
            }),
        }
    }

    fn attest_checked(
        &mut self,
        sender: u32,
        attest: &Attest,
        result: Result<(), AttestError>,
        now: Timestamp,
    ) -> Event {
        let leaf = self.leaves.get_mut(&sender).expect("checked by the caller");
        if let Err(error) = result {
            return Event::InvalidAttestation {
                leaf: sender,
                error,
            };
        }
        leaf.attests.insert(
            attest.period,
            Attested {
                period_key: attest.period_key.to_vec(),
                key_hash: leaf.key_hash.clone(),
                revealed: false,
                missing_reported: false,
            },
        );
        if leaf.attested_for(period_of_ms(ms(now)), ms(now))
            || leaf.attested_for(period_of_ms(ms(now)).saturating_sub(1), ms(now))
        {
            leaf.deadline = None;
        }
        Event::Attested {
            leaf: sender,
            period: attest.period,
            pseudonym: attest.pseudonym,
        }
    }

    fn on_reveal(
        &mut self,
        device: &mut OwnDevice<'_>,
        sender: u32,
        period: u32,
        seed: &[u8; 32],
        now: Timestamp,
    ) -> Option<Event> {
        let leaf = self.leaves.get_mut(&sender)?;
        let identity = leaf.identity();
        device.reveals.record(&identity, period, seed, now);
        let mut bad = None;
        for (&q, attested) in leaf.attests.range_mut(..=period).rev() {
            if period - q >= CHAIN_LEN {
                break;
            }
            if attested.revealed {
                continue;
            }
            if epochal::seed_derives(seed, period, q, &attested.period_key) {
                attested.revealed = true;
            } else if q == period {
                bad = Some(Event::BadReveal {
                    leaf: sender,
                    period,
                });
            }
        }
        bad
    }

    /// The CHALLENGE, ANSWER, ATTEST and REVEAL lines to add to the message
    /// the device is about to post here (12.10), and the events of making
    /// them. Call it only for a message that will be posted, and not for a
    /// live one (8.1), since that carries TYPING alone.
    pub fn take_lines(
        &mut self,
        device: &mut OwnDevice<'_>,
        now: Timestamp,
    ) -> (Vec<ContentLine>, Vec<Event>) {
        let now_ms = ms(now);
        let mut lines = Vec::new();
        let mut events = Vec::new();
        match self.mode {
            Mode::Pairwise => self.take_pairwise(device, now_ms, &mut lines, &mut events),
            Mode::Epochal => self.take_epochal(device, now_ms, &mut lines),
        }
        // Whether it sent in the period before decides when it rotates.
        self.sent_periods.insert(period_of_ms(now_ms));
        let keep = period_of_ms(now_ms).saturating_sub(2);
        self.sent_periods.retain(|&p| p >= keep);
        (lines, events)
    }

    fn take_pairwise(
        &mut self,
        device: &mut OwnDevice<'_>,
        now: u64,
        lines: &mut Vec<ContentLine>,
        events: &mut Vec<Event>,
    ) {
        for (&index, leaf) in &mut self.leaves {
            if leaf.impostor.is_some() || leaf.confirmed {
                leaf.want = None;
                continue;
            }
            if let Some(open) = &mut leaf.open
                && open.resend_by.take().is_some()
            {
                let ct: [u8; CHALLENGE_LEN] = open.ciphertext[..]
                    .try_into()
                    .expect("stored at 1120 bytes");
                lines.push(ContentLine::Challenge {
                    leaf: index,
                    ciphertext: ChallengeCiphertext::from_bytes(&ct),
                });
                open.resends += 1;
                open.last_sent = now;
                continue;
            }
            if leaf.want.is_none() || leaf.open.is_some() {
                continue;
            }
            let identity = leaf.identity();
            let attestation_key = match device.directory.device(&identity) {
                DeviceStatus::Current {
                    attestation_key, ..
                } => attestation_key,
                // Wait for the key file, and ask again later.
                DeviceStatus::Unknown => {
                    leaf.want = Some(Want {
                        send_by: now + SEND_WITHIN_MS,
                    });
                    continue;
                }
                DeviceStatus::NotCurrent => {
                    leaf.want = None;
                    events.push(Event::DeviceNotCurrent { leaf: index });
                    continue;
                }
            };
            let (ciphertext, ss) = match encapsulate(&attestation_key) {
                Ok(pair) => pair,
                Err(ConfirmError::BadAttestationKey) => {
                    leaf.want = None;
                    events.push(Event::BadAttestationKey { leaf: index });
                    continue;
                }
                Err(ConfirmError::Random) => continue,
            };
            lines.push(ContentLine::Challenge {
                leaf: index,
                ciphertext: ChallengeCiphertext::from_bytes(&ciphertext),
            });
            leaf.want = None;
            // The hour to answer starts when the challenge goes (12.7).
            if let Some(d) = &mut leaf.deadline
                && d.kind == DeadlineKind::Impostor
            {
                d.at = d.at.max(now + IMPOSTOR_AFTER_MS);
            }
            leaf.open = Some(Open {
                ciphertext: ciphertext.to_vec(),
                ss,
                answerer_key: leaf.key.clone(),
                challenger_key: self.own.key.clone(),
                last_sent: now,
                resends: 0,
                resend_by: None,
            });
        }
        for (index, answer) in std::mem::take(&mut self.answers) {
            let mac: [u8; MAC_LEN] = answer.mac[..].try_into().expect("stored at 48 bytes");
            lines.push(ContentLine::Answer {
                leaf: index,
                mac: ConfirmMac::from_bytes(mac),
            });
        }
    }

    fn take_epochal(&mut self, device: &mut OwnDevice<'_>, now: u64, lines: &mut Vec<ContentLine>) {
        let period = period_of_ms(now);
        // ATTEST in the first message after the period's leaf key takes
        // effect (12.10). A key of an earlier period is not attested: the
        // device rotates before it sends.
        if self.own.key_period == period && !self.own_attested(period) {
            let identity = self.own_identity();
            if let Ok(attest) = device.periods.attest(
                device.device_key,
                &identity,
                &self.group_id,
                period,
                &self.own.key,
                Pseudonym(self.own.pseudonym),
            ) {
                lines.push(attest.to_line());
                self.attested_key = Some((period, sha384(&self.own.key).to_vec()));
                let reveal_by =
                    epochal::reveal_from(period) + random_below(REVEAL_WITHIN_MS - 3_600_000);
                self.attested.entry(period).or_insert(reveal_by);
            }
        }
        // An ATTEST owed for an authority commit goes with this message, or
        // once the device has rotated (see own_leaf_changed).
        self.attest_send_by = None;
        // REVEAL each period attested here, from 3 hours after it ends.
        // The newest due period of a chain reveals the others before it.
        let due: Vec<u32> = self
            .attested
            .keys()
            .copied()
            .filter(|&p| now >= epochal::reveal_from(p))
            .collect();
        let mut revealed_chains = BTreeSet::new();
        for &p in due.iter().rev() {
            let chain = device.periods.chain_of(p);
            if chain.is_some_and(|c| !revealed_chains.insert(c)) {
                continue;
            }
            if let Some(line) = device.periods.reveal(p) {
                lines.push(line);
            }
        }
        for p in due {
            self.attested.remove(&p);
        }
    }

    /// When the device should post the pending lines on their own, if it
    /// posts nothing else here before then.
    pub fn send_due(&self) -> Option<Timestamp> {
        let mut times = Vec::new();
        match self.mode {
            Mode::Pairwise => {
                for leaf in self.leaves.values() {
                    if leaf.impostor.is_some() || leaf.confirmed {
                        continue;
                    }
                    if let Some(open) = &leaf.open {
                        times.extend(open.resend_by);
                    } else if let Some(want) = leaf.want {
                        times.push(want.send_by);
                    }
                }
                times.extend(self.answers.values().map(|a| a.send_by));
            }
            Mode::Epochal => {
                times.extend(self.attest_send_by);
                times.extend(self.attested.values().copied());
            }
        }
        times.into_iter().min().map(timestamp)
    }

    /// The next time [`Confirmer::poll`] has something to do, or a line
    /// becomes due.
    pub fn next_wake(&self) -> Option<Timestamp> {
        let mut times: Vec<u64> = self.send_due().map(ms).into_iter().collect();
        for leaf in self.leaves.values() {
            times.extend(leaf.deadline.map(|d| d.at));
            for (&p, attested) in &leaf.attests {
                if !attested.revealed && !attested.missing_reported {
                    times.push(epochal::reveal_from(p) + REVEAL_MISSING_AFTER_MS);
                }
            }
        }
        if self.mode == Mode::Epochal {
            // Plan the next period's rotation when it starts.
            let period = self
                .rotation
                .map_or(self.own.key_period, |(p, _)| p.max(self.own.key_period));
            times.push(epochal::period_end(period));
            if let Some((p, Some(at))) = self.rotation
                && self.own.key_period < p
            {
                times.push(at);
            }
        }
        times.into_iter().min().map(timestamp)
    }

    /// Acts on the clock: deadlines that have passed make impostors, or
    /// ask the user; ATTESTs that waited for a key file are checked; in an
    /// epochal group, missing REVEALs are reported and the period's
    /// rotation is planned.
    pub fn poll(&mut self, device: &mut OwnDevice<'_>, now: Timestamp) -> Vec<Event> {
        let now_ms = ms(now);
        let mut events = Vec::new();

        // ATTESTs whose device was unknown.
        let pending: Vec<(u32, PendingAttest)> = self
            .leaves
            .iter_mut()
            .filter_map(|(&i, l)| l.pending_attest.take().map(|p| (i, p)))
            .collect();
        for (index, pending) in pending {
            let attest = Attest {
                period: pending.period,
                period_key: Box::new(pending.period_key[..].try_into().expect("1312 bytes")),
                certificate: Box::new(pending.certificate[..].try_into().expect("2420 bytes")),
                attestation: Box::new(pending.attestation[..].try_into().expect("2420 bytes")),
                pseudonym: Pseudonym(pending.pseudonym),
            };
            let message = (
                timestamp(pending.post_t),
                pending.message_pseudonym.map(Pseudonym),
            );
            events.extend(self.on_attest(device, index, &attest, message, now));
        }

        // Deadlines.
        let mode = self.mode;
        let indices: Vec<u32> = self.leaves.keys().copied().collect();
        for index in indices {
            let state = self.state(index, now);
            let leaf = self.leaves.get_mut(&index).expect("listed above");
            let Some(deadline) = leaf.deadline else {
                continue;
            };
            if state != LeafState::Unconfirmed {
                leaf.deadline = None;
                continue;
            }
            if now_ms < deadline.at {
                continue;
            }
            // A challenge that could not go yet, or an ATTEST that waits for
            // its key file, has not failed: wait (12.7).
            let waiting = match mode {
                Mode::Pairwise => leaf.open.is_none() && leaf.want.is_some(),
                Mode::Epochal => leaf.pending_attest.is_some(),
            };
            if waiting && deadline.kind == DeadlineKind::Impostor {
                leaf.deadline = Some(Deadline {
                    at: now_ms + IMPOSTOR_AFTER_MS,
                    ..deadline
                });
                continue;
            }
            leaf.deadline = None;
            match deadline.kind {
                DeadlineKind::Impostor => {
                    let reason = match mode {
                        Mode::Pairwise => ImpostorReason::NoAnswer,
                        Mode::Epochal => ImpostorReason::NoAttestation,
                    };
                    leaf.impostor = Some(reason);
                    leaf.want = None;
                    leaf.open = None;
                    events.push(Event::Impostor {
                        leaf: index,
                        reason,
                    });
                }
                DeadlineKind::AskUser => {
                    if !leaf.unanswered_reported {
                        leaf.unanswered_reported = true;
                        events.push(Event::Unanswered { leaf: index });
                    }
                }
            }
        }

        if mode == Mode::Epochal {
            let current = period_of_ms(now_ms);
            for (&index, leaf) in &mut self.leaves {
                for (&p, attested) in &mut leaf.attests {
                    if !attested.revealed
                        && !attested.missing_reported
                        && now_ms >= epochal::reveal_from(p) + REVEAL_MISSING_AFTER_MS
                    {
                        attested.missing_reported = true;
                        events.push(Event::RevealMissing {
                            leaf: index,
                            period: p,
                        });
                    }
                }
                // Keep a week of attestations.
                leaf.attests.retain(|&p, _| p + 7 >= current);
            }
            self.plan_rotation(current);
            device.reveals.prune(now);
        }
        events
    }

    /// Plans the proactive rotation of period `current` (12.10): a device
    /// that sent here in the period before proposes its new leaf at a
    /// random time in the first 12 hours, whether or not it has anything
    /// to send.
    fn plan_rotation(&mut self, current: u32) {
        if self.rotation.is_some_and(|(p, _)| p == current) {
            return;
        }
        let at = (self.own.key_period < current
            && current
                .checked_sub(1)
                .is_some_and(|p| self.sent_periods.contains(&p)))
        .then(|| epochal::period_start(current) + random_below(ROTATE_WITHIN_MS));
        self.rotation = Some((current, at));
    }

    /// Whether, in an epochal group, the device should now propose its
    /// period's new leaf by an Update (12.10), as planned by
    /// [`Confirmer::poll`]. False once the new key has taken effect.
    pub fn rotation_due(&self, now: Timestamp) -> bool {
        let current = period_of_ms(ms(now));
        self.mode == Mode::Epochal
            && self.own.key_period < current
            && self
                .rotation
                .is_some_and(|(p, at)| p == current && at.is_some_and(|at| ms(now) >= at))
    }

    /// Whether, in an epochal group, the device must rotate its leaf before
    /// it posts: its key is of an earlier period (12.10).
    pub fn must_rotate_before_sending(&self, now: Timestamp) -> bool {
        self.mode == Mode::Epochal && self.own.key_period < period_of_ms(ms(now))
    }

    /// A leaf's state now: for its next messages, and for the authority it
    /// uses. In an epochal group, a leaf is confirmed while an ATTEST for
    /// its current key, of the current period or of the one before within
    /// its grace hour, stands, or if it was confirmed pairwise before the
    /// group moved to epochal and still has the same key.
    pub fn state(&self, leaf: u32, now: Timestamp) -> LeafState {
        if leaf == self.own.index {
            return LeafState::Confirmed;
        }
        let Some(entry) = self.leaves.get(&leaf) else {
            return LeafState::Unconfirmed;
        };
        if entry.impostor.is_some() {
            return LeafState::Impostor;
        }
        if entry.confirmed {
            return LeafState::Confirmed;
        }
        let now = ms(now);
        let current = period_of_ms(now);
        if self.mode == Mode::Epochal
            && (entry.attested_for(current, now)
                || current
                    .checked_sub(1)
                    .is_some_and(|p| entry.attested_for(p, now)))
        {
            return LeafState::Confirmed;
        }
        LeafState::Unconfirmed
    }

    /// How to show a message from `leaf` whose post's `t` is `t`, as the
    /// device processes it at `now`. In an epochal group it is confirmed
    /// only if the leaf attested for the message's period and, by the
    /// device's clock, that period's grace hour has not ended (12.10). A
    /// public room treats an unconfirmed leaf's messages as a guest's.
    pub fn message_state(&self, leaf: u32, t: Timestamp, now: Timestamp) -> LeafState {
        let state = self.state(leaf, now);
        if self.mode == Mode::Pairwise || state == LeafState::Impostor || leaf == self.own.index {
            return state;
        }
        let Some(entry) = self.leaves.get(&leaf) else {
            return LeafState::Unconfirmed;
        };
        if entry.confirmed || entry.attested_for(period_of_ms(ms(t)), ms(now)) {
            LeafState::Confirmed
        } else {
            LeafState::Unconfirmed
        }
    }

    /// The leaves with a challenge pending or open (pairwise), or a
    /// deadline to meet, and the deadline if any.
    pub fn pending(&self) -> Vec<(u32, Option<Timestamp>)> {
        self.leaves
            .iter()
            .filter(|(_, l)| {
                l.impostor.is_none()
                    && !l.confirmed
                    && (l.want.is_some() || l.open.is_some() || l.deadline.is_some())
            })
            .map(|(&i, l)| (i, l.deadline.map(|d| timestamp(d.at))))
            .collect()
    }

    /// The leaves that are impostors to this device.
    pub fn impostors(&self) -> Vec<(u32, ImpostorReason)> {
        self.leaves
            .iter()
            .filter_map(|(&i, l)| l.impostor.map(|r| (i, r)))
            .collect()
    }
}

/// Whether a private room of `members` identities must be `epochal`
/// (6.2): past 256 members.
pub fn must_be_epochal(members: usize) -> bool {
    members > MAX_PAIRWISE_MEMBERS
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use risala_proto::content::Text;

    use super::*;
    use crate::epochal::{
        GRACE_MS, PERIOD_MS, REVEAL_DELAY_MS, grace_end, period_end, period_start, reveal_from,
    };
    use crate::primitives::tests::hex;

    /// Day 20766, 2026-11-09, at 10:00 UTC.
    const DAY: u32 = 20766;
    const MIN: u64 = 60_000;
    const HOUR: u64 = 3_600_000;

    fn at(ms: u64) -> Timestamp {
        Timestamp::from_unix_millis(ms).unwrap()
    }

    fn t0() -> u64 {
        period_start(DAY) + 10 * HOUR
    }

    #[derive(Default)]
    struct Dir(HashMap<Vec<u8>, DeviceStatus>);

    impl DeviceDirectory for Dir {
        fn device(&self, identity: &RisalaIdentity) -> DeviceStatus {
            self.0
                .get(&identity.encode())
                .cloned()
                .unwrap_or(DeviceStatus::NotCurrent)
        }
    }

    /// A device with one leaf in the group under test.
    struct Node {
        identity: RisalaIdentity,
        device_key: SigningKey,
        attestation: AttestationKey,
        periods: PeriodKeyring,
        reveals: RevealRegistry,
        leaf: LeafInfo,
        pseudonym: Pseudonym,
        confirmer: Option<Confirmer>,
    }

    impl Node {
        /// A device of `uid`, with keys from `seed`, at leaf `index`.
        fn new(uid: &str, seed: u8, index: u32) -> Node {
            let device_key = SigningKey::from_seed([seed; 32]);
            let identity = RisalaIdentity::device(uid.parse().unwrap(), device_key.device_id());
            Node::with_identity(identity, device_key, seed, index)
        }

        fn with_identity(
            identity: RisalaIdentity,
            device_key: SigningKey,
            seed: u8,
            index: u32,
        ) -> Node {
            let leaf_key = SigningKey::from_seed([seed.wrapping_add(100); 32]);
            Node {
                leaf: LeafInfo {
                    index,
                    identity: identity.clone(),
                    signature_key: leaf_key.public_key().to_vec(),
                },
                identity,
                device_key,
                attestation: AttestationKey::from_seed(Zeroizing::new([seed.wrapping_add(50); 32])),
                periods: PeriodKeyring::new(),
                reveals: RevealRegistry::new(),
                pseudonym: Pseudonym([seed; 16]),
                confirmer: None,
            }
        }

        fn register(&self, dir: &mut Dir) {
            dir.0.insert(
                self.identity.encode(),
                DeviceStatus::Current {
                    device_key: self.device_key.public_key().to_vec(),
                    attestation_key: self.attestation.public_key().to_vec(),
                },
            );
        }

        fn parts<'a>(&'a mut self, dir: &'a Dir) -> (&'a mut Confirmer, OwnDevice<'a>) {
            let Node {
                identity,
                device_key,
                attestation,
                periods,
                reveals,
                confirmer,
                ..
            } = self;
            (
                confirmer.as_mut().unwrap(),
                OwnDevice {
                    identity,
                    device_key,
                    attestation_key: attestation,
                    periods,
                    reveals,
                    directory: dir,
                },
            )
        }

        fn c(&self) -> &Confirmer {
            self.confirmer.as_ref().unwrap()
        }

        fn cm(&mut self) -> &mut Confirmer {
            self.confirmer.as_mut().unwrap()
        }

        /// The message this node posts at `now`: `lines`, then its pending
        /// confirmation lines, written and parsed again as on the wire.
        fn send(&mut self, dir: &Dir, lines: Vec<ContentLine>, now: u64) -> Option<Content> {
            let (confirmer, mut device) = self.parts(dir);
            let (extra, _) = confirmer.take_lines(&mut device, at(now));
            let all: Vec<ContentLine> = lines.into_iter().chain(extra).collect();
            if all.is_empty() {
                return None;
            }
            let content = Content::new(all).unwrap();
            Some(Content::parse(content.as_bytes()).unwrap())
        }

        fn receive(
            &mut self,
            dir: &Dir,
            from: &Node,
            content: &Content,
            t: u64,
            now: u64,
        ) -> Vec<Event> {
            self.receive_as(dir, from.leaf.index, Some(from.pseudonym), content, t, now)
        }

        fn receive_as(
            &mut self,
            dir: &Dir,
            sender: u32,
            pseudonym: Option<Pseudonym>,
            content: &Content,
            t: u64,
            now: u64,
        ) -> Vec<Event> {
            let (confirmer, mut device) = self.parts(dir);
            confirmer.message(
                &mut device,
                &Incoming {
                    sender,
                    t: at(t),
                    pseudonym,
                    content,
                },
                at(now),
            )
        }

        fn poll(&mut self, dir: &Dir, now: u64) -> Vec<Event> {
            let (confirmer, mut device) = self.parts(dir);
            confirmer.poll(&mut device, at(now))
        }

        fn state(&self, leaf: &Node, now: u64) -> LeafState {
            self.c().state(leaf.leaf.index, at(now))
        }
    }

    const GROUP: &[u8] = b"group-0123456789abcdef0123456789";

    /// Puts every node in one group.
    fn group(nodes: &mut [&mut Node], mode: ConfirmMode, with_yourself: bool, now: u64) {
        let leaves: Vec<LeafInfo> = nodes.iter().map(|n| n.leaf.clone()).collect();
        for node in nodes.iter_mut() {
            node.confirmer = Some(Confirmer::new(
                GROUP,
                mode,
                with_yourself,
                &node.leaf,
                node.pseudonym,
                &leaves,
                at(now),
            ));
        }
    }

    fn text(s: &str) -> Vec<ContentLine> {
        vec![ContentLine::Text(Text::new(s))]
    }

    fn challenges(content: &Content) -> Vec<u32> {
        content
            .lines()
            .iter()
            .filter_map(|l| match l {
                ContentLine::Challenge { leaf, .. } => Some(*leaf),
                _ => None,
            })
            .collect()
    }

    fn answers(content: &Content) -> Vec<u32> {
        content
            .lines()
            .iter()
            .filter_map(|l| match l {
                ContentLine::Answer { leaf, .. } => Some(*leaf),
                _ => None,
            })
            .collect()
    }

    // -----------------------------------------------------------------------
    // The construction

    #[test]
    fn confirm_content_encoding() {
        let bytes = confirm_content(b"gid", b"ct", b"a", b"b");
        assert_eq!(bytes[0], 1);
        assert_eq!(&bytes[1..5], b"\x03gid");
        assert_eq!(&bytes[5..53], &sha384(b"ct"));
        assert_eq!(&bytes[53..101], &sha384(b"a"));
        assert_eq!(&bytes[101..], &sha384(b"b"));
    }

    #[test]
    fn challenge_and_answer() {
        let a = AttestationKey::generate().unwrap();
        let (ct, ss) = encapsulate(a.public_key()).unwrap();
        let got = a.decapsulate(&ct).unwrap();
        assert_eq!(got, ss);
        let mac = confirm_mac(&got, b"g", &ct[..], b"A", b"B");
        assert!(check_answer(&ss, b"g", &ct[..], b"A", b"B", &mac));
        // Every input counts.
        assert!(!check_answer(&ss, b"h", &ct[..], b"A", b"B", &mac));
        assert!(!check_answer(&ss, b"g", &ct[..1119], b"A", b"B", &mac));
        assert!(!check_answer(&ss, b"g", &ct[..], b"B", b"A", &mac));
        assert!(!check_answer(&ss, b"g", &ct[..], b"A", b"C", &mac));
        assert!(!check_answer(&ss, b"g", &ct[..], b"A", b"B", &mac[..47]));
        let mut bad = mac;
        bad[47] ^= 1;
        assert!(!check_answer(&ss, b"g", &ct[..], b"A", b"B", &bad));
        // Another key decapsulates to something else (implicit rejection).
        let other = AttestationKey::generate().unwrap();
        assert_ne!(other.decapsulate(&ct).unwrap(), ss);
        assert_eq!(format!("{a:?}"), "AttestationKey(…)");
        assert_eq!(format!("{ss:?}"), "SharedSecret(…)");
    }

    /// The attestation key expands its seed as the pairing key and HPKE
    /// do (12.2: the expansion is pinned by a vector).
    #[test]
    fn attestation_key_expansion() {
        let seed = [0xa7; 32];
        let key = AttestationKey::from_seed(Zeroizing::new(seed));
        let pairing = crate::pairing::PairingKey::from_seed(Zeroizing::new(seed));
        assert_eq!(key.public_key(), pairing.public_key());
        assert_eq!(key.public_key().len(), X_WING_PUBLIC_KEY_LEN);
        assert_eq!(key.seed(), &seed);
    }

    /// Keys that fail the X-Wing check of 12.2 are refused before any
    /// encapsulation, short ones included (which libcrux-kem would slice
    /// and panic on).
    #[test]
    fn x_wing_key_checks() {
        let good = AttestationKey::generate().unwrap().public_key().to_vec();
        assert!(encapsulate(&good).is_ok());
        for bad in [
            Vec::new(),
            good[..1215].to_vec(),
            [&good[..], &[0]].concat(),
            vec![0xff; X_WING_PUBLIC_KEY_LEN],
            {
                let mut b = good.clone();
                b[0] = 0xff;
                b[1] |= 0x0f;
                b
            },
        ] {
            assert_eq!(
                encapsulate(&bad).unwrap_err(),
                ConfirmError::BadAttestationKey
            );
        }
    }

    // -----------------------------------------------------------------------
    // Pairwise groups

    #[test]
    fn two_members() {
        let mut dir = Dir::default();
        let mut alice = Node::new("alice@example.org", 1, 0);
        let mut bob = Node::new("bob@example.net", 2, 1);
        alice.register(&mut dir);
        bob.register(&mut dir);
        let now = t0();
        group(
            &mut [&mut alice, &mut bob],
            ConfirmMode::Pairwise,
            false,
            now,
        );
        // Nobody is challenged before they send (senders only).
        assert_eq!(alice.c().send_due(), None);
        assert_eq!(bob.c().send_due(), None);
        assert_eq!(bob.state(&alice, now), LeafState::Unconfirmed);

        // A message with nothing to show does not count.
        let typing = Content::new(vec![ContentLine::Typing]).unwrap();
        bob.receive(&dir, &alice, &typing, now, now);
        assert_eq!(bob.c().send_due(), None);

        // Alice says something: Bob challenges her within 10 minutes.
        let m1 = alice.send(&dir, text("hi"), now).unwrap();
        assert!(bob.receive(&dir, &alice, &m1, now, now).is_empty());
        let due = ms(bob.c().send_due().unwrap());
        assert!((now..now + SEND_WITHIN_MS).contains(&due));
        assert_eq!(bob.c().pending(), vec![(0, None)]);
        // Nothing to send while the line waits for Bob's next message.
        let m2 = bob.send(&dir, vec![], due).unwrap();
        assert_eq!(challenges(&m2), vec![0]);
        assert_eq!(m2.lines().len(), 1);
        assert_eq!(bob.c().send_due(), None);

        // Alice answers in her next message.
        assert!(alice.receive(&dir, &bob, &m2, due, due).is_empty());
        let due2 = ms(alice.c().send_due().unwrap());
        assert!((due..due + SEND_WITHIN_MS).contains(&due2));
        let m3 = alice.send(&dir, text("again"), due2).unwrap();
        assert_eq!(answers(&m3), vec![1]);
        let events = bob.receive(&dir, &alice, &m3, due2, due2);
        assert_eq!(events, vec![Event::Confirmed { leaf: 0 }]);
        assert_eq!(bob.state(&alice, due2), LeafState::Confirmed);
        assert_eq!(bob.c().pending(), vec![]);
        // Alice's message carried a TEXT, but Bob did not send one, so she
        // has no reason to challenge him: he stays unconfirmed to her.
        assert_eq!(alice.state(&bob, due2), LeafState::Unconfirmed);
        assert_eq!(alice.c().send_due(), None);
        // Once Bob says something, she challenges him too.
        let m4 = bob.send(&dir, text("hello"), due2).unwrap();
        alice.receive(&dir, &bob, &m4, due2, due2);
        assert!(alice.c().send_due().is_some());
    }

    #[test]
    fn three_members() {
        let mut dir = Dir::default();
        let mut a = Node::new("alice@example.org", 1, 0);
        let mut b = Node::new("bob@example.net", 2, 1);
        let mut c = Node::new("carol@example.com", 3, 5);
        for n in [&a, &b, &c] {
            n.register(&mut dir);
        }
        let now = t0();
        group(
            &mut [&mut a, &mut b, &mut c],
            ConfirmMode::Pairwise,
            false,
            now,
        );

        let m1 = a.send(&dir, text("hi all"), now).unwrap();
        b.receive(&dir, &a, &m1, now, now);
        c.receive(&dir, &a, &m1, now, now);
        let cb = b.send(&dir, vec![], now + MIN).unwrap();
        let cc = c.send(&dir, vec![], now + MIN).unwrap();
        // Each challenge is seen by everyone; only Alice answers.
        for (sender, msg) in [(&b, &cb), (&c, &cc)] {
            a.receive(&dir, sender, msg, now + MIN, now + MIN);
        }
        c.receive(&dir, &b, &cb, now + MIN, now + MIN);
        b.receive(&dir, &c, &cc, now + MIN, now + MIN);
        assert_eq!(b.c().send_due(), None, "B ignores a challenge to A");
        assert_eq!(c.c().send_due(), None);
        // One message carries both answers.
        let ans = a.send(&dir, vec![], now + 2 * MIN).unwrap();
        let mut got = answers(&ans);
        got.sort();
        assert_eq!(got, vec![1, 5]);
        assert_eq!(
            b.receive(&dir, &a, &ans, now + 2 * MIN, now + 2 * MIN),
            vec![Event::Confirmed { leaf: 0 }]
        );
        assert_eq!(
            c.receive(&dir, &a, &ans, now + 2 * MIN, now + 2 * MIN),
            vec![Event::Confirmed { leaf: 0 }]
        );
        // Alice answers only the newest challenge from each leaf: a second
        // one from Bob replaces the first.
        let mut b2 = Node::new("bob@example.net", 2, 1);
        b2.confirmer = b.confirmer.clone();
        assert_eq!(a.c().answers.len(), 0);
        a.receive(&dir, &b, &cb, now + 3 * MIN, now + 3 * MIN);
        a.receive(&dir, &b, &cb, now + 3 * MIN, now + 3 * MIN);
        assert_eq!(a.c().answers.len(), 1);
    }

    #[test]
    fn wrong_answer_is_an_impostor() {
        // Mallory holds a leaf whose credential names Alice's device, but
        // has not Alice's attestation key.
        let mut dir = Dir::default();
        let alice = Node::new("alice@example.org", 1, 0);
        alice.register(&mut dir);
        let mut mallory =
            Node::with_identity(alice.identity.clone(), SigningKey::from_seed([9; 32]), 9, 0);
        let mut bob = Node::new("bob@example.net", 2, 1);
        bob.register(&mut dir);
        let now = t0();
        group(
            &mut [&mut mallory, &mut bob],
            ConfirmMode::Pairwise,
            false,
            now,
        );
        let m1 = mallory.send(&dir, text("it's me, alice"), now).unwrap();
        bob.receive(&dir, &mallory, &m1, now, now);
        let ch = bob.send(&dir, vec![], now + MIN).unwrap();
        mallory.receive(&dir, &bob, &ch, now + MIN, now + MIN);
        let ans = mallory.send(&dir, vec![], now + 2 * MIN).unwrap();
        assert_eq!(answers(&ans), vec![1]);
        let events = bob.receive(&dir, &mallory, &ans, now + 2 * MIN, now + 2 * MIN);
        assert_eq!(
            events,
            vec![Event::Impostor {
                leaf: 0,
                reason: ImpostorReason::WrongAnswer
            }]
        );
        assert_eq!(bob.state(&mallory, now + 2 * MIN), LeafState::Impostor);
        assert_eq!(bob.c().impostors(), vec![(0, ImpostorReason::WrongAnswer)]);
        // Impostors stay impostors: no more challenges, nothing confirms.
        let m2 = mallory.send(&dir, text("really"), now + 3 * MIN).unwrap();
        bob.receive(&dir, &mallory, &m2, now + 3 * MIN, now + 3 * MIN);
        assert_eq!(bob.c().send_due(), None);
    }

    /// A relay: Mallory, whose leaf names Alice's device, passes Bob's
    /// challenge to the real Alice and her answer back to Bob. Alice's MAC
    /// names her own leaf key and Mallory's as the challenger, so Bob,
    /// who expects Mallory's and his own, rejects it.
    #[test]
    fn relayed_answer_is_an_impostor() {
        let mut dir = Dir::default();
        let mut alice = Node::new("alice@example.org", 1, 0);
        alice.register(&mut dir);
        let mut mallory =
            Node::with_identity(alice.identity.clone(), SigningKey::from_seed([9; 32]), 9, 2);
        let mut bob = Node::new("bob@example.net", 2, 1);
        bob.register(&mut dir);
        let now = t0();
        group(
            &mut [&mut alice, &mut bob, &mut mallory],
            ConfirmMode::Pairwise,
            false,
            now,
        );
        let m1 = mallory.send(&dir, text("hi"), now).unwrap();
        bob.receive(&dir, &mallory, &m1, now, now);
        let ch = bob.send(&dir, vec![], now + MIN).unwrap();
        let ContentLine::Challenge { ciphertext, .. } = &ch.lines()[0] else {
            panic!()
        };
        // Mallory sends the same ciphertext to Alice, as her own challenge.
        let relay = Content::single(ContentLine::Challenge {
            leaf: 0,
            ciphertext: ciphertext.clone(),
        })
        .unwrap();
        alice.receive(&dir, &mallory, &relay, now + MIN, now + MIN);
        let alice_answer = alice.send(&dir, vec![], now + 2 * MIN).unwrap();
        // (Alice also challenges Mallory, a new leaf of her own identity.)
        assert_eq!(challenges(&alice_answer), vec![2]);
        let mac = alice_answer
            .lines()
            .iter()
            .find_map(|l| match l {
                ContentLine::Answer { leaf: 2, mac } => Some(mac),
                _ => None,
            })
            .unwrap();
        let forwarded = Content::single(ContentLine::Answer { leaf: 1, mac: *mac }).unwrap();
        let events = bob.receive(&dir, &mallory, &forwarded, now + 2 * MIN, now + 2 * MIN);
        assert_eq!(
            events,
            vec![Event::Impostor {
                leaf: 2,
                reason: ImpostorReason::WrongAnswer
            }]
        );
    }

    /// Replays and reflections: an ANSWER posted again, or by another
    /// leaf, a CHALLENGE sent back to its maker, and the same exchange in
    /// another group.
    #[test]
    fn replays_and_reflections() {
        let mut dir = Dir::default();
        let mut alice = Node::new("alice@example.org", 1, 0);
        let mut bob = Node::new("bob@example.net", 2, 1);
        let mut carol = Node::new("carol@example.com", 3, 2);
        for n in [&alice, &bob, &carol] {
            n.register(&mut dir);
        }
        let now = t0();
        group(
            &mut [&mut alice, &mut bob, &mut carol],
            ConfirmMode::Pairwise,
            false,
            now,
        );
        let m1 = alice.send(&dir, text("hi"), now).unwrap();
        bob.receive(&dir, &alice, &m1, now, now);
        let ch = bob.send(&dir, vec![], now + MIN).unwrap();
        alice.receive(&dir, &bob, &ch, now + MIN, now + MIN);
        let ans = alice.send(&dir, vec![], now + 2 * MIN).unwrap();

        // Carol posts Alice's ANSWER as her own: Bob has no open challenge
        // to Carol, so it is ignored.
        assert!(
            bob.receive(&dir, &carol, &ans, now + 2 * MIN, now + 2 * MIN)
                .is_empty()
        );
        assert_eq!(bob.state(&carol, now), LeafState::Unconfirmed);
        // Bob's CHALLENGE reflected back to him by Carol: he answers Carol
        // (deniably, it proves nothing), and it confirms nobody.
        let reflected = Content::single(ContentLine::Challenge {
            leaf: 1,
            ciphertext: match &ch.lines()[0] {
                ContentLine::Challenge { ciphertext, .. } => ciphertext.clone(),
                _ => panic!(),
            },
        })
        .unwrap();
        assert!(
            bob.receive(&dir, &carol, &reflected, now + 2 * MIN, now + 2 * MIN)
                .is_empty()
        );
        assert_eq!(bob.c().pending(), vec![(0, None)]);

        // The real answer confirms Alice; replaying it changes nothing.
        assert_eq!(
            bob.receive(&dir, &alice, &ans, now + 2 * MIN, now + 2 * MIN),
            vec![Event::Confirmed { leaf: 0 }]
        );
        assert!(
            bob.receive(&dir, &alice, &ans, now + 3 * MIN, now + 3 * MIN)
                .is_empty()
        );
        assert_eq!(bob.state(&alice, now), LeafState::Confirmed);

        // In another group with the same leaves, the old answer does not
        // fit Bob's new challenge.
        let mut bob2 = Node::new("bob@example.net", 2, 1);
        let mut alice2 = Node::new("alice@example.org", 1, 0);
        let leaves = vec![alice2.leaf.clone(), bob2.leaf.clone()];
        for n in [&mut alice2, &mut bob2] {
            n.confirmer = Some(Confirmer::new(
                b"another group",
                ConfirmMode::Pairwise,
                false,
                &n.leaf,
                n.pseudonym,
                &leaves,
                at(now),
            ));
        }
        bob2.receive(&dir, &alice2, &m1, now, now);
        bob2.send(&dir, vec![], now + MIN).unwrap();
        assert_eq!(
            bob2.receive(&dir, &alice2, &ans, now + 2 * MIN, now + 2 * MIN),
            vec![Event::Impostor {
                leaf: 0,
                reason: ImpostorReason::WrongAnswer
            }]
        );
    }

    #[test]
    fn authority_without_answer_is_an_impostor() {
        let mut dir = Dir::default();
        let mut alice = Node::new("alice@example.org", 1, 0);
        let mut bob = Node::new("bob@example.net", 2, 1);
        alice.register(&mut dir);
        bob.register(&mut dir);
        let now = t0();
        group(
            &mut [&mut alice, &mut bob],
            ConfirmMode::Pairwise,
            false,
            now,
        );
        // Alice's leaf kicks someone: Bob challenges within a minute.
        bob.cm().authority_used(0, at(now));
        let due = ms(bob.c().send_due().unwrap());
        assert!(due < now + URGENT_WITHIN_MS);
        assert_eq!(
            bob.c().pending(),
            vec![(0, Some(at(now + IMPOSTOR_AFTER_MS)))]
        );
        assert_eq!(ms(bob.c().next_wake().unwrap()), due);
        let ch = bob.send(&dir, vec![], due).unwrap();
        assert_eq!(challenges(&ch), vec![0]);
        // The hour starts when the challenge goes.
        let end = due + IMPOSTOR_AFTER_MS;
        assert!(bob.poll(&dir, end - 1).is_empty());
        assert_eq!(
            bob.poll(&dir, end),
            vec![Event::Impostor {
                leaf: 0,
                reason: ImpostorReason::NoAnswer
            }]
        );
        assert_eq!(bob.state(&alice, end), LeafState::Impostor);
        // An answer that arrives later changes nothing.
        alice.receive(&dir, &bob, &ch, due, end);
        let ans = alice.send(&dir, vec![], end).unwrap();
        assert!(bob.receive(&dir, &alice, &ans, end, end).is_empty());
        assert_eq!(bob.state(&alice, end), LeafState::Impostor);
    }

    #[test]
    fn authority_answered_in_time() {
        let mut dir = Dir::default();
        let mut alice = Node::new("alice@example.org", 1, 0);
        let mut bob = Node::new("bob@example.net", 2, 1);
        alice.register(&mut dir);
        bob.register(&mut dir);
        let now = t0();
        group(
            &mut [&mut alice, &mut bob],
            ConfirmMode::Pairwise,
            false,
            now,
        );
        bob.cm().authority_used(0, at(now));
        let ch = bob.send(&dir, vec![], now + MIN).unwrap();
        // Alice made the authority commit: she answers within a minute.
        alice.cm().own_authority_used(at(now));
        alice.receive(&dir, &bob, &ch, now + MIN, now + MIN);
        assert!(ms(alice.c().send_due().unwrap()) < now + 2 * MIN);
        let ans = alice.send(&dir, vec![], now + 2 * MIN).unwrap();
        assert_eq!(
            bob.receive(&dir, &alice, &ans, now + 2 * MIN, now + 2 * MIN),
            vec![Event::Confirmed { leaf: 0 }]
        );
        assert!(bob.poll(&dir, now + 2 * IMPOSTOR_AFTER_MS).is_empty());
        // A confirmed leaf that uses authority is not challenged again.
        bob.cm().authority_used(0, at(now + 3 * HOUR));
        assert_eq!(bob.c().send_due(), None);
    }

    /// Every new leaf of the device's own identity is challenged at once,
    /// at most 64 in a group, and is an impostor without an answer within
    /// an hour (12.7).
    #[test]
    fn own_identity_leaves() {
        let mut dir = Dir::default();
        let mut me = Node::new("alice@example.org", 1, 0);
        me.register(&mut dir);
        let mut other = Node::new("bob@example.net", 2, 1);
        other.register(&mut dir);
        let now = t0();
        group(
            &mut [&mut me, &mut other],
            ConfirmMode::Pairwise,
            false,
            now,
        );
        // 70 new leaves of Alice's identity, of new devices.
        let mut leaves = vec![me.leaf.clone(), other.leaf.clone()];
        let mut nodes = Vec::new();
        for i in 0..70u32 {
            let n = Node::new("alice@example.org", 10 + i as u8, 10 + i);
            n.register(&mut dir);
            leaves.push(n.leaf.clone());
            nodes.push(n);
        }
        me.cm().set_leaves(&leaves, at(now));
        let pending = me.c().pending();
        assert_eq!(pending.len(), MAX_OWN_CHALLENGES);
        assert!(
            pending
                .iter()
                .all(|(_, d)| *d == Some(at(now + IMPOSTOR_AFTER_MS)))
        );
        assert!(ms(me.c().send_due().unwrap()) < now + URGENT_WITHIN_MS);
        let ch = me.send(&dir, vec![], now + MIN).unwrap();
        assert_eq!(challenges(&ch).len(), MAX_OWN_CHALLENGES);
        // Bob's device has no such duty.
        other.cm().set_leaves(&leaves, at(now));
        assert_eq!(other.c().pending(), vec![]);
        // The first answers; the rest do not.
        let first = &mut nodes[0];
        first.confirmer = Some(Confirmer::new(
            GROUP,
            ConfirmMode::Pairwise,
            false,
            &first.leaf,
            first.pseudonym,
            &leaves,
            at(now),
        ));
        first.receive(&dir, &me, &ch, now + MIN, now + MIN);
        let ans = first.send(&dir, vec![], now + 2 * MIN).unwrap();
        let first_index = first.leaf.index;
        assert_eq!(
            me.receive_as(&dir, first_index, None, &ans, now + 2 * MIN, now + 2 * MIN),
            vec![Event::Confirmed { leaf: first_index }]
        );
        let events = me.poll(&dir, now + IMPOSTOR_AFTER_MS + MIN);
        assert_eq!(events.len(), MAX_OWN_CHALLENGES - 1);
        assert!(events.iter().all(|e| matches!(
            e,
            Event::Impostor {
                reason: ImpostorReason::NoAnswer,
                ..
            }
        )));
    }

    /// In the conversation with yourself, every leaf is challenged at
    /// once, silent or not, and after 24 hours without an answer the user
    /// is asked (12.9).
    #[test]
    fn conversation_with_yourself() {
        let mut dir = Dir::default();
        let mut phone = Node::new("alice@example.org", 1, 0);
        let mut laptop = Node::new("alice@example.org", 2, 1);
        let mut tablet = Node::new("alice@example.org", 3, 2);
        for n in [&phone, &laptop, &tablet] {
            n.register(&mut dir);
        }
        let now = t0();
        group(
            &mut [&mut phone, &mut laptop, &mut tablet],
            ConfirmMode::Pairwise,
            true,
            now,
        );
        assert_eq!(phone.c().pending().len(), 2);
        assert!(ms(phone.c().send_due().unwrap()) < now + URGENT_WITHIN_MS);
        let ch = phone.send(&dir, vec![], now + MIN).unwrap();
        let mut got = challenges(&ch);
        got.sort();
        assert_eq!(got, vec![1, 2]);
        // The laptop answers within a minute; the tablet is off.
        laptop.receive(&dir, &phone, &ch, now + MIN, now + MIN);
        assert!(ms(laptop.c().send_due().unwrap()) < now + 2 * MIN);
        let ans = laptop.send(&dir, vec![], now + 2 * MIN).unwrap();
        assert!(answers(&ans).contains(&0));
        assert_eq!(
            phone.receive(&dir, &laptop, &ans, now + 2 * MIN, now + 2 * MIN),
            vec![Event::Confirmed { leaf: 1 }]
        );
        assert!(phone.poll(&dir, now + ASK_USER_AFTER_MS - 1).is_empty());
        assert_eq!(
            phone.poll(&dir, now + ASK_USER_AFTER_MS),
            vec![Event::Unanswered { leaf: 2 }]
        );
        // Asked once; the leaf is not marked an impostor.
        assert!(phone.poll(&dir, now + 2 * ASK_USER_AFTER_MS).is_empty());
        assert_eq!(
            phone.state(&tablet, now + ASK_USER_AFTER_MS),
            LeafState::Unconfirmed
        );
    }

    /// Guests are never challenged, and their lines do nothing.
    #[test]
    fn guests() {
        let mut dir = Dir::default();
        let mut alice = Node::new("alice@example.org", 1, 0);
        alice.register(&mut dir);
        let mut guest = Node::with_identity(
            RisalaIdentity::guest("~visitor".parse().unwrap()),
            SigningKey::from_seed([4; 32]),
            4,
            1,
        );
        let now = t0();
        group(
            &mut [&mut alice, &mut guest],
            ConfirmMode::Pairwise,
            false,
            now,
        );
        let m = Content::new(vec![
            ContentLine::Text(Text::new("hi")),
            ContentLine::Challenge {
                leaf: 0,
                ciphertext: ChallengeCiphertext::from_bytes(&[1; CHALLENGE_LEN]),
            },
        ])
        .unwrap();
        assert!(alice.receive(&dir, &guest, &m, now, now).is_empty());
        assert_eq!(alice.c().send_due(), None);
        alice.cm().authority_used(1, at(now));
        assert_eq!(alice.c().pending(), vec![]);
        assert_eq!(alice.state(&guest, now), LeafState::Unconfirmed);
    }

    /// A key file that cannot be fetched yet delays the challenge; a
    /// device that is not current cannot be confirmed.
    #[test]
    fn unknown_and_removed_devices() {
        let mut dir = Dir::default();
        let mut alice = Node::new("alice@example.org", 1, 0);
        let mut bob = Node::new("bob@example.net", 2, 1);
        let mut carol = Node::new("carol@example.com", 3, 2);
        bob.register(&mut dir);
        dir.0.insert(alice.identity.encode(), DeviceStatus::Unknown);
        let now = t0();
        group(
            &mut [&mut alice, &mut bob, &mut carol],
            ConfirmMode::Pairwise,
            false,
            now,
        );
        let m = alice.send(&dir, text("hi"), now).unwrap();
        bob.receive(&dir, &alice, &m, now, now);
        let m2 = carol.send(&dir, text("hi"), now).unwrap();
        bob.receive(&dir, &carol, &m2, now, now);
        let (lines, events) = {
            let (c, mut d) = bob.parts(&dir);
            c.take_lines(&mut d, at(now + MIN))
        };
        assert!(lines.is_empty());
        assert_eq!(events, vec![Event::DeviceNotCurrent { leaf: 2 }]);
        assert_eq!(bob.c().pending(), vec![(0, None)]);
        // Once Alice's key file arrives, the challenge goes.
        alice.register(&mut dir);
        let ch = bob.send(&dir, vec![], now + 2 * MIN).unwrap();
        assert_eq!(challenges(&ch), vec![0]);
        // A bad attestation key in a key file: no challenge.
        dir.0.insert(
            carol.identity.encode(),
            DeviceStatus::Current {
                device_key: carol.device_key.public_key().to_vec(),
                attestation_key: vec![0xff; X_WING_PUBLIC_KEY_LEN],
            },
        );
        let m3 = carol.send(&dir, text("hi"), now).unwrap();
        bob.receive(&dir, &carol, &m3, now + 3 * MIN, now + 3 * MIN);
        let (_, events) = {
            let (c, mut d) = bob.parts(&dir);
            c.take_lines(&mut d, at(now + 4 * MIN))
        };
        assert_eq!(events, vec![Event::BadAttestationKey { leaf: 2 }]);
    }

    /// A new signature key drops the open challenge, and an answer to it is
    /// then ignored; a removed leaf is forgotten.
    #[test]
    fn key_changes_and_removals() {
        let mut dir = Dir::default();
        let mut alice = Node::new("alice@example.org", 1, 0);
        let mut bob = Node::new("bob@example.net", 2, 1);
        alice.register(&mut dir);
        bob.register(&mut dir);
        let now = t0();
        group(
            &mut [&mut alice, &mut bob],
            ConfirmMode::Pairwise,
            false,
            now,
        );
        let m = alice.send(&dir, text("hi"), now).unwrap();
        bob.receive(&dir, &alice, &m, now, now);
        let ch = bob.send(&dir, vec![], now + MIN).unwrap();
        alice.receive(&dir, &bob, &ch, now + MIN, now + MIN);
        let ans = alice.send(&dir, vec![], now + 2 * MIN).unwrap();
        // Alice's leaf rotates (a last-resort join, 12.5) before her answer
        // arrives.
        let new_key = SigningKey::from_seed([77; 32]);
        let mut rotated = alice.leaf.clone();
        rotated.signature_key = new_key.public_key().to_vec();
        let leaves = [rotated.clone(), bob.leaf.clone()];
        bob.cm().set_leaves(&leaves, at(now + 2 * MIN));
        assert!(
            bob.receive(&dir, &alice, &ans, now + 2 * MIN, now + 2 * MIN)
                .is_empty()
        );
        assert_eq!(bob.state(&alice, now), LeafState::Unconfirmed);
        // Removed: forgotten.
        let leaves = [bob.leaf.clone()];
        bob.cm().set_leaves(&leaves, at(now + 3 * MIN));
        assert_eq!(bob.c().pending(), vec![]);
        assert!(
            bob.receive(&dir, &alice, &m, now + 3 * MIN, now + 3 * MIN)
                .is_empty()
        );

        // A confirmed leaf whose key changes needs confirming again.
        let mut carol = Node::new("carol@example.com", 3, 0);
        let mut dave = Node::new("dave@example.com", 4, 1);
        carol.register(&mut dir);
        dave.register(&mut dir);
        group(
            &mut [&mut carol, &mut dave],
            ConfirmMode::Pairwise,
            false,
            now,
        );
        let m = carol.send(&dir, text("hi"), now).unwrap();
        dave.receive(&dir, &carol, &m, now, now);
        let ch = dave.send(&dir, vec![], now).unwrap();
        carol.receive(&dir, &dave, &ch, now, now);
        let ans = carol.send(&dir, vec![], now).unwrap();
        dave.receive(&dir, &carol, &ans, now, now);
        assert_eq!(dave.state(&carol, now), LeafState::Confirmed);
        let mut rotated = carol.leaf.clone();
        rotated.signature_key = new_key.public_key().to_vec();
        let leaves = [rotated, dave.leaf.clone()];
        dave.cm().set_leaves(&leaves, at(now));
        assert_eq!(dave.state(&carol, now), LeafState::Unconfirmed);
    }

    /// A new device of the user's own identity that joined from its
    /// last-resort KeyPackage, was challenged at once, and then rotated its
    /// leaf key (12.3, 12.5) is not an impostor: an ANSWER to the dropped
    /// challenge, made with its old key or its new one, is ignored, not
    /// checked against the newer challenge (12.10, CR-M3).
    #[test]
    fn last_resort_rotation_is_not_an_impostor() {
        let mut dir = Dir::default();
        let mut b = Node::new("alice@example.org", 1, 0);
        let mut bob = Node::new("bob@example.net", 2, 1);
        let mut a = Node::new("alice@example.org", 3, 2);
        for n in [&b, &bob, &a] {
            n.register(&mut dir);
        }
        let now = t0();
        group(&mut [&mut b, &mut bob], ConfirmMode::Pairwise, false, now);
        // A joins; B challenges its new leaf at once.
        let leaves = [b.leaf.clone(), bob.leaf.clone(), a.leaf.clone()];
        b.cm().set_leaves(&leaves, at(now));
        a.confirmer = Some(Confirmer::new(
            GROUP,
            ConfirmMode::Pairwise,
            false,
            &a.leaf,
            a.pseudonym,
            &leaves,
            at(now),
        ));
        let ch1 = b.send(&dir, vec![], now + MIN).unwrap();
        assert_eq!(challenges(&ch1), vec![a.leaf.index]);
        // A answers with its KeyPackage's key, but B sees the rotation
        // before the answer.
        a.receive(&dir, &b, &ch1, now + MIN, now + MIN);
        let old_answer = a.send(&dir, vec![], now + 2 * MIN).unwrap();
        assert_eq!(answers(&old_answer), vec![b.leaf.index]);
        let new_key = SigningKey::from_seed([88; 32]);
        a.leaf.signature_key = new_key.public_key().to_vec();
        let pseudonym = a.pseudonym;
        a.cm()
            .own_leaf_changed(new_key.public_key(), pseudonym, at(now + 2 * MIN));
        let leaves = [b.leaf.clone(), bob.leaf.clone(), a.leaf.clone()];
        b.cm().set_leaves(&leaves, at(now + 2 * MIN));
        // B challenges the new key at once.
        let ch2 = b.send(&dir, vec![], now + 3 * MIN).unwrap();
        assert_eq!(challenges(&ch2), vec![a.leaf.index]);
        // The old answer arrives: ignored, not a wrong answer.
        assert_eq!(
            b.receive(&dir, &a, &old_answer, now + 3 * MIN, now + 3 * MIN),
            vec![]
        );
        assert_eq!(b.state(&a, now + 3 * MIN), LeafState::Unconfirmed);
        // An answer to the dropped challenge made with the new key (A read
        // ch1 again, as a resend, after rotating) is ignored too.
        a.receive(&dir, &b, &ch1, now + 3 * MIN, now + 3 * MIN);
        let late = a.send(&dir, vec![], now + 4 * MIN).unwrap();
        assert_eq!(
            b.receive(&dir, &a, &late, now + 4 * MIN, now + 4 * MIN),
            vec![]
        );
        // A answers the new challenge: confirmed.
        a.receive(&dir, &b, &ch2, now + 4 * MIN, now + 4 * MIN);
        let answer = a.send(&dir, vec![], now + 5 * MIN).unwrap();
        assert_eq!(
            b.receive(&dir, &a, &answer, now + 5 * MIN, now + 5 * MIN),
            vec![Event::Confirmed { leaf: a.leaf.index }]
        );
        // A's answers made before a rotation are not sent after it.
        let mut c = Node::new("alice@example.org", 4, 3);
        c.register(&mut dir);
        let leaves = [
            b.leaf.clone(),
            bob.leaf.clone(),
            a.leaf.clone(),
            c.leaf.clone(),
        ];
        b.cm().set_leaves(&leaves, at(now + 6 * MIN));
        c.confirmer = Some(Confirmer::new(
            GROUP,
            ConfirmMode::Pairwise,
            false,
            &c.leaf,
            c.pseudonym,
            &leaves,
            at(now + 6 * MIN),
        ));
        let ch = b.send(&dir, vec![], now + 7 * MIN).unwrap();
        c.receive(&dir, &b, &ch, now + 7 * MIN, now + 7 * MIN);
        let pseudonym = c.pseudonym;
        c.cm()
            .own_leaf_changed(&[9; 1312], pseudonym, at(now + 7 * MIN));
        assert!(
            c.send(&dir, vec![], now + 8 * MIN)
                .is_none_or(|content| answers(&content).is_empty())
        );
    }

    /// An unanswered challenge goes again, unchanged, when the leaf shows
    /// that it is active, at most [`MAX_RESENDS`] times; a late answer to
    /// it still confirms.
    #[test]
    fn resends() {
        let mut dir = Dir::default();
        let mut alice = Node::new("alice@example.org", 1, 0);
        let mut bob = Node::new("bob@example.net", 2, 1);
        alice.register(&mut dir);
        bob.register(&mut dir);
        let now = t0();
        group(
            &mut [&mut alice, &mut bob],
            ConfirmMode::Pairwise,
            false,
            now,
        );
        let m = alice.send(&dir, text("hi"), now).unwrap();
        bob.receive(&dir, &alice, &m, now, now);
        let ch = bob.send(&dir, vec![], now).unwrap();
        // Alice never saw it (it expired, 7.5), and keeps talking.
        bob.receive(&dir, &alice, &m, now + MIN, now + MIN);
        assert_eq!(bob.c().send_due(), None, "too soon to send it again");
        let mut sent = Vec::new();
        for i in 1..=MAX_RESENDS as u64 + 2 {
            let t = now + i * RESEND_AFTER_MS;
            bob.receive(&dir, &alice, &m, t, t);
            if let Some(again) = bob.send(&dir, vec![], t) {
                assert_eq!(again.as_str(), ch.as_str(), "the same challenge");
                sent.push(t);
            }
        }
        assert_eq!(sent.len(), MAX_RESENDS as usize);
        alice.receive(&dir, &bob, &ch, now, now + 9 * HOUR);
        let ans = alice.send(&dir, vec![], now + 9 * HOUR).unwrap();
        assert_eq!(
            bob.receive(&dir, &alice, &ans, now + 9 * HOUR, now + 9 * HOUR),
            vec![Event::Confirmed { leaf: 0 }]
        );
    }

    /// The state survives serialisation in the middle of a challenge.
    #[test]
    fn serialised_state() {
        let mut dir = Dir::default();
        let mut alice = Node::new("alice@example.org", 1, 0);
        let mut bob = Node::new("bob@example.net", 2, 1);
        alice.register(&mut dir);
        bob.register(&mut dir);
        let now = t0();
        group(
            &mut [&mut alice, &mut bob],
            ConfirmMode::Pairwise,
            false,
            now,
        );
        let m = alice.send(&dir, text("hi"), now).unwrap();
        bob.receive(&dir, &alice, &m, now, now);
        let ch = bob.send(&dir, vec![], now).unwrap();
        let json = serde_json::to_string(bob.c()).unwrap();
        bob.confirmer = Some(serde_json::from_str(&json).unwrap());
        alice.receive(&dir, &bob, &ch, now, now);
        let ans = alice.send(&dir, vec![], now).unwrap();
        assert_eq!(
            bob.receive(&dir, &alice, &ans, now, now),
            vec![Event::Confirmed { leaf: 0 }]
        );
    }

    #[test]
    fn threshold() {
        assert!(!must_be_epochal(256));
        assert!(must_be_epochal(257));
    }

    /// Moving to epochal drops the pairwise lines; confirmed keys stay
    /// confirmed until they change.
    #[test]
    fn move_to_epochal() {
        let mut dir = Dir::default();
        let mut alice = Node::new("alice@example.org", 1, 0);
        let mut bob = Node::new("bob@example.net", 2, 1);
        let mut carol = Node::new("carol@example.com", 3, 2);
        for n in [&alice, &bob, &carol] {
            n.register(&mut dir);
        }
        let now = t0();
        group(
            &mut [&mut alice, &mut bob, &mut carol],
            ConfirmMode::Pairwise,
            false,
            now,
        );
        let m = alice.send(&dir, text("hi"), now).unwrap();
        bob.receive(&dir, &alice, &m, now, now);
        let ch = bob.send(&dir, vec![], now).unwrap();
        alice.receive(&dir, &bob, &ch, now, now);
        let ans = alice.send(&dir, vec![], now).unwrap();
        bob.receive(&dir, &alice, &ans, now, now);
        let m2 = carol.send(&dir, text("hi"), now).unwrap();
        bob.receive(&dir, &carol, &m2, now, now);
        assert!(bob.c().send_due().is_some());
        bob.cm().set_mode(ConfirmMode::Epochal);
        assert_eq!(bob.c().mode(), ConfirmMode::Epochal);
        assert_eq!(bob.c().pending(), vec![]);
        assert_eq!(bob.state(&alice, now), LeafState::Confirmed);
        assert_eq!(bob.state(&carol, now), LeafState::Unconfirmed);
    }

    // -----------------------------------------------------------------------
    // Epochal groups

    /// Alice's leaf rotates for the period, attests, and reveals.
    #[test]
    fn epochal_attest_and_reveal() {
        let mut dir = Dir::default();
        let mut alice = Node::new("alice@example.org", 1, 0);
        let mut bob = Node::new("bob@example.net", 2, 1);
        alice.register(&mut dir);
        bob.register(&mut dir);
        let now = t0();
        group(
            &mut [&mut alice, &mut bob],
            ConfirmMode::Epochal,
            false,
            now,
        );
        assert!(!alice.c().must_rotate_before_sending(at(now)));
        // The first message of the period carries the ATTEST.
        let m = alice.send(&dir, text("hi"), now).unwrap();
        assert!(matches!(
            m.lines()[1],
            ContentLine::Attest { period: DAY, .. }
        ));
        let events = bob.receive(&dir, &alice, &m, now, now);
        assert_eq!(
            events,
            vec![Event::Attested {
                leaf: 0,
                period: DAY,
                pseudonym: alice.pseudonym
            }]
        );
        assert_eq!(bob.state(&alice, now), LeafState::Confirmed);
        assert_eq!(
            bob.c().message_state(0, at(now), at(now)),
            LeafState::Confirmed
        );
        // The next message does not attest again.
        let m2 = alice.send(&dir, text("again"), now + MIN).unwrap();
        assert_eq!(m2.lines().len(), 1);
        // A message of the day before is not covered.
        assert_eq!(
            bob.c().message_state(0, at(now - PERIOD_MS), at(now)),
            LeafState::Unconfirmed
        );
        // Confirmed through the grace hour, by Bob's clock, and no longer.
        let end = grace_end(DAY);
        assert_eq!(bob.state(&alice, end - 1), LeafState::Confirmed);
        assert_eq!(
            bob.c().message_state(0, at(now), at(end - 1)),
            LeafState::Confirmed
        );
        assert_eq!(bob.state(&alice, end), LeafState::Unconfirmed);
        assert_eq!(
            bob.c().message_state(0, at(now), at(end)),
            LeafState::Unconfirmed
        );

        // No REVEAL before 3 hours after the period ends.
        let early = period_end(DAY) + REVEAL_DELAY_MS - 1;
        let due = ms(alice.c().send_due().unwrap());
        assert!((reveal_from(DAY)..reveal_from(DAY) + REVEAL_WITHIN_MS).contains(&due));
        // (Alice rotated for the new day, so her messages may go.)
        let next_key = SigningKey::from_seed([201; 32]);
        alice.cm().own_leaf_changed(
            next_key.public_key(),
            Pseudonym([42; 16]),
            at(period_end(DAY)),
        );
        let m3 = alice.send(&dir, text("new day"), early).unwrap();
        assert!(
            !m3.lines()
                .iter()
                .any(|l| matches!(l, ContentLine::Reveal { .. }))
        );
        let m4 = alice.send(&dir, text("later"), reveal_from(DAY)).unwrap();
        let reveals: Vec<_> = m4
            .lines()
            .iter()
            .filter(|l| matches!(l, ContentLine::Reveal { .. }))
            .collect();
        assert_eq!(reveals.len(), 1);
        assert!(matches!(
            reveals[0],
            ContentLine::Reveal { period: DAY, .. }
        ));
        // Bob checks it against the key Alice attested with.
        assert!(
            bob.receive(&dir, &alice, &m4, reveal_from(DAY), reveal_from(DAY))
                .is_empty()
        );
        // The ATTEST of that day, replayed, is now worthless everywhere.
        let mut carol = Node::new("carol@example.com", 3, 1);
        carol.register(&mut dir);
        let mut alice_elsewhere = Node::new("alice@example.org", 1, 0);
        group(
            &mut [&mut alice_elsewhere, &mut carol],
            ConfirmMode::Epochal,
            false,
            now,
        );
        // Carol shares Bob's registry of REVEALs.
        std::mem::swap(&mut carol.reveals, &mut bob.reveals);
        let events = carol.receive(&dir, &alice, &m, now, now);
        assert_eq!(
            events,
            vec![Event::InvalidAttestation {
                leaf: 0,
                error: AttestError::Revealed
            }]
        );
        // No more REVEALs owed.
        assert!(alice.send(&dir, vec![], reveal_from(DAY) + HOUR).is_none());
    }

    /// Period boundaries: an ATTEST posted just before midnight is
    /// accepted through the grace hour, and not after; one whose post is
    /// outside the period is not valid.
    #[test]
    fn epochal_boundaries_and_late_attestations() {
        let mut dir = Dir::default();
        let mut alice = Node::new("alice@example.org", 1, 0);
        let mut bob = Node::new("bob@example.net", 2, 1);
        alice.register(&mut dir);
        bob.register(&mut dir);
        let late_evening = period_end(DAY) - MIN;
        group(
            &mut [&mut alice, &mut bob],
            ConfirmMode::Epochal,
            false,
            late_evening,
        );
        let m = alice.send(&dir, text("hi"), late_evening).unwrap();

        // Processed in the grace hour: accepted, until the grace hour ends.
        let mut bob2 = Node::new("bob@example.net", 2, 1);
        bob2.confirmer = bob.confirmer.clone();
        let in_grace = period_end(DAY) + 30 * MIN;
        assert!(matches!(
            bob2.receive(&dir, &alice, &m, late_evening, in_grace)[..],
            [Event::Attested { .. }]
        ));
        assert_eq!(bob2.state(&alice, in_grace), LeafState::Confirmed);
        assert_eq!(
            bob2.state(&alice, period_end(DAY) + GRACE_MS),
            LeafState::Unconfirmed
        );

        // Processed after it (Bob was offline): too late.
        let mut bob3 = Node::new("bob@example.net", 2, 1);
        bob3.confirmer = bob.confirmer.clone();
        let after = period_end(DAY) + GRACE_MS;
        assert_eq!(
            bob3.receive(&dir, &alice, &m, late_evening, after),
            vec![Event::InvalidAttestation {
                leaf: 0,
                error: AttestError::Late
            }]
        );
        assert_eq!(
            bob3.c().message_state(0, at(late_evening), at(after)),
            LeafState::Unconfirmed
        );

        // A post whose t is past the grace hour: not valid.
        assert_eq!(
            bob.receive(&dir, &alice, &m, after, in_grace),
            vec![Event::InvalidAttestation {
                leaf: 0,
                error: AttestError::OutsidePeriod
            }]
        );
        // The pseudonym must be the message's.
        assert_eq!(
            bob.receive_as(
                &dir,
                0,
                Some(Pseudonym([0xee; 16])),
                &m,
                late_evening,
                late_evening
            ),
            vec![Event::InvalidAttestation {
                leaf: 0,
                error: AttestError::Pseudonym
            }]
        );
        // On the new day Alice must rotate before she sends.
        assert!(alice.c().must_rotate_before_sending(at(period_end(DAY))));
        assert!(
            !alice
                .c()
                .must_rotate_before_sending(at(period_end(DAY) - 1))
        );
    }

    /// A device that sent the day before plans its rotation in the first
    /// 12 hours of the new day; one that did not, does not.
    #[test]
    fn epochal_rotation() {
        let mut dir = Dir::default();
        let mut alice = Node::new("alice@example.org", 1, 0);
        let mut bob = Node::new("bob@example.net", 2, 1);
        alice.register(&mut dir);
        bob.register(&mut dir);
        let now = t0();
        group(
            &mut [&mut alice, &mut bob],
            ConfirmMode::Epochal,
            false,
            now,
        );
        alice.send(&dir, text("hi"), now).unwrap();
        let next = period_end(DAY);
        alice.poll(&dir, next);
        bob.poll(&dir, next);
        let Some((p, Some(time))) = alice.c().rotation else {
            panic!("a rotation is planned")
        };
        assert_eq!(p, DAY + 1);
        assert!((next..next + ROTATE_WITHIN_MS).contains(&time));
        assert!(!alice.c().rotation_due(at(time - 1)));
        assert!(alice.c().rotation_due(at(time)));
        assert!(ms(alice.c().next_wake().unwrap()) <= time);
        assert_eq!(bob.c().rotation, Some((DAY + 1, None)));
        assert!(!bob.c().rotation_due(at(next + ROTATE_WITHIN_MS)));
        // Once the new key is in effect, nothing more is due.
        alice
            .cm()
            .own_leaf_changed(&[1; 1312], Pseudonym([3; 16]), at(time));
        assert!(!alice.c().rotation_due(at(time)));
        assert!(!alice.c().must_rotate_before_sending(at(time)));
    }

    /// In an epochal group, a leaf that uses authority must attest within
    /// an hour; a REVEAL that does not derive the attested key, or none at
    /// all, is reported.
    #[test]
    fn epochal_authority_and_bad_reveals() {
        let mut dir = Dir::default();
        let mut alice = Node::new("alice@example.org", 1, 0);
        let mut bob = Node::new("bob@example.net", 2, 1);
        let mut carol = Node::new("carol@example.com", 3, 2);
        for n in [&alice, &bob, &carol] {
            n.register(&mut dir);
        }
        let now = t0();
        group(
            &mut [&mut alice, &mut bob, &mut carol],
            ConfirmMode::Epochal,
            false,
            now,
        );
        // Carol commits with authority and never attests.
        bob.cm().authority_used(2, at(now));
        // Alice does, and attests in a message of her own.
        bob.cm().authority_used(0, at(now));
        alice.cm().own_authority_used(at(now));
        let due = ms(alice.c().send_due().unwrap());
        assert!(due < now + SEND_WITHIN_MS);
        let m = alice.send(&dir, vec![], due).unwrap();
        bob.receive(&dir, &alice, &m, due, due);
        assert_eq!(
            bob.poll(&dir, now + IMPOSTOR_AFTER_MS),
            vec![Event::Impostor {
                leaf: 2,
                reason: ImpostorReason::NoAttestation
            }]
        );
        assert_eq!(
            bob.state(&alice, now + IMPOSTOR_AFTER_MS),
            LeafState::Confirmed
        );

        // A REVEAL with the wrong seed.
        let bad = Content::single(ContentLine::Reveal {
            period: DAY,
            seed: risala_proto::content::PeriodSeed::from_bytes([5; 32]),
        })
        .unwrap();
        let t = reveal_from(DAY);
        assert_eq!(
            bob.receive(&dir, &alice, &bad, t, t),
            vec![Event::BadReveal {
                leaf: 0,
                period: DAY
            }]
        );
        // And none at all, for days.
        let events = bob.poll(&dir, reveal_from(DAY) + REVEAL_MISSING_AFTER_MS);
        assert_eq!(
            events,
            vec![Event::RevealMissing {
                leaf: 0,
                period: DAY
            }]
        );
        assert!(
            bob.poll(&dir, reveal_from(DAY) + 2 * REVEAL_MISSING_AFTER_MS)
                .is_empty()
        );
    }

    /// An ATTEST whose device's key file is not known yet waits for it.
    #[test]
    fn epochal_attest_waits_for_key_file() {
        let mut dir = Dir::default();
        let mut alice = Node::new("alice@example.org", 1, 0);
        let mut bob = Node::new("bob@example.net", 2, 1);
        bob.register(&mut dir);
        dir.0.insert(alice.identity.encode(), DeviceStatus::Unknown);
        let now = t0();
        group(
            &mut [&mut alice, &mut bob],
            ConfirmMode::Epochal,
            false,
            now,
        );
        let m = alice.send(&dir, text("hi"), now).unwrap();
        assert!(bob.receive(&dir, &alice, &m, now, now).is_empty());
        assert_eq!(bob.state(&alice, now), LeafState::Unconfirmed);
        alice.register(&mut dir);
        assert!(matches!(
            bob.poll(&dir, now + MIN)[..],
            [Event::Attested { leaf: 0, .. }]
        ));
        assert_eq!(bob.state(&alice, now + MIN), LeafState::Confirmed);
        // A device removed from its identity: not valid.
        dir.0
            .insert(alice.identity.encode(), DeviceStatus::NotCurrent);
        assert_eq!(
            bob.receive(&dir, &alice, &m, now, now),
            vec![Event::InvalidAttestation {
                leaf: 0,
                error: AttestError::DeviceNotCurrent
            }]
        );
    }

    /// A leaf whose credential names Alice's device cannot attest as her:
    /// it has no certificate from her device key.
    #[test]
    fn epochal_impostor_cannot_attest() {
        let mut dir = Dir::default();
        let alice = Node::new("alice@example.org", 1, 0);
        alice.register(&mut dir);
        let mut mallory =
            Node::with_identity(alice.identity.clone(), SigningKey::from_seed([9; 32]), 9, 0);
        let mut bob = Node::new("bob@example.net", 2, 1);
        bob.register(&mut dir);
        let now = t0();
        group(
            &mut [&mut mallory, &mut bob],
            ConfirmMode::Epochal,
            false,
            now,
        );
        let m = mallory.send(&dir, text("hi"), now).unwrap();
        assert_eq!(
            bob.receive(&dir, &mallory, &m, now, now),
            vec![Event::InvalidAttestation {
                leaf: 0,
                error: AttestError::Certificate
            }]
        );
        assert_eq!(
            bob.c().message_state(0, at(now), at(now)),
            LeafState::Unconfirmed
        );
    }

    /// The hour to answer starts when the challenge goes: a leaf whose key
    /// file cannot be fetched is not an impostor for that (12.7). And no
    /// timer stays in the past once acted on.
    #[test]
    fn deadlines_wait_for_key_files_and_timers_move_on() {
        let mut dir = Dir::default();
        let mut alice = Node::new("alice@example.org", 1, 0);
        let mut bob = Node::new("bob@example.net", 2, 1);
        bob.register(&mut dir);
        dir.0.insert(alice.identity.encode(), DeviceStatus::Unknown);
        let now = t0();
        group(
            &mut [&mut alice, &mut bob],
            ConfirmMode::Pairwise,
            false,
            now,
        );
        bob.cm().authority_used(0, at(now));
        // The challenge cannot go; its send time moves on each time.
        let due = ms(bob.c().send_due().unwrap());
        assert!(bob.send(&dir, vec![], due).is_none());
        assert!(ms(bob.c().send_due().unwrap()) > due);
        // An hour later: not an impostor, the deadline waits.
        assert!(bob.poll(&dir, now + IMPOSTOR_AFTER_MS).is_empty());
        assert!(bob.send(&dir, vec![], now + IMPOSTOR_AFTER_MS).is_none());
        assert!(ms(bob.c().next_wake().unwrap()) > now + IMPOSTOR_AFTER_MS);
        // The key file arrives; the challenge goes; the hour starts.
        alice.register(&mut dir);
        let sent = now + IMPOSTOR_AFTER_MS + 5 * MIN;
        let ch = bob.send(&dir, vec![], sent).unwrap();
        assert_eq!(challenges(&ch), vec![0]);
        assert_eq!(
            bob.c().pending(),
            vec![(0, Some(at(sent + IMPOSTOR_AFTER_MS)))]
        );
        assert!(bob.poll(&dir, sent + IMPOSTOR_AFTER_MS - 1).is_empty());
        assert_eq!(
            bob.poll(&dir, sent + IMPOSTOR_AFTER_MS),
            vec![Event::Impostor {
                leaf: 0,
                reason: ImpostorReason::NoAnswer
            }]
        );
        // Nothing left to wake for.
        assert_eq!(bob.c().next_wake(), None);
        // A leaf naming a removed device that uses authority is an
        // impostor at its deadline.
        let mut carol = Node::new("carol@example.com", 3, 0);
        let mut dave = Node::new("dave@example.com", 4, 1);
        dave.register(&mut dir);
        group(
            &mut [&mut carol, &mut dave],
            ConfirmMode::Pairwise,
            false,
            now,
        );
        dave.cm().authority_used(0, at(now));
        let (lines, events) = {
            let (c, mut d) = dave.parts(&dir);
            c.take_lines(&mut d, at(now + MIN))
        };
        assert!(lines.is_empty());
        assert_eq!(events, vec![Event::DeviceNotCurrent { leaf: 0 }]);
        assert!(matches!(
            dave.poll(&dir, now + IMPOSTOR_AFTER_MS)[..],
            [Event::Impostor { leaf: 0, .. }]
        ));
    }

    /// In an epochal group the device wakes for the next period, and an
    /// ATTEST owed for an authority commit goes once it has rotated.
    #[test]
    fn epochal_timers() {
        let mut dir = Dir::default();
        let mut alice = Node::new("alice@example.org", 1, 0);
        let mut bob = Node::new("bob@example.net", 2, 1);
        alice.register(&mut dir);
        bob.register(&mut dir);
        let now = t0();
        group(
            &mut [&mut alice, &mut bob],
            ConfirmMode::Epochal,
            false,
            now,
        );
        assert_eq!(ms(bob.c().next_wake().unwrap()), period_end(DAY));
        // Alice's key is of yesterday; she makes an authority commit.
        let tomorrow = period_end(DAY) + HOUR;
        alice.cm().own_authority_used(at(tomorrow));
        assert!(alice.c().must_rotate_before_sending(at(tomorrow)));
        let m = alice.send(&dir, vec![], tomorrow);
        assert!(m.is_none(), "no ATTEST with yesterday's key");
        assert!(alice.c().send_due().is_none());
        // She rotates; the ATTEST goes within a minute.
        let key = SigningKey::from_seed([202; 32]);
        alice
            .cm()
            .own_leaf_changed(key.public_key(), Pseudonym([7; 16]), at(tomorrow + MIN));
        let due = ms(alice.c().send_due().unwrap());
        assert!(due < tomorrow + 2 * MIN);
        let m = alice.send(&dir, vec![], due).unwrap();
        assert!(matches!(m.lines()[..], [ContentLine::Attest { .. }]));
    }

    // -----------------------------------------------------------------------
    // Vectors

    /// The confirm MAC (12.10), for Appendix B (task V1): from a fixed
    /// attestation key seed, encapsulation randomness, group id and leaf
    /// keys. Run with `--nocapture` to print it.
    #[test]
    fn vectors() {
        let attestation_seed = [0x55; 32];
        let randomness = [0x66; ENCAPSULATION_RANDOMNESS_LEN];
        let group_id = [0x33; 32];
        let answerer = SigningKey::from_seed([0x44; 32]);
        let challenger = SigningKey::from_seed([0x77; 32]);
        let key = AttestationKey::from_seed(Zeroizing::new(attestation_seed));
        let (ct, ss) = encapsulate_derand(key.public_key(), &randomness).unwrap();
        assert_eq!(key.decapsulate(&ct).unwrap(), ss);
        let content = confirm_content(
            &group_id,
            &ct[..],
            answerer.public_key(),
            challenger.public_key(),
        );
        let k = confirm_key(&ss);
        let mac = confirm_mac(
            &ss,
            &group_id,
            &ct[..],
            answerer.public_key(),
            challenger.public_key(),
        );
        let challenge = ContentLine::Challenge {
            leaf: 3,
            ciphertext: ChallengeCiphertext::from_bytes(&ct),
        };
        let answer = ContentLine::Answer {
            leaf: 7,
            mac: ConfirmMac::from_bytes(mac),
        };

        println!("== confirm (12.10)");
        println!("attestation key seed = {}", hex(&attestation_seed));
        println!("attestation key = {}", hex(key.public_key()));
        println!("encapsulation randomness = {}", hex(&randomness));
        println!("ct = {}", hex(&ct[..]));
        println!("ss = {}", hex(ss.as_bytes()));
        println!("group id = {}", hex(&group_id));
        println!("answerer leaf key seed = {}", hex(&[0x44; 32]));
        println!("challenger leaf key seed = {}", hex(&[0x77; 32]));
        println!("ConfirmContent = {}", hex(&content));
        println!("K = {}", hex(&k[..]));
        println!("MAC = {}", hex(&mac));
        println!("{}", challenge.to_line().unwrap());
        println!("{}", answer.to_line().unwrap());
        println!(
            "sha384(attestation key) = {}",
            hex(&sha384(key.public_key()))
        );
        println!("sha384(ct) = {}", hex(&sha384(&ct[..])));

        assert_eq!(hex(&sha384(&ct[..])), PINNED_CT_HASH);
        assert_eq!(hex(ss.as_bytes()), PINNED_SS);
        assert_eq!(hex(&mac), PINNED_MAC);
    }

    /// Appendix B.12: the same vectors, checked against the appendix.
    #[test]
    fn appendix_b() {
        let mut ck = crate::appendix::Checker::open("B.12 ");
        let attestation_seed = [0x55; 32];
        let randomness = [0x66; ENCAPSULATION_RANDOMNESS_LEN];
        let group_id = [0x33; 32];
        let answerer = SigningKey::from_seed([0x44; 32]);
        let challenger = SigningKey::from_seed([0x77; 32]);
        ck.hex("attestation key seed", &attestation_seed);
        ck.hex("encapsulation randomness", &randomness);
        ck.hex("group id", &group_id);
        ck.hex("answerer leaf key seed", &[0x44; 32]);
        ck.eq("answerer leaf index", "3");
        ck.hex("challenger leaf key seed", &[0x77; 32]);
        ck.eq("challenger leaf index", "7");
        ck.gap();
        let key = AttestationKey::from_seed(Zeroizing::new(attestation_seed));
        let (ct, ss) = encapsulate_derand(key.public_key(), &randomness).unwrap();
        assert_eq!(key.decapsulate(&ct).unwrap(), ss);
        let (a, c) = (answerer.public_key(), challenger.public_key());
        let mac = confirm_mac(&ss, &group_id, &ct[..], a, c);
        ck.file(
            "attestation key",
            "confirm-attestation-key.bin",
            key.public_key(),
        );
        ck.file("ciphertext", "confirm-ciphertext.bin", &ct[..]);
        ck.hex("shared secret", ss.as_bytes());
        ck.hex("ConfirmContent", &confirm_content(&group_id, &ct[..], a, c));
        ck.hex("K", &confirm_key(&ss)[..]);
        ck.hex("MAC", &mac);
        let challenge = ContentLine::Challenge {
            leaf: 3,
            ciphertext: ChallengeCiphertext::from_bytes(&ct),
        };
        ck.file(
            "the CHALLENGE line",
            "confirm-challenge.txt",
            challenge.to_line().unwrap().as_bytes(),
        );
        let answer = ContentLine::Answer {
            leaf: 7,
            mac: ConfirmMac::from_bytes(mac),
        };
        ck.eq("the ANSWER line", answer.to_line().unwrap());
        assert!(check_answer(&ss, &group_id, &ct[..], a, c, &mac));
        ck.gap();
        let mut flipped = mac;
        flipped[HASH_LEN - 1] ^= 1;
        ck.rejected(
            "the MAC with its last bit flipped",
            !check_answer(&ss, &group_id, &ct[..], a, c, &flipped),
        );
        ck.rejected(
            "the MAC checked with the two leaf keys swapped",
            !check_answer(&ss, &group_id, &ct[..], c, a, &mac),
        );
        ck.finish();
    }

    const PINNED_CT_HASH: &str = "b8c1cec58b43296f6b98a7bed384aa7063cde506a717cd87971fb04c7a9b3c176fc4c6c879dbf005710376c91e9c2994";
    const PINNED_SS: &str = "1447f492fbfefd103aeeafaea5e8f44b540f9adf1caae810f659f45cdfce17fd";
    const PINNED_MAC: &str = "2fa54ceb6262059f0aaaec1ee90f9675c30293931c3e1bfdf4654690caf73c39edf45c74af74172137a68edcb12a8904";
}
