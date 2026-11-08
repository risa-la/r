//! Key file records (SPEC 4.4), key log entries (4.5) and the record
//! payload of REGISTER and KEYS PUT (4.7).
//!
//! ```text
//! enum { reserved(0), master(1), signing(2), device(3), log(4), retire(5), (255) } RecordType;
//!
//! struct { opaque origin<V>; opaque key<V>; } LogKey;
//! struct { opaque device_key<V>; opaque attestation_key<V>; opaque label<V>; } DeviceKeys;
//!
//! struct {
//!     uint8 version; RecordType type; opaque uid<V>; opaque previous<V>; uint64 time;
//!     select (type) {
//!         case master:  opaque master_key<V>; opaque signing_key<V>; LogKey log;
//!         case signing: opaque signing_key<V>; opaque removed<V>;
//!         case device:  DeviceKeys keys;
//!         case log:     LogKey log;
//!         case retire:  struct {};
//!     };
//! } RecordContent;
//!
//! struct { RecordContent content; opaque signature<V>; } Record;
//! ```
//!
//! Decoding is exact: shortest vector lengths, nothing after the last
//! field, version 1, a known type, and every key the right length and
//! form (4.4, parsing step 2 and replaying step 5). How records chain is
//! [`chain`](crate::chain)'s job.

use std::fmt;
use std::sync::Arc;

use sha2::{Digest as _, Sha256, Sha384};
use thiserror::Error;

use crate::auth::{PUBLIC_KEY_LEN, PublicKey, SIGNATURE_LEN, SecretKey, SignLabel};
use crate::codec::{DecodeError, Reader, Writer};
use crate::names::{BLOB_HASH_LEN, BlobRef, Identity};
use crate::time::Timestamp;

/// The `version` of a Record, a LogEntry and the record payload (4.4,
/// 4.5, 4.7).
pub const RECORD_VERSION: u8 = 1;

/// The largest encoded Record, 16 KiB (4.4).
pub const MAX_RECORD_LEN: usize = 16 * 1024;

/// The most records in one chain (4.4).
pub const MAX_CHAIN_LEN: usize = 4096;

/// The chain length past which a device tells its user, once, that the
/// identity's chain is filling up (4.4).
pub const CHAIN_WARN_LEN: usize = 3072;

/// The most devices that may be current at once (4.4).
pub const MAX_DEVICES: usize = 64;

/// The longest device label, in bytes of UTF-8 (4.4).
pub const MAX_DEVICE_LABEL: usize = 64;

/// The length of an X-Wing public key (4.4, 12.2).
pub const XWING_PUBLIC_KEY_LEN: usize = 1216;

/// The signed-note signature type of a key log's key (4.4, 4.5, 15).
pub const LOG_SIG_TYPE: u8 = 0x06;

/// The length of a LogKey's `key`: the type byte, then an ML-DSA-44
/// public key (4.4).
pub const LOG_KEY_LEN: usize = 1 + PUBLIC_KEY_LEN;

/// The length of a device id, a SHA-384 hash (4.4).
pub const DEVICE_ID_LEN: usize = 48;

/// The length of a later `master` record's signature: two ML-DSA-44
/// signatures, by the old master key and then the new one (4.4).
pub const DOUBLE_SIGNATURE_LEN: usize = 2 * SIGNATURE_LEN;

/// How far ahead of the reader's clock a record's time may be before the
/// fetch counts as an outage, in milliseconds: 10 minutes (4.4).
pub const MAX_CLOCK_AHEAD_MS: u64 = 10 * 60 * 1000;

/// The path in a key log's origin, before its number (4.5, 15).
pub const LOG_ORIGIN_PATH: &str = "/risala-log/";

/// The longest log origin, as a signed-note key name [TLOG-COSIGNATURE].
pub const MAX_ORIGIN_LEN: usize = 255;

/// Why a record, a log entry or a record payload did not decode, or a
/// value could not be built.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RecordError {
    /// The bytes are not a well-formed structure.
    #[error("malformed: {0}")]
    Malformed(&'static str),
    /// A `version` other than 1 (2.4).
    #[error("unknown version {0}")]
    Version(u8),
    /// A record type or log entry type this version does not define.
    #[error("unknown type {0}")]
    Type(u8),
    /// An encoded Record over 16 KiB, or more than 4,096 records (4.4).
    /// A server answers it with `ERR too-long` (4.7).
    #[error("over the limits of 4.4")]
    TooLarge,
}

impl From<DecodeError> for RecordError {
    fn from(e: DecodeError) -> RecordError {
        RecordError::Malformed(e.0)
    }
}

// ---------------------------------------------------------------------------
// Keys

/// An X-Wing public key, 1216 bytes, that passes the checks of 12.2: its
/// first 1184 bytes are an ML-KEM-768 encapsulation key that passes the
/// modulus check of FIPS 203 (7.2), and the last 32 an X25519 key.
/// Devices' attestation keys (4.4) and pairing keys (4.8) are these.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct XWingPublicKey(Arc<[u8; XWING_PUBLIC_KEY_LEN]>);

/// The length of the ML-KEM-768 encapsulation key inside an X-Wing key.
const MLKEM768_EK_LEN: usize = 1184;

impl XWingPublicKey {
    /// The key, if `bytes` is one that passes the checks of 12.2.
    pub fn from_bytes(bytes: &[u8]) -> Result<XWingPublicKey, RecordError> {
        let bytes: [u8; XWING_PUBLIC_KEY_LEN] = bytes
            .try_into()
            .map_err(|_| RecordError::Malformed("an X-Wing key is 1216 bytes"))?;
        if !mlkem768_ek_check(&bytes[..MLKEM768_EK_LEN]) {
            return Err(RecordError::Malformed(
                "an X-Wing key's ML-KEM-768 part fails the modulus check",
            ));
        }
        Ok(XWingPublicKey(Arc::new(bytes)))
    }

    /// The key's bytes.
    pub fn as_bytes(&self) -> &[u8; XWING_PUBLIC_KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for XWingPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hash = Sha256::digest(&self.0[..]);
        write!(f, "XWingPublicKey({})", crate::auth::hex_lower(&hash[..8]))
    }
}

/// The modulus check of FIPS 203 (7.2, ML-KEM.Encaps step 2) for an
/// ML-KEM-768 encapsulation key: each 12-bit coefficient of its 1152-byte
/// t-hat is below q = 3329, so that ByteEncode12(ByteDecode12(t-hat)) is
/// t-hat. The last 32 bytes are rho, which is not checked.
fn mlkem768_ek_check(ek: &[u8]) -> bool {
    const Q: u16 = 3329;
    debug_assert_eq!(ek.len(), MLKEM768_EK_LEN);
    let (triples, _) = ek[..3 * 384].as_chunks::<3>();
    triples.iter().all(|&[b0, b1, b2]| {
        let d0 = u16::from(b0) | (u16::from(b1 & 0x0f) << 8);
        let d1 = u16::from(b1 >> 4) | (u16::from(b2) << 4);
        d0 < Q && d1 < Q
    })
}

/// Reads an ML-DSA-44 public key from a vector (4.4, replaying step 5).
fn read_mldsa(r: &mut Reader<'_>) -> Result<PublicKey, RecordError> {
    let bytes: &[u8; PUBLIC_KEY_LEN] = r
        .vector()?
        .try_into()
        .map_err(|_| RecordError::Malformed("an ML-DSA-44 key is 1312 bytes"))?;
    Ok(PublicKey::from_bytes(bytes))
}

/// A device id: the SHA-384 hash of the device's raw device key (4.4).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DeviceId([u8; DEVICE_ID_LEN]);

impl DeviceId {
    /// The id of the device whose device key is `key` (4.4).
    pub fn of(key: &PublicKey) -> DeviceId {
        DeviceId(Sha384::digest(key.as_bytes()).into())
    }

    /// The id from its 48 bytes.
    pub const fn from_bytes(bytes: [u8; DEVICE_ID_LEN]) -> DeviceId {
        DeviceId(bytes)
    }

    /// The 48 bytes.
    pub const fn as_bytes(&self) -> &[u8; DEVICE_ID_LEN] {
        &self.0
    }

    /// The short id that clients show next to a device's label: the first
    /// 8 characters of the id in lower-case base32 (12.14).
    pub fn short(&self) -> String {
        // 5 bytes give exactly 8 characters.
        crate::base32::encode(&self.0[..5], false)
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceId({})", self.short())
    }
}

impl fmt::Display for DeviceId {
    /// The whole id, in lower-case hex.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&crate::auth::hex_lower(&self.0))
    }
}

// ---------------------------------------------------------------------------
// LogKey

/// A key log, as a chain names it: its origin and its ML-DSA-44 key
/// (4.4, 4.5). The same log appears in a key file's `log` lines as a
/// signed-note verifier key, [`vkey`](LogKey::vkey).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LogKey {
    origin: Arc<str>,
    key: PublicKey,
}

impl LogKey {
    /// The log `origin`, whose checkpoints `key` signs. The origin must
    /// have the form `<host>/risala-log/<n>` (4.5).
    pub fn new(origin: &str, key: PublicKey) -> Result<LogKey, RecordError> {
        if parse_origin(origin).is_none() {
            return Err(RecordError::Malformed(
                "a log origin is <host>/risala-log/<n>",
            ));
        }
        Ok(LogKey {
            origin: Arc::from(origin),
            key,
        })
    }

    /// The log's origin, such as `chat.example.org/risala-log/1`.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The host part of the origin.
    pub fn host(&self) -> &str {
        parse_origin(&self.origin).expect("checked when made").0
    }

    /// The log's number, `<n>` in its origin (4.5).
    pub fn number(&self) -> u64 {
        parse_origin(&self.origin).expect("checked when made").1
    }

    /// The log's ML-DSA-44 public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.key
    }

    /// The LogKey's `key`: the byte `0x06`, then the public key (4.4).
    pub fn key_bytes(&self) -> [u8; LOG_KEY_LEN] {
        let mut out = [0; LOG_KEY_LEN];
        out[0] = LOG_SIG_TYPE;
        out[1..].copy_from_slice(self.key.as_bytes());
        out
    }

    /// The key ID [SIGNED-NOTE]: the first 4 bytes of the SHA-256 hash of
    /// the origin, an LF, the byte `0x06` and the public key (4.4).
    pub fn key_id(&self) -> u32 {
        let d = Sha256::new()
            .chain_update(self.origin.as_bytes())
            .chain_update(b"\n")
            .chain_update(self.key_bytes())
            .finalize();
        u32::from_be_bytes([d[0], d[1], d[2], d[3]])
    }

    /// The log's signed-note verifier key, as in a key file's `log` line
    /// and INFO's `log-key=` (4.4, 8.5): the origin, `+`, the key ID in
    /// 8 lower-case hex digits, `+`, and the LogKey's `key` in base64.
    pub fn vkey(&self) -> String {
        use base64::Engine as _;
        format!(
            "{}+{:08x}+{}",
            self.origin,
            self.key_id(),
            base64::engine::general_purpose::STANDARD.encode(self.key_bytes())
        )
    }

    /// Reads a verifier key written as [`vkey`](LogKey::vkey) writes it.
    /// The key ID must match, the type must be `0x06`, and the base64
    /// strict (4.4).
    pub fn from_vkey(vkey: &str) -> Result<LogKey, RecordError> {
        use base64::Engine as _;
        const BAD: RecordError = RecordError::Malformed("not a key log's verifier key");
        let mut parts = vkey.splitn(3, '+');
        let (Some(origin), Some(id), Some(key)) = (parts.next(), parts.next(), parts.next()) else {
            return Err(BAD);
        };
        if id.len() != 8 || !id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(BAD);
        }
        let id = u32::from_str_radix(id, 16).map_err(|_| BAD)?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(key)
            .map_err(|_| BAD)?;
        let log = LogKey::from_key_bytes(origin, &bytes)?;
        if log.key_id() != id {
            return Err(RecordError::Malformed("the key ID does not match the key"));
        }
        Ok(log)
    }

    /// The log from its origin and the LogKey's `key` bytes.
    fn from_key_bytes(origin: &str, key: &[u8]) -> Result<LogKey, RecordError> {
        let Some((&LOG_SIG_TYPE, public)) = key.split_first() else {
            return Err(RecordError::Malformed("a log key starts with 0x06"));
        };
        let public: &[u8; PUBLIC_KEY_LEN] = public
            .try_into()
            .map_err(|_| RecordError::Malformed("a log key is 1313 bytes"))?;
        LogKey::new(origin, PublicKey::from_bytes(public))
    }

    fn write(&self, w: &mut Writer) {
        w.vector(self.origin.as_bytes()).vector(&self.key_bytes());
    }

    fn read(r: &mut Reader<'_>) -> Result<LogKey, RecordError> {
        let origin = std::str::from_utf8(r.vector()?)
            .map_err(|_| RecordError::Malformed("a log origin is ASCII"))?;
        LogKey::from_key_bytes(origin, r.vector()?)
    }
}

impl fmt::Debug for LogKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LogKey({}+{:08x})", self.origin, self.key_id())
    }
}

/// Splits a key log origin, `<host>/risala-log/<n>`, into its host and
/// number (4.5). The host must be a DNS name in lower case, without a
/// port, and `<n>` a number (3.3) from 1, so that each log has one
/// spelling (as in `risala-keylog`).
pub fn parse_origin(origin: &str) -> Option<(&str, u64)> {
    if origin.len() > MAX_ORIGIN_LEN {
        return None;
    }
    let (host, n) = origin.split_once(LOG_ORIGIN_PATH)?;
    let n = crate::types::parse_u64(n).ok().filter(|&n| n >= 1)?;
    let host_ok = !host.is_empty()
        && host.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        });
    host_ok.then_some((host, n))
}

// ---------------------------------------------------------------------------
// Records

/// A RecordType (4.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RecordType {
    /// `master`, 1.
    Master = 1,
    /// `signing`, 2.
    Signing = 2,
    /// `device`, 3.
    Device = 3,
    /// `log`, 4.
    Log = 4,
    /// `retire`, 5.
    Retire = 5,
}

impl RecordType {
    /// The type's name, as the spec writes it.
    pub const fn as_str(self) -> &'static str {
        match self {
            RecordType::Master => "master",
            RecordType::Signing => "signing",
            RecordType::Device => "device",
            RecordType::Log => "log",
            RecordType::Retire => "retire",
        }
    }
}

/// A device's keys and label, as a `device` record adds it and a
/// NewDevice offers it (4.4, 4.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceKeys {
    /// The device key, ML-DSA-44.
    pub device_key: PublicKey,
    /// The attestation key, X-Wing.
    pub attestation_key: XWingPublicKey,
    /// A label for people, usually the device's name: UTF-8 of at most
    /// [`MAX_DEVICE_LABEL`] bytes.
    pub label: String,
}

impl DeviceKeys {
    /// The device's id (4.4).
    pub fn device_id(&self) -> DeviceId {
        DeviceId::of(&self.device_key)
    }

    pub(crate) fn write(&self, w: &mut Writer) {
        w.vector(self.device_key.as_bytes())
            .vector(self.attestation_key.as_bytes())
            .vector(self.label.as_bytes());
    }

    pub(crate) fn read(r: &mut Reader<'_>) -> Result<DeviceKeys, RecordError> {
        let device_key = read_mldsa(r)?;
        let attestation_key = XWingPublicKey::from_bytes(r.vector()?)?;
        let label = r.vector()?;
        if label.len() > MAX_DEVICE_LABEL {
            return Err(RecordError::Malformed("a label is at most 64 bytes"));
        }
        let label = std::str::from_utf8(label)
            .map_err(|_| RecordError::Malformed("a label is UTF-8"))?
            .to_owned();
        Ok(DeviceKeys {
            device_key,
            attestation_key,
            label,
        })
    }
}

/// What a record does: the part of a RecordContent after its `time`
/// (4.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordBody {
    /// `master`: names a master key, a device-signing key and the chain's
    /// key log.
    Master {
        /// The master key.
        master_key: PublicKey,
        /// The device-signing key.
        signing_key: PublicKey,
        /// The chain's key log.
        log: LogKey,
    },
    /// `signing`: replaces the device-signing key and removes devices.
    Signing {
        /// The new device-signing key.
        signing_key: PublicKey,
        /// The devices removed, sorted in increasing byte order.
        removed: Vec<DeviceId>,
    },
    /// `device`: adds a device.
    Device(DeviceKeys),
    /// `log`: moves the chain to another key log.
    Log(LogKey),
    /// `retire`: ends the identity.
    Retire,
}

impl RecordBody {
    /// The record's type.
    pub fn record_type(&self) -> RecordType {
        match self {
            RecordBody::Master { .. } => RecordType::Master,
            RecordBody::Signing { .. } => RecordType::Signing,
            RecordBody::Device(_) => RecordType::Device,
            RecordBody::Log(_) => RecordType::Log,
            RecordBody::Retire => RecordType::Retire,
        }
    }
}

/// A RecordContent (4.4): what a record's signature covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordContent {
    /// The identity, in lower case.
    pub uid: Identity,
    /// The hash of the previous Record, or `None` in a chain's first.
    pub previous: Option<BlobRef>,
    /// Milliseconds since 1970-01-01T00:00:00Z. Kept as sent: a time
    /// beyond [`Timestamp::MAX`] is not malformed, only far ahead (4.4).
    pub time: u64,
    /// What the record does.
    pub body: RecordBody,
}

impl RecordContent {
    /// The encoded RecordContent (4.4).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.write(&mut w);
        w.finish()
    }

    /// Whether this is a chain's first record: a `master` record with an
    /// empty `previous` (4.4).
    pub fn is_first_master(&self) -> bool {
        self.previous.is_none() && matches!(self.body, RecordBody::Master { .. })
    }

    /// The record's time as a timestamp, if it is before the year 10000.
    pub fn timestamp(&self) -> Option<Timestamp> {
        Timestamp::from_unix_millis(self.time)
    }

    fn write(&self, w: &mut Writer) {
        w.u8(RECORD_VERSION)
            .u8(self.body.record_type() as u8)
            .vector(self.uid.as_str().as_bytes())
            .vector(self.previous.as_ref().map_or(&[][..], |h| &h.hash()[..]))
            .u64(self.time);
        match &self.body {
            RecordBody::Master {
                master_key,
                signing_key,
                log,
            } => {
                w.vector(master_key.as_bytes())
                    .vector(signing_key.as_bytes());
                log.write(w);
            }
            RecordBody::Signing {
                signing_key,
                removed,
            } => {
                w.vector(signing_key.as_bytes());
                w.nested(|w| {
                    for id in removed {
                        w.fixed(id.as_bytes());
                    }
                });
            }
            RecordBody::Device(keys) => keys.write(w),
            RecordBody::Log(log) => log.write(w),
            RecordBody::Retire => {}
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<RecordContent, RecordError> {
        let version = r.u8()?;
        if version != RECORD_VERSION {
            return Err(RecordError::Version(version));
        }
        let ty = r.u8()?;
        if !(1..=5).contains(&ty) {
            return Err(RecordError::Type(ty));
        }
        let uid = std::str::from_utf8(r.vector()?)
            .map_err(|_| RecordError::Malformed("a uid is UTF-8"))?;
        let uid = uid
            .parse::<Identity>()
            .ok()
            .filter(|id| id.as_str() == uid)
            .ok_or(RecordError::Malformed("a uid is an identity in lower case"))?;
        let previous = match r.vector()? {
            [] => None,
            hash => Some(BlobRef::from_hash(hash.try_into().map_err(|_| {
                RecordError::Malformed("previous is empty or 48 bytes")
            })?)),
        };
        let time = r.u64()?;
        let body = match ty {
            1 => RecordBody::Master {
                master_key: read_mldsa(r)?,
                signing_key: read_mldsa(r)?,
                log: LogKey::read(r)?,
            },
            2 => {
                let signing_key = read_mldsa(r)?;
                let removed = r.vector()?;
                let (ids, rest) = removed.as_chunks::<DEVICE_ID_LEN>();
                if !rest.is_empty() {
                    return Err(RecordError::Malformed("removed is a multiple of 48 bytes"));
                }
                RecordBody::Signing {
                    signing_key,
                    removed: ids.iter().map(|id| DeviceId(*id)).collect(),
                }
            }
            3 => RecordBody::Device(DeviceKeys::read(r)?),
            4 => RecordBody::Log(LogKey::read(r)?),
            _ => RecordBody::Retire,
        };
        Ok(RecordContent {
            uid,
            previous,
            time,
            body,
        })
    }
}

/// A Record (4.4): a RecordContent and its signature, with its encoding.
///
/// Records compare by their encoding. Two records whose contents are
/// equal but whose signatures differ are different records here; 4.5's
/// fork rules treat them as one, see [`Record::same_content`].
#[derive(Clone)]
pub struct Record {
    content: RecordContent,
    signature: Arc<[u8]>,
    encoded: Arc<[u8]>,
    content_len: usize,
}

impl Record {
    /// The record with this content and signature. Fails if it encodes
    /// to more than 16 KiB (4.4). The signature is not checked here.
    pub fn new(content: RecordContent, signature: &[u8]) -> Result<Record, RecordError> {
        let mut w = Writer::new();
        content.write(&mut w);
        let content_len = w.as_bytes().len();
        w.vector(signature);
        let encoded = w.finish();
        if encoded.len() > MAX_RECORD_LEN {
            return Err(RecordError::TooLarge);
        }
        Ok(Record {
            content,
            signature: Arc::from(signature),
            encoded: Arc::from(encoded),
            content_len,
        })
    }

    /// Signs `content` with `key`, using RisalaSign's `record` label and
    /// the hedged variant with randomness `rnd` (4.3, 4.4). For a chain's
    /// first `master` record `key` is its own master key; for `signing`,
    /// `log` and `retire` records the current master key; for `device`
    /// records the current device-signing key. A later `master` record
    /// takes [`sign_rotation`](Record::sign_rotation).
    pub fn sign(
        content: RecordContent,
        key: &SecretKey,
        rnd: [u8; 32],
    ) -> Result<Record, RecordError> {
        let signature = key.risala_sign(SignLabel::Record, &content.encode(), rnd);
        Record::new(content, signature.as_bytes())
    }

    /// [`sign`](Record::sign) with the deterministic variant, for test
    /// vectors (Appendix B).
    pub fn sign_deterministic(
        content: RecordContent,
        key: &SecretKey,
    ) -> Result<Record, RecordError> {
        let signature = key.risala_sign_deterministic(SignLabel::Record, &content.encode());
        Record::new(content, signature.as_bytes())
    }

    /// Signs a later `master` record (4.4): two signatures, one after the
    /// other, by the master key it replaces and then by the new one.
    pub fn sign_rotation(
        content: RecordContent,
        old: &SecretKey,
        new: &SecretKey,
        rnd_old: [u8; 32],
        rnd_new: [u8; 32],
    ) -> Result<Record, RecordError> {
        let bytes = content.encode();
        let mut signature = Vec::with_capacity(DOUBLE_SIGNATURE_LEN);
        signature.extend_from_slice(
            old.risala_sign(SignLabel::Record, &bytes, rnd_old)
                .as_bytes(),
        );
        signature.extend_from_slice(
            new.risala_sign(SignLabel::Record, &bytes, rnd_new)
                .as_bytes(),
        );
        Record::new(content, &signature)
    }

    /// [`sign_rotation`](Record::sign_rotation) with the deterministic
    /// variant, for test vectors (Appendix B).
    pub fn sign_rotation_deterministic(
        content: RecordContent,
        old: &SecretKey,
        new: &SecretKey,
    ) -> Result<Record, RecordError> {
        let bytes = content.encode();
        let mut signature = Vec::with_capacity(DOUBLE_SIGNATURE_LEN);
        signature.extend_from_slice(
            old.risala_sign_deterministic(SignLabel::Record, &bytes)
                .as_bytes(),
        );
        signature.extend_from_slice(
            new.risala_sign_deterministic(SignLabel::Record, &bytes)
                .as_bytes(),
        );
        Record::new(content, &signature)
    }

    /// Decodes exactly one Record (4.4, parsing step 2).
    pub fn decode(bytes: &[u8]) -> Result<Record, RecordError> {
        let mut r = Reader::new(bytes);
        let record = Record::read(&mut r)?;
        r.end()?;
        Ok(record)
    }

    /// Reads one Record from the front of `r`.
    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Record, RecordError> {
        let start = r.rest();
        let content = RecordContent::read(r)?;
        let content_len = start.len() - r.rest().len();
        let signature = r.vector()?;
        let len = start.len() - r.rest().len();
        if len > MAX_RECORD_LEN {
            return Err(RecordError::TooLarge);
        }
        Ok(Record {
            content,
            signature: Arc::from(signature),
            encoded: Arc::from(&start[..len]),
            content_len,
        })
    }

    /// The content.
    pub fn content(&self) -> &RecordContent {
        &self.content
    }

    /// The encoded RecordContent, which the signature covers.
    pub fn content_bytes(&self) -> &[u8] {
        &self.encoded[..self.content_len]
    }

    /// The signature bytes: 2420, or 4840 in a later `master` record, in
    /// a valid chain.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// The encoded Record.
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// The record's hash, SHA-384 of the encoded Record, as a blob-ref:
    /// a key file's `<hash>`, a RECORD line's, a later record's
    /// `previous` and KEYS PUT's `<after>` (4.4, 4.7).
    pub fn hash(&self) -> BlobRef {
        BlobRef::of(&self.encoded)
    }

    /// The record's type.
    pub fn record_type(&self) -> RecordType {
        self.content.body.record_type()
    }

    /// Whether `other` has the same RecordContent. Two such records whose
    /// signatures both verify are the same record (4.5).
    pub fn same_content(&self, other: &Record) -> bool {
        self.content_bytes() == other.content_bytes()
    }

    /// Whether `other` and this record are a **fork** (4.5): records of
    /// one uid with the same `previous` whose RecordContents differ. Two
    /// first `master` records of a uid (both with an empty `previous`)
    /// that differ are one case of this. Where the two were seen, which
    /// 4.5 also asks about, is the caller's to check.
    pub fn forks_with(&self, other: &Record) -> bool {
        self.content.uid == other.content.uid
            && self.content.previous == other.content.previous
            && !self.same_content(other)
    }
}

impl PartialEq for Record {
    fn eq(&self, other: &Record) -> bool {
        self.encoded == other.encoded
    }
}

impl Eq for Record {}

impl fmt::Debug for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Record")
            .field("hash", &self.hash())
            .field("content", &self.content)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// The record payload of REGISTER and KEYS PUT

/// Encodes records as REGISTER's `<keyfile>` and KEYS PUT's `<records>`
/// carry them, before base64 (4.7): a one-byte `version` (1), then the
/// vector `Record records<V>`.
pub fn encode_records(records: &[Record]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(RECORD_VERSION).nested(|w| {
        for record in records {
            w.fixed(record.encoded());
        }
    });
    w.finish()
}

/// Decodes REGISTER's `<keyfile>` or KEYS PUT's `<records>` (4.7), as
/// bytes. The payload holds at least one record, each at most 16 KiB,
/// and at most 4,096 of them ([`RecordError::TooLarge`] otherwise, which
/// a server answers with `ERR too-long`).
pub fn decode_records(bytes: &[u8]) -> Result<Vec<Record>, RecordError> {
    let mut r = Reader::new(bytes);
    let version = r.u8()?;
    if version != RECORD_VERSION {
        return Err(RecordError::Version(version));
    }
    let mut inner = Reader::new(r.vector()?);
    r.end()?;
    let mut records = Vec::new();
    while !inner.is_empty() {
        if records.len() == MAX_CHAIN_LEN {
            return Err(RecordError::TooLarge);
        }
        records.push(Record::read(&mut inner)?);
    }
    if records.is_empty() {
        return Err(RecordError::Malformed("no records"));
    }
    Ok(records)
}

// ---------------------------------------------------------------------------
// Key log entries

/// A LogEntryType (4.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum LogEntryType {
    /// `record`, 1.
    Record = 1,
    /// `handoff`, 2.
    Handoff = 2,
}

/// A key log entry (4.5):
///
/// ```text
/// struct {
///     uint8 version;               // 1
///     LogEntryType type;
///     select (LogEntry.type) {
///         case record:  Record record;
///         case handoff: LogKey next;
///     };
/// } LogEntry;
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogEntry {
    /// A record of a chain.
    Record(Record),
    /// The log's last entry: the log that takes over from it.
    Handoff(LogKey),
}

impl LogEntry {
    /// The entry's type.
    pub fn entry_type(&self) -> LogEntryType {
        match self {
            LogEntry::Record(_) => LogEntryType::Record,
            LogEntry::Handoff(_) => LogEntryType::Handoff,
        }
    }

    /// The encoded LogEntry, the bytes of the log's leaf (4.5).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(RECORD_VERSION).u8(self.entry_type() as u8);
        match self {
            LogEntry::Record(record) => {
                w.fixed(record.encoded());
            }
            LogEntry::Handoff(next) => next.write(&mut w),
        }
        w.finish()
    }

    /// Decodes exactly one LogEntry.
    pub fn decode(bytes: &[u8]) -> Result<LogEntry, RecordError> {
        let mut r = Reader::new(bytes);
        let version = r.u8()?;
        if version != RECORD_VERSION {
            return Err(RecordError::Version(version));
        }
        let entry = match r.u8()? {
            1 => LogEntry::Record(Record::read(&mut r)?),
            2 => LogEntry::Handoff(LogKey::read(&mut r)?),
            ty => return Err(RecordError::Type(ty)),
        };
        r.end()?;
        Ok(entry)
    }

    /// Whether this is the record entry whose Record has the hash `hash`,
    /// as a key file's `<index> <hash>` line requires of the entry at its
    /// index (4.5).
    pub fn is_record(&self, hash: &BlobRef) -> bool {
        matches!(self, LogEntry::Record(record) if record.hash() == *hash)
    }
}

// ---------------------------------------------------------------------------
// Log hints

/// The path, under a log's URL prefix, of a uid's hint (4.5):
/// `risala/uid/` and the SHA-256 hash of the uid in lower-case hex.
pub fn uid_hint_path(uid: &Identity) -> String {
    format!(
        "risala/uid/{}",
        crate::auth::hex_lower(&Sha256::digest(uid.as_str().as_bytes()))
    )
}

/// The path, under a log's URL prefix, of its hand-off hint (4.5).
pub const NEXT_HINT_PATH: &str = "risala/next";

/// Reads a uid hint (4.5): indices as numbers (3.3), one per line, in
/// increasing order, each ending with LF. An empty body is no indices.
/// Anything else is `None`.
pub fn parse_uid_hint(body: &[u8]) -> Option<Vec<u64>> {
    let text = std::str::from_utf8(body).ok()?;
    let mut out: Vec<u64> = Vec::new();
    if text.is_empty() {
        return Some(out);
    }
    let lines = text.strip_suffix('\n')?;
    for line in lines.split('\n') {
        let n = crate::types::parse_u64(line).ok()?;
        if out.last().is_some_and(|&last| last >= n) {
            return None;
        }
        out.push(n);
    }
    Some(out)
}

/// Writes a uid hint (4.5).
pub fn write_uid_hint(indices: &[u64]) -> String {
    indices.iter().map(|i| format!("{i}\n")).collect()
}

/// Reads a hand-off hint (4.5): one number and an LF.
pub fn parse_next_hint(body: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(body).ok()?.strip_suffix('\n')?;
    crate::types::parse_u64(text).ok()
}

/// SHA-384 of `bytes`, as a fixed array.
pub(crate) fn sha384(bytes: &[u8]) -> [u8; BLOB_HASH_LEN] {
    Sha384::digest(bytes).into()
}
