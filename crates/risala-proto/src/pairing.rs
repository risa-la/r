//! Pairing formats (SPEC 4.8): the QR code's PairingCode, the new
//! device's signed NewDevice, and the SealedBundle that carries the
//! IdentityBundle back.
//!
//! ```text
//! struct { uint8 version; opaque host<V>; opaque secret[32]; opaque keys_hash[48]; } PairingCode;
//! struct { DeviceKeys keys; opaque pairing_key<V>; } NewDeviceContent;
//! struct { uint8 version; NewDeviceContent content; opaque signature<V>; } NewDevice;
//! struct { uint8 version; opaque enc[1120]; opaque ciphertext<V>; } SealedBundle;
//! ```
//!
//! What is derived from the secret, the ChaCha20-Poly1305 encryption of
//! the NewDevice, the IdentityBundle and its HPKE sealing are crypto, in
//! `risala-mls` (its `pairing` module). This module holds the bytes.

use std::fmt;

use zeroize::Zeroizing;

use crate::auth::{SIGNATURE_LEN, SecretKey, SignLabel};
use crate::codec::{Reader, Writer};
use crate::record::{DeviceKeys, RecordError, XWingPublicKey, sha384};

/// The `version` of the pairing structures (4.8).
pub const PAIRING_VERSION: u8 = 1;

/// The length of the one-time pairing secret (4.8).
pub const PAIRING_SECRET_LEN: usize = 32;

/// The length of `keys_hash`, SHA-384 of the encoded NewDevice (4.8).
pub const KEYS_HASH_LEN: usize = 48;

/// The length of an X-Wing encapsulated key, a SealedBundle's `enc`
/// (4.8).
pub const XWING_ENC_LEN: usize = 1120;

/// The start of a pairing QR code's text (4.8, 15).
pub const PAIR_QR_PREFIX: &str = "RISALA-PAIR:";

/// The longest host name a PairingCode may carry.
pub const MAX_HOST_LEN: usize = 253;

/// Whether `host` is a server's host name as a PairingCode carries it: a
/// DNS name in lower case, without a port.
///
/// 4.8 says only "the server used for pairing, lower case". A server on
/// another port than 7472 cannot be named this way; a choice to confirm.
pub fn is_pairing_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= MAX_HOST_LEN
        && host.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

/// What a new device's QR code carries (4.8). The secret never reaches
/// the server; `Debug` leaves it out.
#[derive(Clone, PartialEq, Eq)]
pub struct PairingCode {
    /// The server used for pairing, in lower case.
    pub host: String,
    /// The one-time pairing secret.
    pub secret: Zeroizing<[u8; PAIRING_SECRET_LEN]>,
    /// SHA-384 of the encoded NewDevice ([`NewDevice::keys_hash`]).
    pub keys_hash: [u8; KEYS_HASH_LEN],
}

impl PairingCode {
    /// The encoded PairingCode.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut w = Writer::new();
        w.u8(PAIRING_VERSION)
            .vector(self.host.as_bytes())
            .fixed(&self.secret[..])
            .fixed(&self.keys_hash);
        Zeroizing::new(w.finish())
    }

    /// Decodes exactly one PairingCode.
    pub fn decode(bytes: &[u8]) -> Result<PairingCode, RecordError> {
        let mut r = Reader::new(bytes);
        let version = r.u8()?;
        if version != PAIRING_VERSION {
            return Err(RecordError::Version(version));
        }
        let host = std::str::from_utf8(r.vector()?)
            .ok()
            .filter(|h| is_pairing_host(h))
            .ok_or(RecordError::Malformed("a host name in lower case"))?
            .to_owned();
        let secret = Zeroizing::new(*r.fixed::<PAIRING_SECRET_LEN>()?);
        let keys_hash = *r.fixed::<KEYS_HASH_LEN>()?;
        r.end()?;
        Ok(PairingCode {
            host,
            secret,
            keys_hash,
        })
    }

    /// The QR code's text (4.8): `RISALA-PAIR:` and the encoded
    /// PairingCode in upper-case base32 without padding.
    pub fn to_qr_text(&self) -> Zeroizing<String> {
        let code = self.encode();
        Zeroizing::new(format!(
            "{PAIR_QR_PREFIX}{}",
            *Zeroizing::new(crate::base32::encode(&code, true))
        ))
    }

    /// Reads a QR code's text, as [`to_qr_text`](PairingCode::to_qr_text)
    /// writes it. Lower case is not accepted.
    pub fn from_qr_text(text: &str) -> Result<PairingCode, RecordError> {
        let body = text
            .strip_prefix(PAIR_QR_PREFIX)
            .ok_or(RecordError::Malformed("a pairing code starts RISALA-PAIR:"))?;
        let bytes = Zeroizing::new(crate::base32::decode(body, true).ok_or(
            RecordError::Malformed("a pairing code is upper-case base32"),
        )?);
        PairingCode::decode(&bytes)
    }
}

impl fmt::Debug for PairingCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingCode")
            .field("host", &self.host)
            .finish_non_exhaustive()
    }
}

/// What a new device offers (4.8): its keys and label, as its `device`
/// record will hold them, and an X-Wing key for this pairing only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewDeviceContent {
    /// The keys for the `device` record.
    pub keys: DeviceKeys,
    /// The key the IdentityBundle is sealed to.
    pub pairing_key: XWingPublicKey,
}

impl NewDeviceContent {
    /// The encoded NewDeviceContent, which the signature covers.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.write(&mut w);
        w.finish()
    }

    fn write(&self, w: &mut Writer) {
        self.keys.write(w);
        w.vector(self.pairing_key.as_bytes());
    }
}

/// A new device's signed offer (4.8): its NewDeviceContent, signed with
/// RisalaSign(the new device key, "pair", content).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewDevice {
    content: NewDeviceContent,
    signature: Vec<u8>,
    encoded: Vec<u8>,
}

impl NewDevice {
    /// Signs `content` with `device_key`, the secret key of
    /// `content.keys.device_key`, with the hedged variant (randomness
    /// `rnd`).
    pub fn sign(content: NewDeviceContent, device_key: &SecretKey, rnd: [u8; 32]) -> NewDevice {
        let signature = device_key.risala_sign(SignLabel::Pair, &content.encode(), rnd);
        NewDevice::from_parts(content, signature.as_bytes().to_vec())
    }

    /// [`sign`](NewDevice::sign) with the deterministic variant, for test
    /// vectors (Appendix B).
    pub fn sign_deterministic(content: NewDeviceContent, device_key: &SecretKey) -> NewDevice {
        let signature = device_key.risala_sign_deterministic(SignLabel::Pair, &content.encode());
        NewDevice::from_parts(content, signature.as_bytes().to_vec())
    }

    fn from_parts(content: NewDeviceContent, signature: Vec<u8>) -> NewDevice {
        let mut w = Writer::new();
        w.u8(PAIRING_VERSION);
        content.write(&mut w);
        w.vector(&signature);
        NewDevice {
            content,
            signature,
            encoded: w.finish(),
        }
    }

    /// Decodes exactly one NewDevice. Its keys pass the checks of 4.4:
    /// lengths, the X-Wing checks of 12.2, and a label of at most 64
    /// bytes of UTF-8.
    pub fn decode(bytes: &[u8]) -> Result<NewDevice, RecordError> {
        let mut r = Reader::new(bytes);
        let version = r.u8()?;
        if version != PAIRING_VERSION {
            return Err(RecordError::Version(version));
        }
        let keys = DeviceKeys::read(&mut r)?;
        let pairing_key = XWingPublicKey::from_bytes(r.vector()?)?;
        let signature = r.vector()?.to_vec();
        r.end()?;
        Ok(NewDevice {
            content: NewDeviceContent { keys, pairing_key },
            signature,
            encoded: bytes.to_vec(),
        })
    }

    /// The content.
    pub fn content(&self) -> &NewDeviceContent {
        &self.content
    }

    /// The encoded NewDevice.
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// The signature.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// SHA-384 of the encoded NewDevice: a PairingCode's `keys_hash`.
    pub fn keys_hash(&self) -> [u8; KEYS_HASH_LEN] {
        sha384(&self.encoded)
    }

    /// The checks the other device makes on a decrypted NewDevice (4.8,
    /// pairing step 2): its hash is the code's `keys_hash` (compared in
    /// constant time), its signature verifies under the device key in it,
    /// and its three keys differ. Its keys passed 4.4's other checks when
    /// it was decoded. Whether the chain has had the device before is for
    /// the chain to check when the `device` record is added.
    pub fn check(&self, code: &PairingCode) -> Result<(), PairingError> {
        let hash = self.keys_hash();
        let diff = hash
            .iter()
            .zip(code.keys_hash.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        if diff != 0 {
            return Err(PairingError::KeysHash);
        }
        if self.signature.len() != SIGNATURE_LEN
            || !self.content.keys.device_key.risala_verify(
                SignLabel::Pair,
                &self.content.encode(),
                &self.signature,
            )
        {
            return Err(PairingError::Signature);
        }
        if self.content.pairing_key == self.content.keys.attestation_key {
            return Err(PairingError::RepeatedKey);
        }
        Ok(())
    }
}

/// Why a NewDevice failed the other device's checks (4.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PairingError {
    /// Its hash is not the QR code's `keys_hash`.
    #[error("the new device's keys do not match the QR code")]
    KeysHash,
    /// Its signature does not verify under its device key.
    #[error("the new device's signature does not verify")]
    Signature,
    /// Its pairing key is its attestation key.
    #[error("the pairing key repeats the attestation key")]
    RepeatedKey,
}

/// The IdentityBundle, sealed with HPKE to the new device's pairing key
/// (4.8): the X-Wing encapsulated key and the ciphertext.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedBundle {
    /// The X-Wing encapsulated key.
    pub enc: Box<[u8; XWING_ENC_LEN]>,
    /// The sealed IdentityBundle.
    pub ciphertext: Vec<u8>,
}

impl SealedBundle {
    /// The encoded SealedBundle.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(PAIRING_VERSION)
            .fixed(&self.enc[..])
            .vector(&self.ciphertext);
        w.finish()
    }

    /// Decodes exactly one SealedBundle.
    pub fn decode(bytes: &[u8]) -> Result<SealedBundle, RecordError> {
        let mut r = Reader::new(bytes);
        let version = r.u8()?;
        if version != PAIRING_VERSION {
            return Err(RecordError::Version(version));
        }
        let enc = Box::new(*r.fixed::<XWING_ENC_LEN>()?);
        let ciphertext = r.vector()?.to_vec();
        r.end()?;
        Ok(SealedBundle { enc, ciphertext })
    }
}

impl fmt::Debug for SealedBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedBundle")
            .field("ciphertext_len", &self.ciphertext.len())
            .finish_non_exhaustive()
    }
}
