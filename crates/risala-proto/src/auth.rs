//! The sign-in challenge and ML-DSA-44 keys (SPEC 4.1, 4.4-4.6, 12.2,
//! App. A, App. B).
//!
//! A client proves it holds an identity's key by signing the challenge
//! bytes of Section 4.5:
//!
//! ```text
//! "risala-auth-1" LF host LF nonce LF uid LF
//! ```
//!
//! This module builds those bytes, signs them with a [`SecretKey`] and
//! checks them with a [`PublicKey`]. It has no random number generator:
//! callers generate nonces (4.1) and key seeds themselves.
//!
//! Keys and signatures are ML-DSA-44 (FIPS 204). Signing is plain
//! ML-DSA.Sign with an empty context string and no prehash (4.5).
//! [`SecretKey::sign_challenge`] uses the deterministic variant, so it
//! reproduces Appendix B byte for byte; [`SecretKey::sign_challenge_hedged`]
//! takes the fresh randomness of the hedged variant. Verification cannot
//! tell the two apart and accepts both.
//!
//! The implementation is RustCrypto's `ml-dsa`, the same one OpenMLS's
//! `openmls_rust_crypto` provider uses for the MLS cipher suite of 12.2,
//! so a binary carries one ML-DSA.

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ml_dsa::signature::Signer as _;
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, MlDsa44};
use zeroize::{Zeroize as _, Zeroizing};

use crate::error::ParseError;
use crate::fingerprint::Fingerprint;

/// The first line of the signed bytes, without its LF (4.5).
pub const CHALLENGE_PREFIX: &str = "risala-auth-1";

/// The length of an ML-DSA-44 public key in bytes (4.4).
pub const PUBLIC_KEY_LEN: usize = 1312;

/// The length of an ML-DSA-44 signature in bytes (4.5).
pub const SIGNATURE_LEN: usize = 2420;

/// The length of an ML-DSA private key seed in bytes (App. B).
pub const SEED_LEN: usize = 32;

/// The length of a public key in base64, with padding (4.4).
pub const PUBLIC_KEY_BASE64_LEN: usize = 1752;

/// The length of a signature in base64, with padding (4.5).
pub const SIGNATURE_BASE64_LEN: usize = 3228;

/// The fewest random bytes a nonce may have (4.1).
pub const MIN_NONCE_BYTES: usize = 16;

/// The most bytes a nonce may have (4.1).
pub const MAX_NONCE_BYTES: usize = 64;

/// The nonce from the greeting, `RISALA <version> <host> <nonce>` (4.1).
///
/// It is always lower-case hex, an even number of digits, encoding
/// between [`MIN_NONCE_BYTES`] and [`MAX_NONCE_BYTES`] bytes. Parsing
/// folds upper-case hex digits to lower case, so the signed bytes always
/// use the canonical lower-case form.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Nonce(String);

impl Nonce {
    /// Makes a nonce from random bytes, for a server's greeting (4.1).
    ///
    /// The bytes must come from a cryptographically secure source; this
    /// crate does not check that. Fails with `BadSyntax` if there are
    /// fewer than [`MIN_NONCE_BYTES`], or `TooLong` if more than
    /// [`MAX_NONCE_BYTES`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Nonce, ParseError> {
        if bytes.len() < MIN_NONCE_BYTES {
            return Err(ParseError::BadSyntax("nonce is shorter than 16 bytes"));
        }
        if bytes.len() > MAX_NONCE_BYTES {
            return Err(ParseError::TooLong);
        }
        Ok(Nonce(hex_lower(bytes)))
    }

    /// The nonce as it appears in the greeting and the signed bytes (4.1).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The bytes the hex digits encode (4.1).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| (hex_digit(pair[0]).unwrap() << 4) | hex_digit(pair[1]).unwrap())
            .collect()
    }
}

impl FromStr for Nonce {
    type Err = ParseError;

    /// Parses a greeting nonce (4.1), folding upper-case hex digits.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > MAX_NONCE_BYTES * 2 {
            return Err(ParseError::TooLong);
        }
        if s.len() < MIN_NONCE_BYTES * 2 {
            return Err(ParseError::BadSyntax("nonce is shorter than 16 bytes"));
        }
        if !s.len().is_multiple_of(2) {
            return Err(ParseError::BadSyntax(
                "nonce has an odd number of hex digits",
            ));
        }
        if !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ParseError::BadSyntax("nonce is not hex"));
        }
        Ok(Nonce(s.to_ascii_lowercase()))
    }
}

impl fmt::Display for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nonce({})", self.0)
    }
}

/// Builds the bytes a client signs to sign in or register (4.5, 4.6).
///
/// The result is `"risala-auth-1" LF host LF nonce LF uid LF`. `host` is
/// the hostname the client sent in SNI (a server uses its connection's
/// SNI hostname) and `uid` is the identity being signed in as. Both are
/// folded to lower case here. The caller passes values it has already
/// validated, so they contain no LF.
pub fn challenge_bytes(host: &str, nonce: &Nonce, uid: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        CHALLENGE_PREFIX.len() + host.len() + nonce.as_str().len() + uid.len() + 4,
    );
    out.extend_from_slice(CHALLENGE_PREFIX.as_bytes());
    out.push(b'\n');
    out.extend(host.bytes().map(|b| b.to_ascii_lowercase()));
    out.push(b'\n');
    out.extend_from_slice(nonce.as_str().as_bytes());
    out.push(b'\n');
    out.extend(uid.bytes().map(|b| b.to_ascii_lowercase()));
    out.push(b'\n');
    out
}

/// An ML-DSA-44 public key, as listed in key files and sent in REGISTER
/// and KEY commands (4.4, 4.6, 4.7). It is also a device's signature key
/// in encrypted conversations (12.2).
///
/// On the wire it is [`PUBLIC_KEY_LEN`] bytes in standard base64 with
/// padding, exactly [`PUBLIC_KEY_BASE64_LEN`] characters. Parsing is
/// strict: it rejects other lengths, whitespace, missing padding and
/// non-canonical encodings (non-zero trailing bits). Every 1312-byte
/// string is the encoding of some ML-DSA-44 key (FIPS 204 pkDecode), so
/// nothing else is checked.
///
/// Cloning is cheap: the bytes are shared.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey(Arc<[u8; PUBLIC_KEY_LEN]>);

impl PublicKey {
    /// Makes a key from its raw bytes (4.4).
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LEN]) -> PublicKey {
        PublicKey(Arc::new(*bytes))
    }

    /// The key's raw bytes (4.4, 12.2).
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.0
    }

    /// The key's fingerprint for comparing devices through another
    /// channel: the SHA-256 hash of the raw key, written
    /// `sha256:<64 hex digits>` (12.12).
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::from_bytes(<sha2::Sha256 as sha2::Digest>::digest(&self.0[..]).into())
    }

    /// Checks a signature over the challenge bytes for `host`, `nonce`
    /// and `uid` (4.5, 4.6).
    ///
    /// This is ML-DSA.Verify with an empty context string, so it accepts
    /// signatures from both the hedged and the deterministic variant of
    /// ML-DSA.Sign. A signature whose encoding is malformed fails.
    pub fn verify_challenge(
        &self,
        host: &str,
        nonce: &Nonce,
        uid: &str,
        signature: &Signature,
    ) -> bool {
        let message = challenge_bytes(host, nonce, uid);
        let encoded = EncodedSignature::<MlDsa44>::try_from(&signature.0[..])
            .expect("a signature has the ML-DSA-44 length");
        let Some(signature) = ml_dsa::Signature::<MlDsa44>::decode(&encoded) else {
            return false;
        };
        let key = EncodedVerifyingKey::<MlDsa44>::try_from(&self.0[..])
            .expect("a public key has the ML-DSA-44 length");
        ml_dsa::VerifyingKey::<MlDsa44>::decode(&key).verify_with_context(&message, b"", &signature)
    }
}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_bytes().hash(state);
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl FromStr for PublicKey {
    type Err = ParseError;

    /// Parses a key in strict base64 (4.4).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = decode_base64::<PUBLIC_KEY_LEN>(s, PUBLIC_KEY_BASE64_LEN, "bad public key")?;
        Ok(PublicKey(Arc::new(bytes)))
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&BASE64.encode(self.as_bytes()))
    }
}

impl fmt::Debug for PublicKey {
    /// Shows the key's fingerprint (12.12), since the key itself is 1752
    /// characters.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.fingerprint())
    }
}

/// An ML-DSA-44 signature, as sent in AUTH and REGISTER (4.5, 4.6).
///
/// On the wire it is [`SIGNATURE_LEN`] bytes in standard base64 with
/// padding, exactly [`SIGNATURE_BASE64_LEN`] characters, decoded as
/// strictly as [`PublicKey`]. Its inner encoding is checked only when it
/// is verified: a malformed one simply does not verify, which a server
/// answers with `ERR auth-failed`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Signature(Box<[u8; SIGNATURE_LEN]>);

impl Signature {
    /// Makes a signature from its raw bytes (4.5).
    pub fn from_bytes(bytes: &[u8; SIGNATURE_LEN]) -> Signature {
        Signature(Box::new(*bytes))
    }

    /// The signature's raw bytes (4.5).
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        &self.0
    }
}

impl FromStr for Signature {
    type Err = ParseError;

    /// Parses a signature in strict base64 (4.5).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        decode_base64::<SIGNATURE_LEN>(s, SIGNATURE_BASE64_LEN, "bad signature")
            .map(|bytes| Signature(Box::new(bytes)))
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&BASE64.encode(&self.0[..]))
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({self})")
    }
}

/// A device's ML-DSA-44 private key (4.3-4.5, 12.2, App. A, App. B).
///
/// It is kept as the 32-byte seed and the key expanded from it. Both are
/// wiped from memory when the value is dropped, and so is every copy this
/// module makes while reading or writing the key. `Debug` shows only the
/// public key's fingerprint.
#[derive(Clone)]
pub struct SecretKey(ml_dsa::SigningKey<MlDsa44>);

impl SecretKey {
    /// Makes a key from its 32-byte seed, the ξ of FIPS 204's
    /// ML-DSA.KeyGen_internal (App. B).
    ///
    /// To make a new key, pass 32 bytes from a cryptographically secure
    /// random source.
    pub fn from_seed(seed: [u8; SEED_LEN]) -> SecretKey {
        let mut seed = Zeroizing::new(ml_dsa::Seed::from(seed));
        let key = ml_dsa::SigningKey::from_seed(&seed);
        seed.zeroize();
        SecretKey(key)
    }

    /// Reads a PEM-encoded PKCS#8 ML-DSA-44 private key (App. A, App. B).
    ///
    /// The key may be in either form that holds the seed: the seed alone,
    /// as Appendix B and [`to_pkcs8_pem`](Self::to_pkcs8_pem) write it, or
    /// the seed together with the expanded key, which is what
    /// `openssl genpkey -algorithm ML-DSA-44` writes by default. In the
    /// second form the expanded key must match the seed. A key with only
    /// the expanded form, a PKCS#8 v2 key whose public key does not match,
    /// or anything else fails with `BadSyntax`.
    pub fn from_pkcs8_pem(pem: &str) -> Result<SecretKey, ParseError> {
        let der = pem_decode(pem)?;
        SecretKey::from_pkcs8_der(&der)
    }

    /// Reads a DER-encoded PKCS#8 ML-DSA-44 private key, in the forms
    /// [`from_pkcs8_pem`](Self::from_pkcs8_pem) accepts.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<SecretKey, ParseError> {
        pkcs8::decode(der)
    }

    /// Writes the key as PEM-encoded PKCS#8, in the seed-only form (App.
    /// B).
    ///
    /// The output is a PKCS#8 v1 structure with no public key, base64 in
    /// lines of 64 characters, LF line endings and a final LF. It is the
    /// same as `openssl pkey -provparam ml-dsa.output_formats=seed-only`
    /// writes. The string holds the secret and is wiped when dropped.
    pub fn to_pkcs8_pem(&self) -> Zeroizing<String> {
        let der = pkcs8::encode_seed(self.0.as_seed().as_ref());
        let body = Zeroizing::new(BASE64.encode(&der[..]));
        let mut pem = Zeroizing::new(String::with_capacity(body.len() + 64));
        pem.push_str(PEM_BEGIN);
        pem.push('\n');
        for line in body.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
            pem.push('\n');
        }
        pem.push_str(PEM_END);
        pem.push('\n');
        pem
    }

    /// The matching public key (4.4).
    pub fn public_key(&self) -> PublicKey {
        let key: &ml_dsa::VerifyingKey<MlDsa44> = self.0.as_ref();
        let bytes: [u8; PUBLIC_KEY_LEN] = key.encode().into();
        PublicKey(Arc::new(bytes))
    }

    /// Signs the challenge bytes for `host`, `nonce` and `uid`, for AUTH
    /// or REGISTER (4.5, 4.6), with the deterministic variant of
    /// ML-DSA.Sign. The same inputs always give the same signature, as in
    /// Appendix B.
    pub fn sign_challenge(&self, host: &str, nonce: &Nonce, uid: &str) -> Signature {
        let message = challenge_bytes(host, nonce, uid);
        let signature = self.0.sign(&message);
        Signature(Box::new(signature.encode().into()))
    }

    /// Signs the challenge bytes like [`sign_challenge`](Self::sign_challenge),
    /// but with the hedged variant of ML-DSA.Sign, which mixes in `rnd`.
    /// Pass 32 bytes from a cryptographically secure random source.
    /// Verifiers cannot tell the variants apart (4.5).
    pub fn sign_challenge_hedged(
        &self,
        host: &str,
        nonce: &Nonce,
        uid: &str,
        rnd: [u8; 32],
    ) -> Signature {
        let message = challenge_bytes(host, nonce, uid);
        let rnd = Zeroizing::new(ml_dsa::B32::from(rnd));
        let expanded = ExpandedSigningKey::<MlDsa44>::from_seed(self.0.as_seed());
        // M' for ML-DSA.Sign with an empty context: a zero byte for "not
        // prehashed", the context's length (0), then the message (FIPS
        // 204, Algorithm 2).
        let signature = expanded.sign_internal(&[&[0, 0], &message], &rnd);
        Signature(Box::new(signature.encode().into()))
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKey")
            .field("public_key", &self.public_key())
            .finish_non_exhaustive()
    }
}

/// Decodes exactly `len` characters of strict, padded, standard base64
/// into `N` bytes.
fn decode_base64<const N: usize>(
    s: &str,
    len: usize,
    what: &'static str,
) -> Result<[u8; N], ParseError> {
    if s.len() != len {
        return Err(ParseError::BadSyntax(what));
    }
    // STANDARD requires canonical padding and rejects non-zero trailing
    // bits and any character outside the alphabet, whitespace included.
    let mut out = [0u8; N];
    match BASE64.decode_slice(s, &mut out) {
        Ok(n) if n == N => Ok(out),
        _ => Err(ParseError::BadSyntax(what)),
    }
}

// ---------------------------------------------------------------------------
// PEM and PKCS#8

const PEM_BEGIN: &str = "-----BEGIN PRIVATE KEY-----";
const PEM_END: &str = "-----END PRIVATE KEY-----";

/// Reads the DER inside a `PRIVATE KEY` PEM block (RFC 7468). Lines may
/// end in LF or CRLF, the last one need not end at all, and blank space
/// around the block is ignored.
fn pem_decode(pem: &str) -> Result<Zeroizing<Vec<u8>>, ParseError> {
    const NOT_PEM: ParseError = ParseError::BadSyntax("not a PEM private key");
    let mut lines = pem.trim().lines().map(|l| l.trim_end_matches([' ', '\t']));
    if lines.next() != Some(PEM_BEGIN) {
        return Err(NOT_PEM);
    }
    let mut body = Zeroizing::new(String::new());
    let mut ended = false;
    for line in lines {
        if ended {
            return Err(NOT_PEM);
        }
        if line == PEM_END {
            ended = true;
        } else {
            body.push_str(line);
        }
    }
    if !ended {
        return Err(NOT_PEM);
    }
    BASE64
        .decode(body.as_bytes())
        .map(Zeroizing::new)
        .map_err(|_| NOT_PEM)
}

/// The PKCS#8 structures for ML-DSA-44 private keys
/// (draft-ietf-lamps-dilithium-certificates): `OneAsymmetricKey` with the
/// algorithm id-ml-dsa-44 and no parameters, whose private key is one of
///
/// ```text
/// ML-DSA-44-PrivateKey ::= CHOICE {
///   seed [0] IMPLICIT OCTET STRING (SIZE (32)),
///   expandedKey OCTET STRING (SIZE (2560)),
///   both SEQUENCE { seed OCTET STRING (SIZE (32)),
///                   expandedKey OCTET STRING (SIZE (2560)) } }
/// ```
///
/// Only DER is accepted, with definite, minimal lengths.
mod pkcs8 {
    use zeroize::Zeroizing;

    use super::SecretKey;
    use crate::error::ParseError;

    /// The DER of the OID 2.16.840.1.101.3.4.3.17, id-ml-dsa-44.
    const OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11];
    /// The length of an expanded ML-DSA-44 private key.
    const EXPANDED_LEN: usize = 2560;

    const SEQUENCE: u8 = 0x30;
    const INTEGER: u8 = 0x02;
    const OCTET_STRING: u8 = 0x04;
    const OBJECT_ID: u8 = 0x06;
    const SEED_TAG: u8 = 0x80;
    const PUBLIC_KEY_TAG: u8 = 0x81;

    const BAD: ParseError = ParseError::BadSyntax("not a PKCS#8 ML-DSA-44 private key");

    /// Writes the seed-only form, 54 bytes.
    pub(super) fn encode_seed(seed: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut der = Zeroizing::new(Vec::with_capacity(54));
        der.extend_from_slice(&[SEQUENCE, 0x34, INTEGER, 0x01, 0x00]);
        der.extend_from_slice(&[SEQUENCE, 0x0b, OBJECT_ID, 0x09]);
        der.extend_from_slice(OID);
        der.extend_from_slice(&[OCTET_STRING, 0x22, SEED_TAG, 0x20]);
        der.extend_from_slice(seed);
        der
    }

    /// Reads a key in the seed or both form.
    pub(super) fn decode(der: &[u8]) -> Result<SecretKey, ParseError> {
        let (body, rest) = expect(der, SEQUENCE)?;
        if !rest.is_empty() {
            return Err(BAD);
        }
        let (version, body) = expect(body, INTEGER)?;
        let v2 = match version {
            [0] => false,
            [1] => true,
            _ => return Err(BAD),
        };
        let (algorithm, body) = expect(body, SEQUENCE)?;
        let (oid, params) = expect(algorithm, OBJECT_ID)?;
        if oid != OID || !params.is_empty() {
            return Err(BAD);
        }
        let (private_key, mut body) = expect(body, OCTET_STRING)?;
        let mut public_key = None;
        if v2 && !body.is_empty() {
            let (bits, rest) = expect(body, PUBLIC_KEY_TAG)?;
            public_key = Some(bits);
            body = rest;
        }
        if !body.is_empty() {
            return Err(BAD);
        }

        let key = match private_key.first() {
            Some(&SEED_TAG) => {
                let (seed, rest) = expect(private_key, SEED_TAG)?;
                if !rest.is_empty() {
                    return Err(BAD);
                }
                from_seed(seed)?
            }
            Some(&SEQUENCE) => {
                let (both, rest) = expect(private_key, SEQUENCE)?;
                let (seed, both) = expect(both, OCTET_STRING)?;
                let (expanded, both) = expect(both, OCTET_STRING)?;
                if !rest.is_empty() || !both.is_empty() || expanded.len() != EXPANDED_LEN {
                    return Err(BAD);
                }
                let key = from_seed(seed)?;
                if !expanded_matches(&key, expanded) {
                    return Err(ParseError::BadSyntax(
                        "the expanded private key does not match its seed",
                    ));
                }
                key
            }
            Some(&OCTET_STRING) => {
                return Err(ParseError::BadSyntax(
                    "an ML-DSA private key without its seed is not supported",
                ));
            }
            _ => return Err(BAD),
        };

        if let Some(bits) = public_key {
            // A BIT STRING: no unused bits, then the raw key.
            if bits.first() != Some(&0) || &bits[1..] != key.public_key().as_bytes() {
                return Err(ParseError::BadSyntax(
                    "the public key does not match the private key",
                ));
            }
        }
        Ok(key)
    }

    fn from_seed(seed: &[u8]) -> Result<SecretKey, ParseError> {
        let seed = Zeroizing::new(<[u8; 32]>::try_from(seed).map_err(|_| BAD)?);
        Ok(SecretKey::from_seed(*seed))
    }

    /// Whether `expanded` is the FIPS 204 skEncode of the key's seed,
    /// compared without branching on secret bytes.
    #[allow(deprecated)] // to_expanded is deprecated only as a storage form
    fn expanded_matches(key: &SecretKey, expanded: &[u8]) -> bool {
        let ours = ml_dsa::ExpandedSigningKey::<ml_dsa::MlDsa44>::from_seed(key.0.as_seed());
        let ours = Zeroizing::new(ours.to_expanded());
        ours.len() == expanded.len()
            && ours
                .iter()
                .zip(expanded)
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0
    }

    /// Reads one DER element with tag `tag`: its contents and what
    /// follows it.
    fn expect(input: &[u8], tag: u8) -> Result<(&[u8], &[u8]), ParseError> {
        let (&found, rest) = input.split_first().ok_or(BAD)?;
        if found != tag {
            return Err(BAD);
        }
        let (&first, mut rest) = rest.split_first().ok_or(BAD)?;
        let len = if first < 0x80 {
            usize::from(first)
        } else {
            let count = usize::from(first & 0x7f);
            if count == 0 || count > 3 || rest.len() < count {
                return Err(BAD);
            }
            let (bytes, after) = rest.split_at(count);
            rest = after;
            // Minimal: no leading zero, and the long form only from 128.
            if bytes[0] == 0 {
                return Err(BAD);
            }
            let len = bytes.iter().fold(0usize, |n, &b| (n << 8) | usize::from(b));
            if len < 0x80 {
                return Err(BAD);
            }
            len
        };
        if rest.len() < len {
            return Err(BAD);
        }
        Ok(rest.split_at(len))
    }
}

/// Writes bytes as lower-case hex.
pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[usize::from(b >> 4)] as char);
        out.push(DIGITS[usize::from(b & 0x0f)] as char);
    }
    out
}

/// The value of one hex digit, either case.
pub(crate) fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    // Appendix B.
    const SEED_HEX: &str = "c11fae5c592e13be67dc96f6e85004d32e928615f7af1fd3a6c5d9ea0ab6cba8";
    const PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
        MDQCAQAwCwYJYIZIAWUDBAMRBCKAIMEfrlxZLhO+Z9yW9uhQBNMukoYV968f06bF\n\
        2eoKtsuo\n\
        -----END PRIVATE KEY-----\n";
    pub(crate) const PUBLIC_B64: &str = concat!(
        "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",
        "nnO/Wp68V/V/przmVp4j4g==",
    );
    pub(crate) const SIGNATURE: &str = concat!(
        "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",
        "AAAAAAAAAAAAAAAAAAAAAAkXJzM=",
    );
    const PUBLIC_SHA256: &str = "d9d69ac9b18f42759e43edba0106410c07045a1edab642925b7496ea40baccdf";
    const SIGNATURE_SHA256: &str =
        "eeda7aa7dd2ffa7cc2fa6683e7d8d2b94cf46716484b784d6a53b4928df58906";
    const HOST: &str = "chat.example.org";
    const NONCE: &str = "6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e";
    const UID: &str = "alice@example.org";
    const SIGNED: &str = "risala-auth-1\nchat.example.org\n\
        6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e\nalice@example.org\n";

    /// The AUTH command at the end of Appendix B, read from SPEC.md.
    fn spec_auth_line() -> &'static str {
        include_str!("../../../SPEC.md")
            .lines()
            .rev()
            .find(|l| l.starts_with("AUTH alice@example.org "))
            .expect("Appendix B has the AUTH command")
    }

    fn unhex<const N: usize>(s: &str) -> [u8; N] {
        let b = s.as_bytes();
        assert_eq!(b.len(), N * 2);
        let mut out = [0u8; N];
        for (i, pair) in b.as_chunks::<2>().0.iter().enumerate() {
            out[i] = (hex_digit(pair[0]).unwrap() << 4) | hex_digit(pair[1]).unwrap();
        }
        out
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        hex_lower(&<sha2::Sha256 as sha2::Digest>::digest(bytes))
    }

    fn appendix_b_key() -> SecretKey {
        SecretKey::from_seed(unhex::<32>(SEED_HEX))
    }

    fn nonce() -> Nonce {
        NONCE.parse().unwrap()
    }

    #[test]
    fn appendix_b_pem() {
        let key = appendix_b_key();
        assert_eq!(key.to_pkcs8_pem().as_str(), PEM);
        let imported = SecretKey::from_pkcs8_pem(PEM).unwrap();
        assert_eq!(imported.public_key(), key.public_key());
        assert_eq!(imported.to_pkcs8_pem().as_str(), PEM);
        // CRLF line endings and no final newline are accepted too.
        let crlf = PEM.replace('\n', "\r\n");
        assert!(SecretKey::from_pkcs8_pem(&crlf).is_ok());
        assert!(SecretKey::from_pkcs8_pem(PEM.trim_end()).is_ok());
    }

    #[test]
    fn appendix_b_public_key() {
        let public = appendix_b_key().public_key();
        assert_eq!(public.to_string(), PUBLIC_B64);
        assert_eq!(PUBLIC_B64.len(), PUBLIC_KEY_BASE64_LEN);
        assert_eq!(sha256_hex(public.as_bytes()), PUBLIC_SHA256);
        assert_eq!(PUBLIC_B64.parse::<PublicKey>().unwrap(), public);
        assert_eq!(PublicKey::from_bytes(public.as_bytes()), public);
        assert_eq!(
            public.fingerprint().to_string(),
            format!("sha256:{PUBLIC_SHA256}")
        );
    }

    #[test]
    fn appendix_b_challenge() {
        let bytes = challenge_bytes(HOST, &nonce(), UID);
        assert_eq!(bytes, SIGNED.as_bytes());
        assert_eq!(bytes.len(), 82);
        // Host and uid are folded to lower case.
        assert_eq!(
            challenge_bytes("Chat.Example.ORG", &nonce(), "Alice@Example.org"),
            bytes
        );
    }

    #[test]
    fn appendix_b_signature() {
        let key = appendix_b_key();
        let sig = key.sign_challenge(HOST, &nonce(), UID);
        assert_eq!(sig.to_string(), SIGNATURE);
        assert_eq!(SIGNATURE.len(), SIGNATURE_BASE64_LEN);
        assert_eq!(sha256_hex(sig.as_bytes()), SIGNATURE_SHA256);
        assert_eq!(SIGNATURE.parse::<Signature>().unwrap(), sig);
        assert_eq!(format!("AUTH {UID} {sig}"), spec_auth_line());

        // Our signature verifies, and so does the one in the spec.
        let public: PublicKey = PUBLIC_B64.parse().unwrap();
        assert!(public.verify_challenge(HOST, &nonce(), UID, &sig));
        let spec_sig: Signature = SIGNATURE.parse().unwrap();
        assert!(public.verify_challenge(HOST, &nonce(), UID, &spec_sig));
        assert!(public.verify_challenge("CHAT.example.org", &nonce(), "ALICE@example.org", &sig));
    }

    #[test]
    fn hedged_signatures_verify() {
        let key = appendix_b_key();
        let public = key.public_key();
        let a = key.sign_challenge_hedged(HOST, &nonce(), UID, [1; 32]);
        let b = key.sign_challenge_hedged(HOST, &nonce(), UID, [2; 32]);
        assert_ne!(a, b);
        assert_ne!(a.to_string(), SIGNATURE);
        assert!(public.verify_challenge(HOST, &nonce(), UID, &a));
        assert!(public.verify_challenge(HOST, &nonce(), UID, &b));
        assert!(!public.verify_challenge(HOST, &nonce(), "bob@example.org", &a));
        // With zero randomness, the hedged variant is the deterministic one.
        let zero = key.sign_challenge_hedged(HOST, &nonce(), UID, [0; 32]);
        assert_eq!(zero.to_string(), SIGNATURE);
    }

    #[test]
    fn wrong_inputs_fail_verification() {
        let key = appendix_b_key();
        let public = key.public_key();
        let sig: Signature = SIGNATURE.parse().unwrap();
        let other_nonce: Nonce = "6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6f".parse().unwrap();

        assert!(!public.verify_challenge("chat.example.net", &nonce(), UID, &sig));
        assert!(!public.verify_challenge(HOST, &other_nonce, UID, &sig));
        assert!(!public.verify_challenge(HOST, &nonce(), "bob@example.org", &sig));

        // Another key does not verify it.
        let other = SecretKey::from_seed([7; 32]).public_key();
        assert!(!other.verify_challenge(HOST, &nonce(), UID, &sig));

        // Neither does a signature with one bit flipped, anywhere.
        for i in [0, 10, 100, 1000, SIGNATURE_LEN - 1] {
            let mut bytes = *sig.as_bytes();
            bytes[i] ^= 1;
            let flipped = Signature::from_bytes(&bytes);
            assert!(
                !public.verify_challenge(HOST, &nonce(), UID, &flipped),
                "{i}"
            );
        }
        // Nor all zeros or all ones, which do not even decode.
        for b in [0, 0xff] {
            let junk = Signature::from_bytes(&[b; SIGNATURE_LEN]);
            assert!(!public.verify_challenge(HOST, &nonce(), UID, &junk));
        }
    }

    #[test]
    fn strict_base64() {
        // Wrong lengths.
        assert!("".parse::<PublicKey>().is_err());
        assert!(PUBLIC_B64[..1751].parse::<PublicKey>().is_err());
        assert!(format!("{PUBLIC_B64}A").parse::<PublicKey>().is_err());
        assert!(SIGNATURE[..3227].parse::<Signature>().is_err());
        assert!(PUBLIC_B64.parse::<Signature>().is_err());
        assert!(SIGNATURE.parse::<PublicKey>().is_err());
        // The key ends in "g==": 1312 bytes leave one byte over, whose
        // low four bits must be zero.
        assert!(PUBLIC_B64.ends_with("4g=="));
        let mut bad = PUBLIC_B64.to_string();
        bad.replace_range(1749..1750, "h");
        assert!(bad.parse::<PublicKey>().is_err());
        // Missing padding, same length.
        let mut bad = PUBLIC_B64.to_string();
        bad.replace_range(1750..1752, "AA");
        assert!(bad.parse::<PublicKey>().is_err());
        // The signature ends in "M=": two bytes over, low two bits zero.
        assert!(SIGNATURE.ends_with("zM="));
        let mut bad = SIGNATURE.to_string();
        bad.replace_range(3226..3227, "N");
        assert!(bad.parse::<Signature>().is_err());
        // Whitespace and the URL-safe alphabet.
        let mut bad = PUBLIC_B64.to_string();
        bad.replace_range(0..1, " ");
        assert!(bad.parse::<PublicKey>().is_err());
        let url_safe = PUBLIC_B64.replace('/', "_").replace('+', "-");
        assert_ne!(url_safe, PUBLIC_B64);
        assert!(url_safe.parse::<PublicKey>().is_err());
    }

    #[test]
    fn nonce_parsing() {
        let nonce: Nonce = NONCE.parse().unwrap();
        assert_eq!(nonce.as_str(), NONCE);
        assert_eq!(nonce.to_string(), NONCE);
        assert_eq!(Nonce::from_bytes(&nonce.to_bytes()).unwrap(), nonce);

        // Upper case folds to the canonical form.
        let upper: Nonce = NONCE.to_ascii_uppercase().parse().unwrap();
        assert_eq!(upper, nonce);
        assert_eq!(upper.as_str(), NONCE);

        assert!(NONCE[..30].parse::<Nonce>().is_err());
        assert!(NONCE[..31].parse::<Nonce>().is_err());
        assert!(format!("{NONCE}0").parse::<Nonce>().is_err());
        assert!(format!("{}g", &NONCE[..31]).parse::<Nonce>().is_err());
        assert!(format!("{NONCE} ").parse::<Nonce>().is_err());
        assert!("".parse::<Nonce>().is_err());

        assert!("ab".repeat(MAX_NONCE_BYTES).parse::<Nonce>().is_ok());
        assert_eq!(
            "ab".repeat(MAX_NONCE_BYTES + 1).parse::<Nonce>(),
            Err(ParseError::TooLong)
        );

        assert!(Nonce::from_bytes(&[0; 15]).is_err());
        assert_eq!(
            Nonce::from_bytes(&[0xab; 16]).unwrap().as_str(),
            "ab".repeat(16)
        );
        assert_eq!(Nonce::from_bytes(&[0; 65]), Err(ParseError::TooLong));
    }

    #[test]
    fn debug_hides_secret() {
        let key = appendix_b_key();
        let debug = format!("{key:?}");
        assert!(debug.contains(PUBLIC_SHA256), "{debug}");
        assert!(!debug.contains("c11fae"), "{debug}");
        assert!(!debug.contains("MDQCAQAw"), "{debug}");
    }

    #[test]
    fn bad_pem_is_rejected() {
        assert!(SecretKey::from_pkcs8_pem("").is_err());
        assert!(SecretKey::from_pkcs8_pem(&PEM.replace("PRIVATE", "PUBLIC")).is_err());
        assert!(SecretKey::from_pkcs8_pem(&PEM.replace("2eoKtsuo", "2eoKtsu")).is_err());
        assert!(SecretKey::from_pkcs8_pem(&format!("{PEM}junk\n")).is_err());
        // An Ed25519 key (OID 1.3.101.112) is not accepted.
        let ed25519 = "-----BEGIN PRIVATE KEY-----\n\
            MC4CAQAwBQYDK2VwBCIEIMEfrlxZLhO+Z9yW9uhQBNMukoYV968f06bF2eoKtsuo\n\
            -----END PRIVATE KEY-----\n";
        assert!(SecretKey::from_pkcs8_pem(ed25519).is_err());
    }

    /// The DER of `pem`.
    fn der(pem: &str) -> Vec<u8> {
        pem_decode(pem).unwrap().to_vec()
    }

    #[test]
    fn pkcs8_forms() {
        let key = appendix_b_key();
        let seed_only = der(PEM);
        assert_eq!(seed_only.len(), 54);
        assert!(SecretKey::from_pkcs8_der(&seed_only).is_ok());

        // The "both" form, as openssl writes by default.
        #[allow(deprecated)]
        let expanded =
            ExpandedSigningKey::<MlDsa44>::from_seed(&ml_dsa::Seed::from(unhex::<32>(SEED_HEX)))
                .to_expanded();
        let both = |expanded: &[u8]| {
            let mut inner = vec![0x30, 0x82, 0x0a, 0x26, 0x04, 0x20];
            inner.extend_from_slice(&unhex::<32>(SEED_HEX));
            inner.extend_from_slice(&[0x04, 0x82, 0x0a, 0x00]);
            inner.extend_from_slice(expanded);
            let mut der = vec![0x30, 0x82, 0x0a, 0x3e, 0x02, 0x01, 0x00];
            der.extend_from_slice(&seed_only[5..18]);
            der.extend_from_slice(&[0x04, 0x82, 0x0a, 0x2a]);
            der.extend_from_slice(&inner);
            der
        };
        let good = both(&expanded);
        assert_eq!(good.len(), 2626);
        let imported = SecretKey::from_pkcs8_der(&good).unwrap();
        assert_eq!(imported.public_key(), key.public_key());
        let mut wrong = expanded.to_vec();
        wrong[100] ^= 1;
        assert!(SecretKey::from_pkcs8_der(&both(&wrong)).is_err());

        // The expanded form alone has no seed.
        let mut alone = vec![0x30, 0x82, 0x0a, 0x18, 0x02, 0x01, 0x00];
        alone.extend_from_slice(&seed_only[5..18]);
        alone.extend_from_slice(&[0x04, 0x82, 0x0a, 0x04, 0x04, 0x82, 0x0a, 0x00]);
        alone.extend_from_slice(&expanded);
        assert_eq!(
            SecretKey::from_pkcs8_der(&alone).unwrap_err(),
            ParseError::BadSyntax("an ML-DSA private key without its seed is not supported")
        );

        // PKCS#8 v2 with a matching public key, and with a wrong one.
        let v2 = |public: &[u8]| {
            let mut body = vec![0x02, 0x01, 0x01];
            body.extend_from_slice(&seed_only[5..]);
            body.extend_from_slice(&[0x81, 0x82, 0x05, 0x21, 0x00]);
            body.extend_from_slice(public);
            let mut der = vec![0x30, 0x82];
            der.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
            der.extend_from_slice(&body);
            der
        };
        assert!(SecretKey::from_pkcs8_der(&v2(key.public_key().as_bytes())).is_ok());
        let other = SecretKey::from_seed([9; 32]).public_key();
        assert!(SecretKey::from_pkcs8_der(&v2(other.as_bytes())).is_err());

        // Trailing bytes, other versions, parameters and non-minimal lengths.
        let mut trailing = seed_only.clone();
        trailing.push(0);
        assert!(SecretKey::from_pkcs8_der(&trailing).is_err());
        let mut v3 = seed_only.clone();
        v3[4] = 2;
        assert!(SecretKey::from_pkcs8_der(&v3).is_err());
        let mut long_len = vec![0x30, 0x81, 0x34];
        long_len.extend_from_slice(&seed_only[2..]);
        assert!(SecretKey::from_pkcs8_der(&long_len).is_err());
        for cut in 0..seed_only.len() {
            assert!(
                SecretKey::from_pkcs8_der(&seed_only[..cut]).is_err(),
                "{cut}"
            );
        }
    }

    /// Runs openssl with `args`, feeding it `stdin`. Returns `None` if
    /// openssl is not installed or does not know ML-DSA (before 3.5).
    fn openssl(args: &[&str], stdin: &[u8]) -> Option<Vec<u8>> {
        use std::io::Write as _;
        use std::process::{Command, Stdio};
        let mut child = Command::new("openssl")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        child.stdin.take().unwrap().write_all(stdin).unwrap();
        let out = child.wait_with_output().unwrap();
        out.status.success().then_some(out.stdout)
    }

    #[test]
    fn openssl_interop() {
        let Some(pem) = openssl(&["genpkey", "-algorithm", "ML-DSA-44"], b"") else {
            eprintln!("openssl with ML-DSA not found, skipping");
            return;
        };
        let pem = String::from_utf8(pem).unwrap();
        // openssl writes the seed and the expanded key by default.
        let key = SecretKey::from_pkcs8_pem(&pem).unwrap();

        // The same public key as openssl derives, as in Appendix A.
        let der = openssl(&["pkey", "-pubout", "-outform", "der"], pem.as_bytes()).unwrap();
        assert_eq!(
            &der[der.len() - PUBLIC_KEY_LEN..],
            key.public_key().as_bytes()
        );

        // openssl reads the Appendix B key as we export it, and its
        // deterministic signature is the one in Appendix B.
        let exported = appendix_b_key().to_pkcs8_pem();
        let der = openssl(&["pkey", "-pubout", "-outform", "der"], exported.as_bytes()).unwrap();
        assert_eq!(
            sha256_hex(&der[der.len() - PUBLIC_KEY_LEN..]),
            PUBLIC_SHA256
        );
        let dir = std::env::temp_dir().join(format!("risala-auth-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key_path = dir.join("alice.pem");
        std::fs::write(&key_path, exported.as_bytes()).unwrap();
        let key_arg = key_path.to_str().unwrap();
        // openssl signs ML-DSA in one shot, so it reads the bytes from a
        // file, as in Appendix A.
        let chal_path = dir.join("chal");
        std::fs::write(&chal_path, SIGNED).unwrap();
        let chal_arg = chal_path.to_str().unwrap();
        let sign = |extra: &[&str]| {
            let mut args = vec![
                "pkeyutl", "-sign", "-rawin", "-inkey", key_arg, "-in", chal_arg,
            ];
            args.extend_from_slice(extra);
            openssl(&args, b"")
        };
        let sig = sign(&["-pkeyopt", "deterministic:1"]);
        // Hedged, as Appendix A signs by default.
        let hedged = sign(&[]);
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(BASE64.encode(sig.unwrap()), SIGNATURE);
        let hedged = Signature::from_bytes(&hedged.unwrap().try_into().unwrap());
        assert_ne!(hedged.to_string(), SIGNATURE);
        let public: PublicKey = PUBLIC_B64.parse().unwrap();
        assert!(public.verify_challenge(HOST, &nonce(), UID, &hedged));
    }
}
