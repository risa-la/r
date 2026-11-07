//! The sign-in challenge and Ed25519 keys (SPEC 4.1, 4.4-4.6, App. B).
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

use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::Signer as _;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _, KeypairBytes};

use crate::error::ParseError;

/// The first line of the signed bytes, without its LF (4.5).
pub const CHALLENGE_PREFIX: &str = "risala-auth-1";

/// The length of a public key in base64, with padding (4.4).
pub const PUBLIC_KEY_BASE64_LEN: usize = 44;

/// The length of a signature in base64, with padding (4.5).
pub const SIGNATURE_BASE64_LEN: usize = 88;

/// The fewest random bytes a nonce may have (4.1).
pub const MIN_NONCE_BYTES: usize = 16;

/// The most bytes this crate accepts in a nonce (4.1).
///
/// The spec sets only a minimum. This bound keeps a hostile server from
/// sending a huge greeting token; 64 bytes is four times the minimum.
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

/// An Ed25519 public key, as listed in key files and sent in REGISTER and
/// KEY commands (4.4, 4.6, 4.7).
///
/// On the wire it is 32 bytes in standard base64 with padding, exactly
/// [`PUBLIC_KEY_BASE64_LEN`] characters. Parsing is strict: it rejects
/// other lengths, whitespace, missing padding, non-canonical encodings
/// (non-zero trailing bits) and bytes that are not a point on the curve.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey(ed25519_dalek::VerifyingKey);

impl PublicKey {
    /// Makes a key from its 32 raw bytes (4.4). Fails with `BadSyntax` if
    /// they do not encode a curve point.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<PublicKey, ParseError> {
        ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .map(PublicKey)
            .map_err(|_| ParseError::BadSyntax("not an Ed25519 public key"))
    }

    /// The key's 32 raw bytes (4.4).
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Checks a signature over the challenge bytes for `host`, `nonce`
    /// and `uid` (4.5, 4.6).
    ///
    /// This is plain Ed25519 with strict verification: it rejects small
    /// order keys and `R` values and non-canonical `s`, as well as any
    /// signature that does not match.
    pub fn verify_challenge(
        &self,
        host: &str,
        nonce: &Nonce,
        uid: &str,
        signature: &Signature,
    ) -> bool {
        let message = challenge_bytes(host, nonce, uid);
        let signature = ed25519_dalek::Signature::from_bytes(&signature.0);
        self.0.verify_strict(&message, &signature).is_ok()
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
        let bytes = decode_base64::<32>(s, PUBLIC_KEY_BASE64_LEN, "bad public key")?;
        PublicKey::from_bytes(&bytes)
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&BASE64.encode(self.as_bytes()))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({self})")
    }
}

/// An Ed25519 signature, as sent in AUTH and REGISTER (4.5, 4.6).
///
/// On the wire it is 64 bytes in standard base64 with padding, exactly
/// [`SIGNATURE_BASE64_LEN`] characters, decoded as strictly as
/// [`PublicKey`].
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Signature([u8; 64]);

impl Signature {
    /// Makes a signature from its 64 raw bytes (4.5).
    pub fn from_bytes(bytes: [u8; 64]) -> Signature {
        Signature(bytes)
    }

    /// The signature's 64 raw bytes (4.5).
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl FromStr for Signature {
    type Err = ParseError;

    /// Parses a signature in strict base64 (4.5).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        decode_base64::<64>(s, SIGNATURE_BASE64_LEN, "bad signature").map(Signature)
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&BASE64.encode(self.0))
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({self})")
    }
}

/// A device's Ed25519 private key (4.3-4.5, App. A, App. B).
///
/// The secret is wiped from memory when the value is dropped. `Debug`
/// shows only the public key.
#[derive(Clone)]
pub struct SecretKey(ed25519_dalek::SigningKey);

impl SecretKey {
    /// Makes a key from its 32-byte seed, the RFC 8032 private key (App. B).
    ///
    /// To make a new key, pass 32 bytes from a cryptographically secure
    /// random source.
    pub fn from_seed(seed: [u8; 32]) -> SecretKey {
        SecretKey(ed25519_dalek::SigningKey::from_bytes(&seed))
    }

    /// Reads a PEM-encoded PKCS#8 Ed25519 private key (App. A, App. B).
    ///
    /// This is what `openssl genpkey -algorithm ed25519` writes. A PKCS#8
    /// v2 key that also carries the public key is accepted if that public
    /// key matches. Anything else fails with `BadSyntax`.
    pub fn from_pkcs8_pem(pem: &str) -> Result<SecretKey, ParseError> {
        ed25519_dalek::SigningKey::from_pkcs8_pem(pem)
            .map(SecretKey)
            .map_err(|_| ParseError::BadSyntax("not a PKCS#8 Ed25519 private key"))
    }

    /// Writes the key as PEM-encoded PKCS#8 (App. B).
    ///
    /// The output is the same as `openssl genpkey` writes: a PKCS#8 v1
    /// structure with no public key, one line of base64 and LF line
    /// endings, ending in LF. The string holds the secret, so handle it
    /// with care.
    pub fn to_pkcs8_pem(&self) -> String {
        let keypair = KeypairBytes {
            secret_key: self.0.to_bytes(),
            public_key: None,
        };
        let pem = keypair
            .to_pkcs8_pem(LineEnding::LF)
            .expect("encoding a 32-byte Ed25519 key cannot fail");
        pem.as_str().to_owned()
    }

    /// The matching public key (4.4).
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.verifying_key())
    }

    /// Signs the challenge bytes for `host`, `nonce` and `uid`, for AUTH
    /// or REGISTER (4.5, 4.6).
    pub fn sign_challenge(&self, host: &str, nonce: &Nonce, uid: &str) -> Signature {
        let message = challenge_bytes(host, nonce, uid);
        Signature(self.0.sign(&message).to_bytes())
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
mod tests {
    use super::*;

    // Appendix B.
    const SEED_HEX: &str = "c11fae5c592e13be67dc96f6e85004d32e928615f7af1fd3a6c5d9ea0ab6cba8";
    const PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
        MC4CAQAwBQYDK2VwBCIEIMEfrlxZLhO+Z9yW9uhQBNMukoYV968f06bF2eoKtsuo\n\
        -----END PRIVATE KEY-----\n";
    const PUBLIC_HEX: &str = "27f2a6ba9b9461c45dd82db235978acfad4921b20a6dd469fdd2fc95faae0d86";
    const PUBLIC_B64: &str = "J/KmupuUYcRd2C2yNZeKz61JIbIKbdRp/dL8lfquDYY=";
    const HOST: &str = "chat.example.org";
    const NONCE: &str = "6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e";
    const UID: &str = "alice@example.org";
    const SIGNED: &str = "risala-auth-1\nchat.example.org\n\
        6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e\nalice@example.org\n";
    const SIGNATURE: &str =
        "Hk+S5Vd7ciW57dRNS3AhcvZkYNLmj+kkgJUxOYvCrbEQSBk0UDdH+cSBXF6YvCSU85FRVPaURwsQdbV/SAK0CQ==";
    const AUTH_LINE: &str = "AUTH alice@example.org Hk+S5Vd7ciW57dRNS3AhcvZkYNLmj+kkgJUxOYvCrbEQSBk0UDdH+cSBXF6YvCSU85FRVPaURwsQdbV/SAK0CQ==";

    fn unhex<const N: usize>(s: &str) -> [u8; N] {
        let b = s.as_bytes();
        assert_eq!(b.len(), N * 2);
        let mut out = [0u8; N];
        for (i, pair) in b.as_chunks::<2>().0.iter().enumerate() {
            out[i] = (hex_digit(pair[0]).unwrap() << 4) | hex_digit(pair[1]).unwrap();
        }
        out
    }

    fn appendix_b_key() -> SecretKey {
        SecretKey::from_seed(unhex::<32>(SEED_HEX))
    }

    #[test]
    fn appendix_b_pem() {
        let key = appendix_b_key();
        assert_eq!(key.to_pkcs8_pem(), PEM);
        let imported = SecretKey::from_pkcs8_pem(PEM).unwrap();
        assert_eq!(imported.public_key(), key.public_key());
        assert_eq!(imported.to_pkcs8_pem(), PEM);
        // CRLF line endings and no final newline are accepted too.
        let crlf = PEM.replace('\n', "\r\n");
        assert!(SecretKey::from_pkcs8_pem(&crlf).is_ok());
        assert!(SecretKey::from_pkcs8_pem(PEM.trim_end()).is_ok());
    }

    #[test]
    fn appendix_b_public_key() {
        let public = appendix_b_key().public_key();
        assert_eq!(hex_lower(public.as_bytes()), PUBLIC_HEX);
        assert_eq!(public.to_string(), PUBLIC_B64);
        assert_eq!(public.to_string().len(), PUBLIC_KEY_BASE64_LEN);
        assert_eq!(PUBLIC_B64.parse::<PublicKey>().unwrap(), public);
        assert_eq!(
            PublicKey::from_bytes(&unhex::<32>(PUBLIC_HEX)).unwrap(),
            public
        );
    }

    #[test]
    fn appendix_b_challenge() {
        let nonce: Nonce = NONCE.parse().unwrap();
        let bytes = challenge_bytes(HOST, &nonce, UID);
        assert_eq!(bytes, SIGNED.as_bytes());
        assert_eq!(bytes.len(), 82);
        // Host and uid are folded to lower case.
        assert_eq!(
            challenge_bytes("Chat.Example.ORG", &nonce, "Alice@Example.org"),
            bytes
        );
    }

    #[test]
    fn appendix_b_signature() {
        let key = appendix_b_key();
        let nonce: Nonce = NONCE.parse().unwrap();
        let sig = key.sign_challenge(HOST, &nonce, UID);
        assert_eq!(sig.to_string(), SIGNATURE);
        assert_eq!(sig.to_string().len(), SIGNATURE_BASE64_LEN);
        assert_eq!(SIGNATURE.parse::<Signature>().unwrap(), sig);
        assert_eq!(format!("AUTH {UID} {sig}"), AUTH_LINE);

        // Our signature verifies, and so does the one in the spec.
        let public: PublicKey = PUBLIC_B64.parse().unwrap();
        assert!(public.verify_challenge(HOST, &nonce, UID, &sig));
        let spec_sig: Signature = SIGNATURE.parse().unwrap();
        assert!(public.verify_challenge(HOST, &nonce, UID, &spec_sig));
        assert!(public.verify_challenge("CHAT.example.org", &nonce, "ALICE@example.org", &sig));
    }

    #[test]
    fn wrong_inputs_fail_verification() {
        let key = appendix_b_key();
        let public = key.public_key();
        let nonce: Nonce = NONCE.parse().unwrap();
        let sig: Signature = SIGNATURE.parse().unwrap();
        let other_nonce: Nonce = "6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6f".parse().unwrap();

        assert!(!public.verify_challenge("chat.example.net", &nonce, UID, &sig));
        assert!(!public.verify_challenge(HOST, &other_nonce, UID, &sig));
        assert!(!public.verify_challenge(HOST, &nonce, "bob@example.org", &sig));

        // Another key does not verify it.
        let other = SecretKey::from_seed([7; 32]).public_key();
        assert!(!other.verify_challenge(HOST, &nonce, UID, &sig));

        // Neither does a signature with one bit flipped.
        let mut bytes = *sig.as_bytes();
        bytes[10] ^= 1;
        assert!(!public.verify_challenge(HOST, &nonce, UID, &Signature::from_bytes(bytes)));
    }

    #[test]
    fn strict_verification_rejects_non_canonical_s() {
        // Adding the group order L to s gives a signature that lax
        // verifiers accept and strict ones reject.
        const L: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        let public: PublicKey = PUBLIC_B64.parse().unwrap();
        let nonce: Nonce = NONCE.parse().unwrap();
        let sig: Signature = SIGNATURE.parse().unwrap();
        let mut bytes = *sig.as_bytes();
        let mut carry = 0u16;
        for i in 0..32 {
            let sum = u16::from(bytes[32 + i]) + u16::from(L[i]) + carry;
            bytes[32 + i] = sum as u8;
            carry = sum >> 8;
        }
        assert_eq!(carry, 0);
        assert!(!public.verify_challenge(HOST, &nonce, UID, &Signature::from_bytes(bytes)));
    }

    #[test]
    fn small_order_key_is_rejected() {
        // The identity point: a valid encoding, but of small order.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let weak = PublicKey::from_bytes(&identity).unwrap();
        let nonce: Nonce = NONCE.parse().unwrap();
        // With the identity as key, R = identity and s = 0 would pass a
        // lax check: [s]B = R + [k]A.
        let mut forged = [0u8; 64];
        forged[0] = 1;
        assert!(!weak.verify_challenge(HOST, &nonce, UID, &Signature::from_bytes(forged)));
    }

    #[test]
    fn strict_base64() {
        // Wrong lengths.
        assert!("".parse::<PublicKey>().is_err());
        assert!(PUBLIC_B64[..43].parse::<PublicKey>().is_err());
        assert!(format!("{PUBLIC_B64}A").parse::<PublicKey>().is_err());
        assert!(SIGNATURE[..87].parse::<Signature>().is_err());
        assert!(PUBLIC_B64.parse::<Signature>().is_err());
        // Missing padding, same length.
        assert!(
            "J/KmupuUYcRd2C2yNZeKz61JIbIKbdRp/dL8lfquDYYA"
                .parse::<PublicKey>()
                .is_err()
        );
        // Non-zero trailing bits: Y= has bits set below the last byte.
        assert!(
            "J/KmupuUYcRd2C2yNZeKz61JIbIKbdRp/dL8lfquDYZ="
                .parse::<PublicKey>()
                .is_err()
        );
        let mut sig = SIGNATURE.to_string();
        sig.replace_range(85..86, "R");
        assert!(sig.parse::<Signature>().is_err());
        // Whitespace and other alphabets.
        assert!(
            " /KmupuUYcRd2C2yNZeKz61JIbIKbdRp/dL8lfquDYY="
                .parse::<PublicKey>()
                .is_err()
        );
        assert!(
            "J/KmupuUYcRd2C2yNZeKz61JIbIKbdRp/dL8lfquDY\nY"
                .parse::<PublicKey>()
                .is_err()
        );
        assert!(
            "J_KmupuUYcRd2C2yNZeKz61JIbIKbdRp_dL8lfquDYY="
                .parse::<PublicKey>()
                .is_err()
        );
    }

    #[test]
    fn public_key_must_be_a_point() {
        // y = 2 is not the y coordinate of any point on the curve.
        let mut bytes = [0u8; 32];
        bytes[0] = 2;
        assert!(PublicKey::from_bytes(&bytes).is_err());
        assert!(BASE64.encode(bytes).parse::<PublicKey>().is_err());
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
        assert!(debug.contains(PUBLIC_B64), "{debug}");
        assert!(!debug.contains("c11fae"), "{debug}");
    }

    #[test]
    fn bad_pem_is_rejected() {
        assert!(SecretKey::from_pkcs8_pem("").is_err());
        assert!(SecretKey::from_pkcs8_pem(&PEM.replace("PRIVATE", "PUBLIC")).is_err());
        // An Ed448 key (OID 1.3.101.113) is not accepted.
        let ed448 = "-----BEGIN PRIVATE KEY-----\n\
            MEcCAQAwBQYDK2VxBDsEOUVtG3MpMC3pEd3ioFy3Yd8I9aWK2Cp6bvwzdwPnvqJl\n\
            rZb0uubRNNoFQWH9mGHR8tBqC3ZYDgi59A==\n\
            -----END PRIVATE KEY-----\n";
        assert!(SecretKey::from_pkcs8_pem(ed448).is_err());
    }

    /// Runs openssl with `args`, feeding it `stdin`. Returns `None` if
    /// openssl is not installed.
    fn openssl(args: &[&str], stdin: &[u8]) -> Option<Vec<u8>> {
        use std::io::Write as _;
        use std::process::{Command, Stdio};
        let mut child = match Command::new("openssl")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
        {
            Ok(child) => child,
            Err(_) => return None,
        };
        child.stdin.take().unwrap().write_all(stdin).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "openssl {args:?} failed");
        Some(out.stdout)
    }

    #[test]
    fn openssl_interop() {
        let Some(pem) = openssl(&["genpkey", "-algorithm", "ed25519"], b"") else {
            eprintln!("openssl not found, skipping");
            return;
        };
        let pem = String::from_utf8(pem).unwrap();
        let key = SecretKey::from_pkcs8_pem(&pem).unwrap();

        // The same public key as openssl derives, as in Appendix A.
        let der = openssl(&["pkey", "-pubout", "-outform", "der"], pem.as_bytes()).unwrap();
        assert_eq!(&der[der.len() - 32..], key.public_key().as_bytes());

        // Exporting gives back exactly what openssl wrote.
        assert_eq!(key.to_pkcs8_pem(), pem);

        // openssl reads the Appendix B key as we export it.
        let exported = appendix_b_key().to_pkcs8_pem();
        let der = openssl(&["pkey", "-pubout", "-outform", "der"], exported.as_bytes()).unwrap();
        assert_eq!(hex_lower(&der[der.len() - 32..]), PUBLIC_HEX);
    }
}
