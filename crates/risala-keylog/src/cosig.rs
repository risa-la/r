//! Timestamped ML-DSA-44 checkpoint cosignatures, signed-note signature
//! type `0x06` [TLOG-COSIGNATURE] [TLOG-CHECKPOINT]: what a key log signs
//! its checkpoints with, and what witnesses cosign them with (SPEC 4.5).
//!
//! The signature is ML-DSA-44 \[FIPS204\], with an empty context, over a
//! `CosignedSubtree`:
//!
//! ```text
//! struct {
//!     uint8 label[12] = "subtree/v1\n\0";
//!     opaque cosigner_name<1..2^8-1>;
//!     uint64 timestamp;
//!     opaque log_origin<1..2^8-1>;
//!     uint64 start;
//!     uint64 end;
//!     uint8 hash[32];
//! } CosignedSubtree;
//! ```
//!
//! For a checkpoint, `start` is 0, `end` the tree size and `hash` the root.
//! The note signature is the key id, the timestamp as 8 big-endian bytes,
//! and the 2420-byte ML-DSA-44 signature. Extension lines are not signed.

use std::fmt;

use libcrux_ml_dsa::ml_dsa_44 as mldsa;
use thiserror::Error;
use zeroize::Zeroize;

use crate::checkpoint::{Checkpoint, is_valid_name};
use crate::note::{NoteError, NoteSignature, VerifierKey, key_id};

/// The signed-note signature type of timestamped ML-DSA-44 checkpoint
/// cosignatures.
pub const SIG_TYPE: u8 = 0x06;

/// The length of an ML-DSA-44 public key.
pub const PUBLIC_KEY_LEN: usize = 1312;

/// The length of an ML-DSA-44 signature.
pub const SIGNATURE_LEN: usize = 2420;

/// The length of a cosignature after its key id: the timestamp and the
/// ML-DSA-44 signature.
pub const COSIGNATURE_LEN: usize = 8 + SIGNATURE_LEN;

/// The label that starts a `CosignedSubtree`.
pub const LABEL: &[u8; 12] = b"subtree/v1\n\0";

/// Why a cosigner could not be made, or a cosignature did not verify.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CosigError {
    /// The cosigner name is not 1 to 255 bytes with no space, plus or
    /// control character.
    #[error("invalid cosigner name")]
    BadName,
    /// A verifier key of another signature type, or of the wrong length.
    #[error("not an ML-DSA-44 cosignature key (type 0x06)")]
    WrongKeyType,
    /// The verifier key's id is not the hash of its name and key.
    #[error("the key id does not match the key")]
    WrongKeyId,
    /// The signature line is not for this key.
    #[error("the signature is from another key")]
    OtherKey,
    /// The signature is not 2428 bytes after the key id.
    #[error("the cosignature has the wrong length")]
    WrongLength,
    /// The ML-DSA-44 signature does not verify.
    #[error("the cosignature does not verify")]
    BadSignature,
    /// The verifier key did not parse.
    #[error(transparent)]
    Note(#[from] NoteError),
}

/// The bytes an ML-DSA-44 cosigner signs: a `CosignedSubtree`.
pub fn cosigned_subtree(
    cosigner_name: &str,
    timestamp: u64,
    log_origin: &str,
    start: u64,
    end: u64,
    hash: &[u8; 32],
) -> Result<Vec<u8>, CosigError> {
    if !is_valid_name(cosigner_name) || !is_valid_name(log_origin) {
        return Err(CosigError::BadName);
    }
    let mut m = Vec::with_capacity(12 + 2 + cosigner_name.len() + log_origin.len() + 24 + 32);
    m.extend_from_slice(LABEL);
    m.push(cosigner_name.len() as u8);
    m.extend_from_slice(cosigner_name.as_bytes());
    m.extend_from_slice(&timestamp.to_be_bytes());
    m.push(log_origin.len() as u8);
    m.extend_from_slice(log_origin.as_bytes());
    m.extend_from_slice(&start.to_be_bytes());
    m.extend_from_slice(&end.to_be_bytes());
    m.extend_from_slice(hash);
    Ok(m)
}

fn checkpoint_message(
    name: &str,
    timestamp: u64,
    checkpoint: &Checkpoint,
) -> Result<Vec<u8>, CosigError> {
    cosigned_subtree(
        name,
        timestamp,
        checkpoint.origin(),
        0,
        checkpoint.size(),
        checkpoint.root().as_bytes(),
    )
}

/// An ML-DSA-44 cosigner: a log signing its own checkpoints, under its
/// origin's name, or a witness.
pub struct Cosigner {
    name: String,
    key_pair: mldsa::MLDSA44KeyPair,
    key_id: u32,
}

impl Cosigner {
    /// The cosigner whose key ML-DSA.KeyGen makes from this 32-byte seed
    /// \[FIPS204\].
    pub fn from_seed(name: &str, seed: &[u8; 32]) -> Result<Cosigner, CosigError> {
        if !is_valid_name(name) {
            return Err(CosigError::BadName);
        }
        let key_pair = mldsa::generate_key_pair(*seed);
        let key_id = key_id(name, SIG_TYPE, key_pair.verification_key.as_ref());
        Ok(Cosigner {
            name: name.to_owned(),
            key_pair,
            key_id,
        })
    }

    /// The cosigner's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The public key.
    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        self.key_pair.verification_key.as_ref()
    }

    /// The verifier for this cosigner's signatures.
    pub fn verifier(&self) -> CosignatureVerifier {
        CosignatureVerifier {
            name: self.name.clone(),
            key_id: self.key_id,
            public_key: Box::new(*self.public_key()),
        }
    }

    /// The verifier key, `<name>+<id>+<base64(0x06 || key)>`.
    pub fn vkey(&self) -> VerifierKey {
        self.verifier().vkey()
    }

    /// Cosigns a checkpoint at `timestamp`, in seconds since 1970.
    ///
    /// `rnd` is ML-DSA.Sign's randomness: 32 fresh random bytes for the
    /// hedged variant, which signers should use, or zeros for the
    /// deterministic one \[FIPS204\].
    pub fn cosign(&self, checkpoint: &Checkpoint, timestamp: u64, rnd: [u8; 32]) -> NoteSignature {
        let message = checkpoint_message(&self.name, timestamp, checkpoint)
            .expect("names are checked when made");
        // Signing fails only if rejection sampling runs out of attempts,
        // which FIPS 204 Appendix C bounds at 2^-256, or if the context is
        // longer than 255 bytes, which ours is not.
        let sig = mldsa::sign(&self.key_pair.signing_key, &message, b"", rnd)
            .expect("ML-DSA-44 signing with an empty context does not fail");
        let mut signature = Vec::with_capacity(COSIGNATURE_LEN);
        signature.extend_from_slice(&timestamp.to_be_bytes());
        signature.extend_from_slice(sig.as_ref());
        NoteSignature {
            name: self.name.clone(),
            key_id: self.key_id,
            signature,
        }
    }
}

impl Drop for Cosigner {
    fn drop(&mut self) {
        self.key_pair.signing_key.as_ref_mut().zeroize();
    }
}

impl fmt::Debug for Cosigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cosigner")
            .field("name", &self.name)
            .field("key_id", &format_args!("{:08x}", self.key_id))
            .finish_non_exhaustive()
    }
}

/// Checks ML-DSA-44 cosignatures from one cosigner.
#[derive(Clone, PartialEq, Eq)]
pub struct CosignatureVerifier {
    name: String,
    key_id: u32,
    public_key: Box<[u8; PUBLIC_KEY_LEN]>,
}

impl CosignatureVerifier {
    /// A verifier for this name and public key.
    pub fn new(
        name: &str,
        public_key: &[u8; PUBLIC_KEY_LEN],
    ) -> Result<CosignatureVerifier, CosigError> {
        if !is_valid_name(name) {
            return Err(CosigError::BadName);
        }
        Ok(CosignatureVerifier {
            name: name.to_owned(),
            key_id: key_id(name, SIG_TYPE, public_key),
            public_key: Box::new(*public_key),
        })
    }

    /// A verifier from a verifier key, which must be of type `0x06` with a
    /// 1312-byte key, and whose id must be the recommended hash. Keys of
    /// any other type, Ed25519 among them, are refused (SPEC 4.5).
    pub fn from_vkey(vkey: &VerifierKey) -> Result<CosignatureVerifier, CosigError> {
        if vkey.sig_type() != SIG_TYPE {
            return Err(CosigError::WrongKeyType);
        }
        let public_key: &[u8; PUBLIC_KEY_LEN] = vkey
            .public_key()
            .try_into()
            .map_err(|_| CosigError::WrongKeyType)?;
        let v = CosignatureVerifier::new(vkey.name(), public_key)?;
        if v.key_id != vkey.key_id() {
            return Err(CosigError::WrongKeyId);
        }
        Ok(v)
    }

    /// Parses a verifier key and makes a verifier from it.
    pub fn from_vkey_str(vkey: &str) -> Result<CosignatureVerifier, CosigError> {
        CosignatureVerifier::from_vkey(&vkey.parse()?)
    }

    /// The cosigner's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The key id.
    pub fn key_id(&self) -> u32 {
        self.key_id
    }

    /// The public key.
    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public_key
    }

    /// The verifier key.
    pub fn vkey(&self) -> VerifierKey {
        VerifierKey::new(&self.name, SIG_TYPE, &self.public_key[..])
            .expect("names are checked when made")
    }

    /// Whether a signature line names this key: the same name and id.
    /// Lines that match only one of them are from other keys
    /// [SIGNED-NOTE].
    pub fn matches(&self, sig: &NoteSignature) -> bool {
        sig.name == self.name && sig.key_id == self.key_id
    }

    /// Verifies this key's cosignature on a checkpoint, and returns its
    /// timestamp.
    pub fn verify(&self, checkpoint: &Checkpoint, sig: &NoteSignature) -> Result<u64, CosigError> {
        if !self.matches(sig) {
            return Err(CosigError::OtherKey);
        }
        let bytes: &[u8; COSIGNATURE_LEN] = sig
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| CosigError::WrongLength)?;
        let (ts, signature) = bytes.split_first_chunk::<8>().expect("8 bytes");
        let timestamp = u64::from_be_bytes(*ts);
        let message = checkpoint_message(&self.name, timestamp, checkpoint)?;
        let key = mldsa::MLDSA44VerificationKey::new(*self.public_key);
        let signature = mldsa::MLDSA44Signature::new(signature.try_into().expect("2420 bytes"));
        mldsa::verify(&key, &message, b"", &signature).map_err(|_| CosigError::BadSignature)?;
        Ok(timestamp)
    }
}

impl fmt::Debug for CosignatureVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CosignatureVerifier")
            .field("name", &self.name)
            .field("key_id", &format_args!("{:08x}", self.key_id))
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::leaf_hash;

    fn checkpoint() -> Checkpoint {
        Checkpoint::new("chat.example.org/risala-log/1", 7, leaf_hash(b"root")).unwrap()
    }

    #[test]
    fn subtree_encoding() {
        let m = cosigned_subtree("w", 0x0102030405060708, "o/1", 0, 9, &[0xaa; 32]).unwrap();
        let mut want = b"subtree/v1\n\0".to_vec();
        want.extend_from_slice(&[1, b'w']);
        want.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        want.extend_from_slice(&[3, b'o', b'/', b'1']);
        want.extend_from_slice(&[0; 8]);
        want.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 9]);
        want.extend_from_slice(&[0xaa; 32]);
        assert_eq!(m, want);
        assert_eq!(
            cosigned_subtree("", 0, "o", 0, 0, &[0; 32]),
            Err(CosigError::BadName)
        );
        assert_eq!(
            cosigned_subtree("w", 0, &"o".repeat(256), 0, 0, &[0; 32]),
            Err(CosigError::BadName)
        );
        assert!(cosigned_subtree(&"w".repeat(255), 0, "o", 0, 0, &[0; 32]).is_ok());
    }

    #[test]
    fn signs_and_verifies() {
        let c = Cosigner::from_seed("witness.example/w1", &[7; 32]).unwrap();
        let v = c.verifier();
        let cp = checkpoint();
        let sig = c.cosign(&cp, 1_800_000_000, [0; 32]);
        assert_eq!(sig.signature.len(), COSIGNATURE_LEN);
        assert_eq!(
            sig.key_id,
            key_id("witness.example/w1", 0x06, c.public_key())
        );
        assert_eq!(v.verify(&cp, &sig), Ok(1_800_000_000));
        // Deterministic signing gives the same bytes; hedged ones differ
        // but verify.
        assert_eq!(c.cosign(&cp, 1_800_000_000, [0; 32]), sig);
        let hedged = c.cosign(&cp, 1_800_000_000, [9; 32]);
        assert_ne!(hedged, sig);
        assert_eq!(v.verify(&cp, &hedged), Ok(1_800_000_000));

        // Anything changed fails.
        let other_size = Checkpoint::new(cp.origin(), 8, *cp.root()).unwrap();
        assert_eq!(v.verify(&other_size, &sig), Err(CosigError::BadSignature));
        let other_root = Checkpoint::new(cp.origin(), 7, leaf_hash(b"other")).unwrap();
        assert_eq!(v.verify(&other_root, &sig), Err(CosigError::BadSignature));
        let other_origin = Checkpoint::new("chat.example.org/risala-log/2", 7, *cp.root()).unwrap();
        assert_eq!(v.verify(&other_origin, &sig), Err(CosigError::BadSignature));
        let mut later = sig.clone();
        later.signature[7] ^= 1;
        assert_eq!(v.verify(&cp, &later), Err(CosigError::BadSignature));
        let mut short = sig.clone();
        short.signature.pop();
        assert_eq!(v.verify(&cp, &short), Err(CosigError::WrongLength));
        let mut renamed = sig.clone();
        renamed.name = "witness.example/w2".into();
        assert_eq!(v.verify(&cp, &renamed), Err(CosigError::OtherKey));
        let mut reid = sig.clone();
        reid.key_id ^= 1;
        assert_eq!(v.verify(&cp, &reid), Err(CosigError::OtherKey));

        // The name is signed: the same key under another name does not
        // verify.
        let alias = Cosigner::from_seed("witness.example/w2", &[7; 32]).unwrap();
        let alias_sig = alias.cosign(&cp, 1_800_000_000, [0; 32]);
        let mut moved = alias_sig.clone();
        moved.name = sig.name.clone();
        moved.key_id = sig.key_id;
        assert_eq!(v.verify(&cp, &moved), Err(CosigError::BadSignature));

        // Extension lines are not signed.
        let with_ext = Checkpoint::from_text(&format!("{}ext\n", cp.to_text())).unwrap();
        assert_eq!(v.verify(&with_ext, &sig), Ok(1_800_000_000));
    }

    #[test]
    fn vkeys() {
        let c = Cosigner::from_seed("chat.example.org/risala-log/1", &[1; 32]).unwrap();
        let s = c.vkey().to_string();
        assert!(s.starts_with(&format!(
            "chat.example.org/risala-log/1+{:08x}+B",
            c.verifier().key_id()
        )));
        let v = CosignatureVerifier::from_vkey_str(&s).unwrap();
        assert_eq!(v, c.verifier());

        // The Ed25519 key of [SIGNED-NOTE]'s example is refused.
        assert_eq!(
            CosignatureVerifier::from_vkey_str(
                "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k"
            ),
            Err(CosigError::WrongKeyType)
        );
        // So is a type 0x04 (timestamped Ed25519) key.
        let ed = VerifierKey::new("w", 0x04, &[0; 32]).unwrap();
        assert_eq!(
            CosignatureVerifier::from_vkey(&ed),
            Err(CosigError::WrongKeyType)
        );
        // And a type 0x06 key of the wrong length.
        let short = VerifierKey::new("w", 0x06, &[0; 1311]).unwrap();
        assert_eq!(
            CosignatureVerifier::from_vkey(&short),
            Err(CosigError::WrongKeyType)
        );
        assert_eq!(
            Cosigner::from_seed("a b", &[0; 32]).unwrap_err(),
            CosigError::BadName
        );
    }
}
