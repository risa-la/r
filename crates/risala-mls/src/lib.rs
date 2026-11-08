//! The MLS layer of risala (SPEC 12), shared by `risalad`, which reads the
//! framing of posts and checks public rooms' commits, and librisala, which
//! runs the groups.
//!
//! Formats:
//!
//! - [`identity`]: leaf credentials, a RisalaIdentity (12.3).
//! - [`binding`]: device bindings, extension `0xF2A2` (12.3).
//! - [`profile`]: profiles, extension `0xF2A3` (12.3).
//! - [`conversation`]: the conversation extension `0xF2A1`, and who may
//!   change what (12.4, 6.2-6.4).
//! - [`aad`]: RisalaAAD and pseudonyms (12.9, 7.3).
//! - [`token`]: send tokens (7.2).
//! - [`framing`]: reading an MLS message's framing without keys, for the
//!   server (12.2, 7.2).
//! - [`wire`]: MLS values as bytes (12.2).
//!
//! Keys and crypto:
//!
//! - [`crypto`]: the OpenMLS provider for cipher suite `0x0020` (12.2).
//! - [`mldsa`]: ML-DSA-44 keys, and leaf keys (12.3).
//! - [`risala_sign`]: RisalaSign (4.3), until it moves to `risala-proto`.
//! - [`primitives`]: SHA-384, HKDF, HMAC, ChaCha20-Poly1305 and MLS's
//!   labelled functions, for use outside MLS.
//!
//! Groups:
//!
//! - [`keypackage`]: making KeyPackages, and the checks of KEYPKG ADD
//!   (12.5).
//! - [`group`]: creating groups, joining by Welcome and external commit,
//!   commits, SelfRemove, and processing posts (12.6-12.8, 6.1).
//! - [`checks`]: the checks of joining and of every commit (12.7).
//!
//! OpenMLS is patched in two places (`crates/openmls-traits/RISALA.md`,
//! `crates/openmls/RISALA.md`): the suite's value is `0x0020`, and
//! SelfRemove is framed with the group's wire format.

pub mod aad;
pub mod archive;
pub mod backup;
pub mod binding;
pub mod checks;
pub mod codec;
pub mod conversation;
pub mod crypto;
pub mod file;
pub mod framing;
pub mod group;
pub mod identity;
pub mod keypackage;
pub mod mldsa;
pub mod pairing;
pub mod primitives;
pub mod profile;
pub mod risala_sign;
mod seeded;
pub mod token;
pub mod wire;

pub use openmls;
pub use openmls_traits;

pub use aad::{Pseudonym, RisalaAad};
pub use archive::{
    ArchiveError, ArchivedConversation, ArchivedMessage, HistoryArchive, SealedArchive,
    TransferRef, seal_transfer,
};
pub use backup::{Backup, BackupError, BackupKey, RecoveryKey, RecoveryKeyError, WrappedKey};
pub use binding::DeviceBinding;
pub use conversation::{ConversationKind, RisalaConversation};
pub use crypto::{Provider, RisalaCrypto};
pub use file::{BlobRef, BlobRefError, Decryptor, EncryptedFile, Encryptor, FileError, FileKey};
pub use identity::{DeviceId, RisalaIdentity};
pub use mldsa::{LeafKey, SigningKey};
pub use pairing::{IdentityBundle, PairingCode, PairingError, PairingSecret, Relay, RelayId};
pub use profile::RisalaProfile;
pub use token::SendToken;

use openmls::prelude::Ciphersuite;

/// The cipher suite of every conversation, `0x0020`: X-Wing,
/// ChaCha20-Poly1305, SHA-384 and ML-DSA-44 (12.2, 15).
pub const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod suite_tests {
    use super::*;

    /// The suite is pinned (12.2): its value is `0x0020` and its
    /// algorithms are the table's, so an OpenMLS upgrade that changed
    /// either fails here. OpenMLS calls X-Wing's HPKE KEM
    /// `XWingKemDraft6`; HPKE itself uses 0x647a for it (hpke-rs).
    #[test]
    fn suite_value() {
        assert_eq!(framing::CIPHER_SUITE, 0x0020);
        assert_eq!(u16::from(CIPHERSUITE), framing::CIPHER_SUITE);
        assert_eq!(
            CIPHERSUITE.hpke_kem_algorithm(),
            openmls_traits::types::HpkeKemType::XWingKemDraft6
        );
        assert_eq!(
            CIPHERSUITE.hpke_kdf_algorithm(),
            openmls_traits::types::HpkeKdfType::HkdfSha384
        );
        assert_eq!(
            CIPHERSUITE.hpke_aead_algorithm(),
            openmls_traits::types::HpkeAeadType::ChaCha20Poly1305
        );
        assert_eq!(
            Ciphersuite::try_from(framing::CIPHER_SUITE),
            Ok(CIPHERSUITE)
        );
        assert_eq!(
            CIPHERSUITE.signature_algorithm(),
            openmls_traits::types::SignatureScheme::MLDSA44
        );
        assert_eq!(
            CIPHERSUITE.hash_algorithm(),
            openmls_traits::types::HashType::Sha2_384
        );
        assert_eq!(
            CIPHERSUITE.aead_algorithm(),
            openmls_traits::types::AeadType::ChaCha20Poly1305
        );
    }
}
