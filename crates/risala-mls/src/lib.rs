//! The MLS layer of risala (SPEC 12), shared by `risalad` and librisala.
//!
//! - [`crypto`]: the OpenMLS provider for cipher suite `0x0020` (12.2):
//!   libcrux, with ML-DSA-44 added, over any OpenMLS storage.
//! - [`signer`]: a device's [`DeviceSigner`] and credential (12.2). The
//!   device key stays with the caller, out of OpenMLS storage.
//! - [`conversation`]: the conversation extension `0xF2A1` (12.2).
//! - [`group`]: how risala sets up OpenMLS: capabilities, extensions,
//!   creating groups, KeyPackages, joining and commits (12.4-12.7).
//! - [`keypackage`]: the checks of KEYPKG ADD (12.4).
//! - [`wire`]: MLS values to and from the base64 values of
//!   `risala_proto::mls` (12.2).
//! - [`history`]: history keys (12.9).
//! - [`message`]: encrypted messages, the payload of ENC (12.8).
//! - [`backup`]: recovery keys, backup blobs and the recovery signing key
//!   (12.10).
//! - [`primitives`]: the labelled functions of [RFC9420] that risala uses
//!   outside MLS.
//!
//! The server's checks of commits (12.5) and librisala's group engine are
//! built on this crate, not in it.

pub mod archive;
pub mod backup;
pub mod conversation;
pub mod crypto;
pub mod file;
pub mod group;
pub mod history;
pub mod keypackage;
pub mod message;
pub mod pairing;
pub mod primitives;
pub mod signer;
pub mod wire;

pub use openmls;
pub use openmls_traits;

pub use archive::{
    ArchiveError, ArchivedConversation, ArchivedMessage, HistoryArchive, SealedArchive,
    TransferRef, seal_transfer,
};
pub use backup::{Backup, BackupError, BackupKey, RecoveryKey, RecoveryKeyError, WrappedKey};
pub use conversation::{ConversationError, ConversationKind, RisalaConversation};
pub use crypto::{Provider, RisalaCrypto, verify_ml_dsa_44};
pub use file::{BlobRef, BlobRefError, Decryptor, EncryptedFile, Encryptor, FileError, FileKey};
pub use group::{
    Changes, CommitError, CreateGroupError, ExternalJoinError, commit, create_group,
    join_by_external_commit, key_package, stage_welcome,
};
pub use history::HistoryKey;
pub use keypackage::{
    CheckedKeyPackage, KeyPackageError, check_key_package, encryption_key_ok, hpke_public_key_ok,
    lifetime_acceptable,
};
pub use message::{Encrypted, Message, MessageError, UnverifiedMessage, decrypt, encrypt};
pub use pairing::{IdentityBundle, PairingCode, PairingError, PairingSecret, Relay, RelayId};
pub use signer::{DeviceSigner, credential_with_key};
pub use wire::WireError;

use openmls::prelude::Ciphersuite;

/// The cipher suite of every encrypted conversation, `0x0020`: X-Wing,
/// ChaCha20-Poly1305, SHA-384 and ML-DSA-44 (12.2, 15). Its value is
/// `risala_proto::mls::CIPHER_SUITE`.
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
        assert_eq!(risala_proto::mls::CIPHER_SUITE, 0x0020);
        assert_eq!(u16::from(CIPHERSUITE), risala_proto::mls::CIPHER_SUITE);
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
            Ciphersuite::try_from(risala_proto::mls::CIPHER_SUITE),
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
