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
//! - [`mldsa`]: ML-DSA-44 keys, leaf keys (12.3), and RisalaSign (4.3) over
//!   `risala-proto`'s RisalaSignContent.
//! - [`primitives`]: SHA-384, HKDF, HMAC, ChaCha20-Poly1305 and MLS's
//!   labelled functions, for use outside MLS.
//!
//! Groups:
//!
//! - [`keypackage`]: making KeyPackages, and the checks of KEYPKG ADD
//!   (12.5).
//! - [`group`]: creating groups, joining by Welcome and by a public room's
//!   join proposal, commits, Update proposals, SelfRemove, resync commits
//!   and rejoins, mailbox moves, derived pseudonyms and boxes, past epochs,
//!   and processing posts (12.6-12.9, 6.1, 7.3, 7.8).
//! - [`checks`]: the checks of joining, and the group and key checks of
//!   every commit, which depend only on the group's state in the epoch
//!   ([`EpochState`]), the commit and its posts
//!   (12.7).
//! - [`welcome`]: one sealed Welcome per added device (12.8).
//! - [`message`]: RisalaMessage, franking, counters, late messages and
//!   reports (12.9, 5.4, 5.8).
//! - [`confirm`]: confirming leaves, pairwise by CHALLENGE and ANSWER,
//!   and the state machine for both ways (12.10).
//! - [`epochal`]: period keys, ATTEST and REVEAL (12.10). The construction
//!   still needs an outside review (PLAN.md item 53).
//!
//! OpenMLS is patched (`crates/openmls-traits/RISALA.md`,
//! `crates/openmls/RISALA.md`): the suite's value is `0x0020`, SelfRemove
//! is framed with the group's wire format, KeyPackage lifetimes are left to
//! risala's checks, resync commits remove other leaves, join proposals
//! carry a RisalaAAD, and a GroupInfo's signer is readable.

pub mod aad;
pub mod archive;
pub mod backup;
pub mod binding;
pub mod checks;
pub mod codec;
pub mod confirm;
pub mod conversation;
pub mod crypto;
pub mod epochal;
pub mod file;
pub mod framing;
pub mod group;
pub mod identity;
pub mod keypackage;
pub mod message;
pub mod mldsa;
pub mod pairing;
pub mod primitives;
pub mod profile;
mod seeded;
pub mod token;
pub mod welcome;
pub mod wire;

pub use openmls;
pub use openmls_traits;

pub use aad::{EpochPseudonyms, Pseudonym, RisalaAad};
pub use archive::{
    ArchiveError, ArchivedConversation, ArchivedFile, ArchivedMessage, HistoryArchive,
    OpenedTransfer, SealedArchive, TransferRef, open_transfer, seal_transfer,
};
pub use backup::{
    Backup, BackupError, BackupKey, BackupUpload, RecoveryKey, RecoveryKeyError, WrappedKey,
};
pub use binding::DeviceBinding;
pub use checks::{CommitPost, EpochState};
pub use confirm::{AttestationKey, Confirmer, LeafState};
pub use conversation::{ConversationKind, RisalaConversation};
pub use crypto::{Provider, RisalaCrypto};
pub use file::{
    BlobRef, BlobRefError, Decryptor, EncryptedFile, Encryptor, FileError, FileKey, Label,
};
pub use identity::{DeviceId, RisalaIdentity};
pub use message::{
    Decrypted, FrankKey, MemoryHistory, MessageHistory, RisalaMessage, RisalaReport, SendCounter,
};
pub use mldsa::{LeafKey, SigningKey};
pub use pairing::{
    IdentityBundle, NewDevice, NewDeviceContent, PairingCode, PairingError, PairingKey,
    PairingSecret, Relay, RelayId, SealedBundle,
};
pub use profile::RisalaProfile;
pub use token::SendToken;

use openmls::prelude::Ciphersuite;

/// The cipher suite of every conversation, `0x0020`: X-Wing,
/// ChaCha20-Poly1305, SHA-384 and ML-DSA-44 (12.2, 15).
pub const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44;

#[cfg(test)]
mod tests;

/// Appendix B's vectors, read from the spec. The module is shared with
/// risala-proto's tests, which check sections B.1 to B.10; the tests of
/// this crate's modules check B.11 to B.19.
#[cfg(test)]
#[path = "../../risala-proto/tests/common/appendix.rs"]
pub(crate) mod appendix;

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
