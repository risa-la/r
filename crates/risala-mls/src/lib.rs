//! The MLS layer of risala (SPEC 12), shared by `risalad` and librisala.
//!
//! - [`crypto`]: the OpenMLS provider for cipher suite `0x0052` (12.2):
//!   libcrux, with ML-DSA-44 added, over any OpenMLS storage.
//! - [`signer`]: a device's [`DeviceSigner`] and credential (12.2). The
//!   device key stays with the caller, out of OpenMLS storage.
//! - [`history`]: history keys (12.9).
//! - [`message`]: encrypted messages, the payload of ENC (12.8).
//! - [`primitives`]: the labelled functions of [RFC9420] that risala uses
//!   outside MLS.
//!
//! The server's checks of commits (12.5) and librisala's group engine are
//! built on this crate, not in it.

pub mod crypto;
pub mod history;
pub mod message;
pub mod primitives;
pub mod signer;

pub use openmls;
pub use openmls_traits;

pub use crypto::{Provider, RisalaCrypto, verify_ml_dsa_44};
pub use history::HistoryKey;
pub use message::{Encrypted, Message, MessageError, UnverifiedMessage, decrypt, encrypt};
pub use signer::{DeviceSigner, credential_with_key};

use openmls::prelude::Ciphersuite;

/// The cipher suite of every encrypted conversation, `0x0052`: X-Wing,
/// ChaCha20-Poly1305, SHA-384 and ML-DSA-44 (12.2, 15). Its value is
/// `risala_proto::mls::CIPHER_SUITE`.
pub const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44;

#[cfg(test)]
mod suite_tests {
    use super::*;

    #[test]
    fn suite_value() {
        assert_eq!(u16::from(CIPHERSUITE), risala_proto::mls::CIPHER_SUITE);
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
