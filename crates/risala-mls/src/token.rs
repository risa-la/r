//! Send tokens (7.2): what proves to the server that a post comes from a
//! member of its epoch, without saying which.
//!
//! ```text
//! send_token = MLS-Exporter("risala/1 send", "", 32)
//! ```
//!
//! It is a bearer secret: the server keeps only its SHA-384 hash, and
//! compares hashes in constant time.

use openmls::group::{MlsGroup, StagedCommit};
use openmls::prelude::ExportSecretError;
use openmls_traits::crypto::OpenMlsCrypto;
use zeroize::Zeroizing;

use crate::primitives::{HASH_LEN, ct_eq, sha384};

/// The MLS exporter label of send tokens (7.2, 15).
pub const SEND_TOKEN_LABEL: &str = "risala/1 send";

/// The length of a send token (7.2).
pub const SEND_TOKEN_LEN: usize = 32;

/// An epoch's send token (7.2), a bearer secret. `Debug` does not show it,
/// and `==` compares in constant time.
#[derive(Clone)]
pub struct SendToken(Zeroizing<[u8; SEND_TOKEN_LEN]>);

impl PartialEq for SendToken {
    /// Constant time.
    fn eq(&self, other: &SendToken) -> bool {
        ct_eq(&self.0[..], &other.0[..])
    }
}

impl Eq for SendToken {}

impl std::fmt::Debug for SendToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SendToken(…)")
    }
}

fn from_exported(bytes: Vec<u8>) -> SendToken {
    let bytes = Zeroizing::new(bytes);
    let mut token = Zeroizing::new([0; SEND_TOKEN_LEN]);
    token.copy_from_slice(&bytes);
    SendToken(token)
}

impl SendToken {
    /// The send token of `group`'s current epoch.
    pub fn of_group(
        group: &MlsGroup,
        crypto: &impl OpenMlsCrypto,
    ) -> Result<SendToken, ExportSecretError> {
        group
            .export_secret(crypto, SEND_TOKEN_LABEL, b"", SEND_TOKEN_LEN)
            .map(from_exported)
    }

    /// The send token of the epoch that `staged` creates, to check a
    /// commit's next token hash before applying it (7.2, 12.7).
    pub fn of_staged_commit(
        staged: &StagedCommit,
        crypto: &impl OpenMlsCrypto,
    ) -> Result<SendToken, ExportSecretError> {
        staged
            .export_secret(crypto, SEND_TOKEN_LABEL, b"", SEND_TOKEN_LEN)
            .map(from_exported)
    }

    /// A token as a command carries it, decoded from base64.
    pub fn from_bytes(bytes: [u8; SEND_TOKEN_LEN]) -> SendToken {
        SendToken(Zeroizing::new(bytes))
    }

    /// The token's bytes, for a command (in base64 with padding).
    pub fn as_bytes(&self) -> &[u8; SEND_TOKEN_LEN] {
        &self.0
    }

    /// The SHA-384 hash the server keeps (7.2).
    pub fn hash(&self) -> [u8; HASH_LEN] {
        sha384(&self.0[..])
    }
}

/// Whether two token hashes are equal, compared in constant time (7.2).
pub fn token_hashes_equal(a: &[u8; HASH_LEN], b: &[u8; HASH_LEN]) -> bool {
    ct_eq(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes() {
        let token = SendToken::from_bytes([7; 32]);
        assert_eq!(token.hash(), sha384(&[7; 32]));
        assert!(token_hashes_equal(&token.hash(), &sha384(&[7; 32])));
        assert!(!token_hashes_equal(&token.hash(), &sha384(&[8; 32])));
        assert_eq!(format!("{token:?}"), "SendToken(…)");
    }
}
