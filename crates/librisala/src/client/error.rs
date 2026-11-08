//! The client's errors.

use crate::conn;
use crate::keys::KeyStoreError;
use crate::store::StoreError;

/// The client's result.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Anything the client API can fail with.
///
/// Each area has a variant for its own errors, an enum in the area's
/// module, so that area tasks add errors without touching this file.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The operation is part of M5b's API, but its area task has not
    /// built it yet. Holds the method's name.
    #[error("not implemented yet: {0}")]
    NotImplemented(&'static str),
    /// A value given was not valid, such as a server address or a uid.
    #[error("invalid {what}: {value:?}")]
    Invalid {
        /// What it should have been.
        what: &'static str,
        /// What was given.
        value: String,
    },
    /// There is no such account.
    #[error("no such account")]
    NoAccount,
    /// The cache failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The key store failed.
    #[error(transparent)]
    Keys(#[from] KeyStoreError),
    /// A connection failed, or the server refused a command.
    #[error(transparent)]
    Connection(#[from] conn::Error),
    /// Identities, devices and key logs (task C1).
    #[error(transparent)]
    Identity(#[from] super::identity::IdentityError),
    /// Conversations and messages (task C2).
    #[error(transparent)]
    Conversation(#[from] super::conversations::ConversationError),
    /// Files, transfers, backups, push and reports (task C4).
    #[error(transparent)]
    Transfer(#[from] super::files::TransferError),
    /// A bug, or something the platform did that should not happen.
    #[error("internal error: {0}")]
    Internal(String),
}

impl From<crate::addr::TrustStoreError> for Error {
    fn from(e: crate::addr::TrustStoreError) -> Error {
        Error::Connection(e.into())
    }
}

impl Error {
    /// [`Error::Invalid`].
    pub(crate) fn invalid(what: &'static str, value: impl Into<String>) -> Error {
        Error::Invalid {
            what,
            value: value.into(),
        }
    }
}
