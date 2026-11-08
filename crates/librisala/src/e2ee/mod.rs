//! End-to-end encryption (SPEC 12) on the cache's transactions.
//!
//! - [`content`]: the lines inside an encrypted message (12.8).
//! - [`group`]: MLS operations on a conversation's group, each inside one
//!   write transaction of the store, with the checks of 12.6: KeyPackages
//!   (12.4), INIT and commits (12.5), joining by Welcome (12.7) or by
//!   external commit (12.6), and history keys (12.9).
//!
//! The sync engine ([`crate::sync`]) decides when to do what, and sends
//! the commands; everything here is synchronous and does no I/O.
//!
//! Rules from the spike (PLAN.md 22): a group is loaded with
//! `MlsGroup::load` inside every transaction and never kept across one,
//! since another process may share the cache; a Welcome is processed in a
//! transaction that rolls back if joining fails, so that its KeyPackage's
//! keys are kept for another try (12.7).

pub(crate) mod content;
pub(crate) mod group;

use std::sync::Arc;

use risala_mls::{DeviceSigner, Provider, RisalaCrypto};
use risala_proto::auth::SecretKey;
use risala_proto::names::Uid;

use crate::store::StoreError;
use crate::store::mls::MlsStorage;

/// This device, as it takes part in groups: its identity, its device key,
/// which is also its MLS signature key (12.2), and the crypto provider.
#[derive(Clone)]
pub(crate) struct Device {
    /// The identity, as a uid.
    pub uid: Uid,
    /// The device key.
    pub key: Arc<SecretKey>,
    /// Shared by every provider made for this device.
    pub crypto: Arc<RisalaCrypto>,
}

impl std::fmt::Debug for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Device")
            .field("uid", &self.uid)
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

impl Device {
    /// A device of `uid` with `key`. Fails only if the crypto provider
    /// cannot start.
    pub(crate) fn new(uid: Uid, key: Arc<SecretKey>) -> Result<Device, E2eeError> {
        let crypto = RisalaCrypto::new().map_err(|e| E2eeError::Mls(e.to_string()))?;
        Ok(Device {
            uid,
            key,
            crypto: Arc::new(crypto),
        })
    }

    /// The signer for OpenMLS and for messages.
    pub(crate) fn signer(&self) -> DeviceSigner<'_> {
        DeviceSigner::new(&self.key)
    }

    /// A provider on `storage`, usually [`Tx::mls_storage`](crate::store::Tx).
    pub(crate) fn provider<'a>(&self, storage: MlsStorage<'a>) -> Provider<MlsStorage<'a>> {
        Provider::with_crypto(self.crypto.clone(), storage)
    }
}

/// Why an encryption step did not happen. Nothing it did is kept: the
/// write transaction it ran in rolls back.
#[derive(Debug, thiserror::Error)]
pub(crate) enum E2eeError {
    /// The cache failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// MLS refused something, such as a commit whose secrets do not
    /// decrypt (12.6). For a commit, the device may join again by external
    /// commit.
    #[error("MLS: {0}")]
    Mls(String),
    /// A commit or a group fails a check of 12.6. The device must not
    /// follow it, nor join the group again.
    #[error("rejected: {0}")]
    Rejected(&'static str),
    /// The check needs these identities' key files, which are not known
    /// yet: fetch them and try again (12.6).
    #[error("waiting for key files")]
    KeyFiles(Vec<Uid>),
    /// The value from the server is not what it should be.
    #[error("malformed: {0}")]
    Malformed(String),
}

/// An MLS error as an [`E2eeError`].
pub(crate) fn mls(e: impl std::fmt::Display) -> E2eeError {
    E2eeError::Mls(e.to_string())
}
