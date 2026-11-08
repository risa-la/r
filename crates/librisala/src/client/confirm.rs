//! Which leaves are confirmed (12.10): a message shows as verified only if
//! its sender's leaf is confirmed (12.9), and what leaf confirmation warns
//! the user about (12.7).
//!
//! Owned by task C3. The work is done by [`crate::sync::confirm`], from
//! the group engine's hooks and on the driver's ticks; this is what the
//! UI reads, and the keys the client hands it.

use std::sync::Arc;

use risala_mls::confirm::AttestationKey;
use risala_mls::mldsa::SigningKey;

use super::types::{ConversationId, DeviceId, Uid};
use super::{Client, Result};
use crate::keys::{KeyStore, key_seed};
use crate::store::Tx;
use crate::store::confirm::LeafConfirmation;
use crate::sync::confirm::{Confirm, DevicesTable, OwnKeys};

/// Whether a member's leaf is confirmed (12.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafStatus {
    /// The leaf index.
    pub leaf: u32,
    /// The member.
    pub uid: Uid,
    /// Its device, if it is not a guest.
    pub device: Option<DeviceId>,
    /// Whether its leaf is confirmed, pairwise or by a period key.
    pub confirmed: bool,
    /// Whether it is an impostor to this device: it answered wrongly, or
    /// not in time (12.7). Its messages and actions show as unconfirmed.
    pub impostor: bool,
}

/// What leaf confirmation found (12.7, 12.9, 12.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfirmKind {
    /// The leaf is confirmed, and so are its earlier messages with the same
    /// key.
    Confirmed,
    /// The leaf attested for the period (epochal groups).
    Attested {
        /// The period: a UTC day, numbered from 1970-01-01.
        period: u32,
    },
    /// The leaf is an impostor: warn the user. Unless another device does
    /// first, this device removes it after a random wait of up to 10
    /// minutes, where it may (12.7).
    Impostor {
        /// `wrong-answer`, `no-answer` or `no-attestation`.
        reason: String,
    },
    /// In the conversation with yourself, the leaf has not answered within
    /// 24 hours: tell the user, who may remove it (12.9).
    Unanswered,
    /// An ATTEST from the leaf was not valid, or came too late.
    InvalidAttestation {
        /// Why.
        reason: String,
    },
    /// The leaf's REVEAL does not derive the period key it attested with:
    /// it does not give the deniability the group expects (12.10).
    BadReveal {
        /// The period.
        period: u32,
    },
    /// The leaf has not revealed a period key it attested with, well after
    /// it was due (12.10).
    RevealMissing {
        /// The period.
        period: u32,
    },
    /// The leaf's credential names a device that is not a current device
    /// of its identity, so it cannot be confirmed.
    DeviceNotCurrent,
    /// The leaf's device has an attestation key that fails the X-Wing key
    /// check (12.2), so it cannot be challenged.
    BadAttestationKey,
}

impl ConfirmKind {
    /// The warning to keep for the user, as a kind and detail, if this is
    /// one.
    pub(crate) fn warning(&self) -> Option<(&'static str, String)> {
        match self {
            ConfirmKind::Confirmed | ConfirmKind::Attested { .. } => None,
            ConfirmKind::Impostor { reason } => Some(("impostor", reason.clone())),
            ConfirmKind::Unanswered => Some(("unanswered", String::new())),
            ConfirmKind::InvalidAttestation { reason } => Some(("invalid-attest", reason.clone())),
            ConfirmKind::BadReveal { period } => Some(("bad-reveal", period.to_string())),
            ConfirmKind::RevealMissing { period } => Some(("reveal-missing", period.to_string())),
            ConfirmKind::DeviceNotCurrent => Some(("device-not-current", String::new())),
            ConfirmKind::BadAttestationKey => Some(("bad-attestation-key", String::new())),
        }
    }
}

/// An event of leaf confirmation, for the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmEvent {
    /// The conversation.
    pub conversation: ConversationId,
    /// The leaf.
    pub leaf: u32,
    /// Its identity or guest uid.
    pub uid: Uid,
    /// What happened.
    pub kind: ConfirmKind,
}

/// A warning about a leaf, kept for the user (12.7, 12.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmWarning {
    /// The leaf.
    pub leaf: u32,
    /// Its uid.
    pub uid: String,
    /// What: `impostor`, `unanswered`, `invalid-attest`, `bad-reveal`,
    /// `reveal-missing`, `device-not-current` or `bad-attestation-key`.
    pub kind: String,
    /// The impostor's reason, the attestation's error, or the period.
    pub detail: String,
    /// When, in ms since 1970.
    pub at: u64,
}

/// This device's keys for leaf confirmation, from the platform key store:
/// the device key under the identity's `key_id`, and the attestation key
/// under `<key_id>.attest`, as the identity area (task C1) names them.
pub(crate) struct ClientKeys {
    keys: Arc<dyn KeyStore>,
}

impl ClientKeys {
    fn key_id(tx: &Tx<'_>, uid: &Uid) -> Option<String> {
        use rusqlite::OptionalExtension as _;
        tx.conn()
            .query_row(
                "SELECT key_id FROM identities WHERE uid = ?1",
                [uid.as_str()],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten()
    }
}

impl OwnKeys for ClientKeys {
    fn device_key(&self, tx: &Tx<'_>, uid: &Uid) -> Option<SigningKey> {
        let key = self.keys.load(&Self::key_id(tx, uid)?).ok()??;
        Some(SigningKey::from_seed(*key_seed(&key)))
    }

    fn attestation_key(&self, tx: &Tx<'_>, uid: &Uid) -> Option<AttestationKey> {
        let id = format!("{}.attest", Self::key_id(tx, uid)?);
        let key = self.keys.load(&id).ok()??;
        Some(AttestationKey::from_seed(key_seed(&key)))
    }
}

impl Client {
    /// Leaf confirmation with this client's keys and clock.
    pub(crate) fn confirm_service(&self) -> Arc<Confirm> {
        Arc::new(Confirm::new(
            Arc::new(ClientKeys {
                keys: self.options().keys.clone(),
            }),
            Arc::new(DevicesTable),
            self.options().clock.clone(),
        ))
    }

    /// The leaves of a conversation, and whether each is confirmed.
    pub fn leaf_status(&self, conversation: ConversationId) -> Result<Vec<LeafStatus>> {
        let now = self.options().clock.now().unix_millis();
        let states = self.store().leaf_confirmation_rows(conversation)?;
        let leaves = self.store().leaf_rows(conversation)?;
        Ok(leaves
            .into_iter()
            .map(|leaf| {
                let state = states
                    .iter()
                    .find(|s| s.leaf == leaf.leaf && s.signature_key == leaf.signature_key);
                LeafStatus {
                    leaf: leaf.leaf,
                    uid: leaf.uid,
                    device: leaf.device_id.map(DeviceId),
                    confirmed: state.is_some_and(|s| s.confirmed_at(now)),
                    impostor: state.is_some_and(|s| s.state == LeafConfirmation::Impostor),
                }
            })
            .collect())
    }

    /// What leaf confirmation warned about in a conversation, oldest
    /// first.
    pub fn confirm_warnings(&self, conversation: ConversationId) -> Result<Vec<ConfirmWarning>> {
        Ok(self
            .store()
            .confirm_warning_rows(conversation)?
            .into_iter()
            .map(|w| ConfirmWarning {
                leaf: w.leaf,
                uid: w.uid,
                kind: w.kind,
                detail: w.detail,
                at: w.at,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests;
