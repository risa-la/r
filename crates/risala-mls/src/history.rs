//! History keys (12.9).
//!
//! For each epoch of each group it is in, a device derives the epoch's
//! history key from the MLS exporter:
//!
//! ```text
//! history_key = MLS-Exporter("risala history", "", 48)
//! ```
//!
//! MLS keeps only the current epoch's exporter secret, so a device derives
//! an epoch's key before it applies the commit that ends the epoch: from
//! the group, from a staged commit (the next epoch) or from a staged
//! Welcome (the epoch it joins in).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use openmls::group::{ExportSecretError, MlsGroup, StagedCommit, StagedWelcome};
use openmls_traits::crypto::OpenMlsCrypto;
use risala_proto::mls::{HISTORY_KEY_LABEL, HISTORY_KEY_LEN};
use zeroize::Zeroizing;

use crate::primitives::{AEAD_KEY_LEN, expand_with_label, mls_exporter};

/// The ExpandWithLabel label of message keys (12.8).
use risala_proto::mls::MESSAGE_KEY_LABEL;

/// An epoch's history key (12.9): 48 bytes, wiped when dropped. `Debug`
/// does not show it.
#[derive(Clone)]
pub struct HistoryKey(Box<Zeroizing<[u8; HISTORY_KEY_LEN]>>);

impl HistoryKey {
    /// A key from its bytes, for example from storage.
    pub fn from_bytes(bytes: [u8; HISTORY_KEY_LEN]) -> HistoryKey {
        HistoryKey(Box::new(Zeroizing::new(bytes)))
    }

    /// The key's bytes.
    pub fn as_bytes(&self) -> &[u8; HISTORY_KEY_LEN] {
        &self.0
    }

    /// The current epoch's key of a group this device is in.
    pub fn of_group(
        group: &MlsGroup,
        crypto: &impl OpenMlsCrypto,
    ) -> Result<HistoryKey, ExportSecretError> {
        HistoryKey::from_export(group.export_secret(
            crypto,
            HISTORY_KEY_LABEL,
            b"",
            HISTORY_KEY_LEN,
        ))
    }

    /// The key of the epoch a staged commit starts, before it is merged.
    /// Fails if the commit removes this device.
    pub fn of_staged_commit(
        commit: &StagedCommit,
        crypto: &impl OpenMlsCrypto,
    ) -> Result<HistoryKey, ExportSecretError> {
        HistoryKey::from_export(commit.export_secret(
            crypto,
            HISTORY_KEY_LABEL,
            b"",
            HISTORY_KEY_LEN,
        ))
    }

    /// The key of the epoch a staged Welcome joins.
    pub fn of_staged_welcome(
        welcome: &StagedWelcome,
        crypto: &impl OpenMlsCrypto,
    ) -> Result<HistoryKey, ExportSecretError> {
        HistoryKey::from_export(welcome.export_secret(
            crypto,
            HISTORY_KEY_LABEL,
            b"",
            HISTORY_KEY_LEN,
        ))
    }

    fn from_export(
        exported: Result<Vec<u8>, ExportSecretError>,
    ) -> Result<HistoryKey, ExportSecretError> {
        let exported = Zeroizing::new(exported?);
        let bytes: [u8; HISTORY_KEY_LEN] = exported[..]
            .try_into()
            .expect("the exporter gives the length asked for");
        Ok(HistoryKey::from_bytes(bytes))
    }

    /// The key from an epoch's exporter secret, as 12.9 writes it out:
    /// ExpandWithLabel(DeriveSecret(exporter_secret, "risala history"),
    /// "exported", SHA-384(""), 48). Appendix B's vector starts here.
    pub fn from_exporter_secret(exporter_secret: &[u8]) -> HistoryKey {
        let mut out = [0; HISTORY_KEY_LEN];
        mls_exporter(exporter_secret, HISTORY_KEY_LABEL.as_bytes(), b"", &mut out);
        let key = HistoryKey::from_bytes(out);
        zeroize::Zeroize::zeroize(&mut out);
        key
    }

    /// The key as on a KEY line, in base64 with padding (12.9). Wiped when
    /// dropped.
    pub fn to_base64(&self) -> Zeroizing<String> {
        Zeroizing::new(BASE64.encode(&self.0[..]))
    }

    /// Reads a key from a KEY line (12.9): exactly 48 bytes in strict
    /// base64 with padding.
    pub fn from_base64(text: &str) -> Option<HistoryKey> {
        let mut out = Zeroizing::new([0; HISTORY_KEY_LEN]);
        if text.len() != 64 || !risala_proto::mls::is_strict_base64(text) {
            return None;
        }
        match BASE64.decode_slice(text, &mut out[..]) {
            Ok(HISTORY_KEY_LEN) => Some(HistoryKey::from_bytes(*out)),
            _ => None,
        }
    }

    /// The message key for `salt` (12.8, step 6): ExpandWithLabel(history
    /// key, "risala message key", salt, 32).
    pub(crate) fn message_key(&self, salt: &[u8]) -> Zeroizing<[u8; AEAD_KEY_LEN]> {
        let mut key = Zeroizing::new([0; AEAD_KEY_LEN]);
        expand_with_label(
            &self.0[..],
            MESSAGE_KEY_LABEL.as_bytes(),
            salt,
            &mut key[..],
        );
        key
    }
}

/// Constant-time, since the key is secret.
impl PartialEq for HistoryKey {
    fn eq(&self, other: &HistoryKey) -> bool {
        crate::primitives::ct_eq(&self.0[..], &other.0[..])
    }
}

impl Eq for HistoryKey {}

impl std::fmt::Debug for HistoryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HistoryKey(…)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::derive_secret;
    use crate::primitives::tests::hex;

    /// Appendix B: the history key from the exporter secret, and the
    /// DeriveSecret step on the way.
    #[test]
    fn appendix_b_history_key() {
        let exporter_secret: Vec<u8> = (0..48).collect();
        assert_eq!(
            hex(&derive_secret(&exporter_secret, b"risala history")[..]),
            "0d81c7a79130adc8f81c42aaf57395c52332450d604544f5e34436e7c81fc423\
             0fcb06c5154c001efa43ff711e597b43"
        );
        let key = HistoryKey::from_exporter_secret(&exporter_secret);
        assert_eq!(
            hex(key.as_bytes()),
            "a7187b710141caab8322e9f1cc1664a78d63821d360ce6ece27bec3b03e886d5\
             a87d17f40b15c365a59b238b80e568d0"
        );

        // Appendix B, step 6: the message key for the vector's salt.
        let salt: Vec<u8> = (0xc0..=0xdf).collect();
        assert_eq!(
            hex(&key.message_key(&salt)[..]),
            "34820bd2a459f65486d86ed9f9fcf984d9c8069bd2dc088affe4af93f5202e11"
        );
    }

    #[test]
    fn base64_round_trip() {
        let key = HistoryKey::from_bytes([9; 48]);
        let text = key.to_base64();
        assert_eq!(text.len(), 64);
        assert_eq!(HistoryKey::from_base64(&text), Some(key));
        assert_eq!(HistoryKey::from_base64(&text[..60]), None);
        assert_eq!(HistoryKey::from_base64(&format!("{}AAAA", &*text)), None);
        assert_eq!(
            format!("{:?}", HistoryKey::from_bytes([9; 48])),
            "HistoryKey(…)"
        );
    }
}
