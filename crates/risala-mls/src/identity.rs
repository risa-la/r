//! Leaf credentials (12.3): a `basic` credential whose identity is an
//! encoded RisalaIdentity.
//!
//! ```text
//! struct {
//!     uint8 version;          // 1
//!     opaque uid<V>;          // in lower case
//!     opaque device_id<V>;    // the device id (4.4), 48 bytes; empty for a guest
//! } RisalaIdentity;
//! ```

use openmls::prelude::{BasicCredential, Credential, CredentialType, CredentialWithKey};
use risala_proto::auth::{PUBLIC_KEY_LEN, PublicKey};
use risala_proto::names::Uid;
pub use risala_proto::record::DeviceId;

use crate::codec::{DecodeError, Reader, Writer};
use crate::primitives::HASH_LEN;

/// The device id (4.4) of the raw device key `device_key`, or `None` if it
/// is not an ML-DSA-44 public key.
pub fn device_id_of(device_key: &[u8]) -> Option<DeviceId> {
    let key: &[u8; PUBLIC_KEY_LEN] = device_key.try_into().ok()?;
    Some(DeviceId::of(&PublicKey::from_bytes(key)))
}

/// Who a leaf belongs to (12.3): a uid and, unless it is a guest, the
/// device id of one of its devices.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RisalaIdentity {
    /// The uid.
    pub uid: Uid,
    /// The device, or `None` for a guest.
    pub device_id: Option<DeviceId>,
}

/// Why a credential is not a RisalaIdentity (12.3).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    /// It is not a `basic` credential.
    #[error("the credential is not a basic credential")]
    NotBasic,
    /// It is not one well-formed RisalaIdentity of version 1.
    #[error(transparent)]
    Malformed(#[from] DecodeError),
}

impl RisalaIdentity {
    /// The identity of a device of `uid`. `uid` must not be a guest.
    pub fn device(uid: Uid, device_id: DeviceId) -> RisalaIdentity {
        debug_assert!(uid.is_identity());
        RisalaIdentity {
            uid,
            device_id: Some(device_id),
        }
    }

    /// The identity of a guest (4.2), with no device id. `uid` must be a
    /// guest uid.
    pub fn guest(uid: Uid) -> RisalaIdentity {
        debug_assert!(uid.is_guest());
        RisalaIdentity {
            uid,
            device_id: None,
        }
    }

    /// Whether this is a guest's leaf.
    pub fn is_guest(&self) -> bool {
        self.device_id.is_none()
    }

    /// The encoded RisalaIdentity.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(1).vector(self.uid.as_str().as_bytes());
        match &self.device_id {
            Some(id) => w.vector(id.as_bytes()),
            None => w.vector(b""),
        };
        w.into_bytes()
    }

    /// Reads an encoded RisalaIdentity. The uid must be a valid uid already
    /// in lower case; a guest uid must have an empty device id, and any
    /// other uid a 48-byte one.
    pub fn decode(bytes: &[u8]) -> Result<RisalaIdentity, DecodeError> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 1 {
            return Err(DecodeError("unknown RisalaIdentity version"));
        }
        let uid = r.vector()?;
        let device_id = r.vector()?;
        r.finish()?;
        let uid = std::str::from_utf8(uid).map_err(|_| DecodeError("uid is not UTF-8"))?;
        let parsed: Uid = uid.parse().map_err(|_| DecodeError("not a uid"))?;
        if parsed.as_str() != uid {
            return Err(DecodeError("uid not in lower case"));
        }
        let device_id = match (parsed.is_guest(), device_id.len()) {
            (true, 0) => None,
            (false, HASH_LEN) => Some(DeviceId::from_bytes(
                device_id.try_into().expect("48 bytes"),
            )),
            _ => return Err(DecodeError("device id does not fit the uid")),
        };
        Ok(RisalaIdentity {
            uid: parsed,
            device_id,
        })
    }

    /// The `basic` credential holding this identity.
    pub fn to_credential(&self) -> Credential {
        BasicCredential::new(self.encode()).into()
    }

    /// The credential and signature key of a leaf with this identity and
    /// the leaf key whose raw public key is `leaf_key`.
    pub fn credential_with_key(&self, leaf_key: &[u8]) -> CredentialWithKey {
        CredentialWithKey {
            credential: self.to_credential(),
            signature_key: leaf_key.to_vec().into(),
        }
    }

    /// Reads a leaf's credential.
    pub fn from_credential(credential: &Credential) -> Result<RisalaIdentity, IdentityError> {
        if credential.credential_type() != CredentialType::Basic {
            return Err(IdentityError::NotBasic);
        }
        let basic =
            BasicCredential::try_from(credential.clone()).map_err(|_| IdentityError::NotBasic)?;
        Ok(RisalaIdentity::decode(basic.identity())?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uid(s: &str) -> Uid {
        s.parse().unwrap()
    }

    #[test]
    fn encoding() {
        let device = DeviceId::from_bytes([7; 48]);
        let id = RisalaIdentity::device(uid("alice@example.org"), device);
        let mut expected = b"\x01\x11alice@example.org\x30".to_vec();
        expected.extend_from_slice(&[7; 48]);
        assert_eq!(id.encode(), expected);
        assert_eq!(RisalaIdentity::decode(&expected), Ok(id.clone()));
        assert!(!id.is_guest());

        let guest = RisalaIdentity::guest(uid("~sam"));
        assert_eq!(guest.encode(), b"\x01\x04~sam\x00");
        assert_eq!(
            RisalaIdentity::decode(b"\x01\x04~sam\x00"),
            Ok(guest.clone())
        );
        assert!(guest.is_guest());

        let credential = id.to_credential();
        assert_eq!(RisalaIdentity::from_credential(&credential), Ok(id));
    }

    #[test]
    fn malformed() {
        let mut long = b"\x01\x11alice@example.org\x30".to_vec();
        long.extend_from_slice(&[7; 48]);
        let mut bad_version = long.clone();
        bad_version[0] = 2;
        let mut trailing = long.clone();
        trailing.push(0);
        let mut upper = long.clone();
        upper[2] = b'A';
        let mut short_id = b"\x01\x11alice@example.org\x2f".to_vec();
        short_id.extend_from_slice(&[7; 47]);
        for bad in [
            bad_version,
            trailing,
            upper,
            short_id,
            // An identity without a device id, and a guest with one.
            b"\x01\x11alice@example.org\x00".to_vec(),
            [b"\x01\x04~sam\x30".as_slice(), &[7; 48]].concat(),
            b"\x01\x05alice\x00".to_vec(),
            b"\x01\x02\xff\xfe\x00".to_vec(),
            b"".to_vec(),
        ] {
            assert!(RisalaIdentity::decode(&bad).is_err(), "{bad:?}");
        }
        let other: Credential = BasicCredential::new(b"alice@example.org".to_vec()).into();
        assert!(matches!(
            RisalaIdentity::from_credential(&other),
            Err(IdentityError::Malformed(_))
        ));
    }

    #[test]
    fn device_ids() {
        let key = [7; PUBLIC_KEY_LEN];
        let id = device_id_of(&key).unwrap();
        assert_eq!(id.as_bytes(), &crate::primitives::sha384(&key));
        assert_eq!(id, DeviceId::of(&PublicKey::from_bytes(&key)));
        assert!(format!("{id:?}").starts_with("DeviceId("));
        assert_eq!(device_id_of(&key[1..]), None);
    }
}
