//! Device bindings, the extension `0xF2A2` (12.3, 15).
//!
//! ```text
//! struct {
//!     uint8 version;               // 1
//!     opaque device_id[48];
//!     opaque signature<V>;
//! } DeviceBinding;
//!
//! struct {
//!     opaque uid<V>;
//!     opaque init_key<V>;          // empty in a leaf node
//!     opaque encryption_key<V>;    // the leaf's HPKE key
//! } DeviceBindingContent;
//! ```
//!
//! `signature` is RisalaSign(device key, "keypackage",
//! DeviceBindingContent) (4.3). A KeyPackage carries it among its own
//! extensions, covering its init key; the leaf node of an external commit
//! carries it among the leaf's extensions, with an empty init key.

use openmls::prelude::{Extension, ExtensionType, Extensions, UnknownExtension};
use risala_proto::names::Uid;

use crate::codec::{DecodeError, Reader, Writer};
use crate::identity::DeviceId;
use crate::mldsa::SigningKey;
use crate::primitives::HASH_LEN;
use crate::risala_sign::{KEYPACKAGE_LABEL, risala_sign, risala_verify};

/// The extension type of device bindings (12.3, 15).
pub const DEVICE_BINDING_EXTENSION_TYPE: u16 = 0xF2A2;

/// The device binding's type, as OpenMLS names it.
pub const DEVICE_BINDING_EXTENSION: ExtensionType =
    ExtensionType::Unknown(DEVICE_BINDING_EXTENSION_TYPE);

/// A device binding (12.3).
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceBinding {
    /// The device whose key signed it.
    pub device_id: DeviceId,
    /// RisalaSign(device key, "keypackage", DeviceBindingContent).
    pub signature: Vec<u8>,
}

impl std::fmt::Debug for DeviceBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceBinding")
            .field("device_id", &self.device_id)
            .finish_non_exhaustive()
    }
}

/// The encoded DeviceBindingContent.
fn content(uid: &Uid, init_key: &[u8], encryption_key: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.vector(uid.as_str().as_bytes())
        .vector(init_key)
        .vector(encryption_key);
    w.into_bytes()
}

impl DeviceBinding {
    /// Binds `init_key` and `encryption_key` to the device whose key is
    /// `device_key`, for `uid` (12.3). `init_key` is empty for a leaf node.
    pub fn sign(
        device_key: &SigningKey,
        uid: &Uid,
        init_key: &[u8],
        encryption_key: &[u8],
    ) -> DeviceBinding {
        let signature = risala_sign(
            device_key,
            KEYPACKAGE_LABEL,
            &content(uid, init_key, encryption_key),
        );
        DeviceBinding {
            device_id: DeviceId::of_device_key(device_key.public_key()),
            signature: signature.to_vec(),
        }
    }

    /// Whether this binds `init_key` and `encryption_key` to `uid`'s
    /// device whose raw device key is `device_key`: the device id is that
    /// key's, and the signature verifies under it (12.3, 12.5, 12.7).
    pub fn verify(
        &self,
        device_key: &[u8],
        uid: &Uid,
        init_key: &[u8],
        encryption_key: &[u8],
    ) -> bool {
        DeviceId::of_device_key(device_key) == self.device_id
            && risala_verify(
                device_key,
                KEYPACKAGE_LABEL,
                &content(uid, init_key, encryption_key),
                &self.signature,
            )
    }

    /// The extension's data.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(1)
            .fixed(self.device_id.as_bytes())
            .vector(&self.signature);
        w.into_bytes()
    }

    /// Reads the extension's data: exactly one DeviceBinding of version 1.
    pub fn decode(bytes: &[u8]) -> Result<DeviceBinding, DecodeError> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 1 {
            return Err(DecodeError("unknown DeviceBinding version"));
        }
        let device_id = DeviceId(r.array::<HASH_LEN>()?);
        let signature = r.vector()?.to_vec();
        r.finish()?;
        Ok(DeviceBinding {
            device_id,
            signature,
        })
    }

    /// The extension, for a KeyPackage or a leaf node.
    pub fn to_extension(&self) -> Extension {
        Extension::Unknown(
            DEVICE_BINDING_EXTENSION_TYPE,
            UnknownExtension(self.encode()),
        )
    }

    /// Reads the binding from a KeyPackage's or leaf node's extensions:
    /// `None` if there is none.
    pub fn from_extensions<T>(
        extensions: &Extensions<T>,
    ) -> Option<Result<DeviceBinding, DecodeError>> {
        extensions
            .unknown(DEVICE_BINDING_EXTENSION_TYPE)
            .map(|extension| DeviceBinding::decode(&extension.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_and_encoding() {
        let device = SigningKey::from_seed([9; 32]);
        let uid: Uid = "alice@example.org".parse().unwrap();
        let binding = DeviceBinding::sign(&device, &uid, b"init", b"enc");
        assert_eq!(
            binding.device_id,
            DeviceId::of_device_key(device.public_key())
        );
        assert!(binding.verify(device.public_key(), &uid, b"init", b"enc"));
        // Any other uid, key or device fails.
        let bob: Uid = "bob@example.org".parse().unwrap();
        assert!(!binding.verify(device.public_key(), &bob, b"init", b"enc"));
        assert!(!binding.verify(device.public_key(), &uid, b"", b"enc"));
        assert!(!binding.verify(device.public_key(), &uid, b"init", b"other"));
        let other = SigningKey::from_seed([10; 32]);
        assert!(!binding.verify(other.public_key(), &uid, b"init", b"enc"));
        // The content's encoding: the keys cannot be shifted between fields.
        assert_ne!(content(&uid, b"ab", b"c"), content(&uid, b"a", b"bc"));

        let encoded = binding.encode();
        assert_eq!(encoded[0], 1);
        assert_eq!(&encoded[1..49], binding.device_id.as_bytes());
        assert_eq!(&encoded[49..51], &[0x49, 0x74]); // 2420
        assert_eq!(DeviceBinding::decode(&encoded), Ok(binding.clone()));
        let extensions =
            Extensions::<openmls::prelude::KeyPackage>::single(binding.to_extension()).unwrap();
        assert_eq!(
            DeviceBinding::from_extensions(&extensions),
            Some(Ok(binding))
        );

        let mut bad = encoded.clone();
        bad[0] = 2;
        assert!(DeviceBinding::decode(&bad).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(DeviceBinding::decode(&trailing).is_err());
        assert!(DeviceBinding::decode(&encoded[..40]).is_err());
    }
}
