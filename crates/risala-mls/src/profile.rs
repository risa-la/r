//! Profiles, the leaf extension `0xF2A3` (12.3, 15).
//!
//! ```text
//! struct {
//!     uint8 version;               // 1
//!     opaque display_name<V>;      // UTF-8, at most 128 bytes, may be empty
//!     uint64 updated;              // when the leaf was last committed, in ms
//! } RisalaProfile;
//! ```

use openmls::prelude::{Extension, ExtensionType, Extensions, LeafNode, UnknownExtension};

use crate::codec::{DecodeError, Reader, Writer};

/// The extension type of profiles (12.3, 15).
pub const PROFILE_EXTENSION_TYPE: u16 = 0xF2A3;

/// The profile's type, as OpenMLS names it.
pub const PROFILE_EXTENSION: ExtensionType = ExtensionType::Unknown(PROFILE_EXTENSION_TYPE);

/// The longest display name, in bytes (12.3).
pub const MAX_DISPLAY_NAME_LEN: usize = 128;

/// A leaf's profile (12.3).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RisalaProfile {
    /// The display name, which may be empty (8.2).
    pub display_name: String,
    /// When the leaf's device last committed its own leaf, in ms since
    /// 1970-01-01T00:00:00Z, by its clock (12.3, 12.7).
    pub updated: u64,
}

impl RisalaProfile {
    /// A profile, or `None` if the display name is longer than 128 bytes.
    pub fn new(display_name: &str, updated: u64) -> Option<RisalaProfile> {
        (display_name.len() <= MAX_DISPLAY_NAME_LEN).then(|| RisalaProfile {
            display_name: display_name.to_owned(),
            updated,
        })
    }

    /// The extension's data.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(1)
            .vector(self.display_name.as_bytes())
            .u64(self.updated);
        w.into_bytes()
    }

    /// Reads the extension's data: one RisalaProfile of version 1, whose
    /// display name is UTF-8 of at most 128 bytes.
    pub fn decode(bytes: &[u8]) -> Result<RisalaProfile, DecodeError> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 1 {
            return Err(DecodeError("unknown RisalaProfile version"));
        }
        let name = r.vector()?;
        let updated = r.u64()?;
        r.finish()?;
        if name.len() > MAX_DISPLAY_NAME_LEN {
            return Err(DecodeError("display name too long"));
        }
        let display_name = std::str::from_utf8(name)
            .map_err(|_| DecodeError("display name is not UTF-8"))?
            .to_owned();
        Ok(RisalaProfile {
            display_name,
            updated,
        })
    }

    /// The extension, for a leaf node.
    pub fn to_extension(&self) -> Extension {
        Extension::Unknown(PROFILE_EXTENSION_TYPE, UnknownExtension(self.encode()))
    }

    /// Reads the profile from a leaf node's extensions: `None` if there is
    /// none.
    pub fn from_extensions(
        extensions: &Extensions<LeafNode>,
    ) -> Option<Result<RisalaProfile, DecodeError>> {
        extensions
            .unknown(PROFILE_EXTENSION_TYPE)
            .map(|extension| RisalaProfile::decode(&extension.0))
    }

    /// Reads a leaf's profile: `None` if it has none, or a malformed one.
    pub fn of_leaf(leaf: &LeafNode) -> Option<RisalaProfile> {
        RisalaProfile::from_extensions(leaf.extensions())?.ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding() {
        let profile = RisalaProfile::new("Alice", 0x0102030405060708).unwrap();
        let encoded = profile.encode();
        assert_eq!(encoded, b"\x01\x05Alice\x01\x02\x03\x04\x05\x06\x07\x08");
        assert_eq!(RisalaProfile::decode(&encoded), Ok(profile.clone()));
        let empty = RisalaProfile::new("", 0).unwrap();
        assert_eq!(empty.encode(), b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00");

        let extensions = Extensions::<LeafNode>::single(profile.to_extension()).unwrap();
        assert_eq!(
            RisalaProfile::from_extensions(&extensions),
            Some(Ok(profile))
        );
    }

    #[test]
    fn limits() {
        let max = "é".repeat(64);
        assert_eq!(max.len(), 128);
        let profile = RisalaProfile::new(&max, 1).unwrap();
        assert_eq!(RisalaProfile::decode(&profile.encode()), Ok(profile));
        assert!(RisalaProfile::new(&"a".repeat(129), 1).is_none());

        let mut long = b"\x01\x40\x81".to_vec();
        long.extend_from_slice(&[b'a'; 129]);
        long.extend_from_slice(&[0; 8]);
        assert!(RisalaProfile::decode(&long).is_err());
        for bad in [
            &b"\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00"[..],
            b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            b"\x01\x00\x00\x00\x00\x00\x00\x00\x00",
            b"\x01\x02\xff\xfe\x00\x00\x00\x00\x00\x00\x00\x00",
        ] {
            assert!(RisalaProfile::decode(bad).is_err(), "{bad:?}");
        }
    }
}
