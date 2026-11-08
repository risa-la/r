//! Reading an MLS message's framing without its keys (12.2, 7.2, 12.6),
//! for the server.
//!
//! The server reads the group id, epoch, content type and RisalaAAD of
//! every post, and checks the protocol version and, where the message has
//! one, the cipher suite. It never holds a group's secrets, so this is all
//! it can see of a PrivateMessage. It runs on what anyone sends, so it is
//! strict, bounds checked, and does work linear in the message's length.
//!
//! ```text
//! struct {
//!     ProtocolVersion version = mls10;      // uint16, 1
//!     WireFormat wire_format;               // uint16
//!     select (wire_format) { ... };
//! } MLSMessage;
//!
//! struct {                                  // PrivateMessage
//!     opaque group_id<V>;
//!     uint64 epoch;
//!     ContentType content_type;             // uint8
//!     opaque authenticated_data<V>;
//!     opaque encrypted_sender_data<V>;
//!     opaque ciphertext<V>;
//! } PrivateMessage;
//!
//! struct {                                  // the start of a PublicMessage
//!     opaque group_id<V>;
//!     uint64 epoch;
//!     Sender sender;
//!     opaque authenticated_data<V>;
//!     ContentType content_type;
//!     ...
//! } FramedContent;
//! ```

use openmls::prelude::MlsMessageIn;
use tls_codec::Deserialize as _;

use crate::aad::{AadError, RisalaAad};
use crate::codec::{DecodeError, Reader};

/// The protocol version risala uses, `mls10` (12.2).
pub const MLS10: u16 = 1;

/// The cipher suite of every conversation, `0x0020` (12.2, 15).
pub const CIPHER_SUITE: u16 = 0x0020;

/// The length of a group id (12.6).
pub const GROUP_ID_LEN: usize = 32;

/// The content type of an MLS message [RFC9420, 6].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContentType {
    /// `application(1)`.
    Application,
    /// `proposal(2)`.
    Proposal,
    /// `commit(3)`.
    Commit,
}

/// Who sent a PublicMessage [RFC9420, 6].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Sender {
    /// A member, by leaf index.
    Member(u32),
    /// An external sender, by its index in `external_senders`.
    External(u32),
    /// A new member proposing to be added (an external Add proposal).
    NewMemberProposal,
    /// A new member joining by external commit.
    NewMemberCommit,
}

/// The framing of a PublicMessage or PrivateMessage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Framing<'a> {
    /// Whether it is a PrivateMessage.
    pub private: bool,
    /// The group id.
    pub group_id: &'a [u8],
    /// The epoch it belongs to.
    pub epoch: u64,
    /// The content type.
    pub content_type: ContentType,
    /// The sender, which only a PublicMessage shows.
    pub sender: Option<Sender>,
    /// The `authenticated_data`, a RisalaAAD.
    pub authenticated_data: &'a [u8],
}

impl Framing<'_> {
    /// The RisalaAAD, checked against the content type (12.9).
    pub fn aad(&self) -> Result<RisalaAad, AadError> {
        RisalaAad::decode_for(self.authenticated_data, self.content_type)
    }
}

/// What an MLSMessage holds, as far as the server needs to know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MlsMessage<'a> {
    /// A PublicMessage or a PrivateMessage.
    Message(Framing<'a>),
    /// A Welcome of the suite `0x0020`.
    Welcome,
    /// A GroupInfo of `mls10` and the suite `0x0020`.
    GroupInfo {
        /// Its group id.
        group_id: &'a [u8],
        /// Its epoch.
        epoch: u64,
    },
    /// A KeyPackage of `mls10` and the suite `0x0020`.
    KeyPackage,
}

/// Why bytes are not an MLS message risala accepts.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FramingError {
    /// It is not one well-formed MLSMessage.
    #[error(transparent)]
    Malformed(#[from] DecodeError),
    /// Its protocol version is not `mls10`.
    #[error("the protocol version is not mls10")]
    Version,
    /// Its cipher suite is not `0x0020`.
    #[error("the cipher suite is not 0x0020")]
    CipherSuite,
    /// It is a kind of MLSMessage that risala does not post, or the wrong
    /// kind where one was expected.
    #[error("not the kind of MLS message expected")]
    WrongKind,
}

fn content_type(value: u8) -> Result<ContentType, DecodeError> {
    match value {
        1 => Ok(ContentType::Application),
        2 => Ok(ContentType::Proposal),
        3 => Ok(ContentType::Commit),
        _ => Err(DecodeError("unknown content type")),
    }
}

fn check_version(version: u16) -> Result<(), FramingError> {
    if version == MLS10 {
        Ok(())
    } else {
        Err(FramingError::Version)
    }
}

fn check_suite(suite: u16) -> Result<(), FramingError> {
    if suite == CIPHER_SUITE {
        Ok(())
    } else {
        Err(FramingError::CipherSuite)
    }
}

/// Checks that `bytes` are exactly one MLSMessage that OpenMLS can parse.
/// It holds no keys and checks no signatures; it reads the structure.
fn parses_whole(bytes: &[u8]) -> Result<(), DecodeError> {
    MlsMessageIn::tls_deserialize_exact(bytes)
        .map(|_| ())
        .map_err(|_| DecodeError("not a well-formed MLSMessage"))
}

/// Reads an MLSMessage: its version and kind, the framing of a
/// PublicMessage or PrivateMessage, and the suite of a Welcome, GroupInfo
/// or KeyPackage, which must be `0x0020` (12.2).
///
/// A PrivateMessage is read to its end, field by field. Other kinds are
/// also parsed whole, without keys, so that the server stores and relays
/// only well-formed messages. A PublicMessage must not hold an application
/// message, which risala always encrypts (12.6).
pub fn read_message(bytes: &[u8]) -> Result<MlsMessage<'_>, FramingError> {
    let mut r = Reader::new(bytes);
    check_version(r.u16()?)?;
    match r.u16()? {
        // mls_public_message
        1 => {
            let group_id = r.vector()?;
            let epoch = r.u64()?;
            let sender = match r.u8()? {
                1 => Sender::Member(r.u32()?),
                2 => Sender::External(r.u32()?),
                3 => Sender::NewMemberProposal,
                4 => Sender::NewMemberCommit,
                _ => return Err(DecodeError("unknown sender type").into()),
            };
            let authenticated_data = r.vector()?;
            let content_type = content_type(r.u8()?)?;
            if content_type == ContentType::Application {
                return Err(FramingError::WrongKind);
            }
            parses_whole(bytes)?;
            Ok(MlsMessage::Message(Framing {
                private: false,
                group_id,
                epoch,
                content_type,
                sender: Some(sender),
                authenticated_data,
            }))
        }
        // mls_private_message
        2 => {
            let group_id = r.vector()?;
            let epoch = r.u64()?;
            let content_type = content_type(r.u8()?)?;
            let authenticated_data = r.vector()?;
            let _encrypted_sender_data = r.vector()?;
            let _ciphertext = r.vector()?;
            r.finish()?;
            Ok(MlsMessage::Message(Framing {
                private: true,
                group_id,
                epoch,
                content_type,
                sender: None,
                authenticated_data,
            }))
        }
        // mls_welcome
        3 => {
            check_suite(r.u16()?)?;
            parses_whole(bytes)?;
            Ok(MlsMessage::Welcome)
        }
        // mls_group_info: the group context comes first.
        4 => {
            check_version(r.u16()?)?;
            check_suite(r.u16()?)?;
            let group_id = r.vector()?;
            let epoch = r.u64()?;
            parses_whole(bytes)?;
            Ok(MlsMessage::GroupInfo { group_id, epoch })
        }
        // mls_key_package
        5 => {
            check_version(r.u16()?)?;
            check_suite(r.u16()?)?;
            parses_whole(bytes)?;
            Ok(MlsMessage::KeyPackage)
        }
        _ => Err(FramingError::WrongKind),
    }
}

/// Reads the framing of a post (5.2): a PublicMessage or PrivateMessage,
/// with a RisalaAAD that fits its content type (12.9).
pub fn read_post(bytes: &[u8]) -> Result<(Framing<'_>, RisalaAad), PostError> {
    match read_message(bytes)? {
        MlsMessage::Message(framing) => {
            let aad = framing.aad()?;
            Ok((framing, aad))
        }
        _ => Err(PostError::Framing(FramingError::WrongKind)),
    }
}

/// Why a post's framing is not acceptable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PostError {
    /// The MLS framing.
    #[error(transparent)]
    Framing(#[from] FramingError),
    /// The RisalaAAD.
    #[error(transparent)]
    Aad(#[from] AadError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Writer;

    fn private(content_type: u8, aad: &[u8]) -> Vec<u8> {
        let mut w = Writer::new();
        w.fixed(&1u16.to_be_bytes()).fixed(&2u16.to_be_bytes());
        w.vector(&[4; 32]).u64(7).u8(content_type).vector(aad);
        w.vector(b"sender").vector(b"ciphertext");
        w.into_bytes()
    }

    #[test]
    fn private_messages() {
        let aad = RisalaAad::application(crate::aad::Pseudonym([1; 16]), [2; 48]);
        let bytes = private(1, &aad.encode());
        let (framing, read) = read_post(&bytes).unwrap();
        assert!(framing.private);
        assert_eq!(framing.group_id, &[4; 32]);
        assert_eq!(framing.epoch, 7);
        assert_eq!(framing.content_type, ContentType::Application);
        assert_eq!(framing.sender, None);
        assert_eq!(read, aad);

        // The AAD must fit the content type.
        assert!(matches!(
            read_post(&private(3, &aad.encode())),
            Err(PostError::Aad(AadError::WrongFields))
        ));
        // Every truncation fails, and so does a trailing byte.
        for len in 0..bytes.len() {
            assert!(read_message(&bytes[..len]).is_err(), "{len}");
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(read_message(&trailing).is_err());
        // Unknown content type, version and wire format.
        assert!(read_message(&private(0, b"")).is_err());
        assert!(read_message(&private(4, b"")).is_err());
        let mut version = bytes.clone();
        version[1] = 2;
        assert_eq!(read_message(&version), Err(FramingError::Version));
        let mut kind = bytes.clone();
        kind[3] = 6;
        assert_eq!(read_message(&kind), Err(FramingError::WrongKind));
    }

    #[test]
    fn hostile_input_does_not_panic() {
        // Lengths that point past the end, at every size class.
        for bytes in [
            &b"\x00\x01\x00\x02\xbf\xff\xff\xff"[..],
            b"\x00\x01\x00\x02\x7f\xff",
            b"\x00\x01\x00\x01\xc0",
            b"\x00\x01\x00\x03\x00",
            b"\x00\x01\x00\x04\x00\x01\x00\x20\x40",
            b"\x00\x01",
            b"",
        ] {
            assert!(read_message(bytes).is_err());
        }
        // Every byte value at every position of a valid message.
        let bytes = private(
            2,
            &RisalaAad::handshake(crate::aad::Pseudonym([0; 16])).encode(),
        );
        for i in 0..bytes.len() {
            for v in [0u8, 0x3f, 0x40, 0x7f, 0x80, 0xbf, 0xc0, 0xff] {
                let mut b = bytes.clone();
                b[i] = v;
                let _ = read_message(&b);
            }
        }
    }
}
