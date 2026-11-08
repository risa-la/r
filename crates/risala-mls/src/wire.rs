//! MLS values as bytes (12.2): `<keypackage>`, `<groupinfo>`, `<message>`
//! and `<welcome>` are each an MLSMessage, and `<tree>` is the data of a
//! `ratchet_tree` extension. Lines carry them in base64, or as blobs
//! (12.12); that is the caller's.
//!
//! Each must decode to exactly one value of the expected kind, of `mls10`
//! and, where it says, the suite `0x0020` (12.2).

use openmls::messages::group_info::VerifiableGroupInfo;
use openmls::prelude::{
    MlsMessageBodyIn, MlsMessageIn, MlsMessageOut, ProtocolMessage, ProtocolVersion,
    RatchetTreeIn, Welcome,
};
use openmls::treesync::RatchetTree;
use tls_codec::{Deserialize as _, Serialize as _};

use crate::CIPHERSUITE;

/// Why bytes are not the MLS value expected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    /// Not one well-formed value.
    #[error("not a valid {0}")]
    Malformed(&'static str),
    /// Another kind of MLSMessage.
    #[error("the MLSMessage is not a {0}")]
    WrongKind(&'static str),
    /// Another protocol version than `mls10`, or another suite than
    /// `0x0020` (12.2).
    #[error("another protocol version or cipher suite")]
    CipherSuite,
}

/// An MLSMessage from OpenMLS, as bytes.
pub fn to_bytes(message: &MlsMessageOut) -> Vec<u8> {
    message
        .tls_serialize_detached()
        .expect("OpenMLS serialises what it builds")
}

fn decode(bytes: &[u8], what: &'static str) -> Result<MlsMessageBodyIn, WireError> {
    let message =
        MlsMessageIn::tls_deserialize_exact(bytes).map_err(|_| WireError::Malformed(what))?;
    // The version is the first field of every MLSMessage.
    if bytes.get(..2) != Some(&[0, 1]) {
        return Err(WireError::CipherSuite);
    }
    Ok(message.extract())
}

/// Reads a `<groupinfo>` (12.6). Its signature is not checked yet.
pub fn read_group_info(bytes: &[u8]) -> Result<VerifiableGroupInfo, WireError> {
    match decode(bytes, "GroupInfo")? {
        MlsMessageBodyIn::GroupInfo(group_info) => {
            if group_info.ciphersuite() != CIPHERSUITE {
                return Err(WireError::CipherSuite);
            }
            Ok(group_info)
        }
        _ => Err(WireError::WrongKind("GroupInfo")),
    }
}

/// Reads a `<message>`: a PublicMessage or PrivateMessage of `mls10`.
pub fn read_protocol_message(bytes: &[u8]) -> Result<ProtocolMessage, WireError> {
    match decode(bytes, "message")? {
        MlsMessageBodyIn::PublicMessage(message) => Ok(message.into()),
        MlsMessageBodyIn::PrivateMessage(message) => Ok(message.into()),
        _ => Err(WireError::WrongKind("PublicMessage or PrivateMessage")),
    }
}

/// Reads a `<welcome>` (12.8).
pub fn read_welcome(bytes: &[u8]) -> Result<Welcome, WireError> {
    match decode(bytes, "Welcome")? {
        MlsMessageBodyIn::Welcome(welcome) => {
            if welcome.ciphersuite() != CIPHERSUITE {
                return Err(WireError::CipherSuite);
            }
            Ok(welcome)
        }
        _ => Err(WireError::WrongKind("Welcome")),
    }
}

/// A Welcome from OpenMLS, as `<welcome>` bytes.
pub fn welcome_to_bytes(welcome: &Welcome) -> Vec<u8> {
    to_bytes(&MlsMessageOut::from_welcome(
        welcome.clone(),
        ProtocolVersion::Mls10,
    ))
}

/// A ratchet tree as `<tree>` bytes (12.2).
pub fn tree_to_bytes(tree: &RatchetTree) -> Vec<u8> {
    tree.tls_serialize_detached()
        .expect("OpenMLS serialises what it builds")
}

/// Reads a `<tree>` (12.2). OpenMLS checks it against the group when it is
/// used.
pub fn read_tree(bytes: &[u8]) -> Result<RatchetTreeIn, WireError> {
    RatchetTreeIn::tls_deserialize_exact(bytes).map_err(|_| WireError::Malformed("ratchet tree"))
}
