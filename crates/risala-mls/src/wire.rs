//! MLS values on the wire (12.2): between OpenMLS's types and the base64
//! values of `risala_proto::mls`.
//!
//! `<keypackage>`, `<groupinfo>`, `<commit>` and `<welcome>` are each an
//! MLSMessage, and `<tree>` is the data of a `ratchet_tree` extension. Each
//! must decode to exactly one value of the expected kind, with nothing
//! after it.

use openmls::messages::group_info::{GroupInfo, VerifiableGroupInfo};
use openmls::prelude::{
    KeyPackage, KeyPackageIn, MlsMessageBodyIn, MlsMessageIn, MlsMessageOut, ProtocolMessage,
    RatchetTreeIn, Welcome,
};
use openmls::treesync::RatchetTree;
use risala_proto::error::ParseError;
use risala_proto::mls;
use tls_codec::{Deserialize as _, Serialize as _};

/// Why a value from the wire is not what it should be.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    /// The bytes are not one MLSMessage of protocol version `mls10`, or one
    /// ratchet tree.
    #[error("not a valid {0}")]
    Malformed(&'static str),
    /// The MLSMessage holds another kind of value.
    #[error("the MLSMessage is not a {0}")]
    WrongKind(&'static str),
    /// The value is too long for a line (2.3).
    #[error("too long for a line")]
    TooLong,
}

impl From<ParseError> for WireError {
    fn from(_: ParseError) -> WireError {
        WireError::TooLong
    }
}

fn encode(message: &MlsMessageOut) -> Vec<u8> {
    message
        .tls_serialize_detached()
        .expect("OpenMLS serialises what it builds")
}

fn decode(bytes: &[u8], what: &'static str) -> Result<MlsMessageBodyIn, WireError> {
    MlsMessageIn::tls_deserialize_exact(bytes)
        .map(MlsMessageIn::extract)
        .map_err(|_| WireError::Malformed(what))
}

/// A KeyPackage as `<keypackage>`, for KEYPKG ADD (12.4).
pub fn key_package_to_wire(key_package: &KeyPackage) -> Result<mls::KeyPackage, WireError> {
    Ok(mls::KeyPackage::from_bytes(&encode(&MlsMessageOut::from(
        key_package.clone(),
    )))?)
}

/// Reads a `<keypackage>`. It is not checked yet: see
/// [`check_key_package`](crate::check_key_package).
pub fn key_package_from_wire(value: &mls::KeyPackage) -> Result<KeyPackageIn, WireError> {
    match decode(&value.decode(), "KeyPackage")? {
        MlsMessageBodyIn::KeyPackage(key_package) => Ok(key_package),
        _ => Err(WireError::WrongKind("KeyPackage")),
    }
}

/// A GroupInfo from OpenMLS, as `<groupinfo>` (12.5).
pub fn group_info_to_wire(group_info: &MlsMessageOut) -> Result<mls::GroupInfo, WireError> {
    Ok(mls::GroupInfo::from_bytes(&encode(group_info))?)
}

/// A GroupInfo from a commit, as `<groupinfo>` (12.5).
pub fn signed_group_info_to_wire(group_info: &GroupInfo) -> Result<mls::GroupInfo, WireError> {
    group_info_to_wire(&MlsMessageOut::from(group_info.clone()))
}

/// Reads a `<groupinfo>`. Its signature is not checked yet.
pub fn group_info_from_wire(value: &mls::GroupInfo) -> Result<VerifiableGroupInfo, WireError> {
    match decode(&value.decode(), "GroupInfo")? {
        MlsMessageBodyIn::GroupInfo(group_info) => Ok(group_info),
        _ => Err(WireError::WrongKind("GroupInfo")),
    }
}

/// A commit from OpenMLS, as `<commit>` (12.5).
pub fn commit_to_wire(commit: &MlsMessageOut) -> Result<mls::CommitMessage, WireError> {
    Ok(mls::CommitMessage::from_bytes(&encode(commit))?)
}

/// Reads a `<commit>`. It must be a PublicMessage (12.5); whether it holds
/// a commit is up to processing it.
pub fn commit_from_wire(value: &mls::CommitMessage) -> Result<ProtocolMessage, WireError> {
    match decode(&value.decode(), "commit")? {
        MlsMessageBodyIn::PublicMessage(message) => Ok(message.into()),
        _ => Err(WireError::WrongKind("PublicMessage")),
    }
}

/// A Welcome from OpenMLS, as `<welcome>` (12.5, 12.7).
pub fn welcome_to_wire(welcome: &MlsMessageOut) -> Result<mls::Welcome, WireError> {
    Ok(mls::Welcome::from_bytes(&encode(welcome))?)
}

/// Reads a `<welcome>` (12.7).
pub fn welcome_from_wire(value: &mls::Welcome) -> Result<Welcome, WireError> {
    match decode(&value.decode(), "Welcome")? {
        MlsMessageBodyIn::Welcome(welcome) => Ok(welcome),
        _ => Err(WireError::WrongKind("Welcome")),
    }
}

/// A ratchet tree as `<tree>` (12.2).
pub fn tree_to_wire(tree: &RatchetTree) -> Result<mls::RatchetTree, WireError> {
    let bytes = tree
        .tls_serialize_detached()
        .expect("OpenMLS serialises what it builds");
    Ok(mls::RatchetTree::from_bytes(&bytes)?)
}

/// Reads a `<tree>` (12.2). OpenMLS checks it against the group when it
/// is used.
pub fn tree_from_wire(value: &mls::RatchetTree) -> Result<RatchetTreeIn, WireError> {
    RatchetTreeIn::tls_deserialize_exact(value.decode())
        .map_err(|_| WireError::Malformed("ratchet tree"))
}
