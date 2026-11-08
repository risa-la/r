//! RisalaAAD, the `authenticated_data` of everything a device posts
//! (12.9, 7.2, 7.3).
//!
//! ```text
//! struct {
//!     uint8 version;               // 1
//!     opaque pseudonym[16];        // the leaf's pseudonym (7.3)
//!     opaque frank<V>;             // 48 bytes in an application message, otherwise empty
//!     opaque next_token_hash<V>;   // 48 bytes in a commit, otherwise empty
//! } RisalaAAD;
//! ```
//!
//! MLS leaves it in the clear for the server, and authenticates it for the
//! members.
//!
//! **`next_token_hash` cannot be in the commit's own AAD as 7.2 and 12.9
//! say.** The send token of the epoch a commit creates is an exporter
//! value of that epoch (7.2), and every secret of that epoch depends,
//! through the confirmed transcript hash in its group context [RFC9420,
//! 8.2], on the commit's FramedContent, which holds this AAD. So the hash
//! is not known until the commit is built, and cannot be put inside it.
//! Until the spec settles where it travels, this crate builds commits whose
//! `next_token_hash` is empty, and hands the hash back next to the commit
//! ([`crate::group::CommitOutput::next_token_hash`]); see the report of
//! task M1. [`RisalaAad::check_for`] accepts a commit's `next_token_hash`
//! empty or 48 bytes long.

use crate::codec::{DecodeError, Reader, Writer};
use crate::framing::ContentType;
use crate::primitives::HASH_LEN;

/// The length of a pseudonym (7.3).
pub const PSEUDONYM_LEN: usize = 16;

/// A leaf's pseudonym (7.3): 16 random bytes its device picks when it
/// creates the leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Pseudonym(pub [u8; PSEUDONYM_LEN]);

impl Pseudonym {
    /// A new random pseudonym, for a new leaf.
    pub fn generate() -> Result<Pseudonym, getrandom::Error> {
        let mut bytes = [0; PSEUDONYM_LEN];
        getrandom::fill(&mut bytes)?;
        Ok(Pseudonym(bytes))
    }
}

/// A RisalaAAD (12.9).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RisalaAad {
    /// The sending leaf's pseudonym.
    pub pseudonym: Pseudonym,
    /// HMAC-SHA-384(frank_key, content), in an application message (12.9).
    pub frank: Option<[u8; HASH_LEN]>,
    /// The SHA-384 hash of the next epoch's send token, in a commit (7.2).
    pub next_token_hash: Option<[u8; HASH_LEN]>,
}

/// Why a RisalaAAD does not fit the message it is in (12.9).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AadError {
    /// It is not one RisalaAAD of version 1.
    #[error(transparent)]
    Malformed(#[from] DecodeError),
    /// It has a `frank` or `next_token_hash` where the content type has
    /// none, or lacks one where it needs it.
    #[error("the RisalaAAD does not fit a message of this content type")]
    WrongFields,
}

fn optional_hash(bytes: &[u8]) -> Result<Option<[u8; HASH_LEN]>, DecodeError> {
    match bytes.len() {
        0 => Ok(None),
        HASH_LEN => Ok(Some(bytes.try_into().expect("48 bytes"))),
        _ => Err(DecodeError("a hash that is neither empty nor 48 bytes")),
    }
}

impl RisalaAad {
    /// The AAD of an application message (12.9).
    pub fn application(pseudonym: Pseudonym, frank: [u8; HASH_LEN]) -> RisalaAad {
        RisalaAad {
            pseudonym,
            frank: Some(frank),
            next_token_hash: None,
        }
    }

    /// The AAD of a proposal, or of a commit as this crate builds them
    /// (see the module's documentation).
    pub fn handshake(pseudonym: Pseudonym) -> RisalaAad {
        RisalaAad {
            pseudonym,
            frank: None,
            next_token_hash: None,
        }
    }

    /// The encoded RisalaAAD.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(1).fixed(&self.pseudonym.0);
        w.vector(self.frank.as_ref().map_or(&[][..], |h| &h[..]));
        w.vector(self.next_token_hash.as_ref().map_or(&[][..], |h| &h[..]));
        w.into_bytes()
    }

    /// Reads exactly one RisalaAAD of version 1, whose `frank` and
    /// `next_token_hash` are each empty or 48 bytes.
    pub fn decode(bytes: &[u8]) -> Result<RisalaAad, DecodeError> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 1 {
            return Err(DecodeError("unknown RisalaAAD version"));
        }
        let pseudonym = Pseudonym(r.array()?);
        let frank = optional_hash(r.vector()?)?;
        let next_token_hash = optional_hash(r.vector()?)?;
        r.finish()?;
        Ok(RisalaAad {
            pseudonym,
            frank,
            next_token_hash,
        })
    }

    /// Checks the fields against the content type (12.9): `frank` in an
    /// application message only, and `next_token_hash` in no message but
    /// a commit, where it may be empty (see the module's documentation).
    pub fn check_for(&self, content_type: ContentType) -> Result<(), AadError> {
        let ok = match content_type {
            ContentType::Application => self.frank.is_some() && self.next_token_hash.is_none(),
            ContentType::Proposal => self.frank.is_none() && self.next_token_hash.is_none(),
            ContentType::Commit => self.frank.is_none(),
        };
        if ok {
            Ok(())
        } else {
            Err(AadError::WrongFields)
        }
    }

    /// Reads a RisalaAAD and checks it against the content type.
    pub fn decode_for(bytes: &[u8], content_type: ContentType) -> Result<RisalaAad, AadError> {
        let aad = RisalaAad::decode(bytes)?;
        aad.check_for(content_type)?;
        Ok(aad)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding() {
        let p = Pseudonym([3; 16]);
        let app = RisalaAad::application(p, [9; 48]);
        let encoded = app.encode();
        let mut expected = vec![1];
        expected.extend_from_slice(&[3; 16]);
        expected.push(48);
        expected.extend_from_slice(&[9; 48]);
        expected.push(0);
        assert_eq!(encoded, expected);
        assert_eq!(encoded.len(), 67);
        assert_eq!(RisalaAad::decode(&encoded), Ok(app.clone()));

        let commit = RisalaAad {
            pseudonym: p,
            frank: None,
            next_token_hash: Some([5; 48]),
        };
        let encoded = commit.encode();
        assert_eq!(&encoded[17..19], &[0, 48]);
        assert_eq!(RisalaAad::decode(&encoded), Ok(commit.clone()));

        let handshake = RisalaAad::handshake(p);
        assert_eq!(handshake.encode().len(), 19);
        assert_eq!(RisalaAad::decode(&handshake.encode()), Ok(handshake));
    }

    #[test]
    fn malformed() {
        let good = RisalaAad::application(Pseudonym([3; 16]), [9; 48]).encode();
        let mut version = good.clone();
        version[0] = 2;
        let mut trailing = good.clone();
        trailing.push(0);
        let mut short_frank = vec![1];
        short_frank.extend_from_slice(&[3; 16]);
        short_frank.push(32);
        short_frank.extend_from_slice(&[9; 32]);
        short_frank.push(0);
        for bad in [
            version,
            trailing,
            short_frank,
            good[..good.len() - 1].to_vec(),
            vec![1; 10],
            vec![],
        ] {
            assert!(RisalaAad::decode(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn fields_fit_the_content_type() {
        let p = Pseudonym([1; 16]);
        let app = RisalaAad::application(p, [2; 48]);
        let plain = RisalaAad::handshake(p);
        let commit = RisalaAad {
            pseudonym: p,
            frank: None,
            next_token_hash: Some([3; 48]),
        };
        assert_eq!(app.check_for(ContentType::Application), Ok(()));
        assert!(plain.check_for(ContentType::Application).is_err());
        assert!(commit.check_for(ContentType::Application).is_err());
        assert_eq!(plain.check_for(ContentType::Proposal), Ok(()));
        assert!(app.check_for(ContentType::Proposal).is_err());
        assert!(commit.check_for(ContentType::Proposal).is_err());
        assert_eq!(commit.check_for(ContentType::Commit), Ok(()));
        assert_eq!(plain.check_for(ContentType::Commit), Ok(()));
        assert!(app.check_for(ContentType::Commit).is_err());
        assert_eq!(
            RisalaAad::decode_for(&app.encode(), ContentType::Commit),
            Err(AadError::WrongFields)
        );
    }
}
