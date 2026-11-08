//! RisalaAAD, the `authenticated_data` of everything a device posts
//! (12.9, 7.3).
//!
//! ```text
//! struct {
//!     uint8 version;               // 1
//!     opaque pseudonym<V>;         // 16 bytes in a PrivateMessage, empty in a PublicMessage (7.3)
//!     opaque frank<V>;             // 48 bytes in an application message, otherwise empty
//! } RisalaAAD;
//! ```
//!
//! MLS leaves it in the clear for the server, and authenticates it for the
//! members. The hash of the next epoch's send token is not in it: it
//! cannot be, since the commit is part of what that epoch's keys come
//! from, so it travels as POST's `next=` (5.2, 12.6), and devices check it
//! with [`crate::group::check_received_commit`].

use crate::codec::{DecodeError, Reader, Writer};
use crate::framing::ContentType;
use crate::primitives::HASH_LEN;

/// The length of a pseudonym (7.3).
pub const PSEUDONYM_LEN: usize = 16;

/// A leaf's pseudonym (7.3): 16 random bytes its device picks when it
/// creates the leaf, and, in an epochal group, each period.
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
    /// The sending leaf's pseudonym, in a PrivateMessage; `None` in a
    /// PublicMessage, whose sender the server sees anyway, so that the
    /// pseudonym is not tied to the leaf (7.3).
    pub pseudonym: Option<Pseudonym>,
    /// HMAC-SHA-384(frank_key, content), in an application message (12.9).
    pub frank: Option<[u8; HASH_LEN]>,
}

/// Why a RisalaAAD does not fit the message it is in (12.9).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AadError {
    /// It is not one RisalaAAD of version 1.
    #[error(transparent)]
    Malformed(#[from] DecodeError),
    /// It has a `frank` where the content type has none, or lacks one
    /// where it needs it, or a pseudonym in a PublicMessage, or none in a
    /// PrivateMessage.
    #[error("the RisalaAAD does not fit a message of this content type")]
    WrongFields,
}

impl RisalaAad {
    /// The AAD of an application message (12.9), always a PrivateMessage.
    pub fn application(pseudonym: Pseudonym, frank: [u8; HASH_LEN]) -> RisalaAad {
        RisalaAad {
            pseudonym: Some(pseudonym),
            frank: Some(frank),
        }
    }

    /// The AAD of a commit or proposal sent as a PrivateMessage, outside
    /// public rooms (12.6).
    pub fn handshake(pseudonym: Pseudonym) -> RisalaAad {
        RisalaAad {
            pseudonym: Some(pseudonym),
            frank: None,
        }
    }

    /// The AAD of a commit or proposal sent as a PublicMessage, in a public
    /// room (12.6): no pseudonym and no frank.
    pub fn public() -> RisalaAad {
        RisalaAad {
            pseudonym: None,
            frank: None,
        }
    }

    /// The encoded RisalaAAD.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(1);
        w.vector(self.pseudonym.as_ref().map_or(&[][..], |p| &p.0[..]));
        w.vector(self.frank.as_ref().map_or(&[][..], |h| &h[..]));
        w.into_bytes()
    }

    /// Reads exactly one RisalaAAD of version 1, whose pseudonym is empty
    /// or 16 bytes and whose `frank` is empty or 48 bytes.
    pub fn decode(bytes: &[u8]) -> Result<RisalaAad, DecodeError> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 1 {
            return Err(DecodeError("unknown RisalaAAD version"));
        }
        let pseudonym = match r.vector()? {
            [] => None,
            p if p.len() == PSEUDONYM_LEN => Some(Pseudonym(p.try_into().expect("16 bytes"))),
            _ => {
                return Err(DecodeError(
                    "a pseudonym that is neither empty nor 16 bytes",
                ));
            }
        };
        let frank = match r.vector()? {
            [] => None,
            h if h.len() == HASH_LEN => Some(h.try_into().expect("48 bytes")),
            _ => return Err(DecodeError("a frank that is neither empty nor 48 bytes")),
        };
        r.finish()?;
        Ok(RisalaAad { pseudonym, frank })
    }

    /// Checks the fields against the message (12.9, 5.2): `frank` in an
    /// application message and nowhere else, and a pseudonym in a
    /// PrivateMessage (`private`) and none in a PublicMessage.
    pub fn check_for(&self, content_type: ContentType, private: bool) -> Result<(), AadError> {
        let frank_ok = self.frank.is_some() == (content_type == ContentType::Application);
        let pseudonym_ok = self.pseudonym.is_some() == private;
        if frank_ok && pseudonym_ok {
            Ok(())
        } else {
            Err(AadError::WrongFields)
        }
    }

    /// Reads a RisalaAAD and checks it against the message.
    pub fn decode_for(
        bytes: &[u8],
        content_type: ContentType,
        private: bool,
    ) -> Result<RisalaAad, AadError> {
        let aad = RisalaAad::decode(bytes)?;
        aad.check_for(content_type, private)?;
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
        let mut expected = vec![1, 16];
        expected.extend_from_slice(&[3; 16]);
        expected.push(48);
        expected.extend_from_slice(&[9; 48]);
        assert_eq!(encoded, expected);
        assert_eq!(encoded.len(), 67);
        assert_eq!(RisalaAad::decode(&encoded), Ok(app.clone()));

        let handshake = RisalaAad::handshake(p);
        assert_eq!(handshake.encode().len(), 19);
        assert_eq!(RisalaAad::decode(&handshake.encode()), Ok(handshake));

        // A PublicMessage's: both empty.
        assert_eq!(RisalaAad::public().encode(), vec![1, 0, 0]);
        assert_eq!(RisalaAad::decode(&[1, 0, 0]), Ok(RisalaAad::public()));
    }

    #[test]
    fn malformed() {
        let good = RisalaAad::application(Pseudonym([3; 16]), [9; 48]).encode();
        let mut version = good.clone();
        version[0] = 2;
        let mut trailing = good.clone();
        trailing.push(0);
        let mut short_frank = vec![1, 16];
        short_frank.extend_from_slice(&[3; 16]);
        short_frank.push(32);
        short_frank.extend_from_slice(&[9; 32]);
        let mut short_pseudonym = vec![1, 15];
        short_pseudonym.extend_from_slice(&[3; 15]);
        short_pseudonym.push(0);
        // The old layout, with a fixed pseudonym and next_token_hash.
        let mut old = vec![1];
        old.extend_from_slice(&[3; 16]);
        old.extend_from_slice(&[0, 0]);
        for bad in [
            version,
            trailing,
            short_frank,
            short_pseudonym,
            old,
            good[..good.len() - 1].to_vec(),
            vec![1; 10],
            vec![1, 0],
            vec![],
        ] {
            assert!(RisalaAad::decode(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn fields_fit_the_message() {
        use ContentType::*;
        let p = Pseudonym([1; 16]);
        let app = RisalaAad::application(p, [2; 48]);
        let private = RisalaAad::handshake(p);
        let public = RisalaAad::public();
        // Application messages: always private, with a frank.
        assert_eq!(app.check_for(Application, true), Ok(()));
        assert!(app.check_for(Application, false).is_err());
        assert!(private.check_for(Application, true).is_err());
        // Commits and proposals: a pseudonym exactly when private, never
        // a frank.
        for content_type in [Proposal, Commit] {
            assert_eq!(private.check_for(content_type, true), Ok(()));
            assert_eq!(public.check_for(content_type, false), Ok(()));
            assert!(private.check_for(content_type, false).is_err());
            assert!(public.check_for(content_type, true).is_err());
            assert!(app.check_for(content_type, true).is_err());
        }
        assert_eq!(
            RisalaAad::decode_for(&app.encode(), Commit, true),
            Err(AadError::WrongFields)
        );
    }
}
