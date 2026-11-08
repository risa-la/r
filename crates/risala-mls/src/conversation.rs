//! The conversation extension, `0xF2A1` (12.2, 15).
//!
//! Every group carries it in its group context. It ties the group to one
//! conversation, and holds the room's `history` (12.9) and `send` (6.2)
//! settings, so that the server can neither swap groups nor change the
//! settings behind the members' backs:
//!
//! ```text
//! struct {
//!     ConversationKind kind;     // direct(1), room(2)
//!     opaque name<V>;
//!     HistoryMode history;       // shared(1), joined(2)
//!     SendMode send;             // all(1), mods(2)
//! } RisalaConversation;
//! ```

use openmls::prelude::{Extension, Extensions, GroupContext, UnknownExtension};
use risala_proto::mls::CONVERSATION_EXTENSION_TYPE;
use risala_proto::names::{Id, Uid};
use risala_proto::types::{HistoryMode, SendMode};
use tls_codec::{Deserialize as _, Serialize as _, TlsDeserialize, TlsSerialize, TlsSize, VLBytes};

/// The kind of conversation a group belongs to (12.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConversationKind {
    /// A direct conversation, `direct(1)`.
    Direct,
    /// A room, `room(2)`.
    Room,
}

/// The conversation extension of a group (12.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RisalaConversation {
    /// Direct conversation or room.
    pub kind: ConversationKind,
    /// For a direct conversation, its participants' uids, sorted and
    /// joined by a space, or one uid for a conversation with yourself. For
    /// a room, its id (5.1).
    pub name: String,
    /// The room's `history` setting, `shared` for a direct conversation.
    pub history: HistoryMode,
    /// The room's `send` setting, `all` for a direct conversation.
    pub send: SendMode,
}

/// Why a conversation extension is not acceptable (12.2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConversationError {
    /// The group context has no `0xF2A1` extension.
    #[error("the group has no conversation extension")]
    Missing,
    /// The extension's data is not one RisalaConversation with known
    /// values and a UTF-8 name.
    #[error("the conversation extension is malformed")]
    Malformed,
}

/// The extension as it is encoded.
#[derive(TlsSerialize, TlsDeserialize, TlsSize)]
struct Wire {
    kind: u8,
    name: VLBytes,
    history: u8,
    send: u8,
}

impl RisalaConversation {
    /// The extension of the direct conversation between `a` and `b`, which
    /// may be the same uid for a conversation with yourself (12.2). The
    /// order of `a` and `b` does not matter.
    pub fn direct(a: &Uid, b: &Uid) -> RisalaConversation {
        let (a, b) = (a.as_str(), b.as_str());
        let name = match a.cmp(b) {
            std::cmp::Ordering::Equal => a.to_owned(),
            std::cmp::Ordering::Less => format!("{a} {b}"),
            std::cmp::Ordering::Greater => format!("{b} {a}"),
        };
        RisalaConversation {
            kind: ConversationKind::Direct,
            name,
            history: HistoryMode::Shared,
            send: SendMode::All,
        }
    }

    /// The extension of the room with id `id`, and the given settings
    /// (12.2).
    pub fn room(id: &Id, history: HistoryMode, send: SendMode) -> RisalaConversation {
        RisalaConversation {
            kind: ConversationKind::Room,
            name: id.as_str().to_owned(),
            history,
            send,
        }
    }

    /// The extension's data.
    pub fn encode(&self) -> Vec<u8> {
        Wire {
            kind: match self.kind {
                ConversationKind::Direct => 1,
                ConversationKind::Room => 2,
            },
            name: self.name.as_bytes().into(),
            history: match self.history {
                HistoryMode::Shared => 1,
                HistoryMode::Joined => 2,
            },
            send: match self.send {
                SendMode::All => 1,
                SendMode::Mods => 2,
            },
        }
        .tls_serialize_detached()
        .expect("a name fits a variable-size vector")
    }

    /// Reads the extension's data. It must be exactly one
    /// RisalaConversation, with values the enums define and a UTF-8 name.
    pub fn decode(data: &[u8]) -> Result<RisalaConversation, ConversationError> {
        let wire = Wire::tls_deserialize_exact(data).map_err(|_| ConversationError::Malformed)?;
        let kind = match wire.kind {
            1 => ConversationKind::Direct,
            2 => ConversationKind::Room,
            _ => return Err(ConversationError::Malformed),
        };
        let history = match wire.history {
            1 => HistoryMode::Shared,
            2 => HistoryMode::Joined,
            _ => return Err(ConversationError::Malformed),
        };
        let send = match wire.send {
            1 => SendMode::All,
            2 => SendMode::Mods,
            _ => return Err(ConversationError::Malformed),
        };
        let name = String::from_utf8(wire.name.into()).map_err(|_| ConversationError::Malformed)?;
        Ok(RisalaConversation {
            kind,
            name,
            history,
            send,
        })
    }

    /// The extension, for a group context.
    pub fn to_extension(&self) -> Extension {
        Extension::Unknown(CONVERSATION_EXTENSION_TYPE, UnknownExtension(self.encode()))
    }

    /// Reads the extension from a group context's extensions.
    pub fn from_extensions(
        extensions: &Extensions<GroupContext>,
    ) -> Result<RisalaConversation, ConversationError> {
        let extension = extensions
            .unknown(CONVERSATION_EXTENSION_TYPE)
            .ok_or(ConversationError::Missing)?;
        RisalaConversation::decode(&extension.0)
    }

    /// Whether this names the direct conversation between `a` and `b`
    /// (12.6).
    pub fn is_direct(&self, a: &Uid, b: &Uid) -> bool {
        *self == RisalaConversation::direct(a, b)
    }

    /// Whether this names the room with id `id` (12.6).
    pub fn is_room(&self, id: &Id) -> bool {
        self.kind == ConversationKind::Room && self.name == id.as_str()
    }

    /// Whether `other` differs from this one only in `history` and `send`,
    /// the fields an owner's commit may change (12.5, 12.6).
    pub fn same_conversation(&self, other: &RisalaConversation) -> bool {
        self.kind == other.kind && self.name == other.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uid(s: &str) -> Uid {
        s.parse().unwrap()
    }

    #[test]
    fn direct_names() {
        let a = uid("bob@example.net");
        let b = uid("alice@example.org");
        let conv = RisalaConversation::direct(&a, &b);
        assert_eq!(conv.name, "alice@example.org bob@example.net");
        assert_eq!(conv, RisalaConversation::direct(&b, &a));
        assert_eq!(conv.history, HistoryMode::Shared);
        assert_eq!(conv.send, SendMode::All);
        assert!(conv.is_direct(&a, &b));
        assert!(!conv.is_direct(&a, &a));

        let me = RisalaConversation::direct(&a, &a);
        assert_eq!(me.name, "bob@example.net");
        // Upper case is folded by the uid itself.
        assert_eq!(me, RisalaConversation::direct(&uid("Bob@Example.NET"), &a));
    }

    /// The spike's encoding of `room r7x2k9qp, shared`, with `send all`.
    #[test]
    fn encoding() {
        let id: Id = "r7x2k9qp".parse().unwrap();
        let conv = RisalaConversation::room(&id, HistoryMode::Shared, SendMode::All);
        assert_eq!(conv.encode(), b"\x02\x08r7x2k9qp\x01\x01");
        assert_eq!(RisalaConversation::decode(&conv.encode()), Ok(conv.clone()));
        assert!(conv.is_room(&id));
        assert!(!conv.is_room(&"other".parse().unwrap()));

        let mods = RisalaConversation::room(&id, HistoryMode::Joined, SendMode::Mods);
        assert_eq!(mods.encode(), b"\x02\x08r7x2k9qp\x02\x02");
        assert!(conv.same_conversation(&mods));
        assert_ne!(conv, mods);

        for bad in [
            &b"\x02\x08r7x2k9qp\x01\x01\x00"[..],
            b"\x02\x08r7x2k9qp\x01",
            b"\x00\x08r7x2k9qp\x01\x01",
            b"\x03\x08r7x2k9qp\x01\x01",
            b"\x02\x08r7x2k9qp\x00\x01",
            b"\x02\x08r7x2k9qp\x01\x03",
            b"\x02\x02\xff\xfe\x01\x01",
            b"",
        ] {
            assert_eq!(
                RisalaConversation::decode(bad),
                Err(ConversationError::Malformed),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn extensions() {
        let conv = RisalaConversation::direct(&uid("a@example.org"), &uid("b@example.org"));
        let extensions = Extensions::single(conv.to_extension()).unwrap();
        assert_eq!(RisalaConversation::from_extensions(&extensions), Ok(conv));
        assert_eq!(
            RisalaConversation::from_extensions(&Extensions::empty()),
            Err(ConversationError::Missing)
        );
    }
}
