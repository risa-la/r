//! The conversation extension, `0xF2A1` (12.4, 6.2, 6.3, 15).
//!
//! Every group carries it in its group context. It ties the group to one
//! conversation, mailbox and server, and holds the room's roles and
//! settings:
//!
//! ```text
//! struct {
//!     uint8 version;               // 1
//!     ConversationKind kind;       // direct(1), private_room(2), public_room(3)
//!     opaque host<V>;              // the server, in lower case
//!     opaque box[16];              // the mailbox
//!     opaque name<V>;
//!     opaque topic<V>;             // UTF-8, at most 512 bytes
//!     ConfirmMode confirm;         // pairwise(1), epochal(2)
//!     GuestMode guests;            // none(1), read(2), write(3)
//!     SendMode send;               // all(1), mods(2)
//!     Uid owners<V>;
//!     Uid mods<V>;
//!     Uid bans<V>;
//! } RisalaConversation;
//! ```
//!
//! [`RisalaConversation::decode`] reads the structure,
//! [`RisalaConversation::check`] checks that it is well formed (12.4), and
//! [`RisalaConversation::check_change`] that a commit changes only what its
//! committer may (6.2, 6.3, 6.4).

use openmls::prelude::{
    Extension, ExtensionType, Extensions, GroupContext, RequiredCapabilitiesExtension,
    UnknownExtension,
};
use risala_proto::names::{Room, Uid};

use crate::codec::{DecodeError, Reader, Writer};

/// The extension type of the conversation extension (12.4, 15).
pub const CONVERSATION_EXTENSION_TYPE: u16 = 0xF2A1;

/// The conversation extension's type, as OpenMLS names it.
pub const CONVERSATION_EXTENSION: ExtensionType =
    ExtensionType::Unknown(CONVERSATION_EXTENSION_TYPE);

/// The length of a mailbox's box (5.2, 12.4).
pub const BOX_LEN: usize = 16;

/// The longest topic, in bytes (12.4).
pub const MAX_TOPIC_LEN: usize = 512;

/// The longest private room name, in bytes (12.4).
pub const MAX_PRIVATE_NAME_LEN: usize = 128;

/// The longest host name accepted, in bytes.
const MAX_HOST_LEN: usize = 255;

/// The kind of conversation a group belongs to (12.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConversationKind {
    /// `direct(1)`.
    Direct,
    /// `private_room(2)`.
    PrivateRoom,
    /// `public_room(3)`.
    PublicRoom,
}

/// How the group's devices confirm leaves (12.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConfirmMode {
    /// `pairwise(1)`.
    Pairwise,
    /// `epochal(2)`.
    Epochal,
}

/// Whether guests may join a public room, and send (6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GuestMode {
    /// `none(1)`.
    None,
    /// `read(2)`.
    Read,
    /// `write(3)`.
    Write,
}

/// Who may send (6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SendMode {
    /// `all(1)`.
    All,
    /// `mods(2)`.
    Mods,
}

/// An identity's role in a room (6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Role {
    /// A plain member, or a guest.
    Member,
    /// A moderator.
    Mod,
    /// An owner.
    Owner,
}

/// The conversation extension of a group (12.4).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RisalaConversation {
    /// Direct conversation, private room or public room. It never changes.
    pub kind: ConversationKind,
    /// The server, in lower case. It never changes.
    pub host: String,
    /// The mailbox (`box`). It changes only when a direct conversation or
    /// a private room moves to a new mailbox (7.8).
    pub mailbox: [u8; BOX_LEN],
    /// For a direct conversation, the participants' uids, sorted and joined
    /// by a space, or one uid; for a private room, its name; for a public
    /// room, its room name, such as `#general`.
    pub name: String,
    /// The topic, empty in a direct conversation.
    pub topic: String,
    /// How leaves are confirmed.
    pub confirm: ConfirmMode,
    /// Whether guests may join.
    pub guests: GuestMode,
    /// Who may send.
    pub send: SendMode,
    /// The owners.
    pub owners: Vec<Uid>,
    /// The moderators.
    pub mods: Vec<Uid>,
    /// The banned identities.
    pub bans: Vec<Uid>,
}

/// Why a conversation extension is not acceptable (12.4).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConversationError {
    /// The group context has no conversation extension.
    #[error("the group has no conversation extension")]
    Missing,
    /// The group context's extensions are not exactly
    /// `required_capabilities` then the conversation extension, as 12.4
    /// says.
    #[error("the group context's extensions are not risala's")]
    Extensions,
    /// The extension is not one RisalaConversation of version 1 with known
    /// values.
    #[error(transparent)]
    Malformed(#[from] DecodeError),
    /// The extension is well formed, but breaks a rule of 12.4.
    #[error("the conversation extension is not acceptable: {0}")]
    Invalid(&'static str),
}

/// Why a change to the conversation extension is not allowed (6.2, 6.3,
/// 6.4, 12.4).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChangeError {
    /// The new extension is not well formed.
    #[error(transparent)]
    Invalid(#[from] ConversationError),
    /// A field changed that never changes, or not in this kind of
    /// conversation.
    #[error("the field {0} may not change")]
    Fixed(&'static str),
    /// The committer's role does not allow this change.
    #[error("only {0} may change this")]
    NotAllowed(&'static str),
    /// A ban that leaves the uid in `owners` or `mods` (6.4).
    #[error("a ban that leaves the uid in owners or mods")]
    BanKeepsRole,
}

fn kind_value(kind: ConversationKind) -> u8 {
    match kind {
        ConversationKind::Direct => 1,
        ConversationKind::PrivateRoom => 2,
        ConversationKind::PublicRoom => 3,
    }
}

fn confirm_value(confirm: ConfirmMode) -> u8 {
    match confirm {
        ConfirmMode::Pairwise => 1,
        ConfirmMode::Epochal => 2,
    }
}

fn guests_value(guests: GuestMode) -> u8 {
    match guests {
        GuestMode::None => 1,
        GuestMode::Read => 2,
        GuestMode::Write => 3,
    }
}

fn send_value(send: SendMode) -> u8 {
    match send {
        SendMode::All => 1,
        SendMode::Mods => 2,
    }
}

fn write_uids(w: &mut Writer, uids: &[Uid]) {
    let mut inner = Writer::new();
    for uid in uids {
        inner.vector(uid.as_str().as_bytes());
    }
    w.vector(&inner.into_bytes());
}

fn read_uid(bytes: &[u8]) -> Result<Uid, DecodeError> {
    let text = std::str::from_utf8(bytes).map_err(|_| DecodeError("uid is not UTF-8"))?;
    let uid: Uid = text.parse().map_err(|_| DecodeError("not a uid"))?;
    if uid.as_str() != text {
        return Err(DecodeError("uid not in lower case"));
    }
    Ok(uid)
}

fn read_uids(bytes: &[u8]) -> Result<Vec<Uid>, DecodeError> {
    let mut r = Reader::new(bytes);
    let mut uids = Vec::new();
    while r.remaining() > 0 {
        uids.push(read_uid(r.vector()?)?);
    }
    Ok(uids)
}

fn utf8(bytes: &[u8], what: &'static str) -> Result<String, DecodeError> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| DecodeError(what))
}

/// The name of the direct conversation between `a` and `b` (12.4).
fn direct_name(a: &Uid, b: &Uid) -> String {
    let (a, b) = (a.as_str(), b.as_str());
    match a.as_bytes().cmp(b.as_bytes()) {
        std::cmp::Ordering::Equal => a.to_owned(),
        std::cmp::Ordering::Less => format!("{a} {b}"),
        std::cmp::Ordering::Greater => format!("{b} {a}"),
    }
}

/// Whether `host` is a server name in lower case: printable ASCII without
/// spaces or upper case. 12.4 says only "in lower case"; the device also
/// compares it with the server it is on (12.7).
fn host_ok(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= MAX_HOST_LEN
        && host
            .bytes()
            .all(|b| b.is_ascii_graphic() && !b.is_ascii_uppercase())
}

impl RisalaConversation {
    /// The extension of the direct conversation between `a` and `b`, on
    /// `host` with mailbox `mailbox` (12.4). `a` and `b` may be the same
    /// uid, for a conversation with yourself; their order does not matter.
    pub fn direct(host: &str, mailbox: [u8; BOX_LEN], a: &Uid, b: &Uid) -> RisalaConversation {
        RisalaConversation {
            kind: ConversationKind::Direct,
            host: host.to_ascii_lowercase(),
            mailbox,
            name: direct_name(a, b),
            topic: String::new(),
            confirm: ConfirmMode::Pairwise,
            guests: GuestMode::None,
            send: SendMode::All,
            owners: Vec::new(),
            mods: Vec::new(),
            bans: Vec::new(),
        }
    }

    /// The extension of a new private room named `name`, whose only owner
    /// is `creator` (12.4, 6.2): pairwise, no guests, everyone sends.
    pub fn private_room(
        host: &str,
        mailbox: [u8; BOX_LEN],
        name: &str,
        creator: &Uid,
    ) -> RisalaConversation {
        RisalaConversation {
            kind: ConversationKind::PrivateRoom,
            host: host.to_ascii_lowercase(),
            mailbox,
            name: name.to_owned(),
            topic: String::new(),
            confirm: ConfirmMode::Pairwise,
            guests: GuestMode::None,
            send: SendMode::All,
            owners: vec![creator.clone()],
            mods: Vec::new(),
            bans: Vec::new(),
        }
    }

    /// The extension of a new public room `room`, whose only owner is
    /// `creator` (12.4, 6.2): epochal, guests may write, everyone sends.
    pub fn public_room(
        host: &str,
        mailbox: [u8; BOX_LEN],
        room: &Room,
        creator: &Uid,
    ) -> RisalaConversation {
        RisalaConversation {
            kind: ConversationKind::PublicRoom,
            host: host.to_ascii_lowercase(),
            mailbox,
            name: room.as_str().to_owned(),
            topic: String::new(),
            confirm: ConfirmMode::Epochal,
            guests: GuestMode::Write,
            send: SendMode::All,
            owners: vec![creator.clone()],
            mods: Vec::new(),
            bans: Vec::new(),
        }
    }

    /// The extension's data.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(1)
            .u8(kind_value(self.kind))
            .vector(self.host.as_bytes())
            .fixed(&self.mailbox)
            .vector(self.name.as_bytes())
            .vector(self.topic.as_bytes())
            .u8(confirm_value(self.confirm))
            .u8(guests_value(self.guests))
            .u8(send_value(self.send));
        write_uids(&mut w, &self.owners);
        write_uids(&mut w, &self.mods);
        write_uids(&mut w, &self.bans);
        w.into_bytes()
    }

    /// Reads the extension's data: exactly one RisalaConversation of
    /// version 1, with values its enums define, UTF-8 text and uids in
    /// lower case. Whether it is well formed is [`check`](Self::check)'s.
    pub fn decode(bytes: &[u8]) -> Result<RisalaConversation, DecodeError> {
        let mut r = Reader::new(bytes);
        if r.u8()? != 1 {
            return Err(DecodeError("unknown RisalaConversation version"));
        }
        let kind = match r.u8()? {
            1 => ConversationKind::Direct,
            2 => ConversationKind::PrivateRoom,
            3 => ConversationKind::PublicRoom,
            _ => return Err(DecodeError("unknown conversation kind")),
        };
        let host = utf8(r.vector()?, "host is not UTF-8")?;
        let mailbox = r.array::<BOX_LEN>()?;
        let name = utf8(r.vector()?, "name is not UTF-8")?;
        let topic = utf8(r.vector()?, "topic is not UTF-8")?;
        let confirm = match r.u8()? {
            1 => ConfirmMode::Pairwise,
            2 => ConfirmMode::Epochal,
            _ => return Err(DecodeError("unknown confirm mode")),
        };
        let guests = match r.u8()? {
            1 => GuestMode::None,
            2 => GuestMode::Read,
            3 => GuestMode::Write,
            _ => return Err(DecodeError("unknown guest mode")),
        };
        let send = match r.u8()? {
            1 => SendMode::All,
            2 => SendMode::Mods,
            _ => return Err(DecodeError("unknown send mode")),
        };
        let owners = read_uids(r.vector()?)?;
        let mods = read_uids(r.vector()?)?;
        let bans = read_uids(r.vector()?)?;
        r.finish()?;
        Ok(RisalaConversation {
            kind,
            host,
            mailbox,
            name,
            topic,
            confirm,
            guests,
            send,
            owners,
            mods,
            bans,
        })
    }

    /// Checks that the extension is well formed (12.4, 6.2).
    pub fn check(&self) -> Result<(), ConversationError> {
        let invalid = |why| Err(ConversationError::Invalid(why));
        if !host_ok(&self.host) {
            return invalid("host is not a lower-case server name");
        }
        if self.topic.len() > MAX_TOPIC_LEN {
            return invalid("topic longer than 512 bytes");
        }
        for list in [&self.owners, &self.mods, &self.bans] {
            if list.iter().any(Uid::is_guest) {
                return invalid("a guest in owners, mods or bans");
            }
            // 12.4 does not say so, but a list that names a uid twice has
            // no use, and two encodings of the same lists could tell
            // devices apart.
            for (i, uid) in list.iter().enumerate() {
                if list[..i].contains(uid) {
                    return invalid("a uid twice in one list");
                }
            }
        }
        if self.owners.iter().any(|uid| self.mods.contains(uid)) {
            return invalid("a uid in both owners and mods");
        }
        match self.kind {
            ConversationKind::Direct => {
                // "owners holds at least one uid" (12.4) cannot apply here,
                // since the lists of a direct conversation are empty.
                let participants = self.direct_participants();
                if participants.is_none() {
                    return invalid("not the name of a direct conversation");
                }
                if !self.topic.is_empty()
                    || self.confirm != ConfirmMode::Pairwise
                    || self.guests != GuestMode::None
                    || self.send != SendMode::All
                    || !self.owners.is_empty()
                    || !self.mods.is_empty()
                    || !self.bans.is_empty()
                {
                    return invalid("settings a direct conversation does not have");
                }
            }
            ConversationKind::PrivateRoom => {
                if self.name.is_empty() || self.name.len() > MAX_PRIVATE_NAME_LEN {
                    return invalid("private room name not 1 to 128 bytes");
                }
                if self.guests != GuestMode::None {
                    return invalid("guests in a private room");
                }
                if self.owners.is_empty() {
                    return invalid("no owner");
                }
            }
            ConversationKind::PublicRoom => {
                match self.name.parse::<Room>() {
                    Ok(room) if room.as_str() == self.name => {}
                    _ => return invalid("not a room name"),
                }
                if self.confirm != ConfirmMode::Epochal {
                    return invalid("a public room that is not epochal");
                }
                if self.owners.is_empty() {
                    return invalid("no owner");
                }
            }
        }
        Ok(())
    }

    /// The participants of a direct conversation: one uid, or two in byte
    /// order. `None` if the name is not that, or this is a room.
    ///
    /// A participant may be a guest uid: guests may open a direct
    /// conversation with a room's owners and moderators, to report (4.2,
    /// 5.8).
    pub fn direct_participants(&self) -> Option<Vec<Uid>> {
        if self.kind != ConversationKind::Direct {
            return None;
        }
        let parts: Vec<&str> = self.name.split(' ').collect();
        let uids = parts
            .iter()
            .map(|part| read_uid(part.as_bytes()).ok())
            .collect::<Option<Vec<Uid>>>()?;
        match uids.as_slice() {
            [_] => Some(uids),
            [a, b] if a.as_str().as_bytes() < b.as_str().as_bytes() => Some(uids),
            _ => None,
        }
    }

    /// The role of `uid` in a room (6.3). Guests are always plain members.
    pub fn role(&self, uid: &Uid) -> Role {
        if self.owners.contains(uid) {
            Role::Owner
        } else if self.mods.contains(uid) {
            Role::Mod
        } else {
            Role::Member
        }
    }

    /// Whether `uid` is banned (6.4).
    pub fn is_banned(&self, uid: &Uid) -> bool {
        self.bans.contains(uid)
    }

    /// The fields a device compares before it joins a public room again
    /// (12.7, "Rejoining a public room"): those of `owners`, `mods`,
    /// `bans`, `guests`, `send` and `topic` in which `other`, the extension
    /// of the GroupInfo it would join, differs from `self`, the one it
    /// kept. If any differ in a way no commit it checked explains, it MUST
    /// NOT join silently.
    pub fn unexplained_changes(&self, other: &RisalaConversation) -> Vec<&'static str> {
        let mut out = Vec::new();
        if !same_set(&self.owners, &other.owners) {
            out.push("owners");
        }
        if !same_set(&self.mods, &other.mods) {
            out.push("mods");
        }
        if !same_set(&self.bans, &other.bans) {
            out.push("bans");
        }
        if self.guests != other.guests {
            out.push("guests");
        }
        if self.send != other.send {
            out.push("send");
        }
        if self.topic != other.topic {
            out.push("topic");
        }
        out
    }

    /// The extension, for a group context.
    pub fn to_extension(&self) -> Extension {
        Extension::Unknown(CONVERSATION_EXTENSION_TYPE, UnknownExtension(self.encode()))
    }

    /// Reads the extension from a group context's extensions, and checks
    /// that the extensions are exactly what 12.4 says:
    /// `required_capabilities` as [`crate::group::required_capabilities`]
    /// makes it, then a well-formed conversation extension, and nothing
    /// else.
    pub fn from_extensions(
        extensions: &Extensions<GroupContext>,
    ) -> Result<RisalaConversation, ConversationError> {
        let mut iter = extensions.iter();
        let (Some(first), Some(second), None) = (iter.next(), iter.next(), iter.next()) else {
            return Err(match extensions.unknown(CONVERSATION_EXTENSION_TYPE) {
                None => ConversationError::Missing,
                Some(_) => ConversationError::Extensions,
            });
        };
        let Extension::RequiredCapabilities(required) = first else {
            return Err(ConversationError::Extensions);
        };
        if !same_required_capabilities(required, &crate::group::required_capabilities()) {
            return Err(ConversationError::Extensions);
        }
        let Extension::Unknown(CONVERSATION_EXTENSION_TYPE, data) = second else {
            return Err(ConversationError::Missing);
        };
        let conversation = RisalaConversation::decode(&data.0)?;
        conversation.check()?;
        Ok(conversation)
    }

    /// Checks a commit's change from `self`, the extension as of the epoch
    /// the commit is for, to `new`, by a committer with `rights` (6.2, 6.3,
    /// 6.4, 7.8, 12.4, 12.7). Returns whether the change needed the
    /// committer's role.
    ///
    /// This covers the extension alone. That a ban also removes the
    /// identity's leaves, that `guests none` removes the guests', the
    /// 256-member threshold and an impostor repair's restored fields are
    /// checked with the commit (see [`crate::checks`]).
    pub fn check_change(
        &self,
        new: &RisalaConversation,
        rights: &ChangeRights,
    ) -> Result<Change, ChangeError> {
        new.check()?;
        if new.kind != self.kind {
            return Err(ChangeError::Fixed("kind"));
        }
        if new.host != self.host {
            return Err(ChangeError::Fixed("host"));
        }
        if new.mailbox != self.mailbox {
            // A move to a new mailbox (7.8): any member, outside public
            // rooms, in a commit with no other proposal and no other change.
            if self.kind == ConversationKind::PublicRoom {
                return Err(ChangeError::Fixed("box"));
            }
            let mut rest = new.clone();
            rest.mailbox = self.mailbox;
            if !rights.may_move_box || rest != *self {
                return Err(ChangeError::NotAllowed(
                    "a commit that changes the box alone",
                ));
            }
            return Ok(Change { used_role: false });
        }
        let owner = rights.role == Role::Owner;
        let mod_or_owner = rights.role >= Role::Mod;
        let mut used_role = false;
        let mut needs = |allowed: bool, who: &'static str| {
            used_role = true;
            if allowed {
                Ok(())
            } else {
                Err(ChangeError::NotAllowed(who))
            }
        };
        if new.name != self.name {
            if self.kind != ConversationKind::PrivateRoom {
                return Err(ChangeError::Fixed("name"));
            }
            needs(owner, "owners")?;
        }
        if new.topic != self.topic {
            needs(mod_or_owner, "owners and moderators")?;
        }
        if new.guests != self.guests {
            if self.kind != ConversationKind::PublicRoom {
                return Err(ChangeError::Fixed("guests"));
            }
            needs(owner, "owners")?;
        }
        if new.send != self.send {
            needs(owner, "owners")?;
        }
        if new.confirm != self.confirm {
            if !(self.confirm == ConfirmMode::Pairwise && new.confirm == ConfirmMode::Epochal) {
                return Err(ChangeError::Fixed(
                    "confirm, except from pairwise to epochal",
                ));
            }
            // Anyone, in the commit that takes the room past 256 members
            // (6.2).
            if !rights.may_go_epochal {
                needs(owner, "owners")?;
            }
        }
        if !same_set(&new.owners, &self.owners) || !same_set(&new.mods, &self.mods) {
            needs(owner, "owners")?;
        }
        if !same_set(&new.bans, &self.bans) {
            needs(mod_or_owner, "owners and moderators")?;
            // Moderators ban and unban plain members only (6.3, 6.4), by
            // their role as of the epoch the commit is for.
            let added = new.bans.iter().filter(|uid| !self.bans.contains(uid));
            let lifted = self.bans.iter().filter(|uid| !new.bans.contains(uid));
            for uid in added.clone().chain(lifted) {
                if !owner && self.role(uid) != Role::Member {
                    return Err(ChangeError::NotAllowed("owners"));
                }
            }
            // A ban takes the uid out of owners and mods (6.4).
            for uid in added {
                if new.role(uid) != Role::Member {
                    return Err(ChangeError::BanKeepsRole);
                }
            }
        }
        Ok(Change { used_role })
    }
}

/// What a committer may change in the conversation extension (6.2, 6.3,
/// 7.8, 12.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChangeRights {
    /// The committer's role, as of the commit's epoch. A moderator counts
    /// as an owner in a room whose owners have no leaf (6.3).
    pub role: Role,
    /// Whether the commit holds no proposal other than this change, so
    /// that it may move the mailbox, as any member may (7.8).
    pub may_move_box: bool,
    /// Whether the commit takes a private room past 256 members, so that
    /// anyone may change `confirm` to `epochal` in it (6.2).
    pub may_go_epochal: bool,
}

impl ChangeRights {
    /// The rights of a committer with `role`, in an ordinary commit.
    pub fn of_role(role: Role) -> ChangeRights {
        ChangeRights {
            role,
            may_move_box: false,
            may_go_epochal: false,
        }
    }
}

/// A change that [`RisalaConversation::check_change`] allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Change {
    /// Whether only a role allowed it, which makes the commit an authority
    /// commit (12.7).
    pub used_role: bool,
}

fn same_set(a: &[Uid], b: &[Uid]) -> bool {
    a.len() == b.len() && a.iter().all(|uid| b.contains(uid))
}

/// Whether two `required_capabilities` extensions list the same things in
/// the same order.
fn same_required_capabilities(
    a: &RequiredCapabilitiesExtension,
    b: &RequiredCapabilitiesExtension,
) -> bool {
    a.extension_types() == b.extension_types()
        && a.proposal_types() == b.proposal_types()
        && a.credential_types() == b.credential_types()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uid(s: &str) -> Uid {
        s.parse().unwrap()
    }

    const BOX: [u8; 16] = [0xab; 16];

    fn room() -> RisalaConversation {
        let mut conv =
            RisalaConversation::private_room("chat.example.org", BOX, "Friends", &uid("o@x.org"));
        conv.mods.push(uid("m@x.org"));
        conv
    }

    #[test]
    fn direct() {
        let a = uid("bob@example.net");
        let b = uid("alice@example.org");
        let conv = RisalaConversation::direct("Chat.Example.org", BOX, &a, &b);
        assert_eq!(conv.host, "chat.example.org");
        assert_eq!(conv.name, "alice@example.org bob@example.net");
        assert_eq!(
            conv,
            RisalaConversation::direct("chat.example.org", BOX, &b, &a)
        );
        assert_eq!(conv.check(), Ok(()));
        assert_eq!(conv.direct_participants(), Some(vec![b.clone(), a.clone()]));

        let me = RisalaConversation::direct("chat.example.org", BOX, &a, &a);
        assert_eq!(me.name, "bob@example.net");
        assert_eq!(me.direct_participants(), Some(vec![a.clone()]));
        assert_eq!(me.check(), Ok(()));

        // A guest may be a participant (4.2, 5.8).
        let guest = RisalaConversation::direct("chat.example.org", BOX, &uid("~sam"), &b);
        assert_eq!(guest.name, "alice@example.org ~sam");
        assert_eq!(guest.check(), Ok(()));

        for name in [
            "bob@example.net alice@example.org",
            "alice@example.org alice@example.org",
            "alice@example.org  bob@example.net",
            "Alice@example.org",
            "a b c",
            "",
        ] {
            let mut bad = conv.clone();
            bad.name = name.to_owned();
            assert!(bad.check().is_err(), "{name}");
        }
        for change in [
            |c: &mut RisalaConversation| c.topic = "t".into(),
            |c: &mut RisalaConversation| c.confirm = ConfirmMode::Epochal,
            |c: &mut RisalaConversation| c.send = SendMode::Mods,
            |c: &mut RisalaConversation| c.owners.push("a@b.org".parse().unwrap()),
        ] {
            let mut bad = conv.clone();
            change(&mut bad);
            assert!(bad.check().is_err());
        }
    }

    #[test]
    fn encoding() {
        let mut conv = room();
        conv.topic = "hi".into();
        conv.bans.push(uid("b@x.org"));
        let encoded = conv.encode();
        let mut expected = b"\x01\x02\x10chat.example.org".to_vec();
        expected.extend_from_slice(&BOX);
        expected.extend_from_slice(b"\x07Friends\x02hi\x01\x01\x01");
        expected.extend_from_slice(b"\x08\x07o@x.org\x08\x07m@x.org\x08\x07b@x.org");
        assert_eq!(encoded, expected);
        assert_eq!(RisalaConversation::decode(&encoded), Ok(conv.clone()));

        // Every enum value outside its range, and other damage.
        for (offset, value) in [
            (0, 2),
            (1, 0),
            (1, 4),
            (46, 0),
            (46, 3),
            (47, 0),
            (47, 4),
            (48, 3),
        ] {
            let mut bad = encoded.clone();
            bad[offset] = value;
            assert!(RisalaConversation::decode(&bad).is_err(), "{offset}");
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(RisalaConversation::decode(&trailing).is_err());
        assert!(RisalaConversation::decode(&encoded[..encoded.len() - 1]).is_err());
        let mut upper = encoded.clone();
        let at = upper.len() - 7;
        upper[at] = b'B';
        assert!(RisalaConversation::decode(&upper).is_err());
    }

    #[test]
    fn well_formed_rooms() {
        assert_eq!(room().check(), Ok(()));
        let public = RisalaConversation::public_room(
            "chat.example.org",
            BOX,
            &"#general".parse().unwrap(),
            &uid("o@x.org"),
        );
        assert_eq!(public.check(), Ok(()));
        assert_eq!(public.guests, GuestMode::Write);

        type Change = fn(&mut RisalaConversation);
        let checks: [(Change, bool); 11] = [
            (|c| c.owners.clear(), true),
            (|c| c.mods.push("o@x.org".parse().unwrap()), true),
            (|c| c.bans.push("~sam".parse().unwrap()), true),
            (|c| c.mods.push("m@x.org".parse().unwrap()), true),
            (|c| c.topic = "x".repeat(513), true),
            (|c| c.topic = "x".repeat(512), false),
            (|c| c.host = "Chat.example.org".into(), true),
            (|c| c.host = String::new(), true),
            (|c| c.name = String::new(), true),
            (|c| c.name = "x".repeat(129), true),
            (|c| c.guests = GuestMode::Read, true),
        ];
        for (i, (change, fails)) in checks.iter().enumerate() {
            let mut conv = room();
            change(&mut conv);
            assert_eq!(conv.check().is_err(), *fails, "{i}");
        }
        let mut bad = public.clone();
        bad.confirm = ConfirmMode::Pairwise;
        assert!(bad.check().is_err());
        let mut bad = public.clone();
        bad.name = "general".into();
        assert!(bad.check().is_err());
    }

    #[test]
    fn roles_and_changes() {
        let old = room();
        let (owner, moderator, member) = (uid("o@x.org"), uid("m@x.org"), uid("p@x.org"));
        assert_eq!(old.role(&owner), Role::Owner);
        assert_eq!(old.role(&moderator), Role::Mod);
        assert_eq!(old.role(&member), Role::Member);

        let ok = |change: fn(&mut RisalaConversation), who: &Uid| {
            let mut new = old.clone();
            change(&mut new);
            old.check_change(&new, &ChangeRights::of_role(old.role(who)))
                .map(|_| ())
        };
        // Topic: owners and moderators.
        let topic = |c: &mut RisalaConversation| c.topic = "new".into();
        assert_eq!(ok(topic, &owner), Ok(()));
        assert_eq!(ok(topic, &moderator), Ok(()));
        assert!(ok(topic, &member).is_err());
        // Name, send, confirm and roles: owners.
        for change in [
            (|c: &mut RisalaConversation| c.name = "Other".into()) as fn(&mut _),
            |c| c.send = SendMode::Mods,
            |c| c.confirm = ConfirmMode::Epochal,
            |c| c.mods.push("p@x.org".parse().unwrap()),
            |c| c.owners.push("p@x.org".parse().unwrap()),
        ] {
            assert_eq!(ok(change, &owner), Ok(()));
            assert!(ok(change, &moderator).is_err());
        }
        // Bans: moderators only of plain members.
        let ban_member = |c: &mut RisalaConversation| c.bans.push("p@x.org".parse().unwrap());
        let ban_mod = |c: &mut RisalaConversation| {
            c.bans.push("m@x.org".parse().unwrap());
            c.mods.clear();
        };
        assert_eq!(ok(ban_member, &moderator), Ok(()));
        assert!(ok(ban_member, &member).is_err());
        assert!(ok(ban_mod, &moderator).is_err());
        assert_eq!(ok(ban_mod, &owner), Ok(()));
        // A ban takes the uid out of owners and mods (6.4).
        let ban_keeping_role = |c: &mut RisalaConversation| c.bans.push("m@x.org".parse().unwrap());
        assert_eq!(ok(ban_keeping_role, &owner), Err(ChangeError::BanKeepsRole));
        // Never kind, host or box; confirm only to epochal; not the last
        // owner; guests only in public rooms.
        for change in [
            (|c: &mut RisalaConversation| c.kind = ConversationKind::PublicRoom) as fn(&mut _),
            |c| c.host = "other.org".into(),
            |c| c.mailbox = [0; 16],
            |c| c.owners.clear(),
            |c| c.guests = GuestMode::Read,
        ] {
            assert!(ok(change, &owner).is_err());
        }
        let mut epochal = old.clone();
        epochal.confirm = ConfirmMode::Epochal;
        let as_owner = ChangeRights::of_role(Role::Owner);
        assert!(epochal.check_change(&old, &as_owner).is_err());

        let public = RisalaConversation::public_room(
            "chat.example.org",
            BOX,
            &"#general".parse().unwrap(),
            &owner,
        );
        let mut renamed = public.clone();
        renamed.name = "#other".into();
        assert_eq!(
            public.check_change(&renamed, &as_owner),
            Err(ChangeError::Fixed("name"))
        );
        let mut read = public.clone();
        read.guests = GuestMode::Read;
        assert_eq!(
            public.check_change(&read, &as_owner),
            Ok(Change { used_role: true })
        );
    }

    /// Moving the mailbox (7.8): any member, alone in its commit, outside
    /// public rooms.
    #[test]
    fn mailbox_moves() {
        let old = room();
        let mut moved = old.clone();
        moved.mailbox = [0x11; 16];
        let member = ChangeRights {
            may_move_box: true,
            ..ChangeRights::of_role(Role::Member)
        };
        assert_eq!(
            old.check_change(&moved, &member),
            Ok(Change { used_role: false })
        );
        // Not with another proposal, nor with another change.
        assert!(
            old.check_change(&moved, &ChangeRights::of_role(Role::Owner))
                .is_err()
        );
        let mut and_topic = moved.clone();
        and_topic.topic = "x".into();
        assert!(old.check_change(&and_topic, &member).is_err());
        let public = RisalaConversation::public_room(
            "chat.example.org",
            BOX,
            &"#general".parse().unwrap(),
            &uid("o@x.org"),
        );
        let mut moved = public.clone();
        moved.mailbox = [0x11; 16];
        assert_eq!(
            public.check_change(&moved, &member),
            Err(ChangeError::Fixed("box"))
        );
    }

    /// Anyone moves a room to epochal in the commit that takes it past 256
    /// members (6.2); otherwise owners only.
    #[test]
    fn forced_epochal() {
        let old = room();
        let mut epochal = old.clone();
        epochal.confirm = ConfirmMode::Epochal;
        let member = ChangeRights::of_role(Role::Member);
        assert!(old.check_change(&epochal, &member).is_err());
        let crossing = ChangeRights {
            may_go_epochal: true,
            ..member
        };
        assert_eq!(
            old.check_change(&epochal, &crossing),
            Ok(Change { used_role: false })
        );
    }
}
