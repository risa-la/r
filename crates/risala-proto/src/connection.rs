//! Kinds of connection (SPEC 4.1, Section 13): new, anonymous, guest and
//! signed in, and what each may send.
//!
//! A connection starts [`New`](ConnectionKind::New) and becomes one of
//! the other three kinds once, with ANON, GUEST, AUTH or REGISTER, then
//! stays that kind until it closes. Which commands each kind may send is
//! the table in Section 13, answered by
//! [`Command::check_kind`](crate::command::Command::check_kind); the line
//! limits a server applies to it are [`ConnectionKind::client_limits`].

use std::fmt;

use crate::error::ErrorCode;
use crate::frame::LineLimits;

/// The kind of a connection (4.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConnectionKind {
    /// Has not yet become anonymous, a guest or signed in. It may send
    /// only INFO without a room, ANON, GUEST, AUTH, REGISTER, KEYS PUT,
    /// PAIR, PING, PONG and QUIT.
    New,
    /// Became anonymous with ANON (4.2). Used for conversations: posting,
    /// following and fetching.
    Anonymous,
    /// Became a guest with GUEST (4.2): like an anonymous connection, with
    /// a guest name for public rooms.
    Guest,
    /// Signed in with AUTH or REGISTER (4.6, 4.7), for an identity and one
    /// of its devices. Used for what belongs to the account.
    SignedIn,
}

impl ConnectionKind {
    /// Every kind, in the order of the columns of Section 13.
    pub const ALL: [ConnectionKind; 4] = [
        ConnectionKind::New,
        ConnectionKind::Anonymous,
        ConnectionKind::Guest,
        ConnectionKind::SignedIn,
    ];

    /// The limits a server applies to lines from a connection of this
    /// kind (2.3): the normal limit, and 64 KiB for REGISTER, KEYS and
    /// PAIR, on a new connection; long lines for the long verbs
    /// otherwise.
    pub const fn client_limits(self) -> LineLimits {
        match self {
            ConnectionKind::New => LineLimits::NEW_CONNECTION,
            _ => LineLimits::CLIENT,
        }
    }

    /// The error for a command that this kind may not send, but another
    /// kind may (3.7, 4.1, Section 13): `not-authenticated` for a new
    /// connection, `wrong-connection` otherwise.
    ///
    /// ANON, GUEST, AUTH and REGISTER on a connection that already has a
    /// kind get `already-authenticated` instead (3.7), which
    /// [`Command::check_kind`](crate::command::Command::check_kind) says.
    pub const fn refusal(self) -> ErrorCode {
        match self {
            ConnectionKind::New => ErrorCode::NotAuthenticated,
            _ => ErrorCode::WrongConnection,
        }
    }

    /// The kind's name, as in Section 13's table: `new`, `anonymous`,
    /// `guest` or `signed in`.
    pub const fn as_str(self) -> &'static str {
        match self {
            ConnectionKind::New => "new",
            ConnectionKind::Anonymous => "anonymous",
            ConnectionKind::Guest => "guest",
            ConnectionKind::SignedIn => "signed in",
        }
    }
}

impl fmt::Display for ConnectionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A set of [`ConnectionKind`]s: the kinds that may send a command
/// (Section 13).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Kinds(u8);

impl Kinds {
    /// No kind.
    pub const NONE: Kinds = Kinds(0);
    /// New connections only.
    pub const NEW: Kinds = Kinds(1);
    /// Anonymous connections only.
    pub const ANONYMOUS: Kinds = Kinds(2);
    /// Guests only.
    pub const GUEST: Kinds = Kinds(4);
    /// Signed-in connections only.
    pub const SIGNED_IN: Kinds = Kinds(8);
    /// Every kind.
    pub const ALL: Kinds = Kinds(15);

    /// The set of one kind.
    pub const fn of(kind: ConnectionKind) -> Kinds {
        match kind {
            ConnectionKind::New => Kinds::NEW,
            ConnectionKind::Anonymous => Kinds::ANONYMOUS,
            ConnectionKind::Guest => Kinds::GUEST,
            ConnectionKind::SignedIn => Kinds::SIGNED_IN,
        }
    }

    /// The union of two sets.
    pub const fn or(self, other: Kinds) -> Kinds {
        Kinds(self.0 | other.0)
    }

    /// Whether the set holds `kind`.
    pub const fn contains(self, kind: ConnectionKind) -> bool {
        self.0 & Kinds::of(kind).0 != 0
    }

    /// Whether the set is empty.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The kinds in the set, in the order of [`ConnectionKind::ALL`].
    pub fn iter(self) -> impl Iterator<Item = ConnectionKind> {
        ConnectionKind::ALL
            .into_iter()
            .filter(move |&k| self.contains(k))
    }
}

impl std::ops::BitOr for Kinds {
    type Output = Kinds;

    fn bitor(self, other: Kinds) -> Kinds {
        self.or(other)
    }
}

impl fmt::Debug for Kinds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{MAX_CLIENT_LINE, MAX_LONG_CLIENT_LINE, MAX_REGISTER_LINE};

    #[test]
    fn limits_by_kind() {
        let new = ConnectionKind::New.client_limits();
        assert_eq!(new.for_verb("REGISTER"), MAX_REGISTER_LINE);
        assert_eq!(new.for_verb("POST"), MAX_CLIENT_LINE);
        for kind in [
            ConnectionKind::Anonymous,
            ConnectionKind::Guest,
            ConnectionKind::SignedIn,
        ] {
            let limits = kind.client_limits();
            assert_eq!(limits.for_verb("POST"), MAX_LONG_CLIENT_LINE);
            assert_eq!(limits.for_verb("REGISTER"), MAX_CLIENT_LINE);
        }
    }

    #[test]
    fn refusals() {
        assert_eq!(ConnectionKind::New.refusal(), ErrorCode::NotAuthenticated);
        for kind in [
            ConnectionKind::Anonymous,
            ConnectionKind::Guest,
            ConnectionKind::SignedIn,
        ] {
            assert_eq!(kind.refusal(), ErrorCode::WrongConnection);
        }
    }

    #[test]
    fn sets() {
        let set = Kinds::ANONYMOUS | Kinds::GUEST;
        assert!(set.contains(ConnectionKind::Anonymous));
        assert!(set.contains(ConnectionKind::Guest));
        assert!(!set.contains(ConnectionKind::New));
        assert!(!set.contains(ConnectionKind::SignedIn));
        assert_eq!(
            set.iter().collect::<Vec<_>>(),
            [ConnectionKind::Anonymous, ConnectionKind::Guest]
        );
        assert_eq!(format!("{set:?}"), "{Anonymous, Guest}");
        assert!(Kinds::NONE.is_empty());
        for kind in ConnectionKind::ALL {
            assert!(Kinds::ALL.contains(kind));
            assert_eq!(Kinds::of(kind).iter().collect::<Vec<_>>(), [kind]);
        }
    }
}
