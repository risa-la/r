//! Values shared by several areas of the API. Each area's own values are
//! in its module.

use std::fmt;

pub use crate::addr::ServerAddr;
pub use crate::store::conversations::ConversationId;
pub use crate::store::{AccountId, AccountKind};
pub use risala_proto::names::{BoxName, Room, Uid};
pub use risala_proto::time::Timestamp;

/// A device's id: the SHA-384 hash of its device key (4.4).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DeviceId(pub [u8; 48]);

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceId({self})")
    }
}

impl fmt::Display for DeviceId {
    /// The first 8 bytes in hex, enough to tell devices apart on screen.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0[..8] {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// A message's id within its group: 16 random bytes (12.9).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MessageId(pub [u8; 16]);

impl fmt::Debug for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MessageId({self})")
    }
}

impl fmt::Display for MessageId {
    /// In hex.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// An account, as the API shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    /// Its id.
    pub id: AccountId,
    /// The server.
    pub server: ServerAddr,
    /// Identity or guest.
    pub kind: AccountKind,
    /// The identity, or the guest uid asked for (`~<name>`).
    pub uid: Uid,
}

impl From<crate::store::AccountRow> for Account {
    fn from(row: crate::store::AccountRow) -> Account {
        Account {
            id: row.id,
            server: row.server,
            kind: row.kind,
            uid: row.uid,
        }
    }
}

/// What an account has still to get to its servers
/// ([`Client::unsettled`](crate::Client::unsettled)), for tools that
/// connect, act and stop.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Unsettled {
    /// Posts and commits queued, in flight or not yet seen back.
    pub outbox: usize,
    /// Of `outbox`, the messages queued in conversations whose sending is
    /// held ([`SendingHold`]). They go once the hold ends: held is not
    /// failed.
    pub held: usize,
    /// Welcomes not yet sent (12.8).
    pub welcomes: usize,
    /// Whether the identity has records its log does not hold yet: KEYS
    /// PUT is still to succeed (4.7).
    pub records: bool,
    /// Whether this device's KeyPackages are still to be counted or
    /// uploaded since it signed in, or failed to be (12.5). Known only
    /// while the account is connected; `false` otherwise.
    pub key_packages: bool,
    /// History transfers other devices asked for with WANT and not yet
    /// sent (12.13).
    pub transfers: usize,
}

impl Unsettled {
    /// Whether nothing is left.
    pub fn is_empty(&self) -> bool {
        *self == Unsettled::default()
    }
}

/// Why a conversation sends no messages for now (12.7)
/// ([`Client::sending_hold`](crate::Client::sending_hold)). Messages
/// queued meanwhile wait, and go once the hold ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendingHold {
    /// A leaf of `uid` that this device could not check yet, since it
    /// waits for the identity's key file: at most 2 hours, after which the
    /// check fails and the leaf is removed (12.7).
    KeyCheck {
        /// The identity of the leaf.
        uid: Uid,
    },
    /// A leaf of `uid` failed its key check, and its removal is still to
    /// be queued. The removal goes first, then the messages (12.7).
    Repair {
        /// The identity of the leaf.
        uid: Uid,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_show_as_hex() {
        assert_eq!(MessageId([0xab; 16]).to_string(), "ab".repeat(16));
        let mut d = [0; 48];
        d[0] = 1;
        assert_eq!(DeviceId(d).to_string(), "0100000000000000");
    }
}
