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
