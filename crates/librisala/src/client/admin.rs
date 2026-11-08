//! Server administration (Section 10): [`Admin`], the ADMIN commands of an
//! operator, from [`Account::admin`].
//!
//! Anyone who is not an operator gets `forbidden` for every one of them,
//! as [`ClientError::Server`]. An identity learns that it is an operator
//! from `op=yes` when it signs in (4.5); the server may also leave out
//! commands that do not apply to it, with `not-supported`. Each command
//! needs a connection.
//!
//! Operators also have owner rights in every room through the ordinary
//! commands ([`Conversation`](super::Conversation)'s
//! [`kick`](super::Conversation::kick), [`ban`](super::Conversation::ban)
//! and the rest), and see reports with their reporters (5.8).

use std::num::NonZeroU64;

use risala_proto::auth::PublicKey;
use risala_proto::command::{AdminCommand, Command, RoomPage};
use risala_proto::names::{Room, ServerBanTarget};
use risala_proto::server::ServerLine;
use risala_proto::text::{escape, unescape};
use risala_proto::types::ServerSetting;

use super::account::{Account, parse_room};
use super::blocking;
use super::rooms::{missing, parse_uid};
use super::types::{
    ClientError, ConnectionInfo, KeyInfo, ReportInfo, RoomList, RoomListing, ServerBanInfo,
};

/// The ADMIN commands of an operator (Section 10), for one account. See
/// the [module docs](self).
///
/// Cloning it is cheap.
#[derive(Debug, Clone)]
pub struct Admin {
    account: Account,
}

impl Account {
    /// The ADMIN commands (Section 10), sent as this account. They work
    /// only for an operator.
    pub fn admin(&self) -> Admin {
        Admin {
            account: self.clone(),
        }
    }
}

fn parse_ban_target(target: &str) -> Result<ServerBanTarget, ClientError> {
    target
        .trim()
        .parse()
        .map_err(|_| ClientError::Invalid(format!("ban target {target:?}")))
}

/// A key given as a key file line or the key alone (4.4).
fn parse_key(key: &str) -> Result<PublicKey, ClientError> {
    super::identity::parse_public_key(key).map(|(key, _)| key)
}

impl Admin {
    /// The account it acts as.
    pub fn account(&self) -> Account {
        self.account.clone()
    }

    async fn run(&self, command: AdminCommand) -> Result<super::account::Answer, ClientError> {
        self.account.request(Command::Admin(command)).await
    }

    /// The server's operators (ADMIN OPS, 10.1), in the order sent.
    pub async fn operators(&self) -> Result<Vec<String>, ClientError> {
        let answer = self.run(AdminCommand::Ops).await?;
        Ok(answer
            .lines
            .iter()
            .filter_map(|m| match &m.line {
                ServerLine::Op { uid } => Some(uid.to_string()),
                _ => None,
            })
            .collect())
    }

    /// Makes an identity an operator (ADMIN OP, 10.1). Guests cannot be.
    pub async fn add_operator(&self, uid: &str) -> Result<(), ClientError> {
        let uid = parse_uid(uid)?;
        self.run(AdminCommand::Op { uid }).await?;
        Ok(())
    }

    /// Removes an operator (ADMIN DEOP, 10.1). Those named in the server's
    /// configuration cannot be removed: `forbidden`.
    pub async fn remove_operator(&self, uid: &str) -> Result<(), ClientError> {
        let uid = parse_uid(uid)?;
        self.run(AdminCommand::Deop { uid }).await?;
        Ok(())
    }

    /// Bans across the whole server (ADMIN BAN, 10.2). `target` is an
    /// identity (`spam@example.net`), a domain with its subdomains
    /// (`*@example.net`), a connected guest (`~sam`, which bans its
    /// address and closes its connection), or an address or prefix
    /// (`203.0.113.7`, `2001:db8::/32`), which stops guests only.
    pub async fn ban(&self, target: &str, reason: &str) -> Result<(), ClientError> {
        let target = parse_ban_target(target)?;
        let reason = escape(reason.trim());
        self.run(AdminCommand::Ban { target, reason }).await?;
        Ok(())
    }

    /// Lifts a server-wide ban (ADMIN UNBAN, 10.2).
    pub async fn unban(&self, target: &str) -> Result<(), ClientError> {
        let target = parse_ban_target(target)?;
        self.run(AdminCommand::Unban { target }).await?;
        Ok(())
    }

    /// The server-wide bans (ADMIN BANS, 10.2), in the order sent. A
    /// guest's ban is listed under its address.
    pub async fn bans(&self) -> Result<Vec<ServerBanInfo>, ClientError> {
        let answer = self.run(AdminCommand::Bans).await?;
        Ok(answer
            .lines
            .iter()
            .filter_map(|m| match &m.line {
                ServerLine::ServerBan { target, reason } => Some(ServerBanInfo {
                    target: target.to_string(),
                    reason: unescape(reason).into_owned(),
                }),
                _ => None,
            })
            .collect())
    }

    /// Every open connection (ADMIN WHO, 10.3), in the order sent.
    pub async fn connections(&self) -> Result<Vec<ConnectionInfo>, ClientError> {
        let answer = self.run(AdminCommand::Who).await?;
        Ok(answer
            .lines
            .iter()
            .filter_map(|m| match &m.line {
                ServerLine::Connection {
                    uid,
                    address,
                    port,
                    since,
                } => Some(ConnectionInfo {
                    uid: uid.as_ref().map(ToString::to_string),
                    address: address.to_string(),
                    port: *port,
                    since_ms: since.unix_millis(),
                    since: since.to_string(),
                }),
                _ => None,
            })
            .collect())
    }

    /// Closes every connection of `uid`, with BYE and the reason (ADMIN
    /// DISCONNECT, 10.3). They can reconnect; ban them to stop that.
    pub async fn disconnect(&self, uid: &str, reason: &str) -> Result<(), ClientError> {
        let uid = parse_uid(uid)?;
        let reason = escape(reason.trim());
        self.run(AdminCommand::Disconnect { uid, reason }).await?;
        Ok(())
    }

    /// Sends a NOTICE to every open connection (ADMIN NOTICE, 10.3), this
    /// one included.
    pub async fn notice(&self, message: &str) -> Result<(), ClientError> {
        let message = escape(message.trim());
        self.run(AdminCommand::Notice { message }).await?;
        Ok(())
    }

    /// One page of every room, private ones too (ADMIN ROOMS, 10.4), in
    /// byte order of name, after the room `after` if given. It pages like
    /// [`Account::list_rooms`].
    pub async fn rooms(
        &self,
        after: Option<String>,
        limit: Option<u64>,
    ) -> Result<RoomList, ClientError> {
        let after = after.map(|a| parse_room(&a)).transpose()?;
        let answer = self
            .run(AdminCommand::Rooms(RoomPage {
                after,
                limit: limit.and_then(NonZeroU64::new),
            }))
            .await?;
        let rooms = answer
            .lines
            .iter()
            .filter_map(|m| match &m.line {
                ServerLine::Room {
                    room,
                    members,
                    topic,
                } => Some(RoomListing {
                    room: room.to_string(),
                    members: *members,
                    topic: unescape(topic).into_owned(),
                }),
                _ => None,
            })
            .collect();
        Ok(RoomList {
            rooms,
            more: answer.ok.more().ok().flatten().unwrap_or(false),
        })
    }

    /// Deletes a room with all its events (ADMIN DROP, 10.4). This cannot
    /// be undone. Members are removed as if kicked, and the room's open
    /// reports stay. If the account is in the room, the cache removes it
    /// too, with [`Notice::Dropped`](super::Notice::Dropped).
    pub async fn drop_room(&self, room: &str, reason: &str) -> Result<(), ClientError> {
        let room: Room = parse_room(room)?;
        let reason = escape(reason.trim());
        self.run(AdminCommand::Drop { room, reason }).await?;
        Ok(())
    }

    /// Deletes the messages `uid` has sent, in every conversation, each as
    /// DELETE would (ADMIN PURGE, 10.4); only those of the last `hours`
    /// hours if given. Returns how many were deleted.
    pub async fn purge(&self, uid: &str, hours: Option<u64>) -> Result<u64, ClientError> {
        let uid = parse_uid(uid)?;
        let hours = match hours {
            None => None,
            Some(h) => {
                Some(NonZeroU64::new(h).ok_or_else(|| ClientError::Invalid("hours 0".into()))?)
            }
        };
        let answer = self.run(AdminCommand::Purge { uid, hours }).await?;
        answer
            .ok
            .deleted()
            .ok()
            .flatten()
            .ok_or_else(|| missing("deleted"))
    }

    /// Every open report on the server, in rooms and direct conversations
    /// (ADMIN REPORTS, 5.8, 10.4), with their reporters.
    pub async fn reports(&self) -> Result<Vec<ReportInfo>, ClientError> {
        let answer = self.run(AdminCommand::Reports).await?;
        Ok(ReportInfo::from_lines(&answer.lines))
    }

    /// The keys of an identity the server hosts (ADMIN KEYS, 10.5).
    /// `this_device` is set on this device's own key for that identity.
    pub async fn keys(&self, uid: &str) -> Result<Vec<KeyInfo>, ClientError> {
        let uid = parse_uid(uid)?;
        // A platform key store may block, waiting for the user.
        let client = self.account.client();
        let id = uid.to_string();
        let mine = blocking(&self.account.shared().rt, move || {
            client.device_key(&id).ok().flatten().map(|k| k.public_key)
        })
        .await;
        let answer = self.run(AdminCommand::Keys { uid }).await?;
        Ok(answer
            .lines
            .iter()
            .filter_map(|m| match &m.line {
                ServerLine::Key { key, label } => Some(KeyInfo {
                    public_key: key.to_string(),
                    label: unescape(label).into_owned(),
                    fingerprint: key.fingerprint().to_string(),
                    this_device: mine.as_deref() == Some(key.to_string().as_str()),
                }),
                _ => None,
            })
            .collect())
    }

    /// Adds a key to an identity the server hosts (ADMIN ADDKEY, 10.5), for
    /// someone who lost all their keys. `key` is a key file line or the key
    /// alone; `label` names the device.
    pub async fn add_key(&self, uid: &str, key: &str, label: &str) -> Result<(), ClientError> {
        let uid = parse_uid(uid)?;
        let key = parse_key(key)?;
        let label = escape(label.trim());
        self.run(AdminCommand::AddKey { uid, key, label }).await?;
        Ok(())
    }

    /// Removes a key from an identity the server hosts (ADMIN DELKEY,
    /// 10.5). It may remove the last one, which locks the identity.
    pub async fn remove_key(&self, uid: &str, key: &str) -> Result<(), ClientError> {
        let uid = parse_uid(uid)?;
        let key = parse_key(key)?;
        self.run(AdminCommand::DelKey { uid, key }).await?;
        Ok(())
    }

    /// Deletes an identity the server hosts (ADMIN UNREGISTER, 10.5), as
    /// UNREGISTER without `purge` does. Its messages stay unless purged.
    pub async fn unregister(&self, uid: &str) -> Result<(), ClientError> {
        let uid = parse_uid(uid)?;
        self.run(AdminCommand::Unregister { uid }).await?;
        Ok(())
    }

    /// Changes a server setting (ADMIN SET, 10.6): `guests` (`yes` or
    /// `no`), `registration` (`open` or `closed`), `retention` (days or
    /// `forever`) or `welcome` (text). It takes effect at once, and
    /// [`Account::server_info`] shows it. A known key with a bad value
    /// fails with [`ClientError::Invalid`] before anything is sent.
    pub async fn set(&self, key: &str, value: &str) -> Result<(), ClientError> {
        let setting = ServerSetting::parse(key.trim(), &escape(value))
            .map_err(|e| ClientError::Invalid(format!("setting {key}: {e}")))?;
        self.run(AdminCommand::Set(setting)).await?;
        Ok(())
    }
}
