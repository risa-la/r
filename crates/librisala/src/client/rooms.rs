//! Running rooms (5.8, 6.2-6.4, 8.5), as methods of [`Account`] and
//! [`Conversation`].
//!
//! - **Settings** (6.2). [`Conversation::set_setting`] and
//!   [`Conversation::set_topic`] change one; the SET event shows in the
//!   timeline, and the cache keeps the room's settings, from SET events and
//!   from the snapshot SET lines of JOIN and INFO:
//!   [`ConversationInfo::settings`](super::ConversationInfo::settings).
//!   [`Conversation::room_info`] asks the server (INFO).
//! - **Roles** (6.3). [`Conversation::set_role`] and [`Conversation::roles`].
//! - **Moderation** (6.4). [`Conversation::invite`], [`Conversation::kick`],
//!   [`Conversation::ban`], [`Conversation::unban`] and
//!   [`Conversation::bans`]. Being invited, kicked or banned yourself
//!   arrives as [`Notice::Invited`](super::Notice::Invited),
//!   [`Notice::Kicked`](super::Notice::Kicked) and
//!   [`Notice::Banned`](super::Notice::Banned), not as history.
//! - **Deleting** (5.4). [`Conversation::delete`], through the outbox.
//! - **Reports** (5.8). [`Conversation::report`] reports a message.
//!   Reviewers (a room's owners and moderators, and operators) receive
//!   reports live as [`AccountEvent::Report`], list them with
//!   [`Conversation::reports`] or [`Admin::reports`](super::Admin::reports),
//!   and close them with [`Account::resolve_report`]; another reviewer's
//!   resolution arrives as [`AccountEvent::ReportResolved`]. Reports are
//!   never stored as events.
//!
//! Commands that record an event answer once the event has been handled,
//! so the timeline shows it by then. They return its seq; SET, ROLE, BAN
//! and INVITE return `None` when they change nothing and so record
//! nothing. Each needs a
//! connection; the server's refusals are [`ClientError::Server`], with
//! codes such as `forbidden`, `not-found` or `last-owner`.

use risala_proto::command::Command;
use risala_proto::names::{Id, Seq, Uid};
use risala_proto::server::{EventBody, OkResponse, Register, ServerLine, Upload};
use risala_proto::text::{escape, unescape};
use risala_proto::types::{Role, RoomSetting};

use super::account::{Account, Answer, Conversation, RequestOp};
use super::types::{BanInfo, ClientError, ReportInfo, RoleInfo, RoomInfo, ServerInfo, Setting};

#[cfg(doc)]
use super::types::AccountEvent;

pub(crate) fn parse_uid(uid: &str) -> Result<Uid, ClientError> {
    uid.trim()
        .parse()
        .map_err(|_| ClientError::Invalid(format!("uid {uid:?}")))
}

/// An `OK` that lacks a value the command promises: the server broke the
/// protocol.
pub(crate) fn missing(what: &str) -> ClientError {
    ClientError::BadAnswer(format!("the server's OK has no {what}"))
}

/// The `seq` of an `OK seq=<seq>`.
pub(crate) fn seq_of(ok: &OkResponse) -> Result<u64, ClientError> {
    seq_if_any(ok).ok_or_else(|| missing("seq"))
}

/// The `seq` of an `OK` that may have none: commands that record nothing
/// when they change nothing answer a plain `OK` (6.2-6.4).
fn seq_if_any(ok: &OkResponse) -> Option<u64> {
    ok.seq().ok().flatten().map(Seq::get)
}

impl Conversation {
    /// Asks the server about the room (INFO, 6.2): its id, members, head,
    /// the account's role and its settings. If the account is a member, the
    /// cache learns the settings and checks the room's id (7.1). Someone
    /// invited to a private room may see its INFO before joining. Needs a
    /// connection.
    pub async fn room_info(&self) -> Result<RoomInfo, ClientError> {
        let room = self.room()?;
        let Answer { lines, ok } = self
            .account()
            .request_op(RequestOp::Info(room.clone()))
            .await?;
        let settings = lines
            .iter()
            .filter_map(|m| match &m.line {
                ServerLine::Event(e) if e.is_snapshot() => match &e.body {
                    EventBody::Set { room: r, setting } if *r == room => Some(Setting {
                        key: setting.key().to_owned(),
                        value: unescape(&setting.value()).into_owned(),
                    }),
                    _ => None,
                },
                _ => None,
            })
            .collect();
        Ok(RoomInfo {
            room: room.to_string(),
            id: ok
                .id()
                .ok()
                .flatten()
                .ok_or_else(|| missing("id"))?
                .to_string(),
            members: ok.members().ok().flatten().unwrap_or(0),
            head: ok.head().ok().flatten().unwrap_or(0),
            role: ok
                .role()
                .ok()
                .flatten()
                .map_or_else(|| "none".to_owned(), |r| r.to_string()),
            joined: ok.joined().ok().flatten().unwrap_or(false),
            settings,
        })
    }

    /// Changes a room setting (SET, 6.2), such as `public` to `no`, and
    /// returns the SET event's seq, or `None` if the setting had that
    /// value already, when nothing is recorded. `value` is plain text: a keyword or a
    /// number (`yes`, `read`, `30`, `server`), or the topic. Moderators
    /// may set the topic; owners the rest. An unknown key goes to the
    /// server as it is, which answers `not-supported`; a known key with a
    /// bad value fails with [`ClientError::Invalid`] before anything is
    /// sent.
    pub async fn set_setting(&self, key: &str, value: &str) -> Result<Option<u64>, ClientError> {
        let room = self.room()?;
        let setting = RoomSetting::parse(key.trim(), &escape(value))
            .map_err(|e| ClientError::Invalid(format!("setting {key}: {e}")))?;
        let answer = self
            .account()
            .request(Command::Set { room, setting })
            .await?;
        Ok(seq_if_any(&answer.ok))
    }

    /// Sets the room's topic, or clears it with an empty one (6.2). Returns
    /// the SET event's seq, or `None` if the topic was that already.
    pub async fn set_topic(&self, topic: &str) -> Result<Option<u64>, ClientError> {
        self.set_setting("topic", topic).await
    }

    /// Sets `uid`'s role in the room (ROLE, 6.3): `owner`, `mod` or
    /// `member`. Owners only. Returns the ROLE event's seq, or `None` if
    /// they had that role already, when nothing is recorded. The room's
    /// only owner cannot change their own role (`last-owner`).
    pub async fn set_role(&self, uid: &str, role: &str) -> Result<Option<u64>, ClientError> {
        let room = self.room()?;
        let uid = parse_uid(uid)?;
        let role: Role = role
            .trim()
            .parse()
            .map_err(|_| ClientError::Invalid(format!("role {role:?}")))?;
        let answer = self
            .account()
            .request(Command::Role { room, uid, role })
            .await?;
        Ok(seq_if_any(&answer.ok))
    }

    /// The room's owners and moderators, whether or not they are members
    /// now (ROLES, 6.3), in the order the server sent them. Needs a
    /// connection; [`cached_members`](Self::cached_members) has the roles
    /// of the members the cache knows.
    pub async fn roles(&self) -> Result<Vec<RoleInfo>, ClientError> {
        let room = self.room()?;
        let answer = self
            .account()
            .request(Command::Roles { room: room.clone() })
            .await?;
        Ok(answer
            .lines
            .iter()
            .filter_map(|m| match &m.line {
                ServerLine::Event(e) => match &e.body {
                    EventBody::Role { room: r, uid, role } if *r == room => Some(RoleInfo {
                        uid: uid.to_string(),
                        role: role.to_string(),
                    }),
                    _ => None,
                },
                _ => None,
            })
            .collect())
    }

    /// Invites `uid` to the room (INVITE, 6.4), which lets an identity
    /// join a private room. Moderators and owners. Returns the INVITE
    /// event's seq, or `None` if they are a member already, when nothing
    /// is recorded.
    pub async fn invite(&self, uid: &str) -> Result<Option<u64>, ClientError> {
        let room = self.room()?;
        let uid = parse_uid(uid)?;
        let answer = self
            .account()
            .request(Command::Invite { room, uid })
            .await?;
        Ok(seq_if_any(&answer.ok))
    }

    /// Removes a member from the room (KICK, 6.4); they may join again.
    /// Returns the KICK event's seq. Someone who is not a member gets
    /// `not-found`, even if they hold a role.
    pub async fn kick(&self, uid: &str, reason: &str) -> Result<u64, ClientError> {
        let room = self.room()?;
        let uid = parse_uid(uid)?;
        let reason = escape(reason.trim());
        let answer = self
            .account()
            .request(Command::Kick { room, uid, reason })
            .await?;
        seq_of(&answer.ok)
    }

    /// Bans `uid` from the room (BAN, 6.4), removing them if they are a
    /// member. Returns the BAN event's seq, or `None` if they were banned
    /// already and are not a member, when nothing is recorded but the
    /// ban's reason is replaced.
    pub async fn ban(&self, uid: &str, reason: &str) -> Result<Option<u64>, ClientError> {
        let room = self.room()?;
        let uid = parse_uid(uid)?;
        let reason = escape(reason.trim());
        let answer = self
            .account()
            .request(Command::Ban { room, uid, reason })
            .await?;
        Ok(seq_if_any(&answer.ok))
    }

    /// Lifts a ban (UNBAN, 6.4). Returns the UNBAN event's seq.
    pub async fn unban(&self, uid: &str) -> Result<u64, ClientError> {
        let room = self.room()?;
        let uid = parse_uid(uid)?;
        let answer = self.account().request(Command::Unban { room, uid }).await?;
        seq_of(&answer.ok)
    }

    /// The room's bans (BANS, 6.4), in the order the server sent them.
    /// Moderators and owners.
    pub async fn bans(&self) -> Result<Vec<BanInfo>, ClientError> {
        let room = self.room()?;
        let answer = self
            .account()
            .request(Command::Bans { room: room.clone() })
            .await?;
        Ok(answer
            .lines
            .iter()
            .filter_map(|m| match &m.line {
                ServerLine::Event(e) => match &e.body {
                    EventBody::Ban {
                        room: r,
                        uid,
                        reason,
                    } if *r == room => Some(BanInfo {
                        uid: uid.to_string(),
                        reason: unescape(reason).into_owned(),
                    }),
                    _ => None,
                },
                _ => None,
            })
            .collect())
    }

    /// Reports message `seq` to the people who can act on it (REPORT,
    /// 5.8), with an optional reason of up to 512 bytes once escaped.
    /// Returns the report's id; reporting the same message again returns
    /// the same id. Your own messages get `forbidden`.
    pub async fn report(&self, seq: u64, reason: &str) -> Result<String, ClientError> {
        let seq = Seq::new(seq).ok_or_else(|| ClientError::Invalid("seq 0".into()))?;
        let answer = self
            .account()
            .request(Command::Report {
                conv: self.conv().clone(),
                seq,
                franking: None,
                reason: escape(reason.trim()),
            })
            .await?;
        Ok(answer
            .ok
            .id()
            .ok()
            .flatten()
            .ok_or_else(|| missing("id"))?
            .to_string())
    }

    /// The room's open reports (REPORTS, 5.8), for its owners and
    /// moderators, and operators.
    pub async fn reports(&self) -> Result<Vec<ReportInfo>, ClientError> {
        let room = self.room()?;
        let answer = self.account().request(Command::Reports { room }).await?;
        Ok(ReportInfo::from_lines(&answer.lines))
    }
}

impl Account {
    /// Closes report `id` (RESOLVE, 5.8). Any of its reviewers may. The
    /// server tells the other reviewers, who get
    /// [`AccountEvent::ReportResolved`].
    pub async fn resolve_report(&self, id: &str) -> Result<(), ClientError> {
        let id: Id = id
            .trim()
            .parse()
            .map_err(|_| ClientError::Invalid(format!("report id {id:?}")))?;
        self.request(Command::Resolve { id }).await?;
        Ok(())
    }

    /// Asks the server about itself (INFO, 8.5): whether guests may
    /// connect, registration, retention, push and uploads. Needs a
    /// connection.
    pub async fn server_info(&self) -> Result<ServerInfo, ClientError> {
        let ok = self.request(Command::Info { room: None }).await?.ok;
        Ok(server_info(&ok))
    }
}

/// [`ServerInfo`] from INFO's `OK` (8.5). Values left out take the least
/// the client can assume.
pub(crate) fn server_info(ok: &OkResponse) -> ServerInfo {
    ServerInfo {
        version: ok.version().ok().flatten().unwrap_or(1),
        guests: ok.guests().ok().flatten().unwrap_or(false),
        registration: match ok.register().ok().flatten() {
            Some(Register::Domain(d)) => Some(d.to_string()),
            _ => None,
        },
        retention_days: ok
            .retention()
            .ok()
            .flatten()
            .and_then(|r| r.days())
            .map(|d| d.get()),
        push: ok.push().ok().flatten().unwrap_or(false),
        upload: match ok.upload().ok().flatten() {
            Some(Upload::MaxBytes(n)) => Some(n),
            _ => None,
        },
    }
}
