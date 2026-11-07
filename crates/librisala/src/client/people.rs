//! People (5.7, 8.1-8.3): display names, members, presence, typing and
//! blocks, as methods of [`Account`] and [`Conversation`].
//!
//! - **Display names** (8.2). [`Account::set_display_name`] sets or clears
//!   the account's own. Others' names are learned from MEMBER, USER and
//!   NAME lines and kept in the cache: [`Account::display_name`] and
//!   [`Account::user`] read them. Anyone can call themselves anything, so
//!   show people with [`Conversation::labels`], which adds the uid where
//!   two people in a conversation share a name.
//! - **Members and presence** (8.3). [`Conversation::members`] asks the
//!   server (MEMBERS) and keeps the list in the cache, where
//!   [`Conversation::cached_members`] reads it, offline too.
//!   [`Account::whois`] asks about one user. Presence is kept in memory
//!   while connected, from those answers and from PRESENCE lines, and is
//!   [`Presence::NotKnown`] otherwise.
//! - **Typing** (8.1). [`Conversation::set_typing`] as the user types;
//!   [`AccountEvent::Typing`] says who else is typing.
//! - **Blocks** (5.7). [`Account::block`], [`Account::unblock`] and
//!   [`Account::blocks`]; [`Account::is_blocked`]. With
//!   [`Account::set_hide_blocked`], blocked people's messages are hidden
//!   in rooms, on this device only. They stay in the cache, so unblocking
//!   shows them again.
//!
//! Changes arrive as [`AccountEvent::UserChanged`],
//! [`AccountEvent::MembersChanged`], [`AccountEvent::Typing`],
//! [`AccountEvent::PresenceLost`] and [`AccountEvent::BlocksChanged`].

use std::collections::{HashMap, HashSet};

use risala_proto::command::{Command, Request};
use risala_proto::names::{BlockTarget, Conv, Uid};
use risala_proto::server::{ServerLine, ServerMessage};
use risala_proto::text::{escape, unescape};
use tokio::sync::oneshot;

use super::account::{Account, AccountShared, Cmd, Conversation, PeopleOp, wait};
use super::blocking;
use super::driver::publish_changes;
use super::types::{ClientError, MemberInfo, Presence, RefusedKind, UserInfo};
use crate::store::StoreError;

#[cfg(doc)]
use super::types::AccountEvent;

fn parse_uid(uid: &str) -> Result<Uid, ClientError> {
    uid.trim()
        .parse()
        .map_err(|_| ClientError::Invalid(format!("uid {uid:?}")))
}

fn parse_target(target: &str) -> Result<BlockTarget, ClientError> {
    target
        .trim()
        .parse()
        .map_err(|_| ClientError::Invalid(format!("block target {target:?}")))
}

/// A display name as stored (escaped, `''` for none) for the API:
/// unescaped, `None` if empty.
fn shown_name(escaped: Option<&str>) -> Option<String> {
    escaped
        .filter(|n| !n.is_empty())
        .map(|n| unescape(n).into_owned())
}

/// What the account knows about `uid`: its name from the cache, and its
/// presence on this connection.
pub(crate) fn user_info(shared: &AccountShared, uid: &Uid) -> Result<UserInfo, StoreError> {
    let name = shared.store.user_name(shared.id, uid)?;
    let presence = shared.presence.lock().expect("poisoned").get(uid).cloned();
    Ok(UserInfo {
        uid: uid.to_string(),
        display_name: shown_name(name.as_deref()),
        presence: Presence::of(presence.as_ref()),
    })
}

/// The label to show for each of `people`, uids with their display names,
/// who are in one conversation (8.2):
///
/// - the display name, if nobody else among them has the same one;
/// - `name (uid)` if somebody does, comparing names without case and
///   surrounding space, or if the name looks like a different uid;
/// - the uid, for someone with no display name.
///
/// Runs of white space in names, line breaks included, show as one space.
pub(crate) fn labels(people: &[(Uid, Option<String>)]) -> Vec<String> {
    let key = |name: &str| {
        name.split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase()
    };
    let mut owners: HashMap<String, HashSet<&Uid>> = HashMap::new();
    for (uid, name) in people {
        if let Some(name) = name.as_deref().filter(|n| !key(n).is_empty()) {
            owners.entry(key(name)).or_default().insert(uid);
        }
    }
    people
        .iter()
        .map(|(uid, name)| {
            let Some(name) = name.as_deref().filter(|n| !key(n).is_empty()) else {
                return uid.to_string();
            };
            let shown = name.split_whitespace().collect::<Vec<_>>().join(" ");
            let shared = owners.get(&key(name)).is_some_and(|o| o.len() > 1);
            let looks_like_other = shown.parse::<Uid>().is_ok_and(|u| u != *uid);
            if shared || looks_like_other {
                format!("{shown} ({uid})")
            } else {
                shown
            }
        })
        .collect()
}

impl Account {
    /// Sends a command about people through the account's task, and
    /// returns its response lines.
    async fn people(&self, op: PeopleOp) -> Result<Vec<ServerMessage>, ClientError> {
        let (reply, rx) = oneshot::channel();
        self.shared().command(Cmd::People { op, reply });
        wait(rx).await
    }

    /// Fails for a guest, which cannot block (5.7).
    fn identity_only(&self, what: &str) -> Result<(), ClientError> {
        if self.is_guest() {
            return Err(ClientError::refused(
                RefusedKind::Guest,
                format!("a guest cannot {what}"),
            ));
        }
        Ok(())
    }

    /// Sets the account's display name on the server, or clears it if
    /// `name` is empty (8.2). It is any text up to 128 bytes once escaped.
    /// Others see it on their next MEMBERS or WHOIS, and those who share a
    /// conversation see it at once. A guest's lasts as long as its
    /// session. Needs a connection.
    pub async fn set_display_name(&self, name: &str) -> Result<(), ClientError> {
        let name = escape(name.trim());
        Request::new(Command::Name {
            display_name: name.clone(),
        })
        .validate()
        .map_err(|e| ClientError::Invalid(format!("display name: {e}")))?;
        self.people(PeopleOp::Name(name)).await?;
        Ok(())
    }

    /// `uid`'s display name as last learned, unescaped (8.2). `None` if
    /// they have none, or it is not known. It needs no connection.
    pub fn display_name(&self, uid: &str) -> Result<Option<String>, ClientError> {
        let uid = parse_uid(uid)?;
        let name = self.shared().store.user_name(self.id(), &uid)?;
        Ok(shown_name(name.as_deref()))
    }

    /// What the account knows about `uid`: its display name from the
    /// cache, and its presence on this connection (8.2, 8.3). It needs no
    /// connection; [`whois`](Self::whois) asks the server.
    pub fn user(&self, uid: &str) -> Result<UserInfo, ClientError> {
        let uid = parse_uid(uid)?;
        Ok(user_info(self.shared(), &uid)?)
    }

    /// Asks the server about `uid` (WHOIS, 8.3): its display name, kept in
    /// the cache, and its presence. A user the server does not know, or a
    /// guest who has left, gets [`ClientError::Server`] with `not-found`.
    /// Needs a connection.
    pub async fn whois(&self, uid: &str) -> Result<UserInfo, ClientError> {
        let uid = parse_uid(uid)?;
        let lines = self.people(PeopleOp::Whois(uid.clone())).await?;
        lines
            .into_iter()
            .find_map(|m| match m.line {
                ServerLine::User {
                    uid: u,
                    presence,
                    name,
                } if u == uid => Some(UserInfo {
                    uid: u.to_string(),
                    display_name: shown_name(Some(&name)),
                    presence: Presence::of(Some(&presence)),
                }),
                _ => None,
            })
            .ok_or_else(|| ClientError::Server {
                code: "not-found".into(),
                message: format!("no USER line for {uid}"),
            })
    }

    /// Blocks an identity, such as `spam@example.net`, or a whole domain
    /// with its subdomains, written `*@example.net` (5.7). The block
    /// belongs to the account, on all its devices, and nobody else sees
    /// it. It stops direct conversations between the two; in rooms, see
    /// [`set_hide_blocked`](Self::set_hide_blocked). Only identities can
    /// block: a guest gets [`RefusedKind::Guest`]. Needs a connection.
    pub async fn block(&self, target: &str) -> Result<(), ClientError> {
        let target = parse_target(target)?;
        self.identity_only("block")?;
        self.people(PeopleOp::Block(target)).await?;
        Ok(())
    }

    /// Removes a block (5.7). Needs a connection.
    pub async fn unblock(&self, target: &str) -> Result<(), ClientError> {
        let target = parse_target(target)?;
        self.identity_only("unblock")?;
        self.people(PeopleOp::Unblock(target)).await?;
        Ok(())
    }

    /// Asks the server for the account's blocks (BLOCKS, 5.7), keeps them
    /// in the cache and returns them, in byte order. An identity also asks
    /// on each connection, so that blocks made on its other devices are
    /// known. Needs a connection; [`cached_blocks`](Self::cached_blocks)
    /// does not.
    pub async fn blocks(&self) -> Result<Vec<String>, ClientError> {
        self.identity_only("block")?;
        let lines = self.people(PeopleOp::Blocks).await?;
        let mut targets: Vec<String> = lines
            .into_iter()
            .filter_map(|m| match m.line {
                ServerLine::Block { target } => Some(target.to_string()),
                _ => None,
            })
            .collect();
        targets.sort();
        targets.dedup();
        Ok(targets)
    }

    /// The account's blocks as the cache has them, in byte order (5.7).
    pub fn cached_blocks(&self) -> Result<Vec<String>, ClientError> {
        Ok(self
            .shared()
            .store
            .blocks(self.id())?
            .iter()
            .map(ToString::to_string)
            .collect())
    }

    /// Whether one of the account's blocks covers `uid`: the identity
    /// itself, or its domain or a parent domain (5.7). From the cache.
    /// Guests are never blocked.
    pub fn is_blocked(&self, uid: &str) -> Result<bool, ClientError> {
        let uid = parse_uid(uid)?;
        Ok(self.shared().store.is_blocked(self.id(), &uid)?)
    }

    /// Hides the messages of people the account blocked in rooms, or
    /// shows them again (5.7). The server does not hide them, as everyone
    /// in a room sees the same history; this device does. Hidden messages
    /// stay in the cache, and do not count as unread. Off by default.
    /// Timelines reset, and subscribers get [`AccountEvent::BlocksChanged`].
    pub fn set_hide_blocked(&self, hide: bool) -> Result<(), ClientError> {
        let changes = self.shared().store.set_hide_blocked(self.id(), hide)?;
        publish_changes(self.shared(), changes);
        Ok(())
    }

    /// Whether the account hides blocked people's messages in rooms. See
    /// [`set_hide_blocked`](Self::set_hide_blocked).
    pub fn hides_blocked(&self) -> Result<bool, ClientError> {
        Ok(self.shared().store.hides_blocked(self.id())?)
    }
}

impl Conversation {
    /// Says whether the user is typing here (8.1). Call it with `true` as
    /// the user types, on each change to what they are writing: TYPING
    /// goes out at once, then about every 4 seconds while the calls go on,
    /// so the others' notice, which lasts 6 seconds, stays up. Call it
    /// with `false` when the user clears what they wrote; sending a
    /// message does it too. Then nothing more is sent, and the next `true`
    /// sends at once. It does nothing while offline, or in a conversation
    /// the account is not in.
    pub fn set_typing(&self, typing: bool) {
        self.account().shared().command(Cmd::Typing {
            conv: self.conv().clone(),
            active: typing,
        });
    }

    /// Who else is typing here now, in the order they started (8.1).
    /// [`AccountEvent::Typing`] says when it changes.
    pub fn typing_users(&self) -> Vec<String> {
        self.account()
            .shared()
            .typing
            .lock()
            .expect("poisoned")
            .who(self.conv())
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    fn room(&self) -> Result<risala_proto::names::Room, ClientError> {
        match self.conv() {
            Conv::Room(room) => Ok(room.clone()),
            other => Err(ClientError::Invalid(format!("{other} is not a room"))),
        }
    }

    /// Asks the server for the room's members (MEMBERS, 8.3), with their
    /// roles, display names and presence, in the server's order. The list
    /// is kept in the cache for [`cached_members`](Self::cached_members).
    /// Needs a connection.
    pub async fn members(&self) -> Result<Vec<MemberInfo>, ClientError> {
        let room = self.room()?;
        let lines = self
            .account()
            .people(PeopleOp::Members(room.clone()))
            .await?;
        let mut members = Vec::new();
        for m in lines {
            if let ServerLine::Member {
                room: r,
                uid,
                role,
                presence,
                name,
            } = m.line
                && r == room
            {
                members.push(MemberInfo {
                    uid: uid.to_string(),
                    role: role.as_str().to_owned(),
                    display_name: shown_name(Some(&name)),
                    label: String::new(),
                    presence: Presence::of(Some(&presence)),
                });
            }
        }
        label_members(&mut members);
        Ok(members)
    }

    /// The room's members as the cache has them, by uid: from the last
    /// [`members`](Self::members), and the room's events since (6.1, 8.3).
    /// Presence is as heard on this connection. It needs no connection.
    pub fn cached_members(&self) -> Result<Vec<MemberInfo>, ClientError> {
        let account = self.account();
        let shared = account.shared();
        let Some(summary) = shared.store.conversation(shared.id, self.conv())? else {
            return Ok(Vec::new());
        };
        let rows: Vec<_> = shared
            .store
            .room_members(summary.id)?
            .into_iter()
            .filter(|m| m.joined == Some(true))
            .collect();
        let uids: Vec<Uid> = rows.iter().map(|m| m.uid.clone()).collect();
        let names = shared.store.user_names(shared.id, &uids)?;
        let presence = shared.presence.lock().expect("poisoned").clone();
        let mut members: Vec<MemberInfo> = rows
            .into_iter()
            .map(|m| MemberInfo {
                uid: m.uid.to_string(),
                role: m
                    .role
                    .unwrap_or(risala_proto::types::Role::Member)
                    .as_str()
                    .to_owned(),
                display_name: shown_name(names.get(&m.uid).map(String::as_str)),
                label: String::new(),
                presence: Presence::of(presence.get(&m.uid)),
            })
            .collect();
        label_members(&mut members);
        Ok(members)
    }

    /// The label to show for each of `uids`, in the same order, such as the
    /// authors of the messages on screen (8.2): the display name, or
    /// `name (uid)` where two people in the conversation share a name, or
    /// the uid for someone with no name. The names compared are those of
    /// `uids`, the room's members in the cache and the account itself, as
    /// the cache has them. It needs no connection.
    pub fn labels(&self, uids: Vec<String>) -> Result<Vec<String>, ClientError> {
        let account = self.account();
        let shared = account.shared();
        let wanted: Vec<Uid> = uids
            .iter()
            .map(|u| parse_uid(u))
            .collect::<Result<_, _>>()?;
        let mut people: Vec<Uid> = wanted.clone();
        people.push(shared.uid.clone());
        if let Some(summary) = shared.store.conversation(shared.id, self.conv())? {
            people.extend(
                shared
                    .store
                    .room_members(summary.id)?
                    .into_iter()
                    .filter(|m| m.joined == Some(true))
                    .map(|m| m.uid),
            );
        }
        let mut seen = HashSet::new();
        people.retain(|u| seen.insert(u.clone()));
        let names = shared.store.user_names(shared.id, &people)?;
        let with_names: Vec<(Uid, Option<String>)> = people
            .iter()
            .map(|u| (u.clone(), shown_name(names.get(u).map(String::as_str))))
            .collect();
        let all = labels(&with_names);
        let by_uid: HashMap<&Uid, &String> = people.iter().zip(&all).collect();
        Ok(wanted.iter().map(|u| by_uid[u].clone()).collect())
    }

    /// Moves the read marker to the newest message known (7.4): see
    /// [`mark_read`](Self::mark_read).
    pub async fn mark_all_read(&self) -> Result<(), ClientError> {
        let account = self.account();
        let shared = account.shared().clone();
        let conv = self.conv().clone();
        let newest = blocking(&shared.rt.clone(), move || {
            shared.store.conversation(shared.id, &conv)
        })
        .await?
        .map_or(0, |c| c.head.max(c.newest.map_or(0, |s| s.get())));
        if newest == 0 {
            return Ok(());
        }
        self.mark_read(newest).await
    }
}

/// Fills in the members' labels, comparing their names with each other.
fn label_members(members: &mut [MemberInfo]) {
    let people: Vec<(Uid, Option<String>)> = members
        .iter()
        .filter_map(|m| Some((m.uid.parse().ok()?, m.display_name.clone())))
        .collect();
    let shown = labels(&people);
    let by_uid: HashMap<String, String> = people
        .iter()
        .map(|(u, _)| u.to_string())
        .zip(shown)
        .collect();
    for m in members {
        m.label = by_uid.get(&m.uid).cloned().unwrap_or_else(|| m.uid.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uid(s: &str) -> Uid {
        s.parse().unwrap()
    }

    #[test]
    fn labels_add_the_uid_when_names_clash() {
        let people = vec![
            (uid("alice@example.org"), Some("Alice".to_owned())),
            (uid("alice@evil.example"), Some(" alice ".to_owned())),
            (uid("bob@example.net"), Some("Bob\nBuilder".to_owned())),
            (uid("~carol"), None),
            (uid("dave@example.com"), Some("".to_owned())),
            (uid("eve@example.com"), Some("bob@example.net".to_owned())),
            (uid("bob@example.net"), Some("Bob\nBuilder".to_owned())),
        ];
        assert_eq!(
            labels(&people),
            [
                "Alice (alice@example.org)",
                "alice (alice@evil.example)",
                "Bob Builder",
                "~carol",
                "dave@example.com",
                "bob@example.net (eve@example.com)",
                "Bob Builder",
            ]
        );
    }
}
