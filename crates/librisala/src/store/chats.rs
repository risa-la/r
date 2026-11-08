//! Reads for the chat list: every account's conversations, newest
//! activity first, with each one's newest message. See
//! [`ChatList`](crate::client::ChatList).

use risala_proto::names::{Conv, Uid};
use risala_proto::types::RoomSetting;
use rusqlite::{Connection, OptionalExtension, params};

use super::outbox::newest_unsent_message;
use super::people::HIDDEN;
use super::read::{has_unread_sql, unread_sql};
use super::{AccountId, Change, ConvId, OutboxState, Store, StoreError, parse, sql};
use crate::addr::ServerAddr;

/// Which conversations a chat list shows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ChatQuery {
    /// Only conversations of accounts on this server, in its display form.
    pub server: Option<String>,
    /// Only conversations with unread messages.
    pub unread: bool,
    /// Only favourites.
    pub favourites: bool,
    /// Only rooms.
    pub rooms: bool,
}

/// Where a row sorts in the chat list: newest activity first, then by row.
pub(crate) type ChatKey = (u64, ConvId);

/// Orders two keys as the chat list does.
pub(crate) fn key_order(a: &ChatKey, b: &ChatKey) -> std::cmp::Ordering {
    b.0.cmp(&a.0).then(a.1.cmp(&b.1))
}

/// One conversation as the chat list reads it. Text is escaped, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChatRow {
    pub id: ConvId,
    pub account: AccountId,
    /// The account's server.
    pub server: ServerAddr,
    /// The account's uid.
    pub uid: Uid,
    /// The account's own display name, as [`Store::user_name`] has it.
    pub own_name: Option<String>,
    pub name: Conv,
    /// For a direct conversation, the other person's display name, as
    /// [`Store::user_name`] has it.
    pub other_name: Option<String>,
    /// A room's topic (6.2), escaped, if known.
    pub topic: Option<String>,
    pub joined: bool,
    pub favourite: bool,
    /// The sort key, in Unix milliseconds.
    pub activity: u64,
    /// As [`ConversationSummary::unread`](super::ConversationSummary::unread).
    pub unread: u64,
    /// The newest message, if any.
    pub last: Option<PreviewRow>,
}

impl ChatRow {
    /// Where it sorts.
    pub fn key(&self) -> ChatKey {
        (self.activity, self.id)
    }

    /// Whether `query` shows it, not counting its `unread` toggle.
    pub fn matches_base(&self, query: &ChatQuery) -> bool {
        query
            .server
            .as_deref()
            .is_none_or(|s| s == self.server.to_string())
            && (!query.favourites || self.favourite)
            && (!query.rooms || self.name.is_room())
    }

    /// Whether `query` shows it.
    pub fn matches(&self, query: &ChatQuery) -> bool {
        self.matches_base(query) && (!query.unread || self.unread > 0)
    }
}

/// The newest message of a conversation: a stored MSG that is neither an
/// edit nor a reaction nor hidden (5.7), or the account's message in the
/// outbox, whichever is newer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreviewRow {
    pub from: Uid,
    /// The author's display name, as [`Store::user_name`] has it.
    pub from_name: Option<String>,
    pub own: bool,
    /// The current text after edits, escaped; empty when deleted.
    pub text: String,
    pub deleted: bool,
    /// When the server accepted it, or when it was queued, in Unix
    /// milliseconds.
    pub t: u64,
    /// For a message in the outbox, where it is: queued, sending or
    /// failed. `None` for a stored message.
    pub outbox: Option<OutboxState>,
}

/// SQL: every conversation with what the list sorts and filters by, up to
/// the WHERE that `filter` fills in.
fn rows_sql(filter: &str) -> String {
    format!(
        "SELECT id, account, addr, uid, name, joined, favourite, activity, unread, topic,
             own_name
         FROM (
             SELECT c.id AS id, c.account AS account, s.addr AS addr, a.uid AS uid,
                 c.name AS name, c.joined AS joined, c.favourite AS favourite,
                 c.activity AS activity, {} AS unread, {} AS has_unread,
                 (SELECT r.value FROM room_settings r
                  WHERE r.conv = c.id AND r.key = 'topic') AS topic,
                 (SELECT u.name FROM users u
                  WHERE u.account = c.account AND u.uid = a.uid) AS own_name
             FROM convs c JOIN accounts a ON a.id = c.account JOIN servers s ON s.id = a.server
         )
         WHERE {filter}",
        unread_sql(),
        has_unread_sql()
    )
}

/// SQL: every conversation's id, with whether it has unread messages, up
/// to the WHERE that `filter` fills in. Only what the counts need, so that
/// asking it of every conversation stays cheap.
fn unread_flags_sql(filter: &str) -> String {
    format!(
        "SELECT id, has_unread
         FROM (
             SELECT c.id AS id, s.addr AS addr, c.name AS name, c.favourite AS favourite,
                 {} AS has_unread
             FROM convs c JOIN accounts a ON a.id = c.account JOIN servers s ON s.id = a.server
         )
         WHERE {filter}",
        has_unread_sql()
    )
}

/// SQL: whether a row matches the query in ?1 to ?4: server, favourites,
/// rooms and unread. The flag, not the count, decides unread, so that a
/// row's count is only worked out once it is in.
const MATCHES: &str = "(?1 IS NULL OR addr = ?1) AND (?2 = 0 OR favourite = 1)
    AND (?3 = 0 OR substr(name, 1, 1) = '#') AND (?4 = 0 OR has_unread)";

type RawRow = (
    (i64, i64, String, String, String, bool),
    (bool, i64, i64, Option<String>, Option<String>),
);

fn raw_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<RawRow> {
    Ok((
        (
            r.get(0)?,
            r.get(1)?,
            r.get(2)?,
            r.get(3)?,
            r.get(4)?,
            r.get(5)?,
        ),
        (r.get(6)?, r.get(7)?, r.get(8)?, r.get(9)?, r.get(10)?),
    ))
}

fn finish_row(conn: &Connection, raw: RawRow) -> Result<ChatRow, StoreError> {
    let ((id, account, addr, uid, name, joined), (favourite, activity, unread, topic, own_name)) =
        raw;
    let name: Conv = parse(&name, "conversation")?;
    let account = AccountId(account);
    let other_name = match &name {
        Conv::Uid(other) => user_name(conn, account, other)?,
        Conv::Room(_) => None,
    };
    let topic = topic
        .map(|v| match RoomSetting::parse("topic", &v) {
            Ok(RoomSetting::Topic(t)) => Ok(t),
            _ => Err(StoreError::Corrupt(format!("bad topic {v:?}"))),
        })
        .transpose()?;
    let uid: Uid = parse(&uid, "uid")?;
    let id = ConvId(id);
    let last = preview(conn, id, account, &name, &uid, own_name.as_deref())?;
    Ok(ChatRow {
        id,
        account,
        server: parse(&addr, "server address")?,
        uid,
        own_name,
        name,
        other_name,
        topic,
        joined,
        favourite,
        activity: activity.max(0) as u64,
        unread: unread.max(0) as u64,
        last,
    })
}

fn user_name(
    conn: &Connection,
    account: AccountId,
    uid: &Uid,
) -> Result<Option<String>, StoreError> {
    Ok(conn
        .prepare_cached("SELECT name FROM users WHERE account = ?1 AND uid = ?2")?
        .query_row(params![account.0, uid.as_str()], |r| r.get(0))
        .optional()?)
}

/// The newest message of conversation `conv`, of the account `account`
/// whose uid is `uid` and own display name `own_name`; see [`PreviewRow`].
fn preview(
    conn: &Connection,
    conv: ConvId,
    account: AccountId,
    name: &Conv,
    uid: &Uid,
    own_name: Option<&str>,
) -> Result<Option<PreviewRow>, StoreError> {
    type Raw = (i64, String, bool, bool, Option<String>);
    let stored: Option<Raw> = conn
        .prepare_cached(&format!(
            "SELECT e.t, e.author, e.own, e.deleted, m.text
             FROM events e LEFT JOIN message_state m ON m.conv = e.conv AND m.seq = e.seq
             WHERE e.conv = ?1 AND e.verb = 'MSG' AND (e.rel IS NULL OR e.rel = 'reply')
                 AND NOT {HIDDEN}
             ORDER BY e.seq DESC LIMIT 1"
        ))?
        .query_row([conv.0], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })
        .optional()?;
    let stored_t = stored.as_ref().map(|s| s.0.max(0) as u64);
    if let Some(item) = newest_unsent_message(conn, account, name)?
        && stored_t.is_none_or(|t| item.created.unix_millis() >= t)
    {
        return Ok(Some(PreviewRow {
            from: uid.clone(),
            from_name: own_name.map(str::to_owned),
            own: true,
            text: item.draft.text,
            deleted: false,
            t: item.created.unix_millis(),
            outbox: Some(item.state),
        }));
    }
    let Some((t, author, own, deleted, text)) = stored else {
        return Ok(None);
    };
    let from: Uid = parse(&author, "uid")?;
    Ok(Some(PreviewRow {
        from_name: if from == *uid {
            own_name.map(str::to_owned)
        } else {
            user_name(conn, account, &from)?
        },
        from,
        own,
        text: if deleted {
            String::new()
        } else {
            text.unwrap_or_default()
        },
        deleted,
        t: t.max(0) as u64,
        outbox: None,
    }))
}

fn query_flags(query: &ChatQuery) -> (Option<&str>, bool, bool, bool) {
    (
        query.server.as_deref(),
        query.favourites,
        query.rooms,
        query.unread,
    )
}

impl Store {
    /// Up to `limit` rows `query` shows, in the chat list's order, after
    /// the row with key `after` if given. One read.
    pub(crate) fn chat_rows(
        &self,
        query: &ChatQuery,
        after: Option<ChatKey>,
        limit: usize,
    ) -> Result<Vec<ChatRow>, StoreError> {
        let (server, favourites, rooms, unread) = query_flags(query);
        let (activity, id) = after.map_or((i64::MAX, i64::MIN), |(a, id)| (sql(a), id.0));
        self.read(|conn| {
            let raws: Vec<RawRow> = conn
                .prepare_cached(&rows_sql(&format!(
                    "{MATCHES} AND (activity < ?5 OR (activity = ?5 AND id > ?6))
                     ORDER BY activity DESC, id LIMIT ?7"
                )))?
                .query_map(
                    params![
                        server,
                        favourites,
                        rooms,
                        unread,
                        activity,
                        id,
                        i64::try_from(limit).unwrap_or(i64::MAX)
                    ],
                    raw_row,
                )?
                .collect::<Result<_, _>>()?;
            raws.into_iter().map(|raw| finish_row(conn, raw)).collect()
        })
    }

    /// One conversation as the chat list reads it, whatever the filter.
    pub(crate) fn chat_row(&self, conv: ConvId) -> Result<Option<ChatRow>, StoreError> {
        self.read(|conn| {
            let raw = conn
                .prepare_cached(&rows_sql("id = ?1"))?
                .query_row([conv.0], raw_row)
                .optional()?;
            raw.map(|raw| finish_row(conn, raw)).transpose()
        })
    }

    /// Every conversation `query` shows, not counting its `unread` toggle,
    /// with whether it has unread messages: for the list's counts.
    pub(crate) fn chat_unread(&self, query: &ChatQuery) -> Result<Vec<(ConvId, bool)>, StoreError> {
        let (server, favourites, rooms, _) = query_flags(query);
        self.read(|conn| {
            let mut stmt = conn.prepare_cached(&unread_flags_sql(MATCHES))?;
            let rows = stmt.query_map(params![server, favourites, rooms, false], |r| {
                Ok((ConvId(r.get(0)?), r.get(1)?))
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    /// The row of an account's conversation, if it is in the cache.
    pub(crate) fn conversation_id(
        &self,
        account: AccountId,
        name: &Conv,
    ) -> Result<Option<ConvId>, StoreError> {
        self.read(|conn| {
            Ok(conn
                .prepare_cached("SELECT id FROM convs WHERE account = ?1 AND name = ?2")?
                .query_row(params![account.0, name.as_str()], |r| Ok(ConvId(r.get(0)?)))
                .optional()?)
        })
    }

    /// Every conversation of an account.
    pub(crate) fn conversation_ids(&self, account: AccountId) -> Result<Vec<ConvId>, StoreError> {
        self.read(|conn| {
            let mut stmt = conn.prepare_cached("SELECT id FROM convs WHERE account = ?1")?;
            let rows = stmt.query_map([account.0], |r| Ok(ConvId(r.get(0)?)))?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    /// A conversation's activity, the chat list's sort key, in Unix
    /// milliseconds. `None` if it is not in the cache.
    #[cfg(test)]
    pub(crate) fn activity(&self, conv: ConvId) -> Result<Option<u64>, StoreError> {
        self.read(|conn| {
            Ok(conn
                .query_row("SELECT activity FROM convs WHERE id = ?1", [conv.0], |r| {
                    r.get::<_, i64>(0)
                })
                .optional()?
                .map(|a| a.max(0) as u64))
        })
    }

    /// Marks a conversation as a favourite, or not. Favourites are kept
    /// in the cache only: the spec has nowhere to keep them. Returns the
    /// changes, for the UI.
    pub fn set_favourite(&self, conv: ConvId, on: bool) -> Result<Vec<Change>, StoreError> {
        let ((), changes) = self.write(|tx| {
            let n = tx.conn().execute(
                "UPDATE convs SET favourite = ?2 WHERE id = ?1 AND favourite != ?2",
                params![conv.0, on],
            )?;
            if n > 0 {
                tx.changed(Change::Conversation { conv });
            }
            Ok(())
        })?;
        Ok(changes)
    }
}
