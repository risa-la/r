//! Reads for the UI. They need no connection, so they work offline.

use risala_proto::names::{Conv, Id, Seq, Uid};
use risala_proto::server::Event;
use risala_proto::time::Timestamp;
use risala_proto::types::{Role, RoomSetting};
use rusqlite::{Connection, OptionalExtension, params};

use super::events::stored_event;
use super::{AccountId, ConvId, Store, StoreError, opt_id, parse, seq, sql};

/// A conversation, for the conversation list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationSummary {
    /// The conversation's row.
    pub id: ConvId,
    /// The account it belongs to.
    pub account: AccountId,
    /// Its name: a room, or the other person (5.1).
    pub name: Conv,
    /// The id it was last known by (5.1), `None` if not known yet.
    pub conv_id: Option<Id>,
    /// Whether the account is in it, as far as the client knows (7.1).
    pub joined: bool,
    /// Every event the server keeps up to this seq is stored (7.1).
    pub sync_point: u64,
    /// The newest head the server reported.
    pub head: u64,
    /// The read marker (7.4), 0 for none.
    pub read: u64,
    /// Messages after the read marker, not counting the account's own,
    /// edits, reactions or deleted messages.
    pub unread: u64,
    /// The newest stored seq, if any.
    pub newest: Option<Seq>,
}

impl ConversationSummary {
    /// Whether every event up to the reported head is stored.
    pub fn caught_up(&self) -> bool {
        self.sync_point >= self.head
    }
}

/// One item of a timeline: any stored event but an edit, a reaction or a
/// DELETE, which change other items instead (5.3, 5.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineItem {
    /// Its seq.
    pub seq: Seq,
    /// When the server accepted it.
    pub t: Timestamp,
    /// Who caused it.
    pub from: Uid,
    /// The event as stored. A deleted message is the placeholder HISTORY
    /// sends (5.4).
    pub event: Event,
    /// For a message, the current text after edits (5.3), escaped (3.4);
    /// empty when deleted. `None` for other events.
    pub text: Option<String>,
    /// The edit whose text is current, if any.
    pub edit: Option<Seq>,
    /// Whether the message was deleted (5.4).
    pub deleted: bool,
    /// Reactions to it (5.3), in byte order.
    pub reactions: Vec<Reaction>,
}

/// The count of one reaction on a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reaction {
    /// The reaction text, escaped, usually an emoji.
    pub reaction: String,
    /// How many people sent it.
    pub count: u64,
    /// The seq of the account's own reaction, which DELETE takes back.
    pub mine: Option<Seq>,
}

/// A room member as far as the stored events and snapshots show (6.1,
/// 6.3). MEMBERS (8.3) gives the full list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// The member.
    pub uid: Uid,
    /// Whether they are in the room, if known.
    pub joined: Option<bool>,
    /// Their role, if known.
    pub role: Option<Role>,
    /// Whether they are banned (6.4).
    pub banned: bool,
}

const SUMMARY: &str = "
    SELECT c.id, c.account, c.name, c.conv_id, c.joined, c.sync_point, c.head, c.read,
        (SELECT COUNT(*) FROM events e
         WHERE e.conv = c.id AND e.seq > c.read AND e.verb = 'MSG'
             AND (e.rel IS NULL OR e.rel = 'reply') AND e.deleted = 0 AND e.own = 0),
        (SELECT MAX(seq) FROM events e WHERE e.conv = c.id)
    FROM convs c JOIN accounts a ON a.id = c.account";

type RawSummary = (
    (i64, i64, String, Option<String>, bool),
    (i64, i64, i64, i64, Option<i64>),
);

fn raw_summary(r: &rusqlite::Row<'_>) -> rusqlite::Result<RawSummary> {
    Ok((
        (r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?),
        (r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?, r.get(9)?),
    ))
}

fn finish_summary(raw: RawSummary) -> Result<ConversationSummary, StoreError> {
    let ((id, account, name, conv_id, joined), (sp, head, read, unread, newest)) = raw;
    Ok(ConversationSummary {
        id: ConvId(id),
        account: AccountId(account),
        name: parse(&name, "conversation")?,
        conv_id: opt_id(conv_id)?,
        joined,
        sync_point: sp.max(0) as u64,
        head: head.max(0) as u64,
        read: read.max(0) as u64,
        unread: unread.max(0) as u64,
        newest: newest.map(seq).transpose()?,
    })
}

fn summaries(
    conn: &Connection,
    filter: &str,
    args: impl rusqlite::Params,
) -> Result<Vec<ConversationSummary>, StoreError> {
    let mut stmt = conn.prepare_cached(&format!("{SUMMARY} WHERE {filter} ORDER BY c.id"))?;
    let rows = stmt.query_map(args, raw_summary)?;
    let mut out = Vec::new();
    for raw in rows {
        out.push(finish_summary(raw?)?);
    }
    Ok(out)
}

fn reactions(conn: &Connection, conv: ConvId, target: i64) -> Result<Vec<Reaction>, StoreError> {
    let mut stmt = conn.prepare_cached(
        "SELECT reaction, count, mine FROM reactions WHERE conv = ?1 AND target = ?2
         ORDER BY reaction",
    )?;
    let rows = stmt.query_map(params![conv.0, target], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, Option<i64>>(2)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (reaction, count, mine) = row?;
        out.push(Reaction {
            reaction,
            count: count.max(0) as u64,
            mine: mine.map(seq).transpose()?,
        });
    }
    Ok(out)
}

type RawItem = (i64, String, bool, Option<String>, Option<i64>);

const ITEM: &str = "
    SELECT e.seq, e.line, e.deleted, m.text, m.edit_seq
    FROM events e LEFT JOIN message_state m ON m.conv = e.conv AND m.seq = e.seq";

/// Timeline items only: no DELETE, edit or reaction.
const IS_ITEM: &str = "e.verb != 'DELETE' AND (e.rel IS NULL OR e.rel = 'reply')";

fn raw_timeline(r: &rusqlite::Row<'_>) -> rusqlite::Result<RawItem> {
    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
}

fn finish_timeline(
    conn: &Connection,
    conv: ConvId,
    raw: RawItem,
) -> Result<TimelineItem, StoreError> {
    let (n, line, deleted, text, edit) = raw;
    let event = stored_event(&line)?;
    let meta = event
        .meta
        .clone()
        .ok_or_else(|| StoreError::Corrupt(format!("stored event without seq: {line:?}")))?;
    let is_msg = matches!(event.body, risala_proto::server::EventBody::Msg(_));
    Ok(TimelineItem {
        seq: meta.seq,
        t: meta.t,
        from: meta.from,
        text: if is_msg {
            Some(text.unwrap_or_default())
        } else {
            None
        },
        edit: edit.map(seq).transpose()?,
        deleted,
        reactions: if is_msg {
            reactions(conn, conv, n)?
        } else {
            Vec::new()
        },
        event,
    })
}

impl Store {
    /// The conversations of an account.
    pub fn conversations(
        &self,
        account: AccountId,
    ) -> Result<Vec<ConversationSummary>, StoreError> {
        self.read(|conn| summaries(conn, "c.account = ?1", [account.0]))
    }

    /// The sync point of each of an account's conversations (7.1), by
    /// name.
    pub(crate) fn sync_points(
        &self,
        account: AccountId,
    ) -> Result<std::collections::HashMap<Conv, u64>, StoreError> {
        self.read(|conn| {
            let mut stmt =
                conn.prepare_cached("SELECT name, sync_point FROM convs WHERE account = ?1")?;
            let rows = stmt.query_map([account.0], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
            })?;
            let mut out = std::collections::HashMap::new();
            for row in rows {
                let (name, sp) = row?;
                out.insert(parse(&name, "conversation")?, sp.max(0) as u64);
            }
            Ok(out)
        })
    }

    /// A conversation by name.
    pub fn conversation(
        &self,
        account: AccountId,
        name: &Conv,
    ) -> Result<Option<ConversationSummary>, StoreError> {
        self.read(|conn| {
            Ok(summaries(
                conn,
                "c.account = ?1 AND c.name = ?2",
                params![account.0, name.as_str()],
            )?
            .pop())
        })
    }

    /// A conversation by row.
    pub fn conversation_by_id(
        &self,
        id: ConvId,
    ) -> Result<Option<ConversationSummary>, StoreError> {
        self.read(|conn| Ok(summaries(conn, "c.id = ?1", [id.0])?.pop()))
    }

    /// The unread count of a conversation: see
    /// [`ConversationSummary::unread`].
    pub fn unread(&self, conv: ConvId) -> Result<u64, StoreError> {
        Ok(self
            .conversation_by_id(conv)?
            .map(|c| c.unread)
            .unwrap_or(0))
    }

    /// Up to `limit` timeline items before `before` (or the newest, if
    /// `None`), oldest first. Page back by passing the first item's seq.
    pub fn timeline(
        &self,
        conv: ConvId,
        before: Option<Seq>,
        limit: usize,
    ) -> Result<Vec<TimelineItem>, StoreError> {
        self.read(|conn| {
            let mut stmt = conn.prepare_cached(&format!(
                "{ITEM} WHERE e.conv = ?1 AND e.seq < ?2 AND {IS_ITEM}
                 ORDER BY e.seq DESC LIMIT ?3"
            ))?;
            let before = before.map_or(i64::MAX, |s| sql(s.get()));
            let raws: Vec<RawItem> = stmt
                .query_map(
                    params![conv.0, before, i64::try_from(limit).unwrap_or(i64::MAX)],
                    raw_timeline,
                )?
                .collect::<Result<_, _>>()?;
            let mut out = Vec::with_capacity(raws.len());
            for raw in raws.into_iter().rev() {
                out.push(finish_timeline(conn, conv, raw)?);
            }
            Ok(out)
        })
    }

    /// One timeline item, if it is stored and is one.
    pub fn message(&self, conv: ConvId, seq: Seq) -> Result<Option<TimelineItem>, StoreError> {
        self.read(|conn| {
            let raw = conn
                .query_row(
                    &format!("{ITEM} WHERE e.conv = ?1 AND e.seq = ?2 AND {IS_ITEM}"),
                    params![conv.0, sql(seq.get())],
                    raw_timeline,
                )
                .optional()?;
            raw.map(|raw| finish_timeline(conn, conv, raw)).transpose()
        })
    }

    /// Every stored event of a conversation, oldest first, as lines in
    /// canonical form: a full copy for offline use. Deleted messages are
    /// the placeholders of 5.4. To make it complete, first download the
    /// whole history (see [`SyncEngine::download`](crate::sync::SyncEngine::download)).
    pub fn export(&self, conv: ConvId) -> Result<Vec<String>, StoreError> {
        self.read(|conn| {
            let mut stmt =
                conn.prepare_cached("SELECT line FROM events WHERE conv = ?1 ORDER BY seq")?;
            let lines = stmt
                .query_map([conv.0], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            Ok(lines)
        })
    }

    /// A room's settings (6.2), as far as stored events and snapshots show.
    pub fn room_settings(&self, conv: ConvId) -> Result<Vec<RoomSetting>, StoreError> {
        self.read(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT key, value FROM room_settings WHERE conv = ?1 ORDER BY key",
            )?;
            let rows = stmt.query_map([conv.0], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?;
            let mut out = Vec::new();
            for row in rows {
                let (key, value) = row?;
                out.push(
                    RoomSetting::parse(&key, &value)
                        .map_err(|_| StoreError::Corrupt(format!("bad setting {key}")))?,
                );
            }
            Ok(out)
        })
    }

    /// A room's members, roles and bans, as far as stored events and
    /// snapshots show. See [`Member`].
    pub fn room_members(&self, conv: ConvId) -> Result<Vec<Member>, StoreError> {
        self.read(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT uid, joined, role, banned FROM room_members WHERE conv = ?1 ORDER BY uid",
            )?;
            let rows = stmt.query_map([conv.0], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<bool>>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, bool>(3)?,
                ))
            })?;
            let mut out = Vec::new();
            for row in rows {
                let (uid, joined, role, banned) = row?;
                out.push(Member {
                    uid: parse(&uid, "uid")?,
                    joined,
                    role: role.map(|r| parse(&r, "role")).transpose()?,
                    banned,
                });
            }
            Ok(out)
        })
    }
}
