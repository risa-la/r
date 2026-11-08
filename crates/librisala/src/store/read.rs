//! Reads for the UI. They need no connection, so they work offline.

use risala_proto::names::{Conv, Id, Seq, Uid};
use risala_proto::server::Event;
use risala_proto::time::Timestamp;
use risala_proto::types::{Role, RoomSetting};
use rusqlite::{Connection, OptionalExtension, params};

use super::e2ee::EncState;
use super::events::stored_event;
use super::people::HIDDEN;
use super::{AccountId, ConvId, OutboxId, Store, StoreError, opt_id, parse, seq, sql};

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
    /// edits, reactions, deleted messages or hidden ones (5.7). Events above the sync point
    /// that are not stored yet, as when only the newest page was fetched
    /// (7.1 step 4), each count as one: they are not known, and most are
    /// messages.
    pub unread: u64,
    /// The newest stored seq, if any.
    pub newest: Option<Seq>,
    /// A room's settings (6.2), as far as stored events and snapshots
    /// show, in key order. Empty for a direct conversation.
    pub settings: Vec<RoomSetting>,
    /// The account's own role in a room (6.3), as far as the cache knows:
    /// `owner` or `mod` as ROLE events, MEMBERS (8.3) and INFO (6.2) last
    /// said, which an owner or moderator keeps after leaving, or else
    /// `member` while the account is in the room. `None` otherwise, and
    /// for a direct conversation.
    pub role: Option<Role>,
    /// Whether it is end-to-end encrypted (12.3): a direct conversation, or
    /// a room the account holds a group for.
    pub encrypted: bool,
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
    /// Whether the account sent it, from the connection it was stored on
    /// (4.2).
    pub own: bool,
    /// The outbox entry it was sent from, once the server's OK named it
    /// (7.6). `None` for an event the account did not send through this
    /// cache's outbox, and until the OK arrives.
    pub outbox: Option<OutboxId>,
    /// For an ENC event (12.8), how far reading it got: `None` for every
    /// other event, and for a deleted one.
    pub enc: Option<EncState>,
    /// The message it replies to: a MSG's `reply` tag, or the `reply` of a
    /// decrypted TEXT line whose target is that message (5.3, 12.8).
    pub reply_to: Option<Seq>,
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

/// The summary query, up to its WHERE. Hidden messages (5.7) are not
/// unread.
fn summary_sql() -> String {
    format!(
        "SELECT c.id, c.account, c.name, c.conv_id, c.joined, c.sync_point, c.head, c.read,
            {},
            (SELECT MAX(seq) FROM events e WHERE e.conv = c.id),
            (SELECT m.role FROM room_members m WHERE m.conv = c.id AND m.uid = a.uid),
            substr(c.name, 1, 1) != '#' OR EXISTS (SELECT 1 FROM mls_groups g WHERE g.conv = c.id)
        FROM convs c JOIN accounts a ON a.id = c.account",
        unread_sql()
    )
}

/// SQL: the stored events `e` of the conversation `c` that are unread
/// messages, as [`ConversationSummary::unread`] describes them.
fn unread_messages_sql() -> String {
    format!(
        "FROM events e
         WHERE e.conv = c.id AND e.seq > c.read
             AND (e.verb = 'MSG' OR (e.verb = 'ENC' AND e.enc IN ('verified', 'unverified')))
             AND (e.rel IS NULL OR e.rel = 'reply') AND e.deleted = 0 AND e.own = 0
             AND NOT {HIDDEN}"
    )
}

/// SQL: how many events after the read marker and the sync point, up to
/// the head, are not stored. Below 0 when the read marker is past the
/// head.
const UNREAD_GAP: &str = "(c.head - MAX(c.read, c.sync_point)
    - (SELECT COUNT(*) FROM events e
       WHERE e.conv = c.id AND e.seq > MAX(c.read, c.sync_point) AND e.seq <= c.head))";

/// SQL: the unread count of the conversation `c`, as
/// [`ConversationSummary::unread`] describes it.
pub(super) fn unread_sql() -> String {
    format!(
        "((SELECT COUNT(*) {}) + MAX(0, {UNREAD_GAP}))",
        unread_messages_sql()
    )
}

/// SQL: whether [`unread_sql`] is above 0. It stops at the first unread
/// message rather than counting them all, which matters when it is asked
/// of every conversation at once.
pub(super) fn has_unread_sql() -> String {
    format!(
        "(EXISTS (SELECT 1 {}) OR {UNREAD_GAP} > 0)",
        unread_messages_sql()
    )
}

type RawSummary = (
    (i64, i64, String, Option<String>, bool),
    (i64, i64, i64, i64, Option<i64>),
    (Option<String>, bool),
);

fn raw_summary(r: &rusqlite::Row<'_>) -> rusqlite::Result<RawSummary> {
    Ok((
        (r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?),
        (r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?, r.get(9)?),
        (r.get(10)?, r.get(11)?),
    ))
}

fn finish_summary(raw: RawSummary) -> Result<ConversationSummary, StoreError> {
    let ((id, account, name, conv_id, joined), (sp, head, read, unread, newest), (role, encrypted)) =
        raw;
    let name: Conv = parse(&name, "conversation")?;
    let stored: Option<Role> = role.map(|r| parse(&r, "role")).transpose()?;
    let role = match stored {
        _ if !name.is_room() => None,
        Some(r) if r.can_moderate() => Some(r),
        _ if joined => Some(Role::Member),
        _ => None,
    };
    Ok(ConversationSummary {
        id: ConvId(id),
        account: AccountId(account),
        name,
        conv_id: opt_id(conv_id)?,
        joined,
        sync_point: sp.max(0) as u64,
        head: head.max(0) as u64,
        read: read.max(0) as u64,
        unread: unread.max(0) as u64,
        newest: newest.map(seq).transpose()?,
        settings: Vec::new(),
        role,
        encrypted,
    })
}

fn summaries(
    conn: &Connection,
    filter: &str,
    args: impl rusqlite::Params,
) -> Result<Vec<ConversationSummary>, StoreError> {
    summaries_ordered(conn, &format!("{filter} ORDER BY c.id"), args)
}

/// Summaries for `tail`: a filter, then ORDER BY and perhaps LIMIT.
fn summaries_ordered(
    conn: &Connection,
    tail: &str,
    args: impl rusqlite::Params,
) -> Result<Vec<ConversationSummary>, StoreError> {
    let mut stmt = conn.prepare_cached(&format!("{} WHERE {tail}", summary_sql()))?;
    let rows = stmt.query_map(args, raw_summary)?;
    let mut out = Vec::new();
    for raw in rows {
        out.push(finish_summary(raw?)?);
    }
    for summary in &mut out {
        summary.settings = settings(conn, summary.id)?;
    }
    Ok(out)
}

fn settings(conn: &Connection, conv: ConvId) -> Result<Vec<RoomSetting>, StoreError> {
    let mut stmt =
        conn.prepare_cached("SELECT key, value FROM room_settings WHERE conv = ?1 ORDER BY key")?;
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
}

/// The reaction counts of message `target`, not counting people whose
/// messages are hidden because they are blocked (5.7): their reactions
/// are hidden with their messages. A reaction only they sent is left out.
fn reactions(conn: &Connection, conv: ConvId, target: i64) -> Result<Vec<Reaction>, StoreError> {
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT reaction, shown, mine FROM (
             SELECT r.reaction, r.mine, r.count - (
                 SELECT COUNT(DISTINCT e.author) FROM events e
                 WHERE e.conv = r.conv AND e.target = r.target AND e.rel = 'react'
                     AND e.deleted = 0 AND e.text = r.reaction AND {HIDDEN}
             ) AS shown
             FROM reactions r WHERE r.conv = ?1 AND r.target = ?2
         )
         WHERE shown > 0
         ORDER BY reaction"
    ))?;
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

type RawItem = (
    (
        i64,
        String,
        bool,
        Option<String>,
        Option<i64>,
        bool,
        Option<i64>,
    ),
    (Option<String>, Option<String>, Option<String>, Option<i64>),
);

/// The last column is the outbox entry an own event was sent from: the
/// account's message (not a DELETE) for the conversation, bound to its
/// current id (7.6), that the server accepted as this seq.
const ITEM: &str = "
    SELECT e.seq, e.line, e.deleted, m.text, m.edit_seq, e.own,
        CASE WHEN e.own THEN (
            SELECT MIN(o.id) FROM outbox o JOIN convs c ON c.id = e.conv
            WHERE o.account = c.account AND o.conv = c.name AND o.state = 'sent'
                AND o.seq = e.seq AND o.conv_id = c.conv_id AND o.verb = 'MSG'
        ) END,
        e.enc, e.enc_error, e.rel, e.target
    FROM events e LEFT JOIN message_state m ON m.conv = e.conv AND m.seq = e.seq";

/// Timeline items only: no DELETE, edit or reaction. Messages hidden
/// because their author is blocked (5.7) are left out too.
///
/// COMMIT events change the group, not the timeline (12.5), and ENC
/// events that hold KEY or RECOVERY lines, or that the room's rules
/// ignore, are not messages (12.8, 12.11).
fn is_item() -> String {
    format!(
        "e.verb NOT IN ('DELETE', 'COMMIT') AND (e.rel IS NULL OR e.rel = 'reply')
         AND (e.enc IS NULL OR e.enc NOT IN ('control', 'ignored')) AND NOT {HIDDEN}"
    )
}

fn raw_timeline(r: &rusqlite::Row<'_>) -> rusqlite::Result<RawItem> {
    Ok((
        (
            r.get(0)?,
            r.get(1)?,
            r.get(2)?,
            r.get(3)?,
            r.get(4)?,
            r.get(5)?,
            r.get(6)?,
        ),
        (r.get(7)?, r.get(8)?, r.get(9)?, r.get(10)?),
    ))
}

fn finish_timeline(
    conn: &Connection,
    conv: ConvId,
    raw: RawItem,
) -> Result<TimelineItem, StoreError> {
    let ((n, line, deleted, text, edit, own, outbox), (enc, enc_error, rel, target)) = raw;
    let event = stored_event(&line)?;
    let meta = event
        .meta
        .clone()
        .ok_or_else(|| StoreError::Corrupt(format!("stored event without seq: {line:?}")))?;
    let enc = EncState::from_columns(enc.as_deref(), enc_error.as_deref());
    // An ENC event is a message too, with text once it is decrypted and
    // may be shown (12.8).
    let is_msg = matches!(
        event.body,
        risala_proto::server::EventBody::Msg(_) | risala_proto::server::EventBody::Enc(_)
    );
    let readable = !matches!(enc, Some(EncState::Pending | EncState::Failed(_)));
    let reply_to = match (rel.as_deref(), target) {
        (Some("reply"), Some(t)) => Some(seq(t)?),
        _ => None,
    };
    Ok(TimelineItem {
        enc,
        reply_to,
        seq: meta.seq,
        t: meta.t,
        from: meta.from,
        text: if is_msg && readable {
            Some(text.unwrap_or_default())
        } else {
            None
        },
        edit: edit.map(seq).transpose()?,
        deleted,
        own,
        outbox: outbox.map(OutboxId),
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

    /// Up to `limit` conversations of an account in byte order of name,
    /// after the name `after` if given.
    pub fn conversations_page(
        &self,
        account: AccountId,
        after: Option<&Conv>,
        limit: usize,
    ) -> Result<Vec<ConversationSummary>, StoreError> {
        self.read(|conn| {
            summaries_ordered(
                conn,
                "c.account = ?1 AND c.name > ?2 ORDER BY c.name LIMIT ?3",
                params![
                    account.0,
                    after.map_or("", |c| c.as_str()),
                    i64::try_from(limit).unwrap_or(i64::MAX)
                ],
            )
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
    /// Messages hidden because their author is blocked (5.7) are left out.
    pub fn timeline(
        &self,
        conv: ConvId,
        before: Option<Seq>,
        limit: usize,
    ) -> Result<Vec<TimelineItem>, StoreError> {
        self.read(|conn| {
            let mut stmt = conn.prepare_cached(&format!(
                "{ITEM} WHERE e.conv = ?1 AND e.seq < ?2 AND {}
                 ORDER BY e.seq DESC LIMIT ?3",
                is_item()
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

    /// Whether every event the server keeps below `seq` is stored (7.1):
    /// the conversation's sync point reaches up to it. With `None`, whether
    /// every event up to the newest one known is stored. `false` for a
    /// conversation that is not in the cache.
    pub fn complete_below(&self, conv: ConvId, seq: Option<Seq>) -> Result<bool, StoreError> {
        self.read(|conn| {
            let row: Option<(i64, i64, Option<i64>)> = conn
                .query_row(
                    "SELECT c.sync_point, c.head,
                         (SELECT MAX(seq) FROM events e WHERE e.conv = c.id)
                     FROM convs c WHERE c.id = ?1",
                    [conv.0],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            Ok(row.is_some_and(|(sync_point, head, newest)| {
                let sync_point = sync_point.max(0) as u64;
                match seq {
                    Some(seq) => sync_point + 1 >= seq.get(),
                    None => sync_point >= head.max(newest.unwrap_or(0)).max(0) as u64,
                }
            }))
        })
    }

    /// One timeline item, if it is stored and is one, and is not hidden
    /// (5.7).
    pub fn message(&self, conv: ConvId, seq: Seq) -> Result<Option<TimelineItem>, StoreError> {
        self.read(|conn| {
            let raw = conn
                .query_row(
                    &format!("{ITEM} WHERE e.conv = ?1 AND e.seq = ?2 AND {}", is_item()),
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
        self.read(|conn| settings(conn, conv))
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
