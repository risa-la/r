//! The outbox: messages waiting to be sent, with the cid that makes
//! resending safe (7.6), and deletions of messages (5.4).

use std::fmt;

use risala_proto::error::ErrorCode;
use risala_proto::names::{Conv, Id, Seq};
use risala_proto::time::Timestamp;
use risala_proto::types::{Cid, FileUrl, Relation};
use rusqlite::{Connection, OptionalExtension, params};

use super::events::Tx;
use super::{AccountId, Change, OutboxId, Store, StoreError, opt_id, parse, seq, sql};

/// A message to send: MSG's text and tags (5.3, 5.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Draft {
    /// The text, escaped (3.4), not blank.
    pub text: String,
    /// The `reply`, `edit` or `react` tag, if any.
    pub relation: Option<Relation>,
    /// The `file` tag, if any (5.6).
    pub file: Option<FileUrl>,
}

impl Draft {
    /// A plain message.
    pub fn text(text: impl Into<String>) -> Draft {
        Draft {
            text: text.into(),
            relation: None,
            file: None,
        }
    }
}

/// Where an outbox entry is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboxState {
    /// Waiting to be sent: the conversation's id has not been confirmed on
    /// the current connection yet, or there is no connection.
    Queued,
    /// Sent, with no answer yet. After a dropped connection an identity
    /// sends it again with the same cid (7.6).
    Sending,
    /// The server accepted it as event `seq`.
    Sent(Seq),
    /// It will not be sent.
    Failed(FailReason),
}

/// Why an outbox entry failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailReason {
    /// The conversation it was written for is gone, and the server has a
    /// different one under its name (7.1, 7.6). Sending it would put it in
    /// the wrong room.
    RoomChanged,
    /// The room was dropped (10.4).
    Dropped,
    /// The account left the room, or was kicked or banned from it, before
    /// the message went out. Sending it later, after a new JOIN, would put
    /// it out of context (PLAN.md 5, item 34). Never for guests, who rejoin
    /// their rooms by themselves after a reconnect.
    NotInRoom,
    /// The server answered with an error.
    Rejected(ErrorCode),
    /// The connection dropped before the answer, and resending is not safe:
    /// a guest's cids only count within one session, which may have ended,
    /// and an identity's only for 24 hours (7.6). It may or may not have
    /// been sent.
    Unconfirmed,
    /// It could not be written as a line, for example because it is too
    /// long, so it was never sent.
    Invalid,
}

impl fmt::Display for FailReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FailReason::RoomChanged => f.write_str("room-changed"),
            FailReason::Dropped => f.write_str("dropped"),
            FailReason::NotInRoom => f.write_str("not-in-room"),
            FailReason::Unconfirmed => f.write_str("unconfirmed"),
            FailReason::Invalid => f.write_str("invalid"),
            FailReason::Rejected(code) => write!(f, "rejected {code}"),
        }
    }
}

impl FailReason {
    fn parse(s: &str) -> Result<FailReason, StoreError> {
        Ok(match s {
            "room-changed" => FailReason::RoomChanged,
            "dropped" => FailReason::Dropped,
            "not-in-room" => FailReason::NotInRoom,
            "unconfirmed" => FailReason::Unconfirmed,
            "invalid" => FailReason::Invalid,
            _ => match s.strip_prefix("rejected ") {
                Some(code) => FailReason::Rejected(parse(code, "error code")?),
                None => return Err(StoreError::Corrupt(format!("bad outbox error {s:?}"))),
            },
        })
    }
}

/// Who sent an outbox entry that is `sending`: one connection of one
/// process sharing the cache (7.6).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Claim {
    /// The [`Store`] instance, random for each one opened.
    pub instance: String,
    /// The connection, counted within the instance.
    pub connection: u64,
}

impl Claim {
    fn to_sql(&self) -> String {
        format!("{}:{}", self.instance, self.connection)
    }

    fn parse(s: &str) -> Option<Claim> {
        let (instance, connection) = s.rsplit_once(':')?;
        Some(Claim {
            instance: instance.to_owned(),
            connection: connection.parse().ok()?,
        })
    }
}

/// An outbox entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxItem {
    /// The entry.
    pub id: OutboxId,
    /// The account sending it.
    pub account: AccountId,
    /// The conversation it goes to.
    pub conv: Conv,
    /// The conversation id it is bound to (7.6). `None` for a direct
    /// conversation that had not started when the message was queued; it
    /// is bound to the first id learned.
    pub conv_id: Option<Id>,
    /// Its cid (7.6).
    pub cid: Cid,
    /// What to send. Empty for a DELETE.
    pub draft: Draft,
    /// For `DELETE <conv> <seq>` (5.4), the message to delete; then
    /// `draft` is empty. `None` for a message.
    pub delete: Option<Seq>,
    /// Where it is.
    pub state: OutboxState,
    /// When it was queued.
    pub created: Timestamp,
    /// When it was first sent, if it was.
    pub first_sent: Option<Timestamp>,
    /// Who sent it and when, while it is `sending`.
    pub(crate) claim: Option<(Claim, Timestamp)>,
}

const OUTBOX_COLS: &str =
    "id, account, conv, conv_id, cid, text, rel, target, file_url, state, seq, error, created,
     first_sent, claim, claimed_at, verb";

type RawItem = (
    (i64, i64, String, Option<String>, String, String),
    (
        Option<String>,
        Option<i64>,
        Option<String>,
        String,
        Option<i64>,
    ),
    (
        Option<String>,
        i64,
        Option<i64>,
        Option<String>,
        Option<i64>,
        String,
    ),
);

fn raw_item(r: &rusqlite::Row<'_>) -> rusqlite::Result<RawItem> {
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
        (
            r.get(11)?,
            r.get(12)?,
            r.get(13)?,
            r.get(14)?,
            r.get(15)?,
            r.get(16)?,
        ),
    ))
}

fn time(ms: i64) -> Result<Timestamp, StoreError> {
    Timestamp::from_unix_millis(ms.max(0) as u64)
        .ok_or_else(|| StoreError::Corrupt(format!("bad time {ms}")))
}

fn finish_item(raw: RawItem) -> Result<OutboxItem, StoreError> {
    let (
        (id, account, conv, conv_id, cid, text),
        (rel, target, file, state, n),
        (error, created, first, claim, claimed_at, verb),
    ) = raw;
    let relation = match (&rel, target) {
        (Some(key), Some(t)) => Relation::new(key, seq(t)?),
        _ => None,
    };
    let delete = match (verb.as_str(), target) {
        ("MSG", _) => None,
        ("DELETE", Some(t)) => Some(seq(t)?),
        _ => return Err(StoreError::Corrupt(format!("bad outbox verb {verb:?}"))),
    };
    let state = match state.as_str() {
        "queued" => OutboxState::Queued,
        "sending" => OutboxState::Sending,
        "sent" => OutboxState::Sent(seq(n.unwrap_or(0))?),
        "failed" => OutboxState::Failed(FailReason::parse(error.as_deref().unwrap_or(""))?),
        other => return Err(StoreError::Corrupt(format!("bad outbox state {other:?}"))),
    };
    Ok(OutboxItem {
        id: OutboxId(id),
        account: AccountId(account),
        conv: parse(&conv, "conversation")?,
        conv_id: opt_id(conv_id)?,
        cid: parse(&cid, "cid")?,
        draft: Draft {
            text,
            relation,
            file: file.map(|f| parse(&f, "file URL")).transpose()?,
        },
        delete,
        state,
        created: time(created)?,
        first_sent: first.map(time).transpose()?,
        claim: match (claim.as_deref().and_then(Claim::parse), claimed_at) {
            (Some(c), Some(at)) => Some((c, time(at)?)),
            _ => None,
        },
    })
}

fn query_items(
    conn: &Connection,
    filter: &str,
    args: impl rusqlite::Params,
) -> Result<Vec<OutboxItem>, StoreError> {
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT {OUTBOX_COLS} FROM outbox WHERE {filter} ORDER BY id"
    ))?;
    let rows = stmt.query_map(args, raw_item)?;
    let mut out = Vec::new();
    for raw in rows {
        out.push(finish_item(raw?)?);
    }
    Ok(out)
}

fn query_item(conn: &Connection, id: OutboxId) -> Result<Option<OutboxItem>, StoreError> {
    let raw = conn
        .query_row(
            &format!("SELECT {OUTBOX_COLS} FROM outbox WHERE id = ?1"),
            [id.0],
            raw_item,
        )
        .optional()?;
    raw.map(finish_item).transpose()
}

/// A fresh cid: 22 random characters of `A-Z a-z 0-9 - _`, 132 bits (7.6).
pub(crate) fn new_cid() -> Result<Cid, StoreError> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut bytes = [0u8; 22];
    getrandom::fill(&mut bytes).map_err(|e| StoreError::Random(e.to_string()))?;
    let s: String = bytes
        .iter()
        .map(|b| ALPHABET[usize::from(b & 63)] as char)
        .collect();
    parse(&s, "cid")
}

impl Tx<'_> {
    /// Adds a message to the outbox, bound to `conv_id` (7.6).
    pub(crate) fn queue(
        &mut self,
        account: AccountId,
        conv: &Conv,
        conv_id: Option<&Id>,
        draft: &Draft,
        now: Timestamp,
    ) -> Result<OutboxId, StoreError> {
        let cid = new_cid()?;
        self.conn().execute(
            "INSERT INTO outbox (account, conv, conv_id, cid, text, rel, target, file_url, state,
                 created)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'queued', ?9)",
            params![
                account.0,
                conv.as_str(),
                conv_id.map(Id::as_str),
                cid.as_str(),
                draft.text,
                draft.relation.map(Relation::key),
                draft.relation.map(|r| sql(r.seq().get())),
                draft.file.as_ref().map(FileUrl::as_str),
                now.unix_millis() as i64,
            ],
        )?;
        let id = OutboxId(self.conn().last_insert_rowid());
        self.changed(Change::Outbox { id });
        Ok(id)
    }

    /// Adds `DELETE <conv> <target>` to the outbox (5.4), bound to
    /// `conv_id` like a message (7.6): the seq names a message of that
    /// conversation, and of no other with the same name.
    pub(crate) fn queue_delete(
        &mut self,
        account: AccountId,
        conv: &Conv,
        conv_id: &Id,
        target: Seq,
        now: Timestamp,
    ) -> Result<OutboxId, StoreError> {
        let cid = new_cid()?;
        self.conn().execute(
            "INSERT INTO outbox (account, conv, conv_id, cid, text, target, state, created, verb)
             VALUES (?1, ?2, ?3, ?4, '', ?5, 'queued', ?6, 'DELETE')",
            params![
                account.0,
                conv.as_str(),
                conv_id.as_str(),
                cid.as_str(),
                sql(target.get()),
                now.unix_millis() as i64,
            ],
        )?;
        let id = OutboxId(self.conn().last_insert_rowid());
        self.changed(Change::Outbox { id });
        Ok(id)
    }

    /// An outbox entry.
    pub(crate) fn outbox_item(&self, id: OutboxId) -> Result<Option<OutboxItem>, StoreError> {
        query_item(self.conn(), id)
    }

    /// The account's entries that are queued or sending, oldest first.
    pub(crate) fn outbox_pending(&self, account: AccountId) -> Result<Vec<OutboxItem>, StoreError> {
        query_items(
            self.conn(),
            "account = ?1 AND state IN ('queued', 'sending')",
            [account.0],
        )
    }

    /// Sets an entry's state, and drops its claim.
    fn set_state(
        &mut self,
        id: OutboxId,
        state: &str,
        n: Option<Seq>,
        error: Option<String>,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE outbox SET state = ?2, seq = ?3, error = ?4, claim = NULL, claimed_at = NULL
             WHERE id = ?1",
            params![id.0, state, n.map(|s| sql(s.get())), error],
        )?;
        self.changed(Change::Outbox { id });
        Ok(())
    }

    /// Marks an entry as sent by `claim` and waiting for its answer. Do
    /// this in the same transaction that read the entry, so that no other
    /// process sends it too.
    pub(crate) fn outbox_sending(
        &mut self,
        id: OutboxId,
        claim: &Claim,
        now: Timestamp,
    ) -> Result<(), StoreError> {
        let now = now.unix_millis() as i64;
        self.conn().execute(
            "UPDATE outbox SET state = 'sending', seq = NULL, error = NULL,
                 first_sent = COALESCE(first_sent, ?2), claim = ?3, claimed_at = ?2
             WHERE id = ?1",
            params![id.0, now, claim.to_sql()],
        )?;
        self.changed(Change::Outbox { id });
        Ok(())
    }

    /// Marks an entry as accepted as event `seq`.
    pub(crate) fn outbox_sent(&mut self, id: OutboxId, seq: Seq) -> Result<(), StoreError> {
        self.set_state(id, "sent", Some(seq), None)
    }

    /// Marks an entry as failed.
    pub(crate) fn outbox_failed(
        &mut self,
        id: OutboxId,
        why: FailReason,
    ) -> Result<(), StoreError> {
        self.set_state(id, "failed", None, Some(why.to_string()))
    }

    /// Puts an entry back in the queue, for example after `rate-limited`.
    pub(crate) fn outbox_requeue(&mut self, id: OutboxId) -> Result<(), StoreError> {
        self.set_state(id, "queued", None, None)
    }

    /// Binds an entry queued without an id to `conv_id`.
    pub(crate) fn outbox_bind(&mut self, id: OutboxId, conv_id: &Id) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE outbox SET conv_id = ?2 WHERE id = ?1 AND conv_id IS NULL",
            params![id.0, conv_id.as_str()],
        )?;
        self.changed(Change::Outbox { id });
        Ok(())
    }

    /// Fails the messages of `conv` still waiting to be sent, not DELETEs:
    /// the account left the room (PLAN.md 5, item 34). Authors may still
    /// delete their own messages there (5.4). Entries already sent wait for
    /// their answer.
    pub(crate) fn fail_queued_messages(
        &mut self,
        account: AccountId,
        conv: &Conv,
    ) -> Result<(), StoreError> {
        let ids: Vec<i64> = {
            let mut stmt = self.conn().prepare_cached(
                "SELECT id FROM outbox WHERE account = ?1 AND conv = ?2
                     AND state = 'queued' AND verb = 'MSG'",
            )?;
            stmt.query_map(params![account.0, conv.as_str()], |r| r.get(0))?
                .collect::<Result<_, _>>()?
        };
        for id in ids {
            self.outbox_failed(OutboxId(id), FailReason::NotInRoom)?;
        }
        Ok(())
    }

    /// Fails every pending entry of `conv` bound to `old`, a conversation
    /// that is gone (7.6).
    pub(crate) fn fail_bound(
        &mut self,
        account: AccountId,
        conv: &Conv,
        old: &Id,
        why: FailReason,
    ) -> Result<(), StoreError> {
        let ids: Vec<i64> = {
            let mut stmt = self.conn().prepare_cached(
                "SELECT id FROM outbox WHERE account = ?1 AND conv = ?2 AND conv_id = ?3
                     AND state IN ('queued', 'sending')",
            )?;
            stmt.query_map(params![account.0, conv.as_str(), old.as_str()], |r| {
                r.get(0)
            })?
            .collect::<Result<_, _>>()?
        };
        for id in ids {
            self.outbox_failed(OutboxId(id), why.clone())?;
        }
        Ok(())
    }
}

impl Store {
    /// Every outbox entry of an account, oldest first.
    pub fn outbox(&self, account: AccountId) -> Result<Vec<OutboxItem>, StoreError> {
        self.read(|conn| query_items(conn, "account = ?1", [account.0]))
    }

    /// The outbox entries of one conversation, oldest first.
    pub fn outbox_for(
        &self,
        account: AccountId,
        conv: &Conv,
    ) -> Result<Vec<OutboxItem>, StoreError> {
        self.read(|conn| {
            query_items(
                conn,
                "account = ?1 AND conv = ?2",
                params![account.0, conv.as_str()],
            )
        })
    }

    /// One outbox entry.
    pub fn outbox_item(&self, id: OutboxId) -> Result<Option<OutboxItem>, StoreError> {
        self.read(|conn| query_item(conn, id))
    }

    /// Removes an outbox entry, for example one that failed and the user
    /// dismissed. An entry still being sent may yet arrive.
    pub fn remove_outbox(&self, id: OutboxId) -> Result<(), StoreError> {
        self.write(|tx| {
            tx.conn()
                .execute("DELETE FROM outbox WHERE id = ?1", [id.0])?;
            tx.changed(Change::Outbox { id });
            Ok(())
        })?;
        Ok(())
    }
}
