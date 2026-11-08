//! [`MessageStore`] on SQLite.

use rusqlite::{OptionalExtension, params};

use risala_proto::names::{Room, Seq, Uid};
use risala_proto::time::Timestamp;

use super::{
    EVENT_COLUMNS, EventRow, SqliteStore, append_in, event_from_row, ms, parse, seq, sql_seq,
};
use crate::store::{
    Appended, ConvKey, EventKind, MessageStore, NewEvent, Page, PurgeQuery, RelatedQuery, Result,
    StoredEvent,
};

/// `since` as a bound on `t`: no bound is time 0.
fn since_ms(since: Option<Timestamp>) -> i64 {
    since.map_or(0, ms)
}

impl MessageStore for SqliteStore {
    fn reaction(
        &self,
        conv: ConvKey,
        from: &Uid,
        target: Seq,
        text: &str,
        since: Option<Timestamp>,
    ) -> Result<Option<Seq>> {
        self.conn()
            .prepare_cached(
                "SELECT e.seq FROM events e \
                 JOIN event_text x ON x.conv = e.conv AND x.seq = e.seq \
                 WHERE e.conv = ? AND e.target = ? AND e.verb = 'MSG' \
                 AND e.relation = 'react' AND e.deleted = 0 AND e.author = ? \
                 AND e.t >= ? AND x.text = ? \
                 ORDER BY e.seq LIMIT 1",
            )?
            .query_row(
                params![
                    conv.0,
                    sql_seq(target),
                    from.as_str(),
                    since_ms(since),
                    text
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .map(seq)
            .transpose()
    }

    fn delete_of(&self, conv: ConvKey, target: Seq) -> Result<Option<Seq>> {
        self.conn()
            .prepare_cached(
                "SELECT seq FROM events WHERE conv = ? AND target = ? AND verb = 'DELETE' \
                 ORDER BY seq LIMIT 1",
            )?
            .query_row(params![conv.0, sql_seq(target)], |row| row.get::<_, i64>(0))
            .optional()?
            .map(seq)
            .transpose()
    }

    fn related(&self, conv: ConvKey, q: RelatedQuery) -> Result<Page> {
        if q.first > q.last {
            return Ok(Page {
                events: Vec::new(),
                more: false,
            });
        }
        let limit = q.limit.clamp(1, i64::MAX as u64 - 1);
        let after = i64::try_from(q.after).unwrap_or(i64::MAX);
        let rows = self
            .conn()
            .prepare_cached(&format!(
                "SELECT {EVENT_COLUMNS} WHERE e.conv = ? AND e.target BETWEEN ? AND ? \
                 AND e.verb = 'MSG' AND e.relation IN ('edit', 'react') AND e.seq > ? \
                 ORDER BY e.seq ASC LIMIT ?"
            ))?
            .query_map(
                params![
                    conv.0,
                    sql_seq(q.first),
                    sql_seq(q.last),
                    after,
                    (limit + 1) as i64
                ],
                event_from_row,
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let more = rows.len() as u64 > limit;
        let mut events = rows
            .into_iter()
            .map(EventRow::finish)
            .collect::<Result<Vec<_>>>()?;
        if more {
            events.pop();
        }
        Ok(Page { events, more })
    }

    fn authored_rooms(
        &self,
        author: &Uid,
        since: Option<Timestamp>,
    ) -> Result<Vec<(ConvKey, Room)>> {
        self.conn()
            .prepare_cached(
                "SELECT c.conv, c.room FROM conversations c WHERE c.kind = 'room' \
                 AND EXISTS (SELECT 1 FROM events e WHERE e.conv = c.conv \
                 AND e.author = ? AND e.t >= ? AND e.verb = 'MSG' AND e.deleted = 0) \
                 ORDER BY c.room",
            )?
            .query_map(params![author.as_str(), since_ms(since)], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })?
            .map(|r| {
                let (conv, room) = r?;
                Ok((ConvKey(conv), parse("room", &room)?))
            })
            .collect()
    }

    fn purge(&self, conv: ConvKey, q: &PurgeQuery) -> Result<Vec<StoredEvent>> {
        self.write(|tx| {
            let max = i64::try_from(q.max).unwrap_or(i64::MAX);
            let targets = tx
                .prepare_cached(
                    "SELECT seq FROM events WHERE conv = ? AND author = ? AND verb = 'MSG' \
                     AND deleted = 0 AND t >= ? AND seq <= ? ORDER BY seq LIMIT ?",
                )?
                .query_map(
                    params![
                        conv.0,
                        q.author.as_str(),
                        since_ms(q.since),
                        sql_seq(q.upto),
                        max
                    ],
                    |row| row.get::<_, i64>(0),
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut deletes = Vec::new();
            for target in targets {
                // An edit or reaction goes with the message it belongs to,
                // which comes first (5.4).
                let deleted: bool = tx
                    .prepare_cached("SELECT deleted FROM events WHERE conv = ? AND seq = ?")?
                    .query_row(params![conv.0, target], |row| row.get(0))?;
                if deleted {
                    continue;
                }
                let target = seq(target)?;
                let event = NewEvent {
                    t: q.now,
                    from: q.by.clone(),
                    kind: EventKind::Delete { target },
                    cid: None,
                };
                let Appended::New(s) = append_in(tx, conv, &event)? else {
                    // Only a cid makes a duplicate, and a DELETE has none.
                    continue;
                };
                deletes.push(StoredEvent {
                    seq: s,
                    t: event.t,
                    from: event.from,
                    kind: event.kind,
                    deleted: false,
                });
            }
            Ok(deletes)
        })
    }

    fn expire(&self, conv: ConvKey, before: Timestamp, max: usize) -> Result<u64> {
        self.write(|tx| {
            let max = i64::try_from(max).unwrap_or(i64::MAX);
            let oldest = tx
                .prepare_cached("SELECT seq, t FROM events WHERE conv = ? ORDER BY seq LIMIT ?")?
                .query_map(params![conv.0, max], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            // In seq order, up to the first event that is not old enough,
            // whatever the times after it (7.5).
            let last = oldest
                .iter()
                .take_while(|(_, t)| *t < ms(before))
                .last()
                .map(|(s, _)| *s);
            let Some(last) = last else {
                return Ok(0);
            };
            // Their text goes with them (ON DELETE CASCADE).
            let n = tx.execute(
                "DELETE FROM events WHERE conv = ? AND seq <= ?",
                params![conv.0, last],
            )?;
            Ok(n as u64)
        })
    }
}
