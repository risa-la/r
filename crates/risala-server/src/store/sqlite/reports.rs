//! [`ReportStore`] on SQLite.

use rusqlite::{Connection, OptionalExtension, Row, params};

use risala_proto::names::{Id, Seq, Uid};
use risala_proto::server::Attachment;
use risala_proto::time::Timestamp;
use risala_proto::types::Relation;

use super::{SqliteStore, columns, corrupt, load_room, ms, parse, seq, sql_seq, take_id, time};
use crate::store::{
    ConvKey, EventKind, NewReport, ReportAdded, ReportRecord, ReportStore, Result, RoomRecord,
    StoreError, StoredEvent,
};

const REPORT_COLUMNS: &str = "n, id, conv_id, room, seq, reporter, reason, t, ev_t, ev_author, \
     ev_relation, ev_target, ev_file_url, ev_file_type, ev_file_size, ev_text FROM reports";

/// A report's row, before its values are checked.
struct ReportRow {
    n: i64,
    id: String,
    conv_id: String,
    room: Option<String>,
    seq: i64,
    reporter: String,
    reason: String,
    t: i64,
    ev_t: i64,
    ev_author: String,
    ev_relation: Option<String>,
    ev_target: Option<i64>,
    ev_file_url: Option<String>,
    ev_file_type: Option<String>,
    ev_file_size: Option<i64>,
    ev_text: String,
}

fn report_from_row(row: &Row<'_>) -> rusqlite::Result<ReportRow> {
    Ok(ReportRow {
        n: row.get(0)?,
        id: row.get(1)?,
        conv_id: row.get(2)?,
        room: row.get(3)?,
        seq: row.get(4)?,
        reporter: row.get(5)?,
        reason: row.get(6)?,
        t: row.get(7)?,
        ev_t: row.get(8)?,
        ev_author: row.get(9)?,
        ev_relation: row.get(10)?,
        ev_target: row.get(11)?,
        ev_file_url: row.get(12)?,
        ev_file_type: row.get(13)?,
        ev_file_size: row.get(14)?,
        ev_text: row.get(15)?,
    })
}

impl ReportRow {
    fn finish(self) -> Result<ReportRecord> {
        let relation = match &self.ev_relation {
            None => None,
            Some(key) => {
                let target = seq(self
                    .ev_target
                    .ok_or_else(|| corrupt("report", "a relation with no target"))?)?;
                Some(Relation::new(key, target).ok_or_else(|| corrupt("relation", key))?)
            }
        };
        let file = match &self.ev_file_url {
            None => None,
            Some(url) => Some(Attachment {
                url: parse("file URL", url)?,
                media_type: self
                    .ev_file_type
                    .as_deref()
                    .map(|m| parse("media type", m))
                    .transpose()?,
                size: self
                    .ev_file_size
                    .map(|n| u64::try_from(n).map_err(|_| corrupt("file size", n)))
                    .transpose()?,
            }),
        };
        Ok(ReportRecord {
            n: u64::try_from(self.n).map_err(|_| corrupt("report number", self.n))?,
            id: parse("report id", &self.id)?,
            report: NewReport {
                conv_id: parse("conversation id", &self.conv_id)?,
                room: self.room.as_deref().map(|r| parse("room", r)).transpose()?,
                reporter: parse("reporter", &self.reporter)?,
                reason: self.reason,
                t: time(self.t)?,
                event: StoredEvent {
                    seq: seq(self.seq)?,
                    t: time(self.ev_t)?,
                    from: parse("author", &self.ev_author)?,
                    kind: EventKind::Msg {
                        relation,
                        file,
                        text: self.ev_text,
                    },
                    deleted: false,
                },
            },
        })
    }
}

fn report_of_in(conn: &Connection, conv_id: &Id, s: Seq, reporter: &Uid) -> Result<Option<Id>> {
    let id: Option<String> = conn
        .prepare_cached("SELECT id FROM reports WHERE conv_id = ? AND seq = ? AND reporter = ?")?
        .query_row(
            params![conv_id.as_str(), sql_seq(s), reporter.as_str()],
            |row| row.get(0),
        )
        .optional()?;
    id.map(|id| parse("report id", &id)).transpose()
}

impl ReportStore for SqliteStore {
    fn report_of(&self, conv_id: &Id, s: Seq, reporter: &Uid) -> Result<Option<Id>> {
        report_of_in(&self.conn(), conv_id, s, reporter)
    }

    fn add_report(&self, report: &NewReport) -> Result<ReportAdded> {
        let EventKind::Msg { .. } = &report.event.kind else {
            return Err(StoreError::Corrupt(format!(
                "a report of a {} event",
                report.event.kind.verb()
            )));
        };
        self.write(|tx| {
            if let Some(id) = report_of_in(tx, &report.conv_id, report.event.seq, &report.reporter)?
            {
                return Ok(ReportAdded::Existing(id));
            }
            let id = take_id(tx, "report", report.t)?;
            let c = columns(&report.event.kind);
            tx.execute(
                "INSERT INTO reports (id, conv_id, room, seq, reporter, reason, t, ev_t, \
                 ev_author, ev_relation, ev_target, ev_file_url, ev_file_type, ev_file_size, \
                 ev_text) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    id.as_str(),
                    report.conv_id.as_str(),
                    report.room.as_ref().map(|r| r.as_str()),
                    sql_seq(report.event.seq),
                    report.reporter.as_str(),
                    report.reason,
                    ms(report.t),
                    ms(report.event.t),
                    report.event.from.as_str(),
                    c.relation,
                    c.target,
                    c.file_url,
                    c.file_type,
                    c.file_size,
                    c.text.as_deref().unwrap_or(""),
                ],
            )?;
            Ok(ReportAdded::New(id))
        })
    }

    fn report(&self, id: &Id) -> Result<Option<ReportRecord>> {
        self.conn()
            .prepare_cached(&format!("SELECT {REPORT_COLUMNS} WHERE id = ?"))?
            .query_row([id.as_str()], report_from_row)
            .optional()?
            .map(ReportRow::finish)
            .transpose()
    }

    fn reports(&self, conv_id: Option<&Id>, after: u64, limit: u64) -> Result<Vec<ReportRecord>> {
        let after = i64::try_from(after).unwrap_or(i64::MAX);
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let conn = self.conn();
        let rows = match conv_id {
            Some(conv_id) => conn
                .prepare_cached(&format!(
                    "SELECT {REPORT_COLUMNS} WHERE conv_id = ? AND n > ? ORDER BY n LIMIT ?"
                ))?
                .query_map(params![conv_id.as_str(), after, limit], report_from_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?,
            None => conn
                .prepare_cached(&format!(
                    "SELECT {REPORT_COLUMNS} WHERE n > ? ORDER BY n LIMIT ?"
                ))?
                .query_map(params![after, limit], report_from_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?,
        };
        rows.into_iter().map(ReportRow::finish).collect()
    }

    fn resolve_report(&self, id: &Id) -> Result<bool> {
        let n =
            self.write(|tx| Ok(tx.execute("DELETE FROM reports WHERE id = ?", [id.as_str()])?))?;
        Ok(n > 0)
    }

    fn drop_room(
        &self,
        key: ConvKey,
        recreate: bool,
        now: Timestamp,
    ) -> Result<Option<RoomRecord>> {
        self.write(|tx| {
            let room: Option<String> = tx
                .query_row(
                    "SELECT room FROM conversations WHERE conv = ? AND kind = 'room' \
                     AND dropping = 0",
                    [key.0],
                    |row| row.get(0),
                )
                .optional()?;
            let room = room.ok_or(StoreError::NoConversation)?;
            // What a room has a row of per member, or per setting. Its
            // events, and their cids and uploads, go in `clear_dropped`.
            for table in [
                "room_settings",
                "members",
                "guest_members",
                "roles",
                "invites",
                "room_bans",
                "read_markers",
            ] {
                tx.execute(&format!("DELETE FROM {table} WHERE conv = ?"), [key.0])?;
            }
            // The id stays in used_ids, and reports name it, not the key.
            tx.execute(
                "UPDATE conversations SET dropping = 1, room = NULL WHERE conv = ?",
                [key.0],
            )?;
            if !recreate {
                return Ok(None);
            }
            let id = take_id(tx, "conversation", now)?;
            tx.execute(
                "INSERT INTO conversations (id, kind, room, created) VALUES (?, 'room', ?, ?)",
                params![id.as_str(), room, ms(now)],
            )?;
            let conv = tx.last_insert_rowid();
            tx.execute("INSERT INTO room_settings (conv) VALUES (?)", [conv])?;
            let room = parse("room", &room)?;
            load_room(tx, &room)?
                .ok_or(StoreError::NoConversation)
                .map(Some)
        })
    }

    fn clear_dropped(&self, key: ConvKey, max: usize) -> Result<u64> {
        if max == 0 {
            return Ok(0);
        }
        let max = i64::try_from(max).unwrap_or(i64::MAX);
        self.write(|tx| {
            let dropping: Option<bool> = tx
                .query_row(
                    "SELECT dropping FROM conversations WHERE conv = ?",
                    [key.0],
                    |row| row.get(0),
                )
                .optional()?;
            if dropping != Some(true) {
                return Ok(0);
            }
            // The newest of the oldest `max` events goes, with all before
            // it, and their text (ON DELETE CASCADE), cids and uploads.
            let upto: Option<i64> = tx.query_row(
                "SELECT max(seq) FROM (SELECT seq FROM events WHERE conv = ? ORDER BY seq LIMIT ?)",
                params![key.0, max],
                |row| row.get(0),
            )?;
            let mut n = 0;
            if let Some(upto) = upto {
                n = tx.execute(
                    "DELETE FROM events WHERE conv = ? AND seq <= ?",
                    params![key.0, upto],
                )? as i64;
                for table in ["cids", "uploads"] {
                    tx.execute(
                        &format!("DELETE FROM {table} WHERE conv = ? AND seq <= ?"),
                        params![key.0, upto],
                    )?;
                }
            }
            if n < max {
                // That was the last: the row goes, with anything still
                // naming it (ON DELETE CASCADE), such as uploads never
                // attached to a message.
                tx.execute("DELETE FROM conversations WHERE conv = ?", [key.0])?;
            }
            Ok(n as u64)
        })
    }

    fn dropped_rooms(&self) -> Result<Vec<ConvKey>> {
        self.conn()
            .prepare_cached("SELECT conv FROM conversations WHERE dropping = 1 ORDER BY conv")?
            .query_map([], |row| row.get(0).map(ConvKey))?
            .collect::<rusqlite::Result<_>>()
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests;
