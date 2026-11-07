//! The SQLite implementation of [`Store`].

use std::path::Path;
use std::str::FromStr;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, Row, Transaction, TransactionBehavior, params};

use risala_proto::names::{Id, Room, Seq, Uid};
use risala_proto::server::Attachment;
use risala_proto::time::Timestamp;
use risala_proto::types::{Cid, Relation, Role, RoomSetting, ServerSetting};

use super::schema;
use super::{
    Appended, CID_WINDOW_MS, ConvKey, EventKind, HistoryQuery, NewEvent, Page, Result, RoomRecord,
    RoomSettings, ServerSettings, Store, StoreError, StoredEvent, random_id,
};

/// How long a statement waits for another process's lock before failing.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// [`Store`] on a SQLite database, in WAL mode with `synchronous=FULL`, so a
/// commit survives a power failure, and with foreign keys on.
///
/// It holds one connection behind a mutex, so the store's transactions run
/// one at a time. They are all short.
#[derive(Debug)]
pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl SqliteStore {
    /// Opens (or creates) the database at `path` and brings its schema up
    /// to date. Fails if the database cannot use WAL mode.
    pub fn open(path: &Path) -> Result<SqliteStore> {
        SqliteStore::setup(Connection::open(path)?, true)
    }

    /// A store in memory, for tests.
    pub fn open_in_memory() -> Result<SqliteStore> {
        SqliteStore::setup(Connection::open_in_memory()?, false)
    }

    pub(super) fn setup(mut conn: Connection, need_wal: bool) -> Result<SqliteStore> {
        conn.busy_timeout(BUSY_TIMEOUT)?;
        let mode: String =
            conn.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
        if need_wal && !mode.eq_ignore_ascii_case("wal") {
            return Err(StoreError::Setup(format!(
                "the database cannot use WAL mode (journal mode is {mode:?})"
            )));
        }
        // FULL, not NORMAL: in WAL mode, NORMAL can lose the last commits
        // after a power failure, and a seq already sent would then be used
        // again (5.2).
        conn.pragma_update(None, "synchronous", "FULL")?;
        let sync: i64 = conn.pragma_query_value(None, "synchronous", |row| row.get(0))?;
        if sync < 2 {
            return Err(StoreError::Setup(format!(
                "cannot set synchronous=FULL (it is {sync})"
            )));
        }
        conn.pragma_update(None, "foreign_keys", "ON")?;
        schema::migrate(&mut conn)?;
        Ok(SqliteStore {
            conn: Mutex::new(conn),
        })
    }

    /// With `false`, commits are no longer flushed to disk
    /// (`synchronous=OFF`), so a power failure can lose them. Only for
    /// filling a database quickly, for example before a test, never for a
    /// database a server is running on. `true` restores `synchronous=FULL`.
    pub fn set_durable(&self, durable: bool) -> Result<()> {
        let mode = if durable { "FULL" } else { "OFF" };
        self.conn().pragma_update(None, "synchronous", mode)?;
        Ok(())
    }

    pub(super) fn conn(&self) -> MutexGuard<'_, Connection> {
        // A panic while holding the lock cannot leave a transaction open:
        // rusqlite rolls back when a Transaction is dropped.
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Runs `f` in an IMMEDIATE transaction, which takes the write lock up
    /// front, and commits if it succeeds.
    fn write<T>(&self, f: impl FnOnce(&Transaction<'_>) -> Result<T>) -> Result<T> {
        let mut conn = self.conn();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let value = f(&tx)?;
        tx.commit()?;
        Ok(value)
    }
}

// ---------------------------------------------------------------------------
// Reading values back

fn corrupt(what: &str, value: impl std::fmt::Display) -> StoreError {
    StoreError::Corrupt(format!("bad {what}: {value}"))
}

fn parse<T: FromStr>(what: &str, s: &str) -> Result<T>
where
    T::Err: std::fmt::Display,
{
    s.parse().map_err(|e| corrupt(what, format!("{s:?} ({e})")))
}

fn seq(n: i64) -> Result<Seq> {
    u64::try_from(n)
        .ok()
        .and_then(Seq::new)
        .ok_or_else(|| corrupt("seq", n))
}

fn head(n: i64) -> Result<Option<Seq>> {
    if n == 0 { Ok(None) } else { seq(n).map(Some) }
}

fn time(ms: i64) -> Result<Timestamp> {
    u64::try_from(ms)
        .ok()
        .and_then(Timestamp::from_unix_millis)
        .ok_or_else(|| corrupt("time", ms))
}

fn ms(t: Timestamp) -> i64 {
    // Timestamp::MAX is far below i64::MAX.
    t.unix_millis() as i64
}

fn sql_seq(s: Seq) -> i64 {
    // Seq::MAX is i64::MAX.
    s.get() as i64
}

// ---------------------------------------------------------------------------
// Rooms

const ROOM_COLUMNS: &str = "c.conv, c.id, c.room, c.head, c.created, \
     s.topic, s.public, s.guests, s.retention \
     FROM conversations c JOIN room_settings s ON s.conv = c.conv";

fn room_from_row(row: &Row<'_>) -> rusqlite::Result<RoomRow> {
    Ok(RoomRow {
        conv: row.get(0)?,
        id: row.get(1)?,
        room: row.get(2)?,
        head: row.get(3)?,
        created: row.get(4)?,
        topic: row.get(5)?,
        public: row.get(6)?,
        guests: row.get(7)?,
        retention: row.get(8)?,
    })
}

/// A room's row, before its values are checked.
struct RoomRow {
    conv: i64,
    id: String,
    room: String,
    head: i64,
    created: i64,
    topic: String,
    public: bool,
    guests: String,
    retention: String,
}

impl RoomRow {
    fn finish(self, conn: &Connection) -> Result<RoomRecord> {
        let key = ConvKey(self.conv);
        let members = conn
            .prepare_cached("SELECT uid FROM members WHERE conv = ? ORDER BY uid")?
            .query_map([self.conv], |row| row.get::<_, String>(0))?
            .map(|uid| parse::<Uid>("member", &uid?))
            .collect::<Result<Vec<_>>>()?;
        let roles = conn
            .prepare_cached("SELECT uid, role FROM roles WHERE conv = ? ORDER BY uid")?
            .query_map([self.conv], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .map(|r| {
                let (uid, role) = r?;
                Ok((
                    parse::<Uid>("role holder", &uid)?,
                    parse::<Role>("role", &role)?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(RoomRecord {
            key,
            room: parse("room", &self.room)?,
            id: parse("id", &self.id)?,
            head: head(self.head)?,
            created: time(self.created)?,
            settings: RoomSettings {
                topic: self.topic,
                public: self.public,
                guests: parse("guests setting", &self.guests)?,
                retention: parse("retention setting", &self.retention)?,
            },
            members,
            roles,
        })
    }
}

fn load_room(conn: &Connection, room: &Room) -> Result<Option<RoomRecord>> {
    let row = conn
        .prepare_cached(&format!("SELECT {ROOM_COLUMNS} WHERE c.room = ?"))?
        .query_row([room.as_str()], room_from_row)
        .optional()?;
    row.map(|r| r.finish(conn)).transpose()
}

/// Takes a new id that was never used before (5.1).
fn take_id(tx: &Transaction<'_>, kind: &str, now: Timestamp) -> Result<Id> {
    loop {
        let id = random_id()?;
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO used_ids (id, kind, created) VALUES (?, ?, ?)",
            params![id.as_str(), kind, ms(now)],
        )?;
        if inserted == 1 {
            return Ok(id);
        }
    }
}

// ---------------------------------------------------------------------------
// Events

const EVENT_COLUMNS: &str = "e.seq, e.t, e.author, e.verb, e.relation, e.target, e.subject, \
     e.arg, e.file_url, e.file_type, e.file_size, e.deleted, COALESCE(x.text, '') \
     FROM events e LEFT JOIN event_text x ON x.conv = e.conv AND x.seq = e.seq";

/// An event's row, before its values are checked.
struct EventRow {
    seq: i64,
    t: i64,
    author: String,
    verb: String,
    relation: Option<String>,
    target: Option<i64>,
    subject: Option<String>,
    arg: Option<String>,
    file_url: Option<String>,
    file_type: Option<String>,
    file_size: Option<i64>,
    deleted: bool,
    text: String,
}

fn event_from_row(row: &Row<'_>) -> rusqlite::Result<EventRow> {
    Ok(EventRow {
        seq: row.get(0)?,
        t: row.get(1)?,
        author: row.get(2)?,
        verb: row.get(3)?,
        relation: row.get(4)?,
        target: row.get(5)?,
        subject: row.get(6)?,
        arg: row.get(7)?,
        file_url: row.get(8)?,
        file_type: row.get(9)?,
        file_size: row.get(10)?,
        deleted: row.get(11)?,
        text: row.get(12)?,
    })
}

impl EventRow {
    fn finish(self) -> Result<StoredEvent> {
        let subject = || -> Result<Uid> {
            parse(
                "event subject",
                self.subject
                    .as_deref()
                    .ok_or_else(|| corrupt("event", "no subject"))?,
            )
        };
        let target = || seq(self.target.ok_or_else(|| corrupt("event", "no target"))?);
        let kind = match self.verb.as_str() {
            "MSG" => {
                let relation = match &self.relation {
                    None => None,
                    Some(key) => Some(
                        Relation::new(key, target()?).ok_or_else(|| corrupt("relation", key))?,
                    ),
                };
                let file = match &self.file_url {
                    None => None,
                    Some(url) => Some(Attachment {
                        url: parse("file URL", url)?,
                        media_type: self
                            .file_type
                            .as_deref()
                            .map(|m| parse("media type", m))
                            .transpose()?,
                        size: self
                            .file_size
                            .map(|n| u64::try_from(n).map_err(|_| corrupt("file size", n)))
                            .transpose()?,
                    }),
                };
                EventKind::Msg {
                    relation,
                    file,
                    text: self.text,
                }
            }
            "DELETE" => EventKind::Delete { target: target()? },
            "JOIN" => EventKind::Join,
            "PART" => EventKind::Part { reason: self.text },
            "INVITE" => EventKind::Invite { uid: subject()? },
            "KICK" => EventKind::Kick {
                uid: subject()?,
                reason: self.text,
            },
            "BAN" => EventKind::Ban {
                uid: subject()?,
                reason: self.text,
            },
            "UNBAN" => EventKind::Unban { uid: subject()? },
            "SET" => {
                let key = self
                    .arg
                    .as_deref()
                    .ok_or_else(|| corrupt("SET", "no key"))?;
                EventKind::Set(
                    RoomSetting::parse(key, &self.text).map_err(|e| corrupt("setting", e))?,
                )
            }
            "ROLE" => EventKind::Role {
                uid: subject()?,
                role: parse("role", self.arg.as_deref().unwrap_or(""))?,
            },
            verb => return Err(corrupt("verb", verb)),
        };
        Ok(StoredEvent {
            seq: seq(self.seq)?,
            t: time(self.t)?,
            from: parse("author", &self.author)?,
            kind,
            deleted: self.deleted,
        })
    }
}

/// The columns of an event that are not its key, time, author or verb.
#[derive(Default)]
struct EventColumns<'a> {
    relation: Option<&'static str>,
    target: Option<i64>,
    subject: Option<&'a str>,
    arg: Option<&'a str>,
    file_url: Option<&'a str>,
    file_type: Option<&'a str>,
    file_size: Option<i64>,
    text: Option<std::borrow::Cow<'a, str>>,
}

fn columns(kind: &EventKind) -> EventColumns<'_> {
    let mut c = EventColumns::default();
    match kind {
        EventKind::Msg {
            relation,
            file,
            text,
        } => {
            if let Some(r) = relation {
                c.relation = Some(r.key());
                c.target = Some(sql_seq(r.seq()));
            }
            if let Some(f) = file {
                c.file_url = Some(f.url.as_str());
                c.file_type = f.media_type.as_ref().map(|m| m.as_str());
                c.file_size = f.size.map(|n| i64::try_from(n).unwrap_or(i64::MAX));
            }
            c.text = Some(text.as_str().into());
        }
        EventKind::Delete { target } => c.target = Some(sql_seq(*target)),
        EventKind::Join => {}
        EventKind::Part { reason } => c.text = Some(reason.as_str().into()),
        EventKind::Invite { uid } | EventKind::Unban { uid } => c.subject = Some(uid.as_str()),
        EventKind::Kick { uid, reason } | EventKind::Ban { uid, reason } => {
            c.subject = Some(uid.as_str());
            c.text = Some(reason.as_str().into());
        }
        EventKind::Set(setting) => {
            c.arg = Some(setting.key());
            c.text = Some(setting.value());
        }
        EventKind::Role { uid, role } => {
            c.subject = Some(uid.as_str());
            c.arg = Some(role.as_str());
        }
    }
    c
}

/// Applies what an event changes, in the event's transaction.
fn apply_effects(tx: &Transaction<'_>, conv: i64, seq: i64, event: &NewEvent) -> Result<()> {
    let identity = |uid: &Uid| uid.is_identity();
    match &event.kind {
        EventKind::Msg { .. } => {}
        EventKind::Join => {
            if event.from.is_guest() {
                // Kept until the guest's PART, even across a crash (4.2).
                tx.execute(
                    "INSERT OR IGNORE INTO guest_members (conv, uid, since) VALUES (?, ?, ?)",
                    params![conv, event.from.as_str(), ms(event.t)],
                )?;
            }
            if identity(&event.from) {
                tx.execute(
                    "INSERT OR IGNORE INTO members (conv, uid, since) VALUES (?, ?, ?)",
                    params![conv, event.from.as_str(), ms(event.t)],
                )?;
                // An invitation lasts until it is used (6.4).
                tx.execute(
                    "DELETE FROM invites WHERE conv = ? AND uid = ?",
                    params![conv, event.from.as_str()],
                )?;
            }
        }
        EventKind::Part { .. } => {
            for sql in [
                "DELETE FROM members WHERE conv = ? AND uid = ?",
                "DELETE FROM guest_members WHERE conv = ? AND uid = ?",
            ] {
                tx.execute(sql, params![conv, event.from.as_str()])?;
            }
        }
        EventKind::Set(setting) => {
            let sql = match setting {
                RoomSetting::Topic(_) => "UPDATE room_settings SET topic = ? WHERE conv = ?",
                RoomSetting::Public(_) => "UPDATE room_settings SET public = ? WHERE conv = ?",
                RoomSetting::Guests(_) => "UPDATE room_settings SET guests = ? WHERE conv = ?",
                RoomSetting::Retention(_) => {
                    "UPDATE room_settings SET retention = ? WHERE conv = ?"
                }
                RoomSetting::Other { .. } => return Ok(()),
            };
            match setting {
                RoomSetting::Public(public) => tx.execute(sql, params![*public, conv])?,
                other => tx.execute(sql, params![other.value(), conv])?,
            };
        }
        EventKind::Role { uid, role } => {
            if *role == Role::Member {
                tx.execute(
                    "DELETE FROM roles WHERE conv = ? AND uid = ?",
                    params![conv, uid.as_str()],
                )?;
            } else {
                tx.execute(
                    "INSERT OR REPLACE INTO roles (conv, uid, role) VALUES (?, ?, ?)",
                    params![conv, uid.as_str(), role.as_str()],
                )?;
            }
        }
        EventKind::Invite { uid } => {
            tx.execute(
                "INSERT OR REPLACE INTO invites (conv, uid, seq) VALUES (?, ?, ?)",
                params![conv, uid.as_str(), seq],
            )?;
        }
        EventKind::Kick { uid, .. } => {
            // KICK takes the role away (6.3).
            for sql in [
                "DELETE FROM members WHERE conv = ? AND uid = ?",
                "DELETE FROM guest_members WHERE conv = ? AND uid = ?",
                "DELETE FROM roles WHERE conv = ? AND uid = ?",
            ] {
                tx.execute(sql, params![conv, uid.as_str()])?;
            }
        }
        EventKind::Ban { uid, reason } => {
            // BAN removes a member, takes the role away and ends an
            // invitation (6.3, 6.4).
            for sql in [
                "DELETE FROM members WHERE conv = ? AND uid = ?",
                "DELETE FROM guest_members WHERE conv = ? AND uid = ?",
                "DELETE FROM roles WHERE conv = ? AND uid = ?",
                "DELETE FROM invites WHERE conv = ? AND uid = ?",
            ] {
                tx.execute(sql, params![conv, uid.as_str()])?;
            }
            tx.execute(
                "INSERT OR REPLACE INTO room_bans (conv, uid, reason, seq) VALUES (?, ?, ?, ?)",
                params![conv, uid.as_str(), reason, seq],
            )?;
        }
        EventKind::Unban { uid } => {
            tx.execute(
                "DELETE FROM room_bans WHERE conv = ? AND uid = ?",
                params![conv, uid.as_str()],
            )?;
        }
        EventKind::Delete { target } => {
            let target = sql_seq(*target);
            let relation: Option<Option<String>> = tx
                .prepare_cached(
                    "SELECT relation FROM events WHERE conv = ? AND seq = ? AND verb = 'MSG'",
                )?
                .query_row(params![conv, target], |row| row.get(0))
                .optional()?;
            let mut erase = vec![target];
            // Deleting a message also deletes its edits and reactions; replies
            // stay (5.4).
            if is_plain(&relation) {
                let related = tx
                    .prepare_cached(
                        "SELECT seq FROM events WHERE conv = ? AND target = ? \
                         AND verb = 'MSG' AND relation IN ('edit', 'react')",
                    )?
                    .query_map(params![conv, target], |row| row.get::<_, i64>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                erase.extend(related);
            }
            for s in erase {
                tx.execute(
                    "UPDATE events SET deleted = 1, file_url = NULL, file_type = NULL, \
                     file_size = NULL WHERE conv = ? AND seq = ?",
                    params![conv, s],
                )?;
                tx.execute(
                    "DELETE FROM event_text WHERE conv = ? AND seq = ?",
                    params![conv, s],
                )?;
            }
        }
    }
    Ok(())
}

/// The seq of a message sent with `cid` in the 24 hours before `now` (7.6).
fn find_cid(
    conn: &Connection,
    conv: i64,
    from: &Uid,
    cid: &Cid,
    now: Timestamp,
) -> Result<Option<Seq>> {
    let since = ms(now).saturating_sub(CID_WINDOW_MS as i64);
    conn.prepare_cached(
        "SELECT seq FROM cids WHERE conv = ? AND author = ? AND cid = ? AND t >= ?",
    )?
    .query_row(params![conv, from.as_str(), cid.as_str(), since], |row| {
        row.get(0)
    })
    .optional()?
    .map(seq)
    .transpose()
}

/// Whether a stored relation column marks a plain message or a reply.
fn is_plain(relation: &Option<Option<String>>) -> bool {
    matches!(relation, Some(None)) || matches!(relation, Some(Some(r)) if r == "reply")
}

// ---------------------------------------------------------------------------

impl Store for SqliteStore {
    fn load_server_settings(&self, defaults: &ServerSettings) -> Result<ServerSettings> {
        self.write(|tx| {
            for setting in defaults.to_settings() {
                tx.execute(
                    "INSERT OR IGNORE INTO server_settings (key, value) VALUES (?, ?)",
                    params![setting.key(), setting.value()],
                )?;
            }
            let mut settings = defaults.clone();
            let mut stmt = tx.prepare_cached("SELECT key, value FROM server_settings")?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            for row in rows {
                let (key, value) = row?;
                let setting = ServerSetting::parse(&key, &value)
                    .map_err(|e| corrupt("server setting", format!("{key} ({e})")))?;
                settings.apply(&setting);
            }
            Ok(settings)
        })
    }

    fn set_server_setting(&self, setting: &ServerSetting) -> Result<()> {
        self.write(|tx| {
            tx.execute(
                "INSERT OR REPLACE INTO server_settings (key, value) VALUES (?, ?)",
                params![setting.key(), setting.value()],
            )?;
            Ok(())
        })
    }

    fn ensure_room(&self, room: &Room, now: Timestamp) -> Result<RoomRecord> {
        self.write(|tx| {
            if let Some(record) = load_room(tx, room)? {
                return Ok(record);
            }
            let id = take_id(tx, "conversation", now)?;
            tx.execute(
                "INSERT INTO conversations (id, kind, room, created) VALUES (?, 'room', ?, ?)",
                params![id.as_str(), room.as_str(), ms(now)],
            )?;
            let conv = tx.last_insert_rowid();
            tx.execute("INSERT INTO room_settings (conv) VALUES (?)", [conv])?;
            load_room(tx, room)?.ok_or(StoreError::NoConversation)
        })
    }

    fn rooms(&self) -> Result<Vec<RoomRecord>> {
        let conn = self.conn();
        let rows = conn
            .prepare_cached(&format!("SELECT {ROOM_COLUMNS} ORDER BY c.room"))?
            .query_map([], room_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter().map(|r| r.finish(&conn)).collect()
    }

    fn room(&self, room: &Room) -> Result<Option<RoomRecord>> {
        load_room(&self.conn(), room)
    }

    fn append(&self, conv: ConvKey, event: &NewEvent) -> Result<Appended> {
        self.write(|tx| {
            let conv = conv.0;
            if let Some(cid) = &event.cid
                && let Some(earlier) = find_cid(tx, conv, &event.from, cid, event.t)?
            {
                return Ok(Appended::Duplicate(earlier));
            }
            let next: i64 = tx
                .prepare_cached(
                    "UPDATE conversations SET head = head + 1 WHERE conv = ? RETURNING head",
                )?
                .query_row([conv], |row| row.get(0))
                .optional()?
                .ok_or(StoreError::NoConversation)?;
            let c = columns(&event.kind);
            tx.prepare_cached(
                "INSERT INTO events (conv, seq, t, author, verb, relation, target, subject, arg, \
                 file_url, file_type, file_size) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )?
            .execute(params![
                conv,
                next,
                ms(event.t),
                event.from.as_str(),
                event.kind.verb(),
                c.relation,
                c.target,
                c.subject,
                c.arg,
                c.file_url,
                c.file_type,
                c.file_size,
            ])?;
            if let Some(text) = c.text.as_deref().filter(|t| !t.is_empty()) {
                tx.prepare_cached("INSERT INTO event_text (conv, seq, text) VALUES (?, ?, ?)")?
                    .execute(params![conv, next, text])?;
            }
            apply_effects(tx, conv, next, event)?;
            if let Some(cid) = &event.cid {
                tx.prepare_cached(
                    "INSERT OR REPLACE INTO cids (conv, author, cid, seq, t) VALUES (?, ?, ?, ?, ?)",
                )?
                .execute(params![
                    conv,
                    event.from.as_str(),
                    cid.as_str(),
                    next,
                    ms(event.t)
                ])?;
            }
            Ok(Appended::New(seq(next)?))
        })
    }

    fn event(&self, conv: ConvKey, s: Seq) -> Result<Option<StoredEvent>> {
        let conn = self.conn();
        conn.prepare_cached(&format!(
            "SELECT {EVENT_COLUMNS} WHERE e.conv = ? AND e.seq = ?"
        ))?
        .query_row(params![conv.0, sql_seq(s)], event_from_row)
        .optional()?
        .map(EventRow::finish)
        .transpose()
    }

    fn history(&self, conv: ConvKey, q: HistoryQuery) -> Result<Page> {
        let limit = q.limit.clamp(1, i64::MAX as u64 - 1);
        let fetch = (limit + 1) as i64;
        let before = q.before.map_or(i64::MAX, sql_seq);
        let conn = self.conn();
        let rows = match q.after {
            Some(after) => {
                let after = i64::try_from(after).unwrap_or(i64::MAX);
                conn.prepare_cached(&format!(
                    "SELECT {EVENT_COLUMNS} WHERE e.conv = ? AND e.seq > ? AND e.seq < ? \
                     ORDER BY e.seq ASC LIMIT ?"
                ))?
                .query_map(params![conv.0, after, before, fetch], event_from_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?
            }
            None => {
                let mut rows = conn
                    .prepare_cached(&format!(
                        "SELECT {EVENT_COLUMNS} WHERE e.conv = ? AND e.seq < ? \
                         ORDER BY e.seq DESC LIMIT ?"
                    ))?
                    .query_map(params![conv.0, before, fetch], event_from_row)?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                rows.reverse();
                rows
            }
        };
        drop(conn);
        let more = rows.len() as u64 > limit;
        let mut events = rows
            .into_iter()
            .map(EventRow::finish)
            .collect::<Result<Vec<_>>>()?;
        if more {
            match q.after {
                // The extra row is the one after the page...
                Some(_) => {
                    events.pop();
                }
                // ...or the one before it.
                None => {
                    events.remove(0);
                }
            }
        }
        Ok(Page { events, more })
    }

    fn cid_seq(&self, conv: ConvKey, from: &Uid, cid: &Cid, now: Timestamp) -> Result<Option<Seq>> {
        find_cid(&self.conn(), conv.0, from, cid, now)
    }

    fn guest_members(&self) -> Result<Vec<(ConvKey, Uid)>> {
        self.conn()
            .prepare_cached("SELECT conv, uid FROM guest_members ORDER BY conv, uid")?
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })?
            .map(|r| {
                let (conv, uid) = r?;
                Ok((ConvKey(conv), parse("guest member", &uid)?))
            })
            .collect()
    }

    fn prune_cids(&self, before: Timestamp) -> Result<u64> {
        self.write(|tx| {
            let n = tx.execute("DELETE FROM cids WHERE t < ?", [ms(before)])?;
            Ok(n as u64)
        })
    }
}
