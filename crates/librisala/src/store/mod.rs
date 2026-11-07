//! The client's SQLite cache (PLAN.md 3.3).
//!
//! A [`Store`] holds servers and their trust records (2.2), accounts,
//! conversations with their ids, sync points and read markers (7.1, 7.4),
//! events (5.2), tables derived from the events, and the outbox (7.6).
//!
//! - **Writes** come from the sync engine ([`crate::sync`]), through
//!   crate-internal transactions. Each one is short and returns the
//!   [`Change`]s it made, for the UI.
//! - **Reads** are public: [`Store::conversations`], [`Store::timeline`],
//!   [`Store::unread`], [`Store::export`] and the like. They work offline.
//! - **Trust records**: [`Store`] implements [`TrustStore`](crate::addr::TrustStore).
//!
//! Two processes may open the same file at once, for example an app and its
//! iOS notification extension (PLAN.md 3.3). The cache uses WAL mode, a
//! busy timeout and short `BEGIN IMMEDIATE` transactions, and the sync
//! engine keeps no copy of persistent state in memory between calls.
//!
//! A [`Store`] is cheap to clone; clones share one SQLite connection. Its
//! calls block, so async code should make them off the runtime's worker
//! threads.

mod events;
mod outbox;
mod read;
mod schema;
mod trust;

use std::fmt;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use risala_proto::names::{Conv, Id, Name, Room, Seq};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::addr::ServerAddr;
use risala_proto::names::Uid;

pub use outbox::{Draft, FailReason, OutboxItem, OutboxState};
pub use read::{ConversationSummary, Member, Reaction, TimelineItem};

pub(crate) use events::{ConvRow, Tx};

/// How long a write waits for another process's transaction to finish.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// The cache failed.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// SQLite reported an error.
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// The file was written by a newer version of librisala.
    #[error("the cache has schema version {0}, newer than this build understands")]
    TooNew(u32),
    /// Something stored could not be read back, such as a malformed line.
    #[error("corrupt cache: {0}")]
    Corrupt(String),
    /// The system's random number generator failed.
    #[error("random number generator: {0}")]
    Random(String),
    /// An account, conversation or outbox entry does not exist.
    #[error("not found: {0}")]
    NotFound(&'static str),
}

macro_rules! row_id {
    ($(#[$meta:meta])* $ty:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $ty(pub(crate) i64);

        impl $ty {
            /// The row id, stable for as long as the row exists. It is never
            /// reused for another row.
            pub fn get(self) -> i64 {
                self.0
            }
        }

        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

row_id!(
    /// An account in the cache: a uid on a server.
    AccountId
);
row_id!(
    /// A conversation in the cache, for one account.
    ConvId
);
row_id!(
    /// An entry in the outbox (7.6).
    OutboxId
);

/// A change the cache made, for the UI to show.
///
/// The timeline is every stored event except edits, reactions and DELETE
/// events, which change other items instead (5.3, 5.4). Read the new state
/// with [`Store::message`], [`Store::timeline`] or
/// [`Store::conversation_by_id`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Change {
    /// A timeline item was stored.
    Inserted {
        /// The conversation.
        conv: ConvId,
        /// The item's seq.
        seq: Seq,
    },
    /// A stored timeline item changed: it was edited or deleted, or its
    /// reactions changed.
    Updated {
        /// The conversation.
        conv: ConvId,
        /// The item's seq.
        seq: Seq,
    },
    /// The conversation's history was discarded, because the server now
    /// has a different conversation under its name (7.1).
    Cleared {
        /// The conversation.
        conv: ConvId,
    },
    /// A conversation was added, or its summary changed: its id, sync
    /// point, head, read marker or whether the account is in it.
    Conversation {
        /// The conversation.
        conv: ConvId,
    },
    /// A conversation and its history were removed, after DROP (10.4).
    ConversationRemoved {
        /// The conversation's row, which no longer exists.
        conv: ConvId,
        /// Its name.
        name: Conv,
    },
    /// An outbox entry was added or changed state.
    Outbox {
        /// The entry.
        id: OutboxId,
    },
}

/// The client's SQLite cache. See the [module docs](self).
#[derive(Clone)]
pub struct Store {
    conn: Arc<Mutex<Connection>>,
}

impl fmt::Debug for Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Store").finish_non_exhaustive()
    }
}

impl Store {
    /// Opens the cache at `path`, creating it if needed, and brings its
    /// schema up to date.
    pub fn open(path: impl AsRef<Path>) -> Result<Store, StoreError> {
        Store::setup(Connection::open(path)?)
    }

    /// A cache in memory, for tests and short-lived tools.
    pub fn open_in_memory() -> Result<Store, StoreError> {
        Store::setup(Connection::open_in_memory()?)
    }

    fn setup(mut conn: Connection) -> Result<Store, StoreError> {
        conn.busy_timeout(BUSY_TIMEOUT)?;
        // In memory, the journal mode stays "memory"; that is fine.
        let _mode: String =
            conn.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        schema::migrate(&mut conn)?;
        Ok(Store {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        // A panic while holding the lock leaves no transaction open: an
        // uncommitted rusqlite transaction rolls back when dropped.
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Runs `f` on the connection, for reads.
    pub(crate) fn read<T>(
        &self,
        f: impl FnOnce(&Connection) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        f(&self.lock())
    }

    /// Runs `f` in one write transaction (`BEGIN IMMEDIATE`), and returns
    /// its result with the changes it made. Nothing is written if `f`
    /// fails.
    pub(crate) fn write<T>(
        &self,
        f: impl FnOnce(&mut Tx<'_>) -> Result<T, StoreError>,
    ) -> Result<(T, Vec<Change>), StoreError> {
        let mut conn = self.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut w = Tx::new(tx);
        let out = f(&mut w)?;
        let changes = w.finish()?;
        Ok((out, changes))
    }

    /// The account for `uid` on `server`, created if it does not exist.
    pub fn account(&self, server: &ServerAddr, uid: &Uid) -> Result<AccountId, StoreError> {
        let (id, _) = self.write(|tx| {
            let server = tx.server_id(server)?;
            tx.conn().execute(
                "INSERT INTO accounts (server, uid) VALUES (?1, ?2)
                 ON CONFLICT (server, uid) DO NOTHING",
                params![server, uid.as_str()],
            )?;
            let id = tx.conn().query_row(
                "SELECT id FROM accounts WHERE server = ?1 AND uid = ?2",
                params![server, uid.as_str()],
                |row| row.get(0),
            )?;
            Ok(AccountId(id))
        })?;
        Ok(id)
    }

    /// Every account, with its server and uid.
    pub fn accounts(&self) -> Result<Vec<(AccountId, ServerAddr, Uid)>, StoreError> {
        self.read(|conn| {
            let mut stmt = conn.prepare_cached(
                "SELECT a.id, s.addr, a.uid FROM accounts a JOIN servers s ON s.id = a.server
                 ORDER BY a.id",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;
            let mut out = Vec::new();
            for row in rows {
                let (id, addr, uid) = row?;
                out.push((
                    AccountId(id),
                    parse(&addr, "server address")?,
                    parse(&uid, "uid")?,
                ));
            }
            Ok(out)
        })
    }

    /// The uid of an account.
    pub fn account_uid(&self, account: AccountId) -> Result<Uid, StoreError> {
        self.read(|conn| {
            let uid: Option<String> = conn
                .query_row(
                    "SELECT uid FROM accounts WHERE id = ?1",
                    [account.0],
                    |row| row.get(0),
                )
                .optional()?;
            parse(&uid.ok_or(StoreError::NotFound("account"))?, "uid")
        })
    }

    /// The rooms to join again after reconnecting, in name order. Guests
    /// leave their rooms when they disconnect (4.2); the client layer
    /// keeps this list for them.
    pub fn rejoin_rooms(&self, account: AccountId) -> Result<Vec<Room>, StoreError> {
        self.read(|conn| {
            let mut stmt =
                conn.prepare_cached("SELECT room FROM rejoin WHERE account = ?1 ORDER BY room")?;
            let rooms = stmt
                .query_map([account.0], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            rooms.iter().map(|r| parse(r, "room")).collect()
        })
    }

    /// Adds `room` to the rooms to join again after reconnecting, or
    /// removes it. See [`rejoin_rooms`](Self::rejoin_rooms).
    pub fn set_rejoin(&self, account: AccountId, room: &Room, on: bool) -> Result<(), StoreError> {
        self.write(|tx| {
            if on {
                tx.conn().execute(
                    "INSERT INTO rejoin (account, room) VALUES (?1, ?2)
                     ON CONFLICT DO NOTHING",
                    params![account.0, room.as_str()],
                )?;
            } else {
                tx.conn().execute(
                    "DELETE FROM rejoin WHERE account = ?1 AND room = ?2",
                    params![account.0, room.as_str()],
                )?;
            }
            Ok(())
        })?;
        Ok(())
    }

    /// The guest session the account last signed in to (4.2): the name it
    /// got, which may be a numbered fallback, and the token that resumes
    /// it. `None` if there is none. The token is a secret.
    pub fn guest_session(&self, account: AccountId) -> Result<Option<(Name, Id)>, StoreError> {
        self.read(|conn| {
            let row: Option<(Option<String>, Option<String>)> = conn
                .query_row(
                    "SELECT guest_name, guest_token FROM accounts WHERE id = ?1",
                    [account.0],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            match row {
                Some((Some(name), Some(token))) => Ok(Some((
                    parse(&name, "guest name")?,
                    parse(&token, "guest token")?,
                ))),
                _ => Ok(None),
            }
        })
    }

    /// Records the guest session the account signed in to, or forgets it.
    /// See [`guest_session`](Self::guest_session).
    pub fn set_guest_session(
        &self,
        account: AccountId,
        session: Option<(&Name, &Id)>,
    ) -> Result<(), StoreError> {
        let (name, token) = match session {
            Some((name, token)) => (Some(name.as_str()), Some(token.as_str())),
            None => (None, None),
        };
        self.write(|tx| {
            tx.conn().execute(
                "UPDATE accounts SET guest_name = ?2, guest_token = ?3 WHERE id = ?1",
                params![account.0, name, token],
            )?;
            Ok(())
        })?;
        Ok(())
    }

    /// Removes an account with its conversations, history and outbox.
    pub fn remove_account(&self, account: AccountId) -> Result<(), StoreError> {
        self.write(|tx| {
            tx.conn()
                .execute("DELETE FROM accounts WHERE id = ?1", [account.0])?;
            Ok(())
        })?;
        Ok(())
    }
}

/// Parses a value read back from the cache.
pub(crate) fn parse<T: std::str::FromStr>(s: &str, what: &str) -> Result<T, StoreError> {
    s.parse()
        .map_err(|_| StoreError::Corrupt(format!("bad {what}: {s:?}")))
}

/// A seq read back from the cache.
pub(crate) fn seq(n: i64) -> Result<Seq, StoreError> {
    u64::try_from(n)
        .ok()
        .and_then(Seq::new)
        .ok_or_else(|| StoreError::Corrupt(format!("bad seq {n}")))
}

/// A seq or count as SQLite stores it. Every seq fits (3.5).
pub(crate) fn sql(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

/// An optional id read back from the cache.
pub(crate) fn opt_id(s: Option<String>) -> Result<Option<Id>, StoreError> {
    s.map(|s| parse(&s, "conversation id")).transpose()
}

#[cfg(test)]
mod tests;
