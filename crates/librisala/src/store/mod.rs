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
//!   The chat list's reads, across every account, are the client layer's.
//! - **Trust records**: [`Store`] implements [`TrustStore`](crate::addr::TrustStore).
//!
//! Two processes may open the same file at once, for example an app and its
//! iOS notification extension (PLAN.md 3.3). The cache uses WAL mode, a
//! busy timeout and short `BEGIN IMMEDIATE` transactions, and the sync
//! engine keeps no copy of persistent state in memory between calls.
//!
//! A [`Store`] is cheap to clone; clones share its SQLite connections. A
//! store on a file has two: one for writes, and one for reads. In WAL
//! mode a reader never waits for a writer, so reads from the cache return
//! at once even while a write waits for another process's lock. Each read
//! sees one consistent snapshot of what was committed. A store in memory
//! has one connection for both. Calls block, so async code should make
//! them off the runtime's worker threads.

mod chats;
mod cipher;
mod events;
mod mls;
mod outbox;
mod people;
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

pub use cipher::DatabaseKey;
pub(crate) use outbox::Claim;
pub use outbox::{Draft, FailReason, OutboxItem, OutboxState};
pub use read::{ConversationSummary, Member, Reaction, TimelineItem};

pub(crate) use chats::{ChatKey, ChatQuery, ChatRow, key_order};
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
    /// The cache's file could not be created.
    #[error("cache file: {0}")]
    File(#[from] std::io::Error),
    /// The cache could not be read with the key given: the key is wrong,
    /// or the file is not a cache.
    #[error("the cache's key is wrong, or the file is not a risala cache")]
    WrongKey,
    /// This build's SQLite is not SQLCipher, so the cache cannot be
    /// encrypted. Nothing was written.
    #[error("this build's SQLite cannot encrypt the cache: it is not SQLCipher")]
    NoCipher,
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
    /// Someone's display name was learned or changed (8.2). Read it with
    /// [`Store::user_name`].
    User {
        /// The account that learned it.
        account: AccountId,
        /// Whose name it is.
        uid: Uid,
    },
    /// A room's members or roles changed, from its events or from MEMBERS
    /// (6.1, 6.3, 8.3). Read them with [`Store::room_members`].
    Members {
        /// The conversation.
        conv: ConvId,
    },
    /// The account's blocks changed, or whether it hides blocked people
    /// (5.7). Rooms' timelines and unread counts may change with them.
    Blocks {
        /// The account.
        account: AccountId,
    },
}

/// Creates the file at `path` with mode 0600 on Unix, if there is none.
/// SQLite takes an empty file for a new database.
fn create_private(path: &Path) -> Result<(), StoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        // Not a file: SQLite's name for a database in memory.
        if path.as_os_str() == ":memory:" {
            return Ok(());
        }
        let created = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path);
        match created {
            // The umask may have cleared bits of the mode asked for.
            Ok(file) => file.set_permissions(std::fs::Permissions::from_mode(0o600))?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// The client's SQLite cache. See the [module docs](self).
#[derive(Clone)]
pub struct Store {
    conn: Arc<Mutex<Connection>>,
    /// The connection for reads, on a file. In memory, reads use `conn`.
    reader: Option<Arc<Mutex<Connection>>>,
    /// Random for each store opened, to tell its outbox claims from other
    /// processes' (7.6).
    instance: Arc<str>,
    /// Counts the claims handed out, one per connection.
    connections: Arc<std::sync::atomic::AtomicU64>,
}

impl fmt::Debug for Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Store").finish_non_exhaustive()
    }
}

impl Store {
    /// Opens the cache at `path`, creating it if needed, and brings its
    /// schema up to date.
    ///
    /// The file is encrypted with `key` (SQLCipher, PLAN.md 42), which
    /// must be the same every time. A wrong key gives
    /// [`StoreError::WrongKey`]. A cache from before encryption, in the
    /// clear, is encrypted with `key` first, keeping all it holds.
    ///
    /// On Unix a new cache is readable and writable by its owner only
    /// (0600), whatever the umask: it holds private history and a guest's
    /// session token (4.2). SQLite gives the `-wal` and `-shm` files the
    /// same mode. An existing file keeps its mode.
    pub fn open(path: impl AsRef<Path>, key: &DatabaseKey) -> Result<Store, StoreError> {
        let path = path.as_ref();
        create_private(path)?;
        cipher::encrypt_plaintext(path, key)?;
        let writer = Connection::open(path)?;
        writer.busy_timeout(BUSY_TIMEOUT)?;
        cipher::key(&writer, key)?;
        let mut store = Store::setup(writer)?;
        // After the writer, which has set WAL mode and the schema.
        let reader = Connection::open(path)?;
        reader.busy_timeout(BUSY_TIMEOUT)?;
        cipher::key(&reader, key)?;
        reader.pragma_update(None, "query_only", "ON")?;
        store.reader = Some(Arc::new(Mutex::new(reader)));
        Ok(store)
    }

    /// A cache in memory, for tests and short-lived tools. It is never
    /// written to disk, so it has no key.
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
            reader: None,
            instance: outbox::new_cid()?.as_str().into(),
            connections: Arc::default(),
        })
    }

    /// A claim for a new connection's outbox entries (7.6).
    ///
    /// A claim from this store instance but an earlier connection counts as
    /// abandoned at once, so run at most one connection per account on one
    /// store instance at a time, as [`Client`](crate::client::Client) does.
    /// Another process opens its own instance.
    pub(crate) fn new_claim(&self) -> Claim {
        Claim {
            instance: self.instance.to_string(),
            connection: self
                .connections
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        }
    }

    /// Whether `claim` was handed out by this store instance.
    pub(crate) fn is_own_instance(&self, claim: &Claim) -> bool {
        *claim.instance == *self.instance
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        // A panic while holding the lock leaves no transaction open: an
        // uncommitted rusqlite transaction rolls back when dropped.
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Runs `f` for reads: on the read connection, in one read
    /// transaction, so that it sees one snapshot and never waits for a
    /// write.
    pub(crate) fn read<T>(
        &self,
        f: impl FnOnce(&Connection) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let Some(reader) = &self.reader else {
            return f(&self.lock());
        };
        let mut conn = reader.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        let out = f(&tx)?;
        tx.commit()?;
        Ok(out)
    }

    /// Runs `f` in one write transaction (`BEGIN IMMEDIATE`), and returns
    /// its result with the changes it made. Nothing is written if `f`
    /// fails.
    pub(crate) fn write<T>(
        &self,
        f: impl FnOnce(&mut Tx<'_>) -> Result<T, StoreError>,
    ) -> Result<(T, Vec<Change>), StoreError> {
        self.write_with(f)
    }

    /// [`Store::write`] for `f` with an error type of its own, such as an
    /// MLS operation's. Nothing is written if `f` fails: OpenMLS's state
    /// on [`Tx::mls_storage`] rolls back with the rest.
    pub(crate) fn write_with<T, E: From<StoreError>>(
        &self,
        f: impl FnOnce(&mut Tx<'_>) -> Result<T, E>,
    ) -> Result<(T, Vec<Change>), E> {
        let mut conn = self.lock();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(StoreError::from)?;
        let mut w = Tx::new(tx);
        let out = f(&mut w)?;
        let changes = w.finish()?;
        Ok((out, changes))
    }

    /// A number that changes when another process commits a write to the
    /// cache (SQLite's `PRAGMA data_version`). Writes through this store
    /// and its clones do not change it. Compare it with an earlier value to
    /// learn cheaply whether to read again what is shown.
    ///
    /// `None` while this store is writing; ask again later. It never
    /// waits.
    pub fn data_version(&self) -> Result<Option<u64>, StoreError> {
        let conn = match self.conn.try_lock() {
            Ok(conn) => conn,
            Err(std::sync::TryLockError::WouldBlock) => return Ok(None),
            Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner(),
        };
        let v: i64 = conn.pragma_query_value(None, "data_version", |r| r.get(0))?;
        Ok(Some(v as u64))
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

    /// The fingerprint of the device key the server last accepted for the
    /// account (4.5), if it ever has.
    pub fn accepted_key(&self, account: AccountId) -> Result<Option<String>, StoreError> {
        self.read(|conn| {
            Ok(conn
                .query_row(
                    "SELECT accepted_key FROM accounts WHERE id = ?1",
                    [account.0],
                    |r| r.get(0),
                )
                .optional()?
                .flatten())
        })
    }

    /// Records that the server accepted the device key with this
    /// fingerprint for the account. Writes only if it changed.
    pub fn set_accepted_key(
        &self,
        account: AccountId,
        fingerprint: &str,
    ) -> Result<(), StoreError> {
        self.write(|tx| {
            tx.conn().execute(
                "UPDATE accounts SET accepted_key = ?2
                 WHERE id = ?1 AND accepted_key IS NOT ?2",
                rusqlite::params![account.0, fingerprint],
            )?;
            Ok(())
        })?;
        Ok(())
    }

    /// Whether an UNREGISTER of the account may have gone through with no
    /// answer seen (4.8): it was sent, or was about to be, and its answer
    /// was lost or never waited for. `Some(hosted)`, saying whether the
    /// server hosted the identity, or `None`.
    pub fn unregister_lost(&self, account: AccountId) -> Result<Option<bool>, StoreError> {
        self.read(|conn| {
            Ok(conn
                .query_row(
                    "SELECT unregister_lost FROM accounts WHERE id = ?1",
                    [account.0],
                    |r| r.get(0),
                )
                .optional()?
                .flatten())
        })
    }

    /// Records an UNREGISTER whose answer was lost, or forgets it. See
    /// [`unregister_lost`](Self::unregister_lost).
    pub fn set_unregister_lost(
        &self,
        account: AccountId,
        hosted: Option<bool>,
    ) -> Result<(), StoreError> {
        self.write(|tx| {
            tx.conn().execute(
                "UPDATE accounts SET unregister_lost = ?2 WHERE id = ?1",
                params![account.0, hosted],
            )?;
            Ok(())
        })?;
        Ok(())
    }

    /// Whether a REGISTER for the account's identity may have gone through
    /// with no answer seen yet (4.6): `Some(added)`, saying whether the
    /// account was added to the cache for it, or `None`.
    pub fn register_pending(&self, account: AccountId) -> Result<Option<bool>, StoreError> {
        self.read(|conn| {
            Ok(conn
                .query_row(
                    "SELECT register_pending FROM accounts WHERE id = ?1",
                    [account.0],
                    |r| r.get(0),
                )
                .optional()?
                .flatten())
        })
    }

    /// Records, before REGISTER is sent, that `uid` on `server` is being
    /// registered, adding the account if it is not in the cache. Returns
    /// the account, and whether an earlier REGISTER for it was still
    /// pending, which this leaves as it was. See
    /// [`register_pending`](Self::register_pending).
    pub fn begin_register(
        &self,
        server: &ServerAddr,
        uid: &Uid,
    ) -> Result<(AccountId, bool), StoreError> {
        let (out, _) = self.write(|tx| {
            let server = tx.server_id(server)?;
            let added = tx.conn().execute(
                "INSERT INTO accounts (server, uid) VALUES (?1, ?2)
                 ON CONFLICT (server, uid) DO NOTHING",
                params![server, uid.as_str()],
            )? == 1;
            let (id, pending): (i64, Option<bool>) = tx.conn().query_row(
                "SELECT id, register_pending FROM accounts WHERE server = ?1 AND uid = ?2",
                params![server, uid.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            if pending.is_none() {
                tx.conn().execute(
                    "UPDATE accounts SET register_pending = ?2 WHERE id = ?1",
                    params![id, added],
                )?;
            }
            Ok((AccountId(id), pending.is_some()))
        })?;
        Ok(out)
    }

    /// Settles a pending REGISTER for the account: if `registered`, it
    /// stays; if not, it goes if it was added for the REGISTER. Returns
    /// whether it went. Does nothing if none is pending.
    pub fn end_register(&self, account: AccountId, registered: bool) -> Result<bool, StoreError> {
        let (removed, _) = self.write(|tx| {
            if !registered {
                let removed = tx.conn().execute(
                    "DELETE FROM accounts WHERE id = ?1 AND register_pending = 1",
                    [account.0],
                )?;
                if removed == 1 {
                    return Ok(true);
                }
            }
            tx.conn().execute(
                "UPDATE accounts SET register_pending = NULL WHERE id = ?1",
                [account.0],
            )?;
            Ok(false)
        })?;
        Ok(removed)
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
