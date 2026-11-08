//! Push subscriptions (Section 9).
//!
//! Owned by task C4.

use rusqlite::{OptionalExtension as _, Row, params};

use super::conversations::ConversationId;
use super::{AccountId, Change, Store, StoreError, Tx};

/// This area's part of the schema.
pub(crate) const SCHEMA: &str = "
-- Push subscriptions (9.1): one per conversation's mailbox (mailbox set),
-- made on an anonymous connection, and one per account for Welcomes (conv
-- and mailbox NULL), made on the signed-in one. Each has its own URL and
-- random tag, so that they cannot be linked by them (9.1, Appendix C).
-- p256dh and auth are the RFC 8291 keys the bodies are encrypted to, and
-- private_key the device's half. state: 'adding' until the server said OK
-- to PUSH ADD, 'active', 'removing' until it said OK to PUSH DEL. renew_at
-- is when to send PUSH ADD again: a mailbox subscription lasts one
-- retention period from it (9.1).
CREATE TABLE push_subscriptions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    account     INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    conv        INTEGER REFERENCES conversations(id) ON DELETE SET NULL,
    mailbox     TEXT,
    url         TEXT NOT NULL UNIQUE,
    tag         TEXT NOT NULL UNIQUE,
    p256dh      BLOB NOT NULL,
    auth        BLOB NOT NULL,
    private_key BLOB NOT NULL,
    state       TEXT NOT NULL CHECK (state IN ('adding', 'active', 'removing')),
    renew_at    INTEGER,
    created     INTEGER NOT NULL
);

-- Push URLs the app handed over (Appendix C), not used yet: each
-- subscription takes one of its own.
CREATE TABLE push_urls (
    account INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    url     TEXT NOT NULL UNIQUE,
    added   INTEGER NOT NULL
);

-- Conversations whose mailbox pushes the user turned off (9.2).
CREATE TABLE push_off (
    conv INTEGER PRIMARY KEY REFERENCES conversations(id) ON DELETE CASCADE
);
";

/// A change to push subscriptions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PushChange {
    /// Subscriptions were added or removed.
    Subscriptions,
}

/// The state of a subscription.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubState {
    /// PUSH ADD not yet accepted.
    Adding,
    /// Registered.
    Active,
    /// PUSH DEL not yet accepted.
    Removing,
}

impl SubState {
    fn as_str(self) -> &'static str {
        match self {
            SubState::Adding => "adding",
            SubState::Active => "active",
            SubState::Removing => "removing",
        }
    }
}

/// A push subscription row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionRow {
    /// Its id.
    pub id: i64,
    /// The account.
    pub account: AccountId,
    /// The conversation of a mailbox subscription.
    pub conv: Option<ConversationId>,
    /// The mailbox of a mailbox subscription; `None` for the account's.
    pub mailbox: Option<String>,
    /// The URL.
    pub url: String,
    /// The tag.
    pub tag: String,
    /// The P-256 public key, 65 bytes.
    pub p256dh: Vec<u8>,
    /// The authentication secret, 16 bytes.
    pub auth: Vec<u8>,
    /// The P-256 private key, 32 bytes.
    pub private_key: Vec<u8>,
    /// Its state.
    pub state: SubState,
    /// When to renew it.
    pub renew_at: Option<u64>,
}

const SUB_COLUMNS: &str =
    "id, account, conv, mailbox, url, tag, p256dh, auth, private_key, state, renew_at";

fn sub_row(row: &Row<'_>) -> rusqlite::Result<SubscriptionRow> {
    let state: String = row.get(9)?;
    Ok(SubscriptionRow {
        id: row.get(0)?,
        account: AccountId(row.get(1)?),
        conv: row.get::<_, Option<i64>>(2)?.map(ConversationId),
        mailbox: row.get(3)?,
        url: row.get(4)?,
        tag: row.get(5)?,
        p256dh: row.get(6)?,
        auth: row.get(7)?,
        private_key: row.get(8)?,
        state: match state.as_str() {
            "adding" => SubState::Adding,
            "removing" => SubState::Removing,
            _ => SubState::Active,
        },
        renew_at: row.get::<_, Option<i64>>(10)?.map(|t| t as u64),
    })
}

/// A new subscription, for [`Tx::add_subscription`].
#[derive(Debug, Clone)]
pub struct NewSubscription<'a> {
    /// The account.
    pub account: AccountId,
    /// The conversation, for a mailbox subscription.
    pub conv: Option<ConversationId>,
    /// The mailbox, for a mailbox subscription.
    pub mailbox: Option<&'a str>,
    /// The URL.
    pub url: &'a str,
    /// The tag.
    pub tag: &'a str,
    /// The P-256 public key.
    pub p256dh: &'a [u8],
    /// The authentication secret.
    pub auth: &'a [u8],
    /// The P-256 private key.
    pub private_key: &'a [u8],
}

impl Tx<'_> {
    /// Keeps a new subscription, in state `adding`. Returns its id.
    pub(crate) fn add_subscription(
        &mut self,
        s: &NewSubscription<'_>,
        now: u64,
    ) -> Result<i64, StoreError> {
        self.conn().execute(
            "INSERT INTO push_subscriptions
                 (account, conv, mailbox, url, tag, p256dh, auth, private_key, state, created)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'adding', ?9)",
            params![
                s.account.0,
                s.conv.map(|c| c.0),
                s.mailbox,
                s.url,
                s.tag,
                s.p256dh,
                s.auth,
                s.private_key,
                now as i64
            ],
        )?;
        self.changed(Change::Push(PushChange::Subscriptions));
        Ok(self.conn().last_insert_rowid())
    }

    /// Sets a subscription's state and when to renew it.
    pub(crate) fn set_subscription(
        &mut self,
        id: i64,
        state: SubState,
        renew_at: Option<u64>,
    ) -> Result<(), StoreError> {
        self.conn().execute(
            "UPDATE push_subscriptions SET state = ?2, renew_at = ?3 WHERE id = ?1",
            params![id, state.as_str(), renew_at.map(|t| t as i64)],
        )?;
        self.changed(Change::Push(PushChange::Subscriptions));
        Ok(())
    }

    /// Forgets a subscription.
    pub(crate) fn remove_subscription(&mut self, id: i64) -> Result<(), StoreError> {
        self.conn()
            .execute("DELETE FROM push_subscriptions WHERE id = ?1", params![id])?;
        self.changed(Change::Push(PushChange::Subscriptions));
        Ok(())
    }

    /// The account's subscriptions.
    pub(crate) fn subscriptions(
        &self,
        account: AccountId,
    ) -> Result<Vec<SubscriptionRow>, StoreError> {
        let mut stmt = self.conn().prepare_cached(&format!(
            "SELECT {SUB_COLUMNS} FROM push_subscriptions WHERE account = ?1 ORDER BY id"
        ))?;
        let rows = stmt.query_map(params![account.0], sub_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Takes one of the URLs the app handed over, if any is left.
    pub(crate) fn take_push_url(
        &mut self,
        account: AccountId,
    ) -> Result<Option<String>, StoreError> {
        let url: Option<String> = self
            .conn()
            .query_row(
                "SELECT url FROM push_urls WHERE account = ?1 ORDER BY rowid LIMIT 1",
                params![account.0],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(url) = &url {
            self.conn()
                .execute("DELETE FROM push_urls WHERE url = ?1", params![url])?;
        }
        Ok(url)
    }

    /// Keeps URLs the app handed over. Returns how many were new.
    pub(crate) fn add_push_urls(
        &mut self,
        account: AccountId,
        urls: &[String],
        now: u64,
    ) -> Result<usize, StoreError> {
        let mut added = 0;
        for url in urls {
            let used: i64 = self.conn().query_row(
                "SELECT count(*) FROM push_subscriptions WHERE url = ?1",
                params![url],
                |r| r.get(0),
            )?;
            if used == 0 {
                added += self.conn().execute(
                    "INSERT INTO push_urls (account, url, added) VALUES (?1, ?2, ?3)
                     ON CONFLICT DO NOTHING",
                    params![account.0, url, now as i64],
                )?;
            }
        }
        Ok(added)
    }

    /// Drops the URLs the app handed over and no subscription took.
    pub(crate) fn clear_push_urls(&mut self, account: AccountId) -> Result<(), StoreError> {
        self.conn().execute(
            "DELETE FROM push_urls WHERE account = ?1",
            params![account.0],
        )?;
        Ok(())
    }

    /// Whether the user turned off a conversation's mailbox pushes.
    pub(crate) fn push_off(&self, conv: ConversationId) -> Result<bool, StoreError> {
        let n: i64 = self.conn().query_row(
            "SELECT count(*) FROM push_off WHERE conv = ?1",
            params![conv.0],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// Turns a conversation's mailbox pushes off or on.
    pub(crate) fn set_push_off(
        &mut self,
        conv: ConversationId,
        off: bool,
    ) -> Result<(), StoreError> {
        if off {
            self.conn().execute(
                "INSERT INTO push_off (conv) VALUES (?1) ON CONFLICT DO NOTHING",
                params![conv.0],
            )?;
        } else {
            self.conn()
                .execute("DELETE FROM push_off WHERE conv = ?1", params![conv.0])?;
        }
        self.changed(Change::Push(PushChange::Subscriptions));
        Ok(())
    }
}

impl Store {
    /// Every subscription this device holds, of every account.
    pub fn subscription_rows(&self) -> Result<Vec<SubscriptionRow>, StoreError> {
        self.read(|conn| {
            let mut stmt = conn.prepare(&format!(
                "SELECT {SUB_COLUMNS} FROM push_subscriptions ORDER BY id"
            ))?;
            let rows = stmt.query_map([], sub_row)?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    /// How many unused push URLs the account has.
    pub fn push_urls_left(&self, account: AccountId) -> Result<usize, StoreError> {
        self.read(|conn| {
            let n: i64 = conn.query_row(
                "SELECT count(*) FROM push_urls WHERE account = ?1",
                params![account.0],
                |r| r.get(0),
            )?;
            Ok(n as usize)
        })
    }
}
