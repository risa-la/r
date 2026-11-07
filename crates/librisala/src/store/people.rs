//! People: display names (8.2), room members as MEMBERS lists them (8.3),
//! and blocks, with hiding blocked people in rooms (5.7).

use std::collections::{HashMap, HashSet};

use risala_proto::names::{BlockTarget, Conv, Uid};
use risala_proto::types::Role;
use rusqlite::{OptionalExtension, params};

use super::events::Tx;
use super::{AccountId, Change, ConvId, Store, StoreError, parse};

/// SQL: whether the event `e` is hidden: a message from someone the
/// account blocked, in a room, while the account hides blocked people
/// (5.7). A domain block covers the domain's subdomains. The account's own
/// messages are never hidden.
pub(super) const HIDDEN: &str = "(e.verb = 'MSG' AND e.own = 0 AND EXISTS (
    SELECT 1 FROM convs hc
    JOIN accounts ha ON ha.id = hc.account
    JOIN blocks b ON b.account = ha.id
    WHERE hc.id = e.conv AND ha.hide_blocked = 1 AND substr(hc.name, 1, 1) = '#'
        AND (b.target = e.author
            OR (substr(b.target, 1, 2) = '*@' AND instr(e.author, '@') > 0
                AND (substr(e.author, instr(e.author, '@') + 1) = substr(b.target, 3)
                    OR substr(e.author, 1 - length(b.target)) = '.' || substr(b.target, 3))))))";

impl Tx<'_> {
    /// Records `uid`'s display name, escaped; empty if they have none
    /// (8.2). Returns whether it changed.
    pub(crate) fn set_user_name(
        &mut self,
        account: AccountId,
        uid: &Uid,
        name: &str,
    ) -> Result<bool, StoreError> {
        let old: Option<String> = self
            .conn()
            .query_row(
                "SELECT name FROM users WHERE account = ?1 AND uid = ?2",
                params![account.0, uid.as_str()],
                |r| r.get(0),
            )
            .optional()?;
        if old.as_deref() == Some(name) {
            return Ok(false);
        }
        self.conn().execute(
            "INSERT INTO users (account, uid, name) VALUES (?1, ?2, ?3)
             ON CONFLICT (account, uid) DO UPDATE SET name = excluded.name",
            params![account.0, uid.as_str(), name],
        )?;
        self.changed(Change::User {
            account,
            uid: uid.clone(),
        });
        Ok(true)
    }

    /// Records a room's members and roles as MEMBERS listed them (8.3).
    /// Everyone listed is in the room, and anyone else is not.
    ///
    /// `at` is the newest seq known when MEMBERS was sent. The server
    /// computed the list after that, so it covers every event up to `at`;
    /// an event after `at`, stored before or after, counts over it, as
    /// for snapshots.
    pub(crate) fn set_roster(
        &mut self,
        conv: ConvId,
        at: u64,
        members: &[(Uid, Role)],
    ) -> Result<(), StoreError> {
        let listed: HashSet<&str> = members.iter().map(|(u, _)| u.as_str()).collect();
        for (uid, role) in members {
            self.member_field(conv, uid.as_str(), "joined", Some(true), at)?;
            self.member_role(conv, uid.as_str(), role.as_str(), at)?;
        }
        let joined: Vec<String> = {
            let mut stmt = self
                .conn()
                .prepare_cached("SELECT uid FROM room_members WHERE conv = ?1 AND joined = 1")?;
            stmt.query_map([conv.0], |r| r.get(0))?
                .collect::<Result<_, _>>()?
        };
        for uid in joined {
            if !listed.contains(uid.as_str()) {
                self.member_field(conv, &uid, "joined", Some(false), at)?;
            }
        }
        self.changed(Change::Members { conv });
        Ok(())
    }

    /// Replaces the account's blocks with the list BLOCKS returned (5.7).
    /// Returns whether they changed.
    pub(crate) fn set_blocks(
        &mut self,
        account: AccountId,
        targets: &[BlockTarget],
    ) -> Result<bool, StoreError> {
        let old: HashSet<String> = blocks_of(self.conn(), account)?
            .iter()
            .map(ToString::to_string)
            .collect();
        let new: HashSet<String> = targets.iter().map(ToString::to_string).collect();
        if old == new {
            return Ok(false);
        }
        self.conn()
            .execute("DELETE FROM blocks WHERE account = ?1", [account.0])?;
        for target in &new {
            self.conn().execute(
                "INSERT INTO blocks (account, target) VALUES (?1, ?2)",
                params![account.0, target],
            )?;
        }
        self.changed(Change::Blocks { account });
        Ok(true)
    }

    /// Adds a block, or removes one (5.7). Returns whether the blocks
    /// changed.
    pub(crate) fn set_block(
        &mut self,
        account: AccountId,
        target: &BlockTarget,
        on: bool,
    ) -> Result<bool, StoreError> {
        let target = target.to_string();
        let n = if on {
            self.conn().execute(
                "INSERT INTO blocks (account, target) VALUES (?1, ?2) ON CONFLICT DO NOTHING",
                params![account.0, target],
            )?
        } else {
            self.conn().execute(
                "DELETE FROM blocks WHERE account = ?1 AND target = ?2",
                params![account.0, target],
            )?
        };
        if n > 0 {
            self.changed(Change::Blocks { account });
        }
        Ok(n > 0)
    }
}

fn blocks_of(
    conn: &rusqlite::Connection,
    account: AccountId,
) -> Result<Vec<BlockTarget>, StoreError> {
    let mut stmt =
        conn.prepare_cached("SELECT target FROM blocks WHERE account = ?1 ORDER BY target")?;
    let rows: Vec<String> = stmt
        .query_map([account.0], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    rows.iter().map(|t| parse(t, "block")).collect()
}

fn hides(conn: &rusqlite::Connection, account: AccountId) -> Result<bool, StoreError> {
    Ok(conn
        .query_row(
            "SELECT hide_blocked FROM accounts WHERE id = ?1",
            [account.0],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(false))
}

impl Store {
    /// `uid`'s display name as the account last learned it, escaped (8.2).
    /// `Some("")` if they have none, and `None` if it is not known.
    pub fn user_name(&self, account: AccountId, uid: &Uid) -> Result<Option<String>, StoreError> {
        self.read(|conn| {
            Ok(conn
                .query_row(
                    "SELECT name FROM users WHERE account = ?1 AND uid = ?2",
                    params![account.0, uid.as_str()],
                    |r| r.get(0),
                )
                .optional()?)
        })
    }

    /// The display names known for `uids`, escaped, as for
    /// [`user_name`](Self::user_name). Users whose name is not known are
    /// left out.
    pub fn user_names(
        &self,
        account: AccountId,
        uids: &[Uid],
    ) -> Result<HashMap<Uid, String>, StoreError> {
        self.read(|conn| {
            let mut stmt =
                conn.prepare_cached("SELECT name FROM users WHERE account = ?1 AND uid = ?2")?;
            let mut out = HashMap::new();
            for uid in uids {
                let name: Option<String> = stmt
                    .query_row(params![account.0, uid.as_str()], |r| r.get(0))
                    .optional()?;
                if let Some(name) = name {
                    out.insert(uid.clone(), name);
                }
            }
            Ok(out)
        })
    }

    /// The account's blocks (5.7), as far as the cache knows, in byte
    /// order.
    pub fn blocks(&self, account: AccountId) -> Result<Vec<BlockTarget>, StoreError> {
        self.read(|conn| blocks_of(conn, account))
    }

    /// Whether one of the account's blocks covers `uid` (5.7).
    pub fn is_blocked(&self, account: AccountId, uid: &Uid) -> Result<bool, StoreError> {
        Ok(self.blocks(account)?.iter().any(|b| b.covers(uid)))
    }

    /// Whether the account hides blocked people's messages in rooms (5.7).
    pub fn hides_blocked(&self, account: AccountId) -> Result<bool, StoreError> {
        self.read(|conn| hides(conn, account))
    }

    /// Whether `uid` is hidden in `conv`: a room, while the account hides
    /// blocked people and has blocked them (5.7).
    pub fn is_hidden(
        &self,
        account: AccountId,
        conv: &Conv,
        uid: &Uid,
    ) -> Result<bool, StoreError> {
        if !conv.is_room() {
            return Ok(false);
        }
        self.read(|conn| {
            Ok(hides(conn, account)? && blocks_of(conn, account)?.iter().any(|b| b.covers(uid)))
        })
    }

    /// Hides blocked people's messages in rooms, or shows them again
    /// (5.7). They stay stored either way. Returns the changes, for the
    /// UI.
    pub fn set_hide_blocked(
        &self,
        account: AccountId,
        hide: bool,
    ) -> Result<Vec<Change>, StoreError> {
        let ((), changes) = self.write(|tx| {
            let n = tx.conn().execute(
                "UPDATE accounts SET hide_blocked = ?2 WHERE id = ?1 AND hide_blocked != ?2",
                params![account.0, hide],
            )?;
            if n > 0 {
                tx.changed(Change::Blocks { account });
            }
            Ok(())
        })?;
        Ok(changes)
    }
}
