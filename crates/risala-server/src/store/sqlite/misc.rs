//! [`MiscStore`] on SQLite, and the tables of presence, push and reports
//! (5.8, 8.3, 9).

use rusqlite::{OptionalExtension as _, Row, Transaction, params};
use sha2::{Digest as _, Sha384};

use risala_proto::binary::{PushAuth, PushKey, ReportData};
use risala_proto::mls::Pseudonym;
use risala_proto::names::{BoxName, Id, Uid};
use risala_proto::record::DeviceId;
use risala_proto::time::Timestamp;
use risala_proto::types::PushUrl;

use super::SqliteStore;
use crate::store::misc::{
    NewPushSubscription, NewReport, PushAdded, PushSubscription, PushTarget, StoredReport,
};
use crate::store::{MiscStore, Result, StoreError, fixed, millis, parsed, timestamp};

/// The misc area's tables.
pub(super) const SCHEMA: &str = "
-- The identities that turned presence on (8.3). Off has no row.
CREATE TABLE presence (
    uid TEXT PRIMARY KEY
) STRICT, WITHOUT ROWID;

-- Push subscriptions (9.1): a mailbox subscription has a box and expires
-- one retention period after it was made or renewed; an account
-- subscription has a device. The server must send to the URL, so it keeps
-- it, and looks it up by its hash. Nothing links a mailbox subscription to
-- an identity (9.1).
CREATE TABLE push_subscriptions (
    id INTEGER PRIMARY KEY,
    url TEXT NOT NULL,
    url_hash BLOB NOT NULL CHECK (length(url_hash) = 48), -- SHA-384 of url
    tag TEXT NOT NULL,
    key BLOB NOT NULL CHECK (length(key) = 65), -- P-256 public key
    auth BLOB NOT NULL CHECK (length(auth) = 16),
    box BLOB CHECK (length(box) = 16),
    expires INTEGER,                -- ms, a mailbox subscription's end
    uid TEXT,                       -- an account subscription's identity...
    device BLOB CHECK (length(device) = 48), -- ...and device id
    failing_since INTEGER,          -- ms of the first of a run of failures (9.3)
    CHECK ((box IS NULL) != (device IS NULL)),
    CHECK ((box IS NULL) = (expires IS NULL)),
    CHECK ((device IS NULL) = (uid IS NULL))
) STRICT;
CREATE UNIQUE INDEX push_mailbox ON push_subscriptions (box, url_hash) WHERE box IS NOT NULL;
CREATE UNIQUE INDEX push_account ON push_subscriptions (device, url_hash) WHERE device IS NOT NULL;
CREATE INDEX push_uid ON push_subscriptions (uid) WHERE uid IS NOT NULL;
CREATE INDEX push_expires ON push_subscriptions (expires) WHERE expires IS NOT NULL;

-- Reports to the operators (5.8), open until resolved. A resolved report
-- is deleted, with its copies.
CREATE TABLE reports (
    id TEXT PRIMARY KEY,
    box BLOB NOT NULL CHECK (length(box) = 16),
    report TEXT NOT NULL,           -- the RisalaReport, in base64, as received
    t INTEGER NOT NULL,             -- ms
    pseudonym BLOB NOT NULL CHECK (length(pseudonym) = 16), -- the target's
    reporter TEXT                   -- the reporter, if signed in
) STRICT;
CREATE INDEX reports_t ON reports (t);

-- Copies of the posts a report names, kept until it is resolved even if
-- they expire (5.8, 7.5).
CREATE TABLE report_posts (
    report TEXT NOT NULL REFERENCES reports (id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    t INTEGER NOT NULL,             -- ms
    message BLOB NOT NULL,          -- the MLSMessage
    PRIMARY KEY (report, seq)
) STRICT;
";

/// The columns [`subscription`] reads, in order.
const SUB_COLUMNS: &str = "id, url, tag, key, auth, box, uid, device, failing_since";

/// Reads a row of [`SUB_COLUMNS`].
fn subscription(row: &Row<'_>) -> Result<PushSubscription> {
    let url: String = row.get(1)?;
    let tag: String = row.get(2)?;
    let key: Vec<u8> = row.get(3)?;
    let auth: Vec<u8> = row.get(4)?;
    let mailbox: Option<Vec<u8>> = row.get(5)?;
    let uid: Option<String> = row.get(6)?;
    let device: Option<Vec<u8>> = row.get(7)?;
    let failing_since: Option<i64> = row.get(8)?;
    let target = match (mailbox, uid, device) {
        (Some(mailbox), None, None) => {
            PushTarget::Mailbox(BoxName::from_bytes(fixed("box", &mailbox)?))
        }
        (None, Some(uid), Some(device)) => PushTarget::Device {
            uid: parsed("uid", &uid)?,
            device: DeviceId::from_bytes(fixed("device", &device)?),
        },
        _ => return Err(StoreError::Corrupt("a push subscription's target".into())),
    };
    Ok(PushSubscription {
        id: row.get(0)?,
        target,
        url: parsed("push url", &url)?,
        tag: parsed("push tag", &tag)?,
        key: PushKey::from_bytes(fixed("push key", &key)?),
        auth: PushAuth::from_bytes(fixed("push auth", &auth)?),
        failing_since: failing_since.map(timestamp).transpose()?,
    })
}

/// The `WHERE` clause and its two values that pick a target's
/// subscriptions.
fn target_clause(target: &PushTarget) -> (&'static str, Vec<u8>) {
    match target {
        PushTarget::Mailbox(mailbox) => ("box = ?", mailbox.as_bytes().to_vec()),
        PushTarget::Device { device, .. } => ("device = ?", device.as_bytes().to_vec()),
    }
}

fn url_hash(url: &PushUrl) -> Vec<u8> {
    Sha384::digest(url.as_str().as_bytes()).to_vec()
}

fn count(tx: &Transaction<'_>, sql: &str, value: &[u8]) -> Result<u64> {
    let n: i64 = tx.query_row(sql, [value], |row| row.get(0))?;
    Ok(u64::try_from(n).unwrap_or(0))
}

impl MiscStore for SqliteStore {
    fn presence_on(&self, uid: &Uid) -> Result<bool> {
        self.read(|tx| {
            Ok(tx
                .query_row(
                    "SELECT 1 FROM presence WHERE uid = ?",
                    [uid.as_str()],
                    |_| Ok(()),
                )
                .optional()?
                .is_some())
        })
    }

    fn set_presence(&self, uid: &Uid, on: bool) -> Result<()> {
        self.write(|tx| {
            if on {
                tx.execute(
                    "INSERT INTO presence (uid) VALUES (?) ON CONFLICT DO NOTHING",
                    [uid.as_str()],
                )?;
            } else {
                tx.execute("DELETE FROM presence WHERE uid = ?", [uid.as_str()])?;
            }
            Ok(())
        })
    }

    fn add_push(&self, sub: &NewPushSubscription, max: usize) -> Result<PushAdded> {
        self.write(|tx| {
            let (clause, value) = target_clause(&sub.target);
            let hash = url_hash(&sub.url);
            let existing: Option<i64> = tx
                .query_row(
                    &format!("SELECT id FROM push_subscriptions WHERE {clause} AND url_hash = ?"),
                    params![value, hash],
                    |row| row.get(0),
                )
                .optional()?;
            let expires = sub.expires.map(millis);
            if let Some(id) = existing {
                tx.execute(
                    "UPDATE push_subscriptions SET tag = ?, key = ?, auth = ?, expires = ?,
                     failing_since = NULL WHERE id = ?",
                    params![
                        sub.tag.as_str(),
                        &sub.key.as_bytes()[..],
                        &sub.auth.as_bytes()[..],
                        expires,
                        id
                    ],
                )?;
                return Ok(PushAdded::Replaced);
            }
            let n = count(
                tx,
                &format!("SELECT count(*) FROM push_subscriptions WHERE {clause}"),
                &value,
            )?;
            if n >= u64::try_from(max).unwrap_or(u64::MAX) {
                return Ok(PushAdded::TooMany);
            }
            let (mailbox, uid, device) = match &sub.target {
                PushTarget::Mailbox(mailbox) => (Some(mailbox.as_bytes().to_vec()), None, None),
                PushTarget::Device { uid, device } => (
                    None,
                    Some(uid.as_str().to_owned()),
                    Some(device.as_bytes().to_vec()),
                ),
            };
            tx.execute(
                "INSERT INTO push_subscriptions
                 (url, url_hash, tag, key, auth, box, expires, uid, device)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    sub.url.as_str(),
                    hash,
                    sub.tag.as_str(),
                    &sub.key.as_bytes()[..],
                    &sub.auth.as_bytes()[..],
                    mailbox,
                    expires,
                    uid,
                    device
                ],
            )?;
            Ok(PushAdded::Added)
        })
    }

    fn delete_push(&self, target: &PushTarget, url: &PushUrl) -> Result<bool> {
        self.write(|tx| {
            let (clause, value) = target_clause(target);
            Ok(tx.execute(
                &format!("DELETE FROM push_subscriptions WHERE {clause} AND url_hash = ?"),
                params![value, url_hash(url)],
            )? > 0)
        })
    }

    fn delete_push_id(&self, id: i64) -> Result<()> {
        self.write(|tx| {
            tx.execute("DELETE FROM push_subscriptions WHERE id = ?", [id])?;
            Ok(())
        })
    }

    fn push_subscriptions(
        &self,
        target: &PushTarget,
        now: Timestamp,
    ) -> Result<Vec<PushSubscription>> {
        self.read(|tx| {
            let (clause, value) = target_clause(target);
            let mut select = tx.prepare_cached(&format!(
                "SELECT {SUB_COLUMNS} FROM push_subscriptions
                 WHERE {clause} AND (expires IS NULL OR expires > ?) ORDER BY id"
            ))?;
            let mut rows = select.query(params![value, millis(now)])?;
            let mut subs = Vec::new();
            while let Some(row) = rows.next()? {
                subs.push(subscription(row)?);
            }
            Ok(subs)
        })
    }

    fn push_subscription(&self, id: i64) -> Result<Option<PushSubscription>> {
        self.read(|tx| {
            let mut select = tx.prepare_cached(&format!(
                "SELECT {SUB_COLUMNS} FROM push_subscriptions WHERE id = ?"
            ))?;
            let mut rows = select.query([id])?;
            rows.next()?.map(subscription).transpose()
        })
    }

    fn note_push(&self, id: i64, ok: bool, now: Timestamp) -> Result<()> {
        self.write(|tx| {
            if ok {
                tx.execute(
                    "UPDATE push_subscriptions SET failing_since = NULL WHERE id = ?",
                    [id],
                )?;
            } else {
                tx.execute(
                    "UPDATE push_subscriptions SET failing_since = coalesce(failing_since, ?)
                     WHERE id = ?",
                    params![millis(now), id],
                )?;
            }
            Ok(())
        })
    }

    fn delete_mailbox_pushes(&self, mailbox: &BoxName) -> Result<u64> {
        self.write(|tx| {
            let n = tx.execute(
                "DELETE FROM push_subscriptions WHERE box = ?",
                [&mailbox.as_bytes()[..]],
            )?;
            Ok(n as u64)
        })
    }

    fn delete_device_pushes(&self, device: &DeviceId) -> Result<u64> {
        self.write(|tx| {
            let n = tx.execute(
                "DELETE FROM push_subscriptions WHERE device = ?",
                [&device.as_bytes()[..]],
            )?;
            Ok(n as u64)
        })
    }

    fn forget_identity_misc(&self, uid: &Uid) -> Result<()> {
        self.write(|tx| {
            tx.execute(
                "DELETE FROM push_subscriptions WHERE uid = ?",
                [uid.as_str()],
            )?;
            tx.execute("DELETE FROM presence WHERE uid = ?", [uid.as_str()])?;
            Ok(())
        })
    }

    fn expire_pushes(&self, now: Timestamp) -> Result<u64> {
        self.write(|tx| {
            let n = tx.execute(
                "DELETE FROM push_subscriptions WHERE expires <= ?",
                [millis(now)],
            )?;
            Ok(n as u64)
        })
    }

    fn add_report(&self, report: &NewReport) -> Result<()> {
        self.write(|tx| {
            tx.execute(
                "INSERT INTO reports (id, box, report, t, pseudonym, reporter)
                 VALUES (?, ?, ?, ?, ?, ?)",
                params![
                    report.id.as_str(),
                    &report.mailbox.as_bytes()[..],
                    report.report.as_str(),
                    millis(report.t),
                    &report.pseudonym.as_bytes()[..],
                    report.from.as_ref().map(Uid::as_str),
                ],
            )?;
            let mut insert = tx.prepare_cached(
                "INSERT OR IGNORE INTO report_posts (report, seq, t, message) VALUES (?, ?, ?, ?)",
            )?;
            for (seq, t, message) in &report.posts {
                insert.execute(params![
                    report.id.as_str(),
                    super::sql_u64(*seq),
                    millis(*t),
                    message
                ])?;
            }
            Ok(())
        })
    }

    fn open_reports(&self) -> Result<Vec<StoredReport>> {
        self.read(|tx| {
            let mut select = tx.prepare_cached(
                "SELECT id, box, report, t, pseudonym, reporter FROM reports ORDER BY t, rowid",
            )?;
            let mut rows = select.query([])?;
            let mut reports = Vec::new();
            while let Some(row) = rows.next()? {
                let id: String = row.get(0)?;
                let mailbox: Vec<u8> = row.get(1)?;
                let report: String = row.get(2)?;
                let pseudonym: Vec<u8> = row.get(4)?;
                let from: Option<String> = row.get(5)?;
                reports.push(StoredReport {
                    id: parsed("report id", &id)?,
                    mailbox: BoxName::from_bytes(fixed("box", &mailbox)?),
                    report: parsed::<ReportData>("report", &report)?,
                    t: timestamp(row.get(3)?)?,
                    pseudonym: Pseudonym::from_bytes(fixed("pseudonym", &pseudonym)?),
                    from: from.map(|uid| parsed("reporter", &uid)).transpose()?,
                });
            }
            Ok(reports)
        })
    }

    fn resolve_report(&self, id: &Id) -> Result<bool> {
        self.write(|tx| Ok(tx.execute("DELETE FROM reports WHERE id = ?", [id.as_str()])? > 0))
    }
}

#[cfg(test)]
mod tests {
    use risala_proto::types::PushTag;

    use super::*;

    fn t(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    #[test]
    fn presence_is_off_by_default() {
        let store = SqliteStore::open_in_memory().unwrap();
        let alice: Uid = "alice@example.org".parse().unwrap();
        assert!(!store.presence_on(&alice).unwrap());
        store.set_presence(&alice, true).unwrap();
        store.set_presence(&alice, true).unwrap();
        assert!(store.presence_on(&alice).unwrap());
        store.set_presence(&alice, false).unwrap();
        assert!(!store.presence_on(&alice).unwrap());
    }

    fn sub(target: PushTarget, url: &str, tag: &str, expires: Option<&str>) -> NewPushSubscription {
        NewPushSubscription {
            target,
            url: url.parse().unwrap(),
            tag: tag.parse::<PushTag>().unwrap(),
            key: PushKey::from_bytes([4; 65]),
            auth: PushAuth::from_bytes([5; 16]),
            expires: expires.map(t),
        }
    }

    #[test]
    fn push_subscriptions_are_replaced_limited_and_expire() {
        let store = SqliteStore::open_in_memory().unwrap();
        let mailbox = PushTarget::Mailbox(BoxName::from_bytes([1; 16]));
        let other = PushTarget::Mailbox(BoxName::from_bytes([2; 16]));
        let alice: Uid = "alice@example.org".parse().unwrap();
        let device = PushTarget::Device {
            uid: alice.clone(),
            device: DeviceId::from_bytes([3; 48]),
        };
        let now = t("2026-11-09T00:00:00.000Z");
        let later = "2026-12-09T00:00:00.000Z";
        let a = sub(mailbox.clone(), "https://p.example/a", "t1", Some(later));
        assert_eq!(store.add_push(&a, 2).unwrap(), PushAdded::Added);
        let a2 = sub(mailbox.clone(), "https://p.example/a", "t2", Some(later));
        assert_eq!(store.add_push(&a2, 2).unwrap(), PushAdded::Replaced);
        let b = sub(mailbox.clone(), "https://p.example/b", "t3", Some(later));
        assert_eq!(store.add_push(&b, 2).unwrap(), PushAdded::Added);
        let c = sub(mailbox.clone(), "https://p.example/c", "t4", Some(later));
        assert_eq!(store.add_push(&c, 2).unwrap(), PushAdded::TooMany);
        // The same URL for another mailbox is another subscription.
        let a_other = sub(other.clone(), "https://p.example/a", "t1", Some(later));
        assert_eq!(store.add_push(&a_other, 2).unwrap(), PushAdded::Added);
        let d = sub(device.clone(), "https://p.example/d", "t5", None);
        assert_eq!(store.add_push(&d, 2).unwrap(), PushAdded::Added);

        let subs = store.push_subscriptions(&mailbox, now).unwrap();
        let tags: Vec<&str> = subs.iter().map(|s| s.tag.as_str()).collect();
        assert_eq!(tags, ["t2", "t3"]);
        assert_eq!(store.push_subscriptions(&device, now).unwrap().len(), 1);

        store.note_push(subs[0].id, false, now).unwrap();
        store.note_push(subs[0].id, false, t(later)).unwrap();
        let got = store.push_subscription(subs[0].id).unwrap().unwrap();
        assert_eq!(got.failing_since, Some(now));
        store.note_push(subs[0].id, true, now).unwrap();
        let got = store.push_subscription(subs[0].id).unwrap().unwrap();
        assert_eq!(got.failing_since, None);

        assert!(
            store
                .delete_push(&mailbox, &"https://p.example/b".parse().unwrap())
                .unwrap()
        );
        assert!(
            !store
                .delete_push(&mailbox, &"https://p.example/b".parse().unwrap())
                .unwrap()
        );
        // Expired subscriptions are left out, then deleted.
        assert!(
            store
                .push_subscriptions(&other, t(later))
                .unwrap()
                .is_empty()
        );
        assert_eq!(store.expire_pushes(t(later)).unwrap(), 2);
        assert_eq!(store.push_subscriptions(&device, now).unwrap().len(), 1);
        store.forget_identity_misc(&alice).unwrap();
        assert!(store.push_subscriptions(&device, now).unwrap().is_empty());
    }

    #[test]
    fn reports_stay_until_resolved() {
        let store = SqliteStore::open_in_memory().unwrap();
        let report = NewReport {
            id: "k3f9q2".parse().unwrap(),
            mailbox: BoxName::from_bytes([1; 16]),
            report: "AQID".parse().unwrap(),
            t: t("2026-11-09T00:00:00.000Z"),
            pseudonym: Pseudonym::from_bytes([9; 16]),
            from: Some("alice@example.org".parse().unwrap()),
            posts: vec![(3, t("2026-11-08T00:00:00.000Z"), vec![1, 2])],
        };
        store.add_report(&report).unwrap();
        let open = store.open_reports().unwrap();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].id, report.id);
        assert_eq!(open[0].from, report.from);
        assert_eq!(open[0].pseudonym, report.pseudonym);
        assert!(store.resolve_report(&report.id).unwrap());
        assert!(!store.resolve_report(&report.id).unwrap());
        assert!(store.open_reports().unwrap().is_empty());
        let copies: i64 = store
            .raw()
            .query_row("SELECT count(*) FROM report_posts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(copies, 0);
    }
}
