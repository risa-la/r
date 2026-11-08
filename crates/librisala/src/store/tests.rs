//! Opening the cache, its schema, and the C0 tables.

use risala_proto::fingerprint::Fingerprint;
use rusqlite::Connection;

use super::*;
use crate::addr::{PinChange, Replaced, TrustRecord, TrustStore};

fn tables(store: &Store) -> Vec<String> {
    store
        .read(|conn| {
            let mut stmt = conn.prepare(
                "SELECT name FROM sqlite_schema
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
            )?;
            let names = stmt.query_map([], |r| r.get(0))?;
            Ok(names.collect::<Result<_, _>>()?)
        })
        .unwrap()
}

fn version(store: &Store) -> u32 {
    store
        .read(|conn| Ok(conn.pragma_query_value(None, "user_version", |r| r.get(0))?))
        .unwrap()
}

#[test]
fn a_new_cache_has_version_1_and_every_area() {
    let store = Store::open_in_memory().unwrap();
    assert_eq!(version(&store), 1);
    assert_eq!(schema::VERSION, 1);
    assert_eq!(
        tables(&store),
        [
            "accounts",
            "announced",
            "backups",
            "blocks",
            "confirm_warnings",
            "confirmers",
            "contacts",
            "conversations",
            "deletes",
            "devices",
            "epoch_ends",
            "epoch_pseudonyms",
            "file_blobs",
            "files",
            "forks",
            "gaps",
            "group_state",
            "identities",
            "key_packages",
            "leaf_confirmations",
            "leaves",
            "logs",
            "mailboxes",
            "message_meta",
            "messages",
            "openmls_encryption_keys",
            "openmls_epoch_keys_pairs",
            "openmls_group_data",
            "openmls_key_packages",
            "openmls_own_leaf_nodes",
            "openmls_proposals",
            "openmls_psks",
            "openmls_signature_keys",
            "outbox",
            "pairings",
            "period_keys",
            "pin_notices",
            "posts",
            "push_off",
            "push_subscriptions",
            "push_urls",
            "records",
            "reports",
            "seen",
            "self_lines",
            "sender_logs",
            "server_files",
            "servers",
            "settings",
            "tiles",
            "transfer_pending",
            "transfers",
            "trust",
            "want_requests",
            "wants",
            "welcomes_out",
            "witnesses",
        ]
    );
    let parts: Vec<&str> = schema::PARTS.iter().map(|(name, _)| *name).collect();
    assert_eq!(
        parts,
        [
            "settings",
            "identity",
            "keylog",
            "conversations",
            "messages",
            "mls",
            "confirm",
            "transfer",
            "push"
        ]
    );
}

#[test]
fn foreign_keys_are_on() {
    let store = Store::open_in_memory().unwrap();
    let err = store
        .write(|tx| {
            tx.conn().execute(
                "INSERT INTO conversations (account, group_id, mailbox, kind, pseudonym, created)
                 VALUES (99, x'00', 'b', 'direct', x'00', 0)",
                [],
            )?;
            Ok(())
        })
        .unwrap_err();
    assert!(matches!(err, StoreError::Sqlite(_)), "{err}");
}

#[test]
fn a_file_is_encrypted_private_and_reopens() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.db");
    let key = DatabaseKey::for_tests();
    {
        let store = Store::open(&path, &key).unwrap();
        store.set_setting("a", Some("b")).unwrap();
        assert_eq!(version(&store), 1);
    }
    // Encrypted: no SQLite header in the clear.
    let bytes = std::fs::read(&path).unwrap();
    assert_ne!(&bytes[..16], b"SQLite format 3\0");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    let store = Store::open(&path, &key).unwrap();
    assert_eq!(store.setting("a").unwrap().as_deref(), Some("b"));
    // Two stores on one file see each other's writes.
    let other = Store::open(&path, &key).unwrap();
    let before = store.data_version().unwrap().unwrap();
    other.set_setting("a", Some("c")).unwrap();
    assert_eq!(store.setting("a").unwrap().as_deref(), Some("c"));
    assert_ne!(store.data_version().unwrap().unwrap(), before);
}

#[test]
fn a_wrong_key_or_a_plaintext_file_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.db");
    drop(Store::open(&path, &DatabaseKey::for_tests()).unwrap());
    let err = Store::open(&path, &DatabaseKey::from_bytes([8; 32])).unwrap_err();
    assert!(matches!(err, StoreError::WrongKey), "{err}");

    // A cache in the clear, as M5a's were before encryption: not read.
    let plain = dir.path().join("plain.db");
    Connection::open(&plain)
        .unwrap()
        .execute_batch("CREATE TABLE t (x); INSERT INTO t VALUES (1);")
        .unwrap();
    let err = Store::open(&plain, &DatabaseKey::for_tests()).unwrap_err();
    assert!(matches!(err, StoreError::WrongKey), "{err}");
}

#[test]
fn other_versions_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let key = DatabaseKey::for_tests();
    for (name, setup) in [
        // Newer.
        ("newer.db", "PRAGMA user_version = 2;"),
        // M5a's caches reached version 19.
        (
            "m5a.db",
            "CREATE TABLE convs (id); PRAGMA user_version = 19;",
        ),
        // Version 0, but not empty.
        ("odd.db", "CREATE TABLE t (x);"),
    ] {
        let path = dir.path().join(name);
        {
            let conn = Connection::open(&path).unwrap();
            cipher::key(&conn, &key).unwrap();
            conn.execute_batch(setup).unwrap();
        }
        let err = Store::open(&path, &key).unwrap_err();
        let expected = match name {
            "newer.db" => 2,
            "m5a.db" => 19,
            _ => 0,
        };
        assert!(
            matches!(err, StoreError::Version(v) if v == expected),
            "{name}: {err}"
        );
    }
}

#[test]
fn trust_records_and_notices() {
    let store = Store::open_in_memory().unwrap();
    let a: ServerAddr = "chat.example.org".parse().unwrap();
    let b: ServerAddr = "chat.example.net:7000".parse().unwrap();
    let (fp, other) = (
        Fingerprint::from_bytes([7; 32]),
        Fingerprint::from_bytes([8; 32]),
    );
    assert_eq!(TrustStore::get(&store, &a).unwrap(), None);
    assert_eq!(store.pin_if_unknown(&a, fp).unwrap(), None);
    let pinned = Some(TrustRecord::Pinned(fp));
    assert_eq!(TrustStore::get(&store, &a).unwrap(), pinned);
    assert_eq!(store.pin_if_unknown(&a, other).unwrap(), pinned);

    // Compare and swap: only from the record expected.
    let notice = PinChange {
        old: fp,
        new: other,
    };
    assert_eq!(
        store
            .replace(&a, None, TrustRecord::Ca, Some(notice.clone()))
            .unwrap(),
        Replaced::Found(pinned.clone())
    );
    assert!(store.notices().unwrap().is_empty());
    assert_eq!(
        store
            .replace(&a, pinned.as_ref(), TrustRecord::Ca, Some(notice.clone()))
            .unwrap(),
        Replaced::Done
    );
    assert_eq!(TrustStore::get(&store, &a).unwrap(), Some(TrustRecord::Ca));
    assert_eq!(store.notices().unwrap(), [(a.clone(), notice.clone())]);

    // Strict pins are kept as such.
    store
        .replace(&b, None, TrustRecord::Strict(other), None)
        .unwrap();
    assert_eq!(
        TrustStore::get(&store, &b).unwrap(),
        Some(TrustRecord::Strict(other))
    );

    store.dismiss_notice(&a).unwrap();
    assert!(store.notices().unwrap().is_empty());
    store
        .replace(&a, Some(&TrustRecord::Ca), TrustRecord::Ca, Some(notice))
        .unwrap();
    store.forget(&a).unwrap();
    assert_eq!(TrustStore::get(&store, &a).unwrap(), None);
    assert!(store.notices().unwrap().is_empty());
    assert!(TrustStore::get(&store, &b).unwrap().is_some());
}

#[test]
fn accounts_and_guest_sessions() {
    let store = Store::open_in_memory().unwrap();
    let server: ServerAddr = "chat.example.org".parse().unwrap();
    let alice = "alice@example.org".parse().unwrap();
    let sam = "~sam".parse().unwrap();
    let a = store
        .add_account(&server, AccountKind::Identity, &alice)
        .unwrap();
    assert_eq!(
        store
            .add_account(&server, AccountKind::Identity, &alice)
            .unwrap(),
        a
    );
    // A guest uid is not an identity, and the other way round.
    assert!(
        store
            .add_account(&server, AccountKind::Identity, &sam)
            .is_err()
    );
    assert!(
        store
            .add_account(&server, AccountKind::Guest, &alice)
            .is_err()
    );
    let g = store
        .add_account(&server, AccountKind::Guest, &sam)
        .unwrap();
    let rows = store.accounts().unwrap();
    assert_eq!(
        rows,
        [
            AccountRow {
                id: a,
                server: server.clone(),
                kind: AccountKind::Identity,
                uid: alice.clone(),
            },
            AccountRow {
                id: g,
                server: server.clone(),
                kind: AccountKind::Guest,
                uid: sam.clone(),
            },
        ]
    );

    assert_eq!(store.guest_session(g).unwrap(), None);
    let name: risala_proto::names::Name = "sam2".parse().unwrap();
    let token: risala_proto::command::GuestToken = "k3f9q2a8b7c6d5e4f3g2".parse().unwrap();
    store.set_guest_session(g, Some((&name, &token))).unwrap();
    assert_eq!(
        store.guest_session(g).unwrap(),
        Some((name.clone(), token.clone()))
    );
    // Identities have no guest session.
    assert!(store.set_guest_session(a, Some((&name, &token))).is_err());
    store.set_guest_session(g, None).unwrap();
    assert_eq!(store.guest_session(g).unwrap(), None);

    store.remove_account(g).unwrap();
    assert!(matches!(
        store.guest_session(g),
        Err(StoreError::NotFound(_))
    ));
    assert_eq!(store.accounts().unwrap().len(), 1);
}

#[test]
fn writes_report_their_changes_once() {
    let store = Store::open_in_memory().unwrap();
    let a: ServerAddr = "chat.example.org".parse().unwrap();
    let (_, changes) = store
        .write(|tx| {
            tx.changed(Change::Settings(settings::SettingsChange::Accounts));
            tx.changed(Change::Settings(settings::SettingsChange::Trust(a.clone())));
            tx.changed(Change::Settings(settings::SettingsChange::Accounts));
            Ok(())
        })
        .unwrap();
    assert_eq!(
        changes,
        [
            Change::Settings(settings::SettingsChange::Accounts),
            Change::Settings(settings::SettingsChange::Trust(a)),
        ]
    );
    // A failed write writes nothing.
    let err = store
        .write(|tx| {
            tx.server_id(&"chat.example.net".parse().unwrap())?;
            Err::<(), _>(StoreError::NotFound("test"))
        })
        .unwrap_err();
    assert!(matches!(err, StoreError::NotFound("test")));
    let servers: i64 = store
        .read(|c| Ok(c.query_row("SELECT count(*) FROM servers", [], |r| r.get(0))?))
        .unwrap();
    assert_eq!(servers, 0);
}
