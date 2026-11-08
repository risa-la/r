//! What the server keeps of encrypted conversations without reading it,
//! over TLS against a whole server: KEYPKG (12.4), WELCOME (12.7) and
//! BACKUP (12.10), with the long lines that carry MLS data (2.3).
//!
//! Most KeyPackages here are put into the server's database directly,
//! through a second connection to it, so that their sizes can be chosen. The hub's own tests (`src/core/e2ee_tests.rs`)
//! cover each rule at every edge.

mod common;

use std::time::Duration;

use common::command;
use risala_proto::mls::{BackupBlob, KeyPackage};
use risala_server::store::{
    DirectInit, E2eeStore as _, GroupLeaf, GroupMeta, GroupParts, GroupRecord, GroupStore as _,
    NewKeyPackage, SqliteStore,
};
use risala_server::testing::{TestIdentity, TestServer};

/// A server that hosts `example.org`, with registration open, and lets
/// identities at `example.net` sign in.
async fn server() -> TestServer {
    TestServer::builder()
        .identity_domain("example.org")
        .key_domains(&["example.net"])
        .start()
        .await
}

/// Stores a KeyPackage of `len` bytes, all `n`, for `who`'s device, as
/// KEYPKG ADD does once it has checked one.
fn put_key_package(server: &TestServer, who: &TestIdentity, n: u8, len: usize) -> KeyPackage {
    let store = SqliteStore::open(&server.config().database_path()).unwrap();
    let key_package = KeyPackage::from_bytes(&vec![n; len]).unwrap();
    let kp = NewKeyPackage {
        key_package: key_package.clone(),
        kp_ref: vec![n],
        not_after: server
            .now()
            .checked_add(Duration::from_secs(86400))
            .unwrap(),
        last_resort: false,
    };
    store
        .add_key_package(&who.uid(), &who.public_key(), &kp, 100, server.now())
        .unwrap();
    key_package
}

/// A long KEYPKG line is too long before sign-in, and reaches the hub
/// after it (2.3), which finds it is no KeyPackage.
#[tokio::test]
async fn key_packages_are_long_lines_once_signed_in() {
    let server = server().await;
    let data = "A".repeat(3 * 8192);
    let mut conn = server.connect().await;
    common::recv(&mut conn).await;
    let lines = command(&mut conn, &format!("keypkg add {data}")).await;
    assert_eq!(lines, ["ERR too-long too long"]);

    let (_alice, mut laptop) = server.register("alice").await;
    let lines = command(&mut laptop, &format!("keypkg add {data}")).await;
    assert_eq!(lines, ["ERR invalid not a valid KeyPackage"]);
    server.stop().await;
}

/// KeyPackages longer than a normal server line reach the asker, each
/// once (2.3, 12.4), for a hosted identity and for one whose key file the
/// server fetches.
#[tokio::test]
async fn keypkg_get_over_the_wire() {
    let server = server().await;
    let (alice, mut laptop) = server.register("alice").await;
    let phone = server.new_device(&alice).await;
    let bob = server.identity("bob@example.net");
    let mut bob_conn = server.sign_in(&bob).await;

    // Larger than 16384 bytes once in base64.
    let alices = put_key_package(&server, &phone, 1, 15_000);
    let bobs = put_key_package(&server, &bob, 2, 15_000);

    let lines = command(&mut laptop, "keypkg get bob@example.net").await;
    assert_eq!(
        lines,
        [format!("KEYPKG bob@example.net {bobs}"), "OK".into()]
    );
    assert!(lines[0].len() > 16384);
    let lines = command(&mut bob_conn, "keypkg get alice@example.org").await;
    assert_eq!(
        lines,
        [format!("KEYPKG alice@example.org {alices}"), "OK".into()]
    );
    // Used up.
    let lines = command(&mut bob_conn, "keypkg get alice@example.org").await;
    assert_eq!(lines, ["OK"]);

    let mut phone_conn = server.sign_in(&phone).await;
    put_key_package(&server, &phone, 3, 100);
    let lines = command(&mut phone_conn, "keypkg count").await;
    assert_eq!(lines, ["OK count=1 last-resort=no"]);
    let lines = command(&mut laptop, "keypkg count").await;
    assert_eq!(lines, ["OK count=0 last-resort=no"]);
    let lines = command(&mut laptop, "keypkg get carol@example.org").await;
    assert_eq!(lines, ["ERR not-found no such identity"]);
    server.stop().await;
}

/// A removed key's KeyPackages go with it (4.7).
#[tokio::test]
async fn a_deleted_key_takes_its_key_packages() {
    let server = server().await;
    let (alice, mut laptop) = server.register("alice").await;
    let phone = server.new_device(&alice).await;
    put_key_package(&server, &phone, 1, 100);
    let lines = command(&mut laptop, &format!("key del {}", phone.public_key())).await;
    assert_eq!(lines, ["OK"]);
    let bob = server.identity("bob@example.net");
    let mut bob_conn = server.sign_in(&bob).await;
    let lines = command(&mut bob_conn, "keypkg get alice@example.org").await;
    assert_eq!(lines, ["OK"]);
    server.stop().await;
}

/// Starts `who`'s conversation with itself in the store, with a group in
/// epoch `epoch` that is not MLS: BACKUP ADD checks only that the
/// identity is in it, and its epoch (12.10). Returns its id.
fn own_conversation(server: &TestServer, who: &TestIdentity, epoch: u64) -> String {
    let store = SqliteStore::open(&server.config().database_path()).unwrap();
    let record = GroupRecord {
        group_id: vec![1; 32],
        meta: GroupMeta { epoch, seq: None },
        group_info: risala_proto::mls::GroupInfo::from_bytes(&[1; 9]).unwrap(),
        parts: GroupParts {
            tree: vec![1],
            context: vec![2],
            interim_hash: vec![3],
            confirmation_tag: vec![4],
        },
    };
    let leaf = GroupLeaf {
        index: 0,
        uid: who.uid(),
        key: who.public_key(),
    };
    match store
        .init_direct(&who.uid(), &who.uid(), &record, &[leaf], server.now())
        .unwrap()
    {
        DirectInit::Done(direct) => direct.id.to_string(),
        other => panic!("{other:?}"),
    }
}

/// Backups belong to the identity, so a new device reads what another
/// stored, a page at a time (12.10).
#[tokio::test]
async fn backups_over_the_wire() {
    let server = server().await;
    let (alice, mut laptop) = server.register("alice").await;
    let phone = server.new_device(&alice).await;
    let id = own_conversation(&server, &alice, 2);
    let blob = |epoch: u8| {
        let mut b = [epoch; 84];
        b[..8].copy_from_slice(&[1; 8]);
        BackupBlob::from_bytes(b)
    };
    for epoch in 0..3u8 {
        let lines = command(
            &mut laptop,
            &format!("backup add {id} {epoch} {}", blob(epoch)),
        )
        .await;
        assert_eq!(lines, ["OK"]);
    }
    let mut phone_conn = server.sign_in(&phone).await;
    let lines = command(&mut phone_conn, &format!("backup get {id} limit=2")).await;
    assert_eq!(
        lines,
        [
            format!("BACKUP {id} 0 {}", blob(0)),
            format!("BACKUP {id} 1 {}", blob(1)),
            "OK more=1".into()
        ]
    );
    let lines = command(&mut phone_conn, &format!("backup get {id} after=1 limit=2")).await;
    assert_eq!(
        lines,
        [format!("BACKUP {id} 2 {}", blob(2)), "OK more=0".into()]
    );
    assert_eq!(command(&mut phone_conn, "backup del").await, ["OK"]);
    assert_eq!(
        command(&mut laptop, &format!("backup get {id}")).await,
        ["OK more=0"]
    );
    // No Welcomes are pending for a device nobody added.
    assert_eq!(command(&mut laptop, "welcome list").await, ["OK"]);
    server.stop().await;
}
