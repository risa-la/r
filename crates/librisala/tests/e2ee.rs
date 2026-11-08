//! End-to-end encryption (SPEC 12) against the real server: what risalad
//! answers today (KEYPKG, WELCOME, BACKUP, KEY), with librisala's devices.
//!
//! The group scenarios (INIT, COMMIT, GROUPINFO and ENC) are tested with
//! real MLS groups in `src/sync/e2ee_tests.rs`, against a small server in
//! memory, until risalad answers those commands.

mod common;

use common::*;
use librisala::client::ClientError;
use risala_mls::{HistoryKey, RecoveryKey};
use risala_proto::names::Id;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "risalad on this base answers KEYPKG ADD with not-supported"]
async fn a_device_keeps_key_packages_on_the_server() {
    let server = hosted_server(&[], |_| {}).await;
    let _alice = registered(&server, "alice").await;
    // Someone else gets one KeyPackage of Alice's one device (12.4).
    let (_bob, mut bob) = server.register("bob").await;
    bob.send("KEYPKG GET alice@chat.test").await.unwrap();
    let (lines, ok) = until_final(&mut bob).await;
    assert_eq!(ok, "OK");
    assert_eq!(
        lines
            .iter()
            .filter(|l| l.starts_with("KEYPKG alice@chat.test "))
            .count(),
        1,
        "{lines:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backups_restore_history_keys() {
    let server = hosted_server(&["#general"], |_| {}).await;
    let (carol, mut raw) = server.register("carol").await;
    // Carol's key on a librisala device too.
    let (client, addr) = device(&server);
    client
        .import_device_key("carol@chat.test", &carol.key().to_pkcs8_pem(), false)
        .await
        .unwrap();
    let account = client.add_identity(&addr, "carol@chat.test").unwrap();
    within("signing in", account.connect()).await.unwrap();
    let general = within("joining", account.join("#general")).await.unwrap();
    within("syncing", account.wait_synced()).await.unwrap();
    let id: Id = general
        .info()
        .unwrap()
        .unwrap()
        .id
        .unwrap()
        .parse()
        .unwrap();

    // Another device of Carol's backed up three epochs' keys (12.10).
    let recovery = RecoveryKey::from_bytes([5; 32]);
    let backup = recovery.backup_key(carol.identity());
    for epoch in 0..3u8 {
        let blob = backup
            .seal(&id, u64::from(epoch), &HistoryKey::from_bytes([epoch; 48]))
            .unwrap();
        raw.send(&format!("BACKUP ADD {id} {epoch} {blob}"))
            .await
            .unwrap();
        let (_, ok) = until_final(&mut raw).await;
        assert_eq!(ok, "OK");
    }

    // A recovery key that matches no backup is refused.
    let wrong = RecoveryKey::from_bytes([6; 32]).to_display();
    assert!(matches!(
        within("restoring", account.restore_backup(&wrong)).await,
        Err(ClientError::Invalid(_))
    ));
    // The right one restores the three keys.
    let n = within("restoring", account.restore_backup(&recovery.to_display()))
        .await
        .unwrap();
    assert_eq!(n, 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recovery_key_gets_the_identity_back() {
    let server = hosted_server(&[], |_| {}).await;
    let alice = registered(&server, "alice").await;
    let old = alice.device_key().unwrap().unwrap().fingerprint;

    // The server hosts Alice: KEY ADD put the recovery key's own key in her
    // key file, labelled `recovery` (12.10).
    let created = within("a recovery key", alice.create_recovery_key())
        .await
        .unwrap();
    assert_eq!(created.key_file_line, None);
    assert_eq!(created.key.len(), 64, "52 characters in groups of four");
    let keys = within("KEY LIST", alice.keys()).await.unwrap();
    assert!(keys.iter().any(|k| k.label == "recovery"), "{keys:?}");
    within("stopping", alice.disconnect()).await;

    // Every device is lost. On a new one, the recovery key signs in, adds
    // the new device's key and removes the others (12.10).
    let (client, addr) = device(&server);
    client
        .create_device_key("alice@chat.test", false)
        .await
        .unwrap();
    let again = within(
        "recovering",
        client.recover_identity(&addr, "alice@chat.test", &created.key),
    )
    .await
    .unwrap();
    within("syncing", again.wait_synced()).await.unwrap();
    let keys = within("KEY LIST", again.keys()).await.unwrap();
    assert_eq!(keys.len(), 2, "{keys:?}");
    assert!(keys.iter().any(|k| k.this_device));
    assert!(keys.iter().any(|k| k.label == "recovery"));
    assert!(keys.iter().all(|k| k.fingerprint != old));
}
