//! End-to-end encryption (SPEC 12) against the real server: librisala's
//! devices and risalad, with real MLS groups, KeyPackages, Welcomes,
//! commits, encrypted messages, backups and key files fetched over HTTPS.
//!
//! The same scenarios run against a small server in memory in
//! `src/sync/e2ee_tests.rs`, which can also make devices misbehave.

mod common;

use common::*;
use librisala::client::{
    Account, AccountEvent, AccountEvents, ClientError, Encryption, History, Notice, OwnDeviceState,
};
use risala_mls::{HistoryKey, RecoveryKey};
use risala_proto::names::Id;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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

/// The texts of a conversation's messages in the cache, with how each was
/// read.
fn texts(account: &Account, conv: &str) -> Vec<(String, Option<Encryption>)> {
    let Ok(c) = account.conversation(conv) else {
        return Vec::new();
    };
    c.messages(None, 100)
        .unwrap()
        .messages
        .into_iter()
        .filter(|m| m.outbox.is_none() && m.kind == librisala::client::EventKind::Message)
        .map(|m| (m.text.unwrap_or_default(), m.encryption))
        .collect()
}

/// Waits until `account` has read the texts `want`, verified, in order, at
/// the end of `conv`.
async fn reads(account: &Account, conv: &str, want: &[&str]) {
    let events = account.subscribe();
    let ok = || {
        let got = texts(account, conv);
        got.len() >= want.len()
            && got[got.len() - want.len()..]
                .iter()
                .zip(want)
                .all(|((t, e), w)| t == w && *e == Some(Encryption::Verified))
    };
    within(&format!("{} reading {want:?}", account.uid()), async {
        while !ok() {
            let _ =
                tokio::time::timeout(std::time::Duration::from_millis(200), events.next()).await;
        }
    })
    .await;
}

/// Sends `text` to `conv` and waits until the server has it.
async fn say(account: &Account, conv: &str, text: &str) {
    let c = account.conversation(conv).unwrap();
    let entry = within("queueing", c.send(text)).await.unwrap();
    let done = within(&format!("sending {text:?}"), account.wait_outbox(entry.id))
        .await
        .unwrap();
    assert!(
        matches!(done.status, librisala::client::OutboxStatus::Sent { .. }),
        "{done:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_direct_conversation_is_encrypted_both_ways() {
    let server = hosted_server(&[], |_| {}).await;
    let alice = registered(&server, "alice").await;
    let bob = registered(&server, "bob").await;

    // Alice's first message starts the conversation: INIT, KeyPackages,
    // COMMIT with a Welcome, then ENC (12.6).
    say(&alice, "bob@chat.test", "hi bob").await;
    reads(&bob, "alice@chat.test", &["hi bob"]).await;
    reads(&alice, "bob@chat.test", &["hi bob"]).await;
    assert!(
        alice
            .conversation("bob@chat.test")
            .unwrap()
            .info()
            .unwrap()
            .unwrap()
            .encrypted
    );

    // Bob answers in the same group.
    say(&bob, "alice@chat.test", "hi alice").await;
    reads(&alice, "bob@chat.test", &["hi bob", "hi alice"]).await;

    // The server only ever had ciphertext.
    let lines = alice
        .conversation("bob@chat.test")
        .unwrap()
        .export()
        .unwrap();
    assert!(lines.iter().all(|l| !l.contains(" MSG ")), "{lines:?}");
    assert!(lines.iter().any(|l| l.contains(" ENC ")), "{lines:?}");
}

/// How each message of `conv` was read, in order.
fn states(account: &Account, conv: &str) -> Vec<Option<Encryption>> {
    texts(account, conv).into_iter().map(|(_, e)| e).collect()
}

/// Waits for a notice.
async fn notice(what: &str, events: &AccountEvents) -> Notice {
    event(what, events, |e| match e {
        AccountEvent::Notice { notice } => Some(notice.clone()),
        _ => None,
    })
    .await
}

/// This device's fingerprint.
fn fingerprint(account: &Account) -> String {
    account.device_key().unwrap().unwrap().fingerprint
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_encrypted_room_shares_its_history() {
    let server = hosted_server(&[], |_| {}).await;
    let alice = registered(&server, "alice").await;
    let bob = registered(&server, "bob").await;

    // Alice makes a room, alone in it, and encrypts it (12.3, 12.5).
    let room = within("joining", alice.join("#secret")).await.unwrap();
    within("INFO", room.room_info()).await.unwrap();
    within("encrypting", room.encrypt(History::Shared, false))
        .await
        .unwrap();
    within("syncing", alice.wait_synced()).await.unwrap();
    assert!(room.info().unwrap().unwrap().encrypted);
    say(&alice, "#secret", "before bob").await;

    // Inviting adds Bob's device to the group, and sends him the earlier
    // epochs' keys (12.6, 12.9).
    let bob_events = bob.subscribe();
    within("inviting", room.invite("bob@chat.test"))
        .await
        .unwrap();
    let invited = notice("an invitation", &bob_events).await;
    assert!(matches!(invited, Notice::Invited { .. }), "{invited:?}");
    let joined = within("joining", bob.join("#secret")).await.unwrap();
    within("syncing", bob.wait_synced()).await.unwrap();
    assert!(joined.info().unwrap().unwrap().encrypted);
    reads(&bob, "#secret", &["before bob"]).await;

    // Bob writes, and Alice reads it.
    say(&bob, "#secret", "hi all").await;
    reads(&alice, "#secret", &["before bob", "hi all"]).await;
    let lines = room.export().unwrap();
    assert!(
        lines
            .iter()
            .all(|l| !l.contains(" MSG #secret before") && !l.contains(" MSG #secret hi")),
        "{lines:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_room_with_joined_history_hides_what_came_before() {
    let server = hosted_server(&[], |_| {}).await;
    let alice = registered(&server, "alice").await;
    let bob = registered(&server, "bob").await;
    let room = within("joining", alice.join("#quiet")).await.unwrap();
    within("INFO", room.room_info()).await.unwrap();
    within("encrypting", room.encrypt(History::Joined, false))
        .await
        .unwrap();
    within("syncing", alice.wait_synced()).await.unwrap();
    say(&alice, "#quiet", "before bob").await;
    within("inviting", room.invite("bob@chat.test"))
        .await
        .unwrap();
    // Bob can join once he is invited.
    within("invited", async {
        loop {
            match bob.join("#quiet").await {
                Ok(_) => break,
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(100)).await,
            }
        }
    })
    .await;
    within("syncing", bob.wait_synced()).await.unwrap();
    say(&alice, "#quiet", "after bob").await;
    reads(&bob, "#quiet", &["after bob"]).await;
    // 12.9: no earlier keys for someone added to a `joined` room.
    assert_eq!(
        states(&bob, "#quiet"),
        [Some(Encryption::Waiting), Some(Encryption::Verified)]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_device_joins_by_external_commit() {
    let server = hosted_server(&[], |_| {}).await;
    let alice = registered(&server, "alice").await;
    let bob = registered(&server, "bob").await;
    say(&alice, "bob@chat.test", "one").await;
    reads(&bob, "alice@chat.test", &["one"]).await;

    // Bob's second device joins the conversation by external commit
    // (12.6), and reads what is sent from then on.
    let bob2 = second_device(&server, &bob).await;
    within("bob2 joins", async {
        while bob2.conversation("alice@chat.test").is_err()
            || !bob2
                .conversation("alice@chat.test")
                .unwrap()
                .info()
                .unwrap()
                .is_some_and(|i| i.encrypted)
        {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await;
    say(&alice, "bob@chat.test", "two").await;
    reads(&bob2, "alice@chat.test", &["two"]).await;
    reads(&bob, "alice@chat.test", &["one", "two"]).await;
    // It cannot read the epoch before it joined without history keys
    // (12.9).
    assert_eq!(
        states(&bob2, "alice@chat.test"),
        [Some(Encryption::Waiting), Some(Encryption::Verified)]
    );

    // It writes too.
    say(&bob2, "alice@chat.test", "three").await;
    reads(&alice, "bob@chat.test", &["one", "two", "three"]).await;
    reads(&bob, "alice@chat.test", &["one", "two", "three"]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removed_keys_lose_their_leaves() {
    let server = hosted_server(&[], |_| {}).await;
    let alice = registered(&server, "alice").await;
    let bob = registered(&server, "bob").await;
    say(&alice, "bob@chat.test", "one").await;
    let bob2 = second_device(&server, &bob).await;
    say(&bob2, "alice@chat.test", "from bob2").await;
    reads(&alice, "bob@chat.test", &["one", "from bob2"]).await;

    // Bob removes his second device's key (4.7). Its leaf must go before
    // anyone sends again (12.6): the server refuses ENC until a commit
    // removes it.
    let line = bob2.client().key_line("bob@chat.test", "").unwrap();
    within("KEY DEL", bob.remove_key(&line)).await.unwrap();
    say(&alice, "bob@chat.test", "two").await;
    reads(&bob, "alice@chat.test", &["one", "from bob2", "two"]).await;
    // Alice's device committed the removal before it sent (12.6).
    let lines = alice
        .conversation("bob@chat.test")
        .unwrap()
        .export()
        .unwrap();
    let verbs: Vec<(&str, &str)> = lines
        .iter()
        .map(|l| {
            let mut words = l.split(' ');
            let tags = words.next().unwrap();
            let from = tags
                .split(';')
                .find_map(|t| t.strip_prefix("from="))
                .unwrap();
            (from, words.next().unwrap())
        })
        .collect();
    assert_eq!(
        verbs[verbs.len() - 2..],
        [("alice@chat.test", "COMMIT"), ("alice@chat.test", "ENC")],
        "{lines:?}"
    );
    // The removed device does not read it.
    assert_ne!(
        texts(&bob2, "alice@chat.test").last().map(|t| t.0.clone()),
        Some("two".to_owned())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_confirmed_device_gets_the_history_keys() {
    let server = hosted_server(&[], |_| {}).await;
    let alice = registered(&server, "alice").await;
    let bob = registered(&server, "bob").await;
    say(&alice, "bob@chat.test", "before").await;
    reads(&bob, "alice@chat.test", &["before"]).await;

    // Alice's second device joins, and cannot read what came before it.
    let events = alice.subscribe();
    let alice2 = second_device(&server, &alice).await;
    let new = fingerprint(&alice2);
    // Her first device tells her about it (12.12).
    let n = notice("a new device", &events).await;
    assert_eq!(
        n,
        Notice::NewDevice {
            fingerprint: new.clone()
        }
    );
    let devices = alice.devices("alice@chat.test").unwrap();
    assert!(
        devices
            .iter()
            .any(|d| d.fingerprint == new && d.state == Some(OwnDeviceState::New)),
        "{devices:?}"
    );

    // Once she confirms it, it gets every history key and reads the whole
    // history, offline too (12.9).
    within("confirming", alice.confirm_device(&new, true))
        .await
        .unwrap();
    reads(&alice2, "bob@chat.test", &["before"]).await;
    within("stopping", alice2.disconnect()).await;
    assert_eq!(
        texts(&alice2, "bob@chat.test"),
        [("before".to_owned(), Some(Encryption::Verified))]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_declined_device_gets_nothing() {
    let server = hosted_server(&[], |_| {}).await;
    let alice = registered(&server, "alice").await;
    let bob = registered(&server, "bob").await;
    say(&alice, "bob@chat.test", "before").await;
    reads(&bob, "alice@chat.test", &["before"]).await;
    let alice2 = second_device(&server, &alice).await;
    let new = fingerprint(&alice2);
    within("declining", alice.confirm_device(&new, false))
        .await
        .unwrap();
    say(&bob, "alice@chat.test", "after").await;
    reads(&alice2, "bob@chat.test", &["after"]).await;
    assert_eq!(
        states(&alice2, "bob@chat.test"),
        [Some(Encryption::Waiting), Some(Encryption::Verified)]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn both_sides_starting_at_once_end_in_one_group() {
    let server = hosted_server(&[], |_| {}).await;
    let alice = registered(&server, "alice").await;
    let bob = registered(&server, "bob").await;
    // Both send INIT at about the same time: one gets `stale`, and joins
    // the other's group (12.6).
    let a = alice.conversation("bob@chat.test").unwrap();
    let b = bob.conversation("alice@chat.test").unwrap();
    let (ea, eb) = tokio::join!(a.send("from alice"), b.send("from bob"));
    let (ea, eb) = (ea.unwrap(), eb.unwrap());
    let (ra, rb) = tokio::join!(
        within("alice sending", alice.wait_outbox(ea.id)),
        within("bob sending", bob.wait_outbox(eb.id))
    );
    for r in [ra.unwrap(), rb.unwrap()] {
        assert!(
            matches!(r.status, librisala::client::OutboxStatus::Sent { .. }),
            "{r:?}"
        );
    }
    within("both read both", async {
        loop {
            let ta: Vec<_> = texts(&alice, "bob@chat.test");
            let tb: Vec<_> = texts(&bob, "alice@chat.test");
            if ta.len() == 2 && ta == tb && ta.iter().all(|(_, e)| *e == Some(Encryption::Verified))
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn history_keys_are_backed_up_and_restored() {
    let server = hosted_server(&[], |_| {}).await;
    let alice = registered(&server, "alice").await;
    let bob = registered(&server, "bob").await;
    say(&alice, "bob@chat.test", "one").await;

    // With a recovery key, every history key is backed up (12.10).
    let made = within("a recovery key", alice.create_recovery_key())
        .await
        .unwrap();
    say(&bob, "alice@chat.test", "two").await;
    reads(&alice, "bob@chat.test", &["one", "two"]).await;
    within("syncing", alice.wait_synced()).await.unwrap();

    // A new device, never confirmed, restores them and reads everything.
    let alice2 = second_device(&server, &alice).await;
    let n = within("restoring", async {
        // Its own group joins first; then the backup covers each
        // conversation the cache knows.
        loop {
            if alice2.conversation("bob@chat.test").is_ok() {
                break alice2.restore_backup(&made.key).await.unwrap();
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(n >= 2, "{n}");
    let read: Vec<String> = texts(&alice2, "bob@chat.test")
        .into_iter()
        .map(|(t, _)| t)
        .collect();
    assert_eq!(read, ["one", "two"]);
    assert!(
        states(&alice2, "bob@chat.test")
            .iter()
            .all(|s| matches!(s, Some(Encryption::Verified | Encryption::Unverified))),
        "{:?}",
        states(&alice2, "bob@chat.test")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_report_of_an_encrypted_message_verifies() {
    let server = hosted_server(&[], |c| c.operators.push("olga@chat.test".to_owned())).await;
    let olga = registered(&server, "olga").await;
    let alice = registered(&server, "alice").await;
    let bob = registered(&server, "bob").await;
    say(&alice, "bob@chat.test", "something awful").await;
    reads(&bob, "alice@chat.test", &["something awful"]).await;
    let seq = bob
        .conversation("alice@chat.test")
        .unwrap()
        .messages(None, 10)
        .unwrap()
        .messages
        .last()
        .unwrap()
        .seq;

    // Bob reports it with REPORTENC, which reveals the content (5.8).
    let events = olga.subscribe();
    let id = within(
        "reporting",
        bob.conversation("alice@chat.test")
            .unwrap()
            .report(seq, "harassment"),
    )
    .await
    .unwrap();
    // The operator gets it, and the content checks against the franking
    // commitment.
    let report = event("a report", &events, |e| match e {
        AccountEvent::Report { report } => Some(report.clone()),
        _ => None,
    })
    .await;
    assert_eq!(report.id, id);
    assert!(report.encrypted);
    assert_eq!(report.franking, Some(true), "{report:?}");
    assert_eq!(report.message.as_ref().unwrap().text, "something awful");
    let listed = within("ADMIN REPORTS", olga.admin().reports())
        .await
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].franking, Some(true));
    assert_eq!(listed[0].message.as_ref().unwrap().text, "something awful");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_confirmed_device_backs_up_with_the_recovery_key() {
    let server = hosted_server(&[], |_| {}).await;
    let alice = registered(&server, "alice").await;
    let bob = registered(&server, "bob").await;
    say(&alice, "bob@chat.test", "one").await;
    let made = within("a recovery key", alice.create_recovery_key())
        .await
        .unwrap();

    // Confirming a new device sends it the recovery key with the history
    // keys (12.9, 12.10).
    let alice2 = second_device(&server, &alice).await;
    let new = fingerprint(&alice2);
    let events = alice.subscribe();
    within("waiting for the new device", async {
        while !alice
            .devices("alice@chat.test")
            .unwrap()
            .iter()
            .any(|d| d.fingerprint == new && d.state == Some(OwnDeviceState::New))
        {
            let _ =
                tokio::time::timeout(std::time::Duration::from_millis(200), events.next()).await;
        }
    })
    .await;
    within("confirming", alice.confirm_device(&new, true))
        .await
        .unwrap();
    reads(&alice2, "bob@chat.test", &["one"]).await;
    within("syncing", alice.wait_synced()).await.unwrap();
    within("stopping", alice.disconnect()).await;

    // With the first device gone, a new epoch starts and Bob writes in it.
    // Only the confirmed device can back up its key.
    let _bob2 = second_device(&server, &bob).await;
    say(&bob, "alice@chat.test", "two").await;
    reads(&alice2, "bob@chat.test", &["one", "two"]).await;

    // A third device restores it from the backup.
    let alice3 = second_device(&server, &alice2).await;
    within("restoring", async {
        loop {
            if alice3.conversation("bob@chat.test").is_ok() {
                alice3.restore_backup(&made.key).await.unwrap();
                if texts(&alice3, "bob@chat.test")
                    .iter()
                    .any(|(t, _)| t == "two")
                {
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refreshing_shows_what_the_key_file_lists_now() {
    let server = hosted_server(&[], |_| {}).await;
    let alice = registered(&server, "alice").await;
    within("a recovery key", alice.create_recovery_key())
        .await
        .unwrap();
    // The recovery key's own key is in the key file, labelled; with no
    // leaf, it shows as the recovery key, not as a device (12.12).
    assert!(
        within("refreshing", alice.refresh_devices("alice@chat.test"))
            .await
            .unwrap()
    );
    let devices = alice.devices("alice@chat.test").unwrap();
    assert_eq!(devices.len(), 2, "{devices:?}");
    assert!(devices.iter().any(|d| d.this_device && !d.recovery));
    assert!(
        devices
            .iter()
            .any(|d| d.recovery && d.label == "recovery" && d.listed == Some(true)),
        "{devices:?}"
    );
}

/// Alice's encrypted room `room`, with Bob invited and joined.
async fn shared_room(alice: &Account, bob: &Account, room: &str) {
    let conv = within("joining", alice.join(room)).await.unwrap();
    within("INFO", conv.room_info()).await.unwrap();
    within("encrypting", conv.encrypt(History::Shared, false))
        .await
        .unwrap();
    within("syncing", alice.wait_synced()).await.unwrap();
    within("inviting", conv.invite(&bob.uid())).await.unwrap();
    within("invited", async {
        loop {
            match bob.join(room).await {
                Ok(_) => break,
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
            }
        }
    })
    .await;
    within("syncing", bob.wait_synced()).await.unwrap();
}

/// Who sent each COMMIT and ENC of `conv` in `account`'s cache, in order.
fn verbs(account: &Account, conv: &str) -> Vec<(String, String)> {
    account
        .conversation(conv)
        .unwrap()
        .export()
        .unwrap()
        .iter()
        .filter_map(|l| {
            let mut words = l.split(' ');
            let tags = words.next()?;
            let from = tags.split(';').find_map(|t| t.strip_prefix("from="))?;
            let verb = words.next()?;
            matches!(verb, "COMMIT" | "ENC").then(|| (from.to_owned(), verb.to_owned()))
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn leaving_an_encrypted_room_removes_the_leaves() {
    let server = hosted_server(&[], |_| {}).await;
    let alice = registered(&server, "alice").await;
    let bob = registered(&server, "bob").await;
    let carol = registered(&server, "carol").await;
    shared_room(&alice, &bob, "#secret").await;
    let room = alice.conversation("#secret").unwrap();
    within("inviting", room.invite("carol@chat.test"))
        .await
        .unwrap();
    within("invited", async {
        while carol.join("#secret").await.is_err() {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await;
    say(&bob, "#secret", "bob here").await;
    reads(&carol, "#secret", &["bob here"]).await;

    // Bob leaves. His leaves must go before anyone sends again (12.6):
    // Alice's device, or Carol's, commits their removal first.
    within("leaving", bob.part("#secret", "bye")).await.unwrap();
    say(&alice, "#secret", "after bob").await;
    let v = verbs(&alice, "#secret");
    assert_eq!(v[v.len() - 2].1, "COMMIT", "{v:?}");
    assert_ne!(v[v.len() - 2].0, "bob@chat.test", "{v:?}");
    reads(&carol, "#secret", &["bob here", "after bob"]).await;

    // Carol is kicked: the same.
    within("kicking", room.kick("carol@chat.test", ""))
        .await
        .unwrap();
    say(&alice, "#secret", "alone again").await;
    let v = verbs(&alice, "#secret");
    assert_eq!(v[v.len() - 2].1, "COMMIT", "{v:?}");
    reads(&alice, "#secret", &["after bob", "alone again"]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_offline_catches_up_on_commits() {
    let server = hosted_server(&[], |_| {}).await;
    let alice = registered(&server, "alice").await;
    let bob = registered(&server, "bob").await;
    say(&alice, "bob@chat.test", "one").await;
    reads(&bob, "alice@chat.test", &["one"]).await;
    within("stopping", bob.disconnect()).await;

    // While Bob is away, the group moves on: Alice's second device joins,
    // and both write in new epochs.
    let alice2 = second_device(&server, &alice).await;
    say(&alice2, "bob@chat.test", "two").await;
    say(&alice, "bob@chat.test", "three").await;

    // Bob catches up: the commits in order, then the messages (12.11).
    within("signing in", bob.connect()).await.unwrap();
    within("syncing", bob.wait_synced()).await.unwrap();
    reads(&bob, "alice@chat.test", &["one", "two", "three"]).await;
    say(&bob, "alice@chat.test", "four").await;
    reads(&alice2, "bob@chat.test", &["two", "three", "four"]).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inviting_adds_every_device() {
    let server = hosted_server(&[], |_| {}).await;
    let alice = registered(&server, "alice").await;
    let bob = registered(&server, "bob").await;
    let bob2 = second_device(&server, &bob).await;
    let alice2 = second_device(&server, &alice).await;
    within("syncing", alice.wait_synced()).await.unwrap();
    shared_room(&alice, &bob, "#secret").await;
    say(&alice, "#secret", "to all of you").await;
    // Every device of both reads it (12.6): Alice's second device joined
    // its own identity's room by external commit, and Bob's two by the
    // invitation's Welcome. Alice's invitation raced her second device's
    // joining, and was made again after `stale` (12.5).
    for who in [&bob, &bob2, &alice2] {
        reads(who, "#secret", &["to all of you"]).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn messages_wait_until_the_other_side_has_a_device() {
    use librisala::client::OutboxStatus;
    let server = hosted_server(&[], |_| {}).await;
    let alice = registered(&server, "alice").await;
    // Bob registers elsewhere, and no device of his has KeyPackages yet.
    let (bob_id, _raw) = server.register("bob").await;

    // Alice writes. Her device starts the conversation, but holds the
    // messages until a device of Bob's is in its group (12.6).
    let conv = alice.conversation("bob@chat.test").unwrap();
    let mut ids = Vec::new();
    for text in ["one", "two"] {
        ids.push(within("queueing", conv.send(text)).await.unwrap().id);
    }
    let all_held = || {
        let outbox = conv.outbox().unwrap();
        ids.iter().all(|id| {
            outbox
                .iter()
                .any(|e| e.id == *id && e.status == OutboxStatus::Held)
        })
    };
    until("held", &alice.subscribe(), all_held).await;
    assert!(conv.info().unwrap().unwrap().encrypted);
    let lines = conv.export().unwrap();
    assert!(lines.iter().all(|l| !l.contains(" ENC ")), "{lines:?}");

    // Bob's first device comes online and joins the conversation. Alice's
    // device sends what it held, in order, and Bob reads all of it.
    let (client, addr) = device(&server);
    client
        .import_device_key("bob@chat.test", &bob_id.key().to_pkcs8_pem(), false)
        .await
        .unwrap();
    let bob = client.add_identity(&addr, "bob@chat.test").unwrap();
    within("signing in", bob.connect()).await.unwrap();
    reads(&bob, "alice@chat.test", &["one", "two"]).await;
    for id in ids {
        let done = within("sending", alice.wait_outbox(id)).await.unwrap();
        assert!(matches!(done.status, OutboxStatus::Sent { .. }), "{done:?}");
    }
    reads(&alice, "bob@chat.test", &["one", "two"]).await;
}
