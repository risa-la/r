//! Edits, reactions and deletes against a real server (5.3, 5.4, 7.6):
//! what two devices of one identity see, and DELETE through the outbox.
//!
//! The identities are hosted by the test server, under `chat.test` (see
//! `common`).

mod common;

use common::*;
use librisala::client::{Account, Conversation, Message, OutboxStatus};
use risala_server::testing::Proxy;

/// The message `seq` as the account's cache has it now.
fn message(conv: &Conversation, seq: u64) -> Option<Message> {
    conv.messages(None, 200)
        .unwrap()
        .messages
        .into_iter()
        .find(|m| m.seq == seq)
}

/// Text, edited, deleted and reactions of message `seq`, for comparing.
type Shown = (Option<String>, bool, bool, Vec<(String, u64, bool)>);

fn shown(conv: &Conversation, seq: u64) -> Option<Shown> {
    message(conv, seq).map(|m| {
        (
            m.text,
            m.edited,
            m.deleted,
            m.reactions
                .into_iter()
                .map(|r| (r.reaction, r.count, r.mine))
                .collect(),
        )
    })
}

/// Event `seq` as the cache stored it, in canonical form. DELETE events
/// are applied, not shown as timeline items.
fn stored_line(conv: &Conversation, seq: u64) -> Option<String> {
    let prefix = format!("@seq={seq};");
    conv.export()
        .unwrap()
        .into_iter()
        .find(|l| l.starts_with(&prefix))
}

/// Sends through the outbox and waits for the seq.
async fn sent(account: &Account, entry: librisala::client::OutboxEntry) -> u64 {
    let entry = within("the outbox", account.wait_outbox(entry.id))
        .await
        .unwrap();
    match entry.status {
        OutboxStatus::Sent { seq } => seq,
        other => panic!("{other:?}"),
    }
}

/// Waits until every account shows message `seq` as `want`.
async fn all_show(accounts: &[&Account], room: &str, seq: u64, want: Shown) {
    for a in accounts {
        let conv = a.conversation(room).unwrap();
        until(
            &format!("{} shows {seq} as {want:?}", a.uid()),
            &a.subscribe(),
            || shown(&conv, seq).as_ref() == Some(&want),
        )
        .await;
    }
}

#[tokio::test]
async fn two_devices_see_edits_reactions_and_deletes() {
    let server = hosted_server(&["#general"], |_| {}).await;
    let alice_a = registered_in(&server, "alice", "#general").await;
    let alice_b = second_device(&server, &alice_a).await;
    let bob = registered_in(&server, "bob", "#general").await;
    let a = alice_a.conversation("#general").unwrap();
    let b = bob.conversation("#general").unwrap();
    let everyone = [&alice_a, &alice_b, &bob];

    // An edit replaces the text on every device (5.3).
    let first = sent(&alice_a, a.send("teh plan").await.unwrap()).await;
    let edit = sent(&alice_a, a.edit(first, "the plan").await.unwrap()).await;
    all_show(
        &everyone,
        "#general",
        first,
        (Some("the plan".into()), true, false, vec![]),
    )
    .await;
    // Someone else's message cannot be edited.
    let entry = b.edit(first, "bob's plan").await.unwrap();
    let entry = within("refused", bob.wait_outbox(entry.id)).await.unwrap();
    assert!(
        matches!(&entry.status, OutboxStatus::Failed { code: Some(c), .. } if c == "forbidden"),
        "{entry:?}"
    );

    // Reactions, counted, with "mine" for both of the account's devices.
    sent(&bob, b.react(first, "👍").await.unwrap()).await;
    let own_reaction = sent(&alice_b, {
        let conv = alice_b.conversation("#general").unwrap();
        conv.react(first, "👍").await.unwrap()
    })
    .await;
    all_show(
        &everyone,
        "#general",
        first,
        (
            Some("the plan".into()),
            true,
            false,
            vec![("👍".into(), 2, true)],
        ),
    )
    .await;
    // The same reaction again gets the same seq, and records nothing.
    let again = sent(&alice_a, a.react(first, "👍").await.unwrap()).await;
    assert_eq!(again, own_reaction);

    // Deleting a reaction takes it back (5.4), on the other device too.
    let entry = a.delete(own_reaction).await.unwrap();
    assert_eq!(entry.deletes, Some(own_reaction));
    sent(&alice_a, entry).await;
    let shows = |text: &str, edited, mine| {
        (
            Some(text.to_owned()),
            edited,
            false,
            vec![("👍".to_owned(), 1, mine)],
        )
    };
    all_show(
        &[&alice_a, &alice_b],
        "#general",
        first,
        shows("the plan", true, false),
    )
    .await;
    all_show(&[&bob], "#general", first, shows("the plan", true, true)).await;

    // Deleting an edit makes the previous version current again.
    sent(&alice_a, a.delete(edit).await.unwrap()).await;
    all_show(
        &[&alice_a, &alice_b],
        "#general",
        first,
        shows("teh plan", false, false),
    )
    .await;
    all_show(&[&bob], "#general", first, shows("teh plan", false, true)).await;

    // Deleting the message erases its text and its reactions. A reply to
    // it stays.
    let reply = sent(&bob, b.reply(first, "sounds good").await.unwrap()).await;
    sent(&alice_b, {
        let conv = alice_b.conversation("#general").unwrap();
        conv.delete(first).await.unwrap()
    })
    .await;
    all_show(
        &everyone,
        "#general",
        first,
        (Some(String::new()), false, true, vec![]),
    )
    .await;
    for account in everyone {
        let conv = account.conversation("#general").unwrap();
        let m = message(&conv, reply).unwrap();
        assert_eq!(m.text.as_deref(), Some("sounds good"));
        assert_eq!(m.reply_to, Some(first));
        // The deleted text is discarded from the cache, not only hidden.
        assert!(
            !conv
                .export()
                .unwrap()
                .iter()
                .any(|l| l.contains("teh plan") || l.contains("the plan")),
            "{:?}",
            conv.export().unwrap()
        );
    }

    // Bob is no moderator: he cannot delete alice's messages.
    let other = sent(&alice_a, a.send("mine").await.unwrap()).await;
    let entry = b.delete(other).await.unwrap();
    let entry = within("refused", bob.wait_outbox(entry.id)).await.unwrap();
    assert!(
        matches!(&entry.status, OutboxStatus::Failed { code: Some(c), .. } if c == "forbidden"),
        "{entry:?}"
    );
    assert!(!message(&a, other).unwrap().deleted);

    // A device that was offline catches up on all of it with HISTORY.
    let alice_c = second_device(&server, &alice_a).await;
    let c = alice_c.conversation("#general").unwrap();
    for seq in [first, reply, other] {
        assert_eq!(shown(&c, seq), shown(&a, seq), "{seq}");
    }
    server.stop().await;
}

/// A DELETE queued offline goes out on the next connection, and sending
/// the same DELETE again, or one for a message someone else deleted
/// first, ends as sent with the earlier DELETE's seq (5.4).
#[tokio::test]
async fn deletes_queued_offline_go_out_and_repeats_are_harmless() {
    let server = hosted_server(&["#general"], |c| {
        c.operators = vec!["op@chat.test".into()];
    })
    .await;
    let alice = registered_in(&server, "alice", "#general").await;
    let bob = registered_in(&server, "bob", "#general").await;
    let op = registered_in(&server, "op", "#general").await;
    let a = alice.conversation("#general").unwrap();
    let seq = sent(&alice, a.send("oops").await.unwrap()).await;
    all_show(
        &[&bob],
        "#general",
        seq,
        (Some("oops".into()), false, false, vec![]),
    )
    .await;

    alice.disconnect().await;
    let entry = a.delete(seq).await.unwrap();
    assert_eq!(entry.status, OutboxStatus::Queued);
    // The timeline does not show the entry as a message.
    assert!(
        a.timeline(50)
            .unwrap()
            .items()
            .iter()
            .all(|m| m.outbox.is_none())
    );
    within("connecting", alice.connect()).await.unwrap();
    let deleted = sent(&alice, entry).await;
    let gone = (Some(String::new()), false, true, vec![]);
    all_show(&[&alice, &bob], "#general", seq, gone.clone()).await;
    let line = stored_line(&a, deleted).unwrap();
    assert!(line.ends_with(&format!("DELETE #general {seq}")), "{line}");

    // The same DELETE again: the server answers with the first one's seq.
    let again = sent(&alice, a.delete(seq).await.unwrap()).await;
    assert_eq!(again, deleted);

    // Bob's message, deleted by an operator while bob is offline: bob's
    // queued DELETE still ends as sent, with the operator's DELETE.
    let b = bob.conversation("#general").unwrap();
    let mine = sent(&bob, b.send("regret").await.unwrap()).await;
    bob.disconnect().await;
    let entry = b.delete(mine).await.unwrap();
    let o = op.conversation("#general").unwrap();
    all_show(
        &[&op],
        "#general",
        mine,
        (Some("regret".into()), false, false, vec![]),
    )
    .await;
    let by_op = sent(&op, o.delete(mine).await.unwrap()).await;
    within("connecting", bob.connect()).await.unwrap();
    let entry = within("sent", bob.wait_outbox(entry.id)).await.unwrap();
    assert_eq!(entry.status, OutboxStatus::Sent { seq: by_op });
    all_show(&[&bob], "#general", mine, gone.clone()).await;
    let line = stored_line(&b, by_op).unwrap();
    assert!(line.contains("from=op@chat.test"), "{line}");
    server.stop().await;
}

/// A DELETE whose OK was lost when the connection dropped is sent again on
/// the next one, and the server's answer for the repeat completes it
/// (5.4, 7.6).
#[tokio::test]
async fn a_delete_whose_ok_was_lost_is_sent_again() {
    let server = hosted_server(&["#general"], |_| {}).await;
    let proxy = Proxy::start(server.addr()).await;
    let alice = registered_at(&server, proxy.addr(), "alice").await;
    within("joining", alice.join("#general")).await.unwrap();
    let bob = registered_in(&server, "bob", "#general").await;
    let a = alice.conversation("#general").unwrap();
    let seq = sent(&alice, a.send("twice").await.unwrap()).await;
    all_show(
        &[&bob],
        "#general",
        seq,
        (Some("twice".into()), false, false, vec![]),
    )
    .await;

    let events = alice.subscribe();
    proxy.hold(true);
    let entry = a.delete(seq).await.unwrap();
    let gone = (Some(String::new()), false, true, vec![]);
    all_show(&[&bob], "#general", seq, gone.clone()).await;
    assert_eq!(
        alice.outbox().unwrap().last().unwrap().status,
        OutboxStatus::Sending,
        "the OK is held back"
    );
    proxy.cut();
    until("alice notices the cut", &events, || {
        !alice.state().is_online()
    })
    .await;
    proxy.hold(false);

    let entry = within("sent", alice.wait_outbox(entry.id)).await.unwrap();
    let OutboxStatus::Sent { seq: deleted } = entry.status else {
        panic!("{entry:?}")
    };
    all_show(&[&alice], "#general", seq, gone).await;
    // One DELETE was recorded, and that is the seq the entry has.
    let deletes: Vec<String> = server_history(&server, "#general")
        .await
        .into_iter()
        .filter(|l| l.contains(" DELETE "))
        .collect();
    assert_eq!(deletes.len(), 1, "{deletes:?}");
    assert!(
        deletes[0].starts_with(&format!("@seq={deleted};")),
        "{deletes:?}"
    );
    server.stop().await;
}

/// Authors may delete their own messages in a room they have left (5.4),
/// but a DELETE bound to a room that was dropped and created again under
/// the same name deletes nothing in the new room.
#[tokio::test]
async fn deletes_in_a_room_left_name_the_room_they_mean() {
    let server = hosted_server(&[], |c| {
        c.operators = vec!["op@chat.test".into()];
    })
    .await;
    let op = registered_in(&server, "op", "#club").await;
    let alice = registered_in(&server, "alice", "#club").await;
    let a = alice.conversation("#club").unwrap();
    let first = sent(&alice, a.send("first").await.unwrap()).await;
    let second = sent(&alice, a.send("second").await.unwrap()).await;
    within("parting", alice.part("#club", "")).await.unwrap();
    within("syncing", alice.wait_synced()).await.unwrap();
    assert!(!a.info().unwrap().unwrap().joined);

    // Left, and offline: the DELETE goes out on the next connection.
    alice.disconnect().await;
    let entry = a.delete(first).await.unwrap();
    within("connecting", alice.connect()).await.unwrap();
    let entry = within("sent", alice.wait_outbox(entry.id)).await.unwrap();
    assert!(
        matches!(entry.status, OutboxStatus::Sent { .. }),
        "{entry:?}"
    );
    let o = op.conversation("#club").unwrap();
    all_show(
        &[&op],
        "#club",
        first,
        (Some(String::new()), false, true, vec![]),
    )
    .await;
    // No DELETE event reaches alice, who left: her own cache applies the
    // deletion when the OK comes.
    assert_eq!(
        shown(&a, first),
        Some((Some(String::new()), false, true, vec![]))
    );

    // The room is dropped and made again; alice, not a member, hears
    // nothing of it. Her DELETE of `second` names the old room's id.
    within("dropping", op.admin().drop_room("#club", ""))
        .await
        .unwrap();
    within("joining", op.join("#club")).await.unwrap();
    within("syncing", op.wait_synced()).await.unwrap();
    for text in ["new one", "new two", "new three", "new four"] {
        sent(&op, o.send(text).await.unwrap()).await;
    }
    let before = shown(&o, second);
    assert!(before.is_some());
    let entry = a.delete(second).await.unwrap();
    let entry = within("refused", alice.wait_outbox(entry.id))
        .await
        .unwrap();
    assert!(
        matches!(&entry.status, OutboxStatus::Failed { code: Some(c), .. } if c == "not-found"),
        "{entry:?}"
    );
    assert_eq!(shown(&o, second), before);
    // Nor in alice's cache.
    assert_eq!(
        shown(&a, second),
        Some((Some("second".into()), false, false, vec![]))
    );
    assert!(
        !server_history(&server, "#club")
            .await
            .iter()
            .any(|l| l.contains(" DELETE ")),
    );
    server.stop().await;
}
