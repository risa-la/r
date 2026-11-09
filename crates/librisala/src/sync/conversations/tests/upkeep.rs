//! The engine's upkeep (task R2): past epochs deleted by the clock (12.9,
//! LR-H1), the outbox purged (LR-M2), and timers brought back after a
//! restart (LR-M4), against the in-memory server.

use super::*;

const MINUTE: u64 = 60 * 1000;
const HOUR: u64 = 60 * MINUTE;

fn direct(net: &mut Net, a: usize, b: usize) -> (ConversationId, ConversationId) {
    let conv = net
        .job(
            a,
            Job::Direct {
                peer: net.devices[b].uid.clone(),
            },
        )
        .unwrap();
    let cb = net.same_conv(b, a, conv).unwrap();
    (conv, cb)
}

/// A message that device `d` encrypts now in `conv`'s current epoch,
/// without posting it.
fn encrypted(net: &mut Net, d: usize, conv: ConversationId, text: &str) -> Vec<u8> {
    let uid = net.devices[d].uid.clone();
    let now = net.clock.now().unix_millis();
    net.write(d, |tx| {
        content::queue_lines(
            tx,
            conv,
            &uid,
            vec![ContentLine::Text(Text::new(text))],
            false,
            now,
        )
    });
    let cx = net.cx(d);
    let me = net.devices[d].engine.me(&cx).unwrap();
    let mut out = Vec::new();
    net.devices[d]
        .engine
        .write(&cx, &me, &mut out, |tx, c| {
            let row = tx
                .pending_outbox(conv)?
                .into_iter()
                .rfind(|r| r.kind == OutboxKind::Message)
                .unwrap();
            let conv_row = tx.conversation(conv)?;
            let (post, _) = group::encrypt(tx, c, &conv_row, row.body.as_ref().unwrap())?;
            tx.conn()
                .execute("DELETE FROM outbox WHERE id = ?1", [row.id])
                .map_err(crate::store::StoreError::from)?;
            Ok(post)
        })
        .unwrap()
}

/// LR-H1, 12.9: a device deletes a past epoch's secrets 2 hours after it
/// applied the commit that ended it, by its own clock, whatever posts
/// arrive: a late message of that epoch that the posts alone would still
/// let it read is unreadable then.
#[test]
fn past_epochs_go_two_hours_after_their_commit_by_the_clock() {
    let mut net = Net::new();
    let alice = net.device("alice", "alice@example.org");
    let bob = net.device("bob", "bob@example.net");
    net.connect(alice);
    net.connect(bob);
    let (a, b) = direct(&mut net, alice, bob);
    let epoch = net.epoch(alice, a);
    // Bob's device encrypts two messages in this epoch, which the server
    // holds back.
    net.disconnect(bob);
    let early = encrypted(&mut net, bob, b, "early");
    let late = encrypted(&mut net, bob, b, "late");
    // Alice commits: the epoch is past.
    let now = net.clock.now().unix_millis();
    net.write(alice, |tx| {
        group::queue_intent(
            tx,
            a,
            &Intent {
                new_leaf_key: true,
                ..Intent::default()
            },
            now,
        )?;
        Ok(())
    });
    net.tick();
    assert_eq!(net.epoch(alice, a), epoch + 1);
    let commit_t = net.clock.now().unix_millis();
    let mailbox = net.devices[alice]
        .store
        .write_with(|tx| -> Result<_, EngineError> { Ok(tx.current_mailbox(a)?.mailbox) })
        .unwrap()
        .0;
    // A late post within the hour after the commit is read.
    net.server.inject_post(&mailbox, commit_t + MINUTE, early);
    net.restart(alice);
    net.tick();
    assert_eq!(
        net.texts(alice, a),
        [("bob@example.net".into(), "early".into())]
    );
    // Two hours on, by the device's clock, the epoch's secrets are gone,
    // although the post's `t` alone would still let it be read.
    for _ in 0..13 {
        net.advance(10 * MINUTE);
    }
    net.server
        .inject_post(&mailbox, commit_t + 2 * MINUTE, late);
    net.restart(alice);
    net.tick();
    assert_eq!(net.texts(alice, a).len(), 1, "the late one is unreadable");
}

/// LR-M2: what this device sent does not stay in the outbox: the
/// RisalaMessage goes once posted, the row a day later, and a message
/// deleted before it is posted is never sent.
#[test]
fn the_outbox_keeps_no_plaintext() {
    let mut net = Net::new();
    let alice = net.device("alice", "alice@example.org");
    let bob = net.device("bob", "bob@example.net");
    net.connect(alice);
    net.connect(bob);
    let (a, b) = direct(&mut net, alice, bob);
    let id = net.say(alice, a, "sent");
    let outbox = |net: &Net| -> Vec<(Option<Vec<u8>>, String)> {
        net.devices[alice]
            .store
            .write_with(|tx| -> Result<_, EngineError> {
                let mut stmt = tx
                    .conn()
                    .prepare("SELECT body, state FROM outbox WHERE message_id = ?1")
                    .map_err(crate::store::StoreError::from)?;
                let rows = stmt
                    .query_map([&id[..]], |r| Ok((r.get(0)?, r.get(1)?)))
                    .map_err(crate::store::StoreError::from)?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(crate::store::StoreError::from)?;
                Ok(rows)
            })
            .unwrap()
            .0
    };
    assert_eq!(outbox(&net), [(None, "done".to_owned())]);
    net.advance(10 * MINUTE + 1);
    net.advance(24 * HOUR);
    assert!(outbox(&net).is_empty(), "purged a day later");
    // Deleted before it was posted: never sent, and gone from the outbox.
    net.disconnect(alice);
    let oops = net.say(alice, a, "oops");
    net.write(alice, |tx| Ok(tx.erase_message(a, &oops)?));
    net.connect(alice);
    net.tick();
    assert!(
        !net.texts(bob, b).iter().any(|(_, t)| t == "oops"),
        "{:?}",
        net.texts(bob, b)
    );
}

/// LR-M4, 6.1: a SelfRemove that a device would commit after a random
/// wait is still committed if the device restarts during the wait.
#[test]
fn pending_proposals_are_committed_after_a_restart() {
    let mut net = Net::new();
    let alice = net.device_with(
        "alice",
        "alice@example.org",
        Config {
            self_conversation: false,
            max_commit_wait_ms: 5 * MINUTE,
            ..Config::immediate()
        },
    );
    let bob = net.device("bob", "bob@example.net");
    net.connect(alice);
    net.connect(bob);
    let (a, b) = direct(&mut net, alice, bob);
    let now = net.clock.now().unix_millis();
    net.write(bob, |tx| {
        tx.set_state(b, ConvState::Leaving)?;
        group::queue_self_remove(tx, b, now)
    });
    net.tick();
    assert_eq!(net.leaves(alice, a).len(), 2, "alice waits");
    net.restart(alice);
    for _ in 0..6 {
        net.advance(MINUTE);
    }
    assert_eq!(net.leaves(alice, a), ["alice@example.org"]);
    assert_eq!(net.state(bob, b), ConvState::Left);
}

/// LR-M4, 12.7: a RESYNC nobody answers goes to the own devices after an
/// hour, also when the device restarted in between.
#[test]
fn the_resync_escalation_survives_a_restart() {
    let mut net = Net::new();
    let laptop = net.device("laptop", "alice@example.org");
    let phone = net.device_of("phone", laptop);
    let bob = net.device("bob", "bob@example.net");
    for d in [laptop, phone, bob] {
        net.connect(d);
    }
    let me = net.job(laptop, Job::WithYourself).unwrap();
    net.same_conv(phone, laptop, me).unwrap();
    let (direct, _) = direct(&mut net, laptop, bob);
    let p = net.same_conv(phone, laptop, direct).unwrap();
    let before = net.epoch(laptop, direct);
    let now = net.clock.now().unix_millis();
    net.devices[phone].engine.resync_since.insert(p, (now, 1));
    net.tick();
    net.restart(phone);
    net.advance(HOUR + 1);
    assert!(net.epoch(laptop, direct) > before, "the laptop replaced it");
    assert_eq!(net.epoch(phone, p), net.epoch(laptop, direct));
}
