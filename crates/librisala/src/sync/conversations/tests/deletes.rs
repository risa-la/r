//! DELETEs from a leaf less trusted than the message they delete (5.4,
//! 12.10): they wait for the leaf to be confirmed, and go if it turns out
//! an impostor or leaves the tree.

use risala_proto::content::{ContentLine, MessageId as LineId};

use super::*;
use crate::store::confirm::{LeafConfirmation, LeafConfirmationRow};

/// Alice and Bob in a direct conversation, and a second device of Bob's,
/// `other`, that Alice has not confirmed. Returns the network, the three
/// devices, and the conversation at each.
struct Setup {
    net: Net,
    alice: usize,
    bob: usize,
    other: usize,
    a: ConversationId,
    b: ConversationId,
    o: ConversationId,
}

fn setup() -> Setup {
    let mut net = Net::new();
    let alice = net.device("alice", "alice@example.org");
    let bob = net.device("bob", "bob@example.net");
    let other = net.device_of("other", bob);
    for d in [alice, bob, other] {
        net.connect(d);
    }
    let a = net
        .job(
            alice,
            Job::Direct {
                peer: "bob@example.net".parse().unwrap(),
            },
        )
        .unwrap();
    let b = net.same_conv(bob, alice, a).unwrap();
    net.job(
        bob,
        Job::Invite {
            conv: b,
            uids: vec!["bob@example.net".parse().unwrap()],
        },
    )
    .unwrap();
    net.tick();
    let o = net
        .same_conv(other, bob, b)
        .expect("the other device joined");
    let other_id: [u8; 48] = net.devices[other].device_id.clone().try_into().unwrap();
    net.devices[alice]
        .hooks
        .distrust
        .lock()
        .unwrap()
        .insert(other_id);
    Setup {
        net,
        alice,
        bob,
        other,
        a,
        b,
        o,
    }
}

impl Setup {
    /// Alice's leaf of the other device.
    fn other_leaf(&self) -> LeafRow {
        let id = self.net.devices[self.other].device_id.clone();
        self.net.devices[self.alice]
            .store
            .leaf_rows(self.a)
            .unwrap()
            .into_iter()
            .find(|l| l.device_id.map(|d| d.to_vec()) == Some(id.clone()))
            .expect("the other device's leaf")
    }

    /// Writes Alice's leaf states as leaf confirmation (C3) does, every
    /// leaf confirmed but the other device's, which is `state`, and settles
    /// the DELETEs that wait for it.
    fn settle(&self, state: LeafConfirmation) {
        let other = self.net.devices[self.other].device_id.clone();
        let rows: Vec<LeafConfirmationRow> = self.net.devices[self.alice]
            .store
            .leaf_rows(self.a)
            .unwrap()
            .into_iter()
            .map(|l| LeafConfirmationRow {
                state: if l.device_id.map(|d| d.to_vec()) == Some(other.clone()) {
                    state
                } else {
                    LeafConfirmation::Confirmed
                },
                leaf: l.leaf,
                signature_key: l.signature_key,
                until: None,
                since_seq: 0,
                repair_at: None,
            })
            .collect();
        let a = self.a;
        self.net.write(self.alice, |tx| {
            tx.set_leaf_confirmations(a, &rows)?;
            content::settle_deletes(tx, a, &rows)
        });
    }

    fn message(&self, id: [u8; 16]) -> MessageRow {
        self.net
            .messages(self.alice, self.a)
            .into_iter()
            .find(|m| m.message_id == id)
            .unwrap()
    }

    fn unconfirmed(&self, id: [u8; 16]) -> bool {
        self.net.devices[self.alice]
            .store
            .unconfirmed_deletes(self.a)
            .unwrap()
            .contains(&id)
    }

    /// Bob's message, verified at Alice, deleted by the other device.
    fn deleted_by_other(&mut self) -> [u8; 16] {
        let id = self.net.say(self.bob, self.b, "keep me");
        assert!(self.message(id).verified);
        self.net.lines(
            self.other,
            self.o,
            vec![ContentLine::Delete {
                id: LineId::from_bytes(id),
            }],
            false,
        );
        id
    }
}

/// 5.4, 12.10: a DELETE from a leaf this device has not confirmed does not
/// erase a verified message: the message shows as deleted but
/// unconfirmed. Once the leaf turns out an impostor, the DELETE is dropped
/// and the message stays.
#[test]
fn an_impostors_delete_never_erases() {
    let mut s = setup();
    let id = s.deleted_by_other();
    let m = s.message(id);
    assert!(!m.deleted);
    assert_eq!(m.text.as_deref(), Some("keep me"));
    assert!(s.unconfirmed(id), "shown as deleted but unconfirmed");
    // At Bob's own device the DELETE is from a confirmed leaf.
    assert!(
        s.net
            .messages(s.bob, s.b)
            .iter()
            .any(|m| m.message_id == id && m.deleted)
    );

    s.settle(LeafConfirmation::Impostor);
    let m = s.message(id);
    assert!(!m.deleted);
    assert_eq!(m.text.as_deref(), Some("keep me"));
    assert!(!s.unconfirmed(id));
    // Confirming that leaf later, with the same key, brings nothing back.
    s.settle(LeafConfirmation::Confirmed);
    assert!(!s.message(id).deleted);

    // A DELETE from a leaf already found an impostor is ignored at once.
    s.settle(LeafConfirmation::Impostor);
    let id = s.deleted_by_other();
    assert!(!s.unconfirmed(id));
    s.settle(LeafConfirmation::Confirmed);
    assert!(!s.message(id).deleted);
}

/// 5.4, 12.10: a DELETE waiting for its leaf applies once the leaf is
/// confirmed with the key it sent with, also after a restart.
#[test]
fn an_unconfirmed_delete_applies_once_its_leaf_is_confirmed() {
    let mut s = setup();
    let id = s.deleted_by_other();
    assert!(s.unconfirmed(id));
    // Still unconfirmed: nothing changes.
    s.settle(LeafConfirmation::Unconfirmed);
    assert!(s.unconfirmed(id));
    assert!(!s.message(id).deleted);

    s.net.restart(s.alice);
    assert!(s.unconfirmed(id), "kept across a restart");
    s.settle(LeafConfirmation::Confirmed);
    let m = s.message(id);
    assert!(m.deleted);
    assert_eq!(m.text, None);
    assert!(!s.unconfirmed(id));

    // A DELETE from an unconfirmed leaf of a message that is not verified
    // either applies at once: it is as trusted.
    let id = s.net.say(s.other, s.o, "mine");
    assert!(!s.message(id).verified);
    s.net.lines(
        s.other,
        s.o,
        vec![ContentLine::Delete {
            id: LineId::from_bytes(id),
        }],
        false,
    );
    assert!(s.message(id).deleted);
    assert!(!s.unconfirmed(id));
}

/// 5.4, 12.10: the DELETEs of a leaf removed as an impostor are dropped:
/// it can never be confirmed with that key.
#[test]
fn an_impostors_deletes_go_when_it_is_removed() {
    let mut s = setup();
    let id = s.deleted_by_other();
    assert!(s.unconfirmed(id));
    let leaf = s.other_leaf();
    // Alice removes the leaf, as she does an impostor's for a check (12.7).
    let now = s.net.clock.now().unix_millis();
    let a = s.a;
    s.net.write(s.alice, |tx| {
        group::queue_intent(
            tx,
            a,
            &Intent {
                remove: vec![(leaf.uid.to_string(), leaf.device_id)],
                ..Intent::default()
            },
            now,
        )
    });
    s.net.tick();
    s.net.tick();
    assert!(
        s.net.devices[s.alice]
            .store
            .leaf_rows(s.a)
            .unwrap()
            .iter()
            .all(|l| l.device_id != leaf.device_id),
        "the leaf is gone"
    );
    s.settle(LeafConfirmation::Unconfirmed);
    assert!(!s.unconfirmed(id));
    assert!(!s.message(id).deleted);
    let left: i64 = s.net.write(s.alice, |tx| {
        Ok(tx
            .conn()
            .query_row("SELECT count(*) FROM deletes", [], |r| r.get(0))
            .map_err(crate::store::StoreError::from)?)
    });
    assert_eq!(left, 0);
}
