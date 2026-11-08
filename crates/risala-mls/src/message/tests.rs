//! Tests of messages (12.9): round trips between members of real groups,
//! every rejection, and vectors for the frank, the RisalaMessage and the
//! RisalaReport (printed for Appendix B with `--nocapture`).

use std::time::{Duration, SystemTime};

use openmls::group::MlsGroup;
use openmls_memory_storage::MemoryStorage;
use risala_proto::content::ContentLine;

use super::*;
use crate::Provider;
use crate::checks::{CommitPost, History as MlsHistory, JoinExpectation, Verdict};
use crate::group::{
    Changes, apply_commit, commit, create_group, join_by_welcome, merge_own_commit, self_remove,
};
use crate::identity::DeviceId;
use crate::keypackage::make_key_package;
use crate::mldsa::SigningKey;
use crate::profile::RisalaProfile;

const HOST: &str = "chat.example.org";
const BOX: [u8; 16] = [0x42; 16];

type Storage = <Provider<MemoryStorage> as OpenMlsProvider>::StorageError;
type Received = Result<Decrypted, ReceiveError<Storage>>;

/// The time posts are stamped with, unless a test says otherwise.
fn t0() -> Timestamp {
    Timestamp::from_unix_millis(1_800_000_000_000).unwrap()
}

fn at(minutes: u64) -> Timestamp {
    t0().checked_add(Duration::from_secs(minutes * 60)).unwrap()
}

/// The post of a commit, for the group's [`MlsHistory`], which these tests
/// do not keep.
fn post(out: &crate::group::CommitOutput) -> CommitPost {
    CommitPost {
        t: now_ms(),
        next: Some(out.next_token_hash),
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn text(s: &str) -> Content {
    Content::parse(format!("TEXT {s}\n").as_bytes()).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// One device: its storage, its leaf's pseudonym and counter, and what it
/// remembers of the group's messages.
struct Device {
    uid: Uid,
    key: SigningKey,
    provider: Provider<MemoryStorage>,
    pseudonym: Pseudonym,
    counter: SendCounter,
    history: MemoryHistory,
}

impl Device {
    fn new(uid: &str, seed: u8) -> Device {
        Device {
            uid: uid.parse().unwrap(),
            key: SigningKey::from_seed([seed; 32]),
            provider: Provider::new(MemoryStorage::default()).unwrap(),
            pseudonym: Pseudonym::generate().unwrap(),
            counter: SendCounter::default(),
            history: MemoryHistory::default(),
        }
    }

    fn identity(&self) -> RisalaIdentity {
        RisalaIdentity::device(
            self.uid.clone(),
            DeviceId::of_device_key(self.key.public_key()),
        )
    }

    fn profile(&self) -> RisalaProfile {
        RisalaProfile::new(self.uid.name(), now_ms()).unwrap()
    }

    fn key_package(&self) -> openmls::prelude::KeyPackage {
        let profile = RisalaProfile::new("", now_ms()).unwrap();
        make_key_package(&self.provider, &self.key, &self.uid, &profile, false)
            .unwrap()
            .key_package
    }

    fn create(&self, conversation: &RisalaConversation) -> MlsGroup {
        create_group(
            &self.provider,
            &self.identity(),
            &self.profile(),
            conversation,
            now_ms(),
        )
        .unwrap()
        .0
    }

    fn join(&self, welcome: &[u8]) -> MlsGroup {
        let expect = JoinExpectation {
            host: HOST.into(),
            own_uid: self.uid.clone(),
            public_room: None,
        };
        join_by_welcome(&self.provider, welcome, None, &expect, now_ms())
            .unwrap()
            .group
    }

    /// Makes a commit with `changes` and merges it at once.
    fn commit(&self, group: &mut MlsGroup, changes: Changes) -> Vec<u8> {
        let out = commit(
            &self.provider,
            group,
            self.pseudonym,
            &self.profile(),
            &MlsHistory::default(),
            changes,
        )
        .unwrap();
        merge_own_commit(
            &self.provider,
            group,
            &mut MlsHistory::default(),
            &post(&out),
        )
        .unwrap();
        out.message
    }

    /// Processes and applies another device's commit, noting it with `t`.
    fn apply(&mut self, group: &mut MlsGroup, message: &[u8], t: Timestamp) {
        let ended = group.epoch().as_u64();
        let Incoming::Commit(received) =
            group::process_message(&self.provider, group, message).unwrap()
        else {
            panic!("not a commit");
        };
        let removed = removed_leaves(&received.staged);
        apply_commit(
            &self.provider,
            group,
            *received,
            &Verdict::default(),
            &mut MlsHistory::default(),
            &CommitPost {
                t: now_ms(),
                next: None,
            },
        )
        .unwrap();
        self.history.note_commit(ended, t, &removed);
    }

    /// Writes a message at `t0`.
    fn write(&mut self, s: &str) -> RisalaMessage {
        self.counter.write(text(s), t0()).unwrap()
    }

    fn encrypt(&self, group: &mut MlsGroup, message: &RisalaMessage) -> Vec<u8> {
        encrypt(&self.provider, group, self.pseudonym, message).unwrap()
    }

    /// Writes and encrypts a message.
    fn send(&mut self, group: &mut MlsGroup, s: &str) -> (RisalaMessage, Vec<u8>) {
        let message = self.write(s);
        let post = self.encrypt(group, &message);
        (message, post)
    }

    fn receive_at(
        &mut self,
        group: &mut MlsGroup,
        post: &[u8],
        t: Timestamp,
        live: bool,
    ) -> Received {
        receive(
            &self.provider,
            group,
            post,
            PostInfo { t, live },
            &mut self.history,
        )
    }

    fn receive(&mut self, group: &mut MlsGroup, post: &[u8]) -> Received {
        self.receive_at(group, post, t0(), false)
    }
}

/// A direct conversation between Alice, with two devices, and Bob.
struct Direct {
    alice: Device,
    alice2: Device,
    bob: Device,
    a: MlsGroup,
    a2: MlsGroup,
    b: MlsGroup,
    conversation: RisalaConversation,
}

fn direct() -> Direct {
    let alice = Device::new("alice@example.org", 1);
    let alice2 = Device::new("alice@example.org", 11);
    let bob = Device::new("bob@example.org", 2);
    let conversation = RisalaConversation::direct(HOST, BOX, &alice.uid, &bob.uid);
    let mut a = alice.create(&conversation);
    let out = commit(
        &alice.provider,
        &mut a,
        alice.pseudonym,
        &alice.profile(),
        &MlsHistory::default(),
        Changes {
            add: vec![bob.key_package(), alice2.key_package()],
            ..Changes::default()
        },
    )
    .unwrap();
    merge_own_commit(
        &alice.provider,
        &mut a,
        &mut MlsHistory::default(),
        &post(&out),
    )
    .unwrap();
    let welcome = out.welcome.unwrap();
    let b = bob.join(&welcome);
    let a2 = alice2.join(&welcome);
    Direct {
        alice,
        alice2,
        bob,
        a,
        a2,
        b,
        conversation,
    }
}

// ---------------------------------------------------------------------------
// Round trips

#[test]
fn round_trip_between_members() {
    let Direct {
        mut alice,
        mut alice2,
        mut bob,
        mut a,
        mut a2,
        mut b,
        conversation,
    } = direct();

    let (sent, post) = alice.send(&mut a, "hello bob");
    for (device, group) in [(&mut bob, &mut b), (&mut alice2, &mut a2)] {
        let got = device.receive(group, &post).unwrap();
        assert_eq!(got.sender, a.own_leaf_index());
        assert_eq!(got.identity, alice.identity());
        assert_eq!(got.epoch, a.epoch().as_u64());
        assert_eq!(got.message, sent);
        assert_eq!(got.message.content.as_str(), "TEXT hello bob\n");
        assert_eq!(got.message.counter, 1);
        assert_eq!(got.message.previous, None);
        assert_eq!(got.pseudonym, PseudonymCheck::NewlyPinned);
        assert_eq!(got.order, Order::First { earlier: 0 });
        assert_eq!(got.clock, Clock::Agrees);
        // Step 6: confirmation is the caller's (12.10).
        assert_eq!(got.trust(false), Trust::Unverified);
        assert_eq!(got.trust(true), Trust::Verified);
        assert_eq!(got.place(&conversation), Place::new(Conversation::Direct));
    }
    assert_eq!(
        bob.history.sender(a.own_leaf_index()).pseudonym,
        Some(alice.pseudonym)
    );

    let (sent2, post) = alice.send(&mut a, "second");
    assert_eq!(sent2.counter, 2);
    assert_eq!(sent2.previous, Some(sent.message_id));
    let got = bob.receive(&mut b, &post).unwrap();
    assert_eq!(got.pseudonym, PseudonymCheck::Pinned);
    assert_eq!(got.order, Order::Next);
    assert_eq!(alice2.receive(&mut a2, &post).unwrap().order, Order::Next);

    // Bob's own counter starts at 1.
    let (_, reply) = bob.send(&mut b, "hi");
    let got = alice.receive(&mut a, &reply).unwrap();
    assert_eq!(got.order, Order::First { earlier: 0 });
    assert_eq!(got.identity, bob.identity());
    // A device cannot decrypt its own PrivateMessage.
    assert!(matches!(
        bob.receive(&mut b, &reply),
        Err(ReceiveError::Own)
    ));

    // Handshake messages go to group::process_message.
    let commit = bob.commit(&mut b, Changes::default());
    assert!(matches!(
        alice.receive(&mut a, &commit),
        Err(ReceiveError::NotApplication)
    ));
}

#[test]
fn conversation_with_yourself() {
    let alice = Device::new("alice@example.org", 1);
    let conversation = RisalaConversation::direct(HOST, BOX, &alice.uid, &alice.uid);
    assert_eq!(line_conversation(&conversation), Conversation::WithYourself);
    let room = RisalaConversation::private_room(HOST, BOX, "Friends", &alice.uid);
    assert_eq!(
        line_conversation(&room),
        Conversation::PrivateRoom(LineConfirmMode::Pairwise)
    );
}

#[test]
fn padded_to_256_bytes() {
    let Direct {
        mut alice, mut a, ..
    } = direct();
    let lengths: Vec<usize> = (1..=600)
        .step_by(7)
        .map(|n| alice.send(&mut a, &"a".repeat(n)).1.len())
        .collect();
    // Every length differs by a multiple of 256 (12.9, step 5), and short
    // contents of different lengths look the same.
    for len in &lengths {
        assert_eq!((len - lengths[0]) % 256, 0, "{lengths:?}");
    }
    let distinct: BTreeSet<usize> = lengths.iter().copied().collect();
    assert!(distinct.len() <= 4, "{distinct:?}");
    assert!(distinct.len() >= 2, "{distinct:?}");
}

// ---------------------------------------------------------------------------
// Rejections

#[test]
fn bad_frank() {
    let Direct {
        mut alice,
        mut bob,
        mut a,
        mut b,
        ..
    } = direct();
    let message = alice.write("hello");
    let id = message.message_id;

    // A frank that is not of the content.
    let wrong = RisalaAad::application(alice.pseudonym, [0; FRANK_LEN]);
    let post =
        group::encrypt_application(&alice.provider, &mut a, &wrong, &message.encode()).unwrap();
    assert!(matches!(
        bob.receive(&mut b, &post),
        Err(ReceiveError::Frank)
    ));

    // The frank of other content under the same key: a message that
    // would decrypt to one thing and report as another.
    let other = message.frank_key.frank(b"TEXT something else\n");
    let swapped = RisalaAad::application(alice.pseudonym, other);
    let post =
        group::encrypt_application(&alice.provider, &mut a, &swapped, &message.encode()).unwrap();
    assert!(matches!(
        bob.receive(&mut b, &post),
        Err(ReceiveError::Frank)
    ));

    // Nothing was remembered: the message itself, franked right, is new.
    assert!(!bob.history.seen(&id));
    assert_eq!(bob.history.sender(a.own_leaf_index()), SenderLog::default());
    let post = alice.encrypt(&mut a, &message);
    assert_eq!(
        bob.receive(&mut b, &post).unwrap().order,
        Order::First { earlier: 0 }
    );
}

#[test]
fn wrong_pseudonym() {
    let Direct {
        mut alice,
        mut bob,
        mut a,
        mut b,
        ..
    } = direct();
    let (_, post) = alice.send(&mut a, "first");
    bob.receive(&mut b, &post).unwrap();

    // Another pseudonym from the same leaf is ignored (7.3).
    let message = alice.write("dodging a mute");
    let other = encrypt(
        &alice.provider,
        &mut a,
        Pseudonym::generate().unwrap(),
        &message,
    )
    .unwrap();
    assert!(matches!(
        bob.receive(&mut b, &other),
        Err(ReceiveError::Pseudonym)
    ));
    // The same message under the pinned one counts.
    let post = alice.encrypt(&mut a, &message);
    assert_eq!(bob.receive(&mut b, &post).unwrap().order, Order::Next);
}

#[test]
fn replays_and_resends() {
    let Direct {
        mut alice,
        mut bob,
        mut a,
        mut b,
        ..
    } = direct();
    let (message, post) = alice.send(&mut a, "once");
    bob.receive(&mut b, &post).unwrap();

    // The same post again: MLS has deleted its key.
    assert!(matches!(
        bob.receive(&mut b, &post),
        Err(ReceiveError::Process(_))
    ));
    // The same message encrypted again, as a server could not make but a
    // resend does (7.6): shown once.
    let again = alice.encrypt(&mut a, &message);
    assert!(matches!(
        bob.receive(&mut b, &again),
        Err(ReceiveError::Duplicate)
    ));

    // A post that got ERR stale: the commit moved the group on, and the
    // same RisalaMessage goes again in the new epoch (12.9).
    let stale = alice.write("after a commit");
    let _lost = alice.encrypt(&mut a, &stale);
    let commit = bob.commit(&mut b, Changes::default());
    alice.apply(&mut a, &commit, t0());
    let resent = alice.encrypt(&mut a, &stale);
    let got = bob.receive(&mut b, &resent).unwrap();
    assert_eq!(got.order, Order::Next);
    assert_eq!(got.message.counter, 2);
}

#[test]
fn gaps_and_late_messages() {
    let Direct {
        mut alice,
        mut alice2,
        mut bob,
        mut a,
        mut a2,
        mut b,
        ..
    } = direct();
    let (_, p1) = alice.send(&mut a, "one");
    let (_, p2) = alice.send(&mut a, "two");
    let (m3, p3) = alice.send(&mut a, "three");
    let (_, p4) = alice.send(&mut a, "four");
    let leaf = a.own_leaf_index();

    assert_eq!(
        bob.receive(&mut b, &p1).unwrap().order,
        Order::First { earlier: 0 }
    );
    assert_eq!(
        bob.receive(&mut b, &p3).unwrap().order,
        Order::Gap { missing: 1 }
    );
    assert_eq!(bob.history.sender(leaf).gaps, vec![(2, 2)]);
    // The missing one, late, fills the gap.
    assert_eq!(bob.receive(&mut b, &p2).unwrap().order, Order::Late);
    assert!(bob.history.sender(leaf).gaps.is_empty());
    assert_eq!(bob.receive(&mut b, &p4).unwrap().order, Order::Next);

    // Counter 5 whose previous is not message 4.
    let forged = RisalaMessage {
        message_id: MessageId::from_bytes([5; 16]),
        counter: 5,
        previous: Some(m3.message_id),
        ..alice.write("five")
    };
    let post = alice.encrypt(&mut a, &forged);
    assert_eq!(
        bob.receive(&mut b, &post).unwrap().order,
        Order::Inconsistent
    );
    // A counter used before, under a new id.
    let reused = RisalaMessage {
        message_id: MessageId::from_bytes([6; 16]),
        counter: 2,
        ..alice.write("two again")
    };
    let post = alice.encrypt(&mut a, &reused);
    assert_eq!(
        bob.receive(&mut b, &post).unwrap().order,
        Order::Inconsistent
    );
    // A message after a gap of three.
    let mut counter = SendCounter {
        written: 8,
        last: Some(MessageId::from_bytes([8; 16])),
    };
    let post = alice.encrypt(&mut a, &counter.write(text("nine"), t0()).unwrap());
    assert_eq!(
        bob.receive(&mut b, &post).unwrap().order,
        Order::Gap { missing: 3 }
    );
    assert_eq!(bob.history.sender(leaf).gaps, vec![(6, 8)]);

    // The first message seen from a leaf that has written two before it.
    alice2.write("not posted");
    alice2.write("not posted either");
    let (_, post) = alice2.send(&mut a2, "third");
    assert_eq!(
        bob.receive(&mut b, &post).unwrap().order,
        Order::First { earlier: 2 }
    );
    assert_eq!(bob.history.sender(a2.own_leaf_index()).gaps, vec![(1, 2)]);

    // A first message must have no previous, and a later one must.
    let mut log = SenderLog::default();
    let id = |b| MessageId::from_bytes([b; 16]);
    assert_eq!(log.order(1, Some(id(1)), id(2)), Order::Inconsistent);
    assert_eq!(log.order(3, None, id(3)), Order::Inconsistent);
    assert_eq!(log.gaps, vec![(2, 2)]);
}

#[test]
fn live_messages() {
    let Direct {
        mut alice,
        mut bob,
        mut a,
        mut b,
        conversation,
        ..
    } = direct();
    let typing = Content::single(ContentLine::Typing).unwrap();
    let live = RisalaMessage::live(typing.clone(), t0()).unwrap();
    assert!(live.is_live());
    assert_eq!(live.previous, None);

    // Posted live, it does not count.
    let post = alice.encrypt(&mut a, &live);
    let got = bob.receive_at(&mut b, &post, t0(), true).unwrap();
    assert_eq!(got.order, Order::Live);
    let place = got.place(&conversation);
    assert!(place.live);
    assert_eq!(got.message.content.allowed(place).count(), 1);
    // A stored post with counter 0: refused, so a server cannot keep a
    // live message.
    let live = RisalaMessage::live(typing.clone(), t0()).unwrap();
    let post = alice.encrypt(&mut a, &live);
    assert!(matches!(
        bob.receive_at(&mut b, &post, t0(), false),
        Err(ReceiveError::Live)
    ));
    // A live post with a counter.
    let (_, post) = alice.send(&mut a, "stored");
    assert!(matches!(
        bob.receive_at(&mut b, &post, t0(), true),
        Err(ReceiveError::Live)
    ));
    // A counter-0 message with a previous id.
    let odd = RisalaMessage {
        previous: Some(MessageId::from_bytes([1; 16])),
        ..RisalaMessage::live(typing, t0()).unwrap()
    };
    let post = alice.encrypt(&mut a, &odd);
    assert!(matches!(
        bob.receive_at(&mut b, &post, t0(), true),
        Err(ReceiveError::Live)
    ));
    // Live messages did not move the counter: the next stored one is the
    // leaf's second (the first was refused above, so it shows a gap).
    let (_, post) = alice.send(&mut a, "next");
    assert_eq!(
        bob.receive(&mut b, &post).unwrap().order,
        Order::First { earlier: 1 }
    );
    assert_eq!(alice.counter.written, 2);
}

#[test]
fn times() {
    let Direct {
        mut alice,
        mut bob,
        mut a,
        mut b,
        ..
    } = direct();
    for (minutes, clock) in [
        (9, Clock::Agrees),
        (10, Clock::Agrees),
        (11, Clock::Disagrees),
    ] {
        let message = alice.counter.write(text("when"), t0()).unwrap();
        let post = alice.encrypt(&mut a, &message);
        let got = bob.receive_at(&mut b, &post, at(minutes), false).unwrap();
        assert_eq!(got.clock, clock, "{minutes} minutes");
    }
    // Ahead of the server too.
    let message = alice.counter.write(text("early"), at(20)).unwrap();
    let post = alice.encrypt(&mut a, &message);
    assert_eq!(
        bob.receive_at(&mut b, &post, at(5), false).unwrap().clock,
        Clock::Disagrees
    );
    // A time beyond 9999 is not a timestamp at all.
    let message = RisalaMessage {
        time: u64::MAX,
        ..alice.write("never")
    };
    let post = alice.encrypt(&mut a, &message);
    assert_eq!(bob.receive(&mut b, &post).unwrap().clock, Clock::Disagrees);
}

#[test]
fn past_epochs() {
    let Direct {
        mut alice,
        mut bob,
        mut a,
        mut b,
        ..
    } = direct();
    // Three messages of epoch e, then a commit at t0 ends it.
    let e = a.epoch().as_u64();
    let (_, x1) = alice.send(&mut a, "x1");
    let (_, x2) = alice.send(&mut a, "x2");
    let (_, x3) = alice.send(&mut a, "x3");
    let commit = alice.commit(&mut a, Changes::default());
    bob.apply(&mut b, &commit, t0());
    assert_eq!(bob.history.epoch_end(e), Some(t0()));

    // Within an hour of the commit: read.
    let got = bob.receive_at(&mut b, &x1, at(30), false).unwrap();
    assert_eq!(got.epoch, e);
    // More than an hour: unreadable, and the epoch's secrets go.
    assert!(matches!(
        bob.receive_at(&mut b, &x2, at(61), false),
        Err(ReceiveError::TooOld)
    ));
    // So even a post the rule would allow can no longer be decrypted.
    assert!(matches!(
        bob.receive_at(&mut b, &x3, at(30), false),
        Err(ReceiveError::Process(_))
    ));

    // A live post an hour after the commit expires nothing: only stored
    // posts, which every device applies, move the limits.
    let e = a.epoch().as_u64();
    let (_, z1) = alice.send(&mut a, "z1");
    let commit = alice.commit(&mut a, Changes::default());
    bob.apply(&mut b, &commit, at(200));
    let live = RisalaMessage::live(Content::single(ContentLine::Typing).unwrap(), at(300)).unwrap();
    let post = alice.encrypt(&mut a, &live);
    bob.receive_at(&mut b, &post, at(300), true).unwrap();
    let got = bob.receive_at(&mut b, &z1, at(210), false).unwrap();
    assert_eq!(got.epoch, e);

    // At most two epochs behind.
    let e = a.epoch().as_u64();
    let (_, y1) = alice.send(&mut a, "y1");
    let (_, y2) = alice.send(&mut a, "y2");
    for _ in 0..2 {
        let commit = alice.commit(&mut a, Changes::default());
        bob.apply(&mut b, &commit, at(100));
    }
    assert_eq!(b.epoch().as_u64(), e + 2);
    assert!(bob.receive_at(&mut b, &y1, at(100), false).is_ok());
    let commit = alice.commit(&mut a, Changes::default());
    bob.apply(&mut b, &commit, at(100));
    assert!(matches!(
        bob.receive_at(&mut b, &y2, at(100), false),
        Err(ReceiveError::TooOld)
    ));

    // An epoch whose end the device never saw is not read late.
    assert!(!past_epoch_readable(3, 4, t0(), None));
    assert!(past_epoch_readable(4, 4, t0(), None));
    assert!(past_epoch_readable(2, 4, at(60), Some(t0())));
    assert!(!past_epoch_readable(1, 4, at(1), Some(t0())));
}

#[test]
fn removed_leaf() {
    let Direct {
        alice,
        mut alice2,
        mut bob,
        mut a,
        mut a2,
        mut b,
        ..
    } = direct();
    // Alice's second device sends, then a commit removes it before the
    // message's seq.
    let (_, late) = alice2.send(&mut a2, "too late");
    let leaf = a2.own_leaf_index();
    let commit = alice.commit(
        &mut a,
        Changes {
            remove: vec![leaf],
            ..Changes::default()
        },
    );
    bob.apply(&mut b, &commit, t0());
    assert_eq!(bob.history.sender(leaf).removed_in, Some(1));
    assert!(matches!(
        bob.receive(&mut b, &late),
        Err(ReceiveError::Removed)
    ));
}

#[test]
fn self_removed_sender() {
    let Direct {
        mut alice,
        mut alice2,
        mut bob,
        mut a,
        mut a2,
        mut b,
        ..
    } = direct();
    let (_, after) = alice2.send(&mut a2, "after leaving");
    let proposal = self_remove(&alice2.provider, &mut a2, alice2.pseudonym).unwrap();
    for (device, group) in [(&mut bob, &mut b), (&mut alice, &mut a)] {
        let Incoming::Proposal { .. } =
            group::process_message(&device.provider, group, &proposal).unwrap()
        else {
            panic!("not a proposal");
        };
    }
    assert!(matches!(
        bob.receive(&mut b, &after),
        Err(ReceiveError::Left)
    ));
    assert!(bob.history.sender(a2.own_leaf_index()).left);
    note_self_removes(&a, &mut alice.history);
    assert!(alice.history.sender(a2.own_leaf_index()).left);
}

#[test]
fn epochal_pseudonyms() {
    let mut owen = Device::new("owen@example.org", 1);
    let mut mia = Device::new("mia@example.org", 2);
    let mut conversation = RisalaConversation::private_room(HOST, BOX, "Friends", &owen.uid);
    conversation.confirm = ConfirmMode::Epochal;
    let mut o = owen.create(&conversation);
    let out = commit(
        &owen.provider,
        &mut o,
        owen.pseudonym,
        &owen.profile(),
        &MlsHistory::default(),
        Changes {
            add: vec![mia.key_package()],
            ..Changes::default()
        },
    )
    .unwrap();
    merge_own_commit(
        &owen.provider,
        &mut o,
        &mut MlsHistory::default(),
        &post(&out),
    )
    .unwrap();
    let mut m = mia.join(&out.welcome.unwrap());

    // Nothing is pinned until the leaf's ATTEST is checked (7.3, 12.10).
    let (_, post) = mia.send(&mut m, "hello");
    let got = owen.receive(&mut o, &post).unwrap();
    assert_eq!(got.pseudonym, PseudonymCheck::NeedsAttest(mia.pseudonym));
    assert_eq!(got.trust(true), Trust::Withheld);
    assert_eq!(
        got.place(&conversation).conversation,
        Conversation::PrivateRoom(LineConfirmMode::Epochal)
    );
    owen.history.pin(got.sender, mia.pseudonym);
    let (_, post) = mia.send(&mut m, "again");
    let got = owen.receive(&mut o, &post).unwrap();
    assert_eq!(got.pseudonym, PseudonymCheck::Pinned);
    assert_eq!(got.trust(false), Trust::Unverified);
    // A new period's pseudonym waits for that period's ATTEST.
    mia.pseudonym = Pseudonym::generate().unwrap();
    let (_, post) = mia.send(&mut m, "next period");
    assert_eq!(
        owen.receive(&mut o, &post).unwrap().pseudonym,
        PseudonymCheck::NeedsAttest(mia.pseudonym)
    );
}

#[test]
fn skipped_generations() {
    let Direct {
        mut alice,
        mut bob,
        mut a,
        mut b,
        ..
    } = direct();
    apply_limits(&alice.provider, &mut a).unwrap();
    apply_limits(&bob.provider, &mut b).unwrap();
    assert_eq!(
        *b.configuration().sender_ratchet_configuration(),
        sender_ratchet_configuration()
    );
    assert_eq!(b.configuration().padding_size(), group::PADDING_SIZE);

    // Generations 0 to 2001 of Alice's leaf in this epoch; generation g
    // has counter g + 1.
    let posts: Vec<Vec<u8>> = (0..=2001)
        .map(|i| alice.send(&mut a, &i.to_string()).1)
        .collect();
    let mut get = |g: usize| bob.receive(&mut b, &posts[g]);
    assert_eq!(get(1).unwrap().order, Order::First { earlier: 1 });
    assert_eq!(get(1000).unwrap().order, Order::Gap { missing: 998 });
    // 1,000 behind the newest seen: its key was kept.
    assert_eq!(get(0).unwrap().order, Order::Late);
    // 1,001 ahead of the newest seen: rejected; 1,000 ahead: accepted.
    assert!(matches!(get(2001), Err(ReceiveError::Process(_))));
    assert_eq!(get(2000).unwrap().order, Order::Gap { missing: 999 });
    // 1,001 behind: its key is gone; 1,000 and 999 behind: kept.
    assert!(matches!(get(999), Err(ReceiveError::Process(_))));
    assert_eq!(get(1001).unwrap().order, Order::Late);
    assert_eq!(get(1999).unwrap().order, Order::Late);
}

// ---------------------------------------------------------------------------
// Deletes

#[test]
fn deletes() {
    let owen: Uid = "owen@example.org".parse().unwrap();
    let mia: Uid = "mia@example.org".parse().unwrap();
    let pat: Uid = "pat@example.org".parse().unwrap();
    let direct = RisalaConversation::direct(HOST, BOX, &owen, &mia);
    assert!(may_delete(&owen, &owen, &direct, &direct));
    assert!(!may_delete(&owen, &mia, &direct, &direct));

    let room = RisalaConversation::private_room(HOST, BOX, "Friends", &owen);
    let mut with_mod = room.clone();
    with_mod.mods.push(mia.clone());
    // An owner, a moderator in both epochs, the author.
    assert!(may_delete(&owen, &pat, &room, &room));
    assert!(may_delete(&mia, &pat, &with_mod, &with_mod));
    assert!(may_delete(&pat, &pat, &room, &room));
    // A moderator in only one of the two epochs, and a plain member.
    assert!(!may_delete(&mia, &pat, &with_mod, &room));
    assert!(!may_delete(&mia, &pat, &room, &with_mod));
    assert!(!may_delete(&pat, &mia, &with_mod, &with_mod));
}

// ---------------------------------------------------------------------------
// Encodings and vectors

#[test]
fn send_counter() {
    let mut counter = SendCounter::default();
    let first = counter.write(text("a"), t0()).unwrap();
    let second = counter.write(text("b"), t0()).unwrap();
    assert_eq!((first.counter, first.previous), (1, None));
    assert_eq!(
        (second.counter, second.previous),
        (2, Some(first.message_id))
    );
    assert_ne!(first.message_id, second.message_id);
    assert_ne!(first.frank_key, second.frank_key);
    assert_eq!(first.time, t0().unix_millis());
    assert_eq!(counter.written, 2);
    let mut full = SendCounter {
        written: u64::MAX,
        last: None,
    };
    assert_eq!(full.write(text("c"), t0()), Err(WriteError::Counter));
}

/// The frank (12.9): HMAC-SHA-384(frank_key, content), over the content's
/// bytes alone. Vectors for Appendix B, checked against Python's `hmac`.
#[test]
fn frank_vectors() {
    let vectors = [
        (
            (0..32).collect::<Vec<u8>>(),
            "TEXT hello\n",
            "48d7422d3f6b395988131847f92170c6bcc1925eb05495338e4fd9c480c41fa0485cc45e206ed988577a73f3792e8258",
        ),
        (
            vec![0x42; 32],
            "@reply=0Jx1HkY3x9z2b5R0qWm1fA== TEXT see you at 12\n",
            "8622a996f5638802118e2740494e46d0f03d92424f8e566c6aaf253f7496d59149f2c6d9a9629d6d0ac670da68f25f50",
        ),
    ];
    for (key, content, frank) in vectors {
        let key = FrankKey::from_bytes(key.try_into().unwrap());
        assert_eq!(hex(&key.frank(content.as_bytes())), frank);
        let frank: [u8; FRANK_LEN] = unhex(frank).try_into().unwrap();
        assert!(key.matches(content.as_bytes(), &frank));
        // Over the bytes alone: not with a length prefix, not another
        // content, not another key.
        let mut prefixed = vec![content.len() as u8];
        prefixed.extend_from_slice(content.as_bytes());
        assert!(!key.matches(&prefixed, &frank));
        assert!(!key.matches(b"TEXT hello!\n", &frank));
        let mut other = *key.as_bytes();
        other[0] ^= 1;
        assert!(!FrankKey::from_bytes(other).matches(content.as_bytes(), &frank));
        println!(
            "frank_key: {}\ncontent: {content:?}\nfrank: {}\n",
            hex(key.as_bytes()),
            hex(&frank)
        );
    }
}

fn vector_message() -> RisalaMessage {
    RisalaMessage {
        message_id: MessageId::from_bytes([0x01; 16]),
        counter: 2,
        previous: Some(MessageId::from_bytes([0x02; 16])),
        time: 1_800_000_000_000,
        frank_key: FrankKey::from_bytes((0..32).collect::<Vec<u8>>().try_into().unwrap()),
        content: text("hello"),
    }
}

/// A RisalaMessage's bytes (12.9), and its frank.
#[test]
fn message_vector() {
    let message = vector_message();
    let encoded = message.encode();
    let expected = [
        "01",               // version
        &"01".repeat(16),   // message_id
        "0000000000000002", // counter
        "10",               // previous, 16 bytes
        &"02".repeat(16),
        "000001a3185c5000", // time, 1_800_000_000_000 ms
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "0b", // content, 11 bytes: "TEXT hello\n"
        "544558542068656c6c6f0a",
    ]
    .concat();
    assert_eq!(hex(&encoded), expected);
    assert_eq!(
        hex(&message.frank()),
        "48d7422d3f6b395988131847f92170c6bcc1925eb05495338e4fd9c480c41fa0485cc45e206ed988577a73f3792e8258"
    );
    assert_eq!(RisalaMessage::decode(&encoded), Ok(message.clone()));
    println!(
        "RisalaMessage: {}\nfrank: {}",
        hex(&encoded),
        hex(&message.frank())
    );

    // A first message has an empty previous.
    let first = RisalaMessage {
        counter: 1,
        previous: None,
        ..message.clone()
    };
    let encoded_first = first.encode();
    assert_eq!(encoded_first[25], 0);
    assert_eq!(RisalaMessage::decode(&encoded_first), Ok(first));
}

#[test]
fn malformed_messages() {
    let good = vector_message().encode().to_vec();
    let mut version = good.clone();
    version[0] = 2;
    let mut trailing = good.clone();
    trailing.push(0);
    // previous of 5 bytes.
    let mut short_previous = good[..25].to_vec();
    short_previous.push(5);
    short_previous.extend_from_slice(&[2; 5]);
    short_previous.extend_from_slice(&good[42..]);
    for bad in [
        version,
        trailing,
        short_previous,
        good[..good.len() - 1].to_vec(),
        vec![1; 20],
        vec![],
    ] {
        assert!(
            matches!(RisalaMessage::decode(&bad), Err(MessageError::Malformed(_))),
            "{bad:?}"
        );
    }
    // Content that is not lines: no LF at the end, a NUL, not UTF-8.
    for content in [&b"TEXT hello"[..], b"TEXT a\0b\n", b"TEXT \xff\n", b""] {
        let mut bytes = good[..good.len() - 12].to_vec();
        bytes.push(content.len() as u8);
        bytes.extend_from_slice(content);
        assert!(
            matches!(RisalaMessage::decode(&bytes), Err(MessageError::Content(_))),
            "{content:?}"
        );
    }
    // The Debug form shows no frank key.
    assert!(!format!("{:?}", vector_message()).contains("frank_key"));
}

// ---------------------------------------------------------------------------
// Reports (5.8)

#[test]
fn reports() {
    let Direct {
        mut alice,
        mut bob,
        mut a,
        mut b,
        ..
    } = direct();
    // The mailbox keeps posts by seq; the commit is at seq 1.
    let mut posts: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    posts.insert(1, alice.commit(&mut a, Changes::default()));
    bob.apply(&mut b, &posts[&1], t0());
    let mut messages = Vec::new();
    for (seq, s) in [(2, "you there"), (4, "answer me"), (7, "something abusive")] {
        let (_, post) = alice.send(&mut a, s);
        messages.push(bob.receive(&mut b, &post).unwrap().message);
        posts.insert(seq, post);
    }
    let lookup = |seq: u64| posts.get(&seq).cloned();

    let report = RisalaReport {
        target: ReportedPost::of(7, &messages[2]),
        context: vec![
            ReportedPost::of(2, &messages[0]),
            ReportedPost::of(4, &messages[1]),
        ],
        author: alice.uid.clone(),
        reason: "abuse".into(),
    };
    let encoded = report.encode();
    assert_eq!(RisalaReport::decode(&encoded), Ok(report.clone()));
    assert_eq!(verify_report(&report, lookup), Ok(()));
    assert_eq!(report.posts().count(), 3);

    // Another frank key, or other content: the frank does not match.
    let mut wrong_key = report.clone();
    wrong_key.target.frank_key = FrankKey::from_bytes([9; 32]);
    assert_eq!(
        verify_report(&wrong_key, lookup),
        Err(ReportError::Frank(7))
    );
    let mut wrong_content = report.clone();
    wrong_content.context[0].content = b"TEXT something I never said\n".to_vec();
    assert_eq!(
        verify_report(&wrong_content, lookup),
        Err(ReportError::Frank(2))
    );
    // A post the mailbox no longer keeps.
    let mut expired = report.clone();
    expired.context[0].seq = 3;
    assert_eq!(
        verify_report(&expired, lookup),
        Err(ReportError::NotFound(3))
    );
    // A commit is not an application message.
    let mut commit = report.clone();
    commit.context[0].seq = 1;
    assert_eq!(verify_report(&commit, lookup), Err(ReportError::Frank(1)));

    // Context out of order, or not before the target.
    let mut swapped = report.clone();
    swapped.context.reverse();
    let mut after = report.clone();
    after.context[1].seq = 7;
    for bad in [swapped, after] {
        assert!(matches!(bad.check(), Err(ReportError::Invalid(_))));
        assert!(matches!(
            RisalaReport::decode(&bad.encode()),
            Err(ReportError::Invalid(_))
        ));
        assert!(matches!(
            verify_report(&bad, lookup),
            Err(ReportError::Invalid(_))
        ));
    }
    // Ten context posts, and eleven.
    let mut many = report.clone();
    many.target.seq = 100;
    many.context = (1..=10)
        .map(|seq| ReportedPost::of(seq, &messages[0]))
        .collect();
    assert_eq!(many.check(), Ok(()));
    assert_eq!(RisalaReport::decode(&many.encode()), Ok(many.clone()));
    many.context.push(ReportedPost::of(11, &messages[0]));
    assert!(matches!(
        RisalaReport::decode(&many.encode()),
        Err(ReportError::Invalid(_))
    ));
    // A reason of 512 bytes, and of 513.
    let mut reason = report.clone();
    reason.reason = "r".repeat(512);
    assert_eq!(RisalaReport::decode(&reason.encode()), Ok(reason.clone()));
    reason.reason.push('r');
    assert!(matches!(
        RisalaReport::decode(&reason.encode()),
        Err(ReportError::Invalid(_))
    ));
    // An author that is not a uid, a reason that is not UTF-8, another
    // version, trailing bytes.
    let tail = 1 + alice.uid.as_str().len() + 1 + report.reason.len();
    let mut not_uid = encoded[..encoded.len() - tail].to_vec();
    not_uid.extend_from_slice(&[6]);
    not_uid.extend_from_slice(b"no uid");
    not_uid.extend_from_slice(&[0]);
    assert!(matches!(
        RisalaReport::decode(&not_uid),
        Err(ReportError::Invalid(_))
    ));
    let mut not_utf8 = encoded[..encoded.len() - report.reason.len() - 1].to_vec();
    not_utf8.extend_from_slice(&[1, 0xff]);
    assert!(matches!(
        RisalaReport::decode(&not_utf8),
        Err(ReportError::Invalid(_))
    ));
    let mut version = encoded.clone();
    version[0] = 2;
    assert!(matches!(
        RisalaReport::decode(&version),
        Err(ReportError::Malformed(_))
    ));
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(matches!(
        RisalaReport::decode(&trailing),
        Err(ReportError::Malformed(_))
    ));
}

/// A RisalaReport's bytes (5.8), for Appendix B.
#[test]
fn report_vector() {
    let key: [u8; 32] = (0..32).collect::<Vec<u8>>().try_into().unwrap();
    let report = RisalaReport {
        target: ReportedPost {
            seq: 7,
            frank_key: FrankKey::from_bytes(key),
            content: b"TEXT hello\n".to_vec(),
        },
        context: vec![ReportedPost {
            seq: 5,
            frank_key: FrankKey::from_bytes([0x42; 32]),
            content: b"@reply=0Jx1HkY3x9z2b5R0qWm1fA== TEXT see you at 12\n".to_vec(),
        }],
        author: "alice@example.org".parse().unwrap(),
        reason: "spam".into(),
    };
    let post = |seq: u64, key: &[u8], content: &[u8]| {
        let mut out = seq.to_be_bytes().to_vec();
        out.extend_from_slice(key);
        out.push(content.len() as u8);
        out.extend_from_slice(content);
        out
    };
    let context = post(5, &[0x42; 32], &report.context[0].content);
    let mut expected = vec![1];
    expected.extend(post(7, &key, b"TEXT hello\n"));
    // The context is 92 bytes: a two-byte length [RFC9420, 2.1.2].
    assert_eq!(context.len(), 92);
    expected.extend_from_slice(&[0x40, 92]);
    expected.extend(context);
    expected.push(17);
    expected.extend_from_slice(b"alice@example.org");
    expected.push(4);
    expected.extend_from_slice(b"spam");
    let encoded = report.encode();
    assert_eq!(hex(&encoded), hex(&expected));
    assert_eq!(RisalaReport::decode(&encoded), Ok(report.clone()));
    // Its franks are the vectors of frank_vectors.
    let franks = [
        "48d7422d3f6b395988131847f92170c6bcc1925eb05495338e4fd9c480c41fa0485cc45e206ed988577a73f3792e8258",
        "8622a996f5638802118e2740494e46d0f03d92424f8e566c6aaf253f7496d59149f2c6d9a9629d6d0ac670da68f25f50",
    ];
    for (reported, frank) in report.posts().zip(franks) {
        assert!(reported.matches(&unhex(frank).try_into().unwrap()));
    }
    println!("RisalaReport: {}", hex(&encoded));
}
