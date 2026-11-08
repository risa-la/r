//! Groups made with this crate, end to end, with in-memory storage:
//! KeyPackages and KEYPKG ADD's checks, direct conversations, private
//! rooms with roles, SelfRemove, competing commits, `next`, streaks,
//! stale leaves, RESYNC repairs, impostor removals, mailbox moves, derived
//! pseudonyms, Update proposals, public rooms joined by proposal, copies,
//! resync commits and rejoins, last-resort KeyPackages, sealed Welcomes,
//! past epochs, and the framing the server reads of each message.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, SystemTime};

use openmls::group::MlsGroup;
use openmls::prelude::{KeyPackage, LeafNodeIndex, Lifetime, PublicGroup};
use openmls_memory_storage::MemoryStorage;
use openmls_traits::OpenMlsProvider as _;
use risala_proto::names::{Room, Uid};

use crate::aad::{Pseudonym, RisalaAad};
use crate::checks::{
    CommitError, CommitPost, EpochState, External, Fact, GroupView, JoinExpectation, KeyFacts,
    KeyReport, PERIOD_MS, Seen, UPDATED_SKEW_MS, Verdict, needs_refresh,
};
use crate::conversation::{ConfirmMode, ConversationKind, GuestMode, RisalaConversation};
use crate::framing::{ContentType, MlsMessage, Sender, read_message, read_post};
use crate::group::*;
use crate::identity::{DeviceId, RisalaIdentity};
use crate::keypackage::{
    KEY_PACKAGE_LIFETIME, KeyPackageError, check_key_package, has_no_binding, is_last_resort,
    last_resort_updated, leaf_binding, make_join_key_package_with, make_key_package,
    make_key_package_with,
};
use crate::mldsa::{LeafKey, SigningKey};
use crate::profile::RisalaProfile;
use crate::token::SendToken;
use crate::wire::{to_bytes, tree_to_bytes};
use crate::{Provider, RisalaCrypto};

const HOST: &str = "chat.example.org";
const BOX: [u8; 16] = [0x42; 16];
const HOUR: u64 = 60 * 60 * 1000;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn uid(s: &str) -> Uid {
    s.parse().unwrap()
}

/// One device, with its own storage, the state of each of its groups' epoch
/// by group id, and its pseudonym for public rooms.
struct Device {
    uid: Uid,
    device_key: Option<SigningKey>,
    provider: Provider<MemoryStorage>,
    period_pseudonym: Pseudonym,
    states: RefCell<BTreeMap<Vec<u8>, EpochState>>,
}

impl Device {
    fn new(uid_text: &str, seed: u8) -> Device {
        let uid = uid(uid_text);
        let device_key = (!uid.is_guest()).then(|| SigningKey::from_seed([seed; 32]));
        Device {
            uid,
            device_key,
            provider: Provider::new(MemoryStorage::default()).unwrap(),
            period_pseudonym: Pseudonym::generate().unwrap(),
            states: RefCell::default(),
        }
    }

    /// Another device of the same identity, with the same device key: a
    /// device that joins again.
    fn again(&self) -> Device {
        Device {
            uid: self.uid.clone(),
            device_key: self.device_key.clone(),
            provider: Provider::new(MemoryStorage::default()).unwrap(),
            period_pseudonym: Pseudonym::generate().unwrap(),
            states: RefCell::default(),
        }
    }

    fn device_id(&self) -> DeviceId {
        DeviceId::of_device_key(self.device_key.as_ref().unwrap().public_key())
    }

    fn identity(&self) -> RisalaIdentity {
        match &self.device_key {
            Some(_) => RisalaIdentity::device(self.uid.clone(), self.device_id()),
            None => RisalaIdentity::guest(self.uid.clone()),
        }
    }

    fn profile(&self) -> RisalaProfile {
        self.profile_at(now_ms())
    }

    fn profile_at(&self, t: u64) -> RisalaProfile {
        RisalaProfile::new(self.uid.name(), t).unwrap()
    }

    fn key_package(&self, last_resort: bool) -> KeyPackage {
        let profile = RisalaProfile::new("", now_ms()).unwrap();
        make_key_package(
            &self.provider,
            self.device_key.as_ref().unwrap(),
            &self.uid,
            &profile,
            last_resort,
        )
        .unwrap()
        .key_package
    }

    /// A KeyPackage made at `t`, in ms.
    fn key_package_at(&self, t: u64) -> KeyPackage {
        let s = t / 1000;
        make_key_package_with(
            &self.provider,
            self.device_key.as_ref().unwrap(),
            &self.uid,
            &RisalaProfile::new("", t).unwrap(),
            false,
            Lifetime::init(s - 3600, s + KEY_PACKAGE_LIFETIME),
        )
        .unwrap()
        .key_package
    }

    fn expect(&self) -> JoinExpectation {
        JoinExpectation {
            host: HOST.into(),
            own_uid: self.uid.clone(),
            public_room: None,
        }
    }

    fn state(&self, group: &MlsGroup) -> EpochState {
        self.states
            .borrow()
            .get(group.group_id().as_slice())
            .cloned()
            .unwrap_or_default()
    }

    fn set_state(&self, group: &MlsGroup, state: EpochState) {
        self.states
            .borrow_mut()
            .insert(group.group_id().as_slice().to_vec(), state);
    }

    /// What this device saw itself, for the key checks: nothing.
    fn seen(&self) -> Seen<'_> {
        Seen {
            own_uid: &self.uid,
            resyncs: &[],
            impostors: &[],
        }
    }

    /// The device's pseudonym in `group` now (7.3).
    fn pseudonym(&self, group: &MlsGroup) -> Pseudonym {
        let period = (conversation(group).unwrap().kind == ConversationKind::PublicRoom)
            .then_some(self.period_pseudonym);
        sending_pseudonym::<()>(group, self.provider.crypto(), period).unwrap()
    }

    fn create(&self, conversation: &RisalaConversation) -> MlsGroup {
        self.create_at(conversation, now_ms())
    }

    fn create_at(&self, conversation: &RisalaConversation, t: u64) -> MlsGroup {
        let (group, _, state) = create_group(
            &self.provider,
            &self.identity(),
            &self.profile_at(t),
            conversation,
        )
        .unwrap();
        self.set_state(&group, state);
        group
    }

    fn commit(&self, group: &mut MlsGroup, changes: Changes) -> CommitOutput {
        self.commit_at(group, changes, now_ms())
    }

    fn commit_at(&self, group: &mut MlsGroup, changes: Changes, updated: u64) -> CommitOutput {
        commit(
            &self.provider,
            group,
            &self.profile_at(updated),
            &self.state(group),
            changes,
        )
        .unwrap()
    }

    fn merge(&self, group: &mut MlsGroup, _out: &CommitOutput) {
        let mut state = self.state(group);
        let applied = merge_own_commit(&self.provider, group, &mut state).unwrap();
        assert!(applied.active);
        self.set_state(group, state);
    }

    fn merge_at(&self, group: &mut MlsGroup, out: &CommitOutput, _t: u64) {
        self.merge(group, out);
    }

    fn join(&self, welcome: &[u8]) -> MlsGroup {
        self.join_with_tree(welcome, None)
    }

    fn join_with_tree(&self, welcome: &[u8], tree: Option<&[u8]>) -> MlsGroup {
        let expect = match tree {
            Some(_) => public_expect(self),
            None => self.expect(),
        };
        let joined = join_by_welcome(&self.provider, welcome, tree, &expect).unwrap();
        self.set_state(&joined.group, joined.state);
        joined.group
    }

    /// Processes a commit and makes the group checks, without applying it,
    /// with the times of the epoch's proposals that this device noted.
    fn receive_post(
        &self,
        group: &mut MlsGroup,
        message: &[u8],
        post: &CommitPost,
    ) -> (Box<ReceivedCommit>, Result<Verdict, CommitError>) {
        let Incoming::Commit(received) = process_message(&self.provider, group, message).unwrap()
        else {
            panic!("not a commit");
        };
        let state = self.state(group);
        let verdict = check_received_commit(
            group,
            &received,
            &state,
            &state.post(post.t, post.next),
            self.provider.crypto(),
        );
        (received, verdict)
    }

    fn receive(
        &self,
        group: &mut MlsGroup,
        out: &CommitOutput,
    ) -> (Box<ReceivedCommit>, Result<Verdict, CommitError>) {
        self.receive_post(group, &out.message, &post(out, now_ms()))
    }

    fn apply_received(&self, group: &mut MlsGroup, received: ReceivedCommit) -> bool {
        let mut state = self.state(group);
        let applied = apply_commit(&self.provider, group, received, &mut state).unwrap();
        self.set_state(group, state);
        applied.active
    }

    /// The key checks of a received commit, with what this device saw.
    fn keys(
        &self,
        group: &MlsGroup,
        received: &ReceivedCommit,
        verdict: &Verdict,
        facts: &dyn KeyFacts,
        seen: &Seen<'_>,
    ) -> KeyReport {
        check_received_keys(group, received, &self.state(group), verdict, facts, seen)
    }

    /// Processes, checks and applies a commit that must be valid, at `t`.
    fn apply_at(
        &self,
        group: &mut MlsGroup,
        out: &CommitOutput,
        facts: &dyn KeyFacts,
        t: u64,
    ) -> (Verdict, KeyReport) {
        let post = post(out, t);
        let (received, verdict) = self.receive_post(group, &out.message, &post);
        let verdict = verdict.unwrap();
        let report = self.keys(group, &received, &verdict, facts, &self.seen());
        self.apply_received(group, *received);
        (verdict, report)
    }

    fn apply(&self, group: &mut MlsGroup, out: &CommitOutput, facts: &dyn KeyFacts) -> Verdict {
        self.apply_at(group, out, facts, now_ms()).0
    }

    fn send(&self, group: &mut MlsGroup, text: &[u8]) -> Vec<u8> {
        let aad = RisalaAad::application(self.pseudonym(group), [7; 48]);
        encrypt_application(&self.provider, group, &aad, text).unwrap()
    }

    fn read(&self, group: &mut MlsGroup, message: &[u8]) -> (LeafNodeIndex, Vec<u8>) {
        match process_message(&self.provider, group, message).unwrap() {
            Incoming::Application {
                sender, content, ..
            } => (sender, content),
            other => panic!("not an application message: {other:?}"),
        }
    }

    /// Processes a proposal post, noting its time.
    fn propose_in(&self, group: &mut MlsGroup, message: &[u8], t: u64) -> ProposalKind {
        let Incoming::Proposal {
            kind, reference, ..
        } = process_message(&self.provider, group, message).unwrap()
        else {
            panic!("not a proposal");
        };
        let mut state = self.state(group);
        state.note_proposal(&reference, t);
        self.set_state(group, state);
        kind
    }
}

fn post(out: &CommitOutput, t: u64) -> CommitPost {
    CommitPost::at(t, Some(out.next_token_hash))
}

/// Key files and the key log, as the tests set them up.
#[derive(Default)]
struct Facts {
    devices: BTreeMap<(Uid, DeviceId), Vec<u8>>,
    removed: BTreeSet<(Uid, DeviceId)>,
    unknown: bool,
}

impl Facts {
    fn with(devices: &[&Device]) -> Facts {
        let mut facts = Facts::default();
        for device in devices {
            facts.add(device);
        }
        facts
    }

    fn add(&mut self, device: &Device) {
        if let Some(key) = &device.device_key {
            self.devices.insert(
                (device.uid.clone(), device.device_id()),
                key.public_key().to_vec(),
            );
        }
    }
}

impl KeyFacts for Facts {
    fn current_device_key(&self, uid: &Uid, device_id: &DeviceId) -> Fact<Option<Vec<u8>>> {
        if self.unknown {
            return Fact::Unknown;
        }
        let key = (uid.clone(), *device_id);
        if self.removed.contains(&key) {
            return Fact::Known(None);
        }
        Fact::Known(self.devices.get(&key).cloned())
    }

    fn device_removed(&self, uid: &Uid, device_id: &DeviceId) -> Fact<bool> {
        if self.unknown {
            return Fact::Unknown;
        }
        Fact::Known(self.removed.contains(&(uid.clone(), *device_id)))
    }

    fn identity_retired(&self, _: &Uid) -> Fact<bool> {
        if self.unknown {
            return Fact::Unknown;
        }
        Fact::Known(false)
    }

    fn forked_or_missing(&self, _: &Uid) -> Fact<bool> {
        if self.unknown {
            return Fact::Unknown;
        }
        Fact::Known(false)
    }
}

fn add(key_packages: Vec<KeyPackage>) -> Changes {
    Changes {
        add: key_packages,
        ..Changes::default()
    }
}

fn remove(leaves: Vec<LeafNodeIndex>) -> Changes {
    Changes {
        remove: leaves,
        ..Changes::default()
    }
}

fn private_framing(message: &[u8], content_type: ContentType) {
    let (framing, _aad) = read_post(message).unwrap();
    assert!(framing.private);
    assert_eq!(framing.content_type, content_type);
    assert_eq!(framing.sender, None);
}

#[test]
fn key_packages_and_keypkg_add() {
    let alice = Device::new("alice@example.org", 1);
    let crypto = RisalaCrypto::new().unwrap();
    let key = alice.device_key.as_ref().unwrap().public_key().to_vec();
    let kp = alice.key_package(false);
    let bytes = to_bytes(&kp.clone().into());
    assert_eq!(read_message(&bytes), Ok(MlsMessage::KeyPackage));
    let now = SystemTime::now();

    let checked = check_key_package(&crypto, &bytes, &alice.uid, &key, now).unwrap();
    assert!(!checked.last_resort);
    assert_eq!(is_last_resort(&kp), Ok(false));
    // The binding is in the leaf node, not among the KeyPackage's own
    // extensions (12.3), and covers the KeyPackage's init key.
    let binding = leaf_binding(&kp).unwrap().unwrap();
    assert_eq!(binding.device_id, alice.device_id());
    assert!(crate::binding::DeviceBinding::from_extensions(kp.extensions()).is_none());
    assert!(binding.verify(
        &key,
        &alice.uid,
        kp.hpke_init_key().as_slice(),
        &crate::keypackage::encryption_key_bytes(kp.leaf_node().encryption_key()),
    ));
    // The leaf key is the KeyPackage's own, never the device key (12.3),
    // and it is in storage.
    let leaf_key = kp.leaf_node().signature_key().as_slice().to_vec();
    assert_ne!(leaf_key, key);
    assert!(
        LeafKey::load(
            alice.provider.storage(),
            crate::mldsa::KEY_PACKAGE_SCOPE,
            &leaf_key
        )
        .unwrap()
        .is_some()
    );
    // Each KeyPackage has a leaf key of its own, and a profile with
    // streak 0.
    let other = alice.key_package(false);
    assert_ne!(
        other.leaf_node().signature_key(),
        kp.leaf_node().signature_key()
    );
    assert_eq!(RisalaProfile::of_leaf(kp.leaf_node()).unwrap().streak, 0);

    let last = to_bytes(&alice.key_package(true).into());
    assert!(
        check_key_package(&crypto, &last, &alice.uid, &key, now)
            .unwrap()
            .last_resort
    );

    // Another uid, another device's key, an expired lifetime.
    let bob = Device::new("bob@example.org", 2);
    let bob_key = bob.device_key.as_ref().unwrap().public_key().to_vec();
    assert_eq!(
        check_key_package(&crypto, &bytes, &bob.uid, &key, now).err(),
        Some(KeyPackageError::Credential)
    );
    assert_eq!(
        check_key_package(&crypto, &bytes, &alice.uid, &bob_key, now).err(),
        Some(KeyPackageError::Credential)
    );
    let later = now + Duration::from_secs(13 * 7 * 24 * 3600);
    assert_eq!(
        check_key_package(&crypto, &bytes, &alice.uid, &key, later).err(),
        Some(KeyPackageError::Lifetime)
    );
    // A KeyPackage made to join a public room has no binding, so KEYPKG
    // ADD refuses it (12.3, 12.5).
    let join = make_join_key_package_with(
        &alice.provider,
        &alice.identity(),
        Some(&alice.profile()),
        Lifetime::new(KEY_PACKAGE_LIFETIME),
    )
    .unwrap()
    .key_package;
    assert!(has_no_binding(&join));
    assert_eq!(
        check_key_package(&crypto, &to_bytes(&join.into()), &alice.uid, &key, now).err(),
        Some(KeyPackageError::Binding)
    );
    // A flipped byte anywhere fails, one way or another.
    for at in [10, bytes.len() / 2, bytes.len() - 10] {
        let mut bad = bytes.clone();
        bad[at] ^= 1;
        assert!(check_key_package(&crypto, &bad, &alice.uid, &key, now).is_err());
    }
    assert!(check_key_package(&crypto, b"junk", &alice.uid, &key, now).is_err());
    assert_eq!(
        check_key_package(&crypto, &bytes[..bytes.len() - 1], &alice.uid, &key, now).err(),
        Some(KeyPackageError::Malformed)
    );
}

#[test]
fn direct_conversation() {
    let alice = Device::new("alice@example.org", 1);
    let alice2 = Device::new("alice@example.org", 11);
    let bob = Device::new("bob@example.org", 2);
    let mallory = Device::new("mallory@example.org", 3);
    let facts = Facts::with(&[&alice, &alice2, &bob, &mallory]);
    let conv = RisalaConversation::direct(HOST, BOX, &alice.uid, &bob.uid);
    let mut a = alice.create(&conv);
    assert_eq!(a.group_id().as_slice().len(), 32);
    assert_eq!(conversation(&a), Some(conv.clone()));

    // Alice adds Bob's device and her own other device.
    let out = alice.commit(
        &mut a,
        add(vec![bob.key_package(false), alice2.key_package(false)]),
    );
    private_framing(&out.message, ContentType::Commit);
    let (framing, aad) = read_post(&out.message).unwrap();
    assert_eq!(framing.epoch, 0);
    assert_eq!(framing.group_id, a.group_id().as_slice());
    // The RisalaAAD has no next token hash (12.9); it travels as `next=`.
    // Its pseudonym is Alice's leaf's, derived from the epoch (7.3).
    assert_eq!(aad, RisalaAad::handshake(alice.pseudonym(&a)));
    assert!(out.group_info.is_none());
    assert_eq!(out.added.len(), 2);
    let welcome = out.welcome.clone().unwrap();
    assert_eq!(read_message(&welcome), Ok(MlsMessage::Welcome));
    alice.merge(&mut a, &out);
    // The next token hash is the new epoch's (7.2).
    let token = SendToken::of_group(&a, alice.provider.crypto()).unwrap();
    assert_eq!(out.next_token_hash, token.hash());
    assert!(next_token_hash_matches(
        &a,
        alice.provider.crypto(),
        &out.next_token_hash
    ));

    // The Welcome carries the tree (12.8).
    let mut b = bob.join(&welcome);
    let mut a2 = alice2.join(&welcome);
    assert_eq!(
        SendToken::of_group(&b, bob.provider.crypto()).unwrap(),
        token
    );
    assert_eq!(b.members().count(), 3);

    // Messages both ways, as PrivateMessages with the RisalaAAD.
    let message = alice.send(&mut a, b"hello bob");
    private_framing(&message, ContentType::Application);
    assert_eq!(
        bob.read(&mut b, &message),
        (a.own_leaf_index(), b"hello bob".to_vec())
    );
    assert_eq!(alice2.read(&mut a2, &message).1, b"hello bob");
    let reply = bob.send(&mut b, b"hi");
    assert_eq!(alice.read(&mut a, &reply).1, b"hi");

    // A fresh-leaf commit by Bob (12.7) is valid for the others.
    let out = bob.commit(&mut b, Changes::default());
    bob.merge(&mut b, &out);
    assert_eq!(alice.apply(&mut a, &out, &facts), Verdict::default());
    alice2.apply(&mut a2, &out, &facts);
    assert_eq!(
        SendToken::of_group(&a, alice.provider.crypto())
            .unwrap()
            .hash(),
        out.next_token_hash
    );

    // Nobody else may be added to a direct conversation.
    let out = alice.commit(&mut a, add(vec![mallory.key_package(false)]));
    let (_, verdict) = bob.receive(&mut b, &out);
    assert_eq!(verdict, Err(CommitError::Add));
    discard_own_commit(&alice.provider, &mut a).unwrap();

    // Alice may remove Bob's leaf "for a check" (12.7): the group checks
    // pass, it is an authority commit, and each device's key check looks
    // for a reason it can see.
    let bob_leaf = b.own_leaf_index();
    let out = alice.commit(&mut a, remove(vec![bob_leaf]));
    let post = post(&out, now_ms());
    let (received, verdict) = alice2.receive_post(&mut a2, &out.message, &post);
    let verdict = verdict.unwrap();
    assert_eq!(verdict.check_removals, vec![bob_leaf]);
    assert!(verdict.authority);
    // Alice's other device sees no reason: the removal stands, as one it
    // could not check, with a warning naming Alice.
    let report = alice2.keys(&a2, &received, &verdict, &facts, &alice2.seen());
    assert_eq!(report.unexplained_removals, vec![bob_leaf]);
    assert!(report.failed_removals.is_empty());
    // Bob's own device knows its device is current: the removal failed,
    // and Bob's identity adds it back.
    let (bob_received, bob_verdict) = bob.receive_post(&mut b, &out.message, &post);
    let report = bob.keys(
        &b,
        &bob_received,
        &bob_verdict.unwrap(),
        &facts,
        &bob.seen(),
    );
    assert_eq!(report.failed_removals, vec![bob.identity()]);
    // Unknown: still nothing Bob's device can conclude.
    let unknown = Facts {
        unknown: true,
        ..Facts::default()
    };
    let report = alice2.keys(&a2, &received, &verdict, &unknown, &alice2.seen());
    assert_eq!(report.unexplained_removals, vec![bob_leaf]);
    assert!(report.committer_unchecked);
    // Known removed by record: a reason, nothing to report.
    let mut removed = Facts::with(&[&alice, &alice2, &bob]);
    removed.removed.insert((bob.uid.clone(), bob.device_id()));
    assert_eq!(
        alice2.keys(&a2, &received, &verdict, &removed, &alice2.seen()),
        KeyReport::default()
    );
    alice2.apply_received(&mut a2, *received);
    alice.merge(&mut a, &out);
    assert_eq!(a.members().count(), 2);

    // Bob's device back, from a new KeyPackage: any member may add back a
    // device of a participant. Adding the same device twice is not
    // allowed (12.7).
    let kp = bob.key_package(false);
    let out = alice.commit(&mut a, add(vec![kp.clone(), bob.key_package(false)]));
    let (_, verdict) = alice2.receive(&mut a2, &out);
    assert_eq!(verdict, Err(CommitError::SameDevice));
    discard_own_commit(&alice.provider, &mut a).unwrap();
    let out = alice.commit(&mut a, add(vec![kp]));
    alice.merge(&mut a, &out);
    alice2.apply(&mut a2, &out, &facts);
    assert_eq!(a2.members().count(), 3);
}

#[test]
fn next_token_and_updated() {
    let alice = Device::new("alice@example.org", 1);
    let bob = Device::new("bob@example.org", 2);
    let facts = Facts::with(&[&alice, &bob]);
    let mut a = alice.create(&RisalaConversation::direct(HOST, BOX, &alice.uid, &bob.uid));
    let out = alice.commit(&mut a, add(vec![bob.key_package(false)]));
    alice.merge(&mut a, &out);
    let mut b = bob.join(out.welcome.as_ref().unwrap());

    let out = alice.commit(&mut a, Changes::default());
    let t = now_ms();
    let (received, verdict) = bob.receive(&mut b, &out);
    verdict.unwrap();
    // A wrong `next`, or none, makes the commit invalid (12.6, 12.7).
    let wrong = CommitPost::at(t, Some([9; 48]));
    let none = CommitPost::at(t, None);
    for post in [wrong, none] {
        assert_eq!(
            check_received_commit(&b, &received, &bob.state(&b), &post, bob.provider.crypto()),
            Err(CommitError::NextToken)
        );
    }
    // `updated` more than 10 minutes from the post's `t` (12.3).
    let far = CommitPost::at(t + UPDATED_SKEW_MS + 60_000, Some(out.next_token_hash));
    assert_eq!(
        check_received_commit(&b, &received, &bob.state(&b), &far, bob.provider.crypto()),
        Err(CommitError::Updated)
    );
    bob.apply_received(&mut b, *received);
    alice.merge(&mut a, &out);
    // `updated` below the leaf's previous one.
    let out = alice.commit(&mut a, Changes::default());
    discard_own_commit(&alice.provider, &mut a).unwrap();
    let state = alice.state(&a);
    let back = commit(
        &alice.provider,
        &mut a,
        &alice.profile_at(t - 60_000),
        &state,
        Changes::default(),
    )
    .unwrap();
    // commit() raises it to the previous one, so it is valid.
    let (_, verdict) = bob.receive_post(&mut b, &back.message, &post(&back, t));
    verdict.unwrap();
    let _ = (out, facts);
}

/// Commit streaks (12.3, 12.7): a leaf may start 3 epochs in a row, then
/// only 10 minutes after its previous `updated`.
#[test]
fn streaks() {
    let alice = Device::new("alice@example.org", 1);
    let bob = Device::new("bob@example.org", 2);
    let facts = Facts::with(&[&alice, &bob]);
    let mut a = alice.create(&RisalaConversation::direct(HOST, BOX, &alice.uid, &bob.uid));
    let t0 = now_ms();
    let out = alice.commit_at(&mut a, add(vec![bob.key_package(false)]), t0);
    alice.merge_at(&mut a, &out, t0);
    let streak = |g: &MlsGroup| {
        RisalaProfile::of_leaf(g.own_leaf_node().unwrap())
            .unwrap()
            .streak
    };
    assert_eq!(streak(&a), 1);
    let mut b = bob.join(out.welcome.as_ref().unwrap());
    // Bob joined with the GroupInfo Alice signed: he knows she started the
    // epoch.
    assert_eq!(bob.state(&b).started_by, Some(a.own_leaf_index().u32()));
    for expected in [2, 3] {
        let out = alice.commit_at(&mut a, Changes::default(), t0);
        bob.apply_at(&mut b, &out, &facts, t0);
        alice.merge_at(&mut a, &out, t0);
        assert_eq!(streak(&a), expected);
    }
    // A fourth in a row, at the same time: invalid.
    let out = alice.commit_at(&mut a, Changes::default(), t0);
    let (_, verdict) = bob.receive_post(&mut b, &out.message, &post(&out, t0));
    assert_eq!(verdict, Err(CommitError::Streak));
    discard_own_commit(&alice.provider, &mut a).unwrap();
    // Ten minutes later, valid.
    let t1 = t0 + UPDATED_SKEW_MS;
    let out = alice.commit_at(&mut a, Changes::default(), t1);
    bob.apply_at(&mut b, &out, &facts, t1);
    alice.merge_at(&mut a, &out, t1);
    assert_eq!(streak(&a), 4);
    // Bob's commit starts his own count at 1, and Alice's at 1 after it.
    let out = bob.commit_at(&mut b, Changes::default(), t1);
    alice.apply_at(&mut a, &out, &facts, t1);
    bob.merge_at(&mut b, &out, t1);
    assert_eq!(streak(&b), 1);
    let out = alice.commit_at(&mut a, Changes::default(), t1);
    bob.apply_at(&mut b, &out, &facts, t1);
    alice.merge_at(&mut a, &out, t1);
    assert_eq!(streak(&a), 1);
}

#[test]
fn welcome_checks() {
    let alice = Device::new("alice@example.org", 1);
    let bob = Device::new("bob@example.org", 2);
    let carol = Device::new("carol@example.org", 3);
    let conv = RisalaConversation::direct(HOST, BOX, &alice.uid, &carol.uid);
    let mut a = alice.create(&conv);
    // Alice (wrongly) adds Bob to her conversation with Carol: Bob refuses
    // to join, since it is not his conversation (12.7).
    let out = alice.commit(&mut a, add(vec![bob.key_package(false)]));
    let err = join_by_welcome(&bob.provider, &out.welcome.unwrap(), None, &bob.expect());
    assert!(matches!(
        err,
        Err(GroupError::Join(crate::checks::JoinError::NotAParticipant))
    ));

    // A Welcome for a group on another server is refused too.
    let conv = RisalaConversation::direct("other.example", BOX, &alice.uid, &bob.uid);
    let mut a = alice.create(&conv);
    let out = alice.commit(&mut a, add(vec![bob.key_package(false)]));
    let err = join_by_welcome(&bob.provider, &out.welcome.unwrap(), None, &bob.expect());
    assert!(matches!(
        err,
        Err(GroupError::Join(
            crate::checks::JoinError::WrongConversation
        ))
    ));
}

/// One Welcome per device, sealed to its KeyPackage (12.8).
#[test]
fn sealed_welcomes() {
    use crate::welcome::{open_sealed_welcome, seal_welcomes};
    let alice = Device::new("alice@example.org", 1);
    let bob = Device::new("bob@example.org", 2);
    let bob2 = Device::new("bob@example.org", 12);
    let conv = RisalaConversation::direct(HOST, BOX, &alice.uid, &bob.uid);
    let mut a = alice.create(&conv);
    let out = alice.commit(
        &mut a,
        add(vec![bob.key_package(false), bob2.key_package(false)]),
    );
    alice.merge(&mut a, &out);
    let sealed = seal_welcomes(
        alice.provider.crypto(),
        out.welcome.as_ref().unwrap(),
        &out.added,
    )
    .unwrap();
    assert_eq!(sealed.len(), 2);
    // No two copies share any bytes of note.
    assert_ne!(sealed[0].sealed[..64], sealed[1].sealed[..64]);
    let refs: Vec<Vec<u8>> = sealed.iter().map(|s| s.key_package_ref.clone()).collect();
    for (device, sealed) in [(&bob, &sealed[0]), (&bob2, &sealed[1])] {
        let (reference, welcome) =
            open_sealed_welcome(&device.provider, &sealed.sealed, &refs).unwrap();
        assert_eq!(reference, sealed.key_package_ref);
        // Only this device's entry.
        let opened = crate::wire::read_welcome(&welcome).unwrap();
        assert_eq!(opened.secrets().len(), 1);
        let g = device.join(&welcome);
        assert_eq!(g.members().count(), 3);
    }
    // Another device cannot open it.
    assert!(open_sealed_welcome(&bob2.provider, &sealed[0].sealed, &refs).is_err());
}

/// A private room of Owen (owner), Mia (moderator) and Pat (member).
struct Room3 {
    owen: Device,
    mia: Device,
    pat: Device,
    o: MlsGroup,
    m: MlsGroup,
    p: MlsGroup,
    facts: Facts,
}

fn private_room() -> Room3 {
    private_room_at(now_ms())
}

/// The room, made at `t`.
fn private_room_at(t: u64) -> Room3 {
    let owen = Device::new("owen@example.org", 1);
    let mia = Device::new("mia@example.org", 2);
    let pat = Device::new("pat@example.org", 3);
    let facts = Facts::with(&[&owen, &mia, &pat]);
    let mut conv = RisalaConversation::private_room(HOST, BOX, "Friends", &owen.uid);
    conv.mods.push(mia.uid.clone());
    let mut o = owen.create_at(&conv, t);
    let out = owen.commit_at(
        &mut o,
        add(vec![mia.key_package_at(t), pat.key_package_at(t)]),
        t,
    );
    owen.merge_at(&mut o, &out, t);
    let welcome = out.welcome.unwrap();
    let m = mia.join(&welcome);
    let p = pat.join(&welcome);
    Room3 {
        owen,
        mia,
        pat,
        o,
        m,
        p,
        facts,
    }
}

#[test]
fn private_room_roles() {
    let Room3 {
        owen,
        mia,
        pat,
        mut o,
        mut m,
        mut p,
        mut facts,
    } = private_room();
    let quinn = Device::new("quinn@example.org", 4);
    let rhea = Device::new("rhea@example.org", 5);
    facts.add(&quinn);
    facts.add(&rhea);

    // A plain member may not invite a new identity, or set the topic.
    let out = pat.commit(&mut p, add(vec![quinn.key_package(false)]));
    let (_, verdict) = owen.receive(&mut o, &out);
    assert_eq!(verdict, Err(CommitError::Add));
    discard_own_commit(&pat.provider, &mut p).unwrap();
    let mut topic = conversation(&p).unwrap();
    topic.topic = "new topic".into();
    let out = pat.commit(
        &mut p,
        Changes {
            conversation: Some(topic.clone()),
            ..Changes::default()
        },
    );
    let (_, verdict) = owen.receive(&mut o, &out);
    assert!(matches!(verdict, Err(CommitError::Extension(_))));
    discard_own_commit(&pat.provider, &mut p).unwrap();

    // A moderator may not invite an identity listed in `mods` (12.7).
    let mut listed = conversation(&m).unwrap();
    listed.mods.push(rhea.uid.clone());
    let out = owen.commit(
        &mut o,
        Changes {
            conversation: Some(listed),
            ..Changes::default()
        },
    );
    owen.merge(&mut o, &out);
    mia.apply(&mut m, &out, &facts);
    pat.apply(&mut p, &out, &facts);
    let out = mia.commit(&mut m, add(vec![rhea.key_package(false)]));
    // Every device refuses it alike, whenever it joined (12.7).
    for (device, group) in [(&owen, &mut o), (&pat, &mut p)] {
        let (_, verdict) = device.receive(group, &out);
        assert_eq!(verdict, Err(CommitError::Add));
    }
    discard_own_commit(&mia.provider, &mut m).unwrap();

    // A moderator may invite a plain identity and set the topic: an
    // authority commit (12.7).
    let mut topic = conversation(&m).unwrap();
    topic.topic = "new topic".into();
    let out = mia.commit(
        &mut m,
        Changes {
            add: vec![quinn.key_package(false)],
            conversation: Some(topic.clone()),
            ..Changes::default()
        },
    );
    mia.merge(&mut m, &out);
    assert!(owen.apply(&mut o, &out, &facts).authority);
    pat.apply(&mut p, &out, &facts);
    assert_eq!(conversation(&p).unwrap().topic, "new topic");
    let q = quinn.join(out.welcome.as_ref().unwrap());
    assert_eq!(q.members().count(), 4);

    // A moderator may not kick the owner; the owner may ban the moderator,
    // removing her leaf and her role in the same commit.
    let owen_leaf = o.own_leaf_index();
    let mia_leaf = m.own_leaf_index();
    let out = mia.commit(&mut m, remove(vec![owen_leaf]));
    let verdict = pat.receive(&mut p, &out).1.unwrap();
    // Not as a kick: but any member may remove a leaf for a check (12.7),
    // an authority commit, which devices that confirmed Owen's leaf show
    // as abuse, naming Mia.
    assert_eq!(verdict.check_removals, vec![owen_leaf]);
    assert!(verdict.authority);
    discard_own_commit(&mia.provider, &mut m).unwrap();

    let mut ban = conversation(&o).unwrap();
    ban.mods.clear();
    ban.bans.push(mia.uid.clone());
    // A ban that leaves the banned identity's leaf is invalid.
    let out = owen.commit(
        &mut o,
        Changes {
            conversation: Some(ban.clone()),
            ..Changes::default()
        },
    );
    let (_, verdict) = pat.receive(&mut p, &out);
    assert_eq!(verdict, Err(CommitError::LeftBehind));
    discard_own_commit(&owen.provider, &mut o).unwrap();
    let out = owen.commit(
        &mut o,
        Changes {
            remove: vec![mia_leaf],
            conversation: Some(ban),
            ..Changes::default()
        },
    );
    owen.merge(&mut o, &out);
    let verdict = pat.apply(&mut p, &out, &facts);
    assert!(verdict.check_removals.is_empty() && verdict.authority);
    assert!(conversation(&p).unwrap().bans.contains(&mia.uid));
    // Mia's device sees it was removed.
    let (received, verdict) = mia.receive(&mut m, &out);
    verdict.unwrap();
    assert!(!mia.apply_received(&mut m, *received));
}

#[test]
fn self_remove_and_leaving() {
    let Room3 {
        owen,
        pat,
        mut o,
        mut m,
        mut p,
        mia,
        facts,
    } = private_room();
    // Pat leaves: a SelfRemove, as a PrivateMessage (12.6, 6.1).
    let pat_leaf = p.own_leaf_index();
    let pat_pseudonym = pat.pseudonym(&p);
    let proposal = self_remove(&pat.provider, &mut p).unwrap();
    private_framing(&proposal, ContentType::Proposal);
    for (device, group) in [(&owen, &mut o), (&mia, &mut m)] {
        let Incoming::Proposal {
            aad, kind, sender, ..
        } = process_message(&device.provider, group, &proposal).unwrap()
        else {
            panic!("not a proposal");
        };
        assert_eq!(aad.pseudonym, Some(pat_pseudonym));
        assert_eq!(kind, ProposalKind::SelfRemove);
        assert_eq!(sender, Some(pat_leaf));
    }
    // Owen commits it, by reference, with his refresh.
    let out = owen.commit(&mut o, Changes::default());
    owen.merge(&mut o, &out);
    assert!(o.members().all(|member| member.index != pat_leaf));
    mia.apply(&mut m, &out, &facts);
    assert_eq!(m.members().count(), 2);
    let (received, verdict) = pat.receive(&mut p, &out);
    let pat_key = p
        .own_leaf_node()
        .unwrap()
        .signature_key()
        .as_slice()
        .to_vec();
    verdict.unwrap();
    assert!(!pat.apply_received(&mut p, *received));
    assert!(
        LeafKey::load(pat.provider.storage(), p.group_id().as_slice(), &pat_key)
            .unwrap()
            .is_none()
    );
    forget_group(&pat.provider, &mut p).unwrap();

    // Pat left by SelfRemove: nobody but an owner or moderator may add
    // his devices back (12.7).
    let out = mia.commit(&mut m, add(vec![pat.again().key_package(false)]));
    owen.receive(&mut o, &out).1.unwrap();
    discard_own_commit(&mia.provider, &mut m).unwrap();

    // The owner is gone: the moderator may do what an owner may (6.3).
    let owen_leaf = o.own_leaf_index();
    let proposal = self_remove(&owen.provider, &mut o).unwrap();
    process_message(&mia.provider, &mut m, &proposal).unwrap();
    let out = mia.commit(&mut m, Changes::default());
    mia.merge(&mut m, &out);
    assert!(m.members().all(|member| member.index != owen_leaf));
    let mut renamed = conversation(&m).unwrap();
    renamed.name = "Mia's".into();
    renamed.owners.push(mia.uid.clone());
    renamed.mods.clear();
    let quinn = Device::new("quinn@example.org", 4);
    let out = mia.commit(
        &mut m,
        Changes {
            conversation: Some(renamed),
            add: vec![quinn.key_package(false)],
            ..Changes::default()
        },
    );
    mia.merge(&mut m, &out);
    let q = quinn.join(out.welcome.as_ref().unwrap());
    assert_eq!(conversation(&q).unwrap().name, "Mia's");
}

#[test]
fn competing_commits() {
    let Room3 {
        owen,
        mia,
        pat,
        mut o,
        mut m,
        mut p,
        facts,
    } = private_room();
    // Owen and Mia both commit for the same epoch. The server keeps both,
    // in seq order; Owen's comes first.
    let first = owen.commit(&mut o, Changes::default());
    let second = mia.commit(&mut m, Changes::default());
    // Pat applies the first, and cannot even process the second, which is
    // for an epoch that is over.
    pat.apply(&mut p, &first, &facts);
    assert!(process_message(&pat.provider, &mut p, &second.message).is_err());
    // Mia applies the winner, which drops her own pending commit.
    mia.apply(&mut m, &first, &facts);
    assert!(m.pending_commit().is_none());
    // Owen knows he won.
    owen.merge(&mut o, &first);
    let token = SendToken::of_group(&o, owen.provider.crypto()).unwrap();
    assert_eq!(
        SendToken::of_group(&m, mia.provider.crypto()).unwrap(),
        token
    );
    assert_eq!(
        SendToken::of_group(&p, pat.provider.crypto()).unwrap(),
        token
    );
    assert_eq!(first.next_token_hash, token.hash());
    assert_ne!(second.next_token_hash, token.hash());
    // They all read each other in the new epoch.
    let message = mia.send(&mut m, b"after");
    assert_eq!(owen.read(&mut o, &message).1, b"after");
    assert_eq!(pat.read(&mut p, &message).1, b"after");
}

/// Stale leaves (12.7): more than 35 days older than the group's upper
/// median `updated`.
#[test]
fn stale_leaves() {
    // The room was made 40 days ago; Owen has not committed since.
    let long_ago = now_ms() - 40 * 24 * HOUR;
    let Room3 {
        owen,
        mia,
        pat,
        mut o,
        mut m,
        mut p,
        facts,
    } = private_room_at(long_ago);
    // Mia and Pat commit fresh leaves today.
    let now = now_ms();
    let out = mia.commit_at(&mut m, Changes::default(), now);
    mia.merge_at(&mut m, &out, now);
    owen.apply_at(&mut o, &out, &facts, now);
    pat.apply_at(&mut p, &out, &facts, now);
    let out = pat.commit_at(&mut p, Changes::default(), now);
    pat.merge_at(&mut p, &out, now);
    owen.apply_at(&mut o, &out, &facts, now);
    mia.apply_at(&mut m, &out, &facts, now);
    // The upper median of 40 days ago, today and today is today.
    let view = GroupView::of(p.public_group(), &pat.state(&p));
    assert_eq!(view.median_activity(now), Some(now));
    assert_eq!(view.stale_leaves(now), vec![o.own_leaf_index()]);
    assert_eq!(view.bulk_limit(), 1);
    // Pat, a plain member, removes Owen's leaf as stale and adds his device
    // again from a new KeyPackage (12.7): a group reason, not a check,
    // though Owen is an owner, whom Pat could not invite.
    let owen_leaf = o.own_leaf_index();
    let out = pat.commit(
        &mut p,
        Changes {
            remove: vec![owen_leaf],
            add: vec![owen.again().key_package(false)],
            ..Changes::default()
        },
    );
    let verdict = mia.receive(&mut m, &out).1.unwrap();
    assert!(verdict.check_removals.is_empty());
    assert!(!verdict.authority);
    discard_own_commit(&pat.provider, &mut p).unwrap();
    // Mia's leaf is not stale: removing it is a removal for a check, and
    // she may not be added back by Pat in the same commit.
    let mia_leaf = m.own_leaf_index();
    let out = pat.commit(&mut p, remove(vec![mia_leaf]));
    let verdict = owen.receive(&mut o, &out).1.unwrap();
    assert_eq!(verdict.check_removals, vec![mia_leaf]);
    discard_own_commit(&pat.provider, &mut p).unwrap();
    let out = pat.commit(
        &mut p,
        Changes {
            remove: vec![mia_leaf],
            add: vec![mia.again().key_package(false)],
            ..Changes::default()
        },
    );
    assert_eq!(owen.receive(&mut o, &out).1, Err(CommitError::Add));

    // The weekly refresh (12.7).
    let own = RisalaProfile::new("", now_ms() - 8 * 24 * HOUR).unwrap();
    assert!(needs_refresh(&own, now_ms()));
    assert!(!needs_refresh(
        &RisalaProfile::new("", now_ms()).unwrap(),
        now_ms()
    ));
}

/// KeyPackage lifetimes are judged at the post's `t`, give or take an
/// hour, never by the device's clock (12.5). OpenMLS is patched not to
/// check them against the clock.
#[test]
fn lifetimes_at_the_post() {
    let alice = Device::new("alice@example.org", 1);
    let bob = Device::new("bob@example.org", 2);
    let carol = Device::new("carol@example.org", 3);
    // Everything happens two weeks ago, by the posts' times.
    let now_s = now_ms() / 1000;
    let week = 7 * 24 * 3600;
    let then = now_ms() - 2 * week * 1000;
    let mut a = alice.create_at(
        &RisalaConversation::private_room(HOST, BOX, "Room", &alice.uid),
        then,
    );
    let out = alice.commit_at(&mut a, add(vec![bob.key_package_at(then)]), then);
    alice.merge_at(&mut a, &out, then);
    let mut b = bob.join(out.welcome.as_ref().unwrap());
    // Carol's KeyPackage ended a week ago, by the clock.
    let expired = make_key_package_with(
        &carol.provider,
        carol.device_key.as_ref().unwrap(),
        &carol.uid,
        &RisalaProfile::new("", (now_s - 5 * week) * 1000).unwrap(),
        false,
        Lifetime::init(now_s - 6 * week, now_s - week),
    )
    .unwrap()
    .key_package;
    // A commit posted two weeks ago may add it: Bob, processing it now,
    // accepts it.
    let out = alice.commit_at(&mut a, add(vec![expired]), then);
    let (received, verdict) = bob.receive_post(&mut b, &out.message, &post(&out, then));
    verdict.unwrap();
    // Posted now, it would be invalid (with `updated` moved along, so that
    // only the lifetime is wrong).
    let mut view = received.view.clone();
    if let Some(profile) = view.path_leaf.as_mut().and_then(|l| l.profile.as_mut()) {
        profile.updated = now_ms();
    }
    assert_eq!(
        crate::checks::check_commit(
            &GroupView::of(b.public_group(), &bob.state(&b)),
            &view,
            &CommitPost::at(now_ms(), Some(out.next_token_hash)),
        ),
        Err(CommitError::KeyPackage(KeyPackageError::Lifetime))
    );
    bob.apply_received(&mut b, *received);
    alice.merge_at(&mut a, &out, then);
    // Carol joins, though her leaf's lifetime is over (12.5).
    let c = carol.join(out.welcome.as_ref().unwrap());
    assert_eq!(c.members().count(), 3);
}

/// RESYNC (12.7): the device's own identity replaces its leaf; if it has no
/// other leaf, an owner or moderator does, as a removal for a check and an
/// Add its role allows; plain members only warn.
#[test]
fn resync_repairs() {
    let Room3 {
        owen,
        mia,
        pat,
        mut o,
        mut m,
        mut p,
        mut facts,
    } = private_room();
    // Mia's device could not process a commit, and posts RESYNC.
    let mia_leaf = m.own_leaf_index();
    let replace = |device: &Device, group: &mut MlsGroup| {
        device.commit(
            group,
            Changes {
                remove: vec![mia_leaf],
                add: vec![mia.again().key_package(false)],
                ..Changes::default()
            },
        )
    };
    // Mia has no other leaf, so Pat, a plain member, may not: he could hold
    // the new leaf himself (12.7).
    let out = replace(&pat, &mut p);
    assert_eq!(owen.receive(&mut o, &out).1, Err(CommitError::Add));
    discard_own_commit(&pat.provider, &mut p).unwrap();
    // Owen, an owner, may: his role lets him remove all of Mia's leaves,
    // and invite her (a moderator, whom only owners invite).
    let out = replace(&owen, &mut o);
    let (received, verdict) = pat.receive(&mut p, &out);
    let verdict = verdict.unwrap();
    assert!(verdict.check_removals.is_empty());
    assert!(verdict.authority);
    // The device re-added in the same commit: nothing to report.
    assert_eq!(
        pat.keys(&p, &received, &verdict, &facts, &pat.seen()),
        KeyReport::default()
    );
    discard_own_commit(&owen.provider, &mut o).unwrap();

    // With a second device of Mia's in the room, her own identity repairs.
    let mia2 = Device::new("mia@example.org", 12);
    facts.add(&mia2);
    let out = pat.commit(&mut p, add(vec![mia2.key_package(false)]));
    pat.merge(&mut p, &out);
    owen.apply(&mut o, &out, &facts);
    mia.apply(&mut m, &out, &facts);
    let mut m2 = mia2.join(out.welcome.as_ref().unwrap());
    let out = replace(&mia2, &mut m2);
    let verdict = pat.receive(&mut p, &out).1.unwrap();
    assert!(verdict.check_removals.is_empty());
    // Pat, removing Mia's leaf without re-adding it, needs a reason he can
    // see: the RESYNC he read is one.
    discard_own_commit(&mia2.provider, &mut m2).unwrap();
    let out = pat.commit(&mut p, remove(vec![mia_leaf]));
    let (received2, verdict2) = owen.receive(&mut o, &out);
    let verdict2 = verdict2.unwrap();
    let resyncs = [mia_leaf];
    let saw = Seen {
        own_uid: &owen.uid,
        resyncs: &resyncs,
        impostors: &[],
    };
    assert_eq!(
        owen.keys(&o, &received2, &verdict2, &facts, &saw),
        KeyReport::default()
    );
    assert_eq!(
        owen.keys(&o, &received2, &verdict2, &facts, &owen.seen())
            .unexplained_removals,
        vec![mia_leaf]
    );
    // Mia's other device finds no reason at all, and her device is current:
    // the removal failed, and it adds the device again.
    let (received3, verdict3) = mia2.receive(&mut m2, &out);
    let report = mia2.keys(&m2, &received3, &verdict3.unwrap(), &facts, &mia2.seen());
    assert_eq!(report.failed_removals, vec![mia.identity()]);
}

/// Impostors (12.7): any member removes the leaf, for a check, and that
/// undoes nothing; undoing takes ordinary commits by those whose role
/// allows each change.
#[test]
fn impostor_removals() {
    let Room3 {
        owen,
        mia,
        pat,
        mut o,
        mut m,
        mut p,
        mut facts,
    } = private_room();
    let quinn = Device::new("quinn@example.org", 4);
    facts.add(&quinn);
    // Owen invites Quinn.
    let out = owen.commit(&mut o, add(vec![quinn.key_package(false)]));
    owen.merge(&mut o, &out);
    mia.apply(&mut m, &out, &facts);
    pat.apply(&mut p, &out, &facts);
    let quinn_leaf = LeafNodeIndex::new(3);
    // "Mia" (an impostor holding her leaf) kicks Quinn and changes the
    // topic.
    let mut topic = conversation(&m).unwrap();
    topic.topic = "taken".into();
    let out = mia.commit(
        &mut m,
        Changes {
            remove: vec![quinn_leaf],
            conversation: Some(topic),
            ..Changes::default()
        },
    );
    mia.merge(&mut m, &out);
    owen.apply(&mut o, &out, &facts);
    assert!(pat.apply(&mut p, &out, &facts).authority);
    // Pat, a plain member, finds her an impostor and removes her leaf.
    let mia_leaf = m.own_leaf_index();
    let out = pat.commit(&mut p, remove(vec![mia_leaf]));
    let (received, verdict) = owen.receive(&mut o, &out);
    let verdict = verdict.unwrap();
    assert_eq!(verdict.check_removals, vec![mia_leaf]);
    // Owen sees no reason himself: it stands, with a warning naming Pat.
    assert_eq!(
        owen.keys(&o, &received, &verdict, &facts, &owen.seen())
            .unexplained_removals,
        vec![mia_leaf]
    );
    // Pat's device, to which she is an impostor, has its reason.
    let impostors = [mia_leaf];
    let saw = Seen {
        own_uid: &pat.uid,
        resyncs: &[],
        impostors: &impostors,
    };
    let own_commit = crate::checks::CommitView::of(
        &openmls::prelude::Sender::Member(p.own_leaf_index()),
        p.pending_commit().unwrap(),
        p.pending_proposals(),
    );
    assert_eq!(
        crate::checks::key_checks(
            &GroupView::of(p.public_group(), &pat.state(&p)),
            &own_commit,
            &verdict,
            &facts,
            &saw
        ),
        KeyReport::default()
    );
    // The removal undoes nothing: putting the topic back or adding Quinn
    // again in the same commit is not Pat's to do.
    discard_own_commit(&pat.provider, &mut p).unwrap();
    let mut back = conversation(&p).unwrap();
    back.topic = String::new();
    let out = pat.commit(
        &mut p,
        Changes {
            remove: vec![mia_leaf],
            add: vec![quinn.key_package(false)],
            conversation: Some(back.clone()),
            ..Changes::default()
        },
    );
    assert!(owen.receive(&mut o, &out).1.is_err());
    discard_own_commit(&pat.provider, &mut p).unwrap();
    // The owner undoes it in one ordinary commit, as his role allows.
    let out = owen.commit(
        &mut o,
        Changes {
            remove: vec![mia_leaf],
            add: vec![quinn.key_package(false)],
            conversation: Some(back),
            ..Changes::default()
        },
    );
    let verdict = pat.receive(&mut p, &out).1.unwrap();
    assert!(verdict.authority);
}

/// Moving the mailbox (7.8): any member, a commit that changes `box` alone,
/// to the box derived from the epoch's exporter.
#[test]
fn mailbox_moves() {
    let Room3 {
        owen,
        pat,
        mut o,
        mut p,
        facts,
        ..
    } = private_room();
    let derived = moved_box::<()>(&o, owen.provider.crypto()).unwrap();
    let exported = o
        .export_secret(owen.provider.crypto(), "risala/1 box", b"", 16)
        .unwrap();
    assert_eq!(derived.to_vec(), exported);
    // A move to any other box is invalid.
    let mut elsewhere = conversation(&p).unwrap();
    elsewhere.mailbox = [0x77; 16];
    let out = pat.commit(
        &mut p,
        Changes {
            conversation: Some(elsewhere),
            ..Changes::default()
        },
    );
    assert!(matches!(
        owen.receive(&mut o, &out).1,
        Err(CommitError::Extension(_))
    ));
    discard_own_commit(&pat.provider, &mut p).unwrap();
    let out = pat.commit(
        &mut p,
        Changes {
            move_box: true,
            ..Changes::default()
        },
    );
    pat.merge(&mut p, &out);
    let verdict = owen.apply(&mut o, &out, &facts);
    assert!(!verdict.authority);
    assert_eq!(conversation(&o).unwrap().mailbox, derived);
    assert_eq!(conversation(&p).unwrap().mailbox, derived);
}

/// Update proposals in an epochal group (12.10): a leaf rotates its key
/// once a period, and a full client commits the Update by reference.
#[test]
fn update_proposals() {
    let Room3 {
        owen,
        mia,
        pat,
        mut o,
        mut m,
        mut p,
        facts,
    } = private_room();
    // Updates are not allowed in a pairwise group.
    assert!(propose_update(&pat.provider, &mut p, &pat.profile(), None).is_err());
    // The owner moves the room to epochal.
    let mut epochal = conversation(&o).unwrap();
    epochal.confirm = ConfirmMode::Epochal;
    let out = owen.commit(
        &mut o,
        Changes {
            conversation: Some(epochal),
            ..Changes::default()
        },
    );
    owen.merge(&mut o, &out);
    mia.apply(&mut m, &out, &facts);
    pat.apply(&mut p, &out, &facts);
    // Pat proposes a fresh leaf with a new key, the next period.
    let next_day = (now_ms() / PERIOD_MS + 1) * PERIOD_MS + HOUR;
    let new_key = LeafKey::generate().unwrap();
    let old_key = p.own_leaf_node().unwrap().signature_key().clone();
    let update = propose_update(
        &pat.provider,
        &mut p,
        &pat.profile_at(next_day),
        Some(&new_key),
    )
    .unwrap();
    private_framing(&update.message, ContentType::Proposal);
    // Pat notes the `t` of his own proposal's post too, once posted.
    let mut state = pat.state(&p);
    state.note_proposal(&update.reference, next_day);
    pat.set_state(&p, state);
    assert_eq!(
        owen.propose_in(&mut o, &update.message, next_day),
        ProposalKind::Update
    );
    assert_eq!(
        mia.propose_in(&mut m, &update.message, next_day),
        ProposalKind::Update
    );
    // Owen commits it by reference.
    let out = owen.commit_at(&mut o, Changes::default(), next_day);
    owen.merge_at(&mut o, &out, next_day);
    mia.apply_at(&mut m, &out, &facts, next_day);
    pat.apply_at(&mut p, &out, &facts, next_day);
    let leaf = p.own_leaf_node().unwrap();
    assert_eq!(leaf.signature_key().as_slice(), new_key.public_key());
    assert_eq!(RisalaProfile::of_leaf(leaf).unwrap().streak, 0);
    // The old key is gone, the new one in place.
    assert!(
        LeafKey::load(
            pat.provider.storage(),
            p.group_id().as_slice(),
            old_key.as_slice()
        )
        .unwrap()
        .is_none()
    );
    let message = pat.send(&mut p, b"rotated");
    assert_eq!(owen.read(&mut o, &message).1, b"rotated");
    // A second rotation in the same period is not allowed.
    let again = LeafKey::generate().unwrap();
    let update = propose_update(
        &pat.provider,
        &mut p,
        &pat.profile_at(next_day + HOUR),
        Some(&again),
    )
    .unwrap();
    mia.propose_in(&mut m, &update.message, next_day + HOUR);
    owen.propose_in(&mut o, &update.message, next_day + HOUR);
    let out = mia.commit_at(&mut m, Changes::default(), next_day + HOUR);
    let (_, verdict) = owen.receive_post(&mut o, &out.message, &post(&out, next_day + HOUR));
    assert_eq!(verdict, Err(CommitError::Leaf));
}

#[test]
fn last_resort_key_packages() {
    let alice = Device::new("alice@example.org", 1);
    let carol = Device::new("carol@example.org", 3);
    let bob = Device::new("bob@example.org", 2);
    let facts = Facts::with(&[&alice, &bob, &carol]);
    let before = now_ms();
    let last = bob.key_package(true);
    assert_eq!(is_last_resort(&last), Ok(true));
    // Its `updated` is the start of the period before the one it was made
    // in (12.3); an ordinary one's is the time it was made.
    let updated = |kp: &KeyPackage| RisalaProfile::of_leaf(kp.leaf_node()).unwrap().updated;
    let after = now_ms();
    let start = updated(&last);
    assert_eq!(start % PERIOD_MS, 0);
    assert!(start + PERIOD_MS <= after && before < start + 2 * PERIOD_MS);
    assert_eq!(last_resort_updated(2 * PERIOD_MS + 5), PERIOD_MS);
    assert_eq!(last_resort_updated(2 * PERIOD_MS - 1), 0);
    assert_eq!(last_resort_updated(5), 0);
    assert!(updated(&bob.key_package(false)) >= before);

    // Two groups add Bob with the same last-resort KeyPackage.
    let mut a = alice.create(&RisalaConversation::direct(HOST, BOX, &alice.uid, &bob.uid));
    let out_a = alice.commit(&mut a, add(vec![last.clone()]));
    alice.merge(&mut a, &out_a);
    let mut c = carol.create(&RisalaConversation::direct(HOST, BOX, &carol.uid, &bob.uid));
    let out_c = carol.commit(&mut c, add(vec![last]));
    carol.merge(&mut c, &out_c);

    let joined = join_by_welcome(
        &bob.provider,
        out_a.welcome.as_ref().unwrap(),
        None,
        &bob.expect(),
    )
    .unwrap();
    assert!(joined.last_resort);
    let mut b1 = joined.group;
    bob.set_state(&b1, joined.state);
    let joined = join_by_welcome(
        &bob.provider,
        out_c.welcome.as_ref().unwrap(),
        None,
        &bob.expect(),
    )
    .unwrap();
    assert!(joined.last_resort);
    let mut b2 = joined.group;
    bob.set_state(&b2, joined.state);
    // Both leaves share the leaf key, so Bob commits a new one in each
    // before he sends (12.3).
    let shared = b1.own_leaf_node().unwrap().signature_key().clone();
    assert_eq!(&shared, b2.own_leaf_node().unwrap().signature_key());
    let rotate = Changes {
        new_leaf_key: true,
        ..Changes::default()
    };
    let out = bob.commit(&mut b1, rotate.clone());
    bob.merge(&mut b1, &out);
    assert_ne!(b1.own_leaf_node().unwrap().signature_key(), &shared);
    alice.apply(&mut a, &out, &facts);
    let message = bob.send(&mut b1, b"rotated");
    assert_eq!(alice.read(&mut a, &message).1, b"rotated");
    let out = bob.commit(&mut b2, rotate.clone());
    bob.merge(&mut b2, &out);
    carol.apply(&mut c, &out, &facts);
    // Each group's copy of the shared key is gone; the last-resort
    // KeyPackage keeps its own.
    for group in [&b1, &b2] {
        assert!(
            LeafKey::load(
                bob.provider.storage(),
                group.group_id().as_slice(),
                shared.as_slice()
            )
            .unwrap()
            .is_none()
        );
    }
    assert!(
        LeafKey::load(
            bob.provider.storage(),
            crate::mldsa::KEY_PACKAGE_SCOPE,
            shared.as_slice()
        )
        .unwrap()
        .is_some()
    );

    // A second rotation in a pairwise group is not allowed (12.3).
    let out = bob.commit(&mut b1, rotate);
    let (_, verdict) = alice.receive(&mut a, &out);
    assert_eq!(verdict, Err(CommitError::Leaf));
}

/// A public room by Owen, with its GroupInfo and tree as the server holds
/// them.
fn public_room(guests: GuestMode) -> (Device, MlsGroup, RisalaConversation) {
    let owen = Device::new("owen@example.org", 1);
    let room: Room = "#general".parse().unwrap();
    let mut conv = RisalaConversation::public_room(HOST, BOX, &room, &owen.uid);
    conv.guests = guests;
    let o = owen.create(&conv);
    (owen, o, conv)
}

fn public_state(device: &Device, group: &MlsGroup) -> (Vec<u8>, Vec<u8>) {
    let leaf_key = own_leaf_key(&device.provider, group).unwrap();
    let group_info = group
        .export_group_info(device.provider.crypto(), &leaf_key, false)
        .unwrap();
    (
        to_bytes(&group_info),
        tree_to_bytes(&group.export_ratchet_tree()),
    )
}

fn public_expect(device: &Device) -> JoinExpectation {
    JoinExpectation {
        host: HOST.into(),
        own_uid: device.uid.clone(),
        public_room: Some(("#general".parse().unwrap(), BOX)),
    }
}

/// `device` joins `room` by proposal; `members` process the proposal,
/// `committer` commits it, the others apply the commit, and `device` joins
/// by Welcome with the room's tree.
fn join_room(
    device: &Device,
    committer: (&Device, &mut MlsGroup),
    others: Vec<(&Device, &mut MlsGroup)>,
    facts: &Facts,
) -> MlsGroup {
    let (group_info, tree) = public_state(committer.0, committer.1);
    let profile = device.device_key.is_some().then(|| device.profile());
    let join = join_public_room(
        &device.provider,
        &device.identity(),
        profile.as_ref(),
        &group_info,
        &tree,
        &public_expect(device),
    )
    .unwrap();
    // A PublicMessage from a new member, with an empty RisalaAAD (6.1).
    let (framing, aad) = read_post(&join.message).unwrap();
    assert!(!framing.private);
    assert_eq!(framing.sender, Some(Sender::NewMemberProposal));
    assert_eq!(framing.content_type, ContentType::Proposal);
    assert_eq!(aad, RisalaAad::public());
    assert!(has_no_binding(&join.key_package));
    assert_eq!(
        committer.0.propose_in(committer.1, &join.message, now_ms()),
        ProposalKind::Join
    );
    let mut others = others;
    for (other, group) in &mut others {
        other.propose_in(group, &join.message, now_ms());
    }
    let out = committer.0.commit(committer.1, Changes::default());
    let (framing, aad) = read_post(&out.message).unwrap();
    assert!(!framing.private);
    assert_eq!(aad, RisalaAad::public());
    assert!(out.group_info.is_some());
    committer.0.merge(committer.1, &out);
    for (other, group) in others {
        other.apply(group, &out, facts);
    }
    let tree = tree_to_bytes(&committer.1.export_ratchet_tree());
    device.join_with_tree(out.welcome.as_ref().unwrap(), Some(&tree))
}

#[test]
fn public_room_joins() {
    let (owen, mut o, _) = public_room(GuestMode::Write);
    let dave = Device::new("dave@example.org", 4);
    let facts = Facts::default();
    let mut d = join_room(&dave, (&owen, &mut o), vec![], &facts);
    assert_eq!(d.members().count(), 2);
    // Dave's leaf carries no binding (12.3).
    let leaf = d.own_leaf_node().unwrap();
    assert!(crate::binding::DeviceBinding::from_extensions(leaf.extensions()).is_none());

    // Owen's commits are PublicMessages, with a GroupInfo for the server,
    // and Dave applies them.
    let out = owen.commit(&mut o, Changes::default());
    owen.merge(&mut o, &out);
    dave.apply(&mut d, &out, &facts);
    // Application messages stay encrypted.
    let message = dave.send(&mut d, b"hi room");
    private_framing(&message, ContentType::Application);
    assert_eq!(owen.read(&mut o, &message).1, b"hi room");

    // A guest joins, without a profile.
    let sam = Device::new("~sam", 0);
    let s = join_room(&sam, (&owen, &mut o), vec![(&dave, &mut d)], &facts);
    assert_eq!(s.members().count(), 3);
    // A guest's leaf may not commit in a public room (12.6).
    let mut s = s;
    let state = sam.state(&s);
    let out = commit(
        &sam.provider,
        &mut s,
        &sam.profile(),
        &state,
        Changes::default(),
    )
    .unwrap();
    let (_, verdict) = owen.receive(&mut o, &out);
    assert_eq!(verdict, Err(CommitError::Guest));
    // Nobody adds a device to a public room by value (6.1).
    let erin = Device::new("erin@example.org", 5);
    let state = owen.state(&o);
    assert!(
        commit(
            &owen.provider,
            &mut o,
            &owen.profile(),
            &state,
            add(vec![erin.key_package(false)])
        )
        .is_err()
    );
    // Public rooms do not move (7.8).
    assert!(
        commit(
            &owen.provider,
            &mut o,
            &owen.profile(),
            &state,
            Changes {
                move_box: true,
                ..Changes::default()
            }
        )
        .is_err()
    );
}

/// The server's side of a public room (12.6): its group and the state of
/// its epoch.
struct Server {
    crypto: RisalaCrypto,
    storage: MemoryStorage,
    group: PublicGroup,
    state: EpochState,
}

impl Server {
    /// The server, holding `device`'s view of the room.
    fn of(device: &Device, group: &MlsGroup) -> Server {
        let crypto = RisalaCrypto::new().unwrap();
        let storage = MemoryStorage::default();
        let (group_info, tree) = public_state(device, group);
        let public = public_group(&crypto, &storage, &group_info, &tree).unwrap();
        Server {
            crypto,
            storage,
            group: public,
            state: device.state(group),
        }
    }

    /// Checks a commit as the server does; if `keep`, takes it.
    fn sees(
        &mut self,
        message: &[u8],
        t: u64,
        next: [u8; 48],
        keep: bool,
    ) -> Result<Verdict, CommitError> {
        use openmls::prelude::ProcessedMessageContent;
        let processed = self
            .group
            .process_message(
                &self.crypto,
                crate::wire::read_protocol_message(message).unwrap(),
            )
            .unwrap();
        let sender = processed.sender().clone();
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            panic!("not a commit");
        };
        let view = crate::checks::CommitView::of(&sender, &staged, std::iter::empty());
        let verdict = crate::checks::check_commit(
            &GroupView::of(&self.group, &self.state),
            &view,
            &self.state.post(t, Some(next)),
        )?;
        if keep {
            let key = staged
                .update_path_leaf_node()
                .map(|leaf| leaf.signature_key().as_slice().to_vec());
            self.group.merge_commit(&self.storage, *staged).unwrap();
            // The committer started the new epoch; an external committer by
            // its new leaf.
            let started = match sender {
                openmls::prelude::Sender::Member(index) => index,
                _ => {
                    self.group
                        .members()
                        .find(|m| Some(&m.signature_key) == key.as_ref())
                        .unwrap()
                        .index
                }
            };
            self.state = EpochState::started_by(started);
        }
        Ok(verdict)
    }

    fn tree(&self) -> Vec<u8> {
        tree_to_bytes(&self.group.export_ratchet_tree())
    }
}

/// A public room's Welcome carries no tree; the joiner takes the one that
/// WELCOME GET hands out with it, and MLS checks it against the tree hash
/// in the Welcome's group context (12.6, 12.8).
#[test]
fn public_room_welcome_trees() {
    let (owen, mut o, _) = public_room(GuestMode::Write);
    let dave = Device::new("dave@example.org", 4);
    let erin = Device::new("erin@example.org", 5);
    let frank = Device::new("frank@example.org", 6);
    let (group_info, tree) = public_state(&owen, &o);
    for device in [&dave, &erin, &frank] {
        let join = join_public_room(
            &device.provider,
            &device.identity(),
            Some(&device.profile()),
            &group_info,
            &tree,
            &public_expect(device),
        )
        .unwrap();
        owen.propose_in(&mut o, &join.message, now_ms());
    }
    // One commit, and one Welcome for the whole batch (12.8).
    let out = owen.commit(&mut o, Changes::default());
    assert_eq!(out.added.len(), 3);
    let welcome = out.welcome.clone().unwrap();
    owen.merge(&mut o, &out);
    // Without a tree, Erin cannot join.
    assert!(join_by_welcome(&erin.provider, &welcome, None, &public_expect(&erin)).is_err());
    // The tree of the epoch before the commit does not match the hash.
    assert!(
        join_by_welcome(
            &frank.provider,
            &welcome,
            Some(&tree),
            &public_expect(&frank)
        )
        .is_err()
    );
    let right = tree_to_bytes(&o.export_ratchet_tree());
    let d = dave.join_with_tree(&welcome, Some(&right));
    assert_eq!(d.members().count(), 4);
    assert_eq!(dave.state(&d).started_by, Some(o.own_leaf_index().u32()));

    // Outside public rooms the Welcome carries the tree, and a tree from
    // the server is refused.
    let alice = Device::new("alice@example.org", 1);
    let bob = Device::new("bob@example.org", 2);
    let mut a = alice.create(&RisalaConversation::direct(HOST, BOX, &alice.uid, &bob.uid));
    let out = alice.commit(&mut a, add(vec![bob.key_package(false)]));
    alice.merge(&mut a, &out);
    let tree = tree_to_bytes(&a.export_ratchet_tree());
    assert!(matches!(
        join_by_welcome(
            &bob.provider,
            out.welcome.as_ref().unwrap(),
            Some(&tree),
            &bob.expect()
        ),
        Err(GroupError::Group(_))
    ));
}

/// Outside public rooms, a commit or proposal carries its sender's
/// pseudonym for the epoch (7.3), and devices refuse any other.
#[test]
fn handshake_pseudonyms() {
    let Room3 {
        owen,
        pat,
        mut o,
        mut p,
        ..
    } = private_room();
    // A SelfRemove under another pseudonym, as a faulty device could post.
    let key = own_leaf_key(&pat.provider, &p).unwrap();
    p.set_aad(RisalaAad::handshake(owen.pseudonym(&o)).encode());
    let forged = p.leave_group_via_self_remove(&pat.provider, &key).unwrap();
    assert!(matches!(
        process_message(&owen.provider, &mut o, &to_bytes(&forged)),
        Err(ProcessError::Pseudonym)
    ));
    // Every leaf's pseudonym differs, and changes with each epoch.
    let before = owen.pseudonym(&o);
    assert_ne!(before, pat.pseudonym(&p));
    let pseudonyms = epoch_pseudonyms::<()>(&o, owen.provider.crypto()).unwrap();
    assert_eq!(pseudonyms.epoch, o.epoch().as_u64());
    assert_eq!(pseudonyms.of(o.own_leaf_index().u32()), Some(before));
    assert_eq!(pseudonyms.leaves.len(), 3);
}

/// Copies in a public room (12.7): a device that joined again has its
/// earlier leaf removed, by anyone, once its new leaf has committed.
#[test]
fn public_room_copies() {
    let (owen, mut o, _) = public_room(GuestMode::Write);
    let dave = Device::new("dave@example.org", 4);
    let erin = Device::new("erin@example.org", 5);
    let facts = Facts::default();
    let mut d = join_room(&dave, (&owen, &mut o), vec![], &facts);
    let mut e = join_room(&erin, (&owen, &mut o), vec![(&dave, &mut d)], &facts);
    // Dave's first device commits once, so its leaf is in use.
    let t = now_ms();
    let out = dave.commit_at(&mut d, Changes::default(), t);
    dave.merge(&mut d, &out);
    owen.apply_at(&mut o, &out, &facts, t);
    erin.apply_at(&mut e, &out, &facts, t);
    let dave_leaf = d.own_leaf_index();
    // Dave joins again from a new device state: two leaves of one device.
    let dave2 = dave.again();
    let mut d2 = join_room(
        &dave2,
        (&owen, &mut o),
        vec![(&erin, &mut e), (&dave, &mut d)],
        &facts,
    );
    let dave2_leaf = d2.own_leaf_index();
    // Erin, a plain member, may not remove Dave's earlier leaf yet: the new
    // one has not committed, so the earlier is no copy.
    let out = erin.commit_at(&mut e, remove(vec![dave_leaf]), t);
    assert_eq!(
        owen.receive_post(&mut o, &out.message, &post(&out, t)).1,
        Err(CommitError::Remove)
    );
    discard_own_commit(&erin.provider, &mut e).unwrap();
    // Nor the new one, which has never committed, before 8 days; Owen, an
    // owner, may, without kicking Dave.
    let out = erin.commit_at(&mut e, remove(vec![dave2_leaf]), t);
    assert_eq!(
        owen.receive_post(&mut o, &out.message, &post(&out, t)).1,
        Err(CommitError::Remove)
    );
    discard_own_commit(&erin.provider, &mut e).unwrap();
    let out = owen.commit_at(&mut o, remove(vec![dave2_leaf]), t);
    assert!(
        erin.receive_post(&mut e, &out.message, &post(&out, t))
            .1
            .unwrap()
            .authority
    );
    discard_own_commit(&owen.provider, &mut o).unwrap();
    // The new leaf commits: now anyone may remove the earlier one as a copy.
    let t2 = t + 60_000;
    let out = dave2.commit_at(&mut d2, Changes::default(), t2);
    dave2.merge(&mut d2, &out);
    for (device, group) in [(&owen, &mut o), (&erin, &mut e), (&dave, &mut d)] {
        device.apply_at(group, &out, &facts, t2);
    }
    let out = erin.commit_at(&mut e, remove(vec![dave_leaf]), t2);
    let verdict = owen
        .receive_post(&mut o, &out.message, &post(&out, t2))
        .1
        .unwrap();
    assert!(!verdict.authority);
    discard_own_commit(&erin.provider, &mut e).unwrap();
    // Dave's new device may too, as its own identity's.
    let out = dave2.commit_at(&mut d2, remove(vec![dave_leaf]), t2);
    owen.receive_post(&mut o, &out.message, &post(&out, t2))
        .1
        .unwrap();
}

/// A resync commit (12.7): after the server accepted a commit that the
/// devices hold invalid, one device rejoins by external commit, removing
/// the committer; an owner whose proposals nobody commits rejoins by
/// external commit too; nobody else commits externally.
#[test]
fn public_room_resync() {
    let (owen, mut o, _) = public_room(GuestMode::Write);
    let dave = Device::new("dave@example.org", 4);
    let erin = Device::new("erin@example.org", 5);
    let facts = Facts::default();
    let mut d = join_room(&dave, (&owen, &mut o), vec![], &facts);
    let mut e = join_room(&erin, (&owen, &mut o), vec![(&dave, &mut d)], &facts);
    // The server holds the room's public state.
    let mut server = Server::of(&owen, &o);

    // Dave commits with a wrong `next`. The server cannot tell, and
    // accepts it; Owen and Erin refuse it.
    let mut bad = dave.commit(&mut d, Changes::default());
    let right = bad.next_token_hash;
    bad.next_token_hash = [0; 48];
    for (device, group) in [(&owen, &mut o), (&erin, &mut e)] {
        let (_, verdict) = device.receive(group, &bad);
        assert_eq!(verdict, Err(CommitError::NextToken));
    }
    let t = now_ms();
    server.sees(&bad.message, t, [0; 48], true).unwrap();
    dave.merge(&mut d, &bad);
    assert_ne!(right, [0; 48]);
    assert_eq!(server.state.started_by, Some(d.own_leaf_index().u32()));

    // Erin resyncs from the server's GroupInfo, signed by Dave, after
    // checking that the server changed no roles or settings (12.7).
    let dave_leaf = d.own_leaf_index();
    let owen_leaf = o.own_leaf_index();
    let group_info = bad.group_info.clone().unwrap();
    let tree = server.tree();
    let kept = conversation(&e).unwrap();
    let scratch = MemoryStorage::default();
    let theirs = GroupView::of(
        &public_group(&server.crypto, &scratch, &group_info, &tree).unwrap(),
        &EpochState::default(),
    )
    .conversation
    .unwrap();
    assert!(kept.unexplained_changes(&theirs).is_empty());
    let erin2 = erin.again();
    let resync = external_commit(
        &erin2.provider,
        &erin.identity(),
        &erin.profile_at(t),
        &group_info,
        &tree,
        &public_expect(&erin),
        External::Resync,
        &[],
    )
    .unwrap();
    let (framing, aad) = read_post(&resync.message).unwrap();
    assert_eq!(framing.sender, Some(Sender::NewMemberCommit));
    assert_eq!(aad, RisalaAad::public());
    // The server checks it as a resync commit, which removes Dave.
    let verdict = server
        .sees(&resync.message, t, resync.next_token_hash, true)
        .unwrap();
    assert_eq!(verdict.external, Some(External::Resync));
    let dave_identity = dave.identity();
    let server_view = GroupView::of(&server.group, &server.state);
    assert!(
        server_view
            .leaves
            .iter()
            .all(|leaf| leaf.identity.as_ref() != Some(&dave_identity))
    );
    assert_eq!(
        server.state.started_by,
        Some(resync.group.own_leaf_index().u32())
    );
    // Dave's device, which applied its own commit, sees that it was
    // removed.
    let resync_post = CommitPost::at(t, Some(resync.next_token_hash));
    let (received, verdict) = dave.receive_post(&mut d, &resync.message, &resync_post);
    assert_eq!(verdict.unwrap().external, Some(External::Resync));
    assert!(!dave.apply_received(&mut d, *received));
    let r = resync.group;
    erin2.set_state(&r, resync.state);
    let _ = dave_leaf;

    // Owen's device cannot follow either. Owen, an owner, rejoins by
    // external commit, removing his own earlier leaf (12.7).
    let (group_info, tree) = public_state(&erin2, &r);
    let owen2 = owen.again();
    let rejoin = external_commit(
        &owen2.provider,
        &owen.identity(),
        &owen.profile_at(t),
        &group_info,
        &tree,
        &public_expect(&owen),
        External::Rejoin,
        &[owen_leaf],
    )
    .unwrap();
    let verdict = server
        .sees(&rejoin.message, t, rejoin.next_token_hash, false)
        .unwrap();
    assert_eq!(verdict.external, Some(External::Rejoin));
    // Frank, with no leaf and no role, may do neither.
    let frank = Device::new("frank@example.org", 6);
    for kind in [External::Resync, External::Rejoin] {
        let join = external_commit(
            &frank.provider,
            &frank.identity(),
            &frank.profile(),
            &group_info,
            &tree,
            &public_expect(&frank),
            kind,
            &[],
        )
        .unwrap();
        assert_eq!(
            server.sees(&join.message, t, join.next_token_hash, false),
            Err(CommitError::External)
        );
    }
    // Nor may Erin "rejoin" without removing the leaf that started the
    // epoch: she has no role.
    let erin3 = erin.again();
    let join = external_commit(
        &erin3.provider,
        &erin.identity(),
        &erin.profile_at(t),
        &group_info,
        &tree,
        &public_expect(&erin),
        External::Rejoin,
        &[],
    )
    .unwrap();
    assert_eq!(
        server.sees(&join.message, t, join.next_token_hash, false),
        Err(CommitError::External)
    );
}

/// What a server does with a public room's commit (12.6): it holds the
/// public group, built from the GroupInfo and tree without checking leaf
/// lifetimes, checks each commit with the same functions as the devices,
/// and keeps the new state and history.
#[test]
fn server_checks_public_commits() {
    use openmls::prelude::ProcessedMessageContent;

    use crate::checks::{CommitView, GroupView, check_commit};
    use crate::wire::read_protocol_message;

    let (owen, mut o, _) = public_room(GuestMode::Write);
    let crypto = RisalaCrypto::new().unwrap();
    // Dave joins with a KeyPackage whose lifetime ended long ago, by a
    // commit posted while it was still valid: the server can still load
    // the room's tree, since it does not check leaves' lifetimes (12.5).
    let dave = Device::new("dave@example.org", 4);
    let now_s = now_ms() / 1000;
    let week = 7 * 24 * 3600;
    let then = (now_s - 3 * week) * 1000;
    let made = make_join_key_package_with(
        &dave.provider,
        &dave.identity(),
        Some(&dave.profile_at(then)),
        Lifetime::init(now_s - 4 * week, now_s - week),
    )
    .unwrap();
    let context = o.public_group().group_context().clone();
    let proposal = join_proposal::<Provider<MemoryStorage>>(
        &made.key_package,
        context.group_id(),
        context.epoch().as_u64(),
        &made.leaf_key,
    )
    .unwrap();
    owen.propose_in(&mut o, &proposal, then);
    let out = owen.commit_at(&mut o, Changes::default(), then);
    owen.merge_at(&mut o, &out, then);
    let (group_info, tree) = public_state(&owen, &o);
    let storage = MemoryStorage::default();
    let mut public = public_group(&crypto, &storage, &group_info, &tree).unwrap();
    assert_eq!(public.members().count(), 2);
    let mut state = owen.state(&o);

    let mut d = dave.join_with_tree(
        out.welcome.as_ref().unwrap(),
        Some(&tree_to_bytes(&o.export_ratchet_tree())),
    );
    let server_sees =
        |public: &PublicGroup, message: &[u8], state: &EpochState, post: &CommitPost| {
            let processed = public
                .process_message(&crypto, read_protocol_message(message).unwrap())
                .unwrap();
            let sender = processed.sender().clone();
            let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content()
            else {
                panic!("not a commit");
            };
            let view = CommitView::of(&sender, &staged, std::iter::empty());
            let verdict = check_commit(&GroupView::of(public, state), &view, post);
            (staged, verdict)
        };
    // A member's commit that changes what it may not is refused.
    let mut guests = conversation(&d).unwrap();
    guests.guests = GuestMode::None;
    let out = dave.commit(
        &mut d,
        Changes {
            conversation: Some(guests),
            ..Changes::default()
        },
    );
    let (_, verdict) = server_sees(&public, &out.message, &state, &post(&out, now_ms()));
    assert!(matches!(verdict, Err(CommitError::Extension(_))));
    discard_own_commit(&dave.provider, &mut d).unwrap();
    // Dave's refresh is fine, and the server keeps the new state.
    let out = dave.commit(&mut d, Changes::default());
    let t = now_ms();
    let (staged, verdict) = server_sees(&public, &out.message, &state, &post(&out, t));
    verdict.unwrap();
    public.merge_commit(&storage, *staged).unwrap();
    state = EpochState::started_by(d.own_leaf_index());
    dave.merge(&mut d, &out);
    owen.apply(&mut o, &out, &Facts::default());
    assert_eq!(
        tree_to_bytes(&public.export_ratchet_tree()),
        tree_to_bytes(&o.export_ratchet_tree())
    );
    assert_eq!(state, owen.state(&o));
    // The GroupInfo's signer is the committer.
    let info = crate::wire::read_group_info(out.group_info.as_ref().unwrap()).unwrap();
    assert_eq!(info.signer(), d.own_leaf_index());
}

/// The limits of 12.9 in the group's configuration: 2 past epochs, and
/// skipped messages' keys for 1,000 generations each way. The rules that
/// delete past epochs sooner are `message`'s.
#[test]
fn past_epochs_and_generations() {
    assert_eq!(MAX_PAST_EPOCHS, 2);
    assert_eq!(
        sender_ratchet_configuration(),
        openmls::prelude::SenderRatchetConfiguration::new(1000, 1000)
    );
    let config = join_config(ConversationKind::PrivateRoom);
    assert_eq!(
        config.sender_ratchet_configuration(),
        &sender_ratchet_configuration()
    );
}

/// librisala keeps OpenMLS's state in SQLite, inside its own transactions:
/// groups, KeyPackages and leaf keys round-trip there, and a rolled-back
/// commit leaves nothing behind.
#[test]
fn sqlite_storage() {
    use openmls_sqlite_storage::{MsgPack, SCHEMA, SqliteStorageProvider};
    use std::sync::Arc;

    let alice = Device::new("alice@example.org", 1);
    let bob = Device::new("bob@example.org", 2);
    let crypto = Arc::new(RisalaCrypto::new().unwrap());
    let mut db = rusqlite::Connection::open_in_memory().unwrap();
    db.execute_batch(SCHEMA).unwrap();
    let conv = RisalaConversation::direct(HOST, BOX, &alice.uid, &bob.uid);

    // A KeyPackage made in SQLite, used by a Welcome later.
    let kp = {
        let tx = db.transaction().unwrap();
        let provider = Provider::with_crypto(
            crypto.clone(),
            SqliteStorageProvider::<MsgPack, _>::new(&*tx),
        );
        let kp = make_key_package(
            &provider,
            bob.device_key.as_ref().unwrap(),
            &bob.uid,
            &RisalaProfile::new("", now_ms()).unwrap(),
            true,
        )
        .unwrap()
        .key_package;
        drop(provider);
        tx.commit().unwrap();
        kp
    };
    let mut a = alice.create(&conv);
    let out = alice.commit(&mut a, add(vec![kp]));
    alice.merge(&mut a, &out);

    let (group_id, mut state) = {
        let tx = db.transaction().unwrap();
        let provider = Provider::with_crypto(
            crypto.clone(),
            SqliteStorageProvider::<MsgPack, _>::new(&*tx),
        );
        let joined = join_by_welcome(
            &provider,
            out.welcome.as_ref().unwrap(),
            None,
            &bob.expect(),
        )
        .unwrap();
        assert!(joined.last_resort);
        let id = joined.group.group_id().clone();
        drop(provider);
        tx.commit().unwrap();
        (id, joined.state)
    };

    // A commit in a transaction that is rolled back leaves nothing behind;
    // one that is committed is there next time, with its new leaf key.
    for keep in [false, true] {
        let tx = db.transaction().unwrap();
        let provider = Provider::with_crypto(
            crypto.clone(),
            SqliteStorageProvider::<MsgPack, _>::new(&*tx),
        );
        let mut b = MlsGroup::load(provider.storage(), &group_id)
            .unwrap()
            .unwrap();
        assert_eq!(b.epoch().as_u64(), 1);
        own_leaf_key(&provider, &b).unwrap();
        let out = commit(
            &provider,
            &mut b,
            &bob.profile(),
            &state,
            Changes {
                new_leaf_key: true,
                ..Changes::default()
            },
        )
        .unwrap();
        let mut next = state.clone();
        merge_own_commit(&provider, &mut b, &mut next).unwrap();
        let own = b.own_leaf_index();
        drop(provider);
        if keep {
            tx.commit().unwrap();
            state = next;
            assert_eq!(state.started_by, Some(own.u32()));
            alice.apply(&mut a, &out, &Facts::with(&[&alice, &bob]));
        } else {
            tx.rollback().unwrap();
        }
    }
    // The epoch's state round-trips through serde, as librisala keeps it.
    let json = serde_json_like(&state);
    assert!(!json.is_empty());
    let provider = Provider::with_crypto(crypto, SqliteStorageProvider::<MsgPack, _>::new(&db));
    let mut b = MlsGroup::load(provider.storage(), &group_id)
        .unwrap()
        .unwrap();
    assert_eq!(b.epoch().as_u64(), 2);
    let pseudonym = own_pseudonym::<()>(&b, provider.crypto()).unwrap();
    let aad = RisalaAad::application(pseudonym, [1; 48]);
    let message = encrypt_application(&provider, &mut b, &aad, b"from sqlite").unwrap();
    assert_eq!(alice.read(&mut a, &message).1, b"from sqlite");
}

/// The EpochState serialises, for librisala to keep with the group.
fn serde_json_like(state: &EpochState) -> Vec<u8> {
    let bytes = serde_json::to_vec(state).unwrap();
    let back: EpochState = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(&back, state);
    bytes
}
