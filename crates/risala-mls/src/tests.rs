//! Groups made with this crate, end to end, with in-memory storage:
//! KeyPackages and KEYPKG ADD's checks, direct conversations, private
//! rooms with roles, SelfRemove, competing commits, `next`, streaks,
//! stale leaves, RESYNC, impostor repairs, mailbox moves, Update proposals,
//! public rooms joined by proposal, resync commits, last-resort
//! KeyPackages, sealed Welcomes, past epochs, and the framing the server
//! reads of each message.

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
    CommitError, CommitPost, Fact, History, JoinExpectation, KeyFacts, KeyReport, PERIOD_MS,
    UPDATED_SKEW_MS, Verdict, needs_refresh,
};
use crate::conversation::{ConfirmMode, ConversationKind, GuestMode, RisalaConversation};
use crate::framing::{ContentType, MlsMessage, Sender, read_message, read_post};
use crate::group::*;
use crate::identity::{DeviceId, RisalaIdentity};
use crate::keypackage::{
    KEY_PACKAGE_LIFETIME, KeyPackageError, check_key_package, has_no_binding, is_last_resort,
    leaf_binding, make_join_key_package_with, make_key_package, make_key_package_with,
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

/// One device, with its own storage, and the history of each of its
/// groups by group id.
struct Device {
    uid: Uid,
    device_key: Option<SigningKey>,
    provider: Provider<MemoryStorage>,
    pseudonym: Pseudonym,
    histories: RefCell<BTreeMap<Vec<u8>, History>>,
}

impl Device {
    fn new(uid_text: &str, seed: u8) -> Device {
        let uid = uid(uid_text);
        let device_key = (!uid.is_guest()).then(|| SigningKey::from_seed([seed; 32]));
        Device {
            uid,
            device_key,
            provider: Provider::new(MemoryStorage::default()).unwrap(),
            pseudonym: Pseudonym::generate().unwrap(),
            histories: RefCell::default(),
        }
    }

    /// Another device of the same identity, with the same device key: a
    /// device that joins again.
    fn again(&self) -> Device {
        Device {
            uid: self.uid.clone(),
            device_key: self.device_key.clone(),
            provider: Provider::new(MemoryStorage::default()).unwrap(),
            pseudonym: Pseudonym::generate().unwrap(),
            histories: RefCell::default(),
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

    fn history(&self, group: &MlsGroup) -> History {
        self.histories
            .borrow()
            .get(group.group_id().as_slice())
            .cloned()
            .unwrap_or_default()
    }

    fn set_history(&self, group: &MlsGroup, history: History) {
        self.histories
            .borrow_mut()
            .insert(group.group_id().as_slice().to_vec(), history);
    }

    fn create(&self, conversation: &RisalaConversation) -> MlsGroup {
        self.create_at(conversation, now_ms())
    }

    fn create_at(&self, conversation: &RisalaConversation, t: u64) -> MlsGroup {
        let (group, _, history) = create_group(
            &self.provider,
            &self.identity(),
            &self.profile_at(t),
            conversation,
            t,
        )
        .unwrap();
        self.set_history(&group, history);
        group
    }

    fn commit(&self, group: &mut MlsGroup, changes: Changes) -> CommitOutput {
        self.commit_at(group, changes, now_ms())
    }

    fn commit_at(&self, group: &mut MlsGroup, changes: Changes, updated: u64) -> CommitOutput {
        commit(
            &self.provider,
            group,
            self.pseudonym,
            &self.profile_at(updated),
            &self.history(group),
            changes,
        )
        .unwrap()
    }

    fn merge(&self, group: &mut MlsGroup, out: &CommitOutput) {
        self.merge_at(group, out, now_ms());
    }

    fn merge_at(&self, group: &mut MlsGroup, out: &CommitOutput, t: u64) {
        let mut history = self.history(group);
        merge_own_commit(&self.provider, group, &mut history, &post(out, t)).unwrap();
        self.set_history(group, history);
    }

    fn join(&self, welcome: &[u8]) -> MlsGroup {
        self.join_with_tree(welcome, None)
    }

    fn join_with_tree(&self, welcome: &[u8], tree: Option<&[u8]>) -> MlsGroup {
        let expect = match tree {
            Some(_) => public_expect(self),
            None => self.expect(),
        };
        let joined = join_by_welcome(&self.provider, welcome, tree, &expect, now_ms()).unwrap();
        self.set_history(&joined.group, joined.history);
        joined.group
    }

    /// Processes a commit and makes the group checks, without applying it.
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
        let verdict = check_received_commit(
            group,
            &received,
            &self.history(group),
            post,
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

    fn apply_received(
        &self,
        group: &mut MlsGroup,
        received: ReceivedCommit,
        verdict: &Verdict,
        post: &CommitPost,
    ) -> bool {
        let mut history = self.history(group);
        let active =
            apply_commit(&self.provider, group, received, verdict, &mut history, post).unwrap();
        self.set_history(group, history);
        active
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
        let report = check_received_keys(group, &received, &verdict, facts);
        self.apply_received(group, *received, &verdict, &post);
        (verdict, report)
    }

    fn apply(&self, group: &mut MlsGroup, out: &CommitOutput, facts: &dyn KeyFacts) -> Verdict {
        self.apply_at(group, out, facts, now_ms()).0
    }

    fn send(&self, group: &mut MlsGroup, text: &[u8]) -> Vec<u8> {
        let aad = RisalaAad::application(self.pseudonym, [7; 48]);
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

    /// Processes a proposal post, noting an Update's time.
    fn propose_in(&self, group: &mut MlsGroup, message: &[u8], t: u64) -> ProposalKind {
        let Incoming::Proposal {
            kind, reference, ..
        } = process_message(&self.provider, group, message).unwrap()
        else {
            panic!("not a proposal");
        };
        if kind == ProposalKind::Update {
            let mut history = self.history(group);
            history.note_update(&reference, t);
            self.set_history(group, history);
        }
        kind
    }
}

fn post(out: &CommitOutput, t: u64) -> CommitPost {
    CommitPost {
        t,
        next: Some(out.next_token_hash),
    }
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
    assert_eq!(aad, RisalaAad::handshake(alice.pseudonym));
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

    // Alice may remove Bob's leaf "for a key check" (12.7): the group
    // checks pass, and each device's key check decides whether to repair.
    let bob_leaf = b.own_leaf_index();
    let out = alice.commit(&mut a, remove(vec![bob_leaf]));
    let post = post(&out, now_ms());
    let (received, verdict) = alice2.receive_post(&mut a2, &out.message, &post);
    let verdict = verdict.unwrap();
    assert_eq!(verdict.key_check_removals, vec![bob_leaf]);
    assert!(!verdict.authority);
    // Bob's device is current: the key check fails, and the repair adds it
    // back.
    let report = check_received_keys(&a2, &received, &verdict, &facts);
    assert_eq!(report.failed_removals, vec![bob.identity()]);
    // Unknown: the removal stands with a warning.
    let unknown = Facts {
        unknown: true,
        ..Facts::default()
    };
    let report = check_received_keys(&a2, &received, &verdict, &unknown);
    assert_eq!(report.unchecked_removals, vec![bob_leaf]);
    assert!(report.committer_unchecked);
    // Known removed by record: nothing to repair.
    let mut removed = Facts::with(&[&alice, &alice2, &bob]);
    removed.removed.insert((bob.uid.clone(), bob.device_id()));
    assert_eq!(
        check_received_keys(&a2, &received, &verdict, &removed),
        KeyReport::default()
    );
    alice2.apply_received(&mut a2, *received, &verdict, &post);
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
    let wrong = CommitPost {
        t,
        next: Some([9; 48]),
    };
    let none = CommitPost { t, next: None };
    for post in [wrong, none] {
        assert_eq!(
            check_received_commit(
                &b,
                &received,
                &bob.history(&b),
                &post,
                bob.provider.crypto()
            ),
            Err(CommitError::NextToken)
        );
    }
    // `updated` more than 10 minutes from the post's `t` (12.3).
    let far = CommitPost {
        t: t + UPDATED_SKEW_MS + 60_000,
        next: Some(out.next_token_hash),
    };
    assert_eq!(
        check_received_commit(&b, &received, &bob.history(&b), &far, bob.provider.crypto()),
        Err(CommitError::Updated)
    );
    bob.apply_received(&mut b, *received, &Verdict::default(), &post(&out, t));
    alice.merge(&mut a, &out);
    // `updated` below the leaf's previous one.
    let out = alice.commit(&mut a, Changes::default());
    discard_own_commit(&alice.provider, &mut a).unwrap();
    let history = alice.history(&a);
    let back = commit(
        &alice.provider,
        &mut a,
        alice.pseudonym,
        &alice.profile_at(t - 60_000),
        &history,
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
    assert_eq!(bob.history(&b).started_by, Some(a.own_leaf_index().u32()));
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
    let err = join_by_welcome(
        &bob.provider,
        &out.welcome.unwrap(),
        None,
        &bob.expect(),
        now_ms(),
    );
    assert!(matches!(
        err,
        Err(GroupError::Join(crate::checks::JoinError::NotAParticipant))
    ));

    // A Welcome for a group on another server is refused too.
    let conv = RisalaConversation::direct("other.example", BOX, &alice.uid, &bob.uid);
    let mut a = alice.create(&conv);
    let out = alice.commit(&mut a, add(vec![bob.key_package(false)]));
    let err = join_by_welcome(
        &bob.provider,
        &out.welcome.unwrap(),
        None,
        &bob.expect(),
        now_ms(),
    );
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
    // Owen, who saw every commit since the start, refuses it; Pat, who
    // joined since, cannot tell whether Rhea had a leaf in the last 16
    // epochs, and applies it (12.7).
    let (_, verdict) = owen.receive(&mut o, &out);
    assert_eq!(verdict, Err(CommitError::Add));
    let (_, verdict) = pat.receive(&mut p, &out);
    assert_eq!(
        verdict.unwrap().unchecked,
        vec!["adding back a device of the last 16 epochs"]
    );
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
    // Owen's last commit, which changed `mods`, was an authority commit
    // within 24 hours, so any member may remove his leaf as an impostor
    // repair (12.7); devices that confirmed his leaf tell their users.
    assert_eq!(verdict.repairs, vec![owen_leaf]);
    assert!(verdict.key_check_removals.is_empty());
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
    assert!(verdict.key_check_removals.is_empty() && verdict.authority);
    assert!(conversation(&p).unwrap().bans.contains(&mia.uid));
    // Mia's device sees it was removed.
    let (received, verdict) = mia.receive(&mut m, &out);
    assert!(!mia.apply_received(&mut m, *received, &verdict.unwrap(), &post(&out, now_ms())));
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
    let proposal = self_remove(&pat.provider, &mut p, pat.pseudonym).unwrap();
    private_framing(&proposal, ContentType::Proposal);
    for (device, group) in [(&owen, &mut o), (&mia, &mut m)] {
        let Incoming::Proposal {
            aad, kind, sender, ..
        } = process_message(&device.provider, group, &proposal).unwrap()
        else {
            panic!("not a proposal");
        };
        assert_eq!(aad.pseudonym, Some(pat.pseudonym));
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
    assert!(!pat.apply_received(&mut p, *received, &verdict.unwrap(), &post(&out, now_ms())));
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
    let proposal = self_remove(&owen.provider, &mut o, owen.pseudonym).unwrap();
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
    let view = crate::checks::GroupView::of(p.public_group());
    assert_eq!(view.median_updated(), Some(now));
    assert_eq!(view.stale_leaves(), vec![o.own_leaf_index()]);
    assert_eq!(view.max_stale_removals(), 1);
    // Pat, a plain member, removes Owen's leaf as stale: a group reason,
    // not a key check.
    let owen_leaf = o.own_leaf_index();
    let out = pat.commit(&mut p, remove(vec![owen_leaf]));
    let verdict = mia.receive(&mut m, &out).1.unwrap();
    assert!(verdict.key_check_removals.is_empty());
    discard_own_commit(&pat.provider, &mut p).unwrap();
    // Mia's leaf is not stale: removing it is a key-check removal.
    let mia_leaf = m.own_leaf_index();
    let out = pat.commit(&mut p, remove(vec![mia_leaf]));
    let verdict = owen.receive(&mut o, &out).1.unwrap();
    assert_eq!(verdict.key_check_removals, vec![mia_leaf]);

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
            &crate::checks::GroupView::of(b.public_group()),
            &view,
            &bob.history(&b),
            &CommitPost {
                t: now_ms(),
                next: Some(out.next_token_hash)
            },
        ),
        Err(CommitError::KeyPackage(KeyPackageError::Lifetime))
    );
    bob.apply_received(&mut b, *received, &Verdict::default(), &post(&out, then));
    alice.merge_at(&mut a, &out, then);
    // Carol joins, though her leaf's lifetime is over (12.5).
    let c = carol.join(out.welcome.as_ref().unwrap());
    assert_eq!(c.members().count(), 3);
}

/// RESYNC (12.7): a leaf that posted RESYNC in the last 16 epochs may be
/// removed by anyone together with an Add of the same device.
#[test]
fn resync_lines() {
    let Room3 {
        owen,
        mia,
        pat,
        mut o,
        m,
        mut p,
        facts,
    } = private_room();
    // Mia's device could not process a commit, and posts RESYNC. Pat, a
    // plain member, replaces her leaf.
    let mia_leaf = m.own_leaf_index();
    let replace = |group: &mut MlsGroup| {
        pat.commit(
            group,
            Changes {
                remove: vec![mia_leaf],
                add: vec![mia.again().key_package(false)],
                ..Changes::default()
            },
        )
    };
    // Without a RESYNC, the removal is one for a key check.
    let out = replace(&mut p);
    let verdict = owen.receive(&mut o, &out).1.unwrap();
    assert_eq!(verdict.key_check_removals, vec![mia_leaf]);
    discard_own_commit(&pat.provider, &mut p).unwrap();
    // With RESYNC noted in this epoch, it is a group reason.
    for (device, group) in [(&owen, &o), (&pat, &p)] {
        let mut history = device.history(group);
        history.note_resync(mia_leaf, group.epoch().as_u64());
        device.set_history(group, history);
    }
    let out = replace(&mut p);
    let (received, verdict) = owen.receive(&mut o, &out);
    let verdict = verdict.unwrap();
    assert!(verdict.key_check_removals.is_empty());
    // Its key check has nothing to repair: the device is back.
    assert_eq!(
        check_received_keys(&o, &received, &verdict, &facts),
        KeyReport::default()
    );
}

/// An impostor repair (12.7): any member removes a leaf of another
/// identity, puts back the fields its commits changed, and adds back the
/// devices they removed.
#[test]
fn impostor_repairs() {
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
    // Pat, a plain member, repairs: removes Mia's leaf, puts the topic
    // back, and adds Quinn back.
    let mia_leaf = m.own_leaf_index();
    let mut back = conversation(&p).unwrap();
    back.topic = String::new();
    let repair = Changes {
        remove: vec![mia_leaf],
        add: vec![quinn.key_package(false)],
        conversation: Some(back.clone()),
        ..Changes::default()
    };
    let out = pat.commit(&mut p, repair);
    let verdict = owen.receive(&mut o, &out).1.unwrap();
    assert_eq!(verdict.repairs, vec![mia_leaf]);
    assert!(verdict.authority);
    discard_own_commit(&pat.provider, &mut p).unwrap();
    // Without the removal, the same changes are not Pat's to make.
    let out = pat.commit(
        &mut p,
        Changes {
            add: vec![quinn.key_package(false)],
            conversation: Some(back.clone()),
            ..Changes::default()
        },
    );
    assert!(owen.receive(&mut o, &out).1.is_err());
    discard_own_commit(&pat.provider, &mut p).unwrap();
    // Nor may a repair change a field the impostor did not.
    let mut other = back.clone();
    other.name = "Ours".into();
    let out = pat.commit(
        &mut p,
        Changes {
            remove: vec![mia_leaf],
            conversation: Some(other),
            ..Changes::default()
        },
    );
    assert!(matches!(
        owen.receive(&mut o, &out).1,
        Err(CommitError::Extension(_))
    ));
}

/// Moving the mailbox (7.8): any member, a commit that changes `box`
/// alone.
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
    let out = pat.commit(
        &mut p,
        Changes {
            move_box: Some([0x77; 16]),
            ..Changes::default()
        },
    );
    pat.merge(&mut p, &out);
    let verdict = owen.apply(&mut o, &out, &facts);
    assert!(!verdict.authority);
    assert_eq!(conversation(&o).unwrap().mailbox, [0x77; 16]);
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
    assert!(propose_update(&pat.provider, &mut p, pat.pseudonym, &pat.profile(), None).is_err());
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
        pat.pseudonym,
        &pat.profile_at(next_day),
        Some(&new_key),
    )
    .unwrap();
    private_framing(&update.message, ContentType::Proposal);
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
        pat.pseudonym,
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
    let last = bob.key_package(true);
    assert_eq!(is_last_resort(&last), Ok(true));

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
        now_ms(),
    )
    .unwrap();
    assert!(joined.last_resort);
    let mut b1 = joined.group;
    bob.set_history(&b1, joined.history);
    let joined = join_by_welcome(
        &bob.provider,
        out_c.welcome.as_ref().unwrap(),
        None,
        &bob.expect(),
        now_ms(),
    )
    .unwrap();
    assert!(joined.last_resort);
    let mut b2 = joined.group;
    bob.set_history(&b2, joined.history);
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
    let history = sam.history(&s);
    let out = commit(
        &sam.provider,
        &mut s,
        sam.pseudonym,
        &sam.profile(),
        &history,
        Changes::default(),
    )
    .unwrap();
    let (_, verdict) = owen.receive(&mut o, &out);
    assert_eq!(verdict, Err(CommitError::Guest));
    // Nobody adds a device to a public room by value (6.1).
    let erin = Device::new("erin@example.org", 5);
    let history = owen.history(&o);
    assert!(
        commit(
            &owen.provider,
            &mut o,
            owen.pseudonym,
            &owen.profile(),
            &history,
            add(vec![erin.key_package(false)])
        )
        .is_err()
    );
}

/// A public room's earlier leaf of a device that joined again may be
/// removed once inactive for 48 hours (12.7).
#[test]
fn public_room_inactive_leaves() {
    let (owen, mut o, _) = public_room(GuestMode::Write);
    let dave = Device::new("dave@example.org", 4);
    let facts = Facts::default();
    let d = join_room(&dave, (&owen, &mut o), vec![], &facts);
    let dave_leaf = d.own_leaf_index();
    let dave2 = dave.again();
    let d2 = join_room(&dave2, (&owen, &mut o), vec![], &facts);
    assert_eq!(d2.members().count(), 3);
    // Owen removes Dave's earlier leaf: not while it is active. The server,
    // which saw every commit, refuses it; so does Owen's own history.
    let check_as_owen = |o: &MlsGroup, out: &CommitOutput, t: u64| {
        let view = crate::checks::GroupView::of(o.public_group());
        let staged = o.pending_commit().unwrap();
        let commit_view = crate::checks::CommitView::of(
            &openmls::prelude::Sender::Member(o.own_leaf_index()),
            staged,
            o.pending_proposals(),
        );
        crate::checks::check_commit(&view, &commit_view, &owen.history(o), &post(out, t))
    };
    let out = owen.commit(&mut o, remove(vec![dave_leaf]));
    assert_eq!(check_as_owen(&o, &out, now_ms()), Err(CommitError::Remove));
    // Dave's second device joined since, and cannot rule out a resync in
    // the last 24 hours that Dave's first leaf did not follow: it applies
    // the commit (12.7).
    let mut d2 = d2;
    let (_, verdict) = dave2.receive(&mut d2, &out);
    assert_eq!(verdict.unwrap().unchecked, vec!["a removal after a resync"]);
    discard_own_commit(&owen.provider, &mut o).unwrap();
    // 49 hours later, it is inactive, for everyone.
    let later = now_ms() + 49 * HOUR;
    let out = owen.commit_at(&mut o, remove(vec![dave_leaf]), later);
    assert_eq!(
        check_as_owen(&o, &out, later).unwrap().unchecked,
        Vec::<&str>::new()
    );
    let (_, verdict) = dave2.receive_post(&mut d2, &out.message, &post(&out, later));
    assert_eq!(verdict.unwrap().unchecked, Vec::<&str>::new());
}

/// A resync commit (12.7): after the server accepted a commit that the
/// devices hold invalid, one device rejoins by external commit, removing
/// the committer.
#[test]
fn public_room_resync() {
    let (owen, mut o, _) = public_room(GuestMode::Write);
    let dave = Device::new("dave@example.org", 4);
    let erin = Device::new("erin@example.org", 5);
    let facts = Facts::default();
    let mut d = join_room(&dave, (&owen, &mut o), vec![], &facts);
    let mut e = join_room(&erin, (&owen, &mut o), vec![(&dave, &mut d)], &facts);
    let crypto = RisalaCrypto::new().unwrap();
    // The server holds the room's public state and its history.
    let (group_info, tree) = public_state(&owen, &o);
    let storage = MemoryStorage::default();
    let mut server = public_group(&crypto, &storage, &group_info, &tree).unwrap();
    let mut server_history = owen.history(&o);

    // Dave commits with a wrong `next`. The server cannot tell, and
    // accepts it; Owen and Erin refuse it.
    let mut bad = dave.commit(&mut d, Changes::default());
    let right = bad.next_token_hash;
    bad.next_token_hash = [0; 48];
    for (device, group) in [(&owen, &mut o), (&erin, &mut e)] {
        let (_, verdict) = device.receive(group, &bad);
        assert_eq!(verdict, Err(CommitError::NextToken));
    }
    let server_sees =
        |server: &mut PublicGroup, history: &mut History, out: &[u8], post: &CommitPost| {
            use openmls::prelude::ProcessedMessageContent;
            let processed = server
                .process_message(&crypto, crate::wire::read_protocol_message(out).unwrap())
                .unwrap();
            let sender = processed.sender().clone();
            let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content()
            else {
                panic!("not a commit");
            };
            let before = crate::checks::GroupView::of(server);
            let view = crate::checks::CommitView::of(&sender, &staged, std::iter::empty());
            let verdict = crate::checks::check_commit(&before, &view, history, post).unwrap();
            server.merge_commit(&storage, *staged).unwrap();
            let after = crate::checks::GroupView::of(server);
            history.record(&before, &view, &verdict, &after, post);
            verdict
        };
    let t = now_ms();
    server_sees(
        &mut server,
        &mut server_history,
        &bad.message,
        &post(&bad, t),
    );
    dave.merge_at(&mut d, &bad, t);
    assert_ne!(right, [0; 48]);

    // Erin resyncs from the server's GroupInfo, signed by Dave, after
    // checking that the server changed no roles or settings (12.7).
    let dave_leaf = d.own_leaf_index();
    let owen_leaf = o.own_leaf_index();
    let group_info = bad.group_info.clone().unwrap();
    let tree = tree_to_bytes(&server.export_ratchet_tree());
    let kept = conversation(&e).unwrap();
    let scratch = MemoryStorage::default();
    let theirs =
        crate::checks::GroupView::of(&public_group(&crypto, &scratch, &group_info, &tree).unwrap())
            .conversation
            .unwrap();
    assert!(kept.unexplained_changes(&theirs).is_empty());
    let erin2 = erin.again();
    let resync = resync_public_room(
        &erin2.provider,
        &erin.identity(),
        &erin.profile_at(t),
        &group_info,
        &tree,
        &public_expect(&erin),
        &[],
        t,
    )
    .unwrap();
    let (framing, aad) = read_post(&resync.message).unwrap();
    assert_eq!(framing.sender, Some(Sender::NewMemberCommit));
    assert_eq!(aad, RisalaAad::public());
    let resync_post = CommitPost {
        t,
        next: Some(resync.next_token_hash),
    };
    // The server checks it as a resync commit, which removes Dave.
    let verdict = server_sees(
        &mut server,
        &mut server_history,
        &resync.message,
        &resync_post,
    );
    assert!(verdict.resync);
    let dave_identity = dave.identity();
    let server_view = crate::checks::GroupView::of(&server);
    assert!(server_view.leaf(dave_leaf).is_some());
    assert!(
        server_view
            .leaves
            .iter()
            .all(|leaf| leaf.identity.as_ref() != Some(&dave_identity))
    );
    // Dave's device, which applied its own commit, sees that it was
    // removed.
    let (received, verdict) = dave.receive_post(&mut d, &resync.message, &resync_post);
    let verdict = verdict.unwrap();
    assert!(verdict.resync);
    assert!(!dave.apply_received(&mut d, *received, &verdict, &resync_post));

    // Within 24 hours, Erin's new leaf, a plain member's, may remove
    // Owen's, which could not follow: it has neither committed nor been
    // added since the resync commit. A day later it may not.
    let mut r = resync.group;
    erin2.set_history(&r, resync.history);
    for (when, ok) in [(t + HOUR, true), (t + 25 * HOUR, false)] {
        let out = erin2.commit_at(&mut r, remove(vec![owen_leaf]), when);
        let processed = server
            .process_message(
                &crypto,
                crate::wire::read_protocol_message(&out.message).unwrap(),
            )
            .unwrap();
        let sender = processed.sender().clone();
        let openmls::prelude::ProcessedMessageContent::StagedCommitMessage(staged) =
            processed.into_content()
        else {
            panic!("not a commit");
        };
        let view = crate::checks::CommitView::of(&sender, &staged, std::iter::empty());
        let verdict = crate::checks::check_commit(
            &crate::checks::GroupView::of(&server),
            &view,
            &server_history,
            &post(&out, when),
        );
        assert_eq!(verdict.is_ok(), ok, "{verdict:?}");
        discard_own_commit(&erin2.provider, &mut r).unwrap();
    }
    // An external commit that is not a resync, here by an identity with no
    // leaf, is refused.
    let (group_info, tree) = public_state(&erin2, &r);
    let frank = Device::new("frank@example.org", 6);
    let join = resync_public_room(
        &frank.provider,
        &frank.identity(),
        &frank.profile(),
        &group_info,
        &tree,
        &public_expect(&frank),
        &[],
        t,
    )
    .unwrap();
    let mut owen_view = server_history.clone();
    owen_view.since_epoch = 0;
    let processed = server.process_message(
        &crypto,
        crate::wire::read_protocol_message(&join.message).unwrap(),
    );
    // The server's group is an epoch behind Erin's own (her commits above
    // were discarded), so it may not process it; check from Erin's side.
    drop(processed);
    let (_, verdict) = erin2.receive_post(
        &mut r,
        &join.message,
        &CommitPost {
            t,
            next: Some(join.next_token_hash),
        },
    );
    assert_eq!(verdict, Err(CommitError::External));
    let _ = (owen_view, &owen);
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
    let mut history = owen.history(&o);

    let mut d = dave.join_with_tree(
        out.welcome.as_ref().unwrap(),
        Some(&tree_to_bytes(&o.export_ratchet_tree())),
    );
    let server_sees =
        |public: &PublicGroup, message: &[u8], history: &History, post: &CommitPost| {
            let processed = public
                .process_message(&crypto, read_protocol_message(message).unwrap())
                .unwrap();
            let sender = processed.sender().clone();
            let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content()
            else {
                panic!("not a commit");
            };
            let view = CommitView::of(&sender, &staged, std::iter::empty());
            let verdict = check_commit(&GroupView::of(public), &view, history, post);
            (staged, view, verdict)
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
    let (_, _, verdict) = server_sees(&public, &out.message, &history, &post(&out, now_ms()));
    assert!(matches!(verdict, Err(CommitError::Extension(_))));
    discard_own_commit(&dave.provider, &mut d).unwrap();
    // Dave's refresh is fine, and the server keeps the new state.
    let out = dave.commit(&mut d, Changes::default());
    let t = now_ms();
    let before = GroupView::of(&public);
    let (staged, view, verdict) = server_sees(&public, &out.message, &history, &post(&out, t));
    let verdict = verdict.unwrap();
    public.merge_commit(&storage, *staged).unwrap();
    history.record(
        &before,
        &view,
        &verdict,
        &GroupView::of(&public),
        &post(&out, t),
    );
    dave.merge(&mut d, &out);
    owen.apply(&mut o, &out, &Facts::default());
    assert_eq!(
        tree_to_bytes(&public.export_ratchet_tree()),
        tree_to_bytes(&o.export_ratchet_tree())
    );
    assert_eq!(history.started_by, Some(d.own_leaf_index().u32()));
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

    let (group_id, mut history) = {
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
            now_ms(),
        )
        .unwrap();
        assert!(joined.last_resort);
        let id = joined.group.group_id().clone();
        drop(provider);
        tx.commit().unwrap();
        (id, joined.history)
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
            bob.pseudonym,
            &bob.profile(),
            &history,
            Changes {
                new_leaf_key: true,
                ..Changes::default()
            },
        )
        .unwrap();
        let mut h = history.clone();
        merge_own_commit(&provider, &mut b, &mut h, &post(&out, now_ms())).unwrap();
        drop(provider);
        if keep {
            tx.commit().unwrap();
            history = h;
            alice.apply(&mut a, &out, &Facts::with(&[&alice, &bob]));
        } else {
            tx.rollback().unwrap();
        }
    }
    assert_eq!(history.commits.len(), 1);
    // The history round-trips through serde, as librisala keeps it.
    let json = serde_json_like(&history);
    assert!(!json.is_empty());
    let provider = Provider::with_crypto(crypto, SqliteStorageProvider::<MsgPack, _>::new(&db));
    let mut b = MlsGroup::load(provider.storage(), &group_id)
        .unwrap()
        .unwrap();
    assert_eq!(b.epoch().as_u64(), 2);
    let aad = RisalaAad::application(bob.pseudonym, [1; 48]);
    let message = encrypt_application(&provider, &mut b, &aad, b"from sqlite").unwrap();
    assert_eq!(alice.read(&mut a, &message).1, b"from sqlite");
}

/// The History serialises, for librisala to keep with the group.
fn serde_json_like(history: &History) -> Vec<u8> {
    let bytes = serde_json::to_vec(history).unwrap();
    let back: History = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(&back, history);
    bytes
}
