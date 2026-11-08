//! Groups made with this crate, end to end, with in-memory storage:
//! KeyPackages and KEYPKG ADD's checks, direct conversations, private
//! rooms with roles, SelfRemove, competing commits, stale leaves, public
//! rooms joined by external commit, last-resort KeyPackages, and the
//! framing the server reads of each message.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, SystemTime};

use openmls::group::MlsGroup;
use openmls::prelude::{KeyPackage, LeafNodeIndex};
use openmls_memory_storage::MemoryStorage;
use openmls_traits::OpenMlsProvider as _;
use risala_proto::names::{Room, Uid};

use crate::aad::{Pseudonym, RisalaAad};
use crate::checks::{
    CommitError, Fact, JoinExpectation, KeyFacts, STALE_AFTER_MS, Verdict, needs_refresh,
};
use crate::conversation::{ConversationKind, GuestMode, RisalaConversation};
use crate::framing::{ContentType, MlsMessage, Sender, read_message, read_post};
use crate::group::*;
use crate::identity::{DeviceId, RisalaIdentity};
use crate::keypackage::{KeyPackageError, check_key_package, is_last_resort, make_key_package};
use crate::mldsa::{LeafKey, SigningKey};
use crate::profile::RisalaProfile;
use crate::token::SendToken;
use crate::wire::{to_bytes, tree_to_bytes};
use crate::{Provider, RisalaCrypto};

const HOST: &str = "chat.example.org";
const BOX: [u8; 16] = [0x42; 16];

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn uid(s: &str) -> Uid {
    s.parse().unwrap()
}

/// One device, with its own storage.
struct Device {
    uid: Uid,
    device_key: Option<SigningKey>,
    provider: Provider<MemoryStorage>,
    pseudonym: Pseudonym,
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
        RisalaProfile::new(self.uid.name(), now_ms()).unwrap()
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

    fn expect(&self) -> JoinExpectation {
        JoinExpectation {
            host: HOST.into(),
            own_uid: self.uid.clone(),
            public_room: None,
        }
    }

    fn create(&self, conversation: &RisalaConversation) -> MlsGroup {
        create_group(&self.provider, &self.identity(), &self.profile(), conversation)
            .unwrap()
            .0
    }

    fn commit(&self, group: &mut MlsGroup, changes: Changes) -> CommitOutput {
        commit(&self.provider, group, self.pseudonym, &self.profile(), changes).unwrap()
    }

    fn join(&self, welcome: &[u8]) -> MlsGroup {
        join_by_welcome(&self.provider, welcome, None, &self.expect())
            .unwrap()
            .group
    }

    /// Processes a commit and checks it, without applying it.
    fn receive(
        &self,
        group: &mut MlsGroup,
        message: &[u8],
        facts: &dyn KeyFacts,
    ) -> (Box<ReceivedCommit>, Result<Verdict, CommitError>) {
        let Incoming::Commit(received) =
            process_message(&self.provider, group, message).unwrap()
        else {
            panic!("not a commit");
        };
        let verdict = check_received_commit(
            group,
            &received,
            facts,
            self.provider.crypto(),
            SystemTime::now(),
        );
        (received, verdict)
    }

    /// Processes, checks and applies a commit that must be valid.
    fn apply(&self, group: &mut MlsGroup, message: &[u8], facts: &dyn KeyFacts) -> Verdict {
        let (received, verdict) = self.receive(group, message, facts);
        let verdict = verdict.unwrap();
        apply_commit(&self.provider, group, *received).unwrap();
        verdict
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
}

fn add(key_packages: Vec<KeyPackage>) -> Changes {
    Changes {
        add: key_packages,
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
    // The leaf key is the KeyPackage's own, never the device key (12.3),
    // and it is in storage.
    let leaf_key = kp.leaf_node().signature_key().as_slice().to_vec();
    assert_ne!(leaf_key, key);
    assert!(
        LeafKey::load(alice.provider.storage(), crate::mldsa::KEY_PACKAGE_SCOPE, &leaf_key)
            .unwrap()
            .is_some()
    );
    // Each KeyPackage has a leaf key of its own.
    let other = alice.key_package(false);
    assert_ne!(other.leaf_node().signature_key(), kp.leaf_node().signature_key());

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
    let out = alice.commit(&mut a, add(vec![bob.key_package(false), alice2.key_package(false)]));
    private_framing(&out.message, ContentType::Commit);
    let (framing, aad) = read_post(&out.message).unwrap();
    assert_eq!(framing.epoch, 0);
    assert_eq!(framing.group_id, a.group_id().as_slice());
    assert_eq!(aad, RisalaAad::handshake(alice.pseudonym));
    assert!(out.group_info.is_none());
    let welcome = out.welcome.unwrap();
    assert_eq!(read_message(&welcome), Ok(MlsMessage::Welcome));
    merge_own_commit(&alice.provider, &mut a).unwrap();
    // The next token hash is the new epoch's (7.2).
    let token = SendToken::of_group(&a, alice.provider.crypto()).unwrap();
    assert_eq!(out.next_token_hash, token.hash());

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
    assert_eq!(bob.read(&mut b, &message), (a.own_leaf_index(), b"hello bob".to_vec()));
    assert_eq!(alice2.read(&mut a2, &message).1, b"hello bob");
    let reply = bob.send(&mut b, b"hi");
    assert_eq!(alice.read(&mut a, &reply).1, b"hi");

    // A fresh-leaf commit by Bob (12.7) is valid for the others.
    let out = bob.commit(&mut b, Changes::default());
    merge_own_commit(&bob.provider, &mut b).unwrap();
    assert_eq!(alice.apply(&mut a, &out.message, &facts), Verdict::default());
    alice2.apply(&mut a2, &out.message, &facts);
    assert_eq!(
        SendToken::of_group(&a, alice.provider.crypto()).unwrap().hash(),
        out.next_token_hash
    );

    // Nobody else may be added to a direct conversation.
    let out = alice.commit(&mut a, add(vec![mallory.key_package(false)]));
    let (_, verdict) = bob.receive(&mut b, &out.message, &facts);
    assert_eq!(verdict, Err(CommitError::Add));
    discard_own_commit(&alice.provider, &mut a).unwrap();

    // Alice may not remove Bob's leaf unless his key file removed it. A
    // PrivateMessage decrypts once, so one processed commit is checked
    // against each set of facts.
    let bob_leaf = b.own_leaf_index();
    let remove_bob = Changes {
        remove: vec![bob_leaf],
        ..Changes::default()
    };
    let out = alice.commit(&mut a, remove_bob);
    let (received, verdict) = alice2.receive(&mut a2, &out.message, &facts);
    assert_eq!(verdict, Err(CommitError::Remove));
    let check = |facts: &dyn KeyFacts| {
        check_received_commit(
            &a2,
            &received,
            facts,
            alice2.provider.crypto(),
            SystemTime::now(),
        )
    };
    // Unknown, the removal stands with a warning (12.7).
    let unknown = Facts {
        unknown: true,
        ..Facts::default()
    };
    assert_eq!(check(&unknown).unwrap().unchecked_removals, vec![bob_leaf]);
    // Known removed, it is valid.
    let mut removed = Facts::with(&[&alice, &alice2, &bob]);
    removed.removed.insert((bob.uid.clone(), bob.device_id()));
    assert_eq!(check(&removed), Ok(Verdict::default()));
    apply_commit(&alice2.provider, &mut a2, *received).unwrap();
    merge_own_commit(&alice.provider, &mut a).unwrap();
    assert_eq!(a.members().count(), 2);
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
        Err(GroupError::Join(crate::checks::JoinError::WrongConversation))
    ));
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
    let owen = Device::new("owen@example.org", 1);
    let mia = Device::new("mia@example.org", 2);
    let pat = Device::new("pat@example.org", 3);
    let facts = Facts::with(&[&owen, &mia, &pat]);
    let mut conv = RisalaConversation::private_room(HOST, BOX, "Friends", &owen.uid);
    conv.mods.push(mia.uid.clone());
    let mut o = owen.create(&conv);
    let out = owen.commit(&mut o, add(vec![mia.key_package(false), pat.key_package(false)]));
    merge_own_commit(&owen.provider, &mut o).unwrap();
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
    facts.add(&quinn);

    // A plain member may not invite a new identity, or set the topic.
    let out = pat.commit(&mut p, add(vec![quinn.key_package(false)]));
    let (_, verdict) = owen.receive(&mut o, &out.message, &facts);
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
    let (_, verdict) = owen.receive(&mut o, &out.message, &facts);
    assert!(matches!(verdict, Err(CommitError::Extension(_))));
    discard_own_commit(&pat.provider, &mut p).unwrap();

    // A moderator may do both.
    let out = mia.commit(
        &mut m,
        Changes {
            add: vec![quinn.key_package(false)],
            conversation: Some(topic.clone()),
            ..Changes::default()
        },
    );
    merge_own_commit(&mia.provider, &mut m).unwrap();
    owen.apply(&mut o, &out.message, &facts);
    pat.apply(&mut p, &out.message, &facts);
    assert_eq!(conversation(&p).unwrap().topic, "new topic");
    let q = quinn.join(&out.welcome.unwrap());
    assert_eq!(q.members().count(), 4);

    // A moderator may not kick the owner; the owner may ban the moderator,
    // removing her leaf in the same commit.
    let owen_leaf = o.own_leaf_index();
    let mia_leaf = m.own_leaf_index();
    let out = mia.commit(
        &mut m,
        Changes {
            remove: vec![owen_leaf],
            ..Changes::default()
        },
    );
    let (_, verdict) = pat.receive(&mut p, &out.message, &facts);
    assert_eq!(verdict, Err(CommitError::Remove));
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
    let (_, verdict) = pat.receive(&mut p, &out.message, &facts);
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
    merge_own_commit(&owen.provider, &mut o).unwrap();
    pat.apply(&mut p, &out.message, &facts);
    assert!(conversation(&p).unwrap().bans.contains(&mia.uid));
    // Mia's device sees it was removed.
    let (received, verdict) = mia.receive(&mut m, &out.message, &facts);
    verdict.unwrap();
    assert!(!apply_commit(&mia.provider, &mut m, *received).unwrap());
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
        let Incoming::Proposal { aad } =
            process_message(&device.provider, group, &proposal).unwrap()
        else {
            panic!("not a proposal");
        };
        assert_eq!(aad.pseudonym, pat.pseudonym);
    }
    // Owen commits it, by reference, with his refresh.
    let out = owen.commit(&mut o, Changes::default());
    merge_own_commit(&owen.provider, &mut o).unwrap();
    assert!(o.members().all(|member| member.index != pat_leaf));
    mia.apply(&mut m, &out.message, &facts);
    assert_eq!(m.members().count(), 2);
    let (received, verdict) = pat.receive(&mut p, &out.message, &facts);
    verdict.unwrap();
    assert!(!apply_commit(&pat.provider, &mut p, *received).unwrap());

    // Removing someone else's leaf by value needs a reason: Mia may not
    // remove Owen's, nor may a member remove a moderator's.
    let out = mia.commit(
        &mut m,
        Changes {
            remove: vec![o.own_leaf_index()],
            ..Changes::default()
        },
    );
    let (_, verdict) = owen.receive(&mut o, &out.message, &facts);
    assert_eq!(verdict, Err(CommitError::Remove));
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
    pat.apply(&mut p, &first.message, &facts);
    assert!(process_message(&pat.provider, &mut p, &second.message).is_err());
    // Mia applies the winner, which drops her own pending commit.
    mia.apply(&mut m, &first.message, &facts);
    assert!(m.pending_commit().is_none());
    // Owen knows he won.
    merge_own_commit(&owen.provider, &mut o).unwrap();
    let token = SendToken::of_group(&o, owen.provider.crypto()).unwrap();
    assert_eq!(SendToken::of_group(&m, mia.provider.crypto()).unwrap(), token);
    assert_eq!(SendToken::of_group(&p, pat.provider.crypto()).unwrap(), token);
    assert_eq!(first.next_token_hash, token.hash());
    assert_ne!(second.next_token_hash, token.hash());
    // They all read each other in the new epoch.
    let message = mia.send(&mut m, b"after");
    assert_eq!(owen.read(&mut o, &message).1, b"after");
    assert_eq!(pat.read(&mut p, &message).1, b"after");
}

#[test]
fn stale_leaves() {
    let Room3 {
        owen,
        pat,
        mut o,
        mut p,
        facts,
        ..
    } = private_room();
    let owen_leaf = o.own_leaf_index();
    // Pat's refresh claims a time 36 days after Owen's leaf was updated:
    // Owen's leaf is stale for him, and he, a plain member, may remove it
    // (12.7).
    let later = now_ms() + STALE_AFTER_MS + 24 * 3600 * 1000;
    let profile = RisalaProfile::new("pat", later).unwrap();
    let view = crate::checks::GroupView::of(p.public_group());
    assert!(view.stale_leaves(later).contains(&owen_leaf));
    assert!(view.stale_leaves(now_ms()).is_empty());
    let out = commit(
        &pat.provider,
        &mut p,
        pat.pseudonym,
        &profile,
        Changes {
            remove: vec![owen_leaf],
            ..Changes::default()
        },
    )
    .unwrap();
    // Owen's own device checks the same commit: valid.
    let (_, verdict) = owen.receive(&mut o, &out.message, &facts);
    verdict.unwrap();

    // Without the time difference, the same removal is invalid.
    discard_own_commit(&pat.provider, &mut p).unwrap();
    let out = pat.commit(
        &mut p,
        Changes {
            remove: vec![owen_leaf],
            ..Changes::default()
        },
    );
    let (_, verdict) = owen.receive(&mut o, &out.message, &facts);
    assert_eq!(verdict, Err(CommitError::Remove));

    // The weekly refresh (12.7).
    let own = RisalaProfile::new("", now_ms() - 8 * 24 * 3600 * 1000).unwrap();
    assert!(needs_refresh(&own, now_ms()));
    assert!(!needs_refresh(&RisalaProfile::new("", now_ms()).unwrap(), now_ms()));
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
    merge_own_commit(&alice.provider, &mut a).unwrap();
    let mut c = carol.create(&RisalaConversation::direct(HOST, BOX, &carol.uid, &bob.uid));
    let out_c = carol.commit(&mut c, add(vec![last]));
    merge_own_commit(&carol.provider, &mut c).unwrap();

    let joined = join_by_welcome(&bob.provider, &out_a.welcome.unwrap(), None, &bob.expect())
        .unwrap();
    assert!(joined.last_resort);
    let mut b1 = joined.group;
    let joined = join_by_welcome(&bob.provider, &out_c.welcome.unwrap(), None, &bob.expect())
        .unwrap();
    assert!(joined.last_resort);
    let mut b2 = joined.group;
    // Both leaves share the leaf key, so Bob commits a new one in each
    // before he sends (12.3).
    let shared = b1.own_leaf_node().unwrap().signature_key().clone();
    assert_eq!(&shared, b2.own_leaf_node().unwrap().signature_key());
    let rotate = Changes {
        new_leaf_key: true,
        ..Changes::default()
    };
    let out = bob.commit(&mut b1, rotate.clone());
    merge_own_commit(&bob.provider, &mut b1).unwrap();
    assert_ne!(b1.own_leaf_node().unwrap().signature_key(), &shared);
    alice.apply(&mut a, &out.message, &facts);
    let message = bob.send(&mut b1, b"rotated");
    assert_eq!(alice.read(&mut a, &message).1, b"rotated");
    let out = bob.commit(&mut b2, rotate.clone());
    merge_own_commit(&bob.provider, &mut b2).unwrap();
    carol.apply(&mut c, &out.message, &facts);
    // Each group's copy of the shared key is gone; the last-resort
    // KeyPackage keeps its own.
    for group in [&b1, &b2] {
        assert!(
            LeafKey::load(bob.provider.storage(), group.group_id().as_slice(), shared.as_slice())
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
    let (_, verdict) = alice.receive(&mut a, &out.message, &facts);
    assert_eq!(verdict, Err(CommitError::Leaf));
}

/// A public room by Owen, with its GroupInfo and tree as the server holds
/// them.
fn public_room(guests: GuestMode) -> (Device, MlsGroup, Vec<u8>, Vec<u8>, RisalaConversation) {
    let owen = Device::new("owen@example.org", 1);
    let room: Room = "#general".parse().unwrap();
    let mut conv = RisalaConversation::public_room(HOST, BOX, &room, &owen.uid);
    conv.guests = guests;
    let o = owen.create(&conv);
    let (group_info, tree) = public_state(&owen, &o);
    (owen, o, group_info, tree, conv)
}

fn public_state(device: &Device, group: &MlsGroup) -> (Vec<u8>, Vec<u8>) {
    let leaf_key = own_leaf_key(&device.provider, group).unwrap();
    let group_info = group
        .export_group_info(device.provider.crypto(), &leaf_key, false)
        .unwrap();
    (to_bytes(&group_info), tree_to_bytes(&group.export_ratchet_tree()))
}

fn public_expect(device: &Device) -> JoinExpectation {
    JoinExpectation {
        host: HOST.into(),
        own_uid: device.uid.clone(),
        public_room: Some(("#general".parse().unwrap(), BOX)),
    }
}

#[test]
fn public_room_external_joins() {
    let (owen, mut o, group_info, tree, _) = public_room(GuestMode::Write);
    assert!(matches!(
        read_message(&group_info),
        Ok(MlsMessage::GroupInfo { epoch: 0, .. })
    ));
    let dave = Device::new("dave@example.org", 4);
    let mut facts = Facts::with(&[&owen]);

    let join = join_by_external_commit(
        &dave.provider,
        &dave.identity(),
        dave.device_key.as_ref(),
        &dave.profile(),
        dave.pseudonym,
        &group_info,
        &tree,
        &public_expect(&dave),
    )
    .unwrap();
    // A PublicMessage the server can check, from a new member (12.6).
    let (framing, aad) = read_post(&join.message).unwrap();
    assert!(!framing.private);
    assert_eq!(framing.sender, Some(Sender::NewMemberCommit));
    assert_eq!(framing.content_type, ContentType::Commit);
    assert_eq!(aad.pseudonym, dave.pseudonym);
    assert!(matches!(
        read_message(&join.group_info),
        Ok(MlsMessage::GroupInfo { epoch: 1, .. })
    ));
    assert!(join.earlier_leaves.is_empty());
    let mut d = join.group;
    assert_eq!(
        SendToken::of_group(&d, dave.provider.crypto()).unwrap().hash(),
        join.next_token_hash
    );

    // Before Dave's device is in the key log, the add is unchecked; with
    // another device's key it is invalid; with his, valid.
    let unknown = Facts {
        unknown: true,
        ..Facts::default()
    };
    let (_, verdict) = owen.receive(&mut o, &join.message, &unknown);
    assert_eq!(verdict.unwrap().unchecked_adds, vec![dave.identity()]);
    let (_, verdict) = owen.receive(&mut o, &join.message, &facts);
    assert_eq!(verdict, Err(CommitError::NotCurrentDevice));
    let mut wrong = Facts::with(&[&owen]);
    wrong.devices.insert(
        (dave.uid.clone(), dave.device_id()),
        SigningKey::from_seed([99; 32]).public_key().to_vec(),
    );
    let (_, verdict) = owen.receive(&mut o, &join.message, &wrong);
    assert_eq!(verdict, Err(CommitError::NotCurrentDevice));
    facts.add(&dave);
    owen.apply(&mut o, &join.message, &facts);
    assert_eq!(o.members().count(), 2);

    // Owen's commits are PublicMessages too, with a GroupInfo for the
    // server.
    let out = owen.commit(&mut o, Changes::default());
    let (framing, _) = read_post(&out.message).unwrap();
    assert!(!framing.private);
    assert!(matches!(framing.sender, Some(Sender::Member(_))));
    assert!(out.group_info.is_some());
    merge_own_commit(&owen.provider, &mut o).unwrap();
    dave.apply(&mut d, &out.message, &facts);
    // Application messages stay encrypted.
    let message = dave.send(&mut d, b"hi room");
    private_framing(&message, ContentType::Application);
    assert_eq!(owen.read(&mut o, &message).1, b"hi room");

    // A guest joins, without a binding.
    let (group_info, tree) = public_state(&owen, &o);
    let sam = Device::new("~sam", 0);
    let join = join_by_external_commit(
        &sam.provider,
        &sam.identity(),
        None,
        &sam.profile(),
        sam.pseudonym,
        &group_info,
        &tree,
        &public_expect(&sam),
    )
    .unwrap();
    owen.apply(&mut o, &join.message, &facts);
    dave.apply(&mut d, &join.message, &facts);
    assert_eq!(o.members().count(), 3);

    // Dave rejoins with a new leaf; his earlier one comes back to remove.
    let (group_info, tree) = public_state(&owen, &o);
    let dave_again = Device {
        uid: dave.uid.clone(),
        device_key: dave.device_key.clone(),
        provider: Provider::new(MemoryStorage::default()).unwrap(),
        pseudonym: Pseudonym::generate().unwrap(),
    };
    let join = join_by_external_commit(
        &dave_again.provider,
        &dave_again.identity(),
        dave_again.device_key.as_ref(),
        &dave_again.profile(),
        dave_again.pseudonym,
        &group_info,
        &tree,
        &public_expect(&dave_again),
    )
    .unwrap();
    assert_eq!(join.earlier_leaves, vec![d.own_leaf_index()]);
    owen.apply(&mut o, &join.message, &facts);
    let mut d2 = join.group;
    let out = dave_again.commit(
        &mut d2,
        Changes {
            remove: join.earlier_leaves.clone(),
            ..Changes::default()
        },
    );
    merge_own_commit(&dave_again.provider, &mut d2).unwrap();
    owen.apply(&mut o, &out.message, &facts);
    assert_eq!(o.members().count(), 3);
}

#[test]
fn public_room_refusals() {
    // Guests may not join a room whose guests are none.
    let (owen, mut o, group_info, tree, _) = public_room(GuestMode::None);
    let facts = Facts::with(&[&owen]);
    let sam = Device::new("~sam", 0);
    // Sam's own check refuses nothing (a guest-free room has no guests),
    // but the members refuse his commit.
    let join = join_by_external_commit(
        &sam.provider,
        &sam.identity(),
        None,
        &sam.profile(),
        sam.pseudonym,
        &group_info,
        &tree,
        &public_expect(&sam),
    )
    .unwrap();
    let (_, verdict) = owen.receive(&mut o, &join.message, &facts);
    assert_eq!(verdict, Err(CommitError::Add));

    // A device that expects another room does not join.
    let eve = Device::new("eve@example.org", 5);
    let mut expect = public_expect(&eve);
    expect.public_room = Some(("#other".parse().unwrap(), BOX));
    let err = join_by_external_commit(
        &eve.provider,
        &eve.identity(),
        eve.device_key.as_ref(),
        &eve.profile(),
        eve.pseudonym,
        &group_info,
        &tree,
        &expect,
    );
    assert!(matches!(
        err,
        Err(GroupError::Join(crate::checks::JoinError::WrongConversation))
    ));

    // A banned identity's external commit is refused.
    let mut banned = conversation(&o).unwrap();
    banned.bans.push(eve.uid.clone());
    owen.commit(
        &mut o,
        Changes {
            conversation: Some(banned),
            ..Changes::default()
        },
    );
    merge_own_commit(&owen.provider, &mut o).unwrap();
    let (group_info, tree) = public_state(&owen, &o);
    let err = join_by_external_commit(
        &eve.provider,
        &eve.identity(),
        eve.device_key.as_ref(),
        &eve.profile(),
        eve.pseudonym,
        &group_info,
        &tree,
        &public_expect(&eve),
    );
    // Her own device sees no reason to refuse (she has no leaf yet); the
    // members do.
    let join = err.unwrap();
    let facts = Facts::with(&[&owen, &eve]);
    let (_, verdict) = owen.receive(&mut o, &join.message, &facts);
    assert_eq!(verdict, Err(CommitError::Add));

    // External commits are refused outside public rooms.
    let alice = Device::new("alice@example.org", 1);
    let bob = Device::new("bob@example.org", 2);
    let conv = RisalaConversation::direct(HOST, BOX, &alice.uid, &bob.uid);
    assert_eq!(conv.kind, ConversationKind::Direct);
    let a = alice.create(&conv);
    let (group_info, tree) = public_state(&alice, &a);
    let join = join_by_external_commit(
        &bob.provider,
        &bob.identity(),
        bob.device_key.as_ref(),
        &bob.profile(),
        bob.pseudonym,
        &group_info,
        &tree,
        &bob.expect(),
    )
    .unwrap();
    let mut a = a;
    // OpenMLS refuses a PublicMessage commit in a pure-ciphertext group
    // already; the checks would refuse it too.
    assert!(process_message(&alice.provider, &mut a, &join.message).is_err());
}
