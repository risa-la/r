//! Groups made with this crate's provider, end to end: INIT, KEYPKG ADD,
//! COMMIT with a Welcome, joining, ENC both ways, external commits, a
//! change of settings, and the SQLite storage on a transaction.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use openmls::group::MlsGroup;
use openmls::prelude::{
    KeyPackage, Lifetime, ProcessedMessageContent, ProtocolMessage, StagedCommit,
};
use openmls_memory_storage::MemoryStorage;
use openmls_traits::OpenMlsProvider;
use risala_proto::auth::{PublicKey, SecretKey};
use risala_proto::mls;
use risala_proto::names::{Id, Uid};
use risala_proto::types::{HistoryMode, SendMode};

use crate::group::{KEY_PACKAGE_LIFETIME, MAX_LIFETIME_SPAN, capabilities};
use crate::signer::signature_key;
use crate::wire::*;
use crate::*;

struct Device {
    uid: Uid,
    key: SecretKey,
    provider: Provider<MemoryStorage>,
}

impl Device {
    fn new(uid: &str, seed: u8) -> Device {
        Device {
            uid: uid.parse().unwrap(),
            key: SecretKey::from_seed([seed; 32]),
            provider: Provider::new(MemoryStorage::default()).unwrap(),
        }
    }

    fn signer(&self) -> DeviceSigner<'_> {
        DeviceSigner::new(&self.key)
    }

    /// A KeyPackage as KEYPKG ADD sends it.
    fn key_package(&self, last_resort: bool) -> mls::KeyPackage {
        let bundle = key_package(&self.provider, &self.signer(), &self.uid, last_resort).unwrap();
        key_package_to_wire(bundle.key_package()).unwrap()
    }

    /// The KeyPackage as the server hands it out, after its checks.
    fn checked_key_package(&self) -> KeyPackage {
        let crypto = RisalaCrypto::new().unwrap();
        check_key_package(
            &crypto,
            &self.key_package(false),
            &self.uid,
            &self.key.public_key(),
            SystemTime::now(),
        )
        .unwrap()
        .key_package
    }

    /// Applies a COMMIT event, checking the next epoch's history key before
    /// merging (12.9).
    fn apply(&self, group: &mut MlsGroup, commit: &mls::CommitMessage) -> HistoryKey {
        let message: ProtocolMessage = commit_from_wire(commit).unwrap();
        let processed = group.process_message(&self.provider, message).unwrap();
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            panic!("not a commit");
        };
        let staged: StagedCommit = *staged;
        let next = HistoryKey::of_staged_commit(&staged, self.provider.crypto()).unwrap();
        group.merge_staged_commit(&self.provider, staged).unwrap();
        assert_eq!(
            HistoryKey::of_group(group, self.provider.crypto()).unwrap(),
            next
        );
        next
    }

    /// The signature keys of a group's leaves.
    fn leaf_keys(group: &MlsGroup) -> Vec<PublicKey> {
        group
            .members()
            .map(|m| signature_key(&m.signature_key).unwrap())
            .collect()
    }
}

/// What a device sends with COMMIT.
struct Sent {
    commit: mls::CommitMessage,
    group_info: mls::GroupInfo,
    welcome: Option<mls::Welcome>,
}

fn commit_lines(device: &Device, group: &mut MlsGroup, changes: Changes) -> Sent {
    let bundle = commit(&device.provider, group, &device.signer(), changes).unwrap();
    let (commit, welcome, group_info) = bundle.into_messages();
    Sent {
        commit: commit_to_wire(&commit).unwrap(),
        group_info: group_info_to_wire(&group_info.expect("a GroupInfo with every commit"))
            .unwrap(),
        welcome: welcome.map(|w| welcome_to_wire(&w).unwrap()),
    }
}

/// The GroupInfo has `external_pub` and no `ratchet_tree` (12.5).
fn check_group_info(value: &mls::GroupInfo) {
    let group_info = group_info_from_wire(value).unwrap();
    assert!(group_info.extensions().external_pub().is_some());
    assert!(group_info.extensions().ratchet_tree().is_none());
}

fn send(device: &Device, group: &MlsGroup, key: &HistoryKey, text: &[u8]) -> Encrypted {
    encrypt(
        &device.signer(),
        key,
        group.group_id().as_slice(),
        group.epoch().as_u64(),
        text,
    )
    .unwrap()
}

/// Decrypts as a device that was in the group: the sender is a leaf.
fn receive(group: &MlsGroup, key: &HistoryKey, sent: &Encrypted) -> Message {
    let unverified = decrypt(
        key,
        group.group_id().as_slice(),
        group.epoch().as_u64(),
        &sent.payload,
        &sent.frank,
    )
    .unwrap();
    let leaves = Device::leaf_keys(group);
    let sender = unverified.find_sender(&leaves).unwrap().clone();
    unverified.verify(&sender).unwrap()
}

#[test]
fn two_devices_in_a_direct_conversation() {
    let alice = Device::new("alice@example.org", 1);
    let bob = Device::new("bob@example.net", 2);
    let conversation = RisalaConversation::direct(&alice.uid, &bob.uid);

    // INIT: a group with Alice's device alone, its GroupInfo and tree.
    let mut a = create_group(&alice.provider, &alice.signer(), &alice.uid, &conversation).unwrap();
    assert_eq!(a.group_id().as_slice().len(), 32);
    assert_eq!(a.epoch().as_u64(), 0);
    assert_eq!(a.ciphersuite(), CIPHERSUITE);
    let init_info = group_info_to_wire(
        &a.export_group_info(alice.provider.crypto(), &alice.signer(), false)
            .unwrap(),
    )
    .unwrap();
    check_group_info(&init_info);
    let init_tree = tree_to_wire(&a.export_ratchet_tree()).unwrap();
    assert!(tree_from_wire(&init_tree).is_ok());
    assert_eq!(
        RisalaConversation::from_extensions(a.extensions()),
        Ok(conversation.clone())
    );
    let epoch0 = HistoryKey::of_group(&a, alice.provider.crypto()).unwrap();

    // Alice adds Bob's device with a KeyPackage from KEYPKG GET.
    let sent = commit_lines(
        &alice,
        &mut a,
        Changes {
            add: vec![bob.checked_key_package()],
            ..Changes::default()
        },
    );
    check_group_info(&sent.group_info);
    let welcome = sent.welcome.expect("a commit that adds has a Welcome");
    // The server accepts it; Alice merges.
    a.merge_pending_commit(&alice.provider).unwrap();
    assert_eq!(a.epoch().as_u64(), 1);
    let epoch1 = HistoryKey::of_group(&a, alice.provider.crypto()).unwrap();
    assert_ne!(epoch0, epoch1);

    // Bob joins from the WELCOME line, with the tree the server attaches,
    // and checks the group (12.6) before he goes in.
    let tree = tree_to_wire(&a.export_ratchet_tree()).unwrap();
    let staged = stage_welcome(
        &bob.provider,
        welcome_from_wire(&welcome).unwrap(),
        tree_from_wire(&tree).unwrap(),
    )
    .unwrap();
    assert_eq!(
        RisalaConversation::from_extensions(staged.group_context().extensions()),
        Ok(conversation.clone())
    );
    assert!(conversation.is_direct(&bob.uid, &alice.uid));
    let uids: Vec<String> = staged
        .members()
        .map(|m| signer::credential_uid(&m.credential).unwrap())
        .collect();
    assert_eq!(uids, ["alice@example.org", "bob@example.net"]);
    let joined = HistoryKey::of_staged_welcome(&staged, bob.provider.crypto()).unwrap();
    assert_eq!(joined, epoch1);
    let mut b = staged.into_group(&bob.provider).unwrap();
    assert_eq!(
        HistoryKey::of_group(&b, bob.provider.crypto()).unwrap(),
        epoch1
    );

    // ENC both ways.
    let hello = send(&alice, &a, &epoch1, b"TEXT hello bob\n");
    let got = receive(&b, &epoch1, &hello);
    assert_eq!(got.content, b"TEXT hello bob\n");
    assert_eq!(got.sender, Some(alice.key.public_key()));
    let reply = send(&bob, &b, &epoch1, b"TEXT hi alice\n");
    assert_eq!(
        receive(&a, &epoch1, &reply).sender,
        Some(bob.key.public_key())
    );

    // Bob refreshes his leaf with an empty commit (12.6). Alice applies it.
    let sent = commit_lines(&bob, &mut b, Changes::default());
    assert!(sent.welcome.is_none());
    check_group_info(&sent.group_info);
    b.merge_pending_commit(&bob.provider).unwrap();
    let epoch2 = alice.apply(&mut a, &sent.commit);
    assert_eq!(
        HistoryKey::of_group(&b, bob.provider.crypto()).unwrap(),
        epoch2
    );
    assert_ne!(epoch2, epoch1);
    // The refresh kept Bob's credential and signature key (12.2).
    assert_eq!(
        Device::leaf_keys(&a),
        [alice.key.public_key(), bob.key.public_key()]
    );

    // A message of epoch 2 does not decrypt under epoch 1's key, and one
    // of epoch 1 still decrypts with the key Alice kept.
    let later = send(&alice, &a, &epoch2, b"TEXT later\n");
    assert_eq!(receive(&b, &epoch2, &later).content, b"TEXT later\n");
    assert_eq!(
        decrypt(
            &epoch1,
            a.group_id().as_slice(),
            2,
            &later.payload,
            &later.frank
        )
        .unwrap_err(),
        MessageError::Decrypt
    );
    assert_eq!(
        decrypt(
            &epoch1,
            a.group_id().as_slice(),
            1,
            &hello.payload,
            &hello.frank
        )
        .unwrap()
        .verify(&alice.key.public_key())
        .unwrap()
        .content,
        b"TEXT hello bob\n"
    );

    // A message signed by Bob does not verify as Alice's.
    let forged = decrypt(
        &epoch2,
        a.group_id().as_slice(),
        2,
        &later.payload,
        &later.frank,
    )
    .unwrap()
    .verify(&bob.key.public_key());
    assert_eq!(forged.unwrap_err(), MessageError::WrongSender);

    // Alice removes Bob's leaf. Bob sees that he is out.
    let bob_leaf = a
        .members()
        .find(|m| m.signature_key == bob.key.public_key().as_bytes())
        .unwrap()
        .index;
    let sent = commit_lines(
        &alice,
        &mut a,
        Changes {
            remove: vec![bob_leaf],
            ..Changes::default()
        },
    );
    a.merge_pending_commit(&alice.provider).unwrap();
    let message: ProtocolMessage = commit_from_wire(&sent.commit).unwrap();
    let processed = b.process_message(&bob.provider, message).unwrap();
    let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
        panic!("not a commit");
    };
    assert!(staged.self_removed());
    assert!(HistoryKey::of_staged_commit(&staged, bob.provider.crypto()).is_err());
    assert_eq!(a.members().count(), 1);
}

#[test]
fn a_new_device_joins_by_external_commit() {
    let alice = Device::new("alice@example.org", 1);
    let bob = Device::new("bob@example.net", 2);
    let conversation = RisalaConversation::direct(&alice.uid, &bob.uid);
    let mut a = create_group(&alice.provider, &alice.signer(), &alice.uid, &conversation).unwrap();
    let info = group_info_to_wire(
        &a.export_group_info(alice.provider.crypto(), &alice.signer(), false)
            .unwrap(),
    )
    .unwrap();
    let tree = tree_to_wire(&a.export_ratchet_tree()).unwrap();

    // Bob's device joins from GROUPINFO, with the tree out of band.
    let (b, bundle) = join_by_external_commit(
        &bob.provider,
        &bob.signer(),
        &bob.uid,
        group_info_from_wire(&info).unwrap(),
        tree_from_wire(&tree).unwrap(),
    )
    .unwrap();
    let (commit, welcome, group_info) = bundle.into_messages();
    assert!(welcome.is_none());
    check_group_info(&group_info_to_wire(&group_info.unwrap()).unwrap());
    let commit = commit_to_wire(&commit).unwrap();
    let key = alice.apply(&mut a, &commit);
    assert_eq!(
        HistoryKey::of_group(&b, bob.provider.crypto()).unwrap(),
        key
    );
    assert_eq!(b.epoch().as_u64(), 1);
    // The joiner's leaf lists the capabilities of 12.2.
    assert!(group::has_capabilities(
        b.own_leaf_node().unwrap().capabilities()
    ));

    let sent = send(&bob, &b, &key, b"TEXT joined\n");
    assert_eq!(receive(&a, &key, &sent).content, b"TEXT joined\n");

    // The same device joins again, as after a reinstall with the same key:
    // OpenMLS removes its old leaf in the same commit (12.6).
    let bob_again = Device::new("bob@example.net", 2);
    let info = group_info_to_wire(
        &a.export_group_info(alice.provider.crypto(), &alice.signer(), false)
            .unwrap(),
    )
    .unwrap();
    let tree = tree_to_wire(&a.export_ratchet_tree()).unwrap();
    let (_, bundle) = join_by_external_commit(
        &bob_again.provider,
        &bob_again.signer(),
        &bob_again.uid,
        group_info_from_wire(&info).unwrap(),
        tree_from_wire(&tree).unwrap(),
    )
    .unwrap();
    alice.apply(&mut a, &commit_to_wire(bundle.commit()).unwrap());
    assert_eq!(a.members().count(), 2);
}

#[test]
fn an_owner_changes_the_room_settings() {
    let owner = Device::new("owner@example.org", 1);
    let member = Device::new("member@example.org", 2);
    let id: Id = "r7x2k9qp".parse().unwrap();
    let conversation = RisalaConversation::room(&id, HistoryMode::Shared, SendMode::All);
    let mut o = create_group(&owner.provider, &owner.signer(), &owner.uid, &conversation).unwrap();
    let sent = commit_lines(
        &owner,
        &mut o,
        Changes {
            add: vec![member.checked_key_package()],
            ..Changes::default()
        },
    );
    o.merge_pending_commit(&owner.provider).unwrap();
    let mut m = stage_welcome(
        &member.provider,
        welcome_from_wire(&sent.welcome.unwrap()).unwrap(),
        tree_from_wire(&tree_to_wire(&o.export_ratchet_tree()).unwrap()).unwrap(),
    )
    .unwrap()
    .into_group(&member.provider)
    .unwrap();

    let announcements = RisalaConversation::room(&id, HistoryMode::Joined, SendMode::Mods);
    let sent = commit_lines(
        &owner,
        &mut o,
        Changes {
            conversation: Some(announcements.clone()),
            ..Changes::default()
        },
    );
    o.merge_pending_commit(&owner.provider).unwrap();
    member.apply(&mut m, &sent.commit);
    let seen = RisalaConversation::from_extensions(m.extensions()).unwrap();
    assert_eq!(seen, announcements);
    assert!(seen.same_conversation(&conversation));
    assert!(m.extensions().required_capabilities().is_some());
}

#[test]
fn key_package_checks() {
    let crypto = RisalaCrypto::new().unwrap();
    let alice = Device::new("alice@example.org", 1);
    let now = SystemTime::now();
    let check = |value: &mls::KeyPackage, uid: &Uid, key: &PublicKey| {
        check_key_package(&crypto, value, uid, key, now)
    };
    let public = alice.key.public_key();

    let ordinary = check(&alice.key_package(false), &alice.uid, &public).unwrap();
    assert!(!ordinary.last_resort);
    let lifetime = ordinary.key_package.life_time();
    assert_eq!(
        lifetime.not_after() - lifetime.not_before(),
        MAX_LIFETIME_SPAN
    );
    assert_eq!(MAX_LIFETIME_SPAN, 7_261_200);
    assert!(
        check(&alice.key_package(true), &alice.uid, &public)
            .unwrap()
            .last_resort
    );

    // Another uid or device key.
    let bob: Uid = "bob@example.org".parse().unwrap();
    assert_eq!(
        check(&alice.key_package(false), &bob, &public).unwrap_err(),
        KeyPackageError::Credential
    );
    let other = SecretKey::from_seed([9; 32]).public_key();
    assert_eq!(
        check(&alice.key_package(false), &alice.uid, &other).unwrap_err(),
        KeyPackageError::SignatureKey
    );

    // Lifetimes: one that ended, one not yet begun, one that spans too
    // long, and one exactly as long as allowed.
    let unix = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let with_lifetime = |lifetime: Lifetime| {
        let bundle = KeyPackage::builder()
            .leaf_node_capabilities(capabilities())
            .key_package_lifetime(lifetime)
            .build(
                CIPHERSUITE,
                &alice.provider,
                &alice.signer(),
                credential_with_key(alice.uid.as_str(), &public),
            )
            .unwrap();
        key_package_to_wire(bundle.key_package()).unwrap()
    };
    for (not_before, not_after) in [
        (unix - 7200, unix - 3600),
        (unix + 3600, unix + 7200),
        (unix - 3600, unix + KEY_PACKAGE_LIFETIME + 1),
    ] {
        assert_eq!(
            check(
                &with_lifetime(Lifetime::init(not_before, not_after)),
                &alice.uid,
                &public
            )
            .unwrap_err(),
            KeyPackageError::Lifetime,
            "{not_before} {not_after}"
        );
    }
    let longest = with_lifetime(Lifetime::init(unix - 3600, unix + KEY_PACKAGE_LIFETIME));
    assert!(check(&longest, &alice.uid, &public).is_ok());
    let later = now + Duration::from_secs(KEY_PACKAGE_LIFETIME + 1);
    assert!(!lifetime_acceptable(
        &Lifetime::init(unix - 3600, unix + KEY_PACKAGE_LIFETIME),
        later
    ));

    // A leaf without the conversation extension and `last_resort`.
    let bare = KeyPackage::builder()
        .build(
            CIPHERSUITE,
            &alice.provider,
            &alice.signer(),
            credential_with_key(alice.uid.as_str(), &public),
        )
        .unwrap();
    assert_eq!(
        check(
            &key_package_to_wire(bare.key_package()).unwrap(),
            &alice.uid,
            &public
        )
        .unwrap_err(),
        KeyPackageError::Capabilities
    );

    // A tampered signature, garbage, and a GroupInfo instead.
    let mut bytes = alice.key_package(false).decode();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    assert_eq!(
        check(
            &mls::KeyPackage::from_bytes(&bytes).unwrap(),
            &alice.uid,
            &public
        )
        .unwrap_err(),
        KeyPackageError::Invalid
    );
    assert!(matches!(
        check(&"AAEABQABAFI=".parse().unwrap(), &alice.uid, &public).unwrap_err(),
        KeyPackageError::Wire(WireError::Malformed(_))
    ));
    let conversation = RisalaConversation::direct(&alice.uid, &alice.uid);
    let group = create_group(&alice.provider, &alice.signer(), &alice.uid, &conversation).unwrap();
    let info = group
        .export_group_info(alice.provider.crypto(), &alice.signer(), false)
        .unwrap();
    let as_key_package: mls::KeyPackage =
        group_info_to_wire(&info).unwrap().as_str().parse().unwrap();
    assert_eq!(
        check(&as_key_package, &alice.uid, &public).unwrap_err(),
        KeyPackageError::Wire(WireError::WrongKind("KeyPackage"))
    );
}

/// librisala's set-up: the SQLite storage on a borrowed transaction, a
/// shared crypto, and the group loaded again in every transaction.
#[test]
fn sqlite_storage_on_a_transaction() {
    use openmls_sqlite_storage::{MsgPack, SCHEMA, SqliteStorageProvider};

    let alice_key = SecretKey::from_seed([1; 32]);
    let bob = Device::new("bob@example.net", 2);
    let alice_uid: Uid = "alice@example.org".parse().unwrap();
    let crypto = Arc::new(RisalaCrypto::new().unwrap());
    let mut db = rusqlite::Connection::open_in_memory().unwrap();
    db.execute_batch(SCHEMA).unwrap();
    let signer = DeviceSigner::new(&alice_key);
    let conversation = RisalaConversation::direct(&alice_uid, &bob.uid);

    let group_id = {
        let tx = db.transaction().unwrap();
        let provider = Provider::with_crypto(
            crypto.clone(),
            SqliteStorageProvider::<MsgPack, _>::new(&*tx),
        );
        let group = create_group(&provider, &signer, &alice_uid, &conversation).unwrap();
        let id = group.group_id().clone();
        drop(provider);
        tx.commit().unwrap();
        id
    };

    // A commit in a transaction that is rolled back leaves nothing behind.
    {
        let tx = db.transaction().unwrap();
        let provider = Provider::with_crypto(
            crypto.clone(),
            SqliteStorageProvider::<MsgPack, _>::new(&*tx),
        );
        let mut group = MlsGroup::load(provider.storage(), &group_id)
            .unwrap()
            .unwrap();
        commit(
            &provider,
            &mut group,
            &signer,
            Changes {
                add: vec![bob.checked_key_package()],
                ..Changes::default()
            },
        )
        .unwrap();
        group.merge_pending_commit(&provider).unwrap();
        assert_eq!(group.epoch().as_u64(), 1);
        drop(provider);
        tx.rollback().unwrap();
    }

    let tx = db.transaction().unwrap();
    let provider = Provider::with_crypto(crypto, SqliteStorageProvider::<MsgPack, _>::new(&*tx));
    let group = MlsGroup::load(provider.storage(), &group_id)
        .unwrap()
        .unwrap();
    assert_eq!(group.epoch().as_u64(), 0);
    assert_eq!(group.members().count(), 1);
    assert_eq!(
        RisalaConversation::from_extensions(group.extensions()),
        Ok(conversation)
    );
}

#[test]
fn wire_values_are_strict() {
    let alice = Device::new("alice@example.org", 1);
    let value = alice.key_package(false);
    // Trailing bytes after the MLSMessage.
    let mut bytes = value.decode();
    bytes.push(0);
    assert!(matches!(
        key_package_from_wire(&mls::KeyPackage::from_bytes(&bytes).unwrap()),
        Err(WireError::Malformed(_))
    ));
    assert!(matches!(
        welcome_from_wire(&value.as_str().parse().unwrap()),
        Err(WireError::WrongKind("Welcome"))
    ));
    assert!(matches!(
        commit_from_wire(&value.as_str().parse().unwrap()),
        Err(WireError::WrongKind("PublicMessage"))
    ));
    assert!(tree_from_wire(&"AAEC".parse().unwrap()).is_err());
}
