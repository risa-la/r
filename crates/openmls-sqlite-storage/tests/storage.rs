//! The port against real OpenMLS groups, on SQLite files, as librisala
//! uses it: a provider on a borrowed connection or transaction, two devices
//! on separate files, two connections on one file, and rollback.

use std::path::Path;
use std::time::Duration;

use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls::schedule::{ExternalPsk, PreSharedKeyId, Psk};
use openmls_basic_credential::SignatureKeyPair;
use openmls_libcrux_crypto::CryptoProvider;
use openmls_sqlite_storage::{Codec, MsgPack, SCHEMA, SqliteStorageProvider};
use openmls_traits::{OpenMlsProvider, storage::StorageProvider as _};
use rusqlite::{Connection, ErrorCode, TransactionBehavior};

const CS: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

type Storage<'a> = SqliteStorageProvider<MsgPack, &'a Connection>;

/// An OpenMLS provider whose storage is a borrowed connection, or a
/// transaction on one through `&*tx`.
struct Provider<'a> {
    crypto: CryptoProvider,
    storage: Storage<'a>,
}

impl<'a> Provider<'a> {
    fn new(conn: &'a Connection) -> Self {
        Provider {
            crypto: CryptoProvider::new().unwrap(),
            storage: SqliteStorageProvider::new(conn),
        }
    }
}

impl<'a> OpenMlsProvider for Provider<'a> {
    type CryptoProvider = CryptoProvider;
    type RandProvider = CryptoProvider;
    type StorageProvider = Storage<'a>;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }
    fn crypto(&self) -> &CryptoProvider {
        &self.crypto
    }
    fn rand(&self) -> &CryptoProvider {
        &self.crypto
    }
}

/// Opens `path` as librisala does (WAL, a busy timeout), creating the
/// tables if the file is new.
fn open(path: &Path) -> Connection {
    let conn = Connection::open(path).unwrap();
    let _: String = conn
        .pragma_update_and_check(None, "journal_mode", "WAL", |r| r.get(0))
        .unwrap();
    conn.busy_timeout(Duration::from_secs(5)).unwrap();
    let tables: i64 = conn
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE name LIKE 'openmls_%'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    if tables == 0 {
        conn.execute_batch(SCHEMA).unwrap();
    }
    conn
}

fn rows(conn: &Connection, table: &str) -> i64 {
    conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

struct Device {
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
}

impl Device {
    fn new(name: &str) -> Device {
        let signer = SignatureKeyPair::new(CS.signature_algorithm()).unwrap();
        let credential = CredentialWithKey {
            credential: BasicCredential::new(name.as_bytes().to_vec()).into(),
            signature_key: signer.public().into(),
        };
        Device { signer, credential }
    }

    fn key_package(&self, provider: &Provider<'_>) -> KeyPackage {
        KeyPackage::builder()
            .build(CS, provider, &self.signer, self.credential.clone())
            .unwrap()
            .key_package()
            .clone()
    }

    fn create_group(&self, provider: &Provider<'_>) -> MlsGroup {
        MlsGroup::builder()
            .ciphersuite(CS)
            .use_ratchet_tree_extension(true)
            .build(provider, &self.signer, self.credential.clone())
            .unwrap()
    }
}

/// A message as it would cross the wire.
fn wire(message: &MlsMessageOut) -> MlsMessageIn {
    let bytes = message.tls_serialize_detached().unwrap();
    MlsMessageIn::tls_deserialize_exact(bytes).unwrap()
}

fn load(provider: &Provider<'_>, id: &GroupId) -> MlsGroup {
    MlsGroup::load(provider.storage(), id)
        .unwrap()
        .expect("the group is stored")
}

fn exporter(provider: &Provider<'_>, group: &MlsGroup) -> Vec<u8> {
    group
        .export_secret(provider.crypto(), "test", b"", 32)
        .unwrap()
}

/// Commits an update of the device's own leaf, and merges it.
fn self_update(provider: &Provider<'_>, group: &mut MlsGroup, device: &Device) -> MlsMessageOut {
    let bundle = group
        .self_update(provider, &device.signer, LeafNodeParameters::default())
        .unwrap();
    group.merge_pending_commit(provider).unwrap();
    bundle.into_commit()
}

fn apply_commit(provider: &Provider<'_>, group: &mut MlsGroup, commit: &MlsMessageOut) {
    let message = wire(commit).try_into_protocol_message().unwrap();
    let processed = group.process_message(provider, message).unwrap();
    let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
        panic!("not a commit");
    };
    group.merge_staged_commit(provider, *staged).unwrap();
}

#[test]
fn two_devices_on_their_own_files() {
    let dir = tempfile::tempdir().unwrap();
    let a = open(&dir.path().join("alice.db"));
    let b = open(&dir.path().join("bob.db"));
    let (pa, pb) = (Provider::new(&a), Provider::new(&b));
    let (alice, bob) = (Device::new("alice"), Device::new("bob"));

    // Bob's KeyPackage, with its private keys, is in his file.
    let kp = bob.key_package(&pb);
    assert_eq!(rows(&b, "openmls_key_packages"), 1);

    let mut group = alice.create_group(&pa);
    let id = group.group_id().clone();
    let (_, welcome, _) = group.add_members(&pa, &alice.signer, &[kp]).unwrap();
    group.merge_pending_commit(&pa).unwrap();

    let MlsMessageBodyIn::Welcome(welcome) = wire(&welcome).extract() else {
        panic!("not a Welcome");
    };
    let config = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();
    let mut bob_group = StagedWelcome::new_from_welcome(&pb, &config, welcome, None)
        .unwrap()
        .into_group(&pb)
        .unwrap();
    // Joining used up the KeyPackage.
    assert_eq!(rows(&b, "openmls_key_packages"), 0);

    // Bob commits; Alice applies it.
    let commit = self_update(&pb, &mut bob_group, &bob);
    apply_commit(&pa, &mut group, &commit);

    // A message Alice sends after reloading, read by Bob after reloading.
    let mut group = load(&pa, &id);
    let message = group.create_message(&pa, &alice.signer, b"hi").unwrap();
    let mut bob_group = load(&pb, &id);
    let processed = bob_group
        .process_message(&pb, wire(&message).try_into_protocol_message().unwrap())
        .unwrap();
    let ProcessedMessageContent::ApplicationMessage(text) = processed.into_content() else {
        panic!("not an application message");
    };
    assert_eq!(text.into_bytes(), b"hi");

    // Both files hold the same epoch.
    let (ga, gb) = (load(&pa, &id), load(&pb, &id));
    assert_eq!(ga.epoch().as_u64(), 2);
    assert_eq!(ga.epoch(), gb.epoch());
    assert_eq!(exporter(&pa, &ga), exporter(&pb, &gb));
    assert_eq!(ga.own_leaf_index().u32(), 0);
    assert_eq!(gb.own_leaf_index().u32(), 1);
    assert_eq!(ga.members().count(), 2);

    // Each kept its own epoch's leaf keys.
    assert!(rows(&a, "openmls_epoch_keys_pairs") > 0);
    assert!(rows(&b, "openmls_epoch_keys_pairs") > 0);

    // Deleting the group removes its rows.
    let mut gb = gb;
    gb.delete(pb.storage()).unwrap();
    assert!(MlsGroup::load(pb.storage(), &id).unwrap().is_none());
    for table in [
        "openmls_group_data",
        "openmls_own_leaf_nodes",
        "openmls_proposals",
        "openmls_epoch_keys_pairs",
    ] {
        assert_eq!(rows(&b, table), 0, "{table}");
    }
}

/// librisala's two processes: one commits inside `BEGIN IMMEDIATE`, the
/// other loads the group from the same file.
#[test]
fn two_connections_on_one_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.db");
    let mut a = open(&path);
    let b = open(&path);
    b.busy_timeout(Duration::ZERO).unwrap();
    let alice = Device::new("alice");

    let id = alice.create_group(&Provider::new(&a)).group_id().clone();
    let pb = Provider::new(&b);
    let before = load(&pb, &id);
    assert_eq!(before.epoch().as_u64(), 0);

    let tx = a
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    let pt = Provider::new(&tx);
    let mut group = load(&pt, &id);
    self_update(&pt, &mut group, &alice);
    let secret = exporter(&pt, &group);

    // While the write is open, the other connection cannot write, and
    // reads what was committed before it.
    let err = b.execute_batch("BEGIN IMMEDIATE").unwrap_err();
    assert_eq!(err.sqlite_error_code(), Some(ErrorCode::DatabaseBusy));
    assert_eq!(load(&pb, &id).epoch().as_u64(), 0);

    drop(pt);
    tx.commit().unwrap();

    // The other connection's group in memory is now stale; loading it
    // again gives the new epoch.
    assert_eq!(before.epoch().as_u64(), 0);
    let after = load(&pb, &id);
    assert_eq!(after.epoch().as_u64(), 1);
    assert_eq!(exporter(&pb, &after), secret);
}

#[test]
fn rollback_undoes_a_merged_commit() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = open(&dir.path().join("cache.db"));
    let alice = Device::new("alice");
    let id = alice.create_group(&Provider::new(&a)).group_id().clone();
    let secret = exporter(&Provider::new(&a), &load(&Provider::new(&a), &id));

    let tx = a
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    let pt = Provider::new(&tx);
    let mut group = load(&pt, &id);
    self_update(&pt, &mut group, &alice);
    assert_eq!(load(&pt, &id).epoch().as_u64(), 1);
    drop(pt);
    tx.rollback().unwrap();

    let pa = Provider::new(&a);
    let mut group = load(&pa, &id);
    assert_eq!(group.epoch().as_u64(), 0);
    assert_eq!(exporter(&pa, &group), secret);
    // The state left behind is whole: the next commit works.
    self_update(&pa, &mut group, &alice);
    assert_eq!(load(&pa, &id).epoch().as_u64(), 1);
}

/// A Welcome processed in a transaction that is rolled back keeps the
/// KeyPackage, so that the same Welcome can be processed again (spike 8).
#[test]
fn rollback_keeps_the_key_package_of_a_welcome() {
    let dir = tempfile::tempdir().unwrap();
    let a = open(&dir.path().join("alice.db"));
    let mut b = open(&dir.path().join("bob.db"));
    let (alice, bob) = (Device::new("alice"), Device::new("bob"));
    let pa = Provider::new(&a);
    let kp = bob.key_package(&Provider::new(&b));
    let mut group = alice.create_group(&pa);
    let (_, welcome, _) = group.add_members(&pa, &alice.signer, &[kp]).unwrap();
    group.merge_pending_commit(&pa).unwrap();
    let MlsMessageBodyIn::Welcome(welcome) = wire(&welcome).extract() else {
        panic!("not a Welcome");
    };
    let config = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();

    let tx = b
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    let pt = Provider::new(&tx);
    StagedWelcome::new_from_welcome(&pt, &config, welcome.clone(), None).unwrap();
    assert_eq!(rows(&tx, "openmls_key_packages"), 0);
    drop(pt);
    tx.rollback().unwrap();
    assert_eq!(rows(&b, "openmls_key_packages"), 1);

    let pb = Provider::new(&b);
    let joined = StagedWelcome::new_from_welcome(&pb, &config, welcome, None)
        .unwrap()
        .into_group(&pb)
        .unwrap();
    assert_eq!(joined.epoch(), group.epoch());
}

#[test]
fn signature_keys_are_written_and_deleted() {
    let dir = tempfile::tempdir().unwrap();
    let a = open(&dir.path().join("cache.db"));
    let storage = Storage::new(&a);
    let key = SignatureKeyPair::new(CS.signature_algorithm()).unwrap();
    key.store(&storage).unwrap();
    assert_eq!(rows(&a, "openmls_signature_keys"), 1);

    let read = SignatureKeyPair::read(&storage, key.public(), key.signature_scheme()).unwrap();
    assert_eq!(read.public(), key.public());
    assert_eq!(read.to_public_vec(), key.to_public_vec());

    SignatureKeyPair::delete(&storage, key.public(), key.signature_scheme()).unwrap();
    assert_eq!(rows(&a, "openmls_signature_keys"), 0);
    assert!(SignatureKeyPair::read(&storage, key.public(), key.signature_scheme()).is_none());
}

#[test]
fn key_packages_are_written_and_deleted() {
    let dir = tempfile::tempdir().unwrap();
    let a = open(&dir.path().join("cache.db"));
    let pa = Provider::new(&a);
    let kp = Device::new("bob").key_package(&pa);
    assert_eq!(rows(&a, "openmls_key_packages"), 1);

    let hash_ref = kp.hash_ref(pa.crypto()).unwrap();
    let stored: Option<KeyPackageBundle> = pa.storage().key_package(&hash_ref).unwrap();
    assert_eq!(stored.unwrap().key_package(), &kp);

    pa.storage().delete_key_package(&hash_ref).unwrap();
    assert_eq!(rows(&a, "openmls_key_packages"), 0);
    let gone: Option<KeyPackageBundle> = pa.storage().key_package(&hash_ref).unwrap();
    assert!(gone.is_none());
}

#[test]
fn psks_are_written_read_and_deleted() {
    let dir = tempfile::tempdir().unwrap();
    let a = open(&dir.path().join("cache.db"));
    let pa = Provider::new(&a);
    let alice = Device::new("alice");
    let mut group = alice.create_group(&pa);

    let psk =
        PreSharedKeyId::new(CS, pa.rand(), Psk::External(ExternalPsk::new(vec![7; 8]))).unwrap();
    psk.store(&pa, &[1; 32]).unwrap();
    assert_eq!(rows(&a, "openmls_psks"), 1);

    // Committing the PSK reads it back from storage.
    group
        .propose_pre_shared_key(&pa, &alice.signer, psk.clone())
        .unwrap();
    group
        .commit_to_pending_proposals(&pa, &alice.signer)
        .unwrap();
    group.merge_pending_commit(&pa).unwrap();
    assert_eq!(group.epoch().as_u64(), 1);

    pa.storage().delete_psk(psk.psk()).unwrap();
    assert_eq!(rows(&a, "openmls_psks"), 0);
    // Without it, the same proposal cannot be committed.
    let psk = PreSharedKeyId::new(CS, pa.rand(), psk.psk().clone()).unwrap();
    group
        .propose_pre_shared_key(&pa, &alice.signer, psk)
        .unwrap();
    assert!(
        group
            .commit_to_pending_proposals(&pa, &alice.signer)
            .is_err()
    );
}

#[test]
fn the_proposal_queue_is_written_and_cleared() {
    let dir = tempfile::tempdir().unwrap();
    let a = open(&dir.path().join("cache.db"));
    let b = open(&dir.path().join("bob.db"));
    let pa = Provider::new(&a);
    let (alice, bob) = (Device::new("alice"), Device::new("bob"));
    let mut group = alice.create_group(&pa);
    let id = group.group_id().clone();

    let (_, first) = group
        .propose_add_member(&pa, &alice.signer, &bob.key_package(&Provider::new(&b)))
        .unwrap();
    assert_eq!(rows(&a, "openmls_proposals"), 1);
    assert_eq!(load(&pa, &id).pending_proposals().count(), 1);

    // One proposal removed.
    group.remove_pending_proposal(pa.storage(), &first).unwrap();
    assert_eq!(rows(&a, "openmls_proposals"), 0);
    assert_eq!(load(&pa, &id).pending_proposals().count(), 0);

    // The queue cleared by a commit.
    group
        .propose_add_member(&pa, &alice.signer, &bob.key_package(&Provider::new(&b)))
        .unwrap();
    group
        .propose_add_member(
            &pa,
            &alice.signer,
            &Device::new("carol").key_package(&Provider::new(&b)),
        )
        .unwrap();
    let mut group = load(&pa, &id);
    assert_eq!(group.pending_proposals().count(), 2);
    assert_eq!(rows(&a, "openmls_proposals"), 2);
    group
        .commit_to_pending_proposals(&pa, &alice.signer)
        .unwrap();
    group.merge_pending_commit(&pa).unwrap();
    assert_eq!(rows(&a, "openmls_proposals"), 0);
    assert_eq!(load(&pa, &id).members().count(), 3);
}

/// `MlsGroupJoinConfig` reads `PastEpochDeletionPolicy` through
/// `#[serde(untagged)]`, which only a self-describing format can decode.
#[test]
fn msgpack_round_trips_a_join_config() {
    for policy in [
        PastEpochDeletionPolicy::MaxEpochs(5),
        PastEpochDeletionPolicy::KeepAll,
    ] {
        let config = MlsGroupJoinConfig::builder()
            .padding_size(64)
            .set_past_epoch_deletion_policy(policy)
            .number_of_resumption_psks(3)
            .use_ratchet_tree_extension(true)
            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .build();
        let bytes = MsgPack::to_vec(&config).unwrap();
        // Struct fields go by name.
        assert!(bytes.windows(12).any(|w| w == b"padding_size"));
        let back: MlsGroupJoinConfig = MsgPack::from_slice(&bytes).unwrap();
        assert_eq!(back, config);

        // And through the storage.
        let dir = tempfile::tempdir().unwrap();
        let a = open(&dir.path().join("cache.db"));
        let storage = Storage::new(&a);
        let id = GroupId::from_slice(b"group");
        storage.write_mls_join_config(&id, &config).unwrap();
        let read: Option<MlsGroupJoinConfig> = storage.mls_group_join_config(&id).unwrap();
        assert_eq!(read, Some(config));
        storage.delete_group_config(&id).unwrap();
        let read: Option<MlsGroupJoinConfig> = storage.mls_group_join_config(&id).unwrap();
        assert_eq!(read, None);
    }
}
