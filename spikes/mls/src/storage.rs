//! 8. Storage: openmls_sqlite_storage on one SQLite file used by two
//! connections, standing in for librisala's two processes, plus the
//! server's PublicGroup in the same kind of store.

use std::time::Instant;

use openmls::prelude::*;
use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Codec, SqliteStorageProvider};
use openmls_traits::OpenMlsProvider;
use rusqlite::{Connection, TransactionBehavior};

use crate::common::*;

#[derive(Default)]
pub struct Json;
impl Codec for Json {
    type Error = serde_json::Error;
    fn to_vec<T: serde::Serialize>(v: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(v)
    }
    fn from_slice<T: serde::de::DeserializeOwned>(s: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(s)
    }
}

/// An OpenMLS provider whose storage is one SQLite connection (or a
/// transaction on it, through `&*tx`).
pub struct SqlProvider<'a> {
    crypto: RustCrypto,
    storage: SqliteStorageProvider<Json, &'a Connection>,
}

impl<'a> SqlProvider<'a> {
    pub fn new(c: &'a Connection) -> Self {
        Self {
            crypto: RustCrypto::default(),
            storage: SqliteStorageProvider::new(c),
        }
    }
}

impl<'a> OpenMlsProvider for SqlProvider<'a> {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = SqliteStorageProvider<Json, &'a Connection>;
    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }
    fn crypto(&self) -> &RustCrypto {
        &self.crypto
    }
    fn rand(&self) -> &RustCrypto {
        &self.crypto
    }
}

fn open(path: &std::path::Path) -> Connection {
    let c = Connection::open(path).unwrap();
    c.pragma_update(None, "journal_mode", "WAL").unwrap();
    c.busy_timeout(std::time::Duration::from_millis(0)).unwrap();
    c
}

fn epoch_of(c: &Connection, gid: &GroupId) -> u64 {
    let p = SqlProvider::new(c);
    MlsGroup::load(p.storage(), gid)
        .unwrap()
        .expect("group in store")
        .epoch()
        .as_u64()
}

pub fn run() {
    println!("\n== 8. Storage (openmls_sqlite_storage 0.3, rusqlite 0.37)");
    let dir = std::env::temp_dir().join(format!("mls-spike-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("cache.sqlite");
    let _ = std::fs::remove_file(&path);

    let mut a = open(&path);
    let b = open(&path);
    SqliteStorageProvider::<Json, &mut Connection>::new(&mut a)
        .run_migrations()
        .unwrap();
    let tables: Vec<String> = a
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    println!("  tables it creates: {tables:?}");

    // Process A creates the group; the device key itself stays outside
    // OpenMLS storage (our own Signer).
    let alice = Device::new("alice@example.org");
    let bob = Device::new("bob@example.net");
    let conv = RisalaConversation::direct("alice@example.org", "bob@example.net");
    let gid = {
        let pa = SqlProvider::new(&a);
        let gid: [u8; 32] = rand::random();
        let g = MlsGroup::builder()
            .ciphersuite(CS)
            .with_group_id(GroupId::from_slice(&gid))
            .with_capabilities(capabilities())
            .with_group_context_extensions(group_context_extensions(&conv))
            .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(false)
            .build(&pa, &alice.key, alice.credential())
            .unwrap();
        g.group_id().clone()
    };
    println!("  A created the group; B loads it from the file: epoch {}", epoch_of(&b, &gid));

    // B holds an MlsGroup in memory while A commits.
    let pb = SqlProvider::new(&b);
    let b_view = MlsGroup::load(pb.storage(), &gid).unwrap().unwrap();

    // A commits inside an IMMEDIATE transaction, then rolls back.
    {
        let tx = a
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let pt = SqlProvider::new(&tx);
        let mut g = MlsGroup::load(pt.storage(), &gid).unwrap().unwrap();
        let kp = bob.key_package(false);
        g.commit_builder()
            .propose_adds([kp])
            .load_psks(pt.storage())
            .unwrap()
            .build(pt.rand(), pt.crypto(), &alice.key, |_| true)
            .unwrap()
            .stage_commit(&pt)
            .unwrap();
        g.merge_pending_commit(&pt).unwrap();
        println!("  A merged a commit inside a transaction: epoch {} (in tx)", g.epoch().as_u64());
        // While A holds the write lock, B cannot start a write.
        let mut b2 = open(&path);
        let r = b2.transaction_with_behavior(TransactionBehavior::Immediate);
        println!("  B tries BEGIN IMMEDIATE meanwhile: {:?}", r.err().map(|e| e.to_string()));
        drop(pt);
        tx.rollback().unwrap();
    }
    println!("  after rollback, the file says epoch {}: the merge was atomic", epoch_of(&b, &gid));

    // Now A commits for real.
    {
        let tx = a
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let pt = SqlProvider::new(&tx);
        let mut g = MlsGroup::load(pt.storage(), &gid).unwrap().unwrap();
        let kp = bob.key_package(false);
        g.commit_builder()
            .propose_adds([kp])
            .load_psks(pt.storage())
            .unwrap()
            .build(pt.rand(), pt.crypto(), &alice.key, |_| true)
            .unwrap()
            .stage_commit(&pt)
            .unwrap();
        g.merge_pending_commit(&pt).unwrap();
        drop(pt);
        tx.commit().unwrap();
    }
    println!(
        "  A committed: file epoch {}; B's in-memory MlsGroup still says epoch {} (stale until B reloads)",
        epoch_of(&b, &gid),
        b_view.epoch().as_u64()
    );
    let b_view = MlsGroup::load(pb.storage(), &gid).unwrap().unwrap();
    println!("  B reloads: epoch {}", b_view.epoch().as_u64());

    // Server: a PublicGroup in the same kind of store, loaded per command.
    let crypto = RustCrypto::default();
    let srv = open(&dir.join("server.sqlite"));
    let mut srv_mut = srv;
    SqliteStorageProvider::<Json, &mut Connection>::new(&mut srv_mut)
        .run_migrations()
        .unwrap();
    let srv = srv_mut;
    let pa = SqlProvider::new(&a);
    let g = MlsGroup::load(pa.storage(), &gid).unwrap().unwrap();
    let gi = g.export_group_info(&crypto, &alice.key, false).unwrap();
    let MlsMessageBodyIn::GroupInfo(vgi) = parse_msg(&msg_b64(&gi)) else {
        panic!()
    };
    let sstore = SqliteStorageProvider::<Json, &Connection>::new(&srv);
    PublicGroup::from_external(&crypto, &sstore, g.export_ratchet_tree().into(), vgi, ProposalStore::new())
        .unwrap();
    let t = Instant::now();
    let pg = PublicGroup::load(&sstore, &gid).unwrap().unwrap();
    println!(
        "  server: PublicGroup stored and loaded back from SQLite ({} leaves, load {:?})",
        pg.members().count(),
        t.elapsed()
    );

    // 512 leaves in SQLite: one commit adding 511 devices (the worst case
    // for one COMMIT line), then the cost of loading the group per command.
    let big = Device::new("owner@example.org");
    let bgid = {
        let pa = SqlProvider::new(&a);
        let g = MlsGroup::builder()
            .ciphersuite(CS)
            .with_capabilities(capabilities())
            .with_group_context_extensions(group_context_extensions(&RisalaConversation::room("big", 1)))
            .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(false)
            .build(&pa, &big.key, big.credential())
            .unwrap();
        g.group_id().clone()
    };
    let kps: Vec<KeyPackage> = (0..511)
        .map(|i| Device::new(&format!("u{}@example.org", i / 4)).key_package(false))
        .collect();
    let (commit, gi, welcome) = {
        let tx = a.transaction_with_behavior(TransactionBehavior::Immediate).unwrap();
        let pt = SqlProvider::new(&tx);
        let mut g = MlsGroup::load(pt.storage(), &bgid).unwrap().unwrap();
        let t = Instant::now();
        let bundle = g
            .commit_builder()
            .propose_adds(kps)
            .load_psks(pt.storage())
            .unwrap()
            .create_group_info(true)
            .build(pt.rand(), pt.crypto(), &big.key, |_| true)
            .unwrap()
            .stage_commit(&pt)
            .unwrap();
        g.merge_pending_commit(&pt).unwrap();
        let el = t.elapsed();
        drop(pt);
        tx.commit().unwrap();
        let (c, w, gi) = bundle.into_messages();
        println!("  one commit adding 511 devices (1 -> 512 leaves), built and stored in {el:?}");
        (msg_b64(&c), msg_b64(&gi.unwrap()), msg_b64(&w.unwrap()))
    };
    let line = format!("COMMIT #big {commit} {gi} {welcome}\n");
    println!(
        "  its COMMIT line: {} bytes = {:.1}% of 8 MiB (commit {}, groupinfo {}, welcome {})",
        line.len(),
        line.len() as f64 / 8388608.0 * 100.0,
        commit.len(),
        gi.len(),
        welcome.len()
    );
    let t = Instant::now();
    let g = MlsGroup::load(SqlProvider::new(&b).storage(), &bgid).unwrap().unwrap();
    println!("  MlsGroup::load at {} leaves from SQLite (JSON codec): {:?}", g.members().count(), t.elapsed());
    let sz: i64 = a
        .query_row("SELECT SUM(length(group_data)) FROM openmls_group_data", [], |r| r.get(0))
        .unwrap_or(0);
    println!("  openmls_group_data bytes for both groups: {sz}");

    // The server's PublicGroup at 512 leaves.
    let MlsMessageBodyIn::GroupInfo(vgi) = parse_msg(&gi) else { panic!() };
    let t = Instant::now();
    PublicGroup::from_external(&crypto, &sstore, g.export_ratchet_tree().into(), vgi, ProposalStore::new())
        .unwrap();
    println!("  server: from_external + store at 512 leaves: {:?}", t.elapsed());
    let t = Instant::now();
    let pg = PublicGroup::load(&sstore, &bgid).unwrap().unwrap();
    println!("  server: PublicGroup::load at {} leaves: {:?}", pg.members().count(), t.elapsed());

    let _ = std::fs::remove_dir_all(&dir);
}
