//! Transcript tests of KEYPKG (12.4), WELCOME (12.7) and BACKUP (12.10),
//! through the [`Handler`] trait.
//!
//! KeyPackages are put in through the store, as are Welcomes, so that
//! these tests need no MLS: `group_tests` has real ones.
//! Devices sign in without AUTH, each with a key made from a fixed seed.

use std::sync::Arc;
use std::time::Duration;

use risala_proto::auth::{PublicKey, SecretKey};
use risala_proto::mls::{BackupBlob, KeyPackage, RatchetTree, Welcome};
use risala_proto::names::{Identity, Room, Seq, Uid};

use super::tests::{Client, Harness, config, start, timers};
use super::*;
use crate::store::{GroupStore as _, NewKeyPackage, SqliteStore};

/// Hosted here.
const ALICE: &str = "alice@example.org";
/// Not hosted: its key file comes from the fetcher.
const BOB: &str = "bob@example.net";

fn uid(s: &str) -> Uid {
    s.parse().unwrap()
}

fn identity(s: &str) -> Identity {
    s.parse().unwrap()
}

fn key(n: u8) -> PublicKey {
    SecretKey::from_seed([n; 32]).public_key()
}

/// A KeyPackage whose bytes are `n`, whose lifetime ends a day after the
/// start, and whose ref is `n` too.
fn kp(n: u8, last_resort: bool) -> NewKeyPackage {
    NewKeyPackage {
        key_package: KeyPackage::from_bytes(&[n; 6]).unwrap(),
        kp_ref: vec![n],
        not_after: start().checked_add(Duration::from_secs(86400)).unwrap(),
        last_resort,
    }
}

/// The KEYPKG line of `who`'s KeyPackage `n`.
fn kp_line(who: &str, n: u8) -> String {
    format!("KEYPKG {who} {}", kp(n, false).key_package)
}

/// A hub that hosts `example.org`, where alice is registered with keys 1,
/// 2 and 3, and bob of `example.net` has signed in before. Bob's key file
/// lists keys 5 and 6. Alice and Bob have a direct conversation whose
/// group is in epoch 7, and Alice one with herself in epoch 3.
struct World {
    h: Harness,
    fetcher: Arc<MemoryFetcher>,
    /// The id of Alice and Bob's conversation.
    direct: String,
    /// The id of Alice's conversation with herself.
    own: String,
    /// The store, as itself, for what only tests do with it.
    sqlite: Arc<SqliteStore>,
}

/// A group of `who` as the store keeps it, in epoch `epoch`, without
/// MLS: these tests do not read it.
fn fake_group(
    id: u8,
    epoch: u64,
    who: &[(&str, u8)],
) -> (crate::store::GroupRecord, Vec<crate::store::GroupLeaf>) {
    let record = crate::store::GroupRecord {
        group_id: vec![id; 32],
        meta: crate::store::GroupMeta { epoch, seq: None },
        group_info: risala_proto::mls::GroupInfo::from_bytes(&[id; 9]).unwrap(),
        parts: crate::store::GroupParts {
            tree: vec![id, 1],
            context: vec![id, 2],
            interim_hash: vec![id, 3],
            confirmation_tag: vec![id, 4],
        },
    };
    let leaves = who
        .iter()
        .zip(0..)
        .map(|((w, n), index)| crate::store::GroupLeaf {
            index,
            uid: uid(w),
            key: key(*n),
        })
        .collect();
    (record, leaves)
}

/// Starts the direct conversation of `a` and `b` in the store.
fn start_direct(store: &SqliteStore, a: &str, b: &str, id: u8, epoch: u64) -> String {
    let (record, leaves) = fake_group(id, epoch, &[(a, 1)]);
    match store
        .init_direct(&uid(a), &uid(b), &record, &leaves, start())
        .unwrap()
    {
        crate::store::DirectInit::Done(direct) => direct.id.to_string(),
        other => panic!("{other:?}"),
    }
}

impl World {
    fn new() -> World {
        World::with(|_| {})
    }

    fn with(adjust: impl FnOnce(&mut Config)) -> World {
        let mut c = config();
        c.identity_domain = Some("example.org".into());
        adjust(&mut c);
        let store = SqliteStore::open_in_memory().unwrap();
        for room in &c.rooms {
            store.ensure_room(&room.parse().unwrap(), start()).unwrap();
        }
        store.register(&uid(ALICE), &key(1), start()).unwrap();
        for n in [2, 3] {
            store
                .add_hosted_key(&uid(ALICE), &key(n), "", 64, start())
                .unwrap();
        }
        store.touch_identity(&uid(BOB), start()).unwrap();
        let direct = start_direct(&store, ALICE, BOB, 1, 7);
        let own = start_direct(&store, ALICE, ALICE, 2, 3);
        let sqlite = Arc::new(store);
        let store: Arc<dyn Store> = sqlite.clone();
        let fetcher = Arc::new(MemoryFetcher::new());
        fetcher.set(&identity(BOB), vec![key(5), key(6)]);
        let keys = KeyServices::shared(fetcher.clone(), Arc::new(NoPublisher));
        let clock = Arc::new(ManualClock::new(start()));
        let hub = Hub::build(c, store.clone(), clock.clone(), timers(), keys).unwrap();
        World {
            h: Harness {
                hub,
                store,
                clock,
                next: 0,
            },
            fetcher,
            direct,
            own,
            sqlite,
        }
    }

    /// A connection signed in as `who` with device key `n`, without AUTH.
    fn device(&mut self, who: &str, n: u8) -> Client {
        let c = self.h.connect();
        assert!(self.h.hub.inner.reg().attach(c.id, &uid(who), Some(key(n))));
        c
    }

    /// Stores KeyPackage `kp` for `who`'s device `n`.
    fn put_kp(&self, who: &str, n: u8, kp: NewKeyPackage) {
        self.h
            .store
            .add_key_package(&uid(who), &key(n), &kp, 100, start())
            .unwrap();
    }

    async fn send(&self, c: &Client, line: &str) {
        self.h.send(c, line).await;
    }
}

/// `lines` with their order ignored, but for the last.
fn sorted(mut lines: Vec<String>) -> Vec<String> {
    let last = lines.pop();
    lines.sort();
    lines.extend(last);
    lines
}

#[tokio::test]
async fn guests_may_not_use_them() {
    let mut w = World::new();
    let mut sam = w.h.guest("sam").await;
    for line in [
        "keypkg count",
        "keypkg get alice@example.org",
        "welcome list",
        "backup del",
    ] {
        w.send(&sam, line).await;
        assert_eq!(sam.lines(), ["ERR forbidden not for guests"], "{line}");
    }
}

// ---------------------------------------------------------------------------
// KEYPKG (12.4)

/// KEYPKG ADD refuses what is not a KeyPackage (12.4). Real ones are in
/// `group_tests`.
#[tokio::test]
async fn keypkg_add_refuses_what_is_not_a_key_package() {
    let mut w = World::new();
    let mut a1 = w.device(ALICE, 1);
    w.send(&a1, "keypkg add AAEABQAB").await;
    assert_eq!(a1.lines(), ["ERR invalid not a valid KeyPackage"]);
    w.send(&a1, "keypkg count").await;
    assert_eq!(a1.lines(), ["OK count=0 last-resort=no"]);
}

#[tokio::test]
async fn keypkg_count_is_the_devices_own() {
    let mut w = World::new();
    w.put_kp(ALICE, 1, kp(10, false));
    w.put_kp(ALICE, 1, kp(11, false));
    w.put_kp(ALICE, 1, kp(19, true));
    w.put_kp(ALICE, 2, kp(20, false));
    let mut a1 = w.device(ALICE, 1);
    let mut a2 = w.device(ALICE, 2);
    let mut a3 = w.device(ALICE, 3);
    w.send(&a1, "keypkg count").await;
    assert_eq!(a1.lines(), ["OK count=2 last-resort=yes"]);
    w.send(&a2, "keypkg count").await;
    assert_eq!(a2.lines(), ["OK count=1 last-resort=no"]);
    w.send(&a3, "keypkg count").await;
    assert_eq!(a3.lines(), ["OK count=0 last-resort=no"]);
    // Ended KeyPackages do not count.
    w.h.clock.advance(Duration::from_secs(86400));
    w.send(&a1, "keypkg count").await;
    assert_eq!(a1.lines(), ["OK count=0 last-resort=no"]);
    assert_eq!(w.h.hub.prune_key_packages().await.unwrap(), 4);
}

/// Each ordinary KeyPackage once, then the last-resort one, which stays.
/// Devices whose keys left the key file, and the asking device, are left
/// out.
#[tokio::test]
async fn keypkg_get_hands_out_each_once_then_the_last_resort_one() {
    let mut w = World::new();
    w.put_kp(ALICE, 1, kp(10, false));
    w.put_kp(ALICE, 2, kp(20, false));
    w.put_kp(ALICE, 2, kp(21, false));
    w.put_kp(ALICE, 2, kp(29, true));
    // Key 4 is not alice's.
    w.put_kp(ALICE, 4, kp(40, false));
    let mut bob = w.device(BOB, 5);
    w.send(&bob, "@ref=g keypkg get alice@example.org").await;
    assert_eq!(
        sorted(bob.lines()),
        [
            format!("@ref=g {}", kp_line(ALICE, 10)),
            format!("@ref=g {}", kp_line(ALICE, 20)),
            "@ref=g OK".into()
        ]
    );
    w.send(&bob, "keypkg get alice@example.org").await;
    assert_eq!(bob.lines(), [kp_line(ALICE, 21), "OK".into()]);
    for _ in 0..2 {
        w.send(&bob, "keypkg get alice@example.org").await;
        assert_eq!(bob.lines(), [kp_line(ALICE, 29), "OK".into()]);
    }

    // Alice's own devices, but not the one that asks.
    w.put_kp(ALICE, 1, kp(11, false));
    let mut a1 = w.device(ALICE, 1);
    w.send(&a1, "keypkg get alice@example.org").await;
    assert_eq!(a1.lines(), [kp_line(ALICE, 29), "OK".into()]);
    // Its own one is still there; 10 went to bob.
    w.send(&a1, "keypkg count").await;
    assert_eq!(a1.lines(), ["OK count=1 last-resort=no"]);
}

#[tokio::test]
async fn keypkg_get_of_an_unknown_uid_is_not_found() {
    let mut w = World::new();
    let mut bob = w.device(BOB, 5);
    for who in ["carol@example.org", "~sam"] {
        w.send(&bob, &format!("keypkg get {who}")).await;
        assert_eq!(bob.lines(), ["ERR not-found no such identity"], "{who}");
    }
    // A known identity without KeyPackages has none to give.
    w.send(&bob, "keypkg get bob@example.net").await;
    assert_eq!(bob.lines(), ["OK"]);
}

/// For an identity the server does not host, its key file says which
/// devices count (4.4, 12.4).
#[tokio::test]
async fn keypkg_get_goes_by_the_fetched_key_file() {
    let mut w = World::new();
    for n in [5, 6, 7] {
        w.put_kp(BOB, n, kp(n, false));
    }
    let mut alice = w.device(ALICE, 1);
    // Key 7 is not in bob's key file, which was fetched just now: its
    // KeyPackages go.
    w.send(&alice, "keypkg get bob@example.net").await;
    assert_eq!(
        sorted(alice.lines()),
        [kp_line(BOB, 5), kp_line(BOB, 6), "OK".into()]
    );
    assert_eq!(w.h.store.stored_devices(&uid(BOB)).unwrap(), Vec::new());

    // A cached copy that is older than a device is fetched again.
    w.put_kp(BOB, 5, kp(15, false));
    w.put_kp(BOB, 7, kp(17, false));
    w.fetcher.set(&identity(BOB), vec![key(5), key(7)]);
    w.fetcher.set_cached(&identity(BOB), vec![key(5)]);
    w.send(&alice, "keypkg get bob@example.net").await;
    assert_eq!(
        sorted(alice.lines()),
        [kp_line(BOB, 15), kp_line(BOB, 17), "OK".into()]
    );
    assert_eq!(
        w.fetcher.calls()[1..],
        [(identity(BOB), false), (identity(BOB), true)]
    );

    // Without the key file, nothing is handed out.
    w.put_kp(BOB, 5, kp(25, false));
    w.fetcher.fail(&identity(BOB));
    w.send(&alice, "keypkg get bob@example.net").await;
    let lines = alice.lines();
    assert_eq!(lines.len(), 1);
    assert!(
        lines[0].starts_with("@retry=10 ERR unavailable "),
        "{lines:?}"
    );
    assert_eq!(w.h.store.stored_devices(&uid(BOB)).unwrap(), [key(5)]);
}

#[tokio::test]
async fn keypkg_get_is_rate_limited() {
    let mut w = World::with(|c| c.limits.key_package_gets_per_hour = 2);
    let mut bob = w.device(BOB, 5);
    let mut b2 = w.device(BOB, 6);
    for _ in 0..2 {
        w.send(&bob, "keypkg get alice@example.org").await;
        assert_eq!(bob.lines(), ["OK"]);
    }
    // Per identity, whichever device asks.
    w.send(&b2, "keypkg get alice@example.org").await;
    let lines = b2.lines();
    assert!(
        lines.len() == 1 && lines[0].contains("ERR rate-limited"),
        "{lines:?}"
    );
    assert!(lines[0].starts_with("@retry=3600 "), "{lines:?}");
    // One that fails does not count.
    w.h.clock.advance(Duration::from_secs(3600));
    w.send(&bob, "keypkg get carol@example.org").await;
    assert_eq!(bob.lines(), ["ERR not-found no such identity"]);
    for _ in 0..2 {
        w.send(&bob, "keypkg get alice@example.org").await;
        assert_eq!(bob.lines(), ["OK"]);
    }
}

// ---------------------------------------------------------------------------
// WELCOME (12.7)

fn welcome(n: u8) -> Welcome {
    Welcome::from_bytes(&[n; 3]).unwrap()
}

fn tree(len: usize) -> RatchetTree {
    RatchetTree::from_bytes(&vec![7; len]).unwrap()
}

/// What COMMIT does with a Welcome: stores it for `devices` in
/// `#general`, as added by the commit whose event is `seq`, and sends it.
async fn store_welcome(w: &World, seq: u64, n: u8, tree: &RatchetTree, devices: &[(&str, u8)]) {
    let room: Room = "#general".parse().unwrap();
    let st = w.h.hub.inner.lock_room(&room).await.unwrap();
    let welcome = crate::store::NewWelcome {
        welcome: welcome(n),
        tree: tree.clone(),
        devices: devices.iter().map(|(who, n)| (uid(who), key(*n))).collect(),
    };
    let seq = Seq::new(seq).unwrap();
    let ids = w
        .sqlite
        .add_welcomes(
            st.key,
            seq,
            &welcome.welcome,
            &welcome.tree,
            &welcome.devices,
        )
        .unwrap();
    w.h.hub.inner.send_welcomes(&st, seq, &welcome, &ids);
}

/// The id of a WELCOME line.
fn welcome_id(line: &str) -> String {
    line.split(' ').nth(2).unwrap().to_owned()
}

#[tokio::test]
async fn welcomes_reach_their_device_until_it_deletes_them() {
    let mut w = World::new();
    let mut a1 = w.device(ALICE, 1);
    let mut a1b = w.device(ALICE, 1);
    let mut a2 = w.device(ALICE, 2);
    let mut bob = w.device(BOB, 5);
    let small = tree(3);
    store_welcome(&w, 4, 1, &small, &[(ALICE, 1), (BOB, 5)]).await;
    // Live, to every connection of each device added, and no other.
    let live = a1.lines();
    assert_eq!(live.len(), 1);
    let id = welcome_id(&live[0]);
    assert_eq!(
        live[0],
        format!("WELCOME #general {id} 4 {} {small}", welcome(1))
    );
    assert_eq!(a1b.lines(), live);
    assert!(a2.lines().is_empty());
    let bob_live = bob.lines();
    assert_eq!(bob_live.len(), 1);
    assert_ne!(welcome_id(&bob_live[0]), id);

    // Pending until deleted, in the order they were stored.
    store_welcome(&w, 9, 2, &small, &[(ALICE, 1)]).await;
    let second = welcome_id(&a1.lines()[0]);
    a1b.lines();
    w.send(&a1, "@ref=l welcome list").await;
    assert_eq!(
        a1.lines(),
        [
            format!("@ref=l {}", live[0]),
            format!("@ref=l WELCOME #general {second} 9 {} {small}", welcome(2)),
            "@ref=l OK".into()
        ]
    );
    w.send(&a2, "welcome list").await;
    assert_eq!(a2.lines(), ["OK"]);
    // Another device cannot delete it: nothing happens.
    w.send(&a2, &format!("welcome del {id}")).await;
    assert_eq!(a2.lines(), ["OK"]);
    w.send(&a1b, &format!("welcome del {id}")).await;
    assert_eq!(a1b.lines(), ["OK"]);
    // Deleting it again is fine, in case the OK was lost.
    w.send(&a1, &format!("welcome del {id}")).await;
    assert_eq!(a1.lines(), ["OK"]);
    w.send(&a1, "welcome list").await;
    assert_eq!(a1.lines().len(), 2);
    // Bob still has the first commit's Welcome, and its tree.
    w.send(&bob, "welcome list").await;
    assert_eq!(bob.lines(), [bob_live[0].clone(), "OK".into()]);
}

/// A Welcome with its tree is usually longer than a normal server line,
/// so it goes as a long line (2.3), one at a time.
#[tokio::test]
async fn welcomes_may_be_long_lines() {
    let mut w = World::new();
    let mut a1 = w.device(ALICE, 1);
    let big = tree(40_000);
    store_welcome(&w, 4, 1, &big, &[(ALICE, 1)]).await;
    store_welcome(&w, 5, 2, &big, &[(ALICE, 1)]).await;
    assert_eq!(a1.lines().len(), 2);
    w.send(&a1, "welcome list").await;
    let lines = a1.lines();
    assert_eq!(lines.len(), 3);
    assert!(lines[0].len() > 50_000 && lines[1].len() > 50_000);
}

// ---------------------------------------------------------------------------
// BACKUP (12.10)

/// A blob under key id `key_id`, filled with `n`.
fn blob(key_id: u8, n: u8) -> BackupBlob {
    let mut b = [n; 84];
    b[..8].copy_from_slice(&[key_id; 8]);
    BackupBlob::from_bytes(b)
}

#[tokio::test]
async fn backups_belong_to_the_identity() {
    let mut w = World::new();
    let (d, own) = (w.direct.clone(), w.own.clone());
    let mut a1 = w.device(ALICE, 1);
    let mut a2 = w.device(ALICE, 2);
    let mut bob = w.device(BOB, 5);
    for (epoch, b) in [(0, blob(1, 0)), (1, blob(1, 1)), (1, blob(2, 2))] {
        w.send(&a1, &format!("backup add {d} {epoch} {b}")).await;
        assert_eq!(a1.lines(), ["OK"]);
    }
    // The same key id again: the first is kept.
    w.send(&a2, &format!("backup add {d} 0 {}", blob(1, 9)))
        .await;
    assert_eq!(a2.lines(), ["OK"]);
    let all = [
        format!("BACKUP {d} 0 {}", blob(1, 0)),
        format!("BACKUP {d} 1 {}", blob(1, 1)),
        format!("BACKUP {d} 1 {}", blob(2, 2)),
    ];
    w.send(&a2, &format!("backup get {d}")).await;
    assert_eq!(a2.lines(), [&all[..], &["OK more=0".into()]].concat());
    w.send(&bob, &format!("backup get {d}")).await;
    assert_eq!(bob.lines(), ["OK more=0"]);

    // Pages of whole epochs.
    w.send(&a1, &format!("@ref=p backup get {d} limit=1")).await;
    assert_eq!(
        a1.lines(),
        [format!("@ref=p {}", all[0]), "@ref=p OK more=1".into()]
    );
    w.send(&a1, &format!("backup get {d} after=0 limit=1"))
        .await;
    assert_eq!(a1.lines(), [&all[1..], &["OK more=0".into()]].concat());
    w.send(&a1, &format!("backup get {d} after=1")).await;
    assert_eq!(a1.lines(), ["OK more=0"]);

    // Delete one conversation's, then everything.
    w.send(&a1, &format!("backup add {own} 3 {}", blob(1, 3)))
        .await;
    assert_eq!(a1.lines(), ["OK"]);
    w.send(&bob, &format!("backup del {d}")).await;
    assert_eq!(bob.lines(), ["OK"]);
    w.send(&a2, &format!("backup del {d}")).await;
    assert_eq!(a2.lines(), ["OK"]);
    w.send(&a1, &format!("backup get {d}")).await;
    assert_eq!(a1.lines(), ["OK more=0"]);
    w.send(&a1, &format!("backup get {own}")).await;
    assert_eq!(a1.lines().len(), 2);
    w.send(&a1, "backup del").await;
    assert_eq!(a1.lines(), ["OK"]);
    w.send(&a1, &format!("backup get {own}")).await;
    assert_eq!(a1.lines(), ["OK more=0"]);
}

#[tokio::test]
async fn backups_are_for_the_identitys_conversations_up_to_their_epoch() {
    let mut w = World::new();
    let (d, own) = (w.direct.clone(), w.own.clone());
    let mut a1 = w.device(ALICE, 1);
    let mut bob = w.device(BOB, 5);
    let mut carol = w.device("carol@example.org", 9);
    let never = "ERR forbidden you have never been in that conversation";
    let later = "ERR forbidden the conversation's group has not reached that epoch";
    // Up to the current epoch, and not after.
    for (epoch, reply) in [(7, "OK"), (8, later), (1_u64 << 40, later)] {
        w.send(&bob, &format!("backup add {d} {epoch} {}", blob(1, 0)))
            .await;
        assert_eq!(bob.lines(), [reply], "epoch {epoch}");
    }
    // Not someone else's conversation, nor one that does not exist.
    for conv in [&d, &own, &"k3f9q2".to_owned()] {
        w.send(&carol, &format!("backup add {conv} 0 {}", blob(1, 0)))
            .await;
        assert_eq!(carol.lines(), [never], "{conv}");
    }
    w.send(&bob, &format!("backup add {own} 0 {}", blob(1, 0)))
        .await;
    assert_eq!(bob.lines(), [never]);
    // A room without a group has no epoch yet.
    let general =
        w.h.hub
            .inner
            .lock_room(&"#general".parse().unwrap())
            .await
            .unwrap()
            .id
            .to_string();
    w.send(&a1, "join #general").await;
    a1.lines();
    w.send(&a1, &format!("backup add {general} 0 {}", blob(1, 0)))
        .await;
    assert_eq!(a1.lines(), [later]);
    w.send(&bob, &format!("backup add {general} 0 {}", blob(1, 0)))
        .await;
    assert_eq!(bob.lines(), [never]);
}

#[tokio::test]
async fn an_epoch_keeps_a_few_key_ids() {
    let mut w = World::new();
    let d = w.direct.clone();
    let mut a1 = w.device(ALICE, 1);
    for n in 0..MAX_BACKUP_KEYS_PER_EPOCH as u8 {
        w.send(&a1, &format!("backup add {d} 7 {}", blob(n, n)))
            .await;
        assert_eq!(a1.lines(), ["OK"]);
    }
    w.send(&a1, &format!("backup add {d} 7 {}", blob(99, 0)))
        .await;
    let lines = a1.lines();
    assert!(lines[0].starts_with("ERR forbidden "), "{lines:?}");
    // One it has is still fine.
    w.send(&a1, &format!("backup add {d} 7 {}", blob(0, 5)))
        .await;
    assert_eq!(a1.lines(), ["OK"]);
}

// ---------------------------------------------------------------------------
// Keys and identities that go (4.7, 4.8, 10.5)

/// Puts a KeyPackage and a Welcome in for each of `devices`.
async fn give_each(w: &World, devices: &[(&str, u8)]) {
    for (who, n) in devices {
        w.put_kp(who, *n, kp(*n, false));
    }
    store_welcome(w, 4, 1, &tree(3), devices).await;
}

/// The devices of `who` that have KeyPackages or Welcomes.
fn devices_of(w: &World, who: &str) -> Vec<PublicKey> {
    w.h.store.stored_devices(&uid(who)).unwrap()
}

#[tokio::test]
async fn a_deleted_key_takes_its_key_packages_and_welcomes() {
    let mut w = World::with(|c| c.operators = vec!["op@example.org".into()]);
    give_each(&w, &[(ALICE, 1), (ALICE, 2), (ALICE, 3)]).await;
    let mut a1 = w.device(ALICE, 1);
    let mut a2 = w.device(ALICE, 2);
    w.send(&a1, &format!("key del {}", key(2))).await;
    assert_eq!(a1.lines(), ["OK"]);
    assert_eq!(a2.lines(), ["<close> BYE this device's key was removed"]);
    // In the order of their base64.
    let mut left = vec![key(1), key(3)];
    left.sort_by_key(|k| k.to_string());
    assert_eq!(devices_of(&w, ALICE), left);

    // ADMIN DELKEY too (10.5).
    let mut op = w.device("op@example.org", 9);
    w.send(&op, &format!("admin delkey alice@example.org {}", key(3)))
        .await;
    assert_eq!(op.lines(), ["OK"]);
    assert_eq!(devices_of(&w, ALICE), [key(1)]);
}

#[tokio::test]
async fn unregister_deletes_key_packages_welcomes_and_backups() {
    let mut w = World::new();
    let d = w.direct.clone();
    give_each(&w, &[(ALICE, 1), (BOB, 5)]).await;
    let mut a1 = w.device(ALICE, 1);
    w.send(&a1, &format!("backup add {d} 0 {}", blob(1, 0)))
        .await;
    let mut bob = w.device(BOB, 5);
    w.send(&bob, &format!("backup add {d} 0 {}", blob(1, 0)))
        .await;
    a1.lines();
    bob.lines();
    w.send(&a1, "unregister alice@example.org").await;
    assert_eq!(a1.lines(), ["OK", "<close> BYE identity deleted"]);
    assert!(devices_of(&w, ALICE).is_empty());
    let page =
        w.h.store
            .backups(&uid(ALICE), &d.parse().unwrap(), None, 500, 100)
            .unwrap();
    assert!(page.blobs.is_empty());
    // Bob's stay, with the Welcome he still has pending.
    assert_eq!(devices_of(&w, BOB), [key(5)]);
    w.send(&bob, "welcome list").await;
    assert_eq!(bob.lines().len(), 2);
    w.send(&bob, &format!("backup get {d}")).await;
    assert_eq!(bob.lines().len(), 2);
}
