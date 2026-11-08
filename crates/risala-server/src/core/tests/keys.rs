//! KeyPackages, Welcomes, blobs, backups and uploads (5.6, 12.5, 12.8,
//! 12.12, 12.13).
//!
//! These tests run the hub with a files directory of their own, key files
//! from a [`MemoryFetcher`], and the clock stopped at the real time, since
//! OpenMLS gives KeyPackages lifetimes from the system clock (12.5).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use openmls_memory_storage::MemoryStorage;
use risala_mls::openmls::prelude::MlsMessageOut;
use risala_mls::{Provider, RisalaProfile, SigningKey};
use risala_proto::auth::PublicKey;
use risala_proto::binary::{WRAPPED_KEY_LEN, WrappedKey, write_blob_list};
use risala_proto::mls::{
    GroupId, KeyPackage, KeyPackageRef, PutSecret, RatchetTree, SendToken, Welcome,
};
use risala_proto::names::{BlobRef, BoxName, Identity, Uid};
use tls_codec::Serialize as _;

use super::*;
use crate::core::keys::disk::{PutTarget, Refused};
use crate::core::keys::{self, paths};
use crate::keyfiles::{MemoryFetcher, MemoryPublisher};
use crate::store::{MailboxStore as _, NewMailbox};
use crate::testing::{TestChain, TestIdentity, test_log_key};

const FILES: &str = "https://files.example.org";
const BOX: &str = "ujzdegxdncf32epf3dhodzdoci";

/// A hub for these tests, and what it keeps around.
struct Keys {
    h: Harness,
    fetcher: Arc<MemoryFetcher>,
    /// Each identity's chain, and the devices it lists.
    chains: Mutex<HashMap<Identity, (TestChain, Vec<TestIdentity>)>>,
    _dir: tempfile::TempDir,
}

impl std::ops::Deref for Keys {
    type Target = Harness;
    fn deref(&self) -> &Harness {
        &self.h
    }
}

impl std::ops::DerefMut for Keys {
    fn deref_mut(&mut self) -> &mut Harness {
        &mut self.h
    }
}

/// A hub whose files live in a new directory, with `f` applied to the
/// configuration.
fn keys_with(f: impl FnOnce(&mut Config)) -> Keys {
    let dir = tempfile::tempdir().unwrap();
    let mut c = config();
    c.state_dir = dir.path().to_owned();
    f(&mut c);
    let store = Arc::new(SqliteStore::open_in_memory().unwrap());
    let clock = Arc::new(ManualClock::new(Timestamp::now()));
    let fetcher = Arc::new(MemoryFetcher::new());
    let hub = Hub::build(
        c,
        store.clone(),
        clock.clone(),
        timers(),
        KeyServices::shared(fetcher.clone(), Arc::new(MemoryPublisher::new())),
    )
    .unwrap();
    hub.set_files_url(FILES);
    Keys {
        h: Harness {
            hub,
            store,
            clock,
            next: 0,
        },
        fetcher,
        chains: Mutex::new(HashMap::new()),
        _dir: dir,
    }
}

fn keys() -> Keys {
    keys_with(|_| {})
}

/// A device of an identity, with its device key and MLS storage.
struct Dev {
    uid: Uid,
    seed: u8,
    key: SigningKey,
    provider: Provider<MemoryStorage>,
}

impl Dev {
    fn new(uid: &str, seed: u8) -> Dev {
        Dev {
            uid: uid.parse().unwrap(),
            seed,
            key: SigningKey::from_seed([seed; 32]),
            provider: Provider::new(MemoryStorage::default()).unwrap(),
        }
    }

    /// The device id (4.4).
    fn id(&self) -> [u8; 48] {
        risala_mls::DeviceId::of_device_key(self.key.public_key()).0
    }

    fn public(&self) -> PublicKey {
        PublicKey::from_bytes(self.key.public_key())
    }

    /// A new KeyPackage, in base64, and its KeyPackageRef in base64.
    fn key_package(&self, last_resort: bool) -> (String, String) {
        let profile = RisalaProfile::new("", Timestamp::now().unix_millis()).unwrap();
        let kp = risala_mls::keypackage::make_key_package(
            &self.provider,
            &self.key,
            &self.uid,
            &profile,
            last_resort,
        )
        .unwrap()
        .key_package;
        let r = kp.hash_ref(self.provider.shared_crypto().as_ref()).unwrap();
        let bytes = MlsMessageOut::from(kp).tls_serialize_detached().unwrap();
        let kp_ref: [u8; 48] = r.as_slice().try_into().unwrap();
        (
            KeyPackage::from_bytes(&bytes).unwrap().to_string(),
            KeyPackageRef::from_bytes(kp_ref).to_string(),
        )
    }
}

impl Keys {
    /// A connection signed in as `dev`, from `peer`.
    fn sign_in_from(&mut self, dev: &Dev, peer: &str) -> Client {
        let c = self.connect_from(peer);
        let device = Device {
            uid: dev.uid.clone(),
            key: dev.public(),
        };
        assert!(self.inner().reg().set_who(c.id, Who::SignedIn(device)));
        c
    }

    fn sign_in(&mut self, dev: &Dev) -> Client {
        self.sign_in_from(dev, "203.0.113.7:51000")
    }

    /// The key file of `devs`' identity lists `devs` as its current
    /// devices (and the first device of its chain, which has no
    /// KeyPackages): its chain adds the new ones and removes the others,
    /// so that it still extends the server's pin (4.6).
    fn key_file(&self, devs: &[&Dev]) {
        let identity: Identity = devs[0].uid.clone().try_into().unwrap();
        let mut chains = self.chains.lock().unwrap();
        let (chain, listed) = chains.entry(identity.clone()).or_insert_with(|| {
            let log = test_log_key(identity.domain(), 1, [5; 32]);
            (TestChain::new(identity.as_str(), &log).0, Vec::new())
        });
        let gone: Vec<TestIdentity> = listed
            .iter()
            .filter(|t| !devs.iter().any(|d| d.public() == t.public_key()))
            .cloned()
            .collect();
        if !gone.is_empty() {
            chain.remove_devices(&gone.iter().collect::<Vec<_>>());
            listed.retain(|t| devs.iter().any(|d| d.public() == t.public_key()));
        }
        for dev in devs {
            if !listed.iter().any(|t| t.public_key() == dev.public()) {
                let key = risala_proto::auth::SecretKey::from_seed([dev.seed; 32]);
                let added = chain.add_device_with_key("device", key);
                assert_eq!(added.public_key(), dev.public());
                listed.push(added);
            }
        }
        self.fetcher.set(&identity, chain.key_file());
    }

    /// Sends KEYPKG GET for `uid` on `c`, and returns the KeyPackages and
    /// put secrets of its KEYPKG lines, after checking that it ends with
    /// `OK`.
    async fn keypkg_get(&self, c: &mut Client, uid: &str) -> Vec<(String, String)> {
        self.send(c, &format!("KEYPKG GET {uid}")).await;
        let mut lines = c.lines();
        assert_eq!(lines.pop().as_deref(), Some("OK"), "{lines:?}");
        lines
            .iter()
            .map(|line| {
                let parts: Vec<&str> = line.split(' ').collect();
                assert_eq!(parts.len(), 4, "{line}");
                assert_eq!(parts[..2], ["KEYPKG", uid], "{line}");
                (parts[2].to_owned(), parts[3].to_owned())
            })
            .collect()
    }

    /// Uploads a KeyPackage of `dev` on `c`, and returns its ref.
    async fn add_key_package(&self, c: &mut Client, dev: &Dev, last_resort: bool) -> String {
        let (kp, kp_ref) = dev.key_package(last_resort);
        self.send(c, &format!("KEYPKG ADD {kp}")).await;
        assert_eq!(c.lines(), ["OK"]);
        kp_ref
    }

    /// Stores `bytes` as a blob through the BLOB command on `c` and the
    /// listener's side of its `put` URL.
    async fn store_blob(&self, c: &mut Client, bytes: &[u8]) -> BlobRef {
        let hash = BlobRef::of(bytes);
        self.send(
            c,
            &format!("BLOB {hash} {} box={BOX} token={}", bytes.len(), token()),
        )
        .await;
        let line = c.raw_lines().pop().unwrap();
        if line == "OK exists=yes" {
            return hash;
        }
        let url = value(&line, "put");
        self.put(&url, bytes).await.unwrap();
        hash
    }

    /// What the listener does with a body for the `put` URL `url`.
    async fn put(&self, url: &str, bytes: &[u8]) -> Result<bool, Refused> {
        let files = self.hub.files();
        let path = url.strip_prefix(FILES).unwrap();
        let (prefix, rest) = [paths::BLOB_PUT, paths::UPLOAD_PUT]
            .into_iter()
            .find_map(|p| path.strip_prefix(p).map(|rest| (p, rest)))
            .unwrap();
        let target = files.claim_put(prefix, rest).await?;
        assert_eq!(target.size(), bytes.len() as u64);
        if let PutTarget::Blob(put) = &target {
            assert_eq!(put.hash, BlobRef::of(bytes));
        }
        let (tmp, _file) = files.temp_file().await.unwrap();
        std::fs::write(&tmp, bytes).unwrap();
        files.commit(target, tmp).await
    }

    /// Creates the mailbox [`BOX`], whose token is [`token`].
    fn mailbox(&self) {
        self.store
            .create_mailbox(&NewMailbox {
                mailbox: BOX.parse().unwrap(),
                group_id: GroupId::from_bytes([1; 32]),
                first_epoch: 0,
                token_hash: token().hash(),
                created: self.inner().now(),
                moved_from: None,
            })
            .unwrap();
    }

    fn advance(&self, d: Duration) {
        self.clock.advance(d);
    }

    async fn expire(&self) {
        keys::expire(self.inner()).await.unwrap();
    }
}

fn token() -> SendToken {
    SendToken::from_bytes([5; 32])
}

fn days(n: u64) -> Duration {
    Duration::from_secs(n * 24 * 60 * 60)
}

/// A well-formed SealedWelcome (12.8): version 1, a KEM output and a
/// ciphertext.
fn sealed(n: u8) -> String {
    Welcome::from_bytes(&[1, 3, n, n, n, 2, n, n])
        .unwrap()
        .to_string()
}

/// An MLSMessage holding a Welcome of suite 0x0020, with no secrets, and
/// `n` for a GroupInfo.
fn mls_welcome(n: u8) -> String {
    Welcome::from_bytes(&[0, 1, 0, 3, 0, 0x20, 0, 1, n])
        .unwrap()
        .to_string()
}

fn b64(bytes: &[u8]) -> String {
    KeyPackage::from_bytes(bytes).unwrap().to_string()
}

// ---------------------------------------------------------------------------
// KeyPackages (12.5)

#[tokio::test]
async fn keypackages_are_counted_and_handed_out_once_but_the_last_resort_stays() {
    let mut h = keys();
    let bob = Dev::new("bob@example.net", 1);
    h.key_file(&[&bob]);
    let mut b = h.sign_in(&bob);
    h.send(&b, "KEYPKG COUNT").await;
    assert_eq!(b.lines(), ["OK count=0 last-resort=no"]);
    let (kp1, _) = bob.key_package(false);
    let (kp2, _) = bob.key_package(false);
    let (last, _) = bob.key_package(true);
    for kp in [&kp1, &kp2, &last] {
        h.send(&b, &format!("KEYPKG ADD {kp}")).await;
        assert_eq!(b.lines(), ["OK"]);
    }
    // The same one again changes nothing.
    h.send(&b, &format!("KEYPKG ADD {kp1}")).await;
    assert_eq!(b.lines(), ["OK"]);
    h.send(&b, "KEYPKG COUNT").await;
    assert_eq!(b.lines(), ["OK count=2 last-resort=yes"]);

    let mut anon = h.anon().await;
    let mut secrets = Vec::new();
    for expected in [&kp1, &kp2, &last, &last] {
        let got = h.keypkg_get(&mut anon, "bob@example.net").await;
        assert_eq!(got.len(), 1);
        assert_eq!(&got[0].0, expected);
        // A put secret of 32 bytes, new for each handout (12.5).
        let secret: PutSecret = got[0].1.parse().unwrap();
        assert!(!secrets.contains(&secret));
        secrets.push(secret);
    }
    h.send(&b, "KEYPKG COUNT").await;
    assert_eq!(b.lines(), ["OK count=0 last-resort=yes"]);
    // A new last-resort one replaces it.
    let (newer, _) = bob.key_package(true);
    h.send(&b, &format!("KEYPKG ADD {newer}")).await;
    assert_eq!(b.lines(), ["OK"]);
    let got = h.keypkg_get(&mut anon, "bob@example.net").await;
    assert_eq!(got[0].0, newer);
}

#[tokio::test]
async fn keypkg_get_gives_one_for_each_current_device() {
    let mut h = keys();
    let laptop = Dev::new("bob@example.net", 1);
    let phone = Dev::new("bob@example.net", 2);
    let gone = Dev::new("bob@example.net", 3);
    h.key_file(&[&laptop, &phone, &gone]);
    for dev in [&laptop, &phone, &gone] {
        let mut c = h.sign_in(dev);
        h.add_key_package(&mut c, dev, false).await;
        h.add_key_package(&mut c, dev, false).await;
    }
    let mut anon = h.anon().await;
    assert_eq!(h.keypkg_get(&mut anon, "bob@example.net").await.len(), 3);
    // The key file's chain removes the third device (4.4).
    h.key_file(&[&laptop, &phone]);
    let got = h.keypkg_get(&mut anon, "bob@example.net").await;
    assert_eq!(got.len(), 2, "{got:?}");
    assert_ne!(got[0], got[1]);
    // Keys missing: no current devices, so no lines (12.5).
    let identity: Identity = "bob@example.net".parse().unwrap();
    h.fetcher.gone(&identity);
    assert!(h.keypkg_get(&mut anon, "bob@example.net").await.is_empty());
}

#[tokio::test]
async fn keypkg_get_refuses_unknown_uids_and_unreachable_key_files() {
    let mut h = keys();
    let bob = Dev::new("bob@example.net", 1);
    let mut b = h.sign_in(&bob);
    h.add_key_package(&mut b, &bob, false).await;
    let mut anon = h.anon().await;
    for uid in ["carol@example.net", "~sam"] {
        h.send(&anon, &format!("KEYPKG GET {uid}")).await;
        assert_eq!(anon.lines(), ["ERR not-found"], "{uid}");
    }
    // The key file cannot be fetched, and no copy is cached (4.4).
    h.fetcher.fail(&"bob@example.net".parse().unwrap());
    h.send(&anon, "KEYPKG GET bob@example.net").await;
    assert_eq!(anon.lines(), ["ERR unavailable"]);
    // Nothing was handed out.
    h.send(&b, "KEYPKG COUNT").await;
    assert_eq!(b.lines(), ["OK count=1 last-resort=no"]);
    // A uid whose KeyPackages were all uploaded longer ago than retention
    // is forgotten.
    h.advance(days(31));
    h.expire().await;
    h.send(&anon, "KEYPKG GET bob@example.net").await;
    assert_eq!(anon.lines(), ["ERR not-found"]);
}

/// A hosted identity's devices come from the chain the server holds
/// (4.7), with no key file to fetch; here KEYS PUT adds one from a blob.
#[tokio::test]
async fn keypkg_get_reads_a_hosted_identitys_own_chain() {
    let mut h = keys_with(|c| {
        c.identity_domain = Some("example.org".into());
        c.server.registration = true;
    });
    let log = h.hub.key_log().unwrap();
    let (mut chain, first) = TestChain::new("alice@example.org", &log.log);
    let mut c = h.open("203.0.113.7:51000", Some("chat.example.org"));
    let nonce = c.raw_lines()[0].split(' ').nth(3).unwrap().parse().unwrap();
    h.send(&c, &chain.register_line(&first, "chat.example.org", &nonce))
        .await;
    assert_eq!(c.lines(), ["OK uid=alice@example.org"]);
    let alice = Dev::new("alice@example.org", 9);
    chain.add_device_with_key("phone", risala_proto::auth::SecretKey::from_seed([9; 32]));
    // KEYS PUT with its records in a blob (4.7, 12.12): one the server
    // does not hold is not found.
    let records = risala_proto::record::encode_records(&chain.records()[2..]);
    let after = chain.records()[1].hash();
    let missing = BlobRef::of(b"no records");
    h.send(&c, &format!("KEYS PUT {after} {missing}")).await;
    assert_eq!(c.lines(), ["ERR not-found no such blob"]);
    h.mailbox();
    let mut anon = h.anon().await;
    let hash = h.store_blob(&mut anon, &records).await;
    h.send(&c, &format!("KEYS PUT {after} {hash}")).await;
    let lines = c.lines();
    assert_eq!(lines.last().map(String::as_str), Some("OK"), "{lines:?}");
    assert!(lines[0].starts_with("RECORD "), "{lines:?}");
    let mut a = h.sign_in(&alice);
    h.add_key_package(&mut a, &alice, false).await;
    assert_eq!(h.keypkg_get(&mut anon, "alice@example.org").await.len(), 1);
}

#[tokio::test]
async fn keypkg_get_is_rate_limited_per_address_and_per_uid() {
    let mut h = keys_with(|c| c.limits.key_package_gets_per_hour = 2);
    let bob = Dev::new("bob@example.net", 1);
    let carol = Dev::new("carol@example.net", 2);
    for dev in [&bob, &carol] {
        h.key_file(&[dev]);
        let mut c = h.sign_in(dev);
        h.add_key_package(&mut c, dev, true).await;
    }
    // Per uid, from different addresses.
    for (i, peer) in ["198.51.100.1:1", "198.51.100.2:1", "198.51.100.3:1"]
        .iter()
        .enumerate()
    {
        let mut c = h.connect_from(peer);
        h.send(&c, "ANON").await;
        h.send(&c, "KEYPKG GET bob@example.net").await;
        let lines = c.lines();
        if i < 2 {
            assert_eq!(lines.last().unwrap(), "OK", "{lines:?}");
        } else {
            assert!(lines[1].starts_with("@retry="), "{lines:?}");
            assert!(lines[1].ends_with(" ERR rate-limited"), "{lines:?}");
        }
    }
    // Per address: one address has used one of its two.
    let mut c = h.connect_from("198.51.100.1:2");
    h.send(&c, "ANON").await;
    h.send(&c, "KEYPKG GET carol@example.net").await;
    assert_eq!(c.lines().last().unwrap(), "OK");
    h.send(&c, "KEYPKG GET carol@example.net").await;
    assert!(c.lines()[0].ends_with("ERR rate-limited"));
    // An hour later, they are free again.
    h.advance(Duration::from_secs(3601));
    h.send(&c, "KEYPKG GET bob@example.net").await;
    assert_eq!(c.lines().last().unwrap(), "OK");
}

#[tokio::test]
async fn keypkg_add_checks_the_keypackage() {
    let mut h = keys_with(|c| {
        c.limits.max_key_packages = 1;
        c.limits.max_key_package_bytes = 16 * 1024;
    });
    let bob = Dev::new("bob@example.net", 1);
    let other = Dev::new("bob@example.net", 2);
    let carol = Dev::new("carol@example.net", 1);
    let mut b = h.sign_in(&bob);
    // Not a KeyPackage.
    h.send(&b, &format!("KEYPKG ADD {}", b64(&[0, 1, 0, 5, 1, 2, 3])))
        .await;
    assert_eq!(b.lines(), ["ERR invalid"]);
    // Another device's, or another identity's with the same device key.
    for dev in [&other, &carol] {
        let (kp, _) = dev.key_package(false);
        h.send(&b, &format!("KEYPKG ADD {kp}")).await;
        assert_eq!(b.lines(), ["ERR invalid"]);
    }
    // Larger than the server takes (12.5: never below 16 KiB).
    h.send(&b, &format!("KEYPKG ADD {}", b64(&[0; 16 * 1024 + 1])))
        .await;
    assert_eq!(b.lines(), ["ERR too-long"]);
    // As many as the server keeps.
    h.add_key_package(&mut b, &bob, false).await;
    let (kp, _) = bob.key_package(false);
    h.send(&b, &format!("KEYPKG ADD {kp}")).await;
    assert_eq!(b.lines(), ["ERR forbidden"]);
    // The last-resort one does not count.
    h.add_key_package(&mut b, &bob, true).await;
    // Only signed-in connections.
    let mut anon = h.anon().await;
    h.send(&anon, &format!("KEYPKG ADD {kp}")).await;
    assert_eq!(anon.lines(), ["ERR wrong-connection"]);
    h.send(&anon, "KEYPKG COUNT").await;
    assert_eq!(anon.lines(), ["ERR wrong-connection"]);
}

#[tokio::test]
async fn keypackages_whose_lifetime_ended_are_neither_taken_nor_handed_out() {
    let mut h = keys();
    let bob = Dev::new("bob@example.net", 1);
    h.key_file(&[&bob]);
    let mut b = h.sign_in(&bob);
    h.add_key_package(&mut b, &bob, false).await;
    h.add_key_package(&mut b, &bob, true).await;
    // 12 weeks and two hours later, both have ended.
    h.advance(days(84) + Duration::from_secs(2 * 3600));
    h.send(&b, "KEYPKG COUNT").await;
    assert_eq!(b.lines(), ["OK count=0 last-resort=no"]);
    // ...and one made then is not acceptable to the server's clock now.
    let (kp, _) = bob.key_package(false);
    h.send(&b, &format!("KEYPKG ADD {kp}")).await;
    assert_eq!(b.lines(), ["ERR invalid"]);
}

// ---------------------------------------------------------------------------
// Welcomes (12.8)

/// A put secret no handout has.
fn stray_secret() -> PutSecret {
    PutSecret::from_bytes([0x5a; 32])
}

#[tokio::test]
async fn welcomes_need_the_put_secret_and_reach_the_device() {
    let mut h = keys();
    let bob = Dev::new("bob@example.net", 1);
    let phone = Dev::new("bob@example.net", 2);
    h.key_file(&[&bob, &phone]);
    let mut b = h.sign_in(&bob);
    let mut p = h.sign_in(&phone);
    let kp_ref = h.add_key_package(&mut b, &bob, false).await;
    let mut alice = h.anon().await;
    // Not handed out yet.
    let stray = stray_secret();
    h.send(
        &alice,
        &format!("WELCOME PUT {kp_ref} {stray} {}", sealed(1)),
    )
    .await;
    assert_eq!(alice.lines(), ["ERR not-found"]);
    let got = h.keypkg_get(&mut alice, "bob@example.net").await;
    assert_eq!(got.len(), 1);
    let secret = &got[0].1;
    // A plain MLS Welcome is not taken for a KeyPackage of KEYPKG GET, nor
    // anything that is not a Welcome.
    for bad in [
        mls_welcome(0xaa),
        b64(&[2, 1, 1, 1, 1]),
        b64(&[1, 1, 1, 1, 1, 9, 9]),
    ] {
        h.send(&alice, &format!("WELCOME PUT {kp_ref} {secret} {bad}"))
            .await;
        assert_eq!(alice.lines(), ["ERR invalid"]);
    }
    // Only with the handout's put secret (12.8).
    for wrong in [stray.to_string(), "-".into()] {
        let welcome = if wrong == "-" {
            mls_welcome(0xaa)
        } else {
            sealed(1)
        };
        h.send(&alice, &format!("WELCOME PUT {kp_ref} {wrong} {welcome}"))
            .await;
        assert_eq!(alice.lines(), ["ERR forbidden"], "{wrong}");
    }
    assert_eq!(b.lines(), Vec::<String>::new());
    h.send(
        &alice,
        &format!("WELCOME PUT {kp_ref} {secret} {}", sealed(1)),
    )
    .await;
    assert_eq!(alice.lines(), ["OK"]);
    // Sent at once to the device's signed-in connections, not others.
    let line = b.raw_lines();
    assert_eq!(line.len(), 1, "{line:?}");
    let id = line[0].split(' ').nth(1).unwrap().to_owned();
    assert_eq!(line[0], format!("WELCOME {id} {}", sealed(1)));
    assert_eq!(p.lines(), Vec::<String>::new());
    // The same Welcome again, as after a lost OK, changes nothing.
    h.send(
        &alice,
        &format!("WELCOME PUT {kp_ref} {secret} {}", sealed(1)),
    )
    .await;
    assert_eq!(alice.lines(), ["OK"]);
    assert_eq!(b.lines(), Vec::<String>::new());
    // Another replaces it while it is pending, under the same id.
    h.send(
        &alice,
        &format!("WELCOME PUT {kp_ref} {secret} {}", sealed(2)),
    )
    .await;
    assert_eq!(alice.lines(), ["OK"]);
    assert_eq!(b.lines(), [format!("WELCOME {id} {}", sealed(2))]);
    // Kept until the device deletes it.
    h.send(&b, "WELCOME LIST").await;
    assert_eq!(
        b.lines(),
        [format!("WELCOME {id} {}", sealed(2)), "OK".into()]
    );
    h.send(&p, "WELCOME LIST").await;
    assert_eq!(p.lines(), ["OK"]);
    h.send(&p, &format!("WELCOME DEL {id}")).await;
    assert_eq!(p.lines(), ["OK"]);
    h.send(&b, &format!("WELCOME DEL {id}")).await;
    assert_eq!(b.lines(), ["OK"]);
    h.send(&b, &format!("WELCOME DEL {id}")).await;
    assert_eq!(b.lines(), ["OK"]);
    h.send(&b, "WELCOME LIST").await;
    assert_eq!(b.lines(), ["OK"]);
    // Once fetched, each handout has had its one Welcome.
    h.send(
        &alice,
        &format!("WELCOME PUT {kp_ref} {secret} {}", sealed(3)),
    )
    .await;
    assert_eq!(alice.lines(), ["ERR forbidden"]);
    h.send(
        &alice,
        &format!("WELCOME PUT {kp_ref} {secret} {}", sealed(2)),
    )
    .await;
    assert_eq!(alice.lines(), ["OK"]);
    assert_eq!(b.lines(), Vec::<String>::new());
}

#[tokio::test]
async fn a_last_resort_keypackage_takes_one_welcome_per_handing_out() {
    let mut h = keys();
    let bob = Dev::new("bob@example.net", 1);
    h.key_file(&[&bob]);
    let mut b = h.sign_in(&bob);
    let kp_ref = h.add_key_package(&mut b, &bob, true).await;
    let mut alice = h.anon().await;
    let mut secrets = Vec::new();
    for _ in 0..2 {
        let got = h.keypkg_get(&mut alice, "bob@example.net").await;
        secrets.push(got[0].1.clone());
    }
    for (n, secret) in secrets.iter().enumerate() {
        let n = u8::try_from(n).unwrap();
        h.send(
            &alice,
            &format!("WELCOME PUT {kp_ref} {secret} {}", sealed(n)),
        )
        .await;
        assert_eq!(alice.lines(), ["OK"], "{n}");
    }
    assert_eq!(b.lines().len(), 2);
    h.send(&b, "WELCOME LIST").await;
    let lines = b.lines();
    assert_eq!(lines.len(), 2 + 1);
    assert_ne!(lines[0].split(' ').nth(1), lines[1].split(' ').nth(1));
}

#[tokio::test]
async fn pending_welcomes_are_limited_and_expire() {
    let mut h = keys_with(|c| c.files.max_pending_welcomes = 1);
    let bob = Dev::new("bob@example.net", 1);
    h.key_file(&[&bob]);
    let mut b = h.sign_in(&bob);
    let r1 = h.add_key_package(&mut b, &bob, false).await;
    let r2 = h.add_key_package(&mut b, &bob, false).await;
    let mut alice = h.anon().await;
    let s1 = h.keypkg_get(&mut alice, "bob@example.net").await[0]
        .1
        .clone();
    let s2 = h.keypkg_get(&mut alice, "bob@example.net").await[0]
        .1
        .clone();
    h.send(&alice, &format!("WELCOME PUT {r1} {s1} {}", sealed(1)))
        .await;
    assert_eq!(alice.lines(), ["OK"]);
    h.send(&alice, &format!("WELCOME PUT {r2} {s2} {}", sealed(2)))
        .await;
    assert_eq!(alice.lines(), ["ERR rate-limited"]);
    // Replacing one does not add to them.
    h.send(&alice, &format!("WELCOME PUT {r1} {s1} {}", sealed(3)))
        .await;
    assert_eq!(alice.lines(), ["OK"]);
    // Not fetched within retention: deleted (12.8).
    h.advance(days(31));
    h.expire().await;
    b.lines();
    h.send(&b, "WELCOME LIST").await;
    assert_eq!(b.lines(), ["OK"]);
    // Its handing out is forgotten too: no Welcome can be put for it.
    h.send(&alice, &format!("WELCOME PUT {r2} {s2} {}", sealed(2)))
        .await;
    assert_eq!(alice.lines(), ["ERR not-found"]);
}

#[tokio::test]
async fn a_removed_device_loses_its_keypackages_and_welcomes() {
    let mut h = keys();
    let bob = Dev::new("bob@example.net", 1);
    h.key_file(&[&bob]);
    let mut b = h.sign_in(&bob);
    let kp_ref = h.add_key_package(&mut b, &bob, false).await;
    h.add_key_package(&mut b, &bob, true).await;
    let mut alice = h.anon().await;
    let secret = h.keypkg_get(&mut alice, "bob@example.net").await[0]
        .1
        .clone();
    h.send(
        &alice,
        &format!("WELCOME PUT {kp_ref} {secret} {}", sealed(1)),
    )
    .await;
    assert_eq!(alice.lines(), ["OK"]);
    keys::device_removed(h.inner(), bob.uid.clone(), bob.key.public_key())
        .await
        .unwrap();
    b.lines();
    h.send(&b, "WELCOME LIST").await;
    assert_eq!(b.lines(), ["OK"]);
    h.send(&b, "KEYPKG COUNT").await;
    assert_eq!(b.lines(), ["OK count=0 last-resort=no"]);
}

/// The commit of an external proposal in [`BOX`], epoch 5, by `committer`,
/// with `tree`.
async fn room_joins(h: &Keys, committer: &Dev, kp_ref: KeyPackageRef, tree: Vec<u8>) {
    keys::room_joins_committed(
        h.inner(),
        BOX.parse().unwrap(),
        5,
        committer.uid.clone(),
        committer.id(),
        vec![kp_ref],
        tree,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn welcomes_for_external_proposals_come_from_the_committer_with_the_tree() {
    let mut h = keys();
    let bob = Dev::new("bob@example.net", 1);
    let other = Dev::new("bob@example.net", 2);
    let mut b = h.sign_in(&bob);
    let mut o = h.sign_in(&other);
    let kp_ref = KeyPackageRef::from_bytes([7; 48]);
    let mut guest = h.anon().await;
    h.send(&guest, &format!("WELCOME GET {kp_ref}")).await;
    assert_eq!(guest.lines(), ["ERR not-found"]);
    // Before the commit that applies the proposal, nobody may put it.
    h.send(&b, &format!("WELCOME PUT {kp_ref} - {}", mls_welcome(1)))
        .await;
    assert_eq!(b.lines(), ["ERR not-found"]);
    room_joins(&h, &bob, kp_ref, vec![1, 2, 3]).await;
    // Only the committing device, with `-` (12.8).
    let mut anon = h.anon().await;
    for c in [&mut anon, &mut o] {
        h.send(c, &format!("WELCOME PUT {kp_ref} - {}", mls_welcome(1)))
            .await;
        assert_eq!(c.lines(), ["ERR forbidden"]);
    }
    h.send(
        &b,
        &format!("WELCOME PUT {kp_ref} {} {}", stray_secret(), sealed(1)),
    )
    .await;
    assert_eq!(b.lines(), ["ERR forbidden"]);
    // An MLSMessage, not a SealedWelcome.
    h.send(&b, &format!("WELCOME PUT {kp_ref} - {}", sealed(1)))
        .await;
    assert_eq!(b.lines(), ["ERR invalid"]);
    h.send(&b, &format!("WELCOME PUT {kp_ref} - {}", mls_welcome(1)))
        .await;
    assert_eq!(b.lines(), ["OK"]);
    // Replaced while it has not been fetched.
    h.send(&b, &format!("WELCOME PUT {kp_ref} - {}", mls_welcome(2)))
        .await;
    assert_eq!(b.lines(), ["OK"]);
    // WELCOME GET gives the tree of its epoch (12.6, 12.8).
    h.send(&guest, &format!("WELCOME GET {kp_ref}")).await;
    let lines = guest.lines();
    assert_eq!(lines.len(), 2);
    let id = lines[0].split(' ').nth(1).unwrap();
    let tree = RatchetTree::from_bytes(&[1, 2, 3]).unwrap();
    assert_eq!(
        lines[0],
        format!("WELCOME {id} {} tree={tree}", mls_welcome(2))
    );
    assert_eq!(lines[1], "OK");
    // Fetched: only the same Welcome again is taken.
    h.send(&b, &format!("WELCOME PUT {kp_ref} - {}", mls_welcome(3)))
        .await;
    assert_eq!(b.lines(), ["ERR forbidden"]);
    h.send(&b, &format!("WELCOME PUT {kp_ref} - {}", mls_welcome(2)))
        .await;
    assert_eq!(b.lines(), ["OK"]);
    // Light clients are not built (12.6).
    h.send(&guest, &format!("WELCOME GET {kp_ref} light=yes"))
        .await;
    assert_eq!(guest.lines(), ["ERR not-supported"]);
    // Kept 24 hours after the commit, then dropped with the tree.
    h.advance(Duration::from_secs(23 * 3600));
    h.expire().await;
    h.send(&guest, &format!("WELCOME GET {kp_ref}")).await;
    assert_eq!(guest.lines().len(), 2);
    h.advance(Duration::from_secs(3600 + 1));
    h.expire().await;
    h.send(&guest, &format!("WELCOME GET {kp_ref}")).await;
    assert_eq!(guest.lines(), ["ERR not-found"]);
}

#[tokio::test]
async fn a_large_tree_is_a_blob_the_server_keeps_for_its_welcomes() {
    let mut h = keys();
    let bob = Dev::new("bob@example.net", 1);
    let mut b = h.sign_in(&bob);
    let kp_ref = KeyPackageRef::from_bytes([7; 48]);
    let tree = vec![7; 10_000];
    let hash = BlobRef::of(&tree);
    room_joins(&h, &bob, kp_ref, tree.clone()).await;
    h.send(&b, &format!("WELCOME PUT {kp_ref} - {}", mls_welcome(1)))
        .await;
    assert_eq!(b.lines(), ["OK"]);
    let mut guest = h.anon().await;
    h.send(&guest, &format!("WELCOME GET {kp_ref}")).await;
    let lines = guest.lines();
    assert!(lines[0].ends_with(&format!(" tree={hash}")), "{lines:?}");
    let files = h.hub.files();
    let (path, size) = files.blob(hash).await.unwrap();
    assert_eq!(size, 10_000);
    assert_eq!(std::fs::read(&path).unwrap(), tree);
    // Kept past retention while its Welcomes need it; gone with them.
    h.advance(Duration::from_secs(24 * 3600 + 1));
    h.expire().await;
    assert_eq!(files.blob(hash).await, Err(Refused::NotFound));
    assert!(!path.exists());
}

#[tokio::test]
async fn welcomes_may_be_blobs() {
    let mut h = keys();
    h.mailbox();
    let bob = Dev::new("bob@example.net", 1);
    h.key_file(&[&bob]);
    let mut b = h.sign_in(&bob);
    let kp_ref = h.add_key_package(&mut b, &bob, false).await;
    let mut alice = h.anon().await;
    let secret = h.keypkg_get(&mut alice, "bob@example.net").await[0]
        .1
        .clone();
    // The blob must be stored first.
    let missing = BlobRef::of(b"nothing");
    h.send(&alice, &format!("WELCOME PUT {kp_ref} {secret} {missing}"))
        .await;
    assert_eq!(alice.lines(), ["ERR not-found"]);
    let hash = h.store_blob(&mut alice, &[1, 2, 3]).await;
    h.send(&alice, &format!("WELCOME PUT {kp_ref} {secret} {hash}"))
        .await;
    assert_eq!(alice.lines(), ["OK"]);
    assert_eq!(
        b.raw_lines()[0].split(' ').nth(2).unwrap(),
        hash.to_string()
    );
}

// ---------------------------------------------------------------------------
// Blobs (12.12)

#[tokio::test]
async fn blobs_need_a_token_on_anonymous_connections() {
    let mut h = keys();
    let mut anon = h.anon().await;
    let hash = BlobRef::of(b"abc");
    h.send(&anon, &format!("BLOB {hash} 3")).await;
    assert_eq!(anon.lines(), ["ERR bad-syntax"]);
    // No such mailbox.
    h.send(&anon, &format!("BLOB {hash} 3 box={BOX} token={}", token()))
        .await;
    assert_eq!(anon.lines(), ["ERR not-found"]);
    h.mailbox();
    h.send(&anon, &format!("BLOB {hash} 3 box={BOX} token={}", token()))
        .await;
    let line = anon.raw_lines().pop().unwrap();
    let put = value(&line, "put");
    assert!(put.starts_with(&format!("{FILES}/blob/")), "{put}");
    // A guest needs one too.
    let (mut guest, _) = h.guest("sam").await;
    h.send(&guest, &format!("BLOB {hash} 3")).await;
    assert_eq!(guest.lines(), ["ERR bad-syntax"]);
    // A signed-in connection does not.
    let mut alice = h.sign_in(&Dev::new("alice@example.org", 1));
    h.send(&alice, &format!("BLOB {hash} 3")).await;
    assert!(alice.raw_lines()[0].starts_with("OK put=https://"));
}

#[tokio::test]
async fn blobs_are_stored_once_and_checked() {
    let mut h = keys();
    h.mailbox();
    let mut anon = h.anon().await;
    let bytes = b"a blob".to_vec();
    let hash = BlobRef::of(&bytes);
    h.send(
        &anon,
        &format!("BLOB {hash} {} box={BOX} token={}", bytes.len(), token()),
    )
    .await;
    let put = value(&anon.raw_lines().pop().unwrap(), "put");
    let rest = put
        .strip_prefix(&format!("{FILES}{}", paths::BLOB_PUT))
        .unwrap();
    let files = h.hub.files();
    // A wrong secret leads nowhere.
    let (id, _) = rest.split_once('/').unwrap();
    let wrong = format!("{id}/{}", "a".repeat(32));
    assert_eq!(
        files.claim_put(paths::BLOB_PUT, &wrong).await.unwrap_err(),
        Refused::NotFound
    );
    assert_eq!(h.put(&put, &bytes).await, Ok(true));
    // One upload only: the URL is gone once used.
    assert_eq!(h.put(&put, &bytes).await, Err(Refused::NotFound));
    let (path, size) = files.blob(hash).await.unwrap();
    assert_eq!(size, bytes.len() as u64);
    assert_eq!(std::fs::read(path).unwrap(), bytes);
    // The server has it now.
    h.send(
        &anon,
        &format!("BLOB {hash} {} box={BOX} token={}", bytes.len(), token()),
    )
    .await;
    assert_eq!(anon.lines(), ["OK exists=yes"]);
}

#[tokio::test]
async fn put_urls_last_ten_minutes() {
    let mut h = keys();
    h.mailbox();
    let mut anon = h.anon().await;
    let hash = BlobRef::of(b"late");
    h.send(&anon, &format!("BLOB {hash} 4 box={BOX} token={}", token()))
        .await;
    let put = value(&anon.raw_lines().pop().unwrap(), "put");
    h.advance(Duration::from_secs(601));
    assert_eq!(h.put(&put, b"late").await, Err(Refused::Gone));
}

#[tokio::test]
async fn blob_sizes_and_quotas_are_limited() {
    let mut h = keys_with(|c| {
        c.files.quota = 100;
        c.files.address_bytes_per_hour = 150;
    });
    h.mailbox();
    let mut anon = h.anon().await;
    let big = h.inner().config.files.max_blob + 1;
    h.send(
        &anon,
        &format!(
            "BLOB {} {big} box={BOX} token={}",
            BlobRef::of(b"x"),
            token()
        ),
    )
    .await;
    assert_eq!(anon.lines(), ["ERR too-long"]);
    // The mailbox's quota counts what is stored and what is on its way.
    h.send(
        &anon,
        &format!("BLOB {} 60 box={BOX} token={}", BlobRef::of(b"a"), token()),
    )
    .await;
    assert!(anon.raw_lines()[0].starts_with("OK put="));
    h.send(
        &anon,
        &format!("BLOB {} 60 box={BOX} token={}", BlobRef::of(b"b"), token()),
    )
    .await;
    assert_eq!(anon.lines(), ["ERR rate-limited"]);
    // The address's window counts every mailbox's.
    let other: BoxName = "aaaaaaaaaaaaaaaaaaaaaaaaaa".parse().unwrap();
    h.store
        .create_mailbox(&NewMailbox {
            mailbox: other,
            group_id: GroupId::from_bytes([3; 32]),
            first_epoch: 0,
            token_hash: token().hash(),
            created: h.inner().now(),
            moved_from: None,
        })
        .unwrap();
    h.send(
        &anon,
        &format!(
            "BLOB {} 60 box={other} token={}",
            BlobRef::of(b"c"),
            token()
        ),
    )
    .await;
    assert!(anon.raw_lines()[0].starts_with("OK put="));
    // Within the second mailbox's quota, but not the address's window.
    h.send(
        &anon,
        &format!(
            "BLOB {} 40 box={other} token={}",
            BlobRef::of(b"d"),
            token()
        ),
    )
    .await;
    let lines = anon.lines();
    assert!(lines[0].starts_with("@retry=") && lines[0].ends_with("ERR rate-limited"));
}

#[tokio::test]
async fn blobs_without_an_https_listener_are_not_supported() {
    let mut h = Harness::new();
    let mut alice = h.signed_in_as("alice@example.org");
    h.send(&alice, &format!("BLOB {} 3", BlobRef::of(b"abc")))
        .await;
    assert_eq!(alice.lines(), ["ERR not-supported"]);
    let mut anon = h.anon().await;
    h.send(&anon, &format!("UPLOAD {BOX} {} 10", token())).await;
    assert_eq!(anon.lines(), ["ERR not-supported"]);
}

#[tokio::test]
async fn blobs_expire_from_the_last_blob_command_that_named_them() {
    let mut h = keys();
    h.mailbox();
    let mut anon = h.anon().await;
    let hash = h.store_blob(&mut anon, b"old").await;
    let files = h.hub.files();
    h.advance(days(20));
    // Named again: retention counts from now.
    h.send(&anon, &format!("BLOB {hash} 3 box={BOX} token={}", token()))
        .await;
    assert_eq!(anon.lines(), ["OK exists=yes"]);
    h.advance(days(20));
    h.expire().await;
    assert!(files.blob(hash).await.is_ok());
    h.advance(days(11));
    assert_eq!(files.blob(hash).await.unwrap_err(), Refused::NotFound);
    let path = h.inner().config.files_dir().join("blobs").join(hash.hex());
    assert!(path.exists());
    h.expire().await;
    assert!(!path.exists());
    h.send(&anon, &format!("BLOB {hash} 3 box={BOX} token={}", token()))
        .await;
    assert!(anon.raw_lines()[0].starts_with("OK put="));
}

#[tokio::test]
async fn a_public_rooms_current_tree_is_kept() {
    let mut h = keys();
    h.mailbox();
    let mut anon = h.anon().await;
    let tree = h.store_blob(&mut anon, b"tree").await;
    let room: BoxName = BOX.parse().unwrap();
    keys::keep_room_tree(h.inner(), room, Some(tree))
        .await
        .unwrap();
    h.advance(days(60));
    h.expire().await;
    let files = h.hub.files();
    assert!(files.blob(tree).await.is_ok());
    // A new epoch's tree is in the line: the old one expires.
    keys::keep_room_tree(h.inner(), room, None).await.unwrap();
    h.expire().await;
    assert!(files.blob(tree).await.is_err());
}

// ---------------------------------------------------------------------------
// Backups (12.13)

/// A WrappedKey, 61 bytes starting with 1.
fn wrapped() -> WrappedKey {
    let mut key = [9u8; WRAPPED_KEY_LEN];
    key[0] = 1;
    WrappedKey::from_array(&key)
}

#[tokio::test]
async fn backups_are_kept_while_current() {
    let mut h = keys();
    let alice = Dev::new("alice@example.org", 1);
    let mut a = h.sign_in(&alice);
    let first = h.store_signed_in_blob(&mut a, b"archive one").await;
    let file = h.store_signed_in_blob(&mut a, b"a file").await;
    let more = h.store_signed_in_blob(&mut a, b"archive two").await;
    let list = h
        .store_signed_in_blob(&mut a, &write_blob_list(&[more, file]))
        .await;
    let key = wrapped();
    h.send(&a, "BACKUP GET").await;
    assert_eq!(a.lines(), ["ERR not-found"]);
    h.send(&a, &format!("BACKUP PUT 2 {first} {key} files={list}"))
        .await;
    assert_eq!(a.lines(), ["OK"]);
    h.send(&a, "BACKUP GET").await;
    assert_eq!(
        a.lines(),
        [format!("BACKUP 2 {first} {key} files={list}"), "OK".into()]
    );
    // Long past retention, every blob it names is still there.
    h.advance(days(90));
    h.expire().await;
    let files = h.hub.files();
    for hash in [&first, &file, &more, &list] {
        assert!(files.blob(*hash).await.is_ok(), "{hash}");
    }
    // A new backup that keeps the file: the rest of the old one goes.
    let second = h.store_signed_in_blob(&mut a, b"archive three").await;
    let list2 = h
        .store_signed_in_blob(&mut a, &write_blob_list(&[file]))
        .await;
    h.send(&a, &format!("BACKUP PUT 3 {second} {key} files={list2}"))
        .await;
    assert_eq!(a.lines(), ["OK"]);
    for hash in [&first, &more, &list] {
        assert!(files.blob(*hash).await.is_err(), "{hash}");
    }
    h.advance(days(90));
    h.expire().await;
    for hash in [&second, &file, &list2] {
        assert!(files.blob(*hash).await.is_ok(), "{hash}");
    }
    // Deleting it deletes its blobs.
    h.send(&a, "BACKUP DEL").await;
    assert_eq!(a.lines(), ["OK"]);
    h.send(&a, "BACKUP GET").await;
    assert_eq!(a.lines(), ["ERR not-found"]);
    for hash in [&second, &file, &list2] {
        assert!(files.blob(*hash).await.is_err(), "{hash}");
    }
}

#[tokio::test]
async fn backup_put_checks_its_blobs_and_key() {
    let mut h = keys_with(|c| c.files.max_backup = 30);
    let alice = Dev::new("alice@example.org", 1);
    let mut a = h.sign_in(&alice);
    let first = h.store_signed_in_blob(&mut a, b"archive").await;
    let key = wrapped();
    let missing = BlobRef::of(b"missing");
    h.send(&a, &format!("BACKUP PUT 0 {missing} {key}")).await;
    assert_eq!(a.lines(), ["ERR not-found"]);
    // A WrappedKey of another version (12.13).
    let bad = b64(&[2; WRAPPED_KEY_LEN]);
    h.send(&a, &format!("BACKUP PUT 0 {first} {bad}")).await;
    assert_eq!(a.lines(), ["ERR invalid"]);
    h.send(&a, &format!("BACKUP PUT 0 {first} {key} files={missing}"))
        .await;
    assert_eq!(a.lines(), ["ERR not-found"]);
    let odd = h.store_signed_in_blob(&mut a, &[0; 47]).await;
    h.send(&a, &format!("BACKUP PUT 0 {first} {key} files={odd}"))
        .await;
    assert_eq!(a.lines(), ["ERR invalid"]);
    let names_missing = h
        .store_signed_in_blob(&mut a, &write_blob_list(&[missing]))
        .await;
    h.send(
        &a,
        &format!("BACKUP PUT 0 {first} {key} files={names_missing}"),
    )
    .await;
    assert_eq!(a.lines(), ["ERR not-found"]);
    let big = h.store_signed_in_blob(&mut a, &[0; 31]).await;
    h.send(&a, &format!("BACKUP PUT 0 {big} {key}")).await;
    assert_eq!(a.lines(), ["ERR too-long"]);
    h.send(&a, &format!("BACKUP PUT 0 {first} {key}")).await;
    assert_eq!(a.lines(), ["OK"]);
    // Only signed-in connections.
    let mut anon = h.anon().await;
    h.send(&anon, "BACKUP GET").await;
    assert_eq!(anon.lines(), ["ERR wrong-connection"]);
}

#[tokio::test]
async fn a_backup_does_not_delete_blobs_that_others_stored() {
    let mut h = keys();
    h.mailbox();
    let mut anon = h.anon().await;
    let theirs = h.store_blob(&mut anon, b"someone else's").await;
    let alice = Dev::new("alice@example.org", 1);
    let mut a = h.sign_in(&alice);
    let mine = h.store_signed_in_blob(&mut a, b"mine").await;
    let key = wrapped();
    h.send(&a, &format!("BACKUP PUT 0 {theirs} {key}")).await;
    assert_eq!(a.lines(), ["OK"]);
    h.send(&a, &format!("BACKUP PUT 0 {mine} {key}")).await;
    assert_eq!(a.lines(), ["OK"]);
    assert!(h.hub.files().blob(theirs).await.is_ok());
}

impl Keys {
    /// Stores `bytes` as a blob on the signed-in connection `c`.
    async fn store_signed_in_blob(&self, c: &mut Client, bytes: &[u8]) -> BlobRef {
        let hash = BlobRef::of(bytes);
        self.send(c, &format!("BLOB {hash} {}", bytes.len())).await;
        let line = c.raw_lines().pop().unwrap();
        if line != "OK exists=yes" {
            self.put(&value(&line, "put"), bytes).await.unwrap();
        }
        hash
    }
}

// ---------------------------------------------------------------------------
// Uploads (5.6)

#[tokio::test]
async fn uploads_give_put_get_and_del_urls() {
    let mut h = keys();
    h.mailbox();
    let mut anon = h.anon().await;
    h.send(&anon, &format!("UPLOAD {BOX} {} 5", token())).await;
    let line = anon.raw_lines().pop().unwrap();
    let (put, get, del) = (
        value(&line, "put"),
        value(&line, "get"),
        value(&line, "del"),
    );
    for url in [&put, &get, &del] {
        assert!(url.starts_with(FILES), "{url}");
        assert!(url.len() <= 512 && !url.contains(';'), "{url}");
    }
    let files = h.hub.files();
    let get_rest = get
        .strip_prefix(&format!("{FILES}{}", paths::UPLOAD_GET))
        .unwrap();
    let del_rest = del
        .strip_prefix(&format!("{FILES}{}", paths::UPLOAD_DEL))
        .unwrap();
    // Nothing to get before the upload.
    assert_eq!(files.upload(get_rest).await.unwrap_err(), Refused::NotFound);
    assert_eq!(h.put(&put, b"hello").await, Ok(true));
    assert_eq!(h.put(&put, b"hello").await, Err(Refused::Gone));
    let (path, size) = files.upload(get_rest).await.unwrap();
    assert_eq!(
        (std::fs::read(&path).unwrap(), size),
        (b"hello".to_vec(), 5)
    );
    // The secrets are not interchangeable.
    assert!(files.upload(del_rest).await.is_err());
    assert!(files.delete(get_rest).await.is_err());
    files.delete(del_rest).await.unwrap();
    assert_eq!(files.upload(get_rest).await.unwrap_err(), Refused::NotFound);
    assert!(!path.exists());
    assert_eq!(files.delete(del_rest).await.unwrap_err(), Refused::NotFound);
}

#[tokio::test]
async fn upload_checks_its_connection_size_and_mailbox() {
    let mut h = keys_with(|c| c.files.max_upload = 100);
    let mut anon = h.anon().await;
    h.send(&anon, &format!("UPLOAD {BOX} {} 5", token())).await;
    assert_eq!(anon.lines(), ["ERR not-found"]);
    h.mailbox();
    h.send(&anon, &format!("UPLOAD {BOX} {} 101", token()))
        .await;
    assert_eq!(anon.lines(), ["ERR too-long"]);
    let mut alice = h.signed_in_as("alice@example.org");
    h.send(&alice, &format!("UPLOAD {BOX} {} 5", token())).await;
    assert_eq!(alice.lines(), ["ERR wrong-connection"]);
    let mut none = keys_with(|c| c.files.max_upload = 0);
    let mut anon = none.anon().await;
    none.send(&anon, &format!("UPLOAD {BOX} {} 5", token()))
        .await;
    assert_eq!(anon.lines(), ["ERR not-supported"]);
    assert_eq!(
        keys::info(none.inner()).upload,
        risala_proto::server::Upload::No
    );
    assert!(keys::info(none.inner()).files.is_empty());
}

#[tokio::test]
async fn uploads_expire_from_the_upload_unless_a_report_keeps_them() {
    let mut h = keys();
    h.mailbox();
    let mut anon = h.anon().await;
    let mut urls = Vec::new();
    for _ in 0..2 {
        h.send(&anon, &format!("UPLOAD {BOX} {} 1", token())).await;
        let line = anon.raw_lines().pop().unwrap();
        urls.push((
            value(&line, "put"),
            value(&line, "get"),
            value(&line, "del"),
        ));
    }
    // One that is never uploaded goes after its 10 minutes.
    h.send(&anon, &format!("UPLOAD {BOX} {} 1", token())).await;
    let unused = value(&anon.raw_lines().pop().unwrap(), "put");
    h.advance(Duration::from_secs(5 * 24 * 3600));
    for (put, _, _) in &urls {
        assert_eq!(h.put(put, b"x").await, Err(Refused::Gone));
    }
    // Start again, now.
    urls.clear();
    for _ in 0..2 {
        h.send(&anon, &format!("UPLOAD {BOX} {} 1", token())).await;
        let line = anon.raw_lines().pop().unwrap();
        urls.push((
            value(&line, "put"),
            value(&line, "get"),
            value(&line, "del"),
        ));
    }
    for (put, _, _) in &urls {
        assert_eq!(h.put(put, b"x").await, Ok(true));
    }
    h.expire().await;
    assert_eq!(h.put(&unused, b"x").await, Err(Refused::NotFound));
    let files = h.hub.files();
    let rest = |url: &str, prefix: &str| {
        url.strip_prefix(&format!("{FILES}{prefix}"))
            .unwrap()
            .to_owned()
    };
    let (_, kept_get, kept_del) = &urls[0];
    let (_, other_get, _) = &urls[1];
    let url = |u: &str| u.parse::<risala_proto::content::FileUrl>().unwrap();
    let report: risala_proto::names::Id = "r1".parse().unwrap();
    // A URL with the wrong secret, or of another server, keeps nothing.
    let forged = format!("{}{}", &kept_get[..kept_get.len() - 4], "aaaa");
    keys::keep_files_for_report(
        h.inner(),
        &report,
        &[url(&forged), url("https://elsewhere.example/f/a/b")],
    )
    .await;
    let kept_id = rest(kept_get, paths::UPLOAD_GET)
        .split('/')
        .next()
        .unwrap()
        .to_owned();
    let held = |h: &Keys| {
        crate::store::KeysStore::upload(&*h.store, &kept_id)
            .unwrap()
            .unwrap()
            .held
    };
    assert_eq!(held(&h), 0);
    keys::keep_files_for_report(h.inner(), &report, &[url(kept_get), url(kept_get)]).await;
    assert_eq!(held(&h), 1);
    // Its uploader deletes it, but the report keeps it.
    files
        .delete(&rest(kept_del, paths::UPLOAD_DEL))
        .await
        .unwrap();
    assert!(
        files
            .upload(&rest(kept_get, paths::UPLOAD_GET))
            .await
            .is_ok()
    );
    h.advance(days(31));
    h.expire().await;
    assert!(
        files
            .upload(&rest(other_get, paths::UPLOAD_GET))
            .await
            .is_err()
    );
    assert!(
        files
            .upload(&rest(kept_get, paths::UPLOAD_GET))
            .await
            .is_ok()
    );
    // Once the report is resolved, it goes.
    keys::release_files_for_report(h.inner(), &report).await;
    assert!(
        files
            .upload(&rest(kept_get, paths::UPLOAD_GET))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn info_reports_files_and_blobs() {
    let h = keys();
    let info = keys::info(h.inner());
    assert_eq!(
        info.blobs.as_deref(),
        Some("https://files.example.org/blobs/")
    );
    assert_eq!(
        info.upload,
        risala_proto::server::Upload::MaxBytes(h.inner().config.files.max_upload)
    );
    assert_eq!(info.files.len(), 1);
    assert_eq!(info.files[0].to_string(), FILES);
}

#[test]
fn sealed_welcomes_parse() {
    use crate::core::keys::is_sealed_welcome;
    assert!(is_sealed_welcome(&[1, 1, 0, 1, 0]));
    assert!(!is_sealed_welcome(&[2, 1, 0, 1, 0]));
    assert!(!is_sealed_welcome(&[1, 0, 1, 0]));
    assert!(!is_sealed_welcome(&[1, 1, 0, 1, 0, 0]));
    assert!(!is_sealed_welcome(&[1, 1, 0, 2, 0]));
    // Two-byte lengths, and only minimal ones.
    let mut long = vec![1, 0x40, 64];
    long.extend([0; 64]);
    long.extend([1, 0]);
    assert!(is_sealed_welcome(&long));
    assert!(!is_sealed_welcome(&[1, 0x40, 1, 0, 1, 0]));
}

#[test]
fn servers_allow_blobs_of_at_least_256_mib() {
    use crate::config::MIN_MAX_BLOB;
    assert_eq!(MIN_MAX_BLOB, 256 * 1024 * 1024);
    let mut c = config();
    assert!(c.files.max_blob >= MIN_MAX_BLOB);
    c.files.max_blob = MIN_MAX_BLOB - 1;
    let built = Hub::build(
        c,
        Arc::new(SqliteStore::open_in_memory().unwrap()),
        Arc::new(ManualClock::new(T.parse().unwrap())),
        timers(),
        KeyServices::default(),
    );
    assert!(matches!(built, Err(crate::core::HubError::Config(m)) if m.contains("max_blob")));
    let mut c = config();
    c.files.url = Some("http://files.example.org".into());
    assert!(c.validate().is_err());
    c.files.url = Some("https://files.example.org:8443".into());
    assert!(c.validate().is_ok());
}
