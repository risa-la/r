//! Transcript tests of encrypted conversations with real MLS groups
//! (Section 12): KEYPKG ADD (12.4), INIT, COMMIT and GROUPINFO (12.5,
//! 12.6), ENC (12.8), direct conversations (5.1) and REPORTENC (5.8).
//!
//! Each [`Device`] is an OpenMLS client built with `risala-mls`, as
//! librisala's is, with its state in memory. The hub's clock is the
//! system's time, since OpenMLS stamps KeyPackages with it.

use std::sync::Arc;

use openmls_memory_storage::MemoryStorage;
use risala_mls::Provider;
use risala_mls::openmls_traits::OpenMlsProvider as _;
use risala_mls::wire;
use risala_proto::auth::{PublicKey, SecretKey};
use risala_proto::mls;
use risala_proto::names::{Identity, Uid};
use risala_proto::time::Timestamp;

use super::tests::{Client, Harness, config, timers};
use super::*;
use crate::store::SqliteStore;

/// Hosted here.
pub(super) const ALICE: &str = "alice@example.org";
/// Not hosted: its key file comes from the fetcher.
pub(super) const BOB: &str = "bob@example.net";
/// Hosted here.
pub(super) const CAROL: &str = "carol@example.org";

pub(super) fn uid(s: &str) -> Uid {
    s.parse().unwrap()
}

fn identity(s: &str) -> Identity {
    s.parse().unwrap()
}

pub(super) fn secret(n: u8) -> SecretKey {
    SecretKey::from_seed([n; 32])
}

pub(super) fn key(n: u8) -> PublicKey {
    secret(n).public_key()
}

/// A device: an identity, its device key `n`, and its MLS state.
pub(super) struct Device {
    pub(super) uid: Uid,
    pub(super) secret: SecretKey,
    pub(super) provider: Provider<MemoryStorage>,
}

impl Device {
    pub(super) fn new(who: &str, n: u8) -> Device {
        Device {
            uid: uid(who),
            secret: secret(n),
            provider: Provider::new(MemoryStorage::default()).unwrap(),
        }
    }

    pub(super) fn signer(&self) -> risala_mls::DeviceSigner<'_> {
        risala_mls::DeviceSigner::new(&self.secret)
    }

    /// A new KeyPackage of this device, as on the wire.
    pub(super) fn key_package(&self, last_resort: bool) -> mls::KeyPackage {
        let bundle =
            risala_mls::key_package(&self.provider, &self.signer(), &self.uid, last_resort)
                .unwrap();
        wire::key_package_to_wire(bundle.key_package()).unwrap()
    }
}

/// A hub that hosts `example.org`, where alice is registered with keys 1,
/// 2 and 3 and carol with 7, and bob of `example.net` has signed in before
/// with key file 5 and 6. Its clock is the system's.
pub(super) struct World {
    pub(super) h: Harness,
    #[allow(dead_code)] // For the tests of commits.
    pub(super) fetcher: Arc<MemoryFetcher>,
}

impl World {
    pub(super) fn new() -> World {
        let mut c = config();
        c.identity_domain = Some("example.org".into());
        let store = SqliteStore::open_in_memory().unwrap();
        let now = Timestamp::now();
        store.register(&uid(ALICE), &key(1), now).unwrap();
        for n in [2, 3] {
            store
                .add_hosted_key(&uid(ALICE), &key(n), "", 64, now)
                .unwrap();
        }
        store.register(&uid(CAROL), &key(7), now).unwrap();
        store.touch_identity(&uid(BOB), now).unwrap();
        let store: Arc<dyn Store> = Arc::new(store);
        let fetcher = Arc::new(MemoryFetcher::new());
        fetcher.set(&identity(BOB), vec![key(5), key(6)]);
        let keys = KeyServices::shared(fetcher.clone(), Arc::new(NoPublisher));
        let clock = Arc::new(ManualClock::new(now));
        let hub = Hub::build(c, store.clone(), clock.clone(), timers(), keys).unwrap();
        World {
            h: Harness {
                hub,
                store,
                clock,
                next: 0,
            },
            fetcher,
        }
    }

    /// A connection signed in as `d`'s identity with its device key,
    /// without AUTH.
    pub(super) fn connect(&mut self, d: &Device) -> Client {
        let c = self.h.connect();
        assert!(
            self.h
                .hub
                .inner
                .reg()
                .attach(c.id, &d.uid, Some(d.secret.public_key()))
        );
        c
    }

    pub(super) async fn send(&self, c: &Client, line: &str) {
        self.h.send(c, line).await;
    }
}

// ---------------------------------------------------------------------------
// KEYPKG ADD (12.4)

#[tokio::test]
async fn keypkg_add_checks_key_packages() {
    let mut w = World::new();
    let a1 = Device::new(ALICE, 1);
    let mut c = w.connect(&a1);

    let kp = a1.key_package(false);
    w.send(&c, &format!("keypkg add {kp}")).await;
    assert_eq!(c.lines(), ["OK"]);
    // The same one again is stored once.
    w.send(&c, &format!("keypkg add {kp}")).await;
    assert_eq!(c.lines(), ["OK"]);
    w.send(&c, &format!("keypkg add {}", a1.key_package(true)))
        .await;
    assert_eq!(c.lines(), ["OK"]);
    w.send(&c, "keypkg count").await;
    assert_eq!(c.lines(), ["OK count=1 last-resort=yes"]);

    // Another device's KeyPackage, of the same identity or not.
    for other in [Device::new(ALICE, 2), Device::new(CAROL, 7)] {
        w.send(&c, &format!("keypkg add {}", other.key_package(false)))
            .await;
        assert_eq!(
            c.lines(),
            ["ERR invalid the KeyPackage's signature key is not the device key"]
        );
    }
    // The right key under another uid.
    let mut wrong = Device::new(CAROL, 1);
    wrong.uid = uid(CAROL);
    w.send(&c, &format!("keypkg add {}", wrong.key_package(false)))
        .await;
    assert_eq!(
        c.lines(),
        ["ERR invalid the KeyPackage's credential is not the uid"]
    );
    // A GroupInfo is not a KeyPackage.
    let group = risala_mls::create_group(
        &a1.provider,
        &a1.signer(),
        &a1.uid,
        &risala_mls::RisalaConversation::direct(&a1.uid, &uid(BOB)),
    )
    .unwrap();
    let gi = group
        .export_group_info(a1.provider.crypto(), &a1.signer(), false)
        .unwrap();
    let gi = wire::group_info_to_wire(&gi).unwrap();
    w.send(&c, &format!("keypkg add {gi}")).await;
    assert_eq!(
        c.lines(),
        ["ERR invalid the MLSMessage is not a KeyPackage"]
    );

    // Out of its lifetime: two weeks before it starts, and after it ends.
    w.h.clock.set(
        Timestamp::now()
            .checked_sub(std::time::Duration::from_secs(14 * 86400))
            .unwrap(),
    );
    w.send(&c, &format!("keypkg add {}", a1.key_package(false)))
        .await;
    assert_eq!(
        c.lines(),
        ["ERR invalid the KeyPackage's lifetime is not acceptable"]
    );
    w.send(&c, "keypkg count").await;
    assert_eq!(c.lines(), ["OK count=1 last-resort=yes"]);
}

#[test]
fn lifetimes_agree() {
    assert_eq!(
        MAX_KEY_PACKAGE_LIFETIME,
        risala_mls::group::MAX_LIFETIME_SPAN
    );
}
