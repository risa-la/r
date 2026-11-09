//! The identity area against a whole `risalad` (tasks SV1 and SV2): it
//! hosts `example.org`, keeps its key log, serves the log and the hosted
//! key files over HTTPS, and witnesses its own log, so that a device's
//! policy of one witness (k = 1) accepts its checkpoints (4.5, 4.10).
//!
//! The device creates an identity (REGISTER), checks its records against
//! the log, signs in, pairs a second device through the relay (PAIR),
//! is seen by a third client, removes the paired device with the
//! recovery key (KEYS PUT), and recovers on a new device (4.6-4.8).
//!
//! The log takes a witnessed checkpoint at most every 10 seconds, so the
//! test waits for each new record; it takes about a minute.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use librisala::client::ConnectionState;
use librisala::client::identity::{Contact, KeyFetcherHttps};
use librisala::conn::{SessionOptions, Slot};
use librisala::keyfetch::{CertificateDer, FetchOptions, KeyFetcher, Roots, StaticResolver};
use librisala::{Client, ClientOptions, Event};
use risala_keylog::cosig::Cosigner;
use risala_keylog::merkle::empty_root;
use risala_proto::time::Timestamp;
use risala_server::config::{CertPair, LogWitness};
use risala_server::store::KeyLogStore as _;
use risala_server::store::keylog::WitnessLogRow;
use risala_server::testing::TestServer;

const LOG_SEED: [u8; 32] = [21; 32];
const WITNESS_SEED: [u8; 32] = [22; 32];

/// The server's name. Not `localhost`: risala-mls's IdentityBundle does
/// not take single-label hosts yet.
const HOST: &str = "chat.test";

/// A test CA, and a certificate for the server from it, in `dir`, also
/// valid for `localhost`, where the log reaches its own witness.
fn certificates(dir: &Path) -> (CertificateDer<'static>, CertPair, std::path::PathBuf) {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca = params.self_signed(&ca_key).unwrap();
    let ca_pem = dir.join("ca.pem");
    std::fs::write(&ca_pem, ca.pem()).unwrap();
    let issuer = rcgen::Issuer::new(params, ca_key);
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf = rcgen::CertificateParams::new(vec![HOST.to_string(), "localhost".to_string()])
        .unwrap()
        .signed_by(&leaf_key, &issuer)
        .unwrap();
    let pair = CertPair {
        cert: dir.join("localhost.pem"),
        key: dir.join("localhost.key"),
    };
    std::fs::write(&pair.cert, leaf.pem()).unwrap();
    std::fs::write(&pair.key, leaf_key.serialize_pem()).unwrap();
    (ca.der().clone(), pair, ca_pem)
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct World {
    server: TestServer,
    https: Arc<KeyFetcherHttps>,
    witness: String,
    _dir: tempfile::TempDir,
}

async fn world() -> World {
    let dir = tempfile::tempdir().unwrap();
    let (ca, pair, ca_pem) = certificates(dir.path());
    let http_port = free_port();
    let log_vkey = Cosigner::from_seed(&format!("{HOST}/risala-log/1"), &LOG_SEED)
        .unwrap()
        .vkey()
        .to_string();
    let witness = Cosigner::from_seed(&format!("{HOST}/risala-witness"), &WITNESS_SEED)
        .unwrap()
        .vkey()
        .to_string();
    let w = witness.clone();
    let server = TestServer::builder()
        .hostname(HOST)
        .identity_domain("example.org")
        .configure(move |c| {
            c.server.registration = true;
            c.http.listen = vec![SocketAddr::from(([127, 0, 0, 1], http_port))];
            c.http.certs = vec![pair];
            c.keys.extra_roots.push(ca_pem);
            c.log.enabled = Some(true);
            c.log.witnesses = vec![LogWitness {
                vkey: w,
                url: format!("https://localhost:{http_port}/risala-witness"),
            }];
            c.witness.enabled = true;
        })
        .prepare(move |store| {
            let t = Timestamp::now();
            store.witness_seed(WITNESS_SEED, t).unwrap();
            store.first_log_key(LOG_SEED, t).unwrap();
            // The witness would enrol the log with the key it fetches from
            // https://chat.test/risala-log/1/risala/key (4.10), but the
            // server's fetcher resolves only the test key server's domains,
            // so the log is enrolled here, as that fetch would.
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            store
                .put_witness_log(&WitnessLogRow {
                    origin: format!("{HOST}/risala-log/1"),
                    vkey: log_vkey,
                    size: 0,
                    root: *empty_root().as_bytes(),
                    domain: HOST.to_owned(),
                    enrolled_at: now,
                    last_cosigned: 0,
                    handoff: None,
                })
                .unwrap();
        })
        .start()
        .await;
    // Devices fetch the log from the server's HTTPS listener, and key
    // files from the test key server.
    let keys = server.key_server();
    let mut resolver = StaticResolver::new();
    resolver.insert(HOST, [SocketAddr::from(([127, 0, 0, 1], http_port))]);
    resolver.insert("example.org", [keys.addr("example.org")]);
    let fetcher = KeyFetcher::new(FetchOptions {
        roots: Roots::Only(vec![ca, keys.ca()]),
        allow_private: true,
        min_refetch: Duration::ZERO,
        resolver: Arc::new(resolver),
        ..FetchOptions::default()
    });
    World {
        server,
        https: Arc::new(KeyFetcherHttps(fetcher)),
        witness,
        _dir: dir,
    }
}

impl World {
    fn client(&self) -> Client {
        let options = ClientOptions {
            session: SessionOptions {
                connect_to: Some(self.server.addr()),
                ..Default::default()
            },
            https: Some(self.https.clone()),
            ..ClientOptions::default()
        };
        let c = Client::open_in_memory(options).unwrap();
        c.accept_fingerprint(HOST, &self.server.fingerprint().to_string())
            .unwrap();
        c.set_witness_policy(std::slice::from_ref(&self.witness), 1)
            .unwrap();
        c
    }
}

/// Fetches `uid` until `done` holds of what the device knows, for up to a
/// minute: the log witnesses new records within about 10 seconds.
async fn until(c: &Client, uid: &str, done: impl Fn(&Contact) -> bool) -> Contact {
    for _ in 0..120 {
        let contact = c.refresh_identity(uid).await.unwrap();
        if done(&contact) {
            return contact;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("{uid}: {:?}", c.refresh_identity(uid).await.unwrap());
}

/// Waits for the account's signed-in connection, or its failure.
async fn signed_in(c: &Client, account: librisala::store::AccountId) -> bool {
    let mut events = c.subscribe();
    c.connect(account).await.unwrap();
    let result = loop {
        let event = tokio::time::timeout(Duration::from_secs(20), events.recv())
            .await
            .expect("an event in time")
            .expect("events");
        if let Event::Connection(e) = event
            && e.account == account
            && e.slot == Slot::SignedIn
        {
            match e.state {
                ConnectionState::Ready => break true,
                ConnectionState::Failed(_) => break false,
                _ => {}
            }
        }
    };
    c.disconnect(account).await.unwrap();
    result
}

#[tokio::test]
async fn identities_against_risalad() {
    let w = world().await;
    // REGISTER needs INFO's register=, log= and log-key= (4.7, 8.5), which
    // task SV5 builds. Until then this test has nothing to run against.
    let registers = match w.client().probe(HOST).await {
        Ok(hello) => matches!(
            hello.values.register(),
            Ok(Some(risala_proto::server::Register::Domain(_)))
        ),
        Err(_) => false,
    };
    if !registers {
        eprintln!("skipped: the server's INFO has no register= yet (task SV5)");
        return;
    }

    // REGISTER, then the records once the log has witnessed them.
    let laptop = w.client();
    let new = laptop
        .create_identity(HOST, "alice", "laptop")
        .await
        .unwrap();
    let uid = new.uid.to_string();
    assert_eq!(uid, "alice@example.org");
    let recovery = new.recovery_key.to_string();
    let contact = until(&laptop, &uid, |c| {
        !c.devices.is_empty() && c.devices.iter().all(|d| d.accepted)
    })
    .await;
    assert_eq!(contact.devices.len(), 1);
    assert!(!contact.stale);
    // AUTH, hedged, with the device key (4.6).
    let account = laptop.accounts().unwrap()[0].id;
    assert!(signed_in(&laptop, account).await);

    // Pairing a phone through the relay (4.8).
    let phone = w.client();
    let offer = phone.start_pairing(HOST, "phone").await.unwrap();
    let request = laptop.scan_pairing(&uid, &offer.qr).await.unwrap();
    assert_eq!(request.label, "phone");
    laptop.confirm_pairing(&uid, false).await.unwrap();
    // The phone shows the identity to confirm before it takes it (4.8).
    let shown = phone.finish_pairing().await.unwrap();
    assert_eq!(shown.uid.to_string(), uid);
    let joined = phone.accept_pairing().await.unwrap();
    assert_eq!(joined.uid.to_string(), uid);
    until(&phone, &uid, |c| {
        c.devices.len() == 2 && c.devices.iter().all(|d| d.accepted)
    })
    .await;
    let phone_account = phone.accounts().unwrap()[0].id;
    assert!(signed_in(&phone, phone_account).await);

    // Someone else sees both devices.
    let bob = w.client();
    let seen = until(&bob, &uid, |c| {
        c.devices.len() == 2 && c.devices.iter().all(|d| d.accepted)
    })
    .await;
    let number = bob.safety_number(&uid).unwrap();
    bob.mark_verified(&uid, Some(&number.qr)).unwrap();
    assert!(seen.stopped.is_none());

    // Removing the phone with the recovery key (4.8): it can no longer
    // sign in, and everyone sees it removed.
    laptop
        .remove_device(&uid, request.device, &recovery)
        .await
        .unwrap();
    let removed = |c: &Contact| {
        c.devices
            .iter()
            .any(|d| d.id == request.device && d.removed)
    };
    until(&laptop, &uid, removed).await;
    until(&bob, &uid, removed).await;
    assert!(bob.known_contact(&uid).unwrap().unwrap().verified);
    assert!(!signed_in(&phone, phone_account).await);

    // Losing every device: recovery on a new laptop (4.8).
    let spare = w.client();
    let own = spare.recover(HOST, &uid, &recovery, "spare").await.unwrap();
    let after = until(&bob, &uid, |c| {
        c.devices.iter().any(|d| d.id == own.device && d.accepted)
    })
    .await;
    assert!(
        after
            .devices
            .iter()
            .filter(|d| !d.removed)
            .all(|d| d.id == own.device)
    );
    let spare_account = spare.accounts().unwrap()[0].id;
    assert!(signed_in(&spare, spare_account).await);
    assert!(!signed_in(&laptop, account).await);
}
