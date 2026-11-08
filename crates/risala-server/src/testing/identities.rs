//! Identities for tests: [`TestChain`], an identity's keys and chain of
//! records (4.4), [`TestIdentity`], one device of it, and
//! [`TestKeyServer`], an HTTPS server with key files.
//!
//! **For tests only.** See the [module documentation](super) for how a
//! [`TestServer`](super::TestServer) uses them.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use risala_keyfetch::{FetchOptions, Roots, StaticResolver};
use risala_proto::auth::{Nonce, PublicKey, SecretKey, Signature};
use risala_proto::chain::Chain;
use risala_proto::keyfile::KeyFile;
use risala_proto::names::{Identity, Name, Uid};
use risala_proto::record::{
    DeviceId, DeviceKeys, LogKey, Record, RecordBody, RecordContent, XWING_PUBLIC_KEY_LEN,
    XWingPublicKey, encode_records,
};
use rustls::pki_types::CertificateDer;
use tokio::task::JoinHandle;

use super::TempDir;
use crate::config::CertPair;
use crate::http::{HttpServer, KeyDir, KeyFiles};
use crate::keyfiles::KeyFilePublisher as _;
use crate::net::Certificates;

/// The time of a chain's first record: 2026-01-01T00:00:00Z, in ms. Each
/// record after it is a second later, so that records are never ahead of
/// a test server's clock (4.4).
const FIRST_RECORD_MS: u64 = 1_767_225_600_000;

/// One device of an identity, for tests: the identity and the device's
/// ML-DSA-44 device key (4.3).
///
/// Make one with a [`TestChain`], whose records list it, or with
/// [`TestServer::identity`](super::TestServer::identity) or
/// [`TestKeyServer::new_identity`], which also publish its key file.
#[derive(Clone)]
pub struct TestIdentity {
    identity: Identity,
    key: SecretKey,
}

impl fmt::Debug for TestIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TestIdentity")
            .field("identity", &self.identity)
            .field("key", &self.key.public_key().fingerprint())
            .finish()
    }
}

impl TestIdentity {
    /// `identity` with a new random device key, which no chain lists.
    /// Panics if `identity` is not one (4.3).
    pub fn new(identity: &str) -> TestIdentity {
        let identity = identity
            .parse()
            .unwrap_or_else(|e| panic!("{identity:?} is not an identity: {e}"));
        TestIdentity::with_key(identity, random_key())
    }

    /// `identity` with `key`.
    pub fn with_key(identity: Identity, key: SecretKey) -> TestIdentity {
        TestIdentity { identity, key }
    }

    /// The identity, such as `alice@example.org`.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// The identity as a uid.
    pub fn uid(&self) -> Uid {
        self.identity.to_uid()
    }

    /// The device's private key.
    pub fn key(&self) -> &SecretKey {
        &self.key
    }

    /// The device's public key, as its `device` record lists it (4.4).
    pub fn public_key(&self) -> PublicKey {
        self.key.public_key()
    }

    /// The signature AUTH and REGISTER need on a connection to `host`
    /// whose greeting had `nonce` (4.6). `host` is the name the client
    /// sent in SNI.
    pub fn sign(&self, host: &str, nonce: &Nonce) -> Signature {
        self.key.sign_challenge(host, nonce, self.identity.as_str())
    }

    /// The whole `AUTH <identity> <signature>` line (4.6).
    pub fn auth_line(&self, host: &str, nonce: &Nonce) -> String {
        format!("AUTH {} {}", self.identity, self.sign(host, nonce))
    }
}

/// A new random ML-DSA-44 key.
fn random_key() -> SecretKey {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("random bytes");
    SecretKey::from_seed(seed)
}

/// An X-Wing public key that passes the checks of 12.2, different for
/// each `n` below 3329 and random in its X25519 part.
fn xwing(n: u16) -> XWingPublicKey {
    assert!(n < 3329, "too many attestation keys for one test chain");
    let mut bytes = [0u8; XWING_PUBLIC_KEY_LEN];
    // The first 12-bit coefficient of the ML-KEM-768 key, below q.
    let [low, high] = n.to_le_bytes();
    bytes[0] = low;
    bytes[1] = high;
    getrandom::fill(&mut bytes[XWING_PUBLIC_KEY_LEN - 32..]).expect("random bytes");
    XWingPublicKey::from_bytes(&bytes).expect("a valid X-Wing key")
}

/// An identity's keys and its chain of records (4.4), for tests: a
/// master key, a device-signing key, and records that the test adds one
/// at a time, as an identity's devices would.
#[derive(Clone)]
pub struct TestChain {
    identity: Identity,
    master: SecretKey,
    signing: SecretKey,
    records: Vec<Record>,
    attestation_keys: u16,
}

impl fmt::Debug for TestChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TestChain")
            .field("identity", &self.identity)
            .field("records", &self.records.len())
            .finish_non_exhaustive()
    }
}

impl TestChain {
    /// A new identity whose chain names `log` (4.5): its `master` record,
    /// then a `device` record for its first device, labelled `device1`,
    /// which this returns.
    pub fn new(identity: &str, log: &LogKey) -> (TestChain, TestIdentity) {
        let identity: Identity = identity
            .parse()
            .unwrap_or_else(|e| panic!("{identity:?} is not an identity: {e}"));
        let master = random_key();
        let signing = random_key();
        let mut chain = TestChain {
            identity,
            master: master.clone(),
            signing: signing.clone(),
            records: Vec::new(),
            attestation_keys: 0,
        };
        chain.push(
            RecordBody::Master {
                master_key: master.public_key(),
                signing_key: signing.public_key(),
                log: log.clone(),
            },
            &master,
        );
        let device = chain.add_device("device1");
        (chain, device)
    }

    /// The identity.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// The records, oldest first.
    pub fn records(&self) -> &[Record] {
        &self.records
    }

    /// The newest record.
    pub fn head(&self) -> &Record {
        self.records.last().expect("a chain has records")
    }

    /// The chain, replayed (4.4).
    pub fn chain(&self) -> Chain {
        Chain::replay(&self.identity, &self.records).expect("a test chain is valid")
    }

    /// Adds a record with `body`, signed with `key`, after the newest.
    fn push(&mut self, body: RecordBody, key: &SecretKey) -> Record {
        let n = u64::try_from(self.records.len()).expect("a short chain");
        let content = RecordContent {
            uid: self.identity.clone(),
            previous: self.records.last().map(Record::hash),
            time: FIRST_RECORD_MS + n * 1000,
            body,
        };
        let mut rnd = [0u8; 32];
        getrandom::fill(&mut rnd).expect("random bytes");
        let record = Record::sign(content, key, rnd).expect("a valid record");
        self.records.push(record.clone());
        record
    }

    /// Adds a device labelled `label`, with a `device` record signed by
    /// the device-signing key (4.4), and returns it.
    pub fn add_device(&mut self, label: &str) -> TestIdentity {
        self.add_device_with_key(label, random_key())
    }

    /// Adds a device labelled `label` whose device key is `key`, as
    /// [`add_device`](Self::add_device) does, and returns it.
    pub fn add_device_with_key(&mut self, label: &str, key: SecretKey) -> TestIdentity {
        self.attestation_keys += 1;
        let device = TestIdentity::with_key(self.identity.clone(), key);
        let keys = DeviceKeys {
            device_key: device.public_key(),
            attestation_key: xwing(self.attestation_keys),
            label: label.to_owned(),
        };
        let signing = self.signing.clone();
        self.push(RecordBody::Device(keys), &signing);
        device
    }

    /// Removes `devices` with a `signing` record, signed by the master key,
    /// that names a new device-signing key (4.4, 4.8).
    pub fn remove_devices(&mut self, devices: &[&TestIdentity]) -> Record {
        let mut removed: Vec<DeviceId> = devices
            .iter()
            .map(|d| DeviceId::of(&d.public_key()))
            .collect();
        removed.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        self.signing = random_key();
        let master = self.master.clone();
        self.push(
            RecordBody::Signing {
                signing_key: self.signing.public_key(),
                removed,
            },
            &master,
        )
    }

    /// Ends the identity with a `retire` record (4.4, 4.9).
    pub fn retire(&mut self) -> Record {
        let master = self.master.clone();
        self.push(RecordBody::Retire, &master)
    }

    /// Moves the chain to `log` with a `log` record (4.4, 4.8).
    pub fn move_to(&mut self, log: &LogKey) -> Record {
        let master = self.master.clone();
        self.push(RecordBody::Log(log.clone()), &master)
    }

    /// `records` encoded as REGISTER and KEYS PUT carry them, in base64
    /// (4.7).
    pub fn payload(records: &[Record]) -> String {
        BASE64.encode(encode_records(records))
    }

    /// The `REGISTER <name> <keyfile> <signature>` line for this chain's
    /// first two records, signed by `device` for a connection to `host`
    /// whose greeting had `nonce` (4.7).
    pub fn register_line(&self, device: &TestIdentity, host: &str, nonce: &Nonce) -> String {
        format!(
            "REGISTER {} {} {}",
            self.identity.name(),
            TestChain::payload(&self.records[..2]),
            device.sign(host, nonce)
        )
    }

    /// The `KEYS PUT <after> <records>` line for the records from position
    /// `from` on (4.7).
    pub fn keys_put_line(&self, from: usize) -> String {
        let after = match from {
            0 => "-".to_owned(),
            n => self.records[n - 1].hash().to_string(),
        };
        format!(
            "KEYS PUT {after} {}",
            TestChain::payload(&self.records[from..])
        )
    }

    /// The key file of the chain with every record unlogged, as `- `
    /// lines (4.4), each log at `https://<origin>`.
    pub fn key_file(&self) -> String {
        KeyFile::from_chain(&self.chain(), &|_| None)
            .expect("a test chain makes a key file")
            .to_text()
    }

    /// The key file of the chain with the records at the positions
    /// `logged` gives listed by their index (4.4).
    pub fn key_file_logged(&self, logged: &dyn Fn(usize) -> Option<u64>) -> String {
        KeyFile::from_chain(&self.chain(), logged)
            .expect("a test chain makes a key file")
            .to_text()
    }
}

/// A key log's key for tests, `<host>/risala-log/<number>`, from `seed`.
pub fn test_log_key(host: &str, number: u64, seed: [u8; 32]) -> LogKey {
    LogKey::new(
        &format!("{host}/risala-log/{number}"),
        SecretKey::from_seed(seed).public_key(),
    )
    .expect("a valid log origin")
}

/// An HTTPS server with the key files of identities at some domains
/// (4.4), at `https://<domain>/.well-known/risala/<name>`, for tests.
///
/// **For tests only.** Each domain gets its own listener on `127.0.0.1`,
/// with a certificate from a test CA made for this server. Nothing
/// resolves the domains to these listeners on its own: a fetcher needs
/// [`resolver`](Self::resolver), and must trust [`ca`](Self::ca), with
/// private addresses allowed. [`fetch_options`](Self::fetch_options) has
/// all three. A [`TestServer`](super::TestServer) sets this up itself.
///
/// The identities it makes have chains that name a log of their domain,
/// `<domain>/risala-log/1`, which nothing serves: their key files list
/// every record unlogged (4.4).
///
/// ```no_run
/// # async fn f() {
/// use risala_server::testing::TestKeyServer;
///
/// let keys = TestKeyServer::start(&["example.net"]).await;
/// let bob = keys.new_identity("bob@example.net");
/// let phone = keys.new_device(&bob);
/// keys.remove_device(&bob, &phone);
/// # }
/// ```
pub struct TestKeyServer {
    /// Holds the CA, the certificate and the key files.
    _dir: TempDir,
    ca: CertificateDer<'static>,
    ca_path: PathBuf,
    sites: BTreeMap<String, Site>,
    /// The chains of the identities whose key files this server writes. A
    /// domain served from someone else's directory (a server's hosted
    /// identities) is not here.
    chains: Mutex<HashMap<Identity, TestChain>>,
}

struct Site {
    addr: SocketAddr,
    keys: Arc<KeyDir>,
    /// The directory belongs to someone else, who writes it.
    foreign: bool,
    task: JoinHandle<()>,
}

impl fmt::Debug for TestKeyServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sites: Vec<(&String, &SocketAddr)> =
            self.sites.iter().map(|(d, s)| (d, &s.addr)).collect();
        f.debug_struct("TestKeyServer")
            .field("sites", &sites)
            .field("ca_path", &self.ca_path)
            .finish_non_exhaustive()
    }
}

impl Drop for TestKeyServer {
    fn drop(&mut self) {
        for site in self.sites.values() {
            site.task.abort();
        }
    }
}

impl TestKeyServer {
    /// Starts a server for `domains`, each with no key files yet. Panics
    /// if one is not a domain.
    pub async fn start(domains: &[&str]) -> TestKeyServer {
        TestKeyServer::start_with(domains, None).await
    }

    /// Starts a server for `domains`, and for `hosted`, a domain whose key
    /// files are those another writes to a directory: a server's identity
    /// domain and its `key_dir` (4.7).
    pub(crate) async fn start_with(
        domains: &[&str],
        hosted: Option<(&str, PathBuf)>,
    ) -> TestKeyServer {
        let dir = TempDir::new();
        let mut all: Vec<(String, Option<PathBuf>)> = domains
            .iter()
            .map(|d| (domain(d), None))
            .collect::<Vec<_>>();
        if let Some((d, path)) = hosted {
            all.push((domain(d), Some(path)));
        }
        let names: Vec<String> = all.iter().map(|(d, _)| d.clone()).collect();
        let (ca, ca_path, pair) = make_certificates(dir.path(), &names);
        let mut sites = BTreeMap::new();
        for (domain, foreign) in all {
            let is_foreign = foreign.is_some();
            let keys = Arc::new(KeyDir::new(
                foreign.unwrap_or_else(|| dir.path().join("sites").join(&domain)),
            ));
            let certs =
                Certificates::from_pairs(vec![pair.clone()]).expect("loading the test certificate");
            let server = HttpServer::bind(
                &[SocketAddr::from(([127, 0, 0, 1], 0))],
                certs,
                false,
                keys.clone() as Arc<dyn KeyFiles>,
            )
            .expect("binding the key server");
            let addr = server.local_addrs()[0];
            let task = tokio::spawn(async move {
                let _ = server.run(std::future::pending()).await;
            });
            sites.insert(
                domain,
                Site {
                    addr,
                    keys,
                    foreign: is_foreign,
                    task,
                },
            );
        }
        TestKeyServer {
            _dir: dir,
            ca,
            ca_path,
            sites,
            chains: Mutex::new(HashMap::new()),
        }
    }

    /// The domains it serves, in order.
    pub fn domains(&self) -> Vec<&str> {
        self.sites.keys().map(String::as_str).collect()
    }

    /// Whether it serves `domain`.
    pub fn serves(&self, domain: &str) -> bool {
        self.sites.contains_key(&domain.to_ascii_lowercase())
    }

    /// The test CA's certificate, which every listener's certificate
    /// chains to.
    pub fn ca(&self) -> CertificateDer<'static> {
        self.ca.clone()
    }

    /// A PEM file with the test CA's certificate, as `[keys] extra_roots`
    /// takes.
    pub fn ca_path(&self) -> &Path {
        &self.ca_path
    }

    /// Where `domain`'s key files are served. Panics if it serves no such
    /// domain.
    pub fn addr(&self, domain: &str) -> SocketAddr {
        self.site(domain).addr
    }

    /// A resolver that sends each domain to its listener.
    pub fn resolver(&self) -> StaticResolver {
        let mut resolver = StaticResolver::new();
        for (domain, site) in &self.sites {
            resolver.insert(domain, [site.addr]);
        }
        resolver
    }

    /// Fetch options for a [`risala_keyfetch::KeyFetcher`] that fetches
    /// from this server: only the test CA trusted, private addresses
    /// allowed, [`resolver`](Self::resolver), and no limit on how often a
    /// file is fetched again, so that a key added in a test is seen at the
    /// next refetch (4.4).
    pub fn fetch_options(&self) -> FetchOptions {
        FetchOptions {
            roots: Roots::Only(vec![self.ca()]),
            allow_private: true,
            resolver: Arc::new(self.resolver()),
            min_refetch: Duration::ZERO,
            ..FetchOptions::default()
        }
    }

    /// A new identity with one device, labelled `device1`, whose chain
    /// names `<domain>/risala-log/1`, and whose key file lists its records
    /// unlogged. Panics if it serves no such domain, or if the domain is a
    /// server's identity domain: register those instead.
    pub fn new_identity(&self, identity: &str) -> TestIdentity {
        let id: Identity = identity
            .parse()
            .unwrap_or_else(|e| panic!("{identity:?} is not an identity: {e}"));
        let log = test_log_key(id.domain(), 1, [7; 32]);
        let (chain, device) = TestChain::new(identity, &log);
        self.set_chain(chain);
        device
    }

    /// The chain of `identity`. Panics if this server made none for it.
    pub fn chain(&self, identity: &Identity) -> TestChain {
        self.chains
            .lock()
            .expect("poisoned")
            .get(identity)
            .cloned()
            .unwrap_or_else(|| panic!("no chain for {identity}"))
    }

    /// Replaces `chain`'s identity's chain with `chain`, and publishes its
    /// key file.
    pub fn set_chain(&self, chain: TestChain) {
        self.publish_file(chain.identity(), chain.key_file().as_bytes());
        self.chains
            .lock()
            .expect("poisoned")
            .insert(chain.identity().clone(), chain);
    }

    /// A new device of `of`'s identity, labelled `device<n>`, added to its
    /// chain.
    pub fn new_device(&self, of: &TestIdentity) -> TestIdentity {
        let mut chain = self.chain(of.identity());
        let n = chain.chain().devices().len() + 1;
        let device = chain.add_device(&format!("device{n}"));
        self.set_chain(chain);
        device
    }

    /// Removes `device` from its identity's chain, with a `signing`
    /// record (4.4).
    pub fn remove_device(&self, of: &TestIdentity, device: &TestIdentity) {
        let mut chain = self.chain(of.identity());
        chain.remove_devices(&[device]);
        self.set_chain(chain);
    }

    /// Serves `file` as `identity`'s key file, whatever it holds.
    pub fn publish_file(&self, identity: &Identity, file: &[u8]) {
        let site = self.own_site(identity);
        site.keys
            .publish(&name(identity), file)
            .expect("writing a key file");
    }

    /// Deletes `identity`'s key file, so that fetching it gets 404.
    pub fn remove(&self, identity: &Identity) {
        let site = self.own_site(identity);
        site.keys
            .remove(&name(identity))
            .expect("deleting a key file");
    }

    fn site(&self, domain: &str) -> &Site {
        self.sites
            .get(&domain.to_ascii_lowercase())
            .unwrap_or_else(|| panic!("the key server does not serve {domain}"))
    }

    fn own_site(&self, identity: &Identity) -> &Site {
        let site = self.site(identity.domain());
        assert!(
            !site.foreign,
            "{} is the server's identity domain: register identities there, and change their \
             chains with KEYS PUT",
            identity.domain()
        );
        site
    }
}

fn domain(d: &str) -> String {
    let parsed: risala_proto::names::Domain = d
        .parse()
        .unwrap_or_else(|e| panic!("{d:?} is not a domain: {e}"));
    parsed.as_str().to_owned()
}

fn name(identity: &Identity) -> Name {
    identity
        .name()
        .parse()
        .expect("an identity's name is a name")
}

/// Makes a test CA and a certificate from it for `domains`, writes them to
/// `dir`, and returns the CA's certificate, the path of its PEM file, and
/// the certificate and key for the listeners.
fn make_certificates(
    dir: &Path,
    domains: &[String],
) -> (CertificateDer<'static>, PathBuf, CertPair) {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA parameters");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "risala test key server CA");
    let ca_key = rcgen::KeyPair::generate().expect("a CA key");
    let ca = params.self_signed(&ca_key).expect("the CA certificate");
    let ca_path = dir.join("ca.pem");
    std::fs::write(&ca_path, ca.pem()).expect("writing the CA certificate");
    let issuer = rcgen::Issuer::new(params, ca_key);

    let leaf_params =
        rcgen::CertificateParams::new(domains.to_vec()).expect("certificate parameters");
    let leaf_key = rcgen::KeyPair::generate().expect("a key");
    let leaf = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("the certificate");
    let pair = CertPair {
        cert: dir.join("keys.pem"),
        key: dir.join("keys.key"),
    };
    std::fs::write(&pair.cert, leaf.pem()).expect("writing the certificate");
    std::fs::write(&pair.key, leaf_key.serialize_pem()).expect("writing the key");
    (ca.der().clone(), ca_path, pair)
}
