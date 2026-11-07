//! Identities for tests: [`TestIdentity`], a device's key, and
//! [`TestKeyServer`], an HTTPS server with key files (4.4).
//!
//! **For tests only.** See the [module documentation](super) for how a
//! [`TestServer`](super::TestServer) uses them.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use risala_keyfetch::{FetchOptions, Roots, StaticResolver};
use risala_proto::auth::{Nonce, PublicKey, SecretKey, Signature};
use risala_proto::keyfile::KeyEntry;
use risala_proto::names::{Identity, Name, Uid};
use rustls::pki_types::CertificateDer;
use tokio::task::JoinHandle;

use super::TempDir;
use crate::config::CertPair;
use crate::core::KeyFilePublisher as _;
use crate::http::{HttpServer, KeyDir};
use crate::net::Certificates;

/// One device of an identity, for tests: the identity and the device's
/// ML-DSA-44 key (4.3-4.5).
///
/// Make one with [`TestServer::identity`](super::TestServer::identity),
/// [`TestServer::register`](super::TestServer::register) or
/// [`TestKeyServer::new_identity`], which also publish its key, or with
/// [`TestIdentity::new`] for a key that nothing lists yet.
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
    /// `identity` with a new random key. Panics if `identity` is not one
    /// (4.3).
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

    /// Another device of the same identity: a new random key, which
    /// nothing lists yet.
    pub fn new_key(&self) -> TestIdentity {
        TestIdentity::with_key(self.identity.clone(), random_key())
    }

    /// The identity, such as `alice@example.org`.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// The identity as a uid.
    pub fn uid(&self) -> Uid {
        self.identity.to_uid()
    }

    /// The device's private key, for a client's key store.
    pub fn key(&self) -> &SecretKey {
        &self.key
    }

    /// The device's public key, as in key files and `KEY ADD` (4.4, 4.7).
    pub fn public_key(&self) -> PublicKey {
        self.key.public_key()
    }

    /// The device's key file entry (4.4), with `label`.
    pub fn key_entry(&self, label: Option<&str>) -> KeyEntry {
        KeyEntry::new(self.public_key(), label).expect("a label that fits in a key file")
    }

    /// The signature AUTH needs on a connection to `host` whose greeting
    /// had `nonce` (4.5). `host` is the name the client sent in SNI.
    pub fn sign(&self, host: &str, nonce: &Nonce) -> Signature {
        self.key.sign_challenge(host, nonce, self.identity.as_str())
    }

    /// The whole `AUTH <identity> <signature>` line (4.5).
    pub fn auth_line(&self, host: &str, nonce: &Nonce) -> String {
        format!("AUTH {} {}", self.identity, self.sign(host, nonce))
    }

    /// The whole `REGISTER <name> <key> <signature>` line (4.6), to
    /// register this identity on a server whose identity domain is its
    /// domain.
    pub fn register_line(&self, host: &str, nonce: &Nonce) -> String {
        format!(
            "REGISTER {} {} {}",
            self.identity.name(),
            self.public_key(),
            self.sign(host, nonce)
        )
    }
}

/// A new random device key.
fn random_key() -> SecretKey {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("random bytes");
    SecretKey::from_seed(seed)
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
/// ```no_run
/// # async fn f() {
/// use risala_server::testing::TestKeyServer;
///
/// let keys = TestKeyServer::start(&["example.net"]).await;
/// let bob = keys.new_identity("bob@example.net");
/// let phone = keys.new_device(&bob);
/// assert_eq!(keys.keys(bob.identity()).len(), 2);
/// keys.remove_key(bob.identity(), &phone.public_key());
/// # }
/// ```
pub struct TestKeyServer {
    /// Holds the CA, the certificate and the key files.
    _dir: TempDir,
    ca: CertificateDer<'static>,
    ca_path: PathBuf,
    sites: BTreeMap<String, Site>,
    /// The key files this server writes, by identity. A domain served from
    /// someone else's directory (a server's hosted identities) is not here.
    files: Mutex<HashMap<Identity, Vec<KeyEntry>>>,
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
    /// domain and its `key_dir` (4.6).
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
                keys.clone(),
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
            files: Mutex::new(HashMap::new()),
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

    /// A new identity with one device, whose key file lists only that
    /// device's key, labelled `device1`. Panics if it serves no such
    /// domain, or if the domain is a server's identity domain: register
    /// those instead.
    pub fn new_identity(&self, identity: &str) -> TestIdentity {
        let device = TestIdentity::new(identity);
        self.publish(device.identity(), &[device.key_entry(Some("device1"))]);
        device
    }

    /// A new device of `of`'s identity: a new key, added to the end of its
    /// key file with the label `device<n>`.
    pub fn new_device(&self, of: &TestIdentity) -> TestIdentity {
        let device = of.new_key();
        let n = self.keys(of.identity()).len() + 1;
        self.add_key(
            of.identity(),
            &device.public_key(),
            Some(&format!("device{n}")),
        );
        device
    }

    /// The entries of `identity`'s key file, empty if it has none.
    pub fn keys(&self, identity: &Identity) -> Vec<KeyEntry> {
        self.files
            .lock()
            .expect("poisoned")
            .get(identity)
            .cloned()
            .unwrap_or_default()
    }

    /// Replaces `identity`'s key file with one listing `keys`, in order.
    pub fn publish(&self, identity: &Identity, keys: &[KeyEntry]) {
        let site = self.own_site(identity);
        site.keys
            .publish(&name(identity), keys)
            .expect("writing a key file");
        self.files
            .lock()
            .expect("poisoned")
            .insert(identity.clone(), keys.to_vec());
    }

    /// Adds `key` to the end of `identity`'s key file, making the file if
    /// there is none.
    pub fn add_key(&self, identity: &Identity, key: &PublicKey, label: Option<&str>) {
        let mut keys = self.keys(identity);
        keys.push(KeyEntry::new(key.clone(), label).expect("a label that fits in a key file"));
        self.publish(identity, &keys);
    }

    /// Takes `key` out of `identity`'s key file.
    pub fn remove_key(&self, identity: &Identity, key: &PublicKey) {
        let keys: Vec<KeyEntry> = self
            .keys(identity)
            .into_iter()
            .filter(|e| e.key() != key)
            .collect();
        self.publish(identity, &keys);
    }

    /// Deletes `identity`'s key file, so that fetching it gets 404.
    pub fn remove(&self, identity: &Identity) {
        let site = self.own_site(identity);
        site.keys
            .remove(&name(identity))
            .expect("deleting a key file");
        self.files.lock().expect("poisoned").remove(identity);
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
            "{} is the server's identity domain: register identities there, and manage their \
             keys with KEY",
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
