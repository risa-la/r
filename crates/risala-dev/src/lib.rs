//! A local risala server for development and tests: a whole `risalad`
//! that hosts identities, keeps their key log, witnesses that log, and
//! serves the log, hosted key files, files and blobs over HTTPS (4.5,
//! 4.7, 4.10, 5.6, 12.12).
//!
//! **Development and tests only.** The log's and the witness's keys come
//! from fixed seeds, and the certificates from a test CA made here.
//!
//! A [`World`] is what a client needs to reach that server as if it were
//! on the Internet: the server's name ([`HOST`]) and where it really
//! listens, the identity domain ([`DOMAIN`]) whose key files a test key
//! server serves, the CA certificates to trust for HTTPS, and the
//! witness's verifier key, for a witness policy of one witness (k = 1).
//! [`World::cli_args`] gives the same as `risala` command-line options.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use risala_keyfetch::CertificateDer;
use risala_keylog::cosig::Cosigner;
use risala_keylog::merkle::empty_root;
use risala_proto::time::Timestamp;
use risala_server::config::{CertPair, LogWitness};
use risala_server::store::KeyLogStore as _;
use risala_server::store::keylog::WitnessLogRow;
use risala_server::testing::TestServer;

/// The server's name. It need not resolve: clients are told where it
/// listens.
pub const HOST: &str = "chat.test";

/// The identity domain the server hosts (4.7).
pub const DOMAIN: &str = "example.org";

/// The seed of the log's key (development only).
const LOG_SEED: [u8; 32] = [21; 32];

/// The seed of the witness's key (development only).
const WITNESS_SEED: [u8; 32] = [22; 32];

/// What to start.
#[derive(Debug, Clone, Default)]
pub struct WorldOptions {
    /// Keep the server's state, certificates included, in this directory,
    /// and carry on from it if it holds a world already. A temporary
    /// directory if `None`.
    pub state_dir: Option<PathBuf>,
    /// Where the chat server listens; `127.0.0.1` and a free port if
    /// `None`.
    pub listen: Option<SocketAddr>,
    /// The HTTPS listener's port; a free one if `None`.
    pub http_port: Option<u16>,
}

/// A running server with its key log and witness. See the [crate
/// docs](crate).
pub struct World {
    /// The server.
    pub server: TestServer,
    /// The witness's verifier key (4.5): a policy of this one witness,
    /// k = 1, accepts the log's checkpoints.
    pub witness: String,
    /// The HTTPS listener: the log, hosted key files, files and blobs.
    pub http: SocketAddr,
    /// The test CA that signed the server's certificate, PEM.
    pub ca_pem: PathBuf,
    ca: CertificateDer<'static>,
    _dir: Option<tempfile::TempDir>,
}

impl std::fmt::Debug for World {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("World")
            .field("server", &self.server.addr())
            .field("http", &self.http)
            .finish_non_exhaustive()
    }
}

/// A test CA and a certificate for [`HOST`] and `localhost` from it, in
/// `dir`, made once and kept.
fn certificates(dir: &Path) -> (CertificateDer<'static>, CertPair, PathBuf) {
    let ca_pem = dir.join("ca.pem");
    let ca_der = dir.join("ca.der");
    let pair = CertPair {
        cert: dir.join("https.pem"),
        key: dir.join("https.key"),
    };
    if !(ca_der.exists() && pair.cert.exists() && pair.key.exists()) {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "risala-dev test CA");
        let ca_key = rcgen::KeyPair::generate().expect("a CA key");
        let ca = params.self_signed(&ca_key).expect("the CA");
        std::fs::write(&ca_pem, ca.pem()).expect("writing the CA");
        std::fs::write(&ca_der, ca.der()).expect("writing the CA");
        let issuer = rcgen::Issuer::new(params, ca_key);
        let leaf_key = rcgen::KeyPair::generate().expect("a key");
        let leaf = rcgen::CertificateParams::new(vec![HOST.to_string(), "localhost".to_string()])
            .expect("params")
            .signed_by(&leaf_key, &issuer)
            .expect("the certificate");
        std::fs::write(&pair.cert, leaf.pem()).expect("writing the certificate");
        std::fs::write(&pair.key, leaf_key.serialize_pem()).expect("writing the key");
    }
    let der = std::fs::read(&ca_der).expect("reading the CA");
    (CertificateDer::from(der), pair, ca_pem)
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("a free port")
        .local_addr()
        .expect("its address")
        .port()
}

impl World {
    /// Starts a world in a temporary directory.
    pub async fn start() -> World {
        World::start_with(WorldOptions::default()).await
    }

    /// Starts a world.
    pub async fn start_with(options: WorldOptions) -> World {
        let (tmp, dir) = match &options.state_dir {
            Some(dir) => {
                std::fs::create_dir_all(dir).expect("creating the state directory");
                (None, dir.clone())
            }
            None => {
                let tmp = tempfile::tempdir().expect("a temporary directory");
                let dir = tmp.path().to_owned();
                (Some(tmp), dir)
            }
        };
        let certs = dir.join("certs");
        std::fs::create_dir_all(&certs).expect("creating the certificates' directory");
        let (ca, pair, ca_pem) = certificates(&certs);
        let http_port = options.http_port.unwrap_or_else(free_port);
        let log_vkey = Cosigner::from_seed(&format!("{HOST}/risala-log/1"), &LOG_SEED)
            .expect("the log key")
            .vkey()
            .to_string();
        let witness = Cosigner::from_seed(&format!("{HOST}/risala-witness"), &WITNESS_SEED)
            .expect("the witness key")
            .vkey()
            .to_string();
        let marker = dir.join("world");
        let fresh = !marker.exists();
        let w = witness.clone();
        let ca_for_server = ca_pem.clone();
        let mut builder = TestServer::builder()
            .hostname(HOST)
            .identity_domain(DOMAIN)
            .configure(move |c| {
                c.server.registration = true;
                c.http.listen = vec![SocketAddr::from(([127, 0, 0, 1], http_port))];
                c.http.certs = vec![pair];
                c.keys.extra_roots.push(ca_for_server);
                c.log.enabled = Some(true);
                c.log.witnesses = vec![LogWitness {
                    vkey: w,
                    url: format!("https://localhost:{http_port}/risala-witness"),
                }];
                c.witness.enabled = true;
            });
        if let Some(listen) = options.listen {
            builder = builder.listen(listen);
        }
        if options.state_dir.is_some() {
            builder = builder.state_dir(&dir.join("server"));
        }
        if fresh {
            builder = builder.prepare(move |store| {
                let t = Timestamp::now();
                store
                    .witness_seed(WITNESS_SEED, t)
                    .expect("the witness key");
                store.first_log_key(LOG_SEED, t).expect("the log key");
                // The witness would enrol the log with the key it fetches
                // from https://chat.test/risala-log/1/risala/key (4.10),
                // but the server's fetcher resolves only the test key
                // server's domains, so the log is enrolled here, as that
                // fetch would.
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("the time")
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
                    .expect("enrolling the log");
            });
        }
        let server = builder.start().await;
        if fresh {
            std::fs::write(&marker, b"risala-dev world 1\n").expect("writing the marker");
        }
        World {
            server,
            witness,
            http: SocketAddr::from(([127, 0, 0, 1], http_port)),
            ca_pem,
            ca,
            _dir: tmp,
        }
    }

    /// Where each name resolves: [`HOST`] to the HTTPS listener (the log,
    /// files and blobs), [`DOMAIN`] to the test key server.
    pub fn resolves(&self) -> Vec<(String, SocketAddr)> {
        vec![
            (HOST.to_owned(), self.http),
            (DOMAIN.to_owned(), self.server.key_server().addr(DOMAIN)),
        ]
    }

    /// The CA certificates to trust for HTTPS: the server's and the key
    /// server's.
    pub fn roots(&self) -> Vec<CertificateDer<'static>> {
        vec![self.ca.clone(), self.server.key_server().ca()]
    }

    /// The same, as PEM files.
    pub fn root_pems(&self) -> Vec<PathBuf> {
        vec![
            self.ca_pem.clone(),
            self.server.key_server().ca_path().to_owned(),
        ]
    }

    /// The `risala` options that reach this world: where the server
    /// listens and its fingerprint, the CAs, the names, and the witness.
    pub fn cli_args(&self) -> Vec<String> {
        let mut args = vec![
            "--connect-to".to_owned(),
            self.server.addr().to_string(),
            "--fingerprint".to_owned(),
            self.server.fingerprint().to_string(),
            "--witness".to_owned(),
            self.witness.clone(),
        ];
        for pem in self.root_pems() {
            args.push("--ca".to_owned());
            args.push(pem.display().to_string());
        }
        for (name, addr) in self.resolves() {
            args.push("--resolve".to_owned());
            args.push(format!("{name}={addr}"));
        }
        args
    }

    /// How long the log may take to witness a new record: it makes a
    /// checkpoint at most every 10 seconds.
    pub const LOG_DELAY: Duration = Duration::from_secs(10);
}
