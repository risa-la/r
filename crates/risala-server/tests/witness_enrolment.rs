//! The server witnesses its own key log, and enrols it the way it enrols
//! any host's first log (4.10): by fetching the log's key from
//! `https://<host>/risala-log/1/risala/key`, here its own HTTPS listener,
//! which the test server's resolver reaches for its own hostname.

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use risala_keylog::cosig::Cosigner;
use risala_proto::time::Timestamp;
use risala_server::config::{CertPair, LogWitness};
use risala_server::store::{KeyLogStore as _, SqliteStore};
use risala_server::testing::TestServer;

const LOG_SEED: [u8; 32] = [21; 32];
const WITNESS_SEED: [u8; 32] = [22; 32];
const HOST: &str = "chat.test";

/// A test CA in `dir`, and a certificate from it for [`HOST`] and
/// `localhost`, where the log reaches its own witness.
fn certificates(dir: &Path) -> (CertPair, std::path::PathBuf) {
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
        cert: dir.join("leaf.pem"),
        key: dir.join("leaf.key"),
    };
    std::fs::write(&pair.cert, leaf.pem()).unwrap();
    std::fs::write(&pair.key, leaf_key.serialize_pem()).unwrap();
    (pair, ca_pem)
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test]
async fn the_witness_enrols_its_own_log_by_fetching_its_key() {
    let dir = tempfile::tempdir().unwrap();
    let (pair, ca_pem) = certificates(dir.path());
    let port = free_port();
    let witness = Cosigner::from_seed(&format!("{HOST}/risala-witness"), &WITNESS_SEED)
        .unwrap()
        .vkey()
        .to_string();
    let server = TestServer::builder()
        .hostname(HOST)
        .identity_domain("example.org")
        .configure(move |c| {
            c.server.registration = true;
            c.http.listen = vec![SocketAddr::from(([127, 0, 0, 1], port))];
            c.http.certs = vec![pair];
            c.keys.extra_roots.push(ca_pem);
            c.log.enabled = Some(true);
            c.log.witnesses = vec![LogWitness {
                vkey: witness,
                url: format!("https://localhost:{port}/risala-witness"),
            }];
            c.witness.enabled = true;
        })
        .prepare(move |store| {
            let t = Timestamp::now();
            store.witness_seed(WITNESS_SEED, t).unwrap();
            store.first_log_key(LOG_SEED, t).unwrap();
        })
        .start()
        .await;
    // A new record, which the log has witnessed within about 10 seconds.
    let _alice = server.register("alice").await;
    let store = SqliteStore::open(&server.config().database_path()).unwrap();
    let origin = format!("{HOST}/risala-log/1");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(row) = store.witness_log(&origin).unwrap()
            && row.size > 0
        {
            // Enrolled with the key the log serves, and cosigned since.
            let log_vkey = Cosigner::from_seed(&origin, &LOG_SEED)
                .unwrap()
                .vkey()
                .to_string();
            assert_eq!(row.vkey, log_vkey);
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the witness never enrolled the log"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    server.stop().await;
}
