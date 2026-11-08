//! The key log and the witness over HTTPS (4.5, 4.10):
//!
//! - [`route`]: which requests the listener hands to the hub's log
//!   ([`Hub::serve_log`]: `GET /risala-log/<n>/…`, [TLOG-TILES]) and
//!   witness ([`Hub::witness_request`]: `POST /risala-witness/…`,
//!   [TLOG-WITNESS]);
//! - [`HttpsPoster`]: how the log sends `add-checkpoint` and
//!   `risala/handoff` requests to its witnesses: one HTTPS POST per
//!   connection, TLS 1.3, certificates checked against the public CAs and
//!   `keys.extra_roots`, no redirects.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::core::Hub;
use crate::core::keylog::{
    Answer, LOG_PATH, MAX_WITNESS_RESPONSE, Posted, Transport, WITNESS_PATH, WITNESS_TIMEOUT,
};

/// The largest request body the witness takes: an `add-checkpoint` or
/// hand-off request is a few kilobytes (4.10).
pub const MAX_WITNESS_REQUEST: usize = 64 * 1024;

/// Whether `path` is the witness's, so that the listener reads a body.
pub(crate) fn is_witness_path(path: &str) -> bool {
    path.strip_prefix(WITNESS_PATH)
        .is_some_and(|rest| rest.starts_with('/'))
}

/// Answers a request for the log or the witness, or `None` if it is for
/// neither. `GET` and `HEAD` go to the log, `POST` to the witness.
pub(crate) async fn route(hub: &Hub, method: &str, path: &str, body: Vec<u8>) -> Option<Answer> {
    if path.starts_with(LOG_PATH) {
        return match method {
            "GET" | "HEAD" => hub.serve_log(path).await,
            _ => None,
        };
    }
    if is_witness_path(path) {
        return match method {
            "POST" => hub.witness_request(path, body).await,
            _ => None,
        };
    }
    None
}

/// The reason phrase of a status the log or the witness answers with.
pub(crate) fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        _ => "Error",
    }
}

/// Sends the log's requests to its witnesses over HTTPS.
pub(crate) struct HttpsPoster {
    connector: TlsConnector,
}

impl HttpsPoster {
    /// A client trusting the public CAs and the certificates in
    /// `extra_roots`, PEM files. Reads them, so call it from a blocking
    /// context.
    pub(crate) fn new(extra_roots: &[PathBuf]) -> io::Result<HttpsPoster> {
        let mut store = RootCertStore::empty();
        store.add_parsable_certificates(webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().cloned());
        for path in extra_roots {
            let certs = CertificateDer::pem_file_iter(path)
                .and_then(Iterator::collect::<Result<Vec<_>, _>>)
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("keys.extra_roots: {}: {e}", path.display()),
                    )
                })?;
            store.add_parsable_certificates(certs);
        }
        let mut config = ClientConfig::builder_with_provider(risala_keyfetch::provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(io::Error::other)?
            .with_root_certificates(store)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(HttpsPoster {
            connector: TlsConnector::from(Arc::new(config)),
        })
    }

    /// Sends one request and reads its response, whose body may be up to
    /// `max` bytes.
    async fn send(
        &self,
        method: &str,
        url: &str,
        body: Vec<u8>,
        max: usize,
    ) -> Result<(u16, Vec<u8>), String> {
        let rest = url
            .strip_prefix("https://")
            .ok_or_else(|| format!("{url} is not an https URL"))?;
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) if !h.ends_with(']') || h.starts_with('[') => (
                h.trim_start_matches('[').trim_end_matches(']'),
                p.parse::<u16>().map_err(|_| format!("bad port in {url}"))?,
            ),
            _ => (authority, 443),
        };
        let name = ServerName::try_from(host.to_owned()).map_err(|e| e.to_string())?;
        let tcp = TcpStream::connect((host, port))
            .await
            .map_err(|e| e.to_string())?;
        let mut tls = self
            .connector
            .connect(name, tcp)
            .await
            .map_err(|e| e.to_string())?;
        let length = if method == "POST" {
            format!(
                "Content-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n",
                body.len()
            )
        } else {
            String::new()
        };
        let head = format!(
            "{method} {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: risalad/{}\r\n\
             {length}Accept-Encoding: identity\r\nConnection: close\r\n\r\n",
            env!("CARGO_PKG_VERSION"),
        );
        tls.write_all(head.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        tls.write_all(&body).await.map_err(|e| e.to_string())?;
        tls.flush().await.map_err(|e| e.to_string())?;
        let mut response = Vec::new();
        (&mut tls)
            .take((max + 16 * 1024) as u64)
            .read_to_end(&mut response)
            .await
            .map_err(|e| e.to_string())?;
        parse_response(&response, max)
    }

    /// `GET <url>`, for tests that read a log over HTTPS.
    #[cfg(test)]
    pub(crate) async fn get(&self, url: &str) -> Result<(u16, Vec<u8>), String> {
        self.send("GET", url, Vec::new(), 8 << 20).await
    }
}

impl Transport for HttpsPoster {
    fn post<'a>(&'a self, url: &'a str, body: Vec<u8>) -> Posted<'a> {
        Box::pin(async move {
            let post = self.send("POST", url, body, MAX_WITNESS_RESPONSE);
            tokio::time::timeout(WITNESS_TIMEOUT, post)
                .await
                .map_err(|_| "timed out".to_owned())?
        })
    }
}

/// Reads a whole HTTP/1.1 response: its status and its body, framed by
/// `Content-Length`, by chunks, or by the end of the connection. Interim
/// (1xx) responses are skipped. The body may be up to `max` bytes.
pub(crate) fn parse_response(mut bytes: &[u8], max: usize) -> Result<(u16, Vec<u8>), String> {
    let bad = |what: &str| format!("malformed response: {what}");
    loop {
        let end = bytes
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| bad("no end of head"))?;
        let head = std::str::from_utf8(&bytes[..end]).map_err(|_| bad("head is not UTF-8"))?;
        let rest = &bytes[end + 4..];
        let mut lines = head.split("\r\n");
        let status_line = lines.next().unwrap_or_default();
        let mut parts = status_line.splitn(3, ' ');
        let (version, status) = (parts.next(), parts.next());
        if !matches!(version, Some("HTTP/1.1" | "HTTP/1.0")) {
            return Err(bad("status line"));
        }
        let status: u16 = status
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| bad("status"))?;
        if (100..200).contains(&status) {
            bytes = rest;
            continue;
        }
        let mut length = None;
        let mut chunked = false;
        for line in lines {
            let Some((name, value)) = line.split_once(':') else {
                return Err(bad("header"));
            };
            let value = value.trim();
            if name.eq_ignore_ascii_case("content-length") {
                length = Some(value.parse::<usize>().map_err(|_| bad("content-length"))?);
            } else if name.eq_ignore_ascii_case("transfer-encoding") {
                chunked = value.eq_ignore_ascii_case("chunked");
            }
        }
        let body = if chunked {
            dechunk(rest, max).ok_or_else(|| bad("chunks"))?
        } else if let Some(n) = length {
            rest.get(..n).ok_or_else(|| bad("short body"))?.to_vec()
        } else {
            rest.to_vec()
        };
        if body.len() > max {
            return Err(bad("body too large"));
        }
        return Ok((status, body));
    }
}

/// Decodes a chunked body, ignoring chunk extensions and trailers.
fn dechunk(mut rest: &[u8], max: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let eol = rest.windows(2).position(|w| w == b"\r\n")?;
        let line = std::str::from_utf8(&rest[..eol]).ok()?;
        let size = usize::from_str_radix(line.split(';').next()?.trim(), 16).ok()?;
        rest = &rest[eol + 2..];
        if size == 0 {
            return Some(out);
        }
        out.extend_from_slice(rest.get(..size)?);
        rest = rest.get(size..)?.strip_prefix(b"\r\n")?;
        if out.len() > max {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn responses() {
        assert_eq!(
            parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcdef", 100),
            Ok((200, b"abc".to_vec()))
        );
        assert_eq!(
            parse_response(
                b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 409 Conflict\r\n\
                  Transfer-Encoding: chunked\r\n\r\n2;x=y\r\n12\r\n1\r\n\n\r\n0\r\n\r\n",
                100
            ),
            Ok((409, b"12\n".to_vec()))
        );
        assert_eq!(
            parse_response(b"HTTP/1.0 404 Not Found\r\n\r\nno", 100),
            Ok((404, b"no".to_vec()))
        );
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nabc", 100).is_err());
        assert!(parse_response(b"HTTP/2 200\r\n\r\n", 100).is_err());
        assert!(parse_response(b"garbage", 100).is_err());
    }

    #[test]
    fn witness_paths() {
        assert!(is_witness_path("/risala-witness/add-checkpoint"));
        assert!(is_witness_path("/risala-witness/risala/handoff"));
        assert!(!is_witness_path("/risala-witness"));
        assert!(!is_witness_path("/risala-witnesses/add-checkpoint"));
    }

    /// The listener reads a witness request's body by its length, after a
    /// head that ends with LF or CRLF, and refuses others (4.10).
    #[tokio::test]
    async fn witness_request_bodies() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let dir = tempfile::tempdir().unwrap();
        let mut config = crate::config::Config {
            state_dir: dir.path().to_owned(),
            ..crate::config::Config::default()
        };
        config.witness.enabled = true;
        let hub = Hub::new(config, crate::store::SqliteStore::open_in_memory().unwrap()).unwrap();
        let keys: Arc<dyn super::super::KeyFiles> = Arc::new(hub);
        // A request for a log the witness does not know, that does not
        // enrol it: 404 once the body parses, 400 if it does not.
        let log = risala_keylog::testlog::MemoryLog::new(
            &"other.example/risala-log/1".parse().unwrap(),
            &[3; 32],
        );
        let body = risala_keylog::addcheckpoint::AddCheckpoint {
            old_size: 1,
            proof: vec![],
            checkpoint: log.checkpoint(100),
        }
        .to_body();
        let status = |head: String, body: String| {
            let keys = keys.clone();
            async move {
                let (mut client, mut server) = tokio::io::duplex(1 << 20);
                let serve = tokio::spawn(async move {
                    super::super::server::handle(&mut server, &keys).await;
                });
                client.write_all(head.as_bytes()).await.unwrap();
                client.write_all(body.as_bytes()).await.unwrap();
                let mut out = Vec::new();
                client.read_to_end(&mut out).await.unwrap();
                serve.await.unwrap();
                parse_response(&out, 1 << 20).unwrap().0
            }
        };
        let path = "/risala-witness/add-checkpoint";
        let len = body.len();
        let crlf = format!("POST {path} HTTP/1.1\r\nContent-Length: {len}\r\n\r\n");
        let lf = format!("POST {path} HTTP/1.1\nContent-Length: {len}\n\n");
        assert_eq!(status(crlf, body.clone()).await, 404);
        assert_eq!(status(lf, body.clone()).await, 404);
        let short = format!("POST {path} HTTP/1.1\r\nContent-Length: 10\r\n\r\n");
        assert_eq!(status(short, body.clone()).await, 400);
        let none = format!("POST {path} HTTP/1.1\r\n\r\n");
        assert_eq!(status(none, body.clone()).await, 411);
        let chunked = format!("POST {path} HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n");
        assert_eq!(status(chunked, body.clone()).await, 411);
        let big = format!("POST {path} HTTP/1.1\r\nContent-Length: 70000\r\n\r\n");
        assert_eq!(status(big, String::new()).await, 413);
    }

    /// A log in one risalad, witnessed by a second risalad in witness mode,
    /// over real TLS on both sides; a device reads the witnessed
    /// checkpoint, tiles and entry bundle over HTTPS and accepts a record
    /// (4.5, 4.10).
    #[tokio::test]
    async fn a_risalad_witnesses_another_over_tls() {
        use std::time::Duration;

        use risala_keylog::client::{LogView, accept_record};
        use risala_keylog::cosig::Cosigner;
        use risala_keylog::tile::{TileSet, bundle_for_entry, decode_bundle};
        use risala_keylog::{Freshness, WitnessPolicy};
        use risala_proto::auth::SecretKey;
        use risala_proto::record::{LogKey, Record, RecordBody, RecordContent};

        use crate::config::{CertPair, Config, LogWitness};
        use crate::daemon::Daemon;
        use crate::store::{KeyLogStore as _, SqliteStore};

        // A test CA, and a certificate for localhost from it.
        let dir = tempfile::tempdir().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca = params.self_signed(&ca_key).unwrap();
        let ca_pem = dir.path().join("ca.pem");
        std::fs::write(&ca_pem, ca.pem()).unwrap();
        let issuer = rcgen::Issuer::new(params, ca_key);
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .signed_by(&leaf_key, &issuer)
            .unwrap();
        let pair = CertPair {
            cert: dir.path().join("localhost.pem"),
            key: dir.path().join("localhost.key"),
        };
        std::fs::write(&pair.cert, leaf.pem()).unwrap();
        std::fs::write(&pair.key, leaf_key.serialize_pem()).unwrap();

        let t = risala_proto::time::Timestamp::now();
        let base = |state: &str| {
            let mut c = Config {
                hostname: "localhost".into(),
                listen: vec!["127.0.0.1:0".parse().unwrap()],
                state_dir: dir.path().join(state),
                ..Config::default()
            };
            std::fs::create_dir_all(&c.state_dir).unwrap();
            c.http.listen = vec!["127.0.0.1:0".parse().unwrap()];
            c.http.certs = vec![pair.clone()];
            c.keys.extra_roots = vec![ca_pem.clone()];
            c
        };

        // The keys, set before either server starts.
        let log_seed = [21; 32];
        let witness_seed = [22; 32];
        let log_vkey = Cosigner::from_seed("localhost/risala-log/1", &log_seed)
            .unwrap()
            .vkey()
            .to_string();
        let witness_vkey = Cosigner::from_seed("localhost/risala-witness", &witness_seed)
            .unwrap()
            .vkey()
            .to_string();

        let mut wc = base("witness");
        wc.witness.enabled = true;
        SqliteStore::open(&wc.database_path())
            .unwrap()
            .witness_seed(witness_seed, t)
            .unwrap();
        // The witness fetches log 1's key from `https://localhost/...`, on
        // port 443 (4.10), which the test cannot listen on: it gets the
        // file the log serves from memory instead.
        let key_file = risala_keylog::hint::log_key_body(
            &risala_keylog::LogKey::from_vkey_str(&log_vkey).unwrap(),
        );
        let fetcher = crate::keyfiles::MemoryFetcher::new();
        fetcher.serve_log("https://localhost/risala-log/1", move |path| {
            (path == "risala/key").then(|| key_file.clone().into_bytes())
        });
        let keys = crate::keyfiles::KeyServices::shared(
            Arc::new(fetcher),
            Arc::new(crate::keyfiles::NoPublisher),
        );
        let witness = Daemon::bind_with_keys(wc, keys).await.unwrap();
        let witness_port = witness.http_addrs()[0].port();
        let (stop_w, stopped_w) = tokio::sync::oneshot::channel::<()>();
        let witness_task = tokio::spawn(witness.run(async {
            let _ = stopped_w.await;
        }));

        let mut lc = base("log");
        lc.log.enabled = Some(true);
        lc.log.witnesses = vec![LogWitness {
            vkey: witness_vkey.clone(),
            url: format!("https://localhost:{witness_port}/risala-witness"),
        }];
        SqliteStore::open(&lc.database_path())
            .unwrap()
            .first_log_key(log_seed, t)
            .unwrap();
        let log = Daemon::bind(lc).await.unwrap();
        assert_eq!(log.hub().log_vkey(), Some(log_vkey.clone()));
        let log_port = log.http_addrs()[0].port();
        // A record, logged before the server runs.
        let key = LogKey::from_vkey(&log_vkey).unwrap();
        let master = SecretKey::from_seed([23; 32]);
        let record = Record::sign_deterministic(
            RecordContent {
                uid: "alice@example.org".parse().unwrap(),
                previous: None,
                time: t.unix_millis(),
                body: RecordBody::Master {
                    master_key: master.public_key(),
                    signing_key: SecretKey::from_seed([24; 32]).public_key(),
                    log: key,
                },
            },
            &master,
        )
        .unwrap();
        log.hub()
            .append_for_tests(&"alice@example.org".parse().unwrap(), vec![record.clone()])
            .await
            .unwrap();
        let (stop_l, stopped_l) = tokio::sync::oneshot::channel::<()>();
        let log_task = tokio::spawn(log.run(async {
            let _ = stopped_l.await;
        }));

        // A device: the witness's key, k = 1, over HTTPS with the test CA.
        let client = HttpsPoster::new(std::slice::from_ref(&ca_pem)).unwrap();
        let prefix = format!("https://localhost:{log_port}/risala-log/1");
        let policy = WitnessPolicy::from_vkeys(&[witness_vkey], 1).unwrap();
        let log_key = risala_keylog::LogKey::from_vkey_str(&log_vkey).unwrap();
        let now = || risala_proto::time::Timestamp::now().unix_millis() / 1000;
        let mut checkpoint = None;
        for _ in 0..100 {
            if let Ok((200, body)) = client.get(&format!("{prefix}/checkpoint")).await
                && let Ok(w) = policy.verify(&log_key, &body, Freshness::fresh(now()))
            {
                checkpoint = Some(w);
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let checkpoint = checkpoint.expect("a checkpoint witnessed over TLS");
        assert_eq!(checkpoint.checkpoint().size(), 1);

        let mut view = LogView::new(log_key, checkpoint.clone()).unwrap();
        let mut set = TileSet::new();
        for tile in view.tiles_for_entry(checkpoint.checkpoint(), 0) {
            let (status, data) = client
                .get(&format!("{prefix}/{}", tile.path()))
                .await
                .unwrap();
            assert_eq!(status, 200);
            set.insert(tile, data).unwrap();
        }
        let bundle = bundle_for_entry(0, 1).unwrap();
        let (status, data) = client
            .get(&format!("{prefix}/{}", bundle.path()))
            .await
            .unwrap();
        assert_eq!(status, 200);
        let entry = decode_bundle(&data).unwrap().remove(0);
        accept_record(
            &mut view,
            checkpoint,
            &entry,
            0,
            record.hash().hash(),
            &mut set.reader(1),
            now(),
        )
        .unwrap();
        // The hint, over HTTPS too.
        let hint = risala_keylog::hint::uid_hint_path("alice@example.org");
        assert_eq!(
            client.get(&format!("{prefix}/{hint}")).await.unwrap(),
            (200, b"risala-hint/1\n0\n".to_vec())
        );
        // And the log's key file, which the witness enrolled it with.
        let (status, data) = client.get(&format!("{prefix}/risala/key")).await.unwrap();
        assert_eq!(status, 200);
        assert_eq!(
            risala_keylog::hint::parse_log_key(&data, &"localhost/risala-log/1".parse().unwrap()),
            Ok(risala_keylog::LogKey::from_vkey_str(&log_vkey).unwrap())
        );
        // The witness answers nothing but POSTs under its path.
        let w = format!("https://localhost:{witness_port}/risala-witness/add-checkpoint");
        assert_eq!(client.get(&w).await.unwrap().0, 404);

        let _ = stop_l.send(());
        let _ = stop_w.send(());
        log_task.await.unwrap().unwrap();
        witness_task.await.unwrap().unwrap();
    }
}
