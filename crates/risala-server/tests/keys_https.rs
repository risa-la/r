//! Blobs (12.12) and uploaded files (5.6) end to end: BLOB and UPLOAD on
//! a real server's TLS listener, then the bodies over its HTTPS listener.
//!
//! The hub's own tests (`src/core/tests/keys.rs`) cover each rule without
//! sockets. These check the HTTP side: `Content-Length`, hashes, one
//! upload per `put` URL, downloads, deletion, and methods.

use std::net::SocketAddr;
use std::sync::Arc;

use risala_proto::mls::{GroupId, SendToken};
use risala_proto::names::BlobRef;
use risala_server::store::{MailboxStore as _, NewMailbox};
use risala_server::testing::{TestClient, TestServer};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const BOX: &str = "ujzdegxdncf32epf3dhodzdoci";

fn token() -> SendToken {
    SendToken::from_bytes([5; 32])
}

/// A server with an HTTPS listener and the mailbox [`BOX`].
async fn server() -> TestServer {
    server_with(|_| {}).await
}

/// [`server`], with `f` applied to its configuration.
async fn server_with(f: impl FnOnce(&mut risala_server::config::Config)) -> TestServer {
    TestServer::builder()
        .configure(|c| {
            c.http.listen = vec!["127.0.0.1:0".parse().unwrap()];
            f(c);
        })
        .prepare(|store| {
            store
                .create_mailbox(&NewMailbox {
                    mailbox: BOX.parse().unwrap(),
                    group_id: GroupId::from_bytes([1; 32]),
                    first_epoch: 0,
                    token_hash: token().hash(),
                    created: risala_proto::time::Timestamp::now(),
                    moved_from: None,
                })
                .unwrap();
        })
        .start()
        .await
}

/// Sends `line` and returns the final response.
async fn command(c: &mut TestClient, line: &str) -> String {
    c.send(line).await.unwrap();
    c.expect_line().await.unwrap()
}

/// The value of `key=` in `line`.
fn value(line: &str, key: &str) -> String {
    let at = line
        .find(&format!(" {key}="))
        .unwrap_or_else(|| panic!("no {key}= in {line:?}"));
    line[at + key.len() + 2..]
        .split(' ')
        .next()
        .unwrap()
        .to_owned()
}

/// Accepts any certificate, for the test server's self-signed one.
#[derive(Debug)]
struct AcceptAny(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// An HTTP response: its status and body.
#[derive(Debug)]
struct Response {
    status: u16,
    head: String,
    body: Vec<u8>,
}

/// Where an `https://localhost:<port>/...` URL of the test server leads:
/// its address and path.
fn target(url: &str) -> (SocketAddr, String) {
    let rest = url.strip_prefix("https://localhost:").unwrap();
    let (port, path) = rest.split_at(rest.find('/').unwrap());
    (
        SocketAddr::from(([127, 0, 0, 1], port.parse().unwrap())),
        path.to_owned(),
    )
}

/// A TLS connection over `tcp` to the test server.
async fn tls(tcp: TcpStream) -> tokio_rustls::client::TlsStream<TcpStream> {
    let provider = risala_keyfetch::provider();
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny(provider)))
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap()
}

/// Sends one HTTP/1.1 request to `url` with `headers` and `body`, and
/// reads the whole response.
async fn request(method: &str, url: &str, headers: &[&str], body: &[u8]) -> Response {
    let (addr, path) = target(url);
    let mut tls = tls(TcpStream::connect(addr).await.unwrap()).await;
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n");
    for header in headers {
        head.push_str(header);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    tls.write_all(head.as_bytes()).await.unwrap();
    // The server may answer before the body is sent, and close.
    let _ = tls.write_all(body).await;
    let _ = tls.flush().await;
    let mut out = Vec::new();
    let _ = tls.read_to_end(&mut out).await;
    let split = out
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or_else(|| panic!("no head in {:?}", String::from_utf8_lossy(&out)));
    let head = String::from_utf8(out[..split].to_vec()).unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    Response {
        status,
        head,
        body: out[split + 4..].to_vec(),
    }
}

async fn put(url: &str, body: &[u8]) -> Response {
    let length = format!("Content-Length: {}", body.len());
    request(
        "PUT",
        url,
        &[&length, "Content-Type: application/octet-stream"],
        body,
    )
    .await
}

#[tokio::test]
async fn blobs_go_up_and_come_down_over_https() {
    let server = server().await;
    let mut anon = server.anon().await;
    // Large enough to arrive in many pieces.
    let bytes: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let hash = BlobRef::of(&bytes);
    let blob = format!("BLOB {hash} {} box={BOX} token={}", bytes.len(), token());
    let ok = command(&mut anon, &blob).await;
    let url = value(&ok, "put");
    assert!(url.starts_with("https://localhost:"), "{url}");

    // A GET to a put URL is not allowed.
    let r = request("GET", &url, &[], b"").await;
    assert_eq!(r.status, 405);
    assert!(r.head.contains("Allow: PUT"), "{}", r.head);

    let r = put(&url, &bytes).await;
    assert_eq!(r.status, 201, "{r:?}");
    // One upload only.
    assert_eq!(put(&url, &bytes).await.status, 404);

    let base = url.split("/blob/").next().unwrap();
    let get = format!("{base}/blobs/{}", hash.hex());
    let r = request("GET", &get, &[], b"").await;
    assert_eq!(r.status, 200);
    assert!(r.head.contains("Content-Type: application/octet-stream"));
    assert_eq!(r.body, bytes);
    let r = request("HEAD", &get, &[], b"").await;
    assert_eq!(r.status, 200);
    assert!(r.head.contains(&format!("Content-Length: {}", bytes.len())));
    assert!(r.body.is_empty());
    for path in [
        format!("{base}/blobs/{}", BlobRef::of(b"none").hex()),
        format!("{base}/blobs/{}", hash.hex().to_uppercase()),
        format!("{base}/blobs/abc"),
    ] {
        assert_eq!(request("GET", &path, &[], b"").await.status, 404, "{path}");
    }
    assert_eq!(command(&mut anon, &blob).await, "OK exists=yes");
    server.stop().await;
}

#[tokio::test]
async fn blob_bodies_must_match_their_size_and_hash() {
    let server = server().await;
    let mut anon = server.anon().await;
    let bytes = b"the right bytes".to_vec();
    let hash = BlobRef::of(&bytes);
    let blob = format!("BLOB {hash} {} box={BOX} token={}", bytes.len(), token());

    // The wrong length.
    let url = value(&command(&mut anon, &blob).await, "put");
    assert_eq!(put(&url, b"short").await.status, 400);
    // No length.
    let url = value(&command(&mut anon, &blob).await, "put");
    let r = request("PUT", &url, &[], &bytes).await;
    assert_eq!(r.status, 411);
    // Chunked bodies are not taken.
    let url = value(&command(&mut anon, &blob).await, "put");
    let r = request("PUT", &url, &["Transfer-Encoding: chunked"], b"").await;
    assert_eq!(r.status, 501);
    // The right length, the wrong bytes.
    let url = value(&command(&mut anon, &blob).await, "put");
    let wrong = b"the wrong bytes".to_vec();
    assert_eq!(wrong.len(), bytes.len());
    assert_eq!(put(&url, &wrong).await.status, 400);
    // The body ends early.
    let url = value(&command(&mut anon, &blob).await, "put");
    let r = request(
        "PUT",
        &url,
        &[&format!("Content-Length: {}", bytes.len() + 10)],
        &bytes,
    )
    .await;
    assert_eq!(r.status, 400);
    // Nothing was stored.
    let base = url.split("/blob/").next().unwrap();
    let get = format!("{base}/blobs/{}", hash.hex());
    assert_eq!(request("GET", &get, &[], b"").await.status, 404);
    // A wrong secret.
    let url = value(&command(&mut anon, &blob).await, "put");
    let (id, _) = url.rsplit_once('/').unwrap();
    let r = put(&format!("{id}/{}", "a".repeat(32)), &bytes).await;
    assert_eq!(r.status, 404);
    // Right at last, with Expect: 100-continue as curl sends.
    let r = request(
        "PUT",
        &url,
        &[
            &format!("Content-Length: {}", bytes.len()),
            "Expect: 100-continue",
        ],
        &bytes,
    )
    .await;
    assert!(r.head.starts_with("HTTP/1.1 100 Continue"), "{}", r.head);
    assert!(
        String::from_utf8_lossy(&r.body).starts_with("HTTP/1.1 201 Created"),
        "{r:?}"
    );
    assert_eq!(request("GET", &get, &[], b"").await.body, bytes);
    server.stop().await;
}

#[tokio::test]
async fn files_are_uploaded_downloaded_and_deleted_over_https() {
    let server = server().await;
    let mut anon = server.anon().await;
    let file = b"\x01an encrypted file".to_vec();
    let ok = command(
        &mut anon,
        &format!("UPLOAD {BOX} {} {}", token(), file.len()),
    )
    .await;
    let (put_url, get_url, del_url) = (value(&ok, "put"), value(&ok, "get"), value(&ok, "del"));
    assert_eq!(request("GET", &get_url, &[], b"").await.status, 404);
    assert_eq!(put(&put_url, &file).await.status, 201);
    assert_eq!(put(&put_url, &file).await.status, 410);
    let r = request("GET", &get_url, &[], b"").await;
    assert_eq!((r.status, r.body), (200, file.clone()));
    // Only DELETE deletes, and only with the del URL.
    assert_eq!(request("DELETE", &get_url, &[], b"").await.status, 405);
    assert_eq!(request("GET", &del_url, &[], b"").await.status, 405);
    let (id, _) = del_url.rsplit_once('/').unwrap();
    let wrong = format!("{id}/{}", "b".repeat(32));
    assert_eq!(request("DELETE", &wrong, &[], b"").await.status, 404);
    assert_eq!(request("GET", &get_url, &[], b"").await.status, 200);
    assert_eq!(request("DELETE", &del_url, &[], b"").await.status, 204);
    assert_eq!(request("GET", &get_url, &[], b"").await.status, 404);
    assert_eq!(request("DELETE", &del_url, &[], b"").await.status, 404);
    server.stop().await;
}

/// Stores `bytes` as a blob over HTTPS, and returns the URL to get it.
async fn store_blob(anon: &mut TestClient, bytes: &[u8]) -> String {
    let hash = BlobRef::of(bytes);
    let blob = format!("BLOB {hash} {} box={BOX} token={}", bytes.len(), token());
    let url = value(&command(anon, &blob).await, "put");
    let r = put(&url, bytes).await;
    assert_eq!(r.status, 201, "{}", r.head);
    let base = url.split("/blob/").next().unwrap();
    format!("{base}/blobs/{}", hash.hex())
}

/// An upload that keeps below `files.min_rate` over `files.min_rate_secs`
/// is cut off, well before its overall deadline; one that keeps up is
/// not (10.6, 12.12, PLAN item 63).
#[tokio::test]
async fn slow_uploads_are_cut_off() {
    let server = server_with(|c| {
        c.files.min_rate = 64 * 1024;
        c.files.min_rate_secs = 1;
    })
    .await;
    let mut anon = server.anon().await;
    let bytes = vec![7u8; 1024 * 1024];
    let hash = BlobRef::of(&bytes);
    let blob = format!("BLOB {hash} {} box={BOX} token={}", bytes.len(), token());
    let url = value(&command(&mut anon, &blob).await, "put");
    // 1 KiB every 100 ms: 10 KiB a second.
    let (addr, path) = target(&url);
    let stream = tls(TcpStream::connect(addr).await.unwrap()).await;
    let (mut rx, mut tx) = tokio::io::split(stream);
    let head = format!(
        "PUT {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
        bytes.len()
    );
    tx.write_all(head.as_bytes()).await.unwrap();
    let trickle = tokio::spawn(async move {
        for _ in 0..200 {
            if tx.write_all(&[7u8; 1024]).await.is_err() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    });
    let started = std::time::Instant::now();
    let mut answer = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        rx.read_to_end(&mut answer),
    )
    .await
    .expect("cut off within 10 seconds")
    .ok();
    let answer = String::from_utf8_lossy(&answer);
    assert!(answer.starts_with("HTTP/1.1 408"), "{answer}");
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    trickle.abort();
    // At full speed it is taken.
    let url = value(&command(&mut anon, &blob).await, "put");
    assert_eq!(put(&url, &bytes).await.status, 201);
    server.stop().await;
}

/// A download that keeps below `files.min_rate` is cut off, and its
/// transfer slot freed; while every transfer slot is taken, blob and file
/// requests get 503 but key files are still served; a reader that keeps
/// up gets the whole blob (10.6, 12.12, PLAN item 63).
#[tokio::test]
async fn slow_downloads_are_cut_off_and_free_their_slot() {
    let server = server_with(|c| {
        c.files.min_rate = 1024 * 1024;
        c.files.min_rate_secs = 1;
        c.files.max_transfers = 1;
    })
    .await;
    let mut anon = server.anon().await;
    // More than the socket buffers on both sides hold.
    let big: Vec<u8> = (0..24 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
    let big_url = store_blob(&mut anon, &big).await;
    let small_url = store_blob(&mut anon, b"a small blob").await;
    // A reader that keeps up.
    let r = request("GET", &big_url, &[], b"").await;
    assert_eq!(r.status, 200);
    assert!(r.body == big, "{} bytes", r.body.len());

    // A reader that reads nothing, with a small receive buffer.
    let (addr, path) = target(&big_url);
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.set_recv_buffer_size(8 * 1024).unwrap();
    let mut slow = tls(socket.connect(addr).await.unwrap()).await;
    slow.write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
        .await
        .unwrap();
    slow.flush().await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    // It holds the one transfer slot: other blobs get 503, key files do
    // not.
    assert_eq!(request("GET", &small_url, &[], b"").await.status, 503);
    let base = small_url.split("/blobs/").next().unwrap();
    let key_file = format!("{base}/.well-known/risala/nobody");
    assert_eq!(request("GET", &key_file, &[], b"").await.status, 404);
    // Within a few seconds it is cut off, and the slot is free again.
    let started = std::time::Instant::now();
    loop {
        let r = request("GET", &small_url, &[], b"").await;
        if r.status == 200 {
            assert_eq!(r.body, b"a small blob");
            break;
        }
        assert_eq!(r.status, 503);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "the slow reader still holds its slot"
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    drop(slow);
    server.stop().await;
}

/// The `put` URL BLOB gives for a small blob, without opening an HTTPS
/// connection.
async fn put_url(server: &TestServer) -> String {
    let mut anon = server.anon().await;
    let hash = BlobRef::of(b"a blob");
    let blob = format!("BLOB {hash} 6 box={BOX} token={}", token());
    value(&command(&mut anon, &blob).await, "put")
}

/// `limits.https_connections_per_address` caps the HTTPS connections one
/// address may hold open: past it, a new one is closed at once, and once
/// one goes another may come (PLAN item 67).
#[tokio::test]
async fn https_connections_per_address_is_configured() {
    /// Whether the server closed `tcp` at once, rather than waiting for
    /// its handshake.
    async fn closed_at_once(tcp: &mut TcpStream) -> bool {
        let mut byte = [0u8; 1];
        let read =
            tokio::time::timeout(std::time::Duration::from_millis(300), tcp.read(&mut byte)).await;
        matches!(read, Ok(Ok(0) | Err(_)))
    }

    let capped = server_with(|c| c.limits.https_connections_per_address = 2).await;
    let (addr, _) = target(&put_url(&capped).await);
    let mut idle = vec![
        TcpStream::connect(addr).await.unwrap(),
        TcpStream::connect(addr).await.unwrap(),
    ];
    let mut extra = TcpStream::connect(addr).await.unwrap();
    assert!(closed_at_once(&mut extra).await);
    for tcp in &mut idle {
        assert!(!closed_at_once(tcp).await);
    }
    drop(idle.pop());
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let mut next = TcpStream::connect(addr).await.unwrap();
    assert!(!closed_at_once(&mut next).await);
    drop((idle, next));
    capped.stop().await;

    // The default allows more than two.
    let server = server().await;
    let (addr, _) = target(&put_url(&server).await);
    let mut idle = Vec::new();
    for _ in 0..3 {
        idle.push(TcpStream::connect(addr).await.unwrap());
    }
    for tcp in &mut idle {
        assert!(!closed_at_once(tcp).await);
    }
    drop(idle);
    server.stop().await;
}
