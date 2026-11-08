//! Pushes over real HTTPS (9.3): the server's pusher POSTs to a local
//! HTTPS endpoint, which checks the headers and decrypts the RFC 8291
//! body.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use aws_lc_rs::agreement;
use risala_proto::binary::{PushAuth, PushKey};
use risala_proto::server::Notify;
use risala_proto::types::{NotifyReason, PushReason};
use risala_server::config::PushConfig;
use risala_server::push::{self, HttpsPusher, PushRequest, PushTransport as _, SendError};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;

/// One request the endpoint received: its head and its body.
struct Received {
    head: String,
    body: Vec<u8>,
}

impl Received {
    fn header(&self, name: &str) -> Option<&str> {
        self.head.lines().skip(1).find_map(|line| {
            let (n, v) = line.split_once(':')?;
            n.eq_ignore_ascii_case(name).then(|| v.trim())
        })
    }
}

/// A push endpoint on 127.0.0.1 with a self-signed certificate, answering
/// every request with `status`.
struct Endpoint {
    addr: SocketAddr,
    cert: CertificateDer<'static>,
    pem: String,
    received: mpsc::UnboundedReceiver<Received>,
}

impl Endpoint {
    async fn start(status: u16) -> Endpoint {
        let issued = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).unwrap();
        let cert = issued.cert.der().clone();
        let pem = issued.cert.pem();
        let key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(issued.signing_key.serialize_der()));
        let config = rustls::ServerConfig::builder_with_provider(risala_keyfetch::provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, received) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let tx = tx.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut buf = Vec::new();
                    let head_end = loop {
                        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break i + 4;
                        }
                        let mut chunk = [0u8; 1024];
                        match tls.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    };
                    let head = String::from_utf8(buf[..head_end].to_vec()).unwrap();
                    let mut got = Received {
                        head,
                        body: buf[head_end..].to_vec(),
                    };
                    let len: usize = got
                        .header("content-length")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                    while got.body.len() < len {
                        let mut chunk = [0u8; 1024];
                        match tls.read(&mut chunk).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => got.body.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let _ = tx.send(got);
                    let reply = format!(
                        "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 {status} Whatever\r\n\
                         Location: https://127.0.0.1:1/elsewhere\r\nContent-Length: 0\r\n\r\n"
                    );
                    let _ = tls.write_all(reply.as_bytes()).await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        Endpoint {
            addr,
            cert,
            pem,
            received,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("https://{}{path}", self.addr)
    }

    async fn next(&mut self) -> Received {
        tokio::time::timeout(Duration::from_secs(5), self.received.recv())
            .await
            .expect("a request in time")
            .expect("a request")
    }
}

/// A subscription's keys, as a device makes them (9.1).
fn device_keys() -> (agreement::PrivateKey, PushKey, PushAuth) {
    let private = agreement::PrivateKey::generate(&agreement::ECDH_P256).unwrap();
    let public: [u8; 65] = private
        .compute_public_key()
        .unwrap()
        .as_ref()
        .try_into()
        .unwrap();
    (
        private,
        PushKey::from_bytes(public),
        PushAuth::from_bytes([0x5a; 16]),
    )
}

fn request(url: &str, reason: PushReason, key: &PushKey, auth: &PushAuth) -> PushRequest {
    let notify = Notify {
        tag: "x7Hq2".parse().unwrap(),
        reason: NotifyReason::Known(reason),
    };
    PushRequest {
        url: url.parse().unwrap(),
        body: push::encrypt(&notify, key, auth).unwrap(),
        urgency: notify.urgency(),
    }
}

#[tokio::test]
async fn a_push_reaches_the_endpoint_and_decrypts() {
    let mut endpoint = Endpoint::start(201).await;
    let pusher = HttpsPusher::new(vec![endpoint.cert.clone()], true);
    let (private, key, auth) = device_keys();
    for (reason, urgency, line) in [
        (PushReason::Welcome, "high", "NOTIFY x7Hq2 welcome\n"),
        (PushReason::Message, "normal", "NOTIFY x7Hq2 message\n"),
    ] {
        let push = request(&endpoint.url("/n/3f9c?x=1"), reason, &key, &auth);
        assert_eq!(pusher.send(&push).await, Ok(201));
        let got = endpoint.next().await;
        assert!(
            got.head.starts_with("POST /n/3f9c?x=1 HTTP/1.1\r\n"),
            "{}",
            got.head
        );
        assert_eq!(got.header("host"), Some(endpoint.addr.to_string().as_str()));
        assert_eq!(got.header("content-encoding"), Some("aes128gcm"));
        assert_eq!(got.header("ttl"), Some("86400"));
        assert_eq!(got.header("urgency"), Some(urgency));
        // Every body has the same size, padded to 128 bytes (9.3).
        assert_eq!(got.body.len(), push::BODY_LEN);
        let plain = push::decrypt(&got.body, &private, auth.as_bytes()).unwrap();
        assert_eq!(String::from_utf8(plain).unwrap(), line);
    }
}

#[tokio::test]
async fn redirects_are_not_followed_and_statuses_come_back() {
    let mut endpoint = Endpoint::start(301).await;
    let pusher = HttpsPusher::new(vec![endpoint.cert.clone()], true);
    let (_, key, auth) = device_keys();
    let push = request(&endpoint.url("/a"), PushReason::Message, &key, &auth);
    assert_eq!(pusher.send(&push).await, Ok(301));
    endpoint.next().await;
    assert!(endpoint.received.try_recv().is_err());
}

#[tokio::test]
async fn special_addresses_and_unknown_certificates_are_refused() {
    let mut endpoint = Endpoint::start(201).await;
    let (_, key, auth) = device_keys();
    let push = request(&endpoint.url("/a"), PushReason::Message, &key, &auth);
    // Loopback is refused unless the operator allows it (9.3, 4.4).
    let guarded = HttpsPusher::new(vec![endpoint.cert.clone()], false);
    assert_eq!(guarded.send(&push).await, Err(SendError::Refused));
    // A certificate no trusted CA issued fails (9.3).
    let untrusting = HttpsPusher::new(Vec::new(), true);
    assert!(matches!(
        untrusting.send(&push).await,
        Err(SendError::Io(_))
    ));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(endpoint.received.try_recv().is_err());
}

#[tokio::test]
async fn the_configuration_names_extra_roots() {
    let mut endpoint = Endpoint::start(204).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("push-ca.pem");
    std::fs::write(&path, &endpoint.pem).unwrap();
    let config = PushConfig {
        allow_private: true,
        extra_roots: vec![path],
        ..PushConfig::default()
    };
    let pusher = HttpsPusher::from_config(&config).unwrap();
    let (_, key, auth) = device_keys();
    let push = request(&endpoint.url("/"), PushReason::Message, &key, &auth);
    assert_eq!(pusher.send(&push).await, Ok(204));
    endpoint.next().await;
    // A file with no certificate is an error.
    let empty = dir.path().join("empty.pem");
    std::fs::write(&empty, "").unwrap();
    let bad = PushConfig {
        extra_roots: vec![empty],
        ..PushConfig::default()
    };
    assert!(HttpsPusher::from_config(&bad).is_err());
}
