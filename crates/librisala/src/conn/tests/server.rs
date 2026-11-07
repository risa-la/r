//! A TLS server that plays scripted transcripts, and test certificates.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use rcgen::{
    BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose, PublicKeyData,
};
use risala_proto::fingerprint::Fingerprint;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::{CertifiedKey, SigningKey};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::server::TlsStream;

/// A certificate with the key the server signs the handshake with.
#[derive(Clone)]
pub struct ServerCert {
    pub chain: Vec<CertificateDer<'static>>,
    pub key: Arc<dyn SigningKey>,
    /// The fingerprint of the certificate's public key, computed by rcgen
    /// rather than by the code under test.
    pub fingerprint: Fingerprint,
}

impl std::fmt::Debug for ServerCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ServerCert({})", self.fingerprint)
    }
}

fn signing_key(key: &KeyPair) -> Arc<dyn SigningKey> {
    let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    rustls::crypto::aws_lc_rs::sign::any_supported_type(&der).unwrap()
}

fn fingerprint(key: &KeyPair) -> Fingerprint {
    Fingerprint::from_spki_der(&key.subject_public_key_info())
}

impl ServerCert {
    /// A self-signed certificate for `host`.
    pub fn self_signed(host: &str) -> ServerCert {
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec![host.to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        ServerCert {
            chain: vec![cert.der().clone()],
            key: signing_key(&key),
            fingerprint: fingerprint(&key),
        }
    }

    /// The same certificate, but the server signs the handshake with
    /// another key, as someone who copied a certificate would.
    pub fn with_wrong_key(mut self) -> ServerCert {
        self.key = signing_key(&KeyPair::generate().unwrap());
        self
    }
}

/// A test root CA standing in for the platform's trust store.
pub struct TestCa {
    issuer: Issuer<'static, KeyPair>,
    pub cert: CertificateDer<'static>,
}

impl TestCa {
    pub fn new() -> TestCa {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        TestCa {
            issuer: Issuer::new(params, key),
            cert: cert.der().clone(),
        }
    }

    /// A certificate for `host` issued by this CA, with a new key.
    pub fn issue(&self, host: &str) -> ServerCert {
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec![host.to_owned()])
            .unwrap()
            .signed_by(&key, &self.issuer)
            .unwrap();
        ServerCert {
            chain: vec![cert.der().clone()],
            key: signing_key(&key),
            fingerprint: fingerprint(&key),
        }
    }
}

#[derive(Debug)]
struct Fixed(Arc<CertifiedKey>);

impl ResolvesServerCert for Fixed {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// The server's side of one connection.
pub struct Peer {
    stream: BufReader<TlsStream<TcpStream>>,
    /// The SNI the client sent.
    pub sni: Option<String>,
    /// The ALPN protocol negotiated.
    pub alpn: Option<Vec<u8>>,
}

impl Peer {
    /// Sends one line; LF is added.
    pub async fn send(&mut self, line: &str) {
        let s = self.stream.get_mut();
        s.write_all(format!("{line}\n").as_bytes()).await.unwrap();
        s.flush().await.unwrap();
    }

    /// Sends the greeting with this nonce and host.
    pub async fn greet(&mut self) {
        self.send("RISALA 1 chat.test 6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e welcome")
            .await;
    }

    /// The next line from the client, without its LF, or `None` at the
    /// end of the stream.
    pub async fn recv(&mut self) -> Option<String> {
        let mut line = String::new();
        match self.stream.read_line(&mut line).await {
            Ok(0) | Err(_) => None,
            Ok(_) => Some(line.trim_end_matches('\n').to_owned()),
        }
    }

    /// Reads the next line and checks it.
    pub async fn expect(&mut self, expected: &str) {
        assert_eq!(self.recv().await.as_deref(), Some(expected));
    }

    /// Waits for the client to close the connection.
    pub async fn expect_eof(&mut self) {
        assert_eq!(self.recv().await, None);
    }

    /// Closes the connection with `close_notify`.
    pub async fn close(mut self) {
        let _ = self.stream.get_mut().shutdown().await;
    }
}

/// A server on 127.0.0.1 and a random port that runs a script on each of
/// the first `conns` connections.
pub struct ScriptServer {
    pub addr: SocketAddr,
    accept: JoinHandle<()>,
    scripts: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl ScriptServer {
    /// Starts a server presenting `cert`. `script` gets the index of the
    /// connection (from 0) and its peer. Connections whose handshake
    /// fails, as when the client refuses the certificate, run no script
    /// but still count.
    pub async fn start<F, Fut>(cert: ServerCert, conns: usize, script: F) -> ScriptServer
    where
        F: Fn(usize, Peer) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Fixed(Arc::new(CertifiedKey::new(
                cert.chain, cert.key,
            )))));
        config.alpn_protocols = vec![risala_proto::ALPN.to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let scripts = Arc::new(Mutex::new(Vec::new()));
        let script = Arc::new(script);
        let accept = {
            let scripts = scripts.clone();
            tokio::spawn(async move {
                for i in 0..conns {
                    let (tcp, _) = listener.accept().await.unwrap();
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        continue;
                    };
                    let (_, conn) = tls.get_ref();
                    let peer = Peer {
                        sni: conn.server_name().map(str::to_owned),
                        alpn: conn.alpn_protocol().map(<[u8]>::to_vec),
                        stream: BufReader::new(tls),
                    };
                    let script = script.clone();
                    let handle = tokio::spawn(async move { script(i, peer).await });
                    scripts.lock().unwrap().push(handle);
                }
            })
        };
        ScriptServer {
            addr,
            accept,
            scripts,
        }
    }

    /// Waits for every connection and script, failing the test if a
    /// script failed.
    pub async fn done(self) {
        self.accept.await.unwrap();
        let scripts: Vec<_> = self.scripts.lock().unwrap().drain(..).collect();
        for s in scripts {
            if let Err(e) = s.await
                && e.is_panic()
            {
                std::panic::resume_unwind(e.into_panic());
            }
        }
    }
}
