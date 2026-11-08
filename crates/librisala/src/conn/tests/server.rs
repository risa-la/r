//! A TLS server that plays scripted transcripts, and test certificates.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use rcgen::{
    BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose, PublicKeyData,
};
use risala_proto::fingerprint::Fingerprint;
use rustls::NamedGroup;
use rustls::crypto::CryptoProvider;
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
    /// The key exchange group of the handshake.
    pub kx_group: Option<NamedGroup>,
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
///
/// It keeps listening after those, and counts any further connection as a
/// failure, so a client that reconnects when the script did not expect it
/// fails the test with "unexpected connection #n" rather than with a
/// refused connection. [`done`](Self::done) reports the failures, a
/// script's panic first, since it is most often the cause of the rest; if
/// the test panics before calling it, on the thread that started the
/// server, they are printed before the test's own panic message.
pub struct ScriptServer {
    pub addr: SocketAddr,
    accept: JoinHandle<()>,
    /// How many connections were accepted so far.
    accepted: tokio::sync::watch::Receiver<usize>,
    conns: usize,
    state: Arc<Mutex<State>>,
}

/// What the scripts and the accept loop left for [`ScriptServer::done`].
#[derive(Default)]
struct State {
    scripts: Vec<JoinHandle<()>>,
    /// The scripts that panicked, by connection, with their messages.
    panics: Vec<(usize, String)>,
    /// Connections past the scripted ones, and accept errors.
    failures: Vec<String>,
    /// What else happened, shown with the failures: failed handshakes.
    notes: Vec<String>,
}

/// The message of a panic payload.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_owned()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "(a panic without a message)".to_owned()
    }
}

impl ScriptServer {
    /// Starts a server presenting `cert`. `script` gets the index of the
    /// connection (from 0) and its peer. Connections whose handshake
    /// fails, as when the client refuses the certificate, run no script
    /// but still count.
    ///
    /// The server offers every key exchange group of aws-lc-rs, as a
    /// typical TLS server does, X25519MLKEM768 among them.
    pub async fn start<F, Fut>(cert: ServerCert, conns: usize, script: F) -> ScriptServer
    where
        F: Fn(usize, Peer) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        ScriptServer::start_with(provider, cert, conns, script).await
    }

    /// Like [`start`](Self::start), but the server knows only the classic
    /// key exchange X25519, as one without post-quantum support (2.1).
    pub async fn start_classic<F, Fut>(cert: ServerCert, conns: usize, script: F) -> ScriptServer
    where
        F: Fn(usize, Peer) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let provider = CryptoProvider {
            kx_groups: vec![rustls::crypto::aws_lc_rs::kx_group::X25519],
            ..rustls::crypto::aws_lc_rs::default_provider()
        };
        ScriptServer::start_with(provider, cert, conns, script).await
    }

    async fn start_with<F, Fut>(
        provider: CryptoProvider,
        cert: ServerCert,
        conns: usize,
        script: F,
    ) -> ScriptServer
    where
        F: Fn(usize, Peer) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let provider = Arc::new(provider);
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
        let state = Arc::new(Mutex::new(State::default()));
        register(&state);
        let (count, accepted) = tokio::sync::watch::channel(0);
        let script = Arc::new(script);
        let accept = {
            let state = state.clone();
            tokio::spawn(async move {
                let mut i = 0;
                loop {
                    let tcp = match listener.accept().await {
                        Ok((tcp, _)) => tcp,
                        Err(e) => {
                            // Such as running out of file descriptors: the
                            // client's connection fails, and so the test.
                            state
                                .lock()
                                .unwrap()
                                .failures
                                .push(format!("accept failed: {e}"));
                            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                            continue;
                        }
                    };
                    let n = i;
                    i += 1;
                    if n >= conns {
                        state.lock().unwrap().failures.push(format!(
                            "unexpected connection #{i}: the script expects {conns}"
                        ));
                        drop(tcp);
                        count.send_replace(i);
                        continue;
                    }
                    count.send_replace(i);
                    let tls = match acceptor.accept(tcp).await {
                        Ok(tls) => tls,
                        Err(e) => {
                            // Expected when the client refuses the
                            // certificate, so only a note for the failures.
                            state
                                .lock()
                                .unwrap()
                                .notes
                                .push(format!("connection #{i}: the handshake failed: {e}"));
                            continue;
                        }
                    };
                    let (_, conn) = tls.get_ref();
                    let peer = Peer {
                        sni: conn.server_name().map(str::to_owned),
                        alpn: conn.alpn_protocol().map(<[u8]>::to_vec),
                        kx_group: conn.negotiated_key_exchange_group().map(|g| g.name()),
                        stream: BufReader::new(tls),
                    };
                    let run = tokio::spawn(script(n, peer));
                    let watch = {
                        let state = state.clone();
                        tokio::spawn(async move {
                            if let Err(e) = run.await
                                && e.is_panic()
                            {
                                let message = panic_message(&*e.into_panic());
                                state.lock().unwrap().panics.push((n, message));
                            }
                        })
                    };
                    state.lock().unwrap().scripts.push(watch);
                }
            })
        };
        ScriptServer {
            addr,
            accept,
            accepted,
            conns,
            state,
        }
    }

    /// Waits for every scripted connection and script, failing the test
    /// if a script failed or the client connected more often than the
    /// script expects.
    pub async fn done(mut self) {
        let conns = self.conns;
        self.accepted
            .wait_for(|n| *n >= conns)
            .await
            .expect("the accept loop ended");
        let scripts: Vec<_> = self.state.lock().unwrap().scripts.drain(..).collect();
        for s in scripts {
            s.await.unwrap();
        }
        let failures = self.failures();
        self.accept.abort();
        unregister(&self.state);
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    /// The failures so far, the scripts' panics first.
    fn failures(&self) -> Vec<String> {
        failures_of(&self.state.lock().unwrap())
    }
}

/// The failures in `state`, the scripts' panics first, then with the
/// notes if there are any.
fn failures_of(state: &State) -> Vec<String> {
    let mut panics = state.panics.clone();
    panics.sort();
    let mut failures: Vec<String> = panics
        .into_iter()
        .map(|(n, m)| format!("the script of connection #{} panicked: {m}", n + 1))
        .chain(state.failures.iter().cloned())
        .collect();
    if !failures.is_empty() {
        failures.extend(state.notes.iter().cloned());
    }
    failures
}

thread_local! {
    /// The servers a test started on this thread, for the panic hook.
    static SERVERS: std::cell::RefCell<Vec<std::sync::Weak<Mutex<State>>>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Registers a server started on this thread, so that if the test fails
/// here before [`ScriptServer::done`], the failures the server saw are
/// printed before the test's own panic: a script that panicked is most
/// often why the client then failed.
fn register(state: &Arc<Mutex<State>>) {
    static HOOK: std::sync::Once = std::sync::Once::new();
    HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let failures: Vec<String> = SERVERS
                .try_with(|servers| {
                    servers
                        .try_borrow()
                        .map(|servers| {
                            servers
                                .iter()
                                .filter_map(std::sync::Weak::upgrade)
                                .filter_map(|s| s.try_lock().ok().map(|s| failures_of(&s)))
                                .flatten()
                                .collect()
                        })
                        .unwrap_or_default()
                })
                .unwrap_or_default();
            if !failures.is_empty() {
                eprintln!(
                    "the script server failed first, which may be the cause:\n{}\n",
                    failures.join("\n")
                );
            }
            previous(info);
        }));
    });
    SERVERS.with(|s| {
        let mut s = s.borrow_mut();
        s.retain(|w| w.strong_count() > 0);
        s.push(Arc::downgrade(state));
    });
}

/// Forgets a server [`register`]ed on this thread.
fn unregister(state: &Arc<Mutex<State>>) {
    let _ = SERVERS.try_with(|s| {
        if let Ok(mut s) = s.try_borrow_mut() {
            s.retain(|w| w.strong_count() > 0 && !std::ptr::eq(w.as_ptr(), Arc::as_ptr(state)));
        }
    });
}

impl Drop for ScriptServer {
    fn drop(&mut self) {
        self.accept.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::tests::{connect, store};

    #[tokio::test]
    #[should_panic(expected = "unexpected connection #2: the script expects 1")]
    async fn a_connection_past_the_script_fails_the_test() {
        let ca = TestCa::new();
        let server = ScriptServer::start(ca.issue("chat.test"), 1, |_, peer: Peer| async move {
            peer.close().await;
        })
        .await;
        // Neither does TLS: the first still counts.
        for _ in 0..2 {
            drop(TcpStream::connect(server.addr).await.unwrap());
        }
        let mut accepted = server.accepted.clone();
        accepted.wait_for(|n| *n >= 2).await.unwrap();
        server.done().await;
    }

    #[tokio::test]
    async fn a_script_panic_is_reported_before_what_followed() {
        let ca = TestCa::new();
        let server = ScriptServer::start(ca.issue("chat.test"), 1, |_, _: Peer| async move {
            panic!("boom");
        })
        .await;
        assert!(connect(&ca, &server, &store()).await.is_err());
        drop(TcpStream::connect(server.addr).await.unwrap());
        let mut accepted = server.accepted.clone();
        accepted.wait_for(|n| *n >= 2).await.unwrap();
        let err = tokio::spawn(server.done()).await.unwrap_err();
        let message = panic_message(&*err.into_panic());
        assert_eq!(
            message,
            "the script of connection #1 panicked: boom\n\
             unexpected connection #2: the script expects 1"
        );
    }
}
