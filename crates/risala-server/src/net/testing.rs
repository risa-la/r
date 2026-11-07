//! A line-level TLS client for tests, here and in other crates.
//!
//! **For tests only.** [`TestClient`] accepts any server certificate. It
//! still checks the handshake signature, so the fingerprint it reports
//! belongs to a key the server holds, but it trusts nothing about who the
//! server is. Never use it to talk to a server you do not control.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use risala_proto::fingerprint::Fingerprint;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use super::tls::{provider, spki_fingerprint};

/// How long [`TestClient::recv`] waits for a line before failing, so a
/// broken test fails instead of hanging.
pub const RECV_TIMEOUT: Duration = Duration::from_secs(10);

/// How a [`TestClient`] connects.
#[derive(Debug, Clone)]
pub struct ClientOptions {
    /// The SNI name to send (2.1). `None` sends none, as when connecting
    /// to a bare IP address.
    pub sni: Option<String>,
    /// Whether to offer the ALPN `risala/1` (2.1).
    pub alpn: bool,
}

impl Default for ClientOptions {
    fn default() -> Self {
        ClientOptions {
            sni: None,
            alpn: true,
        }
    }
}

impl ClientOptions {
    /// Default options with this SNI name.
    pub fn sni(name: &str) -> ClientOptions {
        ClientOptions {
            sni: Some(name.to_owned()),
            ..ClientOptions::default()
        }
    }
}

/// A TLS client that sends and receives raw lines.
#[derive(Debug)]
pub struct TestClient {
    reader: BufReader<ReadHalf<TlsStream<TcpStream>>>,
    writer: WriteHalf<TlsStream<TcpStream>>,
    fingerprint: Fingerprint,
    alpn: Option<Vec<u8>>,
}

impl TestClient {
    /// Connects to `addr` with the [default options](ClientOptions): no
    /// SNI, ALPN offered.
    pub async fn connect(addr: SocketAddr) -> io::Result<TestClient> {
        TestClient::connect_with(addr, ClientOptions::default()).await
    }

    /// Connects to `addr` with the given options.
    pub async fn connect_with(addr: SocketAddr, options: ClientOptions) -> io::Result<TestClient> {
        let provider = provider();
        let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(io::Error::other)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAny(provider)))
            .with_no_client_auth();
        if options.alpn {
            config.alpn_protocols = vec![risala_proto::ALPN.to_vec()];
        }
        let name = match &options.sni {
            Some(sni) => ServerName::try_from(sni.clone())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
            None => ServerName::IpAddress(addr.ip().into()),
        };
        let tcp = TcpStream::connect(addr).await?;
        let tls = TlsConnector::from(Arc::new(config))
            .connect(name, tcp)
            .await?;
        let session = tls.get_ref().1;
        let leaf = session
            .peer_certificates()
            .and_then(|chain| chain.first())
            .ok_or_else(|| io::Error::other("the server sent no certificate"))?;
        let fingerprint = spki_fingerprint(leaf).map_err(io::Error::other)?;
        let alpn = session.alpn_protocol().map(<[u8]>::to_vec);
        let (rd, writer) = tokio::io::split(tls);
        Ok(TestClient {
            reader: BufReader::new(rd),
            writer,
            fingerprint,
            alpn,
        })
    }

    /// The fingerprint of the server's certificate (2.2).
    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    /// The ALPN protocol the server chose, if any (2.1).
    pub fn alpn(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }

    /// Sends one line, adding the LF.
    pub async fn send(&mut self, line: &str) -> io::Result<()> {
        let mut bytes = Vec::with_capacity(line.len() + 1);
        bytes.extend_from_slice(line.as_bytes());
        bytes.push(b'\n');
        self.send_raw(&bytes).await
    }

    /// Sends bytes as they are, with no LF added.
    pub async fn send_raw(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.writer.write_all(bytes).await?;
        self.writer.flush().await
    }

    /// Receives the next line, without its LF, or `None` at the end of the
    /// stream. Fails if no line comes within [`RECV_TIMEOUT`], or if the
    /// line is not UTF-8.
    pub async fn recv(&mut self) -> io::Result<Option<String>> {
        let mut line = Vec::new();
        let n = tokio::time::timeout(RECV_TIMEOUT, self.reader.read_until(b'\n', &mut line))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no line from the server"))??;
        if n == 0 {
            return Ok(None);
        }
        if line.pop() != Some(b'\n') {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the stream ended inside a line",
            ));
        }
        String::from_utf8(line)
            .map(Some)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Receives the next line and fails if the stream ended instead.
    pub async fn expect_line(&mut self) -> io::Result<String> {
        self.recv()
            .await?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "the server closed"))
    }

    /// Reads until the server closes, and returns the lines it sent first.
    pub async fn recv_until_closed(&mut self) -> io::Result<Vec<String>> {
        let mut lines = Vec::new();
        loop {
            match self.recv().await {
                Ok(Some(line)) => lines.push(line),
                Ok(None) => return Ok(lines),
                // A peer that closes without close_notify is still closed.
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(lines),
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => return Ok(lines),
                Err(e) => return Err(e),
            }
        }
    }

    /// Closes the connection, sending TLS close_notify.
    pub async fn close(mut self) -> io::Result<()> {
        self.writer.shutdown().await
    }
}

/// Accepts any certificate, but checks handshake signatures.
#[derive(Debug)]
struct AcceptAny(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
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
