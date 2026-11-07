//! TLS 1.3 with the server checks of 2.1 and 2.2.
//!
//! [`TrustVerifier`] decides whether to accept a server's certificate:
//!
//! 1. A certificate that the CA verifier accepts for the hostname is
//!    accepted, and "CA" is recorded, replacing any pin. It is never
//!    compared against a pin.
//! 2. Any other certificate is handled by trust on first use, by the
//!    fingerprint of its SubjectPublicKeyInfo:
//!    - no record: refused with [`TrustError::Unknown`], so the app can
//!      ask the user;
//!    - a matching pin: accepted;
//!    - a different pin, or "CA": refused with [`TrustError::Mismatch`].
//!
//! Handshake signatures are verified in every case, against the key in
//! the certificate the server showed. A new record is written only after
//! the handshake has finished, so a server that shows someone else's
//! CA-valid certificate without holding its key cannot replace a pin.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use risala_proto::fingerprint::Fingerprint;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{Resumption, WebPkiServerVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use super::error::{Error, TrustError};
use crate::addr::{ServerAddr, TrustRecord, TrustStore, TrustStoreError};

/// The check for rule 1 of 2.2: whether a certificate is CA-valid for the
/// hostname. Any [`ServerCertVerifier`] will do. Only its
/// `verify_server_cert` is used; signatures are checked separately.
pub type CaVerifier = Arc<dyn ServerCertVerifier>;

/// The crypto provider librisala uses: rustls with ring.
pub fn crypto_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The platform's CA check, through `rustls-platform-verifier`: the OS
/// trust store on each platform (PLAN.md 3.3). This is the default.
///
/// Making one loads the trust store, so reuse it across connections
/// (put it in [`SessionOptions::ca_verifier`](super::SessionOptions)).
///
/// If the platform's check cannot be made, for example because the system
/// has no CA certificates at all, this logs a warning and returns
/// [`no_ca_verifier`]: no certificate is CA-valid then, and every server
/// goes through trust on first use (2.2, rule 2).
pub fn platform_ca_verifier() -> CaVerifier {
    match rustls_platform_verifier::Verifier::new(crypto_provider()) {
        Ok(v) => Arc::new(v),
        Err(e) => {
            tracing::warn!(error = %e, "no CA check available; using trust on first use only");
            no_ca_verifier()
        }
    }
}

/// A CA check that finds no certificate CA-valid, so that every server
/// goes through trust on first use (2.2, rule 2).
pub fn no_ca_verifier() -> CaVerifier {
    Arc::new(NoCaVerifier(
        crypto_provider().signature_verification_algorithms,
    ))
}

/// See [`no_ca_verifier`].
#[derive(Debug)]
struct NoCaVerifier(WebPkiSupportedAlgorithms);

impl ServerCertVerifier for NoCaVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Err(rustls::Error::General(
            "no certificate authorities to check against".into(),
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_schemes()
    }
}

/// A CA check that trusts only the given roots, for tests and private
/// CAs.
pub fn roots_ca_verifier(
    roots: impl IntoIterator<Item = CertificateDer<'static>>,
) -> Result<CaVerifier, Error> {
    let mut store = RootCertStore::empty();
    for root in roots {
        store.add(root).map_err(Error::Tls)?;
    }
    let v = WebPkiServerVerifier::builder_with_provider(Arc::new(store), crypto_provider())
        .build()
        .map_err(|e| Error::Tls(rustls::Error::General(e.to_string())))?;
    Ok(v)
}

/// The fingerprint of a certificate: SHA-256 over its DER-encoded
/// SubjectPublicKeyInfo (2.2). It matches what Appendix A's openssl
/// pipeline prints.
pub fn certificate_fingerprint(cert: &CertificateDer<'_>) -> Result<Fingerprint, TrustError> {
    let ee = webpki::EndEntityCert::try_from(cert)
        .map_err(|e| TrustError::BadCertificate(e.to_string()))?;
    Ok(Fingerprint::from_spki_der(
        ee.subject_public_key_info().as_ref(),
    ))
}

/// Records the fingerprint the user accepted for a server that had no
/// record (2.2), after a [`TrustError::Unknown`].
///
/// It refuses to replace a record that differs: after a mismatch the user
/// must delete the record explicitly, with
/// [`TrustStore::forget`](crate::addr::TrustStore::forget), first. Doing
/// it again with the same fingerprint is fine.
///
/// The trust store may block (SQLite), so call this off the async
/// runtime's worker threads, or through `spawn_blocking`.
pub fn accept_fingerprint(
    trust: &dyn TrustStore,
    addr: &ServerAddr,
    fingerprint: Fingerprint,
) -> Result<(), Error> {
    match trust.get(addr)? {
        None => Ok(trust.set(addr, TrustRecord::Pinned(fingerprint))?),
        Some(TrustRecord::Pinned(fp)) if fp == fingerprint => Ok(()),
        Some(recorded) => Err(TrustError::Mismatch {
            recorded,
            presented: fingerprint,
            ca_error: "a different record exists".into(),
        }
        .into()),
    }
}

/// How a server's certificate was accepted (2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The fingerprint of the certificate's public key. Known even for a
    /// CA-valid certificate, for display.
    pub fingerprint: Fingerprint,
    /// The record that now applies: `Ca`, or `Pinned` with a pin that
    /// matched.
    pub record: TrustRecord,
    /// Whether `record` is new and must be stored once the handshake has
    /// finished.
    pub changed: bool,
}

/// The [`ServerCertVerifier`] of 2.2, for one connection to one server.
///
/// Make one per connection with the record read beforehand (the trust
/// store may block, so it is not read inside the handshake). After the
/// handshake, [`outcome`](Self::outcome) says what was decided. Nothing is
/// written to the trust store here; [`Session`](super::Session) does that
/// once the handshake has succeeded.
#[derive(Debug)]
pub struct TrustVerifier {
    record: Option<TrustRecord>,
    ca: CaVerifier,
    algorithms: WebPkiSupportedAlgorithms,
    outcome: Mutex<Option<Result<Verified, TrustError>>>,
}

impl TrustVerifier {
    /// A verifier for a server with this record (`None`: nothing yet),
    /// using `ca` for rule 1 and `provider` for handshake signatures.
    pub fn new(
        record: Option<TrustRecord>,
        ca: CaVerifier,
        provider: &CryptoProvider,
    ) -> TrustVerifier {
        TrustVerifier {
            record,
            ca,
            algorithms: provider.signature_verification_algorithms,
            outcome: Mutex::new(None),
        }
    }

    /// The decision on the server's certificate, once the handshake has
    /// reached it. `Some(Ok)` does not mean the handshake succeeded: the
    /// signature is checked after this decision.
    pub fn outcome(&self) -> Option<Result<Verified, TrustError>> {
        self.outcome.lock().expect("poisoned").clone()
    }

    fn decide(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<Verified, TrustError> {
        let fingerprint = certificate_fingerprint(end_entity)?;
        // Rule 1: CA-valid. Never compared against a pin.
        let ca_error = match self.ca.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(_) => {
                return Ok(Verified {
                    fingerprint,
                    record: TrustRecord::Ca,
                    changed: self.record != Some(TrustRecord::Ca),
                });
            }
            Err(e) => e.to_string(),
        };
        // Rule 2: trust on first use.
        match &self.record {
            None => Err(TrustError::Unknown {
                fingerprint,
                ca_error,
            }),
            Some(TrustRecord::Pinned(pin)) if *pin == fingerprint => Ok(Verified {
                fingerprint,
                record: TrustRecord::Pinned(fingerprint),
                changed: false,
            }),
            Some(recorded) => Err(TrustError::Mismatch {
                recorded: recorded.clone(),
                presented: fingerprint,
                ca_error,
            }),
        }
    }
}

impl ServerCertVerifier for TrustVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let decision = self.decide(end_entity, intermediates, server_name, ocsp_response, now);
        let ok = decision.is_ok();
        *self.outcome.lock().expect("poisoned") = Some(decision);
        if ok {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // Never used: only TLS 1.3 is enabled (2.1). Checked all the same.
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// Runs a blocking trust store call off the async runtime's workers.
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, TrustStoreError> + Send + 'static,
) -> Result<T, Error> {
    match tokio::task::spawn_blocking(f).await {
        Ok(r) => Ok(r?),
        Err(e) => Err(TrustStoreError(e.to_string()).into()),
    }
}

/// Opens TCP and TLS to `addr`, checking the server under 2.2, and
/// stores a new record once the handshake has succeeded.
///
/// SNI is the host of `addr`, unless it is an IP address (2.1). The ALPN
/// `risala/1` is offered. `connect_to` replaces name resolution.
pub(crate) async fn connect(
    addr: &ServerAddr,
    trust: &Arc<dyn TrustStore>,
    ca: CaVerifier,
    connect_to: Option<SocketAddr>,
) -> Result<(TlsStream<TcpStream>, Verified), Error> {
    let record = {
        let (trust, addr) = (trust.clone(), addr.clone());
        blocking(move || trust.get(&addr)).await?
    };
    let server_name = ServerName::try_from(addr.host().to_owned())
        .map_err(|e| Error::Tls(rustls::Error::General(e.to_string())))?;

    let provider = crypto_provider();
    let verifier = Arc::new(TrustVerifier::new(record, ca, &provider));
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(Error::Tls)?
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    config.alpn_protocols = vec![risala_proto::ALPN.to_vec()];
    // Every connection is checked in full; a resumed session would skip
    // the certificate.
    config.resumption = Resumption::disabled();
    config.enable_sni = true;

    let tcp = match connect_to {
        Some(sa) => TcpStream::connect(sa).await?,
        None => TcpStream::connect((addr.host(), addr.port())).await?,
    };
    tcp.set_nodelay(true)?;

    let result = TlsConnector::from(Arc::new(config))
        .connect(server_name, tcp)
        .await;
    let outcome = verifier.outcome();
    let stream = match (result, outcome) {
        (Err(_), Some(Err(trust_error))) => return Err(trust_error.into()),
        (Err(e), _) => return Err(tls_error(e)),
        (Ok(stream), Some(Ok(verified))) => (stream, verified),
        // Resumption is off, so the certificate is always checked.
        (Ok(_), _) => {
            return Err(Error::Tls(rustls::Error::General(
                "the server certificate was not checked".into(),
            )));
        }
    };
    let (stream, verified) = stream;
    if verified.changed {
        let (trust, addr, record) = (trust.clone(), addr.clone(), verified.record.clone());
        blocking(move || trust.set(&addr, record)).await?;
    }
    Ok((stream, verified))
}

/// Takes the rustls error out of a handshake's I/O error, if it is one.
fn tls_error(e: std::io::Error) -> Error {
    match e
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    {
        Some(tls) => Error::Tls(tls.clone()),
        None => Error::Io(e),
    }
}
