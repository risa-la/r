//! TLS for fetching key files (4.4): rustls with aws-lc-rs, TLS 1.3, and
//! certificates checked against public certificate authorities.

use std::sync::Arc;

use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::CryptoProvider;
use rustls::crypto::aws_lc_rs::kx_group;
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

/// The certificate authorities a key file's server is checked against
/// (4.4).
#[derive(Debug, Clone)]
pub enum Roots {
    /// Mozilla's root store, as the `webpki-root-certs` crate ships it,
    /// plus `extra` roots. The default, with no extras.
    ///
    /// The roots are built in, so a server checks against the same public
    /// CAs whatever its host has installed (or not, as in many
    /// containers). Extras are for tests and private deployments.
    Public {
        /// More trust anchors, besides Mozilla's.
        extra: Vec<CertificateDer<'static>>,
    },
    /// Only these trust anchors, for tests.
    Only(Vec<CertificateDer<'static>>),
    /// Any certificate verifier, for example the platform's
    /// (`rustls-platform-verifier`), as librisala uses for devices.
    Verifier(Arc<dyn ServerCertVerifier>),
}

impl Default for Roots {
    fn default() -> Self {
        Roots::Public { extra: Vec::new() }
    }
}

/// The crypto provider: aws-lc-rs, offering the hybrid post-quantum
/// X25519MLKEM768 first, then the classical groups, since a key file can
/// be on any web server.
pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(CryptoProvider {
        kx_groups: vec![
            kx_group::X25519MLKEM768,
            kx_group::X25519,
            kx_group::SECP256R1,
            kx_group::SECP384R1,
        ],
        ..rustls::crypto::aws_lc_rs::default_provider()
    })
}

/// The TLS client: TLS 1.3 only, ALPN `http/1.1`, and `roots`.
pub(crate) fn connector(roots: &Roots) -> TlsConnector {
    let provider = provider();
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("aws-lc-rs supports TLS 1.3");
    let store = |certs: &mut dyn Iterator<Item = CertificateDer<'static>>| {
        let mut store = RootCertStore::empty();
        let (_, bad) = store.add_parsable_certificates(certs);
        if bad > 0 {
            tracing::warn!(bad, "ignored trust anchors that do not parse");
        }
        store
    };
    let mut config = match roots {
        Roots::Public { extra } => builder
            .with_root_certificates(store(
                &mut webpki_root_certs::TLS_SERVER_ROOT_CERTS
                    .iter()
                    .cloned()
                    .chain(extra.iter().cloned()),
            ))
            .with_no_client_auth(),
        Roots::Only(certs) => builder
            .with_root_certificates(store(&mut certs.iter().cloned()))
            .with_no_client_auth(),
        Roots::Verifier(verifier) => builder
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth(),
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    // No TLS resumption: each fetch has a TLS session of its own, as
    // every risala connection does (2.1), so that a session ticket cannot
    // link one fetch to another.
    config.resumption = rustls::client::Resumption::disabled();
    TlsConnector::from(Arc::new(config))
}
