//! Fetching key files for AUTH (4.4, 4.5): the [`KeyFetcher`] trait the
//! hub uses, and its implementation by [`risala_keyfetch`].

use std::io;
use std::sync::Arc;

use risala_keyfetch::{BoxFuture, FetchOptions};
use risala_proto::auth::PublicKey;
use risala_proto::names::Identity;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject as _;

use crate::config::KeysConfig;

pub use risala_keyfetch::FetchError;

/// Gets the keys of identities the server does not host, from their key
/// files (4.4), to check AUTH (4.5).
///
/// The future is boxed so that the hub can hold an `Arc<dyn KeyFetcher>`,
/// and tests a stub.
pub trait KeyFetcher: Send + Sync + 'static {
    /// The public keys in `identity`'s key file (4.4). Any error means the
    /// identity has no keys.
    ///
    /// With `refresh`, the file is fetched again rather than taken from the
    /// cache: 4.4 asks for this once when a signature does not verify
    /// against a cached file. An implementation may still limit how often
    /// one file is fetched (14).
    fn fetch<'a>(
        &'a self,
        identity: &'a Identity,
        refresh: bool,
    ) -> BoxFuture<'a, Result<Vec<PublicKey>, FetchError>>;

    /// Forgets any cached key file of `identity`. Does nothing by default.
    fn invalidate(&self, identity: &Identity) {
        let _ = identity;
    }
}

impl KeyFetcher for risala_keyfetch::KeyFetcher {
    fn fetch<'a>(
        &'a self,
        identity: &'a Identity,
        refresh: bool,
    ) -> BoxFuture<'a, Result<Vec<PublicKey>, FetchError>> {
        Box::pin(risala_keyfetch::KeyFetcher::fetch(self, identity, refresh))
    }

    fn invalidate(&self, identity: &Identity) {
        risala_keyfetch::KeyFetcher::invalidate(self, identity);
    }
}

/// The fetch options `config` asks for: the address guard on unless
/// `allow_private`, the timeout and cache size, and the public roots plus
/// `extra_roots`.
///
/// Reads the `extra_roots` files, so call it from a blocking context.
/// Fails if one cannot be read or holds no certificate.
pub fn fetch_options(config: &KeysConfig) -> io::Result<FetchOptions> {
    let mut extra = Vec::new();
    for path in &config.extra_roots {
        let invalid = |e: &dyn std::fmt::Display| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("keys.extra_roots: {}: {e}", path.display()),
            )
        };
        let certs = CertificateDer::pem_file_iter(path)
            .map_err(|e| invalid(&e))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| invalid(&e))?;
        if certs.is_empty() {
            return Err(invalid(&"no certificate in the file"));
        }
        extra.extend(certs);
    }
    Ok(FetchOptions {
        roots: risala_keyfetch::Roots::Public { extra },
        allow_private: config.allow_private,
        timeout: std::time::Duration::from_secs(config.fetch_timeout_secs),
        cache_capacity: config.cache_size,
        ..FetchOptions::default()
    })
}

/// The server's [`KeyFetcher`], set up from `config` (see
/// [`fetch_options`]). Call it from a blocking context.
pub fn from_config(config: &KeysConfig) -> io::Result<Arc<dyn KeyFetcher>> {
    Ok(Arc::new(risala_keyfetch::KeyFetcher::new(fetch_options(
        config,
    )?)))
}
