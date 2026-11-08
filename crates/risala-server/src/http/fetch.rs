//! Fetching key files for AUTH (4.4, 4.5): the hub's
//! [`KeyFetcher`], implemented by
//! [`risala_keyfetch`].

use std::io;
use std::sync::Arc;

use risala_keyfetch::FetchOptions;
use risala_proto::names::Identity;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject as _;

use crate::config::KeysConfig;
use crate::keyfiles::{FetchError, FetchedKeys, KeyFetcher};

/// Fetches key files over HTTPS under the rules of 4.4, for the hub's
/// AUTH (4.5). A key file or a gone answer gives the identity's keys; a
/// failed fetch gives an error, and AUTH `ERR unavailable`.
#[derive(Debug)]
pub struct HttpsKeyFetcher(pub risala_keyfetch::KeyFetcher);

impl KeyFetcher for HttpsKeyFetcher {
    async fn fetch(&self, identity: &Identity, refresh: bool) -> Result<FetchedKeys, FetchError> {
        let found = self
            .0
            .lookup(identity, refresh)
            .await
            .map_err(|e| FetchError::Failed(e.to_string()))?;
        Ok(FetchedKeys {
            keys: found.entries.iter().map(|e| e.key().clone()).collect(),
            cached: found.cached,
        })
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
        // One site may take an eighth of the cache, whatever its size.
        cache_per_site: config.cache_size / risala_keyfetch::DEFAULT_CACHE_SHARE,
        ..FetchOptions::default()
    })
}

/// The server's [`KeyFetcher`], set up from `config` (see
/// [`fetch_options`]). Call it from a blocking context.
pub fn from_config(config: &KeysConfig) -> io::Result<Arc<HttpsKeyFetcher>> {
    Ok(Arc::new(HttpsKeyFetcher(risala_keyfetch::KeyFetcher::new(
        fetch_options(config)?,
    ))))
}
