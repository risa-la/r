//! The HTTPS fetches of the identity area (4.4, 4.5): key files, and a
//! key log's checkpoint, tiles, entry bundles and hints.
//!
//! They go through [`Https`], which [`KeyFetcherHttps`] implements with
//! `risala-keyfetch` under the rules of 4.4 (TLS 1.3 with the CA check, no
//! redirects, 10 seconds, a size limit, no TLS resumption), and tests
//! implement from memory.

use std::sync::{Arc, OnceLock};

use risala_keyfetch::{FetchError, FetchOptions, KeyFetcher, Roots, UrlBody};

use crate::conn::{BoxFuture, CaVerifier};

/// What a fetch got (4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fetched {
    /// A 200 response within the limit, with its body.
    Body(Vec<u8>),
    /// A 200 response over the limit.
    TooLarge,
    /// A 404 or 410 response, with its status.
    Gone(u16),
    /// Any other status, a redirect included: an outage.
    Status(u16),
    /// No response: DNS, TLS, a timeout. An outage, with why for logs.
    Failed(String),
}

impl Fetched {
    /// Whether the fetch is an outage (4.4): no answer about the file.
    pub fn is_outage(&self) -> bool {
        matches!(self, Fetched::Status(_) | Fetched::Failed(_))
    }
}

impl From<Result<UrlBody, FetchError>> for Fetched {
    fn from(r: Result<UrlBody, FetchError>) -> Fetched {
        match r {
            Ok(UrlBody::Ok(body)) => Fetched::Body(body),
            Ok(UrlBody::TooLarge) => Fetched::TooLarge,
            Ok(UrlBody::Gone(status)) => Fetched::Gone(status),
            Err(FetchError::Status(status)) => Fetched::Status(status),
            Err(e) => Fetched::Failed(e.to_string()),
        }
    }
}

/// Fetches over HTTPS for the identity area. Each call is one GET with a
/// connection and TLS session of its own (2.1, 4.4).
pub trait Https: Send + Sync {
    /// Fetches `url`, an `https` URL, reading at most `max` bytes of body.
    fn get<'a>(&'a self, url: &'a str, max: usize) -> BoxFuture<'a, Fetched>;
}

/// [`Https`] through `risala-keyfetch`.
#[derive(Clone, Debug)]
pub struct KeyFetcherHttps(pub KeyFetcher);

impl KeyFetcherHttps {
    /// Fetches checking certificates with `verifier`, the platform's CA
    /// check as connections use it. Devices may fetch from any address,
    /// since the user chose the identities (4.4 binds servers only).
    pub fn new(verifier: CaVerifier) -> KeyFetcherHttps {
        KeyFetcherHttps(KeyFetcher::new(FetchOptions {
            roots: Roots::Verifier(verifier),
            allow_private: true,
            min_refetch: std::time::Duration::ZERO,
            ..FetchOptions::default()
        }))
    }
}

impl Https for KeyFetcherHttps {
    fn get<'a>(&'a self, url: &'a str, max: usize) -> BoxFuture<'a, Fetched> {
        Box::pin(async move { self.0.fetch_url(url, max).await.into() })
    }
}

/// The fetcher of a client without one in its options, made once, with
/// the platform's CA check.
pub(crate) fn platform() -> Arc<dyn Https> {
    static PLATFORM: OnceLock<Arc<dyn Https>> = OnceLock::new();
    PLATFORM
        .get_or_init(|| Arc::new(KeyFetcherHttps::new(crate::conn::platform_ca_verifier())))
        .clone()
}
