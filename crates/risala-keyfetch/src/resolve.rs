//! Turning a key file's domain into addresses to connect to.
//!
//! [`SystemResolver`] asks the system, as everything else on the host
//! does. Tests inject a [`StaticResolver`], which maps names to fixed
//! addresses, ports included, so that a test can send
//! `alice@example.test` to a local server, or to `10.0.0.1` to check the
//! address guard.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;

/// A boxed future, so that [`Resolve`] can be used as a trait object.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The HTTPS port, which key file URLs use (4.3).
pub const HTTPS_PORT: u16 = 443;

/// Resolves a domain to the socket addresses to try, in order.
pub trait Resolve: Send + Sync + 'static {
    /// The addresses of `host`, with port [`HTTPS_PORT`] unless the
    /// resolver chooses another (as test resolvers do). `host` is a
    /// lower-case domain.
    fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, io::Result<Vec<SocketAddr>>>;
}

/// The system's resolver (`getaddrinfo`, through tokio).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

impl Resolve for SystemResolver {
    fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, io::Result<Vec<SocketAddr>>> {
        Box::pin(async move { Ok(tokio::net::lookup_host((host, HTTPS_PORT)).await?.collect()) })
    }
}

/// A fixed map from domains to addresses, for tests. Domains it does not
/// know fail with [`io::ErrorKind::NotFound`].
#[derive(Debug, Clone, Default)]
pub struct StaticResolver {
    hosts: HashMap<String, Vec<SocketAddr>>,
}

impl StaticResolver {
    /// An empty map.
    pub fn new() -> StaticResolver {
        StaticResolver::default()
    }

    /// Maps `host` (folded to lower case) to `addrs`, replacing what it
    /// mapped to before.
    pub fn with(mut self, host: &str, addrs: impl IntoIterator<Item = SocketAddr>) -> Self {
        self.insert(host, addrs);
        self
    }

    /// Maps `host` (folded to lower case) to `addrs`, replacing what it
    /// mapped to before.
    pub fn insert(&mut self, host: &str, addrs: impl IntoIterator<Item = SocketAddr>) {
        self.hosts
            .insert(host.to_ascii_lowercase(), addrs.into_iter().collect());
    }
}

impl Resolve for StaticResolver {
    fn resolve<'a>(&'a self, host: &'a str) -> BoxFuture<'a, io::Result<Vec<SocketAddr>>> {
        let found = self.hosts.get(host).cloned().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("{host}: no such test host"),
            )
        });
        Box::pin(std::future::ready(found))
    }
}
