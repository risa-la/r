//! HTTPS: fetching key files for AUTH, and publishing and serving the key
//! files of hosted identities (4.4-4.6, PLAN.md section 6).
//!
//! Owned by task B in docs/plans/M3.md.
//!
//! - [`fetch`]: the [`KeyFetcher`] trait, which the hub uses to get an
//!   identity's keys (4.5), implemented by the `risala-keyfetch` crate.
//! - [`keydir`]: the [`KeyFilePublisher`] trait, which the hub uses to
//!   publish hosted identities' key files (4.6), implemented by
//!   [`KeyDir`], which writes them to a directory.
//! - [`server`]: [`HttpServer`], the optional HTTPS listener (`[http]` in
//!   the configuration), which serves that directory at
//!   `/.well-known/risala/<name>`.

pub mod fetch;
pub mod keydir;
pub mod server;

#[cfg(test)]
mod tests;

pub use fetch::{FetchError, KeyFetcher};
pub use keydir::{KeyDir, KeyFilePublisher};
pub use server::HttpServer;
