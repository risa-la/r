//! HTTPS: fetching key files for AUTH, and publishing and serving the key
//! files of hosted identities (4.4-4.6, PLAN.md section 6).
//!
//! Owned by task B in docs/plans/M3.md.
//!
//! - [`fetch`]: [`HttpsKeyFetcher`], the hub's
//!   [`KeyFetcher`](crate::core::KeyFetcher) over HTTPS (4.5), built on
//!   the `risala-keyfetch` crate.
//! - [`keydir`]: [`KeyDir`], the hub's
//!   [`KeyFilePublisher`](crate::core::KeyFilePublisher), which writes
//!   hosted identities' key files to a directory (4.6).
//! - [`server`]: [`HttpServer`], the optional HTTPS listener (`[http]` in
//!   the configuration), which serves the hosted identities' key files at
//!   `/.well-known/risala/<name>`, made from the hub's records.

pub mod fetch;
pub mod keydir;
pub mod server;

#[cfg(test)]
mod tests;

pub use fetch::HttpsKeyFetcher;
pub use keydir::KeyDir;
pub use server::{HttpServer, KeyFiles};
