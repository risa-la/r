//! `risalad`, the risala server, as a library so that tests (here, in
//! librisala and in risala-cli) can run a real server in-process.
//!
//! It follows draft-03 of the spec (`spec/`). Module map:
//!
//! - [`config`]: the TOML configuration file.
//! - [`handler`]: the interface between the network layer and the core.
//! - [`net`]: TLS listeners, connection tasks, framing and keepalive.
//! - [`http`]: HTTPS: fetching key files, the key file directory, and the
//!   listener that serves hosted identities' key files.
//! - [`keyfiles`]: where the hub gets identities' keys and publishes the
//!   key files of the identities it hosts.
//! - [`core`]: the hub: connection kinds, routing each command to its
//!   area, and the areas themselves.
//! - [`store`]: persistent storage, one trait per area, with SQLite.
//! - [`secret`]: bearer secrets, stored as hashes and compared in constant
//!   time.
//! - [`daemon`]: the whole server, the hub behind the network layer:
//!   [`run`] and [`Daemon`].
//! - [`testing`]: a whole server and a TLS client, for tests.

#![warn(missing_docs)]

pub mod config;
pub mod core;
pub mod daemon;
pub mod handler;
pub mod http;
pub mod keyfiles;
pub mod net;
pub mod push;
pub mod secret;
pub mod store;
pub mod testing;

pub use daemon::{Daemon, RunError, run};
