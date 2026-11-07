//! `risalad`, the risala server, as a library so that tests (here, in
//! librisala and in risala-cli) can run a real server in-process.
//!
//! Module map (owner in M2 brackets, see docs/plans/M2-M5.md):
//!
//! - [`config`]: the TOML configuration file.
//! - [`handler`]: the interface between the network layer and the core.
//! - [`net`]: TLS listeners, connection tasks, framing and keepalive.
//! - [`core`]: the hub: sign-in, rooms, events, history and fan-out.
//! - [`store`]: persistent storage, behind a trait, with SQLite.
//! - [`daemon`]: the whole server, the hub behind the network layer:
//!   [`run`] and [`Daemon`].

#![warn(missing_docs)]

pub mod config;
pub mod core;
pub mod daemon;
pub mod handler;
pub mod net;
pub mod store;

pub use daemon::{Daemon, RunError, run};
