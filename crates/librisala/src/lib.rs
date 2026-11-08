//! librisala, the risala client library (PLAN.md 3.4), for draft-03 of
//! the spec (`spec/`).
//!
//! It owns everything apps share: connections, trust on first use, keys,
//! identities and key logs, the group engine, the encrypted cache and the
//! API. It builds on `risala-proto` for the wire format, `risala-mls` for
//! MLS and `risala-keylog` for the key log.
//!
//! Module map, with the task of docs/plans/M5b.md that owns each part:
//!
//! - [`addr`] (C0): server addresses and trust records (2.1, 2.2).
//! - [`conn`] (C0): TLS with the checks of 2.2, sessions and their kinds
//!   (4.1), reconnects, and an account's connections: one signed in, and
//!   anonymous ones for conversations.
//! - [`keys`] (C1): the device's secret keys, in the platform's store.
//! - [`clock`] (C0): the time, replaceable in tests.
//! - [`store`]: the SQLCipher cache, one module per area.
//! - [`sync`]: the sans-I/O engines, one per area.
//! - [`client`]: the API apps use, one module per area.
//!
//! The areas are: settings and connections (C0), identity and key logs
//! (C1), conversations and messages (C2), confirming leaves (C3), and
//! files, transfers, backups, push and reports (C4). Each has a module in
//! `store`, `sync` and `client`, so that the area tasks can work at the
//! same time; the module docs of each say what is in it.

#![warn(missing_docs)]

pub use risala_keyfetch as keyfetch;
pub use risala_proto as proto;

pub mod addr;
pub mod client;
pub mod clock;
pub mod conn;
pub mod keys;
pub mod store;
pub mod sync;

pub use client::{Client, ClientOptions, Error, Event, Result};
