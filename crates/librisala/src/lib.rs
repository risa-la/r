//! librisala, the risala client library.
//!
//! It owns everything apps share (PLAN.md 3.3): connections, trust on
//! first use, keys, sign-in, sync, the history cache and timelines. It
//! builds on `risala-proto` for everything about the wire format.
//!
//! Module map (owner in M5 brackets, see docs/plans/M2-M5.md):
//!
//! - [`addr`]: server addresses and trust records, shared by all modules.
//! - [`conn`]: TLS with trust on first use, sessions, sign-in, keys.
//! - [`store`]: the SQLite cache: servers, trust, conversations, events,
//!   read markers, the outbox.
//! - [`sync`]: the sans-I/O sync engine (7.1-7.3, 7.6), with the
//!   encryption engine of Section 12 inside it.
//! - `e2ee`: MLS groups, content lines, history keys and backups
//!   (Section 12), on the store's transactions.
//! - [`client`]: the API apps use: [`Client`](client::Client),
//!   accounts, conversations and timelines, driving the three above.

#![warn(missing_docs)]

pub use risala_keyfetch as keyfetch;
pub use risala_proto as proto;

pub mod addr;
pub mod client;
pub mod conn;
pub(crate) mod e2ee;
pub mod store;
pub mod sync;
