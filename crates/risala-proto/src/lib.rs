//! The risala protocol, as defined in the spec (`spec/`, draft-03).
//!
//! This crate has no networking and no async code. It parses and
//! serialises lines, validates names, escapes text and builds and checks
//! the bytes signed when signing in. Both `risalad` and librisala use it.
//!
//! Module map (SPEC section in brackets):
//!
//! - [`error`]: error codes (3.7) and the crate's parse error.
//! - [`frame`]: splitting a byte stream into lines, line limits (2.3).
//! - [`line`](mod@line): one line as tags, verb and parameters (3.1-3.3).
//! - [`text`]: text escaping (3.4) and mentions (5.5).
//! - [`names`]: uids, rooms, boxes, seqs, ids and blob-refs (3.5).
//! - [`time`](mod@time): timestamps (3.5).
//! - [`types`]: small shared values: roles, presence, settings, push.
//! - [`mls`]: MLS objects and the values derived from them, as opaque
//!   values (5.2, 7, 12).
//! - [`binary`]: other binary values: key file records, pairing data,
//!   reports, wrapped backup keys and push keys (4.7, 4.8, 5.8, 9.1,
//!   12.13).
//! - [`connection`]: kinds of connection, and their line limits (4.1, 13).
//! - [`content`]: the lines inside encrypted messages, and where each
//!   counts (12.9).
//! - [`command`]: typed commands, client to server (4-12, 13).
//! - [`server`]: typed server lines, server to client (4-12, 13), and the
//!   NOTIFY push body (9.3).
//! - [`auth`]: the sign-in challenge, RisalaSign and ML-DSA-44 keys (4.3,
//!   4.6, App. B).
//! - [`codec`]: the TLS presentation language of \[RFC9420\], for risala's
//!   own binary structures.
//! - [`record`]: key file records, key log entries and the record payload
//!   of REGISTER and KEYS PUT (4.4, 4.5, 4.7).
//! - [`chain`]: replaying a chain of records, pins, forks, and the chain
//!   checks of REGISTER and KEYS PUT (4.4-4.7).
//! - [`keyfile`]: the key file text format and its three states (4.4).
//! - [`recovery`]: recovery keys and the master key (4.8).
//! - [`pairing`]: PairingCode, NewDevice and SealedBundle (4.8).
//! - [`safety`]: safety numbers (12.14).
//! - [`fingerprint`]: certificate fingerprints for trust on first use (2.2).

#![warn(missing_docs)]

pub mod auth;
mod base32;
pub mod binary;
pub mod chain;
pub mod codec;
pub mod command;
pub mod connection;
pub mod content;
pub mod error;
pub mod fingerprint;
pub mod frame;
pub mod keyfile;
pub mod line;
pub mod mls;
pub mod names;
pub mod pairing;
mod parse;
pub mod record;
pub mod recovery;
pub mod safety;
pub mod server;
pub mod text;
pub mod time;
pub mod types;

#[cfg(kani)]
mod proofs;

/// The protocol version this crate implements, as sent in the greeting (4.1).
pub const PROTOCOL_VERSION: u32 = 1;

/// The default TCP port (15).
pub const DEFAULT_PORT: u16 = 7472;

/// The ALPN protocol identifier (2.1, 15).
pub const ALPN: &[u8] = b"risala/1";
