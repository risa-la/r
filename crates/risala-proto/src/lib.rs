//! The risala protocol, as defined in SPEC.md (draft-01).
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
//! - [`names`]: uids, rooms, conversations, seqs and ids (3.5).
//! - [`time`](mod@time): timestamps (3.5).
//! - [`types`]: small shared values: roles, settings, presence, relations.
//! - [`auth`]: the sign-in challenge and Ed25519 keys (4.5, App. B).
//! - [`keyfile`]: key files (4.4).
//! - [`fingerprint`]: certificate fingerprints for trust on first use (2.2).
//! - [`command`]: typed commands, client to server (4-11).
//! - [`server`]: typed server lines, server to client (4-11).

#![warn(missing_docs)]

pub mod auth;
pub mod command;
pub mod error;
pub mod fingerprint;
pub mod frame;
pub mod keyfile;
pub mod line;
pub mod names;
pub mod server;
pub mod text;
pub mod time;
pub mod types;

#[cfg(kani)]
mod proofs;

/// The protocol version this crate implements, as sent in the greeting (4.1).
pub const PROTOCOL_VERSION: u32 = 1;

/// The default TCP port (14).
pub const DEFAULT_PORT: u16 = 7472;

/// The ALPN protocol identifier (2.1, 14).
pub const ALPN: &[u8] = b"risala/1";
