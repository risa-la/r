//! Connections: TLS with the verifier of 2.2, the session (greeting,
//! sign-in, matching responses to commands), keepalive, reconnects, and
//! device keys.
//!
//! Owned by task C in docs/plans/M2-M5.md.

mod error;
pub mod keys;
mod tls;

pub use error::{CloseReason, CommandError, Error, TrustError};
pub use tls::{
    CaVerifier, TrustVerifier, Verified, accept_fingerprint, certificate_fingerprint,
    crypto_provider, platform_ca_verifier, roots_ca_verifier,
};
