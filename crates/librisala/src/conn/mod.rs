//! Connections: TLS with the verifier of 2.2, the session (greeting,
//! sign-in, matching responses to commands), keepalive, reconnects, and
//! device keys.
//!
//! Owned by task C in docs/plans/M2-M5.md.
//!
//! - [`Session`]: one connection. [`Session::connect`] opens TLS 1.3 with
//!   the ALPN `risala/1` and SNI, checks the certificate under 2.2 and
//!   reads the greeting (4.1). Then [`Session::guest`],
//!   [`Session::auth`] or [`Session::register`] sign in, and
//!   [`Session::request`] sends commands and returns their [`Response`]
//!   (3.6). Other lines arrive on [`Session::take_incoming`], as
//!   [`Incoming`] items. [`Session::send`] sends a command whose response
//!   arrives on that queue too, in its place among the live lines, which
//!   is what the sync engine needs (3.6).
//! - [`TrustVerifier`]: the certificate rules of 2.2. Refusals are
//!   [`TrustError`]s carrying the fingerprint; after the user accepts
//!   one, [`accept_fingerprint`] records it.
//! - [`Supervisor`]: reconnects with backoff, signs in again through a
//!   [`SignIn`], and reports [`SupervisorEvent`]s.
//! - [`keys`]: device keys, the [`KeyStore`](keys::KeyStore) trait and
//!   the AUTH and REGISTER signing helpers.

mod error;
pub mod keys;
mod session;
mod supervisor;
mod tls;

#[cfg(test)]
pub(crate) mod tests;

pub use error::{CloseReason, CommandError, Error, TrustError};
pub use session::{End, Incoming, Response, Session, SessionInfo, SessionOptions};
pub use supervisor::{
    Backoff, BoxFuture, GuestSignIn, GuestToken, IdentitySignIn, SignIn, Supervisor,
    SupervisorEvent,
};
pub use tls::{
    CaVerifier, TrustVerifier, Verified, accept_fingerprint, certificate_fingerprint,
    crypto_provider, no_ca_verifier, platform_ca_verifier, roots_ca_verifier,
};
