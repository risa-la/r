//! Connections: TLS with the checks of 2.2, the session (greeting, the
//! connection's kind, matching responses to commands), keepalive,
//! reconnects, and the set of connections a device keeps (4.1).
//!
//! Owned by task C0 in docs/plans/M5b.md. Area tasks use it, and change it
//! only where they must.
//!
//! - [`Session`]: one connection. [`Session::connect`] opens TLS 1.3 with
//!   the ALPN `risala/1` and SNI, checks the certificate under 2.2 and
//!   reads the greeting (4.1). Then [`Session::anon`],
//!   [`Session::guest`], [`Session::auth`] or [`Session::register`] give
//!   it its kind, and [`Session::request`] sends commands that kind may
//!   send (Section 13) and returns their [`Response`] (3.6). Other lines
//!   arrive on [`Session::take_incoming`], as [`Incoming`] items.
//!   [`Session::send`] sends a command whose response arrives on that
//!   queue too, in its place among the live lines (3.6).
//! - [`TrustVerifier`]: the certificate rules of 2.2, with strict pins
//!   and the notice when a CA-valid certificate replaces a pin (PLAN.md
//!   58). Refusals are [`TrustError`]s carrying the fingerprint; what the
//!   user decides goes through [`accept_fingerprint`],
//!   [`set_strict_pin`], [`clear_strict_pin`] and [`approve_new_pin`].
//! - [`Supervisor`]: reconnects with backoff, and gives each new
//!   connection its kind through an [`Establish`]: [`Anonymous`],
//!   [`GuestSignIn`] or [`IdentitySignIn`].
//! - [`ServerConnections`]: one account's connections to one server, one
//!   signed-in and some anonymous ones, or one guest connection, with
//!   [`MailboxSlots`] to spread the mailboxes it follows.

mod error;
mod pins;
mod pool;
mod session;
mod supervisor;
mod tls;

#[cfg(test)]
pub(crate) mod tests;

pub use error::{CloseReason, CommandError, Error, TrustError};
pub use pins::{accept_fingerprint, approve_new_pin, clear_strict_pin, set_strict_pin};
pub use pool::{ConnectionPlan, MailboxSlots, PoolEvent, ServerConnections, Slot};
pub use risala_proto::connection::ConnectionKind;
pub use session::{End, Incoming, Response, Session, SessionInfo, SessionOptions, auth_command};
pub use supervisor::{
    Anonymous, Backoff, BoxFuture, Establish, GuestSession, GuestSignIn, IdentitySignIn,
    Supervisor, SupervisorEvent,
};
pub use tls::{
    CaVerifier, TrustVerifier, Verified, certificate_fingerprint, crypto_provider, no_ca_verifier,
    platform_ca_verifier, roots_ca_verifier,
};
