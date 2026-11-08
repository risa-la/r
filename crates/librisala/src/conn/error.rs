//! Errors for connections, trust (2.2) and commands (3.6, 3.7).

use std::io;

use risala_proto::connection::ConnectionKind;
use risala_proto::error::{ErrorCode, ParseError};
use risala_proto::fingerprint::Fingerprint;
use risala_proto::server::ErrResponse;

use crate::addr::{TrustRecord, TrustStoreError};

/// Anything that can go wrong with a connection, from opening it to the
/// final response of a command.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The TCP connection failed, or I/O failed during the TLS handshake.
    #[error("connection failed: {0}")]
    Io(#[from] io::Error),
    /// TLS failed for a reason other than trust, such as a handshake
    /// signature that did not verify (2.1).
    #[error("TLS failed: {0}")]
    Tls(rustls::Error),
    /// The TLS handshake failed on the key exchange. librisala offers only
    /// the post-quantum hybrid X25519MLKEM768, which the spec requires
    /// (2.1), so the server most likely does not support it and needs an
    /// upgrade. This is not about trusting the server: no certificate was
    /// checked.
    #[error("the server does not support the key exchange X25519MLKEM768 ({0})")]
    KeyExchange(rustls::Error),
    /// The server's certificate was refused under 2.2. The app shows the
    /// fingerprint and lets the user decide.
    #[error(transparent)]
    Trust(#[from] TrustError),
    /// The trust store could not be read or written.
    #[error(transparent)]
    TrustStore(#[from] TrustStoreError),
    /// Connecting, the handshake and the greeting together took longer
    /// than [`SessionOptions::connect_timeout`](super::SessionOptions).
    #[error("timed out connecting")]
    Timeout,
    /// The first line was not a greeting (4.1).
    #[error("bad greeting: {0}")]
    BadGreeting(String),
    /// The server speaks a protocol version this client does not (3.8).
    /// The connection was closed.
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u32),
    /// The connection is closed, or closed while the command waited.
    #[error("connection closed: {0}")]
    Closed(CloseReason),
    /// The command cannot be sent: a value is not valid or the line is
    /// too long (2.3, 3.3).
    #[error("invalid command: {0}")]
    InvalidCommand(ParseError),
    /// PONG gets no response (3.6), so it cannot be sent as a request.
    #[error("this command gets no response")]
    NoResponse,
    /// The server refused the command (sign-in, for example).
    #[error(transparent)]
    Rejected(#[from] CommandError),
    /// AUTH or REGISTER was already sent on this connection. Every AUTH or
    /// REGISTER uses up the nonce; reconnect to try again (4.6).
    #[error("the sign-in nonce is used up; reconnect to try again")]
    NonceUsed,
    /// ANON, GUEST, AUTH or REGISTER is still waiting for its answer, so
    /// the connection's kind is not known yet (4.1).
    #[error("the connection is still becoming anonymous, a guest or signed in")]
    KindPending,
    /// This kind of connection may not send the command (Section 13), so
    /// it was not sent: the server would answer `wrong-connection`, or
    /// `not-authenticated` on a new connection. Above all, this keeps a
    /// device from following or fetching on its signed-in connection,
    /// which would tell the server who it is (4.1).
    #[error("a {kind} connection may not send {verb}")]
    WrongKind {
        /// The command's verb.
        verb: &'static str,
        /// The connection's kind.
        kind: ConnectionKind,
    },
    /// The address is an IP address, so the client sent no SNI and cannot
    /// sign in as an identity (2.1, 4.6).
    #[error("cannot sign in as an identity without a hostname (SNI)")]
    NoSni,
    /// The server offers no registration (4.7, 8.5).
    #[error("the server offers no registration")]
    NoRegistration,
}

impl Error {
    /// Whether retrying cannot help without the user doing something,
    /// such as accepting a fingerprint or fixing a key. A reconnect
    /// supervisor stops on these.
    ///
    /// Permanent: every [`TrustError`] but
    /// [`RecordChanged`](TrustError::RecordChanged), a key exchange the
    /// server does not support, an unsupported version, a missing SNI, no
    /// registration, an invalid command or one for another kind of
    /// connection, and a sign-in refused
    /// with `auth-failed`, `forbidden` without a `retry` tag,
    /// `not-supported`, `bad-syntax`, `unknown-command` or
    /// `wrong-connection`. `auth-failed`
    /// means the signature did not verify against the keys the server
    /// got, and the same key fails the same way (4.6). Everything else
    /// may pass: `unavailable` (the server could not get the key file,
    /// 4.6), `name-taken` (a guest's old session may not have ended yet,
    /// and [`GuestSignIn`](super::GuestSignIn) has already tried other
    /// names), `rate-limited`, a `forbidden` with `retry` (a limit that
    /// passes with time) and `internal`.
    pub fn is_permanent(&self) -> bool {
        match self {
            Error::Trust(TrustError::RecordChanged) => false,
            Error::Trust(_)
            | Error::KeyExchange(_)
            | Error::UnsupportedVersion(_)
            | Error::NoSni
            | Error::NoRegistration
            | Error::InvalidCommand(_)
            | Error::WrongKind { .. }
            | Error::NoResponse => true,
            Error::Rejected(CommandError::Server(err)) => match err.code {
                ErrorCode::Forbidden => err.retry.is_none(),
                ErrorCode::AuthFailed
                | ErrorCode::NotSupported
                | ErrorCode::BadSyntax
                | ErrorCode::UnknownCommand
                | ErrorCode::WrongConnection => true,
                _ => false,
            },
            _ => false,
        }
    }

    /// Whether the server answered `ERR auth-failed` (4.6).
    pub fn is_auth_failed(&self) -> bool {
        matches!(
            self,
            Error::Rejected(CommandError::Server(err)) if err.code == ErrorCode::AuthFailed
        )
    }

    /// The `retry` tag of an `ERR`, in seconds (3.2): sent with
    /// `rate-limited` and `unavailable`, and with a `forbidden` that
    /// passes with time.
    pub fn retry_after(&self) -> Option<u64> {
        match self {
            Error::Rejected(CommandError::Server(err)) => err.retry,
            _ => None,
        }
    }
}

/// A certificate refused by the rules of 2.2.
///
/// `ca_error` says why the certificate was not CA-valid (expired,
/// self-signed, wrong name and so on), for the app to show.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TrustError {
    /// Nothing is recorded for this server and its certificate is not
    /// CA-valid. The app shows the fingerprint and asks the user. If the
    /// user accepts, record it with
    /// [`accept_fingerprint`](super::accept_fingerprint) and connect
    /// again.
    #[error("unknown server certificate {fingerprint}")]
    Unknown {
        /// The fingerprint of the certificate's public key.
        fingerprint: Fingerprint,
        /// Why the certificate is not CA-valid.
        ca_error: String,
    },
    /// The certificate is not CA-valid and does not match the record: a
    /// different pin, or "CA" (a possible downgrade). The client refuses.
    /// The user must delete the record explicitly
    /// ([`TrustStore::forget`](crate::addr::TrustStore::forget)) before
    /// trying again.
    #[error("server certificate {presented} does not match the record ({recorded})")]
    Mismatch {
        /// What is recorded for this server.
        recorded: TrustRecord,
        /// The fingerprint of the certificate the server showed.
        presented: Fingerprint,
        /// Why the certificate is not CA-valid.
        ca_error: String,
    },
    /// The server has a strict pin (2.2), and the certificate has another
    /// fingerprint, CA-valid or not. The app shows both and asks the user;
    /// if the user approves, record it with
    /// [`approve_new_pin`](super::approve_new_pin) and connect again.
    #[error("server certificate {presented} does not match the strict pin {pinned}")]
    StrictMismatch {
        /// The strictly pinned fingerprint.
        pinned: Fingerprint,
        /// The fingerprint of the certificate the server showed.
        presented: Fingerprint,
        /// Why the certificate is not CA-valid, or `None` if it is.
        ca_error: Option<String>,
    },
    /// The certificate could not be read, so it has no fingerprint.
    #[error("bad server certificate: {0}")]
    BadCertificate(String),
    /// The server's record changed while this connection was checked
    /// against the old one, for example because the user set a strict pin
    /// meanwhile. Nothing was written; connecting again checks against the
    /// new record.
    #[error("the server's trust record changed while connecting")]
    RecordChanged,
}

/// Why a connection closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloseReason {
    /// The server closed the connection, with the text of its BYE if it
    /// sent one (11). The text is escaped, as on the wire.
    Server {
        /// The BYE message, if any.
        bye: Option<String>,
    },
    /// The server did not answer a keepalive PING in time (11).
    PingTimeout,
    /// Reading or writing failed.
    Io(String),
    /// The server broke the protocol, so responses could no longer be
    /// matched to commands (3.6).
    Protocol(String),
    /// The app did not read incoming lines fast enough and the queue
    /// filled up. Reconnect and catch up with FETCH (7.4).
    Overflow,
    /// The app closed the connection.
    Local,
}

impl std::fmt::Display for CloseReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CloseReason::Server { bye: Some(m) } if !m.is_empty() => {
                write!(f, "closed by the server: {m}")
            }
            CloseReason::Server { .. } => f.write_str("closed by the server"),
            CloseReason::PingTimeout => f.write_str("the server stopped answering"),
            CloseReason::Io(e) => write!(f, "I/O error: {e}"),
            CloseReason::Protocol(e) => write!(f, "protocol error: {e}"),
            CloseReason::Overflow => f.write_str("incoming lines were not read in time"),
            CloseReason::Local => f.write_str("closed"),
        }
    }
}

/// A command that ended in failure (3.6, 3.7).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CommandError {
    /// `ERR <code> [<message...>]`. Unknown codes are general failures
    /// (3.7).
    #[error("{} {}", .0.code, .0.message)]
    Server(ErrResponse),
    /// An `OK` or `ERR` that could not be parsed. It still ended the
    /// command, as a general failure (2.3). Holds the raw line.
    #[error("unparseable response: {0}")]
    Unparseable(String),
}

impl CommandError {
    /// The error code, if the server sent one that parsed.
    pub fn code(&self) -> Option<&ErrorCode> {
        match self {
            CommandError::Server(err) => Some(&err.code),
            CommandError::Unparseable(_) => None,
        }
    }
}
