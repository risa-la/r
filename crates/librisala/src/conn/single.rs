//! Connections of their own (4.1, "Keeping connections apart"): a
//! connection opened for one command, used for nothing else and closed
//! afterwards.
//!
//! A device sends each command that names or proves its identity, device,
//! leaf or KeyPackage on its signed-in connection where Section 13 allows
//! it, or on a connection of its own, never on an anonymous connection it
//! uses for anything else: KEYS PUT, PAIR PUT and PAIR GET, WELCOME GET,
//! FETCH with `leaf`, and a public room's PublicMessages. It SHOULD use a
//! fresh anonymous connection for each CREATE, KEYPKG GET and WELCOME PUT
//! too. [`single_use`] does this.

use std::sync::Arc;

use risala_proto::command::Command;

use super::error::Error;
use super::session::{Response, Session, SessionOptions};
use crate::addr::{ServerAddr, TrustStore};

/// What a connection of its own becomes before its command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SingleUse {
    /// Nothing: the command is one a new connection may send, such as
    /// KEYS PUT or PAIR (4.1).
    New,
    /// Anonymous, with ANON first.
    Anonymous,
}

/// Opens a connection to `addr`, makes it `kind`, sends `command`, and
/// closes the connection, whatever the answer. Returns the response.
///
/// The connection shares nothing with any other: its own TLS session,
/// with no resumption (2.1), and no other command.
pub async fn single_use(
    addr: &ServerAddr,
    trust: Arc<dyn TrustStore>,
    options: SessionOptions,
    kind: SingleUse,
    command: Command,
) -> Result<Response, Error> {
    let session = Session::connect(addr, trust, options).await?;
    let result = async {
        if kind == SingleUse::Anonymous {
            session.anon().await?;
        }
        session.request(command).await
    }
    .await;
    session.close();
    result
}
