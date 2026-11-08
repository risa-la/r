//! Servers: what is recorded about each one's certificate (2.2), the
//! user's decisions about it, and what the server says about itself
//! (8.5).
//!
//! Owned by task C0.

use std::sync::Arc;

use risala_proto::command::Command;
use risala_proto::fingerprint::Fingerprint;
use risala_proto::server::OkResponse;

use super::{Client, Error, Result};
use crate::addr::{PinChange, ServerAddr, TrustRecord, TrustStore};
use crate::conn::{self, Session, SessionInfo};

/// A server's greeting, certificate and INFO (4.1, 2.2, 8.5), from
/// [`Client::probe`].
#[derive(Debug, Clone)]
pub struct ServerHello {
    /// The greeting and how the certificate was accepted.
    pub info: SessionInfo,
    /// INFO's values (8.5).
    pub values: OkResponse,
}

/// Reads a server address as the user typed it.
pub(crate) fn server_addr(server: &str) -> Result<ServerAddr> {
    server
        .trim()
        .parse()
        .map_err(|_| Error::invalid("server address", server))
}

impl Client {
    /// Connects to `server`, checks its certificate (2.2), reads the
    /// greeting and INFO (8.5), and closes the connection. A server with
    /// no record yet fails with a
    /// [`TrustError::Unknown`](crate::conn::TrustError::Unknown) carrying
    /// the fingerprint to show the user; see
    /// [`accept_fingerprint`](Self::accept_fingerprint).
    pub async fn probe(&self, server: &str) -> Result<ServerHello> {
        let addr = server_addr(server)?;
        let session = Session::connect(&addr, self.trust(), self.session_options()).await?;
        let values = session.request_ok(Command::Info { room: None }).await;
        session.close();
        Ok(ServerHello {
            info: session.info().clone(),
            values: values?,
        })
    }

    /// What is recorded for `server` (2.2): nothing, "CA", or a pin.
    pub fn trust_record(&self, server: &str) -> Result<Option<TrustRecord>> {
        Ok(TrustStore::get(self.store(), &server_addr(server)?)?)
    }

    /// Records the fingerprint the user accepted for a server with no
    /// record (2.2). See [`conn::accept_fingerprint`].
    pub fn accept_fingerprint(&self, server: &str, fingerprint: &str) -> Result<()> {
        let fp = parse_fingerprint(fingerprint)?;
        let addr = server_addr(server)?;
        conn::accept_fingerprint(self.store(), &addr, fp)?;
        self.notify_trust(&addr);
        Ok(())
    }

    /// Deletes what is recorded for `server`, as the user must do
    /// explicitly after a mismatch (2.2).
    pub fn forget_trust(&self, server: &str) -> Result<()> {
        let addr = server_addr(server)?;
        self.store().forget(&addr)?;
        self.notify_trust(&addr);
        Ok(())
    }

    /// Sets a strict pin on `fingerprint`, the one the user saw for
    /// `server` (2.2, PLAN.md 58). See [`conn::set_strict_pin`].
    pub fn set_strict_pin(&self, server: &str, fingerprint: &str) -> Result<()> {
        let fp = parse_fingerprint(fingerprint)?;
        let addr = server_addr(server)?;
        conn::set_strict_pin(self.store(), &addr, fp)?;
        self.notify_trust(&addr);
        Ok(())
    }

    /// Turns a strict pin back into an ordinary one (2.2).
    pub fn clear_strict_pin(&self, server: &str) -> Result<()> {
        let addr = server_addr(server)?;
        conn::clear_strict_pin(self.store(), &addr)?;
        self.notify_trust(&addr);
        Ok(())
    }

    /// Records the new fingerprint of a strictly pinned server, which the
    /// user approved after a
    /// [`TrustError::StrictMismatch`](crate::conn::TrustError::StrictMismatch).
    pub fn approve_new_pin(&self, server: &str, pinned: &str, presented: &str) -> Result<()> {
        let addr = server_addr(server)?;
        conn::approve_new_pin(
            self.store(),
            &addr,
            parse_fingerprint(pinned)?,
            parse_fingerprint(presented)?,
        )?;
        self.notify_trust(&addr);
        Ok(())
    }

    /// The pins that CA-valid certificates replaced, which the user has
    /// not dismissed yet (2.2).
    pub fn pin_notices(&self) -> Result<Vec<(ServerAddr, PinChange)>> {
        Ok(self.store().notices()?)
    }

    /// Dismisses the notice for `server`, once the user has seen it.
    pub fn dismiss_pin_notice(&self, server: &str) -> Result<()> {
        let addr = server_addr(server)?;
        self.store().dismiss_notice(&addr)?;
        self.notify_trust(&addr);
        Ok(())
    }

    /// The trust store connections use: the cache.
    pub(crate) fn trust(&self) -> Arc<dyn TrustStore> {
        Arc::new(self.store().clone())
    }

    /// The options for a new connection, with the client's CA check.
    pub(crate) fn session_options(&self) -> conn::SessionOptions {
        let mut options = self.options().session.clone();
        if let Some(ca) = &self.options().ca_verifier {
            options.ca_verifier = Some(ca.clone());
        }
        options
    }

    fn notify_trust(&self, addr: &ServerAddr) {
        self.emit(super::Event::Changed(crate::store::Change::Settings(
            crate::store::settings::SettingsChange::Trust(addr.clone()),
        )));
    }
}

fn parse_fingerprint(s: &str) -> Result<Fingerprint> {
    s.trim()
        .parse()
        .map_err(|_| Error::invalid("fingerprint", s))
}
