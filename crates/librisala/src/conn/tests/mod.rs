//! Tests against a scripted TLS server.

pub(crate) mod server;
mod session;
mod supervisor;
mod trust;

use std::sync::Arc;

use crate::addr::{
    MemoryTrustStore, Replaced, ServerAddr, TrustRecord, TrustStore, TrustStoreError,
};

use super::{Session, SessionOptions, roots_ca_verifier};
use server::{ScriptServer, TestCa};

/// The address the tests connect as. The socket address comes from
/// `connect_to`, so SNI and trust records use this name.
fn chat_test() -> ServerAddr {
    "chat.test".parse().unwrap()
}

fn options(ca: &TestCa, server: &ScriptServer) -> SessionOptions {
    SessionOptions {
        ca_verifier: Some(roots_ca_verifier([ca.cert.clone()]).unwrap()),
        connect_to: Some(server.addr),
        ..SessionOptions::default()
    }
}

fn store() -> Arc<dyn TrustStore> {
    Arc::new(MemoryTrustStore::default())
}

/// Connects to `server` as `chat.test` with the test CA.
async fn connect(
    ca: &TestCa,
    server: &ScriptServer,
    trust: &Arc<dyn TrustStore>,
) -> Result<Session, super::Error> {
    Session::connect(&chat_test(), trust.clone(), options(ca, server)).await
}

/// Sets a record whatever was there, as tests need to.
pub(crate) trait SetRecord {
    fn set(&self, addr: &ServerAddr, record: TrustRecord) -> Result<(), TrustStoreError>;
}

impl SetRecord for dyn TrustStore {
    fn set(&self, addr: &ServerAddr, record: TrustRecord) -> Result<(), TrustStoreError> {
        let current = self.get(addr)?;
        match self.replace(addr, current.as_ref(), record, None)? {
            Replaced::Done => Ok(()),
            Replaced::Found(_) => Err(TrustStoreError("changed meanwhile".into())),
        }
    }
}
