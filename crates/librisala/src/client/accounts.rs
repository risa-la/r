//! Accounts: an identity this device holds, on a server it uses (4.1), or
//! a guest on a server (4.2).
//!
//! Owned by task C0. Creating an identity, and with it its first account,
//! is the identity area's ([`Client::create_identity`]); this adds
//! accounts for identities already on this device, and guests.

use super::servers::server_addr;
use super::types::Account;
use super::{Client, Error, Result};
use crate::store::{AccountId, AccountKind};

impl Client {
    /// Every account, in the order they were added.
    pub fn accounts(&self) -> Result<Vec<Account>> {
        Ok(self
            .store()
            .accounts()?
            .into_iter()
            .map(Account::from)
            .collect())
    }

    /// The account with this id.
    pub fn account(&self, id: AccountId) -> Result<Account> {
        self.accounts()?
            .into_iter()
            .find(|a| a.id == id)
            .ok_or(Error::NoAccount)
    }

    /// Adds a guest account, `~<name>` on `server` (4.2), or returns the
    /// one there is.
    pub fn add_guest(&self, server: &str, name: &str) -> Result<Account> {
        let addr = server_addr(server)?;
        let name: risala_proto::names::Name = name
            .parse()
            .map_err(|_| Error::invalid("guest name", name))?;
        let uid = risala_proto::names::Uid::guest(&name);
        let id = self.store().add_account(&addr, AccountKind::Guest, &uid)?;
        self.account(id)
    }

    /// Adds an account for `identity`, which this device holds, on
    /// `server`, so that it can have conversations there (5.1).
    pub fn add_identity_account(&self, server: &str, identity: &str) -> Result<Account> {
        let addr = server_addr(server)?;
        let uid: risala_proto::names::Uid = identity
            .parse()
            .map_err(|_| Error::invalid("identity", identity))?;
        if uid.is_guest() {
            return Err(Error::invalid("identity", identity));
        }
        // Task C1: refuse an identity this device does not hold.
        let id = self
            .store()
            .add_account(&addr, AccountKind::Identity, &uid)?;
        self.account(id)
    }

    /// Removes an account and everything kept for it, after stopping its
    /// connections. It does not leave its conversations or unregister.
    pub async fn remove_account(&self, id: AccountId) -> Result<()> {
        self.disconnect(id).await?;
        self.blocking(move |c| Ok(c.store().remove_account(id)?))
            .await
    }
}
