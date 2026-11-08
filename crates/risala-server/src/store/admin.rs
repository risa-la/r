//! Storage for the ADMIN commands (Section 10), except ADMIN PURGE, which
//! is in [`super::MessageStore`], and ADMIN REPORTS, ROOMS and DROP, which
//! are in [`super::ReportStore`].

use risala_proto::auth::PublicKey;
use risala_proto::names::{ServerBanTarget, Uid};
use risala_proto::time::Timestamp;

use super::{KeyChange, Result};

/// A server-wide ban (10.2), as stored and as `ADMIN BANS` lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerBan {
    /// What is banned: an identity, a domain, an address or a prefix. A
    /// ban of a guest is stored under its address (10.2), never as
    /// [`ServerBanTarget::Guest`].
    pub target: ServerBanTarget,
    /// Why, escaped (3.4); empty if none.
    pub reason: String,
    /// When the ban was made, or last changed.
    pub t: Timestamp,
}

/// Part of [`super::Store`]: see the module documentation.
///
/// Every method blocks, like the rest of [`super::Store`].
pub trait AdminStore {
    /// Stores `uid` as an operator added with ADMIN OP (10.1). Returns
    /// `false` if it was one already, and changes nothing then.
    fn add_operator(&self, uid: &Uid, now: Timestamp) -> Result<bool>;

    /// Removes an operator added with ADMIN OP (10.1). Returns whether
    /// there was one to remove.
    fn remove_operator(&self, uid: &Uid) -> Result<bool>;

    /// Every server ban (10.2), in the byte order of their targets' wire
    /// form.
    fn server_bans(&self) -> Result<Vec<ServerBan>>;

    /// Stores a server ban (10.2). A ban of the same target is replaced,
    /// with the new reason and time.
    fn add_server_ban(&self, ban: &ServerBan) -> Result<()>;

    /// Removes the server ban of `target` (10.2). Returns whether there
    /// was one.
    fn remove_server_ban(&self, target: &ServerBanTarget) -> Result<bool>;

    /// Removes `key` from the hosted identity `uid`, as
    /// [`Store::delete_hosted_key`](super::Store::delete_hosted_key) does,
    /// except that it may remove the last key, which locks the identity
    /// (ADMIN DELKEY, 10.5). Never returns [`KeyChange::LastKey`].
    fn remove_any_hosted_key(&self, uid: &Uid, key: &PublicKey) -> Result<KeyChange>;
}
