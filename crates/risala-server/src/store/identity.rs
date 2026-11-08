//! What the server keeps about identities (4.6-4.9, 10.5): the identities
//! that have signed in here, the identities it hosts with their chains of
//! records, its pins on the identities it does not host, and pairing
//! messages.
//!
//! Tables (`sqlite/identity.rs`):
//!
//! - `accounts`: every identity that has signed in here and not
//!   unregistered since (4.9). KEYPKG GET (12.5) and WHOIS (8.3) answer
//!   `not-found` for one that is not here.
//! - `hosted`: the names the server hosts under its identity domain (4.7),
//!   kept once unregistered so that the name is never registered again
//!   and its key file answers 410 (4.9, 10.5).
//! - `records`: the chains of records the server keeps, for hosted
//!   identities and identities whose chains name its log (4.4, 4.7), in
//!   chain order, each with its index in the key log once logged. They
//!   mirror the log, which never removes an entry, so they are never
//!   deleted either.
//! - `pins`: for each identity the server does not host, the master key
//!   of the first chain it accepted and the newest record it holds of it
//!   (4.6), until ADMIN UNREGISTER or UNREGISTER clears it (4.9, 10.5).
//! - `pairing`: PAIR PUT's messages, for 10 minutes (4.8), by the hash of
//!   their id, which is a bearer secret (Section 14).

use risala_proto::chain::Pin;
use risala_proto::names::{BlobRef, Identity, Name, Uid};
use risala_proto::time::Timestamp;

use super::Result;

/// One record of a chain, as the server keeps it (4.4, 4.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRecord {
    /// The encoded Record.
    pub record: Vec<u8>,
    /// Its SHA-384 hash.
    pub hash: BlobRef,
    /// Its index in the server's key log, if the server logged it (4.5).
    /// Records that belong to another log of the chain have none.
    pub log_index: Option<u64>,
}

/// A name hosted under the identity domain (4.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedName {
    /// The identity, `<name>@<identity domain>`.
    pub identity: Identity,
    /// When it was registered.
    pub registered: Timestamp,
    /// When it was unregistered, if it was (4.9, 10.5): its key file then
    /// answers 410, unless its chain ends with a `retire` record.
    pub unregistered: Option<Timestamp>,
}

/// What PAIR PUT did (4.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairPut {
    /// The data is stored under the id.
    Stored,
    /// The id already holds the same data: `OK` again.
    Same,
    /// The id holds other data: `ERR name-taken`.
    Taken,
}

/// Identities on this server (4.6-4.9, 10.5).
pub trait IdentityStore {
    /// Notes that `uid` signed in at `now` (4.6), and returns whether the
    /// server did not know it before.
    fn note_sign_in(&self, uid: &Uid, now: Timestamp) -> Result<bool>;

    /// Whether `uid` has signed in here and not unregistered since (4.9).
    fn knows(&self, uid: &Uid) -> Result<bool>;

    /// Forgets that `uid` signed in here. Returns whether it was known.
    fn forget(&self, uid: &Uid) -> Result<bool>;

    /// The hosted name `name`, if it was ever registered (4.7).
    fn hosted(&self, name: &Name) -> Result<Option<HostedName>>;

    /// Every name ever registered here, unregistered ones included, in
    /// order.
    fn hosted_names(&self) -> Result<Vec<Name>>;

    /// Registers `name` as `identity` at `now`, with the first records of
    /// its chain (4.7), in one transaction. Returns `false`, and changes
    /// nothing, if the name was ever registered, or the server already
    /// holds records of the identity.
    fn register(
        &self,
        name: &Name,
        identity: &Identity,
        records: &[StoredRecord],
        now: Timestamp,
    ) -> Result<bool>;

    /// The records the server holds of `identity`'s chain, oldest first;
    /// empty if it holds none.
    fn chain_records(&self, identity: &Identity) -> Result<Vec<StoredRecord>>;

    /// Adds `records` to `identity`'s chain, from position `from` (the
    /// number of records it holds now). Fails, and changes nothing, if it
    /// holds another number of records.
    fn add_records(&self, identity: &Identity, from: usize, records: &[StoredRecord])
    -> Result<()>;

    /// The server's pin on `identity`, which it does not host (4.6).
    fn pin(&self, identity: &Identity) -> Result<Option<Pin>>;

    /// Pins `identity`, or moves its head forward (4.6). The caller has
    /// checked that the new head extends the old one.
    fn set_pin(&self, identity: &Identity, pin: &Pin, now: Timestamp) -> Result<()>;

    /// Deletes everything the server keeps about `uid`, as UNREGISTER and
    /// ADMIN UNREGISTER do (4.9, 10.5), at `now`, in one transaction: its
    /// account, its pin, its KeyPackages and the Welcomes waiting for its
    /// devices, its account push subscriptions, its backup and its
    /// presence setting, and marks a hosted name unregistered. Its records
    /// stay, as the log's do. Returns whether the server knew anything of
    /// it.
    fn unregister(&self, uid: &Uid, now: Timestamp) -> Result<bool>;

    /// Stores pairing `data` under `id_hash` until `expires` (4.8), unless
    /// it holds something there that has not expired at `now`.
    fn pair_put(
        &self,
        id_hash: &[u8; 48],
        data: &[u8],
        expires: Timestamp,
        now: Timestamp,
    ) -> Result<PairPut>;

    /// The pairing data under `id_hash`, if it has not expired at `now`.
    fn pair_get(&self, id_hash: &[u8; 48], now: Timestamp) -> Result<Option<Vec<u8>>>;

    /// Deletes the pairing data that has expired at `now`, and returns how
    /// many there were.
    fn expire_pairing(&self, now: Timestamp) -> Result<usize>;
}
