//! OpenMLS storage in SQLite, for librisala (PLAN.md 22, 43).
//!
//! A port of `openmls_sqlite_storage` 0.3.0 by the OpenMLS Authors (MIT) to
//! the workspace's rusqlite. The upstream crate pins an older rusqlite, and
//! two versions of it cannot be linked into one binary. It keeps the
//! upstream name and version, so that the workspace's `[patch.crates-io]`
//! puts it in place of the upstream crate, which OpenMLS lists as an
//! optional dependency. The changes:
//!
//! - The tables come as [`SCHEMA`], for the caller to run as one of its own
//!   migrations, instead of through refinery. They are the upstream tables
//!   after its migrations 1 and 2, without the virtual-client tables.
//! - The `virtual-clients-draft` and `extensions-draft` features are gone.
//!   risala uses neither.
//! - [`MsgPack`] is a binary [`Codec`].
//!
//! [`SqliteStorageProvider`] borrows a [`Connection`], so it works inside
//! the caller's transaction: an MLS operation either stores all its changes
//! or none. Load groups again inside every transaction, since another
//! process may have changed them.

#[cfg(doc)]
use openmls_traits::storage::StorageProvider;

#[cfg(doc)]
use serde::{Serialize, de::DeserializeOwned};

mod codec;
mod encryption_key_pairs;
mod epoch_key_pairs;
mod group_data;
mod key_packages;
mod own_leaf_nodes;
mod proposals;
mod psks;
mod signature_key_pairs;
mod storage_provider;
mod wrappers;

pub use codec::{Codec, MsgPack};
pub use rusqlite::Connection;
pub use storage_provider::SqliteStorageProvider;

/// The version of the storage provider. If the `CURRENT_VERSION` of the OpenMLS
/// storage provider trait changes, the read/write/delete functions of the
/// affected data types must be updated and a migration file must be created to
/// migrate the database's schema and its content. Only then may this version be
/// incremented to match the `CURRENT_VERSION`.
const STORAGE_PROVIDER_VERSION: u16 = 1;

/// The tables [`SqliteStorageProvider`] uses, all prefixed `openmls_`.
///
/// Run it once, in a migration of the caller's schema. A later change to
/// these tables comes as a further statement for the caller to add as a new
/// migration.
pub const SCHEMA: &str = "
CREATE TABLE openmls_encryption_keys (
    provider_version INTEGER NOT NULL,
    public_key BLOB PRIMARY KEY,
    key_pair BLOB NOT NULL
);

CREATE TABLE openmls_epoch_keys_pairs (
    provider_version INTEGER NOT NULL,
    group_id BLOB NOT NULL,
    epoch_id BLOB NOT NULL,
    leaf_index INTEGER NOT NULL,
    key_pairs BLOB NOT NULL,
    PRIMARY KEY (group_id, epoch_id, leaf_index)
);

CREATE TABLE openmls_group_data (
    provider_version INTEGER NOT NULL,
    group_id BLOB NOT NULL,
    data_type TEXT NOT NULL CHECK (data_type IN (
        'join_group_config',
        'tree',
        'interim_transcript_hash',
        'context',
        'confirmation_tag',
        'group_state',
        'message_secrets',
        'resumption_psk_store',
        'own_leaf_index',
        'use_ratchet_tree_extension',
        'group_epoch_secrets'
    )),
    group_data BLOB NOT NULL,
    PRIMARY KEY (group_id, data_type)
);

CREATE TABLE openmls_key_packages (
    provider_version INTEGER NOT NULL,
    key_package_ref BLOB PRIMARY KEY,
    key_package BLOB NOT NULL
);

CREATE TABLE openmls_own_leaf_nodes (
    provider_version INTEGER NOT NULL,
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id BLOB NOT NULL,
    leaf_node BLOB NOT NULL
);

CREATE TABLE openmls_proposals (
    provider_version INTEGER NOT NULL,
    group_id BLOB NOT NULL,
    proposal_ref BLOB NOT NULL,
    proposal BLOB NOT NULL,
    PRIMARY KEY (group_id, proposal_ref)
);

CREATE TABLE openmls_psks (
    provider_version INTEGER NOT NULL,
    psk_id BLOB PRIMARY KEY,
    psk_bundle BLOB NOT NULL
);

CREATE TABLE openmls_signature_keys (
    provider_version INTEGER NOT NULL,
    public_key BLOB PRIMARY KEY,
    signature_key BLOB NOT NULL
);
";
