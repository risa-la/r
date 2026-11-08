//! OpenMLS's state in the cache (12, PLAN.md 22, 43).
//!
//! Owned by task C2. OpenMLS keeps its groups, KeyPackages, proposals and
//! keys, the per-group leaf keys among them (12.3), in the cache's
//! `openmls_*` tables, through [`openmls_sqlite_storage`]. An MLS
//! operation runs inside [`Store::write_with`](super::Store::write_with),
//! with a provider whose storage is [`Tx::mls_storage`]: the operation's
//! state and the cache's own rows then commit together, or roll back
//! together if anything fails, as when a Welcome cannot be processed and
//! its KeyPackage must be kept.
//!
//! Another process may change a group at any time, so load it with
//! `MlsGroup::load` inside every transaction that uses it, and never keep
//! an `MlsGroup` across transactions.

use openmls_sqlite_storage::{MsgPack, SqliteStorageProvider};
use rusqlite::Connection;

use super::Tx;

/// This area's part of the schema: `openmls_sqlite_storage`'s tables.
pub(crate) const SCHEMA: &str = openmls_sqlite_storage::SCHEMA;

/// OpenMLS storage on one of the cache's connections, usually a write
/// transaction. Its codec is MessagePack.
#[allow(dead_code, reason = "for the group engine, task C2")]
pub(crate) type MlsStorage<'a> = SqliteStorageProvider<MsgPack, &'a Connection>;

impl Tx<'_> {
    /// OpenMLS storage inside this transaction, for the provider of an MLS
    /// operation.
    #[allow(dead_code, reason = "for the group engine, task C2")]
    pub(crate) fn mls_storage(&self) -> MlsStorage<'_> {
        SqliteStorageProvider::new(self.conn())
    }
}

#[cfg(test)]
mod tests {
    use openmls::prelude::*;
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_libcrux_crypto::CryptoProvider;
    use openmls_traits::OpenMlsProvider;

    use super::*;
    use crate::store::{DatabaseKey, Store, StoreError};

    const CS: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

    /// A provider as the group engine will have one: crypto, and the
    /// cache's storage on a transaction or connection.
    struct Provider<'a> {
        crypto: CryptoProvider,
        storage: MlsStorage<'a>,
    }

    impl<'a> Provider<'a> {
        fn on(storage: MlsStorage<'a>) -> Self {
            Provider {
                crypto: CryptoProvider::new().unwrap(),
                storage,
            }
        }
    }

    impl<'a> OpenMlsProvider for Provider<'a> {
        type CryptoProvider = CryptoProvider;
        type RandProvider = CryptoProvider;
        type StorageProvider = MlsStorage<'a>;

        fn storage(&self) -> &Self::StorageProvider {
            &self.storage
        }
        fn crypto(&self) -> &CryptoProvider {
            &self.crypto
        }
        fn rand(&self) -> &CryptoProvider {
            &self.crypto
        }
    }

    /// An MLS operation's error, or the cache's.
    #[derive(Debug)]
    enum Error {
        Store(StoreError),
        Mls(String),
    }

    impl From<StoreError> for Error {
        fn from(e: StoreError) -> Error {
            Error::Store(e)
        }
    }

    fn mls(e: impl std::fmt::Debug) -> Error {
        Error::Mls(format!("{e:?}"))
    }

    struct Device {
        signer: SignatureKeyPair,
        credential: CredentialWithKey,
    }

    fn device() -> Device {
        let signer = SignatureKeyPair::new(CS.signature_algorithm()).unwrap();
        let credential = CredentialWithKey {
            credential: BasicCredential::new(b"alice".to_vec()).into(),
            signature_key: signer.public().into(),
        };
        Device { signer, credential }
    }

    /// The group's epoch and exporter secret, read from the cache.
    fn epoch(store: &Store, id: &GroupId) -> Option<(u64, Vec<u8>)> {
        store
            .read(|conn| {
                let p = Provider::on(SqliteStorageProvider::new(conn));
                Ok(MlsGroup::load(p.storage(), id).unwrap().map(|g| {
                    let secret = g.export_secret(p.crypto(), "test", b"", 32).unwrap();
                    (g.epoch().as_u64(), secret)
                }))
            })
            .unwrap()
    }

    fn servers(store: &Store) -> i64 {
        store
            .read(|conn| Ok(conn.query_row("SELECT count(*) FROM servers", [], |r| r.get(0))?))
            .unwrap()
    }

    /// Commits an update of the device's own leaf in one write, with a row
    /// of the cache's own, and fails afterwards if `fail`.
    fn commit(store: &Store, id: &GroupId, alice: &Device, fail: bool) -> Result<u64, Error> {
        let (epoch, _) = store.write_with(|tx| {
            tx.server_id(&"chat.example.org".parse().unwrap())?;
            let p = Provider::on(tx.mls_storage());
            let mut group = MlsGroup::load(p.storage(), id)
                .map_err(mls)?
                .ok_or(Error::Mls("no group".into()))?;
            group
                .self_update(&p, &alice.signer, LeafNodeParameters::default())
                .map_err(mls)?;
            group.merge_pending_commit(&p).map_err(mls)?;
            if fail {
                return Err(Error::Mls("failed after the merge".into()));
            }
            Ok(group.epoch().as_u64())
        })?;
        Ok(epoch)
    }

    #[test]
    fn mls_state_commits_and_rolls_back_with_the_cache() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        let store = Store::open(&path, &DatabaseKey::for_tests()).unwrap();
        let alice = device();

        let (id, _) = store
            .write_with(|tx| {
                let p = Provider::on(tx.mls_storage());
                let group = MlsGroup::builder()
                    .ciphersuite(CS)
                    .build(&p, &alice.signer, alice.credential.clone())
                    .map_err(mls)?;
                Ok::<_, Error>(group.group_id().clone())
            })
            .unwrap();
        let (_, first) = epoch(&store, &id).unwrap();

        // A failure after the merge leaves the group and the cache's rows
        // as they were.
        match commit(&store, &id, &alice, true).unwrap_err() {
            Error::Mls(e) => assert_eq!(e, "failed after the merge"),
            Error::Store(e) => panic!("{e}"),
        }
        assert_eq!(epoch(&store, &id), Some((0, first.clone())));
        assert_eq!(servers(&store), 0);

        // Done again without failing, both are stored.
        assert_eq!(commit(&store, &id, &alice, false).unwrap(), 1);
        let (n, second) = epoch(&store, &id).unwrap();
        assert_eq!(n, 1);
        assert_ne!(second, first);
        assert_eq!(servers(&store), 1);

        // Another process sees the same group, and its commits are seen
        // here.
        let other = Store::open(&path, &DatabaseKey::for_tests()).unwrap();
        assert_eq!(epoch(&other, &id), Some((1, second)));
        assert_eq!(commit(&other, &id, &alice, false).unwrap(), 2);
        assert_eq!(epoch(&store, &id).unwrap().0, 2);
    }

    #[test]
    fn the_schema_has_the_mls_tables() {
        let store = Store::open_in_memory().unwrap();
        let tables: Vec<String> = store
            .read(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT name FROM sqlite_schema
                     WHERE type = 'table' AND name LIKE 'openmls_%' ORDER BY name",
                )?;
                let names = stmt.query_map([], |r| r.get(0))?;
                Ok(names.collect::<Result<_, _>>()?)
            })
            .unwrap();
        assert_eq!(
            tables,
            [
                "openmls_encryption_keys",
                "openmls_epoch_keys_pairs",
                "openmls_group_data",
                "openmls_key_packages",
                "openmls_own_leaf_nodes",
                "openmls_proposals",
                "openmls_psks",
                "openmls_signature_keys",
            ]
        );
    }
}
