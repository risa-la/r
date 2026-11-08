//! Trust records (2.2) on SQLite.

use risala_proto::fingerprint::Fingerprint;
use rusqlite::{Connection, OptionalExtension, params};

use super::{Store, StoreError, parse};
use crate::addr::{ServerAddr, TrustRecord, TrustStore, TrustStoreError};

/// The record for `addr`, if any.
fn record(conn: &Connection, addr: &ServerAddr) -> Result<Option<TrustRecord>, StoreError> {
    let row: Option<(String, Option<String>)> = conn
        .query_row(
            "SELECT t.kind, t.fingerprint FROM trust t JOIN servers s ON s.id = t.server
             WHERE s.addr = ?1",
            [addr.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    Ok(match row {
        None => None,
        Some((kind, None)) if kind == "ca" => Some(TrustRecord::Ca),
        Some((kind, Some(fp))) if kind == "pinned" => {
            Some(TrustRecord::Pinned(parse(&fp, "fingerprint")?))
        }
        Some((kind, _)) => {
            return Err(StoreError::Corrupt(format!("bad trust record {kind:?}")));
        }
    })
}

impl From<StoreError> for TrustStoreError {
    fn from(e: StoreError) -> TrustStoreError {
        TrustStoreError(e.to_string())
    }
}

impl TrustStore for Store {
    fn get(&self, addr: &ServerAddr) -> Result<Option<TrustRecord>, TrustStoreError> {
        Ok(self.read(|conn| record(conn, addr))?)
    }

    fn set(&self, addr: &ServerAddr, record: TrustRecord) -> Result<(), TrustStoreError> {
        self.write(|tx| {
            let server = tx.server_id(addr)?;
            let (kind, fp) = match &record {
                TrustRecord::Ca => ("ca", None),
                TrustRecord::Pinned(fp) => ("pinned", Some(fp.to_string())),
            };
            tx.conn().execute(
                "INSERT INTO trust (server, kind, fingerprint) VALUES (?1, ?2, ?3)
                 ON CONFLICT (server) DO UPDATE SET kind = excluded.kind,
                     fingerprint = excluded.fingerprint",
                params![server, kind, fp],
            )?;
            Ok(())
        })?;
        Ok(())
    }

    fn pin_if_unknown(
        &self,
        addr: &ServerAddr,
        fingerprint: Fingerprint,
    ) -> Result<Option<TrustRecord>, TrustStoreError> {
        // One IMMEDIATE transaction: no other writer comes between the
        // check and the write.
        let (old, _) = self.write(|tx| {
            let old = record(tx.conn(), addr)?;
            if old.is_none() {
                let server = tx.server_id(addr)?;
                tx.conn().execute(
                    "INSERT INTO trust (server, kind, fingerprint) VALUES (?1, 'pinned', ?2)",
                    params![server, fingerprint.to_string()],
                )?;
            }
            Ok(old)
        })?;
        Ok(old)
    }

    fn forget(&self, addr: &ServerAddr) -> Result<(), TrustStoreError> {
        self.write(|tx| {
            tx.conn().execute(
                "DELETE FROM trust WHERE server = (SELECT id FROM servers WHERE addr = ?1)",
                [addr.to_string()],
            )?;
            Ok(())
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinning_keeps_any_record_there_is() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("cache.db")).unwrap();
        let a: ServerAddr = "chat.example.org".parse().unwrap();
        let (fp, other) = (
            Fingerprint::from_bytes([7; 32]),
            Fingerprint::from_bytes([8; 32]),
        );
        assert_eq!(store.pin_if_unknown(&a, fp).unwrap(), None);
        let pinned = Some(TrustRecord::Pinned(fp));
        assert_eq!(TrustStore::get(&store, &a).unwrap(), pinned);
        assert_eq!(store.pin_if_unknown(&a, other).unwrap(), pinned);
        assert_eq!(TrustStore::get(&store, &a).unwrap(), pinned);
        TrustStore::set(&store, &a, TrustRecord::Ca).unwrap();
        let ca = Some(TrustRecord::Ca);
        assert_eq!(store.pin_if_unknown(&a, fp).unwrap(), ca);
        assert_eq!(TrustStore::get(&store, &a).unwrap(), ca);
    }
}
