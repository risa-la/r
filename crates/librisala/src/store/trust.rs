//! Trust records (2.2) on SQLite.

use rusqlite::{OptionalExtension, params};

use super::{Store, StoreError, parse};
use crate::addr::{ServerAddr, TrustRecord, TrustStore, TrustStoreError};

impl From<StoreError> for TrustStoreError {
    fn from(e: StoreError) -> TrustStoreError {
        TrustStoreError(e.to_string())
    }
}

impl TrustStore for Store {
    fn get(&self, addr: &ServerAddr) -> Result<Option<TrustRecord>, TrustStoreError> {
        let record = self.read(|conn| {
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
        })?;
        Ok(record)
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
