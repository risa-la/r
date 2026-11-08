//! Key logs (4.5): the pure parts of checking records against them, with
//! `risala-keylog` doing the proofs.
//!
//! Owned by task C1 in docs/plans/M5b.md. Checking a record takes HTTPS
//! fetches from the log (its checkpoint, tiles, entry bundles and hints),
//! which the server is no part of, so the work happens in
//! [`crate::client::identity`], driven by the client rather than by lines
//! from the server. This module has what it needs that does no I/O: the
//! witness policy from the cache, the device's view of each log, and
//! where things are under a log's URL prefix.
//!
//! The engine has nothing to do with the server's lines: no line of
//! Section 13 is about key logs, since the server has no proof command
//! (4.5).

use risala_keylog::client::LogView;
use risala_keylog::hint::{NEXT_PATH, uid_hint_path};
use risala_keylog::tile::TileId;
use risala_keylog::witness::{Freshness, LogKey as KeylogKey, WitnessPolicy};
use risala_proto::record::LogKey;

use super::Engine;
use crate::store::keylog::LogRow;

/// The engine of this area, for one account. It has nothing to do with
/// the server's lines (see the module docs).
#[derive(Debug, Default)]
pub struct KeyLogEngine {}

impl Engine for KeyLogEngine {}

/// The apps' default witness list (4.10), as signed-note verifier keys,
/// and its k.
///
/// Empty for now: 4.10's list needs witnesses run by independent
/// organisations, and none runs yet. With no list, no checkpoint is
/// witnessed, every record stays pending, and the device shows that its
/// witness list does not fit the log (4.5). Development setups set their
/// own with [`Client::set_witness_policy`](crate::Client::set_witness_policy).
/// (4.10 asks for at least three; a choice to confirm.)
pub const DEFAULT_WITNESSES: (&[&str], usize) = (&[], 0);

/// The witness policy from what the cache holds, or the default if it
/// holds none; `None` if there is no usable policy, as with an empty
/// list.
pub fn policy(vkeys: &[String], k: Option<usize>) -> Option<WitnessPolicy> {
    match k {
        Some(k) => WitnessPolicy::from_vkeys(vkeys, k).ok(),
        None => {
            let (list, k) = DEFAULT_WITNESSES;
            WitnessPolicy::from_vkeys(list, k).ok()
        }
    }
}

/// `risala-keylog`'s form of a log's key, from a key file's.
pub fn keylog_key(log: &LogKey) -> Option<KeylogKey> {
    KeylogKey::from_vkey_str(&log.vkey()).ok()
}

/// The device's view of a log as the cache keeps it: its newest witnessed
/// checkpoint, checked again under `policy` with no limit on age, and its
/// hand-off. `None` if it has none, or none that is witnessed under the
/// policy now, as after the user changed it.
pub fn restore_view(row: &LogRow, key: &KeylogKey, policy: &WitnessPolicy) -> Option<LogView> {
    let text = row.checkpoint.as_ref()?;
    let witnessed = policy.verify(key, text.as_bytes(), Freshness::any()).ok()?;
    let handoff = match &row.handoff {
        Some((index, vkey)) => Some((*index, KeylogKey::from_vkey_str(vkey).ok()?)),
        None => None,
    };
    LogView::restore(key.clone(), witnessed, handoff).ok()
}

/// The URL of something a log serves, under its URL prefix.
pub fn url(prefix: &str, path: &str) -> String {
    format!("{prefix}/{path}")
}

/// The URL of a log's checkpoint [TLOG-TILES].
pub fn checkpoint_url(prefix: &str) -> String {
    url(prefix, "checkpoint")
}

/// The URL of a tile or entry bundle.
pub fn tile_url(prefix: &str, tile: &TileId) -> String {
    url(prefix, &tile.path())
}

/// The URL of a uid's hint (4.5).
pub fn uid_hint_url(prefix: &str, uid: &str) -> String {
    url(prefix, &uid_hint_path(uid))
}

/// The URL of a log's `risala/next` hint (4.5).
pub fn next_url(prefix: &str) -> String {
    url(prefix, NEXT_PATH)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        let p = "https://chat.example.org/risala-log/1";
        assert_eq!(checkpoint_url(p), format!("{p}/checkpoint"));
        assert_eq!(next_url(p), format!("{p}/risala/next"));
        assert!(uid_hint_url(p, "alice@example.org").starts_with(&format!("{p}/risala/uid/")));
        assert_eq!(
            tile_url(p, &TileId::hashes(0, 0, 3).unwrap()),
            format!("{p}/tile/0/000.p/3")
        );
    }

    #[test]
    fn no_default_list_means_no_policy() {
        assert!(policy(&[], None).is_none());
        assert!(policy(&["not a key".into()], Some(1)).is_none());
    }
}
