//! Key files and the device's own identities (4.4-4.8, 12.9, 12.14): the
//! parts that need no network.
//!
//! Owned by task C1 in docs/plans/M5b.md.
//!
//! - **The conversation with yourself** (12.9): [`handle_self_line`]
//!   takes RECORD, ALERT, RECORDS, SIGNINGKEY, BACKUPKEY and PIN lines
//!   that arrived there, and [`queue_line`] queues lines to send, which
//!   the conversations engine (task C2) takes with
//!   [`Client::take_self_lines`](crate::Client::take_self_lines).
//! - **Chains as kept** ([`kept_chain`]): the device's own identities'
//!   chains, with records not yet logged, for making the next record.
//! - **Sending** ([`send_check`]): whether a conversation may send to an
//!   identity (4.4, 4.5, 12.14).
//!
//! Fetching key files and checking them against the key log is in
//! [`crate::client::identity`], since it is HTTPS and not lines from the
//! server. The engine has no lines to handle: the server's RECORD lines
//! answer KEYS PUT, which the identity code sends on a connection of its
//! own (4.1), and PAIR lines answer PAIR GET, the same way.

use risala_proto::auth::SecretKey;
use risala_proto::chain::Chain;
use risala_proto::content::{BackupKey as BackupKeyLine, ContentLine, LogOrigin, Pin};
use risala_proto::names::{BlobRef, Identity};
use risala_proto::record::{LogKey, Record};

use super::Engine;
use crate::keys::{KeyNames, KeyStore};
use crate::store::identity::{ContactRow, KeysState, OwnRow, RecordRow};
use crate::store::{StoreError, Tx};

/// The engine of this area, for one account. It has nothing to do with
/// the server's lines (see the module docs).
#[derive(Debug, Default)]
pub struct IdentityEngine {}

impl Engine for IdentityEngine {}

/// The chain of the records kept of an identity, accepted or not, in the
/// logs they are kept under; or only the accepted ones. `None` if there
/// are none, or they do not replay (which they always do, since only
/// replayed chains are kept).
pub fn kept_chain(uid: &Identity, records: &[RecordRow], accepted_only: bool) -> Option<Chain> {
    let mut decoded = Vec::new();
    for row in records.iter().filter(|r| r.accepted || !accepted_only) {
        let record = Record::decode(&row.record).ok()?;
        let log = LogKey::from_vkey(&row.log.1).ok()?;
        decoded.push((record, log));
    }
    if decoded.is_empty() {
        return None;
    }
    Chain::replay_placed(
        uid,
        decoded.iter().map(|(r, l)| (r, Some(l))),
        // The chain was checked, hand-offs included, when it was kept.
        &|_: &LogKey, _: &LogKey| true,
    )
    .ok()
}

/// Why a conversation may not send to an identity, or warns (4.4, 4.5,
/// 12.14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StopReason {
    /// A new master key, or a new log, not yet acknowledged.
    NewMasterKey,
    /// A fork in its records or its log, or a rollback.
    Fork,
    /// Its key file is gone or not valid.
    KeysMissing,
}

/// Whether a conversation may send to an identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SendCheck {
    /// Yes.
    Send,
    /// Yes, and the user is told why not quite: in a room, an identity the
    /// device cannot check, and in a public room, a new master key.
    Warn(StopReason),
    /// No, until the user acts or a valid key file is back.
    Stop(StopReason),
}

/// The kinds of conversation, which the rules of 12.14 tell apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConversationKind {
    /// A direct conversation.
    Direct,
    /// A private room.
    PrivateRoom,
    /// A public room.
    PublicRoom,
}

/// Why the device cannot check an identity, if it cannot (12.14): it is
/// forked, or its keys are missing.
pub fn unchecked(contact: &ContactRow) -> Option<StopReason> {
    if contact.forked {
        Some(StopReason::Fork)
    } else if matches!(contact.keys, KeysState::Missing(_)) {
        Some(StopReason::KeysMissing)
    } else {
        None
    }
}

/// Whether a conversation of `kind` may send to an identity (4.5,
/// 12.14):
///
/// - An identity the device cannot check, forked or with its keys missing,
///   stops sending in a direct conversation with it. Rooms keep sending,
///   with a warning: there the device treats its leaves as unverified,
///   hides what they send, and outside public rooms removes them, which
///   the conversations area does (see [`unchecked`]). So nobody can stop a
///   room by forking their own chain.
/// - A new master key, not yet acknowledged, stops sending in direct
///   conversations and private rooms, and warns in public rooms.
pub fn send_check(contact: Option<&ContactRow>, kind: ConversationKind) -> SendCheck {
    let Some(c) = contact else {
        return SendCheck::Send;
    };
    let new_key = c
        .new_master_key
        .is_some()
        .then_some(StopReason::NewMasterKey);
    match (kind, unchecked(c), new_key) {
        (ConversationKind::Direct, Some(r), _) => SendCheck::Stop(r),
        (ConversationKind::Direct | ConversationKind::PrivateRoom, None, Some(r))
        | (ConversationKind::PrivateRoom, Some(_), Some(r)) => SendCheck::Stop(r),
        (_, Some(r), _) | (ConversationKind::PublicRoom, None, Some(r)) => SendCheck::Warn(r),
        (_, None, None) => SendCheck::Send,
    }
}

/// Whether a contact's view is stale at `now` (4.5): not refreshed for 7
/// days. A stale identity's devices are not added to groups.
pub fn is_stale(contact: &ContactRow, now: u64) -> bool {
    contact
        .refreshed
        .is_none_or(|t| now.saturating_sub(t) >= crate::client::identity::STALE_AFTER_MS)
}

/// Queues `line` for the conversation with yourself of `uid` (12.9).
pub(crate) fn queue_line(
    tx: &mut Tx<'_>,
    uid: &str,
    line: &ContentLine,
    now: u64,
) -> Result<(), StoreError> {
    let text = line
        .to_line()
        .map_err(|e| StoreError::Corrupt(format!("a line to send: {e}")))?;
    tx.push_self_line(uid, &text, now)
}

/// The PIN line of a contact (12.9), if the device has pinned it.
pub fn pin_line(contact: &ContactRow) -> Option<ContentLine> {
    let uid: Identity = contact.uid.parse().ok()?;
    let master = BlobRef::of(contact.master_key.as_ref()?);
    let origin: LogOrigin = contact.log_origin.as_ref()?.parse().ok()?;
    let head = contact.head?;
    Some(ContentLine::Pin(Pin {
        uid,
        master,
        origin,
        head,
        verified: contact.verified,
    }))
}

/// Queues the PIN line of `contact` for each identity this device holds
/// other than the contact itself (12.9): a device sends one when it pins
/// an identity or a pin or mark changes.
pub(crate) fn queue_pin(
    tx: &mut Tx<'_>,
    own: &[String],
    contact: &ContactRow,
    now: u64,
) -> Result<(), StoreError> {
    let Some(line) = pin_line(contact) else {
        return Ok(());
    };
    for uid in own.iter().filter(|u| **u != contact.uid) {
        queue_line(tx, uid, &line, now)?;
    }
    Ok(())
}

/// What a line of the conversation with yourself asks of the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelfEffect {
    /// Nothing.
    None,
    /// Another device alerts: someone else may control the identity
    /// (4.5).
    Alert(BlobRef),
    /// The device-signing key or backup key was taken.
    KeyTaken,
}

/// Handles one line that arrived in the conversation with yourself of
/// `own`, from a leaf of the identity's own that the device has confirmed
/// (12.9: the caller checks that).
///
/// - RECORD and RECORDS with hashes note the records as announced, and
///   RECORDS without asks for this device's list, which it queues (4.5).
/// - ALERT is shown to the user.
/// - SIGNINGKEY is taken only if its seed gives the device-signing key of
///   the newest `signing` or `master` record the device has accepted, and
///   BACKUPKEY only for the chain's generation (12.9).
/// - PIN gives a pin for an identity the device has not pinned, makes it
///   check again one whose master key differs, and takes the verified
///   mark when the master keys agree (12.9).
pub(crate) fn handle_self_line(
    tx: &mut Tx<'_>,
    keys: &dyn KeyStore,
    own: &OwnRow,
    line: &ContentLine,
    now: u64,
) -> Result<SelfEffect, crate::client::Error> {
    let uid = own.uid.as_str();
    match line {
        ContentLine::Record(hash) => {
            tx.add_announced(uid, hash)?;
        }
        ContentLine::Alert(hash) => return Ok(SelfEffect::Alert(*hash)),
        ContentLine::Records(None) => {
            // The answer is `RECORDS -` when this device knows of none
            // (12.9).
            let mut known: Vec<BlobRef> = Vec::new();
            for r in tx.records(uid)? {
                if r.mine || tx.is_announced(uid, &r.hash)? {
                    known.push(r.hash);
                }
            }
            queue_line(tx, uid, &ContentLine::Records(Some(known)), now)?;
        }
        ContentLine::Records(Some(hashes)) => {
            for hash in hashes {
                tx.add_announced(uid, hash)?;
            }
        }
        ContentLine::SigningKey(seed) => {
            let identity: Identity = parse_uid(uid)?;
            let Some(chain) = kept_chain(&identity, &tx.records(uid)?, true) else {
                return Ok(SelfEffect::None);
            };
            let key = SecretKey::from_seed(*seed.as_bytes());
            if key.public_key() == *chain.signing_key() {
                keys.save_seed(&KeyNames::new(&own.key_id).signing(), seed.as_bytes())?;
                return Ok(SelfEffect::KeyTaken);
            }
        }
        ContentLine::BackupKey { generation, key } => {
            let identity: Identity = parse_uid(uid)?;
            let Some(chain) = kept_chain(&identity, &tx.records(uid)?, true) else {
                return Ok(SelfEffect::None);
            };
            if *generation == chain.generation() {
                keys.save_seed(&KeyNames::new(&own.key_id).backup(), key.as_bytes())?;
                tx.set_backup_generation(uid, *generation)?;
                return Ok(SelfEffect::KeyTaken);
            }
        }
        ContentLine::Pin(pin) if pin.uid.as_str() != uid => {
            let mut c = tx
                .contact(pin.uid.as_str())?
                .unwrap_or_else(|| ContactRow::new(pin.uid.as_str()));
            match &c.master_key {
                None => {
                    c.pin_hint = Some((pin.master, pin.origin.to_string()));
                    c.verified = pin.verified;
                }
                Some(key) if BlobRef::of(key) == pin.master => {
                    c.verified = pin.verified;
                }
                // The other device pinned another master key: check the
                // identity again now. (12.9 says to treat it as a new
                // master key, but a PIN line carries only the key's hash;
                // the fetch finds the key itself. A choice to confirm.)
                Some(_) => c.next_check = Some(now),
            }
            tx.put_contact(&c)?;
        }
        _ => {}
    }
    Ok(SelfEffect::None)
}

/// The BACKUPKEY line for a backup key.
pub fn backup_key_line(generation: u32, key: &[u8; 32]) -> ContentLine {
    ContentLine::BackupKey {
        generation,
        key: BackupKeyLine::from_bytes(*key),
    }
}

fn parse_uid(uid: &str) -> Result<Identity, crate::client::Error> {
    uid.parse()
        .map_err(|_| crate::client::Error::invalid("identity", uid))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_stops_sending() {
        use ConversationKind::{Direct, PrivateRoom, PublicRoom};
        let mut c = ContactRow::new("bob@example.org");
        for kind in [Direct, PrivateRoom, PublicRoom] {
            assert_eq!(send_check(Some(&c), kind), SendCheck::Send);
            assert_eq!(send_check(None, kind), SendCheck::Send);
        }
        // Keys missing, or a fork: only direct conversations stop (12.14).
        for (reason, set) in [
            (
                StopReason::KeysMissing,
                (|c: &mut ContactRow| c.keys = KeysState::Missing("HTTP 410".into()))
                    as fn(&mut ContactRow),
            ),
            (StopReason::Fork, |c: &mut ContactRow| c.forked = true),
        ] {
            let mut c = ContactRow::new("bob@example.org");
            set(&mut c);
            assert_eq!(unchecked(&c), Some(reason));
            assert_eq!(send_check(Some(&c), Direct), SendCheck::Stop(reason));
            assert_eq!(send_check(Some(&c), PrivateRoom), SendCheck::Warn(reason));
            assert_eq!(send_check(Some(&c), PublicRoom), SendCheck::Warn(reason));
        }
        // A new master key stops direct conversations and private rooms,
        // and warns in public rooms.
        c.new_master_key = Some(vec![1]);
        let nmk = StopReason::NewMasterKey;
        assert_eq!(send_check(Some(&c), Direct), SendCheck::Stop(nmk));
        assert_eq!(send_check(Some(&c), PrivateRoom), SendCheck::Stop(nmk));
        assert_eq!(send_check(Some(&c), PublicRoom), SendCheck::Warn(nmk));
        c.forked = true;
        assert_eq!(
            send_check(Some(&c), Direct),
            SendCheck::Stop(StopReason::Fork)
        );
        assert_eq!(send_check(Some(&c), PrivateRoom), SendCheck::Stop(nmk));
    }

    #[test]
    fn staleness() {
        let mut c = ContactRow::new("bob@example.org");
        assert!(is_stale(&c, 0));
        c.refreshed = Some(1000);
        assert!(!is_stale(&c, 1000 + 6 * 24 * 3600 * 1000));
        assert!(is_stale(&c, 1000 + 7 * 24 * 3600 * 1000));
    }
}
