//! Confirming leaves (12.10): pairwise CHALLENGE and ANSWER, and epochal
//! ATTEST and REVEAL with period keys.
//!
//! Owned by task C3 in docs/plans/M5b.md.
//!
//! # Shape
//!
//! Each group's state is risala-mls's [`Confirmer`], kept in the cache
//! (store/confirm.rs) and driven from two places:
//!
//! - **The group engine's hooks** ([`super::conversations::Hooks`]), inside
//!   the transaction that applies a post: after each commit or join the
//!   Confirmer gets the group's leaves and, for an authority commit, its
//!   committer ([`Confirm::commit_applied`], [`Confirm::leaves_changed`]);
//!   each message it applies ([`Confirm::message_received`]), which also
//!   says whether to show it as verified (12.9 step 6); and each message
//!   about to be posted, which carries the pending lines
//!   ([`Confirm::outgoing`]), piggy-backed as 12.10 asks.
//! - **[`ConfirmEngine`]**, on the driver's ticks: deadlines (impostors,
//!   the 24 hours of the conversation with yourself), lines that rode in no
//!   message and are now due on their own, REVEALs, the daily leaf
//!   rotation of epochal groups, and removing impostors after a random
//!   wait (12.7).
//!
//! The device's own keys come through [`OwnKeys`], and what it knows of
//! other devices through [`Directory`]: the identity area (task C1)
//! provides both.

use std::sync::{Arc, OnceLock};

use risala_mls::checks::{EpochState, GroupView};
use risala_mls::confirm::{
    AttestationKey, DeviceDirectory, DeviceStatus, Event as ConfirmerEvent, ImpostorReason,
    Incoming, LeafInfo, OwnDevice,
};
use risala_mls::conversation::{ConfirmMode, ConversationKind, RisalaConversation, Role};
use risala_mls::epochal::{self, PeriodKeyring, RevealRegistry};
use risala_mls::identity::RisalaIdentity;
use risala_mls::message::{Decrypted, MessageHistory as _, Order, PseudonymCheck, RisalaMessage};
use risala_mls::mldsa::SigningKey;
use risala_mls::openmls::group::MlsGroup;
use risala_mls::openmls::prelude::GroupId;
use risala_mls::openmls_traits::OpenMlsProvider as _;
use risala_mls::{Confirmer, LeafState, Pseudonym, RisalaCrypto};
use risala_proto::content::{Content, ContentLine};
use risala_proto::names::Uid;
use risala_proto::time::Timestamp;

use super::conversations::wire::Intent;
use super::conversations::{EngineError, content, group, random_below};
use super::{Action, Context, Engine, Input};
use crate::client::Event;
use crate::client::confirm::{ConfirmEvent, ConfirmKind};
use crate::clock::{Clock, SystemClock};
use crate::store::confirm::{LeafConfirmation, LeafConfirmationRow};
use crate::store::conversations::{ConvKind, ConvRow, ConversationId, LeafRow};
use crate::store::messages::{MessageLog, OutboxKind, OutboxState};
use crate::store::{AccountId, StoreError, Tx};

type Result<T> = std::result::Result<T, EngineError>;

/// The longest random wait before removing an impostor (12.7): 10 minutes.
pub const REPAIR_WITHIN_MS: u64 = 10 * 60_000;

/// This device's own secrets for confirmation, from the platform key store
/// (4.3, 4.4). The identity area (task C1) keeps them.
pub(crate) trait OwnKeys: Send + Sync {
    /// The device key of this device for `uid`, which certifies period
    /// keys (12.10).
    fn device_key(&self, tx: &Tx<'_>, uid: &Uid) -> Option<SigningKey>;
    /// The attestation key of this device for `uid`, which answers
    /// challenges (12.10).
    fn attestation_key(&self, tx: &Tx<'_>, uid: &Uid) -> Option<AttestationKey>;
}

/// No keys: nothing is answered or attested.
#[derive(Debug, Default)]
pub(crate) struct NoKeys;

impl OwnKeys for NoKeys {
    fn device_key(&self, _: &Tx<'_>, _: &Uid) -> Option<SigningKey> {
        None
    }

    fn attestation_key(&self, _: &Tx<'_>, _: &Uid) -> Option<AttestationKey> {
        None
    }
}

/// What this device knows of the device a credential names: whether it is
/// a current, logged device of its identity, and its keys (4.4, 4.5).
pub(crate) trait Directory: Send + Sync {
    /// The device that `identity` names. Never asked for guests.
    fn device(&self, tx: &Tx<'_>, identity: &RisalaIdentity) -> DeviceStatus;
}

/// The devices the identity area (task C1) keeps, from accepted records
/// (4.4, 4.5): a device is current once its record is accepted, not known
/// while it is pending, and not current once removed. C5 may replace this
/// with C1's own checks of the key file.
#[derive(Debug, Default)]
pub(crate) struct DevicesTable;

impl Directory for DevicesTable {
    fn device(&self, tx: &Tx<'_>, identity: &RisalaIdentity) -> DeviceStatus {
        use crate::store::identity::DeviceState;
        let Some(device) = identity.device_id else {
            return DeviceStatus::NotCurrent;
        };
        let Ok(devices) = tx.devices(identity.uid.as_str()) else {
            return DeviceStatus::Unknown;
        };
        let Some(row) = devices
            .into_iter()
            .find(|d| d.device_id == *device.as_bytes())
        else {
            return DeviceStatus::Unknown;
        };
        // The device id is the hash of its device key (4.4).
        if risala_mls::primitives::sha384(&row.device_key)[..] != device.as_bytes()[..] {
            return DeviceStatus::NotCurrent;
        }
        match row.state {
            DeviceState::Current => DeviceStatus::Current {
                device_key: row.device_key,
                attestation_key: row.attestation_key,
            },
            DeviceState::Pending => DeviceStatus::Unknown,
            DeviceState::Removed => DeviceStatus::NotCurrent,
        }
    }
}

/// [`Directory`] inside one transaction, as risala-mls asks for it.
struct TxDirectory<'a, 'b> {
    tx: &'a Tx<'b>,
    directory: &'a dyn Directory,
}

impl DeviceDirectory for TxDirectory<'_, '_> {
    fn device(&self, identity: &RisalaIdentity) -> DeviceStatus {
        self.directory.device(self.tx, identity)
    }
}

/// What [`Confirm::message_received`] found.
#[derive(Debug, Default)]
pub(crate) struct Received {
    /// Whether the message shows as verified: its sender's leaf is
    /// confirmed for it (12.9 step 6, 12.10).
    pub confirmed: bool,
    /// In a public room, the message's valid ATTEST pinned the pseudonym it
    /// was withheld for (7.3): it may be shown.
    pub pinned: bool,
    /// Events for the UI.
    pub actions: Vec<Action>,
}

/// What to do with a message about to be posted ([`Confirm::outgoing`]).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outgoing {
    /// Post it as it is.
    Keep,
    /// Post this RisalaMessage instead: the same one with confirmation
    /// lines added. The outbox has it already.
    Replace(Vec<u8>),
    /// Post no messages yet: the leaf must rotate first, and the commit
    /// that does is queued (12.10).
    Wait,
}

/// Who made a commit the group engine applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommitBy {
    /// This device; `authority` if it was an authority commit (12.7).
    Own {
        /// Whether only a role allowed it.
        authority: bool,
    },
    /// Another member's leaf.
    Member {
        /// Its leaf index.
        leaf: u32,
        /// Whether it was an authority commit (12.7).
        authority: bool,
    },
    /// A public room's external commit.
    External,
}

fn ts(ms: u64) -> Timestamp {
    Timestamp::from_unix_millis(ms).unwrap_or(Timestamp::MAX)
}

fn mls(e: impl std::fmt::Display) -> EngineError {
    EngineError::Mls(e.to_string())
}

/// Serialises confirmation state for the cache (librisala has serde only
/// through serde_json).
macro_rules! json {
    ($value:expr) => {
        serde_json::to_vec($value).map_err(|e| EngineError::Invalid(e.to_string()))
    };
}

/// Reads confirmation state back from the cache.
macro_rules! from_json {
    ($bytes:expr) => {
        serde_json::from_slice($bytes).map_err(|e| {
            EngineError::Store(StoreError::Corrupt(format!("confirmation state: {e}")))
        })
    };
}

/// The account's uid, unless it is a guest's: guests have no attestation
/// key, and confirm nothing (12.10).
fn identity_account(tx: &Tx<'_>, account: AccountId) -> Result<Option<Uid>> {
    use rusqlite::OptionalExtension as _;
    let row: Option<(String, String)> = tx
        .conn()
        .query_row(
            "SELECT uid, kind FROM accounts WHERE id = ?1",
            [account.get()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(StoreError::from)?;
    match row {
        Some((uid, kind)) if kind == "identity" => Ok(Some(crate::store::parse(&uid, "uid")?)),
        _ => Ok(None),
    }
}

/// This device's keys and device-wide state, for one transaction.
struct Own {
    uid: Uid,
    identity: RisalaIdentity,
    device_key: Option<SigningKey>,
    attestation_key: Option<AttestationKey>,
    keyring: PeriodKeyring,
    reveals: RevealRegistry,
    /// Stand-ins for keys a call does not use (see [`Own::device`]).
    spare_device_key: Option<SigningKey>,
    spare_attestation_key: Option<AttestationKey>,
}

impl Own {
    fn load(tx: &Tx<'_>, uid: Uid, identity: RisalaIdentity) -> Result<Own> {
        let (keyring, reveals) = match tx.period_keys(uid.as_str())? {
            Some((k, r)) => (from_json!(&k)?, from_json!(&r)?),
            None => (PeriodKeyring::new(), RevealRegistry::new()),
        };
        Ok(Own {
            uid,
            identity,
            device_key: None,
            attestation_key: None,
            keyring,
            reveals,
            spare_device_key: None,
            spare_attestation_key: None,
        })
    }

    fn save(&self, tx: &mut Tx<'_>) -> Result<()> {
        tx.set_period_keys(
            self.uid.as_str(),
            &json!(&self.keyring)?,
            &json!(&self.reveals)?,
        )?;
        Ok(())
    }

    /// risala-mls's view of the device. The device key signs only period
    /// keys' certificates, and the attestation key only answers
    /// challenges: a call that does neither gets random stand-ins, which
    /// sign and answer nothing.
    fn device<'a>(&'a mut self, directory: &'a dyn DeviceDirectory) -> Result<OwnDevice<'a>> {
        if self.device_key.is_none() && self.spare_device_key.is_none() {
            let seed: [u8; 32] =
                risala_mls::primitives::random().map_err(|_| EngineError::Random)?;
            self.spare_device_key = Some(SigningKey::from_seed(seed));
        }
        if self.attestation_key.is_none() && self.spare_attestation_key.is_none() {
            self.spare_attestation_key =
                Some(AttestationKey::generate().map_err(|_| EngineError::Random)?);
        }
        Ok(OwnDevice {
            identity: &self.identity,
            device_key: self
                .device_key
                .as_ref()
                .or(self.spare_device_key.as_ref())
                .expect("set above"),
            attestation_key: self
                .attestation_key
                .as_ref()
                .or(self.spare_attestation_key.as_ref())
                .expect("set above"),
            periods: &mut self.keyring,
            reveals: &mut self.reveals,
            directory,
        })
    }
}

/// One group, as this device holds it, for one transaction.
struct Session {
    row: ConvRow,
    group: MlsGroup,
    ext: RisalaConversation,
    own_index: u32,
    own_key: Vec<u8>,
    own: Own,
}

/// Leaf confirmation for the client's accounts: see the [module
/// docs](self).
pub(crate) struct Confirm {
    keys: Arc<dyn OwnKeys>,
    directory: Arc<dyn Directory>,
    clock: Arc<dyn Clock>,
    crypto: OnceLock<Arc<RisalaCrypto>>,
}

impl std::fmt::Debug for Confirm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Confirm").finish_non_exhaustive()
    }
}

impl Default for Confirm {
    fn default() -> Confirm {
        Confirm::new(
            Arc::new(NoKeys),
            Arc::new(DevicesTable),
            Arc::new(SystemClock),
        )
    }
}

impl Confirm {
    /// Leaf confirmation with these keys, devices and clock.
    pub(crate) fn new(
        keys: Arc<dyn OwnKeys>,
        directory: Arc<dyn Directory>,
        clock: Arc<dyn Clock>,
    ) -> Confirm {
        Confirm {
            keys,
            directory,
            clock,
            crypto: OnceLock::new(),
        }
    }

    pub(crate) fn now(&self) -> u64 {
        self.clock.now().unix_millis()
    }

    fn crypto(&self) -> Result<Arc<RisalaCrypto>> {
        if let Some(c) = self.crypto.get() {
            return Ok(c.clone());
        }
        let c = Arc::new(RisalaCrypto::new().map_err(mls)?);
        Ok(self.crypto.get_or_init(|| c).clone())
    }

    /// The group of `conv` with this device's view of it, or `None` if
    /// there is nothing to confirm: a guest's account, or a conversation
    /// this device is not in.
    fn session(&self, tx: &Tx<'_>, conv: ConversationId) -> Result<Option<Session>> {
        let row = tx.conversation(conv)?;
        if !row.state.in_group() {
            return Ok(None);
        }
        let Some(uid) = identity_account(tx, row.account)? else {
            return Ok(None);
        };
        let crypto = self.crypto()?;
        let provider = tx.mls(&crypto);
        let Some(group) = MlsGroup::load(provider.storage(), &GroupId::from_slice(&row.group_id))
            .map_err(|e| EngineError::Mls(format!("{e:?}")))?
        else {
            return Ok(None);
        };
        let Some(ext) = risala_mls::group::conversation(&group) else {
            return Ok(None);
        };
        let Some(own_leaf) = group.own_leaf_node() else {
            return Ok(None);
        };
        let own_key = own_leaf.signature_key().as_slice().to_vec();
        let identity = RisalaIdentity::from_credential(own_leaf.credential())
            .map_err(|e| EngineError::Invalid(e.to_string()))?;
        let own_index = group.own_leaf_index().u32();
        let own = Own::load(tx, uid, identity)?;
        Ok(Some(Session {
            row,
            group,
            ext,
            own_index,
            own_key,
            own,
        }))
    }

    /// This device's pseudonym in the group now (7.3): derived from the
    /// epoch outside public rooms, and the period's own in a public room.
    fn pseudonym(&self, s: &Session) -> Result<Pseudonym> {
        if s.row.kind == ConvKind::Public {
            return Ok(Pseudonym(s.row.pseudonym));
        }
        risala_mls::group::own_pseudonym::<()>(&s.group, self.crypto()?.as_ref()).map_err(mls)
    }

    /// The group's leaves, for the Confirmer.
    fn leaves(&self, s: &Session) -> Vec<LeafInfo> {
        GroupView::of(s.group.public_group(), &EpochState::default())
            .leaves
            .into_iter()
            .filter_map(|leaf| {
                Some(LeafInfo {
                    index: leaf.index.u32(),
                    identity: leaf.identity?,
                    signature_key: leaf.signature_key,
                })
            })
            .collect()
    }

    /// The group's Confirmer, made if it has none. With `sync`, it is told
    /// the group's leaves and mode (after a commit or a join); either way
    /// it learns this device's own leaf key and pseudonym.
    fn confirmer(
        &self,
        tx: &mut Tx<'_>,
        s: &mut Session,
        sync: bool,
        now: u64,
    ) -> Result<Confirmer> {
        let mode = s.ext.confirm;
        let stored = tx.confirmer(s.row.id)?;
        let Some((bytes, known_key)) = stored else {
            let pseudonym = self.pseudonym(s)?;
            let own = LeafInfo {
                index: s.own_index,
                identity: s.own.identity.clone(),
                signature_key: s.own_key.clone(),
            };
            return Ok(Confirmer::new(
                &s.row.group_id,
                mode,
                s.row.kind == ConvKind::WithYourself,
                &own,
                pseudonym,
                &self.leaves(s),
                ts(now),
            ));
        };
        let mut c: Confirmer = from_json!(&bytes)?;
        if sync {
            c.set_mode(mode);
            c.set_leaves(&self.leaves(s), ts(now));
        }
        if known_key != s.own_key {
            // A new leaf key of this device: in a public room, with a new
            // pseudonym for the period (7.3, 12.10).
            if s.row.kind == ConvKind::Public {
                let fresh = Pseudonym::generate().map_err(|_| EngineError::Random)?;
                tx.set_own_pseudonym(s.row.id, &fresh.0)?;
                s.row.pseudonym = fresh.0;
            }
            c.own_leaf_changed(&s.own_key, self.pseudonym(s)?, ts(now));
        } else {
            c.pseudonym_changed(self.pseudonym(s)?);
        }
        Ok(c)
    }

    /// Stores the Confirmer, writes each leaf's state where the client
    /// reads it, shows the messages of newly confirmed leaves as verified,
    /// plans impostors' removal, and turns events into warnings and UI
    /// events.
    fn save(
        &self,
        tx: &mut Tx<'_>,
        s: &Session,
        c: &Confirmer,
        events: Vec<ConfirmerEvent>,
        now: u64,
    ) -> Result<Vec<Action>> {
        let conv = s.row.id;
        let leaves = crate::store::conversations::read::leaves(tx.conn(), conv)?;
        let old = tx.leaf_confirmations(conv)?;
        let epochal = c.mode() == ConfirmMode::Epochal;
        let mut rows = Vec::with_capacity(leaves.len());
        for leaf in &leaves {
            let state = match c.state(leaf.leaf, ts(now)) {
                LeafState::Confirmed => LeafConfirmation::Confirmed,
                LeafState::Unconfirmed => LeafConfirmation::Unconfirmed,
                LeafState::Impostor => LeafConfirmation::Impostor,
            };
            let before = old
                .iter()
                .find(|o| o.leaf == leaf.leaf && o.signature_key == leaf.signature_key);
            let since_seq = match before {
                Some(b) => b.since_seq,
                None => tx.newest_message_seq(conv)?,
            };
            let until = if epochal && state == LeafConfirmation::Confirmed {
                confirmed_until(c, leaf.leaf, now)
            } else {
                None
            };
            let repair_at = match (state, before) {
                (LeafConfirmation::Impostor, Some(b)) if b.state == LeafConfirmation::Impostor => {
                    b.repair_at
                }
                (LeafConfirmation::Impostor, _) if leaf.leaf != s.own_index => {
                    // 12.7: remove it, for a check, after a random wait,
                    // where this device may.
                    may_remove(&s.ext, &s.own.uid, leaf)
                        .then(|| now + random_below(REPAIR_WITHIN_MS).unwrap_or(0))
                }
                _ => None,
            };
            if state == LeafConfirmation::Confirmed
                && before.is_none_or(|b| b.state != LeafConfirmation::Confirmed)
                && leaf.leaf != s.own_index
            {
                // Its earlier messages were signed with the same key (12.10).
                tx.mark_leaf_verified(conv, leaf.leaf, since_seq)?;
            }
            rows.push(LeafConfirmationRow {
                leaf: leaf.leaf,
                signature_key: leaf.signature_key.clone(),
                state,
                until,
                since_seq,
                repair_at,
            });
        }
        tx.set_leaf_confirmations(conv, &rows)?;
        tx.set_confirmer(
            conv,
            &json!(c)?,
            &s.own_key,
            c.next_wake().map(|t| t.unix_millis()),
        )?;
        s.own.save(tx)?;

        let mut actions = Vec::new();
        for event in events {
            let (leaf, kind) = match event {
                ConfirmerEvent::Confirmed { leaf } => (leaf, ConfirmKind::Confirmed),
                ConfirmerEvent::Attested { leaf, period, .. } => {
                    (leaf, ConfirmKind::Attested { period })
                }
                ConfirmerEvent::Impostor { leaf, reason } => (
                    leaf,
                    ConfirmKind::Impostor {
                        reason: match reason {
                            ImpostorReason::WrongAnswer => "wrong-answer",
                            ImpostorReason::NoAnswer => "no-answer",
                            ImpostorReason::NoAttestation => "no-attestation",
                        }
                        .to_owned(),
                    },
                ),
                ConfirmerEvent::Unanswered { leaf } => (leaf, ConfirmKind::Unanswered),
                ConfirmerEvent::InvalidAttestation { leaf, error } => (
                    leaf,
                    ConfirmKind::InvalidAttestation {
                        reason: error.to_string(),
                    },
                ),
                ConfirmerEvent::BadReveal { leaf, period } => {
                    (leaf, ConfirmKind::BadReveal { period })
                }
                ConfirmerEvent::RevealMissing { leaf, period } => {
                    (leaf, ConfirmKind::RevealMissing { period })
                }
                ConfirmerEvent::DeviceNotCurrent { leaf } => (leaf, ConfirmKind::DeviceNotCurrent),
                ConfirmerEvent::BadAttestationKey { leaf } => {
                    (leaf, ConfirmKind::BadAttestationKey)
                }
            };
            let Some(row) = leaves.iter().find(|l| l.leaf == leaf) else {
                continue;
            };
            if let Some((what, detail)) = kind.warning() {
                tx.add_confirm_warning(conv, leaf, row.uid.as_str(), what, &detail, now)?;
            }
            actions.push(Action::Emit(Event::Confirm(ConfirmEvent {
                conversation: conv,
                leaf,
                uid: row.uid.clone(),
                kind,
            })));
        }
        Ok(actions)
    }

    // -----------------------------------------------------------------
    // The group engine's hooks

    /// A group's leaves changed, after a commit or a join (12.7).
    pub(crate) fn leaves_changed(
        &self,
        tx: &mut Tx<'_>,
        conv: ConversationId,
    ) -> Result<Vec<Action>> {
        let now = self.now();
        let Some(mut s) = self.session(tx, conv)? else {
            return Ok(Vec::new());
        };
        let c = self.confirmer(tx, &mut s, true, now)?;
        self.save(tx, &s, &c, Vec::new(), now)
    }

    /// A commit was applied: the leaves changed, and its committer may
    /// have used authority (12.7), which needs confirming within the hour.
    pub(crate) fn commit_applied(
        &self,
        tx: &mut Tx<'_>,
        conv: ConversationId,
        by: CommitBy,
    ) -> Result<Vec<Action>> {
        let now = self.now();
        let Some(mut s) = self.session(tx, conv)? else {
            return Ok(Vec::new());
        };
        let mut c = self.confirmer(tx, &mut s, true, now)?;
        match by {
            CommitBy::Member {
                leaf,
                authority: true,
            } => c.authority_used(leaf, ts(now)),
            CommitBy::Own { authority: true } => c.own_authority_used(ts(now)),
            _ => {}
        }
        self.save(tx, &s, &c, Vec::new(), now)
    }

    /// A message the group engine decrypted and checked (12.9 steps 1 to
    /// 5), posted with `t`: its confirmation lines, whether its sender now
    /// needs a challenge, and whether to show it as verified (step 6).
    pub(crate) fn message_received(
        &self,
        tx: &mut Tx<'_>,
        conv: &ConvRow,
        group: &MlsGroup,
        d: &Decrypted,
        t: u64,
    ) -> Result<Received> {
        let now = self.now();
        let sender = d.sender.u32();
        // A live message carries TYPING alone (8.1).
        if d.order == Order::Live {
            let confirmed = tx
                .leaf_confirmation(conv.id, sender)?
                .is_some_and(|r| r.confirmed_at(now));
            return Ok(Received {
                confirmed,
                ..Received::default()
            });
        }
        let Some(mut s) = self.session(tx, conv.id)? else {
            return Ok(Received::default());
        };
        let mut c = self.confirmer(tx, &mut s, false, now)?;

        // A challenge to this device is answered with its attestation key;
        // without one, it is left unanswered rather than answered wrongly.
        let own_index = s.own_index;
        let to_me = move |l: &ContentLine| matches!(l, ContentLine::Challenge { leaf, .. } if *leaf == own_index);
        let mut filtered = None;
        if d.message.content.lines().iter().any(to_me) {
            s.own.attestation_key = self.keys.attestation_key(tx, &s.own.uid);
            if s.own.attestation_key.is_none() {
                let rest: Vec<ContentLine> = d
                    .message
                    .content
                    .lines()
                    .iter()
                    .filter(|l| !to_me(l))
                    .cloned()
                    .collect();
                filtered = Some(Content::new(rest).ok());
            }
        }
        let content = match &filtered {
            Some(Some(content)) => Some(content),
            Some(None) => None,
            None => Some(&d.message.content),
        };

        let pseudonym = if c.mode() == ConfirmMode::Epochal {
            self.message_pseudonym(tx, conv.id, group, d)
        } else {
            None
        };
        let mut events = Vec::new();
        if let Some(content) = content {
            let directory = TxDirectory {
                tx: &*tx,
                directory: self.directory.as_ref(),
            };
            let mut device = s.own.device(&directory)?;
            events = c.message(
                &mut device,
                &Incoming {
                    sender,
                    t: ts(t),
                    pseudonym,
                    content,
                },
                ts(now),
            );
        }

        // 12.7: a line that only a role allows uses authority, such as a
        // DELETE of someone else's message in a room (5.4).
        let room = matches!(conv.kind, ConvKind::Private | ConvKind::Public);
        if room && s.ext.role(&d.identity.uid) >= Role::Mod {
            for line in d.message.content.lines() {
                if let ContentLine::Delete { id } = line
                    && let Some(m) = tx.message(conv.id, id.as_bytes())?
                    && m.sender != d.identity.uid
                {
                    c.authority_used(sender, ts(now));
                    break;
                }
            }
        }

        // 7.3: in a public room, a valid ATTEST pins the pseudonym the
        // message was withheld for.
        let mut pinned = false;
        if let PseudonymCheck::NeedsAttest(p) = d.pseudonym
            && events.iter().any(|e| {
                matches!(e, ConfirmerEvent::Attested { leaf, pseudonym, .. }
                    if *leaf == sender && *pseudonym == p)
            })
        {
            let mut log = MessageLog::new(tx.conn(), conv.id);
            log.pin(d.sender, p);
            log.finish()?;
            pinned = true;
        }
        let confirmed = c.message_state(sender, ts(t), ts(now)) == LeafState::Confirmed;
        let actions = self.save(tx, &s, &c, events, now)?;
        Ok(Received {
            confirmed,
            pinned,
            actions,
        })
    }

    /// The pseudonym in a message's RisalaAAD (7.3), for its ATTEST.
    fn message_pseudonym(
        &self,
        tx: &Tx<'_>,
        conv: ConversationId,
        group: &MlsGroup,
        d: &Decrypted,
    ) -> Option<Pseudonym> {
        let log = MessageLog::new(tx.conn(), conv);
        match d.pseudonym {
            PseudonymCheck::NeedsAttest(p) => Some(p),
            PseudonymCheck::Pinned | PseudonymCheck::NewlyPinned => log.sender(d.sender).pseudonym,
            PseudonymCheck::Derived if d.epoch == group.epoch().as_u64() => {
                let crypto = self.crypto().ok()?;
                risala_mls::group::leaf_pseudonym::<()>(group, crypto.as_ref(), d.sender).ok()
            }
            PseudonymCheck::Derived => log.epoch_pseudonym(d.epoch, d.sender),
        }
    }

    /// A message of this device's is about to be posted (not a live one):
    /// add the pending CHALLENGE, ANSWER, ATTEST and REVEAL lines to it
    /// (12.10). In an epochal group whose leaf key is of an earlier period,
    /// queue the rotation and post nothing yet.
    pub(crate) fn outgoing(
        &self,
        tx: &mut Tx<'_>,
        conv: &ConvRow,
        outbox: i64,
        body: &[u8],
    ) -> Result<Outgoing> {
        let now = self.now();
        let Some(mut s) = self.session(tx, conv.id)? else {
            return Ok(Outgoing::Keep);
        };
        let mut c = self.confirmer(tx, &mut s, false, now)?;
        let epochal = c.mode() == ConfirmMode::Epochal;
        if epochal {
            s.own.device_key = self.keys.device_key(tx, &s.own.uid);
            if s.own.device_key.is_none() {
                // Without the device key nothing can be attested: send
                // what there is, unverified (12.10).
                self.save(tx, &s, &c, Vec::new(), now)?;
                return Ok(Outgoing::Keep);
            }
            if c.must_rotate_before_sending(ts(now)) {
                queue_rotation(tx, conv.id, now)?;
                self.save(tx, &s, &c, Vec::new(), now)?;
                return Ok(Outgoing::Wait);
            }
        }
        let (lines, events) = {
            let directory = TxDirectory {
                tx: &*tx,
                directory: self.directory.as_ref(),
            };
            let mut device = s.own.device(&directory)?;
            c.take_lines(&mut device, ts(now))
        };
        self.save(tx, &s, &c, events, now)?;
        let mut message =
            RisalaMessage::decode(body).map_err(|e| EngineError::Invalid(e.to_string()))?;
        if message.is_live() {
            return Ok(Outgoing::Keep);
        }
        // An ATTEST carries the pseudonym of the message it is in (12.10),
        // which outside public rooms changes with the epoch (7.3). A
        // message queued in one epoch and posted in another gets the new
        // one; the pseudonym is not signed.
        let sending = self.pseudonym(&s)?;
        let mut stale = false;
        let mut all: Vec<ContentLine> = message
            .content
            .lines()
            .iter()
            .cloned()
            .map(|mut line| {
                if let ContentLine::Attest { pseudonym, .. } = &mut line
                    && pseudonym.as_bytes() != &sending.0
                {
                    *pseudonym = risala_proto::mls::Pseudonym::from_bytes(sending.0);
                    stale = true;
                }
                line
            })
            .collect();
        if lines.is_empty() && !stale {
            return Ok(Outgoing::Keep);
        }
        all.extend(lines);
        let Ok(content) = Content::new(all) else {
            // Past 4 MiB with the lines: they are lost, and the leaves are
            // challenged again when they next send.
            return Ok(Outgoing::Keep);
        };
        message.content = content;
        let encoded = message.encode();
        tx.replace_queued_message(
            conv.id,
            outbox,
            message.message_id.as_bytes(),
            &encoded,
            message.content.as_bytes(),
        )?;
        Ok(Outgoing::Replace(encoded.to_vec()))
    }

    /// Whether this device has confirmed a leaf, by the cache (12.10).
    pub(crate) fn leaf_confirmed(&self, tx: &Tx<'_>, conv: ConversationId, leaf: &LeafRow) -> bool {
        tx.leaf_confirmation(conv, leaf.leaf)
            .ok()
            .flatten()
            .is_some_and(|r| r.signature_key == leaf.signature_key && r.confirmed_at(self.now()))
    }

    // -----------------------------------------------------------------
    // The clock

    /// What is due in the account's groups at the clock's time: deadlines,
    /// lines to send on their own, rotations, and impostors to remove.
    pub(crate) fn tick(&self, tx: &mut Tx<'_>, account: AccountId) -> Result<Vec<Action>> {
        let now = self.now();
        let mut actions = Vec::new();
        for conv in tx.confirmers_due(account, now)? {
            match self.tick_group(tx, conv, now) {
                Ok(a) => actions.extend(a),
                Err(e) => {
                    tracing::warn!(error = %e, %conv, "leaf confirmation failed a step");
                    tx.set_confirmer_wake(conv, None)?;
                }
            }
        }
        for (conv, leaf, key) in tx.repairs_due(account, now)? {
            self.repair(tx, conv, leaf, &key, now)?;
        }
        Ok(actions)
    }

    fn tick_group(&self, tx: &mut Tx<'_>, conv: ConversationId, now: u64) -> Result<Vec<Action>> {
        let Some(mut s) = self.session(tx, conv)? else {
            tx.set_confirmer_wake(conv, None)?;
            return Ok(Vec::new());
        };
        let mut c = self.confirmer(tx, &mut s, false, now)?;
        let epochal = c.mode() == ConfirmMode::Epochal;
        if epochal {
            s.own.device_key = self.keys.device_key(tx, &s.own.uid);
        }
        let mut events = {
            let directory = TxDirectory {
                tx: &*tx,
                directory: self.directory.as_ref(),
            };
            let mut device = s.own.device(&directory)?;
            c.poll(&mut device, ts(now))
        };
        let can_attest = !epochal || s.own.device_key.is_some();
        // 12.10: an epochal group's leaf gets a new key each period.
        if epochal && can_attest && c.rotation_due(ts(now)) {
            queue_rotation(tx, conv, now)?;
        }
        let due = c.send_due().is_some_and(|t| t.unix_millis() <= now);
        // Lines are taken only when they can go at once: no message waits
        // for them to ride in, and no commit is pending, which goes first
        // and might give this device's leaf a new key, which CHALLENGE and
        // ATTEST are bound to (12.10). A last-resort leaf key is replaced
        // first (12.5).
        if due && can_attest && !s.row.last_resort && !has_pending(tx, conv)? {
            if epochal && c.must_rotate_before_sending(ts(now)) {
                queue_rotation(tx, conv, now)?;
            } else {
                let (lines, more) = {
                    let directory = TxDirectory {
                        tx: &*tx,
                        directory: self.directory.as_ref(),
                    };
                    let mut device = s.own.device(&directory)?;
                    c.take_lines(&mut device, ts(now))
                };
                events.extend(more);
                if !lines.is_empty() {
                    // 12.10: lines that rode in no message go in one of
                    // their own.
                    content::queue_lines(tx, conv, &s.own.uid, lines, false, now)?;
                }
            }
        }
        let actions = self.save(tx, &s, &c, events, now)?;
        // Lines due on their own that cannot go yet (no message posts while
        // a commit is pending, or no device key) are tried again on the next
        // tick at the earliest.
        if let Some(wake) = c.next_wake().map(|t| t.unix_millis())
            && wake <= now
        {
            tx.set_confirmer_wake(conv, Some(now + 1_000))?;
        }
        Ok(actions)
    }

    /// Removes an impostor's leaf for a check (12.7), unless another device
    /// has, or it no longer has the key it was found out with.
    fn repair(
        &self,
        tx: &mut Tx<'_>,
        conv: ConversationId,
        leaf: u32,
        key: &[u8],
        now: u64,
    ) -> Result<()> {
        tx.set_repair_at(conv, leaf, None)?;
        let row = tx.conversation(conv)?;
        if !row.state.in_group() {
            return Ok(());
        }
        let Some(current) = tx.leaf(conv, leaf)? else {
            return Ok(());
        };
        if current.signature_key != key {
            return Ok(());
        }
        let intent = Intent {
            remove: vec![(current.uid.to_string(), current.device_id)],
            ..Intent::default()
        };
        group::queue_intent(tx, conv, &intent, now)?;
        tracing::info!(%conv, leaf, "removing an impostor's leaf");
        Ok(())
    }
}

/// When an epochal confirmation of `leaf` lapses: at the end of the grace
/// hour of the period its ATTEST is for (12.10). `None` if it does not, as
/// for a leaf confirmed pairwise before the group became epochal.
fn confirmed_until(c: &Confirmer, leaf: u32, now: u64) -> Option<u64> {
    let current = epochal::period_of(ts(now));
    // Confirmed whatever the period: pairwise, for its current key.
    let later = epochal::period_start(current.saturating_add(3));
    if c.state(leaf, ts(later)) == LeafState::Confirmed {
        return None;
    }
    // Confirmed only by the period before, within its grace hour.
    if let Some(previous) = current.checked_sub(1) {
        let grace = epochal::grace_end(previous);
        if now < grace && c.state(leaf, ts(grace)) != LeafState::Confirmed {
            return Some(grace);
        }
    }
    Some(epochal::grace_end(current))
}

/// Whether this device may remove `leaf` as an impostor (12.7). Any member
/// may, except that in a room only owners remove an owner's leaf, and only
/// owners and moderators a moderator's, as the Removes checks allow; a
/// public room has no removals for a check. A leaf of the device's own
/// identity it always may.
fn may_remove(ext: &RisalaConversation, own: &Uid, leaf: &LeafRow) -> bool {
    if leaf.uid == *own {
        return true;
    }
    match ext.kind {
        ConversationKind::PublicRoom => false,
        ConversationKind::Direct => true,
        ConversationKind::PrivateRoom => match ext.role(&leaf.uid) {
            Role::Owner => ext.role(own) == Role::Owner,
            Role::Mod => ext.role(own) >= Role::Mod,
            Role::Member => true,
        },
    }
}

/// Queues the commit of a new leaf key (12.10), unless a commit is pending:
/// it goes once that one is done.
fn queue_rotation(tx: &mut Tx<'_>, conv: ConversationId, now: u64) -> Result<()> {
    let pending = tx
        .pending_outbox(conv)?
        .iter()
        .any(|r| r.kind == OutboxKind::Commit);
    if !pending {
        group::queue_intent(
            tx,
            conv,
            &Intent {
                new_leaf_key: true,
                ..Intent::default()
            },
            now,
        )?;
    }
    Ok(())
}

/// Whether a message waits in the outbox, which pending lines can ride
/// in, or a commit, which goes first.
fn has_pending(tx: &Tx<'_>, conv: ConversationId) -> Result<bool> {
    Ok(tx.pending_outbox(conv)?.iter().any(|r| {
        r.kind == OutboxKind::Commit
            || (r.kind == OutboxKind::Message && r.state == OutboxState::Queued)
    }))
}

/// The engine of this area, for one account: what [`Confirm`] does on the
/// clock. The rest happens in the group engine's hooks.
#[derive(Debug, Default)]
pub struct ConfirmEngine {
    confirm: Option<Arc<Confirm>>,
}

impl ConfirmEngine {
    /// The engine for these settings.
    pub(crate) fn new(confirm: Arc<Confirm>) -> ConfirmEngine {
        ConfirmEngine {
            confirm: Some(confirm),
        }
    }
}

impl Engine for ConfirmEngine {
    fn handle(&mut self, cx: &Context, input: &Input<'_>) -> Vec<Action> {
        let (Some(confirm), Input::Tick { .. }) = (&self.confirm, input) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        match cx.store.confirm_due(cx.account, confirm.now()) {
            Ok(true) => {}
            Ok(false) => return out,
            Err(e) => {
                tracing::warn!(error = %e, "leaf confirmation could not read the cache");
                return out;
            }
        }
        let result = cx.store.write_with(|tx| confirm.tick(tx, cx.account));
        match result {
            Ok((actions, changes)) => {
                out.extend(changes.into_iter().map(|c| Action::Emit(Event::Changed(c))));
                out.extend(actions);
            }
            Err(e) => tracing::warn!(error = %e, "leaf confirmation failed a tick"),
        }
        out
    }
}

#[cfg(test)]
mod tests;
