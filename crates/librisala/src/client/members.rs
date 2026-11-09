//! The identity area (C1) wired into the group engine (C2): task C5.
//!
//! - **Key facts** (12.7): [`TxFacts`] answers the engine's key checks
//!   from the identity tables, and [`device_key_of`] whether a fetched
//!   KeyPackage's device is current, so that bindings are checked against
//!   accepted records only (4.4, 4.5, 12.5).
//! - **The conversation with yourself** (12.9): [`self_line`] hands the
//!   identity area's lines from confirmed leaves of the own identity to
//!   [`handle_self_line`], and [`Client::maintain`] sends the lines that
//!   area queued.
//! - **Members by key file** (12.14): after a fetch, outside public
//!   rooms, a device removes the leaves of devices removed by record, and
//!   adds devices that have none, where 12.7's Adds checks let it. In a
//!   private room it removes the leaves of an identity it cannot check
//!   (forked, or keys missing), where the Removes checks let it.
//!   [`Client::maintain`] does this for each connected account, on the
//!   driver's timer, after the identity area's own daily work.
//! - **Sending** (4.5, 12.14): [`Client::sending_stopped`] says whether a
//!   conversation may not send, from [`Client::send_check`].

use risala_mls::checks::{Fact, KeyFacts};
use risala_mls::conversation::Role as GroupRole;
use risala_mls::identity::DeviceId as MlsDeviceId;
use risala_proto::content::ContentLine;
use risala_proto::names::{Identity, Uid};

use super::identity::{IdentityError, IdentityEvent};
use super::types::{AccountId, ConversationId};
use super::{Client, Event, Result};
use crate::keys::KeyStore;
use crate::store::Tx;
use crate::store::conversations::{ConvKind, ConvRow, LeafRow};
use crate::store::identity::{ContactRow, DeviceState, KeysState, read_own};
use crate::sync::Action;
use crate::sync::conversations::wire::Intent;
use crate::sync::conversations::{Job, group};
use crate::sync::identity::{
    ConversationKind as KeyKind, SelfEffect, SendCheck, StopReason, handle_self_line, kept_chain,
    send_check, unchecked,
};

/// The key facts of 12.7 from the identity tables, as this device has
/// accepted them (4.5). What it has not fetched, or has only pending, is
/// unknown, so a check waits rather than fails; facts that are known stay
/// true (a removed device stays removed, 4.5).
pub(crate) struct TxFacts<'a> {
    tx: &'a Tx<'a>,
}

impl<'a> TxFacts<'a> {
    pub(crate) fn new(tx: &'a Tx<'a>) -> TxFacts<'a> {
        TxFacts { tx }
    }

    /// The contact, if its key file was read: `None` for a guest, for an
    /// identity never fetched, and while every fetch was an outage.
    fn contact(&self, uid: &Uid) -> Option<ContactRow> {
        if uid.is_guest() {
            return None;
        }
        self.tx
            .contact(uid.as_str())
            .ok()
            .flatten()
            .filter(|c| c.keys != KeysState::Unknown)
    }

    fn device(&self, uid: &Uid, device: &MlsDeviceId) -> Option<DeviceState> {
        self.tx
            .devices(uid.as_str())
            .ok()?
            .into_iter()
            .find(|d| d.device_id == *device.as_bytes())
            .map(|d| d.state)
    }
}

impl KeyFacts for TxFacts<'_> {
    fn current_device_key(&self, uid: &Uid, device_id: &MlsDeviceId) -> Fact<Option<Vec<u8>>> {
        if self.contact(uid).is_none() {
            return Fact::Unknown;
        }
        let row = self.tx.devices(uid.as_str()).ok().and_then(|devices| {
            devices
                .into_iter()
                .find(|d| d.device_id == *device_id.as_bytes())
        });
        match row {
            Some(d) if d.state == DeviceState::Current => Fact::Known(Some(d.device_key)),
            Some(d) if d.state == DeviceState::Removed => Fact::Known(None),
            // Pending, or not in the key file as last read: it may be a
            // record this device has not fetched yet, so the check waits
            // (12.7: "has not failed it").
            _ => Fact::Unknown,
        }
    }

    fn device_removed(&self, uid: &Uid, device_id: &MlsDeviceId) -> Fact<bool> {
        if uid.is_guest() {
            return Fact::Unknown;
        }
        match self.device(uid, device_id) {
            Some(DeviceState::Removed) => Fact::Known(true),
            Some(DeviceState::Current) => Fact::Known(false),
            _ => Fact::Unknown,
        }
    }

    fn identity_retired(&self, uid: &Uid) -> Fact<bool> {
        if self.contact(uid).is_none() {
            return Fact::Unknown;
        }
        let Ok(identity) = uid.as_str().parse::<Identity>() else {
            return Fact::Unknown;
        };
        let Ok(records) = self.tx.records(uid.as_str()) else {
            return Fact::Unknown;
        };
        match kept_chain(&identity, &records, true) {
            Some(chain) => Fact::Known(chain.is_retired()),
            None => Fact::Unknown,
        }
    }

    fn forked_or_missing(&self, uid: &Uid) -> Fact<bool> {
        match self.contact(uid) {
            Some(c) => Fact::Known(unchecked(&c).is_some()),
            None => Fact::Unknown,
        }
    }
}

/// Whether a fetched KeyPackage of `uid`'s device `device` may be added,
/// and under which device key its binding must verify (12.5, 12.7), for
/// [`Hooks::device_key_of`](crate::sync::conversations::Hooks):
///
/// - `Some(Some(key))`: a current device, whose record this device has
///   accepted (4.5);
/// - `Some(None)`: not to be added: removed by record, pending, not in the
///   key file as last read, or of an identity whose keys are missing or
///   that is forked (12.14). The device is added later, once its record
///   is accepted, by [`Client::maintain`];
/// - `None`: the key file could not be read at all yet (an outage, 4.4):
///   the KeyPackage is added, and its leaf stays unconfirmed (12.7).
pub(crate) fn device_key_of(
    tx: &Tx<'_>,
    uid: &Uid,
    device: &MlsDeviceId,
) -> Option<Option<Vec<u8>>> {
    if uid.is_guest() {
        return None;
    }
    let contact = tx.contact(uid.as_str()).ok().flatten()?;
    if contact.keys == KeysState::Unknown {
        return None;
    }
    if unchecked(&contact).is_some() {
        return Some(None);
    }
    let row = tx.devices(uid.as_str()).ok().and_then(|devices| {
        devices
            .into_iter()
            .find(|d| d.device_id == *device.as_bytes())
    });
    Some(
        row.filter(|d| d.state == DeviceState::Current)
            .map(|d| d.device_key),
    )
}

/// Whether this device starts the conversation with yourself of `uid`,
/// having found none (5.1): only while no other device of the identity is
/// current as far as it knows. A paired device waits for the identity's
/// other devices to add it to theirs (4.8, 12.7), rather than starting a
/// second one; a recovered device, whose recovery removed every other
/// device, starts it.
pub(crate) fn start_self_conversation(tx: &Tx<'_>, uid: &Uid) -> bool {
    let Ok(Some(own)) = read_own(tx.conn(), uid.as_str()) else {
        return true;
    };
    let others = tx.devices(uid.as_str()).map(|devices| {
        devices
            .iter()
            .any(|d| d.state == DeviceState::Current && d.device_id != own.device_id)
    });
    !others.unwrap_or(false)
}

/// A line of the identity area (RECORD, ALERT, RECORDS, SIGNINGKEY,
/// BACKUPKEY, PIN) that arrived in the conversation with yourself from a
/// confirmed leaf of the own identity: the engine checks both (12.9), and
/// this checks again that the conversation is the one with yourself.
pub(crate) fn self_line(
    tx: &mut Tx<'_>,
    keys: &dyn KeyStore,
    conv: ConversationId,
    leaf: &LeafRow,
    line: &ContentLine,
    now: u64,
) -> Vec<Action> {
    let in_self = tx
        .conversation(conv)
        .is_ok_and(|c| c.kind == ConvKind::WithYourself);
    if !in_self {
        return Vec::new();
    }
    let own = match read_own(tx.conn(), leaf.uid.as_str()) {
        Ok(Some(own)) => own,
        _ => return Vec::new(),
    };
    match handle_self_line(tx, keys, &own, line, now) {
        Ok(SelfEffect::Alert(_)) => vec![Action::Emit(Event::Identity(IdentityEvent::Alert {
            uid: leaf.uid.clone(),
        }))],
        Ok(_) => Vec::new(),
        Err(e) => {
            tracing::info!(error = %e, "a line in the conversation with yourself");
            Vec::new()
        }
    }
}

/// Whether `line` is one of the identity area's lines of the conversation
/// with yourself (12.9).
pub(crate) fn is_identity_line(line: &ContentLine) -> bool {
    matches!(
        line,
        ContentLine::Record(_)
            | ContentLine::Alert(_)
            | ContentLine::Records(_)
            | ContentLine::SigningKey(_)
            | ContentLine::BackupKey { .. }
            | ContentLine::Pin(_)
    )
}

/// The kind of a conversation, as 12.14's rules on sending tell apart.
fn key_kind(kind: &ConvKind) -> Option<KeyKind> {
    match kind {
        ConvKind::Direct => Some(KeyKind::Direct),
        ConvKind::Private => Some(KeyKind::PrivateRoom),
        ConvKind::Public => Some(KeyKind::PublicRoom),
        _ => None,
    }
}

impl Client {
    /// Why a conversation may not send, if it may not (4.5, 12.14): in a
    /// direct conversation, the other identity is forked, has its keys
    /// missing or a new master key not yet acknowledged; in a private
    /// room, a member has a new master key not yet acknowledged. Rooms
    /// keep sending past identities the device cannot check.
    pub fn sending_stopped(&self, conversation: ConversationId) -> Result<Option<StopReason>> {
        let row = self.conv_row(conversation)?;
        self.row_sending_stopped(&row)
    }

    pub(crate) fn row_sending_stopped(&self, row: &ConvRow) -> Result<Option<StopReason>> {
        let Some(kind) = key_kind(&row.kind) else {
            return Ok(None);
        };
        let own = self.account(row.account)?.uid;
        let mut uids: Vec<Uid> = match (&row.kind, &row.peer) {
            (ConvKind::Direct, Some(peer)) => vec![peer.clone()],
            _ => self
                .store()
                .leaf_rows(row.id)?
                .into_iter()
                .map(|l| l.uid)
                .collect(),
        };
        uids.sort();
        uids.dedup();
        for uid in uids.iter().filter(|u| !u.is_guest() && **u != own) {
            let contact = self.store().contact(uid.as_str())?;
            if let SendCheck::Stop(reason) = send_check(contact.as_ref(), kind) {
                return Ok(Some(reason));
            }
        }
        Ok(None)
    }

    /// Refuses to send in a conversation whose sending is stopped (12.14).
    pub(crate) fn check_sending(&self, row: &ConvRow) -> Result<()> {
        if let (Some(reason), Some(uid)) = (self.row_sending_stopped(row)?, self.stopped_uid(row)?)
        {
            return Err(IdentityError::Stopped { uid, reason }.into());
        }
        Ok(())
    }

    fn stopped_uid(&self, row: &ConvRow) -> Result<Option<Uid>> {
        let kind = key_kind(&row.kind);
        let own = self.account(row.account)?.uid;
        let uids: Vec<Uid> = match (&row.kind, &row.peer) {
            (ConvKind::Direct, Some(peer)) => vec![peer.clone()],
            _ => self
                .store()
                .leaf_rows(row.id)?
                .into_iter()
                .map(|l| l.uid)
                .collect(),
        };
        for uid in uids.into_iter().filter(|u| !u.is_guest() && *u != own) {
            let contact = self.store().contact(uid.as_str())?;
            if let Some(kind) = kind
                && let SendCheck::Stop(_) = send_check(contact.as_ref(), kind)
            {
                return Ok(Some(uid));
            }
        }
        Ok(None)
    }

    /// Before starting a conversation with `uid` or inviting it: fetches
    /// its key file if the device has never read it, and refuses an
    /// identity whose devices may not be added (4.5, 12.7, 12.14). Also
    /// makes sure the device has read its own identity's key file, whose
    /// other devices join too.
    pub(crate) async fn prepare_members(&self, account: AccountId, uids: &[Uid]) -> Result<()> {
        let own = self.account(account)?.uid;
        for uid in uids.iter().chain(std::iter::once(&own)) {
            if uid.is_guest() {
                continue;
            }
            let fetched = self
                .store()
                .contact(uid.as_str())?
                .is_some_and(|c| c.fetched.is_some());
            if !fetched {
                self.refresh_identity(uid.as_str()).await?;
            }
            if *uid == own {
                continue;
            }
            let contact = self.store().contact(uid.as_str())?;
            if let SendCheck::Stop(reason) = send_check(contact.as_ref(), KeyKind::Direct) {
                return Err(IdentityError::Stopped {
                    uid: uid.clone(),
                    reason,
                }
                .into());
            }
            if !self.may_add_devices(uid.as_str())? {
                return Err(IdentityError::NotAccepted(uid.clone()).into());
            }
        }
        Ok(())
    }

    /// A connected account's upkeep, which the driver runs every
    /// [`maintenance_every`](super::ClientOptions::maintenance_every):
    /// the identity area's daily work (it does each part only when due),
    /// then the identity area's lines for the conversation with yourself,
    /// then each group's devices against the key files (12.14).
    pub(crate) async fn maintain(&self, account: AccountId) -> Result<()> {
        if let Err(e) = self.identity_maintenance().await {
            tracing::info!(error = %e, "identity maintenance failed; will retry");
        }
        let a = self.account(account)?;
        if a.kind != crate::store::AccountKind::Identity {
            return Ok(());
        }
        // The own identity's records this device made and has not accepted
        // yet (a paired device, a removal, 4.8): read the key file again
        // until they are, so that groups follow at once.
        let pending = self
            .store()
            .records(a.uid.as_str())?
            .iter()
            .any(|r| r.mine && !r.accepted);
        if pending && let Err(e) = self.refresh_identity(a.uid.as_str()).await {
            tracing::info!(error = %e, "reading the own key file failed; will retry");
        }
        self.send_self_lines(account).await?;
        for row in self.store().conversation_rows(account)? {
            if !row.state.in_group() {
                continue;
            }
            if let Err(e) = self.reconcile(account, &a.uid, &row).await {
                tracing::info!(conv = %row.id, error = %e, "checking a group's devices failed");
            }
        }
        Ok(())
    }

    /// Sends the identity area's queued lines in the conversation with
    /// yourself (12.9). SIGNINGKEY and BACKUPKEY go only while every leaf
    /// there is confirmed, and wait meanwhile.
    async fn send_self_lines(&self, account: AccountId) -> Result<()> {
        let uid = self.account(account)?.uid;
        if self.store().self_lines(uid.as_str())?.is_empty() {
            return Ok(());
        }
        let Some(conv) = self
            .store()
            .conversation_rows(account)?
            .into_iter()
            .find(|r| r.kind == ConvKind::WithYourself && r.state.in_group())
        else {
            return Ok(());
        };
        let own_device = self
            .store()
            .own_identity(uid.as_str())?
            .map(|o| o.device_id);
        let all_confirmed = self
            .leaf_status(conv.id)?
            .iter()
            .filter(|l| l.device.map(|d| d.0) != own_device)
            .all(|l| l.confirmed);
        let lines = self.take_self_lines(uid.as_str())?;
        let (keys, rest): (Vec<_>, Vec<_>) = lines.into_iter().partition(|l| {
            matches!(
                l,
                ContentLine::SigningKey(_) | ContentLine::BackupKey { .. }
            )
        });
        let mut send = rest;
        if all_confirmed {
            send.extend(keys);
        } else if !keys.is_empty() {
            let now = self.now_ms();
            let (_, changes) = self.store().write(|tx| {
                for line in &keys {
                    crate::sync::identity::queue_line(tx, uid.as_str(), line, now)?;
                }
                Ok(())
            })?;
            self.emit_changes(changes);
        }
        if !send.is_empty() {
            self.send_lines(conv.id, send, false).await?;
        }
        Ok(())
    }

    /// Adds and removes a group's devices by the key files the device has
    /// read (12.14), where 12.7's checks let this device:
    ///
    /// - leaves of devices removed by record are removed, by any member;
    /// - in a private room, the leaves of an identity the device cannot
    ///   check are removed, a listed owner's only by an owner and a
    ///   listed moderator's only by an owner or moderator;
    /// - current devices with no leaf are added: the own identity's by its
    ///   own devices, and in a direct conversation, the other
    ///   participant's when it has no leaf left (after a recovery, 4.8).
    ///   Other identities' new devices are added by their own devices, so
    ///   that members do not race to add the same device.
    ///
    /// Nothing is done while a commit of this device is pending there.
    async fn reconcile(&self, account: AccountId, own: &Uid, row: &ConvRow) -> Result<()> {
        let leaves = self.store().leaf_rows(row.id)?;
        let readers = self.read_new_members(own, row).await?;
        // Public rooms have no key checks: devices join by themselves
        // (6.1, 12.7).
        if !matches!(
            row.kind,
            ConvKind::Direct | ConvKind::Private | ConvKind::WithYourself
        ) {
            return Ok(());
        }
        let (pending, _) = self.store().write(|tx| {
            Ok(tx
                .pending_outbox(row.id)?
                .iter()
                .any(|o| o.kind == crate::store::messages::OutboxKind::Commit))
        })?;
        if pending {
            return Ok(());
        }
        let (owners, mods) = match self.extension(row) {
            Ok(ext) => (ext.owners.clone(), ext.mods.clone()),
            Err(_) => return Ok(()),
        };
        let my_role = if owners.contains(own) {
            GroupRole::Owner
        } else if mods.contains(own) {
            GroupRole::Mod
        } else {
            GroupRole::Member
        };
        // 12.7: a listed owner's leaves are removed for a check only by an
        // owner, a listed moderator's by an owner or moderator.
        let may_act_on = |uid: &Uid| {
            uid == own
                || row.kind != ConvKind::Private
                || (owners.contains(uid) && my_role == GroupRole::Owner)
                || (mods.contains(uid) && my_role >= GroupRole::Mod)
                || (!owners.contains(uid) && !mods.contains(uid))
        };
        let uids = readers;
        let this_device = self
            .store()
            .own_identity(own.as_str())?
            .map(|o| o.device_id);

        // Removals: one identity per commit (12.7).
        for uid in uids.iter().filter(|u| !u.is_guest()) {
            let Some(contact) = self.store().contact(uid.as_str())? else {
                continue;
            };
            if contact.keys == KeysState::Unknown || !may_act_on(uid) {
                continue;
            }
            let devices = self.store().devices(uid.as_str())?;
            let unchecked_room =
                row.kind == ConvKind::Private && uid != own && unchecked(&contact).is_some();
            let remove: Vec<(String, Option<[u8; 48]>)> = leaves
                .iter()
                .filter(|l| l.uid == *uid && l.device_id.is_some() && l.device_id != this_device)
                .filter(|l| {
                    unchecked_room
                        || devices.iter().any(|d| {
                            Some(d.device_id) == l.device_id && d.state == DeviceState::Removed
                        })
                })
                .map(|l| (l.uid.to_string(), l.device_id))
                .collect();
            if !remove.is_empty() {
                tracing::info!(conv = %row.id, n = remove.len(), "removing leaves for a key check");
                self.queue_commit(
                    row,
                    Intent {
                        remove,
                        ..Intent::default()
                    },
                )
                .await?;
                return Ok(());
            }
        }

        // Adds.
        for uid in uids.iter().filter(|u| !u.is_guest()) {
            let has_leaf = leaves.iter().any(|l| l.uid == *uid);
            let ours = uid == own;
            let returning_peer = row.kind == ConvKind::Direct && !has_leaf;
            if !(ours || returning_peer) || !may_act_on(uid) {
                continue;
            }
            if !self.may_add_devices(uid.as_str())? {
                continue;
            }

            let missing = self
                .store()
                .devices(uid.as_str())?
                .into_iter()
                .filter(|d| d.state == DeviceState::Current)
                .any(|d| {
                    Some(d.device_id) != this_device
                        && !leaves
                            .iter()
                            .any(|l| l.uid == *uid && l.device_id == Some(d.device_id))
                });
            if !missing {
                continue;
            }
            tracing::info!(conv = %row.id, "adding devices that have no leaf");
            self.run_job(
                account,
                Job::Invite {
                    conv: row.id,
                    uids: vec![uid.clone()],
                },
            )
            .await?;
            // 12.9: a new device of the identity gets the pins.
            if ours && row.kind == ConvKind::WithYourself {
                self.queue_all_pins(own.as_str())?;
            }
            return Ok(());
        }
        Ok(())
    }

    /// Reads the key file of each member of a conversation that this
    /// device never read (12.14), so that their devices can be checked
    /// and, in a public room, their ATTESTs (12.10). Later fetches are the
    /// identity area's daily ones. In a public room this reads every
    /// member once; 12.14 asks only for senders, so a choice to confirm.
    /// Returns the members' identities, with the own one and a direct
    /// conversation's peer.
    async fn read_new_members(&self, own: &Uid, row: &ConvRow) -> Result<Vec<Uid>> {
        let mut uids: Vec<Uid> = self
            .store()
            .leaf_rows(row.id)?
            .into_iter()
            .map(|l| l.uid)
            .chain(row.peer.clone())
            .chain(std::iter::once(own.clone()))
            .filter(|u| !u.is_guest())
            .collect();
        uids.sort();
        uids.dedup();
        for uid in &uids {
            let fetched = self
                .store()
                .contact(uid.as_str())?
                .is_some_and(|c| c.fetched.is_some());
            if !fetched && let Err(e) = self.refresh_identity(uid.as_str()).await {
                tracing::info!(error = %e, "reading a member's key file failed; will retry");
            }
        }
        Ok(uids)
    }

    /// Queues a commit and lets the engine send it.
    async fn queue_commit(&self, row: &ConvRow, intent: Intent) -> Result<()> {
        let now = self.now_ms();
        self.store()
            .write_with(|tx| group::queue_intent(tx, row.id, &intent, now))
            .map_err(super::Error::from)?;
        self.kick(row.account).await;
        Ok(())
    }
}

impl Client {
    /// Starts the account's upkeep ([`Client::maintain`]) every
    /// [`maintenance_every`](super::ClientOptions::maintenance_every),
    /// for as long as the account runs and the client lives.
    pub(crate) fn spawn_maintenance(&self, account: AccountId) -> tokio::task::JoinHandle<()> {
        use crate::store::Change;
        use crate::store::conversations::ConversationChange;
        use tokio::sync::broadcast::error::RecvError;

        let weak = std::sync::Arc::downgrade(&self.inner);
        let every = self
            .options()
            .maintenance_every
            .max(std::time::Duration::from_secs(1));
        let mut events = self.subscribe();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(every);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                // A group's members changed: read the new members' key
                // files at once, before their first messages need them
                // (12.10, 12.14); everything else on the timer.
                let changed = tokio::select! {
                    _ = interval.tick() => None,
                    event = events.recv() => match event {
                        Ok(Event::Changed(Change::Conversation(
                            ConversationChange::Members(conv),
                        ))) => Some(conv),
                        Ok(_) | Err(RecvError::Lagged(_)) => continue,
                        Err(RecvError::Closed) => return,
                    },
                };
                let Some(inner) = weak.upgrade() else {
                    return;
                };
                let client = Client { inner };
                let result = match changed {
                    None => client.maintain(account).await,
                    Some(conv) => client.members_changed(account, conv).await,
                };
                if let Err(e) = result {
                    tracing::info!(error = %e, "account upkeep failed; will retry");
                }
            }
        })
    }

    /// A conversation's members changed: reads the key files of new ones.
    async fn members_changed(&self, account: AccountId, conv: ConversationId) -> Result<()> {
        let Some(row) = self.store().conversation_row(conv)? else {
            return Ok(());
        };
        if row.account != account {
            return Ok(());
        }
        let own = self.account(account)?.uid;
        self.read_new_members(&own, &row).await.map(drop)
    }
}

impl Client {
    /// Whether the account has nothing left to send: no post or commit
    /// queued, in flight or not yet seen back, and no Welcome waiting. For
    /// tools that connect, act and stop (task C5's `risala`).
    pub fn is_settled(&self, account: AccountId) -> Result<bool> {
        let (pending, _) = self.store().write(|tx| {
            let outbox = tx.account_outbox(account)?.len() as i64;
            let welcomes: i64 = tx.conn().query_row(
                "SELECT count(*) FROM welcomes_out w JOIN conversations c ON c.id = w.conv
                 WHERE c.account = ?1",
                [account.0],
                |r| r.get(0),
            )?;
            Ok(outbox + welcomes)
        })?;
        Ok(pending == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use crate::store::identity::{DeviceRow, OwnRow};

    const ALICE: &str = "alice@example.org";

    fn device(n: u8, state: DeviceState) -> DeviceRow {
        DeviceRow {
            device_id: [n; 48],
            device_key: vec![n; 1312],
            attestation_key: vec![n; 1216],
            label: format!("device {n}"),
            added: 1,
            state,
        }
    }

    fn uid(s: &str) -> Uid {
        s.parse().unwrap()
    }

    /// A store that knows `ALICE` with `keys`, and her devices 1 (current),
    /// 2 (pending) and 3 (removed).
    fn store(keys: KeysState, forked: bool) -> Store {
        let store = Store::open_in_memory().unwrap();
        store
            .write(|tx| {
                let mut c = ContactRow::new(ALICE);
                c.keys = keys;
                c.forked = forked;
                tx.put_contact(&c)?;
                tx.put_devices(
                    ALICE,
                    &[
                        device(1, DeviceState::Current),
                        device(2, DeviceState::Pending),
                        device(3, DeviceState::Removed),
                    ],
                )?;
                Ok(())
            })
            .unwrap();
        store
    }

    fn id(n: u8) -> MlsDeviceId {
        MlsDeviceId::from_bytes([n; 48])
    }

    /// 12.7: a current device's key is known; a removed one is known not
    /// to be current and to be removed; a pending or unknown one is not
    /// known yet, so a check waits rather than fails.
    #[test]
    fn key_facts_follow_accepted_records() {
        let store = store(KeysState::Keys, false);
        let alice = uid(ALICE);
        store
            .write(|tx| {
                let facts = TxFacts::new(tx);
                assert_eq!(
                    facts.current_device_key(&alice, &id(1)),
                    Fact::Known(Some(vec![1; 1312]))
                );
                assert_eq!(facts.current_device_key(&alice, &id(2)), Fact::Unknown);
                assert_eq!(facts.current_device_key(&alice, &id(3)), Fact::Known(None));
                assert_eq!(facts.current_device_key(&alice, &id(9)), Fact::Unknown);
                assert_eq!(facts.device_removed(&alice, &id(1)), Fact::Known(false));
                assert_eq!(facts.device_removed(&alice, &id(3)), Fact::Known(true));
                assert_eq!(facts.device_removed(&alice, &id(2)), Fact::Unknown);
                assert_eq!(facts.forked_or_missing(&alice), Fact::Known(false));
                // Nobody else is known.
                let bob = uid("bob@example.org");
                assert_eq!(facts.current_device_key(&bob, &id(1)), Fact::Unknown);
                assert_eq!(facts.forked_or_missing(&bob), Fact::Unknown);
                assert_eq!(facts.identity_retired(&bob), Fact::Unknown);
                Ok(())
            })
            .unwrap();
    }

    /// 12.14: a fork or missing keys is a fact the checks know; an
    /// identity whose key file was never read is not.
    #[test]
    fn forks_and_missing_keys_are_facts() {
        let alice = uid(ALICE);
        for (keys, forked, expected) in [
            (KeysState::Keys, true, Fact::Known(true)),
            (KeysState::Missing("gone".into()), false, Fact::Known(true)),
            (KeysState::Unknown, false, Fact::Unknown),
        ] {
            let store = store(keys, forked);
            store
                .write(|tx| {
                    assert_eq!(TxFacts::new(tx).forked_or_missing(&alice), expected);
                    Ok(())
                })
                .unwrap();
        }
    }

    /// 12.5, 12.7: a fetched KeyPackage is added only for a current
    /// device, and checked against its key; while the key file could not
    /// be read at all, it is added unchecked.
    #[test]
    fn keypackage_devices_must_be_current() {
        let alice = uid(ALICE);
        let store = store(KeysState::Keys, false);
        store
            .write(|tx| {
                assert_eq!(device_key_of(tx, &alice, &id(1)), Some(Some(vec![1; 1312])));
                assert_eq!(device_key_of(tx, &alice, &id(2)), Some(None));
                assert_eq!(device_key_of(tx, &alice, &id(3)), Some(None));
                assert_eq!(device_key_of(tx, &alice, &id(9)), Some(None));
                assert_eq!(device_key_of(tx, &uid("bob@example.org"), &id(1)), None);
                Ok(())
            })
            .unwrap();
        // Forked: nothing is added.
        let store = super::tests::store(KeysState::Keys, true);
        store
            .write(|tx| {
                assert_eq!(device_key_of(tx, &alice, &id(1)), Some(None));
                Ok(())
            })
            .unwrap();
        // An outage only: added, unconfirmed.
        let store = super::tests::store(KeysState::Unknown, false);
        store
            .write(|tx| {
                assert_eq!(device_key_of(tx, &alice, &id(1)), None);
                Ok(())
            })
            .unwrap();
    }

    /// 5.1, 4.8: a device starts the conversation with yourself only when
    /// no other device of its identity is current.
    #[test]
    fn a_paired_device_waits_to_be_added() {
        let alice = uid(ALICE);
        let store = store(KeysState::Keys, false);
        let own = |n: u8| OwnRow {
            uid: ALICE.into(),
            device_id: [n; 48],
            key_id: ALICE.into(),
            home: "chat.test".into(),
            backup_generation: 1,
            created: 1,
            told_full: false,
        };
        // This device is 2; device 1 is current: wait.
        store
            .write(|tx| {
                tx.add_own(&own(2))?;
                assert!(!start_self_conversation(tx, &alice));
                Ok(())
            })
            .unwrap();
        // Alone (1 is current, and this is 1): start it.
        let store = super::tests::store(KeysState::Keys, false);
        store
            .write(|tx| {
                tx.add_own(&own(1))?;
                assert!(start_self_conversation(tx, &alice));
                Ok(())
            })
            .unwrap();
    }

    /// 12.9: only the identity area's lines are routed to it.
    #[test]
    fn identity_lines() {
        let lines = [
            ("RECORDS -", true),
            ("TEXT hello", false),
            ("TYPING", false),
        ];
        for (text, expected) in lines {
            let line = ContentLine::parse(text).unwrap();
            assert_eq!(is_identity_line(&line), expected, "{text}");
        }
    }
}
