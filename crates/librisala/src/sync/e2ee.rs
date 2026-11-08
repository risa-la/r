//! The encryption engine (SPEC 12), as part of the [`SyncEngine`]: it
//! sees every line in order, and sends its commands through the engine.
//!
//! On each connection of an identity's device:
//!
//! - **KeyPackages** (12.4). `KEYPKG COUNT`, then `KEYPKG ADD` until the
//!   server holds about ten ordinary ones and a last-resort one. Never on a
//!   connection signed in with the recovery key (12.10).
//! - **Welcomes** (12.7). `WELCOME LIST`, and every live WELCOME line: the
//!   device checks the group (12.6) and joins it, then deletes the Welcome.
//! - **Commits** (12.5, 12.6). COMMIT events are applied in seq order, once
//!   every event before them is stored, so that the checks of 12.6 can see
//!   the room's PART, KICK and BAN events. Encrypted conversations are
//!   therefore always caught up from their sync point forward, never by
//!   the newest page first (7.1 step 4). A commit that fails a check of
//!   12.6 leaves the group rejected; one that MLS refuses leaves it broken,
//!   and the device joins again by external commit.
//! - **Joining** (12.6). A conversation that SYNC lists, that should be
//!   encrypted and that has no group the device follows, is joined by
//!   external commit (GROUPINFO, then COMMIT), the conversation with
//!   itself first, once WELCOME LIST has been answered.
//! - **Duties** (12.6). Leaves whose keys left their key files, or whose
//!   identities left the room, are removed, and the device commits a fresh
//!   leaf about once a week.
//! - **Key files** (12.12). The engine asks for the key files it needs in
//!   [`Output::key_files`](super::Output::key_files), and the caller hands
//!   them back with [`SyncEngine::key_file`]. While a leaf of a group is
//!   not confirmed, the device sends nothing in it (12.6).
//! - **Messages** (12.8). Outbox entries for encrypted conversations go as
//!   ENC, encrypted under the current epoch's history key. Stored ENC
//!   events are decrypted as soon as their epoch's key is here.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use risala_mls::group::Changes;
use risala_mls::openmls::prelude::{KeyPackage, LeafNodeIndex};
use risala_mls::{HistoryKey, RisalaConversation};
use risala_proto::auth::PublicKey;
use risala_proto::command::{Command, KeyPkgCommand, WelcomeCommand};
use risala_proto::error::ErrorCode;
use risala_proto::mls;
use risala_proto::names::{Conv, Id, Seq, Uid};
use risala_proto::server::{EventBody, ServerLine, ServerMessage};
use rusqlite::{OptionalExtension, params};
use tracing::{debug, warn};

use super::engine::Pending;
use super::{Notification, Outcome, Reply, ReqId, SyncEngine, SyncError};
use crate::e2ee::content::{Content, Control};
use crate::e2ee::group::{self, Applied, Joined};
use crate::e2ee::{Device, E2eeError};
use crate::store::e2ee::GroupState;
use crate::store::{ConvRow, StoreError, Tx, sql};

/// A device keeps about this many ordinary KeyPackages on the server
/// (12.4).
pub(super) const KEY_PACKAGES: u64 = 10;

/// It uploads more when the server holds fewer than this (12.4).
pub(super) const KEY_PACKAGES_LOW: u64 = 5;

/// How often a device commits a fresh leaf of its own (12.6).
pub(super) const REFRESH: Duration = Duration::from_secs(7 * 24 * 3600);

/// How old a key file may be before it is fetched again for an identity
/// the device shares a group with (12.12): at least once a day.
pub(super) const KEY_FILE_AGE: Duration = Duration::from_secs(24 * 3600);

/// How long to wait before trying a key file again after a failed fetch,
/// or for a leaf that is not confirmed (12.6).
pub(super) const KEY_FILE_RETRY: Duration = Duration::from_secs(5 * 60);

/// Clients should add at most this many devices in one commit (12.5).
const MAX_ADDS: usize = 256;

/// What the encryption engine keeps for one connection. Everything lasting
/// is in the store.
#[derive(Debug)]
pub(super) struct E2ee {
    pub(super) dev: Device,
    /// Signed in with the recovery key: no KeyPackages, no groups (12.10).
    recovery_conn: bool,
    /// The identity's recovery key, if the device holds it (12.10).
    pub(super) recovery: Option<risala_mls::RecoveryKey>,
    /// BACKUP ADDs in flight, by conversation id and epoch.
    pub(super) backing_up: Vec<(Id, u64)>,
    /// BACKUP ADDs that failed on this connection, not tried again on it.
    pub(super) backups_failed: Vec<(Id, u64)>,
    /// History keys are on their way to the identity's new devices.
    pub(super) sharing_keys: bool,
    /// WELCOME LIST has been answered on this connection.
    welcomes_listed: bool,
    /// Conversations with an INIT, GROUPINFO or COMMIT of this device's in
    /// flight. One at a time each.
    busy: HashSet<Conv>,
    /// Key files asked for and not answered yet.
    fetching: HashSet<Uid>,
    /// Conversations whose next commit waits for these key files.
    waiting: HashMap<Conv, HashSet<Uid>>,
    /// Identities whose key files were fetched for a commit that waited
    /// for them, until a commit is applied (12.6).
    fresh: HashSet<Uid>,
    /// Conversations where ENC got `stale`: nothing is sent there until a
    /// commit is applied or made (12.6).
    held: HashSet<Conv>,
    /// Identities whose KeyPackages were asked for on this connection.
    asked: HashSet<Uid>,
    /// Welcomes of rooms whose id is not known yet.
    deferred: Vec<WelcomeLine>,
    /// Conversations joined by external commit on this connection, so as
    /// not to try twice.
    rejoined: HashSet<Conv>,
    /// Rooms whose earlier history keys wait to be sent to a new member
    /// (12.9).
    to_share: HashSet<Conv>,
    /// Conversations whose INIT the server refused on this connection for
    /// a reason other than `stale`: not tried again on it.
    init_refused: HashSet<Conv>,
    /// Invitations to encrypted rooms waiting for their commit: the
    /// invitees' KeyPackages, kept until the server accepts it, so that a
    /// commit refused as `stale`, or one that waited for another, is made
    /// again (12.5, 12.6).
    invites: HashMap<Conv, Vec<(KeyPackage, PublicKey)>>,
}

/// A WELCOME line (12.7).
#[derive(Debug, Clone)]
pub(super) struct WelcomeLine {
    conv: Conv,
    id: Id,
    seq: Seq,
    welcome: mls::Welcome,
    tree: mls::RatchetTree,
}

/// Why a commit of this device's was made, to know what follows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Purpose {
    /// Adding devices, or other duties.
    Duties,
    /// Joining by external commit.
    Join,
    /// Inviting someone to an encrypted room (12.6).
    Invite,
}

/// An encryption command in flight.
#[derive(Debug, Clone)]
pub(super) enum E2eePending {
    KeyPkgCount,
    KeyPkgAdd,
    WelcomeList,
    WelcomeDel,
    Init {
        conv: Conv,
    },
    Commit {
        conv: Conv,
        commit: mls::CommitMessage,
        purpose: Purpose,
    },
    GroupInfo {
        conv: Conv,
    },
    KeyPkgGet {
        conv: Conv,
        uid: Uid,
        purpose: Purpose,
    },
    /// An ENC of KEY lines (12.9) or a RECOVERY line (12.10). With
    /// `devices`, the last one to the identity's confirmed devices, by
    /// key id.
    Shared {
        devices: Option<Vec<Vec<u8>>>,
    },
    /// BACKUP ADD of one history key (12.10).
    BackupAdd {
        id: Id,
        epoch: u64,
        key_id: Vec<u8>,
    },
}

impl E2ee {
    /// Whether the connection is signed in with the recovery key (12.10).
    pub(super) fn recovery_connection(&self) -> bool {
        self.recovery_conn
    }

    pub(super) fn new(dev: Device, recovery_conn: bool) -> E2ee {
        E2ee {
            dev,
            recovery_conn,
            recovery: None,
            backing_up: Vec::new(),
            backups_failed: Vec::new(),
            sharing_keys: false,
            welcomes_listed: false,
            busy: HashSet::new(),
            fetching: HashSet::new(),
            waiting: HashMap::new(),
            fresh: HashSet::new(),
            held: HashSet::new(),
            asked: HashSet::new(),
            deferred: Vec::new(),
            rejoined: HashSet::new(),
            to_share: HashSet::new(),
            init_refused: HashSet::new(),
            invites: HashMap::new(),
        }
    }
}

/// What the outbox needs to send a message as ENC (12.8).
#[derive(Debug)]
pub(super) struct EncPlan {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub key: HistoryKey,
    /// The target's `message_id`, for a reply, edit or reaction.
    pub target: Option<[u8; 16]>,
}

/// Whether an outbox entry for an encrypted conversation can go now.
#[derive(Debug)]
pub(super) enum EncReady {
    /// Encrypt it with this.
    Go(EncPlan),
    /// Not yet: the group is not ready.
    Wait,
    /// Not until these identities' key files confirm the group's leaves
    /// (12.6).
    Unconfirmed(Vec<Uid>),
    /// Never: its target cannot be named (12.8).
    Fail,
}

impl SyncEngine {
    /// Says that this connection is an identity's device with `key`, which
    /// turns on end-to-end encryption (Section 12). With `recovery`, the
    /// connection is signed in with the recovery key (12.10): it neither
    /// uploads KeyPackages nor joins groups. Call it before
    /// [`start`](Self::start).
    pub fn set_device_key(
        &mut self,
        key: std::sync::Arc<risala_proto::auth::SecretKey>,
        recovery: bool,
    ) -> Result<(), SyncError> {
        if self.guest || !self.config.encryption {
            return Ok(());
        }
        let dev =
            Device::new(self.me.clone(), key).map_err(|e| SyncError::Invalid(e.to_string()))?;
        self.e2ee = Some(E2ee::new(dev, recovery));
        Ok(())
    }

    /// Makes `room` end-to-end encrypted with INIT (12.3, 12.5), with its
    /// `history` and `send` settings. The account must own the room and be
    /// its only member, and the room's id must be known on this connection
    /// (JOIN or INFO first). The room is private for good afterwards.
    pub fn encrypt_room(
        &mut self,
        room: &risala_proto::names::Room,
        history: risala_proto::types::HistoryMode,
        send: risala_proto::types::SendMode,
    ) -> Result<super::Output, SyncError> {
        let conv = Conv::Room(room.clone());
        if !self.is_live(&conv) {
            return Err(SyncError::NotJoined(conv));
        }
        if !self.has_e2ee() || !self.start_room(&conv, history, send)? {
            return Err(SyncError::Invalid(format!(
                "{room} cannot be encrypted now"
            )));
        }
        Ok(self.finish())
    }

    /// Invites `uid` to `room` (6.4): in an encrypted room by adding its
    /// devices to the group with a commit (12.6), otherwise with INVITE.
    /// Returns the request whose answer says how it went, for INVITE.
    pub fn invite(
        &mut self,
        room: &risala_proto::names::Room,
        uid: &Uid,
    ) -> Result<super::Output, SyncError> {
        let conv = Conv::Room(room.clone());
        let account = self.account;
        let encrypted = self.write(|tx| match tx.conv_by_name(account, &conv)? {
            Some(row) => Ok(tx.group(row.id)?.is_some()),
            None => Ok(false),
        })?;
        if encrypted {
            if !self.has_e2ee() {
                return Err(SyncError::Invalid("no device key".into()));
            }
            self.invite_encrypted(&conv, uid);
            return Ok(self.finish());
        }
        Ok(self.request(Command::Invite {
            room: room.clone(),
            uid: uid.clone(),
        }))
    }

    /// Whether encryption is on for this connection.
    pub(super) fn has_e2ee(&self) -> bool {
        self.e2ee.as_ref().is_some_and(|e| !e.recovery_conn)
    }

    /// Runs `f` in a write transaction that may fail with an encryption
    /// error, which rolls it back. A store error ends the engine as
    /// usual; the others are handed back.
    pub(super) fn e2ee_write<T>(
        &mut self,
        f: impl FnOnce(&mut Tx<'_>) -> Result<T, E2eeError>,
    ) -> Result<Result<T, E2eeError>, SyncError> {
        let me = self.me.clone();
        match self.store.write_with(|tx| {
            tx.signed_in_as(&me);
            f(tx)
        }) {
            Ok((t, changes)) => {
                self.out.changes.extend(changes);
                Ok(Ok(t))
            }
            Err(E2eeError::Store(e)) => Err(SyncError::Store(e)),
            Err(e) => Ok(Err(e)),
        }
    }

    fn device(&self) -> Option<Device> {
        self.e2ee
            .as_ref()
            .filter(|e| !e.recovery_conn)
            .map(|e| e.dev.clone())
    }

    pub(super) fn e2(&mut self) -> &mut E2ee {
        self.e2ee.as_mut().expect("encryption is on")
    }

    /// Starts the encryption engine on a new connection: KEYPKG COUNT and
    /// WELCOME LIST (12.4, 12.7).
    pub(super) fn e2ee_start(&mut self) {
        if !self.has_e2ee() {
            return;
        }
        self.issue(
            Command::KeyPkg(KeyPkgCommand::Count),
            Pending::E2ee(E2eePending::KeyPkgCount),
        );
        self.issue(
            Command::Welcome(WelcomeCommand::List),
            Pending::E2ee(E2eePending::WelcomeList),
        );
    }

    /// Handles a line the encryption engine uses: a live WELCOME (12.7).
    pub(super) fn e2ee_line(&mut self, line: &ServerLine) -> Result<(), SyncError> {
        if !self.has_e2ee() {
            return Ok(());
        }
        if let ServerLine::Welcome {
            conv,
            id,
            seq,
            welcome,
            tree,
        } = line
        {
            self.on_welcome(WelcomeLine {
                conv: conv.clone(),
                id: id.clone(),
                seq: *seq,
                welcome: welcome.clone(),
                tree: tree.clone(),
            })?;
        }
        Ok(())
    }

    /// Handles the reply to an encryption command.
    pub(super) fn on_e2ee(
        &mut self,
        req: ReqId,
        pending: E2eePending,
        reply: Reply,
    ) -> Result<(), SyncError> {
        let _ = req;
        match pending {
            E2eePending::KeyPkgCount => self.on_keypkg_count(&reply),
            E2eePending::Shared { devices } => self.on_shared(devices, &reply),
            E2eePending::BackupAdd { id, epoch, key_id } => {
                self.on_backup_add(id, epoch, key_id, &reply)
            }
            E2eePending::KeyPkgAdd | E2eePending::WelcomeDel => {
                if let Outcome::Err(e) = &reply.outcome {
                    debug!(code = %e.code, "an encryption command was refused");
                }
                Ok(())
            }
            E2eePending::WelcomeList => {
                for msg in &reply.lines {
                    self.e2ee_line(&msg.line)?;
                }
                if let Some(e) = self.e2ee.as_mut() {
                    e.welcomes_listed = true;
                }
                self.e2ee_all()?;
                // Messages to direct conversations that have not started
                // waited for this: INIT may go now (12.6).
                self.flush_outbox()
            }
            E2eePending::Init { conv } => self.on_init(&conv, reply),
            E2eePending::Commit {
                conv,
                commit,
                purpose,
            } => self.on_commit(&conv, &commit, purpose, reply),
            E2eePending::GroupInfo { conv } => self.on_groupinfo(&conv, reply),
            E2eePending::KeyPkgGet { conv, uid, purpose } => {
                self.on_keypkg_get(&conv, &uid, purpose, reply)
            }
        }
    }

    // -----------------------------------------------------------------------
    // KeyPackages (12.4)

    fn on_keypkg_count(&mut self, reply: &Reply) -> Result<(), SyncError> {
        let Some(dev) = self.device() else {
            return Ok(());
        };
        let Outcome::Ok(ok) = &reply.outcome else {
            return Ok(());
        };
        let count: u64 = ok.value("count").and_then(|c| c.parse().ok()).unwrap_or(0);
        let last_resort = ok.value("last-resort") == Some("yes");
        let ordinary = if count < KEY_PACKAGES_LOW {
            (KEY_PACKAGES - count) as usize
        } else {
            0
        };
        if ordinary == 0 && last_resort {
            return Ok(());
        }
        let made = self.e2ee_write(|tx| {
            let mut out = group::key_packages(tx, &dev, ordinary, false)?;
            if !last_resort {
                out.extend(group::key_packages(tx, &dev, 1, true)?);
            }
            Ok(out)
        })?;
        match made {
            Ok(packages) => {
                for key_package in packages {
                    self.issue(
                        Command::KeyPkg(KeyPkgCommand::Add { key_package }),
                        Pending::E2ee(E2eePending::KeyPkgAdd),
                    );
                }
            }
            Err(e) => warn!(error = %e, "making KeyPackages"),
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Welcomes (12.7)

    fn on_welcome(&mut self, w: WelcomeLine) -> Result<(), SyncError> {
        let Some(dev) = self.device() else {
            return Ok(());
        };
        let account = self.account;
        let conv = w.conv.clone();
        let row = self.write(|tx| tx.conv_or_create(account, &conv))?;
        // 12.6: the group's conversation extension must name the room by
        // the id JOIN, INFO or SYNC reported; ask INFO first.
        if row.conv_id.is_none() {
            if let Conv::Room(room) = &conv {
                let room = room.clone();
                self.e2().deferred.push(w);
                self.issue_info(&room);
            } else {
                // A direct conversation's id comes with SYNC.
                self.e2().deferred.push(w);
                self.want_sync = true;
            }
            return Ok(());
        }
        let result = self.e2ee_write(|tx| {
            group::join_welcome(tx, &dev, &row, &w.welcome, &w.tree, w.seq.get())
        })?;
        let delete = match result {
            Ok(Joined::Joined { leaves, .. }) => {
                debug!(%conv, "joined a group by Welcome");
                self.check_keys(leaves.iter().map(|(u, _)| u.clone()))?;
                self.e2ee_advance(&conv)?;
                true
            }
            Ok(Joined::Already) => true,
            Err(E2eeError::Rejected(why)) => {
                // 12.7: a Welcome whose group fails the checks goes too.
                warn!(%conv, why, "a Welcome's group fails the checks of 12.6");
                true
            }
            Err(e) => {
                // Kept on the server, to try again (12.7).
                warn!(%conv, error = %e, "joining by Welcome failed");
                false
            }
        };
        if delete {
            self.issue(
                Command::Welcome(WelcomeCommand::Del { id: w.id }),
                Pending::E2ee(E2eePending::WelcomeDel),
            );
        }
        Ok(())
    }

    /// Whether a Welcome of `conv` waits for its id.
    pub(super) fn has_deferred(&self, conv: &Conv) -> bool {
        self.e2ee
            .as_ref()
            .is_some_and(|e| e.deferred.iter().any(|w| w.conv == *conv))
    }

    /// The id of `conv` was learned: Welcomes that waited for it, and the
    /// conversation's group (12.6, 12.7).
    pub(super) fn e2ee_learned(&mut self, conv: &Conv) -> Result<(), SyncError> {
        if self.e2ee.is_none() {
            return Ok(());
        }
        self.retry_deferred()?;
        self.e2ee_advance(conv)
    }

    /// Tries the Welcomes that waited for their conversation's id.
    fn retry_deferred(&mut self) -> Result<(), SyncError> {
        let Some(e) = self.e2ee.as_mut() else {
            return Ok(());
        };
        let waiting = std::mem::take(&mut e.deferred);
        let account = self.account;
        for w in waiting {
            let known = self
                .store
                .write(|tx| Ok(tx.conv_by_name(account, &w.conv)?.and_then(|r| r.conv_id)))
                .map(|(id, _)| id)?;
            if known.is_some() {
                self.on_welcome(w)?;
            } else {
                self.e2().deferred.push(w);
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Advancing a conversation

    /// Brings every encrypted conversation of the account up to date.
    pub(super) fn e2ee_all(&mut self) -> Result<(), SyncError> {
        if self.e2ee.is_none() {
            return Ok(());
        }
        self.retry_deferred()?;
        // 12.9: the conversation with itself carries history keys between
        // the identity's devices. The first device starts it; the others
        // join it.
        let me = Conv::Uid(self.me.clone());
        if self.listed && self.e2ee.as_ref().is_some_and(|e| e.welcomes_listed) {
            self.start_direct(&me)?;
        }
        let account = self.account;
        let names = self.write(|tx| {
            Ok(tx
                .convs(account)?
                .into_iter()
                .map(|r| r.name)
                .collect::<Vec<_>>())
        })?;
        // The conversation with itself first (12.6).
        let me = Conv::Uid(self.me.clone());
        let mut names: Vec<Conv> = names;
        names.sort_by_key(|c| *c != me);
        for conv in names {
            self.e2ee_advance(&conv)?;
        }
        Ok(())
    }

    /// Brings one conversation up to date: applies its commits in order,
    /// decrypts what it can, joins its group if it should, and does the
    /// device's duties in it (12.5-12.9).
    pub(super) fn e2ee_advance(&mut self, conv: &Conv) -> Result<(), SyncError> {
        if self.e2ee.is_none() {
            return Ok(());
        }
        if self.has_e2ee() {
            self.apply_commits(conv)?;
        }
        self.decrypt(conv)?;
        if self.has_e2ee() {
            self.maybe_join(conv)?;
            self.duties(conv)?;
            if self
                .e2ee
                .as_ref()
                .is_some_and(|e| e.to_share.contains(conv))
            {
                self.share_room_keys(conv)?;
            }
            self.own_devices(conv)?;
        }
        self.backup_keys()
    }

    /// Applies the conversation's stored COMMIT events in seq order, as
    /// far as every event before them is stored (12.5, 12.6).
    fn apply_commits(&mut self, conv: &Conv) -> Result<(), SyncError> {
        let Some(dev) = self.device() else {
            return Ok(());
        };
        if self
            .e2ee
            .as_ref()
            .is_some_and(|e| e.waiting.contains_key(conv))
        {
            return Ok(());
        }
        let account = self.account;
        let mut after = None;
        loop {
            let next = self.write(|tx| {
                let Some(row) = tx.conv_by_name(account, conv)? else {
                    return Ok(None);
                };
                let Some(g) = tx.group(row.id)? else {
                    return Ok(None);
                };
                if !matches!(g.state, GroupState::Active | GroupState::Init) {
                    return Ok(None);
                }
                let from = after.unwrap_or(if g.state == GroupState::Active {
                    g.commit_seq
                } else {
                    0
                });
                next_commit(tx, &row, from)
            })?;
            let Some((row, seq, epoch, commit)) = next else {
                return Ok(());
            };
            after = Some(seq);
            let fresh = self
                .e2ee
                .as_ref()
                .map(|e| e.fresh.clone())
                .unwrap_or_default();
            let result = self.e2ee_write(|tx| {
                group::apply_commit(tx, &dev, &row, (seq, epoch), &commit, &fresh)
            })?;
            match result {
                Ok(Applied::Merged { added, own, .. }) => {
                    debug!(%conv, seq, epoch, own, "applied a commit");
                    if let Some(e) = self.e2ee.as_mut() {
                        e.held.remove(conv);
                        e.fresh.clear();
                    }
                    self.check_keys(added.into_iter().map(|(u, _)| u))?;
                }
                Ok(Applied::Old) => {}
                Ok(Applied::Removed) => {
                    debug!(%conv, "removed from the group");
                    return Ok(());
                }
                Ok(Applied::Ahead) => {
                    // The commit before it expired (7.5, 12.11): join
                    // again by external commit.
                    let _ = self.e2ee_write(|tx| group::mark(tx, &row, GroupState::Broken))?;
                    return Ok(());
                }
                Err(E2eeError::Rejected(why)) => {
                    warn!(%conv, seq, why, "a commit fails the checks of 12.6");
                    let _ = self.e2ee_write(|tx| group::mark(tx, &row, GroupState::Rejected))?;
                    self.out
                        .notifications
                        .push(Notification::GroupRejected { conv: conv.clone() });
                    return Ok(());
                }
                Err(E2eeError::KeyFiles(uids)) => {
                    let set: HashSet<Uid> = uids.iter().cloned().collect();
                    self.e2().waiting.insert(conv.clone(), set);
                    for uid in uids {
                        self.fetch_key_file(&uid);
                    }
                    return Ok(());
                }
                Err(e) => {
                    // MLS refused it (12.6): join again by external commit.
                    warn!(%conv, seq, error = %e, "a commit could not be applied");
                    let _ = self.e2ee_write(|tx| group::mark(tx, &row, GroupState::Broken))?;
                    return Ok(());
                }
            }
        }
    }

    /// Decrypts the conversation's ENC events whose keys are here, and
    /// acts on the KEY and RECOVERY lines among them (12.8-12.10).
    fn decrypt(&mut self, conv: &Conv) -> Result<(), SyncError> {
        let account = self.account;
        let me = self.me.clone();
        let cascade = self.write(|tx| tx.decrypt_cascade(account, &me, vec![conv.clone()]))?;
        self.after_cascade(cascade);
        Ok(())
    }

    /// Reports what decrypting led to: conflicting keys (12.9), and a
    /// recovery key from another device (12.10).
    pub(super) fn after_cascade(&mut self, cascade: crate::store::e2ee::Cascade) {
        for (id, epoch) in cascade.conflicts {
            self.out
                .notifications
                .push(Notification::KeyConflict { id, epoch });
        }
        if let Some(key) = cascade.recovery {
            self.keep_recovery_key(Some(key.clone()));
            self.out.recovery = Some(key);
        }
    }

    /// Joins the conversation's group by external commit, if it should be
    /// encrypted and the device follows no group of it (12.6).
    fn maybe_join(&mut self, conv: &Conv) -> Result<(), SyncError> {
        let Some(e) = self.e2ee.as_ref() else {
            return Ok(());
        };
        if !e.welcomes_listed || e.busy.contains(conv) || e.rejoined.contains(conv) {
            return Ok(());
        }
        if !self.is_live(conv) {
            return Ok(());
        }
        let account = self.account;
        let wanted = self.write(|tx| {
            let Some(row) = tx.conv_by_name(account, conv)? else {
                return Ok(false);
            };
            if !row.joined || row.conv_id.is_none() {
                return Ok(false);
            }
            let group = tx.group(row.id)?;
            let needs = match group.map(|g| g.state) {
                None => match &row.name {
                    Conv::Uid(_) => true,
                    Conv::Room(_) => room_setting(tx, &row, "e2ee")?.as_deref() == Some("yes"),
                },
                Some(GroupState::Broken) => true,
                Some(_) => false,
            };
            Ok(needs)
        })?;
        if wanted {
            self.e2().busy.insert(conv.clone());
            self.e2().rejoined.insert(conv.clone());
            self.issue(
                Command::GroupInfo { conv: conv.clone() },
                Pending::E2ee(E2eePending::GroupInfo { conv: conv.clone() }),
            );
        }
        Ok(())
    }

    fn on_groupinfo(&mut self, conv: &Conv, reply: Reply) -> Result<(), SyncError> {
        self.e2().busy.remove(conv);
        let Some(dev) = self.device() else {
            return Ok(());
        };
        let found = reply.lines.iter().find_map(|m| match &m.line {
            ServerLine::GroupInfo {
                conv: c,
                group_info,
                tree,
                ..
            } if c == conv => Some((group_info.clone(), tree.clone())),
            _ => None,
        });
        let (Outcome::Ok(_), Some((info, tree))) = (&reply.outcome, found) else {
            return Ok(());
        };
        let account = self.account;
        let Some(row) = self.write(|tx| tx.conv_by_name(account, conv))? else {
            return Ok(());
        };
        match self.e2ee_write(|tx| group::external_join(tx, &dev, &row, &info, &tree))? {
            Ok(commit) => self.send_commit(conv, commit, Purpose::Join),
            Err(e) => warn!(%conv, error = %e, "joining by external commit"),
        }
        Ok(())
    }

    fn send_commit(&mut self, conv: &Conv, c: group::Commit, purpose: Purpose) {
        self.e2().busy.insert(conv.clone());
        self.issue(
            Command::Commit {
                conv: conv.clone(),
                commit: c.commit.clone(),
                group_info: c.group_info,
                welcome: c.welcome,
            },
            Pending::E2ee(E2eePending::Commit {
                conv: conv.clone(),
                commit: c.commit,
                purpose,
            }),
        );
    }

    fn on_commit(
        &mut self,
        conv: &Conv,
        commit: &mls::CommitMessage,
        purpose: Purpose,
        reply: Reply,
    ) -> Result<(), SyncError> {
        self.e2().busy.remove(conv);
        let Some(dev) = self.device() else {
            return Ok(());
        };
        let account = self.account;
        let Some(row) = self.write(|tx| tx.conv_by_name(account, conv))? else {
            return Ok(());
        };
        match &reply.outcome {
            // The COMMIT event came before the OK and was applied.
            Outcome::Ok(_) => {
                if purpose == Purpose::Invite {
                    self.e2().invites.remove(conv);
                }
                self.e2ee_advance(conv)?;
                if purpose == Purpose::Invite {
                    self.share_room_keys(conv)?;
                }
                self.retry_invite(conv)?;
                self.flush_outbox()?;
            }
            Outcome::Err(err) => {
                debug!(%conv, code = %err.code, ?purpose, "a commit was refused");
                let _ = self.e2ee_write(|tx| group::commit_refused(tx, &dev, &row, commit))?;
                if err.code != ErrorCode::Stale {
                    if purpose == Purpose::Invite {
                        warn!(%conv, code = %err.code, "an invitation was refused");
                        self.e2().invites.remove(conv);
                    }
                    if purpose == Purpose::Join {
                        return Ok(());
                    }
                }
                // 12.5: apply what came first, then try again if needed.
                if let Some(e) = self.e2ee.as_mut() {
                    e.rejoined.remove(conv);
                }
                self.e2ee_advance(conv)?;
                self.retry_invite(conv)?;
            }
            Outcome::Failed | Outcome::NotSent => {
                let _ = self.e2ee_write(|tx| group::commit_refused(tx, &dev, &row, commit))?;
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Starting groups (12.5, 12.6)

    /// Creates a direct conversation's group and starts it with INIT
    /// (12.5, 12.6), if it has none.
    pub(super) fn start_direct(&mut self, conv: &Conv) -> Result<(), SyncError> {
        let Some(dev) = self.device() else {
            return Ok(());
        };
        let Conv::Uid(other) = conv else {
            return Ok(());
        };
        if self.e2ee.as_ref().is_some_and(|e| {
            e.busy.contains(conv) || !e.welcomes_listed || e.init_refused.contains(conv)
        }) {
            return Ok(());
        }
        let account = self.account;
        let conversation = RisalaConversation::direct(&self.me, other);
        let init = self.e2ee_write(|tx| {
            let row = tx.conv_or_create(account, conv)?;
            // A conversation that exists is joined, not started (12.6).
            if row.conv_id.is_some() || tx.group(row.id)?.is_some() {
                return Ok(None);
            }
            group::create(tx, &dev, &row, &conversation, group::now_ms()).map(Some)
        })?;
        match init {
            Ok(Some(init)) => {
                self.e2().busy.insert(conv.clone());
                self.issue(
                    Command::Init {
                        conv: conv.clone(),
                        group_info: init.group_info,
                        tree: init.tree,
                    },
                    Pending::E2ee(E2eePending::Init { conv: conv.clone() }),
                );
            }
            Ok(None) => {}
            Err(e) => warn!(%conv, error = %e, "creating a group"),
        }
        Ok(())
    }

    /// Makes a room encrypted with INIT (12.3, 12.5): the account must own
    /// it and be its only member, and its id must be known.
    pub(super) fn start_room(
        &mut self,
        conv: &Conv,
        history: risala_proto::types::HistoryMode,
        send: risala_proto::types::SendMode,
    ) -> Result<bool, SyncError> {
        let Some(dev) = self.device() else {
            return Ok(false);
        };
        let account = self.account;
        let init = self.e2ee_write(|tx| {
            let Some(row) = tx.conv_by_name(account, conv)? else {
                return Ok(None);
            };
            let Some(id) = row.conv_id.clone() else {
                return Ok(None);
            };
            let conversation = RisalaConversation::room(&id, history, send);
            group::create(tx, &dev, &row, &conversation, group::now_ms()).map(Some)
        })?;
        match init {
            Ok(Some(init)) => {
                self.e2().busy.insert(conv.clone());
                self.issue(
                    Command::Init {
                        conv: conv.clone(),
                        group_info: init.group_info,
                        tree: init.tree,
                    },
                    Pending::E2ee(E2eePending::Init { conv: conv.clone() }),
                );
                Ok(true)
            }
            Ok(None) => Ok(false),
            Err(e) => {
                warn!(%conv, error = %e, "creating a group");
                Ok(false)
            }
        }
    }

    fn on_init(&mut self, conv: &Conv, reply: Reply) -> Result<(), SyncError> {
        self.e2().busy.remove(conv);
        let Some(dev) = self.device() else {
            return Ok(());
        };
        let account = self.account;
        match &reply.outcome {
            Outcome::Ok(ok) => {
                let id = ok.id().ok().flatten();
                let joined = self.e2ee_write(|tx| {
                    let Some(mut row) = tx.conv_by_name(account, conv)? else {
                        return Ok(false);
                    };
                    if let Some(id) = &id {
                        tx.learn_id(&mut row, id, None)?;
                        tx.set_joined(&mut row, true)?;
                    }
                    group::init_accepted(tx, &dev, &row)?;
                    Ok(true)
                })?;
                if let Some(id) = id {
                    self.confirm(conv, id);
                }
                match joined {
                    Ok(true) => {
                        self.check_fill(conv)?;
                        // 12.6: add the other participant's devices and
                        // the identity's own other devices.
                        if let Conv::Uid(other) = conv {
                            let other = other.clone();
                            let me = self.me.clone();
                            self.ask_packages(conv, &other);
                            if other != me {
                                self.ask_packages(conv, &me);
                            }
                        }
                    }
                    Ok(false) => {}
                    Err(e) => warn!(%conv, error = %e, "INIT was accepted, but the group was not"),
                }
            }
            Outcome::Err(err) => {
                debug!(%conv, code = %err.code, "INIT was refused");
                let _ = self.e2ee_write(|tx| match tx.conv_by_name(account, conv)? {
                    Some(row) => group::abandon(tx, &row),
                    None => Ok(()),
                })?;
                // 12.6: someone started it first. Join its group by
                // external commit; its id comes with SYNC once the
                // commit is an event. A conversation whose only event is
                // its INIT has no head yet, so SYNC cannot list it.
                if err.code != ErrorCode::Stale {
                    self.e2().init_refused.insert(conv.clone());
                } else if !self.e2().rejoined.contains(conv) {
                    self.e2().busy.insert(conv.clone());
                    self.e2().rejoined.insert(conv.clone());
                    self.issue(
                        Command::GroupInfo { conv: conv.clone() },
                        Pending::E2ee(E2eePending::GroupInfo { conv: conv.clone() }),
                    );
                }
            }
            Outcome::Failed | Outcome::NotSent => {}
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Adding devices (12.6)

    /// Asks for `uid`'s KeyPackages to add its devices to `conv`'s group,
    /// once per connection.
    fn ask_packages(&mut self, conv: &Conv, uid: &Uid) {
        if !self.e2().asked.insert(uid.clone()) {
            return;
        }
        self.issue(
            Command::KeyPkg(KeyPkgCommand::Get { uid: uid.clone() }),
            Pending::E2ee(E2eePending::KeyPkgGet {
                conv: conv.clone(),
                uid: uid.clone(),
                purpose: Purpose::Duties,
            }),
        );
    }

    fn on_keypkg_get(
        &mut self,
        conv: &Conv,
        uid: &Uid,
        purpose: Purpose,
        reply: Reply,
    ) -> Result<(), SyncError> {
        let Some(dev) = self.device() else {
            return Ok(());
        };
        if !matches!(reply.outcome, Outcome::Ok(_)) {
            return Ok(());
        }
        let mut packages: Vec<(KeyPackage, PublicKey)> = Vec::new();
        for m in &reply.lines {
            if let ServerLine::KeyPkg {
                uid: u,
                key_package,
            } = &m.line
                && u == uid
            {
                match group::checked_key_package(&dev, uid, key_package) {
                    Ok(p) => packages.push(p),
                    Err(e) => warn!(%uid, error = %e, "a KeyPackage from KEYPKG GET"),
                }
            }
        }
        if purpose == Purpose::Invite {
            if packages.is_empty() {
                warn!(%conv, %uid, "no KeyPackages to invite with");
            } else {
                self.e2()
                    .invites
                    .entry(conv.clone())
                    .or_default()
                    .extend(packages);
                self.retry_invite(conv)?;
            }
        } else {
            self.add_devices(conv, packages, purpose)?;
        }
        self.check_keys(std::iter::once(uid.clone()))
    }

    /// Commits the invitations waiting for `conv`, unless another commit
    /// of this device's is in flight there, whose answer tries again. Once
    /// every invitee's device has a leaf, the invitations are done.
    fn retry_invite(&mut self, conv: &Conv) -> Result<(), SyncError> {
        let Some(e) = self.e2ee.as_ref() else {
            return Ok(());
        };
        if e.busy.contains(conv) {
            return Ok(());
        }
        let Some(packages) = e.invites.get(conv).cloned() else {
            return Ok(());
        };
        self.add_devices(conv, packages, Purpose::Invite)?;
        if !self.e2ee.as_ref().is_some_and(|e| e.busy.contains(conv)) {
            // Nothing left to add, or it cannot be done.
            self.e2().invites.remove(conv);
        }
        Ok(())
    }

    /// Commits the addition of devices that have no leaf yet (12.6).
    fn add_devices(
        &mut self,
        conv: &Conv,
        packages: Vec<(KeyPackage, PublicKey)>,
        purpose: Purpose,
    ) -> Result<(), SyncError> {
        let Some(dev) = self.device() else {
            return Ok(());
        };
        if self.e2ee.as_ref().is_some_and(|e| e.busy.contains(conv)) {
            return Ok(());
        }
        let account = self.account;
        let made = self.e2ee_write(|tx| {
            let Some(row) = tx.conv_by_name(account, conv)? else {
                return Ok(None);
            };
            let Some(leaves) = group::current_leaves(tx, &row)? else {
                return Ok(None);
            };
            let mut keys: HashSet<Vec<u8>> =
                leaves.iter().map(|l| l.key.as_bytes().to_vec()).collect();
            let add: Vec<KeyPackage> = packages
                .into_iter()
                .filter(|(_, k)| keys.insert(k.as_bytes().to_vec()))
                .map(|(p, _)| p)
                .take(MAX_ADDS)
                .collect();
            if add.is_empty() {
                return Ok(None);
            }
            group::own_commit(
                tx,
                &dev,
                &row,
                Changes {
                    add,
                    ..Changes::default()
                },
            )
            .map(Some)
        })?;
        match made {
            Ok(Some(c)) => self.send_commit(conv, c, purpose),
            Ok(None) => {}
            Err(e) => warn!(%conv, error = %e, "adding devices"),
        }
        Ok(())
    }

    /// Invites `uid` to an encrypted room, by adding its devices to the
    /// room's group (12.6). The server records the INVITE.
    pub(super) fn invite_encrypted(&mut self, conv: &Conv, uid: &Uid) {
        self.issue(
            Command::KeyPkg(KeyPkgCommand::Get { uid: uid.clone() }),
            Pending::E2ee(E2eePending::KeyPkgGet {
                conv: conv.clone(),
                uid: uid.clone(),
                purpose: Purpose::Invite,
            }),
        );
    }

    /// Sends, right after this device's commit that added someone to a
    /// room whose `history` is `shared`, every earlier history key of the
    /// room it holds, as KEY lines in ENC (12.9). Under `joined`, none.
    fn share_room_keys(&mut self, conv: &Conv) -> Result<(), SyncError> {
        let account = self.account;
        let found = self.e2ee_write(|tx| {
            let Some(row) = tx.conv_by_name(account, conv)? else {
                return Ok(None);
            };
            if group::history_mode(tx, &row)? != Some(risala_proto::types::HistoryMode::Shared) {
                return Ok(None);
            }
            let Some(g) = tx.group(row.id)? else {
                return Ok(None);
            };
            let Some(id) = row.conv_id.clone() else {
                return Ok(None);
            };
            let keys: Vec<Control> = tx
                .history_keys(account, &id)?
                .into_iter()
                .filter(|k| k.epoch < g.epoch)
                .map(|k| Control::Key {
                    id: id.clone(),
                    epoch: k.epoch,
                    key: k.key,
                })
                .collect();
            if keys.is_empty() {
                return Ok(None);
            }
            Ok(Some((row, keys)))
        })?;
        match found {
            Ok(Some((row, keys))) => {
                self.send_control_for(conv, &row, keys, None)?;
                Ok(())
            }
            Ok(None) => Ok(()),
            Err(e) => {
                warn!(%conv, error = %e, "sharing a room's history keys");
                Ok(())
            }
        }
    }

    /// Sends KEY or RECOVERY lines in ENC, as many messages as they need,
    /// in the group's current epoch (12.8-12.10). The last one carries
    /// `devices`, for [`on_shared`](Self::on_shared). Returns whether they
    /// went; a room's keys that could not are tried again later.
    pub(super) fn send_control_for(
        &mut self,
        conv: &Conv,
        row: &ConvRow,
        lines: Vec<Control>,
        devices: Option<Vec<Vec<u8>>>,
    ) -> Result<bool, SyncError> {
        // A KEY line is about 90 bytes: well under 4 MiB per message.
        const PER_MESSAGE: usize = 40_000;
        let plan = self.write(|tx| SyncEngine::enc_ready(tx, row, None, false))?;
        let plan = match plan {
            EncReady::Go(plan) => plan,
            other => {
                debug!(%conv, "the group is not ready to share keys");
                if let EncReady::Unconfirmed(uids) = other {
                    self.check_keys(uids)?;
                }
                if conv.is_room() {
                    self.e2().to_share.insert(conv.clone());
                }
                return Ok(false);
            }
        };
        self.e2().to_share.remove(conv);
        let Some(e) = self.e2ee.as_ref() else {
            return Ok(false);
        };
        let mut commands = Vec::new();
        for chunk in lines.chunks(PER_MESSAGE) {
            let content = Content::Control(chunk.to_vec()).encode();
            let enc = risala_mls::encrypt(
                &e.dev.signer(),
                &plan.key,
                &plan.group_id,
                plan.epoch,
                &content,
            )
            .map_err(|e| SyncError::Invalid(e.to_string()))?;
            commands.push(Command::Enc {
                conv: conv.clone(),
                epoch: plan.epoch,
                payload: enc.payload,
                frank: Some(enc.frank),
                file: None,
                cid: None,
            });
        }
        let last = commands.len().saturating_sub(1);
        let mut devices = devices;
        for (i, command) in commands.into_iter().enumerate() {
            let devices = if i == last { devices.take() } else { None };
            self.issue(command, Pending::E2ee(E2eePending::Shared { devices }));
        }
        Ok(true)
    }

    // -----------------------------------------------------------------------
    // Duties (12.6)

    /// Removes leaves that must go, and refreshes the device's own leaf
    /// about once a week (12.6). One commit at a time.
    fn duties(&mut self, conv: &Conv) -> Result<(), SyncError> {
        let Some(dev) = self.device() else {
            return Ok(());
        };
        if self
            .e2ee
            .as_ref()
            .is_some_and(|e| e.busy.contains(conv) || e.waiting.contains_key(conv))
        {
            return Ok(());
        }
        let account = self.account;
        let now = group::now_ms();
        let made = self.e2ee_write(|tx| {
            let Some(row) = tx.conv_by_name(account, conv)? else {
                return Ok(None);
            };
            // Only once every event is stored, so that the room's PART,
            // KICK and BAN events are known (12.6).
            if row.sync_point < row.head {
                return Ok(None);
            }
            let Some(g) = tx.group(row.id)? else {
                return Ok(None);
            };
            if g.state != GroupState::Active || g.pending.is_some() {
                return Ok(None);
            }
            let Some(leaves) = group::current_leaves(tx, &row)? else {
                return Ok(None);
            };
            let mut remove: Vec<LeafNodeIndex> = Vec::new();
            for leaf in &leaves {
                let gone = tx.key_listed(account, &leaf.uid, &leaf.key)? == Some(false)
                    || (row.name.is_room() && left(tx, &row, &leaf.uid)?);
                if gone && leaf.key != dev.key.public_key() {
                    remove.push(leaf.index);
                }
            }
            let stale = now.saturating_sub(g.refreshed) > REFRESH.as_millis() as i64;
            if remove.is_empty() && !stale {
                return Ok(None);
            }
            group::own_commit(
                tx,
                &dev,
                &row,
                Changes {
                    remove,
                    ..Changes::default()
                },
            )
            .map(Some)
        })?;
        match made {
            Ok(Some(c)) => self.send_commit(conv, c, Purpose::Duties),
            Ok(None) => {}
            Err(e) => warn!(%conv, error = %e, "a commit of the device's duties"),
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Key files (12.12)

    /// Asks for the key files of `uids` that are older than a day, or
    /// were never fetched (12.12).
    fn check_keys(&mut self, uids: impl IntoIterator<Item = Uid>) -> Result<(), SyncError> {
        let account = self.account;
        let now = group::now_ms();
        for uid in uids {
            if !uid.is_identity() {
                continue;
            }
            let ((fetched, tried), unknown) = self.write(|tx| {
                Ok((
                    tx.key_file_times(account, &uid)?,
                    tx.has_unknown_keys(account, &uid)?,
                ))
            })?;
            // A key no fetch has told about yet, such as a new leaf's, is
            // checked at once; otherwise once a day, and a failed fetch is
            // tried again after a while (12.6, 12.12).
            let due = match (fetched, tried) {
                _ if unknown => true,
                (Some(f), _) if now - f < KEY_FILE_AGE.as_millis() as i64 => false,
                (_, Some(t)) if now - t < KEY_FILE_RETRY.as_millis() as i64 => false,
                _ => true,
            };
            if due {
                self.fetch_key_file(&uid);
            }
        }
        Ok(())
    }

    /// Asks for the key files that would confirm the leaves of groups the
    /// outbox waits for (12.6).
    pub(super) fn check_unconfirmed(&mut self, uids: Vec<Uid>) -> Result<(), SyncError> {
        if uids.is_empty() || self.e2ee.is_none() {
            return Ok(());
        }
        self.check_keys(uids)
    }

    /// Whether a key file asked for has not been handed back yet.
    pub(super) fn fetching_key_files(&self) -> bool {
        self.e2ee.as_ref().is_some_and(|e| !e.fetching.is_empty())
    }

    fn fetch_key_file(&mut self, uid: &Uid) {
        if self.e2().fetching.insert(uid.clone()) {
            self.out.key_files.push(uid.clone());
        }
    }

    /// Hands back a key file asked for in
    /// [`Output::key_files`](super::Output::key_files): its keys and their
    /// labels, or `None` if it could not be fetched (4.4, 12.12). A key
    /// file that is gone lists no keys.
    pub fn key_file(
        &mut self,
        uid: &Uid,
        keys: Option<Vec<(PublicKey, Option<String>)>>,
    ) -> Result<super::Output, SyncError> {
        if self.e2ee.is_none() {
            return Ok(self.finish());
        }
        self.e2().fetching.remove(uid);
        let account = self.account;
        let now = group::now_ms();
        let failed = keys.is_none();
        self.write(|tx| tx.key_file_fetched(account, uid, keys.as_deref(), now))?;
        // Commits that waited for it, once it says something.
        let mut ready = Vec::new();
        if let Some(e) = self.e2ee.as_mut() {
            for (conv, uids) in &mut e.waiting {
                if !failed && uids.remove(uid) {
                    e.fresh.insert(uid.clone());
                }
                if uids.is_empty() {
                    ready.push(conv.clone());
                }
            }
            for conv in &ready {
                e.waiting.remove(conv);
            }
        }
        for conv in ready {
            self.e2ee_advance(&conv)?;
        }
        if !failed {
            // Leaves to remove, and messages that waited for confirmed
            // leaves.
            self.e2ee_all()?;
            self.flush_outbox()?;
        }
        Ok(self.finish())
    }

    // -----------------------------------------------------------------------
    // Sending (12.8)

    /// Whether an outbox entry for `row`, an encrypted conversation, can go
    /// now, and with what (12.6, 12.8). A direct conversation with no
    /// group yet is started.
    pub(super) fn enc_ready(
        tx: &Tx<'_>,
        row: &ConvRow,
        relation: Option<risala_proto::types::Relation>,
        held: bool,
    ) -> Result<EncReady, StoreError> {
        let Some(g) = tx.group(row.id)? else {
            return Ok(EncReady::Wait);
        };
        let Some(conv_id) = &row.conv_id else {
            return Ok(EncReady::Wait);
        };
        if g.state != GroupState::Active || g.pending.is_some() || held {
            return Ok(EncReady::Wait);
        }
        // 12.6: nothing goes while a leaf is not confirmed.
        let unconfirmed: Vec<Uid> = {
            let mut stmt = tx.conn().prepare_cached(
                "SELECT DISTINCT l.uid FROM epoch_leaves l
                 LEFT JOIN device_keys d ON d.account = l.account AND d.key_id = l.key_id
                 WHERE l.account = ?1 AND l.conv_id = ?2 AND l.epoch = ?3
                     AND COALESCE(d.listed, 0) != 1",
            )?;
            let rows = stmt.query_map(
                params![row.account.get(), conv_id.as_str(), sql(g.epoch)],
                |r| r.get::<_, String>(0),
            )?;
            let mut out = Vec::new();
            for r in rows {
                if let Ok(uid) = r?.parse() {
                    out.push(uid);
                }
            }
            out
        };
        if !unconfirmed.is_empty() {
            return Ok(EncReady::Unconfirmed(unconfirmed));
        }
        let Some(key) = tx.history_key(row.account, conv_id, g.epoch)? else {
            return Ok(EncReady::Wait);
        };
        let target = match relation {
            None => None,
            Some(r) => match tx.message_id_of(row.id, r.seq().get())? {
                Some(mid) => match <[u8; 16]>::try_from(mid.as_slice()) {
                    Ok(mid) => Some(mid),
                    Err(_) => return Ok(EncReady::Fail),
                },
                None => return Ok(EncReady::Fail),
            },
        };
        Ok(EncReady::Go(EncPlan {
            group_id: g.group_id,
            epoch: g.epoch,
            key: key.key,
            target,
        }))
    }

    /// Whether ENC is held in `conv` after `stale` (12.6).
    pub(super) fn enc_held(&self, conv: &Conv) -> bool {
        self.e2ee.as_ref().is_some_and(|e| e.held.contains(conv))
    }

    /// ENC in `conv` got `stale`: hold sending until the group changes,
    /// and look for leaves to remove (12.6, 12.8).
    pub(super) fn enc_stale(&mut self, conv: &Conv) -> Result<(), SyncError> {
        if self.e2ee.is_none() {
            return Ok(());
        }
        self.e2().held.insert(conv.clone());
        let account = self.account;
        let uids = self.write(|tx| {
            let Some(row) = tx.conv_by_name(account, conv)? else {
                return Ok(Vec::new());
            };
            let Some(g) = tx.group(row.id)? else {
                return Ok(Vec::new());
            };
            let Some(id) = &row.conv_id else {
                return Ok(Vec::new());
            };
            let mut stmt = tx.conn().prepare_cached(
                "SELECT DISTINCT uid FROM epoch_leaves WHERE account = ?1 AND conv_id = ?2
                     AND epoch = ?3",
            )?;
            let rows = stmt.query_map(params![account.get(), id.as_str(), sql(g.epoch)], |r| {
                r.get::<_, String>(0)
            })?;
            let mut out = Vec::new();
            for r in rows {
                if let Ok(uid) = r?.parse::<Uid>() {
                    out.push(uid);
                }
            }
            Ok(out)
        })?;
        // A key may have left its key file: fetch them again.
        for uid in uids {
            self.fetch_key_file(&uid);
        }
        self.e2ee_advance(conv)?;
        // Nothing to remove that the device can see: let it try again.
        if self
            .e2ee
            .as_ref()
            .is_some_and(|e| !e.busy.contains(conv) && e.fetching.is_empty())
        {
            self.e2().held.remove(conv);
        }
        Ok(())
    }

    /// Encrypts a message's content for ENC (12.8).
    pub(super) fn encrypt_draft(
        &self,
        plan: &EncPlan,
        draft: &crate::store::Draft,
    ) -> Result<risala_mls::Encrypted, SyncError> {
        let e = self.e2ee.as_ref().expect("encryption is on");
        let target = match (draft.relation, plan.target) {
            (Some(relation), Some(message_id)) => Some(crate::e2ee::content::Target {
                relation,
                message_id,
            }),
            _ => None,
        };
        let content = Content::Text(crate::e2ee::content::Text {
            text: draft.text.clone(),
            target,
            file: None,
        });
        risala_mls::encrypt(
            &e.dev.signer(),
            &plan.key,
            &plan.group_id,
            plan.epoch,
            &content.encode(),
        )
        .map_err(|e| SyncError::Invalid(e.to_string()))
    }
}

/// The next stored COMMIT event of `row` after seq `after`, if every event
/// up to it is stored (12.5): its seq, epoch and commit.
fn next_commit(
    tx: &Tx<'_>,
    row: &ConvRow,
    after: u64,
) -> Result<Option<(ConvRow, u64, u64, mls::CommitMessage)>, StoreError> {
    let found: Option<(i64, String)> = tx
        .conn()
        .query_row(
            "SELECT seq, line FROM events WHERE conv = ?1 AND verb = 'COMMIT' AND seq > ?2
                 AND seq <= ?3 ORDER BY seq LIMIT 1",
            params![row.id.get(), sql(after), sql(row.sync_point)],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((seq, line)) = found else {
        return Ok(None);
    };
    let event = crate::store::stored_event(&line)?;
    let EventBody::Commit { epoch, commit, .. } = event.body else {
        return Ok(None);
    };
    Ok(Some((row.clone(), seq.max(0) as u64, epoch, commit)))
}

/// A room setting as stored.
fn room_setting(tx: &Tx<'_>, row: &ConvRow, key: &str) -> Result<Option<String>, StoreError> {
    Ok(tx
        .conn()
        .query_row(
            "SELECT value FROM room_settings WHERE conv = ?1 AND key = ?2",
            params![row.id.get(), key],
            |r| r.get(0),
        )
        .optional()?)
}

/// Whether the room's stored events show that `uid` is no longer a member
/// or invited (12.6).
fn left(tx: &Tx<'_>, row: &ConvRow, uid: &Uid) -> Result<bool, StoreError> {
    let member: Option<(Option<bool>, bool)> = tx
        .conn()
        .query_row(
            "SELECT joined, banned FROM room_members WHERE conv = ?1 AND uid = ?2",
            params![row.id.get(), uid.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    Ok(matches!(member, Some((Some(false), _)) | Some((_, true))))
}

/// A line of a reply that the encryption engine reads.
#[allow(dead_code)]
fn is_e2ee_line(msg: &ServerMessage) -> bool {
    matches!(
        msg.line,
        ServerLine::Welcome { .. } | ServerLine::KeyPkg { .. } | ServerLine::GroupInfo { .. }
    )
}
