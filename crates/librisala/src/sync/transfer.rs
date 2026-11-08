//! History transfers (12.13), files (12.11) and reports (5.8): what can be
//! decided inside the cache, without I/O.
//!
//! Owned by task C4 in docs/plans/M5b.md.
//!
//! - **Lines.** The group engine hands this area WANT, TRANSFER and REPORT
//!   lines ([`content_line`]), and posts that expired before the device
//!   fetched them ([`posts_expired`]), which it asks the identity's other
//!   devices for with WANT. What needs HTTPS (fetching a transfer's blobs,
//!   building and storing archives) is kept in the cache, for the account's
//!   worker in [`crate::client::backups`] to do.
//! - **Archives.** [`collect`] reads the messages to archive from the
//!   cache, for a backup, a transfer at pairing or an answer to a WANT.
//! - **Applying.** [`apply`] stores the messages of an opened transfer or
//!   backup under the rules of 12.13: only groups the device is in (or,
//!   at pairing and after recovery, joins later), only ranges asked for
//!   with WANT, never replacing a message it holds, shown as copied or
//!   restored.
//! - **Received messages.** [`note_message`] keeps what a message's
//!   RisalaMessage held besides its content (counter, `previous`, the
//!   sender's device), which archives carry.

use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, OnceLock};

use risala_mls::DeviceId;
use risala_mls::RisalaCrypto;
use risala_mls::archive::{ArchivedConversation, ArchivedFile, ArchivedMessage, HistoryArchive};
use risala_mls::conversation::{RisalaConversation, Role};
use risala_proto::content::{Content, ContentLine};
use risala_proto::names::{BoxName, Identity, Seq, ServerAddr, Uid};
use risala_proto::server::ServerLine;

use super::conversations::{EngineError, content};
use super::{Action, Context, Engine, Input};
use crate::client::Event;
use crate::client::files::TransferEvent;
use crate::store::conversations::{ConvKind, ConvRow, ConversationId, LeafRow, is_blocked};
use crate::store::messages::NewMessage;
use crate::store::transfer::{MessageMeta, Origin, TransferKind, WantRange};
use crate::store::{AccountId, StoreError, Tx};

type Result<T> = std::result::Result<T, EngineError>;

#[cfg(test)]
mod tests;

/// How long a range asked for with WANT stays open for answers: a day.
/// Another device may answer a part of it later than the first.
pub const WANT_OPEN_MS: u64 = 24 * 60 * 60 * 1000;

/// How long the conversations of a pairing transfer or a backup wait for
/// the device to join their groups: a week.
pub const PENDING_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// The crypto provider, made once.
pub(crate) fn crypto() -> Result<Arc<RisalaCrypto>> {
    static CRYPTO: OnceLock<Arc<RisalaCrypto>> = OnceLock::new();
    if let Some(c) = CRYPTO.get() {
        return Ok(c.clone());
    }
    let c = Arc::new(RisalaCrypto::new().map_err(|e| EngineError::Mls(e.to_string()))?);
    Ok(CRYPTO.get_or_init(|| c).clone())
}

/// The conversation extension of a group in the cache (12.4).
pub(crate) fn extension(tx: &Tx<'_>, group_id: &[u8]) -> Result<Option<RisalaConversation>> {
    use risala_mls::openmls_traits::OpenMlsProvider as _;
    let crypto = crypto()?;
    let p = tx.mls(&crypto);
    let group = risala_mls::openmls::group::MlsGroup::load(
        p.storage(),
        &risala_mls::openmls::prelude::GroupId::from_slice(group_id),
    )
    .map_err(|e| EngineError::Mls(format!("{e:?}")))?;
    Ok(group.and_then(|g| risala_mls::group::conversation(&g)))
}

/// The send token of a group's current epoch (7.2), for UPLOAD, BLOB and
/// PUSH ADD.
pub(crate) fn send_token(tx: &Tx<'_>, group_id: &[u8]) -> Result<risala_mls::token::SendToken> {
    use risala_mls::openmls_traits::OpenMlsProvider as _;
    let crypto = crypto()?;
    let p = tx.mls(&crypto);
    let group = risala_mls::openmls::group::MlsGroup::load(
        p.storage(),
        &risala_mls::openmls::prelude::GroupId::from_slice(group_id),
    )
    .map_err(|e| EngineError::Mls(format!("{e:?}")))?
    .ok_or(EngineError::Mls("the group is not in the cache".into()))?;
    risala_mls::token::SendToken::of_group(&group, crypto.as_ref())
        .map_err(|e| EngineError::Mls(format!("{e:?}")))
}

/// The account's server and uid.
pub(crate) fn account_of(tx: &Tx<'_>, account: AccountId) -> Result<(String, Uid)> {
    let (addr, uid): (String, String) = tx
        .conn()
        .query_row(
            "SELECT s.addr, a.uid FROM accounts a JOIN servers s ON s.id = a.server
             WHERE a.id = ?1",
            [account.get()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(StoreError::from)?;
    let uid = uid
        .parse()
        .map_err(|_| EngineError::Invalid(format!("bad uid {uid:?}")))?;
    Ok((addr, uid))
}

/// A server address as archives name servers (3.5, 12.13), from the
/// account's server as stored.
pub(crate) fn host_of(addr: &str) -> Result<ServerAddr> {
    addr.parse()
        .map_err(|_| EngineError::Invalid(format!("bad server {addr:?}")))
}

/// This device's device id for `uid`, if it holds the identity (C1).
pub(crate) fn own_device(tx: &Tx<'_>, uid: &str) -> Result<Option<[u8; 48]>> {
    Ok(crate::store::identity::read_own(tx.conn(), uid)?.map(|o| o.device_id))
}

/// The label of `uid`'s device, as this device knows it (4.4).
pub(crate) fn device_label(tx: &Tx<'_>, uid: &str, device: &[u8; 48]) -> Result<Option<String>> {
    Ok(tx
        .devices(uid)?
        .into_iter()
        .find(|d| d.device_id == *device)
        .map(|d| d.label))
}

/// Whether the identity has a current device besides this one, as far as
/// this device knows (4.4).
fn has_other_devices(tx: &Tx<'_>, uid: &str, own: Option<&[u8; 48]>) -> Result<bool> {
    Ok(tx.devices(uid)?.iter().any(|d| {
        d.state == crate::store::identity::DeviceState::Current && Some(&d.device_id) != own
    }))
}

/// The account's conversation with yourself, if the device is in it.
pub(crate) fn self_conversation(tx: &Tx<'_>, account: AccountId) -> Result<Option<ConvRow>> {
    Ok(tx
        .conversations_of(account)?
        .into_iter()
        .find(|c| c.kind == ConvKind::WithYourself && c.state.in_group()))
}

// ---------------------------------------------------------------------------
// Received messages

/// Keeps what a stored message's RisalaMessage held besides its content:
/// its counter and `previous`, and the sender's device (12.9, 12.13).
/// The group engine calls it for each message it stores, received or
/// sent; `device` is `None` for a guest's, and for this device's own,
/// whose device id is found when it is archived.
pub(crate) fn note_message(
    tx: &mut Tx<'_>,
    conv: ConversationId,
    message_id: &[u8; 16],
    counter: u64,
    previous: Option<[u8; 16]>,
    device: Option<[u8; 48]>,
) -> std::result::Result<(), StoreError> {
    tx.set_message_meta(
        conv,
        message_id,
        &MessageMeta {
            counter,
            previous,
            device_id: device,
            origin: Origin::Server,
            vouched: false,
        },
    )
}

// ---------------------------------------------------------------------------
// Lines

/// A WANT, TRANSFER or REPORT line from `leaf` in `conv` (12.13, 5.8),
/// which the group engine hands over. The lines of the conversation with
/// yourself come only from confirmed leaves of the own identity (12.9).
pub(crate) fn content_line(
    tx: &mut Tx<'_>,
    conv: ConversationId,
    leaf: &LeafRow,
    line: &ContentLine,
    now: u64,
) -> Result<Vec<Action>> {
    let row = tx.conversation(conv)?;
    match line {
        ContentLine::Want {
            mailbox,
            after,
            before,
        } if row.kind == ConvKind::WithYourself => {
            // 12.13: an empty range is ignored; the parser refuses one.
            let range = WantRange {
                after: *after,
                before: before.map(Seq::get),
            };
            if range.before.is_some_and(|b| b <= range.after + 1) {
                return Ok(Vec::new());
            }
            // Only for a mailbox of a conversation this device is in.
            if tx.mailbox(row.account, mailbox)?.is_some() {
                tx.add_want_request(row.account, &mailbox.to_string(), range, now)?;
            }
            Ok(Vec::new())
        }
        ContentLine::Transfer(reference) if row.kind == ConvKind::WithYourself => {
            // 12.13, 2.4: a TransferRef of another version is refused.
            if reference.version() != risala_mls::archive::ARCHIVE_VERSION {
                tracing::info!("a TRANSFER of an unknown version, ignored");
                return Ok(Vec::new());
            }
            // 12.13: after pairing, only answers to WANTs this device sent.
            let wanted = !tx.all_wants(row.account)?.is_empty();
            if !wanted {
                tracing::info!("a TRANSFER this device did not ask for, ignored");
                return Ok(Vec::new());
            }
            let label = match &leaf.device_id {
                Some(d) => device_label(tx, leaf.uid.as_str(), d)?,
                None => None,
            };
            tx.add_transfer(
                row.account,
                TransferKind::Want,
                &reference.as_bytes()[..],
                leaf.device_id.as_ref(),
                label.as_deref(),
                now,
            )?;
            Ok(Vec::new())
        }
        ContentLine::Report(report) if row.kind == ConvKind::Direct => {
            report_line(tx, &row, leaf, report, now)
        }
        _ => Ok(Vec::new()),
    }
}

/// A REPORT line to this device's identity, as an owner or moderator of
/// the room it names (5.8). It is kept only for a room this device is in
/// where its identity holds that role, and from a member of that room.
fn report_line(
    tx: &mut Tx<'_>,
    row: &ConvRow,
    leaf: &LeafRow,
    report: &risala_proto::content::Report,
    now: u64,
) -> Result<Vec<Action>> {
    let (_, own) = account_of(tx, row.account)?;
    let Some(mailbox) = tx.mailbox(row.account, &report.mailbox)? else {
        tracing::info!("a report about a room this device is not in");
        return Ok(Vec::new());
    };
    let room = tx.conversation(mailbox.conv)?;
    if !matches!(room.kind, ConvKind::Private | ConvKind::Public) {
        return Ok(Vec::new());
    }
    let Some(ext) = extension(tx, &room.group_id)? else {
        return Ok(Vec::new());
    };
    if ext.role(&own) < Role::Mod {
        tracing::info!("a report to an identity that is not the room's moderator");
        return Ok(Vec::new());
    }
    // 5.8: a guest reports in a report conversation of its own, and only
    // about a public room that allows guests (12.7).
    if leaf.uid.is_guest()
        && !(room.kind == ConvKind::Public
            && ext.guests != risala_mls::conversation::GuestMode::None)
    {
        return Ok(Vec::new());
    }
    let context: Vec<[u8; 16]> = report.context.iter().map(|id| *id.as_bytes()).collect();
    let id = tx.add_report(
        row.account,
        row.id,
        leaf.uid.as_str(),
        Some(room.id),
        &report.mailbox.to_string(),
        report.target.as_bytes(),
        &context,
        &report.reason,
        now,
    )?;
    Ok(vec![Action::Emit(Event::Transfer(TransferEvent::Report {
        account: row.account,
        report: id,
    }))])
}

/// Posts of `mailbox` after `after` and before `before` expired before
/// this device fetched them (7.4): it asks the identity's other devices
/// for them with WANT, in the conversation with yourself (12.13).
pub(crate) fn posts_expired(
    tx: &mut Tx<'_>,
    account: AccountId,
    mailbox: &BoxName,
    after: u64,
    before: Option<u64>,
    now: u64,
) -> Result<Vec<Action>> {
    if before.is_some_and(|b| b <= after + 1) {
        return Ok(Vec::new());
    }
    let (_, uid) = account_of(tx, account)?;
    if uid.is_guest() {
        return Ok(Vec::new());
    }
    let own = own_device(tx, uid.as_str())?;
    if !has_other_devices(tx, uid.as_str(), own.as_ref())? {
        return Ok(Vec::new());
    }
    let Some(me) = self_conversation(tx, account)? else {
        return Ok(Vec::new());
    };
    let range = WantRange { after, before };
    if !tx.add_want(account, &mailbox.to_string(), range, now)? {
        return Ok(Vec::new());
    }
    let line = ContentLine::Want {
        mailbox: *mailbox,
        after,
        before: before.and_then(Seq::new),
    };
    content::queue_lines(tx, me.id, &uid, vec![line], false, now)?;
    Ok(Vec::new())
}

// ---------------------------------------------------------------------------
// Collecting history to archive

/// What to archive.
#[derive(Debug, Clone)]
pub(crate) enum Selection {
    /// Every conversation: a backup, or a transfer at pairing.
    All,
    /// The posts of one mailbox in a range: an answer to a WANT.
    Range {
        /// The mailbox.
        mailbox: BoxName,
        /// The range.
        range: WantRange,
    },
}

/// A file to include in an archive: its decrypted copy, and the blob made
/// for it before, if any (12.13).
#[derive(Debug, Clone)]
pub(crate) struct FileToArchive {
    /// Its `file-hash`.
    pub file_hash: [u8; 48],
    /// The decrypted copy on this device.
    pub path: String,
    /// The blob and key made for it before.
    pub blob: Option<([u8; 48], [u8; 32])>,
}

/// History read from the cache, ready to archive.
#[derive(Debug, Default)]
pub(crate) struct Collected {
    /// The conversations, each with its messages in seq order.
    pub conversations: Vec<ArchivedConversation>,
    /// The files their messages share that this device fetched.
    pub files: Vec<FileToArchive>,
}

/// Reads the history to archive (12.13): messages as this device received
/// them, without deleted ones, edits and reactions as messages of their
/// own. A message goes into the archive of the mailbox it was posted to,
/// the one whose first epoch is the latest at or before the message's
/// epoch; one that no known mailbox covers, or that has no seq, is left
/// out, since its place in the order of posts is not known.
pub(crate) fn collect(
    tx: &Tx<'_>,
    account: AccountId,
    selection: &Selection,
    with_files: bool,
) -> Result<Collected> {
    let (addr, uid) = account_of(tx, account)?;
    let host = host_of(&addr)?;
    let own_device = own_device(tx, uid.as_str())?;
    let convs: Vec<ConvRow> = match selection {
        Selection::All => tx.conversations_of(account)?,
        Selection::Range { mailbox, .. } => match tx.mailbox(account, mailbox)? {
            Some(m) => vec![tx.conversation(m.conv)?],
            None => Vec::new(),
        },
    };
    let mut out = Collected::default();
    let mut files_seen = HashSet::new();
    for conv in convs {
        let mut mailboxes = tx.mailboxes(conv.id)?;
        mailboxes.sort_by_key(|m| m.first_epoch);
        if mailboxes.is_empty() {
            continue;
        }
        let mut by_box: BTreeMap<u64, ArchivedConversation> = BTreeMap::new();
        for m in crate::store::messages::read::messages(tx.conn(), conv.id)? {
            let (Some(seq), Some(content), false) = (m.seq, m.content.as_ref(), m.deleted) else {
                continue;
            };
            let epoch = m.epoch.unwrap_or(0);
            let Some(mailbox) = mailboxes.iter().rev().find(|b| b.first_epoch <= epoch) else {
                continue;
            };
            if let Selection::Range {
                mailbox: want,
                range,
            } = selection
                && (mailbox.mailbox != *want || !range.holds(seq))
            {
                continue;
            }
            let Some(meta) = tx.message_meta(conv.id, &m.message_id)? else {
                // Without its counter the receiver could not take it into
                // its record of the sender's messages (12.13).
                continue;
            };
            let device_id = if m.own { own_device } else { meta.device_id };
            if !m.sender.is_guest() && device_id.is_none() {
                continue;
            }
            if with_files
                && let Ok(parsed) = Content::parse(content)
                && let Some(file) = text_file(&parsed)
            {
                let hash = *file.hash.as_bytes();
                if files_seen.insert(hash)
                    && let Some(row) = tx.file(conv.id, &m.message_id)?
                    && let Some(path) = row.path.filter(|p| std::path::Path::new(p).exists())
                {
                    out.files.push(FileToArchive {
                        file_hash: hash,
                        path,
                        blob: tx.file_blob(account, &hash)?,
                    });
                }
            }
            let entry = by_box
                .entry(mailbox.first_epoch)
                .or_insert_with(|| ArchivedConversation {
                    group_id: conv.group_id.clone(),
                    host: host.clone(),
                    mailbox: *mailbox.mailbox.as_bytes(),
                    messages: Vec::new(),
                });
            entry.messages.push(ArchivedMessage {
                message_id: m.message_id,
                sender: m.sender.clone(),
                device_id: if m.sender.is_guest() {
                    None
                } else {
                    device_id.map(DeviceId::from_bytes)
                },
                counter: meta.counter,
                previous: meta.previous,
                verified: m.verified,
                sent: m.sent,
                received: m.received.unwrap_or(m.sent),
                seq,
                content: content.clone(),
            });
        }
        for (_, mut c) in by_box {
            c.messages.sort_by_key(|m| m.seq);
            c.messages.dedup_by_key(|m| m.seq);
            if !c.messages.is_empty() {
                out.conversations.push(c);
            }
        }
    }
    Ok(out)
}

/// The file a message's TEXT line shares, if any.
fn text_file(content: &Content) -> Option<&risala_proto::content::FileRef> {
    content.lines().iter().find_map(|l| match l {
        ContentLine::Text(t) => t.file.as_ref(),
        _ => None,
    })
}

// ---------------------------------------------------------------------------
// Applying

/// Where an opened transfer or backup came from.
#[derive(Debug, Clone)]
pub(crate) enum Source {
    /// A TRANSFER line, for a WANT: only ranges asked for are applied.
    Want {
        /// The device that sent it.
        device: Option<[u8; 48]>,
        /// Its label.
        label: Option<String>,
    },
    /// The IdentityBundle's transfer (4.8): conversations the device is
    /// not in yet wait until it joins them.
    Pairing {
        /// The transfer's row.
        transfer: i64,
        /// The device that sent it.
        device: Option<[u8; 48]>,
        /// Its label.
        label: Option<String>,
    },
    /// A backup restored after recovery (12.13), made at `made`:
    /// conversations wait until the device joins them, as at pairing.
    Backup {
        /// The transfer row that keeps its waiting conversations.
        transfer: i64,
        /// When it was made.
        made: u64,
    },
}

impl Source {
    fn origin(&self) -> Origin {
        match self {
            Source::Want { device, label } | Source::Pairing { device, label, .. } => {
                Origin::Copied {
                    device: *device,
                    label: label.clone(),
                }
            }
            Source::Backup { made, .. } => Origin::Restored { made: *made },
        }
    }

    fn waits(&self) -> Option<i64> {
        match self {
            Source::Want { .. } => None,
            Source::Pairing { transfer, .. } | Source::Backup { transfer, .. } => Some(*transfer),
        }
    }
}

/// What [`apply`] did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Applied {
    /// Messages stored.
    pub messages: usize,
    /// Conversations kept to apply once the device joins them.
    pub waiting: usize,
}

/// Stores the messages of an opened transfer or backup (12.13):
///
/// - only of conversations whose group the device is in; at pairing and
///   after recovery, the others wait until it joins them;
/// - for a TRANSFER line, only messages whose seqs lie in a range asked
///   for with WANT and still open;
/// - never replacing a message the device holds, and skipping message ids
///   already seen in the group;
/// - each shown as copied from the device that sent it, or as restored,
///   with that device's `verified` flag kept as its word, not as this
///   device's own check;
/// - each matched to its sender's leaf by device id, so that a gap it
///   fills is no longer shown.
pub(crate) fn apply(
    tx: &mut Tx<'_>,
    account: AccountId,
    conversations: &[ArchivedConversation],
    files: &[ArchivedFile],
    source: &Source,
    now: u64,
) -> Result<Applied> {
    let (addr, uid) = account_of(tx, account)?;
    let host = host_of(&addr)?;
    let mut applied = Applied::default();
    for archived in conversations {
        if archived.host != host {
            continue;
        }
        let conv = tx
            .conversations_of(account)?
            .into_iter()
            .find(|c| c.group_id == archived.group_id && c.state.in_group());
        let Some(conv) = conv else {
            if let Some(transfer) = source.waits() {
                let archive = HistoryArchive {
                    uid: uid_identity(&uid)?,
                    made: now,
                    conversations: vec![archived.clone()],
                    files: files.to_vec(),
                    more: Vec::new(),
                };
                tx.add_transfer_pending(transfer, &archived.group_id, &archive.encode())?;
                applied.waiting += 1;
            }
            continue;
        };
        let mailbox = BoxName::from_bytes(archived.mailbox);
        let ranges = match source {
            Source::Want { .. } => {
                // The ranges asked for are by mailbox: the archived box
                // must be one of this conversation's, or a device could
                // pass another group's messages off as the ones asked for.
                if tx
                    .mailbox(account, &mailbox)?
                    .is_none_or(|m| m.conv != conv.id)
                {
                    continue;
                }
                let open: Vec<WantRange> = tx.wants(account, &mailbox.to_string())?;
                if open.is_empty() {
                    continue;
                }
                Some(open)
            }
            _ => None,
        };
        applied.messages += apply_conversation(
            tx,
            &conv,
            archived,
            files,
            ranges.as_deref(),
            &source.origin(),
            now,
        )?;
    }
    Ok(applied)
}

fn uid_identity(uid: &Uid) -> Result<Identity> {
    uid.as_str()
        .parse()
        .map_err(|_| EngineError::Invalid("a guest has no history".into()))
}

/// Applies the conversations of pairing transfers and backups that waited
/// for the device to join their groups. Those older than [`PENDING_MS`]
/// are dropped.
pub(crate) fn apply_waiting(tx: &mut Tx<'_>, account: AccountId, now: u64) -> Result<usize> {
    tx.expire_transfer_pending(account, now.saturating_sub(PENDING_MS))?;
    let mut count = 0;
    let convs = tx.conversations_of(account)?;
    for (transfer, group_id, encoded) in tx.transfer_pending(account)? {
        let Some(conv) = convs
            .iter()
            .find(|c| c.group_id == group_id && c.state.in_group())
        else {
            continue;
        };
        let Some(row) = tx.transfer(transfer)? else {
            continue;
        };
        let archive = HistoryArchive::decode(&encoded)
            .map_err(|e| EngineError::Invalid(format!("a kept archive: {e}")))?;
        let origin = match row.kind {
            TransferKind::Backup => Origin::Restored {
                made: row.made.unwrap_or(row.created),
            },
            TransferKind::Pairing | TransferKind::Want => Origin::Copied {
                device: row.from_device,
                label: row.from_label.clone(),
            },
        };
        for archived in &archive.conversations {
            count += apply_conversation(tx, conv, archived, &archive.files, None, &origin, now)?;
        }
        tx.remove_transfer_pending(transfer, &group_id)?;
    }
    Ok(count)
}

/// Applies one conversation's archived messages. Returns how many were
/// stored.
fn apply_conversation(
    tx: &mut Tx<'_>,
    conv: &ConvRow,
    archived: &ArchivedConversation,
    files: &[ArchivedFile],
    ranges: Option<&[WantRange]>,
    origin: &Origin,
    now: u64,
) -> Result<usize> {
    let blocks = tx.blocks(conv.account)?;
    let leaves = crate::store::conversations::read::leaves(tx.conn(), conv.id)?;
    let ext = extension(tx, &conv.group_id)?;
    let in_transfer: HashSet<[u8; 16]> = archived.messages.iter().map(|m| m.message_id).collect();
    let mut stored = 0;
    for m in &archived.messages {
        if let Some(ranges) = ranges
            && !ranges.iter().any(|r| r.holds(m.seq))
        {
            continue;
        }
        // Never replace or change a message the device holds (12.13).
        if tx.message_seen(conv.id, &m.message_id)? {
            continue;
        }
        let Ok(content) = Content::parse(&m.content) else {
            continue;
        };
        let leaf = m
            .device_id
            .and_then(|d| leaves.iter().find(|l| l.device_id == Some(*d.as_bytes())));
        let mut shown = false;
        for line in content.lines() {
            match line {
                ContentLine::Text(text) => {
                    let (reply_to, edit_of, react_to) = match text.target {
                        Some(risala_proto::content::Target::Reply(id)) => {
                            (Some(*id.as_bytes()), None, None)
                        }
                        Some(risala_proto::content::Target::Edit(id)) => {
                            (None, Some(*id.as_bytes()), None)
                        }
                        Some(risala_proto::content::Target::React(id)) => {
                            (None, None, Some(*id.as_bytes()))
                        }
                        None => (None, None, None),
                    };
                    // 12.13: an edit or reaction whose target the device
                    // neither holds nor gets in this transfer is ignored.
                    if let Some(target) = edit_of.or(react_to)
                        && !in_transfer.contains(&target)
                        && tx.message(conv.id, &target)?.is_none()
                    {
                        break;
                    }
                    let inserted = tx.insert_message(
                        conv.id,
                        &NewMessage {
                            message_id: m.message_id,
                            seq: Some(m.seq),
                            epoch: None,
                            sender: Some(&m.sender),
                            leaf: leaf.map(|l| l.leaf),
                            own: false,
                            sent: m.sent,
                            received: Some(m.received),
                            // Never shown as this device's own check: the
                            // sending device's word is in message_meta.
                            verified: false,
                            time_mismatch: m.sent.abs_diff(m.received) > 10 * 60 * 1000,
                            restored: true,
                            hidden: is_blocked(&blocks, &m.sender),
                            content: Some(&m.content),
                            text: Some(&text.text),
                            reply_to,
                            edit_of,
                            react_to,
                            frank_key: None,
                        },
                    )?;
                    if inserted {
                        shown = true;
                        if let Some(file) = &text.file
                            && let Some(listed) = files
                                .iter()
                                .find(|f| f.file_hash.as_bytes() == file.hash.as_bytes())
                        {
                            tx.set_file_blob(
                                conv.id,
                                &m.message_id,
                                file.hash.as_bytes(),
                                file.url.as_str(),
                                listed.blob.as_bytes(),
                                listed.key.as_bytes(),
                                now,
                            )?;
                        }
                    }
                    break;
                }
                ContentLine::Delete { id } => {
                    // 5.4: by the author, or in a room by an owner or
                    // moderator.
                    let room = matches!(conv.kind, ConvKind::Private | ConvKind::Public);
                    let with_role =
                        room && ext.as_ref().is_some_and(|e| e.role(&m.sender) >= Role::Mod);
                    if let Some(target) = tx.message(conv.id, id.as_bytes())?
                        && (target.sender == m.sender || with_role)
                    {
                        tx.erase_message(conv.id, id.as_bytes())?;
                    }
                }
                _ => {}
            }
        }
        if !shown {
            tx.mark_seen(conv.id, &m.message_id)?;
        }
        tx.set_message_meta(
            conv.id,
            &m.message_id,
            &MessageMeta {
                counter: m.counter,
                previous: m.previous,
                device_id: m.device_id.map(|d| *d.as_bytes()),
                origin: origin.clone(),
                vouched: m.verified,
            },
        )?;
        // 12.13: the gap the message fills is no longer shown as held
        // back (7.4).
        if let Some(leaf) = leaf {
            tx.fill_gap(conv.id, leaf.leaf, m.counter)?;
        }
        if shown {
            stored += 1;
        }
    }
    if stored > 0 {
        tx.touch(conv.id, now)?;
    }
    Ok(stored)
}

// ---------------------------------------------------------------------------
// The engine

/// The engine of this area, for one account: the REPORT lines an
/// operator's connection gets (5.8). The rest of the area's work needs
/// HTTPS, and is done by the account's worker
/// ([`crate::client::backups`]).
#[derive(Debug, Default)]
pub struct TransferEngine {}

impl Engine for TransferEngine {
    fn handle(&mut self, cx: &Context, input: &Input<'_>) -> Vec<Action> {
        let Input::Line { message, .. } = input else {
            return Vec::new();
        };
        match &message.line {
            ServerLine::Report(report) => vec![Action::Emit(Event::Transfer(
                TransferEvent::OperatorReport {
                    account: cx.account,
                    line: message.to_line().to_string(),
                    mailbox: report.mailbox,
                },
            ))],
            _ => Vec::new(),
        }
    }
}
