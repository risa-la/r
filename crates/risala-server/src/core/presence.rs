//! Presence (8.3): telling people when the identities they share a
//! conversation with come online or go offline.
//!
//! An identity is online while it has a connection. When its first
//! connection opens, or `limits.presence_offline_secs` after its last one
//! closes, the change is noted, and changes are collected for
//! `limits.presence_batch_ms` before they are sent, so that one PRESENCE
//! line covers many users. A connection that opens while the offline delay
//! runs cancels it, and nothing is sent: a client that reconnects does not
//! blink off and on.
//!
//! What has been said is kept per identity ([`PresenceBook`]), under the
//! registry's lock, since that is where connections come and go. Changes
//! are sent by [`Inner::flush_presence`], one flush at a time, so that the
//! lines for one user arrive in the order of its changes.
//!
//! MEMBERS and WHOIS report the presence the PRESENCE lines are heading
//! for ([`PresenceBook::is_online`]): an identity is online while it has a
//! connection or its offline delay runs. So what a client learns from them
//! agrees with the PRESENCE lines that follow.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Weak};
use std::time::Duration;

use risala_proto::frame::MAX_SERVER_LINE;
use risala_proto::names::Uid;
use risala_proto::server::{ServerLine, ServerMessage};
use risala_proto::types::Presence;

use super::Inner;
use super::state::{ConvEntry, UserEntry};
use crate::handler::OutLine;

/// What the hub knows and has said about the presence of identities.
#[derive(Debug, Default)]
pub(crate) struct PresenceBook {
    /// The hub, for the tasks that wait out the offline delay and the
    /// batching.
    weak: Weak<Inner>,
    /// `limits.presence_offline_secs`.
    offline_delay: Duration,
    /// `limits.presence_batch_ms`.
    batch: Duration,
    /// Identities that are connected, waiting out the offline delay, or
    /// last reported online. Others are offline, and have been reported so
    /// or never reported at all.
    users: HashMap<Uid, Seen>,
    /// Identities whose presence may have changed since the last flush.
    dirty: BTreeSet<Uid>,
    /// A flush is on its way.
    flush_pending: bool,
}

#[derive(Debug, Default)]
struct Seen {
    /// It has at least one connection.
    connected: bool,
    /// The offline delay that is running, by its number, and the task that
    /// ends it.
    waiting: Option<(u64, tokio::task::AbortHandle)>,
    /// Counts offline delays, so that one cut short cannot end a later one.
    epoch: u64,
    /// The last presence reported for it was `online`.
    shown: bool,
}

impl Seen {
    fn is_online(&self) -> bool {
        self.connected || self.waiting.is_some()
    }
}

impl PresenceBook {
    /// A book for the hub `weak`, with the timers of `limits`.
    pub(crate) fn new(weak: Weak<Inner>, offline_delay: Duration, batch: Duration) -> PresenceBook {
        PresenceBook {
            weak,
            offline_delay,
            batch,
            ..PresenceBook::default()
        }
    }

    /// Whether the identity `uid` counts as online (8.3): it has a
    /// connection, or its offline delay has not run out yet.
    pub(crate) fn is_online(&self, uid: &Uid) -> bool {
        self.users.get(uid).is_some_and(Seen::is_online)
    }

    /// The identity `uid` has opened its first connection.
    pub(crate) fn connected(&mut self, uid: &Uid) {
        let seen = self.users.entry(uid.clone()).or_default();
        seen.connected = true;
        if let Some((_, task)) = seen.waiting.take() {
            // Back within the offline delay: nobody hears of it.
            task.abort();
            return;
        }
        self.changed(uid);
    }

    /// The identity `uid` has closed its last connection.
    pub(crate) fn disconnected(&mut self, uid: &Uid) {
        let Some(seen) = self.users.get_mut(uid) else {
            return;
        };
        seen.connected = false;
        // Wait only if people were told it is online.
        if seen.shown && !self.offline_delay.is_zero() {
            seen.epoch += 1;
            let epoch = seen.epoch;
            if let Some(task) = spawn_after(self.offline_delay, &self.weak, {
                let uid = uid.clone();
                move |inner| inner.reg().presence.delay_over(&uid, epoch)
            }) {
                seen.waiting = Some((epoch, task));
                return;
            }
        }
        self.changed(uid);
    }

    /// The offline delay numbered `epoch` of `uid` has run out.
    fn delay_over(&mut self, uid: &Uid, epoch: u64) {
        let Some(seen) = self.users.get_mut(uid) else {
            return;
        };
        if seen.waiting.as_ref().is_some_and(|(e, _)| *e == epoch) {
            seen.waiting = None;
            self.changed(uid);
        }
    }

    /// Notes that the presence of `uid` may have changed, and makes sure a
    /// flush is on its way.
    fn changed(&mut self, uid: &Uid) {
        self.dirty.insert(uid.clone());
        if self.flush_pending {
            return;
        }
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let (weak, batch) = (self.weak.clone(), self.batch);
        rt.spawn(async move {
            tokio::time::sleep(batch).await;
            if let Some(inner) = weak.upgrade() {
                inner.flush_presence().await;
            }
        });
        self.flush_pending = true;
    }

    /// The changes to report, in uid order, as reported from now on.
    fn take_changes(&mut self) -> Vec<(Uid, Presence)> {
        self.flush_pending = false;
        let mut changes = Vec::new();
        for uid in std::mem::take(&mut self.dirty) {
            let Some(seen) = self.users.get_mut(&uid) else {
                continue;
            };
            let online = seen.is_online();
            if online != seen.shown {
                seen.shown = online;
                changes.push((
                    uid.clone(),
                    if online {
                        Presence::Online
                    } else {
                        Presence::Offline
                    },
                ));
            }
            if !online && !seen.shown {
                self.users.remove(&uid);
            }
        }
        changes
    }
}

/// Runs `f` on the hub after `wait`, if the hub is still there. Returns
/// the task, or `None` outside a tokio runtime.
fn spawn_after(
    wait: Duration,
    weak: &Weak<Inner>,
    f: impl FnOnce(Arc<Inner>) + Send + 'static,
) -> Option<tokio::task::AbortHandle> {
    let rt = tokio::runtime::Handle::try_current().ok()?;
    let weak = weak.clone();
    Some(
        rt.spawn(async move {
            tokio::time::sleep(wait).await;
            if let Some(inner) = weak.upgrade() {
                f(inner);
            }
        })
        .abort_handle(),
    )
}

/// The PRESENCE lines for `uids`, all with `presence`, in order, each at
/// most `max` bytes with its LF (2.3). Uids cannot contain commas (8.3).
pub(crate) fn presence_lines(presence: &Presence, uids: &[Uid], max: usize) -> Vec<ServerLine> {
    // "PRESENCE <presence> " and the LF.
    let base = "PRESENCE ".len() + presence.as_str().len() + 1 + 1;
    let mut lines = Vec::new();
    let mut batch: Vec<Uid> = Vec::new();
    let mut len = base;
    for uid in uids {
        let more = uid.as_str().len() + usize::from(!batch.is_empty());
        if !batch.is_empty() && len + more > max {
            lines.push(ServerLine::Presence {
                presence: presence.clone(),
                uids: std::mem::take(&mut batch),
            });
            len = base;
        }
        len += uid.as_str().len() + usize::from(!batch.is_empty());
        batch.push(uid.clone());
    }
    if !batch.is_empty() {
        lines.push(ServerLine::Presence {
            presence: presence.clone(),
            uids: batch,
        });
    }
    lines
}

impl Inner {
    /// Whether `uid` counts as online for MEMBERS and WHOIS (8.3). A guest
    /// is online while it is a member, or has a session for WHOIS.
    pub(super) fn presence_of(&self, uid: &Uid) -> Presence {
        if uid.is_guest() || self.reg().presence.is_online(uid) {
            Presence::Online
        } else {
            Presence::Offline
        }
    }

    /// Sends the presence changes collected since the last flush (8.3), to
    /// the connections of everyone who shares a conversation with each
    /// changed identity, each only the uids it shares one with.
    pub(super) async fn flush_presence(&self) {
        // One flush at a time, so that a user's changes arrive in order.
        let _order = self.presence_lock.lock().await;
        let (changes, convs) = {
            let mut reg = self.reg();
            let changes = reg.presence.take_changes();
            // The conversations of the changed users, each once, with the
            // changes that may concern its members.
            let mut convs: HashMap<usize, (Arc<ConvEntry>, Vec<usize>)> = HashMap::new();
            for (i, (uid, _)) in changes.iter().enumerate() {
                let Some(user) = reg.users.get(uid) else {
                    continue;
                };
                for conv in user.convs() {
                    convs
                        .entry(Arc::as_ptr(&conv).addr())
                        .or_insert_with(|| (conv.clone(), Vec::new()))
                        .1
                        .push(i);
                }
            }
            (changes, convs)
        };
        if changes.is_empty() {
            return;
        }
        tracing::debug!(changes = changes.len(), "sending presence");
        // Who hears of which changes.
        let mut heard: BTreeMap<Uid, (Arc<UserEntry>, BTreeSet<usize>)> = BTreeMap::new();
        for (conv, which) in convs.into_values() {
            let st = conv.lock().await;
            if st.dropped {
                continue;
            }
            let which: Vec<usize> = which
                .into_iter()
                .filter(|&i| st.is_member(&changes[i].0))
                .collect();
            for (member, user) in &st.members {
                for &i in &which {
                    if changes[i].0 != *member {
                        heard
                            .entry(member.clone())
                            .or_insert_with(|| (user.clone(), BTreeSet::new()))
                            .1
                            .insert(i);
                    }
                }
            }
        }
        // People who share the same conversations hear the same changes:
        // their lines are made once.
        let mut made: HashMap<Vec<usize>, Vec<OutLine>> = HashMap::new();
        for (user, which) in heard.into_values() {
            let which: Vec<usize> = which.into_iter().collect();
            let lines = made.entry(which).or_insert_with_key(|which| {
                let mut lines = Vec::new();
                for presence in [Presence::Online, Presence::Offline] {
                    let uids: Vec<Uid> = which
                        .iter()
                        .filter(|&&i| changes[i].1 == presence)
                        .map(|&i| changes[i].0.clone())
                        .collect();
                    for line in presence_lines(&presence, &uids, MAX_SERVER_LINE) {
                        lines.push(OutLine::new(ServerMessage::new(line)));
                    }
                }
                lines
            });
            for line in lines.iter() {
                user.send(line);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `n` uids of `len` bytes each (at least 20).
    fn uids(n: usize, len: usize) -> Vec<Uid> {
        (0..n)
            .map(|i| {
                let host = "x".repeat(len - "u00000@.example.org".len());
                let uid: Uid = format!("u{i:0>5}@{host}.example.org").parse().unwrap();
                assert_eq!(uid.as_str().len(), len);
                uid
            })
            .collect()
    }

    #[test]
    fn long_lists_are_split_to_fit_a_line() {
        let all = uids(1000, 64);
        let lines = presence_lines(&Presence::Online, &all, MAX_SERVER_LINE);
        assert!(lines.len() > 1);
        let mut seen = Vec::new();
        for line in &lines {
            let text = ServerMessage::new(line.clone()).to_line().to_string();
            assert!(text.len() < MAX_SERVER_LINE, "{}", text.len());
            match line {
                ServerLine::Presence { uids, .. } => seen.extend(uids.iter().cloned()),
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(seen, all);
        // Every line but the last is full: a comma, one more uid and the LF
        // would not fit.
        let first = ServerMessage::new(lines[0].clone()).to_line().to_string();
        assert!(first.len() + 1 + 64 + 1 > MAX_SERVER_LINE);
    }

    #[test]
    fn lines_fit_exactly() {
        // "PRESENCE online " is 16 bytes, and the LF one more.
        let all = uids(3, 20);
        for (max, expected) in [(17 + 20, 3), (17 + 41, 2), (17 + 62, 1), (17 + 61, 2)] {
            let lines = presence_lines(&Presence::Online, &all, max);
            assert_eq!(lines.len(), expected, "max {max}");
            for line in &lines {
                let text = ServerMessage::new(line.clone()).to_line().to_string();
                assert!(text.len() < max, "{text}");
            }
        }
        assert!(presence_lines(&Presence::Offline, &[], 100).is_empty());
    }
}
