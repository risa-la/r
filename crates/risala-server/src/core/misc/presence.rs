//! Presence (8.3): PRESENCE ON and OFF, WATCH, WHOIS, and the PRESENCE
//! lines sent to the connections that watch an identity.
//!
//! An identity is online while it has a signed-in connection. The server
//! reports it so only while its presence is ON, which is off by default;
//! otherwise it is `offline` to everyone. Guests have no presence, and
//! show as `offline`.
//!
//! When an identity's first connection signs in, or `presence_offline`
//! after its last one closes, or when it turns presence on or off, the
//! change is noted, and changes are collected for `presence_batch` before
//! they are sent, so that one PRESENCE line covers many identities. A
//! connection that signs in while the offline delay runs cancels it, and
//! nothing is sent: a client that reconnects does not blink off and on.
//! WHOIS, WATCH and MEMBERS report the presence the PRESENCE lines are
//! heading for, so what a client learns from them agrees with the lines
//! that follow.
//!
//! # Locks
//!
//! The book is behind a plain mutex, never held across an `await`. It may
//! take the registry's lock while held, never the other way round (see
//! `state`). Flushes run one at a time, so that the lines about one
//! identity arrive in the order of its changes.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use risala_proto::error::ErrorCode;
use risala_proto::frame::MAX_SERVER_LINE;
use risala_proto::names::Uid;
use risala_proto::server::{OkResponse, ServerLine, ServerMessage};
use risala_proto::types::Presence;

use super::super::Inner;
use super::super::command::{Cx, Reply, err};
use super::super::state::{ConnEntry, Who};
use super::shown_presence;
use crate::handler::{ConnId, OutLine};

/// The most uids a WATCH list may hold (8.3: at least 1,000).
pub(crate) const MAX_WATCH: usize = 1000;

/// The presence part of the misc area's state.
#[derive(Debug, Default)]
pub(crate) struct State {
    book: Mutex<Book>,
    /// Held while a flush sends its lines.
    flush: tokio::sync::Mutex<()>,
}

impl State {
    fn book(&self) -> MutexGuard<'_, Book> {
        self.book.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// What the hub knows and has said about the presence of identities, and
/// who watches whom.
#[derive(Debug, Default)]
struct Book {
    /// Identities that are signed in, waiting out the offline delay, or
    /// last reported online.
    users: HashMap<Uid, Seen>,
    /// Identities whose reported presence may have changed since the last
    /// flush.
    dirty: BTreeSet<Uid>,
    /// A flush is on its way.
    flush_pending: bool,
    /// Each connection's WATCH list.
    watching: HashMap<ConnId, BTreeSet<Uid>>,
    /// The connections that watch each identity.
    watchers: HashMap<Uid, BTreeSet<ConnId>>,
}

#[derive(Debug, Default)]
struct Seen {
    /// Its presence is ON (8.3).
    on: bool,
    /// It has at least one signed-in connection.
    connected: bool,
    /// The offline delay that is running, by its number, and its task.
    waiting: Option<(u64, tokio::task::AbortHandle)>,
    /// Counts offline delays, so that one cut short cannot end a later one.
    epoch: u64,
    /// The last presence reported for it was `online`.
    shown: bool,
}

impl Seen {
    /// The presence the lines are heading for.
    fn online(&self) -> bool {
        self.on && (self.connected || self.waiting.is_some())
    }
}

impl Book {
    fn online(&self, uid: &Uid) -> bool {
        self.users.get(uid).is_some_and(Seen::online)
    }

    /// Notes that the reported presence of `uid` may have changed, and
    /// makes sure a flush is on its way.
    fn changed(&mut self, inner: &Arc<Inner>, uid: &Uid) {
        self.dirty.insert(uid.clone());
        if self.flush_pending {
            return;
        }
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let weak = Arc::downgrade(inner);
        let batch = inner.timers.presence_batch;
        rt.spawn(async move {
            tokio::time::sleep(batch).await;
            if let Some(inner) = weak.upgrade() {
                flush(&inner).await;
            }
        });
        self.flush_pending = true;
    }

    /// The changes to report, in uid order, as reported from now on.
    fn take_changes(&mut self) -> Vec<(Uid, bool)> {
        self.flush_pending = false;
        let mut changes = Vec::new();
        for uid in std::mem::take(&mut self.dirty) {
            let Some(seen) = self.users.get_mut(&uid) else {
                continue;
            };
            let online = seen.online();
            if online != seen.shown {
                seen.shown = online;
                changes.push((uid.clone(), online));
            }
            if !seen.connected && seen.waiting.is_none() && !seen.shown {
                self.users.remove(&uid);
            }
        }
        changes
    }

    fn unwatch(&mut self, conn: ConnId) {
        for uid in self.watching.remove(&conn).unwrap_or_default() {
            if let Some(conns) = self.watchers.get_mut(&uid) {
                conns.remove(&conn);
                if conns.is_empty() {
                    self.watchers.remove(&uid);
                }
            }
        }
    }
}

/// Whether the identity `uid` has a signed-in connection now.
fn has_connection(inner: &Inner, uid: &Uid) -> bool {
    let reg = inner.reg();
    reg.by_uid.get(uid).is_some_and(|ids| {
        ids.iter().any(|id| {
            reg.conns
                .get(id)
                .is_some_and(|c| matches!(c.who, Who::SignedIn(_)))
        })
    })
}

/// The presence MEMBER and USER lines show for `uid` (8.3).
pub(crate) fn presence_of(inner: &Inner, uid: &Uid) -> Presence {
    shown_presence(!uid.is_guest() && inner.misc.presence.book().online(uid))
}

/// Connection `conn` has signed in as `uid` (4.6, 4.7): `command::route`
/// calls this after AUTH and REGISTER. Reads whether its presence is ON.
pub(crate) async fn signed_in(inner: &Arc<Inner>, uid: &Uid) {
    let who = uid.clone();
    let on = match inner.db(move |store| store.presence_on(&who)).await {
        Ok(on) => on,
        Err(e) => {
            tracing::error!("reading a presence setting: {e}");
            false
        }
    };
    let mut book = inner.misc.presence.book();
    // Asked of the registry, so that a connection that closed meanwhile
    // does not leave the identity online.
    let connected = has_connection(inner, uid);
    let seen = book.users.entry(uid.clone()).or_default();
    seen.on = on;
    seen.connected = connected;
    if connected && let Some((_, task)) = seen.waiting.take() {
        // Back within the offline delay: nobody hears of it.
        task.abort();
    }
    book.changed(inner, uid);
}

/// A connection has closed: it watches nothing now, and a signed-in
/// identity's last connection starts its offline delay.
pub(super) fn conn_closed(inner: &Arc<Inner>, id: ConnId, conn: &ConnEntry) {
    let mut book = inner.misc.presence.book();
    book.unwatch(id);
    let Who::SignedIn(device) = &conn.who else {
        return;
    };
    let uid = &device.uid;
    if has_connection(inner, uid) {
        return;
    }
    let delay = inner.timers.presence_offline;
    let Some(seen) = book.users.get_mut(uid) else {
        return;
    };
    if !seen.connected {
        return;
    }
    seen.connected = false;
    // Wait only if people were told it is online.
    if seen.shown && !delay.is_zero() {
        seen.epoch += 1;
        let epoch = seen.epoch;
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            let weak: Weak<Inner> = Arc::downgrade(inner);
            let uid = uid.clone();
            let task = rt.spawn(async move {
                tokio::time::sleep(delay).await;
                if let Some(inner) = weak.upgrade() {
                    delay_over(&inner, &uid, epoch);
                }
            });
            seen.waiting = Some((epoch, task.abort_handle()));
            return;
        }
    }
    book.changed(inner, uid);
}

/// The offline delay numbered `epoch` of `uid` has run out.
fn delay_over(inner: &Arc<Inner>, uid: &Uid, epoch: u64) {
    let mut book = inner.misc.presence.book();
    let Some(seen) = book.users.get_mut(uid) else {
        return;
    };
    if seen.waiting.as_ref().is_some_and(|(e, _)| *e == epoch) {
        seen.waiting = None;
        book.changed(inner, uid);
    }
}

/// Sends the changes collected since the last flush to the connections
/// that watch each changed identity (8.3).
async fn flush(inner: &Arc<Inner>) {
    let _order = inner.misc.presence.flush.lock().await;
    // Who hears of which changes, and their handles.
    let mut heard: BTreeMap<ConnId, (Vec<Uid>, Vec<Uid>)> = BTreeMap::new();
    {
        let mut book = inner.misc.presence.book();
        let changes = book.take_changes();
        for (uid, online) in changes {
            for conn in book.watchers.get(&uid).into_iter().flatten() {
                let (on, off) = heard.entry(*conn).or_default();
                if online {
                    on.push(uid.clone());
                } else {
                    off.push(uid.clone());
                }
            }
        }
    }
    if heard.is_empty() {
        return;
    }
    // Connections that hear the same changes share their lines.
    let mut made: HashMap<(Vec<Uid>, Vec<Uid>), Vec<OutLine>> = HashMap::new();
    let mut sends = Vec::new();
    for (conn, which) in heard {
        let lines = made
            .entry(which)
            .or_insert_with_key(|(on, off)| {
                let mut lines = Vec::new();
                for (presence, uids) in [(Presence::Online, on), (Presence::Offline, off)] {
                    for line in presence_lines(&presence, uids, MAX_SERVER_LINE) {
                        lines.push(OutLine::new(ServerMessage::new(line)));
                    }
                }
                lines
            })
            .clone();
        sends.push((conn, lines));
    }
    let reg = inner.reg();
    for (conn, lines) in sends {
        if let Some(entry) = reg.conns.get(&conn) {
            for line in lines {
                entry.handle.send_line(line);
            }
        }
    }
}

/// The PRESENCE lines for `uids`, all with `presence`, in order, each at
/// most `max` bytes with its LF (2.3, 8.3).
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

/// `PRESENCE ON` and `PRESENCE OFF` (8.3).
pub(super) async fn set(cx: &Cx, on: bool) -> Reply {
    let Some(device) = cx.device() else {
        return Err(err(ErrorCode::WrongConnection));
    };
    let uid = device.uid.clone();
    let who = uid.clone();
    cx.db(move |store| store.set_presence(&who, on)).await?;
    let inner = &cx.inner;
    let mut book = inner.misc.presence.book();
    let connected = has_connection(inner, &uid);
    let seen = book.users.entry(uid.clone()).or_default();
    seen.on = on;
    seen.connected = connected;
    book.changed(inner, &uid);
    Ok(OkResponse::new())
}

/// `WATCH [<uids>]` (8.3): replaces the connection's list, and replies with
/// a USER line for each identity on it.
pub(super) async fn watch(cx: &Cx, uids: Vec<Uid>) -> Reply {
    let mut seen = BTreeSet::new();
    let uids: Vec<Uid> = uids
        .into_iter()
        .filter(|u| seen.insert(u.clone()))
        .collect();
    if uids.len() > MAX_WATCH {
        return Err(err(ErrorCode::TooLong).with_message(format!("at most {MAX_WATCH} uids")));
    }
    let shown: Vec<(Uid, Presence)> = {
        let mut book = cx.inner.misc.presence.book();
        book.unwatch(cx.conn);
        if !uids.is_empty() {
            for uid in &uids {
                book.watchers
                    .entry(uid.clone())
                    .or_default()
                    .insert(cx.conn);
            }
            book.watching.insert(cx.conn, seen);
        }
        uids.into_iter()
            .map(|uid| {
                let online = !uid.is_guest() && book.online(&uid);
                (uid, shown_presence(online))
            })
            .collect()
    };
    for (i, (uid, presence)) in shown.into_iter().enumerate() {
        if i > 0 && i % 64 == 0 {
            cx.wait_for_room().await;
        }
        cx.send(ServerLine::User { uid, presence });
    }
    Ok(OkResponse::new())
}

/// `WHOIS <uid>` (8.3): `USER <uid> <presence>`, or `ERR not-found` for an
/// identity the server does not know: one that has not signed in here.
/// Guests have no presence, and are not identities the server knows.
pub(super) async fn whois(cx: &Cx, uid: Uid) -> Reply {
    if uid.is_guest() {
        // 8.3: guests have no presence. Answering not-found tells nobody
        // which guest names are in use.
        return Err(err(ErrorCode::NotFound));
    }
    let who = uid.clone();
    if !cx.db(move |store| store.knows(&who)).await? {
        return Err(err(ErrorCode::NotFound));
    }
    let presence = presence_of(&cx.inner, &uid);
    cx.send(ServerLine::User { uid, presence });
    Ok(OkResponse::new())
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
