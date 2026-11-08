//! Push (Section 9): PUSH ADD, DEL and LIST, and sending pushes.
//!
//! # Subscriptions (9.1)
//!
//! Mailbox subscriptions are made on anonymous connections and belong to
//! no identity; each lasts one retention period from the PUSH ADD that
//! made or renewed it. Account subscriptions are made on signed-in
//! connections and belong to the device key. Each mailbox, connection and
//! device may have only so many (`push.max_per_*`, `ERR rate-limited`).
//!
//! # Pushes (9.2)
//!
//! When a mailbox gets a kept post ([`post_kept`]), or a device a Welcome
//! ([`welcome_arrived`]), each of its subscriptions that has no push on
//! its way gets one, after a random delay of its own of up to
//! `push_delay`, and no sooner than `push_interval` after the last push to
//! the subscription or to its URL. Posts that arrive meanwhile go into
//! that push.
//!
//! Before it sends, the server checks whether the device is reading:
//!
//! - a mailbox subscription is held back while a connection follows the
//!   mailbox with `quiet=<tag>`, where `<tag>` is the subscription's, and
//!   is alive: it has sent a line in the last `push_liveness`, or answers
//!   the PING sent to it within `push_liveness`;
//! - an account subscription is held back while its device key has a
//!   signed-in connection.
//!
//! # Results (9.3)
//!
//! A 2xx response is a success; 404 and 410 delete the subscription; any
//! other result is retried with growing delays, and the subscription is
//! deleted after a day of failures.
//!
//! Timing lives in memory: a restart forgets pushes on their way, and
//! sends the next one when the next post arrives.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::Duration;

use risala_proto::command::PushCommand;
use risala_proto::error::ErrorCode;
use risala_proto::names::{BoxName, Uid};
use risala_proto::record::DeviceId;
use risala_proto::server::{Notify, OkResponse, ServerLine, ServerMessage};
use risala_proto::types::{NotifyReason, PushReason, PushTag};
use tokio::time::Instant;

use super::super::Inner;
use super::super::command::{Cx, Reply, err};
use super::super::state::Who;
use crate::config::Config;
use crate::handler::ConnId;
use crate::push::{HttpsPusher, PushRequest, PushTransport};
use crate::store::{NewPushSubscription, PushAdded, PushSubscription, PushTarget};

/// How long a subscription may keep failing before it is deleted (9.3: MAY
/// after a day).
const GIVE_UP_AFTER: Duration = Duration::from_secs(24 * 60 * 60);

/// The first retry's delay; each later one doubles, up to
/// [`MAX_RETRY_DELAY`] (9.3).
const FIRST_RETRY_DELAY: Duration = Duration::from_secs(30);

/// The longest delay between retries.
const MAX_RETRY_DELAY: Duration = Duration::from_secs(60 * 60);

/// The push part of the misc area's state.
pub(crate) struct State {
    transport: RwLock<Arc<dyn PushTransport>>,
    timing: Mutex<Timing>,
}

/// What the pusher remembers between pushes.
#[derive(Default)]
struct Timing {
    /// Subscriptions with a push on its way, or sent recently.
    subs: HashMap<i64, SubTiming>,
    /// When each URL last got a push (9.2: one every 10 seconds).
    urls: HashMap<String, Instant>,
    /// How many mailbox subscriptions each connection added (9.1).
    added: HashMap<ConnId, usize>,
    /// The connections that follow each mailbox with each `quiet` tag
    /// (9.2), and the tags each connection follows with.
    quiet: HashMap<(BoxName, PushTag), BTreeSet<ConnId>>,
    quiet_by_conn: HashMap<ConnId, HashMap<BoxName, PushTag>>,
    /// When each connection that follows quietly last sent a line.
    heard: HashMap<ConnId, Instant>,
}

#[derive(Default)]
struct SubTiming {
    /// A push or a retry is on its way.
    pending: bool,
    /// When it last got a push.
    last_sent: Option<Instant>,
    /// Failed attempts in a row.
    failures: u32,
}

impl State {
    /// The state for `config`: pushes go over HTTPS, as `push` asks.
    pub(crate) fn new(config: &Config) -> State {
        let transport: Arc<dyn PushTransport> = match HttpsPusher::from_config(&config.push) {
            Ok(pusher) => Arc::new(pusher),
            Err(e) => {
                tracing::error!("push: {e}; using the public CAs only");
                Arc::new(HttpsPusher::new(Vec::new(), config.push.allow_private))
            }
        };
        State {
            transport: RwLock::new(transport),
            timing: Mutex::default(),
        }
    }

    fn timing(&self) -> MutexGuard<'_, Timing> {
        self.timing.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn transport(&self) -> Arc<dyn PushTransport> {
        self.transport
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Sends pushes through `transport` from now on, as tests do.
    #[cfg_attr(not(test), allow(dead_code, reason = "for tests"))]
    pub(crate) fn set_transport(&self, transport: Arc<dyn PushTransport>) {
        *self.transport.write().unwrap_or_else(|e| e.into_inner()) = transport;
    }
}

/// Handles `PUSH ADD`, `PUSH DEL` and `PUSH LIST` (9.1).
pub(super) async fn handle(cx: &Cx, command: PushCommand) -> Reply {
    if !cx.inner.config.push.enabled {
        return Err(err(ErrorCode::NotSupported));
    }
    match command {
        PushCommand::Add {
            url,
            tag,
            key,
            auth,
            mailbox,
        } => {
            if !crate::push::valid_key(&key) {
                return Err(err(ErrorCode::Invalid).with_message("not a P-256 public key"));
            }
            let (target, max, expires) = match mailbox {
                Some(mailbox) => {
                    if !matches!(cx.who, Who::Anonymous) {
                        return Err(err(ErrorCode::WrongConnection));
                    }
                    let found = cx.db(move |store| store.mailbox(&mailbox)).await?;
                    if found.is_none() {
                        return Err(err(ErrorCode::NotFound));
                    }
                    let retention = cx.inner.settings().retention;
                    let expires = cx
                        .inner
                        .now()
                        .checked_add(Duration::from_secs(u64::from(retention.days()) * 86_400));
                    (
                        PushTarget::Mailbox(mailbox),
                        cx.inner.config.push.max_per_mailbox,
                        Some(expires.unwrap_or(risala_proto::time::Timestamp::MAX)),
                    )
                }
                None => {
                    let Some(device) = cx.device() else {
                        return Err(err(ErrorCode::WrongConnection));
                    };
                    (
                        PushTarget::Device {
                            uid: device.uid.clone(),
                            device: DeviceId::of(&device.key),
                        },
                        cx.inner.config.push.max_per_device,
                        None,
                    )
                }
            };
            let per_conn = cx.inner.config.push.max_per_connection;
            let is_mailbox = matches!(target, PushTarget::Mailbox(_));
            if is_mailbox {
                let timing = cx.inner.misc.push.timing();
                if timing.added.get(&cx.conn).copied().unwrap_or(0) >= per_conn {
                    return Err(err(ErrorCode::RateLimited));
                }
            }
            let sub = NewPushSubscription {
                target,
                url,
                tag,
                key,
                auth,
                expires,
            };
            match cx.db(move |store| store.add_push(&sub, max)).await? {
                PushAdded::TooMany => Err(err(ErrorCode::RateLimited)),
                added => {
                    if is_mailbox && added == PushAdded::Added {
                        *cx.inner.misc.push.timing().added.entry(cx.conn).or_default() += 1;
                    }
                    Ok(OkResponse::new())
                }
            }
        }
        PushCommand::Del { url, mailbox } => {
            let target = match mailbox {
                Some(mailbox) => PushTarget::Mailbox(mailbox),
                None => {
                    let Some(device) = cx.device() else {
                        return Err(err(ErrorCode::WrongConnection));
                    };
                    PushTarget::Device {
                        uid: device.uid.clone(),
                        device: DeviceId::of(&device.key),
                    }
                }
            };
            if cx.db(move |store| store.delete_push(&target, &url)).await? {
                Ok(OkResponse::new())
            } else {
                Err(err(ErrorCode::NotFound))
            }
        }
        PushCommand::List => {
            let Some(device) = cx.device() else {
                return Err(err(ErrorCode::WrongConnection));
            };
            let target = PushTarget::Device {
                uid: device.uid.clone(),
                device: DeviceId::of(&device.key),
            };
            let now = cx.inner.now();
            let subs = cx
                .db(move |store| store.push_subscriptions(&target, now))
                .await?;
            for sub in subs {
                cx.send(ServerLine::Push {
                    url: sub.url,
                    tag: sub.tag,
                });
            }
            Ok(OkResponse::new())
        }
    }
}

// ---------------------------------------------------------------------------
// Hooks

/// A line arrived on connection `conn` (9.2): `command::route` calls this
/// for every line, so that a connection following quietly counts as alive.
pub(crate) fn heard(inner: &Inner, conn: ConnId) {
    let mut timing = inner.misc.push.timing();
    if timing.quiet_by_conn.contains_key(&conn) {
        timing.heard.insert(conn, Instant::now());
    }
}

/// Connection `conn` follows `mailbox` with `quiet=<tag>` (7.1, 9.2): the
/// mailbox area's FOLLOW calls this. A FOLLOW without `quiet` passes
/// `None`, which ends an earlier quiet follow of the mailbox.
#[allow(dead_code, reason = "called by the mailbox area's FOLLOW (SV3)")]
pub(crate) fn follow_quiet(inner: &Inner, conn: ConnId, mailbox: BoxName, tag: Option<PushTag>) {
    unfollow(inner, conn, &mailbox);
    let Some(tag) = tag else {
        return;
    };
    let mut timing = inner.misc.push.timing();
    timing
        .quiet
        .entry((mailbox, tag.clone()))
        .or_default()
        .insert(conn);
    timing
        .quiet_by_conn
        .entry(conn)
        .or_default()
        .insert(mailbox, tag);
    timing.heard.insert(conn, Instant::now());
}

/// Connection `conn` no longer follows `mailbox` (7.1): the mailbox area's
/// UNFOLLOW calls this.
pub(crate) fn unfollow(inner: &Inner, conn: ConnId, mailbox: &BoxName) {
    let mut timing = inner.misc.push.timing();
    let Some(tags) = timing.quiet_by_conn.get_mut(&conn) else {
        return;
    };
    let Some(tag) = tags.remove(mailbox) else {
        return;
    };
    if tags.is_empty() {
        timing.quiet_by_conn.remove(&conn);
        timing.heard.remove(&conn);
    }
    let key = (*mailbox, tag);
    if let Some(conns) = timing.quiet.get_mut(&key) {
        conns.remove(&conn);
        if conns.is_empty() {
            timing.quiet.remove(&key);
        }
    }
}

/// Connection `conn` has closed.
pub(super) fn conn_closed(inner: &Inner, conn: ConnId) {
    let mailboxes: Vec<BoxName> = inner
        .misc
        .push
        .timing()
        .quiet_by_conn
        .get(&conn)
        .map(|tags| tags.keys().copied().collect())
        .unwrap_or_default();
    for mailbox in mailboxes {
        unfollow(inner, conn, &mailbox);
    }
    inner.misc.push.timing().added.remove(&conn);
}

/// `mailbox` got a kept post (5.2, 9.2): the mailbox area's POST calls
/// this once the post is stored. Each of the mailbox's subscriptions gets
/// a push, unless one is on its way.
#[allow(dead_code, reason = "called by the mailbox area's POST (SV3)")]
pub(crate) fn post_kept(inner: &Arc<Inner>, mailbox: BoxName) {
    if !inner.config.push.enabled {
        return;
    }
    let inner = inner.clone();
    tokio::spawn(async move {
        let now = inner.now();
        let target = PushTarget::Mailbox(mailbox);
        match inner
            .db(move |store| store.push_subscriptions(&target, now))
            .await
        {
            Ok(subs) => {
                for sub in subs {
                    schedule(&inner, sub.id, PushReason::Message);
                }
            }
            Err(e) => tracing::error!("reading push subscriptions: {e}"),
        }
    });
}

/// The device `device` of `uid` got a Welcome (12.8, 9.2): the keys area's
/// WELCOME PUT calls this. Each of the device's account subscriptions gets
/// a push, unless one is on its way.
#[allow(dead_code, reason = "called by the keys area's WELCOME PUT (SV4)")]
pub(crate) fn welcome_arrived(inner: &Arc<Inner>, uid: &Uid, device: DeviceId) {
    if !inner.config.push.enabled {
        return;
    }
    let inner = inner.clone();
    let target = PushTarget::Device {
        uid: uid.clone(),
        device,
    };
    tokio::spawn(async move {
        let now = inner.now();
        match inner
            .db(move |store| store.push_subscriptions(&target, now))
            .await
        {
            Ok(subs) => {
                for sub in subs {
                    schedule(&inner, sub.id, PushReason::Welcome);
                }
            }
            Err(e) => tracing::error!("reading push subscriptions: {e}"),
        }
    });
}

/// A device was removed from its identity's chain (4.4, 9.1): its account
/// subscriptions go. The identity area calls this.
#[allow(dead_code, reason = "called by the identity area (SV1)")]
pub(crate) async fn device_removed(inner: &Inner, device: DeviceId) {
    if let Err(e) = inner
        .db(move |store| store.delete_device_pushes(&device))
        .await
    {
        tracing::error!("deleting a removed device's push subscriptions: {e}");
    }
}

/// An identity unregistered (4.9, 10.5): its account subscriptions and its
/// presence setting go. The identity area calls this.
#[allow(dead_code, reason = "called by the identity area (SV1)")]
pub(crate) async fn identity_removed(inner: &Inner, uid: &Uid) {
    let who = uid.clone();
    if let Err(e) = inner
        .db(move |store| store.forget_identity_misc(&who))
        .await
    {
        tracing::error!("deleting an identity's push subscriptions: {e}");
    }
}

/// A mailbox was dropped (10.4): its subscriptions go.
pub(crate) async fn mailbox_dropped(inner: &Inner, mailbox: BoxName) {
    if let Err(e) = inner
        .db(move |store| store.delete_mailbox_pushes(&mailbox))
        .await
    {
        tracing::error!("deleting a dropped mailbox's push subscriptions: {e}");
    }
}

// ---------------------------------------------------------------------------
// Sending

/// A random delay of up to `max`.
fn random_delay(max: Duration) -> Duration {
    let ms = u64::try_from(max.as_millis()).unwrap_or(u64::MAX);
    if ms == 0 {
        return Duration::ZERO;
    }
    let r = crate::secret::random_bytes::<8>()
        .map(u64::from_le_bytes)
        .unwrap_or(0);
    Duration::from_millis(r % (ms + 1))
}

/// Plans a push to subscription `id`, unless one is on its way (9.2).
fn schedule(inner: &Arc<Inner>, id: i64, reason: PushReason) {
    let at = {
        let mut timing = inner.misc.push.timing();
        let sub = timing.subs.entry(id).or_default();
        if sub.pending {
            return;
        }
        sub.pending = true;
        let mut at = Instant::now() + random_delay(inner.timers.push_delay);
        if let Some(last) = sub.last_sent {
            at = at.max(last + inner.timers.push_interval);
        }
        at
    };
    run(inner, id, reason, at);
}

/// Delivers the push planned for subscription `id` at `at`, and its
/// retries (9.3), in a task of its own.
fn run(inner: &Arc<Inner>, id: i64, reason: PushReason, at: Instant) {
    let weak = Arc::downgrade(inner);
    tokio::spawn(async move {
        let mut at = at;
        loop {
            tokio::time::sleep_until(at).await;
            let Some(inner) = weak.upgrade() else {
                return;
            };
            match deliver(&inner, id, reason).await {
                Some(retry) => at = Instant::now() + retry,
                None => return,
            }
        }
    });
}

/// Nothing is on its way to subscription `id` any more.
fn settle(inner: &Inner, id: i64) {
    if let Some(sub) = inner.misc.push.timing().subs.get_mut(&id) {
        sub.pending = false;
    }
}

/// Sends the push planned for subscription `id`, once its URL may get one,
/// unless its device is reading (9.2). Returns when to try again, if it
/// failed and should be retried (9.3).
async fn deliver(inner: &Arc<Inner>, id: i64, reason: PushReason) -> Option<Duration> {
    let sub = match inner.db(move |store| store.push_subscription(id)).await {
        Ok(Some(sub)) => sub,
        Ok(None) => {
            inner.misc.push.timing().subs.remove(&id);
            return None;
        }
        Err(e) => {
            tracing::error!("reading a push subscription: {e}");
            settle(inner, id);
            return None;
        }
    };
    // One push every push_interval to each URL, whichever subscriptions it
    // belongs to: wait for the URL, check that the device is not reading,
    // then take the URL's turn, unless another push took it meanwhile.
    loop {
        let wait = {
            let timing = inner.misc.push.timing();
            timing
                .urls
                .get(sub.url.as_str())
                .map(|last| *last + inner.timers.push_interval)
                .filter(|at| *at > Instant::now())
        };
        if let Some(at) = wait {
            tokio::time::sleep_until(at).await;
            continue;
        }
        if reading(inner, &sub).await {
            tracing::debug!("push held back: the device is reading");
            settle(inner, id);
            return None;
        }
        let now = Instant::now();
        let mut timing = inner.misc.push.timing();
        if timing
            .urls
            .get(sub.url.as_str())
            .is_some_and(|last| *last + inner.timers.push_interval > now)
        {
            continue;
        }
        timing.urls.insert(sub.url.as_str().to_owned(), now);
        let t = timing.subs.entry(id).or_default();
        t.last_sent = Some(now);
        // Posts from now on go into the next push.
        t.pending = false;
        break;
    }
    send(inner, sub, reason).await
}

/// Whether the subscription's device is reading, so gets no push (9.2).
async fn reading(inner: &Arc<Inner>, sub: &PushSubscription) -> bool {
    match &sub.target {
        PushTarget::Device { uid, device } => {
            let reg = inner.reg();
            reg.by_uid.get(uid).is_some_and(|ids| {
                ids.iter().any(|id| {
                    reg.conns.get(id).is_some_and(|conn| {
                        matches!(&conn.who, Who::SignedIn(d) if DeviceId::of(&d.key) == *device)
                    })
                })
            })
        }
        PushTarget::Mailbox(mailbox) => {
            let liveness = inner.timers.push_liveness;
            let started = Instant::now();
            let stale: Vec<ConnId> = {
                let timing = inner.misc.push.timing();
                let Some(conns) = timing.quiet.get(&(*mailbox, sub.tag.clone())) else {
                    return false;
                };
                // 9.2, step 1 pings only connections heard from more than
                // push_liveness ago; one heard from since is alive.
                if conns.iter().any(|c| {
                    timing
                        .heard
                        .get(c)
                        .is_some_and(|t| started.duration_since(*t) < liveness)
                }) {
                    return true;
                }
                conns.iter().copied().collect()
            };
            if stale.is_empty() {
                return false;
            }
            {
                let reg = inner.reg();
                for id in &stale {
                    if let Some(conn) = reg.conns.get(id) {
                        conn.handle.send(ServerMessage::new(ServerLine::Ping {
                            token: "push".into(),
                        }));
                    }
                }
            }
            tokio::time::sleep(liveness).await;
            let timing = inner.misc.push.timing();
            stale
                .iter()
                .any(|c| timing.heard.get(c).is_some_and(|t| *t >= started))
        }
    }
}

/// Encrypts and POSTs one push, and handles the result (9.3). Returns when
/// to try again, if it should be retried.
async fn send(inner: &Arc<Inner>, sub: PushSubscription, reason: PushReason) -> Option<Duration> {
    let notify = Notify {
        tag: sub.tag.clone(),
        reason: NotifyReason::Known(reason),
    };
    let body = match crate::push::encrypt(&notify, &sub.key, &sub.auth) {
        Ok(body) => body,
        Err(e) => {
            tracing::warn!("push not encrypted: {e}");
            return None;
        }
    };
    let request = PushRequest {
        url: sub.url.clone(),
        body,
        urgency: notify.urgency(),
    };
    let result = inner.misc.push.transport().send(&request).await;
    let id = sub.id;
    match result {
        Ok(200..=299) => {
            inner.misc.push.timing().subs.entry(id).or_default().failures = 0;
            if sub.failing_since.is_some() {
                let now = inner.now();
                if let Err(e) = inner.db(move |store| store.note_push(id, true, now)).await {
                    tracing::error!("noting a push: {e}");
                }
            }
            None
        }
        Ok(404 | 410) => {
            tracing::debug!("push subscription gone");
            inner.misc.push.timing().subs.remove(&id);
            if let Err(e) = inner.db(move |store| store.delete_push_id(id)).await {
                tracing::error!("deleting a push subscription: {e}");
            }
            None
        }
        other => {
            match other {
                Ok(status) => tracing::debug!(status, "push refused"),
                Err(e) => tracing::debug!("push failed: {e}"),
            }
            failed(inner, sub).await
        }
    }
}

/// A push to `sub` failed: retry later, or give up after a day (9.3).
/// Returns the delay before the retry, unless a newer push is on its way.
async fn failed(inner: &Arc<Inner>, sub: PushSubscription) -> Option<Duration> {
    let id = sub.id;
    let now = inner.now();
    if sub
        .failing_since
        .is_some_and(|since| now.saturating_duration_since(since) >= GIVE_UP_AFTER)
    {
        tracing::debug!("push subscription failing for a day: deleted");
        inner.misc.push.timing().subs.remove(&id);
        if let Err(e) = inner.db(move |store| store.delete_push_id(id)).await {
            tracing::error!("deleting a push subscription: {e}");
        }
        return None;
    }
    if let Err(e) = inner.db(move |store| store.note_push(id, false, now)).await {
        tracing::error!("noting a push: {e}");
    }
    let mut timing = inner.misc.push.timing();
    let t = timing.subs.entry(id).or_default();
    if t.pending {
        // A newer push is on its way already.
        return None;
    }
    t.pending = true;
    let delay = FIRST_RETRY_DELAY
        .saturating_mul(1u32 << t.failures.min(16))
        .min(MAX_RETRY_DELAY);
    t.failures = t.failures.saturating_add(1);
    Some(delay)
}

/// Once a minute: deletes expired mailbox subscriptions (9.1), and forgets
/// timing that no longer holds anything back.
pub(crate) async fn maintain_once(inner: &Arc<Inner>) {
    let now = inner.now();
    match inner.db(move |store| store.expire_pushes(now)).await {
        Ok(0) => {}
        Ok(n) => tracing::debug!(n, "expired push subscriptions"),
        Err(e) => tracing::error!("expiring push subscriptions: {e}"),
    }
    let interval = inner.timers.push_interval;
    let mut timing = inner.misc.push.timing();
    let now = Instant::now();
    timing.urls.retain(|_, last| now.duration_since(*last) < interval);
    timing.subs.retain(|_, t| {
        t.pending
            || t.failures > 0
            || t.last_sent.is_some_and(|last| now.duration_since(last) < interval)
    });
}

/// Delivers a push to subscription `id` now, as a retry would, for tests.
#[cfg(test)]
pub(crate) async fn deliver_now(inner: &Arc<Inner>, id: i64) {
    deliver(inner, id, PushReason::Message).await;
}
