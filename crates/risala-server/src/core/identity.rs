//! Identities: AUTH (4.5), REGISTER (4.6), KEY (4.7) and UNREGISTER
//! (4.8).
//!
//! None of these holds a conversation lock while it fetches a key file or
//! checks a signature. A key file fetch has a time limit
//! ([`KEY_FETCH_TIMEOUT`]), and holds up only the AUTH that waits for it.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use risala_proto::auth::{Nonce, PublicKey, Signature};
use risala_proto::command::KeyCommand;
use risala_proto::error::ErrorCode;
use risala_proto::keyfile::{KeyEntry, MAX_KEY_LABEL, MAX_KEYS};
use risala_proto::names::{Identity, Name, Uid};
use risala_proto::server::{ErrResponse, OkResponse, ServerLine};
use risala_proto::text::unescape;

use super::commands::{Fail, Outcome, Reply, fail, respond};
use super::keys::{FetchError, KeyFilePublisher};
use super::rate::network;
use super::state::{ConvEntry, UserEntry};
use super::{Inner, KEY_FETCH_TIMEOUT, UNAVAILABLE_RETRY};
use crate::handler::ConnId;
use crate::store::{HostedKey, KeyChange, Registered};

/// The BYE text for a connection whose device key was removed (4.4, 4.7).
pub const BYE_KEY_REMOVED: &str = "this device's key was removed";

/// The BYE text for the connections of an identity that was deleted (4.8).
pub const BYE_UNREGISTERED: &str = "identity deleted";

/// How long to wait before each try at removing a key file again, after
/// the first fails (4.8). `None` marks the last try.
const UNPUBLISH_RETRIES: [Option<Duration>; 3] = [
    Some(Duration::from_millis(100)),
    Some(Duration::from_secs(1)),
    None,
];

/// The window of `limits.registrations_per_hour` (13).
pub(super) const REGISTRATION_WINDOW: Duration = Duration::from_secs(60 * 60);

/// UNREGISTER of an identity that is being deleted already, or whose
/// connections are deleting one (4.8, 10.5).
fn being_deleted() -> Fail {
    fail(ErrorCode::Forbidden, "the identity is being deleted")
}

fn auth_failed(message: &str) -> Fail {
    fail(ErrorCode::AuthFailed, message)
}

/// `ERR unavailable` (4.5): the key file could not be had, so the
/// signature could not be checked. Try again later, unless the server
/// fetches no key files at all.
pub(super) fn unavailable(e: &FetchError) -> Fail {
    let err = ErrResponse::new(ErrorCode::Unavailable)
        .with_message("could not get the identity's key file; try again later");
    Fail::Err(match e {
        FetchError::Failed(_) => err.with_retry(UNAVAILABLE_RETRY.as_secs()),
        FetchError::Unavailable => err,
    })
}

/// What AUTH and REGISTER need from the connection, taken as they start.
struct Challenge {
    /// The greeting's nonce, unless an earlier AUTH or REGISTER used it up.
    nonce: Option<Nonce>,
    /// The SNI hostname, in lower case (4.5).
    sni: Option<String>,
    /// Whether the SNI hostname is a name on one of the server's
    /// certificates (4.5).
    sni_certified: bool,
    /// The client's address, for the registration limit (13).
    peer: IpAddr,
}

/// The key file entry for a hosted key, whose label is escaped (3.4). A
/// label that cannot go in a key file gets `None`.
pub(super) fn key_entry(key: &HostedKey) -> KeyEntry {
    KeyEntry::new(key.key.clone(), Some(&unescape(&key.label)))
        .or_else(|_| KeyEntry::new(key.key.clone(), None))
        .expect("an entry without a label is valid")
}

/// Publishes the key file of the hosted identity `uid` (4.6). Failures are
/// logged and returned. Blocks.
pub(super) fn publish(
    publisher: &dyn KeyFilePublisher,
    uid: &Uid,
    keys: &[HostedKey],
) -> std::io::Result<()> {
    let Ok(name) = uid.name().parse::<Name>() else {
        return Err(std::io::Error::other(format!("{uid} has no name")));
    };
    let entries: Vec<KeyEntry> = keys.iter().map(key_entry).collect();
    let result = publisher.publish(&name, &entries);
    if let Err(e) = &result {
        tracing::error!(%uid, "publishing the key file failed: {e}");
    }
    result
}

/// The first of `keys` under which `signature` signs the challenge for
/// `host`, `nonce` and `uid` (4.5). Runs on the blocking pool: each check
/// is an ML-DSA verification.
async fn verify(
    host: String,
    nonce: Nonce,
    uid: Uid,
    signature: Signature,
    keys: Vec<PublicKey>,
) -> Option<PublicKey> {
    tokio::task::spawn_blocking(move || {
        keys.into_iter()
            .take(MAX_KEYS)
            .find(|key| key.verify_challenge(&host, &nonce, uid.as_str(), &signature))
    })
    .await
    .ok()
    .flatten()
}

impl Inner {
    /// Whether `uid` is a server operator (10.1).
    pub(super) fn is_operator(&self, uid: &Uid) -> bool {
        self.operators
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains(uid)
    }

    /// Whether `identity` is under this server's identity domain, so that
    /// its keys are the server's own records (4.5, 4.6).
    pub(super) fn hosts(&self, identity: &Identity) -> bool {
        self.identity_domain
            .as_ref()
            .is_some_and(|d| d.as_str() == identity.domain())
    }

    /// Whether `uid` is an identity under this server's identity domain.
    pub(super) fn hosts_uid(&self, uid: &Uid) -> bool {
        uid.to_identity().is_some_and(|i| self.hosts(&i))
    }

    /// Takes the connection's nonce, using it up (4.5), with what else AUTH
    /// and REGISTER need. `None` if the connection is gone.
    fn take_challenge(&self, id: ConnId) -> Option<Challenge> {
        let mut reg = self.reg();
        let conn = reg.conns.get_mut(&id)?;
        Some(Challenge {
            nonce: conn.nonce.take(),
            sni: conn.info.sni.clone(),
            sni_certified: conn.info.sni_certified,
            peer: conn.info.peer.ip(),
        })
    }

    /// The host and nonce to check a signature against (4.5): the
    /// connection's SNI hostname, since the client signs the name it
    /// connected to, and its nonce, unless it was used up.
    ///
    /// The SNI hostname must be a name this server serves: its configured
    /// hostname, or a name on one of its certificates (4.5, step 1).
    /// Otherwise a server could connect here with its own name in SNI,
    /// pass this connection's nonce on to one of its own users, and sign
    /// in here as them with the signature it gets back (14).
    fn host_and_nonce(&self, challenge: Challenge) -> Result<(String, Nonce), Fail> {
        let nonce = challenge
            .nonce
            .ok_or_else(|| auth_failed("this connection's nonce was used up; reconnect"))?;
        let host = challenge
            .sni
            .ok_or_else(|| auth_failed("connect with SNI to sign in as an identity"))?;
        if !challenge.sni_certified && !self.is_hostname(&host) {
            return Err(auth_failed(
                "the host name this connection used is not one of this server's; \
                 connect using the server's own name",
            ));
        }
        Ok((host, nonce))
    }

    /// Whether `host` is the configured hostname, ignoring case and one
    /// trailing `.` (2.1).
    fn is_hostname(&self, host: &str) -> bool {
        let trim = |h: &str| h.strip_suffix('.').unwrap_or(h).to_ascii_lowercase();
        trim(host) == trim(&self.config.hostname)
    }

    /// AUTH (4.5).
    pub(super) async fn auth(
        self: &Arc<Self>,
        id: ConnId,
        identity: Identity,
        signature: Signature,
    ) -> Outcome {
        let Some(challenge) = self.take_challenge(id) else {
            return Ok(None);
        };
        let (host, nonce) = self.host_and_nonce(challenge)?;
        let uid = identity.to_uid();
        // Server bans (10.2) are checked in `finish_sign_in`, after the
        // signature, so that only the identity's owner learns of a ban
        // (PLAN.md 5, item 31).
        // Held from here to the end, so that an UNREGISTER that starts
        // meanwhile marks this very entry, and the sign-in sees it (4.8).
        let user = self.pin(&uid);
        let result = async {
            let key = if self.hosts(&identity) {
                let who = uid.clone();
                let keys = self.db(move |s| s.hosted_keys(&who)).await?;
                let keys = keys
                    .unwrap_or_default()
                    .into_iter()
                    .map(|k| k.key)
                    .collect();
                verify(host, nonce, uid.clone(), signature, keys).await
            } else {
                self.verify_fetched(&identity, host, nonce, signature)
                    .await?
            };
            let Some(key) = key else {
                tracing::debug!(conn = id.0, "AUTH failed");
                return Err(auth_failed("the signature did not verify"));
            };
            self.finish_sign_in(id, &user, key).await
        }
        .await;
        self.unpin(&uid, user);
        result
    }

    /// The entry of `uid`, made if there is none, and held until
    /// [`unpin`](Self::unpin) so that it is not forgotten meanwhile.
    pub(super) fn pin(&self, uid: &Uid) -> Arc<UserEntry> {
        self.reg().user(uid)
    }

    /// Lets go of an entry from [`pin`](Self::pin).
    pub(super) fn unpin(&self, uid: &Uid, user: Arc<UserEntry>) {
        drop(user);
        self.reg().release(uid);
    }

    /// Checks an AUTH signature against `identity`'s key file (4.4): first
    /// as the fetcher has it, then, if that came from a cache and fails,
    /// once more freshly fetched. Returns the key that verified, `None` if
    /// none of the keys the server got did (`auth-failed`), or `ERR
    /// unavailable` if a fetch failed before the server got any keys to
    /// go by (4.5).
    ///
    /// Only an answer fetched just now closes the identity's connections
    /// whose key it does not list (4.4), and deletes those keys'
    /// KeyPackages and pending Welcomes (12.4, 12.7). A failed fetch
    /// closes and deletes nothing.
    async fn verify_fetched(
        &self,
        identity: &Identity,
        host: String,
        nonce: Nonce,
        signature: Signature,
    ) -> Result<Option<PublicKey>, Fail> {
        let uid = identity.to_uid();
        for refresh in [false, true] {
            let fetch = self.keys.fetcher.fetch_boxed(identity, refresh);
            let fetched = match tokio::time::timeout(KEY_FETCH_TIMEOUT, fetch).await {
                Ok(Ok(fetched)) => fetched,
                Ok(Err(e)) => {
                    tracing::debug!(%uid, refresh, "no key file: {e}");
                    return Err(unavailable(&e));
                }
                Err(_) => {
                    tracing::debug!(%uid, refresh, "fetching the key file timed out");
                    return Err(unavailable(&FetchError::Failed("timed out".into())));
                }
            };
            if !fetched.cached {
                self.close_removed_keys(&uid, &fetched.keys);
                // Their KeyPackages and pending Welcomes go too (12.4, 12.7).
                self.forget_unlisted_devices(&uid, &fetched.keys).await;
            }
            let found = verify(
                host.clone(),
                nonce.clone(),
                uid.clone(),
                signature.clone(),
                fetched.keys,
            )
            .await;
            // Fetching again is for a copy from the cache, which may be
            // older than the device (4.4): one fetched just now is the
            // file as it is.
            if found.is_some() || !fetched.cached {
                return Ok(found);
            }
        }
        Ok(None)
    }

    /// Signs connection `id` in as the identity of `user`, with `key` as
    /// its device key (4.5), and records that the server knows the
    /// identity (5.1). Replies `OK uid=<uid>`, with `op=yes` for an
    /// operator.
    ///
    /// The signature was checked without any lock held, so this checks
    /// again, under `keys_lock`, that nothing changed meanwhile: that the
    /// identity is not being deleted, nor was deleted since `user` was
    /// pinned (4.8), and that a hosted identity still has `key` (4.7). KEY
    /// DEL and UNREGISTER change keys and forget identities under the same
    /// lock, so either they come first and this fails, or this comes first
    /// and they find the connection signed in, and close it.
    async fn finish_sign_in(&self, id: ConnId, user: &Arc<UserEntry>, key: PublicKey) -> Outcome {
        let uid = &user.uid;
        let being_deleted = || auth_failed("the identity is being deleted");
        let _keys = self.keys_lock.lock().await;
        if user.lock().ending {
            return Err(being_deleted());
        }
        if self.hosts_uid(uid) {
            let who = uid.clone();
            let keys = self.db(move |s| s.hosted_keys(&who)).await?;
            if !keys.is_some_and(|keys| keys.iter().any(|k| k.key == key)) {
                // KEY DEL took the key away meanwhile.
                return Err(auth_failed("the signature did not verify"));
            }
        }
        let (who, now) = (uid.clone(), self.now());
        let new = self.db(move |s| s.touch_identity(&who, now)).await?;
        {
            let mut reg = self.reg();
            if user.lock().ending {
                // UNREGISTER began meanwhile. It forgets the identity,
                // and the row touched above, once this lets go of the lock.
                return Err(being_deleted());
            }
            // A server ban made meanwhile (10.2): see `admin`.
            self.check_not_banned(uid)?;
            if !reg.attach(id, uid, Some(key)) {
                // The connection closed meanwhile.
                return Ok(None);
            }
        }
        drop(_keys);
        if new {
            // Before the reply, so that its SYNC lists them.
            self.rejoin_directs(user).await;
        }
        tracing::debug!(conn = id.0, "signed in as an identity");
        let ok = OkResponse::new().with_uid(uid);
        Ok(Some(if self.is_operator(uid) {
            ok.with_op(true)
        } else {
            ok
        }))
    }

    /// Makes the identity of `user`, which the server did not know until
    /// it signed in just now, a participant again of the direct
    /// conversations it was in before it unregistered (4.8): they belong
    /// to the pair (5.1). The store keeps them, and that the identity is
    /// known, so a restart agrees ([`Hub::build`](super::Hub::build)).
    ///
    /// Each is changed under its lock, as UNREGISTER's [`auto_part`]
    /// takes it, and under the registry's, as UNREGISTER marks the entry
    /// ending: one that began meanwhile either finds the conversation in
    /// the user's list, or is seen here and nothing is added.
    ///
    /// [`auto_part`]: Inner::auto_part
    pub(super) async fn rejoin_directs(&self, user: &Arc<UserEntry>) {
        let uid = &user.uid;
        let entries: Vec<Arc<ConvEntry>> = self
            .directs
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|((a, b), _)| a == uid || b == uid)
            .map(|(_, entry)| entry.clone())
            .collect();
        for entry in entries {
            let mut st = entry.lock().await;
            let _reg = self.reg();
            if user.lock().ending {
                return;
            }
            if !st.is_member(uid) {
                st.add_member(&entry, user);
            }
        }
    }

    /// Closes the connections of `uid` whose device key is not in `keys`
    /// (4.4): a key file fetched for AUTH no longer lists them, or the
    /// file is gone.
    pub(super) fn close_removed_keys(&self, uid: &Uid, keys: &[PublicKey]) {
        self.close_keys(uid, |key| !keys.contains(key));
    }

    /// Closes the connections of `uid` signed in with a device key for
    /// which `removed` is true, with BYE (4.4, 4.7).
    pub(super) fn close_keys(&self, uid: &Uid, removed: impl Fn(&PublicKey) -> bool) {
        let mut reg = self.reg();
        let Some(user) = reg.users.get(uid).cloned() else {
            return;
        };
        let gone: Vec<ConnId> = user
            .lock()
            .conns
            .iter()
            .filter(|c| c.key.as_ref().is_some_and(&removed))
            .map(|c| c.handle.id())
            .collect();
        drop(user);
        for id in gone {
            tracing::debug!(conn = id.0, "closing a connection whose key was removed");
            reg.detach(id, BYE_KEY_REMOVED);
        }
    }

    /// Publishes the key file of the hosted identity `uid` on the blocking
    /// pool (4.6).
    async fn publish(&self, uid: &Uid, keys: Vec<HostedKey>) -> std::io::Result<()> {
        let publisher = self.keys.publisher.clone();
        let uid = uid.clone();
        tokio::task::spawn_blocking(move || publish(&*publisher, &uid, &keys))
            .await
            .map_err(std::io::Error::other)?
    }

    /// Removes the key file of the hosted identity `uid` (4.8), trying
    /// again a few times if that fails. The HTTPS listener stops serving
    /// it at once either way, since it serves from the store, but another
    /// web server serving `key_dir` would go on serving it, so a failure
    /// is logged as an error, and the file is removed at the next start
    /// ([`KeyFilePublisher::retain`]).
    async fn unpublish(&self, uid: &Uid) {
        let Ok(name) = uid.name().parse::<Name>() else {
            return;
        };
        for wait in UNPUBLISH_RETRIES {
            let publisher = self.keys.publisher.clone();
            let file = name.clone();
            let result = tokio::task::spawn_blocking(move || publisher.remove(&file))
                .await
                .map_err(std::io::Error::other)
                .and_then(|r| r);
            match (result, wait) {
                (Ok(()), _) => return,
                (Err(e), Some(wait)) => {
                    tracing::warn!(%uid, "removing the key file failed, trying again: {e}");
                    tokio::time::sleep(wait).await;
                }
                (Err(e), None) => {
                    tracing::error!(
                        %uid,
                        "removing the key file failed: {e}; it is removed at the next start"
                    );
                }
            }
        }
    }

    /// REGISTER (4.6).
    pub(super) async fn register(
        self: &Arc<Self>,
        id: ConnId,
        name: Name,
        key: PublicKey,
        signature: Signature,
    ) -> Outcome {
        // Any REGISTER that parses uses up the nonce (4.5).
        let Some(challenge) = self.take_challenge(id) else {
            return Ok(None);
        };
        let Some(domain) = self.identity_domain.clone() else {
            return Err(fail(
                ErrorCode::NotSupported,
                "this server does not offer registration",
            ));
        };
        if !self.settings().registration {
            return Err(fail(ErrorCode::Forbidden, "registration is closed"));
        }
        let peer = challenge.peer;
        let (host, nonce) = self.host_and_nonce(challenge)?;
        let now = self.now();
        // The slot is taken now and given back if this fails, so that
        // registrations in progress count too (4.6, 14).
        let limit = self.config.limits.registrations_per_hour;
        let slot = self
            .registrations
            .take(network(peer), limit, now)
            .map_err(|retry| {
                Fail::Err(
                    ErrResponse::new(ErrorCode::RateLimited)
                        .with_retry(retry)
                        .with_message("too many registrations from this address"),
                )
            })?;
        let uid = Identity::new(&name, &domain).to_uid();
        // The signature proves the client holds the key (4.6).
        if verify(host, nonce, uid.clone(), signature, vec![key.clone()])
            .await
            .is_none()
        {
            return Err(auth_failed("the signature did not verify"));
        }
        // Only after the signature, as in AUTH (PLAN.md 5, item 31).
        self.check_not_banned(&uid)?;
        {
            let _keys = self.keys_lock.lock().await;
            let (who, first) = (uid.clone(), key.clone());
            match self.db(move |s| s.register(&who, &first, now)).await? {
                Registered::Done => {}
                Registered::Taken => {
                    return Err(fail(ErrorCode::NameTaken, "that name is registered"));
                }
                // A name that was unregistered stays taken (4.8, 10.5).
                Registered::Retired => {
                    return Err(fail(ErrorCode::NameTaken, "that name was used before"));
                }
            }
            let who = uid.clone();
            let keys = self.db(move |s| s.hosted_keys(&who)).await?;
            if self.publish(&uid, keys.unwrap_or_default()).await.is_err() {
                // Without a key file, nobody else can check the identity:
                // undo it, and leave the name free.
                let who = uid.clone();
                self.db(move |s| s.forget_identity(&who, false, now))
                    .await?;
                return Err(fail(
                    ErrorCode::Internal,
                    "the key file could not be published",
                ));
            }
        }
        if let Some(slot) = slot {
            slot.keep();
        }
        tracing::info!(%uid, "identity registered");
        let user = self.pin(&uid);
        let result = self.finish_sign_in(id, &user, key).await;
        self.unpin(&uid, user);
        result
    }

    /// KEY LIST, KEY ADD and KEY DEL (4.7), for hosted identities only.
    pub(super) async fn key(&self, uid: &Uid, reply: &Reply, command: KeyCommand) -> Outcome {
        let hosted_here = || {
            fail(
                ErrorCode::NotSupported,
                "this server does not host your identity; edit your key file",
            )
        };
        if !self.hosts_uid(uid) {
            return Err(hosted_here());
        }
        let now = self.now();
        match command {
            KeyCommand::List => {
                let who = uid.clone();
                let keys = self
                    .db(move |s| s.hosted_keys(&who))
                    .await?
                    .ok_or_else(hosted_here)?;
                for key in keys {
                    reply.line(ServerLine::Key {
                        key: key.key,
                        label: key.label,
                    });
                }
                Ok(Some(OkResponse::new()))
            }
            KeyCommand::Add { key, label } => {
                // The label is stored as received (3.4), and goes in the
                // key file as plain text (4.4), so it may not hold a line
                // break.
                // The 64-byte limit (4.4, 4.7) counts the escaped label,
                // which the parser has checked already, so a label that
                // fails here holds a line break.
                if label.len() > MAX_KEY_LABEL {
                    return Err(fail(ErrorCode::TooLong, "a label is at most 64 bytes"));
                }
                KeyEntry::new(key.clone(), Some(&unescape(&label)))
                    .map_err(|_| fail(ErrorCode::BadSyntax, "the label cannot go in a key file"))?;
                let _keys = self.keys_lock.lock().await;
                let who = uid.clone();
                let change = self
                    .db(move |s| s.add_hosted_key(&who, &key, &label, MAX_KEYS, now))
                    .await?;
                match change {
                    KeyChange::Done(keys) => self.republish(uid, keys).await,
                    KeyChange::TooMany => Err(fail(
                        ErrorCode::Forbidden,
                        "an identity has at most 64 keys",
                    )),
                    KeyChange::NotHosted | KeyChange::NotFound | KeyChange::LastKey => {
                        Err(hosted_here())
                    }
                }
            }
            KeyCommand::Del { key } => {
                let _keys = self.keys_lock.lock().await;
                let (who, gone) = (uid.clone(), key.clone());
                let change = self.db(move |s| s.delete_hosted_key(&who, &gone)).await?;
                match change {
                    KeyChange::Done(keys) => {
                        let result = self.republish(uid, keys).await;
                        // 4.7: the connections that used the key are closed,
                        // this one too, after its response.
                        respond(reply, "KEY", result);
                        // The store deleted its KeyPackages and pending
                        // Welcomes with it (4.7), under `keys_lock`: see
                        // `e2ee`.
                        self.close_keys(uid, |k| *k == key);
                        Ok(None)
                    }
                    KeyChange::NotFound => Err(fail(ErrorCode::NotFound, "no such key")),
                    KeyChange::LastKey => Err(fail(
                        ErrorCode::Forbidden,
                        "an identity's last key cannot be deleted",
                    )),
                    KeyChange::NotHosted | KeyChange::TooMany => Err(hosted_here()),
                }
            }
        }
    }

    /// Publishes the key file after a change to its keys (4.6, 4.7). The
    /// change is stored either way; a failure to publish is
    /// `ERR internal`, and the next change or restart publishes again.
    pub(super) async fn republish(&self, uid: &Uid, keys: Vec<HostedKey>) -> Outcome {
        match self.publish(uid, keys).await {
            Ok(()) => Ok(Some(OkResponse::new())),
            Err(_) => Err(fail(
                ErrorCode::Internal,
                "the change was saved, but the key file could not be published",
            )),
        }
    }

    /// UNREGISTER (4.8).
    pub(super) async fn unregister(
        self: &Arc<Self>,
        uid: &Uid,
        reply: &Reply,
        target: &Uid,
        purge: bool,
    ) -> Outcome {
        if target != uid {
            return Err(fail(
                ErrorCode::Forbidden,
                "type your own identity to delete it",
            ));
        }
        // From here on, the identity may not join rooms or sign in, and
        // its connections start no more commands. They still get the
        // PARTs.
        let me = reply.handle.id();
        let (user, gates) = {
            let mut reg = self.reg();
            let user = reg.user(uid);
            let conns: Vec<ConnId> = {
                let state = user.lock();
                if state.ending {
                    // Another device is deleting it already.
                    return Err(being_deleted());
                }
                state.conns.iter().map(|c| c.handle.id()).collect()
            };
            // This waits for the gates of the identity's connections below.
            // If one of them is itself deleting an identity, perhaps this
            // one's, it may be waiting for this connection's gate: refuse,
            // rather than wait for each other for ever. Both look under the
            // registry's lock, so the second to come is refused.
            let busy = conns
                .iter()
                .any(|conn| *conn != me && reg.conns.get(conn).is_some_and(|c| c.unregistering));
            if busy {
                return Err(being_deleted());
            }
            user.lock().ending = true;
            if let Some(entry) = reg.conns.get_mut(&me) {
                entry.unregistering = true;
            }
            let mut gates = Vec::new();
            for conn in conns {
                if let Some(entry) = reg.conns.get_mut(&conn) {
                    entry.detached = true;
                    if conn != me {
                        gates.push(entry.gate.clone());
                    }
                }
            }
            (user, gates)
        };
        // Commands that the identity's other connections started before
        // now run to the end first: a JOIN that creates a room, or a READ,
        // BLOCK or MSG that stores something for the identity, must not
        // store it after it has been forgotten. Holding their gates, this
        // waits for them, and they start nothing new until it is done.
        // None of them waits for anything this holds, an UNREGISTER having
        // been refused above, so this ends.
        let mut held = Vec::with_capacity(gates.len());
        for gate in gates {
            held.push(gate.lock_owned().await);
        }
        let result = self.forget(uid, &user, purge).await;
        let done = result.is_ok();
        // Close every connection, this one after its response.
        respond(
            reply,
            "UNREGISTER",
            result.map(|()| Some(OkResponse::new())),
        );
        {
            let mut reg = self.reg();
            let conns: Vec<ConnId> = user.lock().conns.iter().map(|c| c.handle.id()).collect();
            for conn in conns {
                reg.detach(conn, BYE_UNREGISTERED);
            }
            if let Some(entry) = reg.conns.get_mut(&me) {
                entry.unregistering = false;
            }
            // The entry stays marked, so that a sign-in that pinned it
            // before now fails (4.8). The registry forgets it, so that a
            // later sign-in starts afresh, as a new identity.
            if reg.users.get(uid).is_some_and(|u| Arc::ptr_eq(u, &user)) {
                reg.users.remove(uid);
            }
        }
        drop(held);
        if done {
            tracing::info!(%uid, "identity deleted");
        }
        Ok(None)
    }

    /// Deletes what the server keeps about `uid` (4.8): its memberships,
    /// with a PART each, then with `purge` every message it sent, as if by
    /// DELETE, then everything stored, then its roles and invitations in
    /// each room, in memory and stored at once, and for a hosted identity
    /// its key file.
    async fn forget(&self, uid: &Uid, user: &Arc<UserEntry>, purge: bool) -> Result<(), Fail> {
        // A JOIN under way may add a room after the first pass, but none
        // can start after it, since the user is ending. So this ends.
        loop {
            let convs = user.convs();
            if convs.is_empty() {
                break;
            }
            for conv in convs {
                self.auto_part(conv, uid).await;
            }
        }
        if purge {
            let deleted = self.purge(uid, uid, None).await?;
            tracing::info!(%uid, deleted, "purged an identity's messages");
        }
        let hosted = self.hosts_uid(uid);
        let now = self.now();
        {
            let _keys = self.keys_lock.lock().await;
            let who = uid.clone();
            let is_hosted = self.db(move |s| s.hosted_keys(&who)).await?.is_some() && hosted;
            let who = uid.clone();
            // A hosted name is never registered again (4.8, 10.5).
            self.db(move |s| s.forget_identity(&who, is_hosted, now))
                .await?;
            if is_hosted {
                self.unpublish(uid).await;
            }
        }
        // The store forgot its roles and invitations above, but a ROLE or
        // INVITE may have stored one since, or be about to put one in
        // memory. So each room's are removed again from both at once,
        // under its lock: after that, a ROLE or INVITE changes both too.
        // Every room is in memory, so this covers them all.
        let entries: Vec<_> = self
            .rooms
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect();
        for entry in entries {
            let mut st = entry.lock().await;
            let key = st.key;
            if st.dropped {
                continue;
            }
            let Some(info) = st.room_info_mut() else {
                continue;
            };
            if !info.roles.contains_key(uid) && !info.invites.contains(uid) {
                continue;
            }
            let who = uid.clone();
            self.db(move |s| s.forget_room_roles(key, &who)).await?;
            info.roles.remove(uid);
            info.invites.remove(uid);
        }
        // Operators from the configuration stay operators (10.1).
        let configured = self.config.operators().iter().any(|op| op.to_uid() == *uid);
        if !configured {
            self.operators
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .remove(uid);
        }
        // Its KeyPackages, pending Welcomes and backups went with
        // `forget_identity` (4.8). Its connections, which could store more,
        // are held at their gates until it is done.
        Ok(())
    }
}
