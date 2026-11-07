//! Identities (4.3-4.8): this device's keys, REGISTER, KEY and
//! UNREGISTER, as methods of [`Client`] and [`Account`].
//!
//! - **Device keys.** Each device has its own ML-DSA-44 key per identity,
//!   kept in [`ClientOptions::keys`](super::ClientOptions::keys) under the
//!   identity, such as `alice@example.org`. [`Client::create_device_key`]
//!   makes one and [`Client::import_device_key`] reads one from PEM (App.
//!   A). [`Client::key_line`] gives the line to publish in a self-hosted
//!   identity's key file (4.4), at [`Client::key_file_url`].
//! - **Signing in.** [`Client::add_identity`] adds the account, and
//!   [`Account::connect`] signs in with AUTH (4.5). `auth-failed` is
//!   final, since the same key fails the same way:
//!   [`ConnectionState::Failed`](super::ConnectionState::Failed) with
//!   [`RefusedKind::AuthFailed`], or [`RefusedKind::KeyRemoved`] if the
//!   server accepted this key before. `unavailable` means the server could
//!   not get the identity's key file, and the account tries again later
//!   ([`RefusedKind::Unavailable`]).
//! - **Registering.** [`Client::register`] creates `<name>@<domain>` on a
//!   server that hosts identities, with this device's key (4.6).
//! - **Hosted identities' keys.** [`Account::keys`],
//!   [`Account::add_key`] and [`Account::remove_key`] (4.7).
//! - **Deleting.** [`Account::unregister`] (4.8).
//!
//! Refusals are [`ClientError::Refused`], with a [`RefusedKind`]; key
//! store failures are [`ClientError::Keys`].

use std::sync::Arc;

use risala_proto::auth::{PublicKey, SecretKey};
use risala_proto::command::{Command, KeyCommand};
use risala_proto::error::ErrorCode;
use risala_proto::keyfile::{KeyEntry, well_known_url};
use risala_proto::names::{Identity, Name, Uid};
use risala_proto::server::{ServerLine, ServerMessage};
use risala_proto::text::{escape, unescape};
use tracing::warn;

use super::account::Account;
use super::types::{ClientError, DeviceKey, KeyErrorKind, KeyInfo, RefusedKind, Unregistered};
use super::{Client, blocking, parse_server};
use crate::addr::{ServerAddr, TrustStore};
use crate::conn::keys::{self, KeyStore, KeyStoreError};
use crate::conn::{self, CommandError, Session, SessionOptions};

/// How long QUIT may take after a one-off session.
const QUIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

fn parse_identity(identity: &str) -> Result<Identity, ClientError> {
    identity
        .trim()
        .parse()
        .map_err(|_| ClientError::Invalid(format!("identity {identity:?}")))
}

fn store_error(e: KeyStoreError) -> ClientError {
    let kind = match e {
        KeyStoreError::BadKey(_) => KeyErrorKind::BadKey,
        _ => KeyErrorKind::Failed,
    };
    ClientError::keys(kind, e.to_string())
}

fn exists(identity: &Identity) -> ClientError {
    ClientError::keys(
        KeyErrorKind::Exists,
        format!("{identity} already has a device key on this device"),
    )
}

fn no_key(identity: &Identity) -> ClientError {
    ClientError::keys(KeyErrorKind::NoKey, format!("no device key for {identity}"))
}

/// Reads a public key the user typed or pasted (4.4).
fn parse_public_key(input: &str) -> Result<(PublicKey, Option<String>), ClientError> {
    keys::parse_key_input(input).map_err(|e| {
        ClientError::keys(
            KeyErrorKind::BadKey,
            format!("not an mldsa44 key or key file line: {e}"),
        )
    })
}

/// The key stored for `identity`, or a new one, saved. Says whether it is
/// new.
fn load_or_create(
    keys: &dyn KeyStore,
    identity: &Identity,
) -> Result<(SecretKey, bool), ClientError> {
    if let Some(key) = keys.load(identity.as_str()).map_err(store_error)? {
        return Ok((key, false));
    }
    let key = keys::generate_device_key()
        .map_err(|e| ClientError::keys(KeyErrorKind::Failed, e.to_string()))?;
    keys.save(identity.as_str(), &key).map_err(store_error)?;
    Ok((key, true))
}

/// Runs `f` on the client's runtime, so that it may be awaited on any
/// executor.
async fn on_runtime<T: Send + 'static>(
    client: &Client,
    f: impl Future<Output = Result<T, ClientError>> + Send + 'static,
) -> Result<T, ClientError> {
    match client.runtime().spawn(f).await {
        Ok(result) => result,
        Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
        Err(_) => Err(ClientError::NotConnected),
    }
}

/// Opens a one-off connection and signs in as `identity` with `key`.
async fn signed_in_session(
    addr: &ServerAddr,
    trust: Arc<dyn TrustStore>,
    options: SessionOptions,
    identity: &Identity,
    key: &SecretKey,
) -> Result<Session, ClientError> {
    let server = addr.to_string();
    let session = Session::connect(addr, trust, options)
        .await
        .map_err(|e| ClientError::from_sign_in(&server, &e))?;
    session
        .auth(identity, key)
        .await
        .map_err(|e| ClientError::from_sign_in(&server, &e))?;
    Ok(session)
}

/// Sends QUIT, waiting a little for the server to close.
async fn quit(session: &Session) {
    let _ = tokio::time::timeout(QUIT_TIMEOUT, session.quit("")).await;
}

impl Client {
    /// The key store, or [`KeyErrorKind::NoKeyStore`].
    pub(crate) fn key_store(&self) -> Result<Arc<dyn KeyStore>, ClientError> {
        self.options()
            .keys
            .clone()
            .ok_or_else(|| ClientError::keys(KeyErrorKind::NoKeyStore, "no key store"))
    }

    /// This device's key for `identity`, such as `alice@example.org`, if
    /// the key store has one. It reads the key store, which may block for
    /// a moment: call it off a UI thread.
    pub fn device_key(&self, identity: &str) -> Result<Option<DeviceKey>, ClientError> {
        let identity = parse_identity(identity)?;
        let key = self
            .key_store()?
            .load(identity.as_str())
            .map_err(store_error)?;
        Ok(key.map(|k| DeviceKey::new(identity.as_str(), &k.public_key())))
    }

    /// Makes a new device key for `identity` and stores it (4.4). If the
    /// identity already has one, it fails with [`KeyErrorKind::Exists`]
    /// unless `replace` is set.
    ///
    /// Then publish its [`key_line`](Self::key_line) in the identity's key
    /// file, or, for an identity a server hosts, add it from a device that
    /// is signed in ([`Account::add_key`], 4.7).
    pub async fn create_device_key(
        &self,
        identity: &str,
        replace: bool,
    ) -> Result<DeviceKey, ClientError> {
        let identity = parse_identity(identity)?;
        let keys = self.key_store()?;
        blocking(self.runtime(), move || {
            if !replace && keys.load(identity.as_str()).map_err(store_error)?.is_some() {
                return Err(exists(&identity));
            }
            let key = keys::generate_device_key()
                .map_err(|e| ClientError::keys(KeyErrorKind::Failed, e.to_string()))?;
            keys.save(identity.as_str(), &key).map_err(store_error)?;
            Ok(DeviceKey::new(identity.as_str(), &key.public_key()))
        })
        .await
    }

    /// Stores a private key from PEM as the device key for `identity`. It
    /// takes PKCS#8 in both forms Appendix A describes: the seed alone, or
    /// the seed with the expanded key, which `openssl genpkey -algorithm
    /// ML-DSA-44` writes.
    ///
    /// Importing the key already stored does nothing. A different key
    /// fails with [`KeyErrorKind::Exists`] unless `replace` is set. A PEM
    /// that is not such a key fails with [`KeyErrorKind::BadKey`].
    pub async fn import_device_key(
        &self,
        identity: &str,
        pem: &str,
        replace: bool,
    ) -> Result<DeviceKey, ClientError> {
        let identity = parse_identity(identity)?;
        let key = SecretKey::from_pkcs8_pem(pem).map_err(|_| {
            ClientError::keys(
                KeyErrorKind::BadKey,
                "not a PEM PKCS#8 ML-DSA-44 private key",
            )
        })?;
        let keys = self.key_store()?;
        blocking(self.runtime(), move || {
            match keys.load(identity.as_str()).map_err(store_error)? {
                Some(old) if old.public_key() == key.public_key() => {}
                Some(_) if !replace => return Err(exists(&identity)),
                _ => keys.save(identity.as_str(), &key).map_err(store_error)?,
            }
            Ok(DeviceKey::new(identity.as_str(), &key.public_key()))
        })
        .await
    }

    /// Deletes this device's key for `identity` from the key store, for
    /// example a key kept after [`RefusedKind::NotRegistered`]. Deleting a
    /// key that is not there does nothing.
    ///
    /// If the identity's key file lists the key, signing in as it from
    /// this device then needs a new key, and if it is the identity's only
    /// key, nobody can sign in as it. Ask the user first.
    pub async fn delete_device_key(&self, identity: &str) -> Result<(), ClientError> {
        let identity = parse_identity(identity)?;
        let keys = self.key_store()?;
        blocking(self.runtime(), move || {
            keys.delete(identity.as_str()).map_err(store_error)
        })
        .await
    }

    /// The key file line for this device's key for `identity`,
    /// `mldsa44 <key> [<label>]`, without a line break (4.4). A
    /// self-hosted identity publishes it in its key file, at
    /// [`key_file_url`](Self::key_file_url). `label` is a note for people,
    /// usually the device's name; empty for none.
    pub fn key_line(&self, identity: &str, label: &str) -> Result<String, ClientError> {
        let id = parse_identity(identity)?;
        let key = self
            .key_store()?
            .load(id.as_str())
            .map_err(store_error)?
            .ok_or_else(|| no_key(&id))?;
        keys::key_line(&key.public_key(), Some(label))
            .map_err(|_| ClientError::Invalid(format!("label {label:?}")))
    }

    /// Where `identity`'s key file is published:
    /// `https://<domain>/.well-known/risala/<name>` (4.3).
    pub fn key_file_url(&self, identity: &str) -> Result<String, ClientError> {
        let identity = parse_identity(identity)?;
        Ok(well_known_url(identity.name(), identity.domain()))
    }

    /// Registers `<name>@<domain>` on `server`, which hosts identities
    /// under `<domain>` (4.6), and adds it as an account. The account is
    /// not started: call [`Account::start`] or [`Account::connect`].
    ///
    /// It asks INFO for the identity domain first (8.5). The device key is
    /// the one the key store has for `<name>@<domain>`, or a new one,
    /// stored before REGISTER is sent, so that it is not lost if the
    /// answer is. A new key is deleted again only if the server refuses
    /// REGISTER. The server publishes the identity's key file itself;
    /// [`key_line`](Self::key_line) shows the line it holds.
    ///
    /// Refusals are [`ClientError::Refused`]:
    /// [`RefusedKind::NoRegistration`], [`RefusedKind::NoHostname`] for
    /// an IP address, [`RefusedKind::NameTaken`],
    /// [`RefusedKind::Forbidden`] (closed, banned, or a limit with
    /// `retry_after_secs`), [`RefusedKind::RateLimited`] and
    /// [`RefusedKind::AuthFailed`].
    ///
    /// If the connection drops before REGISTER is answered, the identity
    /// may or may not exist, and the key is kept (4.6). The client
    /// connects again and signs in with the key to find out: if that
    /// works, the registration went through and this returns the account
    /// as usual. If the server refuses the key, the identity was not
    /// created: [`RefusedKind::NotRegistered`], with the key still kept
    /// for the user to decide on. If neither can be learned,
    /// [`ClientError::Unconfirmed`].
    pub async fn register(&self, server: &str, name: &str) -> Result<Account, ClientError> {
        let addr = parse_server(server)?;
        let name: Name = name
            .trim()
            .parse()
            .map_err(|_| ClientError::Invalid(format!("name {name:?}")))?;
        if addr.is_ip() {
            return Err(ClientError::from_conn(
                &addr.to_string(),
                &conn::Error::NoSni,
            ));
        }
        let keys = self.key_store()?;
        let trust: Arc<dyn TrustStore> = Arc::new(self.store().clone());
        let options = self.options().session.clone();
        let identity = {
            let addr = addr.clone();
            on_runtime(self, register_on(addr, trust, options, keys, name)).await?
        };
        self.add_uid(&addr.to_string(), identity.to_uid())
    }
}

/// Connects to `addr`, learns its identity domain and registers `name`
/// under it. Returns the new identity.
async fn register_on(
    addr: ServerAddr,
    trust: Arc<dyn TrustStore>,
    options: SessionOptions,
    keys: Arc<dyn KeyStore>,
    name: Name,
) -> Result<Identity, ClientError> {
    let server = addr.to_string();
    let fail = |e: conn::Error| ClientError::from_sign_in(&server, &e);
    let session = Session::connect(&addr, trust.clone(), options.clone())
        .await
        .map_err(fail)?;
    let rt = tokio::runtime::Handle::current();
    let prepared = async {
        let domain = session.identity_domain().await.map_err(fail)?;
        let identity = Identity::new(&name, &domain);
        let (keys, id) = (keys.clone(), identity.clone());
        let (key, created) = blocking(&rt, move || load_or_create(&*keys, &id)).await?;
        Ok((domain, identity, key, created))
    }
    .await;
    let (domain, identity, key, created) = match prepared {
        Ok(p) => p,
        Err(e) => {
            quit(&session).await;
            return Err(e);
        }
    };
    let sent = session.register_under(&name, &domain, &key).await;
    match sent {
        Ok(_) => {
            quit(&session).await;
            Ok(identity)
        }
        Err(e) if certainly_not_registered(&e) => {
            quit(&session).await;
            if created {
                let id = identity.clone();
                if let Err(e) = blocking(&rt, move || keys.delete(id.as_str())).await {
                    warn!(error = %e, "deleting the key of a failed registration");
                }
            }
            Err(fail(e))
        }
        Err(lost) => {
            // The answer was lost: the identity may exist, with this key as
            // its only key. Keep the key, and sign in to find out (4.6).
            session.close();
            warn!(error = %lost, %identity, "REGISTER got no answer; signing in to check");
            confirm_registration(&addr, trust, options, &identity, &key, &lost).await
        }
    }
}

/// Whether REGISTER certainly did not create the identity: the server
/// answered `ERR`, or the command was never sent.
fn certainly_not_registered(e: &conn::Error) -> bool {
    matches!(
        e,
        conn::Error::Rejected(conn::CommandError::Server(_))
            | conn::Error::NoRegistration
            | conn::Error::NoSni
            | conn::Error::NonceUsed
            | conn::Error::InvalidCommand(_)
            | conn::Error::NoResponse
    )
}

/// After REGISTER got no answer, signs in on a new connection as
/// `identity` with the key it was sent with, to learn whether it was
/// created (4.6). The key is kept whatever happens.
async fn confirm_registration(
    addr: &ServerAddr,
    trust: Arc<dyn TrustStore>,
    options: SessionOptions,
    identity: &Identity,
    key: &SecretKey,
    lost: &conn::Error,
) -> Result<Identity, ClientError> {
    let unconfirmed = |why: String| ClientError::Unconfirmed {
        uid: identity.to_string(),
        message: format!(
            "REGISTER got no answer ({lost}), and {why}: whether {identity} was registered \
             is not known. This device's key for it is kept"
        ),
    };
    let session = match Session::connect(addr, trust, options).await {
        Ok(session) => session,
        Err(e) => return Err(unconfirmed(format!("connecting again failed ({e})"))),
    };
    let signed_in = session.auth(identity, key).await;
    quit(&session).await;
    match signed_in {
        Ok(_) => Ok(identity.clone()),
        Err(e) if e.is_auth_failed() => Err(ClientError::refused(
            RefusedKind::NotRegistered,
            format!(
                "REGISTER got no answer ({lost}), and the server refused to sign in with its \
                 key: {identity} was not registered. This device's key for it is kept"
            ),
        )),
        Err(e) => Err(unconfirmed(format!("signing in to check failed ({e})"))),
    }
}

/// An `ERR` to a KEY or UNREGISTER command as a client error.
/// `not-supported` to KEY means the server does not host the identity
/// (4.7), and `forbidden` to KEY DEL that the key is the last one.
fn refused(err: &risala_proto::server::ErrResponse, command: &Command) -> ClientError {
    let kind = match (&err.code, command) {
        (ErrorCode::NotSupported, Command::Key(_)) => RefusedKind::NotHosted,
        (ErrorCode::Forbidden, Command::Key(KeyCommand::Del { .. })) => RefusedKind::LastKey,
        _ => return ClientError::from_err(err).unwrap_or_else(|| ClientError::server(err)),
    };
    let mut e = ClientError::from_err(err).expect("a refusal");
    if let ClientError::Refused { kind: k, .. } = &mut e {
        *k = kind;
    }
    e
}

/// Sends `command` on `session`, and returns its response lines.
async fn request(
    server: &str,
    session: &Session,
    command: Command,
) -> Result<Vec<ServerMessage>, ClientError> {
    let response = session
        .request(command.clone())
        .await
        .map_err(|e| ClientError::from_conn(server, &e))?;
    match response.into_result() {
        Ok((lines, _)) => Ok(lines),
        Err(CommandError::Server(err)) => Err(refused(&err, &command)),
        Err(e) => Err(ClientError::from_conn(server, &e.into())),
    }
}

impl Account {
    /// The account's identity, or [`RefusedKind::Guest`].
    fn identity(&self) -> Result<Identity, ClientError> {
        self.shared().uid.to_identity().ok_or_else(|| {
            ClientError::refused(RefusedKind::Guest, "a guest has no keys or identity")
        })
    }

    /// This device's key for the account's identity, if the key store has
    /// one. See [`Client::device_key`].
    pub fn device_key(&self) -> Result<Option<DeviceKey>, ClientError> {
        let identity = self.identity()?;
        self.client().device_key(identity.as_str())
    }

    /// The public key of this device's key, if the key store has one.
    async fn device_public_key(&self) -> Result<Option<PublicKey>, ClientError> {
        let identity = self.identity()?;
        let keys = self.client().key_store()?;
        let rt = self.shared().rt.clone();
        let key = blocking(&rt, move || {
            keys.load(identity.as_str()).map_err(store_error)
        })
        .await?;
        Ok(key.map(|k| k.public_key()))
    }

    /// Sends a KEY command on the signed-in connection.
    async fn key_command(&self, command: KeyCommand) -> Result<Vec<ServerMessage>, ClientError> {
        self.identity()?;
        let session = self.session()?;
        request(&self.server(), &session, Command::Key(command)).await
    }

    /// The keys of the account's identity, which the server hosts (KEY
    /// LIST, 4.7). Needs a connection. An identity the server does not
    /// host gets [`RefusedKind::NotHosted`]: its keys are in its own key
    /// file.
    pub async fn keys(&self) -> Result<Vec<KeyInfo>, ClientError> {
        let lines = self.key_command(KeyCommand::List).await?;
        let mine = self.device_public_key().await?;
        Ok(lines
            .into_iter()
            .filter_map(|m| match m.line {
                ServerLine::Key { key, label } => Some(KeyInfo {
                    public_key: key.to_string(),
                    label: unescape(&label).into_owned(),
                    fingerprint: key.fingerprint().to_string(),
                    this_device: mine.as_ref() == Some(&key),
                }),
                _ => None,
            })
            .collect())
    }

    /// Adds a key to the account's identity, which the server hosts (KEY
    /// ADD, 4.7): usually a new device's, so that it can sign in. `key` is
    /// the key file line the new device shows ([`Client::key_line`]), or
    /// its key alone in base64. `label` names the device; if empty, the
    /// line's own label is used. Needs a connection.
    pub async fn add_key(&self, key: &str, label: &str) -> Result<KeyInfo, ClientError> {
        let (key, line_label) = parse_public_key(key)?;
        let label = match label.trim() {
            "" => line_label.unwrap_or_default(),
            l => l.to_owned(),
        };
        // Checks the label as a key file line would (4.4).
        let entry = KeyEntry::new(key.clone(), Some(&label))
            .map_err(|_| ClientError::Invalid(format!("label {label:?}")))?;
        let label = entry.label().unwrap_or("").to_owned();
        self.key_command(KeyCommand::Add {
            key: key.clone(),
            label: escape(&label),
        })
        .await?;
        let mine = self.device_public_key().await?;
        Ok(KeyInfo {
            public_key: key.to_string(),
            fingerprint: key.fingerprint().to_string(),
            this_device: mine.as_ref() == Some(&key),
            label,
        })
    }

    /// Removes a key from the account's identity, which the server hosts
    /// (KEY DEL, 4.7). `key` is a key file line or the key alone. Needs a
    /// connection.
    ///
    /// The server refuses to remove the last key:
    /// [`RefusedKind::LastKey`]. Removing this device's own key signs it
    /// out: the server closes its connections, and the account then
    /// fails with [`RefusedKind::KeyRemoved`].
    pub async fn remove_key(&self, key: &str) -> Result<(), ClientError> {
        let (key, _) = parse_public_key(key)?;
        self.key_command(KeyCommand::Del { key }).await?;
        Ok(())
    }

    /// Deletes the account's identity from the server (UNREGISTER, 4.8),
    /// then the account and its cache. `uid` must be the account's own
    /// uid, typed out by the user as a guard against mistakes; anything
    /// else fails with [`RefusedKind::WrongUid`] and sends nothing. With
    /// `purge`, the server also deletes every message the identity sent.
    ///
    /// The server leaves the identity's rooms and deletes what it keeps
    /// about it. If it hosts the identity, which KEY LIST tells first
    /// (4.7), it deletes its keys and key file too, so this device's key
    /// is deleted from the key store as well. Otherwise the key is kept:
    /// the identity's own key file is not the server's to change, and the
    /// key works on other servers.
    ///
    /// The account stops first, and the command goes on a connection of
    /// its own, so that the account cannot sign in again in between. If
    /// UNREGISTER fails, an account that was running starts again.
    pub async fn unregister(&self, uid: &str, purge: bool) -> Result<Unregistered, ClientError> {
        let identity = self.identity()?;
        let typed: Option<Uid> = uid.trim().parse().ok();
        if typed.as_ref() != Some(&self.shared().uid) {
            return Err(ClientError::refused(
                RefusedKind::WrongUid,
                format!("type {} to confirm", self.shared().uid),
            ));
        }
        let client = self.client();
        let keys = client.key_store()?;
        let key = {
            let (keys, identity) = (keys.clone(), identity.clone());
            blocking(&self.shared().rt, move || {
                keys.load(identity.as_str())
                    .map_err(store_error)?
                    .ok_or_else(|| no_key(&identity))
            })
            .await?
        };
        let was_running = self.is_running();
        self.disconnect().await;

        let addr = self.shared().server.clone();
        let trust: Arc<dyn TrustStore> = Arc::new(self.shared().store.clone());
        let options = self.shared().options.session.clone();
        let result = {
            let identity = identity.clone();
            on_runtime(&client, async move {
                let server = addr.to_string();
                let session = signed_in_session(&addr, trust, options, &identity, &key).await?;
                let result = async {
                    // KEY LIST tells whether the server hosts the identity
                    // (4.7). INFO does not: it says register=no while
                    // registration is closed.
                    let hosted =
                        match request(&server, &session, Command::Key(KeyCommand::List)).await {
                            Ok(_) => true,
                            Err(ClientError::Refused {
                                kind: RefusedKind::NotHosted,
                                ..
                            }) => false,
                            Err(e) => return Err(e),
                        };
                    let command = Command::Unregister {
                        uid: identity.to_uid(),
                        purge,
                    };
                    request(&server, &session, command).await?;
                    Ok(hosted)
                }
                .await;
                if result.is_err() {
                    quit(&session).await;
                }
                // After OK the server closes the connection itself.
                session.close();
                result
            })
            .await
        };
        let hosted = match result {
            Ok(hosted) => hosted,
            Err(e) => {
                if was_running {
                    self.start();
                }
                return Err(e);
            }
        };

        client.remove_account(self).await?;
        let mut key_deleted = false;
        if hosted {
            let id = identity.clone();
            match blocking(&self.shared().rt, move || keys.delete(id.as_str())).await {
                Ok(()) => key_deleted = true,
                Err(e) => warn!(error = %e, "deleting the device key of an unregistered identity"),
            }
        }
        Ok(Unregistered {
            uid: identity.to_string(),
            hosted,
            key_deleted,
        })
    }
}
