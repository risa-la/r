//! One connection to one server: the greeting (4.1), becoming anonymous,
//! a guest or signed in (4.1, 4.2, 4.6, 4.7), commands matched to their
//! responses (3.6) and keepalive (11).

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use risala_proto::auth::{Nonce, SecretKey};
use risala_proto::binary::EncodedRecords;
use risala_proto::command::{Command, GuestToken, Request};
use risala_proto::connection::ConnectionKind;
use risala_proto::frame::{LineDecoder, LineLimits};
use risala_proto::line::read_ref;
use risala_proto::names::{Domain, Identity, Name, Uid};
use risala_proto::server::{
    ErrResponse, Greeting, OkResponse, Register, ServerLine, ServerMessage,
};
use risala_proto::types::Ref;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;

use super::error::{CloseReason, CommandError, Error};
use super::tls::{self, CaVerifier, Verified};
use crate::addr::{ServerAddr, TrustStore};

/// The most response lines kept for one command before the server is
/// considered broken. Far above any page a server sends (7.2, 6.1).
const MAX_RESPONSE_LINES: usize = 100_000;

/// Settings for [`Session::connect`].
#[derive(Clone)]
pub struct SessionOptions {
    /// The CA check for rule 1 of 2.2. `None` uses
    /// [`platform_ca_verifier`](super::platform_ca_verifier), loaded anew
    /// for each connection; pass one in to reuse it.
    pub ca_verifier: Option<CaVerifier>,
    /// Connect to this socket address instead of resolving the host. SNI,
    /// trust records and signing still use the [`ServerAddr`].
    pub connect_to: Option<SocketAddr>,
    /// The longest that TCP, TLS and the greeting may take together.
    pub connect_timeout: Duration,
    /// Send a PING after this long with nothing received (11).
    pub ping_after: Duration,
    /// Close the connection if nothing at all arrives this long after
    /// that PING (11).
    pub ping_timeout: Duration,
    /// How many incoming lines may wait unread. If the app falls further
    /// behind, the session closes with [`CloseReason::Overflow`] rather
    /// than stop reading or grow without bound.
    pub incoming_capacity: usize,
}

impl Default for SessionOptions {
    /// No CA verifier given (the platform's), a 30 second connect
    /// timeout, a PING after 90 seconds of silence (before the server's
    /// own 120, 11) and a 30 second answer timeout, and room for 4096
    /// incoming lines.
    fn default() -> Self {
        SessionOptions {
            ca_verifier: None,
            connect_to: None,
            connect_timeout: Duration::from_secs(30),
            ping_after: Duration::from_secs(90),
            ping_timeout: Duration::from_secs(30),
            incoming_capacity: 4096,
        }
    }
}

impl std::fmt::Debug for SessionOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionOptions")
            .field("ca_verifier", &self.ca_verifier.as_ref().map(|_| ".."))
            .field("connect_to", &self.connect_to)
            .field("connect_timeout", &self.connect_timeout)
            .field("ping_after", &self.ping_after)
            .field("ping_timeout", &self.ping_timeout)
            .field("incoming_capacity", &self.incoming_capacity)
            .finish()
    }
}

/// What is known about a connection once it is open.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// The server address connected to.
    pub addr: ServerAddr,
    /// The hostname sent in SNI, in lower case: what AUTH and REGISTER
    /// sign (4.6). `None` for an IP address, which sends no SNI (2.1).
    pub sni: Option<String>,
    /// The server's greeting (4.1). Its `host` is informational only.
    pub greeting: Greeting,
    /// How the certificate was accepted (2.2).
    pub verified: Verified,
}

/// How a command ended (3.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum End {
    /// `OK`, with its result values.
    Ok(OkResponse),
    /// `ERR`.
    Err(ErrResponse),
    /// An `OK` or `ERR` that could not be parsed: a general failure
    /// (2.3). Holds the raw line.
    Unparseable(String),
}

/// The response to one command (3.6): the lines tagged with its `ref`,
/// in order, and the final `OK` or `ERR`.
///
/// Live events the command caused are not here. They arrive on the
/// incoming queue, and are already queued when the response is
/// returned (3.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// The response lines, such as the posts of FETCH or the ROOM lines
    /// of LIST, with their `ref`.
    pub lines: Vec<ServerMessage>,
    /// The final response.
    pub end: End,
}

impl Response {
    /// Whether the command succeeded.
    pub fn is_ok(&self) -> bool {
        matches!(self.end, End::Ok(_))
    }

    /// The `OK`, or the failure.
    pub fn ok(&self) -> Result<&OkResponse, CommandError> {
        match &self.end {
            End::Ok(ok) => Ok(ok),
            End::Err(err) => Err(CommandError::Server(err.clone())),
            End::Unparseable(line) => Err(CommandError::Unparseable(line.clone())),
        }
    }

    /// Splits the response into its lines and its `OK`, or the failure.
    pub fn into_result(self) -> Result<(Vec<ServerMessage>, OkResponse), CommandError> {
        match self.end {
            End::Ok(ok) => Ok((self.lines, ok)),
            End::Err(err) => Err(CommandError::Server(err)),
            End::Unparseable(line) => Err(CommandError::Unparseable(line)),
        }
    }
}

/// What arrives on a session's incoming queue, in the order the server
/// sent it (3.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Incoming {
    /// A line that is not part of a response: a live post, WELCOME,
    /// PRESENCE, GONE, DROP, NOTICE, BYE or a line with an unknown verb.
    Line(ServerMessage),
    /// The response to a command sent with [`Session::send`], placed where
    /// its final `OK` or `ERR` arrived. Every line before it in the queue
    /// arrived before that final line, and every line after it arrived
    /// after.
    Reply {
        /// The `ref` [`Session::send`] returned for the command.
        ref_: Ref,
        /// The response.
        response: Response,
    },
}

impl Incoming {
    /// The line, if this is not a reply.
    pub fn into_line(self) -> Option<ServerMessage> {
        match self {
            Incoming::Line(msg) => Some(msg),
            Incoming::Reply { .. } => None,
        }
    }
}

/// One connection to a server (2, 3.6, 4, 11).
///
/// - [`connect`](Self::connect) opens TLS with the checks of 2.2 and reads
///   the greeting. The connection is then [`New`](ConnectionKind::New).
/// - [`anon`](Self::anon), [`guest`](Self::guest), [`auth`](Self::auth)
///   and [`register`](Self::register) make it anonymous, a guest or
///   signed in, once (4.1). [`kind`](Self::kind) says which it is.
/// - [`request`](Self::request) sends any command that the connection's
///   kind may send (Section 13), and returns its [`Response`]. A command
///   the kind may not send is refused here with [`Error::WrongKind`] and
///   never reaches the server: a FOLLOW or FETCH on a signed-in
///   connection would tell the server who follows (4.1). POST passes on
///   every kind, since a public room's PublicMessages may go on a
///   signed-in connection (5.2, 12.6); which connection a post takes is
///   the group engine's to decide. Requests may be made concurrently;
///   each gets a fresh `ref`, and responses are matched in order (3.6).
/// - Every other line arrives on the queue from
///   [`take_incoming`](Self::take_incoming), in order: live posts,
///   WELCOME, PRESENCE, GONE, DROP, NOTICE, BYE and lines with unknown
///   verbs. Server PINGs are answered inside the session (11).
/// - [`send`](Self::send) sends a command whose response arrives on that
///   same queue, as an [`Incoming::Reply`] at the point its final line
///   arrived. Use it when the order of responses relative to live lines
///   matters, as it does for FOLLOW and its live posts (3.6, 7.1).
///
/// Dropping the session closes the connection.
pub struct Session {
    info: SessionInfo,
    shared: Arc<Shared>,
    out: mpsc::UnboundedSender<Outgoing>,
    incoming: Mutex<Option<mpsc::Receiver<Incoming>>>,
    closed: watch::Receiver<Option<CloseReason>>,
    stop: watch::Sender<bool>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("addr", &self.info.addr)
            .field("kind", &self.kind())
            .field("uid", &self.uid())
            .finish_non_exhaustive()
    }
}

struct Shared {
    state: Mutex<State>,
}

struct State {
    next_ref: u64,
    pending: VecDeque<Pending>,
    closed: Option<CloseReason>,
    /// The connection's kind (4.1).
    kind: ConnectionKind,
    /// ANON, GUEST, AUTH or REGISTER is waiting for its answer.
    kind_pending: bool,
    /// The guest or identity uid, for a guest or signed-in connection.
    uid: Option<Uid>,
    /// The sign-in's `OK` carried `op=yes` (4.6, 10.1).
    operator: bool,
    nonce_used: bool,
}

struct Pending {
    ref_: Ref,
    lines: Vec<ServerMessage>,
    /// For ANON, GUEST, AUTH and REGISTER: the kind and uid the
    /// connection gets if the command succeeds.
    sets: Option<(ConnectionKind, Option<Uid>)>,
    reply: ReplyTo,
}

/// Where a command's response goes.
enum ReplyTo {
    /// Nowhere: the session's own keepalive PING.
    Keepalive,
    /// To [`Session::request`]'s future.
    Waiter(oneshot::Sender<Result<Response, Error>>),
    /// Onto the incoming queue, from [`Session::send`].
    Queue,
}

enum Outgoing {
    Line(String),
    Close,
}

impl Session {
    /// Connects to `addr`, checks the certificate under 2.2 using `trust`,
    /// and reads the greeting (4.1).
    ///
    /// A greeting with a version other than 1 closes the connection with
    /// [`Error::UnsupportedVersion`] (3.8). A trust failure is
    /// [`Error::Trust`], carrying the fingerprint for the app to show.
    pub async fn connect(
        addr: &ServerAddr,
        trust: Arc<dyn TrustStore>,
        options: SessionOptions,
    ) -> Result<Session, Error> {
        let timeout = options.connect_timeout;
        match tokio::time::timeout(timeout, Session::connect_inner(addr, trust, options)).await {
            Ok(r) => r,
            Err(_) => Err(Error::Timeout),
        }
    }

    async fn connect_inner(
        addr: &ServerAddr,
        trust: Arc<dyn TrustStore>,
        options: SessionOptions,
    ) -> Result<Session, Error> {
        let ca = match &options.ca_verifier {
            Some(ca) => ca.clone(),
            None => tls::platform_ca_verifier_blocking().await,
        };
        let (stream, verified) = tls::connect(addr, &trust, ca, options.connect_to).await?;
        let (mut rd, wr) = tokio::io::split(stream);
        // 2.3: lines that carry MLS data, such as POST, WELCOME, GROUPINFO
        // and KEYPKG, may be long. A server sends them only once the
        // connection has a kind; reading them at any time costs nothing
        // more than the limit.
        let mut decoder = LineDecoder::with_limits(LineLimits::SERVER);
        let greeting = read_greeting(&mut rd, &mut decoder).await;
        let greeting = match greeting {
            Ok(g) => g,
            Err(e) => {
                let mut wr = wr;
                let _ = wr.shutdown().await;
                return Err(e);
            }
        };
        tracing::debug!(addr = %addr, fingerprint = %verified.fingerprint, "connected");
        let info = SessionInfo {
            addr: addr.clone(),
            sni: (!addr.is_ip()).then(|| addr.host().to_owned()),
            greeting,
            verified,
        };
        Ok(Session::start(info, rd, wr, decoder, &options))
    }

    fn start<S>(
        info: SessionInfo,
        rd: ReadHalf<S>,
        wr: WriteHalf<S>,
        decoder: LineDecoder,
        options: &SessionOptions,
    ) -> Session
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                next_ref: 1,
                pending: VecDeque::new(),
                closed: None,
                kind: ConnectionKind::New,
                kind_pending: false,
                uid: None,
                operator: false,
                nonce_used: false,
            }),
        });
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        let (in_tx, in_rx) = mpsc::channel(options.incoming_capacity.max(1));
        let (closed_tx, closed_rx) = watch::channel(None);
        let (stop_tx, stop_rx) = watch::channel(false);
        let write_failed = Arc::new(tokio::sync::Notify::new());

        tokio::spawn(write_loop(wr, out_rx, write_failed.clone()));
        let reader = Reader {
            rd,
            decoder,
            shared: shared.clone(),
            out: out_tx.clone(),
            incoming: in_tx,
            ping_after: options.ping_after,
            ping_timeout: options.ping_timeout,
            bye: None,
        };
        tokio::spawn(reader.run(stop_rx, write_failed, closed_tx));

        Session {
            info,
            shared,
            out: out_tx,
            incoming: Mutex::new(Some(in_rx)),
            closed: closed_rx,
            stop: stop_tx,
        }
    }

    /// What is known about the connection: address, SNI, greeting and
    /// how the certificate was accepted.
    pub fn info(&self) -> &SessionInfo {
        &self.info
    }

    /// The connection's kind (4.1): new until ANON, GUEST, AUTH or
    /// REGISTER succeeds.
    pub fn kind(&self) -> ConnectionKind {
        self.shared.state.lock().expect("poisoned").kind
    }

    /// The uid of a guest or signed-in connection, once GUEST, AUTH or
    /// REGISTER has succeeded. An anonymous connection has none.
    pub fn uid(&self) -> Option<Uid> {
        self.shared.state.lock().expect("poisoned").uid.clone()
    }

    /// Whether the sign-in's `OK` said the identity is a server operator
    /// (`op=yes`, 4.6, 10.1). `false` until signed in.
    pub fn is_operator(&self) -> bool {
        self.shared.state.lock().expect("poisoned").operator
    }

    /// Takes the incoming queue: every server line that is not a response
    /// to a command or a PING, and the responses to commands sent with
    /// [`send`](Self::send), in arrival order. It ends when the
    /// connection closes. Only the first call returns it.
    pub fn take_incoming(&self) -> Option<mpsc::Receiver<Incoming>> {
        self.incoming.lock().expect("poisoned").take()
    }

    /// Sends a command and waits for its response (3.6).
    ///
    /// The command gets a fresh `ref`. It fails with
    /// [`Error::InvalidCommand`] if it cannot be written as a valid line,
    /// [`Error::WrongKind`] if the connection's kind may not send it
    /// (Section 13), [`Error::NoResponse`] for PONG,
    /// [`Error::KindPending`] while ANON, GUEST, AUTH or REGISTER waits
    /// for its answer, [`Error::NonceUsed`] for a second AUTH or REGISTER
    /// (4.6), and [`Error::Closed`] if the connection closes first. A
    /// server `ERR` is not an error here: it is in the [`Response`].
    ///
    /// When it returns, every incoming line that came before the final
    /// response, such as the live post a POST caused, is already queued.
    pub async fn request(&self, command: Command) -> Result<Response, Error> {
        self.request_setting(command, None).await
    }

    /// [`request`](Self::request), for a command that gives the
    /// connection its kind and uid if it succeeds.
    async fn request_setting(
        &self,
        command: Command,
        sets: Option<(ConnectionKind, Option<Uid>)>,
    ) -> Result<Response, Error> {
        let (tx, rx) = oneshot::channel();
        self.enqueue(command, ReplyTo::Waiter(tx), sets)?;
        match rx.await {
            Ok(result) => result,
            Err(_) => Err(Error::Closed(self.close_reason())),
        }
    }

    /// Sends a command whose response arrives on the incoming queue, as an
    /// [`Incoming::Reply`] carrying the returned `ref`, in its place among
    /// the other lines (3.6). Commands are written in the order of the
    /// calls.
    ///
    /// It fails as [`request`](Self::request) does. If the connection
    /// closes before the final response, no reply arrives: the queue ends
    /// instead.
    pub fn send(&self, command: Command) -> Result<Ref, Error> {
        if command.sets_kind() {
            // Use anon(), guest(), auth() or register(), which know the
            // kind and uid it gives.
            return Err(Error::WrongKind {
                verb: command.verb(),
                kind: self.kind(),
            });
        }
        self.enqueue(command, ReplyTo::Queue, None)
    }

    /// Writes a command with a fresh `ref` and records where its response
    /// goes.
    fn enqueue(
        &self,
        command: Command,
        reply: ReplyTo,
        sets: Option<(ConnectionKind, Option<Uid>)>,
    ) -> Result<Ref, Error> {
        if !command.gets_response() {
            return Err(Error::NoResponse);
        }
        let mut st = self.shared.state.lock().expect("poisoned");
        if let Some(reason) = &st.closed {
            return Err(Error::Closed(reason.clone()));
        }
        if command.sets_kind() && st.kind_pending {
            return Err(Error::KindPending);
        }
        // Section 13. A connection that has a kind and sends ANON, GUEST,
        // AUTH or REGISTER again is refused here too.
        if !command.kinds().contains(st.kind) {
            return Err(Error::WrongKind {
                verb: command.verb(),
                kind: st.kind,
            });
        }
        let uses_nonce = matches!(command, Command::Auth { .. } | Command::Register { .. });
        if uses_nonce && st.nonce_used {
            return Err(Error::NonceUsed);
        }
        let ref_: Ref = st
            .next_ref
            .to_string()
            .parse()
            .expect("a number is a valid ref");
        let request = Request {
            ref_: Some(ref_.clone()),
            command,
        };
        let line = request
            .try_to_line()
            .map_err(Error::InvalidCommand)?
            .to_string();
        // 2.3: the limits the server applies to this kind of connection.
        st.kind
            .client_limits()
            .check(&line)
            .map_err(Error::InvalidCommand)?;
        if self.out.send(Outgoing::Line(line)).is_err() {
            return Err(Error::Closed(CloseReason::Local));
        }
        st.next_ref += 1;
        st.nonce_used |= uses_nonce;
        st.kind_pending |= sets.is_some();
        st.pending.push_back(Pending {
            ref_: ref_.clone(),
            lines: Vec::new(),
            sets,
            reply,
        });
        Ok(ref_)
    }

    /// Sends a command and returns its `OK`, or the failure as
    /// [`Error::Rejected`].
    pub async fn request_ok(&self, command: Command) -> Result<OkResponse, Error> {
        let response = self.request(command).await?;
        Ok(response.into_result()?.1)
    }

    /// Sends ANON: the connection becomes anonymous (4.2), for posting,
    /// following and fetching (Section 7).
    pub async fn anon(&self) -> Result<(), Error> {
        let sets = Some((ConnectionKind::Anonymous, None));
        self.request_setting(Command::Anon, sets).await?.ok()?;
        Ok(())
    }

    /// Becomes the guest `~<name>` (4.2), starting a new session.
    pub async fn guest(&self, name: &Name) -> Result<Uid, Error> {
        Ok(self.guest_session(name, None).await?.0)
    }

    /// Becomes the guest `~<name>` (4.2). With `token`, the server resumes
    /// that guest's session if the token is its current one, and otherwise
    /// ignores it. Returns the uid, the session's new token, which the next
    /// resume needs, and whether the session was resumed (`resumed=yes`).
    /// The token is a secret.
    pub async fn guest_session(
        &self,
        name: &Name,
        token: Option<&GuestToken>,
    ) -> Result<(Uid, Option<GuestToken>, bool), Error> {
        let uid = Uid::guest(name);
        let command = Command::Guest {
            name: name.clone(),
            token: token.cloned(),
        };
        let sets = Some((ConnectionKind::Guest, Some(uid.clone())));
        let response = self.request_setting(command, sets).await?;
        let ok = response.ok()?;
        let new_token = ok.token().ok().flatten();
        // Only a resume can be resumed=yes; ignore it on a new session.
        let resumed = token.is_some() && ok.resumed().ok().flatten().unwrap_or(false);
        Ok((uid, new_token, resumed))
    }

    /// Signs in as `identity` with the device key of one of its current
    /// devices (4.6).
    ///
    /// The signed bytes use the hostname this client sent in SNI, never
    /// the greeting's host, and the greeting's nonce. Fails with
    /// [`Error::NoSni`] over an IP address (2.1).
    pub async fn auth(&self, identity: &Identity, key: &SecretKey) -> Result<Uid, Error> {
        self.auth_hedged(identity, key, [0; 32]).await
    }

    /// [`auth`](Self::auth) with the hedged variant of ML-DSA, which
    /// signers SHOULD use (4.6, PLAN.md 58): `rnd` is 32 fresh random
    /// bytes. All zeros gives the deterministic variant.
    pub async fn auth_hedged(
        &self,
        identity: &Identity,
        key: &SecretKey,
        rnd: [u8; 32],
    ) -> Result<Uid, Error> {
        let sni = self.info.sni.as_deref().ok_or(Error::NoSni)?;
        let signature =
            key.sign_challenge_hedged(sni, &self.info.greeting.nonce, identity.as_str(), rnd);
        let command = Command::Auth {
            identity: identity.clone(),
            signature,
        };
        let uid = identity.to_uid();
        let sets = Some((ConnectionKind::SignedIn, Some(uid.clone())));
        self.request_setting(command, sets).await?.ok()?;
        Ok(uid)
    }

    /// The server's identity domain, from INFO's `register=` (4.7, 8.5).
    /// A server without registration (`register=no`, or no value that
    /// parses) gives [`Error::NoRegistration`].
    pub async fn identity_domain(&self) -> Result<Domain, Error> {
        let info = self.request_ok(Command::Info { room: None }).await?;
        match info.register() {
            Ok(Some(Register::Domain(domain))) => Ok(domain),
            _ => Err(Error::NoRegistration),
        }
    }

    /// Sends `REGISTER <name> <keyfile> <signature>` (4.7): creates the
    /// identity `<name>@<domain>` with its first records, and signs in as
    /// it with `key`, the device key of the `device` record among them.
    /// `domain` is the server's identity domain, from
    /// [`identity_domain`](Self::identity_domain).
    ///
    /// It signs as [`auth`](Self::auth) does, and fails with
    /// [`Error::NoSni`] over an IP address (2.1). A server that answers
    /// `not-supported` offers no registration after all:
    /// [`Error::NoRegistration`]. Building the records is the identity
    /// code's (task C1).
    pub async fn register(
        &self,
        name: &Name,
        domain: &Domain,
        records: EncodedRecords,
        key: &SecretKey,
    ) -> Result<Uid, Error> {
        self.register_hedged(name, domain, records, key, [0; 32])
            .await
    }

    /// [`register`](Self::register) with the hedged variant of ML-DSA, as
    /// [`auth_hedged`](Self::auth_hedged).
    pub async fn register_hedged(
        &self,
        name: &Name,
        domain: &Domain,
        records: EncodedRecords,
        key: &SecretKey,
        rnd: [u8; 32],
    ) -> Result<Uid, Error> {
        let sni = self.info.sni.as_deref().ok_or(Error::NoSni)?;
        let identity = Identity::new(name, domain);
        let signature =
            key.sign_challenge_hedged(sni, &self.info.greeting.nonce, identity.as_str(), rnd);
        let command = Command::Register {
            name: name.clone(),
            records,
            signature,
        };
        let uid = identity.to_uid();
        let sets = Some((ConnectionKind::SignedIn, Some(uid.clone())));
        match self.request_setting(command, sets).await?.ok() {
            Ok(_) => Ok(uid),
            Err(CommandError::Server(err))
                if err.code == risala_proto::error::ErrorCode::NotSupported =>
            {
                Err(Error::NoRegistration)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Sends QUIT and waits for the server to close the connection (11).
    pub async fn quit(&self, message: &str) -> Result<CloseReason, Error> {
        let command = Command::Quit {
            message: risala_proto::text::escape(message),
        };
        let response = self.request(command).await;
        let reason = self.closed().await;
        match response {
            Ok(_) | Err(Error::Closed(_)) => Ok(reason),
            Err(e) => Err(e),
        }
    }

    /// Closes the connection from this side, sending TLS `close_notify`.
    /// Pending commands fail with [`CloseReason::Local`].
    pub fn close(&self) {
        let _ = self.stop.send(true);
    }

    /// Whether the connection has closed.
    pub fn is_closed(&self) -> bool {
        self.closed.borrow().is_some()
    }

    /// Waits until the connection closes, and says why.
    pub async fn closed(&self) -> CloseReason {
        let mut rx = self.closed.clone();
        match rx.wait_for(Option::is_some).await {
            Ok(reason) => reason.clone().unwrap_or(CloseReason::Local),
            Err(_) => CloseReason::Local,
        }
    }

    fn close_reason(&self) -> CloseReason {
        self.closed.borrow().clone().unwrap_or(CloseReason::Local)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
    }
}

/// The AUTH command for `identity` (4.6): an ML-DSA-44 signature with the
/// device key over the sign-in bytes.
///
/// `sni_host` must be the hostname this client sent in SNI, not the host
/// in the greeting. `nonce` is the greeting's nonce. It signs with the
/// deterministic variant, so that Appendix B's vector can be checked; the
/// spec's SHOULD for the hedged one is task C1's to weigh.
pub fn auth_command(
    sni_host: &str,
    nonce: &Nonce,
    identity: &Identity,
    key: &SecretKey,
) -> Command {
    let signature = key.sign_challenge(sni_host, nonce, identity.as_str());
    Command::Auth {
        identity: identity.clone(),
        signature,
    }
}

/// Reads lines until the greeting (4.1). Empty lines are skipped.
async fn read_greeting<R: AsyncRead + Unpin>(
    rd: &mut R,
    decoder: &mut LineDecoder,
) -> Result<Greeting, Error> {
    let mut buf = vec![0u8; 8192];
    loop {
        while let Some(line) = decoder.next_line() {
            let line = match line {
                Ok(line) if line.is_empty() => continue,
                Ok(line) => line,
                Err(e) => return Err(Error::BadGreeting(e.to_string())),
            };
            let msg: ServerMessage = line
                .parse()
                .map_err(|e: risala_proto::error::ParseError| Error::BadGreeting(e.to_string()))?;
            return match msg.line {
                ServerLine::Greeting(g) if g.version == risala_proto::PROTOCOL_VERSION => Ok(g),
                ServerLine::Greeting(g) => Err(Error::UnsupportedVersion(g.version)),
                ServerLine::Bye { message } => {
                    Err(Error::Closed(CloseReason::Server { bye: Some(message) }))
                }
                other => Err(Error::BadGreeting(format!(
                    "expected RISALA, got {}",
                    other.verb()
                ))),
            };
        }
        match rd.read(&mut buf).await {
            Ok(0) => return Err(Error::Closed(CloseReason::Server { bye: None })),
            Ok(n) => decoder.push(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(Error::Closed(CloseReason::Server { bye: None }));
            }
            Err(e) => return Err(Error::Io(e)),
        }
    }
}

/// Writes queued lines with LF; on `Close`, or when the session is gone,
/// sends `close_notify`.
async fn write_loop<W: AsyncWrite>(
    mut wr: WriteHalf<W>,
    mut rx: mpsc::UnboundedReceiver<Outgoing>,
    failed: Arc<tokio::sync::Notify>,
) {
    while let Some(msg) = rx.recv().await {
        let Outgoing::Line(mut line) = msg else {
            break;
        };
        line.push('\n');
        if let Err(e) = async {
            wr.write_all(line.as_bytes()).await?;
            wr.flush().await
        }
        .await
        {
            tracing::debug!(error = %e, "write failed");
            failed.notify_one();
            return;
        }
    }
    let _ = wr.shutdown().await;
}

/// The read side: splits lines, matches responses, answers PINGs, queues
/// everything else and keeps the connection alive.
struct Reader<S> {
    rd: ReadHalf<S>,
    decoder: LineDecoder,
    shared: Arc<Shared>,
    out: mpsc::UnboundedSender<Outgoing>,
    incoming: mpsc::Sender<Incoming>,
    ping_after: Duration,
    ping_timeout: Duration,
    bye: Option<String>,
}

impl<S: AsyncRead + AsyncWrite> Reader<S> {
    async fn run(
        mut self,
        stop: watch::Receiver<bool>,
        write_failed: Arc<tokio::sync::Notify>,
        closed: watch::Sender<Option<CloseReason>>,
    ) {
        let reason = self.read_loop(stop, write_failed).await;
        tracing::debug!(reason = %reason, "connection closed");
        let pending: Vec<Pending> = {
            let mut st = self.shared.state.lock().expect("poisoned");
            st.closed = Some(reason.clone());
            st.pending.drain(..).collect()
        };
        for p in pending {
            if let ReplyTo::Waiter(reply) = p.reply {
                let _ = reply.send(Err(Error::Closed(reason.clone())));
            }
        }
        let _ = self.out.send(Outgoing::Close);
        let _ = closed.send(Some(reason));
        // Dropping `self.incoming` ends the app's queue.
    }

    async fn read_loop(
        &mut self,
        mut stop: watch::Receiver<bool>,
        write_failed: Arc<tokio::sync::Notify>,
    ) -> CloseReason {
        let mut buf = vec![0u8; 16384];
        let mut last_rx = Instant::now();
        let mut ping_sent: Option<Instant> = None;
        loop {
            if let Err(reason) = self.drain_lines() {
                return reason;
            }
            let deadline = match ping_sent {
                None => last_rx + self.ping_after,
                Some(at) => at + self.ping_timeout,
            };
            tokio::select! {
                read = self.rd.read(&mut buf) => match read {
                    Ok(0) => return CloseReason::Server { bye: self.bye.take() },
                    Ok(n) => {
                        last_rx = Instant::now();
                        ping_sent = None;
                        self.decoder.push(&buf[..n]);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        return CloseReason::Server { bye: self.bye.take() };
                    }
                    Err(e) => return CloseReason::Io(e.to_string()),
                },
                () = tokio::time::sleep_until(deadline) => {
                    if ping_sent.is_some() {
                        return CloseReason::PingTimeout;
                    }
                    if let Err(reason) = self.send_keepalive() {
                        return reason;
                    }
                    ping_sent = Some(Instant::now());
                }
                () = write_failed.notified() => {
                    return CloseReason::Io("write failed".into());
                }
                _ = stop.wait_for(|stop| *stop) => return CloseReason::Local,
            }
        }
    }

    /// Sends a PING of the session's own, matched like any command.
    fn send_keepalive(&mut self) -> Result<(), CloseReason> {
        let mut st = self.shared.state.lock().expect("poisoned");
        let ref_: Ref = st.next_ref.to_string().parse().expect("a valid ref");
        st.next_ref += 1;
        let line = Request {
            ref_: Some(ref_.clone()),
            command: Command::Ping { token: None },
        }
        .to_line()
        .to_string();
        self.out
            .send(Outgoing::Line(line))
            .map_err(|_| CloseReason::Io("write failed".into()))?;
        st.pending.push_back(Pending {
            ref_,
            lines: Vec::new(),
            sets: None,
            reply: ReplyTo::Keepalive,
        });
        Ok(())
    }

    fn drain_lines(&mut self) -> Result<(), CloseReason> {
        while let Some(line) = self.decoder.next_line() {
            match line {
                Ok(line) if line.is_empty() => {}
                Ok(line) => self.handle_line(line)?,
                // Lines a client cannot read are ignored (2.3). Without
                // its text, a bad line cannot be told to be a final
                // response.
                Err(e) => tracing::debug!(error = %e, "ignoring a bad line"),
            }
        }
        Ok(())
    }

    fn handle_line(&mut self, line: String) -> Result<(), CloseReason> {
        let msg = match line.parse::<ServerMessage>() {
            Ok(msg) => msg,
            Err(e) => {
                // An OK or ERR that does not parse still ends its command,
                // as a general failure (2.3). Anything else is ignored.
                if is_final_verb(&line) {
                    let ref_ = read_ref(line.as_bytes());
                    return self.finish(ref_, End::Unparseable(line));
                }
                tracing::debug!(error = %e, "ignoring a line that does not parse");
                return Ok(());
            }
        };
        match msg.line {
            ServerLine::Ok(ok) => self.finish(msg.ref_, End::Ok(ok)),
            ServerLine::Err(err) => self.finish(msg.ref_, End::Err(err)),
            ServerLine::Ping { token } => {
                // Answer straight away (11). PONG gets no response.
                let pong = Request::new(Command::Pong { token });
                match pong.try_to_line() {
                    Ok(line) => {
                        let _ = self.out.send(Outgoing::Line(line.to_string()));
                    }
                    Err(e) => tracing::debug!(error = %e, "cannot answer PING"),
                }
                Ok(())
            }
            ServerLine::Greeting(_) => {
                tracing::debug!("ignoring a second greeting");
                Ok(())
            }
            _ if msg.ref_.is_some() => self.add_response_line(msg),
            _ => {
                if let ServerLine::Bye { message } = &msg.line {
                    self.bye = Some(message.clone());
                }
                self.queue(Incoming::Line(msg))
            }
        }
    }

    fn add_response_line(&mut self, msg: ServerMessage) -> Result<(), CloseReason> {
        let mut st = self.shared.state.lock().expect("poisoned");
        let ref_ = msg.ref_.as_ref().expect("checked");
        let Some(pending) = st.pending.iter_mut().find(|p| p.ref_ == *ref_) else {
            tracing::debug!("ignoring a response line for no command");
            return Ok(());
        };
        if pending.lines.len() >= MAX_RESPONSE_LINES {
            return Err(CloseReason::Protocol("too many response lines".into()));
        }
        pending.lines.push(msg);
        Ok(())
    }

    fn queue(&mut self, msg: Incoming) -> Result<(), CloseReason> {
        match self.incoming.try_send(msg) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => Err(CloseReason::Overflow),
            // The app does not want incoming lines.
            Err(mpsc::error::TrySendError::Closed(_)) => Ok(()),
        }
    }

    /// Ends the oldest pending command (3.6: final responses come in the
    /// order of the commands). A `ref` that names another command means
    /// the server broke that order, so the session closes.
    fn finish(&mut self, ref_: Option<Ref>, end: End) -> Result<(), CloseReason> {
        let mut st = self.shared.state.lock().expect("poisoned");
        let Some(front) = st.pending.front() else {
            return Err(CloseReason::Protocol(
                "a final response with no command".into(),
            ));
        };
        if ref_.as_ref().is_some_and(|r| *r != front.ref_) {
            return Err(CloseReason::Protocol(
                "a final response out of order".into(),
            ));
        }
        let pending = st.pending.pop_front().expect("checked");
        if pending.sets.is_some() {
            st.kind_pending = false;
        }
        // The uid is the one asked for, whatever the OK names: a server
        // cannot sign the connection in as someone else (4.6).
        if let (Some((kind, uid)), End::Ok(ok)) = (&pending.sets, &end) {
            st.kind = *kind;
            st.uid = uid.clone();
            st.operator =
                *kind == ConnectionKind::SignedIn && ok.op().ok().flatten().unwrap_or(false);
        }
        drop(st);
        let response = Response {
            lines: pending.lines,
            end,
        };
        match pending.reply {
            ReplyTo::Keepalive => Ok(()),
            ReplyTo::Waiter(reply) => {
                let _ = reply.send(Ok(response));
                Ok(())
            }
            ReplyTo::Queue => self.queue(Incoming::Reply {
                ref_: pending.ref_,
                response,
            }),
        }
    }
}

/// Whether a line that did not parse has the verb OK or ERR.
fn is_final_verb(line: &str) -> bool {
    let rest = match line.strip_prefix('@') {
        Some(tagged) => match tagged.split_once(' ') {
            Some((_, rest)) => rest.trim_start_matches(' '),
            None => return false,
        },
        None => line,
    };
    let end = rest
        .find(|c: char| !c.is_ascii_alphabetic())
        .unwrap_or(rest.len());
    let (verb, after) = rest.split_at(end);
    (after.is_empty() || after.starts_with(' '))
        && (verb.eq_ignore_ascii_case("OK") || verb.eq_ignore_ascii_case("ERR"))
}

#[cfg(test)]
mod tests {
    use super::is_final_verb;

    #[test]
    fn final_verbs() {
        for line in ["OK", "ok x", "@ref=1 ERR", "@bad;;tags OK =", "@a  err x"] {
            assert!(is_final_verb(line), "{line}");
        }
        for line in ["OKAY", "MSG #a ok", "@ref=1", "", "OK1", "ERR=", "PING"] {
            assert!(!is_final_verb(line), "{line}");
        }
    }
}
