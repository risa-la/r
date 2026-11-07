//! A signed-in or signing-in connection to one server: the greeting (4.1),
//! sign-in (4.2, 4.5, 4.6), commands matched to their responses (3.6) and
//! keepalive (11).

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use risala_proto::auth::SecretKey;
use risala_proto::command::{Command, Request};
use risala_proto::frame::{LineDecoder, MAX_CLIENT_LINE, MAX_SERVER_LINE, check_line_len};
use risala_proto::line::read_ref;
use risala_proto::names::{Id, Identity, Name, Uid};
use risala_proto::server::{
    ErrResponse, Greeting, OkResponse, Register, ServerLine, ServerMessage,
};
use risala_proto::types::Ref;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;

use super::error::{CloseReason, CommandError, Error};
use super::keys;
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
    /// sign (4.5). `None` for an IP address, which sends no SNI (2.1).
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
    /// The response lines, such as the events of HISTORY or the ROOM
    /// lines of LIST, with their `ref`.
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
    /// A line that is not part of a response: a live event, PRESENCE,
    /// NOTICE, READ, TYPING, DROP, BYE or a line with an unknown verb.
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
///   the greeting.
/// - [`guest`](Self::guest), [`auth`](Self::auth) and
///   [`register`](Self::register) sign in.
/// - [`request`](Self::request) sends any command and returns its
///   [`Response`]. Requests may be made concurrently; each gets a fresh
///   `ref`, and responses are matched in order (3.6).
/// - Every other line arrives on the queue from
///   [`take_incoming`](Self::take_incoming), in order: live events,
///   PRESENCE, NOTICE, READ, TYPING, DROP, BYE and lines with unknown
///   verbs. Server PINGs are answered inside the session (11).
/// - [`send`](Self::send) sends a command whose response arrives on that
///   same queue, as an [`Incoming::Reply`] at the point its final line
///   arrived. Use it when the order of responses relative to live lines
///   matters, as it does for the sync engine (3.6, "Consistent with live
///   events").
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
    uid: Option<Uid>,
    nonce_used: bool,
}

struct Pending {
    ref_: Ref,
    lines: Vec<ServerMessage>,
    signs_in: bool,
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
            None => tls::platform_ca_verifier(),
        };
        let (stream, verified) = tls::connect(addr, &trust, ca, options.connect_to).await?;
        let (mut rd, wr) = tokio::io::split(stream);
        let mut decoder = LineDecoder::new(MAX_SERVER_LINE);
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
                uid: None,
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

    /// The uid this connection signed in as, once a GUEST, AUTH or
    /// REGISTER has succeeded.
    pub fn uid(&self) -> Option<Uid> {
        self.shared.state.lock().expect("poisoned").uid.clone()
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
    /// [`Error::NoResponse`] for PONG, [`Error::NonceUsed`] for a second
    /// AUTH or REGISTER (4.5), and [`Error::Closed`] if the connection
    /// closes first. A server `ERR` is not an error here: it is in the
    /// [`Response`].
    ///
    /// When it returns, every incoming line that came before the final
    /// response, such as the live event a MSG caused, is already queued.
    pub async fn request(&self, command: Command) -> Result<Response, Error> {
        let (tx, rx) = oneshot::channel();
        self.enqueue(command, ReplyTo::Waiter(tx))?;
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
        self.enqueue(command, ReplyTo::Queue)
    }

    /// Writes a command with a fresh `ref` and records where its response
    /// goes.
    fn enqueue(&self, command: Command, reply: ReplyTo) -> Result<Ref, Error> {
        if !command.gets_response() {
            return Err(Error::NoResponse);
        }
        let mut st = self.shared.state.lock().expect("poisoned");
        if let Some(reason) = &st.closed {
            return Err(Error::Closed(reason.clone()));
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
        let signs_in = command.signs_in();
        let request = Request {
            ref_: Some(ref_.clone()),
            command,
        };
        let line = request
            .try_to_line()
            .map_err(Error::InvalidCommand)?
            .to_string();
        check_line_len(&line, MAX_CLIENT_LINE).map_err(Error::InvalidCommand)?;
        if self.out.send(Outgoing::Line(line)).is_err() {
            return Err(Error::Closed(CloseReason::Local));
        }
        st.next_ref += 1;
        st.nonce_used |= uses_nonce;
        st.pending.push_back(Pending {
            ref_: ref_.clone(),
            lines: Vec::new(),
            signs_in,
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

    /// Signs in as the guest `~<name>` (4.2), starting a new session.
    pub async fn guest(&self, name: &Name) -> Result<Uid, Error> {
        Ok(self.guest_session(name, None).await?.0)
    }

    /// Signs in as the guest `~<name>` (4.2). With `token`, the server
    /// resumes that guest's session if the token is its current one, and
    /// otherwise ignores it. Returns the uid and the session's new token,
    /// which the next resume needs. The token is a secret.
    pub async fn guest_session(
        &self,
        name: &Name,
        token: Option<&Id>,
    ) -> Result<(Uid, Option<Id>), Error> {
        let ok = self
            .request_ok(Command::Guest {
                name: name.clone(),
                token: token.cloned(),
            })
            .await?;
        let token = ok.token().ok().flatten();
        Ok((signed_in_uid(&ok, Uid::guest(name)), token))
    }

    /// Signs in as `identity` with a device key listed in its key file
    /// (4.5).
    ///
    /// The signed bytes use the hostname this client sent in SNI, never
    /// the greeting's host, and the greeting's nonce. Fails with
    /// [`Error::NoSni`] over an IP address (2.1).
    pub async fn auth(&self, identity: &Identity, key: &SecretKey) -> Result<Uid, Error> {
        let sni = self.info.sni.as_deref().ok_or(Error::NoSni)?;
        let command = keys::auth_command(sni, &self.info.greeting.nonce, identity, key);
        let ok = self.request_ok(command).await?;
        Ok(signed_in_uid(&ok, identity.to_uid()))
    }

    /// Creates the identity `<name>@<identity domain>` with `key` as its
    /// first key, and signs in as it (4.6).
    ///
    /// The identity domain comes from INFO (8.5) first; a server without
    /// registration gives [`Error::NoRegistration`]. Signs with the SNI
    /// hostname, as [`auth`](Self::auth) does.
    pub async fn register(&self, name: &Name, key: &SecretKey) -> Result<Uid, Error> {
        let sni = self.info.sni.clone().ok_or(Error::NoSni)?;
        let info = self.request_ok(Command::Info { room: None }).await?;
        let domain = match info.register() {
            Ok(Some(Register::Domain(domain))) => domain,
            _ => return Err(Error::NoRegistration),
        };
        let command = keys::register_command(&sni, &self.info.greeting.nonce, name, &domain, key);
        let ok = self.request_ok(command).await?;
        let expected = risala_proto::names::Identity::new(name, &domain).to_uid();
        Ok(signed_in_uid(&ok, expected))
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

/// The uid an `OK` to a sign-in names, or the expected one if it names
/// none that parses.
fn signed_in_uid(ok: &OkResponse, expected: Uid) -> Uid {
    match ok.uid() {
        Ok(Some(uid)) => uid,
        _ => expected,
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
            signs_in: false,
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
        if pending.signs_in
            && let End::Ok(ok) = &end
            && let Ok(Some(uid)) = ok.uid()
        {
            st.uid = Some(uid);
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
