//! The interface between the network layer ([`crate::net`]) and the core
//! ([`crate::core`]).
//!
//! The network layer accepts TCP, runs TLS, splits the byte stream into
//! lines and parses them. Each line that parses as a
//! [`Request`] goes to the [`Handler`], one at a time and in arrival order
//! (3.6). Lines that do not parse never reach the handler: the network
//! layer answers them with `ERR` itself (2.3), using
//! [`ParseError::code`](risala_proto::error::ParseError::code).
//!
//! Everything the server sends to a connection goes through its
//! [`ConnHandle`]: the greeting, responses, live events and closing. One
//! queue per connection keeps the order the spec needs: the events a
//! command causes reach its sender before the command's final response
//! (3.6).

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

use risala_proto::command::Request;
use risala_proto::connection::ConnectionKind;
use risala_proto::error::ErrorCode;
use risala_proto::frame::LineLimits;
use risala_proto::server::{ErrResponse, ServerMessage};
use risala_proto::time::Timestamp;
use tokio::sync::{Notify, mpsc};

/// Identifies one connection for as long as the server runs. Never reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnId(pub u64);

/// What the network layer knows about a connection when it opens.
#[derive(Debug, Clone)]
pub struct ConnInfo {
    /// The client's address and port, for ADMIN WHO (10.3) and address bans
    /// (10.2).
    pub peer: SocketAddr,
    /// The SNI hostname the client sent, in lower case, or `None` if it sent
    /// none (2.1, 4.1).
    pub sni: Option<String>,
    /// Whether `sni` is a name on one of the server's certificates,
    /// wildcard names included, as they were when the handshake finished.
    /// The hub accepts sign-ins only on connections whose SNI is its
    /// configured hostname or such a name (4.5).
    pub sni_certified: bool,
    /// When the TLS handshake finished.
    pub since: Timestamp,
}

/// A line to send, encoded once and shared by every connection it goes to,
/// so that fan-out to many connections costs one copy of the line, not one
/// each.
///
/// It dereferences to its [`ServerMessage`].
#[derive(Debug, Clone)]
pub struct OutLine(Arc<Encoded>);

#[derive(Debug)]
struct Encoded {
    msg: ServerMessage,
    /// What is written: the line and its LF.
    wire: Box<[u8]>,
}

impl OutLine {
    /// Encodes `msg` for the wire.
    ///
    /// A line may be as long as 2.3 allows a server line: long if its verb
    /// is one of those that carry MLS data, such as KEYPKG and WELCOME.
    ///
    /// A message that cannot be written, or is too long for a server line
    /// (2.3), is a bug in the core. It is logged, and nothing is written
    /// for it; if it is a final response, `ERR internal` is written in its
    /// place, so the client still gets one final response per command
    /// (3.6).
    pub fn new(msg: ServerMessage) -> OutLine {
        let problem = match msg.try_to_line() {
            Ok(line) => {
                let text = line.to_string();
                match LineLimits::SERVER.check(&text) {
                    Ok(()) => {
                        let mut wire = text.into_bytes();
                        wire.push(b'\n');
                        return OutLine(Arc::new(Encoded {
                            msg,
                            wire: wire.into(),
                        }));
                    }
                    Err(e) => e,
                }
            }
            Err(e) => e,
        };
        tracing::error!(verb = msg.line.verb(), error = %problem, "dropping a line that cannot be sent");
        let mut wire = Vec::new();
        if msg.line.is_final() {
            let err = ServerMessage::new(ErrResponse::new(ErrorCode::Internal))
                .with_ref_opt(msg.ref_.clone());
            wire.extend_from_slice(err.to_line().to_string().as_bytes());
            wire.push(b'\n');
        }
        OutLine(Arc::new(Encoded {
            msg,
            wire: wire.into(),
        }))
    }

    /// The message.
    pub fn message(&self) -> &ServerMessage {
        &self.0.msg
    }

    /// The bytes to write: the line and its LF.
    pub fn wire(&self) -> &[u8] {
        &self.0.wire
    }

    /// The number of bytes [`wire`](Self::wire) has, which is what the line
    /// counts against its queue's byte budget.
    pub fn size(&self) -> usize {
        self.0.wire.len()
    }

    /// Whether `self` and `other` share one encoded line.
    pub fn ptr_eq(&self, other: &OutLine) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl std::ops::Deref for OutLine {
    type Target = ServerMessage;

    fn deref(&self) -> &ServerMessage {
        &self.0.msg
    }
}

impl From<ServerMessage> for OutLine {
    fn from(msg: ServerMessage) -> OutLine {
        OutLine::new(msg)
    }
}

/// One item in a connection's outgoing queue.
#[derive(Debug, Clone)]
pub enum Outgoing {
    /// A line to send.
    Line(OutLine),
    /// Send everything queued before this, then close the connection.
    /// With `bye: Some(text)`, a `BYE` line with that text is sent first
    /// (11). After QUIT's `OK`, the core uses `bye: None`.
    Close {
        /// The text of the `BYE` line, if one is sent.
        bye: Option<String>,
    },
}

impl Outgoing {
    /// What the item counts against its queue's byte budget.
    fn size(&self) -> usize {
        match self {
            Outgoing::Line(line) => line.size(),
            Outgoing::Close { .. } => 0,
        }
    }
}

/// The sending half of a connection, held by the core.
///
/// The queue is bounded twice: by a number of lines and by their bytes on
/// the wire. A client that reads too slowly fills it, and then the
/// connection is killed at once rather than letting the server's memory
/// grow (PLAN.md 3.2). Sending never blocks, so one slow client cannot hold
/// up fan-out to everyone else.
///
/// The network layer waits for room in the queue before it hands the
/// connection's next command to the core
/// ([`wait_for_room`](Self::wait_for_room)), so a client's own commands
/// fill it only as fast as the client reads.
#[derive(Debug, Clone)]
pub struct ConnHandle {
    id: ConnId,
    tx: mpsc::Sender<Outgoing>,
    state: Arc<QueueState>,
}

/// What both halves of a queue share.
#[derive(Debug)]
struct QueueState {
    killed: AtomicBool,
    /// The connection's kind (4.1), as [`kind_code`], which decides the
    /// limits the network layer applies to its lines (2.3).
    kind: AtomicU8,
    /// Wakes the network layer when the connection is killed.
    kill: Notify,
    /// The bytes of the lines in the queue.
    bytes: AtomicUsize,
    /// The most bytes the queue may hold.
    max_bytes: usize,
    /// Wakes [`ConnHandle::wait_for_room`] when lines leave the queue.
    drained: Notify,
}

/// A connection kind as stored in [`QueueState::kind`].
const fn kind_code(kind: ConnectionKind) -> u8 {
    match kind {
        ConnectionKind::New => 0,
        ConnectionKind::Anonymous => 1,
        ConnectionKind::Guest => 2,
        ConnectionKind::SignedIn => 3,
    }
}

/// The receiving half of a connection, held by the network layer.
#[derive(Debug)]
pub struct ConnReceiver {
    rx: mpsc::Receiver<Outgoing>,
    state: Arc<QueueState>,
}

/// Makes the two halves of a connection's queue, holding at most `lines`
/// items, and lines of at most `bytes` bytes in all.
pub fn conn_channel(id: ConnId, lines: usize, bytes: usize) -> (ConnHandle, ConnReceiver) {
    let (tx, rx) = mpsc::channel(lines);
    let state = Arc::new(QueueState {
        killed: AtomicBool::new(false),
        kind: AtomicU8::new(kind_code(ConnectionKind::New)),
        kill: Notify::new(),
        bytes: AtomicUsize::new(0),
        max_bytes: bytes,
        drained: Notify::new(),
    });
    (
        ConnHandle {
            id,
            tx,
            state: state.clone(),
        },
        ConnReceiver { rx, state },
    )
}

impl ConnHandle {
    /// This connection's id.
    pub fn id(&self) -> ConnId {
        self.id
    }

    /// Queues a line. Returns `false`, and kills the connection, if the
    /// queue is full, in lines or in bytes. Returns `false` if the
    /// connection is already gone.
    pub fn send(&self, msg: ServerMessage) -> bool {
        self.send_line(OutLine::new(msg))
    }

    /// Queues a line that is already encoded, as [`send`](Self::send) does.
    /// Fan-out encodes a line once and queues it for every connection.
    pub fn send_line(&self, line: OutLine) -> bool {
        self.push(Outgoing::Line(line))
    }

    /// Queues a close, optionally with a `BYE` line (11).
    pub fn close(&self, bye: Option<String>) {
        self.push(Outgoing::Close { bye });
    }

    /// Drops the connection straight away, without sending what is queued.
    pub fn kill(&self) {
        self.state.killed.store(true, Ordering::SeqCst);
        self.state.kill.notify_waiters();
        self.state.kill.notify_one();
        self.state.drained.notify_waiters();
    }

    /// Records the connection's kind (4.1). From the next line on, the
    /// network layer applies that kind's line limits
    /// ([`ConnectionKind::client_limits`], 2.3): the normal limit, and
    /// 64 KiB for REGISTER, KEYS and PAIR, while it is new; long lines for
    /// the verbs that carry MLS data or records once it is anonymous, a
    /// guest or signed in.
    pub fn set_kind(&self, kind: ConnectionKind) {
        self.state.kind.store(kind_code(kind), Ordering::SeqCst);
    }

    /// The kind [`set_kind`](Self::set_kind) last recorded:
    /// [`ConnectionKind::New`] until then.
    pub fn kind(&self) -> ConnectionKind {
        match self.state.kind.load(Ordering::SeqCst) {
            1 => ConnectionKind::Anonymous,
            2 => ConnectionKind::Guest,
            3 => ConnectionKind::SignedIn,
            _ => ConnectionKind::New,
        }
    }

    /// Whether the connection has been killed or its receiver dropped.
    pub fn is_closed(&self) -> bool {
        self.state.killed.load(Ordering::SeqCst) || self.tx.is_closed()
    }

    /// Whether the queue is empty, or has room for `lines` more lines of
    /// `bytes` bytes in all.
    pub fn has_room(&self, lines: usize, bytes: usize) -> bool {
        let free_bytes = self
            .state
            .max_bytes
            .saturating_sub(self.state.bytes.load(Ordering::SeqCst));
        let free_lines = self.tx.capacity();
        free_lines == self.tx.max_capacity() || (free_lines >= lines && free_bytes >= bytes)
    }

    /// Waits until [`has_room`](Self::has_room), or until the connection
    /// is closed.
    pub async fn wait_for_room(&self, lines: usize, bytes: usize) {
        loop {
            let drained = self.state.drained.notified();
            let mut drained = std::pin::pin!(drained);
            // Registered before checking, so a wake-up in between is not
            // missed.
            drained.as_mut().enable();
            if self.is_closed() || self.has_room(lines, bytes) {
                return;
            }
            drained.await;
        }
    }

    fn push(&self, item: Outgoing) -> bool {
        if self.is_closed() {
            return false;
        }
        let size = item.size();
        let before = self.state.bytes.fetch_add(size, Ordering::SeqCst);
        if before.saturating_add(size) > self.state.max_bytes {
            self.state.bytes.fetch_sub(size, Ordering::SeqCst);
            self.kill();
            return false;
        }
        match self.tx.try_send(item) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.state.bytes.fetch_sub(size, Ordering::SeqCst);
                self.kill();
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.state.bytes.fetch_sub(size, Ordering::SeqCst);
                false
            }
        }
    }
}

impl ConnReceiver {
    /// The next item, waiting for one. `None` once every [`ConnHandle`] is
    /// gone and the queue is empty. Cancel safe.
    pub async fn recv(&mut self) -> Option<Outgoing> {
        let item = self.rx.recv().await;
        self.taken(item)
    }

    /// The next item, if one is queued.
    pub fn try_recv(&mut self) -> Option<Outgoing> {
        let item = self.rx.try_recv().ok();
        self.taken(item)
    }

    fn taken(&self, item: Option<Outgoing>) -> Option<Outgoing> {
        if let Some(item) = &item {
            self.state.bytes.fetch_sub(item.size(), Ordering::SeqCst);
            self.state.drained.notify_waiters();
        }
        item
    }

    /// Resolves once the connection has been killed. The network layer
    /// selects on this next to its reads and writes, and drops the
    /// connection when it fires. The future does not borrow the receiver.
    pub fn killed(&self) -> impl Future<Output = ()> + Send + 'static {
        let state = self.state.clone();
        async move {
            loop {
                let notified = state.kill.notified();
                if state.killed.load(Ordering::SeqCst) {
                    return;
                }
                notified.await;
            }
        }
    }

    /// Whether the connection has been killed.
    pub fn is_killed(&self) -> bool {
        self.state.killed.load(Ordering::SeqCst)
    }
}

impl Drop for ConnReceiver {
    fn drop(&mut self) {
        // Nothing will drain the queue any more.
        self.state.drained.notify_waiters();
    }
}

/// The core, as the network layer sees it.
///
/// The network layer calls [`open`](Handler::open) once the TLS handshake
/// is done, then [`command`](Handler::command) for each parsed line,
/// awaiting each call before it reads the next command, and waiting before
/// each until the connection's queue has room for a whole response
/// ([`Limits::command_room`](crate::config::Limits::command_room)), then
/// [`closed`](Handler::closed) exactly once when the connection is gone for
/// any reason (EOF, error, timeout, kill, or after a `Close`).
pub trait Handler: Send + Sync + 'static {
    /// A connection has opened. The handler sends the greeting (4.1)
    /// through `conn`, and keeps `conn` to send to it later.
    fn open(&self, info: ConnInfo, conn: ConnHandle);

    /// Handles one command from `conn`. Before it returns, it has queued
    /// the command's final response (`OK` or `ERR`), unless the command is
    /// PONG, which gets none (3.6).
    fn command(&self, conn: ConnId, req: Request) -> impl Future<Output = ()> + Send;

    /// The connection is gone. A guest session starts waiting to be
    /// resumed here (4.2).
    fn closed(&self, conn: ConnId) -> impl Future<Output = ()> + Send;

    /// The server's time, as it stamps posts (3.2). A PING carries it in
    /// `t` (11), so it must come from the same clock as posts' `t`: a post
    /// accepted after a PING is never stamped earlier than it.
    fn now(&self) -> Timestamp;
}

#[cfg(test)]
mod tests {
    use risala_proto::server::{OkResponse, ServerLine};

    use risala_proto::frame::{MAX_LONG_CLIENT_LINE, MAX_LONG_SERVER_LINE, MAX_SERVER_LINE};

    use super::*;

    fn ok(n: usize) -> ServerMessage {
        ServerMessage::new(OkResponse::new().with("n", n))
    }

    #[test]
    fn bad_final_responses_become_internal_errors() {
        let long = ServerMessage::new(
            ErrResponse::new(ErrorCode::NotFound).with_message("x".repeat(MAX_SERVER_LINE)),
        )
        .with_ref("7".parse().unwrap());
        assert_eq!(OutLine::new(long).wire(), b"@ref=7 ERR internal\n");

        // A line that is not final is just dropped.
        let notice = ServerMessage::new(ServerLine::Bye {
            message: "x".repeat(MAX_SERVER_LINE),
        });
        assert!(OutLine::new(notice).wire().is_empty());
    }

    /// Lines that carry MLS data may be long (2.3); others may not.
    #[test]
    fn mls_lines_may_be_long() {
        use risala_proto::mls::KeyPackage;

        let uid: risala_proto::names::Uid = "alice@example.org".parse().unwrap();
        let line = |bytes: usize| {
            ServerMessage::new(ServerLine::KeyPkg {
                uid: uid.clone(),
                key_package: KeyPackage::from_bytes(&vec![7; bytes]).unwrap(),
                secret: risala_proto::mls::PutSecret::from_bytes([1; 32]),
            })
        };
        let long = OutLine::new(line(3 * MAX_SERVER_LINE));
        assert!(long.size() > MAX_SERVER_LINE);
        assert!(long.wire().starts_with(b"KEYPKG alice@example.org "));
        // The longest KeyPackage a client may send (2.3).
        let longest = OutLine::new(line(MAX_LONG_CLIENT_LINE / 4 * 3 - 3));
        assert!(longest.size() > MAX_LONG_CLIENT_LINE);
        assert!(longest.size() < MAX_LONG_SERVER_LINE);
        // Other lines keep the normal limit.
        let notice = ServerMessage::new(ServerLine::Notice {
            message: "x".repeat(2 * MAX_SERVER_LINE),
        });
        assert!(OutLine::new(notice).wire().is_empty());
    }

    #[test]
    fn kinds_are_recorded() {
        let (handle, _rx) = conn_channel(ConnId(1), 4, 1 << 20);
        assert_eq!(handle.kind(), ConnectionKind::New);
        for kind in ConnectionKind::ALL {
            handle.set_kind(kind);
            assert_eq!(handle.kind(), kind);
        }
    }

    #[test]
    fn lines_count_their_bytes() {
        let line = OutLine::new(ok(12));
        assert_eq!(line.wire(), b"OK n=12\n");
        assert_eq!(line.size(), 8);
        let shared = line.clone();
        assert!(shared.ptr_eq(&line));
        assert!(!OutLine::new(ok(12)).ptr_eq(&line));
    }

    #[test]
    fn a_queue_over_its_byte_budget_is_killed() {
        // "OK n=1\n" is 7 bytes: three fit in 21, a fourth does not.
        let (handle, mut rx) = conn_channel(ConnId(1), 100, 21);
        for n in 1..=3 {
            assert!(handle.send(ok(n)));
        }
        assert!(!handle.has_room(1, 7));
        // Lines taken out give their bytes back.
        assert!(rx.try_recv().is_some());
        assert!(handle.has_room(1, 7));
        assert!(handle.send(ok(4)));
        assert!(!rx.is_killed());
        assert!(!handle.send(ok(5)));
        assert!(rx.is_killed());
        assert!(handle.is_closed());
    }

    #[test]
    fn a_queue_over_its_line_count_is_killed() {
        let (handle, rx) = conn_channel(ConnId(1), 2, 1 << 20);
        assert!(handle.send(ok(1)));
        assert!(handle.send(ok(2)));
        assert!(!handle.send(ok(3)));
        assert!(rx.is_killed());
    }

    #[tokio::test]
    async fn waiting_for_room() {
        let (handle, mut rx) = conn_channel(ConnId(1), 4, 1 << 20);
        // An empty queue always has room, even for more than it holds.
        assert!(handle.has_room(10, 1 << 30));
        for n in 1..=3 {
            assert!(handle.send(ok(n)));
        }
        assert!(handle.has_room(1, 7));
        assert!(!handle.has_room(2, 7));
        let waiter = tokio::spawn({
            let handle = handle.clone();
            async move { handle.wait_for_room(3, 7).await }
        });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        rx.recv().await.unwrap();
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        rx.recv().await.unwrap();
        waiter.await.unwrap();

        // A killed connection stops the wait too.
        assert!(handle.send(ok(4)));
        assert!(handle.send(ok(5)));
        let waiter = tokio::spawn({
            let handle = handle.clone();
            async move { handle.wait_for_room(4, 7).await }
        });
        tokio::task::yield_now().await;
        handle.kill();
        waiter.await.unwrap();
    }
}
