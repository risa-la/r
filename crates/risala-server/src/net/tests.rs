//! Tests of the network layer against a stub [`Handler`].
//!
//! The connection tests run over an in-memory pipe with tokio's paused
//! clock, so timers are exact. The TLS tests run a real server on
//! 127.0.0.1, port 0, in real time, with no timing assumptions beyond
//! generous timeouts.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use risala_proto::auth::Nonce;
use risala_proto::command::{Command, Request};
use risala_proto::fingerprint::Fingerprint;
use risala_proto::server::{Greeting, OkResponse, ServerLine, ServerMessage};
use risala_proto::time::Timestamp;
use tokio::io::{
    AsyncBufReadExt as _, AsyncWriteExt as _, BufReader, DuplexStream, ReadHalf, WriteHalf,
};
use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use super::testing::{ClientOptions, TestClient};
use super::*;
use crate::config::CertPair;

// ---------------------------------------------------------------------
// The stub handler

/// Greets, answers every command with `OK verb=<verb>`, closes after QUIT
/// and records what happens.
#[derive(Debug, Default)]
struct Stub {
    conns: Mutex<HashMap<ConnId, ConnHandle>>,
    opened: Mutex<Vec<ConnInfo>>,
    closed: Mutex<Vec<ConnId>>,
    commands: Mutex<Vec<Request>>,
    running: AtomicUsize,
    overlapped: AtomicUsize,
    /// How long each command takes.
    delay: Duration,
    /// Lines of 1 KiB each command queues before its OK.
    lines_per_command: usize,
}

impl Stub {
    fn new() -> Arc<Stub> {
        Arc::new(Stub::default())
    }

    fn handle(&self, id: ConnId) -> ConnHandle {
        self.conns.lock().unwrap()[&id].clone()
    }

    fn closed(&self) -> Vec<ConnId> {
        self.closed.lock().unwrap().clone()
    }

    fn opened(&self) -> Vec<ConnInfo> {
        self.opened.lock().unwrap().clone()
    }
}

impl Handler for Stub {
    fn open(&self, info: ConnInfo, conn: ConnHandle) {
        let host = info.sni.clone().unwrap_or_else(|| "localhost".into());
        conn.send(ServerMessage::new(Greeting {
            version: 1,
            host: host.parse().unwrap(),
            nonce: Nonce::from_bytes(&[0xab; 16]).unwrap(),
            message: "hello".into(),
        }));
        self.opened.lock().unwrap().push(info);
        self.conns.lock().unwrap().insert(conn.id(), conn);
    }

    async fn command(&self, conn: ConnId, req: Request) {
        if self.running.fetch_add(1, Ordering::SeqCst) > 0 {
            self.overlapped.fetch_add(1, Ordering::SeqCst);
        }
        if self.delay.is_zero() {
            tokio::task::yield_now().await;
        } else {
            tokio::time::sleep(self.delay).await;
        }
        let handle = self.handle(conn);
        if matches!(req.command, Command::Guest { .. }) {
            handle.set_signed_in();
        }
        for n in 0..self.lines_per_command {
            let message = format!("{n:04} {}", "x".repeat(1019));
            handle.send(ServerMessage::new(ServerLine::Notice { message }));
        }
        match &req.command {
            Command::Pong { .. } => {}
            command => {
                let ok = OkResponse::new().with("verb", command.verb().to_ascii_lowercase());
                handle.send(ServerMessage::new(ok).with_ref_opt(req.ref_.clone()));
                if matches!(command, Command::Quit { .. }) {
                    handle.close(None);
                }
            }
        }
        self.commands.lock().unwrap().push(req);
        self.running.fetch_sub(1, Ordering::SeqCst);
    }

    async fn closed(&self, conn: ConnId) {
        self.closed.lock().unwrap().push(conn);
        self.conns.lock().unwrap().remove(&conn);
    }
}

const GREETING: &str = "RISALA 1 localhost abababababababababababababababab hello";

// ---------------------------------------------------------------------
// Connections over an in-memory pipe, in paused time

const ID: ConnId = ConnId(1);

const TIMERS: Timers = Timers {
    idle_ping: Duration::from_secs(120),
    ping_timeout: Duration::from_secs(60),
};

/// Room for a stub's response: the OK, and a line for a PING.
const ROOM: CommandRoom = CommandRoom {
    lines: 2,
    bytes: 2 * risala_proto::frame::MAX_SERVER_LINE,
};

/// One connection task, served over a pipe.
struct Pipe {
    rd: BufReader<ReadHalf<DuplexStream>>,
    wr: WriteHalf<DuplexStream>,
    stub: Arc<Stub>,
    task: JoinHandle<()>,
    _stop: watch::Sender<bool>,
}

impl Pipe {
    fn new(stub: Arc<Stub>, out_queue: usize, pipe_bytes: usize) -> Pipe {
        Pipe::with_room(stub, out_queue, pipe_bytes, ROOM)
    }

    fn with_room(stub: Arc<Stub>, out_queue: usize, pipe_bytes: usize, room: CommandRoom) -> Pipe {
        let (client, server) = tokio::io::duplex(pipe_bytes);
        let (handle, receiver) = conn_channel(ID, out_queue, usize::MAX);
        let (stop_tx, stop_rx) = watch::channel(false);
        let info = ConnInfo {
            peer: "127.0.0.1:50000".parse().unwrap(),
            sni: None,
            sni_certified: false,
            since: Timestamp::now(),
        };
        let task = tokio::spawn(conn::serve(
            server,
            info,
            handle,
            receiver,
            stub.clone(),
            TIMERS,
            room,
            stop_rx,
        ));
        let (rd, wr) = tokio::io::split(client);
        Pipe {
            rd: BufReader::new(rd),
            wr,
            stub,
            task,
            _stop: stop_tx,
        }
    }

    async fn greeted(stub: Arc<Stub>) -> Pipe {
        let mut pipe = Pipe::new(stub, 64, 64 * 1024);
        assert_eq!(pipe.line().await.as_deref(), Some(GREETING));
        pipe
    }

    async fn send(&mut self, bytes: &[u8]) {
        self.wr.write_all(bytes).await.unwrap();
    }

    /// The next line, or `None` at the end of the stream.
    async fn line(&mut self) -> Option<String> {
        let mut line = String::new();
        let n = self.rd.read_line(&mut line).await.unwrap();
        if n == 0 {
            return None;
        }
        assert_eq!(line.pop(), Some('\n'));
        Some(line)
    }

    async fn expect(&mut self, want: &str) {
        assert_eq!(self.line().await.as_deref(), Some(want));
    }

    async fn expect_prefix(&mut self, prefix: &str) -> String {
        let line = self.line().await.expect("a line");
        assert!(
            line.starts_with(prefix),
            "{line:?} does not start with {prefix:?}"
        );
        line
    }

    /// Waits for the server to close, and checks `closed` ran once.
    async fn expect_end(mut self) {
        assert_eq!(self.line().await, None);
        self.task.await.unwrap();
        assert_eq!(self.stub.closed(), vec![ID]);
    }
}

#[tokio::test(start_paused = true)]
async fn commands_get_answers_in_order() {
    let mut pipe = Pipe::greeted(Stub::new()).await;
    pipe.send(b"PING\n@ref=a1 PING x\n@ref=a2 JOIN #general\n")
        .await;
    pipe.expect("OK verb=ping").await;
    pipe.expect("@ref=a1 OK verb=ping").await;
    pipe.expect("@ref=a2 OK verb=join").await;
}

#[tokio::test(start_paused = true)]
async fn commands_run_one_at_a_time() {
    let stub = Arc::new(Stub {
        delay: Duration::from_secs(1),
        ..Stub::default()
    });
    let mut pipe = Pipe::greeted(stub.clone()).await;
    let start = Instant::now();
    pipe.send(b"@ref=1 PING\n@ref=2 PING\n@ref=3 PING\n").await;
    for r in 1..=3 {
        pipe.expect(&format!("@ref={r} OK verb=ping")).await;
    }
    assert_eq!(stub.overlapped.load(Ordering::SeqCst), 0);
    assert!(start.elapsed() >= Duration::from_secs(3));
}

#[tokio::test(start_paused = true)]
async fn bad_lines_get_errors_with_their_ref() {
    let mut pipe = Pipe::greeted(Stub::new()).await;

    // Too long: the rest is discarded up to the LF, and the next line
    // works (2.3).
    let mut long = b"@ref=t1 MSG #general ".to_vec();
    long.extend(std::iter::repeat_n(
        b'x',
        risala_proto::frame::MAX_CLIENT_LINE,
    ));
    long.extend(b"\n@ref=t2 PING\n");
    pipe.send(&long).await;
    pipe.expect("@ref=t1 ERR too-long too long").await;
    pipe.expect("@ref=t2 OK verb=ping").await;

    // Exactly at the limit is fine: 8191 bytes and the LF.
    let mut fits = b"@ref=t3 PING ".to_vec();
    fits.resize(8191, b'y');
    fits.push(b'\n');
    pipe.send(&fits).await;
    pipe.expect("@ref=t3 OK verb=ping").await;

    // Not UTF-8, and control characters (2.3).
    pipe.send(b"@ref=u1 MSG #general \xff\xfe\n").await;
    pipe.expect_prefix("@ref=u1 ERR bad-syntax ").await;
    pipe.send(b"@ref=c1 MSG #general a\x01b\n").await;
    pipe.expect_prefix("@ref=c1 ERR bad-syntax ").await;
    pipe.send(b"@ref=c2 MSG #general a\rb\n").await;
    pipe.expect_prefix("@ref=c2 ERR bad-syntax ").await;
    pipe.send("@ref=c3 MSG #general a\u{85}b\n".as_bytes())
        .await;
    pipe.expect_prefix("@ref=c3 ERR bad-syntax ").await;

    // CRLF line endings are fine.
    pipe.send(b"@ref=r1 PING\r\n").await;
    pipe.expect("@ref=r1 OK verb=ping").await;

    // Unknown verbs, bad parameters, and lines that do not parse at all
    // (3.6, 3.7).
    pipe.send(b"@ref=v1 FROBNICATE x\n").await;
    pipe.expect("@ref=v1 ERR unknown-command unknown command FROBNICATE")
        .await;
    pipe.send(b"@ref=p1 JOIN\n").await;
    pipe.expect_prefix("@ref=p1 ERR bad-syntax ").await;
    pipe.send(b"@ref=p2;=x PING\n").await;
    pipe.expect_prefix("@ref=p2 ERR bad-syntax ").await;
    pipe.send(b"@ref=p3 \n").await;
    pipe.expect_prefix("@ref=p3 ERR bad-syntax ").await;

    // Without a readable ref, the ERR has none.
    pipe.send(b"FROBNICATE\n").await;
    pipe.expect("ERR unknown-command unknown command FROBNICATE")
        .await;
    pipe.send(b"@ref= FROBNICATE\n").await;
    pipe.expect_prefix("ERR bad-syntax ").await;
    pipe.send(b"MSG #general \xff\n").await;
    pipe.expect_prefix("ERR bad-syntax ").await;

    // None of them reached the handler.
    let refs: Vec<String> = pipe
        .stub
        .commands
        .lock()
        .unwrap()
        .iter()
        .map(|r| r.ref_.as_ref().unwrap().to_string())
        .collect();
    assert_eq!(refs, ["t2", "t3", "r1"]);
}

/// Lines that carry MLS data may be long once the connection has signed
/// in, and not before (2.3).
#[tokio::test(start_paused = true)]
async fn long_lines_once_signed_in() {
    let mut pipe = Pipe::greeted(Stub::new()).await;
    let data = "A".repeat(2 * risala_proto::frame::MAX_CLIENT_LINE);
    let keypkg = format!("@ref=k KEYPKG ADD {data}\n");
    pipe.send(keypkg.as_bytes()).await;
    pipe.expect("@ref=k ERR too-long too long").await;
    pipe.send(b"GUEST sam\n").await;
    pipe.expect("OK verb=guest").await;
    pipe.send(keypkg.as_bytes()).await;
    pipe.expect("@ref=k OK verb=keypkg").await;
    // Other verbs keep the normal limit.
    pipe.send(format!("@ref=m MSG #general {data}\n").as_bytes())
        .await;
    pipe.expect("@ref=m ERR too-long too long").await;
}

#[tokio::test(start_paused = true)]
async fn ping_then_bye_after_silence() {
    let mut pipe = Pipe::greeted(Stub::new()).await;
    let start = Instant::now();
    let ping = pipe.expect_prefix("PING ").await;
    assert_eq!(start.elapsed(), TIMERS.idle_ping);
    assert_eq!(ping.len(), "PING ".len() + 16);
    pipe.expect("BYE ping timeout").await;
    assert_eq!(start.elapsed(), TIMERS.idle_ping + TIMERS.ping_timeout);
    pipe.expect_end().await;
}

#[tokio::test(start_paused = true)]
async fn any_line_resets_the_timers() {
    let mut pipe = Pipe::greeted(Stub::new()).await;
    // Empty lines, with and without CR, keep the connection quiet (2.3)
    // but alive (11).
    tokio::time::sleep(Duration::from_secs(100)).await;
    pipe.send(b"\n").await;
    tokio::time::sleep(Duration::from_secs(100)).await;
    pipe.send(b"\r\n").await;
    tokio::time::sleep(Duration::from_secs(100)).await;
    // So far no PING: this OK is the next line.
    pipe.send(b"PING\n").await;
    pipe.expect("OK verb=ping").await;
    let last = Instant::now();

    // The PING comes 120 seconds after the last line. Answering it, even
    // late, starts both timers again.
    let ping = pipe.expect_prefix("PING ").await;
    assert_eq!(last.elapsed(), TIMERS.idle_ping);
    tokio::time::sleep(Duration::from_secs(59)).await;
    pipe.send(format!("PONG {}\n", &ping[5..]).as_bytes()).await;
    let pong = Instant::now();
    pipe.expect_prefix("PING ").await;
    assert_eq!(pong.elapsed(), TIMERS.idle_ping);

    // A bad line counts too.
    tokio::time::sleep(Duration::from_secs(59)).await;
    pipe.send(b"\x01\n").await;
    pipe.expect_prefix("ERR bad-syntax").await;
    let bad = Instant::now();
    pipe.expect_prefix("PING ").await;
    assert_eq!(bad.elapsed(), TIMERS.idle_ping);
    pipe.expect("BYE ping timeout").await;
    let stub = pipe.stub.clone();
    pipe.expect_end().await;
    // The PONG reached the handler, and got no response.
    let verbs: Vec<&str> = Pipe::commands(&stub)
        .iter()
        .map(|r| r.command.verb())
        .collect();
    assert_eq!(verbs, ["PING", "PONG"]);
}

#[tokio::test(start_paused = true)]
async fn a_long_line_resets_the_timers_only_at_its_end() {
    // `ERR too-long` comes as soon as the line is known to be too long,
    // but the line counts as received only when its LF arrives (2.3, 11;
    // PLAN.md 5, item 16).
    let mut pipe = Pipe::greeted(Stub::new()).await;
    let start = Instant::now();
    tokio::time::sleep(Duration::from_secs(60)).await;
    let mut long = b"@ref=L PING ".to_vec();
    long.extend(std::iter::repeat_n(
        b'x',
        risala_proto::frame::MAX_CLIENT_LINE,
    ));
    pipe.send(&long).await;
    pipe.expect("@ref=L ERR too-long too long").await;
    assert_eq!(start.elapsed(), Duration::from_secs(60));
    // More of the same line, still with no LF.
    tokio::time::sleep(Duration::from_secs(30)).await;
    pipe.send(&[b'x'; 100]).await;
    // Nothing complete has arrived since the greeting.
    pipe.expect_prefix("PING ").await;
    assert_eq!(start.elapsed(), TIMERS.idle_ping);

    // The LF ends the line: both timers start again.
    tokio::time::sleep(Duration::from_secs(10)).await;
    pipe.send(b"xx\n").await;
    let lf = Instant::now();
    pipe.expect_prefix("PING ").await;
    assert_eq!(lf.elapsed(), TIMERS.idle_ping);
    pipe.expect("BYE ping timeout").await;
    pipe.expect_end().await;
}

impl Pipe {
    fn commands(stub: &Stub) -> Vec<Request> {
        stub.commands.lock().unwrap().clone()
    }
}

#[tokio::test(start_paused = true)]
async fn quit_closes_after_the_ok() {
    let mut pipe = Pipe::greeted(Stub::new()).await;
    // Lines after QUIT are not read.
    pipe.send(b"@ref=q QUIT see you\nPING\n").await;
    pipe.expect("@ref=q OK verb=quit").await;
    let stub = pipe.stub.clone();
    pipe.expect_end().await;
    assert_eq!(Pipe::commands(&stub).len(), 1);
}

#[tokio::test(start_paused = true)]
async fn close_with_bye() {
    let mut pipe = Pipe::greeted(Stub::new()).await;
    let handle = pipe.stub.handle(ID);
    handle.send(ServerMessage::new(OkResponse::new()));
    handle.close(Some("go away".into()));
    // Nothing queued after the close is sent.
    handle.send(ServerMessage::new(OkResponse::new()));
    pipe.expect("OK").await;
    pipe.expect("BYE go away").await;
    pipe.expect_end().await;
}

#[tokio::test(start_paused = true)]
async fn client_eof_ends_the_connection() {
    let mut pipe = Pipe::greeted(Stub::new()).await;
    // The answer to a command sent just before the end is still written.
    pipe.send(b"@ref=last PING").await;
    pipe.send(b"\n").await;
    pipe.wr.shutdown().await.unwrap();
    pipe.expect("@ref=last OK verb=ping").await;
    pipe.expect_end().await;
}

#[tokio::test(start_paused = true)]
async fn kill_drops_the_connection_at_once() {
    let mut pipe = Pipe::greeted(Stub::new()).await;
    let handle = pipe.stub.handle(ID);
    handle.send(ServerMessage::new(OkResponse::new()));
    handle.kill();
    assert!(handle.is_closed());
    assert!(!handle.send(ServerMessage::new(OkResponse::new())));
    // The line may or may not have been written before the kill.
    let mut lines = Vec::new();
    while let Some(line) = pipe.line().await {
        lines.push(line);
    }
    assert!(lines.is_empty() || lines == ["OK"], "{lines:?}");
    pipe.task.await.unwrap();
    assert_eq!(pipe.stub.closed(), vec![ID]);
}

#[tokio::test(start_paused = true)]
async fn slow_reader_is_killed() {
    // A tiny pipe and a short queue. The client never reads.
    let stub = Stub::new();
    let mut pipe = Pipe::new(stub.clone(), 4, 64);
    tokio::task::yield_now().await;
    let handle = stub.handle(ID);
    let mut sent = 0;
    while handle.send(ServerMessage::new(OkResponse::new().with("n", sent))) {
        sent += 1;
        // Let the writer fill the pipe, as a real socket would.
        tokio::task::yield_now().await;
        assert!(sent < 10_000, "the queue never filled");
    }
    assert!(handle.is_closed());
    // The connection ends without the client reading anything.
    (&mut pipe.task).await.unwrap();
    assert_eq!(stub.closed(), vec![ID]);
}

#[tokio::test(start_paused = true)]
async fn pipelined_commands_wait_for_a_slow_reader() {
    // Each command queues 40 lines of 1 KiB and an OK, into a queue of 64
    // lines, over a pipe that holds 64 bytes. The client sends 12 commands
    // at once, then reads slowly. Run back to back, the commands would
    // overflow the queue and the connection would be dropped. Instead each
    // waits for room for its response (and a little more), which the
    // client makes as it reads.
    let stub = Arc::new(Stub {
        lines_per_command: 40,
        ..Stub::default()
    });
    let room = CommandRoom {
        lines: 50,
        bytes: 50 * 1024,
    };
    let mut pipe = Pipe::with_room(stub.clone(), 64, 64, room);
    pipe.expect(GREETING).await;
    let commands: String = (0..12).map(|i| format!("@ref={i:02} PING\n")).collect();
    // The commands do not fit in the pipe at once, so send them while
    // reading.
    let Pipe { rd, wr, .. } = &mut pipe;
    let send = async { wr.write_all(commands.as_bytes()).await.unwrap() };
    let read = async {
        let mut line = String::new();
        for i in 0..12 {
            for n in 0..40 {
                line.clear();
                rd.read_line(&mut line).await.unwrap();
                assert!(line.starts_with(&format!("NOTICE {n:04} ")), "{line}");
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            line.clear();
            rd.read_line(&mut line).await.unwrap();
            assert_eq!(line, format!("@ref={i:02} OK verb=ping\n"));
        }
    };
    tokio::join!(send, read);
    assert_eq!(stub.closed(), Vec::new());
    assert_eq!(Pipe::commands(&stub).len(), 12);
    pipe.wr.shutdown().await.unwrap();
    pipe.expect_end().await;
}

#[tokio::test(start_paused = true)]
async fn a_client_that_stops_reading_times_out_while_waiting() {
    // While a command waits for room, the keepalive timers still run:
    // a client that sends commands but never reads is closed in the end.
    let stub = Arc::new(Stub {
        lines_per_command: 40,
        ..Stub::default()
    });
    let room = CommandRoom {
        lines: 50,
        bytes: 50 * 1024,
    };
    let mut pipe = Pipe::with_room(stub.clone(), 64, 64, room);
    pipe.expect(GREETING).await;
    let start = Instant::now();
    pipe.send(b"PING\nPING\nPING\nPING\n").await;
    (&mut pipe.task).await.unwrap();
    // PING after 120 seconds, BYE 60 later, then 5 seconds to drain.
    assert!(start.elapsed() >= TIMERS.idle_ping + TIMERS.ping_timeout);
    assert!(start.elapsed() <= TIMERS.idle_ping + TIMERS.ping_timeout + conn::DRAIN_TIMEOUT);
    assert!(Pipe::commands(&stub).len() < 4);
    assert_eq!(stub.closed(), vec![ID]);
}

#[tokio::test(start_paused = true)]
async fn shutdown_stops_reading() {
    let stub = Stub::new();
    let (client, server) = tokio::io::duplex(4096);
    let (handle, receiver) = conn_channel(ID, 16, usize::MAX);
    let (stop_tx, stop_rx) = watch::channel(false);
    let info = ConnInfo {
        peer: "127.0.0.1:50000".parse().unwrap(),
        sni: None,
        sni_certified: false,
        since: Timestamp::now(),
    };
    let task = tokio::spawn(conn::serve(
        server,
        info,
        handle.clone(),
        receiver,
        stub.clone(),
        TIMERS,
        ROOM,
        stop_rx,
    ));
    let (rd, _wr) = tokio::io::split(client);
    let mut rd = BufReader::new(rd);
    let mut line = String::new();
    rd.read_line(&mut line).await.unwrap();
    assert_eq!(line, format!("{GREETING}\n"));

    // As Server::run does: BYE through the queue, then the stop signal.
    handle.close(Some(SHUTDOWN_BYE.into()));
    stop_tx.send(true).unwrap();
    let mut rest = String::new();
    tokio::io::AsyncReadExt::read_to_string(&mut rd, &mut rest)
        .await
        .unwrap();
    assert_eq!(rest, "BYE server shutting down\n");
    task.await.unwrap();
    assert_eq!(stub.closed(), vec![ID]);
}

// ---------------------------------------------------------------------
// The whole server, over TLS, in real time

fn test_config(state_dir: &Path) -> Config {
    Config {
        hostname: "localhost".into(),
        listen: vec!["127.0.0.1:0".parse().unwrap()],
        state_dir: state_dir.to_owned(),
        ..Config::default()
    }
}

/// A server running in the background.
struct Running {
    addr: SocketAddr,
    stub: Arc<Stub>,
    certs: Certificates,
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<io::Result<()>>,
}

impl Running {
    fn start(config: &Config) -> Running {
        Running::start_with(config, |_| {})
    }

    fn start_with(config: &Config, tweak: impl FnOnce(&mut Server<Stub>)) -> Running {
        let stub = Stub::new();
        let mut server = Server::bind(config, stub.clone()).unwrap();
        tweak(&mut server);
        let addr = server.local_addrs()[0];
        let certs = server.certificates().clone();
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(server.run(async {
            let _ = stopped.await;
        }));
        Running {
            addr,
            stub,
            certs,
            stop: Some(stop),
            task,
        }
    }

    async fn client(&self, options: ClientOptions) -> TestClient {
        let mut client = TestClient::connect_with(self.addr, options).await.unwrap();
        let greeting = client.expect_line().await.unwrap();
        assert!(greeting.starts_with("RISALA 1 "), "{greeting}");
        client
    }

    async fn shutdown(mut self) {
        self.stop.take().unwrap().send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(20), self.task)
            .await
            .expect("shutdown finishes")
            .unwrap()
            .unwrap();
    }
}

/// Polls `cond` until it holds, for up to ten seconds.
async fn wait_until(mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !cond() {
        assert!(Instant::now() < deadline, "condition never held");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Writes a new self-signed certificate and key for `names` to `pair`, and
/// returns its fingerprint.
fn write_cert(pair: &CertPair, names: &[&str]) -> Fingerprint {
    let names: Vec<String> = names.iter().map(|n| n.to_string()).collect();
    let issued = rcgen::generate_simple_self_signed(names).unwrap();
    std::fs::write(&pair.cert, issued.cert.pem()).unwrap();
    std::fs::write(&pair.key, issued.signing_key.serialize_pem()).unwrap();
    tls::spki_fingerprint(issued.cert.der()).unwrap()
}

fn pair_in(dir: &Path, name: &str) -> CertPair {
    CertPair {
        cert: dir.join(format!("{name}.crt")),
        key: dir.join(format!("{name}.key")),
    }
}

#[tokio::test]
async fn greeting_with_and_without_sni() {
    let dir = tempfile::tempdir().unwrap();
    let server = Running::start(&test_config(dir.path()));

    let mut c = TestClient::connect(server.addr).await.unwrap();
    assert_eq!(c.expect_line().await.unwrap(), GREETING);

    let mut c = TestClient::connect_with(server.addr, ClientOptions::sni("Chat.Example.ORG"))
        .await
        .unwrap();
    assert_eq!(
        c.expect_line().await.unwrap(),
        "RISALA 1 chat.example.org abababababababababababababababab hello"
    );
    c.send("@ref=1 PING").await.unwrap();
    assert_eq!(c.expect_line().await.unwrap(), "@ref=1 OK verb=ping");

    let opened = server.stub.opened();
    assert_eq!(opened.len(), 2);
    assert_eq!(opened[0].sni, None);
    assert_eq!(opened[1].sni.as_deref(), Some("chat.example.org"));
    assert!(opened[0].peer.ip().is_loopback());
    server.shutdown().await;
}

#[tokio::test]
async fn alpn_is_optional() {
    let dir = tempfile::tempdir().unwrap();
    let server = Running::start(&test_config(dir.path()));

    let offered = server.client(ClientOptions::default()).await;
    assert_eq!(offered.alpn(), Some(risala_proto::ALPN));

    let none = server
        .client(ClientOptions {
            alpn: false,
            ..ClientOptions::default()
        })
        .await;
    assert_eq!(none.alpn(), None);
    server.shutdown().await;
}

#[tokio::test]
async fn only_x25519mlkem768_is_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let server = Running::start(&test_config(dir.path()));

    let pq = server.client(ClientOptions::default()).await;
    assert_eq!(pq.kx_group(), Some(rustls::NamedGroup::X25519MLKEM768));

    // A client that offers only X25519 fails the handshake (2.1).
    let classic = ClientOptions {
        classic_kx: true,
        ..ClientOptions::sni("localhost")
    };
    let err = TestClient::connect_with(server.addr, classic)
        .await
        .unwrap_err();
    let tls = err
        .get_ref()
        .and_then(|e| e.downcast_ref::<rustls::Error>())
        .unwrap_or_else(|| panic!("{err:?}"));
    assert_eq!(
        *tls,
        rustls::Error::AlertReceived(rustls::AlertDescription::HandshakeFailure)
    );
    assert_eq!(server.stub.opened().len(), 1);
    server.shutdown().await;
}

#[test]
fn a_refused_key_exchange_is_explained() {
    let no_group = io::Error::other(rustls::Error::PeerIncompatible(
        rustls::PeerIncompatible::NoKxGroupsInCommon,
    ));
    let reason = tls::handshake_failure(&no_group).unwrap();
    assert!(reason.contains("X25519MLKEM768"), "{reason}");
    let other = io::Error::other(rustls::Error::AlertReceived(
        rustls::AlertDescription::BadCertificate,
    ));
    assert_eq!(tls::handshake_failure(&other), None);
}

#[tokio::test]
async fn certificates_are_chosen_by_sni() {
    let dir = tempfile::tempdir().unwrap();
    let a = pair_in(dir.path(), "a");
    let b = pair_in(dir.path(), "b");
    let fp_a = write_cert(&a, &["a.test"]);
    let fp_b = write_cert(&b, &["b.test", "*.b.test"]);
    let mut config = test_config(dir.path());
    config.tls.certs = vec![a, b];
    let server = Running::start(&config);
    assert_eq!(server.certs.fingerprints(), vec![fp_a, fp_b]);
    assert_eq!(server.certs.fingerprint(), fp_a);

    for (sni, want) in [
        (Some("a.test"), fp_a),
        (Some("b.test"), fp_b),
        (Some("B.Test"), fp_b),
        (Some("chat.b.test"), fp_b),
        (Some("other.test"), fp_a),
        (None, fp_a),
    ] {
        let options = ClientOptions {
            sni: sni.map(str::to_owned),
            ..ClientOptions::default()
        };
        assert_eq!(server.client(options).await.fingerprint(), want, "{sni:?}");
    }
    server.shutdown().await;
}

/// The names on the certificates, which the hub checks sign-ins against
/// (4.5), with wildcards matched as usual, and the network layer telling
/// the handler whether a connection's SNI is one of them.
#[tokio::test]
async fn certificate_names_follow_reloads() {
    let dir = tempfile::tempdir().unwrap();
    let a = pair_in(dir.path(), "a");
    let b = pair_in(dir.path(), "b");
    write_cert(&a, &["a.test"]);
    write_cert(&b, &["B.test", "*.b.test", "a.test"]);
    let mut config = test_config(dir.path());
    config.tls.certs = vec![a.clone(), b];
    let server = Running::start(&config);
    assert_eq!(server.certs.names(), ["a.test", "b.test", "*.b.test"]);
    for (host, served) in [
        ("a.test", true),
        ("A.Test.", true),
        ("b.test", true),
        ("chat.b.test", true),
        // A wildcard covers one label, and not the name it is under.
        ("x.chat.b.test", false),
        ("other.test", false),
        ("127.0.0.1", false),
        ("", false),
    ] {
        assert_eq!(server.certs.serves(host), served, "{host}");
    }

    for (sni, certified) in [
        (Some("a.test"), true),
        (Some("Chat.B.Test"), true),
        (Some("elsewhere.test"), false),
        (None, false),
    ] {
        let options = ClientOptions {
            sni: sni.map(str::to_owned),
            ..ClientOptions::default()
        };
        server.client(options).await;
        let opened = server.stub.opened();
        assert_eq!(opened.last().unwrap().sni_certified, certified, "{sni:?}");
    }

    // A reload changes the names.
    write_cert(&a, &["new.test"]);
    assert!(server.certs.reload());
    assert!(server.certs.serves("new.test"));
    assert!(server.certs.serves("a.test"), "still on the second");
    write_cert(&a, &["a.test"]);
    let b = pair_in(dir.path(), "b");
    write_cert(&b, &["b.test"]);
    assert!(server.certs.reload());
    assert!(!server.certs.serves("new.test"));
    assert!(!server.certs.serves("chat.b.test"));
    assert_eq!(server.certs.names(), ["a.test", "b.test"]);
    server.client(ClientOptions::sni("new.test")).await;
    assert!(!server.stub.opened().last().unwrap().sni_certified);
    server.shutdown().await;
}

#[tokio::test]
async fn certificates_reload_without_dropping_connections() {
    let dir = tempfile::tempdir().unwrap();
    let a = pair_in(dir.path(), "a");
    let fp_1 = write_cert(&a, &["a.test"]);
    let mut config = test_config(dir.path());
    config.tls.certs = vec![a.clone()];
    let server = Running::start(&config);
    let mut old = server.client(ClientOptions::sni("a.test")).await;
    assert_eq!(old.fingerprint(), fp_1);

    // Nothing changed: nothing is reloaded.
    assert!(server.certs.reload_if_changed());
    assert_eq!(server.certs.fingerprint(), fp_1);

    // Replaced files are picked up by new connections.
    let fp_2 = write_cert(&a, &["a.test"]);
    assert_ne!(fp_1, fp_2);
    assert!(server.certs.reload());
    assert_eq!(
        server
            .client(ClientOptions::sni("a.test"))
            .await
            .fingerprint(),
        fp_2
    );

    // A broken file keeps the old certificate.
    std::fs::write(&a.cert, "not a certificate").unwrap();
    assert!(!server.certs.reload());
    assert_eq!(
        server
            .client(ClientOptions::sni("a.test"))
            .await
            .fingerprint(),
        fp_2
    );

    // A key that does not belong to the certificate is refused too.
    let other = pair_in(dir.path(), "other");
    write_cert(&other, &["a.test"]);
    let fp_3 = write_cert(&a, &["a.test"]);
    std::fs::copy(&other.key, &a.key).unwrap();
    assert!(!server.certs.reload());
    assert_eq!(server.certs.fingerprint(), fp_2);

    // The poll notices changed modification times.
    let fp_4 = write_cert(&a, &["a.test"]);
    assert_ne!(fp_3, fp_4);
    let t = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000_000);
    for path in [&a.cert, &a.key] {
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(t)
            .unwrap();
    }
    assert!(server.certs.reload_if_changed());
    assert_eq!(
        server
            .client(ClientOptions::sni("a.test"))
            .await
            .fingerprint(),
        fp_4
    );

    // The first connection is still up.
    old.send("@ref=still PING").await.unwrap();
    assert_eq!(old.expect_line().await.unwrap(), "@ref=still OK verb=ping");
    server.shutdown().await;
}

#[tokio::test]
async fn self_signed_certificate_is_generated_once() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(dir.path());
    let paths = tls::self_signed_paths(dir.path());

    let server = Server::bind(&config, Stub::new()).unwrap();
    let fp = server.fingerprint();
    assert!(paths.cert.exists() && paths.key.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&paths.key).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let cert_pem = std::fs::read(&paths.cert).unwrap();
    drop(server);

    // A restart reuses it.
    let running = Running::start(&config);
    assert_eq!(running.certs.fingerprint(), fp);
    assert_eq!(std::fs::read(&paths.cert).unwrap(), cert_pem);
    let client = running.client(ClientOptions::sni("localhost")).await;
    assert_eq!(client.fingerprint(), fp);
    running.shutdown().await;

    // A new hostname gets a new certificate with the same key, so the
    // fingerprint a client pinned still holds (2.2).
    let mut renamed = config.clone();
    renamed.hostname = "chat.example.org".into();
    let running = Running::start(&renamed);
    assert_eq!(running.certs.fingerprint(), fp);
    assert_ne!(std::fs::read(&paths.cert).unwrap(), cert_pem);
    let client = running.client(ClientOptions::sni("chat.example.org")).await;
    assert_eq!(client.fingerprint(), fp);
    running.shutdown().await;
}

#[tokio::test]
async fn a_self_signed_key_from_before_aws_lc_keeps_its_fingerprint() {
    // A key that rcgen made with ring, as risalad did before it moved to
    // aws-lc-rs. State dirs from then still load it, and clients' pins
    // still hold (2.2). The fingerprint is from Appendix A's openssl
    // commands.
    const KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgKjoEWK82rPH2OZUt
5lWSHVUTBekWiMHfEnsfJpUwexqhRANCAAQu+yb+cneTHqqntfe2qw2iwv5t9r4t
ZeNUFcQGhu9zcuJFt5rUiNnQcsSatYCsYfoJsUTs6BZ38hd0xQBUM06I
-----END PRIVATE KEY-----
";
    const FINGERPRINT: &str =
        "sha256:2e04d75f37e2ac68e9743b9e9354188868e4286c7cfd377057ce442b30d0e9d1";
    let dir = tempfile::tempdir().unwrap();
    let paths = tls::self_signed_paths(dir.path());
    std::fs::create_dir_all(paths.key.parent().unwrap()).unwrap();
    std::fs::write(&paths.key, KEY).unwrap();

    let running = Running::start(&test_config(dir.path()));
    assert_eq!(running.certs.fingerprint().to_string(), FINGERPRINT);
    assert_eq!(std::fs::read_to_string(&paths.key).unwrap(), KEY);
    let client = running.client(ClientOptions::sni("localhost")).await;
    assert_eq!(client.fingerprint().to_string(), FINGERPRINT);
    running.shutdown().await;
}

#[tokio::test]
async fn unusable_certificates_fail_bind() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = test_config(dir.path());
    config.tls.certs = vec![pair_in(dir.path(), "missing")];
    let err = Server::bind(&config, Stub::new()).unwrap_err();
    assert!(err.to_string().contains("missing.crt"), "{err}");
}

#[tokio::test]
async fn unusable_limits_fail_bind() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = test_config(dir.path());
    config.limits.out_queue = 1;
    let err = Server::bind(&config, Stub::new()).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("out_queue"), "{err}");
}

/// Appendix A's pipeline prints the fingerprint the server logs.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn fingerprint_matches_openssl() {
    if !super::testing::openssl_has_x25519mlkem768() {
        eprintln!("OpenSSL 3.5 or later not found, skipping");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let server = Running::start(&test_config(dir.path()));
    let pipeline = format!(
        "openssl s_client -connect {} </dev/null 2>/dev/null \
         | openssl x509 -pubkey -noout \
         | openssl pkey -pubin -outform der \
         | openssl dgst -sha256",
        server.addr
    );
    let out = tokio::task::spawn_blocking(move || {
        std::process::Command::new("sh")
            .args(["-c", &pipeline])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(out.status.success(), "{out:?}");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let hex = stdout.split_whitespace().last().unwrap();
    assert_eq!(
        format!("sha256:{hex}"),
        server.certs.fingerprint().to_string()
    );
    server.shutdown().await;
}

#[tokio::test]
async fn shutdown_says_bye_to_everyone() {
    let dir = tempfile::tempdir().unwrap();
    let server = Running::start(&test_config(dir.path()));
    let mut a = server.client(ClientOptions::default()).await;
    let mut b = server.client(ClientOptions::sni("localhost")).await;
    // Answers queued before the shutdown come first.
    a.send("@ref=1 PING").await.unwrap();
    assert_eq!(a.expect_line().await.unwrap(), "@ref=1 OK verb=ping");

    let stub = server.stub.clone();
    server.shutdown().await;
    assert_eq!(
        a.recv_until_closed().await.unwrap(),
        ["BYE server shutting down"]
    );
    assert_eq!(
        b.recv_until_closed().await.unwrap(),
        ["BYE server shutting down"]
    );
    let mut closed = stub.closed();
    closed.sort();
    assert_eq!(closed.len(), 2);
    closed.dedup();
    assert_eq!(closed.len(), 2);
}

#[tokio::test]
async fn handshake_times_out() {
    let dir = tempfile::tempdir().unwrap();
    let server = Running::start_with(&test_config(dir.path()), |s| {
        s.handshake_timeout = Duration::from_millis(100);
    });
    let mut tcp = tokio::net::TcpStream::connect(server.addr).await.unwrap();
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::io::AsyncReadExt::read(&mut tcp, &mut buf),
    )
    .await
    .expect("the server closes")
    .unwrap_or(0);
    assert_eq!(n, 0);
    assert!(server.stub.opened().is_empty());
    server.shutdown().await;
}

#[tokio::test]
async fn connections_are_capped() {
    let dir = tempfile::tempdir().unwrap();
    let server = Running::start_with(&test_config(dir.path()), |s| s.max_connections = 1);
    let first = server.client(ClientOptions::default()).await;
    assert!(TestClient::connect(server.addr).await.is_err());

    first.close().await.unwrap();
    let stub = server.stub.clone();
    wait_until(|| stub.closed().len() == 1).await;
    // The slot is free once the connection task has ended.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match TestClient::connect(server.addr).await {
            Ok(_) => break,
            Err(_) => {
                assert!(Instant::now() < deadline, "the slot was never freed");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }
    server.shutdown().await;
}
