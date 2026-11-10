//! One connection after its TLS handshake: reading and framing lines,
//! answering lines that do not parse (2.3, 3.6), passing commands to the
//! [`Handler`], writing the connection's queue, and keepalive (11).
//!
//! The task is generic over the stream, so tests can drive it over an
//! in-memory pipe, with tokio's paused clock, and no TLS.

use std::sync::Arc;
use std::time::Duration;

use risala_proto::command::{Command, Request};
use risala_proto::error::ParseError;
use risala_proto::frame::LineDecoder;
use risala_proto::line::{Line, read_ref};
use risala_proto::server::{ErrResponse, ServerLine, ServerMessage};
use risala_proto::text::escape;
use risala_proto::types::Ref;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::handler::{ConnHandle, ConnInfo, ConnReceiver, Handler, OutLine, Outgoing};

/// How long a connection that has stopped reading commands has to send
/// what is queued for it before it is dropped.
pub(crate) const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// The bytes read from the socket at a time.
const READ_BUF: usize = 8192;

/// Write at most about this many bytes in one go, so one connection with a
/// long queue does not build a huge buffer.
const WRITE_BATCH: usize = 64 * 1024;

/// Timers for one connection (11).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Timers {
    /// Silence before the server sends PING.
    pub idle_ping: Duration,
    /// Further silence before the server sends BYE and closes.
    pub ping_timeout: Duration,
}

/// The room a connection's queue must have before the next command goes
/// to the handler: [`Limits::command_room`](crate::config::Limits::command_room)
/// and [`command_room_bytes`](crate::config::Limits::command_room_bytes).
#[derive(Debug, Clone, Copy)]
pub(crate) struct CommandRoom {
    /// Free lines.
    pub lines: usize,
    /// Free bytes.
    pub bytes: usize,
}

/// Why the reading side stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ended {
    /// The writer finished: after a `Close`, a kill or a write error.
    Writer,
    /// The client closed its side, or reading failed.
    Eof,
    /// The client sent QUIT.
    Quit,
    /// Nothing was received for too long. BYE is queued.
    Timeout,
    /// The server is shutting down. BYE is queued by the server.
    Shutdown,
}

/// Runs a connection to its end.
///
/// Calls [`Handler::open`] first and [`Handler::closed`] exactly once
/// last, however the connection ends. `stop` turns true when the server
/// shuts down; the caller queues the BYE.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve<S, H>(
    stream: S,
    info: ConnInfo,
    handle: ConnHandle,
    receiver: ConnReceiver,
    handler: Arc<H>,
    timers: Timers,
    room: CommandRoom,
    stop: watch::Receiver<bool>,
) where
    S: AsyncRead + AsyncWrite + Send + 'static,
    H: Handler,
{
    let id = handle.id();
    let (rd, wr) = tokio::io::split(stream);
    let mut writer = tokio::spawn(write_loop(wr, receiver));
    handler.open(info, handle.clone());

    let ended = read_loop(rd, &handle, &*handler, timers, room, stop, &mut writer).await;
    tracing::debug!(conn = id.0, ?ended, "connection stopped reading");
    if ended != Ended::Writer {
        if ended == Ended::Eof {
            // Send what is queued, then close.
            handle.close(None);
        }
        if tokio::time::timeout(DRAIN_TIMEOUT, &mut writer)
            .await
            .is_err()
        {
            tracing::debug!(conn = id.0, "queue did not drain in time");
            handle.kill();
            let _ = writer.await;
        }
    }
    handler.closed(id).await;
    tracing::debug!(conn = id.0, "connection closed");
}

/// Reads lines and handles them until the connection should stop reading.
///
/// Before each command goes to the handler, it waits until the queue has
/// `room` for the command's response. So a client that sends many commands
/// at once gets their responses as fast as it reads them, rather than
/// being dropped as too slow when they overflow its queue. The keepalive
/// timers still run while it waits, so a client that stops reading
/// altogether is closed in the end.
async fn read_loop<R, H>(
    mut rd: R,
    handle: &ConnHandle,
    handler: &H,
    timers: Timers,
    room: CommandRoom,
    mut stop: watch::Receiver<bool>,
    writer: &mut JoinHandle<()>,
) -> Ended
where
    R: AsyncRead + Unpin,
    H: Handler,
{
    let id = handle.id();
    let mut decoder = LineDecoder::with_limits(handle.kind().client_limits());
    let mut buf = vec![0u8; READ_BUF];
    let mut keepalive = Keepalive::new(timers, Instant::now());
    let mut long_line = LongLine::default();
    loop {
        while let Some((line, ref_)) = decoder.next_line_with_ref() {
            // Any complete line, even an empty or bad one, resets the timers
            // (11). A line reported as too long before its end is complete
            // only once its LF arrives (2.3).
            let too_long = matches!(line, Err(ParseError::TooLong));
            if long_line.taken(too_long, decoder.is_discarding()) {
                keepalive.activity(Instant::now());
            }
            if writer.is_finished() {
                return Ended::Writer;
            }
            if *stop.borrow() {
                return Ended::Shutdown;
            }
            match line {
                Ok(line) if line.is_empty() => {}
                Ok(line) => {
                    let req = match Line::parse(&line) {
                        Ok(parsed) => {
                            Request::parse(&parsed).map_err(|e| (e, Request::ref_of(&parsed)))
                        }
                        Err(e) => Err((e, read_ref(line.as_bytes()))),
                    };
                    match req {
                        Ok(req) => {
                            if let Some(ended) = wait_for_room(
                                handle,
                                handler,
                                room,
                                &mut keepalive,
                                &mut stop,
                                writer,
                            )
                            .await
                            {
                                return ended;
                            }
                            let quit = matches!(req.command, Command::Quit { .. });
                            handler.command(id, req).await;
                            if quit {
                                return Ended::Quit;
                            }
                            // The limits follow the connection's kind (2.3):
                            // a new connection's REGISTER, KEYS and PAIR may
                            // be 64 KiB, and once it has a kind, the lines
                            // that carry MLS data and records may be long. Lines already
                            // split off keep the limit they were judged by.
                            let limits = handle.kind().client_limits();
                            if decoder.limits() != limits {
                                decoder.set_limits(limits);
                            }
                        }
                        Err((e, ref_)) => reply_parse_error(handle, &e, ref_),
                    }
                }
                Err(e) => reply_parse_error(handle, &e, ref_),
            }
        }

        let deadline = keepalive.deadline();
        tokio::select! {
            biased;
            _ = &mut *writer => return Ended::Writer,
            _ = stop.wait_for(|stopping| *stopping) => return Ended::Shutdown,
            () = tokio::time::sleep_until(deadline) => {
                if let Some(ended) = keepalive_expired(handle, handler, &mut keepalive) {
                    return ended;
                }
            }
            read = rd.read(&mut buf) => match read {
                Ok(0) => return Ended::Eof,
                Ok(n) => {
                    decoder.push(&buf[..n]);
                    if long_line.pushed(decoder.is_discarding()) {
                        keepalive.activity(Instant::now());
                    }
                }
                Err(e) => {
                    tracing::debug!(conn = id.0, error = %e, "read failed");
                    return Ended::Eof;
                }
            },
        }
    }
}

/// Waits until the queue has `room` for a command's response (see
/// [`read_loop`]). Returns why the connection should stop reading instead,
/// if it should.
async fn wait_for_room<H: Handler>(
    handle: &ConnHandle,
    handler: &H,
    room: CommandRoom,
    keepalive: &mut Keepalive,
    stop: &mut watch::Receiver<bool>,
    writer: &mut JoinHandle<()>,
) -> Option<Ended> {
    while !handle.has_room(room.lines, room.bytes) {
        let deadline = keepalive.deadline();
        tokio::select! {
            biased;
            _ = &mut *writer => return Some(Ended::Writer),
            _ = stop.wait_for(|stopping| *stopping) => return Some(Ended::Shutdown),
            () = tokio::time::sleep_until(deadline) => {
                if let Some(ended) = keepalive_expired(handle, handler, keepalive) {
                    return Some(ended);
                }
            }
            () = handle.wait_for_room(room.lines, room.bytes) => {}
        }
    }
    None
}

/// Called when the keepalive deadline may have passed: sends PING, or
/// gives up with BYE (11).
fn keepalive_expired<H: Handler>(
    handle: &ConnHandle,
    handler: &H,
    keepalive: &mut Keepalive,
) -> Option<Ended> {
    match keepalive.expired(Instant::now()) {
        Some(Expired::Ping) => {
            handle.send(ServerMessage::new(ServerLine::Ping {
                token: ping_token(),
                t: handler.now(),
            }));
            None
        }
        Some(Expired::Timeout) => {
            tracing::debug!(conn = handle.id().0, "ping timeout");
            handle.close(Some("ping timeout".into()));
            Some(Ended::Timeout)
        }
        None => None,
    }
}

/// Answers a line that did not parse with the code for its error,
/// carrying its `ref` if one could be read (2.3, 3.6).
fn reply_parse_error(handle: &ConnHandle, e: &ParseError, ref_: Option<Ref>) {
    tracing::debug!(conn = handle.id().0, error = %e, "bad line");
    let err = ErrResponse::new(e.code()).with_message(escape(&e.to_string()));
    handle.send(ServerMessage::new(err).with_ref_opt(ref_));
}

/// A random token for a server PING (11): 16 lower-case hex digits.
fn ping_token() -> String {
    let mut bytes = [0u8; 8];
    // Uniqueness is all that matters here, so a failing random source
    // still gives a usable, if fixed, token.
    let _ = getrandom::fill(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Writes the connection's queue to the stream until a `Close`, a kill,
/// a write error, or every [`ConnHandle`] is gone.
async fn write_loop<W>(mut wr: W, mut receiver: ConnReceiver)
where
    W: AsyncWrite + Unpin,
{
    let mut out = Vec::with_capacity(4096);
    loop {
        let first = tokio::select! {
            biased;
            () = receiver.killed() => return,
            item = receiver.recv() => item,
        };
        let mut close = false;
        let mut next = first;
        // Gather what is queued already into one write.
        loop {
            match next {
                Some(Outgoing::Line(line)) => out.extend_from_slice(line.wire()),
                Some(Outgoing::Close { bye }) => {
                    if let Some(text) = bye {
                        let bye =
                            OutLine::new(ServerMessage::new(ServerLine::Bye { message: text }));
                        out.extend_from_slice(bye.wire());
                    }
                    close = true;
                    break;
                }
                // Every handle is gone: nothing more can come.
                None => {
                    close = true;
                    break;
                }
            }
            if out.len() >= WRITE_BATCH {
                break;
            }
            match receiver.try_recv() {
                Some(item) => next = Some(item),
                None => break,
            }
        }
        let wrote = tokio::select! {
            biased;
            () = receiver.killed() => return,
            r = async {
                wr.write_all(&out).await?;
                wr.flush().await
            } => r,
        };
        out.clear();
        if wrote.is_err() {
            return;
        }
        if close {
            // Sends TLS close_notify, then closes the write side.
            tokio::select! {
                biased;
                () = receiver.killed() => {}
                _ = tokio::time::timeout(DRAIN_TIMEOUT, wr.shutdown()) => {}
            }
            return;
        }
    }
}

/// Follows a line that [`LineDecoder`] reports as too long before its LF
/// has arrived, so that the line resets the keepalive timers only when it
/// ends (2.3, 11; PLAN.md 5, item 16).
///
/// The decoder reports such a line as soon as it is known to be too long,
/// and then discards bytes up to and including the LF, without reporting
/// the LF. So a `TooLong` taken while the decoder is discarding is early,
/// and the line has ended once the decoder stops discarding, or yields
/// anything after it.
#[derive(Debug, Default)]
struct LongLine {
    /// An early `TooLong` was taken, and its LF has not been seen yet.
    waiting: bool,
}

impl LongLine {
    /// For each item taken from the decoder: whether a line has ended.
    /// `too_long` says whether the item is a `TooLong` error, and
    /// `discarding` is [`LineDecoder::is_discarding`] after taking it.
    fn taken(&mut self, too_long: bool, discarding: bool) -> bool {
        // While the decoder discards, the last item it holds is the
        // `TooLong` that started the discarding. An earlier `TooLong`
        // could look the same, but then this item follows it, and so ends
        // the line it waits for.
        let early = too_long && discarding;
        let ended = !early || self.waiting;
        self.waiting = early;
        ended
    }

    /// After bytes are pushed into the decoder: whether they ended the line
    /// that was reported early.
    fn pushed(&mut self, discarding: bool) -> bool {
        let ended = self.waiting && !discarding;
        if ended {
            self.waiting = false;
        }
        ended
    }
}

/// What a keepalive deadline means when it passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expired {
    /// Send PING.
    Ping,
    /// Give up: send BYE and close.
    Timeout,
}

/// The keepalive timers of Section 11, without I/O.
#[derive(Debug)]
struct Keepalive {
    timers: Timers,
    deadline: Instant,
    pinged: bool,
}

impl Keepalive {
    fn new(timers: Timers, now: Instant) -> Keepalive {
        Keepalive {
            timers,
            deadline: now + timers.idle_ping,
            pinged: false,
        }
    }

    /// Something was received: both timers start again.
    fn activity(&mut self, now: Instant) {
        self.pinged = false;
        self.deadline = now + self.timers.idle_ping;
    }

    /// When [`expired`](Self::expired) next has something to do.
    fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Called when the deadline may have passed.
    fn expired(&mut self, now: Instant) -> Option<Expired> {
        if now < self.deadline {
            None
        } else if self.pinged {
            Some(Expired::Timeout)
        } else {
            self.pinged = true;
            self.deadline = now + self.timers.ping_timeout;
            Some(Expired::Ping)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keepalive_state_machine() {
        let t = Timers {
            idle_ping: Duration::from_secs(120),
            ping_timeout: Duration::from_secs(60),
        };
        let start = Instant::now();
        let mut k = Keepalive::new(t, start);
        assert_eq!(k.deadline(), start + t.idle_ping);
        assert_eq!(k.expired(start + Duration::from_secs(119)), None);
        let at = start + t.idle_ping;
        assert_eq!(k.expired(at), Some(Expired::Ping));
        assert_eq!(k.deadline(), at + t.ping_timeout);
        assert_eq!(k.expired(at + Duration::from_secs(59)), None);
        assert_eq!(k.expired(at + t.ping_timeout), Some(Expired::Timeout));

        // Activity after the PING starts both timers again.
        let mut k = Keepalive::new(t, start);
        assert_eq!(k.expired(at), Some(Expired::Ping));
        let later = at + Duration::from_secs(30);
        k.activity(later);
        assert_eq!(k.deadline(), later + t.idle_ping);
        assert_eq!(k.expired(later + t.idle_ping), Some(Expired::Ping));
    }

    #[test]
    fn long_lines_end_at_their_lf() {
        fn activity(d: &mut LineDecoder, l: &mut LongLine, bytes: &[u8]) -> usize {
            d.push(bytes);
            let mut n = usize::from(l.pushed(d.is_discarding()));
            while let Some((line, _)) = d.next_line_with_ref() {
                let too_long = matches!(line, Err(ParseError::TooLong));
                n += usize::from(l.taken(too_long, d.is_discarding()));
            }
            n
        }
        let mut d = LineDecoder::new(8);
        let mut l = LongLine::default();
        // Lines that end at once count at once, too long or not.
        assert_eq!(activity(&mut d, &mut l, b"ab\n\n0123456789\n"), 3);
        // A long line counts only when its LF arrives.
        assert_eq!(activity(&mut d, &mut l, b"0123456789"), 0);
        assert_eq!(activity(&mut d, &mut l, b"0123456789"), 0);
        assert_eq!(activity(&mut d, &mut l, b"01\n"), 1);
        assert_eq!(activity(&mut d, &mut l, b"ab\n"), 1);
        // Its LF, and the start of another long line, in one push.
        assert_eq!(activity(&mut d, &mut l, b"0123456789"), 0);
        assert_eq!(activity(&mut d, &mut l, b"\n0123456789"), 1);
        assert_eq!(activity(&mut d, &mut l, b"89\nab\n"), 2);
        // A long line that ends, then one that does not.
        assert_eq!(activity(&mut d, &mut l, b"0123456789\n0123456789"), 1);
        assert_eq!(activity(&mut d, &mut l, b"\n"), 1);
    }

    #[test]
    fn ping_tokens_are_hex() {
        let a = ping_token();
        assert_eq!(a.len(), 16);
        assert!(
            a.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        assert_ne!(a, ping_token());
    }
}
