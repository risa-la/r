//! Files, transfers, backups and reports with several devices, against the
//! group engine's in-memory server ([`FakeServer`], task C2) for
//! mailboxes, and [`Remote`] for what the server's blob and backup area
//! (task SV4) does: INFO, UPLOAD, BLOB, BACKUP and REPORT, with files and
//! blobs kept in memory behind [`FileHttps`]. SV4 has not landed on `m5b`,
//! so `risalad` cannot serve these yet.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::{Arc, Mutex};

use risala_mls::backup::RecoveryKey;
use risala_mls::mldsa::SigningKey;
use risala_proto::command::{BackupCommand, Command};
use risala_proto::connection::ConnectionKind;
use risala_proto::content::{ContentLine, Text};
use risala_proto::names::Uid;
use risala_proto::server::{ErrResponse, OkResponse, ServerMessage};
use tokio::sync::broadcast;

use super::*;
use crate::client::files::{ARCHIVE_BLOB, Commands, FileHttps, HttpError, Jobs, TransferError};
use crate::clock::ManualClock;
use crate::conn::{BoxFuture, End, Response, Slot};
use crate::keys::{KeyStore, MemoryKeyStore};
use crate::store::conversations::ConvState;
use crate::store::transfer::Origin;
use crate::store::{AccountKind, Store};
use crate::sync::Target;
use crate::sync::conversations::tests::server::FakeServer;
use crate::sync::conversations::{
    Config, ConversationEngine, Hooks, Job, SINGLE_USE_SLOT, content,
};
use crate::sync::{Action, Context, Input, Token};

/// 2026-11-09.
const START: u64 = 1_794_182_400_000;

const FILES: &str = "https://files.test";

fn block_on<F: Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

// ---------------------------------------------------------------------------
// The server's blob, file, backup and report area, in memory

#[derive(Default)]
struct RemoteState {
    /// Blobs by hex hash.
    blobs: HashMap<String, Vec<u8>>,
    /// Put URLs waiting for their upload: a blob's hex hash and size, or a
    /// file's get URL and size.
    puts: HashMap<String, (Put, u64)>,
    /// Files by get URL.
    files: HashMap<String, Vec<u8>>,
    /// del URL to get URL.
    dels: HashMap<String, String>,
    /// Backups by uid: generation, hash, key, files.
    backups: HashMap<String, (u32, String, String, Option<String>)>,
    /// Reports to operators: mailbox and report.
    reports: Vec<(String, String)>,
    /// Every command, for assertions.
    log: Vec<String>,
    next: u64,
}

#[derive(Clone)]
enum Put {
    Blob(String),
    File(String),
}

#[derive(Clone, Default)]
struct Remote(Arc<Mutex<RemoteState>>);

fn ok_response(ok: OkResponse) -> Response {
    Response {
        lines: Vec::new(),
        end: End::Ok(ok),
    }
}

fn err_response(code: risala_proto::error::ErrorCode) -> Response {
    Response {
        lines: Vec::new(),
        end: End::Err(ErrResponse {
            code,
            retry: None,
            message: String::new(),
        }),
    }
}

impl Remote {
    fn handle(&self, uid: &str, command: Command) -> Response {
        let mut s = self.0.lock().unwrap();
        s.log.push(format!("{command:?}"));
        s.next += 1;
        let n = s.next;
        match command {
            Command::Info { .. } => ok_response(
                OkResponse::new()
                    .with("upload", 10_000_000)
                    .with("files", FILES)
                    .with("blobs", format!("{FILES}/b/")),
            ),
            Command::Blob { hash, size, .. } => {
                if s.blobs.contains_key(&hash.hex()) {
                    return ok_response(OkResponse::new().with_exists());
                }
                let put = format!("{FILES}/put/{n}");
                s.puts.insert(put.clone(), (Put::Blob(hash.hex()), size));
                ok_response(OkResponse::new().with_put_url(&put).unwrap())
            }
            Command::Upload { size, .. } => {
                let put = format!("{FILES}/put/{n}");
                let get = format!("{FILES}/f/{n}");
                let del = format!("{FILES}/del/{n}");
                s.puts.insert(put.clone(), (Put::File(get.clone()), size));
                s.dels.insert(del.clone(), get.clone());
                ok_response(
                    OkResponse::new()
                        .with("put", &put)
                        .with("get", &get)
                        .with("del", &del),
                )
            }
            Command::Backup(BackupCommand::Put {
                generation,
                hash,
                key,
                files,
            }) => {
                // 12.13: every blob it names must still be stored.
                let mut named = vec![hash.hex()];
                if let Some(list) = files {
                    let Some(bytes) = s.blobs.get(&list.hex()) else {
                        return err_response(risala_proto::error::ErrorCode::NotFound);
                    };
                    let Some(hashes) = risala_mls::backup::read_list(bytes) else {
                        return err_response(risala_proto::error::ErrorCode::Invalid);
                    };
                    named.extend(hashes.iter().map(proto_hex));
                }
                if named.iter().any(|h| !s.blobs.contains_key(h)) {
                    return err_response(risala_proto::error::ErrorCode::NotFound);
                }
                s.backups.insert(
                    uid.to_owned(),
                    (
                        generation,
                        hash.to_string(),
                        key.to_string(),
                        files.map(|f| f.to_string()),
                    ),
                );
                ok_response(OkResponse::new())
            }
            Command::Backup(BackupCommand::Get) => match s.backups.get(uid) {
                None => err_response(risala_proto::error::ErrorCode::NotFound),
                Some((g, hash, key, files)) => {
                    let mut line = format!("BACKUP {g} {hash} {key}");
                    if let Some(f) = files {
                        line.push_str(&format!(" files={f}"));
                    }
                    Response {
                        lines: vec![line.parse::<ServerMessage>().unwrap()],
                        end: End::Ok(OkResponse::new()),
                    }
                }
            },
            Command::Backup(BackupCommand::Del) => {
                s.backups.remove(uid);
                ok_response(OkResponse::new())
            }
            Command::Report { mailbox, report } => {
                s.reports.push((mailbox.to_string(), report.to_string()));
                ok_response(OkResponse::new().with("id", "r7k2qm"))
            }
            _ => err_response(risala_proto::error::ErrorCode::NotSupported),
        }
    }
}

fn proto_hex(h: &risala_mls::file::BlobRef) -> String {
    crate::client::files::proto_ref(h).hex()
}

impl FileHttps for Remote {
    fn put<'a>(
        &'a self,
        url: &'a str,
        body: &'a [u8],
    ) -> BoxFuture<'a, std::result::Result<(), HttpError>> {
        Box::pin(async move {
            let mut s = self.0.lock().unwrap();
            let (put, size) = s.puts.remove(url).ok_or(HttpError::Gone(404))?;
            if body.len() as u64 != size {
                return Err(HttpError::Status(400));
            }
            match put {
                Put::Blob(hex) => {
                    if risala_proto::names::BlobRef::of(body).hex() != hex {
                        return Err(HttpError::Status(400));
                    }
                    s.blobs.insert(hex, body.to_vec());
                }
                Put::File(get) => {
                    s.files.insert(get, body.to_vec());
                }
            }
            Ok(())
        })
    }

    fn get<'a>(
        &'a self,
        url: &'a str,
        max: usize,
    ) -> BoxFuture<'a, std::result::Result<Vec<u8>, HttpError>> {
        Box::pin(async move {
            let s = self.0.lock().unwrap();
            let body = if let Some(hex) = url.strip_prefix(&format!("{FILES}/b/")) {
                s.blobs.get(hex).cloned()
            } else {
                s.files.get(url).cloned()
            };
            let body = body.ok_or(HttpError::Gone(404))?;
            if body.len() > max {
                return Err(HttpError::TooLarge);
            }
            Ok(body)
        })
    }

    fn delete<'a>(&'a self, url: &'a str) -> BoxFuture<'a, std::result::Result<(), HttpError>> {
        Box::pin(async move {
            let mut s = self.0.lock().unwrap();
            let get = s.dels.remove(url).ok_or(HttpError::Gone(404))?;
            s.files.remove(&get);
            Ok(())
        })
    }
}

/// [`Commands`] for one device: the area's commands go to [`Remote`].
struct DeviceCommands {
    remote: Remote,
    uid: String,
}

impl Commands for DeviceCommands {
    fn request<'a>(
        &'a self,
        _target: Target,
        command: Command,
    ) -> BoxFuture<'a, crate::client::Result<Response>> {
        Box::pin(async move { Ok(self.remote.handle(&self.uid, command)) })
    }
}

// ---------------------------------------------------------------------------
// Devices

/// A test device's hooks: its device key, every leaf confirmed, and this
/// area's lines.
struct C4Hooks {
    key: SigningKey,
    clock: ManualClock,
}

impl Hooks for C4Hooks {
    fn device_key(&self, _: AccountId, _: &Uid) -> Option<SigningKey> {
        Some(SigningKey::from_seed(*self.key.seed()))
    }

    fn leaf_confirmed(&self, _: &Tx<'_>, _: ConversationId, _: &LeafRow) -> bool {
        true
    }

    fn content_line(
        &self,
        tx: &mut Tx<'_>,
        conv: ConversationId,
        leaf: &LeafRow,
        line: &ContentLine,
    ) -> Vec<Action> {
        let now = crate::clock::Clock::now(&self.clock).unix_millis();
        content_line(tx, conv, leaf, line, now).unwrap()
    }

    fn posts_expired(
        &self,
        tx: &mut Tx<'_>,
        account: AccountId,
        mailbox: &BoxName,
        after: u64,
        before: u64,
    ) -> Vec<Action> {
        let now = crate::clock::Clock::now(&self.clock).unix_millis();
        posts_expired(tx, account, mailbox, after, Some(before), now).unwrap()
    }
}

struct Device {
    name: &'static str,
    uid: Uid,
    store: Store,
    account: AccountId,
    engine: ConversationEngine,
    device_id: [u8; 48],
    keys: Arc<MemoryKeyStore>,
    online: bool,
    events: Vec<crate::client::Event>,
}

enum Owned {
    Ready(Slot, ConnectionKind),
    Line(Slot, ServerMessage),
    Reply(Slot, Token, Response),
    Tick,
}

struct Net {
    server: FakeServer,
    remote: Remote,
    devices: Vec<Device>,
    queue: VecDeque<(usize, Owned)>,
    clock: ManualClock,
    downloads: tempfile::TempDir,
}

impl Net {
    fn new() -> Net {
        Net {
            server: FakeServer::new(START),
            remote: Remote::default(),
            devices: Vec::new(),
            queue: VecDeque::new(),
            clock: ManualClock::new(START),
            downloads: tempfile::tempdir().unwrap(),
        }
    }

    /// A device of `uid`. The identity rows of 4.4 that C1 keeps are
    /// written here: this device's, and every device of the identity on
    /// every device of it.
    fn device(&mut self, name: &'static str, uid: &str) -> usize {
        let uid: Uid = uid.parse().unwrap();
        let store = Store::open_in_memory().unwrap();
        let addr: crate::addr::ServerAddr = "chat.example.org".parse().unwrap();
        let account = store
            .add_account(&addr, AccountKind::Identity, &uid)
            .unwrap();
        let key = SigningKey::generate().unwrap();
        let device_id = risala_mls::identity::DeviceId::of_device_key(key.public_key()).0;
        let hooks = Arc::new(C4Hooks {
            key,
            clock: self.clock.clone(),
        });
        let engine = ConversationEngine::new(
            Config {
                self_conversation: false,
                ..Config::immediate()
            },
            hooks,
            Arc::new(self.clock.clone()),
        );
        let d = self.devices.len();
        self.server
            .signed_in
            .insert((d, Slot::SignedIn), (uid.to_string(), device_id.to_vec()));
        store
            .write(|tx| {
                tx.conn().execute(
                    "INSERT INTO identities (uid, device_id, key_id, created) VALUES (?1, ?2, ?1, 0)",
                    rusqlite::params![uid.as_str(), &device_id[..]],
                )?;
                Ok(())
            })
            .unwrap();
        self.devices.push(Device {
            name,
            uid: uid.clone(),
            store,
            account,
            engine,
            device_id,
            keys: Arc::new(MemoryKeyStore::default()),
            online: false,
            events: Vec::new(),
        });
        // Every device of the identity knows every other (4.4).
        let same: Vec<usize> = (0..self.devices.len())
            .filter(|&o| self.devices[o].uid == uid)
            .collect();
        for &o in &same {
            for &p in &same {
                let (id, label) = (self.devices[p].device_id, self.devices[p].name);
                self.devices[o]
                    .store
                    .write(|tx| {
                        tx.conn().execute(
                            "INSERT OR IGNORE INTO devices
                                 (uid, device_id, device_key, attestation_key, label, added_by)
                             VALUES (?1, ?2, x'00', x'00', ?3, x'00')",
                            rusqlite::params![uid.as_str(), &id[..], label],
                        )?;
                        Ok(())
                    })
                    .unwrap();
            }
        }
        d
    }

    fn connect(&mut self, d: usize) {
        self.devices[d].online = true;
        self.queue
            .push_back((d, Owned::Ready(Slot::SignedIn, ConnectionKind::SignedIn)));
        self.queue.push_back((
            d,
            Owned::Ready(Slot::Anonymous(0), ConnectionKind::Anonymous),
        ));
        self.run();
    }

    fn disconnect(&mut self, d: usize) {
        self.devices[d].online = false;
        self.server.close((d, Slot::Anonymous(0)));
        let cx = self.cx(d);
        for slot in [Slot::Anonymous(0), Slot::SignedIn] {
            self.devices[d].engine.handle(&cx, &Input::Closed { slot });
        }
    }

    fn cx(&self, d: usize) -> Context {
        Context {
            store: self.devices[d].store.clone(),
            account: self.devices[d].account,
        }
    }

    fn run(&mut self) {
        let mut steps = 0;
        while let Some((d, owned)) = self.queue.pop_front() {
            steps += 1;
            assert!(steps < 100_000, "the network does not settle");
            if !self.devices[d].online {
                continue;
            }
            let cx = self.cx(d);
            let input = match &owned {
                Owned::Ready(slot, kind) => Input::Ready {
                    slot: *slot,
                    kind: *kind,
                },
                Owned::Line(slot, message) => Input::Line {
                    slot: *slot,
                    message,
                },
                Owned::Reply(slot, token, response) => Input::Reply {
                    slot: *slot,
                    token: *token,
                    response,
                },
                Owned::Tick => Input::Tick {
                    now: crate::clock::Clock::now(&self.clock),
                },
            };
            let actions = self.devices[d].engine.handle(&cx, &input);
            self.act(d, actions);
        }
    }

    fn act(&mut self, d: usize, actions: Vec<Action>) {
        for action in actions {
            match action {
                Action::Send {
                    target,
                    command,
                    token,
                } => {
                    let slot = match target {
                        Target::SignedIn => Slot::SignedIn,
                        Target::Mailbox(_) | Target::Conversing => Slot::Anonymous(0),
                        Target::Watch => Slot::Watch,
                        Target::Own(_) => SINGLE_USE_SLOT,
                    };
                    self.server.now = crate::clock::Clock::now(&self.clock).unix_millis();
                    let (response, live) = self.server.handle((d, slot), command);
                    for ((to, s), line) in live {
                        self.queue.push_back((to, Owned::Line(s, line)));
                    }
                    self.queue
                        .push_back((d, Owned::Reply(slot, token, response)));
                }
                Action::Emit(event) => self.devices[d].events.push(event),
            }
        }
    }

    fn tick(&mut self) {
        for d in 0..self.devices.len() {
            self.queue.push_back((d, Owned::Tick));
        }
        self.run();
    }

    fn job(&mut self, d: usize, job: Job) -> ConversationId {
        let cx = self.cx(d);
        let (id, actions) = self.devices[d].engine.start(&cx, job);
        self.act(d, actions);
        self.run();
        self.tick();
        for event in &self.devices[d].events {
            if let crate::client::Event::Conversation(
                crate::client::conversations::ConversationEvent::JobDone {
                    job,
                    conversation: Some(c),
                    error: None,
                },
            ) = event
                && *job == id
            {
                return *c;
            }
        }
        panic!("{}: the job did not finish", self.devices[d].name);
    }

    fn same_conv(&self, d: usize, other: usize, conv: ConversationId) -> Option<ConversationId> {
        let group = self.devices[other]
            .store
            .conversation_row(conv)
            .unwrap()
            .unwrap()
            .group_id;
        self.devices[d]
            .store
            .conversation_rows(self.devices[d].account)
            .unwrap()
            .into_iter()
            .find(|c| c.group_id == group && c.state == ConvState::Active)
            .map(|c| c.id)
    }

    fn lines(&mut self, d: usize, conv: ConversationId, lines: Vec<ContentLine>) -> [u8; 16] {
        let uid = self.devices[d].uid.clone();
        let now = crate::clock::Clock::now(&self.clock).unix_millis();
        let id = self.devices[d]
            .store
            .write_with(|tx| content::queue_lines(tx, conv, &uid, lines, false, now))
            .unwrap()
            .0;
        self.queue.push_back((d, Owned::Tick));
        self.run();
        id
    }

    fn say(&mut self, d: usize, conv: ConversationId, text: &str) -> [u8; 16] {
        self.lines(d, conv, vec![ContentLine::Text(Text::new(text))])
    }

    fn texts(&self, d: usize, conv: ConversationId) -> Vec<String> {
        self.devices[d]
            .store
            .message_rows(conv)
            .unwrap()
            .into_iter()
            .filter_map(|m| m.text)
            .collect()
    }

    fn jobs(&self, d: usize) -> Jobs {
        let dev = &self.devices[d];
        Jobs {
            store: dev.store.clone(),
            account: dev.account,
            server: "chat.example.org".into(),
            uid: dev.uid.clone(),
            commands: Arc::new(DeviceCommands {
                remote: self.remote.clone(),
                uid: dev.uid.to_string(),
            }),
            https: Arc::new(self.remote.clone()),
            clock: Arc::new(self.clock.clone()),
            keys: dev.keys.clone(),
            events: broadcast::channel(1024).0,
            downloads: self.downloads.path().join(dev.name),
            max_blob: ARCHIVE_BLOB,
        }
    }

    /// Alice's two devices and Bob, all connected, with Alice's
    /// conversation with herself and a direct conversation with Bob.
    fn alice_bob() -> (Net, [usize; 3], ConversationId) {
        let mut net = Net::new();
        let a1 = net.device("alice1", "alice@example.org");
        let a2 = net.device("alice2", "alice@example.org");
        let b = net.device("bob", "bob@example.net");
        for d in [a1, a2, b] {
            net.connect(d);
        }
        let me = net.job(a1, Job::WithYourself);
        net.same_conv(a2, a1, me).expect("alice2 is in it");
        let conv = net.job(
            a1,
            Job::Direct {
                peer: "bob@example.net".parse().unwrap(),
            },
        );
        (net, [a1, a2, b], conv)
    }
}

// ---------------------------------------------------------------------------
// History transfer for a gap (12.13)

#[test]
fn a_gap_is_filled_by_another_device_with_want_and_transfer() {
    let (mut net, [a1, a2, b], conv) = Net::alice_bob();
    let c2 = net.same_conv(a2, a1, conv).unwrap();
    let cb = net.same_conv(b, a1, conv).unwrap();
    net.say(b, cb, "one");
    net.say(b, cb, "two");
    assert_eq!(net.texts(a2, c2), ["one", "two"]);

    // Alice's second device goes away; three more posts arrive, and expire
    // before it comes back (7.4).
    net.disconnect(a2);
    net.say(b, cb, "three");
    net.say(b, cb, "four");
    net.say(b, cb, "five");
    let seqs: Vec<u64> = net.devices[a1]
        .store
        .message_rows(conv)
        .unwrap()
        .iter()
        .filter_map(|m| m.seq)
        .collect();
    let seq_of = |i: usize| seqs[i];
    let mailbox = net.devices[a2].store.mailbox_rows(c2).unwrap()[0].mailbox;
    let account = net.devices[a2].account;
    let now = crate::clock::Clock::now(&net.clock).unix_millis();
    // It asks for the posts after "two" and before "five", as the group
    // engine does when FETCH shows them gone (7.4, 12.13).
    let (after, before) = (seq_of(1), seq_of(4));
    net.devices[a2]
        .store
        .write_with(|tx| {
            tx.set_sync(c2, &mailbox, before, None)?;
            posts_expired(tx, account, &mailbox, after, Some(before), now)
        })
        .unwrap();
    assert_eq!(
        net.devices[a2].store.want_rows(account).unwrap(),
        [(
            mailbox.to_string(),
            WantRange {
                after,
                before: Some(before)
            }
        )]
    );
    net.connect(a2);
    net.tick();
    // Alice's first device got the WANT, and answers it.
    let a1_account = net.devices[a1].account;
    let requests = net.devices[a1]
        .store
        .write(|tx| tx.want_requests(a1_account))
        .unwrap()
        .0;
    assert_eq!(requests.len(), 1);
    block_on(net.jobs(a1).answer_wants()).unwrap();
    net.tick();
    // The second device has the TRANSFER, fetches it and applies it.
    let transfers = net.devices[a2].store.transfer_rows(account).unwrap();
    assert_eq!(transfers.len(), 1);
    assert_eq!(transfers[0].from_label.as_deref(), Some("alice1"));
    block_on(net.jobs(a2).fetch_transfers()).unwrap();
    // "three" and "four" lie in the range; "five" came from the server
    // after the sync point.
    let texts = net.texts(a2, c2);
    assert!(texts.contains(&"three".to_owned()), "{texts:?}");
    assert!(texts.contains(&"four".to_owned()), "{texts:?}");
    let rows = net.devices[a2].store.message_rows(c2).unwrap();
    let three = rows
        .iter()
        .find(|m| m.text.as_deref() == Some("three"))
        .unwrap();
    // Shown as copied, by the sending device's label, and its verification
    // as its word, not this device's (12.13).
    assert!(three.restored);
    assert!(!three.verified);
    assert_eq!(
        net.devices[a2]
            .store
            .message_origin(c2, &three.message_id)
            .unwrap(),
        Origin::Copied {
            device: Some(net.devices[a1].device_id),
            label: Some("alice1".into())
        }
    );
    // Held messages are not touched: "one" is still the one from the
    // server.
    let one = rows
        .iter()
        .find(|m| m.text.as_deref() == Some("one"))
        .unwrap();
    assert!(!one.restored);
    assert_eq!(
        transfers[0].state, "pending",
        "the row was read before the fetch"
    );
    assert_eq!(
        net.devices[a2].store.transfer_rows(account).unwrap()[0].state,
        "done"
    );
}

#[test]
fn transfers_nobody_asked_for_are_ignored() {
    let (mut net, [a1, a2, _b], conv) = Net::alice_bob();
    net.say(a1, conv, "history");
    let me = net
        .same_conv(a1, a2, {
            let a2_account = net.devices[a2].account;
            net.devices[a2]
                .store
                .conversation_rows(a2_account)
                .unwrap()
                .into_iter()
                .find(|c| c.kind == ConvKind::WithYourself)
                .unwrap()
                .id
        })
        .unwrap();
    let stored = block_on(net.jobs(a1).store_transfer_for_tests()).unwrap();
    net.lines(
        a1,
        me,
        vec![ContentLine::Transfer(
            risala_proto::content::TransferRef::from_bytes(stored.try_into().unwrap()),
        )],
    );
    // 12.13: after pairing, only answers to WANTs this device sent.
    let account = net.devices[a2].account;
    assert!(
        net.devices[a2]
            .store
            .transfer_rows(account)
            .unwrap()
            .is_empty()
    );
}

/// Applies an archived conversation to a device's own copy of the group,
/// as a transfer for a WANT would.
fn apply_want(
    net: &Net,
    d: usize,
    _conv: ConversationId,
    archived: ArchivedConversation,
) -> Applied {
    let account = net.devices[d].account;
    let now = crate::clock::Clock::now(&net.clock).unix_millis();
    net.devices[d]
        .store
        .write_with(|tx| {
            apply(
                tx,
                account,
                &[archived],
                &[],
                &Source::Want {
                    device: None,
                    label: Some("other".into()),
                },
                now,
            )
        })
        .unwrap()
        .0
}

#[test]
fn transfers_apply_only_asked_ranges_and_never_replace() {
    let (mut net, [a1, a2, b], conv) = Net::alice_bob();
    let c2 = net.same_conv(a2, a1, conv).unwrap();
    let cb = net.same_conv(b, a1, conv).unwrap();
    net.say(b, cb, "one");
    let account = net.devices[a1].account;
    // What Alice's first device would send for the whole conversation.
    let mut archived = net.devices[a1]
        .store
        .write_with(|tx| collect(tx, account, &Selection::All, false))
        .unwrap()
        .0
        .conversations
        .into_iter()
        .find(|c| {
            c.messages
                .iter()
                .any(|m| m.seq > 0 && !m.content.is_empty())
                && {
                    let group = net.devices[a1]
                        .store
                        .conversation_row(conv)
                        .unwrap()
                        .unwrap()
                        .group_id;
                    c.group_id == group
                }
        })
        .unwrap();
    // A forged message beside the real one, with seq 50, and an edit of
    // the held message with a new id.
    let mut forged = archived.messages[0].clone();
    forged.message_id = [9; 16];
    forged.seq = 50;
    forged.content =
        risala_proto::content::Content::new(vec![ContentLine::Text(Text::new("not asked for"))])
            .unwrap()
            .as_bytes()
            .to_vec();
    archived.messages.push(forged);

    // Nothing asked: nothing applied.
    let a2_account = net.devices[a2].account;
    assert_eq!(apply_want(&net, a2, c2, archived.clone()).messages, 0);
    // Asked for 40 to 60: only the message at 50.
    let mailbox = BoxName::from_bytes(archived.mailbox).to_string();
    net.devices[a2]
        .store
        .write(|tx| {
            tx.add_want(
                a2_account,
                &mailbox,
                WantRange {
                    after: 40,
                    before: Some(60),
                },
                0,
            )
        })
        .unwrap();
    assert_eq!(apply_want(&net, a2, c2, archived.clone()).messages, 1);
    assert_eq!(net.texts(a2, c2), ["one", "not asked for"]);
    // Asked for everything: the held message is skipped, never replaced.
    net.devices[a2]
        .store
        .write(|tx| {
            tx.add_want(
                a2_account,
                &mailbox,
                WantRange {
                    after: 0,
                    before: None,
                },
                0,
            )
        })
        .unwrap();
    let mut changed = archived.clone();
    changed.messages[0].content =
        risala_proto::content::Content::new(vec![ContentLine::Text(Text::new("changed"))])
            .unwrap()
            .as_bytes()
            .to_vec();
    assert_eq!(apply_want(&net, a2, c2, changed).messages, 0);
    assert_eq!(net.texts(a2, c2), ["one", "not asked for"]);
    // A conversation the device is not in is not applied.
    let mut other = archived;
    other.group_id = vec![7; 32];
    other.messages[1].message_id = [8; 16];
    assert_eq!(apply_want(&net, a2, c2, other), Applied::default());
}

// ---------------------------------------------------------------------------
// Files (5.6, 12.11)

#[test]
fn files_are_shared_fetched_checked_and_deleted() {
    let (mut net, [a1, _a2, b], conv) = Net::alice_bob();
    let cb = net.same_conv(b, a1, conv).unwrap();
    let photo: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
    let id = block_on(
        net.jobs(a1)
            .send_file(conv, &photo, "photo.png", None, Some("image/png")),
    )
    .unwrap();
    net.tick();
    // UPLOAD went with the group's token; the encrypted file is on the
    // server, padded (12.11).
    let stored: Vec<Vec<u8>> = net
        .remote
        .0
        .lock()
        .unwrap()
        .files
        .values()
        .cloned()
        .collect();
    assert_eq!(stored.len(), 1);
    assert_eq!(
        stored[0].len() as u64,
        risala_mls::file::encrypted_len(photo.len() as u64).unwrap()
    );
    // Bob's device received the TEXT line with the file's tags.
    assert_eq!(net.texts(b, cb), ["photo.png"]);
    let info = block_on(net.jobs(b).fetch_file(cb, &id, false)).unwrap();
    assert!(info.on_server);
    assert_eq!(info.media_type.as_deref(), Some("image/png"));
    assert_eq!(std::fs::read(info.path.unwrap()).unwrap(), photo);

    // A file swapped on the server fails the hash, and nothing is saved.
    {
        let mut s = net.remote.0.lock().unwrap();
        let url = s.files.keys().next().unwrap().clone();
        s.files.get_mut(&url).unwrap()[100] ^= 1;
    }
    let jobs = net.jobs(b);
    let err = block_on(jobs.fetch_file(cb, &id, false)).unwrap_err();
    assert!(
        matches!(
            err,
            crate::client::Error::Transfer(TransferError::HashMismatch)
        ),
        "{err}"
    );

    // Deleting the message deletes the file (5.6).
    net.lines(
        a1,
        conv,
        vec![ContentLine::Delete {
            id: risala_proto::content::MessageId::from_bytes(id),
        }],
    );
    block_on(net.jobs(a1).delete_files()).unwrap();
    assert!(net.remote.0.lock().unwrap().files.is_empty());
    let row = net.devices[a1].store.file_row(conv, &id).unwrap().unwrap();
    assert_eq!(row.state, "deleted");
    assert!(
        net.devices[a1]
            .store
            .files_to_delete(net.devices[a1].account)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn files_off_the_servers_origins_need_the_user() {
    let (mut net, [a1, _a2, b], conv) = Net::alice_bob();
    let cb = net.same_conv(b, a1, conv).unwrap();
    // A file on another host, as any member can share.
    let encrypted = risala_mls::file::encrypt(risala_mls::file::Label::File, b"hello").unwrap();
    let url = "https://elsewhere.example/f/1";
    net.remote
        .0
        .lock()
        .unwrap()
        .files
        .insert(url.into(), encrypted.upload.clone());
    let line = ContentLine::Text(Text {
        text: "hello.txt".into(),
        target: None,
        file: Some(risala_proto::content::FileRef {
            url: url.parse().unwrap(),
            key: risala_proto::content::FileKey::from_bytes(*encrypted.key.as_bytes()),
            hash: risala_proto::content::FileHash::from_bytes(*encrypted.hash.as_bytes()),
            media_type: None,
            size: Some(5),
        }),
    });
    let id = net.lines(a1, conv, vec![line]);
    let err = block_on(net.jobs(b).fetch_file(cb, &id, false)).unwrap_err();
    assert!(
        matches!(
            err,
            crate::client::Error::Transfer(TransferError::OtherHost(_))
        ),
        "{err}"
    );
    // Once the user agrees (12.11).
    let info = block_on(net.jobs(b).fetch_file(cb, &id, true)).unwrap();
    assert!(!info.on_server);
    assert_eq!(std::fs::read(info.path.unwrap()).unwrap(), b"hello");
}

// ---------------------------------------------------------------------------
// Transfer at pairing (4.8, 12.13)

#[test]
fn a_new_device_gets_history_and_files_at_pairing() {
    let (mut net, [a1, _a2, b], conv) = Net::alice_bob();
    let cb = net.same_conv(b, a1, conv).unwrap();
    net.say(b, cb, "before the new device");
    let file = b"a file that travels with history".to_vec();
    let id = block_on(
        net.jobs(b)
            .send_file(cb, &file, "notes.txt", Some("my notes"), None),
    )
    .unwrap();
    net.tick();
    block_on(net.jobs(a1).fetch_file(conv, &id, false)).unwrap();

    // The old device builds the transfer for the IdentityBundle.
    let reference = block_on(net.jobs(a1).store_transfer_for_tests()).unwrap();
    // The new device keeps it, and fetches it: it is in no group yet.
    let a3 = net.device("alice3", "alice@example.org");
    net.connect(a3);
    let account = net.devices[a3].account;
    let device = net.devices[a1].device_id;
    let now = crate::clock::Clock::now(&net.clock).unix_millis();
    net.devices[a3]
        .store
        .write(|tx| {
            tx.add_transfer(
                account,
                TransferKind::Pairing,
                &reference,
                Some(&device),
                Some("alice1"),
                now,
            )
        })
        .unwrap();
    block_on(net.jobs(a3).fetch_transfers()).unwrap();
    let row = &net.devices[a3].store.transfer_rows(account).unwrap()[0];
    assert_eq!(row.state, "waiting");

    // The old device adds it to the conversation (12.7); the kept history
    // is applied, shown as copied.
    net.job(
        a1,
        Job::Invite {
            conv,
            uids: vec!["alice@example.org".parse().unwrap()],
        },
    );
    let c3 = net.same_conv(a3, a1, conv).expect("alice3 was added");
    net.jobs(a3).apply_waiting().unwrap();
    let texts = net.texts(a3, c3);
    assert!(
        texts.contains(&"before the new device".to_owned()),
        "{texts:?}"
    );
    assert!(texts.contains(&"my notes".to_owned()), "{texts:?}");
    assert_eq!(
        net.devices[a3].store.transfer_rows(account).unwrap()[0].state,
        "done"
    );
    // The file is read from the blob the transfer listed, not its URL.
    net.remote.0.lock().unwrap().files.clear();
    let info = block_on(net.jobs(a3).fetch_file(c3, &id, false)).unwrap();
    assert_eq!(std::fs::read(info.path.unwrap()).unwrap(), file);
}

// ---------------------------------------------------------------------------
// Backups (12.13)

fn give_backup_key(net: &Net, d: usize, recovery: &RecoveryKey, generation: u32) {
    let dev = &net.devices[d];
    let uid: Identity = dev.uid.as_str().parse().unwrap();
    let key = recovery.backup_key(&uid, generation);
    dev.keys
        .save(
            &format!("{}.backup", dev.uid),
            &risala_proto::auth::SecretKey::from_seed(*key.as_bytes()),
        )
        .unwrap();
    dev.store
        .write(|tx| {
            tx.conn()
                .execute("UPDATE identities SET backup_generation = ?1", [generation])?;
            Ok(())
        })
        .unwrap();
}

#[test]
fn backups_are_made_daily_and_on_a_new_generation_and_restored() {
    let (mut net, [a1, _a2, b], conv) = Net::alice_bob();
    let cb = net.same_conv(b, a1, conv).unwrap();
    net.say(b, cb, "keep this");
    let id = block_on(net.jobs(b).send_file(cb, b"attached", "a.txt", None, None)).unwrap();
    net.tick();
    block_on(net.jobs(a1).fetch_file(conv, &id, false)).unwrap();
    let recovery = RecoveryKey::generate().unwrap();
    give_backup_key(&net, a1, &recovery, 0);
    let uid = "alice@example.org";

    // Off: nothing.
    block_on(net.jobs(a1).backup_if_due()).unwrap();
    assert!(net.remote.0.lock().unwrap().backups.is_empty());
    net.devices[a1]
        .store
        .set_setting(&format!("backups.{uid}"), Some("on"))
        .unwrap();
    block_on(net.jobs(a1).backup_if_due()).unwrap();
    let first = net.remote.0.lock().unwrap().backups[uid].clone();
    assert_eq!(first.0, 0);
    // The file's blob is listed (12.13).
    let list = first.3.clone().expect("files= with the file's blob");
    let list_bytes =
        net.remote.0.lock().unwrap().blobs[list.strip_prefix("sha384:").unwrap()].clone();
    assert_eq!(risala_mls::backup::read_list(&list_bytes).unwrap().len(), 1);
    // At most once a day.
    block_on(net.jobs(a1).backup_if_due()).unwrap();
    assert_eq!(net.remote.0.lock().unwrap().backups[uid], first);
    net.clock.advance(BACKUP_DAY);
    block_on(net.jobs(a1).backup_if_due()).unwrap();
    let second = net.remote.0.lock().unwrap().backups[uid].clone();
    assert_ne!(second.1, first.1);
    // The file's blob is reused: the list names the same blob.
    assert_eq!(second.3, first.3);

    // Restoring on a recovered device (generation 1 now): the backup of
    // generation 0, read with the recovery key.
    let a4 = net.device("alice4", uid);
    net.connect(a4);
    give_backup_key(&net, a4, &recovery, 1);
    let restored = block_on(net.jobs(a4).restore(&recovery.to_display())).unwrap();
    assert!(restored.waiting >= 1, "{restored:?}");
    assert_eq!(restored.made.unix_millis(), START + BACKUP_DAY);
    // The wrong recovery key does not open it.
    let a5 = net.device("alice5", uid);
    give_backup_key(&net, a5, &recovery, 1);
    let wrong = RecoveryKey::generate().unwrap();
    let err = block_on(net.jobs(a5).restore(&wrong.to_display())).unwrap_err();
    assert!(
        matches!(
            err,
            crate::client::Error::Transfer(TransferError::Unreadable(_))
        ),
        "{err}"
    );

    // A new generation: a new backup at once, under its key.
    give_backup_key(&net, a1, &recovery, 1);
    block_on(net.jobs(a1).backup_if_due()).unwrap();
    let third = net.remote.0.lock().unwrap().backups[uid].clone();
    assert_eq!(third.0, 1);
    // A device that may restore only generation 0 refuses it: the
    // generation comes from the chain, not the server (12.13).
    let err = block_on(net.jobs(a5).restore(&recovery.to_display())).unwrap_err();
    assert!(
        matches!(err, crate::client::Error::Transfer(TransferError::NoBackup)),
        "{err}"
    );
}

const BACKUP_DAY: u64 = crate::client::backups::BACKUP_EVERY_MS;

#[test]
fn restored_conversations_wait_for_the_device_to_join() {
    let (mut net, [a1, _a2, b], conv) = Net::alice_bob();
    let cb = net.same_conv(b, a1, conv).unwrap();
    net.say(b, cb, "from before");
    let recovery = RecoveryKey::generate().unwrap();
    give_backup_key(&net, a1, &recovery, 0);
    block_on(net.jobs(a1).backup_now()).unwrap();
    let a3 = net.device("alice3", "alice@example.org");
    net.connect(a3);
    give_backup_key(&net, a3, &recovery, 1);
    block_on(net.jobs(a3).restore(&recovery.to_display())).unwrap();
    net.job(
        a1,
        Job::Invite {
            conv,
            uids: vec!["alice@example.org".parse().unwrap()],
        },
    );
    let c3 = net.same_conv(a3, a1, conv).unwrap();
    net.jobs(a3).apply_waiting().unwrap();
    let rows = net.devices[a3].store.message_rows(c3).unwrap();
    let old = rows
        .iter()
        .find(|m| m.text.as_deref() == Some("from before"))
        .expect("restored");
    assert!(matches!(
        net.devices[a3]
            .store
            .message_origin(c3, &old.message_id)
            .unwrap(),
        Origin::Restored { .. }
    ));
}

// ---------------------------------------------------------------------------
// Reports (5.8)

#[test]
fn reports_reach_the_rooms_moderators_only() {
    let (mut net, [a1, a2, b], _conv) = Net::alice_bob();
    // Alice owns a room with Bob in it.
    let room = net.job(
        a1,
        Job::PrivateRoom {
            name: "garden".into(),
            members: vec!["bob@example.net".parse().unwrap()],
        },
    );
    let rb = net.same_conv(b, a1, room).unwrap();
    let bad = net.say(a1, room, "something bad");
    let earlier = net.say(b, rb, "earlier");
    let mailbox = net.devices[b].store.mailbox_rows(rb).unwrap()[0].mailbox;
    // Bob reports it in his direct conversation with Alice.
    let direct = net.same_conv(b, a1, _conv).unwrap();
    net.lines(
        b,
        direct,
        vec![ContentLine::Report(risala_proto::content::Report {
            mailbox,
            target: risala_proto::content::MessageId::from_bytes(bad),
            context: vec![risala_proto::content::MessageId::from_bytes(earlier)],
            reason: "not\\snice".into(),
        })],
    );
    for d in [a1, a2] {
        let account = net.devices[d].account;
        let reports = net.devices[d].store.report_rows(account).unwrap();
        assert_eq!(reports.len(), 1, "{}", net.devices[d].name);
        assert_eq!(reports[0].reporter, "bob@example.net");
        assert_eq!(reports[0].target, bad);
        assert_eq!(reports[0].context, [earlier]);
    }

    // A room where Alice is no moderator: Bob's report to her is ignored.
    let bobs = net.job(
        b,
        Job::PrivateRoom {
            name: "bob's".into(),
            members: vec!["alice@example.org".parse().unwrap()],
        },
    );
    let m2 = net.devices[b].store.mailbox_rows(bobs).unwrap()[0].mailbox;
    let target = net.say(b, bobs, "hi");
    net.lines(
        b,
        direct,
        vec![ContentLine::Report(risala_proto::content::Report {
            mailbox: m2,
            target: risala_proto::content::MessageId::from_bytes(target),
            context: Vec::new(),
            reason: String::new(),
        })],
    );
    let account = net.devices[a1].account;
    assert_eq!(net.devices[a1].store.report_rows(account).unwrap().len(), 1);
}

#[test]
fn reports_to_operators_carry_franked_posts() {
    let (mut net, [a1, _a2, b], conv) = Net::alice_bob();
    let cb = net.same_conv(b, a1, conv).unwrap();
    let mut ids = Vec::new();
    for i in 0..12 {
        ids.push(net.say(a1, conv, &format!("message {i}")));
    }
    let rows = net.devices[b].store.message_rows(cb).unwrap();
    let target = rows.iter().find(|r| r.message_id == ids[11]).unwrap();
    // Context out of order, with the target itself and a later message
    // left out.
    let context: Vec<crate::client::types::MessageId> = [ids[3], ids[1], ids[2]]
        .iter()
        .map(|i| crate::client::types::MessageId(*i))
        .collect();
    let report = crate::client::reports::operator_report(&rows, target, &context, "spam").unwrap();
    let seqs: Vec<u64> = report.context.iter().map(|p| p.seq).collect();
    assert!(seqs.windows(2).all(|w| w[0] < w[1]));
    assert_eq!(seqs.len(), 3);
    assert_eq!(report.author.as_str(), "alice@example.org");
    // The server's check (5.8): each post is kept, and its RisalaAAD's
    // frank matches the reported content under the reported frank key.
    let mailbox = net.devices[b].store.mailbox_rows(cb).unwrap()[0].mailbox;
    let (response, _) = net.server.handle(
        (b, Slot::Anonymous(0)),
        Command::Fetch {
            mailbox,
            after: 0,
            limit: None,
            leaf: None,
        },
    );
    let posts: HashMap<u64, Vec<u8>> = response
        .lines
        .iter()
        .filter_map(|l| match &l.line {
            risala_proto::server::ServerLine::Post(p) => match &p.message {
                risala_proto::mls::OrBlob::Inline(m) => Some((p.seq?.get(), m.decode())),
                risala_proto::mls::OrBlob::Blob(_) => None,
            },
            _ => None,
        })
        .collect();
    assert_eq!(
        risala_mls::message::verify_report(&report, |seq| posts.get(&seq).cloned()),
        Ok(())
    );
    // Content that was not posted fails the frank.
    let mut forged = report.clone();
    forged.target.content = b"TEXT something else\n".to_vec();
    assert!(risala_mls::message::verify_report(&forged, |seq| posts.get(&seq).cloned()).is_err());
    assert_eq!(
        risala_mls::message::RisalaReport::decode(&report.encode()).unwrap(),
        report
    );
}

// ---------------------------------------------------------------------------
// Push (Section 9)

/// Encrypts `plain` to a subscription as a server does (RFC 8291, 9.3):
/// one record, padded to 128 bytes, under a fresh key and salt.
fn push_body(plain: &[u8], ua_public: &[u8], auth: &[u8]) -> Vec<u8> {
    use aws_lc_rs::{aead, agreement, hmac};
    let hmac256 = |key: &[u8], parts: &[&[u8]]| -> Vec<u8> {
        let mut ctx = hmac::Context::with_key(&hmac::Key::new(hmac::HMAC_SHA256, key));
        for p in parts {
            ctx.update(p);
        }
        ctx.sign().as_ref().to_vec()
    };
    let private = agreement::PrivateKey::generate(&agreement::ECDH_P256).unwrap();
    let as_public = private.compute_public_key().unwrap();
    let salt = [7u8; 16];
    let ecdh = agreement::agree(
        &private,
        agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, ua_public),
        (),
        |s| Ok(s.to_vec()),
    )
    .unwrap();
    let prk_key = hmac256(auth, &[&ecdh]);
    let ikm = hmac256(
        &prk_key,
        &[b"WebPush: info\0", ua_public, as_public.as_ref(), &[1]],
    );
    let prk = hmac256(&salt, &[&ikm]);
    let cek = hmac256(&prk, &[b"Content-Encoding: aes128gcm\0", &[1]]);
    let nonce = hmac256(&prk, &[b"Content-Encoding: nonce\0", &[1]]);
    let key =
        aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &cek[..16]).unwrap());
    let mut record = plain.to_vec();
    record.push(2);
    record.resize(128, 0);
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(nonce[..12].try_into().unwrap()),
        aead::Aad::empty(),
        &mut record,
    )
    .unwrap();
    let mut body = salt.to_vec();
    body.extend_from_slice(&4096u32.to_be_bytes());
    body.push(65);
    body.extend_from_slice(as_public.as_ref());
    body.extend_from_slice(&record);
    body
}

fn b64url(s: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .unwrap()
}

/// RFC 8291, Section 5: the example push decrypts.
#[test]
fn push_bodies_decrypt_as_rfc_8291_says() {
    let body = b64url(
        "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN",
    );
    let ua_private = b64url("q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94");
    let auth = b64url("BTBZMqHH6r4Tts7J_aSIgg");
    assert_eq!(
        crate::client::push::decrypt(&body, &ua_private, &auth).unwrap(),
        b"When I grow up, I want to be a watermelon"
    );
    assert!(crate::client::push::decrypt(&body, &ua_private, &[0; 16]).is_none());
    let mut bad = body.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(crate::client::push::decrypt(&bad, &ua_private, &auth).is_none());
}

fn push_sends(actions: &[Action]) -> Vec<(Target, String, Token)> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::Send {
                target,
                command,
                token,
            } => Some((target.clone(), format!("{command:?}"), *token)),
            _ => None,
        })
        .collect()
}

#[test]
fn push_subscriptions_follow_the_conversations() {
    use crate::sync::Engine as _;
    use crate::sync::push::PushEngine;
    let (net, [a1, _a2, _b], conv) = Net::alice_bob();
    let cx = net.cx(a1);
    let account = cx.account;
    let mut push = PushEngine::default();
    for (slot, kind) in [
        (Slot::SignedIn, ConnectionKind::SignedIn),
        (Slot::Anonymous(0), ConnectionKind::Anonymous),
    ] {
        push.handle(&cx, &Input::Ready { slot, kind });
    }
    let tick = |net: &Net, push: &mut PushEngine| {
        net.clock.advance(10_000);
        push.handle(
            &net.cx(a1),
            &Input::Tick {
                now: crate::clock::Clock::now(&net.clock),
            },
        )
    };
    let ok = Response {
        lines: Vec::new(),
        end: End::Ok(OkResponse::new()),
    };
    // Off: nothing.
    assert!(push_sends(&tick(&net, &mut push)).is_empty());

    // On, with one URL for three subscriptions: the account's and the two
    // conversations' (Alice's own and Bob's). The app is asked for more.
    let store = net.devices[a1].store.clone();
    store
        .set_setting(&crate::sync::push::setting(account), Some("on"))
        .unwrap();
    let urls = |n: std::ops::Range<u32>| -> Vec<String> {
        n.map(|i| format!("https://push.example.net/w/{i}"))
            .collect()
    };
    store
        .write(|tx| tx.add_push_urls(account, &urls(0..1), 0))
        .unwrap();
    let actions = tick(&net, &mut push);
    let sent = push_sends(&actions);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert!(actions.iter().any(|a| matches!(
        a,
        Action::Emit(crate::client::Event::Transfer(
            crate::client::files::TransferEvent::PushUrlsNeeded { count: 2, .. }
        ))
    )));
    let mut all = sent;
    store
        .write(|tx| tx.add_push_urls(account, &urls(1..3), 0))
        .unwrap();
    all.extend(push_sends(&tick(&net, &mut push)));
    assert_eq!(all.len(), 3, "{all:?}");
    // The account's on the signed-in connection, without box; each
    // mailbox's on the connection that follows it, with box (9.1).
    let mailbox = store.mailbox_rows(conv).unwrap()[0].mailbox;
    assert!(
        all.iter()
            .any(|(t, c, _)| *t == Target::SignedIn && c.contains("mailbox: None"))
    );
    assert!(
        all.iter()
            .any(|(t, c, _)| *t == Target::Mailbox(mailbox) && c.contains(&mailbox.to_string()))
    );
    // Every subscription has its own URL and tag.
    let subs = store.subscription_rows().unwrap();
    let tags: std::collections::HashSet<_> = subs.iter().map(|s| s.tag.clone()).collect();
    assert_eq!(tags.len(), 3);
    for (_, _, token) in &all {
        push.handle(
            &cx,
            &Input::Reply {
                slot: Slot::SignedIn,
                token: *token,
                response: &ok,
            },
        );
    }
    let now = crate::clock::Clock::now(&net.clock).unix_millis();
    for s in store.subscription_rows().unwrap() {
        assert_eq!(s.state, crate::store::push::SubState::Active);
        match s.mailbox {
            // Renewed within a week, well inside retention (9.1).
            Some(_) => {
                let renew = s.renew_at.unwrap();
                assert!(renew > now && renew <= now + crate::sync::push::RENEW_MAX_MS);
            }
            None => assert_eq!(s.renew_at, None),
        }
    }
    // Nothing more to do.
    assert!(push_sends(&tick(&net, &mut push)).is_empty());

    // A push to the conversation's subscription decrypts to it (9.3).
    let sub = store
        .subscription_rows()
        .unwrap()
        .into_iter()
        .find(|s| s.mailbox.as_deref() == Some(&mailbox.to_string()))
        .unwrap();
    let client = crate::client::Client::with_store(store.clone(), Default::default());
    let body = push_body(
        format!("NOTIFY {} message\n", sub.tag).as_bytes(),
        &sub.p256dh,
        &sub.auth,
    );
    assert_eq!(
        client.handle_push(&body, None).unwrap(),
        crate::client::push::PushNotice::Message {
            account,
            conversation: conv
        }
    );
    // Another tag inside is not this subscription's.
    let body = push_body(b"NOTIFY other message\n", &sub.p256dh, &sub.auth);
    assert!(client.handle_push(&body, None).is_err());
    // FOLLOW's quiet: only if asked for (9.2).
    assert_eq!(
        crate::sync::push::follow_quiet(&store, account, &mailbox),
        None
    );
    client.set_quiet_follows(account, true).unwrap();
    assert_eq!(
        crate::sync::push::follow_quiet(&store, account, &mailbox).map(|t| t.to_string()),
        Some(sub.tag.clone())
    );

    // Renewed when due.
    net.clock.advance(crate::sync::push::RENEW_MAX_MS);
    let sent = push_sends(&tick(&net, &mut push));
    assert_eq!(sent.len(), 2, "{sent:?}");
    for (_, _, token) in &sent {
        push.handle(
            &cx,
            &Input::Reply {
                slot: Slot::SignedIn,
                token: *token,
                response: &ok,
            },
        );
    }

    // Pushes off for one conversation: its subscription is deleted.
    store.write(|tx| tx.set_push_off(conv, true)).unwrap();
    let sent = push_sends(&tick(&net, &mut push));
    assert_eq!(sent.len(), 1);
    assert!(sent[0].1.contains("Del"), "{sent:?}");
    push.handle(
        &cx,
        &Input::Reply {
            slot: Slot::SignedIn,
            token: sent[0].2,
            response: &ok,
        },
    );
    assert_eq!(store.subscription_rows().unwrap().len(), 2);

    // Push off: every subscription is deleted.
    store
        .set_setting(&crate::sync::push::setting(account), None)
        .unwrap();
    let sent = push_sends(&tick(&net, &mut push));
    assert_eq!(sent.len(), 2);
    assert!(sent.iter().all(|(_, c, _)| c.contains("Del")));
}
