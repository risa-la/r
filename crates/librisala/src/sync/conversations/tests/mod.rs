//! The group engine with several devices, against the in-memory server of
//! [`server`]: direct conversations, private rooms, the conversation with
//! yourself, commits racing for an epoch, leaving, gaps and catching up.

mod public;
mod recovery;
mod scenarios;
pub(crate) mod server;

use std::collections::VecDeque;
use std::sync::Arc;

use risala_mls::mldsa::SigningKey;
use risala_proto::connection::ConnectionKind;
use risala_proto::content::{ContentLine, Text};
use risala_proto::names::Uid;
use risala_proto::server::ServerMessage;

use super::*;
use crate::addr::ServerAddr;
use crate::clock::ManualClock;
use crate::conn::{Response, Slot};
use crate::store::conversations::ConvRow;
use crate::store::messages::MessageRow;
use crate::store::{AccountKind, Store};

use server::FakeServer;

/// The time the tests start at: 2026-11-09.
const START: u64 = 1_794_182_400_000;

/// The hooks of a test device: its device key, and every leaf confirmed,
/// so that the lines of the conversation with yourself count.
struct TestHooks {
    key: SigningKey,
    confirm: bool,
    blobs: Arc<std::sync::Mutex<std::collections::HashMap<[u8; 48], Vec<u8>>>>,
    /// What the blob store answers: 0 the blob, 1 waiting, 2 none.
    blob_mode: Arc<std::sync::atomic::AtomicU8>,
}

impl Hooks for TestHooks {
    fn device_key(&self, _: AccountId, _: &Uid) -> Option<SigningKey> {
        Some(SigningKey::from_seed(*self.key.seed()))
    }

    fn leaf_confirmed(&self, _: &Tx<'_>, _: ConversationId, _: &LeafRow) -> bool {
        self.confirm
    }

    fn blob(&self, _: AccountId, _: Option<&str>, blob: &BlobRef) -> BlobFetch {
        match self.blob_mode.load(std::sync::atomic::Ordering::SeqCst) {
            0 => match self.blobs.lock().unwrap().get(blob.hash()) {
                Some(bytes) => BlobFetch::Ready(bytes.clone()),
                None => BlobFetch::Unavailable,
            },
            1 => BlobFetch::Waiting,
            _ => BlobFetch::Unavailable,
        }
    }
}

struct Device {
    name: &'static str,
    uid: Uid,
    store: Store,
    account: AccountId,
    engine: ConversationEngine,
    device_id: Vec<u8>,
    events: Vec<Event>,
    online: bool,
    guest: bool,
}

enum Owned {
    Ready(Slot, ConnectionKind),
    Closed(Slot),
    Line(Slot, ServerMessage),
    Reply(Slot, Token, Response),
    Tick,
}

struct Net {
    server: FakeServer,
    devices: Vec<Device>,
    queue: VecDeque<(usize, Owned)>,
    clock: ManualClock,
    blob_mode: Arc<std::sync::atomic::AtomicU8>,
}

impl Net {
    fn new() -> Net {
        Net {
            server: FakeServer::new(START),
            devices: Vec::new(),
            queue: VecDeque::new(),
            clock: ManualClock::new(START),
            blob_mode: Arc::new(std::sync::atomic::AtomicU8::new(0)),
        }
    }

    /// Adds a device of `uid`, with the engine's settings for tests.
    fn device(&mut self, name: &'static str, uid: &str) -> usize {
        self.device_with(
            name,
            uid,
            Config {
                self_conversation: false,
                ..Config::immediate()
            },
        )
    }

    fn device_with(&mut self, name: &'static str, uid: &str, config: Config) -> usize {
        let uid: Uid = uid.parse().unwrap();
        let store = Store::open_in_memory().unwrap();
        let addr: ServerAddr = "chat.example.org".parse().unwrap();
        let kind = if uid.is_guest() {
            AccountKind::Guest
        } else {
            AccountKind::Identity
        };
        let account = store.add_account(&addr, kind, &uid).unwrap();
        let key = SigningKey::generate().unwrap();
        let device_id = key.device_id().as_bytes().to_vec();
        let hooks = Arc::new(TestHooks {
            key,
            confirm: true,
            blobs: self.server.blobs.clone(),
            blob_mode: self.blob_mode.clone(),
        });
        let engine = ConversationEngine::new(config, hooks, Arc::new(self.clock.clone()));
        let d = self.devices.len();
        self.server
            .signed_in
            .insert((d, Slot::SignedIn), (uid.to_string(), device_id.clone()));
        self.devices.push(Device {
            name,
            uid,
            store,
            account,
            engine,
            device_id,
            events: Vec::new(),
            online: false,
            guest: false,
        });
        d
    }

    /// Adds a second device of the identity of device `of`.
    fn device_of(&mut self, name: &'static str, of: usize) -> usize {
        let uid = self.devices[of].uid.to_string();
        let uid: &'static str = Box::leak(uid.into_boxed_str());
        self.device(name, uid)
    }

    /// Adds a guest, `~<name>` (4.2): no device key, one guest connection.
    fn guest(&mut self, name: &'static str, uid: &str) -> usize {
        let d = self.device(name, uid);
        self.devices[d].guest = true;
        self.server.signed_in.remove(&(d, Slot::SignedIn));
        d
    }

    /// Brings a device's connections up: signed in, and one anonymous.
    fn connect(&mut self, d: usize) {
        self.devices[d].online = true;
        if self.devices[d].guest {
            self.queue
                .push_back((d, Owned::Ready(Slot::Guest, ConnectionKind::Guest)));
            self.run();
            return;
        }
        self.queue
            .push_back((d, Owned::Ready(Slot::SignedIn, ConnectionKind::SignedIn)));
        self.queue.push_back((
            d,
            Owned::Ready(Slot::Anonymous(0), ConnectionKind::Anonymous),
        ));
        self.run();
    }

    /// Takes a device's connections down.
    fn disconnect(&mut self, d: usize) {
        self.devices[d].online = false;
        if self.devices[d].guest {
            self.server.close((d, Slot::Guest));
            self.queue.push_back((d, Owned::Closed(Slot::Guest)));
            self.run();
            return;
        }
        self.server.close((d, Slot::Anonymous(0)));
        self.queue.push_back((d, Owned::Closed(Slot::Anonymous(0))));
        self.queue.push_back((d, Owned::Closed(Slot::SignedIn)));
        self.run();
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
            if !self.devices[d].online && !matches!(owned, Owned::Closed(_)) {
                continue;
            }
            let cx = self.cx(d);
            let actions = match &owned {
                Owned::Ready(slot, kind) => self.devices[d].engine.handle(
                    &cx,
                    &Input::Ready {
                        slot: *slot,
                        kind: *kind,
                    },
                ),
                Owned::Closed(slot) => self.devices[d]
                    .engine
                    .handle(&cx, &Input::Closed { slot: *slot }),
                Owned::Line(slot, message) => self.devices[d].engine.handle(
                    &cx,
                    &Input::Line {
                        slot: *slot,
                        message,
                    },
                ),
                Owned::Reply(slot, token, response) => self.devices[d].engine.handle(
                    &cx,
                    &Input::Reply {
                        slot: *slot,
                        token: *token,
                        response,
                    },
                ),
                Owned::Tick => self.devices[d].engine.handle(
                    &cx,
                    &Input::Tick {
                        now: self.clock.now(),
                    },
                ),
            };
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
                        Target::Mailbox(_) | Target::Conversing if self.devices[d].guest => {
                            Slot::Guest
                        }
                        Target::Mailbox(_) | Target::Conversing => Slot::Anonymous(0),
                        Target::Watch => Slot::Watch,
                        Target::Own(_) => SINGLE_USE_SLOT,
                    };
                    self.server.now = self.clock.now().unix_millis();
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

    /// Ticks every online device.
    fn tick(&mut self) {
        for d in 0..self.devices.len() {
            self.queue.push_back((d, Owned::Tick));
        }
        self.run();
    }

    /// Moves the clock on, and ticks.
    fn advance(&mut self, ms: u64) {
        self.clock.advance(ms);
        self.tick();
    }

    /// Starts a job on a device, and runs until it is done. Returns the
    /// conversation.
    fn job(&mut self, d: usize, job: Job) -> Result<ConversationId, String> {
        let cx = self.cx(d);
        let (id, actions) = self.devices[d].engine.start(&cx, job);
        self.act(d, actions);
        self.run();
        self.tick();
        for event in &self.devices[d].events {
            if let Event::Conversation(ConversationEvent::JobDone {
                job,
                conversation,
                error,
            }) = event
                && *job == id
            {
                return match (conversation, error) {
                    (Some(c), None) => Ok(*c),
                    (_, Some(e)) => Err(e.clone()),
                    _ => Err("no result".into()),
                };
            }
        }
        Err(format!("{}: the job did not finish", self.devices[d].name))
    }

    fn convs(&self, d: usize) -> Vec<ConvRow> {
        self.devices[d]
            .store
            .conversation_rows(self.devices[d].account)
            .unwrap()
    }

    /// The device's conversation of `kind` in the group of `like`, on
    /// another device.
    fn same_conv(&self, d: usize, other: usize, conv: ConversationId) -> Option<ConversationId> {
        let group = self.devices[other]
            .store
            .conversation_row(conv)
            .unwrap()
            .unwrap()
            .group_id;
        self.convs(d)
            .into_iter()
            .find(|c| c.group_id == group)
            .map(|c| c.id)
    }

    fn write<T>(&self, d: usize, f: impl FnOnce(&mut Tx<'_>) -> Result<T, EngineError>) -> T {
        self.devices[d].store.write_with(f).unwrap().0
    }

    /// Queues a text message, and lets the network run.
    fn say(&mut self, d: usize, conv: ConversationId, text: &str) -> [u8; 16] {
        self.lines(d, conv, vec![ContentLine::Text(Text::new(text))], false)
    }

    fn lines(
        &mut self,
        d: usize,
        conv: ConversationId,
        lines: Vec<ContentLine>,
        live: bool,
    ) -> [u8; 16] {
        let uid = self.devices[d].uid.clone();
        let now = self.clock.now().unix_millis();
        let id = self.write(d, |tx| {
            content::queue_lines(tx, conv, &uid, lines, live, now)
        });
        self.queue.push_back((d, Owned::Tick));
        self.run();
        id
    }

    fn texts(&self, d: usize, conv: ConversationId) -> Vec<(String, String)> {
        self.messages(d, conv)
            .into_iter()
            .filter(|m| m.edit_of.is_none() && m.react_to.is_none())
            .map(|m| {
                (
                    m.sender.to_string(),
                    m.text.unwrap_or_else(|| "<deleted>".into()),
                )
            })
            .collect()
    }

    fn messages(&self, d: usize, conv: ConversationId) -> Vec<MessageRow> {
        self.devices[d].store.message_rows(conv).unwrap()
    }

    fn epoch(&self, d: usize, conv: ConversationId) -> u64 {
        self.devices[d]
            .store
            .conversation_row(conv)
            .unwrap()
            .unwrap()
            .epoch
    }

    fn leaves(&self, d: usize, conv: ConversationId) -> Vec<String> {
        self.devices[d]
            .store
            .leaf_rows(conv)
            .unwrap()
            .into_iter()
            .map(|l| l.uid.to_string())
            .collect()
    }

    fn state(&self, d: usize, conv: ConversationId) -> ConvState {
        self.devices[d]
            .store
            .conversation_row(conv)
            .unwrap()
            .unwrap()
            .state
    }
}

impl Net {
    /// Starts a job, and lets the network and the clock run for up to
    /// `minutes` minutes, a minute at a time, until it is done.
    fn job_over(&mut self, d: usize, job: Job, minutes: u64) -> Result<ConversationId, String> {
        let cx = self.cx(d);
        let (id, actions) = self.devices[d].engine.start(&cx, job);
        self.act(d, actions);
        self.run();
        self.tick();
        for _ in 0..=minutes {
            if let Some(r) = self.job_result(d, id) {
                return r;
            }
            self.advance(60_000);
        }
        Err(format!("{}: the job did not finish", self.devices[d].name))
    }

    fn job_result(&self, d: usize, id: JobId) -> Option<Result<ConversationId, String>> {
        self.devices[d].events.iter().find_map(|event| match event {
            Event::Conversation(ConversationEvent::JobDone {
                job,
                conversation,
                error,
            }) if *job == id => Some(match (conversation, error) {
                (Some(c), None) => Ok(*c),
                (_, Some(e)) => Err(e.clone()),
                _ => Err("no result".into()),
            }),
            _ => None,
        })
    }

    /// Delivers live lines from the server, as if it sent them.
    fn deliver(&mut self, lines: Vec<(server::ConnId, ServerMessage)>) {
        for ((to, slot), line) in lines {
            self.queue.push_back((to, Owned::Line(slot, line)));
        }
        self.run();
    }

    /// Pins the pseudonym that device `sender` sends under in `conv` (its
    /// conversation there) at device `d`, as leaf confirmation (task C3)
    /// does once it has checked the sender's ATTEST (7.3, 12.10).
    fn pin(&self, d: usize, conv_d: ConversationId, sender: usize, conv_s: ConversationId) {
        use risala_mls::message::MessageHistory as _;
        let row = self.devices[sender]
            .store
            .conversation_row(conv_s)
            .unwrap()
            .unwrap();
        let leaf = self.devices[d]
            .store
            .leaf_rows(conv_d)
            .unwrap()
            .into_iter()
            .find(|l| {
                l.uid == self.devices[sender].uid
                    && (self.devices[sender].guest
                        || l.device_id.map(|x| x.to_vec())
                            == Some(self.devices[sender].device_id.clone()))
            })
            .expect("the sender's leaf")
            .leaf;
        self.write(d, |tx| {
            let mut log = crate::store::messages::MessageLog::new(tx.conn(), conv_d);
            log.pin(
                risala_mls::openmls::prelude::LeafNodeIndex::new(leaf),
                risala_mls::aad::Pseudonym(row.pseudonym),
            );
            log.finish()?;
            Ok(())
        });
    }

    fn events(&self, d: usize) -> &[Event] {
        &self.devices[d].events
    }
}
