//! The group engine with several devices, against the in-memory server of
//! [`server`]: direct conversations, private rooms, the conversation with
//! yourself, commits racing for an epoch, leaving, gaps and catching up.

mod blobs;
mod deletes;
mod gaps;
mod keychecks;
mod leaving;
mod moves;
mod own_commits;
mod public;
mod recovery;
mod scenarios;
pub(crate) mod server;
mod upkeep;

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

/// The device keys of the test devices, as their key files would give
/// them (4.4), for the key checks of 12.7: a registered device is current,
/// with its key, and never removed; an identity marked unknown has its
/// facts unknown, as when its key file was never read or its record is
/// pending (4.5). One marked unreadable has a key file that cannot be read
/// now (4.4): with unknown, never read; without, read before, its devices
/// cached.
#[derive(Clone, Default)]
pub(crate) struct KnownKeys(Arc<std::sync::Mutex<KnownKeysInner>>);

#[derive(Default)]
struct KnownKeysInner {
    keys: std::collections::HashMap<(String, [u8; 48]), Vec<u8>>,
    unknown: std::collections::HashSet<String>,
    unreadable: std::collections::HashSet<String>,
    removed: std::collections::HashSet<(String, [u8; 48])>,
}

impl KnownKeys {
    /// Registers a device's key.
    pub(crate) fn add(&self, uid: &Uid, key: &SigningKey) {
        self.0.lock().unwrap().keys.insert(
            (uid.to_string(), *key.device_id().as_bytes()),
            key.public_key().to_vec(),
        );
    }

    /// Makes an identity's facts unknown, or known again.
    pub(crate) fn set_unknown(&self, uid: &Uid, unknown: bool) {
        let mut inner = self.0.lock().unwrap();
        if unknown {
            inner.unknown.insert(uid.to_string());
        } else {
            inner.unknown.remove(uid.as_str());
        }
    }

    /// Makes an identity's key file unreadable, an outage (4.4), or
    /// readable again.
    pub(crate) fn set_unreadable(&self, uid: &Uid, unreadable: bool) {
        let mut inner = self.0.lock().unwrap();
        if unreadable {
            inner.unreadable.insert(uid.to_string());
        } else {
            inner.unreadable.remove(uid.as_str());
        }
    }

    /// Whether an identity's key file cannot be read now.
    pub(crate) fn unreadable(&self, uid: &Uid) -> bool {
        self.0.lock().unwrap().unreadable.contains(uid.as_str())
    }

    /// Removes a device by record (4.4).
    pub(crate) fn remove(&self, uid: &Uid, device: &[u8; 48]) {
        let mut inner = self.0.lock().unwrap();
        inner.keys.remove(&(uid.to_string(), *device));
        inner.removed.insert((uid.to_string(), *device));
    }

    /// A copy that no longer follows this one: what one device has
    /// accepted of key files, which another may not have (12.7).
    pub(crate) fn copy(&self) -> KnownKeys {
        let inner = self.0.lock().unwrap();
        KnownKeys(Arc::new(std::sync::Mutex::new(KnownKeysInner {
            keys: inner.keys.clone(),
            unknown: inner.unknown.clone(),
            unreadable: inner.unreadable.clone(),
            removed: inner.removed.clone(),
        })))
    }

    /// What [`Hooks::device_key_of`] answers.
    pub(crate) fn device_key_of(&self, uid: &Uid, device: &DeviceId) -> Option<Option<Vec<u8>>> {
        let inner = self.0.lock().unwrap();
        if inner.unknown.contains(uid.as_str()) {
            return None;
        }
        Some(
            inner
                .keys
                .get(&(uid.to_string(), *device.as_bytes()))
                .cloned(),
        )
    }
}

impl KeyFacts for KnownKeys {
    fn current_device_key(&self, uid: &Uid, device: &DeviceId) -> Fact<Option<Vec<u8>>> {
        match self.device_key_of(uid, device) {
            Some(key) => Fact::Known(key),
            None => Fact::Unknown,
        }
    }

    fn device_removed(&self, uid: &Uid, device: &DeviceId) -> Fact<bool> {
        let inner = self.0.lock().unwrap();
        if inner.unknown.contains(uid.as_str()) {
            return Fact::Unknown;
        }
        Fact::Known(
            inner
                .removed
                .contains(&(uid.to_string(), *device.as_bytes())),
        )
    }

    fn identity_retired(&self, uid: &Uid) -> Fact<bool> {
        if self.0.lock().unwrap().unknown.contains(uid.as_str()) {
            return Fact::Unknown;
        }
        Fact::Known(false)
    }

    fn forked_or_missing(&self, uid: &Uid) -> Fact<bool> {
        if self.0.lock().unwrap().unknown.contains(uid.as_str()) {
            return Fact::Unknown;
        }
        Fact::Known(false)
    }
}

/// The hooks of a test device: its device key, and every leaf confirmed,
/// so that the lines of the conversation with yourself count.
struct TestHooks {
    key: SigningKey,
    keys: KnownKeys,
    confirm: bool,
    /// Devices whose leaves this device has not confirmed, despite
    /// `confirm` (12.10).
    distrust: std::sync::Mutex<std::collections::HashSet<[u8; 48]>>,
    /// PUTs of blobs in flight (12.12).
    puts: std::sync::Mutex<std::collections::HashMap<BlobRef, Vec<u8>>>,
    blobs: Arc<std::sync::Mutex<std::collections::HashMap<[u8; 48], Vec<u8>>>>,
    /// What the blob store answers: 0 the blob, 1 waiting, 2 none.
    blob_mode: Arc<std::sync::atomic::AtomicU8>,
    /// While set, PUTs of blobs stay in flight (12.12).
    hold_puts: Arc<std::sync::atomic::AtomicBool>,
    /// The blobs this device asked the blob store for (12.12).
    fetched: std::sync::Mutex<Vec<BlobRef>>,
}

impl Hooks for TestHooks {
    fn device_key(&self, _: AccountId, _: &Uid) -> Option<SigningKey> {
        Some(SigningKey::from_seed(*self.key.seed()))
    }

    fn leaf_confirmed(&self, _: &Tx<'_>, _: ConversationId, leaf: &LeafRow) -> bool {
        self.confirm
            && leaf
                .device_id
                .is_none_or(|d| !self.distrust.lock().unwrap().contains(&d))
    }

    fn device_key_of(
        &self,
        _: &Tx<'_>,
        _: AccountId,
        uid: &Uid,
        device: &DeviceId,
    ) -> Option<Option<Vec<u8>>> {
        self.keys.device_key_of(uid, device)
    }

    fn key_facts<'a>(&'a self, _: &'a Tx<'_>, _: AccountId) -> Box<dyn KeyFacts + 'a> {
        Box::new(self.keys.clone())
    }

    fn key_file_unreadable(&self, _: &Tx<'_>, uid: &Uid) -> bool {
        self.keys.unreadable(uid)
    }

    fn blob(&self, _: AccountId, _: Option<&str>, blob: &BlobRef) -> BlobFetch {
        self.fetched.lock().unwrap().push(*blob);
        match self.blob_mode.load(std::sync::atomic::Ordering::SeqCst) {
            0 => match self.blobs.lock().unwrap().get(blob.hash()) {
                Some(bytes) => BlobFetch::Ready(bytes.clone()),
                None => BlobFetch::Unavailable,
            },
            1 => BlobFetch::Waiting,
            _ => BlobFetch::Unavailable,
        }
    }

    /// The PUT lands in the server's blob store, unless PUTs are held
    /// (12.12).
    fn put_blob(&self, _: &str, blob: &BlobRef, bytes: Arc<Vec<u8>>) {
        assert_eq!(BlobRef::of(&bytes), *blob);
        self.puts.lock().unwrap().insert(*blob, bytes.to_vec());
    }

    fn blob_put(&self, blob: &BlobRef) -> BlobPut {
        if self.hold_puts.load(std::sync::atomic::Ordering::SeqCst) {
            return BlobPut::Waiting;
        }
        match self.puts.lock().unwrap().remove(blob) {
            Some(bytes) => {
                self.blobs.lock().unwrap().insert(*blob.hash(), bytes);
                BlobPut::Done
            }
            None => BlobPut::Failed,
        }
    }
}

struct Device {
    name: &'static str,
    uid: Uid,
    store: Store,
    account: AccountId,
    engine: ConversationEngine,
    /// The engine's hooks and settings, to start it again (LR-M4).
    hooks: Arc<TestHooks>,
    config: Config,
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
    hold_puts: Arc<std::sync::atomic::AtomicBool>,
    keys: KnownKeys,
}

impl Net {
    fn new() -> Net {
        Net {
            server: FakeServer::new(START),
            devices: Vec::new(),
            queue: VecDeque::new(),
            clock: ManualClock::new(START),
            blob_mode: Arc::new(std::sync::atomic::AtomicU8::new(0)),
            hold_puts: Arc::default(),
            keys: KnownKeys::default(),
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
        if !uid.is_guest() {
            self.keys.add(&uid, &key);
        }
        let hooks = Arc::new(TestHooks {
            keys: self.keys.clone(),
            key,
            confirm: true,
            distrust: Default::default(),
            puts: Default::default(),
            blobs: self.server.blobs.clone(),
            blob_mode: self.blob_mode.clone(),
            hold_puts: self.hold_puts.clone(),
            fetched: Default::default(),
        });
        let engine =
            ConversationEngine::new(config.clone(), hooks.clone(), Arc::new(self.clock.clone()));
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
            hooks,
            config,
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

    /// Starts a device's engine again, as after the app was killed: what
    /// it kept in memory is gone, the cache stays (LR-M4).
    fn restart(&mut self, d: usize) {
        self.disconnect(d);
        let dev = &mut self.devices[d];
        dev.engine = ConversationEngine::new(
            dev.config.clone(),
            dev.hooks.clone(),
            Arc::new(self.clock.clone()),
        );
        self.connect(d);
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
