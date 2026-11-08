//! Tests of the encryption engine (SPEC 12) with real MLS groups: devices
//! on caches of their own, each with an engine, and a small server in
//! memory that relays what they send.
//!
//! The server here checks only what the tests need: epochs (`stale`),
//! who is in each conversation, and KeyPackages handed out once. The real
//! server's checks of 12.5 are tested in `risala-server`.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::SystemTime;

use risala_mls::openmls::group::MlsGroup;
use risala_mls::openmls::prelude::GroupId;
use risala_mls::wire;
use risala_proto::auth::{PublicKey, SecretKey};
use risala_proto::command::{BackupCommand, Command, KeyPkgCommand, Request, WelcomeCommand};
use risala_proto::mls;
use risala_proto::names::{Conv, Id, Room, Uid};
use risala_proto::server::ServerMessage;
use risala_proto::time::Timestamp;

use super::*;
use crate::addr::ServerAddr;
use crate::store::e2ee::GroupState;
use crate::store::{AccountId, Draft, OutboxState, Store};

const T0: u64 = 1_800_000_000_000;

fn uid(s: &str) -> Uid {
    s.parse().unwrap()
}

/// A device: a cache, an account, an engine and its commands.
struct Dev {
    uid: Uid,
    key: Arc<SecretKey>,
    store: Store,
    account: AccountId,
    engine: SyncEngine,
    queue: VecDeque<Outgoing>,
    key_files: VecDeque<Uid>,
    notes: Vec<Notification>,
    recovery: Option<risala_mls::RecoveryKey>,
}

impl Dev {
    fn new(me: &str, seed: u8) -> Dev {
        let store = Store::open_in_memory().unwrap();
        let server: ServerAddr = "chat.example.org".parse().unwrap();
        let me = uid(me);
        let account = store.account(&server, &me).unwrap();
        let key = Arc::new(SecretKey::from_seed([seed; 32]));
        let engine = Dev::engine(&store, account, &me, &key);
        Dev {
            uid: me,
            key,
            store,
            account,
            engine,
            queue: VecDeque::new(),
            key_files: VecDeque::new(),
            notes: Vec::new(),
            recovery: None,
        }
    }

    fn engine(store: &Store, account: AccountId, me: &Uid, key: &Arc<SecretKey>) -> SyncEngine {
        let config = SyncConfig {
            lazy_gap: None,
            fetch_blocks: false,
            clock: Clock::new(Timestamp::now),
            ..SyncConfig::default()
        };
        let mut engine = SyncEngine::signed_in_as(store.clone(), account, me.clone(), config);
        engine.set_device_key(key.clone(), false).unwrap();
        engine
    }

    fn absorb(&mut self, out: Output) {
        self.queue.extend(out.send);
        self.key_files.extend(out.key_files);
        self.notes.extend(out.notifications);
        if out.recovery.is_some() {
            self.recovery = out.recovery;
        }
    }

    fn public(&self) -> PublicKey {
        self.key.public_key()
    }

    /// The texts of the conversation's timeline, with how each was read.
    fn texts(&self, conv: &str) -> Vec<(String, Option<crate::store::e2ee::EncState>)> {
        let Some(c) = self
            .store
            .conversations(self.account)
            .unwrap()
            .into_iter()
            .find(|c| c.name.as_str() == conv)
        else {
            return Vec::new();
        };
        self.store
            .timeline(c.id, None, 100)
            .unwrap()
            .into_iter()
            .filter_map(|i| Some((i.text.clone()?, i.enc)))
            .collect()
    }

    fn group(&self, conv: &str) -> Option<crate::store::e2ee::GroupRow> {
        let conv: Conv = conv.parse().unwrap();
        let account = self.account;
        self.store
            .write(|tx| match tx.conv_by_name(account, &conv)? {
                Some(row) => tx.group(row.id),
                None => Ok(None),
            })
            .unwrap()
            .0
    }

    /// The ratchet tree of the device's group `group_id`.
    fn tree(&self, group_id: &[u8]) -> Option<mls::RatchetTree> {
        self.store
            .read(|conn| {
                let storage = crate::store::mls::MlsStorage::new(conn);
                let group = MlsGroup::load(&storage, &GroupId::from_slice(group_id)).unwrap();
                Ok(group.map(|g| wire::tree_to_wire(&g.export_ratchet_tree()).unwrap()))
            })
            .unwrap()
    }
}

#[derive(Debug, Clone)]
enum Kind {
    Direct(Uid, Uid),
    Room(Room),
}

#[derive(Debug, Clone)]
enum Body {
    Commit {
        epoch: u64,
        commit: mls::CommitMessage,
    },
    Enc {
        epoch: u64,
        payload: mls::Ciphertext,
        frank: mls::Frank,
    },
    Join,
    Set(String),
}

#[derive(Debug, Clone)]
struct SEvent {
    from: Uid,
    body: Body,
}

#[derive(Debug)]
struct SConv {
    id: String,
    kind: Kind,
    members: Vec<Uid>,
    invited: Vec<Uid>,
    events: Vec<SEvent>,
    epoch: Option<u64>,
    group_info: Option<mls::GroupInfo>,
    group_id: Option<Vec<u8>>,
    tree: Option<mls::RatchetTree>,
    commit_seq: u64,
}

impl SConv {
    /// The conversation's name as `to` sees it (5.2).
    fn name_for(&self, to: &Uid) -> String {
        match &self.kind {
            Kind::Room(r) => r.to_string(),
            Kind::Direct(a, b) => if a == to { b } else { a }.to_string(),
        }
    }

    fn line(&self, n: usize, to: &Uid) -> String {
        let e = &self.events[n - 1];
        let t = Timestamp::from_unix_millis(T0 + n as u64).unwrap();
        let conv = self.name_for(to);
        let head = format!("@seq={n};t={t};from={}", e.from);
        match &e.body {
            Body::Commit { epoch, commit } => format!("{head} COMMIT {conv} {epoch} {commit}"),
            Body::Enc {
                epoch,
                payload,
                frank,
            } => format!("{head};frank={frank} ENC {conv} {epoch} {payload}"),
            Body::Join => format!("{head};id={} JOIN {conv}", self.id),
            Body::Set(s) => format!("{head} SET {conv} {s}"),
        }
    }
}

/// A Welcome the server keeps for a device: its id, the conversation as
/// the device names it, the COMMIT's seq, the Welcome and the tree.
type PendingWelcome = (u64, String, u64, mls::Welcome, mls::RatchetTree);

/// The server and its devices.
struct Net {
    devs: Vec<Dev>,
    convs: Vec<SConv>,
    next_id: u64,
    key_files: HashMap<Uid, Vec<PublicKey>>,
    packages: HashMap<usize, Vec<mls::KeyPackage>>,
    last_resort: HashMap<usize, mls::KeyPackage>,
    /// Devices whose KeyPackages a device was handed, for its Welcome.
    handed: HashMap<usize, Vec<usize>>,
    welcomes: HashMap<usize, Vec<PendingWelcome>>,
    next_welcome: u64,
    backups: HashMap<(Uid, String, u64), mls::BackupBlob>,
    /// Every command sent, as a line, by device.
    log: Vec<(usize, String)>,
}

impl Net {
    fn new() -> Net {
        Net {
            devs: Vec::new(),
            convs: Vec::new(),
            next_id: 1,
            key_files: HashMap::new(),
            packages: HashMap::new(),
            last_resort: HashMap::new(),
            handed: HashMap::new(),
            welcomes: HashMap::new(),
            next_welcome: 1,
            backups: HashMap::new(),
            log: Vec::new(),
        }
    }

    /// Adds a device, lists its key in its identity's key file, and
    /// starts its engine.
    fn device(&mut self, me: &str, seed: u8) -> usize {
        let dev = Dev::new(me, seed);
        self.key_files
            .entry(dev.uid.clone())
            .or_default()
            .push(dev.public());
        self.devs.push(dev);
        let d = self.devs.len() - 1;
        let out = self.devs[d].engine.start().unwrap();
        self.devs[d].absorb(out);
        d
    }

    fn new_id(&mut self) -> String {
        let id = format!("c{:07}", self.next_id);
        self.next_id += 1;
        id
    }

    fn conv_of(&self, d: usize, name: &str) -> Option<usize> {
        let me = &self.devs[d].uid;
        self.convs
            .iter()
            .position(|c| c.members.contains(me) && c.name_for(me) == name)
    }

    /// Runs until no device has anything to send.
    fn run(&mut self) {
        for _ in 0..10_000 {
            let mut busy = false;
            for d in 0..self.devs.len() {
                if let Some(uid) = self.devs[d].key_files.pop_front() {
                    busy = true;
                    let keys = self
                        .key_files
                        .get(&uid)
                        .map(|k| k.iter().map(|k| (k.clone(), None)).collect());
                    let out = self.devs[d].engine.key_file(&uid, keys).unwrap();
                    self.devs[d].absorb(out);
                }
                if let Some(o) = self.devs[d].queue.pop_front() {
                    busy = true;
                    self.handle(d, o);
                }
            }
            if !busy {
                return;
            }
        }
        panic!("the devices never settle");
    }

    fn deliver(&mut self, d: usize, line: &str) {
        let msg: ServerMessage = line.parse().unwrap_or_else(|e| panic!("{line}: {e}"));
        let out = self.devs[d].engine.handle_line(&msg).unwrap();
        self.devs[d].absorb(out);
    }

    fn reply(&mut self, d: usize, req: ReqId, lines: &[String], last: &str) {
        let lines: Vec<ServerMessage> = lines
            .iter()
            .map(|l| l.parse().unwrap_or_else(|e| panic!("{l}: {e}")))
            .collect();
        let last: ServerMessage = last.parse().unwrap();
        let out = self.devs[d]
            .engine
            .handle_reply(req, Reply::new(lines, last.line))
            .unwrap();
        self.devs[d].absorb(out);
    }

    /// Sends event `n` of conversation `c` to every device in it.
    fn broadcast(&mut self, c: usize, n: usize) {
        for d in 0..self.devs.len() {
            if self.convs[c].members.contains(&self.devs[d].uid) {
                let line = self.convs[c].line(n, &self.devs[d].uid);
                self.deliver(d, &line);
            }
        }
    }

    fn push(&mut self, c: usize, from: &Uid, body: Body) -> usize {
        self.convs[c].events.push(SEvent {
            from: from.clone(),
            body,
        });
        let n = self.convs[c].events.len();
        self.broadcast(c, n);
        n
    }

    fn handle(&mut self, d: usize, o: Outgoing) {
        let line = Request::new(o.command.clone()).to_line().to_string();
        self.log.push((d, line.clone()));
        let me = self.devs[d].uid.clone();
        let req = o.req;
        match o.command {
            Command::Sync => {
                let lines: Vec<String> = self
                    .convs
                    .iter()
                    .filter(|c| c.members.contains(&me) && !c.events.is_empty())
                    .map(|c| format!("CONV {} {} {} 0", c.name_for(&me), c.id, c.events.len()))
                    .collect();
                self.reply(d, req, &lines, "OK");
            }
            Command::History { conv, after, .. } => {
                let Some(c) = self.conv_of(d, conv.as_str()) else {
                    return self.reply(d, req, &[], "ERR not-found");
                };
                let after = after.unwrap_or(0) as usize;
                let n = self.convs[c].events.len();
                let lines: Vec<String> = ((after + 1)..=n)
                    .map(|i| self.convs[c].line(i, &me))
                    .collect();
                let id = self.convs[c].id.clone();
                self.reply(d, req, &lines, &format!("OK id={id} more=0"));
            }
            Command::KeyPkg(KeyPkgCommand::Count) => {
                let n = self.packages.get(&d).map_or(0, Vec::len);
                let lr = if self.last_resort.contains_key(&d) {
                    "yes"
                } else {
                    "no"
                };
                self.reply(d, req, &[], &format!("OK count={n} last-resort={lr}"));
            }
            Command::KeyPkg(KeyPkgCommand::Add { key_package }) => {
                let crypto = risala_mls::RisalaCrypto::new().unwrap();
                let checked = risala_mls::check_key_package(
                    &crypto,
                    &key_package,
                    &me,
                    &self.devs[d].public(),
                    SystemTime::now(),
                )
                .unwrap();
                if checked.last_resort {
                    self.last_resort.insert(d, key_package);
                } else {
                    self.packages.entry(d).or_default().push(key_package);
                }
                self.reply(d, req, &[], "OK");
            }
            Command::KeyPkg(KeyPkgCommand::Get { uid: who }) => {
                let listed = self.key_files.get(&who).cloned().unwrap_or_default();
                let mut lines = Vec::new();
                for other in 0..self.devs.len() {
                    if other == d
                        || self.devs[other].uid != who
                        || !listed.contains(&self.devs[other].public())
                    {
                        continue;
                    }
                    let kp = match self.packages.get_mut(&other).and_then(Vec::pop) {
                        Some(kp) => Some(kp),
                        None => self.last_resort.get(&other).cloned(),
                    };
                    if let Some(kp) = kp {
                        lines.push(format!("KEYPKG {who} {kp}"));
                        self.handed.entry(d).or_default().push(other);
                    }
                }
                self.reply(d, req, &lines, "OK");
            }
            Command::Welcome(WelcomeCommand::List) => {
                let pending = self.welcomes.get(&d).cloned().unwrap_or_default();
                let lines: Vec<String> = pending
                    .iter()
                    .map(|(id, conv, seq, w, t)| format!("WELCOME {conv} w{id} {seq} {w} {t}"))
                    .collect();
                self.reply(d, req, &lines, "OK");
            }
            Command::Welcome(WelcomeCommand::Del { id }) => {
                if let Some(list) = self.welcomes.get_mut(&d) {
                    list.retain(|(i, ..)| format!("w{i}") != id.as_str());
                }
                self.reply(d, req, &[], "OK");
            }
            Command::Init {
                conv,
                group_info,
                tree,
            } => self.init(d, req, &conv, group_info, tree),
            Command::Commit {
                conv,
                commit,
                group_info,
                welcome,
            } => self.commit(d, req, &conv, commit, group_info, welcome),
            Command::GroupInfo { conv } => {
                let Some(c) = self.conv_of(d, conv.as_str()) else {
                    return self.reply(d, req, &[], "ERR not-found");
                };
                let s = &self.convs[c];
                let (Some(epoch), Some(gi), Some(tree)) = (s.epoch, &s.group_info, &s.tree) else {
                    return self.reply(d, req, &[], "ERR not-found");
                };
                let line = format!("GROUPINFO {conv} {epoch} {} {gi} {tree}", s.commit_seq);
                self.reply(d, req, &[line], "OK");
            }
            Command::Enc {
                conv,
                epoch,
                payload,
                frank,
                ..
            } => {
                let Some(c) = self.conv_of(d, conv.as_str()) else {
                    return self.reply(d, req, &[], "ERR not-found");
                };
                if self.convs[c].epoch != Some(epoch) {
                    return self.reply(d, req, &[], "ERR stale");
                }
                let n = self.push(
                    c,
                    &me,
                    Body::Enc {
                        epoch,
                        payload,
                        frank: frank.unwrap(),
                    },
                );
                self.reply(d, req, &[], &format!("OK seq={n}"));
            }
            Command::Backup(BackupCommand::Add { id, epoch, blob }) => {
                self.backups
                    .entry((me.clone(), id.to_string(), epoch))
                    .or_insert(blob);
                self.reply(d, req, &[], "OK");
            }
            Command::Backup(BackupCommand::Get { id, .. }) => {
                let mut lines: Vec<(u64, String)> = self
                    .backups
                    .iter()
                    .filter(|((u, i, _), _)| *u == me && i == id.as_str())
                    .map(|((_, _, e), b)| (*e, format!("BACKUP {id} {e} {b}")))
                    .collect();
                lines.sort();
                let lines: Vec<String> = lines.into_iter().map(|(_, l)| l).collect();
                self.reply(d, req, &lines, "OK more=0");
            }
            Command::Join { room } => {
                let Some(c) = self
                    .convs
                    .iter()
                    .position(|c| matches!(&c.kind, Kind::Room(r) if *r == room))
                else {
                    return self.reply(d, req, &[], "ERR not-found");
                };
                if !self.convs[c].invited.contains(&me) {
                    return self.reply(d, req, &[], "ERR forbidden");
                }
                self.convs[c].invited.retain(|u| *u != me);
                self.convs[c].members.push(me.clone());
                let n = self.push(c, &me, Body::Join);
                let id = self.convs[c].id.clone();
                self.reply(d, req, &[], &format!("OK id={id} head={n} role=member"));
            }
            Command::Info { room: Some(room) } => {
                let Some(c) = self
                    .convs
                    .iter()
                    .position(|c| matches!(&c.kind, Kind::Room(r) if *r == room))
                else {
                    return self.reply(d, req, &[], "ERR not-found");
                };
                let s = &self.convs[c];
                let joined = if s.members.contains(&me) { "yes" } else { "no" };
                let ok = format!(
                    "OK id={} head={} joined={joined} members={}",
                    s.id,
                    s.events.len().max(1),
                    s.members.len()
                );
                self.reply(d, req, &[], &ok);
            }
            other => {
                let line = Request::new(other).to_line().to_string();
                panic!("the test server does not know {line}");
            }
        }
    }

    fn init(
        &mut self,
        d: usize,
        req: ReqId,
        conv: &Conv,
        group_info: mls::GroupInfo,
        tree: mls::RatchetTree,
    ) {
        let me = self.devs[d].uid.clone();
        let c = match self.conv_of(d, conv.as_str()) {
            Some(c) => c,
            None => {
                let Conv::Uid(other) = conv else {
                    return self.reply(d, req, &[], "ERR not-found");
                };
                let id = self.new_id();
                let mut members = vec![me.clone()];
                if *other != me {
                    members.push(other.clone());
                }
                self.convs.push(SConv {
                    id,
                    kind: Kind::Direct(me.clone(), other.clone()),
                    members,
                    invited: Vec::new(),
                    events: Vec::new(),
                    epoch: None,
                    group_info: None,
                    group_id: None,
                    tree: None,
                    commit_seq: 0,
                });
                self.convs.len() - 1
            }
        };
        if self.convs[c].epoch.is_some() {
            return self.reply(d, req, &[], "ERR stale");
        }
        let info = wire::group_info_from_wire(&group_info).unwrap();
        let s = &mut self.convs[c];
        s.epoch = Some(0);
        s.group_id = Some(info.group_id().as_slice().to_vec());
        s.group_info = Some(group_info);
        s.tree = Some(tree);
        if matches!(s.kind, Kind::Room(_)) {
            for set in ["public no", "guests none", "e2ee yes"] {
                self.push(c, &me, Body::Set(set.into()));
            }
        }
        let id = self.convs[c].id.clone();
        self.reply(d, req, &[], &format!("OK id={id} epoch=0"));
    }

    fn commit(
        &mut self,
        d: usize,
        req: ReqId,
        conv: &Conv,
        commit: mls::CommitMessage,
        group_info: mls::GroupInfo,
        welcome: Option<mls::Welcome>,
    ) {
        let me = self.devs[d].uid.clone();
        let Some(c) = self.conv_of(d, conv.as_str()) else {
            return self.reply(d, req, &[], "ERR not-found");
        };
        let message = wire::commit_from_wire(&commit).unwrap();
        let epoch = message.epoch().as_u64();
        if self.convs[c].epoch != Some(epoch) {
            return self.reply(d, req, &[], "ERR stale");
        }
        let new_epoch = epoch + 1;
        self.convs[c].epoch = Some(new_epoch);
        self.convs[c].group_info = Some(group_info);
        let n = self.push(
            c,
            &me,
            Body::Commit {
                epoch: new_epoch,
                commit,
            },
        );
        self.convs[c].commit_seq = n as u64;
        // The new tree, from the committer, who has merged the commit.
        let group_id = self.convs[c].group_id.clone().unwrap();
        self.convs[c].tree = self.devs[d].tree(&group_id);
        let recipients = self.handed.remove(&d).unwrap_or_default();
        if let Some(welcome) = welcome {
            let tree = self.convs[c].tree.clone().unwrap();
            for r in recipients {
                let invitee = self.devs[r].uid.clone();
                if !self.convs[c].members.contains(&invitee)
                    && !self.convs[c].invited.contains(&invitee)
                {
                    self.convs[c].invited.push(invitee);
                }
                let id = self.next_welcome;
                self.next_welcome += 1;
                let name = self.convs[c].name_for(&self.devs[r].uid);
                self.welcomes.entry(r).or_default().push((
                    id,
                    name.clone(),
                    n as u64,
                    welcome.clone(),
                    tree.clone(),
                ));
                let line = format!("WELCOME {name} w{id} {n} {welcome} {tree}");
                self.deliver(r, &line);
            }
        }
        self.reply(d, req, &[], &format!("OK seq={n} epoch={new_epoch}"));
    }

    /// Makes a room with `owner` as its only member.
    fn room(&mut self, owner: usize, name: &str) -> usize {
        let id = self.new_id();
        let room: Room = name.parse().unwrap();
        let owner_uid = self.devs[owner].uid.clone();
        self.convs.push(SConv {
            id,
            kind: Kind::Room(room),
            members: vec![owner_uid.clone()],
            invited: Vec::new(),
            events: Vec::new(),
            epoch: None,
            group_info: None,
            group_id: None,
            tree: None,
            commit_seq: 0,
        });
        let c = self.convs.len() - 1;
        self.push(c, &owner_uid, Body::Join);
        c
    }

    fn send(&mut self, d: usize, conv: &str, text: &str) -> crate::store::OutboxId {
        let (id, out) = self.devs[d]
            .engine
            .send(&conv.parse().unwrap(), &Draft::text(text))
            .unwrap();
        self.devs[d].absorb(out);
        self.run();
        id
    }

    /// How many `verb` commands device `d` sent for `conv`.
    fn sent_to(&self, d: usize, verb: &str, conv: &str) -> usize {
        self.log
            .iter()
            .filter(|(dd, l)| {
                let mut words = l.split(' ').filter(|w| !w.starts_with('@'));
                *dd == d && words.next() == Some(verb) && words.next() == Some(conv)
            })
            .count()
    }

    fn sent(&self, d: usize, verb: &str) -> usize {
        self.log
            .iter()
            .filter(|(dd, l)| *dd == d && l.split(' ').find(|w| !w.starts_with('@')) == Some(verb))
            .count()
    }
}

#[test]
fn key_packages_are_kept_up() {
    let mut net = Net::new();
    let a = net.device("alice@example.org", 1);
    net.run();
    // Ten ordinary ones and a last-resort one (12.4).
    assert_eq!(net.packages[&a].len(), 10);
    assert!(net.last_resort.contains_key(&a));
    // Enough left: nothing more on the next connection.
    let before = net.sent(a, "KEYPKG");
    reconnect(&mut net, a);
    assert_eq!(net.sent(a, "KEYPKG"), before + 1, "only KEYPKG COUNT");
    // Under five: topped up to ten.
    net.packages.get_mut(&a).unwrap().truncate(4);
    reconnect(&mut net, a);
    assert_eq!(net.packages[&a].len(), 10);
}

fn reconnect(net: &mut Net, d: usize) {
    let dev = &mut net.devs[d];
    dev.queue.clear();
    dev.engine = Dev::engine(&dev.store, dev.account, &dev.uid, &dev.key);
    let out = dev.engine.start().unwrap();
    dev.absorb(out);
    net.run();
}

#[test]
fn a_direct_conversation_is_encrypted_both_ways() {
    let mut net = Net::new();
    let a = net.device("alice@example.org", 1);
    let b = net.device("bob@example.net", 2);
    net.run();

    // Alice's first message starts the conversation (12.6): INIT, KEYPKG
    // GET for Bob and for her own other devices, COMMIT with a Welcome,
    // then ENC.
    let first = net.send(a, "bob@example.net", "hi bob");
    assert_eq!(net.sent_to(a, "INIT", "bob@example.net"), 1);
    assert_eq!(net.sent_to(a, "COMMIT", "bob@example.net"), 1);
    assert_eq!(
        net.sent(a, "MSG"),
        0,
        "never MSG to a direct conversation (12.3)"
    );
    assert_eq!(net.sent(a, "ENC"), 1);
    assert!(matches!(
        net.devs[a].store.outbox_item(first).unwrap().unwrap().state,
        OutboxState::Sent(_)
    ));
    // Bob joined by Welcome, deleted it, and reads the message.
    assert_eq!(
        net.devs[b].group("alice@example.org").unwrap().state,
        GroupState::Active
    );
    assert!(net.welcomes.get(&b).is_none_or(Vec::is_empty));
    use crate::store::e2ee::EncState::Verified;
    assert_eq!(
        net.devs[b].texts("alice@example.org"),
        [("hi bob".to_owned(), Some(Verified))]
    );
    assert_eq!(
        net.devs[a].texts("bob@example.net"),
        [("hi bob".to_owned(), Some(Verified))]
    );

    // Bob answers.
    net.send(b, "alice@example.org", "hi alice");
    assert_eq!(net.sent_to(b, "INIT", "alice@example.org"), 0);
    assert_eq!(
        net.devs[a].texts("bob@example.net"),
        [
            ("hi bob".to_owned(), Some(Verified)),
            ("hi alice".to_owned(), Some(Verified))
        ]
    );
}

#[test]
fn a_new_device_joins_by_external_commit() {
    let mut net = Net::new();
    let a = net.device("alice@example.org", 1);
    let b = net.device("bob@example.net", 2);
    net.run();
    net.send(a, "bob@example.net", "one");

    // Bob's second device signs in for the first time.
    let b2 = net.device("bob@example.net", 3);
    net.run();
    assert_eq!(net.sent_to(b2, "GROUPINFO", "alice@example.org"), 1);
    assert_eq!(
        net.devs[b2].group("alice@example.org").unwrap().state,
        GroupState::Active
    );
    let epoch = net.devs[a].group("bob@example.net").unwrap().epoch;
    assert_eq!(
        net.devs[b2].group("alice@example.org").unwrap().epoch,
        epoch
    );
    assert_eq!(net.devs[b].group("alice@example.org").unwrap().epoch, epoch);

    // Everyone reads what is sent from now on.
    net.send(a, "bob@example.net", "two");
    assert_eq!(
        net.devs[b2].texts("alice@example.org").last().unwrap().0,
        "two"
    );
    assert_eq!(
        net.devs[b].texts("alice@example.org").last().unwrap().0,
        "two"
    );
    // The epoch before it joined is not readable without history keys
    // (12.9).
    use crate::store::e2ee::EncState::Pending;
    assert_eq!(
        net.devs[b2].store_enc_states("alice@example.org"),
        [Some(Pending), Some(crate::store::e2ee::EncState::Verified)]
    );
}

impl Dev {
    /// How each ENC event of a conversation was read, in seq order.
    fn store_enc_states(&self, conv: &str) -> Vec<Option<crate::store::e2ee::EncState>> {
        self.texts_all(conv)
    }

    fn texts_all(&self, conv: &str) -> Vec<Option<crate::store::e2ee::EncState>> {
        let Some(c) = self
            .store
            .conversations(self.account)
            .unwrap()
            .into_iter()
            .find(|c| c.name.as_str() == conv)
        else {
            return Vec::new();
        };
        self.store
            .timeline(c.id, None, 100)
            .unwrap()
            .into_iter()
            .filter(|i| matches!(i.event.body, risala_proto::server::EventBody::Enc(_)))
            .map(|i| i.enc)
            .collect()
    }
}

#[test]
fn removed_keys_lose_their_leaves() {
    let mut net = Net::new();
    let a = net.device("alice@example.org", 1);
    let b = net.device("bob@example.net", 2);
    net.run();
    net.send(a, "bob@example.net", "one");
    let b2 = net.device("bob@example.net", 3);
    net.run();
    let leaves = |net: &Net| {
        net.devs[a]
            .store
            .write(|tx| {
                let row = tx
                    .conv_by_name(net.devs[a].account, &"bob@example.net".parse().unwrap())?
                    .unwrap();
                Ok(crate::e2ee::group::current_leaves(tx, &row)
                    .unwrap()
                    .unwrap()
                    .len())
            })
            .unwrap()
            .0
    };
    assert_eq!(leaves(&net), 3);

    // Bob removes his second device's key from his key file (4.7). Alice
    // learns it when she fetches it again (12.12), and removes its leaf
    // (12.6). Until then, nothing goes out: her next message waits for
    // the key file.
    let gone = net.devs[b2].public();
    net.key_files
        .get_mut(&uid("bob@example.net"))
        .unwrap()
        .retain(|k| *k != gone);
    let uid_b = uid("bob@example.net");
    let out = net.devs[a]
        .engine
        .key_file(
            &uid_b,
            Some(
                net.key_files[&uid_b]
                    .iter()
                    .map(|k| (k.clone(), None))
                    .collect(),
            ),
        )
        .unwrap();
    net.devs[a].absorb(out);
    net.run();
    assert_eq!(leaves(&net), 2);
    net.send(a, "bob@example.net", "two");
    assert_eq!(
        net.devs[b].texts("alice@example.org").last().unwrap().0,
        "two"
    );
    // The removed device can no longer read.
    assert_ne!(
        net.devs[b2]
            .texts("alice@example.org")
            .last()
            .map(|t| t.0.clone()),
        Some("two".to_owned())
    );
}

#[test]
fn an_encrypted_room_shares_its_history() {
    use risala_proto::types::{HistoryMode, SendMode};
    let mut net = Net::new();
    let a = net.device("alice@example.org", 1);
    let b = net.device("bob@example.net", 2);
    net.run();
    let room: Room = "#secret".parse().unwrap();
    net.room(a, "#secret");
    reconnect(&mut net, a);

    // Alice owns the room and is its only member: INIT (12.5).
    let out = net.devs[a]
        .engine
        .encrypt_room(&room, HistoryMode::Shared, SendMode::All)
        .unwrap();
    net.devs[a].absorb(out);
    net.run();
    assert_eq!(
        net.devs[a].group("#secret").unwrap().state,
        GroupState::Active
    );
    net.send(a, "#secret", "before bob");
    assert_eq!(
        net.sent(a, "MSG"),
        0,
        "never MSG in a room with a group (12.3)"
    );

    // Inviting adds Bob's device to the group (12.6); his device joins by
    // Welcome once it knows the room's id from INFO.
    let out = net.devs[a]
        .engine
        .invite(&room, &uid("bob@example.net"))
        .unwrap();
    net.devs[a].absorb(out);
    net.run();
    assert_eq!(net.sent(a, "INVITE"), 0);
    assert_eq!(
        net.devs[b].group("#secret").unwrap().state,
        GroupState::Active
    );
    // History is shared: Alice sent the earlier epoch's key (12.9).
    assert_eq!(net.sent(a, "ENC"), 2);

    // Bob joins the room, reads what was sent before he was invited, and
    // writes.
    let out = net.devs[b].engine.join(&room);
    net.devs[b].absorb(out);
    net.run();
    use crate::store::e2ee::EncState::Verified;
    assert_eq!(
        net.devs[b].texts("#secret"),
        [("before bob".to_owned(), Some(Verified))]
    );
    net.send(b, "#secret", "hi all");
    assert_eq!(
        net.devs[a].texts("#secret").last().unwrap(),
        &("hi all".to_owned(), Some(Verified))
    );
}

#[test]
fn a_confirmed_device_gets_the_history_keys() {
    use crate::store::e2ee::EncState::{Pending, Verified};
    let mut net = Net::new();
    let a1 = net.device("alice@example.org", 1);
    let b = net.device("bob@example.net", 2);
    net.run();
    net.send(a1, "bob@example.net", "before");
    assert!(net.devs[a1].group("alice@example.org").is_some());

    // Alice's second device joins her conversation with herself, and the
    // one with Bob, by external commit (12.6). It cannot read what was
    // sent before it joined.
    let a2 = net.device("alice@example.org", 3);
    net.run();
    assert_eq!(
        net.devs[a2].group("alice@example.org").unwrap().state,
        GroupState::Active
    );
    assert_eq!(
        net.devs[a2].store_enc_states("bob@example.net"),
        [Some(Pending)]
    );

    // Her first device tells her about the new one, and sends it nothing
    // until she confirms it (12.9).
    let fingerprint = net.devs[a2].public().fingerprint().to_string();
    assert!(
        net.devs[a1].notes.contains(&Notification::NewDevice {
            fingerprint: fingerprint.clone()
        }),
        "{:?}",
        net.devs[a1].notes
    );
    assert!(
        !net.devs[a2]
            .notes
            .iter()
            .any(|n| matches!(n, Notification::NewDevice { .. }))
    );
    let key = net.devs[a2].public();
    let out = net.devs[a1].engine.confirm_device(&key, true).unwrap();
    net.devs[a1].absorb(out);
    net.run();
    assert_eq!(
        net.devs[a2].texts("bob@example.net"),
        [("before".to_owned(), Some(Verified))]
    );
    let _ = b;
}

#[test]
fn history_keys_are_backed_up_and_restored() {
    use crate::store::e2ee::EncState::Verified;
    let mut net = Net::new();
    let a1 = net.device("alice@example.org", 1);
    let b = net.device("bob@example.net", 2);
    net.run();
    net.send(a1, "bob@example.net", "one");

    // With a recovery key, every history key is backed up (12.10).
    let recovery = risala_mls::RecoveryKey::from_bytes([7; 32]);
    let out = net.devs[a1]
        .engine
        .set_recovery_key(Some(recovery.clone()))
        .unwrap();
    net.devs[a1].absorb(out);
    net.run();
    let alice = uid("alice@example.org");
    let backed: Vec<u64> = net
        .backups
        .keys()
        .filter(|(u, _, _)| *u == alice)
        .map(|(_, _, e)| *e)
        .collect();
    assert!(backed.len() >= 2, "{backed:?}");
    net.send(a1, "bob@example.net", "two");

    // A new device restores them, and reads everything, unverified where
    // it does not know the sender's key (12.8).
    let a2 = net.device("alice@example.org", 3);
    net.run();
    let identity = alice.to_identity().unwrap();
    let backup = recovery.backup_key(&identity);
    let keys: Vec<(Id, u64, risala_mls::HistoryKey)> = net
        .backups
        .iter()
        .filter(|((u, _, _), _)| *u == alice)
        .map(|((_, id, e), blob)| {
            let id: Id = id.parse().unwrap();
            let key = backup.open(&id, *e, blob).unwrap();
            (id, *e, key)
        })
        .collect();
    let dev = &net.devs[a2];
    let (account, me) = (dev.account, dev.uid.clone());
    dev.store
        .write(|tx| {
            let mut convs = Vec::new();
            for (id, epoch, key) in &keys {
                tx.put_history_key(
                    account,
                    id,
                    *epoch,
                    key,
                    crate::store::e2ee::KeySource::Backup,
                    None,
                    None,
                )?;
                if let Some(row) = tx.conv_by_id(account, id)? {
                    convs.push(row.name);
                }
            }
            tx.decrypt_cascade(account, &me, convs)
        })
        .unwrap();
    let texts: Vec<String> = net.devs[a2]
        .texts("bob@example.net")
        .into_iter()
        .map(|(t, _)| t)
        .collect();
    assert_eq!(texts, ["one", "two"]);
    assert!(
        net.devs[a2]
            .texts("bob@example.net")
            .iter()
            .all(|(_, s)| *s == Some(Verified))
    );
    let _ = b;
}

#[test]
fn a_commit_that_adds_an_outsider_is_rejected() {
    let mut net = Net::new();
    let a = net.device("alice@example.org", 1);
    let b = net.device("bob@example.net", 2);
    let c = net.device("carol@example.com", 4);
    net.run();
    net.send(a, "bob@example.net", "hi");

    // Bob's device, misbehaving, adds Carol's device to his direct
    // conversation with Alice. This server does not check (12.5).
    let kp = net.packages.get_mut(&c).unwrap().pop().unwrap();
    let dev = &net.devs[b];
    let device = crate::e2ee::Device::new(dev.uid.clone(), dev.key.clone()).unwrap();
    let conv: Conv = "alice@example.org".parse().unwrap();
    let account = dev.account;
    let (commit, _) = dev
        .store
        .write_with(|tx| {
            let row = tx.conv_by_name(account, &conv)?.unwrap();
            let (kp, _) =
                crate::e2ee::group::checked_key_package(&device, &uid("carol@example.com"), &kp)?;
            crate::e2ee::group::own_commit(
                tx,
                &device,
                &row,
                risala_mls::group::Changes {
                    add: vec![kp],
                    ..Default::default()
                },
            )
        })
        .unwrap();
    net.handle(
        b,
        Outgoing {
            req: ReqId(9999),
            command: Command::Commit {
                conv,
                commit: commit.commit,
                group_info: commit.group_info,
                welcome: commit.welcome,
            },
        },
    );
    net.run();

    // Alice's device rejects it, warns, and sends nothing more there
    // (12.6).
    assert_eq!(
        net.devs[a].group("bob@example.net").unwrap().state,
        GroupState::Rejected
    );
    assert!(net.devs[a].notes.contains(&Notification::GroupRejected {
        conv: "bob@example.net".parse().unwrap()
    }));
    let id = net.send(a, "bob@example.net", "after");
    assert_eq!(
        net.devs[a].store.outbox_item(id).unwrap().unwrap().state,
        OutboxState::Queued
    );
    // It does not join the group again either (12.6).
    assert_eq!(net.sent_to(a, "GROUPINFO", "bob@example.net"), 0);
}
