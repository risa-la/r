//! Tests of the encryption engine (SPEC 12) with real MLS groups: devices
//! on caches of their own, each with an engine, and a small server in
//! memory that relays what they send.
//!
//! The server here checks only what the tests need: epochs (`stale`),
//! who is in each conversation, and KeyPackages handed out once. The real
//! server's checks of 12.5 are tested in `risala-server`.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

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
use crate::e2ee::content::Control;
use risala_mls::RisalaConversation;
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
    /// The shortest [`Output::retry_after`] asked for.
    retry: Option<Duration>,
    /// How far the device's clock is ahead of the real one, in ms.
    skew: Arc<AtomicU64>,
}

impl Dev {
    fn new(me: &str, seed: u8) -> Dev {
        let store = Store::open_in_memory().unwrap();
        let server: ServerAddr = "chat.example.org".parse().unwrap();
        let me = uid(me);
        let account = store.account(&server, &me).unwrap();
        let key = Arc::new(SecretKey::from_seed([seed; 32]));
        let skew = Arc::new(AtomicU64::new(0));
        let engine = Dev::engine(&store, account, &me, &key, &skew);
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
            retry: None,
            skew,
        }
    }

    fn engine(
        store: &Store,
        account: AccountId,
        me: &Uid,
        key: &Arc<SecretKey>,
        skew: &Arc<AtomicU64>,
    ) -> SyncEngine {
        let skew = skew.clone();
        let config = SyncConfig {
            lazy_gap: None,
            fetch_blocks: false,
            clock: Clock::new(move || {
                let ahead = Duration::from_millis(skew.load(Ordering::Relaxed));
                Timestamp::now().checked_add(ahead).unwrap()
            }),
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
        if let Some(r) = out.retry_after {
            self.retry = Some(self.retry.map_or(r, |old| old.min(r)));
        }
    }

    /// Moves the device's clock forward by `by`.
    fn later(&self, by: Duration) {
        self.skew
            .fetch_add(by.as_millis() as u64, Ordering::Relaxed);
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
    Invite(Uid),
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
            Body::Invite(u) => format!("{head} INVITE {conv} {u}"),
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
    /// Key files a device cannot fetch: the fetch fails (4.4).
    unreachable: Vec<(usize, Uid)>,
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
            unreachable: Vec::new(),
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
                        .filter(|_| !self.unreachable.contains(&(d, uid.clone())))
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
                    // A direct conversation that INIT started is listed
                    // with head 0 (7.1).
                    .filter(|c| {
                        c.members.contains(&me) && (!c.events.is_empty() || c.epoch.is_some())
                    })
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
                    self.convs[c].invited.push(invitee.clone());
                    // The server records the invitation (12.6).
                    if matches!(self.convs[c].kind, Kind::Room(_)) {
                        self.push(c, &me, Body::Invite(invitee));
                    }
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
    dev.engine = Dev::engine(&dev.store, dev.account, &dev.uid, &dev.key, &dev.skew);
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
fn a_message_queued_offline_starts_its_conversation() {
    let mut net = Net::new();
    let a = net.device("alice@example.org", 1);
    let b = net.device("bob@example.net", 2);
    net.run();
    // Alice writes to Bob while offline: the message waits in the outbox.
    let dev = &net.devs[a];
    let account = dev.account;
    dev.store
        .write(|tx| {
            tx.queue(
                account,
                &"bob@example.net".parse().unwrap(),
                None,
                &Draft::text("written offline"),
                Timestamp::now(),
            )
        })
        .unwrap();
    // On the next connection, INIT waits for WELCOME LIST, and then the
    // conversation starts and the message goes (12.6, 12.7).
    reconnect(&mut net, a);
    assert_eq!(net.sent_to(a, "INIT", "bob@example.net"), 1);
    use crate::store::e2ee::EncState::Verified;
    assert_eq!(
        net.devs[b].texts("alice@example.org"),
        [("written offline".to_owned(), Some(Verified))]
    );
}

/// Whether outbox entry `id` of device `d` is queued and held (12.6).
fn held(net: &Net, d: usize, id: crate::store::OutboxId) -> bool {
    let item = net.devs[d].store.outbox_item(id).unwrap().unwrap();
    item.state == OutboxState::Queued && item.held
}

/// Whether outbox entry `id` of device `d` was sent, and is not held.
fn went(net: &Net, d: usize, id: crate::store::OutboxId) -> bool {
    let item = net.devs[d].store.outbox_item(id).unwrap().unwrap();
    matches!(item.state, OutboxState::Sent(_)) && !item.held
}

impl Net {
    /// How many times device `d` asked for `uid`'s KeyPackages.
    fn asked_for(&self, d: usize, uid: &str) -> usize {
        let want = format!("KEYPKG GET {uid}");
        self.log
            .iter()
            .filter(|(dd, l)| *dd == d && l.contains(&want))
            .count()
    }

    /// Takes away the KeyPackages the server holds for device `d`.
    fn take_packages(&mut self, d: usize) -> (Vec<mls::KeyPackage>, mls::KeyPackage) {
        (
            self.packages.remove(&d).unwrap(),
            self.last_resort.remove(&d).unwrap(),
        )
    }

    fn resume(&mut self, d: usize) {
        let out = self.devs[d].engine.resume_outbox().unwrap();
        self.devs[d].absorb(out);
        self.run();
    }
}

#[test]
fn messages_wait_until_the_other_side_has_a_device() {
    use crate::store::e2ee::EncState::Verified;
    let mut net = Net::new();
    let a = net.device("alice@example.org", 1);
    net.run();

    // Bob has no device yet, so KEYPKG GET finds nothing for him. Alice's
    // device starts the conversation, but holds her messages: Bob could
    // never read them (12.6).
    let one = net.send(a, "bob@example.net", "one");
    let two = net.send(a, "bob@example.net", "two");
    assert_eq!(net.sent_to(a, "INIT", "bob@example.net"), 1);
    assert_eq!(net.sent(a, "ENC"), 0);
    assert!(held(&net, a, one) && held(&net, a, two));
    // It asks again later, not at once.
    assert_eq!(net.asked_for(a, "bob@example.net"), 1);
    assert!(
        net.devs[a]
            .retry
            .is_some_and(|r| r <= SyncConfig::default().peer_retry)
    );

    // Bob's first device signs in. SYNC lists the conversation, and the
    // device joins it by external commit. Alice's device sees the commit
    // and sends what it held, in order.
    let b = net.device("bob@example.net", 2);
    net.run();
    assert_eq!(net.sent_to(b, "GROUPINFO", "alice@example.org"), 1);
    assert_eq!(
        net.devs[b].texts("alice@example.org"),
        [
            ("one".to_owned(), Some(Verified)),
            ("two".to_owned(), Some(Verified))
        ]
    );
    assert!(went(&net, a, one) && went(&net, a, two));
    assert_eq!(net.asked_for(a, "bob@example.net"), 1);
}

#[test]
fn held_messages_go_once_key_packages_appear() {
    use crate::store::e2ee::EncState::Verified;
    let mut net = Net::new();
    let a = net.device("alice@example.org", 1);
    let b = net.device("bob@example.net", 2);
    net.run();
    // The server has no KeyPackages of Bob's device, and the device does
    // not hear of the new conversation, which has no events.
    let (packages, last) = net.take_packages(b);
    let one = net.send(a, "bob@example.net", "one");
    assert!(held(&net, a, one));

    // Woken before it is time, the device does not ask again.
    net.resume(a);
    assert_eq!(net.asked_for(a, "bob@example.net"), 1);

    // Once it is time, it asks again: it adds Bob's device with a Welcome,
    // then sends.
    net.packages.insert(b, packages);
    net.last_resort.insert(b, last);
    net.devs[a].later(SyncConfig::default().peer_retry);
    net.resume(a);
    assert_eq!(net.asked_for(a, "bob@example.net"), 2);
    assert_eq!(
        net.devs[b].texts("alice@example.org"),
        [("one".to_owned(), Some(Verified))]
    );
    assert!(went(&net, a, one));
}

#[test]
fn held_messages_ask_again_on_each_connection() {
    use crate::store::e2ee::EncState::Verified;
    let mut net = Net::new();
    let a = net.device("alice@example.org", 1);
    let b = net.device("bob@example.net", 2);
    net.run();
    let (packages, last) = net.take_packages(b);
    let one = net.send(a, "bob@example.net", "one");
    assert!(held(&net, a, one));

    // The next connection asks at once.
    net.packages.insert(b, packages);
    net.last_resort.insert(b, last);
    reconnect(&mut net, a);
    assert_eq!(net.asked_for(a, "bob@example.net"), 2);
    assert_eq!(
        net.devs[b].texts("alice@example.org"),
        [("one".to_owned(), Some(Verified))]
    );
    assert!(went(&net, a, one));
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
fn a_removal_waits_for_a_key_file_that_cannot_be_fetched() {
    let mut net = Net::new();
    let a = net.device("alice@example.org", 1);
    let b = net.device("bob@example.net", 2);
    net.run();
    net.send(a, "bob@example.net", "one");
    let b2 = net.device("bob@example.net", 3);
    net.run();

    // Bob's second key leaves his key file, and Alice's device removes its
    // leaf. Bob's first device must check that against his key file
    // (12.6), which it cannot fetch right now.
    let bob = uid("bob@example.net");
    let gone = net.devs[b2].public();
    net.key_files.get_mut(&bob).unwrap().retain(|k| *k != gone);
    net.unreachable.push((b, bob.clone()));
    let listed: Vec<_> = net.key_files[&bob]
        .iter()
        .map(|k| (k.clone(), None))
        .collect();
    let out = net.devs[a]
        .engine
        .key_file(&bob, Some(listed.clone()))
        .unwrap();
    net.devs[a].absorb(out);
    net.run();
    let epoch = net.devs[a].group("bob@example.net").unwrap().epoch;

    // It does not reject the commit: it waits, behind it (PLAN.md 47).
    let group = net.devs[b].group("alice@example.org").unwrap();
    assert_eq!(group.state, GroupState::Active);
    assert!(group.epoch < epoch);
    assert!(!net.devs[b].notes.contains(&Notification::GroupRejected {
        conv: "alice@example.org".parse().unwrap()
    }));

    // Once the key file can be fetched, the commit is applied, and Bob
    // reads what was sent after it.
    net.unreachable.clear();
    let out = net.devs[b].engine.key_file(&bob, Some(listed)).unwrap();
    net.devs[b].absorb(out);
    net.run();
    assert_eq!(net.devs[b].group("alice@example.org").unwrap().epoch, epoch);
    net.send(a, "bob@example.net", "two");
    assert_eq!(
        net.devs[b].texts("alice@example.org").last().unwrap().0,
        "two"
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

    // Inviting adds Bob's device to the group (12.6). His device keeps the
    // Welcome until it can check the group's leaves against the room's
    // events, once Bob has joined the room.
    let out = net.devs[a]
        .engine
        .invite(&room, &uid("bob@example.net"))
        .unwrap();
    net.devs[a].absorb(out);
    net.run();
    assert_eq!(net.sent(a, "INVITE"), 0);
    assert!(net.devs[b].group("#secret").is_none());
    assert_eq!(net.welcomes[&b].len(), 1);
    // History is shared: Alice sent the earlier epoch's key (12.9).
    assert_eq!(net.sent(a, "ENC"), 2);

    // Bob joins the room, and his device joins its group by the Welcome.
    // He reads what was sent before he was invited, and writes.
    let out = net.devs[b].engine.join(&room);
    net.devs[b].absorb(out);
    net.run();
    assert_eq!(
        net.devs[b].group("#secret").unwrap().state,
        GroupState::Active
    );
    assert!(net.welcomes[&b].is_empty());
    assert_eq!(net.sent_to(b, "GROUPINFO", "#secret"), 0);
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
fn a_confirmed_device_gets_the_recovery_key() {
    let mut net = Net::new();
    let a1 = net.device("alice@example.org", 1);
    let b = net.device("bob@example.net", 2);
    net.run();
    net.send(a1, "bob@example.net", "before");
    let recovery = risala_mls::RecoveryKey::from_bytes([7; 32]);
    net.list_recovery("alice@example.org", &recovery);
    let out = net.devs[a1]
        .engine
        .set_recovery_key(Some(recovery.clone()))
        .unwrap();
    net.devs[a1].absorb(out);
    net.run();

    // A new device gets nothing before the user confirms it, and then the
    // recovery key with the history keys (12.9, 12.10).
    let a2 = net.device("alice@example.org", 3);
    net.run();
    assert_eq!(net.devs[a2].recovery, None);
    let key = net.devs[a2].public();
    let out = net.devs[a1].engine.confirm_device(&key, true).unwrap();
    net.devs[a1].absorb(out);
    net.run();
    assert_eq!(net.devs[a2].recovery, Some(recovery.clone()));

    // It backs up what it gets from then on, without the first device.
    let alice = uid("alice@example.org");
    let before = net.backups.keys().filter(|(u, _, _)| *u == alice).count();
    let b2 = net.device("bob@example.net", 4);
    net.run();
    net.send(a2, "bob@example.net", "after");
    assert!(
        net.log
            .iter()
            .any(|(d, l)| *d == a2 && l.contains("BACKUP ADD")),
        "the new device backs up"
    );
    assert!(net.backups.keys().filter(|(u, _, _)| *u == alice).count() > before);
    let _ = (b, b2);
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

impl Net {
    /// Device `d` joins conversation `c`'s group by external commit,
    /// whoever it is, as a server that does not check would let it, and
    /// the commit is sent to the conversation's devices (12.6).
    fn force_external_join(&mut self, d: usize, c: usize) {
        let s = &self.convs[c];
        let info = wire::group_info_from_wire(s.group_info.as_ref().unwrap()).unwrap();
        let tree = wire::tree_from_wire(s.tree.as_ref().unwrap()).unwrap();
        let dev = &self.devs[d];
        let device = crate::e2ee::Device::new(dev.uid.clone(), dev.key.clone()).unwrap();
        let (commit, _) = dev
            .store
            .write(|tx| {
                let provider = device.provider(tx.mls_storage());
                let (_, bundle) = risala_mls::join_by_external_commit(
                    &provider,
                    &device.signer(),
                    &device.uid,
                    info,
                    tree,
                )
                .unwrap();
                let (commit, _, _) = bundle.into_messages();
                Ok(wire::commit_to_wire(&commit).unwrap())
            })
            .unwrap();
        let epoch = self.convs[c].epoch.unwrap() + 1;
        self.convs[c].epoch = Some(epoch);
        let from = self.devs[d].uid.clone();
        self.push(c, &from, Body::Commit { epoch, commit });
        self.run();
    }
}

#[test]
fn an_outsiders_external_commit_to_a_direct_conversation_is_rejected() {
    let mut net = Net::new();
    let a = net.device("alice@example.org", 1);
    let b = net.device("bob@example.net", 2);
    let c = net.device("carol@example.com", 4);
    net.run();
    net.send(a, "bob@example.net", "hi");

    // Carol's device joins Alice and Bob's group by external commit, which
    // this server lets through (12.5).
    let conv = net.conv_of(a, "bob@example.net").unwrap();
    net.force_external_join(c, conv);

    // Alice's device rejects it: her messages must never reach Carol
    // (12.6).
    assert_eq!(
        net.devs[a].group("bob@example.net").unwrap().state,
        GroupState::Rejected
    );
    let enc_before = net.sent(a, "ENC");
    net.send(a, "bob@example.net", "secret");
    assert_eq!(net.sent(a, "ENC"), enc_before);
    let _ = b;
}

#[test]
fn a_key_listed_for_someone_else_does_not_count() {
    // Bob's second key left his key file, and Mallory's key file lists it
    // (12.12): it is still not Bob's.
    let dev = Dev::new("alice@example.org", 1);
    let (bob, mallory) = (uid("bob@example.net"), uid("mallory@example.com"));
    let b1 = SecretKey::from_seed([2; 32]).public_key();
    let b2 = SecretKey::from_seed([3; 32]).public_key();
    let account = dev.account;
    let now = 1_000;
    let listed = dev
        .store
        .write(|tx| {
            tx.note_device_key(account, &bob, &b1)?;
            tx.note_device_key(account, &bob, &b2)?;
            tx.key_file_fetched(account, &bob, Some(&[(b1.clone(), None)]), now)?;
            tx.key_file_fetched(account, &mallory, Some(&[(b2.clone(), None)]), now)?;
            Ok((
                tx.key_listed(account, &bob, &b2)?,
                tx.key_listed(account, &mallory, &b2)?,
            ))
        })
        .unwrap()
        .0;
    assert_eq!(listed, (Some(false), Some(true)));
}

#[test]
fn a_leaf_with_someone_elses_key_is_not_confirmed() {
    let mut net = Net::new();
    let a = net.device("alice@example.org", 1);
    let b = net.device("bob@example.net", 2);
    let c = net.device("carol@example.com", 4);
    net.run();
    net.send(a, "bob@example.net", "hi");
    // Alice's device knows Carol's key from Carol's key file.
    let carol = uid("carol@example.com");
    let carol_key = net.devs[c].public();
    let out = net.devs[a]
        .engine
        .key_file(&carol, Some(vec![(carol_key.clone(), None)]))
        .unwrap();
    net.devs[a].absorb(out);
    net.run();

    // Bob's device, misbehaving, adds a leaf with Bob's credential and
    // Carol's key (12.2).
    let dev = &net.devs[b];
    let bob_device = crate::e2ee::Device::new(dev.uid.clone(), dev.key.clone()).unwrap();
    let imposter = crate::e2ee::Device::new(dev.uid.clone(), net.devs[c].key.clone()).unwrap();
    let conv: Conv = "alice@example.org".parse().unwrap();
    let account = dev.account;
    let (commit, _) = dev
        .store
        .write_with(|tx| {
            let kp = crate::e2ee::group::key_packages(tx, &imposter, 1, false)?.remove(0);
            let (kp, _) = crate::e2ee::group::checked_key_package(&bob_device, &dev.uid, &kp)?;
            let row = tx.conv_by_name(account, &conv)?.unwrap();
            crate::e2ee::group::own_commit(
                tx,
                &bob_device,
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
                welcome: None,
            },
        },
    );
    net.run();

    // Bob's key file does not list that key, so Alice's device sends
    // nothing to the leaf, and removes it (12.6).
    let account = net.devs[a].account;
    let leaves = net.devs[a]
        .store
        .write(|tx| {
            let row = tx
                .conv_by_name(account, &"bob@example.net".parse().unwrap())?
                .unwrap();
            Ok(crate::e2ee::group::current_leaves(tx, &row).unwrap().unwrap())
        })
        .unwrap()
        .0;
    assert!(
        !leaves.iter().any(|l| l.key == carol_key),
        "the leaf with Carol's key stays: {leaves:?}"
    );
}

impl Net {
    /// A commit message of conversation `c`, to deliver where it does not
    /// belong.
    fn a_commit_of(&self, c: usize) -> mls::CommitMessage {
        self.convs[c]
            .events
            .iter()
            .find_map(|e| match &e.body {
                Body::Commit { commit, .. } => Some(commit.clone()),
                _ => None,
            })
            .unwrap()
    }

    /// The server sends a COMMIT event of epoch `epoch` with `commit` in
    /// conversation `c`, as if `from` sent it.
    fn forge_commit(&mut self, c: usize, from: &str, epoch: u64, commit: mls::CommitMessage) {
        self.push(c, &uid(from), Body::Commit { epoch, commit });
        self.run();
    }

    /// An encrypted room `name` owned by device `a`, with device `b`'s
    /// identity invited and joined. Returns the conversation.
    fn encrypted_room(&mut self, a: usize, b: usize, name: &str) -> usize {
        use risala_proto::types::{HistoryMode, SendMode};
        let room: Room = name.parse().unwrap();
        let c = self.room(a, name);
        reconnect(self, a);
        let out = self.devs[a]
            .engine
            .encrypt_room(&room, HistoryMode::Shared, SendMode::All)
            .unwrap();
        self.devs[a].absorb(out);
        self.run();
        let invitee = self.devs[b].uid.clone();
        let out = self.devs[a].engine.invite(&room, &invitee).unwrap();
        self.devs[a].absorb(out);
        self.run();
        let out = self.devs[b].engine.join(&room);
        self.devs[b].absorb(out);
        self.run();
        assert_eq!(
            self.devs[b].group(name).unwrap().state,
            GroupState::Active
        );
        c
    }
}

#[test]
fn a_room_group_with_an_outsider_is_not_joined_again() {
    use risala_proto::types::{HistoryMode, SendMode};
    let mut net = Net::new();
    let a = net.device("alice@example.org", 1);
    let b = net.device("bob@example.net", 2);
    let m = net.device("mallory@example.com", 5);
    net.run();
    net.send(a, "bob@example.net", "hi");
    let direct = net.conv_of(a, "bob@example.net").unwrap();
    let c = net.encrypted_room(a, b, "#secret");

    // Mallory makes a group that names the room, and the server hands it
    // out as the room's group. It then sends Bob's device a commit that
    // MLS refuses, so that the device would join again (12.6).
    let id: Id = net.convs[c].id.parse().unwrap();
    let dev = &net.devs[m];
    let device = crate::e2ee::Device::new(dev.uid.clone(), dev.key.clone()).unwrap();
    let (info, tree) = dev
        .store
        .write(|tx| {
            let provider = device.provider(tx.mls_storage());
            let conversation =
                RisalaConversation::room(&id, HistoryMode::Shared, SendMode::All);
            let group =
                risala_mls::create_group(&provider, &device.signer(), &device.uid, &conversation)
                    .unwrap();
            let info = group
                .export_group_info(&*device.crypto, &device.signer(), false)
                .unwrap();
            Ok((
                wire::group_info_to_wire(&info).unwrap(),
                wire::tree_to_wire(&group.export_ratchet_tree()).unwrap(),
            ))
        })
        .unwrap()
        .0;
    let epoch = net.convs[c].epoch.unwrap() + 1;
    net.convs[c].group_info = Some(info);
    net.convs[c].tree = Some(tree);
    net.convs[c].epoch = Some(0);
    let junk = net.a_commit_of(direct);
    net.forge_commit(c, "alice@example.org", epoch, junk);

    // Bob's device does not join a group with a leaf of someone the room's
    // events do not show as a member or invitee.
    assert_eq!(net.sent_to(b, "COMMIT", "#secret"), 0);
    assert_ne!(
        net.devs[b].group("#secret").unwrap().state,
        GroupState::Active
    );
}

/// Flips the last byte of a commit: its membership tag, which only the
/// group's members can check.
fn bad_membership_tag(commit: &mls::CommitMessage) -> mls::CommitMessage {
    let mut bytes = commit.decode();
    *bytes.last_mut().unwrap() ^= 1;
    mls::CommitMessage::from_bytes(&bytes).unwrap()
}

#[test]
fn a_commit_that_fails_the_checks_and_mls_is_rejected() {
    let mut net = Net::new();
    let a = net.device("alice@example.org", 1);
    let b = net.device("bob@example.net", 2);
    let c = net.device("carol@example.com", 4);
    net.run();
    net.send(a, "bob@example.net", "hi");

    // Bob's device adds Carol's to his direct conversation with Alice,
    // with a membership tag that MLS refuses.
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
    let s = net.conv_of(a, "bob@example.net").unwrap();
    let epoch = net.convs[s].epoch.unwrap() + 1;
    net.convs[s].epoch = Some(epoch);
    net.convs[s].group_info = Some(commit.group_info);
    net.forge_commit(s, "bob@example.net", epoch, bad_membership_tag(&commit.commit));

    // Alice's device rejects it, rather than join again (12.6).
    assert_eq!(
        net.devs[a].group("bob@example.net").unwrap().state,
        GroupState::Rejected
    );
    assert_eq!(net.sent_to(a, "GROUPINFO", "bob@example.net"), 0);
}

#[test]
fn a_commit_that_skips_an_epoch_is_not_a_reason_to_join_again() {
    let mut net = Net::new();
    let a = net.device("alice@example.org", 1);
    let b = net.device("bob@example.net", 2);
    net.run();
    net.send(a, "bob@example.net", "hi");
    let s = net.conv_of(a, "bob@example.net").unwrap();

    // Every event is here, and the server sends a commit two epochs on.
    let epoch = net.convs[s].epoch.unwrap() + 2;
    let commit = net.a_commit_of(s);
    net.forge_commit(s, "alice@example.org", epoch, commit);

    // Nothing expired, so the server left a commit out: Bob's device does
    // not take whatever group GROUPINFO offers (12.6).
    assert_eq!(net.sent_to(b, "GROUPINFO", "alice@example.org"), 0);
    assert_eq!(
        net.devs[b].group("alice@example.org").unwrap().state,
        GroupState::Rejected
    );
}

#[test]
fn a_rejected_group_stays_rejected_under_a_new_id() {
    let mut net = Net::new();
    let a = net.device("alice@example.org", 1);
    let _b = net.device("bob@example.net", 2);
    let c = net.device("carol@example.com", 4);
    net.run();
    net.send(a, "bob@example.net", "hi");
    let s = net.conv_of(a, "bob@example.net").unwrap();
    net.force_external_join(c, s);
    assert_eq!(
        net.devs[a].group("bob@example.net").unwrap().state,
        GroupState::Rejected
    );

    // The server reports another id for the conversation. The device
    // discards its history, but not the rejection (12.6).
    net.convs[s].id = "c9999999".into();
    reconnect(&mut net, a);
    assert_eq!(
        net.devs[a].group("bob@example.net").unwrap().state,
        GroupState::Rejected
    );
    assert_eq!(net.sent_to(a, "GROUPINFO", "bob@example.net"), 0);
}

impl Net {
    /// Lists the signing key of `recovery` in `who`'s key file (12.10).
    fn list_recovery(&mut self, who: &str, recovery: &risala_mls::RecoveryKey) {
        let id = uid(who).to_identity().unwrap();
        self.key_files
            .entry(uid(who))
            .or_default()
            .push(recovery.signing_key(&id).public_key());
    }

    fn confirm(&mut self, d: usize, of: usize, yes: bool) {
        let key = self.devs[of].public();
        let out = self.devs[d].engine.confirm_device(&key, yes).unwrap();
        self.devs[d].absorb(out);
        self.run();
    }

    /// Whether device `d`'s account holds a history key for epoch `epoch`
    /// of conversation `id`.
    fn holds_key(&self, d: usize, id: &str, epoch: u64) -> bool {
        let dev = &self.devs[d];
        let account = dev.account;
        let id: Id = id.parse().unwrap();
        dev.store
            .write(|tx| Ok(tx.history_key(account, &id, epoch)?.is_some()))
            .unwrap()
            .0
    }
}

#[test]
fn an_unconfirmed_device_does_not_get_the_recovery_key() {
    let mut net = Net::new();
    let a1 = net.device("alice@example.org", 1);
    let _b = net.device("bob@example.net", 2);
    net.run();
    net.send(a1, "bob@example.net", "before");
    let recovery = risala_mls::RecoveryKey::from_bytes([7; 32]);
    net.list_recovery("alice@example.org", &recovery);
    let out = net.devs[a1]
        .engine
        .set_recovery_key(Some(recovery.clone()))
        .unwrap();
    net.devs[a1].absorb(out);
    let a2 = net.device("alice@example.org", 3);
    net.run();

    // Every leaf of the conversation with herself reads what is sent
    // there, so the recovery key waits while a device is not confirmed
    // (12.9, 12.10).
    let out = net.devs[a1].engine.share_recovery_key(&recovery).unwrap();
    net.devs[a1].absorb(out);
    net.run();
    assert_eq!(net.devs[a2].recovery, None);

    // Once she confirms it, it gets the key.
    net.confirm(a1, a2, true);
    assert_eq!(net.devs[a2].recovery, Some(recovery));
}

#[test]
fn keys_wait_while_any_own_device_is_unconfirmed() {
    use crate::store::e2ee::EncState::{Pending, Verified};
    let mut net = Net::new();
    let a1 = net.device("alice@example.org", 1);
    let _b = net.device("bob@example.net", 2);
    net.run();
    net.send(a1, "bob@example.net", "before");
    let a2 = net.device("alice@example.org", 3);
    net.run();
    let a3 = net.device("alice@example.org", 4);
    net.run();

    // Alice confirms her third device, and not yet her second: the second
    // would read the history keys too, so none are sent (12.9).
    net.confirm(a1, a3, true);
    assert_eq!(net.devs[a2].store_enc_states("bob@example.net"), [Some(Pending)]);
    assert_eq!(net.devs[a3].store_enc_states("bob@example.net"), [Some(Pending)]);

    // She declines the second. Its leaves are removed from every group,
    // and then the third gets the keys.
    net.confirm(a1, a2, false);
    for conv in ["alice@example.org", "bob@example.net"] {
        let leaves = {
            let dev = &net.devs[a1];
            let account = dev.account;
            dev.store
                .write(|tx| {
                    let row = tx.conv_by_name(account, &conv.parse().unwrap())?.unwrap();
                    Ok(crate::e2ee::group::current_leaves(tx, &row).unwrap().unwrap())
                })
                .unwrap()
                .0
        };
        assert!(
            !leaves.iter().any(|l| l.key == net.devs[a2].public()),
            "{conv} keeps the declined device's leaf"
        );
    }
    assert_eq!(
        net.devs[a3].texts("bob@example.net"),
        [("before".to_owned(), Some(Verified))]
    );
    assert_eq!(net.devs[a2].store_enc_states("bob@example.net"), [Some(Pending)]);
}

#[test]
fn keys_from_an_unconfirmed_device_are_ignored() {
    let mut net = Net::new();
    let a1 = net.device("alice@example.org", 1);
    let _b = net.device("bob@example.net", 2);
    net.run();
    net.send(a1, "bob@example.net", "before");
    let a2 = net.device("alice@example.org", 3);
    net.run();

    // The new device, which Alice has not confirmed, sends a history key
    // and a recovery key in the conversation with herself.
    let recovery = risala_mls::RecoveryKey::from_bytes([9; 32]);
    net.list_recovery("alice@example.org", &recovery);
    let conv: Conv = "alice@example.org".parse().unwrap();
    let account = net.devs[a2].account;
    let row = net.devs[a2]
        .store
        .write(|tx| tx.conv_by_name(account, &conv))
        .unwrap()
        .0
        .unwrap();
    let lines = vec![
        Control::Key {
            id: "c7777777".parse().unwrap(),
            epoch: 0,
            key: risala_mls::HistoryKey::from_bytes([1; 48]),
        },
        Control::Recovery(recovery),
    ];
    assert!(
        net.devs[a2]
            .engine
            .send_control_for(&conv, &row, lines, None)
            .unwrap()
    );
    let out = net.devs[a2].engine.resume_outbox().unwrap();
    net.devs[a2].absorb(out);
    net.run();

    // Alice's first device takes neither (12.9, 12.10).
    assert!(!net.holds_key(a1, "c7777777", 0));
    assert_eq!(net.devs[a1].recovery, None);
}

#[test]
fn a_recovery_key_counts_only_while_the_key_file_lists_it() {
    let mut net = Net::new();
    let a1 = net.device("alice@example.org", 1);
    net.run();
    let a2 = net.device("alice@example.org", 3);
    net.run();
    net.confirm(a1, a2, true);

    // A recovery key whose signing key the key file does not list is
    // ignored (12.10).
    let unlisted = risala_mls::RecoveryKey::from_bytes([3; 32]);
    let out = net.devs[a2].engine.set_recovery_key(Some(unlisted.clone())).unwrap();
    net.devs[a2].absorb(out);
    let a1_conv: Conv = "alice@example.org".parse().unwrap();
    let account = net.devs[a2].account;
    let row = net.devs[a2]
        .store
        .write(|tx| tx.conv_by_name(account, &a1_conv))
        .unwrap()
        .0
        .unwrap();
    net.devs[a2]
        .engine
        .send_control_for(&a1_conv, &row, vec![Control::Recovery(unlisted)], None)
        .unwrap();
    let out = net.devs[a2].engine.resume_outbox().unwrap();
    net.devs[a2].absorb(out);
    net.run();
    assert_eq!(net.devs[a1].recovery, None);

    // A listed one is taken by a device that holds none.
    let first = risala_mls::RecoveryKey::from_bytes([4; 32]);
    net.list_recovery("alice@example.org", &first);
    let out = net.devs[a2].engine.set_recovery_key(Some(first.clone())).unwrap();
    net.devs[a2].absorb(out);
    let out = net.devs[a2].engine.share_recovery_key(&first).unwrap();
    net.devs[a2].absorb(out);
    net.run();
    assert_eq!(net.devs[a1].recovery, Some(first.clone()));

    // A device that holds one asks the user before replacing it.
    let second = risala_mls::RecoveryKey::from_bytes([5; 32]);
    net.list_recovery("alice@example.org", &second);
    let out = net.devs[a2].engine.set_recovery_key(Some(second.clone())).unwrap();
    net.devs[a2].absorb(out);
    let out = net.devs[a2].engine.share_recovery_key(&second).unwrap();
    net.devs[a2].absorb(out);
    net.run();
    assert_eq!(net.devs[a1].recovery, Some(first));
    assert!(net.devs[a1].notes.contains(&Notification::RecoveryKeyOffered));
    let out = net.devs[a1].engine.accept_recovery_key(true).unwrap();
    net.devs[a1].absorb(out);
    assert_eq!(net.devs[a1].recovery, Some(second));
}

#[test]
fn a_welcome_does_not_undo_a_rejection() {
    let mut net = Net::new();
    let a = net.device("alice@example.org", 1);
    let b = net.device("bob@example.net", 2);
    let c = net.device("carol@example.com", 4);
    net.run();
    net.send(a, "bob@example.net", "hi");
    let s = net.conv_of(a, "bob@example.net").unwrap();
    net.force_external_join(c, s);
    assert_eq!(
        net.devs[a].group("bob@example.net").unwrap().state,
        GroupState::Rejected
    );

    // Bob's device makes a new group for the conversation, adds Alice's
    // device to it, and the server hands her device the Welcome.
    let kp = net.packages.get_mut(&a).unwrap().pop().unwrap();
    let dev = &net.devs[b];
    let device = crate::e2ee::Device::new(dev.uid.clone(), dev.key.clone()).unwrap();
    let alice = uid("alice@example.org");
    let (welcome, tree) = dev
        .store
        .write_with(|tx| {
            let (kp, _) = crate::e2ee::group::checked_key_package(&device, &alice, &kp)?;
            let provider = device.provider(tx.mls_storage());
            let conversation = RisalaConversation::direct(&device.uid, &alice);
            let mut group =
                risala_mls::create_group(&provider, &device.signer(), &device.uid, &conversation)
                    .unwrap();
            let bundle = risala_mls::commit(
                &provider,
                &mut group,
                &device.signer(),
                risala_mls::group::Changes {
                    add: vec![kp],
                    ..Default::default()
                },
            )
            .unwrap();
            let (_, welcome, _) = bundle.into_messages();
            group.merge_pending_commit(&provider).unwrap();
            Ok::<_, crate::e2ee::E2eeError>((
                wire::welcome_to_wire(&welcome.unwrap()).unwrap(),
                wire::tree_to_wire(&group.export_ratchet_tree()).unwrap(),
            ))
        })
        .unwrap()
        .0;
    let n = net.convs[s].events.len() + 1;
    net.deliver(
        a,
        &format!("WELCOME bob@example.net w99 {n} {welcome} {tree}"),
    );
    net.run();

    // Alice's device does not join it (12.6).
    assert_eq!(
        net.devs[a].group("bob@example.net").unwrap().state,
        GroupState::Rejected
    );
}

#[test]
fn a_rejected_room_is_not_started_again() {
    use risala_proto::types::{HistoryMode, SendMode};
    let mut net = Net::new();
    let a = net.device("alice@example.org", 1);
    net.run();
    let room: Room = "#secret".parse().unwrap();
    net.room(a, "#secret");
    reconnect(&mut net, a);
    let account = net.devs[a].account;
    net.devs[a]
        .store
        .write_with(|tx| {
            let row = tx.conv_by_name(account, &Conv::Room(room.clone()))?.unwrap();
            let device =
                crate::e2ee::Device::new(net.devs[a].uid.clone(), net.devs[a].key.clone())
                    .unwrap();
            let conversation = RisalaConversation::room(
                row.conv_id.as_ref().unwrap(),
                HistoryMode::Shared,
                SendMode::All,
            );
            crate::e2ee::group::create(tx, &device, &row, &conversation, 0)?;
            crate::e2ee::group::mark(tx, &row, GroupState::Rejected)
        })
        .unwrap();

    // A group the device rejected is not replaced by a new one (12.6).
    let _ = net.devs[a]
        .engine
        .encrypt_room(&room, HistoryMode::Shared, SendMode::All);
    net.run();
    assert_eq!(net.sent_to(a, "INIT", "#secret"), 0);
    assert_eq!(net.devs[a].group("#secret").unwrap().state, GroupState::Rejected);

    // Only the user's reset lets it start again.
    let out = net.devs[a]
        .engine
        .reset_encryption(&Conv::Room(room.clone()))
        .unwrap();
    net.devs[a].absorb(out);
    let out = net.devs[a]
        .engine
        .encrypt_room(&room, HistoryMode::Shared, SendMode::All)
        .unwrap();
    net.devs[a].absorb(out);
    net.run();
    assert_eq!(net.sent_to(a, "INIT", "#secret"), 1);
}
