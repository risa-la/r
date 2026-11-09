//! An in-memory server for the group engine's tests: the mailbox, token,
//! KeyPackage and Welcome commands of 5.2, 7.1, 7.2, 12.5 and 12.8, as far
//! as the engine uses them, with knobs that `risalad` has not (refused
//! Welcomes, posts as blob-refs, GONE on demand). The same paths run
//! against `risalad` in `client/conversations/server_tests.rs`.
//!
//! It checks what a server can check without a group's secrets: framing,
//! group ids, token hashes per epoch, `next` on commits only. Public rooms
//! (6.1, 12.6) keep their group as an outsider sees it: commits and
//! proposals must be valid MLS for it, one commit per epoch, commits on a
//! signed-in connection with `groupinfo=`, joins with the token `-`. It
//! does not make the group checks of 12.7, which `risalad` makes.

use std::collections::{BTreeMap, HashMap, HashSet};

use risala_mls::framing::{ContentType, read_post};
use risala_mls::keypackage::{is_last_resort, read_key_package, verify_key_package};
use risala_mls::primitives::sha384;
use risala_proto::command::{Command, KeyPkgCommand, WelcomeCommand};
use risala_proto::error::ErrorCode;
use risala_proto::mls::{OrBlob, PostToken, WelcomeSecret};
use risala_proto::names::{BoxName, Uid};
use risala_proto::server::{ErrResponse, OkResponse, ServerMessage};

use crate::conn::{End, Response};

/// A connection: a device, by its index in the test, and its slot.
pub type ConnId = (usize, crate::conn::Slot);

/// A kept post: seq, t, message and `next`.
type KeptPost = (u64, u64, Vec<u8>, Option<[u8; 48]>);

/// A device: uid and device id.
type DeviceKey = (String, Vec<u8>);

struct Mailbox {
    group_id: Vec<u8>,
    posts: Vec<KeptPost>,
    tokens: HashMap<u64, HashSet<[u8; 48]>>,
    followers: HashSet<ConnId>,
    room: Option<FakeRoom>,
}

/// A public room's group as the server holds it (12.6).
struct FakeRoom {
    name: String,
    group: risala_mls::openmls::prelude::PublicGroup,
    storage: openmls_memory_storage::MemoryStorage,
    group_info: Vec<u8>,
    tree: Vec<u8>,
    /// The seq of the commit that started the current epoch.
    epoch_seq: u64,
    /// The tree of each epoch, for Welcomes (12.6).
    trees: HashMap<u64, Vec<u8>>,
    /// The refs of KeyPackages that accepted commits added from join
    /// proposals, and the epoch each commit started.
    added: HashMap<Vec<u8>, u64>,
}

impl FakeRoom {
    fn build(
        crypto: &risala_mls::RisalaCrypto,
        name: String,
        group_info: Vec<u8>,
        tree: Vec<u8>,
    ) -> Option<FakeRoom> {
        let storage = openmls_memory_storage::MemoryStorage::default();
        let group = risala_mls::group::public_group(crypto, &storage, &group_info, &tree).ok()?;
        let epoch = group.group_context().epoch().as_u64();
        Some(FakeRoom {
            name,
            group,
            storage,
            trees: HashMap::from([(epoch, tree.clone())]),
            group_info,
            tree,
            epoch_seq: 0,
            added: HashMap::new(),
        })
    }

    fn epoch(&self) -> u64 {
        self.group.group_context().epoch().as_u64()
    }

    fn members(&self) -> u64 {
        self.group.members().count() as u64
    }
}

struct StoredKp {
    reference: Vec<u8>,
    bytes: Vec<u8>,
    last_resort: bool,
}

/// The server.
pub struct FakeServer {
    pub now: u64,
    mailboxes: BTreeMap<String, Mailbox>,
    /// KeyPackages by (uid, device id).
    key_packages: BTreeMap<(String, Vec<u8>), Vec<StoredKp>>,
    /// Refs handed out by KEYPKG GET: whose device, and the hash of the
    /// put secret (12.5).
    handed_out: HashMap<Vec<u8>, (DeviceKey, [u8; 48])>,
    /// Pending Welcomes, by device: (id, welcome).
    welcomes: HashMap<DeviceKey, Vec<(String, Vec<u8>)>>,
    next_welcome: u64,
    /// Each connection's identity and device, for signed-in connections.
    pub signed_in: HashMap<ConnId, (String, Vec<u8>)>,
    crypto: risala_mls::RisalaCrypto,
    /// Every command, for assertions: the connection and the verb.
    pub log: Vec<(ConnId, String)>,
    /// Refuse the next POST of this mailbox with `ERR stale`.
    pub stale_next: HashSet<String>,
    /// Welcomes of join proposals, by KeyPackageRef: id, Welcome, epoch.
    public_welcomes: HashMap<Vec<u8>, (String, Vec<u8>, u64)>,
    /// Refuse the next this many WELCOME PUTs with `ERR forbidden`.
    pub refuse_welcomes: usize,
    /// Send posts as blob-refs (12.12), with their bytes in `blobs`.
    pub blob_posts: bool,
    /// The blob store: bytes by hash.
    pub blobs: std::sync::Arc<std::sync::Mutex<HashMap<[u8; 48], Vec<u8>>>>,
}

fn ok() -> OkResponse {
    OkResponse::new()
}

fn err(code: ErrorCode) -> End {
    End::Err(ErrResponse {
        code,
        retry: None,
        message: String::new(),
    })
}

fn line(s: &str) -> ServerMessage {
    s.parse().unwrap_or_else(|e| panic!("{s}: {e}"))
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn timestamp(ms: u64) -> String {
    risala_proto::time::Timestamp::from_unix_millis(ms)
        .unwrap()
        .to_string()
}

impl FakeServer {
    pub fn new(now: u64) -> FakeServer {
        FakeServer {
            now,
            mailboxes: BTreeMap::new(),
            key_packages: BTreeMap::new(),
            handed_out: HashMap::new(),
            welcomes: HashMap::new(),
            next_welcome: 1,
            signed_in: HashMap::new(),
            crypto: risala_mls::RisalaCrypto::new().unwrap(),
            log: Vec::new(),
            stale_next: HashSet::new(),
            public_welcomes: HashMap::new(),
            refuse_welcomes: 0,
            blob_posts: false,
            blobs: Default::default(),
        }
    }

    /// The members and epoch of a public room.
    pub fn room(&self, name: &str) -> Option<(u64, u64)> {
        self.mailboxes
            .values()
            .filter_map(|m| m.room.as_ref())
            .find(|r| r.name == name)
            .map(|r| (r.members(), r.epoch()))
    }

    /// The live lines a server sends when a guest's session ends (6.1):
    /// `GONE <box> <uid>` to the followers of each public room the guest
    /// has a leaf in.
    pub fn gone(&self, uid: &str) -> Vec<(ConnId, ServerMessage)> {
        let mut out = Vec::new();
        for (b, m) in &self.mailboxes {
            let Some(room) = &m.room else { continue };
            let has = room.group.members().any(|member| {
                risala_mls::identity::RisalaIdentity::from_credential(&member.credential)
                    .is_ok_and(|id| id.uid.as_str() == uid)
            });
            if has {
                for f in &m.followers {
                    out.push((*f, line(&format!("GONE {b} {uid}"))));
                }
            }
        }
        out
    }

    /// The checks of 12.6 that the engine's posts to a public room must
    /// pass here: the current epoch, valid MLS for the room's group, a
    /// commit on a signed-in connection with its GroupInfo, `-` only for
    /// joins and external commits. Returns the error, if any.
    fn check_room_post(
        &mut self,
        mailbox: &str,
        conn: ConnId,
        bytes: &[u8],
        epoch: u64,
        token_is_join: bool,
        groupinfo: Option<Vec<u8>>,
    ) -> Option<End> {
        use risala_mls::openmls::prelude::{ProcessedMessageContent, Sender};
        let crypto = &self.crypto;
        let m = self.mailboxes.get_mut(mailbox)?;
        let room = m.room.as_mut()?;
        if epoch != room.epoch() {
            return Some(err(ErrorCode::Stale));
        }
        let Ok(protocol) = risala_mls::wire::read_protocol_message(bytes) else {
            return Some(err(ErrorCode::Invalid));
        };
        let processed = match room.group.process_message(crypto, protocol) {
            Ok(p) => p,
            Err(_) => return Some(err(ErrorCode::Invalid)),
        };
        let sender = processed.sender().clone();
        match processed.into_content() {
            ProcessedMessageContent::ExternalJoinProposalMessage(queued) => {
                if !token_is_join {
                    return Some(err(ErrorCode::Invalid));
                }
                room.group.add_proposal(&room.storage, *queued).ok()?;
                None
            }
            ProcessedMessageContent::ProposalMessage(queued) => {
                if token_is_join {
                    return Some(err(ErrorCode::Invalid));
                }
                room.group.add_proposal(&room.storage, *queued).ok()?;
                None
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                let external = matches!(sender, Sender::NewMemberCommit);
                if token_is_join != external {
                    return Some(err(ErrorCode::Invalid));
                }
                // 12.6, point 4: from a signed-in connection.
                if conn.1 != crate::conn::Slot::SignedIn {
                    return Some(err(ErrorCode::Forbidden));
                }
                let Some(group_info) = groupinfo else {
                    return Some(err(ErrorCode::Invalid));
                };
                let added: Vec<Vec<u8>> = staged
                    .add_proposals()
                    .filter_map(|q| {
                        q.add_proposal()
                            .key_package()
                            .hash_ref(crypto)
                            .ok()
                            .map(|r| r.as_slice().to_vec())
                    })
                    .collect();
                if room.group.merge_commit(&room.storage, *staged).is_err() {
                    return Some(err(ErrorCode::Invalid));
                }
                let tree = risala_mls::wire::tree_to_bytes(&room.group.export_ratchet_tree());
                let Some(mut fresh) =
                    FakeRoom::build(crypto, room.name.clone(), group_info, tree.clone())
                else {
                    return Some(err(ErrorCode::Invalid));
                };
                let new_epoch = fresh.epoch();
                fresh.trees = std::mem::take(&mut room.trees);
                fresh.trees.insert(new_epoch, tree);
                fresh.added = std::mem::take(&mut room.added);
                for r in added {
                    fresh.added.insert(r, new_epoch);
                }
                fresh.epoch_seq = m.posts.len() as u64 + 1;
                *room = fresh;
                None
            }
            _ => Some(err(ErrorCode::Invalid)),
        }
    }

    /// The posts of a mailbox: (seq, content type).
    pub fn posts(&self, mailbox: &BoxName) -> Vec<(u64, ContentType)> {
        self.mailboxes
            .get(&mailbox.to_string())
            .map(|m| {
                m.posts
                    .iter()
                    .map(|(seq, _, msg, _)| (*seq, read_post(msg).unwrap().0.content_type))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// How many KeyPackages a device has here.
    pub fn key_package_count(&self, uid: &str, device: &[u8]) -> usize {
        self.key_packages
            .get(&(uid.to_owned(), device.to_vec()))
            .map_or(0, Vec::len)
    }

    /// Forgets a connection, as when it closes.
    pub fn close(&mut self, conn: ConnId) {
        for m in self.mailboxes.values_mut() {
            m.followers.remove(&conn);
        }
    }

    /// Handles one command: its response, and live lines for connections.
    pub fn handle(
        &mut self,
        conn: ConnId,
        command: Command,
    ) -> (Response, Vec<(ConnId, ServerMessage)>) {
        self.log.push((conn, command.verb().to_owned()));
        let blobs = self.blob_posts.then(|| self.blobs.clone());
        let post_line = |seq: u64, t: u64, mailbox: &str, bytes: &[u8], next| {
            post_text(blobs.as_deref(), seq, t, mailbox, bytes, next)
        };
        let mut lines = Vec::new();
        let mut live = Vec::new();
        let end = match command {
            Command::Create {
                mailbox,
                group_id,
                token_hash,
                form,
            } => {
                let b = mailbox.to_string();
                // 7.8: a move's mailbox needs the group's old one, and a
                // token of the epoch before.
                let moving = match &form {
                    risala_proto::command::CreateForm::Private { moving: Some(m) } => {
                        Some(m.clone())
                    }
                    _ => None,
                };
                let refused =
                    moving
                        .as_ref()
                        .and_then(|m| match self.mailboxes.get(&m.from.to_string()) {
                            Some(old) if old.group_id == group_id.as_bytes() => {
                                let ok = old
                                    .tokens
                                    .get(&(m.epoch.get() - 1))
                                    .is_some_and(|set| set.contains(&sha384(m.token.as_bytes())));
                                (!ok).then(|| err(ErrorCode::Stale))
                            }
                            _ => Some(err(ErrorCode::NotFound)),
                        });
                let public = match &form {
                    risala_proto::command::CreateForm::Public(p) => {
                        let (OrBlob::Inline(gi), OrBlob::Inline(tree)) = (&p.groupinfo, &p.tree)
                        else {
                            panic!("no blobs")
                        };
                        Some((p.room.to_string(), gi.decode(), tree.decode()))
                    }
                    _ => None,
                };
                let room = match public {
                    Some((name, gi, tree)) => {
                        if conn.1 != crate::conn::Slot::SignedIn {
                            return (
                                Response {
                                    lines,
                                    end: err(ErrorCode::WrongConnection),
                                },
                                live,
                            );
                        }
                        match FakeRoom::build(&self.crypto, name, gi, tree) {
                            Some(room) => Some(room),
                            None => {
                                return (
                                    Response {
                                        lines,
                                        end: err(ErrorCode::Invalid),
                                    },
                                    live,
                                );
                            }
                        }
                    }
                    None => None,
                };
                if let Some(refused) = refused {
                    refused
                } else {
                    match self.mailboxes.entry(b) {
                        std::collections::btree_map::Entry::Occupied(_) => {
                            err(ErrorCode::NameTaken)
                        }
                        std::collections::btree_map::Entry::Vacant(slot) => {
                            let mut tokens = HashMap::new();
                            tokens.insert(
                                form.first_epoch(),
                                HashSet::from([*token_hash.as_bytes()]),
                            );
                            slot.insert(Mailbox {
                                group_id: group_id.as_bytes().to_vec(),
                                posts: Vec::new(),
                                tokens,
                                followers: HashSet::new(),
                                room,
                            });
                            End::Ok(ok())
                        }
                    }
                }
            }
            Command::Post {
                mailbox,
                token,
                message,
                live: is_live,
                next,
                groupinfo,
                ..
            } => {
                let b = mailbox.to_string();
                let stale = self.stale_next.remove(&b);
                // 12.6: a public room's commits and proposals.
                let public = self.mailboxes.get(&b).is_some_and(|m| m.room.is_some());
                let refused = match (&message, public) {
                    (OrBlob::Inline(msg), true) => {
                        let bytes = msg.decode();
                        match read_post(&bytes) {
                            Ok((framing, _))
                                if framing.content_type != ContentType::Application =>
                            {
                                let gi = groupinfo.as_ref().map(|g| match g {
                                    OrBlob::Inline(g) => g.decode(),
                                    OrBlob::Blob(_) => panic!("no blobs"),
                                });
                                let join = matches!(token, PostToken::Join);
                                self.check_room_post(&b, conn, &bytes, framing.epoch, join, gi)
                            }
                            _ => None,
                        }
                    }
                    _ => None,
                };
                match self.mailboxes.get_mut(&b) {
                    _ if refused.is_some() => refused.unwrap(),
                    None => err(ErrorCode::NotFound),
                    Some(m) => {
                        let OrBlob::Inline(message) = message else {
                            panic!("no blobs here")
                        };
                        let bytes = message.decode();
                        match read_post(&bytes) {
                            Err(_) => err(ErrorCode::Invalid),
                            Ok((framing, _)) if framing.group_id != m.group_id.as_slice() => {
                                err(ErrorCode::Invalid)
                            }
                            Ok((framing, _)) => {
                                let is_commit = framing.content_type == ContentType::Commit;
                                let epoch = framing.epoch;
                                let token_ok = match &token {
                                    PostToken::Send(t) => m
                                        .tokens
                                        .get(&epoch)
                                        .is_some_and(|set| set.contains(&sha384(t.as_bytes()))),
                                    // Checked above, for public rooms only.
                                    PostToken::Join => m.room.is_some(),
                                };
                                if is_commit != next.is_some()
                                    || (is_live && framing.content_type != ContentType::Application)
                                {
                                    err(ErrorCode::Invalid)
                                } else if !token_ok || stale {
                                    err(ErrorCode::Stale)
                                } else if is_live {
                                    let text = format!(
                                        "@t={} POST {} {}",
                                        timestamp(self.now),
                                        b,
                                        b64(&bytes)
                                    );
                                    for f in &m.followers {
                                        live.push((*f, line(&text)));
                                    }
                                    End::Ok(ok())
                                } else {
                                    let seq = m.posts.len() as u64 + 1;
                                    let next = next.map(|n| *n.as_bytes());
                                    if let Some(n) = next {
                                        m.tokens.entry(epoch + 1).or_default().insert(n);
                                    }
                                    m.posts.push((seq, self.now, bytes.clone(), next));
                                    let text = post_line(seq, self.now, &b, &bytes, next);
                                    for f in &m.followers {
                                        live.push((*f, line(&text)));
                                    }
                                    End::Ok(
                                        ok().with_seq(risala_proto::names::Seq::new(seq).unwrap()),
                                    )
                                }
                            }
                        }
                    }
                }
            }
            Command::Follow { mailbox, .. } => match self.mailboxes.get_mut(&mailbox.to_string()) {
                None => err(ErrorCode::NotFound),
                Some(m) => {
                    m.followers.insert(conn);
                    End::Ok(ok().with_head(m.posts.len() as u64))
                }
            },
            Command::Unfollow { mailbox } => {
                if let Some(m) = self.mailboxes.get_mut(&mailbox.to_string()) {
                    m.followers.remove(&conn);
                }
                End::Ok(ok())
            }
            Command::Fetch {
                mailbox,
                after,
                limit,
                ..
            } => match self.mailboxes.get(&mailbox.to_string()) {
                None => err(ErrorCode::NotFound),
                Some(m) => {
                    let limit = limit.map_or(50, |l| l.get().min(50)) as usize;
                    let page: Vec<_> = m.posts.iter().filter(|p| p.0 > after).collect();
                    for (seq, t, bytes, next) in page.iter().take(limit) {
                        lines.push(line(&post_line(
                            *seq,
                            *t,
                            &mailbox.to_string(),
                            bytes,
                            *next,
                        )));
                    }
                    End::Ok(ok().with_more(page.len() > limit))
                }
            },
            Command::Token {
                mailbox,
                epoch,
                token,
                hash,
            } => match self.mailboxes.get_mut(&mailbox.to_string()) {
                None => err(ErrorCode::NotFound),
                Some(m) => {
                    let ok_token = m
                        .tokens
                        .get(&epoch)
                        .is_some_and(|set| set.contains(&sha384(token.as_bytes())));
                    if ok_token {
                        m.tokens
                            .entry(epoch + 1)
                            .or_default()
                            .insert(*hash.as_bytes());
                        End::Ok(ok())
                    } else {
                        err(ErrorCode::Stale)
                    }
                }
            },
            Command::KeyPkg(KeyPkgCommand::Add { key_package }) => {
                let (uid, device) = self.signed_in.get(&conn).cloned().expect("signed in");
                let bytes = key_package.decode();
                let kp =
                    verify_key_package(&self.crypto, read_key_package(&bytes).unwrap()).unwrap();
                let reference = kp.hash_ref(&self.crypto).unwrap().as_slice().to_vec();
                let last_resort = is_last_resort(&kp).unwrap();
                let list = self.key_packages.entry((uid, device)).or_default();
                if last_resort {
                    list.retain(|k| !k.last_resort);
                }
                list.push(StoredKp {
                    reference,
                    bytes,
                    last_resort,
                });
                End::Ok(ok())
            }
            Command::KeyPkg(KeyPkgCommand::Count) => {
                let key = self.signed_in.get(&conn).cloned().expect("signed in");
                let list = self.key_packages.get(&key);
                let count = list.map_or(0, |l| l.iter().filter(|k| !k.last_resort).count());
                let lr = list.is_some_and(|l| l.iter().any(|k| k.last_resort));
                End::Ok(ok().with_count(count as u64).with_last_resort(lr))
            }
            Command::KeyPkg(KeyPkgCommand::Get { uid }) => {
                let devices: Vec<(String, Vec<u8>)> = self
                    .key_packages
                    .keys()
                    .filter(|(u, _)| *u == uid.as_str())
                    .cloned()
                    .collect();
                if devices.is_empty() && !self.signed_in.values().any(|(u, _)| *u == uid.as_str()) {
                    err(ErrorCode::NotFound)
                } else {
                    for key in devices {
                        let list = self.key_packages.get_mut(&key).unwrap();
                        let pick = list
                            .iter()
                            .position(|k| !k.last_resort)
                            .or_else(|| list.iter().position(|k| k.last_resort));
                        let Some(i) = pick else { continue };
                        let (reference, bytes) = if list[i].last_resort {
                            (list[i].reference.clone(), list[i].bytes.clone())
                        } else {
                            let k = list.remove(i);
                            (k.reference, k.bytes)
                        };
                        let secret: [u8; 32] = risala_mls::primitives::random().unwrap();
                        self.handed_out
                            .insert(reference, (key.clone(), sha384(&secret)));
                        lines.push(line(&format!(
                            "KEYPKG {} {} {}",
                            uid,
                            b64(&bytes),
                            b64(&secret)
                        )));
                    }
                    End::Ok(ok())
                }
            }
            Command::Welcome(WelcomeCommand::Put {
                key_package_ref,
                secret,
                welcome,
            }) if !matches!(secret, WelcomeSecret::Proposal) => match self
                .handed_out
                .get(key_package_ref.as_bytes().as_slice())
                .cloned()
            {
                None => err(ErrorCode::NotFound),
                // Only whoever fetched the KeyPackage delivers its Welcome
                // (12.8).
                Some((_, hash)) if !matches!(&secret, WelcomeSecret::Put(s) if sha384(s.as_bytes()) == hash) => {
                    err(ErrorCode::Forbidden)
                }
                Some(_) if self.refuse_welcomes > 0 => {
                    self.refuse_welcomes -= 1;
                    err(ErrorCode::Forbidden)
                }
                Some((device, _)) => {
                    self.handed_out
                        .remove(key_package_ref.as_bytes().as_slice());
                    let OrBlob::Inline(welcome) = welcome else {
                        panic!("no blobs")
                    };
                    let id = format!("w{}", self.next_welcome);
                    self.next_welcome += 1;
                    let bytes = welcome.decode();
                    self.welcomes
                        .entry(device.clone())
                        .or_default()
                        .push((id.clone(), bytes.clone()));
                    for (c, d) in &self.signed_in {
                        if *d == device {
                            live.push((*c, line(&format!("WELCOME {id} {}", b64(&bytes)))));
                        }
                    }
                    End::Ok(ok())
                }
            },
            Command::Welcome(WelcomeCommand::List) => {
                let key = self.signed_in.get(&conn).cloned().expect("signed in");
                for (id, bytes) in self.welcomes.get(&key).cloned().unwrap_or_default() {
                    lines.push(line(&format!("WELCOME {id} {}", b64(&bytes))));
                }
                End::Ok(ok())
            }
            Command::Welcome(WelcomeCommand::Del { id }) => {
                let key = self.signed_in.get(&conn).cloned().expect("signed in");
                if let Some(list) = self.welcomes.get_mut(&key) {
                    list.retain(|(i, _)| *i != id.to_string());
                }
                End::Ok(ok())
            }
            Command::List { .. } => {
                let mut rooms: Vec<(&String, &Mailbox)> = self
                    .mailboxes
                    .iter()
                    .filter(|(_, m)| m.room.is_some())
                    .collect();
                rooms.sort_by(|a, b| {
                    a.1.room
                        .as_ref()
                        .unwrap()
                        .name
                        .cmp(&b.1.room.as_ref().unwrap().name)
                });
                for (b, m) in rooms {
                    let room = m.room.as_ref().unwrap();
                    lines.push(line(&format!("ROOM {} {b} {}", room.name, room.members())));
                }
                End::Ok(ok().with_more(false))
            }
            Command::Info { room: None } => End::Ok(ok()),
            Command::Info { room: Some(name) } => {
                match self
                    .mailboxes
                    .iter()
                    .find(|(_, m)| m.room.as_ref().is_some_and(|r| r.name == name.as_str()))
                {
                    Some((b, m)) => {
                        let room = m.room.as_ref().unwrap();
                        End::Ok(
                            ok().with_mailbox(&b.parse().unwrap())
                                .with_members(room.members())
                                .with_epoch(room.epoch()),
                        )
                    }
                    None => err(ErrorCode::NotFound),
                }
            }
            Command::GroupInfo { mailbox } => match self
                .mailboxes
                .get(&mailbox.to_string())
                .and_then(|m| m.room.as_ref())
            {
                Some(room) => {
                    lines.push(line(&format!(
                        "GROUPINFO {mailbox} {} {} {} {}",
                        room.epoch(),
                        room.epoch_seq,
                        b64(&room.group_info),
                        b64(&room.tree)
                    )));
                    End::Ok(ok())
                }
                None => err(ErrorCode::NotFound),
            },
            Command::Welcome(WelcomeCommand::Put {
                key_package_ref,
                secret: WelcomeSecret::Proposal,
                welcome,
            }) => {
                let reference = key_package_ref.as_bytes().to_vec();
                let epoch = self
                    .mailboxes
                    .values()
                    .filter_map(|m| m.room.as_ref())
                    .find_map(|r| r.added.get(&reference).copied());
                match epoch {
                    None => err(ErrorCode::NotFound),
                    // 12.8: on the signed-in connection of the committer.
                    Some(_) if conn.1 != crate::conn::Slot::SignedIn => err(ErrorCode::Forbidden),
                    Some(_) if self.refuse_welcomes > 0 => {
                        self.refuse_welcomes -= 1;
                        err(ErrorCode::Forbidden)
                    }
                    Some(epoch) => {
                        let OrBlob::Inline(welcome) = welcome else {
                            panic!("no blobs")
                        };
                        let id = format!("w{}", self.next_welcome);
                        self.next_welcome += 1;
                        self.public_welcomes
                            .insert(reference, (id, welcome.decode(), epoch));
                        End::Ok(ok())
                    }
                }
            }
            Command::Welcome(WelcomeCommand::Get {
                key_package_ref, ..
            }) => match self
                .public_welcomes
                .get(key_package_ref.as_bytes().as_slice())
            {
                Some((id, welcome, epoch)) => {
                    let tree = self
                        .mailboxes
                        .values()
                        .filter_map(|m| m.room.as_ref())
                        .find_map(|r| r.trees.get(epoch).cloned())
                        .unwrap_or_default();
                    lines.push(line(&format!(
                        "WELCOME {id} {} tree={}",
                        b64(welcome),
                        b64(&tree)
                    )));
                    End::Ok(ok())
                }
                None => err(ErrorCode::NotFound),
            },
            other => panic!("the fake server does not do {}", other.verb()),
        };
        (Response { lines, end }, live)
    }

    /// The pending Welcomes of a device.
    pub fn pending_welcomes(&self, uid: &Uid, device: &[u8]) -> usize {
        self.welcomes
            .get(&(uid.to_string(), device.to_vec()))
            .map_or(0, Vec::len)
    }
}

fn post_line(seq: u64, t: u64, mailbox: &str, bytes: &[u8], next: Option<[u8; 48]>) -> String {
    let mut s = format!(
        "@seq={seq};t={} POST {mailbox} {}",
        timestamp(t),
        b64(bytes)
    );
    if let Some(n) = next {
        s.push_str(&format!(" next={}", b64(&n)));
    }
    s
}

/// A POST line, its message inline or, with a blob store, as a blob-ref
/// whose bytes go there (12.12).
fn post_text(
    blobs: Option<&std::sync::Mutex<HashMap<[u8; 48], Vec<u8>>>>,
    seq: u64,
    t: u64,
    mailbox: &str,
    bytes: &[u8],
    next: Option<[u8; 48]>,
) -> String {
    let Some(blobs) = blobs else {
        return post_line(seq, t, mailbox, bytes, next);
    };
    let blob = risala_proto::names::BlobRef::of(bytes);
    blobs.lock().unwrap().insert(*blob.hash(), bytes.to_vec());
    let mut s = format!("@seq={seq};t={} POST {mailbox} {blob}", timestamp(t));
    if let Some(n) = next {
        s.push_str(&format!(" next={}", b64(&n)));
    }
    s
}
