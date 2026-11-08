//! An in-memory server for the group engine's tests: the mailbox, token,
//! KeyPackage and Welcome commands of 5.2, 7.1, 7.2, 12.5 and 12.8, as far
//! as the engine uses them. It stands in for `risalad` until its mailbox
//! and Welcome areas (tasks SV3, SV4) land on `m5b`.
//!
//! It checks what a server can check without a group's secrets: framing,
//! group ids, token hashes per epoch, `next` on commits only. It does not
//! check public rooms' commits.

use std::collections::{BTreeMap, HashMap, HashSet};

use risala_mls::framing::{ContentType, read_post};
use risala_mls::keypackage::{is_last_resort, read_key_package, verify_key_package};
use risala_mls::primitives::sha384;
use risala_proto::command::{Command, KeyPkgCommand, WelcomeCommand};
use risala_proto::error::ErrorCode;
use risala_proto::mls::{OrBlob, PostToken};
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
    /// Refs handed out by KEYPKG GET, and whose device they are.
    handed_out: HashMap<Vec<u8>, (String, Vec<u8>)>,
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
                match self.mailboxes.entry(b) {
                    std::collections::btree_map::Entry::Occupied(_) => err(ErrorCode::NameTaken),
                    std::collections::btree_map::Entry::Vacant(slot) => {
                        let mut tokens = HashMap::new();
                        tokens.insert(form.first_epoch(), HashSet::from([*token_hash.as_bytes()]));
                        slot.insert(Mailbox {
                            group_id: group_id.as_bytes().to_vec(),
                            posts: Vec::new(),
                            tokens,
                            followers: HashSet::new(),
                        });
                        End::Ok(ok())
                    }
                }
            }
            Command::Post {
                mailbox,
                token,
                message,
                live: is_live,
                next,
                ..
            } => {
                let b = mailbox.to_string();
                let stale = self.stale_next.remove(&b);
                match self.mailboxes.get_mut(&b) {
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
                                    PostToken::Join => false,
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
                        self.handed_out.insert(reference, key.clone());
                        lines.push(line(&format!("KEYPKG {} {}", uid, b64(&bytes))));
                    }
                    End::Ok(ok())
                }
            }
            Command::Welcome(WelcomeCommand::Put {
                key_package_ref,
                welcome,
            }) => match self
                .handed_out
                .remove(key_package_ref.as_bytes().as_slice())
            {
                None => err(ErrorCode::NotFound),
                Some(device) => {
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
