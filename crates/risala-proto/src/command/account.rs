//! The commands of Sections 8, 9 and 12: PRESENCE, WATCH, WHOIS and
//! MEMBERS (8.3), PUSH (9.1), KEYPKG (12.5), WELCOME (12.8), BLOB (12.12)
//! and BACKUP (12.13).

use std::str::FromStr;

use super::{ANON, Command, HAVING_A_KIND, SIGNED};
use crate::binary::{PushAuth, PushKey, WrappedKey};
use crate::connection::Kinds;
use crate::error::ParseError;
use crate::line::{LineBuilder, Params};
use crate::mls::{KeyPackage, KeyPackageRef, OrBlob, SendToken, Welcome};
use crate::names::{BlobRef, BoxName, Id, Uid};
use crate::parse::{
    bad, flag_opt, last, number, number_u32, opt, options, subcommand, tok, unknown_subcommand,
};
use crate::types::{PushTag, PushUrl};

/// `PUSH ADD`, `PUSH DEL` and `PUSH LIST` (9.1).
///
/// With `box=`, ADD and DEL are about a mailbox subscription, made on an
/// anonymous connection; without it, about an account subscription, made
/// on a signed-in connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushCommand {
    /// `PUSH ADD <url> <tag> <key> <auth> [box=<box>]`.
    Add {
        /// The `https` URL to push to.
        url: PushUrl,
        /// The opaque tag that goes inside every push (9.3).
        tag: PushTag,
        /// The subscription's P-256 public key.
        key: PushKey,
        /// The subscription's authentication secret.
        auth: PushAuth,
        /// The mailbox, for a mailbox subscription.
        mailbox: Option<BoxName>,
    },
    /// `PUSH DEL <url> [box=<box>]`.
    Del {
        /// The URL of the subscription.
        url: PushUrl,
        /// The mailbox, for a mailbox subscription.
        mailbox: Option<BoxName>,
    },
    /// `PUSH LIST`: the device's account subscriptions, as PUSH lines.
    List,
}

impl PushCommand {
    /// The subcommand, in upper case.
    pub fn word(&self) -> &'static str {
        match self {
            PushCommand::Add { .. } => "ADD",
            PushCommand::Del { .. } => "DEL",
            PushCommand::List => "LIST",
        }
    }

    /// The kinds of connection that may send it (Section 13).
    pub fn kinds(&self) -> Kinds {
        match self {
            PushCommand::Add {
                mailbox: Some(_), ..
            }
            | PushCommand::Del {
                mailbox: Some(_), ..
            } => ANON,
            _ => SIGNED,
        }
    }
}

/// `KEYPKG ADD`, `KEYPKG COUNT` and `KEYPKG GET` (12.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyPkgCommand {
    /// `KEYPKG ADD <keypackage>`: stores a KeyPackage for this device.
    Add {
        /// The KeyPackage.
        key_package: KeyPackage,
    },
    /// `KEYPKG COUNT`: how many KeyPackages the server holds for this
    /// device.
    Count,
    /// `KEYPKG GET <uid>`: a KeyPackage of each current device of `<uid>`.
    Get {
        /// The identity.
        uid: Uid,
    },
}

impl KeyPkgCommand {
    /// The subcommand, in upper case.
    pub fn word(&self) -> &'static str {
        match self {
            KeyPkgCommand::Add { .. } => "ADD",
            KeyPkgCommand::Count => "COUNT",
            KeyPkgCommand::Get { .. } => "GET",
        }
    }

    /// The kinds of connection that may send it (Section 13).
    pub fn kinds(&self) -> Kinds {
        match self {
            // Section 13's table; 12.5 says "any kind of connection".
            KeyPkgCommand::Get { .. } => ANON | SIGNED,
            _ => SIGNED,
        }
    }
}

/// `WELCOME PUT`, `WELCOME LIST`, `WELCOME DEL` and `WELCOME GET` (12.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WelcomeCommand {
    /// `WELCOME PUT <ref> <welcome>`: a Welcome for the KeyPackage whose
    /// KeyPackageRef is `<ref>`.
    Put {
        /// The KeyPackageRef.
        key_package_ref: KeyPackageRef,
        /// The Welcome, or a blob that holds it.
        welcome: OrBlob<Welcome>,
    },
    /// `WELCOME LIST`: every Welcome pending for this device.
    List,
    /// `WELCOME DEL <id>`: deletes a pending Welcome.
    Del {
        /// The Welcome's id, from its WELCOME line.
        id: Id,
    },
    /// `WELCOME GET <ref> [light=yes]`: the Welcome for a KeyPackage of an
    /// external proposal (6.1).
    Get {
        /// The KeyPackageRef.
        key_package_ref: KeyPackageRef,
        /// `light=yes`: an AnnotatedWelcome for a light client (12.6).
        light: bool,
    },
}

impl WelcomeCommand {
    /// The subcommand, in upper case.
    pub fn word(&self) -> &'static str {
        match self {
            WelcomeCommand::Put { .. } => "PUT",
            WelcomeCommand::List => "LIST",
            WelcomeCommand::Del { .. } => "DEL",
            WelcomeCommand::Get { .. } => "GET",
        }
    }

    /// The kinds of connection that may send it (Section 13).
    pub fn kinds(&self) -> Kinds {
        match self {
            WelcomeCommand::Put { .. } | WelcomeCommand::Get { .. } => HAVING_A_KIND,
            WelcomeCommand::List | WelcomeCommand::Del { .. } => SIGNED,
        }
    }
}

/// The `box=` and `token=` of BLOB (12.12), which show that an anonymous
/// or guest connection is a member of some group.
///
/// The syntax line writes them as a pair, `[box=<box> token=<token>]`, so
/// one without the other is `BadSyntax`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobPermit {
    /// A mailbox.
    pub mailbox: BoxName,
    /// A send token of its group, checked as for POST (5.2).
    pub token: SendToken,
}

/// `BACKUP PUT`, `BACKUP GET` and `BACKUP DEL` (12.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackupCommand {
    /// `BACKUP PUT <generation> <hash> <key>`: stores a backup, replacing
    /// the identity's previous one.
    Put {
        /// The generation of the backup key that wraps `key`.
        generation: u32,
        /// The blob-ref of the encrypted archive.
        hash: BlobRef,
        /// The archive's key, wrapped under the backup key.
        key: WrappedKey,
    },
    /// `BACKUP GET`: replies with a BACKUP line, or `ERR not-found`.
    Get,
    /// `BACKUP DEL`: deletes the backup.
    Del,
}

impl BackupCommand {
    /// The subcommand, in upper case.
    pub fn word(&self) -> &'static str {
        match self {
            BackupCommand::Put { .. } => "PUT",
            BackupCommand::Get => "GET",
            BackupCommand::Del => "DEL",
        }
    }
}

/// Reads WATCH's `<uids>`: one or more uids separated by commas, with no
/// spaces (8.3).
fn uid_list(s: &str) -> Result<Vec<Uid>, ParseError> {
    s.split(',').map(Uid::from_str).collect()
}

/// Parses the commands of this module; `None` for any other verb.
pub(super) fn parse(verb: &str, p: Params<'_>) -> Option<Result<Command, ParseError>> {
    let parse: fn(Params<'_>) -> Result<Command, ParseError> = match verb {
        "PRESENCE" => |mut p| {
            let on = match subcommand(&mut p)?.as_str() {
                "ON" => true,
                "OFF" => false,
                word => return Err(unknown_subcommand("PRESENCE", word)),
            };
            p.end()?;
            Ok(Command::Presence { on })
        },
        "WATCH" => |mut p| {
            let uids = match p.opt_token()? {
                None => Vec::new(),
                Some(list) => uid_list(list)?,
            };
            p.end()?;
            Ok(Command::Watch { uids })
        },
        "WHOIS" => |p| Ok(Command::Whois { uid: last(p)? }),
        "MEMBERS" => |p| Ok(Command::Members { room: last(p)? }),
        "PUSH" => |mut p| {
            Ok(Command::Push(match subcommand(&mut p)?.as_str() {
                "ADD" => {
                    let url = tok(&mut p)?;
                    let tag = tok(&mut p)?;
                    let key = tok(&mut p)?;
                    let auth = tok(&mut p)?;
                    let options = options(p, &["box"])?;
                    PushCommand::Add {
                        url,
                        tag,
                        key,
                        auth,
                        mailbox: opt(&options, "box")?,
                    }
                }
                "DEL" => {
                    let url = tok(&mut p)?;
                    let options = options(p, &["box"])?;
                    PushCommand::Del {
                        url,
                        mailbox: opt(&options, "box")?,
                    }
                }
                "LIST" => {
                    p.end()?;
                    PushCommand::List
                }
                word => return Err(unknown_subcommand("PUSH", word)),
            }))
        },
        "KEYPKG" => |mut p| {
            Ok(Command::KeyPkg(match subcommand(&mut p)?.as_str() {
                "ADD" => KeyPkgCommand::Add {
                    key_package: last(p)?,
                },
                "COUNT" => {
                    p.end()?;
                    KeyPkgCommand::Count
                }
                "GET" => KeyPkgCommand::Get { uid: last(p)? },
                word => return Err(unknown_subcommand("KEYPKG", word)),
            }))
        },
        "WELCOME" => |mut p| {
            Ok(Command::Welcome(match subcommand(&mut p)?.as_str() {
                "PUT" => {
                    let key_package_ref = tok(&mut p)?;
                    let welcome = last(p)?;
                    WelcomeCommand::Put {
                        key_package_ref,
                        welcome,
                    }
                }
                "LIST" => {
                    p.end()?;
                    WelcomeCommand::List
                }
                "DEL" => WelcomeCommand::Del { id: last(p)? },
                "GET" => {
                    let key_package_ref = tok(&mut p)?;
                    let options = options(p, &["light"])?;
                    WelcomeCommand::Get {
                        key_package_ref,
                        light: flag_opt(&options, "light")?,
                    }
                }
                word => return Err(unknown_subcommand("WELCOME", word)),
            }))
        },
        "BLOB" => |mut p| {
            let hash = tok(&mut p)?;
            let size = number(&mut p)?;
            let options = options(p, &["box", "token"])?;
            let permit = match (opt(&options, "box")?, opt(&options, "token")?) {
                (Some(mailbox), Some(token)) => Some(BlobPermit { mailbox, token }),
                (None, None) => None,
                _ => return Err(bad("BLOB takes box= and token= together")),
            };
            Ok(Command::Blob { hash, size, permit })
        },
        "BACKUP" => |mut p| {
            Ok(Command::Backup(match subcommand(&mut p)?.as_str() {
                "PUT" => {
                    let generation = number_u32(&mut p)?;
                    let hash = tok(&mut p)?;
                    let key = last(p)?;
                    BackupCommand::Put {
                        generation,
                        hash,
                        key,
                    }
                }
                "GET" => {
                    p.end()?;
                    BackupCommand::Get
                }
                "DEL" => {
                    p.end()?;
                    BackupCommand::Del
                }
                word => return Err(unknown_subcommand("BACKUP", word)),
            }))
        },
        _ => return None,
    };
    Some(parse(p))
}

/// Writes the commands of this module; `false` for any other command.
pub(super) fn write(command: &Command, b: &mut LineBuilder) -> bool {
    match command {
        Command::Presence { on } => {
            b.token(if *on { "ON" } else { "OFF" });
        }
        Command::Watch { uids } => {
            if !uids.is_empty() {
                let list: Vec<&str> = uids.iter().map(Uid::as_str).collect();
                b.token(list.join(","));
            }
        }
        Command::Whois { uid } => {
            b.token(uid);
        }
        Command::Members { room } => {
            b.token(room);
        }
        Command::Push(push) => {
            b.token(push.word());
            match push {
                PushCommand::Add {
                    url,
                    tag,
                    key,
                    auth,
                    mailbox,
                } => {
                    b.token(url).token(tag).token(key).token(auth);
                    if let Some(mailbox) = mailbox {
                        b.option("box", mailbox);
                    }
                }
                PushCommand::Del { url, mailbox } => {
                    b.token(url);
                    if let Some(mailbox) = mailbox {
                        b.option("box", mailbox);
                    }
                }
                PushCommand::List => {}
            }
        }
        Command::KeyPkg(keypkg) => {
            b.token(keypkg.word());
            match keypkg {
                KeyPkgCommand::Add { key_package } => {
                    b.token(key_package);
                }
                KeyPkgCommand::Count => {}
                KeyPkgCommand::Get { uid } => {
                    b.token(uid);
                }
            }
        }
        Command::Welcome(welcome) => {
            b.token(welcome.word());
            match welcome {
                WelcomeCommand::Put {
                    key_package_ref,
                    welcome,
                } => {
                    b.token(key_package_ref).token(welcome);
                }
                WelcomeCommand::List => {}
                WelcomeCommand::Del { id } => {
                    b.token(id);
                }
                WelcomeCommand::Get {
                    key_package_ref,
                    light,
                } => {
                    b.token(key_package_ref);
                    if *light {
                        b.option("light", "yes");
                    }
                }
            }
        }
        Command::Blob { hash, size, permit } => {
            b.token(hash).token(size);
            if let Some(permit) = permit {
                b.option("box", permit.mailbox)
                    .option("token", &permit.token);
            }
        }
        Command::Backup(backup) => {
            b.token(backup.word());
            if let BackupCommand::Put {
                generation,
                hash,
                key,
            } = backup
            {
                b.token(generation).token(hash).token(key);
            }
        }
        _ => return false,
    }
    true
}
