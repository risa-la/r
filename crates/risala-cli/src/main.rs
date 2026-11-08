//! `risala`, a small terminal client and key tool built on librisala.
//!
//! Everything it learns is kept in a state directory (by default
//! `$XDG_STATE_HOME/risala`, or `~/.local/state/risala`): the cache
//! `cache.db`, with trust records, accounts, history and the outbox, and
//! device keys under `keys/`. So `log` and `export` work with no
//! connection. A guest resumes its session on each run (4.2), so running
//! commands one after another adds no JOIN or PART to its rooms. Once its
//! session has ended, its rooms are joined again.
//!
//! Identities (4.3) sign in with this device's key, kept in `keys/` under
//! the identity: `login` adds one (making a key or importing a PEM file),
//! `register` creates one on a server that hosts identities, `keys`
//! manages a hosted identity's keys and `unregister` deletes one.
//!
//! People: `read` moves read markers, `name` sets the display name,
//! `members` and `whois` show members and presence, and `block`,
//! `unblock` and `blocks` manage blocks. `chat` shows who is typing.
//!
//! Rooms: `delete` deletes a message, `info`, `topic` and `set` show and
//! change settings, `role` and `roles` manage roles, `invite`, `kick`,
//! `ban`, `unban` and `bans` moderate, and `report`, `reports` and
//! `resolve` handle reports. `admin` has the operators' commands.
//! `chat` shows notices and reports as they arrive.
//!
//! Exit codes: 0 done, 1 failed, 2 bad arguments, 3 needs you to act
//! first: the server refused (a key it does not accept, a name taken,
//! registration closed), or a certificate or key needs your decision.

mod admin;
mod rooms;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use librisala::client::{
    Account, Client, ClientError, ClientOptions, Conversation, ConversationInfo, EventKind,
    KeyErrorKind, KeyInfo, Label, Message, Notice, OutboxStatus, Presence, RefusedKind,
    TimelineDiff, TrustInfo,
};
use librisala::conn::keys::FileKeyStore;

/// How long to wait for a server before giving up.
const WAIT: Duration = Duration::from_secs(30);

#[derive(Parser)]
#[command(
    name = "risala",
    version,
    about = "A small terminal client for risala",
    after_help = "Exit codes: 0 done, 1 failed, 2 bad arguments, 3 needs you to act first \
                  (the server refused, or a certificate or key needs your decision)."
)]
struct Cli {
    /// The state directory: cache, trust records and keys.
    #[arg(long, global = true, value_name = "DIR")]
    state: Option<PathBuf>,
    /// The account to use on the server, such as ~sam, when there are
    /// several.
    #[arg(long = "as", global = true, value_name = "UID")]
    account: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Connect to a server and show who it is. On first use, shows the
    /// certificate's fingerprint to check and trust.
    Connect {
        /// The server, such as chat.example.org or host:7472.
        server: String,
    },
    /// Trust a server's certificate fingerprint (sha256:...), after
    /// checking it with the operator.
    Trust { server: String, fingerprint: String },
    /// Forget how a server's certificate is trusted, for example after
    /// the operator replaced its key.
    Untrust { server: String },
    /// Add a guest account on a server and sign in once to check it.
    Guest { server: String, name: String },
    /// Join a room and fetch its recent history.
    Join { server: String, room: String },
    /// Leave a room. Its history stays in the cache.
    Part {
        server: String,
        room: String,
        /// Why, shown to the room.
        reason: Vec<String>,
    },
    /// List the server's public rooms.
    List { server: String },
    /// Send a message to a room or a person.
    Send {
        server: String,
        conversation: String,
        /// The text; the words are joined with spaces.
        #[arg(required = true)]
        text: Vec<String>,
    },
    /// Print a conversation from the cache. Works offline.
    Log {
        server: String,
        conversation: String,
        /// How many of the newest messages to print.
        #[arg(short = 'n', long, default_value_t = 50)]
        count: u32,
    },
    /// Catch up every conversation, on one server or all of them.
    Sync { server: Option<String> },
    /// Download a conversation's whole history and print it as lines,
    /// for reading offline. Prints the cache as it is if offline.
    Export {
        server: String,
        conversation: String,
        /// Write to this file instead of standard output.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Chat in a room: shows messages as they arrive, who is typing, and
    /// sends each line typed. /quit leaves.
    Chat { server: String, room: String },
    /// Mark a conversation read, up to a seq or to its newest message
    /// (7.4). Offline, it is marked here, and the server hears on the next
    /// connection.
    Read {
        server: String,
        conversation: String,
        /// The newest seq read; the newest message if left out.
        seq: Option<u64>,
    },
    /// Set your display name, or clear it with no text (8.2).
    Name {
        server: String,
        /// The name; the words are joined with spaces.
        text: Vec<String>,
    },
    /// List a room's members, with their roles, presence and names (8.3).
    Members { server: String, room: String },
    /// Show a user's presence and display name (8.3).
    Whois { server: String, uid: String },
    /// Block an identity, or a whole domain written *@example.net (5.7).
    Block { server: String, target: String },
    /// Remove a block (5.7).
    Unblock { server: String, target: String },
    /// List your blocks (5.7). --hide hides blocked people's messages in
    /// rooms on this device, and --show shows them again; with either, it
    /// works offline and lists the blocks the cache has.
    Blocks {
        server: String,
        /// Hide blocked people's messages in rooms.
        #[arg(long, conflicts_with = "show")]
        hide: bool,
        /// Show blocked people's messages in rooms again.
        #[arg(long)]
        show: bool,
    },
    /// Register a new identity, <name>@<domain>, on a server that hosts
    /// identities, and add it as an account. Prints the uid and this device's
    /// key file line.
    Register {
        server: String,
        /// The name, the part before the @.
        name: String,
        /// A label for the key file line, usually the device's name.
        #[arg(long)]
        label: Option<String>,
    },
    /// Add an identity account, such as alice@example.org, and sign in.
    /// Without a key for it, makes one and prints its key file line to
    /// publish first.
    Login {
        server: String,
        identity: String,
        /// Use this private key (PEM PKCS#8 ML-DSA-44, as openssl genpkey
        /// writes it) as the device key.
        #[arg(long, value_name = "PEM_FILE")]
        key: Option<PathBuf>,
        /// Replace a different device key already stored for the identity.
        #[arg(long)]
        force: bool,
        /// A label for the key file line, usually the device's name.
        #[arg(long)]
        label: Option<String>,
    },
    #[command(flatten)]
    Rooms(rooms::RoomCommand),
    /// Administer the server, as one of its operators (Section 10).
    Admin {
        #[command(subcommand)]
        command: admin::AdminCommand,
    },
    /// Manage the keys of an identity the server hosts (4.7).
    Keys {
        #[command(subcommand)]
        command: KeysCommand,
    },
    /// Delete your identity from a server, with what the server keeps
    /// about it, then the account and its cache here (4.8). Type the uid
    /// out to confirm.
    Unregister {
        server: String,
        /// The identity to delete, typed out in full.
        uid: String,
        /// Also delete every message the identity sent.
        #[arg(long)]
        purge: bool,
    },
    /// Show the accounts, on one server or all of them, and their device
    /// keys.
    Whoami { server: Option<String> },
    /// Generate a device key for an identity, such as alice@example.org,
    /// and print the line to add to its key file (4.4).
    Keygen {
        identity: String,
        /// A label for the key file line, usually the device's name.
        #[arg(long)]
        label: Option<String>,
        /// Replace an existing key.
        #[arg(long)]
        force: bool,
    },
    /// Print the key file line for an identity's device key (4.4).
    Keyline {
        identity: String,
        /// A label for the line, usually the device's name.
        #[arg(long)]
        label: Option<String>,
    },
}

#[derive(Subcommand)]
enum KeysCommand {
    /// List the identity's keys.
    List {
        server: String,
        /// Print each key's full key file line.
        #[arg(long)]
        lines: bool,
    },
    /// Add another device's key, so that it can sign in. Paste the line
    /// it shows (risala keyline on that device), or its key alone.
    Add {
        server: String,
        /// The key file line or key; the words are joined with spaces.
        #[arg(required = true)]
        key: Vec<String>,
        /// A label for the key, usually the device's name, instead of the
        /// line's own.
        #[arg(long)]
        label: Option<String>,
    },
    /// Remove a key, given as a key file line, a key, or a fingerprint
    /// (sha256:...) from keys list.
    Del {
        server: String,
        /// The key file line, key or fingerprint.
        #[arg(required = true)]
        key: Vec<String>,
    },
}

/// A failure, already explained to the user, with the exit code.
struct Failed(u8);

/// Something failed.
const FAILED: u8 = 1;
/// The arguments are wrong.
const USAGE: u8 = 2;
/// The user must act first: the server refused, or a certificate or key
/// needs a decision.
const ACT: u8 = 3;

type Res<T = ()> = Result<T, Failed>;

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            // The platform verifier logs an error for every certificate
            // that is not CA-valid, which is normal with trust on first
            // use (2.2).
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn,rustls_platform_verifier=off".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("starting the runtime");
    match runtime.block_on(run(cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failed(code)) => ExitCode::from(code),
    }
}

fn fail<T>(message: impl std::fmt::Display) -> Res<T> {
    fail_with(FAILED, message)
}

fn fail_with<T>(code: u8, message: impl std::fmt::Display) -> Res<T> {
    eprintln!("risala: {message}");
    Err(Failed(code))
}

/// The exit code for an error.
fn exit_code(e: &ClientError) -> u8 {
    match e {
        ClientError::Invalid(_)
        | ClientError::Keys {
            kind: KeyErrorKind::BadKey,
            ..
        } => USAGE,
        ClientError::UnknownCertificate { .. }
        | ClientError::CertificateMismatch { .. }
        | ClientError::AlreadyTrusted { .. }
        | ClientError::Refused { .. }
        | ClientError::Keys { .. } => ACT,
        _ => FAILED,
    }
}

/// Explains a client error, with what to do about trust errors (2.2).
fn explain<T>(e: ClientError) -> Res<T> {
    match &e {
        ClientError::UnknownCertificate {
            server,
            fingerprint,
            reason,
        } => {
            eprintln!("risala: {server} has a certificate that is not CA-valid ({reason}).");
            eprintln!("Its fingerprint is:");
            eprintln!();
            eprintln!("    {fingerprint}");
            eprintln!();
            eprintln!("Check it with the server's operator. If it matches, trust it with:");
            eprintln!();
            eprintln!("    risala trust {server} {fingerprint}");
            Err(Failed(ACT))
        }
        ClientError::AlreadyTrusted { server, recorded } => {
            eprintln!("risala: {server} is already trusted, with {recorded}.");
            eprintln!("If its operator confirms a new certificate, remove the record first:");
            eprintln!("    risala untrust {server}");
            Err(Failed(ACT))
        }
        ClientError::CertificateMismatch {
            server,
            recorded,
            presented,
            ..
        } => {
            eprintln!("risala: {server} showed a certificate that does not match what is trusted.");
            eprintln!("Trusted:   {recorded}");
            eprintln!("Presented: {presented}");
            eprintln!("This may be an attack. If the operator confirms the change, run:");
            eprintln!("    risala untrust {server}");
            Err(Failed(ACT))
        }
        ClientError::Refused {
            kind,
            message,
            retry_after_secs,
        } => {
            let why = match kind {
                RefusedKind::NameTaken => "that name is taken; pick another".to_owned(),
                RefusedKind::NoRegistration => "the server does not offer registration".to_owned(),
                RefusedKind::NoHostname => {
                    "an identity needs the server's hostname, not an IP address (2.1)".to_owned()
                }
                RefusedKind::LastKey => {
                    "the server keeps at least one key; add another before removing this one"
                        .to_owned()
                }
                RefusedKind::Guest => "a guest has no keys and nothing to delete".to_owned(),
                RefusedKind::Unavailable => {
                    "the server could not get the identity's key file to check the key; try \
                     again later"
                        .to_owned()
                }
                RefusedKind::NotRegistered => {
                    "the server did not register the identity; this device's key for it is \
                     kept in the keys directory"
                        .to_owned()
                }
                _ => message.clone(),
            };
            match retry_after_secs {
                Some(secs) => fail_with(ACT, format!("{why}; try again in {secs} seconds")),
                None => fail_with(ACT, why),
            }
        }
        ClientError::Unconfirmed { message, .. } => fail(format!("{message}.")),
        ClientError::Server {
            retry_after_secs: Some(secs),
            ..
        } => fail_with(exit_code(&e), format!("{e}; try again in {secs} seconds")),
        _ => fail_with(exit_code(&e), e),
    }
}

/// The state directory: `--state`, `$XDG_STATE_HOME/risala` or
/// `~/.local/state/risala`.
fn state_dir(arg: Option<PathBuf>) -> Res<PathBuf> {
    if let Some(dir) = arg {
        return Ok(dir);
    }
    if let Some(dir) = std::env::var_os("XDG_STATE_HOME").filter(|d| !d.is_empty()) {
        return Ok(PathBuf::from(dir).join("risala"));
    }
    match std::env::var_os("HOME").filter(|d| !d.is_empty()) {
        Some(home) => Ok(PathBuf::from(home).join(".local/state/risala")),
        None => fail("no state directory: set HOME or XDG_STATE_HOME, or pass --state"),
    }
}

struct Ctx {
    client: Client,
    account: Option<String>,
}

fn open(dir: &Path, account: Option<String>) -> Res<Ctx> {
    if let Err(e) = std::fs::create_dir_all(dir) {
        return fail(format!("creating {}: {e}", dir.display()));
    }
    let keys_dir = dir.join("keys");
    let options = ClientOptions {
        keys: Some(std::sync::Arc::new(FileKeyStore::new(&keys_dir))),
        ..ClientOptions::default()
    };
    match Client::open(&dir.join("cache.db"), options) {
        Ok(client) => Ok(Ctx { client, account }),
        Err(e) => fail(format!("opening the cache in {}: {e}", dir.display())),
    }
}

async fn run(cli: Cli) -> Res {
    let dir = state_dir(cli.state)?;
    let ctx = open(&dir, cli.account)?;
    let result = command(&ctx, cli.command).await;
    ctx.client.shutdown().await;
    result
}

async fn command(ctx: &Ctx, command: Command) -> Res {
    let client = &ctx.client;
    match command {
        Command::Connect { server } => {
            let hello = client.probe(&server).await.or_else(explain)?;
            println!("{} ({})", hello.server, hello.host);
            if !hello.welcome.is_empty() {
                println!("{}", hello.welcome);
            }
            let how = match hello.trust {
                TrustInfo::Ca => "signed by a certificate authority".to_owned(),
                TrustInfo::Pinned { .. } => "trusted on first use".to_owned(),
            };
            println!("certificate {} ({how})", hello.fingerprint);
            Ok(())
        }
        Command::Trust {
            server,
            fingerprint,
        } => {
            client
                .accept_fingerprint(&server, &fingerprint)
                .or_else(explain)?;
            println!("trusting {server} with {}", fingerprint.trim());
            Ok(())
        }
        Command::Untrust { server } => client.forget_trust(&server).or_else(explain),
        Command::Guest { server, name } => {
            let account = client.add_guest(&server, &name).or_else(explain)?;
            let uid = connect(ctx, &account).await?;
            println!("signed in to {} as {uid}", account.server());
            Ok(())
        }
        Command::Join { server, room } => {
            let account = online(ctx, &server).await?;
            let conv = within(account.join(&room)).await?;
            within(account.wait_synced()).await?;
            let count = conv.export().or_else(explain)?.len();
            println!("joined {} ({count} events stored)", conv.name());
            Ok(())
        }
        Command::Part {
            server,
            room,
            reason,
        } => {
            let account = pick(ctx, &server)?;
            if account.is_guest() {
                // The guest's session may still be in the room, waiting to
                // be resumed (4.2). If the server cannot be reached,
                // parting offline still stops the room being joined again.
                let _ = tokio::time::timeout(WAIT, account.connect()).await;
            } else {
                connect(ctx, &account).await?;
            }
            within(async {
                match account.part(&room, &reason.join(" ")).await {
                    // A guest whose session has ended is in no room.
                    Err(e) if account.is_guest() && e.code() == Some("not-found") => Ok(()),
                    result => result,
                }
            })
            .await?;
            println!("left {room}");
            Ok(())
        }
        Command::List { server } => {
            let account = online(ctx, &server).await?;
            let mut after = None;
            loop {
                let page = within(account.list_rooms(after.take(), None)).await?;
                for room in &page.rooms {
                    print_room(&room.room, room.members, &room.topic);
                }
                match page.rooms.last() {
                    Some(last) if page.more => after = Some(last.room.clone()),
                    _ => return Ok(()),
                }
            }
        }
        Command::Send {
            server,
            conversation,
            text,
        } => {
            let account = pick(ctx, &server)?;
            let connected = try_connect(&account).await;
            let conv = account.conversation(&conversation).or_else(explain)?;
            let entry = conv.send(&text.join(" ")).await.or_else(explain)?;
            if let Err(e) = connected {
                return queued_offline(e, "sent");
            }
            let entry = within(account.wait_outbox(entry.id)).await?;
            match entry.status {
                OutboxStatus::Sent { seq } => {
                    println!("sent to {} as {seq}", conv.name());
                    Ok(())
                }
                OutboxStatus::Failed { reason, .. } => fail(format!("not sent: {reason}")),
                _ => fail("queued; it will be sent on the next connection"),
            }
        }
        Command::Log {
            server,
            conversation,
            count,
        } => {
            let account = pick(ctx, &server)?;
            let conv = account.conversation(&conversation).or_else(explain)?;
            let Some(info) = conv.info().or_else(explain)? else {
                return fail(format!("nothing stored for {conversation}"));
            };
            for m in last_messages(&conv, count).or_else(explain)? {
                println!("{}", show(&m));
            }
            for e in conv.outbox().or_else(explain)? {
                let what = match e.deletes {
                    Some(seq) => format!("(delete {seq})"),
                    None => e.text,
                };
                match e.status {
                    OutboxStatus::Sent { .. } => {}
                    OutboxStatus::Failed { reason, .. } => {
                        println!("(not sent: {reason}) {what}")
                    }
                    _ => println!("(waiting to be sent) {what}"),
                }
            }
            if !info.caught_up {
                eprintln!(
                    "risala: the cache has events up to {} of {}; run risala sync to catch up",
                    info.sync_point, info.head
                );
            }
            Ok(())
        }
        Command::Sync { server } => {
            let accounts = client.accounts().or_else(explain)?;
            let accounts: Vec<Account> = match &server {
                Some(server) => vec![pick(ctx, server)?],
                None => accounts,
            };
            if accounts.is_empty() {
                return fail("no accounts; add one with risala guest <server> <name>");
            }
            let mut failed = false;
            for account in accounts {
                if connect(ctx, &account).await.is_err() {
                    failed = true;
                    continue;
                }
                if within(account.wait_synced()).await.is_err() {
                    failed = true;
                    continue;
                }
                println!("{} as {}", account.server(), account.uid());
                for c in all_conversations(&account).or_else(explain)? {
                    println!("  {}", summary(&c));
                }
                account.disconnect().await;
            }
            if failed { Err(Failed(FAILED)) } else { Ok(()) }
        }
        Command::Export {
            server,
            conversation,
            output,
        } => {
            let account = pick(ctx, &server)?;
            let conv = account.conversation(&conversation).or_else(explain)?;
            match connect(ctx, &account).await {
                Ok(_) => {
                    within(conv.download()).await?;
                    within(account.wait_synced()).await?;
                }
                Err(Failed(_)) => eprintln!("risala: offline; exporting what the cache has"),
            }
            let lines = conv.export().or_else(explain)?;
            let text: String = lines.iter().map(|l| format!("{l}\n")).collect();
            match output {
                Some(path) => {
                    if let Err(e) = std::fs::write(&path, text) {
                        return fail(format!("writing {}: {e}", path.display()));
                    }
                    eprintln!(
                        "risala: {} events written to {}",
                        lines.len(),
                        path.display()
                    );
                }
                None => {
                    let _ = std::io::stdout().write_all(text.as_bytes());
                }
            }
            Ok(())
        }
        Command::Chat { server, room } => chat(ctx, &server, &room).await,
        Command::Rooms(command) => rooms::run(ctx, command).await,
        Command::Admin { command } => admin::run(ctx, command).await,
        Command::Read {
            server,
            conversation,
            seq,
        } => {
            let account = pick(ctx, &server)?;
            let online = match tokio::time::timeout(WAIT, account.connect()).await {
                Ok(Ok(_)) => within(account.wait_synced()).await.is_ok(),
                _ => false,
            };
            let conv = account.conversation(&conversation).or_else(explain)?;
            if conv.info().or_else(explain)?.is_none() {
                return fail(format!("nothing stored for {conversation}"));
            }
            match seq {
                Some(seq) => within(conv.mark_read(seq)).await?,
                None => within(conv.mark_all_read()).await?,
            }
            if online {
                // Let READ go out.
                within(account.wait_synced()).await?;
            }
            let info = conv.info().or_else(explain)?.expect("stored");
            println!(
                "{}: read up to {}, {} unread",
                info.name, info.read, info.unread
            );
            if !online && !account.is_guest() {
                eprintln!("risala: offline; the server hears on the next connection");
            }
            Ok(())
        }
        Command::Name { server, text } => {
            let account = online(ctx, &server).await?;
            let name = text.join(" ");
            within(account.set_display_name(&name)).await?;
            if name.trim().is_empty() {
                println!("display name cleared");
            } else {
                println!("display name set to {}", name.trim());
            }
            Ok(())
        }
        Command::Members { server, room } => {
            let account = online(ctx, &server).await?;
            let conv = account.conversation(&room).or_else(explain)?;
            // The uid comes first on each line, so the display name
            // follows it as it is (8.2).
            for m in within(conv.members()).await? {
                let mut line = format!("{} {} {}", m.uid, m.role, presence(m.presence));
                if let Some(name) = &m.display_name {
                    line.push(' ');
                    line.push_str(name);
                }
                println!("{line}");
            }
            Ok(())
        }
        Command::Whois { server, uid } => {
            let account = online(ctx, &server).await?;
            let user = within(account.whois(&uid)).await?;
            match user.display_name {
                Some(name) => println!("{} {} {name}", user.uid, presence(user.presence)),
                None => println!("{} {}", user.uid, presence(user.presence)),
            }
            Ok(())
        }
        Command::Block { server, target } => {
            let account = identity_online(ctx, &server).await?;
            within(account.block(&target)).await?;
            println!("blocked {}", target.trim());
            Ok(())
        }
        Command::Unblock { server, target } => {
            let account = identity_online(ctx, &server).await?;
            within(account.unblock(&target)).await?;
            println!("unblocked {}", target.trim());
            Ok(())
        }
        Command::Blocks { server, hide, show } => {
            let account = identity(ctx, &server)?;
            let targets = if hide || show {
                // Hiding is this device's alone (5.7): no connection, and
                // the blocks as the cache has them.
                account.set_hide_blocked(hide).or_else(explain)?;
                account.cached_blocks().or_else(explain)?
            } else {
                connect(ctx, &account).await?;
                within(account.blocks()).await?
            };
            for target in targets {
                println!("{target}");
            }
            if account.hides_blocked().or_else(explain)? {
                eprintln!("risala: blocked people's messages are hidden in rooms");
            }
            Ok(())
        }
        Command::Register {
            server,
            name,
            label,
        } => {
            let account = within(client.register(&server, &name)).await?;
            let uid = account.uid();
            let line = client
                .key_line(&uid, label.as_deref().unwrap_or(""))
                .or_else(explain)?;
            println!("{uid}");
            println!("{line}");
            eprintln!("risala: registered {uid} on {}", account.server());
            eprintln!(
                "risala: the server publishes its key file; to add another device, show its \
                 key line there and run risala keys add {} <line> here",
                account.server()
            );
            Ok(())
        }
        Command::Login {
            server,
            identity,
            key,
            force,
            label,
        } => login(ctx, &server, &identity, key, force, label.as_deref()).await,
        Command::Keys { command } => keys(ctx, command).await,
        Command::Unregister { server, uid, purge } => {
            let Some(account) = client.account(&server, &uid).or_else(explain)? else {
                return fail(format!(
                    "no account {} on {server}; risala whoami lists them",
                    uid.trim()
                ));
            };
            let done = within(account.unregister(&uid, purge)).await?;
            println!("deleted {} from {server}", done.uid);
            eprintln!("risala: removed the account and its cache");
            if done.key_deleted {
                eprintln!("risala: deleted this device's key, which the server no longer lists");
            } else if done.hosted {
                eprintln!(
                    "risala: could not delete this device's key for {}; the server no longer \
                     lists it",
                    done.uid
                );
            } else {
                eprintln!(
                    "risala: kept this device's key: {server} does not host {}, whose own key \
                     file is unchanged and still decides where the key works",
                    done.uid
                );
            }
            Ok(())
        }
        Command::Whoami { server } => {
            let accounts: Vec<Account> = match &server {
                Some(server) => {
                    let wanted = server_name(server)?;
                    client
                        .accounts()
                        .or_else(explain)?
                        .into_iter()
                        .filter(|a| a.server() == wanted)
                        .collect()
                }
                None => client.accounts().or_else(explain)?,
            };
            if accounts.is_empty() {
                return fail(
                    "no accounts; add one with risala guest, risala login or risala register",
                );
            }
            for account in accounts {
                let what = if account.is_guest() {
                    "guest".to_owned()
                } else {
                    match account.device_key().or_else(explain)? {
                        Some(key) => format!("key {}", key.fingerprint),
                        None => "no device key".to_owned(),
                    }
                };
                println!("{} on {} ({what})", account.uid(), account.server());
            }
            Ok(())
        }
        Command::Keygen {
            identity,
            label,
            force,
        } => {
            let key = match within(client.create_device_key(&identity, force)).await {
                Ok(key) => key,
                Err(failed) => {
                    if !force && matches!(client.device_key(&identity), Ok(Some(_))) {
                        eprintln!("risala: pass --force to replace it");
                    }
                    return Err(failed);
                }
            };
            let line = client
                .key_line(&key.identity, label.as_deref().unwrap_or(""))
                .or_else(explain)?;
            println!("{line}");
            let url = client.key_file_url(&key.identity).or_else(explain)?;
            eprintln!(
                "risala: add this line to the key file of {} at {url} (4.4)",
                key.identity
            );
            Ok(())
        }
        Command::Keyline { identity, label } => {
            match client.key_line(&identity, label.as_deref().unwrap_or("")) {
                Ok(line) => {
                    println!("{line}");
                    Ok(())
                }
                Err(ClientError::Keys {
                    kind: KeyErrorKind::NoKey,
                    ..
                }) => fail_with(
                    ACT,
                    format!("no key for {identity}; make one with risala keygen {identity}"),
                ),
                Err(e) => explain(e),
            }
        }
    }
}

/// The server address as the client shows it, or a usage error.
fn server_name(server: &str) -> Res<String> {
    match server.parse::<librisala::addr::ServerAddr>() {
        Ok(addr) => Ok(addr.to_string()),
        Err(_) => fail_with(USAGE, format!("invalid server address {server:?}")),
    }
}

/// `risala login`: adds the identity account, with a key made or
/// imported, and signs in unless the key is new.
async fn login(
    ctx: &Ctx,
    server: &str,
    identity: &str,
    pem_file: Option<PathBuf>,
    force: bool,
    label: Option<&str>,
) -> Res {
    let client = &ctx.client;
    let mut new_key = false;
    match pem_file {
        Some(path) => {
            // The PEM holds the private key: wiped when dropped.
            let pem = match std::fs::read_to_string(&path) {
                Ok(pem) => zeroize::Zeroizing::new(pem),
                Err(e) => return fail(format!("reading {}: {e}", path.display())),
            };
            match within(client.import_device_key(identity, &pem, force)).await {
                Ok(_) => {}
                Err(Failed(code)) => {
                    if code == ACT {
                        eprintln!("risala: pass --force to replace the key stored for {identity}");
                    }
                    return Err(Failed(code));
                }
            }
        }
        None => {
            if client.device_key(identity).or_else(explain)?.is_none() {
                within(client.create_device_key(identity, false)).await?;
                new_key = true;
            }
        }
    }
    let account = client.add_identity(server, identity).or_else(explain)?;
    if new_key {
        let uid = account.uid();
        println!("{}", key_line_of(ctx, &uid, label)?);
        eprintln!("risala: made a new key for {uid} on this device.");
        how_to_publish(ctx, &account)?;
        eprintln!("Then sign in with:");
        eprintln!("    risala login {} {uid}", account.server());
        return Err(Failed(ACT));
    }
    let uid = connect(ctx, &account).await?;
    if account.is_operator() {
        println!("signed in to {} as {uid}, an operator", account.server());
    } else {
        println!("signed in to {} as {uid}", account.server());
    }
    Ok(())
}

fn key_line_of(ctx: &Ctx, uid: &str, label: Option<&str>) -> Res<String> {
    ctx.client
        .key_line(uid, label.unwrap_or(""))
        .or_else(explain)
}

/// Tells the user how to get this device's key accepted.
fn how_to_publish(ctx: &Ctx, account: &Account) -> Res {
    let uid = account.uid();
    let url = ctx.client.key_file_url(&uid).or_else(explain)?;
    let server = account.server();
    eprintln!("Before it can sign in, the identity's key file must list the key line above:");
    eprintln!("  - add the line to {url}, or");
    eprintln!("  - if {server} hosts {uid}, add it from a device that is signed in:");
    eprintln!("        risala keys add {server} <the line>");
    Ok(())
}

/// `risala keys ...`.
async fn keys(ctx: &Ctx, command: KeysCommand) -> Res {
    match command {
        KeysCommand::List { server, lines } => {
            let account = identity_online(ctx, &server).await?;
            let keys = within(account.keys()).await?;
            for key in &keys {
                if lines {
                    let line = if key.label.is_empty() {
                        format!("mldsa44 {}", key.public_key)
                    } else {
                        format!("mldsa44 {} {}", key.public_key, key.label)
                    };
                    println!("{line}");
                } else {
                    println!("{}", show_key(key));
                }
            }
            Ok(())
        }
        KeysCommand::Add { server, key, label } => {
            let account = identity_online(ctx, &server).await?;
            let added =
                within(account.add_key(&key.join(" "), label.as_deref().unwrap_or(""))).await?;
            println!("added {} to {}", show_key(&added), account.uid());
            Ok(())
        }
        KeysCommand::Del { server, key } => {
            let account = identity_online(ctx, &server).await?;
            let key = key.join(" ");
            let key = if key.trim().starts_with("sha256:") {
                let wanted = key.trim();
                let keys = within(account.keys()).await?;
                match keys.into_iter().find(|k| k.fingerprint == wanted) {
                    Some(k) => k.public_key,
                    // Well-formed, but not one of the keys: a failure, not
                    // a usage error.
                    None => return fail(format!("{} has no key {wanted}", account.uid())),
                }
            } else {
                key
            };
            within(account.remove_key(&key)).await?;
            println!("removed the key from {}", account.uid());
            Ok(())
        }
    }
}

/// One line for a key: its fingerprint and label.
fn show_key(key: &KeyInfo) -> String {
    let mut s = key.fingerprint.clone();
    if !key.label.is_empty() {
        s.push(' ');
        s.push_str(&key.label);
    }
    if key.this_device {
        s.push_str(" (this device)");
    }
    s
}

/// How presence is shown (8.3).
fn presence(p: Presence) -> &'static str {
    match p {
        Presence::Online => "online",
        Presence::Offline => "offline",
        Presence::NotKnown => "unknown",
    }
}

/// The identity account on `server`.
fn identity(ctx: &Ctx, server: &str) -> Res<Account> {
    let account = pick(ctx, server)?;
    if account.is_guest() {
        return fail_with(
            USAGE,
            format!(
                "{} is a guest, which has no keys and cannot block",
                account.uid()
            ),
        );
    }
    Ok(account)
}

/// The identity account on `server`, signed in.
async fn identity_online(ctx: &Ctx, server: &str) -> Res<Account> {
    let account = identity(ctx, server)?;
    connect(ctx, &account).await?;
    Ok(account)
}

/// Waits for a server, at most [`WAIT`].
async fn within<T>(f: impl Future<Output = Result<T, ClientError>>) -> Res<T> {
    match tokio::time::timeout(WAIT, f).await {
        Ok(r) => r.or_else(explain),
        Err(_) => fail("timed out waiting for the server"),
    }
}

/// The account to use on `server`: the one `--as` names, or the only one.
fn pick(ctx: &Ctx, server: &str) -> Res<Account> {
    let client = &ctx.client;
    if let Some(uid) = &ctx.account {
        return match client.account(server, uid).or_else(explain)? {
            Some(a) => Ok(a),
            None => fail(format!("no account {uid} on {server}")),
        };
    }
    let wanted = server_name(server)?;
    let mut on: Vec<Account> = client
        .accounts()
        .or_else(explain)?
        .into_iter()
        .filter(|a| a.server() == wanted)
        .collect();
    match on.len() {
        0 => fail(format!(
            "no account on {server}; add one with risala guest, risala login or risala register"
        )),
        1 => Ok(on.remove(0)),
        _ => {
            let uids: Vec<String> = on.iter().map(Account::uid).collect();
            fail(format!(
                "several accounts on {server} ({}); pick one with --as",
                uids.join(", ")
            ))
        }
    }
}

/// Connects an account and waits until it has signed in.
///
/// If the server does not accept the device's key, this says how to
/// publish it. `auth-failed` is final (4.5): it is not tried again.
async fn connect(ctx: &Ctx, account: &Account) -> Res<String> {
    let result = match tokio::time::timeout(WAIT, account.connect()).await {
        Ok(result) => result,
        Err(_) => return fail("timed out waiting for the server"),
    };
    let uid = account.uid();
    match result {
        Ok(uid) => Ok(uid),
        Err(ClientError::Refused {
            kind: RefusedKind::AuthFailed,
            ..
        }) => {
            eprintln!(
                "risala: {} did not accept this device's key for {uid}.",
                account.server()
            );
            match ctx.client.key_line(&uid, "") {
                Ok(line) => {
                    eprintln!("This device's key line is:");
                    eprintln!();
                    eprintln!("{line}");
                    eprintln!();
                }
                Err(e) => eprintln!("risala: {e}"),
            }
            how_to_publish(ctx, account)?;
            Err(Failed(ACT))
        }
        Err(ClientError::Refused {
            kind: RefusedKind::KeyRemoved,
            ..
        }) => {
            eprintln!(
                "risala: {} no longer accepts this device's key for {uid}, which it accepted \
                 before. It was most likely removed from the identity's key file.",
                account.server()
            );
            eprintln!("To use this device again, add its key back:");
            how_to_publish(ctx, account)?;
            Err(Failed(ACT))
        }
        Err(e) => explain(e),
    }
}

/// The account on `server`, signed in.
/// Connects for a command that queues in the outbox, which it does
/// whether or not this works, so the error is kept for after.
async fn try_connect(account: &Account) -> Result<(), ClientError> {
    match tokio::time::timeout(WAIT, account.connect()).await {
        Ok(r) => r.map(drop),
        Err(_) => Err(ClientError::NotConnected),
    }
}

/// Explains why an entry was queued but not `done` (`sent`, `deleted`),
/// after [`try_connect`] failed with `e`.
fn queued_offline(e: ClientError, done: &str) -> Res {
    if e.is_permanent() {
        // Connecting again will not help until the user acts.
        let _: Res = explain(e);
        fail(format!(
            "queued, but it cannot be {done} until that is fixed; then run risala sync"
        ))
    } else {
        eprintln!("risala: {e}");
        fail(format!("queued; it will be {done} on the next connection"))
    }
}

async fn online(ctx: &Ctx, server: &str) -> Res<Account> {
    let account = pick(ctx, server)?;
    connect(ctx, &account).await?;
    Ok(account)
}

/// One line for a message: `[seq] HH:MM <from> text`.
fn show(m: &Message) -> String {
    let time = m.time.get(11..16).unwrap_or(&m.time);
    let text = m.text.as_deref().unwrap_or("");
    let subject = m.subject.as_deref().unwrap_or("");
    let body = match m.kind {
        EventKind::Message if m.deleted => "(deleted)".to_owned(),
        EventKind::Message => {
            let mut s = text.replace('\n', "\n    ");
            if let Some(to) = m.reply_to {
                s = format!("(re {to}) {s}");
            }
            if m.edited {
                s.push_str(" (edited)");
            }
            for r in &m.reactions {
                s.push_str(&format!(" [{} {}]", r.reaction, r.count));
            }
            format!("<{}> {s}", m.from)
        }
        EventKind::Join => format!("* {} joined", m.from),
        EventKind::Part if text.is_empty() => format!("* {} left", m.from),
        EventKind::Part => format!("* {} left ({text})", m.from),
        EventKind::Set => format!("* {} set {text}", m.from),
        EventKind::Invite => format!("* {} invited {subject}", m.from),
        EventKind::Kick | EventKind::Ban => {
            let verb = if m.kind == EventKind::Kick {
                "kicked"
            } else {
                "banned"
            };
            match text {
                "" => format!("* {} {verb} {subject}", m.from),
                why => format!("* {} {verb} {subject} ({why})", m.from),
            }
        }
        EventKind::Unban => format!("* {} unbanned {subject}", m.from),
        EventKind::Role => format!("* {} made {subject} {text}", m.from),
        _ => format!("* {}", m.line),
    };
    format!("[{}] {time} {body}", m.seq)
}

/// Every conversation of an account, page by page.
fn all_conversations(account: &Account) -> Result<Vec<ConversationInfo>, ClientError> {
    let mut out = Vec::new();
    let mut cursor = None;
    loop {
        let page = account.conversations(cursor, 0)?;
        out.extend(page.conversations);
        match page.next {
            Some(next) => cursor = Some(next),
            None => return Ok(out),
        }
    }
}

/// The newest `count` messages of a conversation, oldest first, page by
/// page.
fn last_messages(conv: &Conversation, count: u32) -> Result<Vec<Message>, ClientError> {
    let mut out: Vec<Message> = Vec::new();
    let mut cursor = None;
    while (out.len() as u32) < count {
        let page = conv.messages(cursor, count - out.len() as u32)?;
        let mut older = page.messages;
        older.append(&mut out);
        out = older;
        match page.older {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }
    Ok(out)
}

fn summary(c: &ConversationInfo) -> String {
    let mut s = format!("{}: {} events", c.name, c.newest);
    if c.unread > 0 {
        s.push_str(&format!(", {} unread", c.unread));
    }
    if !c.joined {
        s.push_str(" (left)");
    }
    if !c.caught_up {
        s.push_str(&format!(" (stored up to {} of {})", c.sync_point, c.head));
    }
    s
}

/// The interactive line mode: messages as they arrive, each typed line
/// sent. Lines starting with `/` are commands: `/quit`. Who else is typing
/// is shown; this side sends no TYPING, since standard input arrives a
/// whole line at a time.
async fn chat(ctx: &Ctx, server: &str, room: &str) -> Res {
    let account = online(ctx, server).await?;
    let conv = within(account.join(room)).await?;
    let timeline = conv.timeline(20).or_else(explain)?;
    for m in timeline.items() {
        println!("{}", show(&m));
    }
    // What is shown is read (7.4).
    let _ = conv.mark_all_read().await;
    eprintln!(
        "risala: in {} as {}; type to send, /quit to leave",
        conv.name(),
        uid_of(&account)
    );

    // Standard input is read on a thread of its own.
    let (lines_tx, mut lines) = tokio::sync::mpsc::unbounded_channel::<String>();
    std::thread::spawn(move || {
        for line in std::io::stdin().lines() {
            let Ok(line) = line else { break };
            if lines_tx.send(line).is_err() {
                break;
            }
        }
    });
    let events = account.subscribe();
    loop {
        tokio::select! {
            diffs = timeline.next() => {
                let Some(diffs) = diffs else { return Ok(()) };
                let shown = !diffs.is_empty();
                for diff in diffs {
                    match diff {
                        TimelineDiff::Insert { item, .. } | TimelineDiff::Update { item, .. } => {
                            println!("{}", show(&item));
                        }
                        TimelineDiff::Reset { items } => {
                            println!("-- the history was replaced --");
                            for m in items {
                                println!("{}", show(&m));
                            }
                        }
                        TimelineDiff::Remove { .. } => {}
                    }
                }
                if shown {
                    let _ = conv.mark_all_read().await;
                }
            }
            event = events.next() => {
                use librisala::client::AccountEvent;
                match event {
                    Some(AccountEvent::State { state }) => eprintln!("risala: {state:?}"),
                    Some(AccountEvent::Notice { notice }) => eprintln!("risala: {}", show_notice(&notice)),
                    // 5.8: this account reviews the room's reports.
                    Some(AccountEvent::Report { report }) => {
                        eprintln!("risala: report {}", rooms::show_report(&report));
                    }
                    Some(AccountEvent::ReportResolved { id }) => {
                        eprintln!("risala: report {id} was resolved");
                    }
                    Some(AccountEvent::Outbox { entry }) => {
                        if let OutboxStatus::Failed { reason, .. } = entry.status {
                            eprintln!("risala: not sent ({reason}): {}", entry.text);
                        }
                    }
                    // 8.1. Standard input is read a line at a time, so the
                    // terminal cannot tell when the user types: nothing is
                    // sent for that.
                    Some(AccountEvent::Typing { conversation, uids })
                        if conversation == conv.name() && !uids.is_empty() =>
                    {
                        let who: Vec<String> = match conv.labels(uids.clone()) {
                            Ok(labels) => labels.iter().map(show_label).collect(),
                            Err(_) => uids,
                        };
                        let verb = if who.len() == 1 { "is" } else { "are" };
                        eprintln!("risala: {} {verb} typing", who.join(", "));
                    }
                    Some(_) => {}
                    None => return Ok(()),
                }
            }
            line = lines.recv() => {
                let Some(line) = line else { break };
                let line = line.trim_end();
                match line {
                    "" => {}
                    "/quit" | "/q" => break,
                    _ if line.starts_with('/') => eprintln!("risala: commands: /quit"),
                    _ => {
                        if let Err(e) = conv.send(line).await {
                            eprintln!("risala: {e}");
                        }
                    }
                }
            }
        }
    }
    // Let what was typed go out before leaving.
    let _ = tokio::time::timeout(Duration::from_secs(5), account.wait_synced()).await;
    account.disconnect().await;
    Ok(())
}

/// A notice as the terminal shows it (6.4, 7.1, 8.4, 10.4).
fn show_notice(notice: &Notice) -> String {
    let because = |why: &str| {
        if why.is_empty() {
            String::new()
        } else {
            format!(" ({why})")
        }
    };
    match notice {
        Notice::Invited { room, by } => format!("{by} invited you to {room}"),
        Notice::Kicked { room, by, reason } => {
            format!("{by} kicked you from {room}{}", because(reason))
        }
        Notice::Banned { room, by, reason } => {
            format!("{by} banned you from {room}{}", because(reason))
        }
        Notice::Left { conversation } => format!("you are no longer in {conversation}"),
        Notice::Dropped { room, reason } => {
            format!("{room} was deleted by the server{}", because(reason))
        }
        Notice::RejoinFailed { room, error } => format!("could not join {room} again: {error}"),
        Notice::Server { text } => format!("notice: {text}"),
    }
}

/// A person as the terminal shows them (8.2): the name, then the uid in
/// angle brackets when it must be shown.
fn show_label(label: &Label) -> String {
    match &label.uid {
        Some(uid) => format!("{} <{uid}>", label.name),
        None => label.name.clone(),
    }
}

fn uid_of(account: &Account) -> String {
    match account.state() {
        librisala::client::ConnectionState::Online { uid } => uid,
        _ => account.uid(),
    }
}

/// One room of LIST or ADMIN ROOMS (6.1, 10.4).
pub(crate) fn print_room(room: &str, members: u64, topic: &str) {
    let people = if members == 1 { "member" } else { "members" };
    if topic.is_empty() {
        println!("{room} ({members} {people})");
    } else {
        println!("{room} ({members} {people}): {topic}");
    }
}
