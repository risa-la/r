//! `risala`, a small terminal client and key tool built on librisala.
//!
//! Everything it learns is kept in a state directory (by default
//! `$XDG_STATE_HOME/risala`, or `~/.local/state/risala`): the cache
//! `cache.db`, with trust records, accounts, history and the outbox, and
//! device keys under `keys/`. So `log` and `export` work with no
//! connection. A guest resumes its session on each run (4.2), so running
//! commands one after another adds no JOIN or PART to its rooms. Once its
//! session has ended, its rooms are joined again.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use librisala::client::{
    Account, Client, ClientError, ClientOptions, Conversation, ConversationInfo, EventKind,
    Message, OutboxStatus, TimelineDiff, TrustInfo,
};
use librisala::conn::keys::{FileKeyStore, KeyStore, generate_device_key, key_line};

/// How long to wait for a server before giving up.
const WAIT: Duration = Duration::from_secs(30);

#[derive(Parser)]
#[command(name = "risala", version, about = "A small terminal client for risala")]
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
    /// Chat in a room: shows messages as they arrive, and sends each line
    /// typed. /quit leaves.
    Chat { server: String, room: String },
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

/// A failure, already explained to the user.
struct Failed;

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
        Err(Failed) => ExitCode::FAILURE,
    }
}

fn fail<T>(message: impl std::fmt::Display) -> Res<T> {
    eprintln!("risala: {message}");
    Err(Failed)
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
            Err(Failed)
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
            Err(Failed)
        }
        _ => fail(e),
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
    keys_dir: PathBuf,
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
        Ok(client) => Ok(Ctx {
            client,
            keys_dir,
            account,
        }),
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
            let uid = connect(&account).await?;
            println!("signed in to {} as {uid}", account.server());
            Ok(())
        }
        Command::Join { server, room } => {
            let account = online(ctx, &server).await?;
            let conv = within(account.join(&room)).await?;
            within(account.wait_synced()).await?;
            let count = conv.messages(None, 1000).or_else(explain)?.messages.len();
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
                connect(&account).await?;
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
                    if room.topic.is_empty() {
                        println!("{} ({} members)", room.room, room.members);
                    } else {
                        println!("{} ({} members): {}", room.room, room.members, room.topic);
                    }
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
            let connected = connect(&account).await;
            let conv = account.conversation(&conversation).or_else(explain)?;
            let entry = conv.send(&text.join(" ")).await.or_else(explain)?;
            if connected.is_err() {
                return fail("queued; it will be sent on the next connection");
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
                match e.status {
                    OutboxStatus::Sent { .. } => {}
                    OutboxStatus::Failed { reason, .. } => {
                        println!("(not sent: {reason}) {}", e.text)
                    }
                    _ => println!("(waiting to be sent) {}", e.text),
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
                if connect(&account).await.is_err() {
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
            if failed { Err(Failed) } else { Ok(()) }
        }
        Command::Export {
            server,
            conversation,
            output,
        } => {
            let account = pick(ctx, &server)?;
            let conv = account.conversation(&conversation).or_else(explain)?;
            match connect(&account).await {
                Ok(_) => {
                    within(conv.download()).await?;
                    within(account.wait_synced()).await?;
                }
                Err(Failed) => eprintln!("risala: offline; exporting what the cache has"),
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
        Command::Keygen {
            identity,
            label,
            force,
        } => {
            let keys = key_store(ctx, &identity)?;
            match keys.load(&identity) {
                Ok(Some(_)) if !force => {
                    return fail(format!(
                        "a key for {identity} exists; pass --force to replace it"
                    ));
                }
                Ok(_) => {}
                Err(e) => return fail(e),
            }
            let key = match generate_device_key() {
                Ok(key) => key,
                Err(e) => return fail(format!("generating a key: {e}")),
            };
            if let Err(e) = keys.save(&identity, &key) {
                return fail(e);
            }
            print_key_line(&key.public_key(), label.as_deref())?;
            eprintln!("risala: add this line to the key file of {identity} (4.4)");
            Ok(())
        }
        Command::Keyline { identity, label } => {
            let keys = key_store(ctx, &identity)?;
            match keys.load(&identity) {
                Ok(Some(key)) => print_key_line(&key.public_key(), label.as_deref()),
                Ok(None) => fail(format!(
                    "no key for {identity}; make one with risala keygen {identity}"
                )),
                Err(e) => fail(e),
            }
        }
    }
}

fn key_store(ctx: &Ctx, identity: &str) -> Res<FileKeyStore> {
    if identity
        .parse::<librisala::proto::names::Identity>()
        .is_err()
    {
        return fail(format!(
            "{identity:?} is not an identity like alice@example.org"
        ));
    }
    Ok(FileKeyStore::new(&ctx.keys_dir))
}

fn print_key_line(key: &librisala::proto::auth::PublicKey, label: Option<&str>) -> Res {
    match key_line(key, label) {
        Ok(line) => {
            println!("{line}");
            Ok(())
        }
        Err(e) => fail(format!("bad label: {e}")),
    }
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
    let wanted = match server.parse::<librisala::addr::ServerAddr>() {
        Ok(addr) => addr.to_string(),
        Err(_) => return fail(format!("invalid server address {server:?}")),
    };
    let mut on: Vec<Account> = client
        .accounts()
        .or_else(explain)?
        .into_iter()
        .filter(|a| a.server() == wanted)
        .collect();
    match on.len() {
        0 => fail(format!(
            "no account on {server}; add one with risala guest {server} <name>"
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
async fn connect(account: &Account) -> Res<String> {
    within(account.connect()).await
}

/// The account on `server`, signed in.
async fn online(ctx: &Ctx, server: &str) -> Res<Account> {
    let account = pick(ctx, server)?;
    connect(&account).await?;
    Ok(account)
}

/// One line for a message: `[seq] HH:MM <from> text`.
fn show(m: &Message) -> String {
    let time = m.time.get(11..16).unwrap_or(&m.time);
    let text = m.text.as_deref().unwrap_or("");
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
/// sent. Lines starting with `/` are commands: `/quit`.
async fn chat(ctx: &Ctx, server: &str, room: &str) -> Res {
    let account = online(ctx, server).await?;
    let conv = within(account.join(room)).await?;
    let timeline = conv.timeline(20).or_else(explain)?;
    for m in timeline.items() {
        println!("{}", show(&m));
    }
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
            }
            event = events.next() => {
                use librisala::client::AccountEvent;
                match event {
                    Some(AccountEvent::State { state }) => eprintln!("risala: {state:?}"),
                    Some(AccountEvent::Notice { notice }) => eprintln!("risala: {notice:?}"),
                    Some(AccountEvent::Outbox { entry }) => {
                        if let OutboxStatus::Failed { reason, .. } = entry.status {
                            eprintln!("risala: not sent ({reason}): {}", entry.text);
                        }
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

fn uid_of(account: &Account) -> String {
    match account.state() {
        librisala::client::ConnectionState::Online { uid } => uid,
        _ => account.uid(),
    }
}
