//! `risala`, a small, scriptable terminal client built on librisala.
//!
//! Each run does one thing and stops. Everything it learns is kept in a
//! state directory (by default `$XDG_STATE_HOME/risala`, or
//! `~/.local/state/risala`): the cache `cache.db`, encrypted with the key
//! in `cache.key`, and the device's secret keys under `keys/`.
//!
//! ```sh
//! risala create chat.example.org alice laptop      # prints the uid and recovery key
//! risala direct bob@example.org                     # prints the conversation's number
//! risala send bob@example.org hello                 # by number, peer or room name
//! risala sync && risala read bob@example.org
//! risala pair new chat.example.org phone            # on the new device: prints the QR text
//! risala pair accept 'RISALA-PAIR:...'              # on a device of the identity
//! risala recover chat.example.org alice@example.org spare < recovery-key
//! ```
//!
//! Commands that talk to the server connect the account, act, then stay
//! connected until what they queued is sent, for at most `--wait`
//! seconds. `sync` stays for `--wait` seconds, to receive. Output is one
//! record per line, fields separated by tabs.
//!
//! The options `--connect-to`, `--trust`, `--ca`, `--resolve`, `--witness`
//! and `--short-waits` reach a development server such as `risala-dev`'s,
//! which prints them.
//!
//! Exit codes: 0 done, 1 failed, 2 bad arguments.

use std::io::{BufRead as _, Write as _};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{Args, Parser, Subcommand};
use librisala::client::conversations::{ConversationKind, ConversationSummary};
use librisala::client::types::{AccountKind, ConversationId, MessageId};
use librisala::client::{ConnectionState, identity::KeyFetcherHttps};
use librisala::conn::Slot;
use librisala::keyfetch::{CertificateDer, FetchOptions, KeyFetcher, Roots, StaticResolver};
use librisala::keys::FileKeyStore;
use librisala::store::{AccountId, DatabaseKey, Store, StoreError};
use librisala::{Client, ClientOptions, Event};
use rustls::pki_types::pem::PemObject as _;

/// How long to wait for a connection to sign in.
const SIGN_IN: Duration = Duration::from_secs(30);

/// How long to wait for the device's own records to be witnessed (4.5): a
/// log SHOULD witness a record within a minute.
const WITNESSED: Duration = Duration::from_secs(180);

type Res<T = ()> = Result<T, String>;

#[derive(Parser)]
#[command(
    name = "risala",
    version,
    about = "A small, scriptable terminal client for risala",
    after_help = "Exit codes: 0 done, 1 failed, 2 bad arguments."
)]
struct Cli {
    /// The state directory: cache and keys.
    #[arg(long, global = true, value_name = "DIR")]
    state: Option<PathBuf>,
    /// The account to use, by its uid, when there are several.
    #[arg(long = "as", global = true, value_name = "UID")]
    account: Option<String>,
    /// At most how many seconds to stay connected once done, for what was
    /// queued to be sent; `sync` stays this long to receive.
    #[arg(long, global = true, default_value_t = 20, value_name = "SECONDS")]
    wait: u64,
    #[command(flatten)]
    dev: Dev,
    #[command(subcommand)]
    command: Command,
}

/// Options for development servers and tests.
#[derive(Args)]
struct Dev {
    /// Connect to this address for every server, instead of resolving
    /// its name. Its certificate is still checked against the name.
    #[arg(long, global = true, value_name = "ADDR")]
    connect_to: Option<SocketAddr>,
    /// Trust a server's certificate fingerprint (2.2), checked with its
    /// operator: `HOST=sha256:...`.
    #[arg(long, global = true, value_name = "HOST=FINGERPRINT")]
    trust: Vec<String>,
    /// A PEM file of CA certificates to trust for HTTPS (key files, key
    /// logs, files), instead of the system's. Repeatable.
    #[arg(long, global = true, value_name = "PEM")]
    ca: Vec<PathBuf>,
    /// Reach `NAME` at `ADDR` for HTTPS, instead of resolving it; also
    /// allows private addresses. Repeatable.
    #[arg(long, global = true, value_name = "NAME=ADDR")]
    resolve: Vec<String>,
    /// A witness's verifier key for the witness policy (4.5). Repeatable;
    /// replaces the policy kept in the cache.
    #[arg(long, global = true, value_name = "VKEY")]
    witness: Vec<String>,
    /// How many of the witnesses must cosign; more than half by default.
    #[arg(long, global = true, value_name = "K")]
    witness_k: Option<usize>,
    /// Cut the spec's random waits before following, committing and
    /// sending Welcomes (7.4, 7.2, 12.8) from up to 10 minutes to a
    /// second. For development: it lets the server tie actions together
    /// by their timing.
    #[arg(long, global = true)]
    short_waits: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Create an identity on a server that hosts them (4.7). Prints the
    /// uid, then the recovery key, which is shown only this once (4.8).
    Create {
        server: String,
        /// The name, such as alice; the uid is name@domain.
        name: String,
        /// This device's label, such as laptop.
        label: String,
    },
    /// Pair a device by QR text (4.8).
    #[command(subcommand)]
    Pair(Pair),
    /// Recover an identity on this device with its recovery key, read
    /// from standard input (4.8). Every other device is removed.
    Recover {
        server: String,
        uid: String,
        /// This device's label.
        label: String,
    },
    /// Remove one of the identity's devices, by the start of its id, with
    /// the recovery key read from standard input (4.8).
    RemoveDevice { device: String },
    /// The identities this device holds, and their devices.
    Whoami,
    /// What this device knows of an identity: its keys' state and devices
    /// (4.4, 4.5).
    Identity {
        uid: String,
        /// Fetch its key file again first.
        #[arg(long)]
        refresh: bool,
    },
    /// An identity's safety number (12.14): the digits, then the QR text.
    Safety { uid: String },
    /// Mark an identity as verified, after comparing safety numbers, or
    /// with the QR text scanned from the other person's device (12.14).
    Verify { uid: String, qr: Option<String> },
    /// Connect and receive for `--wait` seconds, then list conversations.
    Sync,
    /// List conversations, from the cache: number, kind, name, unread.
    List,
    /// Start the direct conversation with an identity, or find it (5.1).
    /// Prints its number.
    Direct { uid: String },
    /// Private rooms (6.1).
    #[command(subcommand)]
    Room(RoomCommand),
    /// Public rooms (6.1).
    #[command(subcommand)]
    Public(PublicCommand),
    /// Set the display name shown in every group (8.2): a commit in each.
    Name { name: String },
    /// Leave a conversation (6.1).
    Leave { conversation: String },
    /// Send a message.
    Send {
        /// A conversation's number, its peer's uid, or its room's name.
        conversation: String,
        /// The text; the words are joined with spaces.
        #[arg(required = true)]
        text: Vec<String>,
    },
    /// Print a conversation's messages from the cache: id, time, sender,
    /// flags and text.
    Read {
        conversation: String,
        /// How many of the newest.
        #[arg(short = 'n', long, default_value_t = 50)]
        count: usize,
        /// Connect and receive for `--wait` seconds first.
        #[arg(long)]
        sync: bool,
    },
    /// Send a file (5.6, 12.11). Prints the message's id.
    SendFile {
        conversation: String,
        path: PathBuf,
        /// A caption.
        #[arg(long)]
        caption: Option<String>,
    },
    /// Fetch a message's file, check it, and print where it was saved.
    Fetch {
        conversation: String,
        message: String,
    },
    /// Make a backup of this device's history now, and keep making them
    /// (12.13).
    Backup,
    /// Restore the backup of the generation before, after a recovery,
    /// with the recovery key read from standard input (12.13).
    Restore,
}

#[derive(Subcommand)]
enum Pair {
    /// On the new device: prints the QR text, then waits for a device of
    /// the identity to accept it, and joins the identity.
    New { server: String, label: String },
    /// On a device of the identity: accepts the new device whose QR text
    /// this is, and sends it the history (12.13) unless `--no-history`.
    Accept {
        qr: String,
        #[arg(long)]
        no_history: bool,
    },
}

#[derive(Subcommand)]
enum RoomCommand {
    /// Create a private room. Prints its number.
    Create { name: String },
    /// Invite an identity (6.1, 6.3).
    Invite { room: String, uid: String },
    /// Remove an identity, and ban it with `--ban` (6.4).
    Remove {
        room: String,
        uid: String,
        #[arg(long)]
        ban: bool,
    },
    /// The room's members: uid, role, devices, display name.
    Members { room: String },
}

#[derive(Subcommand)]
enum PublicCommand {
    /// List the server's public rooms.
    List,
    /// Create a public room, such as #garden. Prints its number.
    Create { room: String },
    /// Join a public room. Prints its number.
    Join { room: String },
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("RISALA_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("risala: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("risala: {e}");
            ExitCode::FAILURE
        }
    }
}

fn state_dir(arg: Option<PathBuf>) -> Res<PathBuf> {
    if let Some(dir) = arg {
        return Ok(dir);
    }
    if let Some(dir) = std::env::var_os("XDG_STATE_HOME").filter(|d| !d.is_empty()) {
        return Ok(PathBuf::from(dir).join("risala"));
    }
    match std::env::var_os("HOME").filter(|d| !d.is_empty()) {
        Some(home) => Ok(PathBuf::from(home).join(".local/state/risala")),
        None => Err("no state directory: set HOME or XDG_STATE_HOME, or pass --state".into()),
    }
}

/// Creates the state directory, on Unix for its owner only (0700).
fn make_state_dir(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(dir)
}

/// The key `cache.db` is encrypted with: 32 bytes in `cache.key`, made
/// on first use, its owner's only (0600) on Unix.
fn cache_key(dir: &Path) -> Res<DatabaseKey> {
    let path = dir.join("cache.key");
    match std::fs::read(&path) {
        Ok(bytes) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let mode = std::fs::metadata(&path)
                    .map_err(|e| format!("{}: {e}", path.display()))?
                    .permissions()
                    .mode();
                if mode & 0o077 != 0 {
                    return Err(format!(
                        "{}: others can read it; chmod 600 it",
                        path.display()
                    ));
                }
            }
            let key: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| format!("{}: not a key", path.display()))?;
            Ok(DatabaseKey::from_bytes(key))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key = DatabaseKey::generate().map_err(|e| e.to_string())?;
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            options
                .open(&path)
                .and_then(|mut f| f.write_all(key.as_bytes()))
                .map_err(|e| format!("{}: {e}", path.display()))?;
            Ok(key)
        }
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

fn read_certs(paths: &[PathBuf]) -> Res<Vec<CertificateDer<'static>>> {
    let mut out = Vec::new();
    for path in paths {
        for cert in
            CertificateDer::pem_file_iter(path).map_err(|e| format!("{}: {e}", path.display()))?
        {
            out.push(cert.map_err(|e| format!("{}: {e}", path.display()))?);
        }
    }
    Ok(out)
}

fn resolves(items: &[String]) -> Res<Vec<(String, SocketAddr)>> {
    items
        .iter()
        .map(|item| {
            let (name, addr) = item
                .split_once('=')
                .ok_or_else(|| format!("--resolve {item}: not NAME=ADDR"))?;
            let addr = addr
                .parse()
                .map_err(|_| format!("--resolve {item}: not an address"))?;
            Ok((name.to_owned(), addr))
        })
        .collect()
}

/// Opens the client with the state directory and the options.
fn open(state: &Path, dev: &Dev) -> Res<Client> {
    make_state_dir(state).map_err(|e| format!("{}: {e}", state.display()))?;
    let mut options = ClientOptions {
        keys: Arc::new(FileKeyStore::new(state.join("keys"))),
        download_dir: Some(state.join("files")),
        // The upkeep (4.5, 12.14) runs at once on connecting, and then
        // often, since a run lasts seconds.
        maintenance_every: Duration::from_secs(5),
        ..ClientOptions::default()
    };
    options.session.connect_to = dev.connect_to;
    if dev.short_waits {
        options.conversations = librisala::sync::conversations::Config {
            max_follow_wait_ms: 1_000,
            max_welcome_wait_ms: 1_000,
            max_commit_wait_ms: 1_000,
            retry_ms: 1_000,
            ..librisala::sync::conversations::Config::default()
        };
    }
    if !dev.ca.is_empty() || !dev.resolve.is_empty() {
        let roots = read_certs(&dev.ca)?;
        let names = resolves(&dev.resolve)?;
        let mut resolver = StaticResolver::new();
        for (name, addr) in &names {
            resolver.insert(name, [*addr]);
        }
        let fetcher = KeyFetcher::new(FetchOptions {
            roots: if roots.is_empty() {
                FetchOptions::default().roots
            } else {
                Roots::Only(roots.clone())
            },
            allow_private: !names.is_empty(),
            min_refetch: Duration::ZERO,
            resolver: Arc::new(resolver),
            ..FetchOptions::default()
        });
        options.https = Some(Arc::new(KeyFetcherHttps(fetcher)));
        if !roots.is_empty() {
            let verifier =
                librisala::conn::roots_ca_verifier(roots).map_err(|e| format!("--ca: {e}"))?;
            options.file_https = Some(Arc::new(
                librisala::client::files::TlsFileHttps::new(verifier).connect_to(names),
            ));
        }
    }
    let key = cache_key(state)?;
    let store = match Store::open(state.join("cache.db"), &key) {
        Ok(store) => store,
        Err(StoreError::WrongKey) => {
            return Err(format!(
                "cache.key in {} does not open cache.db",
                state.display()
            ));
        }
        Err(e) => return Err(format!("opening the cache in {}: {e}", state.display())),
    };
    let client = Client::with_store(store, options);
    for item in &dev.trust {
        let (host, fp) = item
            .split_once('=')
            .ok_or_else(|| format!("--trust {item}: not HOST=FINGERPRINT"))?;
        client
            .accept_fingerprint(host, fp)
            .map_err(|e| e.to_string())?;
    }
    if !dev.witness.is_empty() {
        let k = dev.witness_k.unwrap_or(dev.witness.len() / 2 + 1);
        client
            .set_witness_policy(&dev.witness, k)
            .map_err(|e| e.to_string())?;
    }
    Ok(client)
}

struct Ctx {
    client: Client,
    account: Option<String>,
    wait: Duration,
}

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

async fn run(cli: Cli) -> Res {
    let state = state_dir(cli.state)?;
    let client = open(&state, &cli.dev)?;
    let ctx = Ctx {
        client,
        account: cli.account,
        wait: Duration::from_secs(cli.wait),
    };
    let result = command(&ctx, cli.command).await;
    for a in ctx.client.accounts().unwrap_or_default() {
        let _ = ctx.client.disconnect(a.id).await;
    }
    result
}

impl Ctx {
    /// The account to act as: `--as`, or the only identity account.
    fn account(&self) -> Res<AccountId> {
        let accounts = self.client.accounts().map_err(err)?;
        let matching: Vec<_> = accounts
            .iter()
            .filter(|a| match &self.account {
                Some(uid) => a.uid.as_str() == uid,
                None => a.kind == AccountKind::Identity,
            })
            .collect();
        match matching.as_slice() {
            [one] => Ok(one.id),
            [] => Err("no account: create, pair or recover an identity first".into()),
            _ => Err("several accounts: choose one with --as".into()),
        }
    }

    /// Connects an account and waits for its signed-in connection.
    async fn online(&self, account: AccountId) -> Res {
        let mut events = self.client.subscribe();
        self.client.connect(account).await.map_err(err)?;
        let deadline = Instant::now() + SIGN_IN;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let event = tokio::time::timeout(left, events.recv())
                .await
                .map_err(|_| "the server did not answer in time".to_string())?;
            match event {
                Ok(Event::Connection(e))
                    if e.account == account && matches!(e.slot, Slot::SignedIn | Slot::Guest) =>
                {
                    match e.state {
                        ConnectionState::Ready => return Ok(()),
                        ConnectionState::Failed(why) => return Err(format!("signing in: {why}")),
                        _ => {}
                    }
                }
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    return Err("the client closed".into());
                }
            }
        }
    }

    /// Stays connected at least `min`, and then until what was queued is
    /// sent, for at most `--wait`.
    async fn settle(&self, account: AccountId, min: Duration) {
        let start = Instant::now();
        let max = self.wait.max(min);
        loop {
            let elapsed = start.elapsed();
            if elapsed >= max {
                return;
            }
            if elapsed >= min && self.client.is_settled(account).unwrap_or(false) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// A conversation by number, peer uid or room name.
    fn conversation(&self, account: AccountId, name: &str) -> Res<ConversationId> {
        let all = self.client.conversations(account).map_err(err)?;
        if let Ok(n) = name.parse::<i64>()
            && let Some(c) = all.iter().find(|c| c.id.get() == n)
        {
            return Ok(c.id);
        }
        let found: Vec<&ConversationSummary> = all
            .iter()
            .filter(|c| {
                c.active
                    && (c.name == name || c.room.as_ref().is_some_and(|r| r.to_string() == name))
            })
            .collect();
        match found.as_slice() {
            [one] => Ok(one.id),
            [] => Err(format!("no conversation {name}")),
            _ => Err(format!(
                "several conversations are called {name}: use a number"
            )),
        }
    }

    /// Reads a recovery key from standard input.
    fn recovery_key() -> Res<String> {
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| format!("reading the recovery key: {e}"))?;
        let key = line.trim().to_owned();
        if key.is_empty() {
            return Err("no recovery key on standard input".into());
        }
        Ok(key)
    }

    /// Waits until `uid`'s records that hold this device are accepted
    /// (4.5), so that it can sign in.
    async fn until_accepted(&self, uid: &str) -> Res {
        let deadline = Instant::now() + WITNESSED;
        loop {
            let contact = self.client.refresh_identity(uid).await.map_err(err)?;
            if contact.devices.iter().any(|d| d.this_device && d.accepted) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!("{uid}: this device's record is not accepted yet"));
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
}

fn kind(k: ConversationKind) -> &'static str {
    match k {
        ConversationKind::Direct => "direct",
        ConversationKind::WithYourself => "self",
        ConversationKind::PrivateRoom => "room",
        ConversationKind::PublicRoom => "public",
    }
}

fn print_conversations(client: &Client, account: AccountId) -> Res {
    let mut out = std::io::stdout().lock();
    for c in client.conversations(account).map_err(err)? {
        if !c.active {
            continue;
        }
        let stopped = if c.sending_stopped { "\tstopped" } else { "" };
        let _ = writeln!(
            out,
            "{}\t{}\t{}\t{}{stopped}",
            c.id,
            kind(c.kind),
            c.name,
            c.unread
        );
    }
    Ok(())
}

fn parse_message_id(s: &str) -> Res<MessageId> {
    let bytes: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| s.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok()))
        .collect::<Option<_>>()
        .ok_or_else(|| format!("not a message id: {s}"))?;
    let id: [u8; 16] = bytes
        .try_into()
        .map_err(|_| format!("not a message id: {s}"))?;
    Ok(MessageId(id))
}

async fn command(ctx: &Ctx, command: Command) -> Res {
    let c = &ctx.client;
    match command {
        Command::Create {
            server,
            name,
            label,
        } => {
            let new = c
                .create_identity(&server, &name, &label)
                .await
                .map_err(err)?;
            println!("{}", new.uid);
            println!("{}", new.recovery_key.as_str());
            let _ = std::io::stdout().flush();
            ctx.until_accepted(new.uid.as_str()).await?;
            ctx.online(new.account).await?;
            // KeyPackages and the conversation with yourself (12.5, 5.1).
            ctx.settle(new.account, Duration::from_secs(3)).await;
        }
        Command::Pair(Pair::New { server, label }) => {
            let offer = c.start_pairing(&server, &label).await.map_err(err)?;
            println!("{}", offer.qr);
            let _ = std::io::stdout().flush();
            let own = c.finish_pairing().await.map_err(err)?;
            println!("{}", own.uid);
            ctx.until_accepted(own.uid.as_str()).await?;
            let account = c
                .accounts()
                .map_err(err)?
                .into_iter()
                .find(|a| a.uid == own.uid)
                .ok_or("no account for the identity")?
                .id;
            ctx.online(account).await?;
            ctx.settle(account, Duration::from_secs(3)).await;
        }
        Command::Pair(Pair::Accept { qr, no_history }) => {
            let account = ctx.account()?;
            let uid = c.account(account).map_err(err)?.uid;
            ctx.online(account).await?;
            let request = c.scan_pairing(uid.as_str(), &qr).await.map_err(err)?;
            println!("{}\t{}", request.short, request.label);
            c.confirm_pairing(uid.as_str(), !no_history)
                .await
                .map_err(err)?;
            ctx.settle(account, Duration::from_secs(1)).await;
        }
        Command::Recover { server, uid, label } => {
            let key = Ctx::recovery_key()?;
            let own = c.recover(&server, &uid, &key, &label).await.map_err(err)?;
            println!("{}\t{}", own.uid, own.device);
            ctx.until_accepted(own.uid.as_str()).await?;
            let account = c
                .accounts()
                .map_err(err)?
                .into_iter()
                .find(|a| a.uid == own.uid)
                .ok_or("no account for the identity")?
                .id;
            ctx.online(account).await?;
            ctx.settle(account, Duration::from_secs(3)).await;
        }
        Command::RemoveDevice { device } => {
            let account = ctx.account()?;
            let uid = c.account(account).map_err(err)?.uid;
            let key = Ctx::recovery_key()?;
            let found: Vec<_> = c
                .identity_devices(uid.as_str())
                .map_err(err)?
                .into_iter()
                .filter(|d| {
                    !d.removed
                        && (d.short.starts_with(&device) || d.id.to_string().starts_with(&device))
                })
                .collect();
            let [one] = found.as_slice() else {
                return Err(format!("{} devices match {device}", found.len()));
            };
            c.remove_device(uid.as_str(), one.id, &key)
                .await
                .map_err(err)?;
            ctx.online(account).await?;
            ctx.settle(account, Duration::from_secs(3)).await;
        }
        Command::Whoami => {
            for own in c.own_identities().map_err(err)? {
                println!("{}\t{}", own.uid, own.device);
                for d in c.identity_devices(own.uid.as_str()).map_err(err)? {
                    println!("\t{}\t{}\t{}", d.short, device_state(&d), d.label);
                }
            }
        }
        Command::Identity { uid, refresh } => {
            let contact = if refresh {
                c.refresh_identity(&uid).await
            } else {
                c.contact(&uid).await
            }
            .map_err(err)?;
            println!(
                "{}\t{:?}\t{}\t{}",
                contact.uid,
                contact.keys,
                if contact.verified {
                    "verified"
                } else {
                    "unverified"
                },
                match contact.stopped {
                    Some(r) => format!("stopped: {r:?}"),
                    None => "sending".into(),
                }
            );
            for d in &contact.devices {
                println!("\t{}\t{}\t{}", d.short, device_state(d), d.label);
            }
        }
        Command::Safety { uid } => {
            c.contact(&uid).await.map_err(err)?;
            let number = c.safety_number(&uid).map_err(err)?;
            println!("{}", number.digits);
            println!("{}", number.qr);
        }
        Command::Verify { uid, qr } => {
            c.contact(&uid).await.map_err(err)?;
            c.mark_verified(&uid, qr.as_deref()).map_err(err)?;
        }
        Command::Sync => {
            let account = ctx.account()?;
            ctx.online(account).await?;
            tokio::time::sleep(ctx.wait).await;
            print_conversations(c, account)?;
        }
        Command::List => print_conversations(c, ctx.account()?)?,
        Command::Direct { uid } => {
            let account = ctx.account()?;
            ctx.online(account).await?;
            let conv = c.direct(account, &uid).await.map_err(err)?;
            println!("{}", conv);
            ctx.settle(account, Duration::from_secs(1)).await;
        }
        Command::Room(RoomCommand::Create { name }) => {
            let account = ctx.account()?;
            ctx.online(account).await?;
            let conv = c.create_private_room(account, &name).await.map_err(err)?;
            println!("{}", conv);
            ctx.settle(account, Duration::from_secs(1)).await;
        }
        Command::Room(RoomCommand::Invite { room, uid }) => {
            let account = ctx.account()?;
            let conv = ctx.conversation(account, &room)?;
            ctx.online(account).await?;
            c.invite(conv, &uid).await.map_err(err)?;
            ctx.settle(account, Duration::from_secs(1)).await;
        }
        Command::Room(RoomCommand::Remove { room, uid, ban }) => {
            let account = ctx.account()?;
            let conv = ctx.conversation(account, &room)?;
            ctx.online(account).await?;
            c.remove_member(conv, &uid, ban).await.map_err(err)?;
            ctx.settle(account, Duration::from_secs(1)).await;
        }
        Command::Room(RoomCommand::Members { room }) => {
            let account = ctx.account()?;
            let conv = ctx.conversation(account, &room)?;
            for m in c.members(conv).map_err(err)? {
                println!(
                    "{}\t{:?}\t{}\t{}",
                    m.uid,
                    m.role,
                    m.devices,
                    m.display_name.unwrap_or_default()
                );
            }
        }
        Command::Public(PublicCommand::List) => {
            let account = ctx.account()?;
            ctx.online(account).await?;
            for r in c.list_public_rooms(account, None).await.map_err(err)? {
                println!("{}\t{}\t{}", r.room, r.members, r.topic);
            }
        }
        Command::Public(PublicCommand::Create { room }) => {
            let account = ctx.account()?;
            ctx.online(account).await?;
            let conv = c.create_public_room(account, &room).await.map_err(err)?;
            println!("{}", conv);
            ctx.settle(account, Duration::from_secs(1)).await;
        }
        Command::Public(PublicCommand::Join { room }) => {
            let account = ctx.account()?;
            ctx.online(account).await?;
            let conv = c.join_public_room(account, &room).await.map_err(err)?;
            println!("{}", conv);
            ctx.settle(account, Duration::from_secs(1)).await;
        }
        Command::Name { name } => {
            let account = ctx.account()?;
            ctx.online(account).await?;
            c.set_display_name(account, &name).await.map_err(err)?;
            ctx.settle(account, Duration::from_secs(1)).await;
        }
        Command::Leave { conversation } => {
            let account = ctx.account()?;
            let conv = ctx.conversation(account, &conversation)?;
            ctx.online(account).await?;
            c.leave(conv).await.map_err(err)?;
            ctx.settle(account, Duration::from_secs(1)).await;
        }
        Command::Send { conversation, text } => {
            let account = ctx.account()?;
            let conv = ctx.conversation(account, &conversation)?;
            ctx.online(account).await?;
            let id = c
                .send_text(conv, &text.join(" "), None)
                .await
                .map_err(err)?;
            println!("{id}");
            ctx.settle(account, Duration::ZERO).await;
        }
        Command::Read {
            conversation,
            count,
            sync,
        } => {
            let account = ctx.account()?;
            if sync {
                ctx.online(account).await?;
                tokio::time::sleep(ctx.wait).await;
            }
            let conv = ctx.conversation(account, &conversation)?;
            let mut out = std::io::stdout().lock();
            for m in c.messages(conv, None, count).map_err(err)? {
                let mut flags = Vec::new();
                if m.own {
                    flags.push("own");
                }
                if m.verified {
                    flags.push("verified");
                }
                if m.restored {
                    flags.push("restored");
                }
                if m.edited {
                    flags.push("edited");
                }
                let _ = writeln!(
                    out,
                    "{}\t{}\t{}\t{}\t{}",
                    m.id,
                    m.sent,
                    m.sender,
                    if flags.is_empty() {
                        "-".into()
                    } else {
                        flags.join(",")
                    },
                    m.text.unwrap_or_default()
                );
            }
        }
        Command::SendFile {
            conversation,
            path,
            caption,
        } => {
            let account = ctx.account()?;
            let conv = ctx.conversation(account, &conversation)?;
            ctx.online(account).await?;
            let id = c
                .send_file(conv, &path, None, caption.as_deref())
                .await
                .map_err(err)?;
            println!("{id}");
            ctx.settle(account, Duration::ZERO).await;
        }
        Command::Fetch {
            conversation,
            message,
        } => {
            let account = ctx.account()?;
            let conv = ctx.conversation(account, &conversation)?;
            let message = parse_message_id(&message)?;
            ctx.online(account).await?;
            let info = c.fetch_file(conv, message).await.map_err(err)?;
            match info.path {
                Some(path) => println!("{}\t{}", path.display(), info.size),
                None => return Err("the file was not saved".into()),
            }
        }
        Command::Backup => {
            let account = ctx.account()?;
            ctx.online(account).await?;
            let info = c.backup_now(account).await.map_err(err)?;
            println!(
                "{}\t{}",
                info.generation,
                info.made.map(|t| t.to_string()).unwrap_or_default()
            );
        }
        Command::Restore => {
            let account = ctx.account()?;
            let key = Ctx::recovery_key()?;
            ctx.online(account).await?;
            let restored = c.restore_backup(account, &key).await.map_err(err)?;
            println!(
                "{}\t{}\t{}",
                restored.made, restored.messages, restored.missing
            );
            ctx.settle(account, Duration::from_secs(1)).await;
        }
    }
    Ok(())
}

fn device_state(d: &librisala::client::identity::Device) -> &'static str {
    match (d.removed, d.accepted, d.this_device) {
        (true, _, _) => "removed",
        (false, true, true) => "current,this",
        (false, true, false) => "current",
        (false, false, _) => "pending",
    }
}
