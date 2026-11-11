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
//! risala send bob@example.org hello                 # a uid: the direct conversation
//! risala room create garden && risala send '#garden' hi   # a room: #name or number
//! risala sync && risala read bob@example.org
//! risala pair new chat.example.org phone            # on the new device: prints the QR text
//! risala pair accept 'RISALA-PAIR:...'              # on a device of the identity
//! risala recover chat.example.org alice@example.org spare < recovery-key
//! ```
//!
//! A conversation is named by its number from `list`; a uid names only
//! the direct conversation with that identity (your own, the conversation
//! with yourself), and `send` starts it if there is none; a room is named
//! `#name`, a private room by its name and a public one by its address.
//!
//! Commands that talk to the server connect the account, act, then stay
//! connected until what they queued has reached the server, for at most
//! `--wait` seconds, and fail if it has not: messages and commits, Welcomes,
//! the identity's new records (KEYS PUT), the device's KeyPackages and
//! history other devices asked for. It is sent on the next run. A message
//! that waits because its conversation's sending is held (12.7), as while
//! a new device's key check waits up to 2 hours for its key file, is not
//! a failure: `send` and `send-file` say it is queued, and why, and exit
//! 0. `sync` stays for `--wait` seconds, to receive. Output is one record
//! per line, fields separated by tabs.
//!
//! The options `--connect-to`, `--trust`, `--ca`, `--resolve`, `--witness`
//! and `--short-waits` reach a development server such as `risala-dev`'s,
//! which prints them. `--ca`, `--resolve` and `--short-waits` weaken what
//! the client checks or hides, so each run that has them says so.
//!
//! The witness policy (4.5) is kept in the state directory, and changes
//! only with `risala witness set` or `clear`. `--witness` may set it while
//! the state directory has no identity yet, with `create`, `pair new` or
//! `recover`, so that setting up can be scripted; after that, a
//! `--witness` that differs from the saved policy is an error.
//!
//! Text from other people and servers is printed with its control
//! characters, bidi controls among them, shown as `\u{..}` (see `shown`).
//!
//! Exit codes: 0 done, 1 failed, 2 bad arguments.

mod shown;

use std::io::{BufRead as _, Write as _};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{Args, Parser, Subcommand};
use librisala::client::conversations::{ConversationKind, ConversationState, ConversationSummary};
use librisala::client::identity::PairingIdentity;
use librisala::client::types::{AccountKind, ConversationId, MessageId, SendingHold, Unsettled};
use librisala::client::{ConnectionState, identity::KeyFetcherHttps};
use librisala::conn::Slot;
use librisala::keyfetch::{CertificateDer, FetchOptions, KeyFetcher, Roots, StaticResolver};
use librisala::keys::FileKeyStore;
use librisala::proto::names::Identity;
use librisala::store::{AccountId, DatabaseKey, Store, StoreError};
use librisala::{Client, ClientOptions, Event};
use rustls::pki_types::pem::PemObject as _;

use crate::shown::{Shown, shown};

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
    after_help = "Conversations: a number from `list`, a uid for the direct conversation \
                  with that identity, or #name for a room.\n\n\
                  Exit codes: 0 done, 1 failed, 2 bad arguments."
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
    /// logs, files), instead of the system's. Repeatable. For development:
    /// each run warns.
    #[arg(long, global = true, value_name = "PEM")]
    ca: Vec<PathBuf>,
    /// Reach `NAME` at `ADDR` for HTTPS, instead of resolving it; also
    /// allows private addresses. Repeatable. For development: each run
    /// warns.
    #[arg(long, global = true, value_name = "NAME=ADDR")]
    resolve: Vec<String>,
    /// A witness's verifier key for the witness policy (4.5). Repeatable.
    /// Saved with `create`, `pair new` or `recover` while the state
    /// directory has no identity; otherwise it must be the saved policy,
    /// which `risala witness set` changes.
    #[arg(long, global = true, value_name = "VKEY")]
    witness: Vec<String>,
    /// How many of the `--witness` witnesses must cosign; more than half by
    /// default.
    #[arg(long, global = true, value_name = "K", requires = "witness")]
    witness_k: Option<usize>,
    /// Cut the spec's random waits before following, committing and
    /// sending Welcomes (7.4, 7.2, 12.8) from up to 10 minutes to a
    /// second. For development: it lets the server tie actions together
    /// by their timing, and each run warns.
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
    /// List conversations, from the cache: number, kind, name, unread, and
    /// state: active, joining, leaving, lost or left (6.1, 7.5).
    List,
    /// Start the direct conversation with an identity, or find it (5.1).
    /// Prints its number.
    Direct { uid: String },
    /// The witness policy (4.5): the witnesses that must cosign a key
    /// log's checkpoint for its records to be accepted.
    #[command(subcommand)]
    Witness(WitnessCommand),
    /// Private rooms (6.1).
    #[command(subcommand)]
    Room(RoomCommand),
    /// Public rooms (6.1).
    #[command(subcommand)]
    Public(PublicCommand),
    /// Invitations back into conversations this device left for good, as
    /// one it could no longer follow (6.1). They are held, not joined,
    /// until you accept or decline them, and expire after the server's
    /// retention period.
    #[command(subcommand)]
    Invitation(InvitationCommand),
    /// Set the display name shown in every group (8.2): a commit in each.
    Name { name: String },
    /// Leave a conversation (6.1): a number, a uid or #room. A public room
    /// being joined, or a conversation this device can no longer follow,
    /// is given up too.
    Leave { conversation: String },
    /// Send a message. Prints its id.
    ///
    /// Held is not failed: if the conversation's sending is held (12.7),
    /// as while a new device's key check waits for its key file, the
    /// message stays queued, `send` says why on standard error, and exits
    /// 0. It goes out on a later run once the hold ends.
    Send {
        /// A conversation's number; a uid, for the direct conversation with
        /// that identity, started if there is none; or #name, for a room.
        conversation: String,
        /// The text; the words are joined with spaces.
        #[arg(required = true)]
        text: Vec<String>,
    },
    /// Print a conversation's messages from the cache: id, time, sender,
    /// flags and text.
    Read {
        /// A number, a uid or #room.
        conversation: String,
        /// How many of the newest.
        #[arg(short = 'n', long, default_value_t = 50)]
        count: usize,
        /// Connect and receive for `--wait` seconds first.
        #[arg(long)]
        sync: bool,
    },
    /// Send a file (5.6, 12.11). Prints the message's id.
    ///
    /// A message held by its conversation (12.7) is queued, not failed, as
    /// with `send`.
    SendFile {
        /// A number, a uid (started if there is none) or #room.
        conversation: String,
        path: PathBuf,
        /// A caption.
        #[arg(long)]
        caption: Option<String>,
    },
    /// Fetch a message's file, check it, and print where it was saved.
    Fetch {
        /// A number, a uid or #room.
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
    /// the identity to accept it; prints the identity and its devices,
    /// and joins it once you confirm on standard input (4.8, step 5).
    New {
        server: String,
        label: String,
        /// Join without asking: you have checked the identity elsewhere.
        #[arg(long)]
        yes: bool,
    },
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
    /// Create a private room. Prints its number; it is also `#<name>`.
    Create { name: String },
    /// Invite an identity (6.1, 6.3).
    Invite {
        /// The room's number or #name.
        room: String,
        uid: String,
    },
    /// Remove an identity, and ban it with `--ban` (6.4).
    Remove {
        /// The room's number or #name.
        room: String,
        uid: String,
        #[arg(long)]
        ban: bool,
    },
    /// The room's members: uid, role, devices, display name.
    Members {
        /// The room's number or #name.
        room: String,
    },
}

#[derive(Subcommand)]
enum WitnessCommand {
    /// Print the policy: k, how many witnesses, and whether it is saved or
    /// the default; then each witness's verifier key.
    Show,
    /// Save a policy of these witnesses' verifier keys (4.5).
    Set {
        #[arg(required = true, value_name = "VKEY")]
        witnesses: Vec<String>,
        /// How many must cosign; more than half by default.
        #[arg(short, long)]
        k: Option<usize>,
    },
    /// Forget the saved policy, for the default list (4.10).
    Clear,
}

#[derive(Subcommand)]
enum InvitationCommand {
    /// List the invitations held: id, conversation number, and who sent
    /// it.
    List,
    /// Accept an invitation, by its id, and join. Prints the
    /// conversation's number.
    Accept { id: i64 },
    /// Decline an invitation, by its id: it is forgotten.
    Decline { id: i64 },
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
            // Errors can carry the server's text (11) or a peer's names.
            eprintln!("risala: {}", Shown(&e.why));
            ExitCode::from(e.code)
        }
    }
}

/// Why a run failed, and its exit code: 1 failed, 2 bad arguments.
#[derive(Debug)]
struct Fail {
    code: u8,
    why: String,
}

impl From<String> for Fail {
    fn from(why: String) -> Fail {
        Fail { code: 1, why }
    }
}

/// Bad arguments: exit code 2.
fn usage(why: impl Into<String>) -> Fail {
    Fail {
        code: 2,
        why: why.into(),
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
    Ok(client)
}

/// The start of `risala-dev`'s witness's verifier key (4.5): its name and
/// key id, which name the key in a signed note. The key comes from a fixed
/// seed, so anyone can cosign as it. Kept here so that `risala` need not
/// depend on risala-dev; a test checks that they agree.
const DEV_WITNESS: &str = "chat.test/risala-witness+5404e4c4+";

/// Warns of the options that weaken what this run checks or hides.
fn warn_dev_options(dev: &Dev) {
    if !dev.ca.is_empty() {
        eprintln!(
            "risala: warning: --ca: HTTPS is checked against the given CAs, not the \
             system's; for development only"
        );
    }
    if !dev.resolve.is_empty() {
        eprintln!(
            "risala: warning: --resolve: names are reached at the given addresses, \
             private ones too; for development only"
        );
    }
    if dev.short_waits {
        eprintln!(
            "risala: warning: --short-waits: the random waits are cut to a second, which \
             lets the server tie your actions together by their timing; for development only"
        );
    }
}

/// Warns if the witness policy names risala-dev's witness.
fn warn_dev_witness(client: &Client) {
    if client
        .witness_policy()
        .is_ok_and(|(list, _)| list.iter().any(|v| v.starts_with(DEV_WITNESS)))
    {
        eprintln!(
            "risala: warning: the witness policy names risala-dev's witness, whose key \
             comes from a fixed seed: anyone can cosign as it. For development only; \
             `risala witness clear` forgets it"
        );
    }
}

/// k by default: more than half the witnesses (4.5).
fn default_k(witnesses: &[String]) -> usize {
    witnesses.len() / 2 + 1
}

/// Whether two policies name the same witnesses, in any order, with the
/// same k.
fn same_policy(a: &[String], a_k: usize, b: &[String], b_k: usize) -> bool {
    let sorted = |list: &[String]| {
        let mut list = list.to_vec();
        list.sort();
        list.dedup();
        list
    };
    a_k == b_k && sorted(a) == sorted(b)
}

/// Whether the policy is the default one: none saved (4.10).
fn is_default_policy(list: &[String], k: usize) -> bool {
    let (default, default_k) = librisala::sync::keylog::DEFAULT_WITNESSES;
    k == default_k && list.iter().map(String::as_str).eq(default.iter().copied())
}

/// `--witness`: the saved witness policy, or the one to save while the
/// state directory has no identity yet, with `create`, `pair new` or
/// `recover`. Otherwise only `risala witness set` changes the policy, so
/// that an option left in a script cannot replace it unseen.
fn witness_option(client: &Client, dev: &Dev, command: &Command) -> Result<(), Fail> {
    if dev.witness.is_empty() {
        return Ok(());
    }
    if matches!(command, Command::Witness(_)) {
        return Err(usage(
            "--witness: give the witnesses to `risala witness set` instead",
        ));
    }
    let k = dev.witness_k.unwrap_or_else(|| default_k(&dev.witness));
    let (saved, saved_k) = client.witness_policy().map_err(err)?;
    if same_policy(&saved, saved_k, &dev.witness, k) {
        return Ok(());
    }
    let setting_up = matches!(
        command,
        Command::Create { .. } | Command::Recover { .. } | Command::Pair(Pair::New { .. })
    );
    if !is_default_policy(&saved, saved_k) {
        return Err(usage(
            "--witness differs from the witness policy saved in the state directory: \
             see it with `risala witness show`, and change it with `risala witness set`",
        ));
    }
    if !setting_up || !client.accounts().map_err(err)?.is_empty() {
        return Err(usage(
            "--witness sets the witness policy only with create, pair new or recover, \
             on a state directory with no identity: use `risala witness set`",
        ));
    }
    client.set_witness_policy(&dev.witness, k).map_err(err)?;
    Ok(())
}

struct Ctx {
    client: Client,
    account: Option<String>,
    wait: Duration,
}

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

async fn run(cli: Cli) -> Result<(), Fail> {
    warn_dev_options(&cli.dev);
    let state = state_dir(cli.state)?;
    let client = open(&state, &cli.dev)?;
    witness_option(&client, &cli.dev, &cli.command)?;
    // `witness set` and `clear` say so for the policy they leave.
    if !matches!(
        cli.command,
        Command::Witness(WitnessCommand::Set { .. } | WitnessCommand::Clear)
    ) {
        warn_dev_witness(&client);
    }
    let ctx = Ctx {
        client,
        account: cli.account,
        wait: Duration::from_secs(cli.wait),
    };
    let result = command(&ctx, cli.command).await;
    for a in ctx.client.accounts().unwrap_or_default() {
        let _ = ctx.client.disconnect(a.id).await;
    }
    Ok(result?)
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

    /// Stays connected at least `min`, and then until what was queued has
    /// reached the server, for at most `--wait`; fails if it has not.
    async fn settle(&self, account: AccountId, min: Duration) -> Res {
        self.settle_or_held(account, min, None).await
    }

    /// As [`settle`](Self::settle), after queuing a message in `conv`
    /// (`send`, `send-file`): messages that wait only because their
    /// conversation's sending is held (12.7) are not a failure, since they
    /// go once the hold ends. Says so on standard error, and why.
    async fn settle_message(&self, account: AccountId, conv: ConversationId) -> Res {
        self.settle_or_held(account, Duration::ZERO, Some(conv))
            .await
    }

    async fn settle_or_held(
        &self,
        account: AccountId,
        min: Duration,
        message_in: Option<ConversationId>,
    ) -> Res {
        let start = Instant::now();
        let max = self.wait.max(min);
        loop {
            let elapsed = start.elapsed();
            if elapsed >= min && self.client.is_settled(account).unwrap_or(false) {
                return Ok(());
            }
            if elapsed >= max {
                let left = self.client.unsettled(account).map_err(err)?;
                if left.is_empty() {
                    return Ok(());
                }
                if let Some(conv) = message_in {
                    let hold = self.client.sending_hold(conv).map_err(err)?;
                    if let Some(note) = held_note(&left, hold.as_ref()) {
                        eprintln!("risala: {note}");
                        return Ok(());
                    }
                }
                return Err(format!(
                    "not everything reached the server within {} seconds: {}; \
                     it is sent on the next run, such as `risala sync`",
                    max.as_secs(),
                    unsettled_text(&left)
                ));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// A conversation in the cache, by number, uid or `#room` (see the
    /// module docs).
    fn conversation(&self, account: AccountId, name: &str) -> Res<ConversationId> {
        self.conversation_among(account, name, Among::InGroup)
    }

    /// As [`conversation`](Self::conversation), among the conversations
    /// that `among` says.
    fn conversation_among(
        &self,
        account: AccountId,
        name: &str,
        among: Among,
    ) -> Res<ConversationId> {
        let named = named(name)?;
        let own = self.client.account(account).map_err(err)?.uid;
        let all = self.client.conversations(account).map_err(err)?;
        let entries: Vec<Entry> = all.iter().map(Entry::from).collect();
        match find(&entries, own.as_str(), &named, among)? {
            Some(n) => Ok(all
                .iter()
                .find(|c| c.id.get() == n)
                .map(|c| c.id)
                .ok_or("the conversation is gone")?),
            None => Err(format!(
                "no direct conversation with {name}: start it with `risala direct {name}`"
            )),
        }
    }

    /// A room, by number or `#name`: never a uid.
    fn room(&self, account: AccountId, name: &str) -> Res<ConversationId> {
        if let Named::Uid(uid) = named(name)? {
            return Err(format!(
                "{uid} is an identity: name the room by its number or #name"
            ));
        }
        self.conversation(account, name)
    }

    /// A conversation for a command that starts a uid's direct
    /// conversation if there is none (5.1): `None` for a uid, which
    /// [`start_direct`](Self::start_direct) finds once online.
    fn conversation_or_uid(&self, account: AccountId, name: &str) -> Res<Option<ConversationId>> {
        match named(name)? {
            Named::Uid(_) => Ok(None),
            _ => self.conversation(account, name).map(Some),
        }
    }

    /// The direct conversation with `uid`, started if there is none (5.1),
    /// or the conversation with yourself for the own uid.
    async fn start_direct(&self, account: AccountId, uid: &str) -> Res<ConversationId> {
        let uid = match named(uid)? {
            Named::Uid(uid) => uid,
            _ => return Err(format!("{uid}: not a uid")),
        };
        let own = self.client.account(account).map_err(err)?.uid;
        if own.as_str() == uid {
            self.client.with_yourself(account).await.map_err(err)
        } else {
            self.client.direct(account, &uid).await.map_err(err)
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

/// How a command names a conversation.
#[derive(Debug, PartialEq, Eq)]
enum Named {
    /// Its number, from `list`.
    Number(i64),
    /// An identity: only ever the direct conversation with it.
    Uid(String),
    /// A room: `#` and a private room's name, or a public room's address.
    Room(String),
    /// None of these.
    Other(String),
}

fn named(name: &str) -> Res<Named> {
    if let Ok(n) = name.parse::<i64>() {
        return Ok(Named::Number(n));
    }
    if name.starts_with('#') {
        return Ok(Named::Room(name.to_owned()));
    }
    if name.contains('@') {
        let uid: Identity = name.parse().map_err(|_| format!("{name}: not a uid"))?;
        return Ok(Named::Uid(uid.to_string()));
    }
    Ok(Named::Other(name.to_owned()))
}

/// What [`find`] needs of a conversation.
#[derive(Debug, Clone)]
struct Entry {
    number: i64,
    kind: ConversationKind,
    /// A room's name, or the peer's uid for a direct conversation.
    name: String,
    /// A public room's address.
    room: Option<String>,
    state: ConversationState,
}

impl From<&ConversationSummary> for Entry {
    fn from(c: &ConversationSummary) -> Entry {
        Entry {
            number: c.id.get(),
            kind: c.kind,
            name: c.name.clone(),
            room: c.room.as_ref().map(ToString::to_string),
            state: c.state,
        }
    }
}

/// Which conversations a uid or a room's name may find; a number finds
/// any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Among {
    /// Those the device is in, leaving them or not.
    InGroup,
    /// Any it has not left: a public room being joined, and one it can no
    /// longer follow, too, which `leave` gives up (6.1, 7.5).
    NotLeft,
}

impl Among {
    fn has(self, state: ConversationState) -> bool {
        match self {
            Among::InGroup => state.in_group(),
            Among::NotLeft => state != ConversationState::Left,
        }
    }
}

/// The number of the conversation `named` names among `all`, for the
/// account whose uid is `own`; `None` for a uid with no direct
/// conversation yet.
///
/// A uid means only the direct conversation with that identity, or the
/// conversation with yourself for `own`, whatever the rooms are called;
/// the newest if there are several, as after a peer left one (6.1). A
/// room is `#` and a private room's name, or a public room's address.
/// Either finds only the conversations that `among` says.
fn find(all: &[Entry], own: &str, named: &Named, among: Among) -> Res<Option<i64>> {
    let is_room = |c: &Entry, room: &str| {
        among.has(c.state)
            && match c.kind {
                ConversationKind::PrivateRoom => room.strip_prefix('#') == Some(c.name.as_str()),
                ConversationKind::PublicRoom => c.room.as_deref() == Some(room),
                ConversationKind::Direct | ConversationKind::WithYourself => false,
            }
    };
    match named {
        Named::Number(n) => match all.iter().find(|c| c.number == *n) {
            Some(c) => Ok(Some(c.number)),
            None => Err(format!("no conversation {n}")),
        },
        Named::Uid(uid) => Ok(all
            .iter()
            .filter(|c| {
                among.has(c.state)
                    && if own == uid {
                        c.kind == ConversationKind::WithYourself
                    } else {
                        c.kind == ConversationKind::Direct && c.name == *uid
                    }
            })
            .map(|c| c.number)
            .max()),
        Named::Room(room) => {
            let found: Vec<i64> = all
                .iter()
                .filter(|c| is_room(c, room))
                .map(|c| c.number)
                .collect();
            match found.as_slice() {
                [one] => Ok(Some(*one)),
                [] => Err(format!("no room {room}")),
                _ => Err(format!(
                    "several rooms are called {room}: use a number from `risala list`"
                )),
            }
        }
        Named::Other(word) => {
            let room = format!("#{word}");
            Err(if all.iter().any(|c| is_room(c, &room)) {
                format!("{word}: a room is named with #: {room}")
            } else {
                format!("{word}: name a conversation by its number, a uid, or #name for a room")
            })
        }
    }
}

/// What `send` says when all that is left at the end of its wait is
/// messages held by their conversation's sending (12.7): queued, not
/// failed. `hold` is why the conversation just sent to holds them, if it
/// does. `None` if anything else is left, which is a failure.
fn held_note(left: &Unsettled, hold: Option<&SendingHold>) -> Option<String> {
    let only_held = left.held > 0
        && left.held == left.outbox
        && Unsettled {
            outbox: 0,
            held: 0,
            ..left.clone()
        }
        .is_empty();
    if !only_held {
        return None;
    }
    let later = "it goes out on a later run once the hold ends, such as `risala sync`";
    Some(match hold {
        Some(SendingHold::KeyCheck { uid }) => format!(
            "the message is queued: sending in this conversation is held until a device \
             of {} passes its key check (12.7), for at most 2 hours; {later}",
            Shown(uid.as_str())
        ),
        Some(SendingHold::Repair { uid }) => format!(
            "the message is queued: sending in this conversation is held until a device \
             of {}, which failed its key check, is removed (12.7); {later}",
            Shown(uid.as_str())
        ),
        None => format!(
            "{} queued in conversations whose sending is held (12.7); {later}",
            if left.held == 1 {
                "1 message is".to_owned()
            } else {
                format!("{} messages are", left.held)
            }
        ),
    })
}

/// What has not reached the server yet, for the error.
fn unsettled_text(left: &Unsettled) -> String {
    let count =
        |n: usize, one: &str, many: &str| format!("{n} {}", if n == 1 { one } else { many });
    let mut parts = Vec::new();
    if left.outbox > 0 {
        let mut outbox = count(left.outbox, "message or commit", "messages or commits");
        if left.held > 0 {
            outbox.push_str(&format!(
                " ({} held: their conversation's sending is held, 12.7)",
                left.held
            ));
        }
        parts.push(outbox);
    }
    if left.welcomes > 0 {
        parts.push(count(left.welcomes, "Welcome", "Welcomes"));
    }
    if left.records {
        parts.push("the identity's new records (KEYS PUT)".to_owned());
    }
    if left.key_packages {
        parts.push("this device's KeyPackages".to_owned());
    }
    if left.transfers > 0 {
        parts.push(count(
            left.transfers,
            "history transfer another device asked for",
            "history transfers other devices asked for",
        ));
    }
    parts.join(", ")
}

fn state(s: ConversationState) -> &'static str {
    match s {
        ConversationState::Active => "active",
        ConversationState::Joining => "joining",
        ConversationState::Leaving => "leaving",
        ConversationState::Lost => "lost",
        ConversationState::Left => "left",
    }
}

/// One line of `list`: number, kind, name, unread, state, and `stopped`
/// if sending is stopped for someone in it (12.14). The name comes from
/// the group, so it is shown escaped.
fn conversation_line(
    number: i64,
    k: ConversationKind,
    name: &str,
    unread: u64,
    s: ConversationState,
    stopped: bool,
) -> String {
    let stopped = if stopped { "\tstopped" } else { "" };
    format!(
        "{number}\t{}\t{}\t{unread}\t{}{stopped}",
        kind(k),
        Shown(name),
        state(s)
    )
}

fn print_conversations(client: &Client, account: AccountId) -> Res {
    let mut out = std::io::stdout().lock();
    for c in client.conversations(account).map_err(err)? {
        let _ = writeln!(
            out,
            "{}",
            conversation_line(
                c.id.get(),
                c.kind,
                &c.name,
                c.unread,
                c.state,
                c.sending_stopped
            )
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
            println!("{}", shown(&new.uid));
            println!("{}", new.recovery_key.as_str());
            let _ = std::io::stdout().flush();
            ctx.until_accepted(new.uid.as_str()).await?;
            ctx.online(new.account).await?;
            // KeyPackages and the conversation with yourself (12.5, 5.1).
            ctx.settle(new.account, Duration::from_secs(3)).await?;
        }
        Command::Pair(Pair::New { server, label, yes }) => {
            let offer = c.start_pairing(&server, &label).await.map_err(err)?;
            println!("{}", offer.qr);
            let _ = std::io::stdout().flush();
            // 4.8, step 5: whoever saw the QR code can answer it with an
            // identity of their own, so the user confirms the identity.
            let identity = c.finish_pairing().await.map_err(err)?;
            let _ = show_pairing(&mut std::io::stdout().lock(), &identity);
            if !yes {
                eprint!("{}", pairing_question(&identity));
                let _ = std::io::stderr().flush();
                let mut answer = String::new();
                let _ = std::io::stdin().lock().read_line(&mut answer);
                if !matches!(answer.trim(), "y" | "Y" | "yes") {
                    c.decline_pairing().map_err(err)?;
                    return Err("declined".into());
                }
            }
            let own = c.accept_pairing().await.map_err(err)?;
            ctx.until_accepted(own.uid.as_str()).await?;
            let account = c
                .accounts()
                .map_err(err)?
                .into_iter()
                .find(|a| a.uid == own.uid)
                .ok_or("no account for the identity")?
                .id;
            ctx.online(account).await?;
            ctx.settle(account, Duration::from_secs(3)).await?;
        }
        Command::Pair(Pair::Accept { qr, no_history }) => {
            let account = ctx.account()?;
            let uid = c.account(account).map_err(err)?.uid;
            ctx.online(account).await?;
            let request = c.scan_pairing(uid.as_str(), &qr).await.map_err(err)?;
            println!("{}\t{}", Shown(&request.short), Shown(&request.label));
            c.confirm_pairing(uid.as_str(), !no_history)
                .await
                .map_err(err)?;
            ctx.settle(account, Duration::from_secs(1)).await?;
        }
        Command::Recover { server, uid, label } => {
            let key = Ctx::recovery_key()?;
            let own = c.recover(&server, &uid, &key, &label).await.map_err(err)?;
            println!("{}\t{}", shown(&own.uid), own.device);
            ctx.until_accepted(own.uid.as_str()).await?;
            let account = c
                .accounts()
                .map_err(err)?
                .into_iter()
                .find(|a| a.uid == own.uid)
                .ok_or("no account for the identity")?
                .id;
            ctx.online(account).await?;
            ctx.settle(account, Duration::from_secs(3)).await?;
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
            ctx.settle(account, Duration::from_secs(3)).await?;
        }
        Command::Whoami => {
            for own in c.own_identities().map_err(err)? {
                println!("{}\t{}", shown(&own.uid), own.device);
                for d in c.identity_devices(own.uid.as_str()).map_err(err)? {
                    print_device(&d);
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
            // `KeysStatus::Missing` carries text from the fetch.
            println!(
                "{}\t{}\t{}\t{}",
                shown(&contact.uid),
                shown(format_args!("{:?}", contact.keys)),
                if contact.verified {
                    "verified"
                } else {
                    "unverified"
                },
                match contact.stopped {
                    Some(r) => shown(format_args!("stopped: {r:?}")),
                    None => "sending".into(),
                }
            );
            for d in &contact.devices {
                print_device(d);
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
            let conv = ctx.start_direct(account, &uid).await?;
            println!("{}", conv);
            ctx.settle(account, Duration::from_secs(1)).await?;
        }
        Command::Witness(WitnessCommand::Show) => {
            let (list, k) = c.witness_policy().map_err(err)?;
            let saved = if is_default_policy(&list, k) {
                "default"
            } else {
                "saved"
            };
            println!("{k}\t{}\t{saved}", list.len());
            for vkey in &list {
                println!("{}", shown(vkey));
            }
        }
        Command::Witness(WitnessCommand::Set { witnesses, k }) => {
            let k = k.unwrap_or_else(|| default_k(&witnesses));
            c.set_witness_policy(&witnesses, k).map_err(err)?;
            warn_dev_witness(c);
        }
        Command::Witness(WitnessCommand::Clear) => c.clear_witness_policy().map_err(err)?,
        Command::Room(RoomCommand::Create { name }) => {
            let account = ctx.account()?;
            ctx.online(account).await?;
            let conv = c.create_private_room(account, &name).await.map_err(err)?;
            println!("{}", conv);
            ctx.settle(account, Duration::from_secs(1)).await?;
        }
        Command::Room(RoomCommand::Invite { room, uid }) => {
            let account = ctx.account()?;
            let conv = ctx.room(account, &room)?;
            ctx.online(account).await?;
            c.invite(conv, &uid).await.map_err(err)?;
            ctx.settle(account, Duration::from_secs(1)).await?;
        }
        Command::Room(RoomCommand::Remove { room, uid, ban }) => {
            let account = ctx.account()?;
            let conv = ctx.room(account, &room)?;
            ctx.online(account).await?;
            c.remove_member(conv, &uid, ban).await.map_err(err)?;
            ctx.settle(account, Duration::from_secs(1)).await?;
        }
        Command::Room(RoomCommand::Members { room }) => {
            let account = ctx.account()?;
            let conv = ctx.room(account, &room)?;
            for m in c.members(conv).map_err(err)? {
                println!(
                    "{}\t{}\t{}\t{}",
                    shown(&m.uid),
                    shown(format_args!("{:?}", m.role)),
                    m.devices,
                    Shown(m.display_name.as_deref().unwrap_or_default())
                );
            }
        }
        Command::Public(PublicCommand::List) => {
            let account = ctx.account()?;
            ctx.online(account).await?;
            for r in c.list_public_rooms(account, None).await.map_err(err)? {
                println!("{}\t{}\t{}", shown(&r.room), r.members, Shown(&r.topic));
            }
        }
        Command::Public(PublicCommand::Create { room }) => {
            let account = ctx.account()?;
            ctx.online(account).await?;
            let conv = c.create_public_room(account, &room).await.map_err(err)?;
            println!("{}", conv);
            ctx.settle(account, Duration::from_secs(1)).await?;
        }
        Command::Public(PublicCommand::Join { room }) => {
            let account = ctx.account()?;
            ctx.online(account).await?;
            let conv = c.join_public_room(account, &room).await.map_err(err)?;
            println!("{}", conv);
            ctx.settle(account, Duration::from_secs(1)).await?;
        }
        Command::Invitation(InvitationCommand::List) => {
            for i in c.invitations(ctx.account()?).map_err(err)? {
                println!("{}\t{}\t{}", i.id, i.conversation.get(), shown(&i.by));
            }
        }
        Command::Invitation(InvitationCommand::Accept { id }) => {
            let account = ctx.account()?;
            ctx.online(account).await?;
            let conv = c.accept_invitation(account, id).await.map_err(err)?;
            println!("{}", conv);
            ctx.settle(account, Duration::from_secs(1)).await?;
        }
        Command::Invitation(InvitationCommand::Decline { id }) => {
            c.decline_invitation(ctx.account()?, id).map_err(err)?;
        }
        Command::Name { name } => {
            let account = ctx.account()?;
            ctx.online(account).await?;
            c.set_display_name(account, &name).await.map_err(err)?;
            ctx.settle(account, Duration::from_secs(1)).await?;
        }
        Command::Leave { conversation } => {
            let account = ctx.account()?;
            // 6.1, 7.5: a public room being joined, or a conversation the
            // device can no longer follow, is left too.
            let conv = ctx.conversation_among(account, &conversation, Among::NotLeft)?;
            ctx.online(account).await?;
            c.leave(conv).await.map_err(err)?;
            ctx.settle(account, Duration::from_secs(1)).await?;
        }
        Command::Send { conversation, text } => {
            let account = ctx.account()?;
            let conv = ctx.conversation_or_uid(account, &conversation)?;
            ctx.online(account).await?;
            let conv = match conv {
                Some(conv) => conv,
                None => ctx.start_direct(account, &conversation).await?,
            };
            let id = c
                .send_text(conv, &text.join(" "), None)
                .await
                .map_err(err)?;
            println!("{id}");
            ctx.settle_message(account, conv).await?;
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
                // The text stays escaped as on the wire (3.4), one line.
                let _ = writeln!(
                    out,
                    "{}\t{}\t{}\t{}\t{}",
                    m.id,
                    m.sent,
                    shown(&m.sender),
                    if flags.is_empty() {
                        "-".into()
                    } else {
                        flags.join(",")
                    },
                    Shown(m.text.as_deref().unwrap_or_default())
                );
            }
        }
        Command::SendFile {
            conversation,
            path,
            caption,
        } => {
            let account = ctx.account()?;
            let conv = ctx.conversation_or_uid(account, &conversation)?;
            ctx.online(account).await?;
            let conv = match conv {
                Some(conv) => conv,
                None => ctx.start_direct(account, &conversation).await?,
            };
            let id = c
                .send_file(conv, &path, None, caption.as_deref())
                .await
                .map_err(err)?;
            println!("{id}");
            ctx.settle_message(account, conv).await?;
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
                Some(path) => println!("{}\t{}", shown(path.display()), info.size),
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
            ctx.settle(account, Duration::from_secs(1)).await?;
        }
    }
    Ok(())
}

/// One of an identity's devices, under its uid: short id, state, label.
fn print_device(d: &librisala::client::identity::Device) {
    println!(
        "\t{}\t{}\t{}",
        Shown(&d.short),
        device_state(d),
        Shown(&d.label)
    );
}

/// Prints the identity a new device is about to take, and its devices
/// (4.8, step 5). Their labels are the answering identity's, which may not
/// be the user's: whoever saw the QR code can answer.
fn show_pairing(out: &mut impl std::io::Write, identity: &PairingIdentity) -> std::io::Result<()> {
    writeln!(out, "{}", shown(&identity.uid))?;
    for d in &identity.devices {
        let this = if d.this_device { "\tthis" } else { "" };
        writeln!(out, "\t{}\t{}{this}", Shown(&d.short), Shown(&d.label))?;
    }
    out.flush()
}

/// The question that asks the user to confirm the identity (4.8, step 5),
/// repeating its uid so that nothing printed before can stand in for it.
fn pairing_question(identity: &PairingIdentity) -> String {
    format!("join {}? [y/N] ", shown(&identity.uid))
}

fn device_state(d: &librisala::client::identity::Device) -> &'static str {
    match (d.removed, d.accepted, d.this_device) {
        (true, _, _) => "removed",
        (false, true, true) => "current,this",
        (false, true, false) => "current",
        (false, false, _) => "pending",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use librisala::client::identity::PairingDevice;
    use librisala::client::types::DeviceId;

    fn identity(labels: &[&str]) -> PairingIdentity {
        PairingIdentity {
            uid: "mallory@example.org".parse().unwrap(),
            devices: labels
                .iter()
                .enumerate()
                .map(|(i, label)| PairingDevice {
                    id: DeviceId([i as u8; 48]),
                    short: format!("abcdefg{i}"),
                    label: (*label).to_owned(),
                    this_device: i == 0,
                })
                .collect(),
        }
    }

    /// A label that moves the cursor up, clears the uid's line and writes
    /// another uid over it (4.8, step 5) is printed escaped.
    #[test]
    fn pairing_labels_are_printed_escaped() {
        let evil = "x\u{1b}[2A\u{1b}[2K\ralice@example.org\u{9b}K\u{202e}";
        let shown = identity(&["phone", evil]);
        let mut out = Vec::new();
        show_pairing(&mut out, &shown).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert_eq!(
            out,
            "mallory@example.org\n\tabcdefg0\tphone\tthis\n\tabcdefg1\t\
             x\\u{1b}[2A\\u{1b}[2K\\u{d}alice@example.org\\u{9b}K\\u{202e}\n"
        );
        assert!(!out.contains(['\u{1b}', '\r', '\u{9b}', '\u{202e}']));
        assert_eq!(pairing_question(&shown), "join mallory@example.org? [y/N] ");
    }

    /// `list` shows each conversation's state, after the unread count,
    /// and the name from the group escaped (6.1, 7.5).
    #[test]
    fn list_lines_show_the_state_and_escape_the_name() {
        assert_eq!(
            conversation_line(
                3,
                ConversationKind::PrivateRoom,
                "team\u{1b}[2K\tx",
                2,
                ConversationState::Active,
                false
            ),
            "3\troom\tteam\\u{1b}[2K\\u{9}x\t2\tactive"
        );
        assert_eq!(
            conversation_line(
                4,
                ConversationKind::Direct,
                "bob@example.org",
                0,
                ConversationState::Leaving,
                true
            ),
            "4\tdirect\tbob@example.org\t0\tleaving\tstopped"
        );
        for (s, word) in [
            (ConversationState::Joining, "joining"),
            (ConversationState::Lost, "lost"),
            (ConversationState::Left, "left"),
        ] {
            assert_eq!(
                conversation_line(5, ConversationKind::PublicRoom, "#general", 0, s, false),
                format!("5\tpublic\t#general\t0\t{word}")
            );
        }
    }

    fn entry(number: i64, kind: ConversationKind, name: &str, room: Option<&str>) -> Entry {
        Entry {
            number,
            kind,
            name: name.to_owned(),
            room: room.map(str::to_owned),
            state: ConversationState::Active,
        }
    }

    fn found(all: &[Entry], name: &str) -> Res<Option<i64>> {
        find(all, "alice@example.org", &named(name)?, Among::InGroup)
    }

    /// A private room named like a uid is never what the uid names: the
    /// uid means only the direct conversation with that identity.
    #[test]
    fn a_uid_names_only_the_direct_conversation() {
        let mut all = vec![
            entry(1, ConversationKind::WithYourself, "", None),
            entry(2, ConversationKind::PrivateRoom, "bob@example.org", None),
            entry(
                3,
                ConversationKind::PublicRoom,
                "bob@example.org",
                Some("#garden"),
            ),
            entry(4, ConversationKind::PrivateRoom, "garden", None),
        ];
        assert_eq!(found(&all, "bob@example.org"), Ok(None));
        assert_eq!(found(&all, "#bob@example.org"), Ok(Some(2)));
        all.push(entry(5, ConversationKind::Direct, "bob@example.org", None));
        assert_eq!(found(&all, "bob@example.org"), Ok(Some(5)));
        // The newest of several, as after the peer left one; one the device
        // left does not count.
        all.push(entry(7, ConversationKind::Direct, "bob@example.org", None));
        assert_eq!(found(&all, "bob@example.org"), Ok(Some(7)));
        all.last_mut().unwrap().state = ConversationState::Left;
        assert_eq!(found(&all, "bob@example.org"), Ok(Some(5)));
        // A uid is written in its canonical form.
        assert_eq!(
            named("Bob@Example.org"),
            Ok(Named::Uid("bob@example.org".into()))
        );
        // The own uid: the conversation with yourself.
        assert_eq!(found(&all, "alice@example.org"), Ok(Some(1)));
        // Numbers name any conversation.
        assert_eq!(found(&all, "2"), Ok(Some(2)));
        assert!(found(&all, "9").is_err());
    }

    /// `leave` finds, by name, a public room being joined and a
    /// conversation the device can no longer follow, which it gives up
    /// (6.1, 7.5); other commands find neither, and none finds one left.
    #[test]
    fn leave_finds_joining_and_lost_conversations() {
        let mut all = vec![
            entry(3, ConversationKind::PublicRoom, "Plaza", Some("#plaza")),
            entry(5, ConversationKind::Direct, "bob@example.org", None),
            entry(6, ConversationKind::Direct, "carol@example.org", None),
        ];
        all[0].state = ConversationState::Joining;
        all[1].state = ConversationState::Lost;
        all[2].state = ConversationState::Left;
        let leaving = |name: &str| {
            find(
                &all,
                "alice@example.org",
                &named(name).unwrap(),
                Among::NotLeft,
            )
        };
        assert_eq!(leaving("#plaza"), Ok(Some(3)));
        assert_eq!(leaving("bob@example.org"), Ok(Some(5)));
        assert_eq!(leaving("carol@example.org"), Ok(None));
        assert!(found(&all, "#plaza").is_err());
        assert_eq!(found(&all, "bob@example.org"), Ok(None));
    }

    /// Rooms are named `#name`, or by number; a bare name is refused, with
    /// a hint when a room has it.
    #[test]
    fn rooms_are_named_with_a_hash() {
        let all = vec![
            entry(3, ConversationKind::PublicRoom, "Plaza", Some("#plaza")),
            entry(4, ConversationKind::PrivateRoom, "garden", None),
            entry(5, ConversationKind::PrivateRoom, "twice", None),
            entry(6, ConversationKind::PrivateRoom, "twice", None),
            entry(8, ConversationKind::Direct, "garden@example.org", None),
        ];
        assert_eq!(found(&all, "#garden"), Ok(Some(4)));
        assert_eq!(found(&all, "#plaza"), Ok(Some(3)));
        // A public room by its address, not its group name.
        assert!(found(&all, "#Plaza").is_err());
        assert!(found(&all, "#twice").unwrap_err().contains("several"));
        assert!(found(&all, "#nowhere").is_err());
        let bare = found(&all, "garden").unwrap_err();
        assert!(bare.contains("#garden"), "{bare}");
        assert!(found(&all, "nowhere").is_err());
        assert!(named("not@a@uid").is_err());
    }

    fn dev(witness: &[&str], k: Option<usize>) -> Dev {
        Dev {
            connect_to: None,
            trust: Vec::new(),
            ca: Vec::new(),
            resolve: Vec::new(),
            witness: witness.iter().map(|s| (*s).to_owned()).collect(),
            witness_k: k,
            short_waits: false,
        }
    }

    fn create() -> Command {
        Command::Create {
            server: "chat.test".into(),
            name: "alice".into(),
            label: "laptop".into(),
        }
    }

    /// `--witness` sets the policy only while setting up a state
    /// directory with no identity; afterwards it must match the saved one,
    /// and `risala witness set` changes it.
    #[test]
    fn witness_option_rules() {
        let a = risala_dev::witness_vkey();
        let client = Client::open_in_memory(ClientOptions::default()).unwrap();
        let none = dev(&[], None);
        let with_a = dev(&[&a], None);
        assert!(witness_option(&client, &none, &create()).is_ok());
        // Not while setting up: refused, and nothing is saved.
        let e = witness_option(&client, &with_a, &Command::Whoami).unwrap_err();
        assert_eq!(e.code, 2);
        assert!(e.why.contains("witness set"), "{}", e.why);
        let (list, k) = client.witness_policy().unwrap();
        assert!(is_default_policy(&list, k));
        // Never with the witness command itself.
        let e = witness_option(&client, &with_a, &Command::Witness(WitnessCommand::Show));
        assert_eq!(e.unwrap_err().code, 2);
        // Setting up: saved.
        witness_option(&client, &with_a, &create()).unwrap();
        assert_eq!(client.witness_policy().unwrap(), (vec![a.clone()], 1));
        // The same again, for any command: fine.
        witness_option(&client, &with_a, &Command::Whoami).unwrap();
        // Another k, or other witnesses: refused, even while setting up.
        let e = witness_option(&client, &dev(&[&a, "x"], None), &create()).unwrap_err();
        assert_eq!(e.code, 2);
        assert!(e.why.contains("differs"), "{}", e.why);
        assert_eq!(client.witness_policy().unwrap(), (vec![a.clone()], 1));
        // Once the state directory has an identity, a cleared policy is not
        // set again by an option.
        client.clear_witness_policy().unwrap();
        client
            .add_identity_account("chat.test", "alice@example.org")
            .unwrap();
        let e = witness_option(&client, &with_a, &create()).unwrap_err();
        assert!(e.why.contains("witness set"), "{}", e.why);
        assert!(same_policy(
            &[a.clone(), "b".into()],
            2,
            &["b".into(), a],
            2
        ));
    }

    /// `--witness-k` alone is a bad argument.
    #[test]
    fn witness_k_needs_witness() {
        let e = Cli::try_parse_from(["risala", "--witness-k", "1", "list"])
            .err()
            .expect("refused");
        assert_eq!(e.exit_code(), 2);
        assert!(
            Cli::try_parse_from(["risala", "--witness", "v", "--witness-k", "1", "list"]).is_ok()
        );
    }

    /// risala-dev's witness key is the one `risala` warns of.
    #[test]
    fn invitations_are_answered_by_id() {
        for args in [
            &["risala", "invitation", "list"][..],
            &["risala", "invitation", "accept", "3"],
            &["risala", "invitation", "decline", "3"],
        ] {
            assert!(Cli::try_parse_from(args).is_ok(), "{args:?}");
        }
        assert!(Cli::try_parse_from(["risala", "invitation", "accept", "bob"]).is_err());
        assert!(Cli::try_parse_from(["risala", "invitation", "decline"]).is_err());
    }

    #[test]
    fn dev_witness_is_risala_devs() {
        assert!(risala_dev::witness_vkey().starts_with(DEV_WITNESS));
    }

    /// A send that leaves only held messages is not a failure: it says
    /// they are queued, and why, with the uid printed safely. Anything else
    /// left still is (PLAN item 66).
    #[test]
    fn held_messages_are_queued_not_failed() {
        let uid: librisala::client::types::Uid = "bob@example.org".parse().unwrap();
        let held = Unsettled {
            outbox: 1,
            held: 1,
            ..Unsettled::default()
        };
        let check = SendingHold::KeyCheck { uid: uid.clone() };
        let note = held_note(&held, Some(&check)).unwrap();
        assert!(note.starts_with("the message is queued: "), "{note}");
        assert!(note.contains("a device of bob@example.org passes its key check"));
        assert!(note.contains("at most 2 hours"));
        let repair = SendingHold::Repair { uid };
        let note = held_note(&held, Some(&repair)).unwrap();
        assert!(note.contains("failed its key check, is removed"), "{note}");
        // Held elsewhere, from an earlier run: this message went out.
        let two = Unsettled {
            outbox: 2,
            held: 2,
            ..Unsettled::default()
        };
        let note = held_note(&two, None).unwrap();
        assert!(
            note.starts_with("2 messages are queued in conversations"),
            "{note}"
        );

        // Anything not held is still a failure.
        assert_eq!(held_note(&Unsettled::default(), None), None);
        let more = Unsettled {
            outbox: 2,
            held: 1,
            ..Unsettled::default()
        };
        assert_eq!(held_note(&more, Some(&check)), None);
        for other in [
            Unsettled {
                welcomes: 1,
                ..held.clone()
            },
            Unsettled {
                records: true,
                ..held.clone()
            },
            Unsettled {
                key_packages: true,
                ..held.clone()
            },
            Unsettled {
                transfers: 1,
                ..held.clone()
            },
        ] {
            assert_eq!(held_note(&other, Some(&check)), None, "{other:?}");
        }
    }

    #[test]
    fn unsettled_is_said() {
        let left = Unsettled {
            outbox: 2,
            held: 1,
            welcomes: 2,
            records: true,
            key_packages: true,
            transfers: 1,
        };
        assert_eq!(
            unsettled_text(&left),
            "2 messages or commits (1 held: their conversation's sending is held, 12.7), \
             2 Welcomes, the identity's new records (KEYS PUT), \
             this device's KeyPackages, 1 history transfer another device asked for"
        );
    }
}
