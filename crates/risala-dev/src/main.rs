//! `risala-dev`: a local risala server filled with development data, for
//! the apps and the CLI to run against.
//!
//! ```sh
//! risala-dev busy            # seed once, then serve
//! risala-dev busy --live     # and keep bots posting
//! risala-dev huge --reset    # start again from nothing
//! ```
//!
//! It runs `risala_server::testing`'s server with its state in `.dev/` at
//! the root of the repository: the database, the self-signed certificate,
//! and for clients `.dev/me.json` (where the server is, its fingerprint,
//! and the account) and `.dev/me.pem` (the account's device key). A run
//! whose state already holds the scenario serves it as it is, so an app's
//! cache stays valid.
//!
//! Scenarios are seeded through the protocol, as clients would, with the
//! server's clock set back in time and moved forward step by step, so
//! history has real dates. Then the clock follows the system clock.
//!
//! Development only: the server accepts any number of registrations and
//! room creations, and the keys come from a fixed seed.

mod actors;
mod corpus;
mod kick;
mod live;
mod plan;
mod rng;
mod seed;
#[cfg(test)]
mod tests;

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use risala_proto::time::Timestamp;
use risala_server::config::Limits;
use risala_server::testing::{TestServer, TestServerBuilder};

use plan::Scenario;

/// The port the development server listens on unless told otherwise:
/// one above risala's own (7472), so that it does not clash with a real
/// server on the same machine.
const DEFAULT_PORT: u16 = 7473;

/// Changes when what seeding makes changes, so that older state is seeded
/// again rather than served.
const STATE_VERSION: u32 = 1;

#[derive(Parser)]
#[command(
    name = "risala-dev",
    about = "A local risala server filled with development data",
    after_help = "State lives in .dev/ at the root of the repository. Clients sign in with \
                  .dev/me.json and .dev/me.pem."
)]
struct Cli {
    /// What the server holds.
    scenario: Scenario,
    /// After seeding, keep bots posting, editing, reacting and joining.
    #[arg(long)]
    live: bool,
    /// With --live, how many things the bots do per minute.
    #[arg(long, default_value_t = 20, value_name = "N")]
    rate: u32,
    /// Delete the state and seed again. Apps must then clear their cache.
    #[arg(long)]
    reset: bool,
    /// The address to listen on. 0.0.0.0 lets a phone on the network
    /// connect; give it the Mac's name with --hostname too.
    #[arg(long, default_value = "127.0.0.1", value_name = "ADDR")]
    listen: IpAddr,
    /// The port to listen on.
    #[arg(long, default_value_t = DEFAULT_PORT, value_name = "N")]
    port: u16,
    /// The server's hostname, which clients connect to and sign for (4.5).
    /// The default works on this machine and in the iOS simulator; for a
    /// phone, use a name it can resolve, such as the Mac's `<name>.local`.
    #[arg(long, default_value = "localhost", value_name = "NAME")]
    hostname: String,
    /// The random seed scenarios are made from. Kept with the state.
    #[arg(long, default_value_t = 1, value_name = "N")]
    seed: u64,
    /// The state directory, instead of .dev/ at the repository's root.
    #[arg(long, value_name = "DIR")]
    state: Option<PathBuf>,
}

/// What `.dev/scenario.json` records: which scenario the state holds.
#[derive(serde::Serialize, serde::Deserialize)]
struct Marker {
    version: u32,
    scenario: Scenario,
    seed: u64,
    /// When seeding finished, in ms since the Unix epoch.
    seeded_at: u64,
    seconds: f64,
}

/// What `.dev/me.json` holds: everything a client needs to sign in.
#[derive(serde::Serialize)]
struct Me<'a> {
    /// The server's address, `host:port` (2.1). The host is what a client
    /// sends in SNI and signs in AUTH.
    server: String,
    hostname: &'a str,
    port: u16,
    /// The certificate's fingerprint, to pin (2.2).
    fingerprint: String,
    /// The account, a hosted identity (4.6).
    identity: String,
    /// The account's device key, PKCS#8 PEM (Appendix A), next to this
    /// file.
    key: &'a str,
    scenario: Scenario,
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("risala-dev: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<(), String> {
    let dir = match &cli.state {
        Some(dir) => dir.clone(),
        None => repo_root()?.join(".dev"),
    };
    if cli.reset && dir.exists() {
        wipe(&dir)?;
        eprintln!(
            "risala-dev: deleted {}. Apps and CLI state that used it must clear their cache \
             (the app: launch with -ResetCache).",
            dir.display()
        );
    }
    let marker = read_marker(&dir)?;
    let (seeded, seed) = match &marker {
        Some(m) if m.scenario != cli.scenario => {
            return Err(format!(
                "{} holds the {} scenario; pass --reset to replace it with {}",
                dir.display(),
                m.scenario,
                cli.scenario
            ));
        }
        Some(m) => {
            if m.seed != cli.seed {
                eprintln!(
                    "risala-dev: the state was seeded with --seed {}; using that (--reset to \
                     change it)",
                    m.seed
                );
            }
            (true, m.seed)
        }
        None => {
            if dir.join("risala.db").exists() {
                eprintln!("risala-dev: an earlier seeding did not finish; starting again");
                wipe(&dir)?;
            }
            (false, cli.seed)
        }
    };

    let addr = SocketAddr::new(cli.listen, cli.port);
    // A clear message instead of a panic when the port is taken.
    if let Err(e) = std::net::TcpListener::bind(addr) {
        return Err(format!(
            "cannot listen on {addr}: {e}. Is risala-dev already running? Pick another port \
             with --port."
        ));
    }

    let plan = plan::build(cli.scenario, seed);
    // Seeding ends a little before now, so that the clock can follow the
    // system clock afterwards without going back.
    let end = Timestamp::now()
        .checked_sub(Duration::from_secs(60))
        .expect("a time after 1970");
    let first = plan.items.first().map_or(0, |i| i.ago);
    let mut builder = builder(&cli, &dir);
    if !seeded {
        let start = end
            .checked_sub(Duration::from_millis(first))
            .expect("a time after 1970");
        builder = builder.manual_clock_at(start);
    }
    let mut server = builder.start().await;

    let me = seed::actors(&plan, seed)
        .into_iter()
        .next()
        .expect("the account");
    write_key(&dir, &seed::key_for(seed, plan::ME))?;
    let summary = if seeded {
        let m = marker.as_ref().expect("seeded");
        format!(
            "serving {} (seed {seed}) as seeded {} ago, in {:.1} s",
            cli.scenario,
            ago(m.seeded_at),
            m.seconds
        )
    } else {
        eprintln!(
            "risala-dev: seeding {}: {} people, {} rooms, {} messages, {} steps",
            cli.scenario,
            plan.people.len(),
            plan.rooms.len(),
            plan.messages(),
            plan.items.len()
        );
        let outcome = seed::seed(&server, &plan, seed, end).await;
        server.follow_system_clock();
        // A fresh start, as on later runs: the seeding connections are
        // gone, and so is their presence (8.3), so the account shows as
        // offline until a client signs in.
        server.restart().await;
        let seconds = outcome.elapsed.as_secs_f64();
        write_marker(
            &dir,
            &Marker {
                version: STATE_VERSION,
                scenario: cli.scenario,
                seed,
                seeded_at: Timestamp::now().unix_millis(),
                seconds,
            },
        )?;
        let refused = if outcome.refused == 0 {
            String::new()
        } else {
            format!(", {} refused (see above)", outcome.refused)
        };
        format!(
            "seeded {} (seed {seed}) in {seconds:.1} s: {} steps{refused}",
            cli.scenario, outcome.steps
        )
    };

    let (kicks, kick_rooms) = kick::arm(&server, &plan, seed).await;

    let fingerprint = server.fingerprint().to_string();
    let address = if cli.port == risala_proto::DEFAULT_PORT {
        cli.hostname.clone()
    } else {
        format!("{}:{}", cli.hostname, cli.port)
    };
    let identity = me.uid().to_string();
    let me_json = Me {
        server: address.clone(),
        hostname: &cli.hostname,
        port: cli.port,
        fingerprint: fingerprint.clone(),
        identity: identity.clone(),
        key: "me.pem",
        scenario: cli.scenario,
    };
    let json = serde_json::to_string_pretty(&me_json).expect("JSON") + "\n";
    std::fs::write(dir.join("me.json"), json).map_err(|e| format!("writing me.json: {e}"))?;

    let shown = shown_path(&dir);
    println!("risala-dev: {summary}");
    println!();
    println!(
        "  server       {address}   (listening on {})",
        server.addr()
    );
    println!("  fingerprint  {fingerprint}");
    println!("  account      {identity}, device key {shown}/me.pem");
    println!("  for clients  {shown}/me.json");
    println!();
    println!("  risala-cli:");
    println!("    risala --state /tmp/risala-dev-cli trust {address} {fingerprint}");
    println!(
        "    risala --state /tmp/risala-dev-cli login {address} {identity} --key {shown}/me.pem"
    );
    println!("    risala --state /tmp/risala-dev-cli sync");
    println!();
    if !kick_rooms.is_empty() {
        let mut names: Vec<String> = kick_rooms.iter().take(3).map(|r| r.to_string()).collect();
        if kick_rooms.len() > 3 {
            names.push(format!("{} more", kick_rooms.len() - 3));
        }
        println!(
            "  {identity} is kicked from {} a few seconds after it first comes online, so that \
             its client has seen the room first.",
            names.join(", ")
        );
        println!();
    }
    if cli.listen.is_unspecified() && cli.hostname == "localhost" {
        println!(
            "  A phone cannot reach \"localhost\": pass --hostname with a name it resolves to \
             this machine, such as <name>.local."
        );
    }
    if cli.live {
        println!(
            "Bots are posting, {} things a minute. Ctrl-C stops the server.",
            cli.rate
        );
        live::run(&server, &plan, seed, cli.rate, ctrl_c()).await;
    } else {
        println!("Ctrl-C stops the server. The state stays; --reset starts again.");
        ctrl_c().await;
    }
    for task in kicks {
        task.abort();
    }
    server.stop().await;
    Ok(())
}

/// The server, as both seeding and serving runs use it.
fn builder(cli: &Cli, dir: &Path) -> TestServerBuilder {
    TestServer::builder()
        .hostname(&cli.hostname)
        .identity_domain(seed::IDENTITY_DOMAIN)
        .state_dir(dir)
        .listen(SocketAddr::new(cli.listen, cli.port))
        .welcome(&risala_proto::text::escape(&format!(
            "risala-dev: the {} scenario",
            cli.scenario
        )))
        .limits(limits())
}

/// The server's limits: the defaults, except that seeding registers
/// everyone and creates every room from one address in a few seconds.
fn limits() -> Limits {
    Limits {
        registrations_per_hour: 0,
        rooms_per_day: 0,
        ..Limits::default()
    }
}

async fn ctrl_c() {
    let _ = tokio::signal::ctrl_c().await;
    eprintln!();
}

/// The root of the repository: the nearest directory, from here up, that
/// has this crate in it.
fn repo_root() -> Result<PathBuf, String> {
    let here = std::env::current_dir().map_err(|e| format!("the current directory: {e}"))?;
    let mut dir = here.as_path();
    loop {
        if dir.join("crates/risala-dev/Cargo.toml").is_file() && dir.join("Cargo.toml").is_file() {
            return Ok(dir.to_owned());
        }
        match dir.parent() {
            Some(parent) => dir = parent,
            None => {
                return Err(format!(
                    "{} is not inside the risala repository; run from there, or pass --state",
                    here.display()
                ));
            }
        }
    }
}

/// Deletes a state directory, after checking that it is one.
fn wipe(dir: &Path) -> Result<(), String> {
    let ours = ["scenario.json", "me.json", "risala.db", "selfsigned"]
        .iter()
        .any(|f| dir.join(f).exists());
    let empty = std::fs::read_dir(dir)
        .map(|mut d| d.next().is_none())
        .unwrap_or(false);
    if !ours && !empty {
        return Err(format!(
            "{} does not look like risala-dev's state; not deleting it",
            dir.display()
        ));
    }
    std::fs::remove_dir_all(dir).map_err(|e| format!("deleting {}: {e}", dir.display()))
}

fn read_marker(dir: &Path) -> Result<Option<Marker>, String> {
    let path = dir.join("scenario.json");
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("reading {}: {e}", path.display())),
    };
    match serde_json::from_str::<Marker>(&text) {
        Ok(m) if m.version == STATE_VERSION => Ok(Some(m)),
        _ => {
            eprintln!("risala-dev: the state is from an older risala-dev; seeding again");
            wipe(dir)?;
            Ok(None)
        }
    }
}

fn write_marker(dir: &Path, marker: &Marker) -> Result<(), String> {
    let json = serde_json::to_string_pretty(marker).expect("JSON") + "\n";
    std::fs::write(dir.join("scenario.json"), json)
        .map_err(|e| format!("writing scenario.json: {e}"))
}

/// Writes the account's device key to `me.pem`, readable only by its
/// owner: it is the point of the file, for clients to import.
fn write_key(dir: &Path, key: &risala_proto::auth::SecretKey) -> Result<(), String> {
    use std::io::Write as _;
    let path = dir.join("me.pem");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options
        .open(&path)
        .and_then(|mut f| {
            // The mode above applies only to a new file. One left from an
            // earlier run keeps its own, so set it before the key goes in.
            #[cfg(unix)]
            f.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
            f.write_all(key.to_pkcs8_pem().as_bytes())
        })
        .map_err(|e| format!("writing {}: {e}", path.display()))
}

/// `dir` relative to the current directory when it is inside it.
fn shown_path(dir: &Path) -> String {
    let here = std::env::current_dir().ok();
    match here.as_deref().and_then(|h| dir.strip_prefix(h).ok()) {
        Some(rel) => rel.display().to_string(),
        None => dir.display().to_string(),
    }
}

/// How long ago `ms` was, roughly.
fn ago(ms: u64) -> String {
    let secs = Timestamp::now().unix_millis().saturating_sub(ms) / 1000;
    match secs {
        0..120 => format!("{secs} s"),
        120..7200 => format!("{} min", secs / 60),
        7200..172_800 => format!("{} h", secs / 3600),
        _ => format!("{} days", secs / 86_400),
    }
}
