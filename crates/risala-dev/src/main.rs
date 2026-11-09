//! `risala-dev`: a local risala server with its key log and a witness,
//! for the apps and the CLI to run against.
//!
//! ```sh
//! risala-dev                 # serve, with state in .dev/ at the repository's root
//! risala-dev --reset         # start again from nothing
//! ```
//!
//! It runs [`risala_dev::World`]: `risalad` named `chat.test`, hosting
//! identities at `example.org`, keeping their key log and witnessing it.
//! It prints, and writes to `.dev/cli-args`, the options that point
//! `risala` at it:
//!
//! ```sh
//! risala --state /tmp/alice $(cat .dev/cli-args) create chat.test alice laptop
//! ```
//!
//! Development only: the log's and witness's keys come from fixed seeds.
//! M5a's seeded scenarios and bots talked in plain text, which draft-03
//! has no commands for; they are gone until they are rebuilt on
//! librisala.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use risala_dev::{World, WorldOptions};

/// The port the chat server listens on unless told otherwise: one above
/// risala's own (7472), so that it does not clash with a real server.
const DEFAULT_PORT: u16 = 7473;

#[derive(Parser)]
#[command(
    name = "risala-dev",
    about = "A local risala server with its key log and a witness",
    after_help = "State lives in .dev/ at the root of the repository. Point risala at it \
                  with the options in .dev/cli-args."
)]
struct Cli {
    /// Delete the state and start again. Clients must then start afresh.
    #[arg(long)]
    reset: bool,
    /// The address the chat server listens on.
    #[arg(long, default_value = "127.0.0.1", value_name = "ADDR")]
    listen: IpAddr,
    /// The chat server's port.
    #[arg(long, default_value_t = DEFAULT_PORT, value_name = "N")]
    port: u16,
    /// The HTTPS listener's port (the log, key files, files and blobs).
    #[arg(long, default_value_t = DEFAULT_PORT + 1, value_name = "N")]
    http_port: u16,
    /// The state directory, instead of .dev/ at the repository's root.
    #[arg(long, value_name = "DIR")]
    state: Option<PathBuf>,
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

/// The root of the risala repository holding the current directory: the
/// state's default home. Not the directory the binary was built in, which
/// for `nix run .#dev` is a build sandbox long gone.
fn repo_root() -> Result<PathBuf, String> {
    let here = std::env::current_dir().map_err(|e| format!("the current directory: {e}"))?;
    repo_root_from(&here).ok_or_else(|| {
        format!(
            "{} is not inside the risala repository; run from there, or pass --state",
            here.display()
        )
    })
}

/// The nearest directory from `dir` up that holds the workspace's
/// `Cargo.toml` and `crates/risala-dev/Cargo.toml`.
fn repo_root_from(dir: &Path) -> Option<PathBuf> {
    dir.ancestors()
        .find(|d| {
            d.join("crates/risala-dev/Cargo.toml").is_file() && d.join("Cargo.toml").is_file()
        })
        .map(Path::to_path_buf)
}

async fn run(cli: Cli) -> Result<(), String> {
    let state = match cli.state {
        Some(dir) => dir,
        None => repo_root()?.join(".dev"),
    };
    if cli.reset && state.exists() {
        std::fs::remove_dir_all(&state).map_err(|e| format!("{}: {e}", state.display()))?;
    }
    let world = World::start_with(WorldOptions {
        state_dir: Some(state.clone()),
        listen: Some(SocketAddr::new(cli.listen, cli.port)),
        http_port: Some(cli.http_port),
    })
    .await;
    let args = world.cli_args().join(" ");
    let path = state.join("cli-args");
    std::fs::write(&path, format!("{args}\n")).map_err(|e| format!("{}: {e}", path.display()))?;
    println!(
        "risala-dev: serving {} at {}",
        risala_dev::HOST,
        world.server.addr()
    );
    println!("risala options ({}):\n{args}", path.display());
    tokio::signal::ctrl_c()
        .await
        .map_err(|e| format!("waiting for ctrl-c: {e}"))?;
    world.server.stop().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_root_is_found_from_inside_the_repository() {
        let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let root = crate_dir.parent().unwrap().parent().unwrap();
        assert_eq!(repo_root_from(crate_dir).as_deref(), Some(root));
        assert_eq!(
            repo_root_from(&crate_dir.join("src")).as_deref(),
            Some(root)
        );
        assert_eq!(repo_root_from(root).as_deref(), Some(root));
    }

    #[test]
    fn outside_the_repository_there_is_no_root() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(repo_root_from(dir.path()), None);
    }
}
