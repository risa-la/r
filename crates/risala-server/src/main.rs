//! `risalad`, the risala server.
//!
//! ```text
//! risalad [--config <path>]
//! ```
//!
//! With `--config`, it reads that TOML file (see [`risala_server::config`]).
//! Without it, it runs a development server: the defaults of an empty
//! configuration file. Logging goes to standard error, filtered by `RUST_LOG`
//! (default `info`). SIGINT and SIGTERM shut the server down cleanly.

use std::io::IsTerminal as _;
use std::path::PathBuf;
use std::process::ExitCode;

use risala_server::config::Config;
use tracing_subscriber::EnvFilter;

const USAGE: &str = "\
Usage: risalad [--config <path>]

The risala chat server.

Options:
  -c, --config <path>  Read the configuration from this TOML file. Without
                       it, run a development server: listen on port 7472,
                       keep the database and a self-signed certificate in
                       the current directory, and allow anonymous
                       connections and guests.
  -h, --help           Print this help and exit.
  -V, --version        Print the version and exit.

Logging goes to standard error. Set RUST_LOG to change what is logged, for
example RUST_LOG=debug or RUST_LOG=risala_server=trace (default: info).
SIGINT and SIGTERM shut the server down, SIGHUP reloads its certificates.
";

/// What the command line asks for.
#[derive(Debug, PartialEq, Eq)]
enum Args {
    Run { config: Option<PathBuf> },
    Help,
    Version,
}

/// Parses the arguments after the program name.
fn parse_args(args: impl IntoIterator<Item = std::ffi::OsString>) -> Result<Args, String> {
    let mut config = None;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let text = arg.to_string_lossy();
        if let Some(path) = text.strip_prefix("--config=") {
            set_config(&mut config, PathBuf::from(path))?;
            continue;
        }
        match &*text {
            "-h" | "--help" => return Ok(Args::Help),
            "-V" | "--version" => return Ok(Args::Version),
            "-c" | "--config" => {
                let path = args.next().ok_or_else(|| format!("{text} needs a path"))?;
                set_config(&mut config, PathBuf::from(path))?;
            }
            _ => return Err(format!("unexpected argument {text:?}")),
        }
    }
    Ok(Args::Run { config })
}

fn set_config(slot: &mut Option<PathBuf>, path: PathBuf) -> Result<(), String> {
    if slot.replace(path).is_some() {
        return Err("--config given more than once".into());
    }
    Ok(())
}

/// The configuration of a development server, used without `--config`.
fn dev_config() -> Config {
    Config::default()
}

fn main() -> ExitCode {
    let config_path = match parse_args(std::env::args_os().skip(1)) {
        Ok(Args::Run { config }) => config,
        Ok(Args::Help) => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Ok(Args::Version) => {
            println!(
                "risalad {} (protocol version {})",
                env!("CARGO_PKG_VERSION"),
                risala_proto::PROTOCOL_VERSION
            );
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("risalad: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };

    // Events that name network addresses stay off unless their target is
    // named on its own (4.2: addresses are not logged by default), even
    // with `RUST_LOG=debug`.
    let mut filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let named = std::env::var("RUST_LOG").is_ok_and(|v| v.contains(risala_server::net::ADDRESSES));
    if !named && let Ok(off) = format!("{}=off", risala_server::net::ADDRESSES).parse() {
        filter = filter.add_directive(off);
    }
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        // No colour codes in files or the journal.
        .with_ansi(std::io::stderr().is_terminal())
        .init();

    let config = match &config_path {
        Some(path) => match Config::load(path) {
            Ok(config) => config,
            Err(e) => {
                tracing::error!("{e}");
                return ExitCode::FAILURE;
            }
        },
        None => {
            tracing::warn!("no --config given: running a development server");
            dev_config()
        }
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!("starting the runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(serve(config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e}");
            ExitCode::FAILURE
        }
    }
}

async fn serve(config: Config) -> Result<(), risala_server::RunError> {
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        hostname = %config.hostname,
        state_dir = %config.state_dir.display(),
        "starting risalad"
    );
    let daemon = risala_server::Daemon::bind(config).await?;
    for addr in daemon.local_addrs() {
        tracing::info!(%addr, "listening");
    }
    for fingerprint in daemon.fingerprints() {
        tracing::info!(%fingerprint, "certificate");
    }
    daemon.run(shutdown_signal()).await
}

/// Resolves at the first SIGINT or SIGTERM.
async fn shutdown_signal() {
    let interrupt = async {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::error!("cannot listen for SIGINT: {e}");
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(e) => {
                tracing::error!("cannot listen for SIGTERM: {e}");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = interrupt => tracing::info!("SIGINT: shutting down"),
        () = terminate => tracing::info!("SIGTERM: shutting down"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Args, String> {
        parse_args(args.iter().map(std::ffi::OsString::from))
    }

    #[test]
    fn arguments() {
        assert_eq!(parse(&[]), Ok(Args::Run { config: None }));
        let with = |p: &str| {
            Ok(Args::Run {
                config: Some(PathBuf::from(p)),
            })
        };
        assert_eq!(parse(&["--config", "a.toml"]), with("a.toml"));
        assert_eq!(parse(&["-c", "a.toml"]), with("a.toml"));
        assert_eq!(parse(&["--config=a.toml"]), with("a.toml"));
        assert_eq!(parse(&["--help"]), Ok(Args::Help));
        assert_eq!(parse(&["-h", "--bogus"]), Ok(Args::Help));
        assert_eq!(parse(&["--version"]), Ok(Args::Version));
        assert!(parse(&["--config"]).is_err());
        assert!(parse(&["--config", "a", "--config", "b"]).is_err());
        assert!(parse(&["serve"]).is_err());
    }

    #[test]
    fn dev_server_is_open() {
        let config = dev_config();
        assert!(config.server.anon);
        assert!(config.server.guests);
    }
}
