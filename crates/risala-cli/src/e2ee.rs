//! End-to-end encryption (Section 12): encrypted rooms, the identity's
//! devices, and its recovery key.
//!
//! Direct conversations are always encrypted, so `send` to a person needs
//! nothing more. These commands are for the rest:
//!
//! - `encrypt` makes a room you own, and are alone in, encrypted for good.
//!   `invite` then adds the invitee's devices to it (12.6).
//! - `devices` lists an identity's devices with their fingerprints, to
//!   compare through another channel (12.12). A new device of your own
//!   identity reads earlier history only once you `confirm` it here (12.9).
//! - `recovery create` makes a recovery key, shown once, and backs up the
//!   history keys under it; `recovery restore` restores them; `recover`
//!   gets the identity back on a new device after every device is lost
//!   (12.10).

use clap::Subcommand;
use librisala::client::{History, OwnDeviceState};

use super::{Ctx, Res, explain, fail, online, within};

#[derive(Subcommand)]
pub(crate) enum E2eeCommand {
    /// Make a room you own, and are its only member, end-to-end encrypted
    /// for good (12.3). New members then read what was sent before they
    /// were invited, unless --joined.
    Encrypt {
        server: String,
        room: String,
        /// New members read only what is sent after they are invited.
        #[arg(long)]
        joined: bool,
        /// Only owners and moderators may send; others only react.
        #[arg(long)]
        announcements: bool,
    },
    /// List an identity's devices, or your own, with their fingerprints
    /// (12.12). Compare them with their owner through another channel.
    Devices {
        server: String,
        /// Whose devices; your own if left out.
        uid: Option<String>,
    },
    /// Confirm that a new device of your identity is yours, by its
    /// fingerprint, so that this device sends it the keys to read earlier
    /// history (12.9). --decline says it is not yours.
    Confirm {
        server: String,
        fingerprint: String,
        /// The device is not yours: send it nothing.
        #[arg(long)]
        decline: bool,
    },
    /// Make or use a recovery key (12.10).
    Recovery {
        #[command(subcommand)]
        command: RecoveryCommand,
    },
    /// Get an identity back after every device is lost, with its recovery
    /// key (12.10): sign in with it, put this device's key in place of the
    /// lost ones, and restore the history keys. Needs a server that hosts
    /// the identity; makes this device's key if it has none.
    Recover {
        server: String,
        identity: String,
        /// The recovery key; the words are joined with spaces.
        #[arg(required = true)]
        key: Vec<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum RecoveryCommand {
    /// Make a new recovery key, print it once, and back up every history
    /// key under it. Keep it like a password: it can sign in as you.
    Create { server: String },
    /// Restore the history keys from the backups, with the recovery key.
    Restore {
        server: String,
        /// The recovery key; the words are joined with spaces.
        #[arg(required = true)]
        key: Vec<String>,
    },
}

pub(crate) async fn run(ctx: &Ctx, command: E2eeCommand) -> Res {
    match command {
        E2eeCommand::Encrypt {
            server,
            room,
            joined,
            announcements,
        } => {
            let account = online(ctx, &server).await?;
            let conv = account.conversation(&room).or_else(explain)?;
            // The room's id comes with JOIN or INFO (12.5).
            within(conv.room_info()).await?;
            let history = if joined {
                History::Joined
            } else {
                History::Shared
            };
            within(conv.encrypt(history, announcements)).await?;
            within(account.wait_synced()).await?;
            match conv.info().or_else(explain)? {
                Some(info) if info.encrypted => {
                    println!("{} is end-to-end encrypted", conv.name());
                    Ok(())
                }
                _ => fail(format!(
                    "{} was not encrypted: you must own it and be its only member",
                    conv.name()
                )),
            }
        }
        E2eeCommand::Devices { server, uid } => {
            let account = online(ctx, &server).await?;
            within(account.wait_synced()).await?;
            let uid = uid.unwrap_or_else(|| account.uid());
            let devices = account.devices(&uid).or_else(explain)?;
            if devices.is_empty() {
                println!("no devices of {uid} known here");
            }
            for d in devices {
                let mut notes = Vec::new();
                if d.this_device {
                    notes.push("this device");
                }
                if d.recovery {
                    notes.push("recovery key");
                }
                match d.listed {
                    Some(false) => notes.push("not in the key file"),
                    None => notes.push("key file not checked yet"),
                    Some(true) => {}
                }
                match d.state {
                    Some(OwnDeviceState::New) => notes.push("new: confirm it"),
                    Some(OwnDeviceState::Confirmed) => notes.push("confirmed"),
                    Some(OwnDeviceState::Declined) => notes.push("declined"),
                    Some(OwnDeviceState::Sent) | None => {}
                }
                let label = if d.label.is_empty() {
                    String::new()
                } else {
                    format!(" {}", d.label)
                };
                let notes = if notes.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", notes.join(", "))
                };
                println!("{}{label}{notes}", d.fingerprint);
            }
            Ok(())
        }
        E2eeCommand::Confirm {
            server,
            fingerprint,
            decline,
        } => {
            let account = online(ctx, &server).await?;
            within(account.wait_synced()).await?;
            within(account.confirm_device(&fingerprint, !decline)).await?;
            within(account.wait_synced()).await?;
            if decline {
                println!("{fingerprint} gets no history keys from this device");
            } else {
                println!("{fingerprint} gets the history keys from this device");
            }
            Ok(())
        }
        E2eeCommand::Recovery {
            command: RecoveryCommand::Create { server },
        } => {
            let account = online(ctx, &server).await?;
            within(account.wait_synced()).await?;
            let made = within(account.create_recovery_key()).await?;
            within(account.wait_synced()).await?;
            println!("recovery key, shown once; keep it like a password:");
            println!();
            println!("    {}", made.key);
            println!();
            if let Some(line) = made.key_file_line {
                println!("add this line to your key file:");
                println!("{line}");
                if let Some(old) = made.old_key_file_line {
                    println!("and remove the previous recovery key's line:");
                    println!("{old}");
                }
            }
            Ok(())
        }
        E2eeCommand::Recovery {
            command: RecoveryCommand::Restore { server, key },
        } => {
            let account = online(ctx, &server).await?;
            within(account.wait_synced()).await?;
            let n = within(account.restore_backup(&key.join(" "))).await?;
            println!("restored {n} history keys");
            Ok(())
        }
        E2eeCommand::Recover {
            server,
            identity,
            key,
        } => {
            let client = &ctx.client;
            if client.device_key(&identity).or_else(explain)?.is_none() {
                within(client.create_device_key(&identity, false)).await?;
            }
            let account =
                within(client.recover_identity(&server, &identity, &key.join(" "))).await?;
            within(account.wait_synced()).await?;
            // The new device joins the identity's encrypted conversations
            // by itself (12.6); the history keys come from the backup.
            match account.restore_backup(&key.join(" ")).await {
                Ok(n) => println!(
                    "{} is back on this device; restored {n} history keys",
                    account.uid()
                ),
                Err(e) => {
                    println!("{} is back on this device", account.uid());
                    return explain(e);
                }
            }
            Ok(())
        }
    }
}
