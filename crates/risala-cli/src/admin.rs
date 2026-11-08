//! `risala admin`: the ADMIN commands of a server's operators (Section 10).

use clap::Subcommand;

use super::rooms::show_report;
use super::{Ctx, Res, fail_with, online, print_room, show_key, within};

#[derive(Subcommand)]
pub(crate) enum AdminCommand {
    /// List the server's operators (10.1).
    Ops { server: String },
    /// Make an identity an operator (10.1).
    Op { server: String, uid: String },
    /// Remove an operator (10.1).
    Deop { server: String, uid: String },
    /// Ban across the server (10.2): an identity, a domain written
    /// *@example.net, a connected guest such as ~sam (bans its address),
    /// or an address or prefix such as 2001:db8::/32 (guests only).
    Ban {
        server: String,
        target: String,
        /// Why; the words are joined with spaces.
        reason: Vec<String>,
    },
    /// Lift a server-wide ban (10.2).
    Unban { server: String, target: String },
    /// List the server-wide bans (10.2).
    Bans { server: String },
    /// List the open connections (10.3).
    Who { server: String },
    /// Close every connection of a user (10.3).
    Disconnect {
        server: String,
        uid: String,
        /// The reason sent with BYE; the words are joined with spaces.
        reason: Vec<String>,
    },
    /// Send a notice to every connection (10.3).
    Notice {
        server: String,
        /// The notice; the words are joined with spaces.
        #[arg(required = true)]
        message: Vec<String>,
    },
    /// List every room, private ones too (10.4).
    Rooms { server: String },
    /// Delete a room and all its events, for good (10.4). Type the room
    /// twice to confirm.
    Drop {
        server: String,
        room: String,
        /// The room again.
        confirm: String,
        /// Why; the words are joined with spaces.
        reason: Vec<String>,
    },
    /// Delete what a user sent, in every conversation (10.4).
    Purge {
        server: String,
        uid: String,
        /// Only messages from the last this many hours.
        #[arg(long)]
        hours: Option<u64>,
    },
    /// List every open report on the server, with its reporter (5.8).
    Reports { server: String },
    /// List the keys of an identity the server hosts (10.5).
    Keys { server: String, uid: String },
    /// Add a key to an identity the server hosts (10.5).
    Addkey {
        server: String,
        uid: String,
        /// The key file line or key; the words are joined with spaces.
        #[arg(required = true)]
        key: Vec<String>,
        /// A label for the key, usually the device's name.
        #[arg(long)]
        label: Option<String>,
    },
    /// Remove a key from an identity the server hosts; it may be the last
    /// (10.5).
    Delkey {
        server: String,
        uid: String,
        /// The key file line or key; the words are joined with spaces.
        #[arg(required = true)]
        key: Vec<String>,
    },
    /// Delete an identity the server hosts (10.5). Type the uid twice to
    /// confirm.
    Unregister {
        server: String,
        uid: String,
        /// The uid again.
        confirm: String,
    },
    /// Change a server setting (10.6): `guests yes|no`,
    /// `registration open|closed`, `retention <days>|forever`, or
    /// `welcome <text>`.
    Set {
        server: String,
        key: String,
        /// The value; the words are joined with spaces.
        value: Vec<String>,
    },
}

pub(crate) async fn run(ctx: &Ctx, command: AdminCommand) -> Res {
    use AdminCommand as A;
    let server = match &command {
        A::Ops { server }
        | A::Op { server, .. }
        | A::Deop { server, .. }
        | A::Ban { server, .. }
        | A::Unban { server, .. }
        | A::Bans { server }
        | A::Who { server }
        | A::Disconnect { server, .. }
        | A::Notice { server, .. }
        | A::Rooms { server }
        | A::Drop { server, .. }
        | A::Purge { server, .. }
        | A::Reports { server }
        | A::Keys { server, .. }
        | A::Addkey { server, .. }
        | A::Delkey { server, .. }
        | A::Unregister { server, .. }
        | A::Set { server, .. } => server.clone(),
    };
    // The commands that cannot be undone are typed twice, and checked
    // before connecting.
    match &command {
        A::Drop { room, confirm, .. } if room.trim() != confirm.trim() => {
            return fail_with(super::USAGE, "type the room twice to confirm");
        }
        A::Unregister { uid, confirm, .. } if uid.trim() != confirm.trim() => {
            return fail_with(super::USAGE, "type the uid twice to confirm");
        }
        _ => {}
    }
    let admin = online(ctx, &server).await?.admin();
    match command {
        A::Ops { .. } => {
            for uid in within(admin.operators()).await? {
                println!("{uid}");
            }
        }
        A::Op { uid, .. } => {
            within(admin.add_operator(&uid)).await?;
            println!("{} is an operator", uid.trim());
        }
        A::Deop { uid, .. } => {
            within(admin.remove_operator(&uid)).await?;
            println!("{} is no longer an operator", uid.trim());
        }
        A::Ban { target, reason, .. } => {
            within(admin.ban(&target, &reason.join(" "))).await?;
            println!("banned {}", target.trim());
        }
        A::Unban { target, .. } => {
            within(admin.unban(&target)).await?;
            println!("unbanned {}", target.trim());
        }
        A::Bans { .. } => {
            for b in within(admin.bans()).await? {
                if b.reason.is_empty() {
                    println!("{}", b.target);
                } else {
                    println!("{} {}", b.target, b.reason);
                }
            }
        }
        A::Who { .. } => {
            for c in within(admin.connections()).await? {
                let address = match c.port {
                    Some(port) if c.address.contains(':') => format!("[{}]:{port}", c.address),
                    Some(port) => format!("{}:{port}", c.address),
                    None => c.address,
                };
                println!("{} {address} {}", c.uid.as_deref().unwrap_or("-"), c.since);
            }
        }
        A::Disconnect { uid, reason, .. } => {
            within(admin.disconnect(&uid, &reason.join(" "))).await?;
            println!("disconnected {}", uid.trim());
        }
        A::Notice { message, .. } => {
            within(admin.notice(&message.join(" "))).await?;
        }
        A::Rooms { .. } => {
            let mut after = None;
            loop {
                let page = within(admin.rooms(after.take(), None)).await?;
                for room in &page.rooms {
                    print_room(&room.room, room.members, &room.topic);
                }
                match page.rooms.last() {
                    Some(last) if page.more => after = Some(last.room.clone()),
                    _ => break,
                }
            }
        }
        A::Drop { room, reason, .. } => {
            within(admin.drop_room(&room, &reason.join(" "))).await?;
            println!("dropped {}", room.trim());
        }
        A::Purge { uid, hours, .. } => {
            let n = within(admin.purge(&uid, hours)).await?;
            println!("deleted {n} messages of {}", uid.trim());
        }
        A::Reports { .. } => {
            for r in within(admin.reports()).await? {
                println!("{}", show_report(&r));
            }
        }
        A::Keys { uid, .. } => {
            for key in within(admin.keys(&uid)).await? {
                println!("{}", show_key(&key));
            }
        }
        A::Addkey {
            uid, key, label, ..
        } => {
            within(admin.add_key(&uid, &key.join(" "), label.as_deref().unwrap_or(""))).await?;
            println!("key added to {}", uid.trim());
        }
        A::Delkey { uid, key, .. } => {
            within(admin.remove_key(&uid, &key.join(" "))).await?;
            println!("key removed from {}", uid.trim());
        }
        A::Unregister { uid, .. } => {
            within(admin.unregister(&uid)).await?;
            println!("unregistered {}", uid.trim());
        }
        A::Set { key, value, .. } => {
            within(admin.set(&key, &value.join(" "))).await?;
            println!("{} set", key.trim());
        }
    }
    Ok(())
}
