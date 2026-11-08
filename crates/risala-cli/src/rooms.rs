//! Running rooms: deleting, settings, roles, moderation and reports (5.4,
//! 5.8, 6.2-6.4, 8.5).

use clap::Subcommand;
use librisala::client::{OutboxStatus, ReportInfo};

use super::{Ctx, Res, explain, fail, online, pick, within};

#[derive(Subcommand)]
pub(crate) enum RoomCommand {
    /// Delete a message (5.4): your own, or as a moderator anyone's in a
    /// room. Offline, it is queued and goes out on the next connection.
    Delete {
        server: String,
        conversation: String,
        seq: u64,
    },
    /// Show a room's settings, members and your role (6.2), or with no
    /// room, the server's settings (8.5).
    Info {
        server: String,
        room: Option<String>,
    },
    /// Set a room's topic, or clear it with no text (6.2).
    Topic {
        server: String,
        room: String,
        /// The topic; the words are joined with spaces.
        text: Vec<String>,
    },
    /// Change a room setting (6.2): public yes|no, guests none|read|write,
    /// retention <days>|server, or topic <text>.
    Set {
        server: String,
        room: String,
        key: String,
        /// The value; the words are joined with spaces.
        value: Vec<String>,
    },
    /// Set someone's role in a room: owner, mod or member (6.3).
    Role {
        server: String,
        room: String,
        uid: String,
        role: String,
    },
    /// List a room's owners and moderators (6.3).
    Roles { server: String, room: String },
    /// Invite an identity to a room (6.4).
    Invite {
        server: String,
        room: String,
        uid: String,
    },
    /// Remove a member from a room; they may join again (6.4).
    Kick {
        server: String,
        room: String,
        uid: String,
        /// Why; the words are joined with spaces.
        reason: Vec<String>,
    },
    /// Ban someone from a room, removing them if they are in it (6.4).
    Ban {
        server: String,
        room: String,
        uid: String,
        /// Why; the words are joined with spaces.
        reason: Vec<String>,
    },
    /// Lift a ban in a room (6.4).
    Unban {
        server: String,
        room: String,
        uid: String,
    },
    /// List a room's bans (6.4).
    Bans { server: String, room: String },
    /// Report a message to the room's moderators and the server's
    /// operators (5.8). Prints the report's id.
    Report {
        server: String,
        conversation: String,
        seq: u64,
        /// Why; the words are joined with spaces.
        reason: Vec<String>,
    },
    /// List a room's open reports, as one of its owners or moderators, or
    /// an operator (5.8).
    Reports { server: String, room: String },
    /// Close a report (5.8).
    Resolve { server: String, id: String },
}

/// A report in two lines: who reported what and why, then the message.
pub(crate) fn show_report(r: &ReportInfo) -> String {
    let mut s = format!("{} {} {} {}", r.id, r.conversation, r.seq, r.time);
    if let Some(by) = &r.reporter {
        s.push_str(&format!(" by {by}"));
    }
    if r.encrypted {
        s.push_str(" (encrypted)");
    }
    if !r.reason.is_empty() {
        s.push_str(&format!(": {}", r.reason));
    }
    if let Some(m) = &r.message {
        s.push_str(&format!(
            "\n    [{}] <{}> {}",
            m.seq,
            m.from,
            m.text.replace('\n', "\n    ")
        ));
    }
    s
}

pub(crate) async fn run(ctx: &Ctx, command: RoomCommand) -> Res {
    match command {
        RoomCommand::Delete {
            server,
            conversation,
            seq,
        } => {
            let account = pick(ctx, &server)?;
            let connected = matches!(
                tokio::time::timeout(super::WAIT, account.connect()).await,
                Ok(Ok(_))
            );
            let conv = account.conversation(&conversation).or_else(explain)?;
            let entry = conv.delete(seq).await.or_else(explain)?;
            if !connected {
                return fail("offline; the deletion goes out on the next connection");
            }
            let entry = within(account.wait_outbox(entry.id)).await?;
            match entry.status {
                OutboxStatus::Sent { .. } => {
                    println!("deleted {seq} in {}", conv.name());
                    Ok(())
                }
                OutboxStatus::Failed { reason, .. } => fail(format!("not deleted: {reason}")),
                _ => fail("queued; it goes out on the next connection"),
            }
        }
        RoomCommand::Info { server, room } => {
            let account = online(ctx, &server).await?;
            match room {
                Some(room) => {
                    let conv = account.conversation(&room).or_else(explain)?;
                    let info = within(conv.room_info()).await?;
                    println!(
                        "{} ({}): {} members, head {}, your role {}{}",
                        info.room,
                        info.id,
                        info.members,
                        info.head,
                        info.role,
                        if info.joined { "" } else { ", not joined" }
                    );
                    for s in info.settings {
                        println!("{} {}", s.key, s.value);
                    }
                }
                None => {
                    let info = within(account.server_info()).await?;
                    println!("version {}", info.version);
                    println!("guests {}", if info.guests { "yes" } else { "no" });
                    println!(
                        "registration {}",
                        info.registration.as_deref().unwrap_or("closed")
                    );
                    match info.retention_days {
                        Some(days) => println!("retention {days} days"),
                        None => println!("retention forever"),
                    }
                    println!("push {}", if info.push { "yes" } else { "no" });
                    match info.upload {
                        Some(bytes) => println!("upload {bytes} bytes"),
                        None => println!("upload no"),
                    }
                }
            }
            Ok(())
        }
        RoomCommand::Topic { server, room, text } => {
            let account = online(ctx, &server).await?;
            let conv = account.conversation(&room).or_else(explain)?;
            match within(conv.set_topic(&text.join(" "))).await? {
                Some(seq) => println!("topic set ({seq})"),
                None => println!("the topic is that already"),
            }
            Ok(())
        }
        RoomCommand::Set {
            server,
            room,
            key,
            value,
        } => {
            let account = online(ctx, &server).await?;
            let conv = account.conversation(&room).or_else(explain)?;
            match within(conv.set_setting(&key, &value.join(" "))).await? {
                Some(seq) => println!("{key} set ({seq})"),
                None => println!("{key} is that already"),
            }
            Ok(())
        }
        RoomCommand::Role {
            server,
            room,
            uid,
            role,
        } => {
            let account = online(ctx, &server).await?;
            let conv = account.conversation(&room).or_else(explain)?;
            match within(conv.set_role(&uid, &role)).await? {
                Some(seq) => println!("{uid} is now {role} ({seq})"),
                None => println!("{uid} is {role} already"),
            }
            Ok(())
        }
        RoomCommand::Roles { server, room } => {
            let account = online(ctx, &server).await?;
            let conv = account.conversation(&room).or_else(explain)?;
            for r in within(conv.roles()).await? {
                println!("{} {}", r.uid, r.role);
            }
            Ok(())
        }
        RoomCommand::Invite { server, room, uid } => {
            let account = online(ctx, &server).await?;
            let conv = account.conversation(&room).or_else(explain)?;
            match within(conv.invite(&uid)).await? {
                Some(seq) => println!("invited {uid} ({seq})"),
                None => println!("{uid} is a member already"),
            }
            Ok(())
        }
        RoomCommand::Kick {
            server,
            room,
            uid,
            reason,
        } => {
            let account = online(ctx, &server).await?;
            let conv = account.conversation(&room).or_else(explain)?;
            let seq = within(conv.kick(&uid, &reason.join(" "))).await?;
            println!("kicked {uid} ({seq})");
            Ok(())
        }
        RoomCommand::Ban {
            server,
            room,
            uid,
            reason,
        } => {
            let account = online(ctx, &server).await?;
            let conv = account.conversation(&room).or_else(explain)?;
            match within(conv.ban(&uid, &reason.join(" "))).await? {
                Some(seq) => println!("banned {uid} ({seq})"),
                None => println!("{uid} was banned already; the reason is updated"),
            }
            Ok(())
        }
        RoomCommand::Unban { server, room, uid } => {
            let account = online(ctx, &server).await?;
            let conv = account.conversation(&room).or_else(explain)?;
            let seq = within(conv.unban(&uid)).await?;
            println!("unbanned {uid} ({seq})");
            Ok(())
        }
        RoomCommand::Bans { server, room } => {
            let account = online(ctx, &server).await?;
            let conv = account.conversation(&room).or_else(explain)?;
            for b in within(conv.bans()).await? {
                if b.reason.is_empty() {
                    println!("{}", b.uid);
                } else {
                    println!("{} {}", b.uid, b.reason);
                }
            }
            Ok(())
        }
        RoomCommand::Report {
            server,
            conversation,
            seq,
            reason,
        } => {
            let account = online(ctx, &server).await?;
            let conv = account.conversation(&conversation).or_else(explain)?;
            let id = within(conv.report(seq, &reason.join(" "))).await?;
            println!("{id}");
            Ok(())
        }
        RoomCommand::Reports { server, room } => {
            let account = online(ctx, &server).await?;
            let conv = account.conversation(&room).or_else(explain)?;
            for r in within(conv.reports()).await? {
                println!("{}", show_report(&r));
            }
            Ok(())
        }
        RoomCommand::Resolve { server, id } => {
            let account = online(ctx, &server).await?;
            within(account.resolve_report(&id)).await?;
            println!("resolved {}", id.trim());
            Ok(())
        }
    }
}
