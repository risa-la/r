//! Notices: what the client tells the user while a command runs, one line
//! each on standard error.
//!
//! The spec has devices tell their users a good deal: that another device
//! of the identity removed this one (12.7), that a held invitation waits
//! (6.1), that a key check failed, that a group may have split. librisala
//! sends those as [`Event`]s while the client is connected, and
//! [`Notices`] prints each one that is for the user, while any command
//! runs: `sync`, `read --sync`, and every command that stays connected
//! for what it sent. Standard output stays the command's own, for
//! scripts.
//!
//! Every line is made by [`notice`], which passes it whole through
//! [`Shown`]: names, uids, labels, topics and reasons come from other
//! people and servers.
//!
//! Skipped, as they are not for the user or are told otherwise:
//! - cache changes and connection states: commands read the cache, and a
//!   sign-in that fails is the command's error;
//! - typing and presence: they mean nothing once the run ends;
//! - a group job's end: the command that started it waits for it, and
//!   fails with its error;
//!
//! Only the conversation area's events are told so far.

use librisala::client::conversations::{ConversationEvent, ConversationKind, ConversationSummary};
use librisala::client::types::ConversationId;
use librisala::{Client, Event};
use tokio::sync::broadcast::error::{RecvError, TryRecvError};
use tokio::sync::{broadcast, oneshot};
use tokio::task::JoinHandle;

use crate::shown::Shown;

/// Prints notices while the command runs. Start it before connecting, so
/// that nothing is missed, and [`stop`](Self::stop) it once disconnected.
pub struct Notices {
    stop: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

impl Notices {
    pub fn start(client: &Client) -> Notices {
        let events = client.subscribe();
        let client = client.clone();
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(print(client, events, stopped));
        Notices { stop, task }
    }

    /// Prints what is left to print, and stops.
    pub async fn stop(self) {
        let _ = self.stop.send(());
        let _ = self.task.await;
    }
}

async fn print(
    client: Client,
    mut events: broadcast::Receiver<Event>,
    mut stopped: oneshot::Receiver<()>,
) {
    let mut printer = Printer::default();
    loop {
        tokio::select! {
            // Events first, so that none sent before the stop is lost.
            biased;
            event = events.recv() => match event {
                Ok(event) => printer.event(&client, &event),
                Err(RecvError::Lagged(n)) => printer.line(&missed(n)),
                Err(RecvError::Closed) => return,
            },
            _ = &mut stopped => break,
        }
    }
    loop {
        match events.try_recv() {
            Ok(event) => printer.event(&client, &event),
            Err(TryRecvError::Lagged(n)) => printer.line(&missed(n)),
            Err(TryRecvError::Empty | TryRecvError::Closed) => return,
        }
    }
}

/// Prints notices, each line once in a row: some events come again for
/// every post that shows the same thing, as
/// [`ConversationEvent::MaybeSplit`] does. A line that comes again after
/// another is printed again, as sending held after it resumed.
#[derive(Default)]
struct Printer {
    last: Option<String>,
}

impl Printer {
    fn event(&mut self, client: &Client, event: &Event) {
        let conv = |id| Conv::of(id, client.conversation(id).ok().as_ref());
        if let Some(line) = notice(event, &conv) {
            self.line(&line);
        }
    }

    fn line(&mut self, line: &str) {
        if self.last.as_deref() == Some(line) {
            return;
        }
        use std::io::Write as _;
        // A closed standard error must not stop the command.
        let _ = writeln!(std::io::stderr().lock(), "risala: {line}");
        self.last = Some(line.to_owned());
    }
}

fn missed(n: u64) -> String {
    format!(
        "{n} events came faster than they could be read, so some notices may be missing; \
         `risala list` shows each conversation's state"
    )
}

/// A conversation as a notice names it: its number, and how commands name
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conv {
    number: i64,
    /// Its kind and name, if the cache has it.
    known: Option<Known>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Known {
    kind: ConversationKind,
    /// A room's name, or the peer's uid for a direct conversation.
    name: String,
    /// A public room's address.
    room: Option<String>,
    /// A direct conversation that the peer left (6.1).
    left_by_peer: bool,
}

impl Conv {
    fn of(id: ConversationId, summary: Option<&ConversationSummary>) -> Conv {
        Conv {
            number: id.get(),
            known: summary.map(|s| Known {
                kind: s.kind,
                name: s.name.clone(),
                room: s.room.as_ref().map(ToString::to_string),
                left_by_peer: s.left_by_peer,
            }),
        }
    }

    fn kind(&self) -> Option<ConversationKind> {
        self.known.as_ref().map(|k| k.kind)
    }

    /// The peer of a direct conversation.
    fn peer(&self) -> Option<&str> {
        self.known
            .as_ref()
            .filter(|k| k.kind == ConversationKind::Direct)
            .map(|k| k.name.as_str())
    }
}

/// `conversation 3 (#garden)`: the number for commands, and what it is.
impl std::fmt::Display for Conv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "conversation {}", self.number)?;
        let Some(k) = &self.known else {
            return Ok(());
        };
        match k.kind {
            ConversationKind::Direct => write!(f, " (with {})", k.name),
            ConversationKind::WithYourself => write!(f, " (with yourself)"),
            ConversationKind::PrivateRoom => write!(f, " (#{})", k.name),
            ConversationKind::PublicRoom => match &k.room {
                Some(room) => write!(f, " ({room})"),
                None => write!(f, " (#{})", k.name),
            },
        }
    }
}

/// The line that tells the user of `event`, escaped, or `None` if it is
/// not for the user (see the module docs). `conv` names a conversation.
pub fn notice(event: &Event, conv: &dyn Fn(ConversationId) -> Conv) -> Option<String> {
    let text = match event {
        Event::Changed(_) | Event::Connection(_) => None,
        Event::Conversation(e) => conversation(e, conv),
        Event::PinReplaced { .. } | Event::Identity(_) | Event::Confirm(_) | Event::Transfer(_) => {
            None
        }
    }?;
    Some(escaped(&text))
}

/// The one way out of [`notice`]: the whole line through [`Shown`], so
/// that no text from others is printed raw, whichever part it is in.
fn escaped(text: &str) -> String {
    Shown(text).to_string()
}

fn conversation(e: &ConversationEvent, conv: &dyn Fn(ConversationId) -> Conv) -> Option<String> {
    use ConversationEvent as E;
    Some(match e {
        E::Typing { .. } | E::Presence { .. } | E::JobDone { .. } => return None,
        E::Joined { conversation } => joined(&conv(*conversation)),
        E::Left { conversation } => left(&conv(*conversation)),
        E::Dropped {
            conversation,
            reason,
        } => dropped(&conv(*conversation), reason),
        E::MaybeSplit { conversation } => maybe_split(&conv(*conversation)),
        E::MaybeOtherBranch { conversation } => maybe_other_branch(&conv(*conversation)),
        E::CannotFollow { conversation } => cannot_follow(&conv(*conversation)),
        E::InvalidCommitAccepted { conversation } => invalid_commit(&conv(*conversation)),
        E::RoomChanged {
            conversation,
            fields,
        } => room_changed(&conv(*conversation), fields),
        E::Resynced { conversation, by } => resynced(&conv(*conversation), by.as_str()),
        E::WelcomeRefused { conversation, uid } => {
            welcome_refused(&conv(*conversation), uid.as_ref().map(|u| u.as_str()))
        }
        E::SendingHeld { conversation } => sending_held(&conv(*conversation)),
        E::SendingResumed { conversation } => sending_resumed(&conv(*conversation)),
        E::KeyCheckFailed {
            conversation,
            uid,
            repairing,
        } => key_check_failed(&conv(*conversation), uid.as_str(), *repairing),
        E::KeyFileUnavailable { conversation, uid } => {
            key_file_unavailable(&conv(*conversation), uid.as_str())
        }
        E::CouldNotResync { conversation } => could_not_resync(&conv(*conversation)),
        E::RemovalUnchecked { conversation, by } => {
            removal_unchecked(&conv(*conversation), by.as_ref().map(|u| u.as_str()))
        }
        E::OwnLeafRemoved { conversation } => own_leaf_removed(&conv(*conversation)),
        E::WelcomeForKnownGroupRefused {
            conversation,
            reason,
        } => known_group_welcome(&conv(*conversation), reason),
        E::ReportOffered { guest, .. } => report_offered(guest.as_str()),
        E::Invited {
            invitation,
            conversation,
            by,
            ..
        } => invited(*invitation, &conv(*conversation), by.as_str()),
    })
}

fn joined(c: &Conv) -> String {
    format!("joined {c}: read it with `risala read {}`", c.number)
}

fn left(c: &Conv) -> String {
    match c.peer() {
        Some(peer) if c.known.as_ref().is_some_and(|k| k.left_by_peer) => format!(
            "{peer} left {c}, so this device left it too (6.1); \
             `risala send {peer}` starts a new one"
        ),
        _ => format!("this device is no longer in {c}: it left, or was removed (6.1)"),
    }
}

fn dropped(c: &Conv, reason: &str) -> String {
    if reason.is_empty() {
        format!("the server's operator dropped {c} (10.4)")
    } else {
        format!("the server's operator dropped {c} (10.4): {reason}")
    }
}

fn maybe_split(c: &Conv) -> String {
    format!(
        "{c} may have split: another device of yours is in a different branch of the \
         group, which the server may have caused (7.7, 12.7); what you send there may not \
         reach everyone"
    )
}

fn maybe_other_branch(c: &Conv) -> String {
    format!(
        "this device may be in a branch of {c} that nobody else follows: a day after \
         joining, it reads nobody's posts there (12.8); it has asked to be added again"
    )
}

fn cannot_follow(c: &Conv) -> String {
    let then = if c.kind() == Some(ConversationKind::PublicRoom) {
        "it joins the room again by itself (6.1)".to_owned()
    } else {
        format!(
            "it reads and sends nothing there until another device of yours or a member \
             adds it again (12.7), or you leave it with `risala leave {}`",
            c.number
        )
    };
    format!(
        "this device can no longer follow {c}: posts expired on the server before it \
         read them (7.5); {then}"
    )
}

fn invalid_commit(c: &Conv) -> String {
    format!(
        "the server accepted a commit in {c} that this device holds invalid (12.7); it \
         resyncs the room, or joins it again"
    )
}

fn room_changed(c: &Conv, fields: &[String]) -> String {
    format!(
        "the server changed {} of {c} in a way that no commit this device checked \
         explains (12.7); it does not join the room again unless you accept the change, \
         which risala-cli cannot do yet",
        fields.join(", ")
    )
}

fn resynced(c: &Conv, by: &str) -> String {
    format!(
        "{by} resynced {c}, which this device followed without trouble (12.7): that may \
         be abuse, and the room's owners and moderators can ban {by}"
    )
}

fn welcome_refused(c: &Conv, uid: Option<&str>) -> String {
    let whose = uid.map_or_else(|| "a device".to_owned(), |u| format!("a device of {u}"));
    format!(
        "the server refused this device's Welcome for {whose} in {c}, so it cannot tell \
         who holds that device's place (12.8); it adds the device again where it may"
    )
}

fn sending_held(c: &Conv) -> String {
    format!(
        "sending in {c} is held: a device was added that this device could not check yet \
         (12.7); messages wait in the queue until the check is done"
    )
}

fn sending_resumed(c: &Conv) -> String {
    format!("sending in {c} goes on: the key checks are done, and queued messages go out")
}

fn key_check_failed(c: &Conv, uid: &str, repairing: bool) -> String {
    let then = if repairing {
        "this device removes it after a random wait, unless another does first"
    } else {
        "this device cannot remove it here, and hides what it sends"
    };
    format!(
        "a key check failed in {c}: a device of {uid} is not, or no longer, one that \
         {uid}'s key file vouches for (12.7); {then}"
    )
}

fn key_file_unavailable(c: &Conv, uid: &str) -> String {
    format!(
        "a key check in {c} has waited 2 hours for {uid}'s key file, which this device \
         cannot read (4.4, 12.7); nothing is removed for it, and sending there stays held \
         while the check is of a new device; try `risala identity {uid} --refresh`"
    )
}

fn could_not_resync(c: &Conv) -> String {
    format!(
        "{c} could not be resynced (12.7): the server took a commit that this device \
         could not apply, and no commit has let it join again since; it goes on once a \
         device that can apply that commit commits the waiting joins"
    )
}

fn removal_unchecked(c: &Conv, by: Option<&str>) -> String {
    let by = by.map_or_else(|| "a commit".to_owned(), |u| format!("a commit by {u}"));
    format!(
        "in {c}, {by} removed a device for a check whose reason this device could not see \
         (12.7); the removal stands"
    )
}

/// 12.7: worded for a leave and a theft alike, since the removed device
/// cannot tell them apart.
fn own_leaf_removed(c: &Conv) -> String {
    format!(
        "a device of yours left {c} or removed your other devices from it, this one or \
         another, without adding them again; if that wasn't you, that device may be \
         stolen: check your devices with `risala whoami`, and remove one that is not \
         yours with `risala remove-device`"
    )
}

fn known_group_welcome(c: &Conv, reason: &str) -> String {
    format!(
        "this device refused a Welcome that named the group of {c} but does not continue \
         it (12.8): {reason}; the conversation is unchanged"
    )
}

fn report_offered(guest: &str) -> String {
    format!(
        "{guest} wants to report something to you, as an owner or moderator of a public \
         room (5.8); risala-cli cannot take reports yet"
    )
}

fn invited(invitation: i64, c: &Conv, by: &str) -> String {
    format!(
        "invitation {invitation} back into {c} from {by} (6.1): accept it with \
         `risala invitation accept {invitation}`, or decline it with \
         `risala invitation decline {invitation}`"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use librisala::addr::ServerAddr;
    use librisala::client::types::Uid;
    use librisala::store::{AccountId, AccountKind, Store};

    fn conv(number: i64, kind: ConversationKind, name: &str, room: Option<&str>) -> Conv {
        Conv {
            number,
            known: Some(Known {
                kind,
                name: name.into(),
                room: room.map(Into::into),
                left_by_peer: false,
            }),
        }
    }

    fn garden() -> Conv {
        conv(3, ConversationKind::PrivateRoom, "garden", None)
    }

    fn plaza() -> Conv {
        conv(5, ConversationKind::PublicRoom, "plaza", Some("#plaza"))
    }

    fn account() -> AccountId {
        let store = Store::open_in_memory().unwrap();
        let server = ServerAddr::new("chat.example.org", 7472).unwrap();
        let uid: Uid = "alice@example.org".parse().unwrap();
        store
            .add_account(&server, AccountKind::Identity, &uid)
            .unwrap()
    }

    /// No notice needs a conversation.
    fn no_conv(_: ConversationId) -> Conv {
        unreachable!()
    }

    #[test]
    fn conversations_are_named_by_number_and_as_commands_name_them() {
        let direct = conv(1, ConversationKind::Direct, "bob@example.org", None);
        let own = conv(2, ConversationKind::WithYourself, "alice@example.org", None);
        let unnamed = conv(6, ConversationKind::PublicRoom, "plaza", None);
        let unknown = Conv {
            number: 7,
            known: None,
        };
        assert_eq!(direct.to_string(), "conversation 1 (with bob@example.org)");
        assert_eq!(own.to_string(), "conversation 2 (with yourself)");
        assert_eq!(garden().to_string(), "conversation 3 (#garden)");
        assert_eq!(plaza().to_string(), "conversation 5 (#plaza)");
        assert_eq!(unnamed.to_string(), "conversation 6 (#plaza)");
        assert_eq!(unknown.to_string(), "conversation 7");
    }

    #[test]
    fn an_invitation_says_how_to_answer_it() {
        assert_eq!(
            invited(4, &garden(), "bob@example.org"),
            "invitation 4 back into conversation 3 (#garden) from bob@example.org (6.1): \
             accept it with `risala invitation accept 4`, or decline it with \
             `risala invitation decline 4`"
        );
    }

    #[test]
    fn an_own_leaf_removed_is_worded_for_a_leave_and_a_theft() {
        let text = own_leaf_removed(&garden());
        assert!(
            text.starts_with("a device of yours left conversation 3 (#garden) or removed"),
            "{text}"
        );
        assert!(
            text.contains("if that wasn't you, that device may be stolen"),
            "{text}"
        );
        assert!(text.contains("`risala remove-device`"), "{text}");
    }

    #[test]
    fn what_follows_a_lost_conversation_depends_on_its_kind() {
        let text = cannot_follow(&garden());
        assert!(text.starts_with("this device can no longer follow conversation 3 (#garden)"));
        assert!(
            text.ends_with("or you leave it with `risala leave 3`"),
            "{text}"
        );
        let text = cannot_follow(&plaza());
        assert!(
            text.ends_with("it joins the room again by itself (6.1)"),
            "{text}"
        );
    }

    #[test]
    fn a_direct_conversation_the_peer_left_says_so() {
        let mut direct = conv(1, ConversationKind::Direct, "bob@example.org", None);
        assert_eq!(
            left(&direct),
            "this device is no longer in conversation 1 (with bob@example.org): it left, \
             or was removed (6.1)"
        );
        if let Some(k) = &mut direct.known {
            k.left_by_peer = true;
        }
        assert_eq!(
            left(&direct),
            "bob@example.org left conversation 1 (with bob@example.org), so this device \
             left it too (6.1); `risala send bob@example.org` starts a new one"
        );
    }

    #[test]
    fn key_checks_say_what_this_device_does() {
        let text = key_check_failed(&garden(), "bob@example.org", true);
        assert!(text.starts_with("a key check failed in conversation 3 (#garden)"));
        assert!(text.ends_with("unless another does first"), "{text}");
        let text = key_check_failed(&garden(), "bob@example.org", false);
        assert!(text.ends_with("hides what it sends"), "{text}");
        let text = key_file_unavailable(&garden(), "bob@example.org");
        assert!(text.contains("waited 2 hours for bob@example.org's key file"));
        assert!(text.ends_with("`risala identity bob@example.org --refresh`"));
        let text = removal_unchecked(&garden(), None);
        assert!(text.starts_with("in conversation 3 (#garden), a commit removed"));
        let text = removal_unchecked(&garden(), Some("bob@example.org"));
        assert!(text.starts_with("in conversation 3 (#garden), a commit by bob@example.org"));
    }

    #[test]
    fn room_notices_name_the_room() {
        assert!(
            could_not_resync(&plaza()).starts_with("conversation 5 (#plaza) could not be resynced")
        );
        assert!(
            invalid_commit(&plaza())
                .contains("in conversation 5 (#plaza) that this device holds invalid")
        );
        let fields = ["owners".to_owned(), "topic".to_owned()];
        let text = room_changed(&plaza(), &fields);
        assert!(text.starts_with("the server changed owners, topic of conversation 5 (#plaza)"));
        assert!(
            resynced(&plaza(), "bob@example.org")
                .starts_with("bob@example.org resynced conversation 5")
        );
        assert_eq!(
            dropped(&garden(), ""),
            "the server's operator dropped conversation 3 (#garden) (10.4)"
        );
        assert_eq!(
            dropped(&garden(), "spam"),
            "the server's operator dropped conversation 3 (#garden) (10.4): spam"
        );
    }

    #[test]
    fn sending_held_and_resumed() {
        assert!(sending_held(&garden()).starts_with("sending in conversation 3 (#garden) is held"));
        assert!(
            sending_resumed(&garden()).starts_with("sending in conversation 3 (#garden) goes on")
        );
    }

    #[test]
    fn routine_events_are_not_told() {
        let account = account();
        for event in [
            Event::Conversation(ConversationEvent::Presence {
                account,
                uids: vec!["bob@example.org".parse().unwrap()],
                online: true,
            }),
            Event::Connection(librisala::client::ConnectionEvent {
                account,
                slot: librisala::conn::Slot::SignedIn,
                state: librisala::client::ConnectionState::Ready,
            }),
        ] {
            assert_eq!(notice(&event, &no_conv), None, "{event:?}");
        }
    }

    /// Moves the cursor up, clears the line, writes a command there, then
    /// reverses what follows.
    const EVIL: &str = "x\u{1b}[2A\u{1b}[2K\rrisala invitation accept 9\n\t\u{9b}K\u{202e}y";
    const EVIL_SHOWN: &str =
        "x\\u{1b}[2A\\u{1b}[2K\\u{d}risala invitation accept 9\\u{a}\\u{9}\\u{9b}K\\u{202e}y";

    #[test]
    fn names_from_others_are_escaped() {
        let evil = conv(3, ConversationKind::PrivateRoom, EVIL, None);
        let lines = [
            escaped(&joined(&evil)),
            escaped(&invited(4, &evil, "bob@example.org")),
            escaped(&dropped(&evil, EVIL)),
            escaped(&room_changed(&evil, &[EVIL.to_owned()])),
            escaped(&known_group_welcome(&evil, EVIL)),
        ];
        for line in lines {
            assert!(
                line.contains(&format!("conversation 3 (#{EVIL_SHOWN})")),
                "{line}"
            );
            assert!(!line.chars().any(char::is_control), "{line:?}");
            assert!(!line.contains(['\u{1b}', '\u{9b}', '\u{202e}']), "{line:?}");
        }
    }
}
