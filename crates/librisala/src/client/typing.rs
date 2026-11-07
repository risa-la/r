//! Who is typing where (8.1), kept in memory while connected.

use std::collections::HashMap;
use std::time::Duration;

use risala_proto::names::{Conv, Uid};
use tokio::time::Instant;

/// How long a typing notice lasts (8.1).
pub(crate) const TYPING_LASTS: Duration = Duration::from_secs(6);

/// Who is typing in each conversation, and until when. It has no clock:
/// callers pass the time.
#[derive(Debug, Default)]
pub(crate) struct Typists {
    /// By conversation: who, in the order they started, and when their
    /// notice runs out.
    convs: HashMap<Conv, Vec<(Uid, Instant)>>,
}

impl Typists {
    /// `from` is typing in `conv`, as of `now`. Returns whether the set of
    /// typists there changed; a repeated notice only extends it.
    pub fn typing(&mut self, conv: &Conv, from: &Uid, now: Instant) -> bool {
        let until = now + TYPING_LASTS;
        let list = self.convs.entry(conv.clone()).or_default();
        match list.iter_mut().find(|(u, _)| u == from) {
            Some((_, at)) => {
                *at = until;
                false
            }
            None => {
                list.push((from.clone(), until));
                true
            }
        }
    }

    /// `from` sent a message in `conv`, which ends their typing. Returns
    /// whether they were typing.
    pub fn spoke(&mut self, conv: &Conv, from: &Uid) -> bool {
        let Some(list) = self.convs.get_mut(conv) else {
            return false;
        };
        let before = list.len();
        list.retain(|(u, _)| u != from);
        let changed = list.len() != before;
        if list.is_empty() {
            self.convs.remove(conv);
        }
        changed
    }

    /// Drops the notices that ran out by `now`. Returns the conversations
    /// whose typists changed.
    pub fn expire(&mut self, now: Instant) -> Vec<Conv> {
        let mut changed = Vec::new();
        self.convs.retain(|conv, list| {
            let before = list.len();
            list.retain(|(_, until)| *until > now);
            if list.len() != before {
                changed.push(conv.clone());
            }
            !list.is_empty()
        });
        changed.sort();
        changed
    }

    /// When the next notice runs out, if any.
    pub fn next_expiry(&self) -> Option<Instant> {
        self.convs
            .values()
            .flat_map(|l| l.iter().map(|(_, at)| *at))
            .min()
    }

    /// Forgets everyone, as when the connection closes. Returns the
    /// conversations that had typists.
    pub fn clear(&mut self) -> Vec<Conv> {
        let mut convs: Vec<Conv> = self.convs.drain().map(|(c, _)| c).collect();
        convs.sort();
        convs
    }

    /// Who is typing in `conv`, in the order they started.
    pub fn who(&self, conv: &Conv) -> Vec<Uid> {
        self.convs
            .get(conv)
            .map(|l| l.iter().map(|(u, _)| u.clone()).collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conv(s: &str) -> Conv {
        s.parse().unwrap()
    }

    fn uid(s: &str) -> Uid {
        s.parse().unwrap()
    }

    #[test]
    fn notices_last_six_seconds_and_messages_end_them() {
        let mut t = Typists::default();
        let general = conv("#general");
        let (bob, carol) = (uid("bob@example.net"), uid("~carol"));
        let t0 = Instant::now();
        assert!(t.typing(&general, &bob, t0));
        assert!(t.typing(&general, &carol, t0 + Duration::from_secs(1)));
        assert_eq!(t.who(&general), [bob.clone(), carol.clone()]);
        // A repeat extends the notice without changing the set.
        assert!(!t.typing(&general, &bob, t0 + Duration::from_secs(4)));
        assert_eq!(t.next_expiry(), Some(t0 + Duration::from_secs(7)));
        // Carol's runs out at 7 s, Bob's at 10 s.
        assert!(t.expire(t0 + Duration::from_secs(6)).is_empty());
        assert_eq!(t.expire(t0 + Duration::from_secs(7)), std::slice::from_ref(&general));
        assert_eq!(t.who(&general), std::slice::from_ref(&bob));
        // Bob's message ends it at once.
        assert!(t.spoke(&general, &bob));
        assert!(!t.spoke(&general, &bob));
        assert!(t.who(&general).is_empty());
        assert_eq!(t.next_expiry(), None);

        assert!(t.typing(&conv("#dev"), &bob, t0));
        assert!(t.typing(&general, &bob, t0));
        assert_eq!(t.clear(), [conv("#dev"), general.clone()]);
        assert!(t.who(&general).is_empty());
    }
}
