//! Helpers for the end-to-end tests: transcripts played against a
//! [`TestServer`] over TLS, and the example sessions of SPEC.md and
//! README.md.
//!
//! A transcript is written as in the spec, one line each:
//!
//! ```text
//! C: join #general                 the first client sends a line
//! S: OK id={id} head=1             the first client receives a line
//! bob C: msg #general hi           the client called bob sends a line
//! bob S: @seq=2;t={*};from=~bob MSG #general hi
//! ```
//!
//! In an expected line, `{*}` matches any value, and `{name}` matches a
//! value and binds it, so later uses of `{name}` must be the same. A value
//! runs up to the next space or `;`. `{..}` matches the rest of the line,
//! even nothing, as in `ERR forbidden{..}` for an error whose message is
//! for people. Blank lines are skipped. Every line received must also
//! parse as a [`ServerMessage`].

#![allow(dead_code)]

use std::collections::HashMap;

use risala_proto::server::ServerMessage;
use risala_server::store::{EventKind, NewEvent, SqliteStore, Store as _};
use risala_server::testing::TestClient;

/// The text of SPEC.md.
pub const SPEC: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../SPEC.md"));

/// The text of README.md.
pub const README: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../README.md"));

/// Clients talking to one server, by name, and the values bound so far.
#[derive(Debug, Default)]
pub struct Session {
    clients: Vec<(String, TestClient)>,
    vars: HashMap<String, String>,
}

impl Session {
    pub fn new() -> Session {
        Session::default()
    }

    /// Adds a client. The first one is the default for lines with no name.
    pub fn add(&mut self, name: &str, client: TestClient) {
        self.clients.push((name.to_owned(), client));
    }

    /// The client called `name`.
    pub fn client(&mut self, name: &str) -> &mut TestClient {
        &mut self
            .clients
            .iter_mut()
            .find(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("no client called {name}"))
            .1
    }

    /// Removes the client called `name` and returns it.
    pub fn take(&mut self, name: &str) -> TestClient {
        let i = self
            .clients
            .iter()
            .position(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("no client called {name}"));
        self.clients.remove(i).1
    }

    /// A value bound by `{name}`.
    pub fn var(&self, name: &str) -> &str {
        self.vars
            .get(name)
            .unwrap_or_else(|| panic!("{{{name}}} is not bound"))
    }

    /// Binds a value, as if `{name}` had matched it.
    pub fn bind(&mut self, name: &str, value: &str) {
        self.vars.insert(name.to_owned(), value.to_owned());
    }

    /// Plays a transcript: sends each `C:` line and checks each `S:` line.
    pub async fn play(&mut self, script: &str) {
        for raw in script.lines() {
            let line = raw.trim();
            if line.is_empty() {
                continue;
            }
            let (who, rest) = if line.starts_with("C: ") || line.starts_with("S: ") {
                (self.clients[0].0.clone(), line)
            } else {
                let (who, rest) = line
                    .split_once(' ')
                    .unwrap_or_else(|| panic!("bad script line {line:?}"));
                (who.to_owned(), rest)
            };
            if let Some(sent) = rest.strip_prefix("C: ") {
                self.client(&who).send(sent).await.unwrap();
            } else if let Some(want) = rest.strip_prefix("S: ") {
                let got = recv(self.client(&who)).await;
                if let Err(e) = matches(want, &got, &mut self.vars) {
                    panic!("{who} expected\n  {want}\ngot\n  {got}\n({e})");
                }
            } else {
                panic!("bad script line {line:?}");
            }
        }
    }

    /// Checks a line `who` received against the pattern `want`, binding
    /// values as [`play`](Self::play) does.
    pub fn check(&mut self, who: &str, want: &str, got: &str) {
        if let Err(e) = matches(want, got, &mut self.vars) {
            panic!("{who} expected\n  {want}\ngot\n  {got}\n({e})");
        }
    }

    /// Checks that nothing more is waiting for any client.
    pub async fn settled(&mut self) {
        for (_, client) in &mut self.clients {
            settled(client).await;
        }
    }
}

/// `who` joins `room`, and its JOIN, the settings and the OK are read.
/// Returns the OK.
pub async fn join(s: &mut Session, who: &str, room: &str) -> String {
    let lines = command(s.client(who), &format!("join {room}")).await;
    let ok = lines.last().unwrap().clone();
    assert!(ok.starts_with("OK id="), "{who}: {lines:?}");
    ok
}

/// Reads one line from `who` and checks it against the pattern.
pub async fn expect(s: &mut Session, who: &str, want: &str) {
    let got = recv(s.client(who)).await;
    s.check(who, want, &got);
}

/// Sends `line` as `who`, and checks that every line up to the final OK or
/// ERR matches `want`, in order. A pattern that starts with `*` matches a
/// line that ends with the rest, and `*` alone matches any line.
pub async fn exchange(s: &mut Session, who: &str, line: &str, want: &[&str]) {
    s.client(who).send(line).await.unwrap();
    for w in want {
        let got = recv(s.client(who)).await;
        if let Some(end) = w.strip_prefix('*') {
            assert!(
                got.ends_with(end),
                "{who}: {line}: expected\n  {w}\ngot\n  {got}"
            );
        } else {
            s.check(who, w, &got);
        }
    }
}

/// Receives a line, checking that it parses as a server line.
pub async fn recv(client: &mut TestClient) -> String {
    let line = client.expect_line().await.unwrap();
    if let Err(e) = line.parse::<ServerMessage>() {
        panic!("the server sent a line that does not parse: {line:?}: {e}");
    }
    line
}

/// Sends `line` and returns every line received up to and including the
/// final `OK` or `ERR`.
pub async fn command(client: &mut TestClient, line: &str) -> Vec<String> {
    client.send(line).await.unwrap();
    let mut lines = Vec::new();
    loop {
        let got = recv(client).await;
        let verb = got
            .strip_prefix('@')
            .and_then(|l| l.split_once(' '))
            .map_or(got.as_str(), |(_, rest)| rest)
            .split(' ')
            .next()
            .unwrap_or("")
            .to_owned();
        lines.push(got);
        if verb == "OK" || verb == "ERR" {
            return lines;
        }
    }
}

/// Checks that nothing is waiting for `client`: a PING's `OK` comes next.
/// Anything the server queued for it before the PING would come first.
pub async fn settled(client: &mut TestClient) {
    client.send("@ref=settled PING").await.unwrap();
    let got = recv(client).await;
    assert_eq!(got, "@ref=settled OK", "an unexpected line was waiting");
}

/// Reads until the server closes, and returns the lines it sent first.
pub async fn until_closed(client: &mut TestClient) -> Vec<String> {
    client.recv_until_closed().await.unwrap()
}

/// The value of `key=` in a line, from its tags or its options.
pub fn value(line: &str, key: &str) -> String {
    line.split([' ', ';', '@'])
        .find_map(|part| part.strip_prefix(key)?.strip_prefix('='))
        .unwrap_or_else(|| panic!("no {key}= in {line:?}"))
        .to_owned()
}

/// Whether `got` matches the pattern `want`, binding `{name}`s in `vars`.
pub fn matches(want: &str, got: &str, vars: &mut HashMap<String, String>) -> Result<(), String> {
    let mut want = want;
    let mut got = got;
    let mut bound = Vec::new();
    loop {
        let Some(start) = want.find('{') else {
            if want != got {
                return Err(format!("differs at {got:?}"));
            }
            break;
        };
        let (lit, rest) = want.split_at(start);
        got = got
            .strip_prefix(lit)
            .ok_or_else(|| format!("expected {lit:?} at {got:?}"))?;
        let end = rest.find('}').expect("an unclosed {");
        let name = &rest[1..end];
        want = &rest[end + 1..];
        if name == ".." {
            assert!(want.is_empty(), "{{..}} must end the line");
            break;
        }
        let len = got.find([' ', ';']).unwrap_or(got.len());
        let (value, after) = got.split_at(len);
        if value.is_empty() {
            return Err(format!("no value for {{{name}}}"));
        }
        got = after;
        if name != "*" {
            match vars.get(name) {
                Some(old) if old != value => {
                    return Err(format!("{{{name}}} was {old:?}, now {value:?}"));
                }
                Some(_) => {}
                None => bound.push((name.to_owned(), value.to_owned())),
            }
        }
    }
    vars.extend(bound);
    Ok(())
}

/// Appends an event to `room` straight in the store, as if it had happened
/// before the server started.
pub fn put(store: &SqliteStore, room: &str, from: &str, kind: EventKind) {
    let key = store
        .room(&room.parse().unwrap())
        .unwrap()
        .expect("the room exists")
        .key;
    let event = NewEvent {
        t: risala_proto::time::Timestamp::now(),
        from: from.parse().unwrap(),
        kind,
        cid: None,
    };
    store.append(key, &event).unwrap();
}

/// A plain message, for [`put`].
pub fn msg(text: &str) -> EventKind {
    EventKind::Msg {
        relation: None,
        file: None,
        text: text.into(),
    }
}

/// One example session from a document, as transcript lines.
#[derive(Debug, Clone)]
pub struct Example {
    /// The lines, each `C: ...` or `S: ...`.
    pub lines: Vec<String>,
}

impl Example {
    /// The transcript, with the values that change from run to run
    /// replaced by patterns: times, the greeting's nonce, a guest's token,
    /// and the room id `k3f9q2`, which becomes `{id}`.
    pub fn script(&self) -> String {
        self.lines
            .iter()
            .map(|l| mask(l))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The lines up to and including the first that contains `needle`.
    pub fn until(&self, needle: &str) -> Example {
        let end = self
            .lines
            .iter()
            .position(|l| l.contains(needle))
            .unwrap_or_else(|| panic!("no line contains {needle:?}"));
        Example {
            lines: self.lines[..=end].to_vec(),
        }
    }

    /// The lines after the first that contains `needle`.
    pub fn after(&self, needle: &str) -> Example {
        let start = self
            .lines
            .iter()
            .position(|l| l.contains(needle))
            .unwrap_or_else(|| panic!("no line contains {needle:?}"));
        Example {
            lines: self.lines[start + 1..].to_vec(),
        }
    }
}

fn mask(line: &str) -> String {
    let (dir, text) = line.split_at(3);
    let mut text = text.replace("k3f9q2", "{id}");
    if text.starts_with("RISALA ") {
        // RISALA <version> <host> <nonce> [<message...>]
        let mut parts: Vec<&str> = text.splitn(5, ' ').collect();
        parts[3] = "{*}";
        text = parts.join(" ");
    }
    if text.starts_with("OK uid=~") {
        // OK uid=~<name> token=<token> (4.2). The example in SPEC.md 1.4
        // leaves the token out.
        let uid = text.split(' ').nth(1).unwrap_or_default();
        text = format!("OK {uid} token={{*}}");
    }
    if let Some(tags_end) = text.strip_prefix('@').and_then(|t| t.find(' ')) {
        let tags: Vec<String> = text[1..=tags_end]
            .split(';')
            .map(|tag| match tag.strip_prefix("t=") {
                Some(_) => "t={*}".to_owned(),
                None => tag.to_owned(),
            })
            .collect();
        text = format!("@{}{}", tags.join(";"), &text[tags_end + 1..]);
    }
    format!("{dir}{text}")
}

/// The fenced code blocks of a Markdown document, each as its lines.
fn code_blocks(doc: &str) -> Vec<Vec<&str>> {
    let mut blocks = Vec::new();
    let mut current: Option<Vec<&str>> = None;
    for line in doc.lines() {
        if line.trim_start().starts_with("```") {
            match current.take() {
                Some(block) => blocks.push(block),
                None => current = Some(Vec::new()),
            }
        } else if let Some(block) = &mut current {
            block.push(line);
        }
    }
    blocks
}

/// The `C:` and `S:` lines of the first code block that has any, after
/// the heading that starts with `heading` in SPEC.md.
pub fn spec_example(heading: &str) -> Example {
    let start = SPEC
        .find(&format!("\n{heading}"))
        .unwrap_or_else(|| panic!("SPEC.md has no heading {heading:?}"));
    let lines: Vec<String> = code_blocks(&SPEC[start..])
        .into_iter()
        .map(|block| {
            block
                .into_iter()
                .filter(|l| l.starts_with("C: ") || l.starts_with("S: "))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .find(|lines| !lines.is_empty())
        .unwrap_or_else(|| panic!("no example lines under {heading:?}"));
    Example { lines }
}

/// The session in README.md: the lines after `$ openssl s_client` in its
/// first code block. The direction comes from the verb's case: people
/// type lower case, and servers send upper case (3.1).
pub fn readme_example() -> Example {
    let block = code_blocks(README)
        .into_iter()
        .find(|b| b.iter().any(|l| l.starts_with("$ openssl s_client")))
        .expect("README.md has an openssl session");
    let lines = block
        .into_iter()
        .skip_while(|l| !l.starts_with("$ openssl s_client"))
        .skip(1)
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let verb = l
                .strip_prefix('@')
                .and_then(|l| l.split_once(' '))
                .map_or(l, |(_, rest)| rest)
                .split(' ')
                .next()
                .unwrap();
            if verb.bytes().all(|b| b.is_ascii_uppercase()) {
                format!("S: {l}")
            } else {
                format!("C: {l}")
            }
        })
        .collect();
    Example { lines }
}
