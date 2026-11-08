//! The content lines inside an encrypted message (12.8): one TEXT line,
//! or any number of KEY and RECOVERY lines.
//!
//! ```text
//! [@<tags>] TEXT <text...>
//! KEY <id> <epoch> <key>
//! RECOVERY <key>
//! ```
//!
//! Each line ends in LF and follows the character rules of 2.3, but not
//! its length limits. Lines with verbs a device does not know are ignored.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use risala_mls::message::{MESSAGE_ID_LEN, MessageId};
use risala_mls::{HistoryKey, RecoveryKey};
use risala_proto::line::Line;
use risala_proto::names::Id;
use risala_proto::types::{MAX_REACTION, MediaType, Relation};

/// The most bytes a TEXT line's text may have, as for MSG (12.8).
pub(crate) const MAX_TEXT: usize = 8192;

/// The length of a file's key (12.11).
pub(crate) const FILE_KEY_LEN: usize = 32;

/// A reply, edit or reaction inside the encryption: the target's seq, as
/// in 5.3, and its `message_id` (12.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Target {
    /// The relation and the target's seq.
    pub relation: Relation,
    /// The target's `message_id`, from the `target` tag.
    pub message_id: MessageId,
}

/// A TEXT line (12.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Text {
    /// The text, escaped (3.4), not blank.
    pub text: String,
    /// The `reply`, `edit` or `react` tag with its `target`.
    pub target: Option<Target>,
    /// The `file-key` and `file-type` tags, for a file (12.11).
    pub file: Option<([u8; FILE_KEY_LEN], MediaType)>,
}

/// A KEY or RECOVERY line (12.9, 12.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Control {
    /// `KEY <id> <epoch> <key>`: a history key.
    Key {
        /// The conversation's id.
        id: Id,
        /// The epoch.
        epoch: u64,
        /// The key.
        key: HistoryKey,
    },
    /// `RECOVERY <key>`: the identity's recovery key.
    Recovery(RecoveryKey),
}

/// What a message's content holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Content {
    /// A message.
    Text(Text),
    /// History keys and a recovery key. Lines of unknown verbs are left
    /// out, so this may be empty.
    Control(Vec<Control>),
}

/// Why content is not acceptable. A device treats it as a message that
/// could not be read (12.8, step 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ContentError {
    /// Not UTF-8 lines ending in LF, or a line does not parse.
    #[error("the content is not lines")]
    Lines,
    /// A TEXT line with other lines, or a known line with bad values.
    #[error("the content is malformed")]
    Malformed,
}

impl Content {
    /// Reads the content of a decrypted message (12.8).
    pub(crate) fn parse(bytes: &[u8]) -> Result<Content, ContentError> {
        let text = std::str::from_utf8(bytes).map_err(|_| ContentError::Lines)?;
        let Some(body) = text.strip_suffix('\n') else {
            return Err(ContentError::Lines);
        };
        let mut texts = Vec::new();
        let mut controls = Vec::new();
        for raw in body.split('\n') {
            let line = Line::parse(raw).map_err(|_| ContentError::Lines)?;
            match line.verb_upper().as_ref() {
                "TEXT" => texts.push(parse_text(&line)?),
                "KEY" => controls.push(parse_key(&line)?),
                "RECOVERY" => controls.push(parse_recovery(&line)?),
                _ => {}
            }
        }
        match (texts.len(), controls.is_empty()) {
            (0, _) => Ok(Content::Control(controls)),
            (1, true) => Ok(Content::Text(texts.pop().expect("one"))),
            _ => Err(ContentError::Malformed),
        }
    }

    /// The content's bytes: the lines, each ending in LF.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = String::new();
        match self {
            Content::Text(text) => {
                out.push_str(&text_line(text));
                out.push('\n');
            }
            Content::Control(lines) => {
                for line in lines {
                    match line {
                        Control::Key { id, epoch, key } => {
                            out.push_str(&format!("KEY {id} {epoch} {}\n", *key.to_base64()));
                        }
                        Control::Recovery(key) => {
                            out.push_str(&format!("RECOVERY {}\n", *key.to_base64()));
                        }
                    }
                }
            }
        }
        out.into_bytes()
    }
}

fn text_line(text: &Text) -> String {
    let mut tags = Vec::new();
    if let Some(target) = &text.target {
        tags.push(format!(
            "{}={}",
            target.relation.key(),
            target.relation.seq()
        ));
        tags.push(format!("target={}", BASE64.encode(target.message_id)));
    }
    if let Some((key, media_type)) = &text.file {
        tags.push(format!("file-key={}", BASE64.encode(key)));
        tags.push(format!("file-type={media_type}"));
    }
    if tags.is_empty() {
        format!("TEXT {}", text.text)
    } else {
        format!("@{} TEXT {}", tags.join(";"), text.text)
    }
}

fn parse_text(line: &Line) -> Result<Text, ContentError> {
    let tags = line.tags();
    let mut relation = None;
    for key in Relation::KEYS {
        let Some(value) = tags.entry(key) else {
            continue;
        };
        if let Some(r) = Relation::from_tag(key, value).map_err(|_| ContentError::Malformed)? {
            if relation.is_some() {
                return Err(ContentError::Malformed);
            }
            relation = Some(r);
        }
    }
    let target = match (relation, tags.get("target")) {
        (Some(relation), Some(mid)) => Some(Target {
            relation,
            message_id: decode_fixed::<MESSAGE_ID_LEN>(mid)?,
        }),
        (None, None) => None,
        _ => return Err(ContentError::Malformed),
    };
    let file = match (tags.get("file-key"), tags.get("file-type")) {
        (Some(key), Some(media_type)) => Some((
            decode_fixed::<FILE_KEY_LEN>(key)?,
            media_type
                .parse::<MediaType>()
                .map_err(|_| ContentError::Malformed)?,
        )),
        (None, None) => None,
        _ => return Err(ContentError::Malformed),
    };
    let text = line.params().text();
    if text.is_empty()
        || text.len() > MAX_TEXT
        || risala_proto::text::is_blank(text)
        || matches!(relation, Some(Relation::React(_))) && text.len() > MAX_REACTION
    {
        return Err(ContentError::Malformed);
    }
    Ok(Text {
        text: text.to_owned(),
        target,
        file,
    })
}

fn parse_key(line: &Line) -> Result<Control, ContentError> {
    let mut p = line.params();
    let id: Id = p
        .token()
        .ok()
        .and_then(|t| t.parse().ok())
        .ok_or(ContentError::Malformed)?;
    let epoch: u64 = p
        .token()
        .ok()
        .and_then(|t| t.parse().ok())
        .filter(|e| *e <= i64::MAX as u64)
        .ok_or(ContentError::Malformed)?;
    let key = p
        .token()
        .ok()
        .and_then(HistoryKey::from_base64)
        .ok_or(ContentError::Malformed)?;
    p.end().map_err(|_| ContentError::Malformed)?;
    Ok(Control::Key { id, epoch, key })
}

fn parse_recovery(line: &Line) -> Result<Control, ContentError> {
    let mut p = line.params();
    let key = p
        .token()
        .ok()
        .and_then(RecoveryKey::from_base64)
        .ok_or(ContentError::Malformed)?;
    p.end().map_err(|_| ContentError::Malformed)?;
    Ok(Control::Recovery(key))
}

/// Exactly `N` bytes in strict base64 with padding.
fn decode_fixed<const N: usize>(text: &str) -> Result<[u8; N], ContentError> {
    if !risala_proto::mls::is_strict_base64(text) {
        return Err(ContentError::Malformed);
    }
    let mut out = [0; N];
    match BASE64.decode_slice(text, &mut out) {
        Ok(n) if n == N && text.len() == N.div_ceil(3) * 4 => Ok(out),
        _ => Err(ContentError::Malformed),
    }
}

/// The `target` of a message id, as a TEXT line carries it.
#[cfg(test)]
pub(crate) fn target_text(id: &MessageId) -> String {
    BASE64.encode(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use risala_proto::names::Seq;

    fn seq(n: u64) -> Seq {
        Seq::new(n).unwrap()
    }

    #[test]
    fn text_round_trip() {
        let plain = Content::Text(Text {
            text: "hello\\sthere".into(),
            target: None,
            file: None,
        });
        assert_eq!(plain.encode(), b"TEXT hello\\sthere\n");
        assert_eq!(Content::parse(&plain.encode()), Ok(plain));

        let reply = Content::Text(Text {
            text: "see you at 12".into(),
            target: Some(Target {
                relation: Relation::Reply(seq(15)),
                message_id: [7; 16],
            }),
            file: None,
        });
        let bytes = reply.encode();
        assert_eq!(
            bytes,
            format!(
                "@reply=15;target={} TEXT see you at 12\n",
                target_text(&[7; 16])
            )
            .as_bytes()
        );
        assert_eq!(Content::parse(&bytes), Ok(reply));
    }

    /// The example of 12.8.
    #[test]
    fn spec_example() {
        let line = b"@reply=15;target=0Jx1HkY3x9z2b5R0qWm1fA== TEXT see you at 12\n";
        let Content::Text(text) = Content::parse(line).unwrap() else {
            panic!("a TEXT line");
        };
        assert_eq!(text.text, "see you at 12");
        assert_eq!(text.target.unwrap().relation, Relation::Reply(seq(15)));
    }

    #[test]
    fn keys_round_trip() {
        let id: Id = "d7hq2klm".parse().unwrap();
        let content = Content::Control(vec![
            Control::Key {
                id: id.clone(),
                epoch: 0,
                key: HistoryKey::from_bytes([1; 48]),
            },
            Control::Key {
                id,
                epoch: 7,
                key: HistoryKey::from_bytes([2; 48]),
            },
            Control::Recovery(RecoveryKey::from_bytes([3; 32])),
        ]);
        assert_eq!(Content::parse(&content.encode()), Ok(content));
        // Unknown verbs are ignored.
        assert_eq!(
            Content::parse(b"FUTURE x y\n"),
            Ok(Content::Control(Vec::new()))
        );
    }

    #[test]
    fn bad_content() {
        for bad in [
            &b"TEXT hi"[..],
            b"TEXT \n",
            b"TEXT  \n",
            b"TEXT a\nTEXT b\n",
            b"TEXT a\nRECOVERY AAAA\n",
            b"@reply=3 TEXT a\n",
            b"@target=AAAA TEXT a\n",
            b"@reply=3;edit=4;target=0Jx1HkY3x9z2b5R0qWm1fA== TEXT a\n",
            b"@file-key=AAAA TEXT a\n",
            b"KEY d7hq2klm 1 AAAA\n",
            b"KEY d7hq2klm x AAAA\n",
            b"\xff\n",
            b"TEXT a\rb\n",
        ] {
            assert!(
                Content::parse(bad).is_err(),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
        let long = format!(
            "@react=1;target={} TEXT {}\n",
            target_text(&[0; 16]),
            "x".repeat(65)
        );
        assert!(Content::parse(long.as_bytes()).is_err());
        let ok = format!("TEXT {}\n", "x".repeat(MAX_TEXT));
        assert!(Content::parse(ok.as_bytes()).is_ok());
        let over = format!("TEXT {}\n", "x".repeat(MAX_TEXT + 1));
        assert!(Content::parse(over.as_bytes()).is_err());
    }
}
