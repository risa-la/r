//! The body of a hand-off request to a witness, `POST <witness URL
//! prefix>/risala/handoff` (SPEC 4.10): the host shows each witness of log
//! `n`-1 the hand-off entry naming log `n`, before log `n`'s first
//! checkpoint, since the cosignatures do not cover anything a witness
//! could learn the next log from.
//!
//! ```text
//! risala-handoff/1
//! index <index of the hand-off entry>
//! <the encoded LogEntry, base64>
//! <inclusion proof hash, base64>
//! …
//!
//! <the checkpoint of log n-1 that includes it, a signed note>
//! ```
//!
//! Every line ends with LF. Base64 is strict, with padding.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use thiserror::Error;

use crate::checkpoint::{CheckpointError, SignedCheckpoint, parse_decimal};
use crate::entry::MAX_ENTRY_LEN;
use crate::merkle::Hash;

/// The path of the request, under a witness's URL prefix (SPEC 4.10, 15).
pub const HANDOFF_PATH: &str = "risala/handoff";

/// The first line of the request body (SPEC 4.10, 15).
pub const HANDOFF_HEADER: &str = "risala-handoff/1";

/// The most inclusion proof hashes a request may have: one per level of a
/// tree of 2^64 entries.
pub const MAX_PROOF_LINES: usize = 64;

/// A hand-off request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandoffRequest {
    /// The index of the hand-off entry in log `n`-1.
    pub index: u64,
    /// The encoded LogEntry.
    pub entry: Vec<u8>,
    /// Its inclusion proof in the checkpoint's tree.
    pub proof: Vec<Hash>,
    /// The checkpoint of log `n`-1 whose last entry is the hand-off.
    pub checkpoint: SignedCheckpoint,
}

/// Why a hand-off request body did not parse.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HandoffRequestError {
    /// The lines before the checkpoint are malformed.
    #[error("malformed hand-off request: {0}")]
    Malformed(&'static str),
    /// The checkpoint is malformed.
    #[error(transparent)]
    Checkpoint(#[from] CheckpointError),
}

impl HandoffRequest {
    /// The request body.
    pub fn to_body(&self) -> String {
        let mut s = format!(
            "{HANDOFF_HEADER}\nindex {}\n{}\n",
            self.index,
            BASE64.encode(&self.entry)
        );
        for h in &self.proof {
            s.push_str(&h.to_base64());
            s.push('\n');
        }
        s.push('\n');
        s.push_str(&self.checkpoint.to_text());
        s
    }

    /// Parses a request body. The entry is not decoded here; the witness
    /// decodes it as a LogEntry.
    pub fn parse(body: &[u8]) -> Result<HandoffRequest, HandoffRequestError> {
        let split =
            body.windows(2)
                .position(|w| w == b"\n\n")
                .ok_or(HandoffRequestError::Malformed(
                    "no blank line before the checkpoint",
                ))?;
        let head = std::str::from_utf8(&body[..split])
            .map_err(|_| HandoffRequestError::Malformed("not UTF-8"))?;
        let mut lines = head.split('\n');
        if lines.next() != Some(HANDOFF_HEADER) {
            return Err(HandoffRequestError::Malformed(
                "does not start with risala-handoff/1",
            ));
        }
        let index = lines
            .next()
            .and_then(|l| l.strip_prefix("index "))
            .and_then(parse_decimal)
            .ok_or(HandoffRequestError::Malformed("no index"))?;
        let entry = lines
            .next()
            .filter(|l| l.len() <= MAX_ENTRY_LEN.div_ceil(3) * 4)
            .and_then(|l| BASE64.decode(l).ok())
            .filter(|e| !e.is_empty())
            .ok_or(HandoffRequestError::Malformed("no entry"))?;
        let proof = lines
            .map(|l| Hash::from_base64(l).ok_or(HandoffRequestError::Malformed("bad proof hash")))
            .collect::<Result<Vec<_>, _>>()?;
        if proof.len() > MAX_PROOF_LINES {
            return Err(HandoffRequestError::Malformed("too many proof lines"));
        }
        let checkpoint = SignedCheckpoint::parse(&body[split + 2..])?;
        Ok(HandoffRequest {
            index,
            entry,
            proof,
            checkpoint,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::Checkpoint;
    use crate::merkle::leaf_hash;
    use crate::note::NoteSignature;

    fn request(proof: Vec<Hash>) -> HandoffRequest {
        let cp = Checkpoint::new("log.example/risala-log/1", 3, leaf_hash(b"r")).unwrap();
        let mut checkpoint = SignedCheckpoint::unsigned(cp);
        checkpoint
            .push_signature(NoteSignature {
                name: "log.example/risala-log/1".into(),
                key_id: 7,
                signature: vec![1, 2, 3],
            })
            .unwrap();
        HandoffRequest {
            index: 2,
            entry: b"\x01\x02entry".to_vec(),
            proof,
            checkpoint,
        }
    }

    #[test]
    fn round_trips() {
        for proof in [vec![], vec![leaf_hash(b"a"), leaf_hash(b"b")]] {
            let r = request(proof);
            let body = r.to_body();
            assert!(body.starts_with("risala-handoff/1\nindex 2\nAQJlbnRyeQ==\n"));
            assert_eq!(HandoffRequest::parse(body.as_bytes()), Ok(r));
        }
    }

    #[test]
    fn rejects_malformed_bodies() {
        let body = request(vec![leaf_hash(b"a")]).to_body();
        let cp = &body[body.find("\n\n").unwrap() + 2..];
        let hash = leaf_hash(b"a").to_base64();
        // The version line comes first (SPEC 4.10).
        for bad in [
            format!("index 2\nAQJlbnRyeQ==\n\n{cp}"),
            format!("risala-handoff/2\nindex 2\nAQJlbnRyeQ==\n\n{cp}"),
            format!("RISALA-HANDOFF/1\nindex 2\nAQJlbnRyeQ==\n\n{cp}"),
        ] {
            assert!(HandoffRequest::parse(bad.as_bytes()).is_err(), "{bad:?}");
        }
        for bad in [
            format!("risala-handoff/1\nindex 02\nAQJlbnRyeQ==\n\n{cp}"),
            format!("risala-handoff/1\nindex\nAQJlbnRyeQ==\n\n{cp}"),
            format!("risala-handoff/1\nidx 2\nAQJlbnRyeQ==\n\n{cp}"),
            format!("risala-handoff/1\nindex 2\nAQJlbnRyeQ\n\n{cp}"),
            format!("risala-handoff/1\nindex 2\nAQJlbnRyeR==\n\n{cp}"),
            format!("risala-handoff/1\nindex 2\n\n{cp}"),
            format!("risala-handoff/1\nindex 2\nAQJlbnRyeQ==\nAAAA\n\n{cp}"),
            format!("risala-handoff/1\nindex 2\nAQJlbnRyeQ==\n{hash}\n{cp}"),
            format!(
                "risala-handoff/1\nindex 2\nAQJlbnRyeQ==\n{}\n{cp}",
                format!("{hash}\n").repeat(65)
            ),
            "risala-handoff/1\nindex 2\nAQJlbnRyeQ==\n\nnot a checkpoint\n".to_owned(),
        ] {
            assert!(HandoffRequest::parse(bad.as_bytes()).is_err(), "{bad:?}");
        }
        let max = format!(
            "risala-handoff/1\nindex 2\nAQJlbnRyeQ==\n{}\n{cp}",
            format!("{hash}\n").repeat(64)
        );
        assert!(HandoffRequest::parse(max.as_bytes()).is_ok());
    }
}
