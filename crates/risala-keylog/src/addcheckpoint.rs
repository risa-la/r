//! The body of a witness's `add-checkpoint` request [TLOG-WITNESS], which
//! a key log sends to get each new checkpoint cosigned (SPEC 4.5):
//!
//! ```text
//! old <old size>
//! <consistency proof hash, base64>
//! …
//!
//! <signed checkpoint>
//! ```
//!
//! The response is one or more signature lines, which
//! [`NoteSignature::parse_lines`](crate::note::NoteSignature::parse_lines)
//! reads.

use thiserror::Error;

use crate::checkpoint::{CheckpointError, SignedCheckpoint, parse_decimal};
use crate::merkle::Hash;

/// The most consistency proof lines a request may have.
pub const MAX_PROOF_LINES: usize = 63;

/// An `add-checkpoint` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddCheckpoint {
    /// The size of the checkpoint the witness last cosigned for the log,
    /// as the log believes it to be; 0 if none.
    pub old_size: u64,
    /// The consistency proof from `old_size` to the checkpoint's size.
    pub proof: Vec<Hash>,
    /// The checkpoint, with the log's signature.
    pub checkpoint: SignedCheckpoint,
}

/// Why a request body did not parse.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RequestError {
    /// The lines before the checkpoint are malformed.
    #[error("malformed add-checkpoint request: {0}")]
    Malformed(&'static str),
    /// The checkpoint is malformed.
    #[error(transparent)]
    Checkpoint(#[from] CheckpointError),
}

impl AddCheckpoint {
    /// The request body.
    pub fn to_body(&self) -> String {
        let mut s = format!("old {}\n", self.old_size);
        for h in &self.proof {
            s.push_str(&h.to_base64());
            s.push('\n');
        }
        s.push('\n');
        s.push_str(&self.checkpoint.to_text());
        s
    }

    /// Parses a request body.
    pub fn parse(body: &[u8]) -> Result<AddCheckpoint, RequestError> {
        let split = body
            .windows(2)
            .position(|w| w == b"\n\n")
            .ok_or(RequestError::Malformed(
                "no blank line before the checkpoint",
            ))?;
        let head = std::str::from_utf8(&body[..split])
            .map_err(|_| RequestError::Malformed("not UTF-8"))?;
        let mut lines = head.split('\n');
        let old = lines
            .next()
            .and_then(|l| l.strip_prefix("old "))
            .ok_or(RequestError::Malformed("no old size"))?;
        let old_size = parse_decimal(old).ok_or(RequestError::Malformed("bad old size"))?;
        let proof = lines
            .map(|l| Hash::from_base64(l).ok_or(RequestError::Malformed("bad proof hash")))
            .collect::<Result<Vec<_>, _>>()?;
        if proof.len() > MAX_PROOF_LINES {
            return Err(RequestError::Malformed("too many proof lines"));
        }
        let checkpoint = SignedCheckpoint::parse(&body[split + 2..])?;
        Ok(AddCheckpoint {
            old_size,
            proof,
            checkpoint,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The example request of [TLOG-WITNESS].
    const SPEC_REQUEST: &str = "old 20852014
PlRNCrwHpqhGrupue0L7gxbjbMiKA9temvuZZDDpkaw=
jrJZDmY8Y7SyJE0MWLpLozkIVMSMZcD5kvuKxPC3swk=
5+pKlUdi2LeF/BcMHBn+Ku6yhPGNCswZZD1X/6QgPd8=
/6WVhPs2CwSsb5rYBH5cjHV/wSmA79abXAwhXw3Kj/0=

example.com/behind-the-sofa
20852163
CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=

\u{2014} example.com/behind-the-sofa Az3grlgtzPICa5OS8npVmf1Myq/5IZniMp+ZJurmRDeOoRDe4URYN7u5/Zhcyv2q1gGzGku9nTo+zyWE+xeMcTOAYQ8=
\u{2014} example.com/behind-the-sofa opLqBQsREYCgu6xQkYQwJr9fo45a62DN9EdmHXnZdXNqlcVGlCum2Wks+49/V6267UEjw6QUXTS5Rovnzv++qbSzm9Q=
";

    #[test]
    fn spec_example() {
        let r = AddCheckpoint::parse(SPEC_REQUEST.as_bytes()).unwrap();
        assert_eq!(r.old_size, 20852014);
        assert_eq!(r.proof.len(), 4);
        assert_eq!(r.checkpoint.checkpoint().size(), 20852163);
        assert_eq!(r.checkpoint.note().signatures().len(), 2);
        assert_eq!(r.to_body(), SPEC_REQUEST);
    }

    #[test]
    fn empty_proof_and_errors() {
        let cp = &SPEC_REQUEST[SPEC_REQUEST.find("example.com").unwrap()..];
        let r = AddCheckpoint::parse(format!("old 0\n\n{cp}").as_bytes()).unwrap();
        assert_eq!((r.old_size, r.proof.len()), (0, 0));
        assert_eq!(r.to_body(), format!("old 0\n\n{cp}"));
        for bad in [
            format!("old 00\n\n{cp}"),
            format!("old\n\n{cp}"),
            format!("new 1\n\n{cp}"),
            format!("old 1\nAAAA\n\n{cp}"),
            format!("old 1\n{cp}"),
            format!(
                "old 1\n{}\n{cp}",
                "PlRNCrwHpqhGrupue0L7gxbjbMiKA9temvuZZDDpkaw=\n".repeat(64)
            ),
        ] {
            assert!(AddCheckpoint::parse(bad.as_bytes()).is_err(), "{bad:?}");
        }
        let max = format!(
            "old 1\n{}\n{cp}",
            "PlRNCrwHpqhGrupue0L7gxbjbMiKA9temvuZZDDpkaw=\n".repeat(63)
        );
        assert!(AddCheckpoint::parse(max.as_bytes()).is_ok());
    }
}
