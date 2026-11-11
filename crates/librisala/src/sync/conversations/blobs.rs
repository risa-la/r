//! This device's MLS objects too long for a line, as blobs (2.3, 12.12):
//! a commit, a public room's GroupInfo, or a Welcome that carries a large
//! group's tree. Each is stored first with BLOB on the anonymous or guest
//! connection that follows the group's mailbox, with its `box` and a send
//! token of the group, and an HTTP PUT of its bytes; the POST or WELCOME
//! PUT then names it by its blob-ref. A public room's external commit,
//! whose device holds no send token, has its blobs stored on the signed-in
//! connection that posts it, without `box` and `token` (4.1, 5.2, 12.6).
//!
//! What stores a blob is a small state machine per blob, [`Upload`]: BLOB
//! in flight, then the PUT in flight in the hooks, then stored. Posts whose
//! blobs are not all stored yet wait in the engine, as they were made, and
//! are posted on a later step; their outbox rows stay sent meanwhile. If a
//! blob cannot be stored, they go back to the queue, to be made again.

use std::sync::Arc;

use risala_proto::command::{Command, MailboxPermit};
use risala_proto::names::BlobRef;

use super::{BlobPut, ConversationEngine, Pending};
use crate::conn::{End, Response};
use crate::sync::{Action, Target};

/// Room in a POST or WELCOME PUT line for everything but its MLS objects:
/// the verb, box, token, ref and options (2.3). They take a few hundred
/// bytes at most.
pub(super) const LINE_OVERHEAD: usize = 1024;

/// Where storing one of this device's blobs is (12.12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Upload {
    /// BLOB is in flight.
    Asked,
    /// The PUT is in flight, in the hooks.
    Putting,
    /// The server has it.
    Stored,
    /// The server refused it, or the PUT failed.
    Failed,
}

/// Whether the blobs a post or Welcome names are stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Blobs {
    /// The server has them all: post.
    Stored,
    /// Not yet: post on a later step.
    Waiting,
    /// One could not be stored: make the post again later, since the
    /// group may have moved on and the token with it.
    Failed,
}

/// Where this device stores a post's or Welcome's blobs (4.1, 12.12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum BlobsOn {
    /// The anonymous or guest connection that follows the permit's
    /// mailbox, with the permit: a member's posts and Welcomes.
    Mailbox(MailboxPermit),
    /// The signed-in connection, with no permit, counted against the
    /// identity: a public room's external commit, which that connection
    /// posts, and whose device holds no send token (5.2, 12.6).
    SignedIn,
}

/// The length of `n` bytes in base64 with padding.
fn base64_len(n: usize) -> usize {
    n.div_ceil(3) * 4
}

/// Which of the objects of lengths `sizes` go as blobs, so that a line
/// with the others in base64, and [`LINE_OVERHEAD`] bytes besides, is at
/// most `limit` bytes long (2.3): none if they all fit, else the largest
/// first, until the rest fit.
pub(super) fn as_blobs(sizes: &[usize], limit: usize) -> Vec<bool> {
    let mut blob = vec![false; sizes.len()];
    let mut order: Vec<usize> = (0..sizes.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(sizes[i]));
    let mut total: usize = LINE_OVERHEAD + sizes.iter().map(|&n| base64_len(n)).sum::<usize>();
    for i in order {
        if total <= limit {
            break;
        }
        if sizes[i] > 0 {
            blob[i] = true;
            total = total - base64_len(sizes[i]) + BlobRef::PREFIX.len() + 96;
        }
    }
    blob
}

impl ConversationEngine {
    /// Whether the server holds each of `blobs`, this device's, which the
    /// next POST or WELCOME PUT names (12.12). Starts storing those it does
    /// not hold yet: BLOB where `on` says, then a PUT by the hooks.
    pub(super) fn blobs_stored(
        &mut self,
        out: &mut Vec<Action>,
        on: &BlobsOn,
        blobs: &[(BlobRef, Arc<Vec<u8>>)],
    ) -> Blobs {
        let mut all = Blobs::Stored;
        for (blob, bytes) in blobs {
            let state = match self.uploads.get(blob) {
                Some(Upload::Putting) => match self.hooks.blob_put(blob) {
                    BlobPut::Done => Upload::Stored,
                    BlobPut::Waiting => Upload::Putting,
                    BlobPut::Failed => {
                        tracing::info!(%blob, "a blob's PUT failed");
                        Upload::Failed
                    }
                },
                Some(state) => *state,
                None => {
                    let (target, permit) = match on {
                        BlobsOn::Mailbox(permit) => {
                            (Target::Mailbox(permit.mailbox), Some(permit.clone()))
                        }
                        BlobsOn::SignedIn => (Target::SignedIn, None),
                    };
                    self.send(
                        out,
                        target,
                        Command::Blob {
                            hash: *blob,
                            size: bytes.len() as u64,
                            permit,
                        },
                        Pending::Blob {
                            blob: *blob,
                            bytes: bytes.clone(),
                        },
                    );
                    Upload::Asked
                }
            };
            all = match (all, state) {
                (Blobs::Failed, _) | (_, Upload::Failed) => Blobs::Failed,
                (Blobs::Stored, Upload::Stored) => Blobs::Stored,
                _ => Blobs::Waiting,
            };
            self.uploads.insert(*blob, state);
        }
        if all != Blobs::Waiting {
            self.forget_blobs(blobs);
        }
        all
    }

    /// Forgets blobs once a POST or WELCOME PUT named them, or one failed:
    /// should they be needed again, BLOB answers `exists=yes` at once for
    /// those stored.
    fn forget_blobs(&mut self, blobs: &[(BlobRef, Arc<Vec<u8>>)]) {
        for (blob, _) in blobs {
            if self.uploads.get(blob) != Some(&Upload::Asked) {
                self.uploads.remove(blob);
            }
        }
    }

    /// BLOB answered (12.12): the server has the blob already, or the PUT
    /// starts.
    pub(super) fn on_blob_reply(
        &mut self,
        blob: BlobRef,
        bytes: Arc<Vec<u8>>,
        response: &Response,
    ) {
        let state = match &response.end {
            End::Ok(ok) if ok.exists().ok().flatten() == Some(true) => Upload::Stored,
            End::Ok(ok) => match ok.put_url() {
                Some(url) => {
                    self.hooks.put_blob(url, &blob, bytes);
                    Upload::Putting
                }
                None => Upload::Failed,
            },
            End::Err(e) => {
                tracing::warn!(code = %e.code, %blob, "BLOB refused");
                Upload::Failed
            }
            // The connection closed.
            End::Unparseable(_) => Upload::Failed,
        };
        self.uploads.insert(blob, state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_fits_stays_inline_and_the_largest_goes_first() {
        let limit = 1 << 20;
        assert_eq!(as_blobs(&[1000, 0], limit), [false, false]);
        // 786,000 bytes are 1,048,000 in base64: with the overhead, too
        // long.
        assert_eq!(as_blobs(&[786_000, 0], limit), [true, false]);
        // Each fits alone, not both: the larger goes.
        assert_eq!(as_blobs(&[400_000, 500_000], limit), [false, true]);
        assert_eq!(as_blobs(&[900_000, 900_000], limit), [true, true]);
        // Exactly at the limit is fine.
        let n = (limit - LINE_OVERHEAD) / 4 * 3;
        assert_eq!(as_blobs(&[n], limit), [false]);
        assert_eq!(as_blobs(&[n + 1], limit), [true]);
    }
}
