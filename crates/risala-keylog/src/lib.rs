//! The risala key log (SPEC 4.5, 4.10), from the C2SP specifications it
//! uses:
//!
//! - [`note`]: signed notes and verifier keys [SIGNED-NOTE];
//! - [`checkpoint`]: checkpoints [TLOG-CHECKPOINT], and key log origins,
//!   `<host>/risala-log/<n>`;
//! - [`cosig`]: timestamped ML-DSA-44 checkpoint cosignatures, signed-note
//!   type `0x06` [TLOG-COSIGNATURE], with which the log signs its
//!   checkpoints and witnesses cosign them;
//! - [`entry`]: the log's entries, `LogEntry`: a key file Record, or a
//!   hand-off to the host's next log;
//! - [`hint`]: the log's `risala/uid/<hash>` and `risala/next` hints;
//! - [`merkle`] and [`proof`]: the Merkle tree of RFC 6962 with SHA-256,
//!   and RFC 9162's inclusion and consistency proofs;
//! - [`tile`]: tiles and entry bundles [TLOG-TILES], built by the server
//!   and read by devices;
//! - [`witness`]: the witness policy, k of n, and freshness;
//! - [`client`]: what a device does with a log: records and hand-offs
//!   proved against witnessed checkpoints, keeping them consistent, and
//!   fork evidence;
//! - [`addcheckpoint`]: the body of a witness's `add-checkpoint` request
//!   [TLOG-WITNESS];
//! - [`handoff`]: the body of a witness's `risala/handoff` request;
//! - [`witnessing`]: a witness for risala key logs (SPEC 4.10), with its
//!   storage behind a trait;
//! - [`testlog`]: an in-memory log and witness, for tests.
//!
//! What a Record holds (SPEC 4.4) is not this crate's business: a record
//! entry carries it as bytes. The crate does no I/O; tiles come in through
//! [`tile::TileFetcher`] or a [`tile::TileSet`] the caller fills.
//!
//! Times are POSIX seconds, as cosignatures carry them.

pub mod addcheckpoint;
pub mod checkpoint;
pub mod client;
pub mod cosig;
pub mod entry;
pub mod handoff;
pub mod hint;
pub mod merkle;
pub mod note;
pub mod proof;
pub mod testlog;
pub mod tile;
pub mod witness;
pub mod witnessing;

pub use checkpoint::{Checkpoint, LogOrigin, SignedCheckpoint};
pub use client::{ForkEvidence, LogView, Seen};
pub use cosig::{CosignatureVerifier, Cosigner};
pub use entry::{LogEntry, LogEntryType, record_hash};
pub use hint::UidHint;
pub use merkle::{Hash, leaf_hash};
pub use note::{Note, NoteSignature, VerifierKey};
pub use tile::{TileFetcher, TileId, TileSet};
pub use witness::{Freshness, LogKey, WitnessPolicy, WitnessedCheckpoint};
pub use witnessing::{WitnessConfig, WitnessCore, WitnessStore};
