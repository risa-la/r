//! The risala key log (SPEC 4.5), from the C2SP specifications it uses:
//!
//! - [`note`]: signed notes and verifier keys [SIGNED-NOTE];
//! - [`checkpoint`]: checkpoints [TLOG-CHECKPOINT], and key log origins,
//!   `<host>/risala-log/<n>`;
//! - [`cosig`]: timestamped ML-DSA-44 checkpoint cosignatures, signed-note
//!   type `0x06` [TLOG-COSIGNATURE], with which the log signs its
//!   checkpoints and witnesses cosign them;
//! - [`merkle`] and [`proof`]: the Merkle tree of RFC 6962 with SHA-256,
//!   and RFC 9162's inclusion and consistency proofs;
//! - [`tile`]: tiles and entry bundles [TLOG-TILES], built by the server
//!   and read by devices;
//! - [`witness`]: the witness policy, k of n;
//! - [`addcheckpoint`]: the body of a witness's `add-checkpoint` request
//!   [TLOG-WITNESS];
//!
//! What an entry holds, an encoded Record (SPEC 4.4), is not this crate's
//! business: entries are bytes here. The crate does no I/O; tiles come in
//! through [`tile::TileFetcher`] or a [`tile::TileSet`] the caller fills.
//!
//! Times are POSIX seconds, as cosignatures carry them.

pub mod addcheckpoint;
pub mod checkpoint;
pub mod cosig;
pub mod merkle;
pub mod note;
pub mod proof;
pub mod tile;
pub mod witness;

pub use checkpoint::{Checkpoint, LogOrigin, SignedCheckpoint};
pub use cosig::{CosignatureVerifier, Cosigner};
pub use merkle::{Hash, leaf_hash};
pub use note::{Note, NoteSignature, VerifierKey};
pub use tile::{TileFetcher, TileId, TileSet};
pub use witness::{Freshness, LogKey, WitnessPolicy, WitnessedCheckpoint};
