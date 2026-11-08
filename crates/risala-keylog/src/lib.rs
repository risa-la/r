//! The risala key log (SPEC 4.5), from the C2SP specifications it uses:
//!
//! - [`merkle`] and [`proof`]: the Merkle tree of RFC 6962 with SHA-256,
//!   and RFC 9162's inclusion and consistency proofs;
//! - [`tile`]: tiles and entry bundles [TLOG-TILES], built by the server
//!   and read by devices;
//!
//! What an entry holds, an encoded Record (SPEC 4.4), is not this crate's
//! business: entries are bytes here. The crate does no I/O; tiles come in
//! through [`tile::TileFetcher`] or a [`tile::TileSet`] the caller fills.
//!
//! Times are POSIX seconds, as cosignatures carry them.

pub mod merkle;
pub mod proof;
pub mod tile;

pub use merkle::{Hash, leaf_hash};
pub use tile::{TileFetcher, TileId, TileSet};
