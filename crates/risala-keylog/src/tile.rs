//! Tiles and entry bundles, as [TLOG-TILES] lays them out (SPEC 4.5).
//!
//! A tile at level `l` holds up to 256 hashes of complete subtrees of
//! height `8 * l`: the `n`-th tile's `i`-th hash is the hash of
//! [`NodeId`] `{ height: 8 * l, index: n * 256 + i }`. A tile with fewer
//! than 256 hashes is *partial*, and only the rightmost tile of a level is.
//! Level 0 tiles hold leaf hashes, and the entry bundle with the same
//! index holds the entries themselves.
//!
//! The server builds tiles with [`HashTiles`]. A device works out which
//! tiles a proof needs ([`tiles_for_nodes`]), fetches them, through a
//! [`TileFetcher`] or by itself, into a [`TileSet`], and reads hashes
//! from them with [`TileHashReader`].

use std::collections::BTreeMap;
use std::fmt;

use thiserror::Error;

use crate::merkle::{HASH_LEN, Hash, NodeId, fold_complete};
use crate::proof::HashReader;

/// How many tree levels a tile spans.
pub const TILE_HEIGHT: u8 = 8;

/// The number of hashes, or entries, in a full tile.
pub const TILE_WIDTH: u64 = 256;

/// The highest tile level a path may name [TLOG-TILES].
pub const MAX_LEVEL: u8 = 63;

/// The largest entry an entry bundle can hold: its length is a `uint16`.
pub const MAX_ENTRY_LEN: usize = 0xffff;

/// What a tile holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TileKind {
    /// Hashes, at this level.
    Hashes(u8),
    /// An entry bundle.
    Entries,
}

/// A tile, or an entry bundle: what it holds, its index within its level
/// and its width.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TileId {
    kind: TileKind,
    index: u64,
    width: u16,
}

/// Why a tile path or a tile did not parse.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TileError {
    /// The path is not a tile path, or not in its canonical form.
    #[error("not a tile path")]
    BadPath,
    /// A tile's data is not `width * 32` bytes.
    #[error("tile {0} has the wrong length")]
    WrongLength(TileId),
    /// A hash comes from a tile that is not in the set.
    #[error("tile {0} is missing")]
    Missing(TileId),
    /// The node asked for is not complete in the tree.
    #[error("node is not in the tree")]
    NotInTree,
}

impl TileId {
    /// A hash tile. `width` is 1 to 256; 256 is a full tile.
    pub fn hashes(level: u8, index: u64, width: u16) -> Option<TileId> {
        (level <= MAX_LEVEL).then_some(())?;
        TileId::new(TileKind::Hashes(level), index, width)
    }

    /// An entry bundle. `width` is 1 to 256; 256 is a full bundle.
    pub fn entries(index: u64, width: u16) -> Option<TileId> {
        TileId::new(TileKind::Entries, index, width)
    }

    fn new(kind: TileKind, index: u64, width: u16) -> Option<TileId> {
        ((1..=TILE_WIDTH as u16).contains(&width)).then_some(TileId { kind, index, width })
    }

    /// What the tile holds.
    pub fn kind(&self) -> TileKind {
        self.kind
    }

    /// The tile's index within its level.
    pub fn index(&self) -> u64 {
        self.index
    }

    /// How many hashes or entries the tile holds.
    pub fn width(&self) -> u16 {
        self.width
    }

    /// Whether the tile is partial.
    pub fn is_partial(&self) -> bool {
        u64::from(self.width) < TILE_WIDTH
    }

    /// The full tile at the same place.
    pub fn full(&self) -> TileId {
        TileId {
            width: TILE_WIDTH as u16,
            ..*self
        }
    }

    /// The entry bundle that goes with a level 0 tile, or the level 0
    /// tile that goes with an entry bundle.
    pub fn counterpart(&self) -> Option<TileId> {
        match self.kind {
            TileKind::Hashes(0) => Some(TileId {
                kind: TileKind::Entries,
                ..*self
            }),
            TileKind::Entries => Some(TileId {
                kind: TileKind::Hashes(0),
                ..*self
            }),
            TileKind::Hashes(_) => None,
        }
    }

    /// The tile's path under the log's prefix, without a leading slash:
    /// `tile/<L>/<N>[.p/<W>]` or `tile/entries/<N>[.p/<W>]`.
    pub fn path(&self) -> String {
        let level = match self.kind {
            TileKind::Hashes(l) => l.to_string(),
            TileKind::Entries => "entries".to_owned(),
        };
        let mut p = format!("tile/{level}/{}", encode_index(self.index));
        if self.is_partial() {
            p.push_str(&format!(".p/{}", self.width));
        }
        p
    }

    /// Parses a tile path, as [`path`](Self::path) writes it. Only the
    /// canonical form is accepted.
    pub fn parse(path: &str) -> Result<TileId, TileError> {
        let rest = path.strip_prefix("tile/").ok_or(TileError::BadPath)?;
        let (level, rest) = rest.split_once('/').ok_or(TileError::BadPath)?;
        let kind = if level == "entries" {
            TileKind::Entries
        } else {
            let l = parse_decimal(level).ok_or(TileError::BadPath)?;
            TileKind::Hashes(
                u8::try_from(l)
                    .ok()
                    .filter(|l| *l <= MAX_LEVEL)
                    .ok_or(TileError::BadPath)?,
            )
        };
        let (n, width) = match rest.split_once(".p/") {
            Some((n, w)) => {
                let w = parse_decimal(w)
                    .filter(|w| (1..TILE_WIDTH).contains(w))
                    .ok_or(TileError::BadPath)?;
                (n, w as u16)
            }
            None => (rest, TILE_WIDTH as u16),
        };
        let index = decode_index(n).ok_or(TileError::BadPath)?;
        Ok(TileId { kind, index, width })
    }
}

impl fmt::Display for TileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.path())
    }
}

/// A decimal number with no leading zeros.
fn parse_decimal(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0'))
    {
        return None;
    }
    s.parse().ok()
}

/// Writes a tile index as 3-digit path elements, all but the last
/// starting with `x`: 1234067 is `x001/x234/067`.
pub fn encode_index(mut n: u64) -> String {
    let mut s = format!("{:03}", n % 1000);
    while n >= 1000 {
        n /= 1000;
        s = format!("x{:03}/{s}", n % 1000);
    }
    s
}

/// Reads a tile index written by [`encode_index`], in its canonical form
/// only.
pub fn decode_index(s: &str) -> Option<u64> {
    let mut n: u64 = 0;
    let mut parts = s.split('/').peekable();
    while let Some(part) = parts.next() {
        let digits = if parts.peek().is_some() {
            part.strip_prefix('x')?
        } else {
            part
        };
        if digits.len() != 3 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        n = n
            .checked_mul(1000)?
            .checked_add(digits.parse::<u64>().ok()?)?;
    }
    // Leading `x000/` elements would give a second path for one tile.
    (encode_index(n) == s).then_some(n)
}

/// How many hashes level `level` of a tree of `size` leaves holds: the
/// complete subtrees of height `8 * level`.
fn level_count(size: u64, level: u8) -> u64 {
    let shift = u32::from(level) * u32::from(TILE_HEIGHT);
    size.checked_shr(shift).unwrap_or(0)
}

/// The tiles of a level for a tree of `size` leaves from tile `from` on.
fn level_tiles(kind: TileKind, count: u64, from: u64) -> impl Iterator<Item = TileId> {
    let end = count.div_ceil(TILE_WIDTH);
    (from..end).map(move |n| {
        let width = (count - n * TILE_WIDTH).min(TILE_WIDTH) as u16;
        TileId {
            kind,
            index: n,
            width,
        }
    })
}

/// The hash tiles that are new or have grown when a tree grows from `old`
/// leaves to `new`: the ones a log writes. For `old == 0`, every tile of
/// the tree.
pub fn tiles_for_growth(old: u64, new: u64) -> Vec<TileId> {
    let mut out = Vec::new();
    for level in 0..=MAX_LEVEL {
        let c1 = level_count(new, level);
        if c1 == 0 {
            break;
        }
        let c0 = level_count(old, level);
        if c1 > c0 {
            out.extend(level_tiles(TileKind::Hashes(level), c1, c0 / TILE_WIDTH));
        }
    }
    out
}

/// The entry bundles that are new or have grown when a tree grows from
/// `old` leaves to `new`.
pub fn bundles_for_growth(old: u64, new: u64) -> Vec<TileId> {
    if new <= old {
        return Vec::new();
    }
    level_tiles(TileKind::Entries, new, old / TILE_WIDTH).collect()
}

/// The entry bundle that holds entry `index` in a tree of `size` leaves.
pub fn bundle_for_entry(index: u64, size: u64) -> Option<TileId> {
    (index < size).then(|| level_tiles(TileKind::Entries, size, index / TILE_WIDTH).next())?
}

/// The tile that holds what a node is made of in a tree of `size` leaves,
/// and the range of hashes in that tile that fold into it.
pub fn tile_for_node(node: NodeId, size: u64) -> Option<(TileId, std::ops::Range<usize>)> {
    if !node.is_in_tree(size) {
        return None;
    }
    let level = node.height / TILE_HEIGHT;
    let r = node.height % TILE_HEIGHT;
    let first = node.index << r;
    let n = first / TILE_WIDTH;
    let offset = (first % TILE_WIDTH) as usize;
    let tile = level_tiles(TileKind::Hashes(level), level_count(size, level), n).next()?;
    Some((tile, offset..offset + (1 << r)))
}

/// The tiles needed to read these nodes from a tree of `size` leaves.
/// Nodes that are not complete in the tree are skipped.
pub fn tiles_for_nodes(nodes: &[NodeId], size: u64) -> Vec<TileId> {
    let mut tiles: Vec<TileId> = nodes
        .iter()
        .filter_map(|n| tile_for_node(*n, size))
        .map(|(t, _)| t)
        .collect();
    tiles.sort_unstable();
    tiles.dedup();
    tiles
}

/// The hash a full tile contributes to the level above it: the root of
/// its 256 hashes. `None` if `data` is not a full tile.
pub fn full_tile_hash(data: &[u8]) -> Option<Hash> {
    (data.len() == TILE_WIDTH as usize * HASH_LEN).then(|| fold_complete(&split_hashes(data)))
}

fn split_hashes(data: &[u8]) -> Vec<Hash> {
    data.as_chunks::<HASH_LEN>()
        .0
        .iter()
        .map(|c| Hash(*c))
        .collect()
}

fn join_hashes(hashes: &[Hash]) -> Vec<u8> {
    hashes.iter().flat_map(|h| h.0).collect()
}

/// A log's hash tiles, built in memory as entries are added: what a server
/// serves, and what it reads its own proofs from.
///
/// Level `l` keeps the hash of every complete subtree of height `8 * l`,
/// which are exactly the hashes the level's tiles hold.
#[derive(Clone, Debug, Default)]
pub struct HashTiles {
    levels: Vec<Vec<Hash>>,
}

impl HashTiles {
    /// An empty tree.
    pub fn new() -> HashTiles {
        HashTiles::default()
    }

    /// The tree from these leaf hashes.
    pub fn from_leaf_hashes(leaves: impl IntoIterator<Item = Hash>) -> HashTiles {
        let mut t = HashTiles::new();
        for h in leaves {
            t.push(h);
        }
        t
    }

    /// The number of leaves.
    pub fn size(&self) -> u64 {
        self.levels.first().map_or(0, |l| l.len() as u64)
    }

    /// Adds a leaf, by its hash.
    pub fn push(&mut self, leaf: Hash) {
        let mut hash = leaf;
        let mut level = 0;
        loop {
            if self.levels.len() == level {
                self.levels.push(Vec::new());
            }
            let row = &mut self.levels[level];
            row.push(hash);
            if !(row.len() as u64).is_multiple_of(TILE_WIDTH) {
                break;
            }
            hash = fold_complete(&row[row.len() - TILE_WIDTH as usize..]);
            level += 1;
        }
    }

    /// The data of a hash tile, if the tree has it: a full tile once its
    /// 256 hashes exist, and a partial tile of any width up to what exists.
    /// Older partial tiles stay available, for proofs against older
    /// checkpoints.
    pub fn tile(&self, tile: &TileId) -> Option<Vec<u8>> {
        let TileKind::Hashes(level) = tile.kind else {
            return None;
        };
        let row = self.levels.get(usize::from(level))?;
        let start = usize::try_from(tile.index.checked_mul(TILE_WIDTH)?).ok()?;
        let end = start.checked_add(usize::from(tile.width))?;
        row.get(start..end).map(join_hashes)
    }

    /// The tree's root.
    pub fn root(&self) -> Hash {
        let mut me = self;
        crate::proof::tree_hash(self.size(), &mut me).expect("the tree has every node")
    }
}

impl HashReader for &HashTiles {
    type Error = TileError;

    fn node(&mut self, node: NodeId) -> Result<Hash, TileError> {
        let (tile, range) = tile_for_node(node, self.size()).ok_or(TileError::NotInTree)?;
        let TileKind::Hashes(level) = tile.kind else {
            unreachable!()
        };
        let row = &self.levels[usize::from(level)];
        let start = tile.index as usize * TILE_WIDTH as usize;
        Ok(fold_complete(&row[start + range.start..start + range.end]))
    }
}

/// Hash tiles a device has fetched, checked only for their length.
#[derive(Clone, Debug, Default)]
pub struct TileSet {
    tiles: BTreeMap<TileId, Vec<u8>>,
}

impl TileSet {
    /// An empty set.
    pub fn new() -> TileSet {
        TileSet::default()
    }

    /// Adds a fetched hash tile. Its data must be `width * 32` bytes.
    pub fn insert(&mut self, tile: TileId, data: Vec<u8>) -> Result<(), TileError> {
        if !matches!(tile.kind, TileKind::Hashes(_))
            || data.len() != usize::from(tile.width) * HASH_LEN
        {
            return Err(TileError::WrongLength(tile));
        }
        self.tiles.insert(tile, data);
        Ok(())
    }

    /// Whether the set can serve this tile: it has it, or a wider tile at
    /// the same place, whose start is the same in an honest log.
    pub fn contains(&self, tile: &TileId) -> bool {
        self.get(tile).is_some()
    }

    /// The tile's data, cut from a wider tile at the same place if that is
    /// what the set has.
    ///
    /// Partial tiles of a log are the starts of the full tile, so any tile
    /// at least as wide serves. If a log broke that, the hashes would be
    /// wrong, and so would every proof computed from them.
    pub fn get(&self, tile: &TileId) -> Option<&[u8]> {
        let (_, data) = self.tiles.range(*tile..=tile.full()).next()?;
        Some(&data[..usize::from(tile.width) * HASH_LEN])
    }

    /// Of these tiles, the ones the set cannot serve yet.
    pub fn missing(&self, tiles: &[TileId]) -> Vec<TileId> {
        tiles
            .iter()
            .filter(|t| !self.contains(t))
            .copied()
            .collect()
    }

    /// Fetches the tiles the set does not have yet.
    pub fn fetch<F: TileFetcher>(
        &mut self,
        tiles: &[TileId],
        fetcher: &mut F,
    ) -> Result<(), FetchError<F::Error>> {
        for tile in self.missing(tiles) {
            let data = fetcher.fetch_tile(&tile).map_err(FetchError::Fetch)?;
            self.insert(tile, data).map_err(FetchError::Tile)?;
        }
        Ok(())
    }

    /// A hash reader over the set. Any tile wide enough serves, so one
    /// reader serves every tree up to `size` leaves; `size` names the tile
    /// that is missing when one is.
    pub fn reader(&self, size: u64) -> TileHashReader<'_> {
        TileHashReader { tiles: self, size }
    }
}

/// Fetches tiles and entry bundles from a log, for example over HTTPS
/// under the rules for key files (SPEC 4.4, 4.5). This crate does no I/O
/// itself.
///
/// Callers that fetch asynchronously can skip this trait: they work out
/// the tiles with [`tiles_for_nodes`] or the helpers in
/// [`crate::client`], fetch them, and put them in a [`TileSet`].
pub trait TileFetcher {
    /// Why a fetch failed.
    type Error;

    /// The tile's data, as the log serves it at [`TileId::path`].
    fn fetch_tile(&mut self, tile: &TileId) -> Result<Vec<u8>, Self::Error>;
}

/// Why fetching tiles failed.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum FetchError<E> {
    /// The fetcher failed.
    #[error("fetching a tile: {0}")]
    Fetch(E),
    /// The log served a tile of the wrong length.
    #[error(transparent)]
    Tile(TileError),
}

/// Reads hashes from a [`TileSet`].
#[derive(Clone, Copy, Debug)]
pub struct TileHashReader<'a> {
    tiles: &'a TileSet,
    size: u64,
}

impl HashReader for TileHashReader<'_> {
    type Error = TileError;

    fn node(&mut self, node: NodeId) -> Result<Hash, TileError> {
        let (tile, range) = tile_for_node(node, self.size).ok_or(TileError::NotInTree)?;
        let enough = TileId {
            width: range.end as u16,
            ..tile
        };
        let data = self.tiles.get(&enough).ok_or(TileError::Missing(tile))?;
        let hashes = split_hashes(&data[range.start * HASH_LEN..range.end * HASH_LEN]);
        Ok(fold_complete(&hashes))
    }
}

/// Why an entry bundle did not encode or decode.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum BundleError {
    /// An entry is longer than 65,535 bytes.
    #[error("an entry is too long for a bundle")]
    EntryTooLong,
    /// More than 256 entries.
    #[error("too many entries for a bundle")]
    TooManyEntries,
    /// The bundle is cut short, or has bytes after its last entry.
    #[error("malformed entry bundle")]
    Malformed,
}

/// Encodes entries as an entry bundle: each a big-endian `uint16` length
/// and the entry.
pub fn encode_bundle<E: AsRef<[u8]>>(entries: &[E]) -> Result<Vec<u8>, BundleError> {
    if entries.len() as u64 > TILE_WIDTH {
        return Err(BundleError::TooManyEntries);
    }
    let mut out = Vec::new();
    for e in entries {
        let e = e.as_ref();
        let len = u16::try_from(e.len()).map_err(|_| BundleError::EntryTooLong)?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(e);
    }
    Ok(out)
}

/// Decodes an entry bundle. The caller checks that it holds as many
/// entries as the bundle's width.
pub fn decode_bundle(mut data: &[u8]) -> Result<Vec<Vec<u8>>, BundleError> {
    let mut entries = Vec::new();
    while !data.is_empty() {
        if entries.len() as u64 == TILE_WIDTH {
            return Err(BundleError::TooManyEntries);
        }
        let (len, rest) = data
            .split_first_chunk::<2>()
            .ok_or(BundleError::Malformed)?;
        let len = usize::from(u16::from_be_bytes(*len));
        if rest.len() < len {
            return Err(BundleError::Malformed);
        }
        let (entry, rest) = rest.split_at(len);
        entries.push(entry.to_vec());
        data = rest;
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{leaf_hash, root_from_leaf_hashes};
    use crate::proof::tree_hash;

    #[test]
    fn index_encoding() {
        // The examples of [TLOG-TILES], and of golang.org/x/mod/sumdb/tlog's
        // tile path tests.
        assert_eq!(encode_index(1234067), "x001/x234/067");
        assert_eq!(encode_index(123456078), "x123/x456/078");
        assert_eq!(encode_index(3057500), "x003/x057/500");
        assert_eq!(encode_index(0), "000");
        assert_eq!(encode_index(1000), "x001/000");
        for n in [0, 1, 999, 1000, 1234067, u64::MAX] {
            assert_eq!(decode_index(&encode_index(n)), Some(n));
        }
        for bad in [
            "",
            "1",
            "0001",
            "x000/001",
            "001/001",
            "x001",
            "x01/001",
            "x001/x001",
            "abc",
            "x1a2/000",
        ] {
            assert_eq!(decode_index(bad), None, "{bad}");
        }
        // One past u64::MAX.
        assert_eq!(decode_index("x018/x446/x744/x073/x709/x551/616"), None);
    }

    #[test]
    fn paths() {
        let cases = [
            ("tile/0/000", TileId::hashes(0, 0, 256)),
            ("tile/3/x123/x456/078", TileId::hashes(3, 123456078, 256)),
            ("tile/3/x123/x456/078.p/2", TileId::hashes(3, 123456078, 2)),
            (
                "tile/1/x003/x057/500.p/255",
                TileId::hashes(1, 3057500, 255),
            ),
            ("tile/63/001", TileId::hashes(63, 1, 256)),
            ("tile/entries/x001/x234/067", TileId::entries(1234067, 256)),
            ("tile/entries/000.p/1", TileId::entries(0, 1)),
        ];
        for (path, tile) in cases {
            let tile = tile.unwrap();
            assert_eq!(tile.path(), path);
            assert_eq!(TileId::parse(path), Ok(tile));
        }
        for bad in [
            "tile/0/000.p/256",
            "tile/0/000.p/0",
            "tile/0/000.p/01",
            "tile/64/000",
            "tile/01/000",
            "tile/-1/000",
            "tile/data/000",
            "tile/0/x000/000",
            "tile/0/0",
            "tile/0/000.p/",
            "tile/0/000/",
            "/tile/0/000",
            "tile/0",
            "tile/entries/000.p/1/x",
        ] {
            assert_eq!(TileId::parse(bad), Err(TileError::BadPath), "{bad}");
        }
        assert_eq!(TileId::hashes(64, 0, 1), None);
        assert_eq!(TileId::hashes(0, 0, 0), None);
        assert_eq!(TileId::entries(0, 257), None);
    }

    #[test]
    fn tiles_of_the_tlog_tiles_example() {
        // [TLOG-TILES]: "a tree of size 70,000 will be represented by 273
        // full level 0 tiles, one partial level 0 tile of width 112, one
        // full level 1 tile, one partial level 1 tile of width 17, and one
        // partial level 2 tile of width 1."
        let tiles = tiles_for_growth(0, 70_000);
        let level = |l| {
            tiles
                .iter()
                .filter(move |t| t.kind() == TileKind::Hashes(l))
        };
        assert_eq!(level(0).filter(|t| !t.is_partial()).count(), 273);
        assert_eq!(
            level(0)
                .filter(|t| t.is_partial())
                .map(|t| t.width())
                .collect::<Vec<_>>(),
            [112]
        );
        assert_eq!(level(1).map(|t| t.width()).collect::<Vec<_>>(), [256, 17]);
        assert_eq!(level(2).map(|t| t.width()).collect::<Vec<_>>(), [1]);
        assert_eq!(tiles.len(), 273 + 1 + 2 + 1);

        // "a tree of size 256 will be represented by a full level 0 tile
        // and a partial level 1 tile of width 1."
        assert_eq!(
            tiles_for_growth(0, 256),
            [
                TileId::hashes(0, 0, 256).unwrap(),
                TileId::hashes(1, 0, 1).unwrap()
            ]
        );
        assert_eq!(
            bundles_for_growth(0, 256),
            [TileId::entries(0, 256).unwrap()]
        );
    }

    #[test]
    fn growth_lists_changed_tiles() {
        assert_eq!(tiles_for_growth(5, 5), []);
        assert_eq!(tiles_for_growth(5, 6), [TileId::hashes(0, 0, 6).unwrap()]);
        assert_eq!(
            tiles_for_growth(255, 257),
            [
                TileId::hashes(0, 0, 256).unwrap(),
                TileId::hashes(0, 1, 1).unwrap(),
                TileId::hashes(1, 0, 1).unwrap()
            ]
        );
        assert_eq!(
            tiles_for_growth(256, 257),
            [TileId::hashes(0, 1, 1).unwrap()]
        );
        assert_eq!(bundles_for_growth(300, 600).len(), 2);
        assert_eq!(bundle_for_entry(511, 600), TileId::entries(1, 256));
        assert_eq!(bundle_for_entry(599, 600), TileId::entries(2, 88));
        assert_eq!(bundle_for_entry(600, 600), None);
    }

    #[test]
    fn built_tiles_match_the_tree() {
        let leaves: Vec<Hash> = (0u32..1000).map(|i| leaf_hash(&i.to_be_bytes())).collect();
        let mut tiles = HashTiles::new();
        let mut set = TileSet::new();
        for (n, leaf) in leaves.iter().enumerate() {
            tiles.push(*leaf);
            let size = n as u64 + 1;
            if [1, 2, 255, 256, 257, 511, 512, 513, 1000].contains(&size) {
                assert_eq!(
                    tiles.root(),
                    root_from_leaf_hashes(&leaves[..=n]),
                    "size {size}"
                );
                // A device rebuilds the root from the tiles alone.
                for t in tiles_for_growth(0, size) {
                    set.insert(t, tiles.tile(&t).unwrap()).unwrap();
                }
                assert_eq!(
                    tree_hash(size, &mut set.reader(size)).unwrap(),
                    tiles.root()
                );
            }
        }
        // Level 1's first hash is the root of the first full tile.
        let first = tiles.tile(&TileId::hashes(0, 0, 256).unwrap()).unwrap();
        let up = tiles.tile(&TileId::hashes(1, 0, 3).unwrap()).unwrap();
        assert_eq!(full_tile_hash(&first).unwrap().0, up[..32]);
        assert_eq!(full_tile_hash(&up), None);
        // An older partial tile is the start of the full one.
        let old = tiles.tile(&TileId::hashes(0, 1, 7).unwrap()).unwrap();
        let full = tiles.tile(&TileId::hashes(0, 1, 256).unwrap()).unwrap();
        assert_eq!(old[..], full[..7 * 32]);
        assert_eq!(tiles.tile(&TileId::hashes(0, 3, 233).unwrap()), None);
        assert_eq!(tiles.tile(&TileId::entries(0, 1).unwrap()), None);
    }

    #[test]
    fn sets_check_lengths_and_fall_back_to_full_tiles() {
        let tiles = HashTiles::from_leaf_hashes((0u32..300).map(|i| leaf_hash(&i.to_be_bytes())));
        let mut set = TileSet::new();
        let t = TileId::hashes(0, 0, 256).unwrap();
        assert_eq!(set.insert(t, vec![0; 31]), Err(TileError::WrongLength(t)));
        assert_eq!(
            set.insert(TileId::entries(0, 1).unwrap(), vec![0; 32]),
            Err(TileError::WrongLength(TileId::entries(0, 1).unwrap()))
        );
        set.insert(t, tiles.tile(&t).unwrap()).unwrap();
        let partial = TileId::hashes(0, 0, 100).unwrap();
        assert!(set.contains(&partial));
        assert_eq!(
            set.get(&partial).unwrap(),
            &tiles.tile(&partial).unwrap()[..]
        );
        let mut reader = set.reader(100);
        assert_eq!(tree_hash(100, &mut reader).unwrap(), {
            let small =
                HashTiles::from_leaf_hashes((0u32..100).map(|i| leaf_hash(&i.to_be_bytes())));
            small.root()
        });
        let mut reader = set.reader(300);
        assert_eq!(
            tree_hash(300, &mut reader),
            Err(crate::proof::ProofError::Read(TileError::Missing(
                TileId::hashes(1, 0, 1).unwrap()
            )))
        );
    }

    #[test]
    fn bundles() {
        let entries: Vec<Vec<u8>> = vec![vec![], vec![1, 2, 3], vec![7; 300]];
        let b = encode_bundle(&entries).unwrap();
        assert_eq!(&b[..5], [0, 0, 0, 3, 1]);
        assert_eq!(decode_bundle(&b).unwrap(), entries);
        assert_eq!(
            decode_bundle(&b[..b.len() - 1]),
            Err(BundleError::Malformed)
        );
        assert_eq!(decode_bundle(&[0]), Err(BundleError::Malformed));
        assert_eq!(
            encode_bundle(&[vec![0; 65536]]),
            Err(BundleError::EntryTooLong)
        );
        assert!(encode_bundle(&[vec![0; 65535]]).is_ok());
        assert_eq!(
            encode_bundle(&vec![vec![]; 257]),
            Err(BundleError::TooManyEntries)
        );
        let max = encode_bundle(&vec![vec![]; 256]).unwrap();
        assert_eq!(decode_bundle(&max).unwrap().len(), 256);
        let mut over = max;
        over.extend_from_slice(&[0, 0]);
        assert_eq!(decode_bundle(&over), Err(BundleError::TooManyEntries));
    }
}
