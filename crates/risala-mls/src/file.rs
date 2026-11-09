//! Encrypted files (12.11) and blob refs (12.12).
//!
//! **The file format.** A file is encrypted under a random 32-byte file
//! key. The plain text is the file's length as an 8-byte big-endian
//! number, the file, then zero bytes up to Padmé of 8 plus the file's
//! length. It is split into chunks of 65536 bytes (the last may be
//! shorter, never empty), and chunk i is encrypted with ChaCha20-Poly1305
//! under the file key, with the nonce `i (11 bytes, big-endian) || flag`,
//! where `flag` is `0x01` for the last chunk and `0x00` for the others.
//! The associated data of every chunk is a [`Label`]: the ASCII text
//! `risala/1 file`, or `risala/1 archive` for a history archive (12.13).
//! The upload is one version byte, `0x01`, then the encrypted chunks in
//! order, each followed by its tag.
//!
//! Since a chunk's position and flag are part of its nonce, a download
//! that was truncated at a chunk boundary, extended, reordered, or has a
//! chunk from another file or position fails to decrypt, and the label
//! keeps a file from being read as an archive and the reverse. A device
//! checks the SHA-384 hash of the whole upload (`file-hash`) before it
//! decrypts anything, then the version byte, then decrypts chunk by chunk,
//! and uses nothing unless every check passes.
//!
//! **Blob refs** (3.5, 12.12) name a blob by the SHA-384 hash of its bytes,
//! as `sha384:` and 96 lower-case hex digits. A `file-hash` is the same
//! hash, in base64 (12.9).

use std::fmt;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use sha2::Digest as _;
use zeroize::Zeroizing;

use crate::primitives::{AEAD_NONCE_LEN, AEAD_TAG_LEN, HASH_LEN, ct_eq, open, seal, sha384};

/// The length of a file key (12.11).
pub const FILE_KEY_LEN: usize = 32;

/// The length of a plain-text chunk, except perhaps the last (12.11).
pub const CHUNK_LEN: usize = 65536;

/// The length of an encrypted chunk with its tag, except perhaps the last.
pub const ENCRYPTED_CHUNK_LEN: usize = CHUNK_LEN + AEAD_TAG_LEN;

/// The length of the length at the start of the plain text (12.11).
pub const LENGTH_LEN: usize = 8;

/// The version byte at the start of every upload (12.11, 2.4).
pub const UPLOAD_VERSION: u8 = 1;

/// What an upload holds, which is the associated data of each of its
/// chunks (12.11): the ASCII label alone, without a length or terminator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Label {
    /// A file shared in a conversation, or carried with history (12.13):
    /// `risala/1 file`.
    File,
    /// A history archive (12.13): `risala/1 archive`.
    Archive,
}

impl Label {
    /// The label's bytes, the associated data of every chunk.
    pub fn as_bytes(self) -> &'static [u8] {
        match self {
            Label::File => b"risala/1 file",
            Label::Archive => b"risala/1 archive",
        }
    }
}

/// The prefix of a blob-ref (3.5).
pub const BLOB_REF_PREFIX: &str = "sha384:";

/// The length of a blob-ref's text: the prefix and 96 hex digits.
pub const BLOB_REF_TEXT_LEN: usize = BLOB_REF_PREFIX.len() + 2 * HASH_LEN;

/// Padmé \[PADME\] of `len` (12.11): for `len` of at least 2, with
/// E = floor(log2(len)), S = floor(log2(E)) + 1, z = E - S and
/// m = 2^z - 1, `len + m` with its lowest z bits cleared. 0 and 1 are
/// their own padded lengths. `None` if the result does not fit 64 bits.
pub fn padme(len: u64) -> Option<u64> {
    if len < 2 {
        return Some(len);
    }
    let e = len.ilog2();
    let s = e.ilog2() + 1;
    let z = e - s;
    let mask = (1u64 << z) - 1;
    Some(len.checked_add(mask)? & !mask)
}

/// The length of the plain text of a file of `file_len` bytes (12.11):
/// Padmé of 8 plus `file_len`.
pub fn plaintext_len(file_len: u64) -> Option<u64> {
    padme(file_len.checked_add(LENGTH_LEN as u64)?)
}

/// The length of the upload of a file of `file_len` bytes (12.11): the
/// version byte, then its padded plain text plus a tag per chunk. This is the `<size>` of UPLOAD
/// (5.6), and what the server learns. A device can compare it with a
/// download's length before it fetches the rest, but the length inside
/// the plain text is the one that counts, not `file-size` (12.11).
pub fn encrypted_len(file_len: u64) -> Option<u64> {
    let plain = plaintext_len(file_len)?;
    let chunks = plain.div_ceil(CHUNK_LEN as u64);
    plain
        .checked_add(chunks.checked_mul(AEAD_TAG_LEN as u64)?)?
        .checked_add(1)
}

/// The nonce of chunk `index` (12.11): the index as an 11-byte big-endian
/// number, then `0x01` for the last chunk or `0x00` for the others. An
/// index never reaches 2^64, so the top three bytes are zero.
fn chunk_nonce(index: u64, last: bool) -> [u8; AEAD_NONCE_LEN] {
    let mut nonce = [0; AEAD_NONCE_LEN];
    nonce[3..11].copy_from_slice(&index.to_be_bytes());
    nonce[11] = u8::from(last);
    nonce
}

/// Why a file cannot be encrypted or decrypted (12.11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FileError {
    /// The hash of the download is not `file-hash`, or a blob's is not its
    /// blob-ref. Nothing was decrypted.
    #[error("the file's hash does not match")]
    Hash,
    /// The download's first byte is not the version this device reads
    /// (2.4, 12.11). Nothing was decrypted.
    #[error("unsupported upload version {0}")]
    Version(u8),
    /// The download's length cannot be an upload: it is empty, has nothing
    /// after the version byte, or its last chunk would be empty.
    #[error("the file has the wrong length")]
    Length,
    /// A chunk does not decrypt: it was changed, moved, cut short,
    /// followed by more, or is under another key.
    #[error("chunk {0} of the file does not decrypt")]
    Chunk(u64),
    /// The length inside the plain text does not fit it, or the plain
    /// text is not exactly Padmé of 8 plus that length.
    #[error("the length inside the file is wrong")]
    InnerLength,
    /// The padding has a byte that is not zero.
    #[error("the file's padding is not zero")]
    Padding,
    /// More or fewer bytes were given to encrypt than the file's length,
    /// or the file is too large to pad.
    #[error("the file is not as long as declared")]
    Size,
}

/// A file key (12.11): 32 bytes, wiped when dropped. `Debug` does not
/// show it, and equality is in constant time.
#[derive(Clone)]
pub struct FileKey(Zeroizing<[u8; FILE_KEY_LEN]>);

impl FileKey {
    /// A new random file key.
    pub fn generate() -> Result<FileKey, getrandom::Error> {
        let mut key = Zeroizing::new([0; FILE_KEY_LEN]);
        getrandom::fill(&mut key[..])?;
        Ok(FileKey(key))
    }

    /// A file key from its bytes.
    pub fn from_bytes(bytes: [u8; FILE_KEY_LEN]) -> FileKey {
        FileKey(Zeroizing::new(bytes))
    }

    /// The key's bytes.
    pub fn as_bytes(&self) -> &[u8; FILE_KEY_LEN] {
        &self.0
    }

    /// The key as the `file-key` tag carries it (12.9): base64 with
    /// padding.
    pub fn to_base64(&self) -> Zeroizing<String> {
        Zeroizing::new(BASE64.encode(&self.0[..]))
    }

    /// Reads a `file-key` tag: exactly 32 bytes in canonical base64 with
    /// padding.
    pub fn from_base64(text: &str) -> Option<FileKey> {
        let mut key = Zeroizing::new([0; FILE_KEY_LEN]);
        decode_base64_exact(text, &mut key[..])?;
        Some(FileKey(key))
    }
}

impl PartialEq for FileKey {
    fn eq(&self, other: &FileKey) -> bool {
        ct_eq(&self.0[..], &other.0[..])
    }
}

impl Eq for FileKey {}

impl fmt::Debug for FileKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FileKey(…)")
    }
}

/// Decodes canonical base64 with padding into exactly `out.len()` bytes.
pub(crate) fn decode_base64_exact(text: &str, out: &mut [u8]) -> Option<()> {
    // The STANDARD engine wants padding and rejects non-zero trailing
    // bits, so only one text decodes to given bytes. A slice of exactly
    // the decoded length also rejects longer input.
    if text.len() != out.len().div_ceil(3) * 4 {
        return None;
    }
    match BASE64.decode_slice(text, out) {
        Ok(n) if n == out.len() => Some(()),
        _ => None,
    }
}

/// A SHA-384 hash that names bytes: a blob's (12.12), or a file's upload
/// as `file-hash` (12.11). Comparisons are in constant time.
#[derive(Clone, Copy)]
pub struct BlobRef([u8; HASH_LEN]);

impl BlobRef {
    /// The hash of `bytes`.
    pub fn of(bytes: &[u8]) -> BlobRef {
        BlobRef(sha384(bytes))
    }

    /// A hash from its 48 bytes.
    pub fn from_bytes(bytes: [u8; HASH_LEN]) -> BlobRef {
        BlobRef(bytes)
    }

    /// The hash's 48 bytes.
    pub fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }

    /// Checks, in constant time, that `bytes` hash to this hash. A device
    /// MUST do this before it uses a blob (12.12) or decrypts a file
    /// (12.11).
    pub fn check(&self, bytes: &[u8]) -> Result<(), FileError> {
        if *self == BlobRef::of(bytes) {
            Ok(())
        } else {
            Err(FileError::Hash)
        }
    }

    /// The hash as a `file-hash` tag carries it (12.9): base64 with
    /// padding, 64 characters.
    pub fn to_base64(&self) -> String {
        BASE64.encode(self.0)
    }

    /// Reads a `file-hash` tag: exactly 48 bytes in canonical base64 with
    /// padding.
    pub fn from_base64(text: &str) -> Option<BlobRef> {
        let mut out = [0; HASH_LEN];
        decode_base64_exact(text, &mut out)?;
        Some(BlobRef(out))
    }
}

impl PartialEq for BlobRef {
    fn eq(&self, other: &BlobRef) -> bool {
        ct_eq(&self.0, &other.0)
    }
}

impl Eq for BlobRef {}

impl fmt::Debug for BlobRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlobRef({self})")
    }
}

/// The blob-ref text (3.5): `sha384:` and 96 lower-case hex digits.
impl fmt::Display for BlobRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(BLOB_REF_PREFIX)?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// Why a blob-ref cannot be read (3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a blob-ref is sha384: and 96 lower-case hex digits")]
pub struct BlobRefError;

impl FromStr for BlobRef {
    type Err = BlobRefError;

    /// Reads a blob-ref (3.5). Only lower-case hex is accepted, so each
    /// hash has one text.
    fn from_str(s: &str) -> Result<BlobRef, BlobRefError> {
        let hex = s.strip_prefix(BLOB_REF_PREFIX).ok_or(BlobRefError)?;
        if hex.len() != 2 * HASH_LEN {
            return Err(BlobRefError);
        }
        let digit = |c: u8| match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            _ => Err(BlobRefError),
        };
        let mut out = [0; HASH_LEN];
        let (pairs, _) = hex.as_bytes().as_chunks::<2>();
        for (o, [high, low]) in out.iter_mut().zip(pairs) {
            *o = (digit(*high)? << 4) | digit(*low)?;
        }
        Ok(BlobRef(out))
    }
}

/// SHA-384 of bytes that arrive in pieces, such as a download.
#[derive(Clone, Default)]
pub struct Hasher(sha2::Sha384);

impl Hasher {
    /// A hasher with nothing in it.
    pub fn new() -> Hasher {
        Hasher::default()
    }

    /// Adds `data`.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// The hash of everything added.
    pub fn finish(self) -> BlobRef {
        BlobRef(self.0.finalize().into())
    }
}

/// An encrypted file, ready to upload (12.11).
#[derive(Debug)]
pub struct EncryptedFile {
    /// The bytes to upload.
    pub upload: Vec<u8>,
    /// The file key, for `file-key`.
    pub key: FileKey,
    /// The hash of `upload`, for `file-hash`, or the blob-ref when it is
    /// stored as a blob.
    pub hash: BlobRef,
    /// The file's length before encryption, for `file-size`.
    pub size: u64,
}

/// Encrypts `file`, as `label` says it is, under a new random key (12.11).
pub fn encrypt(label: Label, file: &[u8]) -> Result<EncryptedFile, getrandom::Error> {
    let key = FileKey::generate()?;
    let (upload, hash) = encrypt_with_key(&key, label, file);
    Ok(EncryptedFile {
        upload,
        key,
        hash,
        size: file.len() as u64,
    })
}

/// Encrypts `file` under `key` with `label` (12.11), giving the upload
/// and its hash. A key MUST NOT encrypt two files, since the nonces repeat;
/// [`encrypt`] makes a new one.
pub fn encrypt_with_key(key: &FileKey, label: Label, file: &[u8]) -> (Vec<u8>, BlobRef) {
    let mut encryptor =
        Encryptor::new(key, label, file.len() as u64).expect("a file in memory can be padded");
    let mut upload = Vec::with_capacity(
        usize::try_from(encryptor.encrypted_len())
            .expect("it fits in memory, padded by at most 12%"),
    );
    encryptor
        .update(file, &mut upload)
        .expect("the file is as long as declared");
    let hash = encryptor
        .finish(&mut upload)
        .expect("the file is as long as declared");
    (upload, hash)
}

/// Encrypts a file that arrives in pieces (12.11). Its length must be
/// known at the start, since it is at the front of the plain text.
pub struct Encryptor {
    key: FileKey,
    label: Label,
    /// Whether the version byte has been written.
    started: bool,
    /// The plain text not yet encrypted: less than one chunk.
    pending: Zeroizing<Vec<u8>>,
    /// The index of the next chunk.
    index: u64,
    /// The index of the last chunk.
    last: u64,
    /// The file's bytes still to come.
    remaining: u64,
    /// Zero bytes still to add after the file.
    padding: u64,
    encrypted_len: u64,
    hasher: Hasher,
}

impl Encryptor {
    /// Starts encrypting a file of `file_len` bytes under `key`, with
    /// `label`. A key MUST NOT encrypt two files.
    pub fn new(key: &FileKey, label: Label, file_len: u64) -> Result<Encryptor, FileError> {
        let plain = plaintext_len(file_len).ok_or(FileError::Size)?;
        let encrypted_len = encrypted_len(file_len).ok_or(FileError::Size)?;
        let mut pending = Zeroizing::new(Vec::with_capacity(CHUNK_LEN));
        pending.extend_from_slice(&file_len.to_be_bytes());
        Ok(Encryptor {
            key: key.clone(),
            label,
            started: false,
            pending,
            index: 0,
            // The plain text is at least 8 bytes, so there is a chunk.
            last: (plain - 1) / CHUNK_LEN as u64,
            remaining: file_len,
            padding: plain - LENGTH_LEN as u64 - file_len,
            encrypted_len,
            hasher: Hasher::new(),
        })
    }

    /// The length the upload will have.
    pub fn encrypted_len(&self) -> u64 {
        self.encrypted_len
    }

    /// Encrypts the next piece of the file, appending the version byte and
    /// whole encrypted chunks to `out`.
    pub fn update(&mut self, mut data: &[u8], out: &mut Vec<u8>) -> Result<(), FileError> {
        if data.len() as u64 > self.remaining {
            return Err(FileError::Size);
        }
        self.start(out);
        self.remaining -= data.len() as u64;
        while !data.is_empty() {
            let take = (CHUNK_LEN - self.pending.len()).min(data.len());
            self.pending.extend_from_slice(&data[..take]);
            data = &data[take..];
            self.flush_full(out);
        }
        Ok(())
    }

    /// Adds the padding, encrypts the rest, and gives the upload's hash.
    pub fn finish(mut self, out: &mut Vec<u8>) -> Result<BlobRef, FileError> {
        if self.remaining != 0 {
            return Err(FileError::Size);
        }
        self.start(out);
        while self.padding > 0 {
            let take = ((CHUNK_LEN - self.pending.len()) as u64).min(self.padding) as usize;
            let len = self.pending.len() + take;
            self.pending.resize(len, 0);
            self.padding -= take as u64;
            self.flush_full(out);
        }
        if !self.pending.is_empty() {
            self.seal_pending(out);
        }
        debug_assert_eq!(self.index, self.last + 1);
        Ok(self.hasher.finish())
    }

    /// Writes the version byte, once, before the first chunk.
    fn start(&mut self, out: &mut Vec<u8>) {
        if !self.started {
            self.started = true;
            self.hasher.update(&[UPLOAD_VERSION]);
            out.push(UPLOAD_VERSION);
        }
    }

    /// Encrypts the pending chunk if it is full.
    fn flush_full(&mut self, out: &mut Vec<u8>) {
        if self.pending.len() == CHUNK_LEN {
            self.seal_pending(out);
        }
    }

    fn seal_pending(&mut self, out: &mut Vec<u8>) {
        let nonce = chunk_nonce(self.index, self.index == self.last);
        let chunk = seal(
            self.key.as_bytes(),
            &nonce,
            self.label.as_bytes(),
            &self.pending,
        );
        self.hasher.update(&chunk);
        out.extend_from_slice(&chunk);
        self.pending.clear();
        self.index += 1;
    }
}

/// Checks `upload` against `file_hash`, then decrypts it as `label` says
/// it is (12.11). The hash is checked before anything is decrypted, and the
/// file is given only if every check passes.
pub fn decrypt(
    key: &FileKey,
    label: Label,
    file_hash: &BlobRef,
    upload: &[u8],
) -> Result<Zeroizing<Vec<u8>>, FileError> {
    file_hash.check(upload)?;
    let mut decryptor = Decryptor::new(key, label);
    let mut file = Zeroizing::new(Vec::new());
    decryptor.update(upload, &mut file)?;
    decryptor.finish(&mut file)?;
    Ok(file)
}

/// Decrypts an upload that arrives in pieces (12.11).
///
/// The caller MUST first check the whole upload's hash against
/// `file-hash` (with [`Hasher`] or [`BlobRef::check`]), and MUST NOT show
/// or save anything this gives unless [`Decryptor::finish`] succeeds.
pub struct Decryptor {
    key: FileKey,
    label: Label,
    /// Whether the version byte has been read and checked.
    started: bool,
    /// Encrypted bytes not yet decrypted: at most one encrypted chunk.
    pending: Vec<u8>,
    index: u64,
    /// The file's length, once the first chunk is decrypted.
    file_len: Option<u64>,
    /// The plain text decrypted so far.
    plain_len: u64,
    failed: Option<FileError>,
}

impl Decryptor {
    /// Starts decrypting an upload under `key`, which `label` says what it
    /// holds.
    pub fn new(key: &FileKey, label: Label) -> Decryptor {
        Decryptor {
            key: key.clone(),
            label,
            started: false,
            pending: Vec::with_capacity(ENCRYPTED_CHUNK_LEN),
            index: 0,
            file_len: None,
            plain_len: 0,
            failed: None,
        }
    }

    /// Decrypts the next piece of the upload, appending the file's bytes
    /// to `out`. A chunk is decrypted only once a byte after it has
    /// arrived, since only then is it known not to be the last.
    pub fn update(&mut self, mut data: &[u8], out: &mut Vec<u8>) -> Result<(), FileError> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        if !self.started
            && let Some((&version, rest)) = data.split_first()
        {
            self.started = true;
            if version != UPLOAD_VERSION {
                self.failed = Some(FileError::Version(version));
                return Err(FileError::Version(version));
            }
            data = rest;
        }
        while !data.is_empty() {
            if self.pending.len() == ENCRYPTED_CHUNK_LEN {
                self.open_pending(false, out)?;
            }
            let take = (ENCRYPTED_CHUNK_LEN - self.pending.len()).min(data.len());
            self.pending.extend_from_slice(&data[..take]);
            data = &data[take..];
        }
        Ok(())
    }

    /// Decrypts the last chunk and checks the length and padding. Gives
    /// the file's length.
    pub fn finish(mut self, out: &mut Vec<u8>) -> Result<u64, FileError> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        // An empty upload, nothing after the version, or a last chunk with
        // nothing but a tag.
        if !self.started || self.pending.len() <= AEAD_TAG_LEN {
            return Err(FileError::Length);
        }
        self.open_pending(true, out)?;
        let file_len = self.file_len.ok_or(FileError::InnerLength)?;
        // The plain text is exactly Padmé of 8 + L bytes (12.11).
        if plaintext_len(file_len) != Some(self.plain_len) {
            return Err(FileError::InnerLength);
        }
        Ok(file_len)
    }

    fn open_pending(&mut self, last: bool, out: &mut Vec<u8>) -> Result<(), FileError> {
        let result = self.open_pending_inner(last, out);
        if let Err(error) = result {
            self.failed = Some(error);
        }
        result
    }

    fn open_pending_inner(&mut self, last: bool, out: &mut Vec<u8>) -> Result<(), FileError> {
        let nonce = chunk_nonce(self.index, last);
        let plain = open(
            self.key.as_bytes(),
            &nonce,
            self.label.as_bytes(),
            &self.pending,
        )
        .ok_or(FileError::Chunk(self.index))?;
        self.pending.clear();
        self.index += 1;

        let mut body = &plain[..];
        if self.file_len.is_none() {
            let length = body.get(..LENGTH_LEN).ok_or(FileError::InnerLength)?;
            let file_len = u64::from_be_bytes(length.try_into().expect("8 bytes"));
            // A length that cannot fit is caught here, before any of the
            // file is given; one that fits a longer plain text than this
            // is caught by finish.
            let plain_len = plaintext_len(file_len).ok_or(FileError::InnerLength)?;
            if last && plain_len != plain.len() as u64 {
                return Err(FileError::InnerLength);
            }
            self.file_len = Some(file_len);
            body = &body[LENGTH_LEN..];
            self.plain_len = LENGTH_LEN as u64;
        }
        let file_len = self.file_len.expect("set above");
        // The file's bytes still to come, then padding.
        let file_left = (LENGTH_LEN as u64 + file_len).saturating_sub(self.plain_len);
        let take = usize::try_from(file_left.min(body.len() as u64)).expect("at most a chunk");
        let (file_part, padding) = body.split_at(take);
        if padding.iter().fold(0, |acc, b| acc | b) != 0 {
            return Err(FileError::Padding);
        }
        self.plain_len += body.len() as u64;
        out.extend_from_slice(file_part);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Counting bytes: 0, 1, 2, ... modulo 251, so that chunks differ.
    fn counting(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    fn key() -> FileKey {
        FileKey::from_bytes(std::array::from_fn(|i| i as u8))
    }

    /// Encrypts `file` as a file under `key`.
    fn enc(key: &FileKey, file: &[u8]) -> (Vec<u8>, BlobRef) {
        encrypt_with_key(key, Label::File, file)
    }

    /// Padmé by its definition, with floating point avoided: the published
    /// algorithm \[PADME\] spelled out.
    fn padme_reference(l: u64) -> u64 {
        if l < 2 {
            return l;
        }
        let e = 63 - l.leading_zeros() as u64;
        let s = 64 - e.leading_zeros() as u64;
        let last_bits = e - s;
        let mask = (1u64 << last_bits) - 1;
        (l + mask) & !mask
    }

    #[test]
    fn padme_values() {
        for (l, padded) in [
            (0, 0),
            (1, 1),
            (2, 2),
            (3, 3),
            (8, 8),
            (9, 10),
            (10, 10),
            (11, 12),
            (100, 104),
            (1000, 1024),
            (1025, 1088),
            (65536, 65536),
            (65537, 67584),
            (1_000_000, 1_015_808),
        ] {
            assert_eq!(padme(l), Some(padded), "Padmé of {l}");
        }
        for l in (0..5000).chain([u32::MAX as u64, 1 << 40, (1 << 40) + 1]) {
            let p = padme(l).unwrap();
            assert_eq!(p, padme_reference(l));
            assert!(p >= l);
            // At most about 12% more.
            assert!(p - l <= l / 8 + 1, "{l} padded to {p}");
        }
        assert_eq!(padme(u64::MAX), None);
        assert_eq!(plaintext_len(u64::MAX), None);
        assert_eq!(encrypted_len(u64::MAX - 8), None);
    }

    #[test]
    fn lengths() {
        assert_eq!(plaintext_len(0), Some(8));
        assert_eq!(encrypted_len(0), Some(25));
        assert_eq!(plaintext_len(1), Some(10));
        assert_eq!(plaintext_len(65528), Some(65536));
        assert_eq!(encrypted_len(65528), Some(65553));
        assert_eq!(plaintext_len(65529), Some(67584));
        assert_eq!(encrypted_len(65529), Some(67584 + 32 + 1));
        for len in [0, 1, 7, 100, 65527, 65528, 65529, 200_000] {
            let (upload, _) = enc(&key(), &counting(len));
            assert_eq!(upload.len() as u64, encrypted_len(len as u64).unwrap());
            assert_eq!(upload[0], UPLOAD_VERSION);
        }
    }

    #[test]
    fn round_trips() {
        for len in [
            0,
            1,
            2,
            100,
            CHUNK_LEN - 9,
            CHUNK_LEN - 8,
            CHUNK_LEN - 7,
            CHUNK_LEN,
            2 * CHUNK_LEN - 8,
            300_000,
        ] {
            let file = counting(len);
            for label in [Label::File, Label::Archive] {
                let encrypted = encrypt(label, &file).unwrap();
                assert_eq!(encrypted.size, len as u64);
                assert_eq!(encrypted.hash, BlobRef::of(&encrypted.upload));
                let decrypted =
                    decrypt(&encrypted.key, label, &encrypted.hash, &encrypted.upload).unwrap();
                assert_eq!(&decrypted[..], &file[..], "length {len}");
            }
        }
        // A new key each time.
        assert_ne!(
            encrypt(Label::File, b"x").unwrap().key,
            encrypt(Label::File, b"x").unwrap().key
        );
    }

    /// Feeding the encryptor and decryptor in odd pieces gives the same
    /// bytes as all at once.
    #[test]
    fn streaming() {
        let file = counting(3 * CHUNK_LEN + 12345);
        let (whole, hash) = enc(&key(), &file);
        for piece in [
            1,
            7,
            4096,
            CHUNK_LEN,
            ENCRYPTED_CHUNK_LEN,
            ENCRYPTED_CHUNK_LEN + 1,
        ] {
            let mut encryptor = Encryptor::new(&key(), Label::File, file.len() as u64).unwrap();
            let mut upload = Vec::new();
            for part in file.chunks(piece) {
                encryptor.update(part, &mut upload).unwrap();
            }
            assert_eq!(encryptor.finish(&mut upload).unwrap(), hash);
            assert_eq!(upload, whole);

            let mut hasher = Hasher::new();
            let mut decryptor = Decryptor::new(&key(), Label::File);
            let mut out = Vec::new();
            for part in upload.chunks(piece) {
                hasher.update(part);
                decryptor.update(part, &mut out).unwrap();
            }
            assert_eq!(hasher.finish(), hash);
            assert_eq!(decryptor.finish(&mut out).unwrap(), file.len() as u64);
            assert_eq!(out, file);
        }
    }

    #[test]
    fn encryptor_checks_length() {
        let mut out = Vec::new();
        let mut e = Encryptor::new(&key(), Label::File, 3).unwrap();
        assert_eq!(e.update(b"abcd", &mut out), Err(FileError::Size));
        let mut e = Encryptor::new(&key(), Label::File, 3).unwrap();
        e.update(b"ab", &mut out).unwrap();
        assert_eq!(e.finish(&mut out), Err(FileError::Size));
        assert!(Encryptor::new(&key(), Label::File, u64::MAX).is_err());
        // An empty file still gets its version byte, once.
        let mut out = Vec::new();
        let mut e = Encryptor::new(&key(), Label::File, 0).unwrap();
        e.update(b"", &mut out).unwrap();
        let hash = e.finish(&mut out).unwrap();
        assert_eq!(out.len(), 25);
        assert_eq!((out.clone(), hash), enc(&key(), b""));
    }

    /// Decrypts without the hash check, to reach the chunk checks behind
    /// it.
    fn decrypt_unhashed(key: &FileKey, upload: &[u8]) -> Result<Vec<u8>, FileError> {
        decrypt(key, Label::File, &BlobRef::of(upload), upload).map(|f| f.to_vec())
    }

    /// Chunk `index` of `upload`, with its tag, after the version byte.
    fn chunk(upload: &[u8], index: usize) -> &[u8] {
        let start = 1 + index * ENCRYPTED_CHUNK_LEN;
        &upload[start..(start + ENCRYPTED_CHUNK_LEN).min(upload.len())]
    }

    /// The version byte, then `chunks`.
    fn upload_of(chunks: &[&[u8]]) -> Vec<u8> {
        [&[UPLOAD_VERSION][..], &chunks.concat()].concat()
    }

    #[test]
    fn rejections() {
        let file = counting(3 * CHUNK_LEN);
        let (upload, hash) = enc(&key(), &file);
        // 3 * 65536 + 8 bytes pad to 3 * 65536 + 4096: four chunks.
        assert_eq!(upload.len(), 1 + 3 * ENCRYPTED_CHUNK_LEN + 4096 + 16);
        let chunks: Vec<&[u8]> = (0..4).map(|i| chunk(&upload, i)).collect();

        // The hash is checked first: a flipped bit fails it.
        let mut changed = upload.clone();
        changed[100] ^= 1;
        assert_eq!(
            decrypt(&key(), Label::File, &hash, &changed),
            Err(FileError::Hash)
        );
        // ... and with a matching hash, the chunk fails.
        assert_eq!(decrypt_unhashed(&key(), &changed), Err(FileError::Chunk(0)));

        // Another key.
        let other = FileKey::from_bytes([9; 32]);
        assert_eq!(
            decrypt(&other, Label::File, &hash, &upload),
            Err(FileError::Chunk(0))
        );
        // The same upload read as an archive: the label differs.
        assert_eq!(
            decrypt(&key(), Label::Archive, &hash, &upload),
            Err(FileError::Chunk(0))
        );

        // Another version byte, checked after the hash and before any
        // chunk.
        for version in [0, 2, 0xff] {
            let mut b = upload.clone();
            b[0] = version;
            assert_eq!(
                decrypt(&key(), Label::File, &hash, &b),
                Err(FileError::Hash)
            );
            assert_eq!(
                decrypt_unhashed(&key(), &b),
                Err(FileError::Version(version))
            );
        }
        // No version byte at all: the chunks alone.
        assert_eq!(
            decrypt_unhashed(&key(), &upload[1..]),
            Err(FileError::Version(upload[1]))
        );

        // Truncated at a chunk boundary: the new last chunk lacks the flag.
        let truncated = upload_of(&chunks[..3]);
        assert_eq!(
            decrypt_unhashed(&key(), &truncated),
            Err(FileError::Chunk(2))
        );
        // Truncated inside a chunk.
        assert_eq!(
            decrypt_unhashed(&key(), &upload[..upload.len() - 1]),
            Err(FileError::Chunk(3))
        );
        // Extended by a chunk: the old last chunk has the flag.
        let extended = [&upload[..], chunks[1]].concat();
        assert_eq!(extended.len(), upload.len() + ENCRYPTED_CHUNK_LEN);
        assert_eq!(
            decrypt_unhashed(&key(), &extended),
            Err(FileError::Chunk(3))
        );
        // Extended by a byte.
        assert_eq!(
            decrypt_unhashed(&key(), &[&upload[..], &[0]].concat()),
            Err(FileError::Chunk(3))
        );
        // Bytes after a full last chunk: a tag's worth or less is a chunk
        // that cannot be, and more is a chunk that does not decrypt.
        let (full, _) = enc(&key(), &counting(CHUNK_LEN - 8));
        assert_eq!(full.len(), 1 + ENCRYPTED_CHUNK_LEN);
        assert_eq!(
            decrypt_unhashed(&key(), &[&full[..], &[0; 16]].concat()),
            Err(FileError::Chunk(0))
        );
        assert_eq!(
            decrypt_unhashed(&key(), &[&full[..], &[0; 17]].concat()),
            Err(FileError::Chunk(0))
        );
        // Reordered, and a chunk repeated in place of another.
        let swapped = upload_of(&[chunks[1], chunks[0], chunks[2], chunks[3]]);
        assert_eq!(decrypt_unhashed(&key(), &swapped), Err(FileError::Chunk(0)));
        let repeated = upload_of(&[chunks[0], chunks[0], chunks[2], chunks[3]]);
        assert_eq!(
            decrypt_unhashed(&key(), &repeated),
            Err(FileError::Chunk(1))
        );
        // A chunk from another file, in its own place.
        let other_file: Vec<u8> = file.iter().map(|b| !b).collect();
        let (other_upload, _) = enc(&FileKey::from_bytes([7; 32]), &other_file);
        let spliced = upload_of(&[chunks[0], chunk(&other_upload, 1), chunks[2], chunks[3]]);
        assert_eq!(decrypt_unhashed(&key(), &spliced), Err(FileError::Chunk(1)));
        // Had both files used one key, which a sender must never do, the
        // chunk would decrypt: the hash is what catches it then.
        let (same_key, _) = enc(&key(), &other_file);
        let spliced = upload_of(&[chunks[0], chunk(&same_key, 1), chunks[2], chunks[3]]);
        assert!(decrypt_unhashed(&key(), &spliced).is_ok());
        assert_eq!(
            decrypt(&key(), Label::File, &hash, &spliced),
            Err(FileError::Hash)
        );
        // Empty, the version byte alone, or with a tag's worth after it.
        assert_eq!(decrypt_unhashed(&key(), b""), Err(FileError::Length));
        assert_eq!(decrypt_unhashed(&key(), &[1]), Err(FileError::Length));
        assert_eq!(decrypt_unhashed(&key(), &[1; 17]), Err(FileError::Length));
        // The last chunk dropped to just the tag's length.
        assert_eq!(
            decrypt_unhashed(&key(), &upload[..1 + 3 * ENCRYPTED_CHUNK_LEN + 16]),
            Err(FileError::Length)
        );

        // A failed decryptor stays failed.
        let mut d = Decryptor::new(&key(), Label::File);
        let mut out = Vec::new();
        d.update(&swapped, &mut out).unwrap_err();
        assert_eq!(d.update(b"x", &mut out), Err(FileError::Chunk(0)));
        assert_eq!(d.finish(&mut out), Err(FileError::Chunk(0)));
        let mut d = Decryptor::new(&key(), Label::File);
        assert_eq!(d.update(&[2], &mut out), Err(FileError::Version(2)));
        assert_eq!(d.update(&upload[1..], &mut out), Err(FileError::Version(2)));
        assert_eq!(d.finish(&mut out), Err(FileError::Version(2)));
    }

    /// Encrypts a hand-made plain text in the 12.11 layout.
    fn seal_plaintext(plain: &[u8]) -> Vec<u8> {
        let count = plain.len().div_ceil(CHUNK_LEN);
        let mut out = vec![UPLOAD_VERSION];
        for (i, part) in plain.chunks(CHUNK_LEN).enumerate() {
            let nonce = chunk_nonce(i as u64, i + 1 == count);
            out.extend(seal(key().as_bytes(), &nonce, Label::File.as_bytes(), part));
        }
        out
    }

    #[test]
    fn labels() {
        assert_eq!(Label::File.as_bytes(), b"risala/1 file");
        assert_eq!(Label::Archive.as_bytes(), b"risala/1 archive");
        // The first chunk's tag is over the label as associated data.
        let (upload, _) = enc(&key(), b"hi");
        let plain = [&2u64.to_be_bytes()[..], b"hi"].concat();
        let expected = seal(
            key().as_bytes(),
            &chunk_nonce(0, true),
            b"risala/1 file",
            &plain,
        );
        assert_eq!(&upload[1..], &expected[..]);
    }

    #[test]
    fn inner_checks() {
        let well_formed = |len: u64, body: &[u8], pad: usize| {
            [&len.to_be_bytes()[..], body, &vec![0; pad]].concat()
        };
        // The layout itself decrypts.
        assert_eq!(
            decrypt_unhashed(&key(), &seal_plaintext(&well_formed(2, b"hi", 0))).unwrap(),
            b"hi"
        );
        // A length past the plain text.
        assert_eq!(
            decrypt_unhashed(&key(), &seal_plaintext(&well_formed(3, b"hi", 0))),
            Err(FileError::InnerLength)
        );
        // A length too large to pad.
        assert_eq!(
            decrypt_unhashed(&key(), &seal_plaintext(&well_formed(u64::MAX, b"hi", 0))),
            Err(FileError::InnerLength)
        );
        // A shorter length than the data: the rest is not zero padding.
        assert_eq!(
            decrypt_unhashed(&key(), &seal_plaintext(&well_formed(1, b"hi", 0))),
            Err(FileError::Padding)
        );
        // Non-zero padding: 1 byte of file pads to 10 bytes.
        let mut plain = well_formed(1, b"h", 1);
        plain[9] = 1;
        assert_eq!(
            decrypt_unhashed(&key(), &seal_plaintext(&plain)),
            Err(FileError::Padding)
        );
        assert_eq!(
            decrypt_unhashed(&key(), &seal_plaintext(&well_formed(1, b"h", 1))).unwrap(),
            b"h"
        );
        // More padding than Padmé gives.
        assert_eq!(
            decrypt_unhashed(&key(), &seal_plaintext(&well_formed(1, b"h", 3))),
            Err(FileError::InnerLength)
        );
        // A first chunk shorter than the length.
        assert_eq!(
            decrypt_unhashed(&key(), &seal_plaintext(&[0; 5])),
            Err(FileError::InnerLength)
        );
        // A length that spans more chunks than there are.
        let plain = well_formed(70_000, &counting(65528), 0);
        assert_eq!(
            decrypt_unhashed(&key(), &seal_plaintext(&plain)),
            Err(FileError::InnerLength)
        );
        // Non-zero padding in a later chunk.
        let len = 65529u64;
        let mut plain = well_formed(len, &counting(len as usize), 67584 - 8 - len as usize);
        assert_eq!(
            decrypt_unhashed(&key(), &seal_plaintext(&plain)).unwrap(),
            counting(len as usize)
        );
        *plain.last_mut().unwrap() = 1;
        assert_eq!(
            decrypt_unhashed(&key(), &seal_plaintext(&plain)),
            Err(FileError::Padding)
        );
    }

    #[test]
    fn nonces() {
        assert_eq!(chunk_nonce(0, false), [0; 12]);
        assert_eq!(chunk_nonce(0, true), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(
            chunk_nonce(0x0102_0304_0506_0708, false),
            [0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0]
        );
    }

    #[test]
    fn keys_and_hashes() {
        let k = key();
        assert_eq!(FileKey::from_base64(&k.to_base64()), Some(k.clone()));
        assert_eq!(k.to_base64().len(), 44);
        assert_eq!(format!("{k:?}"), "FileKey(…)");
        assert_eq!(FileKey::from_base64("AAAA"), None);
        // Non-canonical: the last character carries non-zero spare bits.
        let mut text = k.to_base64().to_string();
        text.replace_range(42..43, "B");
        assert_eq!(FileKey::from_base64(&text), None);
        assert_eq!(FileKey::from_base64(&text.replace('=', "")), None);

        let h = BlobRef::of(b"abc");
        let text = h.to_string();
        assert_eq!(
            text,
            "sha384:cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
             8086072ba1e7cc2358baeca134c825a7"
        );
        assert_eq!(text.len(), BLOB_REF_TEXT_LEN);
        assert_eq!(text.parse::<BlobRef>(), Ok(h));
        assert_eq!(text.to_uppercase().parse::<BlobRef>(), Err(BlobRefError));
        assert_eq!(
            text.replace("sha384:", "SHA384:").parse::<BlobRef>(),
            Err(BlobRefError)
        );
        assert_eq!(text[..text.len() - 1].parse::<BlobRef>(), Err(BlobRefError));
        assert_eq!(format!("{text}0").parse::<BlobRef>(), Err(BlobRefError));
        assert_eq!(text.replace('c', "g").parse::<BlobRef>(), Err(BlobRefError));
        assert_eq!(
            text.replacen("cb", "+b", 1).parse::<BlobRef>(),
            Err(BlobRefError)
        );
        assert_eq!(h.check(b"abc"), Ok(()));
        assert_eq!(h.check(b"abd"), Err(FileError::Hash));
        assert_eq!(BlobRef::from_base64(&h.to_base64()), Some(h));
        assert_eq!(h.to_base64().len(), 64);
        let mut hasher = Hasher::new();
        hasher.update(b"a");
        hasher.update(b"bc");
        assert_eq!(hasher.finish(), h);
    }

    const FILE_VECTOR_UPLOAD: &str = "01695c7cd9310ab87445141243dc38376079825e2cafbb7fb2f4733b92958a61\
     462ef6b8fc2908";
    const FILE_VECTOR_HASH: &str =
        "NhCQTv1i4+tHqcz5ZpTBHCwVGQ3x1hFYL592D7m0qvnuYSm2BhfToxD1N1yyOGhK";
    const FILE_VECTOR_ARCHIVE: &str = "01695c7cd9310ab87445141243dc38376079825e2cafbb6a50e919373de1083f\
     d8a25c88a12d43";
    const FILE_VECTOR_TWO_CHUNKS: &str = "sha384:df178956097f8985bee1e44daa2cf41c0f5a54cf7cd23297250ba8072\
     3370c93d952bf4838eaa576bfe62949b83d745e";

    /// A fixed-input vector for Appendix B: the file "hello, risala\n"
    /// under the key 00 01 ... 1f.
    #[test]
    fn vector() {
        let file = b"hello, risala\n";
        let (upload, hash) = enc(&key(), file);
        // 8 + 14 = 22 bytes, which Padmé leaves as they are.
        assert_eq!(upload.len(), 1 + 22 + 16);
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        println!("file key   {}", hex(key().as_bytes()));
        println!("file       {}", hex(file));
        println!("upload     {}", hex(&upload));
        println!("file-hash  {}", hash.to_base64());
        println!("blob-ref   {hash}");
        assert_eq!(hex(&upload), FILE_VECTOR_UPLOAD);
        assert_eq!(
            decrypt(&key(), Label::File, &hash, &upload)
                .unwrap()
                .as_slice(),
            file
        );
        assert_eq!(hash.to_base64(), FILE_VECTOR_HASH);
        // The same file and key as an archive.
        let (archive, archive_hash) = encrypt_with_key(&key(), Label::Archive, file);
        println!("as archive {}", hex(&archive));
        println!("archive-hash {}", archive_hash.to_base64());
        assert_eq!(hex(&archive), FILE_VECTOR_ARCHIVE);

        // Two chunks: 65529 counting bytes pad to 67584, the second chunk
        // carrying the last-chunk flag.
        let (upload, hash) = enc(&key(), &counting(65529));
        println!("65529 bytes {hash}");
        assert_eq!(upload.len(), 67617);
        assert_eq!(hash.to_string(), FILE_VECTOR_TWO_CHUNKS);
    }
    /// Appendix B.15: [`vector`] and its cases that must fail, checked
    /// against the appendix.
    #[test]
    fn appendix_b() {
        let mut ck = crate::appendix::Checker::open("B.15 ");
        let file_1 = b"hello, risala\n";
        let file_2 = counting(65529);
        ck.hex("file key", key().as_bytes());
        ck.hex("file 1", file_1);
        ck.eq("file 2", "65529 bytes, byte i being i modulo 251");
        ck.gap();
        let (upload_1, hash_1) = enc(&key(), file_1);
        ck.hex("upload of file 1", &upload_1);
        ck.eq("file-hash of file 1", hash_1.to_base64());
        ck.eq("blob-ref of file 1", hash_1.to_string());
        let (archive_1, archive_hash) = encrypt_with_key(&key(), Label::Archive, file_1);
        ck.hex("file 1 as an archive", &archive_1);
        let (upload_2, hash_2) = enc(&key(), &file_2);
        ck.eq("length of the upload of file 2", upload_2.len().to_string());
        ck.eq("blob-ref of file 2", hash_2.to_string());
        assert_eq!(
            decrypt(&key(), Label::File, &hash_1, &upload_1)
                .unwrap()
                .as_slice(),
            file_1
        );
        assert_eq!(
            decrypt(&key(), Label::Archive, &archive_hash, &archive_1)
                .unwrap()
                .as_slice(),
            file_1
        );
        assert_eq!(
            decrypt(&key(), Label::File, &hash_2, &upload_2)
                .unwrap()
                .as_slice(),
            &file_2[..]
        );
        ck.gap();
        let fails = |upload: &[u8]| decrypt_unhashed(&key(), upload).is_err();
        let mut version = upload_1.clone();
        version[0] = 2;
        ck.rejected("the upload of file 1 with version byte 2", fails(&version));
        ck.rejected(
            "file 1 as an archive, decrypted as a file",
            decrypt(&key(), Label::File, &archive_hash, &archive_1).is_err(),
        );
        let chunks = [chunk(&upload_2, 0), chunk(&upload_2, 1)];
        ck.rejected(
            "the upload of file 2 cut after its first chunk",
            fails(&upload_of(&chunks[..1])),
        );
        ck.rejected(
            "the upload of file 2 with its two chunks swapped",
            fails(&upload_of(&[chunks[1], chunks[0]])),
        );
        ck.rejected(
            "the upload of file 2 with its first chunk again after the last",
            fails(&upload_of(&[chunks[0], chunks[1], chunks[0]])),
        );
        // Both chunks sealed with the last-chunk flag.
        let plain = [
            &(file_2.len() as u64).to_be_bytes()[..],
            &file_2,
            &vec![0; 67584 - 8 - file_2.len()],
        ]
        .concat();
        let mut flagged = vec![UPLOAD_VERSION];
        for (i, part) in plain.chunks(CHUNK_LEN).enumerate() {
            flagged.extend(seal(
                key().as_bytes(),
                &chunk_nonce(i as u64, true),
                Label::File.as_bytes(),
                part,
            ));
        }
        assert_eq!(flagged.len(), upload_2.len());
        assert!(fails(&flagged));
        ck.file(
            "file 2 with the last-chunk flag on its first chunk too",
            "file-flagged.bin",
            &flagged,
        );
        ck.gap();
        let plain = |len: u64, body: &[u8]| [&len.to_be_bytes()[..], body].concat();
        let bad = [
            ("length 1, h, then the padding byte 01", plain(1, b"h\x01")),
            ("length 1, h, then 3 zero bytes", plain(1, b"h\0\0\0")),
            ("length 3, then hi", plain(3, b"hi")),
        ];
        for (name, plain) in bad {
            let upload = seal_plaintext(&plain);
            assert!(fails(&upload), "{name}");
            ck.hex(name, &upload);
        }
        ck.finish();
    }
}
