//! Recovery keys and backups (4.8, 12.13).
//!
//! - A **recovery key** is 32 random bytes, shown once when an identity
//!   is made, as 52 characters of lower-case base32 [RFC4648] in groups of
//!   four (4.8). People type it back ignoring case, spaces and `-`.
//! - An identity's backup **generation** is its key file chain's (4.4):
//!   the number of `signing` records plus the number of `master` records
//!   after the first. It comes from the chain, checked against the key
//!   log, never from a server or a counter of this module's, so every
//!   function here takes it as an input. Removing a device, recovering
//!   the identity and changing the recovery key each move to the next one.
//! - A **backup key** is HKDF-Expand(HKDF-Extract("", recovery key), info,
//!   32) with SHA-384, where `info` is `risala/1 backup `, the uid, a
//!   space and the generation in decimal (12.13). Every device keeps the
//!   current generation's backup key, never the recovery key.
//! - A **backup** is a transfer of history archives ([`crate::archive`]),
//!   each encrypted as a file and stored as a blob, with the files it
//!   carries as blobs of their own. The first archive's key is
//!   **wrapped** as a [`WrappedKey`]: version `0x01`, a random 12-byte
//!   nonce, then the key encrypted with ChaCha20-Poly1305 under the backup
//!   key, with the associated data `risala/1 backup <uid> <generation>
//!   <blob-ref>`: 61 bytes. BACKUP PUT stores the generation, the first
//!   archive's blob-ref, the wrapped key and, if there are other blobs,
//!   the blob-ref of a list of their hashes.
//! - **Restoring** ([`restore`]) follows 12.13's steps: the device names
//!   the generation it computed from the key log, a backup of any other
//!   generation is refused, and the first archive's `made` is given back
//!   to show.
//!
//! The master key's derivation from the recovery key (`risala/1 identity
//! <uid>`, 4.8) belongs with the key file records, in risala-proto.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use risala_proto::names::Identity;
use zeroize::Zeroizing;

use crate::archive::{
    ArchiveError, ArchivedConversation, ArchivedFile, OpenedTransfer, TransferRef, open_transfer,
    seal_transfer,
};
use crate::file::{self, BlobRef, FILE_KEY_LEN, FileKey};
use crate::primitives::{
    AEAD_KEY_LEN, AEAD_NONCE_LEN, AEAD_TAG_LEN, HASH_LEN, ct_eq, hkdf_expand, hkdf_extract, open,
    random, seal,
};

/// The length of a recovery key (4.8).
pub const RECOVERY_KEY_LEN: usize = 32;

/// The length of a recovery key as people see it, without spaces: 52
/// characters of base32 (4.8).
pub const RECOVERY_KEY_BASE32_LEN: usize = 52;

/// The length of a backup key (12.13).
pub const BACKUP_KEY_LEN: usize = AEAD_KEY_LEN;

/// The version of a WrappedKey (12.13).
pub const WRAPPED_KEY_VERSION: u8 = 1;

/// The length of a WrappedKey (12.13): version, nonce, key and tag.
pub const WRAPPED_KEY_LEN: usize = 1 + AEAD_NONCE_LEN + FILE_KEY_LEN + AEAD_TAG_LEN;

/// The HKDF info of backup keys, and the start of a wrapped key's
/// associated data, before the uid (12.13).
pub const BACKUP_LABEL: &str = "risala/1 backup ";

const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Why a typed recovery key cannot be read (4.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryKeyError {
    /// It has another number of characters than 52, after leaving out
    /// spaces and `-`.
    #[error("a recovery key has 52 characters")]
    Length,
    /// It has a character that is not base32, or ends in one that cannot
    /// end a key, so it was mistyped.
    #[error("a recovery key has only the letters a to z and digits 2 to 7")]
    Character,
}

/// A recovery key (4.8): 32 bytes, wiped when dropped. `Debug` does not
/// show it, and equality is in constant time.
#[derive(Clone)]
pub struct RecoveryKey(Box<Zeroizing<[u8; RECOVERY_KEY_LEN]>>);

impl RecoveryKey {
    /// A new random recovery key.
    pub fn generate() -> Result<RecoveryKey, getrandom::Error> {
        let mut bytes = Zeroizing::new([0; RECOVERY_KEY_LEN]);
        getrandom::fill(&mut bytes[..])?;
        Ok(RecoveryKey(Box::new(bytes)))
    }

    /// A recovery key from its bytes.
    pub fn from_bytes(bytes: [u8; RECOVERY_KEY_LEN]) -> RecoveryKey {
        RecoveryKey(Box::new(Zeroizing::new(bytes)))
    }

    /// The key's bytes.
    pub fn as_bytes(&self) -> &[u8; RECOVERY_KEY_LEN] {
        &self.0
    }

    /// The key as people see it (4.8): 52 characters of lower-case base32
    /// without padding, in 13 groups of four separated by spaces.
    pub fn to_display(&self) -> Zeroizing<String> {
        let plain = base32_lower(&self.0[..]);
        let mut out = Zeroizing::new(String::with_capacity(RECOVERY_KEY_BASE32_LEN + 12));
        for (i, group) in plain.as_bytes().chunks(4).enumerate() {
            if i > 0 {
                out.push(' ');
            }
            out.push_str(std::str::from_utf8(group).expect("base32 is ASCII"));
        }
        out
    }

    /// Reads a key a person typed (4.8), ignoring case, spaces and `-`.
    pub fn parse(typed: &str) -> Result<RecoveryKey, RecoveryKeyError> {
        let mut bits: u64 = 0;
        let mut count = 0;
        let mut filled = 0;
        let mut written = 0;
        let mut out = Zeroizing::new([0; RECOVERY_KEY_LEN]);
        for c in typed.bytes().filter(|&c| c != b' ' && c != b'-') {
            if count == RECOVERY_KEY_BASE32_LEN {
                return Err(RecoveryKeyError::Length);
            }
            let value = BASE32
                .iter()
                .position(|&b| b == c.to_ascii_lowercase())
                .ok_or(RecoveryKeyError::Character)?;
            bits = (bits << 5) | value as u64;
            filled += 5;
            count += 1;
            if filled >= 8 {
                filled -= 8;
                // 52 characters fill exactly 32 bytes.
                out[written] = (bits >> filled) as u8;
                written += 1;
                bits &= (1 << filled) - 1;
            }
        }
        if count != RECOVERY_KEY_BASE32_LEN {
            return Err(RecoveryKeyError::Length);
        }
        // 52 characters carry 260 bits: the last 4 are zero in a key.
        if bits != 0 {
            return Err(RecoveryKeyError::Character);
        }
        zeroize::Zeroize::zeroize(&mut bits);
        Ok(RecoveryKey(Box::new(out)))
    }

    /// The backup key of generation `generation` of `uid`'s backups
    /// (12.13). The generation is the key file chain's (4.4): after
    /// publishing a record that moves it, a device derives the new one's
    /// key here, sends it in a BACKUPKEY line, and replaces the backup at
    /// once.
    pub fn backup_key(&self, uid: &Identity, generation: u32) -> BackupKey {
        let prk = hkdf_extract(b"", &self.0[..]);
        let info = format!("{BACKUP_LABEL}{} {generation}", uid.as_str());
        let mut key = Zeroizing::new([0; BACKUP_KEY_LEN]);
        hkdf_expand(&prk[..], info.as_bytes(), &mut key[..]);
        BackupKey { generation, key }
    }
}

impl PartialEq for RecoveryKey {
    fn eq(&self, other: &RecoveryKey) -> bool {
        ct_eq(&self.0[..], &other.0[..])
    }
}

impl Eq for RecoveryKey {}

impl fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryKey(…)")
    }
}

/// Lower-case base32 [RFC4648] without padding.
pub(crate) fn base32_lower(bytes: &[u8]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(bytes.len().div_ceil(5) * 8));
    let mut bits: u32 = 0;
    let mut filled = 0;
    for &b in bytes {
        bits = (bits << 8) | u32::from(b);
        filled += 8;
        while filled >= 5 {
            filled -= 5;
            out.push(char::from(BASE32[((bits >> filled) & 31) as usize]));
        }
        bits &= (1 << filled) - 1;
    }
    if filled > 0 {
        out.push(char::from(BASE32[((bits << (5 - filled)) & 31) as usize]));
    }
    out
}

/// Why a backup cannot be made or restored (12.13).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BackupError {
    /// The backup is of another generation than the one the key log gives
    /// (or this key's). The device tells the user that there is no usable
    /// backup.
    #[error("the backup is of generation {backup}, not {expected}")]
    Generation {
        /// The backup's generation, as the server gave it.
        backup: u32,
        /// The generation the device expected.
        expected: u32,
    },
    /// The wrapped key names a version this device does not support (2.4).
    #[error("unsupported wrapped key version {0}")]
    Version(u8),
    /// The wrapped key is not 61 bytes.
    #[error("a wrapped key is 61 bytes")]
    Length,
    /// The wrapped key does not decrypt: another key, uid, generation or
    /// hash, or it was changed.
    #[error("the backup's key does not unwrap")]
    Unwrap,
    /// The first archive cannot be fetched, does not match the hash, does
    /// not decrypt, is not the identity's, or the archives do not belong
    /// together.
    #[error(transparent)]
    Archive(#[from] ArchiveError),
    /// The operating system gave no randomness for a key or nonce.
    #[error("no randomness: {0}")]
    Random(#[from] getrandom::Error),
}

/// A backup key (12.13), with its generation. The key is wiped when
/// dropped, `Debug` does not show it, and equality is in constant time.
#[derive(Clone)]
pub struct BackupKey {
    generation: u32,
    key: Zeroizing<[u8; BACKUP_KEY_LEN]>,
}

impl BackupKey {
    /// A backup key from its generation and bytes, as in an
    /// IdentityBundle (4.8) or a BACKUPKEY line (12.9).
    pub fn from_bytes(generation: u32, key: [u8; BACKUP_KEY_LEN]) -> BackupKey {
        BackupKey {
            generation,
            key: Zeroizing::new(key),
        }
    }

    /// The key's generation.
    pub fn generation(&self) -> u32 {
        self.generation
    }

    /// The key's bytes.
    pub fn as_bytes(&self) -> &[u8; BACKUP_KEY_LEN] {
        &self.key
    }

    /// The `<key>` of a BACKUPKEY line (12.9): base64 with padding.
    pub fn to_base64(&self) -> Zeroizing<String> {
        Zeroizing::new(BASE64.encode(&self.key[..]))
    }

    /// Reads the `<generation>` and `<key>` of a BACKUPKEY line: the key
    /// is exactly 32 bytes in canonical base64 with padding.
    pub fn from_base64(generation: u32, text: &str) -> Option<BackupKey> {
        let mut key = Zeroizing::new([0; BACKUP_KEY_LEN]);
        file::decode_base64_exact(text, &mut key[..])?;
        Some(BackupKey { generation, key })
    }

    /// Wraps `file_key`, the key of the backup blob `blob` of `uid`
    /// (12.13), under a new random nonce.
    pub fn wrap(
        &self,
        uid: &Identity,
        blob: &BlobRef,
        file_key: &FileKey,
    ) -> Result<WrappedKey, getrandom::Error> {
        Ok(self.wrap_with_nonce(uid, blob, file_key, random()?))
    }

    fn wrap_with_nonce(
        &self,
        uid: &Identity,
        blob: &BlobRef,
        file_key: &FileKey,
        nonce: [u8; AEAD_NONCE_LEN],
    ) -> WrappedKey {
        let aad = self.associated_data(uid, blob);
        let sealed = seal(&self.key, &nonce, &aad, file_key.as_bytes());
        let mut out = [0; WRAPPED_KEY_LEN];
        out[0] = WRAPPED_KEY_VERSION;
        out[1..1 + AEAD_NONCE_LEN].copy_from_slice(&nonce);
        out[1 + AEAD_NONCE_LEN..].copy_from_slice(&sealed);
        WrappedKey(out)
    }

    /// Unwraps the key of the backup blob `blob` of `uid` (12.13).
    pub fn unwrap(
        &self,
        uid: &Identity,
        blob: &BlobRef,
        wrapped: &WrappedKey,
    ) -> Result<FileKey, BackupError> {
        let aad = self.associated_data(uid, blob);
        let nonce: [u8; AEAD_NONCE_LEN] = wrapped.0[1..1 + AEAD_NONCE_LEN]
            .try_into()
            .expect("a wrapped key has a nonce after its version");
        let plain = open(&self.key, &nonce, &aad, &wrapped.0[1 + AEAD_NONCE_LEN..])
            .ok_or(BackupError::Unwrap)?;
        Ok(FileKey::from_bytes(
            plain[..]
                .try_into()
                .expect("the ciphertext is one key long"),
        ))
    }

    /// `risala/1 backup <uid> <generation> <blob-ref>` (12.13), with the
    /// first archive's hash as BACKUP PUT sends it.
    fn associated_data(&self, uid: &Identity, blob: &BlobRef) -> Vec<u8> {
        format!("{BACKUP_LABEL}{} {} {blob}", uid.as_str(), self.generation).into_bytes()
    }

    /// Makes a backup of `conversations` and `files` (12.13): seals them
    /// as archives of at most `max_blob` bytes each ([`seal_transfer`]),
    /// wraps the first archive's key, and lists every other blob. The
    /// files' blobs ([`ArchivedFile::encrypt`]) are the caller's to store,
    /// and SHOULD be reused from earlier backups.
    pub fn make_backup(
        &self,
        uid: &Identity,
        made: u64,
        conversations: Vec<ArchivedConversation>,
        files: Vec<ArchivedFile>,
        max_blob: u64,
    ) -> Result<BackupUpload, BackupError> {
        let file_blobs: Vec<BlobRef> = files.iter().map(|f| f.blob).collect();
        let archives = seal_transfer(uid, made, conversations, files, max_blob)?;
        let first = &archives[0].transfer;
        let key = self.wrap(uid, &first.blob, &first.key)?;
        // The hashes of every other blob: the archives in `more`, then the
        // files in `files` (12.13).
        let others: Vec<BlobRef> = archives[1..]
            .iter()
            .map(|a| a.transfer.blob)
            .chain(file_blobs)
            .collect();
        let list = (!others.is_empty()).then(|| write_list(&others));
        Ok(BackupUpload {
            backup: Backup {
                generation: self.generation,
                hash: first.blob,
                key,
                files: list.as_deref().map(BlobRef::of),
            },
            archives: archives.into_iter().map(|a| a.blob).collect(),
            list,
        })
    }

    /// Opens `uid`'s backup `backup` with this key (12.13): refuses a
    /// backup of another generation than this key's, unwraps the first
    /// archive's key, and opens the archives through `fetch`
    /// ([`open_transfer`]). The result's `made` is the first archive's,
    /// for the device to show.
    pub fn restore(
        &self,
        uid: &Identity,
        backup: &Backup,
        fetch: impl FnMut(&BlobRef) -> Option<Vec<u8>>,
    ) -> Result<OpenedTransfer, BackupError> {
        if backup.generation != self.generation {
            return Err(BackupError::Generation {
                backup: backup.generation,
                expected: self.generation,
            });
        }
        let key = self.unwrap(uid, &backup.hash, &backup.key)?;
        let first = TransferRef {
            blob: backup.hash,
            key,
        };
        Ok(open_transfer(&first, uid, fetch)?)
    }
}

impl PartialEq for BackupKey {
    fn eq(&self, other: &BackupKey) -> bool {
        self.generation == other.generation && ct_eq(&self.key[..], &other.key[..])
    }
}

impl Eq for BackupKey {}

impl fmt::Debug for BackupKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackupKey")
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

/// A WrappedKey (12.13): the version `0x01`, the nonce, then the
/// encrypted file key and its tag. 61 bytes.
///
/// ```text
/// struct { uint8 version; opaque nonce[12]; opaque ciphertext[48]; } WrappedKey;
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct WrappedKey([u8; WRAPPED_KEY_LEN]);

impl WrappedKey {
    /// Reads a wrapped key: exactly 61 bytes, of version 1. A server
    /// replies `ERR invalid` to BACKUP PUT for one that fails (12.13).
    pub fn from_bytes(bytes: &[u8]) -> Result<WrappedKey, BackupError> {
        let bytes: [u8; WRAPPED_KEY_LEN] = bytes.try_into().map_err(|_| BackupError::Length)?;
        if bytes[0] != WRAPPED_KEY_VERSION {
            return Err(BackupError::Version(bytes[0]));
        }
        Ok(WrappedKey(bytes))
    }

    /// The wrapped key's bytes.
    pub fn as_bytes(&self) -> &[u8; WRAPPED_KEY_LEN] {
        &self.0
    }

    /// The `<key>` of BACKUP PUT and BACKUP (12.13): base64 with padding,
    /// 84 characters.
    pub fn to_base64(&self) -> String {
        BASE64.encode(self.0)
    }

    /// Reads the `<key>` of BACKUP PUT or BACKUP: exactly 61 bytes in
    /// canonical base64 with padding, then as [`WrappedKey::from_bytes`].
    pub fn from_base64(text: &str) -> Result<WrappedKey, BackupError> {
        let mut out = [0; WRAPPED_KEY_LEN];
        file::decode_base64_exact(text, &mut out).ok_or(BackupError::Length)?;
        WrappedKey::from_bytes(&out)
    }
}

/// A backup as BACKUP PUT stores it and BACKUP GET returns it (12.13).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Backup {
    /// The generation of the backup key that wraps the key.
    pub generation: u32,
    /// The blob-ref of the first archive.
    pub hash: BlobRef,
    /// The wrapped key of the first archive.
    pub key: WrappedKey,
    /// The blob-ref of the list of every other blob of the backup, if
    /// there are any: BACKUP PUT's `files` (12.13).
    pub files: Option<BlobRef>,
}

/// A backup ready to store (12.13): the blobs to upload, then BACKUP PUT.
#[derive(Debug)]
pub struct BackupUpload {
    /// What BACKUP PUT sends.
    pub backup: Backup,
    /// The archives' blobs, the first one first.
    pub archives: Vec<Vec<u8>>,
    /// The list blob: the version byte `0x01`, then the 48-byte hashes of
    /// every other blob, the archives after the first then the files, if
    /// there are any. Its hash is `backup.files`.
    pub list: Option<Vec<u8>>,
}

/// The `version` byte that starts the list blob of BACKUP PUT's `files`
/// (12.13).
pub const LIST_VERSION: u8 = 1;

/// Writes the list blob of BACKUP PUT's `files` (12.13): the version byte
/// [`LIST_VERSION`], then the 48-byte hashes one after another.
pub fn write_list(blobs: &[BlobRef]) -> Vec<u8> {
    std::iter::once(LIST_VERSION)
        .chain(blobs.iter().flat_map(|h| *h.as_bytes()))
        .collect()
}

/// Reads the list blob of BACKUP PUT's `files` (12.13): the version byte
/// [`LIST_VERSION`], then 48-byte hashes, one after another. `None` if the
/// first byte is not `0x01`, or if the length is not 1 plus a multiple of
/// 48, which a server answers with `ERR invalid`.
pub fn read_list(list: &[u8]) -> Option<Vec<BlobRef>> {
    let (&LIST_VERSION, hashes) = list.split_first()? else {
        return None;
    };
    let (hashes, rest) = hashes.as_chunks::<HASH_LEN>();
    rest.is_empty()
        .then(|| hashes.iter().map(|h| BlobRef::from_bytes(*h)).collect())
}

/// Restores `uid`'s backup with the recovery key, after recovering the
/// identity (12.13):
///
/// 1. `generation` is the one the caller computed from the identity's key
///    file, checked against the key log: the generation current just
///    before its own recovery record (4.4).
/// 2. A backup of any other generation is refused
///    ([`BackupError::Generation`]): the device tells the user there is no
///    usable backup. The server cannot choose the generation.
/// 3. The generation's backup key is derived, the wrapped key's version
///    was checked when it was read ([`WrappedKey::from_bytes`]), and the
///    key is unwrapped and the archives opened.
/// 4. The result's `made` is the first archive's, which the wrap covers
///    through its blob-ref: the device shows it, so that the user can
///    notice an older backup.
/// 5. The device shows the messages as restored from a backup, and their
///    `verified` flags as the user's device's at the time.
pub fn restore(
    recovery: &RecoveryKey,
    uid: &Identity,
    generation: u32,
    backup: &Backup,
    fetch: impl FnMut(&BlobRef) -> Option<Vec<u8>>,
) -> Result<OpenedTransfer, BackupError> {
    if backup.generation != generation {
        return Err(BackupError::Generation {
            backup: backup.generation,
            expected: generation,
        });
    }
    recovery
        .backup_key(uid, generation)
        .restore(uid, backup, fetch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::{ArchivedMessage, HistoryArchive};
    use crate::file::FileError;
    use crate::primitives::{hmac_sha384, sha384};
    use std::collections::HashMap;

    fn alice() -> Identity {
        "alice@example.org".parse().unwrap()
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// RFC 4648, section 10, in lower case without padding.
    #[test]
    fn base32() {
        for (input, output) in [
            ("", ""),
            ("f", "my"),
            ("fo", "mzxq"),
            ("foo", "mzxw6"),
            ("foob", "mzxw6yq"),
            ("fooba", "mzxw6ytb"),
            ("foobar", "mzxw6ytboi"),
        ] {
            assert_eq!(*base32_lower(input.as_bytes()), output);
        }
    }

    #[test]
    fn display_and_parse() {
        let key = RecoveryKey::from_bytes(std::array::from_fn(|i| i as u8 * 7 + 3));
        let shown = key.to_display();
        assert_eq!(shown.len(), 52 + 12);
        let groups: Vec<&str> = shown.split(' ').collect();
        assert_eq!(groups.len(), 13);
        assert!(groups.iter().all(|g| g.len() == 4));
        assert!(shown.bytes().all(|c| c == b' ' || BASE32.contains(&c)));
        assert_eq!(RecoveryKey::parse(&shown), Ok(key.clone()));

        // Case, spaces and `-` are ignored.
        let typed = shown.to_uppercase().replace(' ', "-");
        assert_eq!(RecoveryKey::parse(&typed), Ok(key.clone()));
        let squashed: String = shown.split(' ').collect();
        assert_eq!(RecoveryKey::parse(&squashed), Ok(key.clone()));
        assert_eq!(
            RecoveryKey::parse(&format!(" {squashed} ")),
            Ok(key.clone())
        );

        // Too short or long, letters outside base32, and a last character
        // with bits a key cannot have.
        assert_eq!(
            RecoveryKey::parse(&squashed[..51]),
            Err(RecoveryKeyError::Length)
        );
        assert_eq!(
            RecoveryKey::parse(&format!("{squashed}a")),
            Err(RecoveryKeyError::Length)
        );
        assert_eq!(RecoveryKey::parse(""), Err(RecoveryKeyError::Length));
        let mut bad = squashed.clone();
        bad.replace_range(0..1, "1");
        assert_eq!(RecoveryKey::parse(&bad), Err(RecoveryKeyError::Character));
        let mut bad = squashed.clone();
        bad.replace_range(51..52, "b");
        assert_eq!(RecoveryKey::parse(&bad), Err(RecoveryKeyError::Character));

        for _ in 0..50 {
            let key = RecoveryKey::generate().unwrap();
            assert_eq!(RecoveryKey::parse(&key.to_display()), Ok(key));
        }
        assert_eq!(format!("{key:?}"), "RecoveryKey(…)");
    }

    /// Backup keys, checked against HKDF written out with HMAC: for one
    /// block, HKDF-Expand(prk, info, L) is the first L bytes of
    /// HMAC(prk, info || 0x01) [RFC5869], and HKDF-Extract("", ikm) is
    /// HMAC(48 zero bytes, ikm).
    #[test]
    fn key_derivation() {
        let recovery = RecoveryKey::from_bytes([0x11; 32]);
        let prk = hmac_sha384(&[0; 48], recovery.as_bytes());
        for generation in [0, 1, 4_294_967_295] {
            let key = recovery.backup_key(&alice(), generation);
            let info = format!("risala/1 backup alice@example.org {generation}\x01");
            let expected = hmac_sha384(&prk, info.as_bytes());
            assert_eq!(key.as_bytes(), &expected[..32]);
            assert_eq!(key.generation(), generation);
        }
        let g0 = recovery.backup_key(&alice(), 0);
        let g1 = recovery.backup_key(&alice(), 1);
        assert_ne!(g0, g1);
        // Another uid or recovery key.
        let bob: Identity = "bob@example.org".parse().unwrap();
        assert_ne!(recovery.backup_key(&bob, 0).as_bytes(), g0.as_bytes());
        assert_ne!(
            RecoveryKey::from_bytes([0x12; 32]).backup_key(&alice(), 0),
            g0
        );
        // Same bytes, other generation: not equal.
        assert_ne!(BackupKey::from_bytes(1, *g0.as_bytes()), g0);
        assert_eq!(format!("{g0:?}"), "BackupKey { generation: 0, .. }");
        assert_eq!(BackupKey::from_base64(0, &g0.to_base64()), Some(g0.clone()));
        assert_eq!(BackupKey::from_base64(0, "AAAA"), None);
    }

    #[test]
    fn wrapping() {
        let key = RecoveryKey::from_bytes([0x11; 32]).backup_key(&alice(), 3);
        let blob = BlobRef::of(b"the archive");
        let file_key = FileKey::from_bytes([0x42; 32]);

        let wrapped = key.wrap(&alice(), &blob, &file_key).unwrap();
        assert_eq!(key.unwrap(&alice(), &blob, &wrapped), Ok(file_key.clone()));
        // A new nonce each time.
        assert_ne!(key.wrap(&alice(), &blob, &file_key).unwrap(), wrapped);

        // The layout: version, nonce, then the key under the associated
        // data, which ends with the blob-ref text.
        let fixed = key.wrap_with_nonce(&alice(), &blob, &file_key, [7; 12]);
        let aad = format!("risala/1 backup alice@example.org 3 {blob}");
        assert!(aad.ends_with(&format!(" 3 sha384:{}", hex(blob.as_bytes()))));
        let expected = seal(key.as_bytes(), &[7; 12], aad.as_bytes(), &[0x42; 32]);
        assert_eq!(fixed.as_bytes()[0], 1);
        assert_eq!(&fixed.as_bytes()[1..13], &[7; 12]);
        assert_eq!(&fixed.as_bytes()[13..], &expected[..]);
        assert_eq!(fixed.as_bytes().len(), 61);

        // Another uid, blob, generation, key, or a flipped bit.
        let bob: Identity = "bob@example.org".parse().unwrap();
        assert_eq!(key.unwrap(&bob, &blob, &wrapped), Err(BackupError::Unwrap));
        assert_eq!(
            key.unwrap(&alice(), &BlobRef::of(b"other"), &wrapped),
            Err(BackupError::Unwrap)
        );
        let other_generation = BackupKey::from_bytes(4, *key.as_bytes());
        assert_eq!(
            other_generation.unwrap(&alice(), &blob, &wrapped),
            Err(BackupError::Unwrap)
        );
        let other = RecoveryKey::from_bytes([0x12; 32]).backup_key(&alice(), 3);
        assert_eq!(
            other.unwrap(&alice(), &blob, &wrapped),
            Err(BackupError::Unwrap)
        );
        for i in [1, 12, 13, 44, 45, 60] {
            let mut bytes = *wrapped.as_bytes();
            bytes[i] ^= 1;
            assert_eq!(
                key.unwrap(&alice(), &blob, &WrappedKey::from_bytes(&bytes).unwrap()),
                Err(BackupError::Unwrap)
            );
        }
        // Another version, or another length, does not read.
        for version in [0, 2] {
            let mut bytes = *wrapped.as_bytes();
            bytes[0] = version;
            assert_eq!(
                WrappedKey::from_bytes(&bytes),
                Err(BackupError::Version(version))
            );
            assert_eq!(
                WrappedKey::from_base64(&BASE64.encode(bytes)),
                Err(BackupError::Version(version))
            );
        }
        assert_eq!(
            WrappedKey::from_bytes(&wrapped.as_bytes()[..60]),
            Err(BackupError::Length)
        );
        assert_eq!(
            WrappedKey::from_bytes(&[&wrapped.as_bytes()[..], &[0]].concat()),
            Err(BackupError::Length)
        );

        // Text form.
        let text = wrapped.to_base64();
        assert_eq!(text.len(), 84);
        assert_eq!(WrappedKey::from_base64(&text), Ok(wrapped));
        assert_eq!(
            WrappedKey::from_base64(&text[..80]),
            Err(BackupError::Length)
        );
    }

    fn conversations() -> Vec<ArchivedConversation> {
        vec![ArchivedConversation {
            group_id: vec![1; 32],
            host: "example.org".parse().unwrap(),
            mailbox: [2; 16],
            messages: (1..=30)
                .map(|seq| ArchivedMessage {
                    message_id: [seq as u8; 16],
                    sender: "alice@example.org".parse().unwrap(),
                    device_id: Some(crate::identity::DeviceId::from_bytes([4; 48])),
                    counter: seq,
                    previous: None,
                    verified: true,
                    sent: 1,
                    received: 2,
                    seq,
                    content: format!("TEXT hello {seq} {}", "x".repeat(100)).into_bytes(),
                })
                .collect(),
        }]
    }

    const MADE: u64 = 1_762_600_000_000;

    /// Makes a backup and gives it with a store of its blobs, the files'
    /// included.
    fn make(
        key: &BackupKey,
        files: Vec<(Vec<u8>, ArchivedFile)>,
        max_blob: u64,
    ) -> (Backup, BackupUpload, HashMap<[u8; 48], Vec<u8>>) {
        let entries = files.iter().map(|(_, f)| f.clone()).collect();
        let upload = key
            .make_backup(&alice(), MADE, conversations(), entries, max_blob)
            .unwrap();
        let mut blobs: HashMap<[u8; 48], Vec<u8>> = upload
            .archives
            .iter()
            .map(|b| (sha384(b), b.clone()))
            .collect();
        for (blob, _) in files {
            blobs.insert(sha384(&blob), blob);
        }
        (upload.backup, upload, blobs)
    }

    #[test]
    fn backups() {
        let recovery = RecoveryKey::from_bytes([0x11; 32]);
        let g0 = recovery.backup_key(&alice(), 0);
        let (backup, upload, blobs) = make(&g0, vec![], 1 << 20);
        let fetch = |h: &BlobRef| blobs.get(h.as_bytes()).cloned();
        assert_eq!(backup.generation, 0);
        assert_eq!(upload.archives.len(), 1);
        assert_eq!(backup.hash, BlobRef::of(&upload.archives[0]));
        assert_eq!((backup.files, upload.list.as_ref()), (None, None));

        // With the recovery key and the generation from the log, or the
        // device's backup key. `made` comes back to show.
        let restored = restore(&recovery, &alice(), 0, &backup, fetch).unwrap();
        assert_eq!(restored.conversations, conversations());
        assert_eq!(restored.made, MADE);
        assert_eq!(g0.restore(&alice(), &backup, fetch), Ok(restored.clone()));

        // A device removed: the log says generation 1. The old backup is
        // refused, whatever key opens it.
        let g1 = recovery.backup_key(&alice(), 1);
        let (backup1, _, blobs1) = make(&g1, vec![], 1 << 20);
        let fetch1 = |h: &BlobRef| blobs1.get(h.as_bytes()).cloned();
        assert_eq!(
            restore(&recovery, &alice(), 1, &backup, fetch),
            Err(BackupError::Generation {
                backup: 0,
                expected: 1
            })
        );
        assert_eq!(
            g0.restore(&alice(), &backup1, fetch1),
            Err(BackupError::Generation {
                backup: 1,
                expected: 0
            })
        );
        assert_eq!(
            restore(&recovery, &alice(), 1, &backup1, fetch1).map(|r| r.made),
            Ok(MADE)
        );
        // A backup that claims the log's generation but was wrapped under
        // another does not unwrap: the generation is in the associated
        // data.
        let relabelled = Backup {
            generation: 1,
            ..backup
        };
        assert_eq!(
            restore(&recovery, &alice(), 1, &relabelled, fetch),
            Err(BackupError::Unwrap)
        );

        // A swapped blob fails its hash; a hash swapped with it fails the
        // unwrap, since the blob-ref is in the associated data.
        let swapped_blob = |h: &BlobRef| {
            if h == &backup.hash {
                blobs1.get(backup1.hash.as_bytes()).cloned()
            } else {
                None
            }
        };
        assert_eq!(
            restore(&recovery, &alice(), 0, &backup, swapped_blob),
            Err(BackupError::Archive(ArchiveError::File(FileError::Hash)))
        );
        let swapped = Backup {
            hash: backup1.hash,
            ..backup
        };
        assert_eq!(
            restore(&recovery, &alice(), 0, &swapped, fetch1),
            Err(BackupError::Unwrap)
        );
        // The first archive missing.
        assert_eq!(
            restore(&recovery, &alice(), 0, &backup, |_| None),
            Err(BackupError::Archive(ArchiveError::Missing))
        );
        // Another identity's recovery key or uid.
        let bob: Identity = "bob@example.org".parse().unwrap();
        assert_eq!(
            restore(&recovery, &bob, 0, &backup, fetch),
            Err(BackupError::Unwrap)
        );
        assert_eq!(
            restore(
                &RecoveryKey::from_bytes([0x12; 32]),
                &alice(),
                0,
                &backup,
                fetch
            ),
            Err(BackupError::Unwrap)
        );
        // An archive of another identity, wrapped for this one.
        let theirs = HistoryArchive {
            uid: bob.clone(),
            made: MADE,
            conversations: conversations(),
            files: vec![],
            more: vec![],
        };
        let sealed = theirs.seal().unwrap();
        let backup = Backup {
            generation: 0,
            hash: sealed.transfer.blob,
            key: g0
                .wrap(&alice(), &sealed.transfer.blob, &sealed.transfer.key)
                .unwrap(),
            files: None,
        };
        assert_eq!(
            g0.restore(&alice(), &backup, |_| Some(sealed.blob.clone())),
            Err(BackupError::Archive(ArchiveError::OtherIdentity))
        );
    }

    /// A backup split over several archives, with files: the list names
    /// every other blob, and restoring gives back the files.
    #[test]
    fn split_backups_with_files() {
        let g2 = RecoveryKey::from_bytes([0x11; 32]).backup_key(&alice(), 2);
        let files: Vec<(Vec<u8>, ArchivedFile)> = (0..3u8)
            .map(|i| ArchivedFile::encrypt(BlobRef::of(&[i]), &[i; 300]).unwrap())
            .collect();
        let (backup, upload, blobs) = make(&g2, files.clone(), 2048);
        assert!(upload.archives.len() > 2);
        let list = upload.list.as_ref().unwrap();
        assert_eq!(backup.files, Some(BlobRef::of(list)));
        let named = read_list(list).unwrap();
        let expected: Vec<BlobRef> = upload.archives[1..]
            .iter()
            .map(|b| BlobRef::of(b))
            .chain(files.iter().map(|(_, f)| f.blob))
            .collect();
        assert_eq!(named, expected);

        let restored = g2
            .restore(&alice(), &backup, |h| blobs.get(h.as_bytes()).cloned())
            .unwrap();
        assert_eq!(restored.conversations, conversations());
        assert_eq!((restored.made, restored.missing), (MADE, 0));
        assert_eq!(restored.files.len(), 3);
        for (entry, (_, original)) in restored.files.iter().zip(&files) {
            assert_eq!(entry, original);
            let blob = &blobs[entry.blob.as_bytes()];
            assert_eq!(entry.decrypt(blob).unwrap().len(), 300);
        }

        // A list starts with its version byte, then whole hashes (12.13).
        assert_eq!(list[0], LIST_VERSION);
        assert_eq!(list.len(), 1 + 48 * named.len());
        let list_of = |n: usize| {
            let mut l = vec![1];
            l.resize(n, 0);
            l
        };
        assert_eq!(read_list(&[1]), Some(vec![]));
        assert_eq!(read_list(&[]), None);
        assert_eq!(read_list(&list_of(48)), None);
        assert_eq!(read_list(&list_of(98)), None);
        assert_eq!(read_list(&list_of(97)).map(|l| l.len()), Some(2));
        let mut v2 = list_of(97);
        v2[0] = 2;
        assert_eq!(read_list(&v2), None);
        assert_eq!(read_list(&[0; 96]), None);
    }

    /// Fixed-input vectors for Appendix B.
    #[test]
    fn vector() {
        let recovery = RecoveryKey::from_bytes(std::array::from_fn(|i| i as u8));
        let g0 = recovery.backup_key(&alice(), 0);
        let g1 = recovery.backup_key(&alice(), 1);
        let blob = BlobRef::of(b"backup");
        let file_key = FileKey::from_bytes(std::array::from_fn(|i| 0x40 + i as u8));
        let g3 = recovery.backup_key(&alice(), 3);
        let wrapped = g0.wrap_with_nonce(
            &alice(),
            &blob,
            &file_key,
            std::array::from_fn(|i| 0xa0 + i as u8),
        );
        println!("recovery key    {}", hex(recovery.as_bytes()));
        println!("recovery text   {}", *recovery.to_display());
        println!("uid             alice@example.org");
        println!("backup key g=0  {}", hex(g0.as_bytes()));
        println!("backup key g=1  {}", hex(g1.as_bytes()));
        println!("backup key g=3  {}", hex(g3.as_bytes()));
        println!("blob-ref        {blob}");
        println!("file key        {}", hex(file_key.as_bytes()));
        println!("wrap aad        risala/1 backup alice@example.org 0 {blob}");
        println!("wrapped (g=0)   {}", hex(wrapped.as_bytes()));
        println!("wrapped base64  {}", wrapped.to_base64());
        assert_eq!(hex(&sha384(b"backup")), hex(blob.as_bytes()));
        assert_eq!(
            [
                hex(g0.as_bytes()),
                hex(g1.as_bytes()),
                hex(g3.as_bytes()),
                hex(wrapped.as_bytes()),
                recovery.to_display().to_string(),
            ],
            BACKUP_VECTOR
        );
    }

    /// Appendix B.17: [`vector`], checked against the appendix.
    #[test]
    fn appendix_b() {
        let mut ck = crate::appendix::Checker::open("B.17 ");
        let recovery = RecoveryKey::from_bytes(std::array::from_fn(|i| i as u8));
        let blob = BlobRef::of(b"backup");
        let file_key = FileKey::from_bytes(std::array::from_fn(|i| 0x40 + i as u8));
        let nonce: [u8; AEAD_NONCE_LEN] = std::array::from_fn(|i| 0xa0 + i as u8);
        ck.hex("recovery key", recovery.as_bytes());
        ck.eq("uid", alice().to_string());
        ck.hex("archive", b"backup");
        ck.hex("file key", file_key.as_bytes());
        ck.hex("nonce", &nonce);
        ck.gap();
        for g in [0, 1, 3] {
            ck.hex(
                &format!("backup key of generation {g}"),
                recovery.backup_key(&alice(), g).as_bytes(),
            );
        }
        let g0 = recovery.backup_key(&alice(), 0);
        ck.eq("blob-ref of the archive", blob.to_string());
        let aad = g0.associated_data(&alice(), &blob);
        ck.eq("associated data", String::from_utf8(aad).expect("ASCII"));
        let wrapped = g0.wrap_with_nonce(&alice(), &blob, &file_key, nonce);
        ck.hex("WrappedKey under generation 0", wrapped.as_bytes());
        assert_eq!(g0.unwrap(&alice(), &blob, &wrapped), Ok(file_key));
        ck.gap();
        let g1 = recovery.backup_key(&alice(), 1);
        ck.rejected(
            "the WrappedKey unwrapped under generation 1",
            g1.unwrap(&alice(), &blob, &wrapped).is_err(),
        );
        // The key of generation 0, but told it is generation 1: the
        // associated data names the generation.
        let g0_as_1 = BackupKey::from_bytes(1, *g0.as_bytes());
        ck.rejected(
            "the WrappedKey unwrapped with generation 0's key as generation 1",
            g0_as_1.unwrap(&alice(), &blob, &wrapped).is_err(),
        );
        let bob: Identity = "bob@example.org".parse().unwrap();
        ck.rejected(
            "the WrappedKey unwrapped for uid bob@example.org",
            g0.unwrap(&bob, &blob, &wrapped).is_err(),
        );
        ck.rejected(
            "the WrappedKey unwrapped for the blob-ref of backup2",
            g0.unwrap(&alice(), &BlobRef::of(b"backup2"), &wrapped)
                .is_err(),
        );
        ck.finish();
    }

    // The backup keys and the recovery text are unchanged from M4: only
    // the wrapped key gained its version byte.
    const BACKUP_VECTOR: [&str; 5] = [
        "bf567b1a74771d13e35f3428b382fe18ae35a8352a7b2b7eff120c991b5fab3d",
        "dab608fa392ada87879cb614886bdf24c06ba42d79bbb73b55dbe4037b255bb3",
        "8ff5d23bd7c76d43e7fd34e2eda98546e3164ce8e7b7ecc8c8e5173695a2c46c",
        "01a0a1a2a3a4a5a6a7a8a9aaab6d97c6f02c7c3b1131a3e629e03523ef22fba8\
         dabdc18677cb9b30be712ffb6f6ba6efbd70e20f7e0e0eebf3a7a7c97a",
        "aaaq eaye auda ocaj bifq ydio b4ib ceqt cqkr mfyy denb wha5 dypq",
    ];
}
