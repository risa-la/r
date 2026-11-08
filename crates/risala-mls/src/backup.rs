//! Recovery keys and backups (4.8, 12.13).
//!
//! - A **recovery key** is 32 random bytes, shown once when an identity
//!   is made, as 52 characters of lower-case base32 [RFC4648] in groups of
//!   four (4.8). People type it back ignoring case, spaces and `-`.
//! - A **backup key** is HKDF-Expand(HKDF-Extract("", recovery key), info,
//!   32) with SHA-384, where `info` is `risala/1 backup `, the uid, a
//!   space and the **generation** in decimal (12.13). The first generation
//!   is 0. Every device keeps the current generation's backup key, never
//!   the recovery key.
//! - A **backup** is a HistoryArchive ([`crate::archive`]) encrypted as a
//!   file under a new random key and stored as a blob. Its key is
//!   **wrapped**: a random 12-byte nonce, then the key encrypted with
//!   ChaCha20-Poly1305 under the backup key, with the associated data
//!   `risala/1 backup <uid> <generation> <hash>`. The wrapped key is 60
//!   bytes. BACKUP PUT stores the generation, the blob's hash and the
//!   wrapped key; one backup per identity is current.
//! - **Removing a device** moves to the next generation (4.8), since the
//!   removed device knew the current backup key: the device that removes
//!   it derives the next generation's key from the recovery key
//!   ([`RecoveryKey::next_backup_key`]), sends it to the other devices in a
//!   BACKUPKEY line, and makes a new backup under it, which replaces the
//!   old one. Nothing is re-wrapped: the old backup's file key is one the
//!   removed device may have kept, so the new backup has a new one.
//!
//! The master key's derivation from the recovery key (`risala/1 identity
//! <uid>`, 4.8) belongs with the key file records, in risala-proto.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use risala_proto::names::Identity;
use zeroize::Zeroizing;

use crate::archive::{ArchiveError, HistoryArchive};
use crate::file::{self, BlobRef, FILE_KEY_LEN, FileKey};
use crate::primitives::{
    AEAD_KEY_LEN, AEAD_NONCE_LEN, AEAD_TAG_LEN, ct_eq, hkdf_expand, hkdf_extract, open, random,
    seal,
};

/// The length of a recovery key (4.8).
pub const RECOVERY_KEY_LEN: usize = 32;

/// The length of a recovery key as people see it, without spaces: 52
/// characters of base32 (4.8).
pub const RECOVERY_KEY_BASE32_LEN: usize = 52;

/// The length of a backup key (12.13).
pub const BACKUP_KEY_LEN: usize = AEAD_KEY_LEN;

/// The length of a wrapped key (12.13): nonce, key and tag.
pub const WRAPPED_KEY_LEN: usize = AEAD_NONCE_LEN + FILE_KEY_LEN + AEAD_TAG_LEN;

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
    /// (12.13).
    pub fn backup_key(&self, uid: &Identity, generation: u32) -> BackupKey {
        let prk = hkdf_extract(b"", &self.0[..]);
        let info = format!("{BACKUP_LABEL}{} {generation}", uid.as_str());
        let mut key = Zeroizing::new([0; BACKUP_KEY_LEN]);
        hkdf_expand(&prk[..], info.as_bytes(), &mut key[..]);
        BackupKey { generation, key }
    }

    /// The backup key of the generation after `current`'s, for removing a
    /// device (4.8). `None` after generation 2^32 - 1.
    pub fn next_backup_key(&self, uid: &Identity, current: &BackupKey) -> Option<BackupKey> {
        Some(self.backup_key(uid, current.generation.checked_add(1)?))
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

/// Why a backup cannot be restored (12.13).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BackupError {
    /// The backup was made under another generation than this key's.
    #[error("the backup is of generation {backup}, the key of {key}")]
    Generation {
        /// The backup's generation.
        backup: u32,
        /// The key's generation.
        key: u32,
    },
    /// The wrapped key does not decrypt: another key, uid, generation or
    /// hash, or it was changed.
    #[error("the backup's key does not unwrap")]
    Unwrap,
    /// The blob does not match the hash, does not decrypt, or is not the
    /// identity's archive.
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
        out[..AEAD_NONCE_LEN].copy_from_slice(&nonce);
        out[AEAD_NONCE_LEN..].copy_from_slice(&sealed);
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
        let nonce: [u8; AEAD_NONCE_LEN] = wrapped.0[..AEAD_NONCE_LEN]
            .try_into()
            .expect("a wrapped key starts with a nonce");
        let plain = open(&self.key, &nonce, &aad, &wrapped.0[AEAD_NONCE_LEN..])
            .ok_or(BackupError::Unwrap)?;
        Ok(FileKey::from_bytes(
            plain[..]
                .try_into()
                .expect("the ciphertext is one key long"),
        ))
    }

    /// `risala/1 backup <uid> <generation> <hash>` (12.13), with the hash
    /// as a blob-ref, the form BACKUP PUT sends it in (PLAN.md 62).
    fn associated_data(&self, uid: &Identity, blob: &BlobRef) -> Vec<u8> {
        format!("{BACKUP_LABEL}{} {} {blob}", uid.as_str(), self.generation).into_bytes()
    }

    /// Encrypts `archive` as a backup (12.13): the blob to store, and the
    /// generation, hash and wrapped key for BACKUP PUT.
    pub fn make_backup(&self, archive: &HistoryArchive) -> Result<(Vec<u8>, Backup), BackupError> {
        let sealed = archive.seal()?;
        let key = self.wrap(&archive.uid, &sealed.transfer.blob, &sealed.transfer.key)?;
        Ok((
            sealed.blob,
            Backup {
                generation: self.generation,
                hash: sealed.transfer.blob,
                key,
            },
        ))
    }

    /// Opens the backup `backup` of `uid` in `blob` (12.13): unwraps its
    /// key, checks the blob's hash, decrypts it, and checks that the
    /// archive is `uid`'s.
    pub fn restore(
        &self,
        uid: &Identity,
        backup: &Backup,
        blob: &[u8],
    ) -> Result<HistoryArchive, BackupError> {
        if backup.generation != self.generation {
            return Err(BackupError::Generation {
                backup: backup.generation,
                key: self.generation,
            });
        }
        let key = self.unwrap(uid, &backup.hash, &backup.key)?;
        let transfer = crate::archive::TransferRef {
            blob: backup.hash,
            key,
        };
        Ok(HistoryArchive::open(&transfer, blob, uid)?)
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

/// A wrapped backup key (12.13): the nonce, then the encrypted file key
/// and its tag. 60 bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct WrappedKey([u8; WRAPPED_KEY_LEN]);

impl WrappedKey {
    /// A wrapped key from its bytes.
    pub fn from_bytes(bytes: [u8; WRAPPED_KEY_LEN]) -> WrappedKey {
        WrappedKey(bytes)
    }

    /// The wrapped key's bytes.
    pub fn as_bytes(&self) -> &[u8; WRAPPED_KEY_LEN] {
        &self.0
    }

    /// The `<key>` of BACKUP PUT and BACKUP (12.13): base64 with padding,
    /// 80 characters.
    pub fn to_base64(&self) -> String {
        BASE64.encode(self.0)
    }

    /// Reads the `<key>` of BACKUP PUT or BACKUP: exactly 60 bytes in
    /// canonical base64 with padding.
    pub fn from_base64(text: &str) -> Option<WrappedKey> {
        let mut out = [0; WRAPPED_KEY_LEN];
        file::decode_base64_exact(text, &mut out)?;
        Some(WrappedKey(out))
    }
}

/// A backup as BACKUP PUT stores it and BACKUP GET returns it (12.13).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Backup {
    /// The generation of the backup key that wraps the key.
    pub generation: u32,
    /// The blob-ref of the encrypted archive.
    pub hash: BlobRef,
    /// The wrapped key.
    pub key: WrappedKey,
}

/// Restores `uid`'s backup with the recovery key (12.13): derives the
/// backup key of the backup's generation, then [`BackupKey::restore`].
pub fn restore(
    recovery: &RecoveryKey,
    uid: &Identity,
    backup: &Backup,
    blob: &[u8],
) -> Result<HistoryArchive, BackupError> {
    recovery
        .backup_key(uid, backup.generation)
        .restore(uid, backup, blob)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::{ArchivedConversation, ArchivedMessage};
    use crate::file::FileError;
    use crate::primitives::{hmac_sha384, sha384};

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
        let g1 = recovery.next_backup_key(&alice(), &g0).unwrap();
        assert_eq!(g1, recovery.backup_key(&alice(), 1));
        assert_ne!(g0, g1);
        assert_eq!(
            recovery.next_backup_key(&alice(), &recovery.backup_key(&alice(), u32::MAX)),
            None
        );
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

        // The layout: nonce, then the key under the associated data.
        let fixed = key.wrap_with_nonce(&alice(), &blob, &file_key, [7; 12]);
        let aad = format!("risala/1 backup alice@example.org 3 {blob}");
        let expected = seal(key.as_bytes(), &[7; 12], aad.as_bytes(), &[0x42; 32]);
        assert_eq!(&fixed.as_bytes()[..12], &[7; 12]);
        assert_eq!(&fixed.as_bytes()[12..], &expected[..]);
        assert_eq!(fixed.as_bytes().len(), 60);

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
        for i in [0, 11, 12, 43, 44, 59] {
            let mut bytes = *wrapped.as_bytes();
            bytes[i] ^= 1;
            assert_eq!(
                key.unwrap(&alice(), &blob, &WrappedKey::from_bytes(bytes)),
                Err(BackupError::Unwrap)
            );
        }

        // Text form.
        let text = wrapped.to_base64();
        assert_eq!(text.len(), 80);
        assert_eq!(WrappedKey::from_base64(&text), Some(wrapped));
        assert_eq!(WrappedKey::from_base64(&text[..76]), None);
    }

    fn archive() -> HistoryArchive {
        HistoryArchive {
            uid: alice(),
            made: 1_762_600_000_000,
            conversations: vec![ArchivedConversation {
                group_id: vec![1; 32],
                host: "example.org".parse().unwrap(),
                mailbox: [2; 16],
                messages: vec![ArchivedMessage {
                    message_id: [3; 16],
                    sender: "alice@example.org".parse().unwrap(),
                    verified: true,
                    sent: 1,
                    received: 2,
                    seq: 3,
                    content: b"TEXT hello".to_vec(),
                }],
            }],
            more: vec![],
        }
    }

    #[test]
    fn backups() {
        let recovery = RecoveryKey::from_bytes([0x11; 32]);
        let g0 = recovery.backup_key(&alice(), 0);
        let (blob, backup) = g0.make_backup(&archive()).unwrap();
        assert_eq!(backup.generation, 0);
        assert_eq!(backup.hash, BlobRef::of(&blob));

        // With the recovery key, or the device's backup key.
        assert_eq!(restore(&recovery, &alice(), &backup, &blob), Ok(archive()));
        assert_eq!(g0.restore(&alice(), &backup, &blob), Ok(archive()));

        // After a device is removed, the old key cannot read the new
        // backup, and the next generation cannot read the old one.
        let g1 = recovery.next_backup_key(&alice(), &g0).unwrap();
        let (blob1, backup1) = g1.make_backup(&archive()).unwrap();
        assert_eq!(backup1.generation, 1);
        assert_eq!(
            g0.restore(&alice(), &backup1, &blob1),
            Err(BackupError::Generation { backup: 1, key: 0 })
        );
        assert_eq!(
            restore(&recovery, &alice(), &backup1, &blob1),
            Ok(archive())
        );
        // A backup that claims another generation does not unwrap.
        let relabelled = Backup {
            generation: 1,
            ..backup
        };
        assert_eq!(
            restore(&recovery, &alice(), &relabelled, &blob),
            Err(BackupError::Unwrap)
        );

        // A swapped blob fails its hash; a hash swapped with it fails the
        // unwrap, since the hash is in the associated data.
        assert_eq!(
            restore(&recovery, &alice(), &backup, &blob1),
            Err(BackupError::Archive(ArchiveError::File(FileError::Hash)))
        );
        let swapped = Backup {
            hash: backup1.hash,
            ..backup
        };
        assert_eq!(
            restore(&recovery, &alice(), &swapped, &blob1),
            Err(BackupError::Unwrap)
        );
        // Another identity's recovery key or uid.
        let bob: Identity = "bob@example.org".parse().unwrap();
        assert_eq!(
            restore(&recovery, &bob, &backup, &blob),
            Err(BackupError::Unwrap)
        );
        assert_eq!(
            restore(
                &RecoveryKey::from_bytes([0x12; 32]),
                &alice(),
                &backup,
                &blob
            ),
            Err(BackupError::Unwrap)
        );
        // An archive of another identity, wrapped for this one.
        let mut theirs = archive();
        theirs.uid = bob.clone();
        let sealed = theirs.seal().unwrap();
        let backup = Backup {
            generation: 0,
            hash: sealed.transfer.blob,
            key: g0
                .wrap(&alice(), &sealed.transfer.blob, &sealed.transfer.key)
                .unwrap(),
        };
        assert_eq!(
            g0.restore(&alice(), &backup, &sealed.blob),
            Err(BackupError::Archive(ArchiveError::OtherIdentity))
        );
    }

    /// Fixed-input vectors for Appendix B.
    #[test]
    fn vector() {
        let recovery = RecoveryKey::from_bytes(std::array::from_fn(|i| i as u8));
        let g0 = recovery.backup_key(&alice(), 0);
        let g1 = recovery.backup_key(&alice(), 1);
        let blob = BlobRef::of(b"backup");
        let file_key = FileKey::from_bytes(std::array::from_fn(|i| 0x40 + i as u8));
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
        println!("blob-ref        {blob}");
        println!("file key        {}", hex(file_key.as_bytes()));
        println!("wrapped (g=0)   {}", hex(wrapped.as_bytes()));
        println!("wrapped base64  {}", wrapped.to_base64());
        assert_eq!(hex(&sha384(b"backup")), hex(blob.as_bytes()));
        assert_eq!(
            [
                hex(g0.as_bytes()),
                hex(g1.as_bytes()),
                hex(wrapped.as_bytes()),
                recovery.to_display().to_string(),
            ],
            BACKUP_VECTOR
        );
    }

    const BACKUP_VECTOR: [&str; 4] = [
        "bf567b1a74771d13e35f3428b382fe18ae35a8352a7b2b7eff120c991b5fab3d",
        "dab608fa392ada87879cb614886bdf24c06ba42d79bbb73b55dbe4037b255bb3",
        "a0a1a2a3a4a5a6a7a8a9aaab6d97c6f02c7c3b1131a3e629e03523ef22fba8da\
         bdc18677cb9b30be712ffb6f6ba6efbd70e20f7e0e0eebf3a7a7c97a",
        "aaaq eaye auda ocaj bifq ydio b4ib ceqt cqkr mfyy denb wha5 dypq",
    ];
}
