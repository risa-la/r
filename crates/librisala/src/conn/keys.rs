//! Device keys (4.3-4.6, PLAN.md 3.3): generating them, storing them
//! through a platform trait, the key file line to publish, and the AUTH
//! and REGISTER commands signed with them.
//!
//! Each device has its own ML-DSA-44 key. Apps keep keys in the platform's
//! store (Keychain, Android Keystore, libsecret) by implementing
//! [`KeyStore`]. [`FileKeyStore`] keeps PEM files for the CLI and for
//! Linux until libsecret support exists.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use risala_proto::auth::{Nonce, PublicKey, SecretKey};
use risala_proto::command::Command;
use risala_proto::error::ParseError;
use risala_proto::keyfile::KeyEntry;
use risala_proto::names::{Domain, Identity, Name};

/// Makes a new device key from 32 bytes of the OS's secure random source
/// (4.4).
pub fn generate_device_key() -> Result<SecretKey, getrandom::Error> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)?;
    let key = SecretKey::from_seed(seed);
    seed.fill(0);
    Ok(key)
}

/// The key file line for a device's key, `mldsa44 <key> [<label>]`,
/// without its LF (4.4). The label is usually the device's name.
///
/// Fails with `BadSyntax` if the label has a line break or another
/// control character.
pub fn key_line(key: &PublicKey, label: Option<&str>) -> Result<String, ParseError> {
    Ok(KeyEntry::new(key.clone(), label)?.to_string())
}

/// Reads a public key given either as a key file line,
/// `mldsa44 <key> [<label...>]` (4.4), or as the key alone in base64. The
/// key alone may be wrapped over several lines, as Appendix B shows it.
/// Returns the key, and the line's label if it has one.
///
/// This is what a user pastes from another device's "show my key" (4.7).
pub fn parse_key_input(input: &str) -> Result<(PublicKey, Option<String>), ParseError> {
    let input = input.trim();
    let first = input.split([' ', '\t']).next().unwrap_or("");
    if first.eq_ignore_ascii_case("mldsa44") {
        let entry: KeyEntry = input.parse()?;
        return Ok((entry.key().clone(), entry.label().map(str::to_owned)));
    }
    let key: String = input.split_whitespace().collect();
    Ok((key.parse()?, None))
}

/// The AUTH command for `identity` (4.5).
///
/// `sni_host` must be the hostname this client sent in SNI, not the host
/// in the greeting. `nonce` is the greeting's nonce.
pub fn auth_command(
    sni_host: &str,
    nonce: &Nonce,
    identity: &Identity,
    key: &SecretKey,
) -> Command {
    let signature = key.sign_challenge(sni_host, nonce, identity.as_str());
    Command::Auth {
        identity: identity.clone(),
        signature,
    }
}

/// The REGISTER command for `<name>@<domain>`, with `key` as the first
/// key (4.6). `domain` is the server's identity domain from INFO (8.5);
/// the rest is as for [`auth_command`].
pub fn register_command(
    sni_host: &str,
    nonce: &Nonce,
    name: &Name,
    domain: &Domain,
    key: &SecretKey,
) -> Command {
    let uid = Identity::new(name, domain);
    let signature = key.sign_challenge(sni_host, nonce, uid.as_str());
    Command::Register {
        name: name.clone(),
        key: key.public_key(),
        signature,
    }
}

/// A key store failed.
#[derive(Debug, thiserror::Error)]
pub enum KeyStoreError {
    /// The key id cannot be stored under: see [`FileKeyStore`].
    #[error("invalid key id {0:?}")]
    BadId(String),
    /// Reading or writing failed.
    #[error("key store I/O: {0}")]
    Io(#[from] io::Error),
    /// A stored key is not a PKCS#8 ML-DSA-44 key.
    #[error("stored key {0:?} is not a PKCS#8 ML-DSA-44 private key")]
    BadKey(String),
    /// A key file can be read by other users. Fix it with `chmod 600`.
    #[error("key file {0} can be read by other users; run chmod 600 on it")]
    InsecurePermissions(PathBuf),
    /// The platform's store failed.
    #[error("key store: {0}")]
    Platform(String),
}

/// Where device keys are kept (PLAN.md 3.3): Keychain on Apple platforms,
/// an Android Keystore-wrapped key on Android, libsecret on Linux.
///
/// Keys are found by an id the app chooses, usually the identity they
/// sign in as, such as `alice@example.org`.
pub trait KeyStore: Send + Sync {
    /// The key stored under `id`, if any.
    fn load(&self, id: &str) -> Result<Option<SecretKey>, KeyStoreError>;
    /// Stores `key` under `id`, replacing any other.
    fn save(&self, id: &str, key: &SecretKey) -> Result<(), KeyStoreError>;
    /// Deletes the key stored under `id`. Deleting a missing key is not
    /// an error.
    fn delete(&self, id: &str) -> Result<(), KeyStoreError>;
}

/// The key stored under `id`, or a new one, generated and stored.
pub fn load_or_generate(store: &dyn KeyStore, id: &str) -> Result<SecretKey, KeyStoreError> {
    if let Some(key) = store.load(id)? {
        return Ok(key);
    }
    let key = generate_device_key().map_err(|e| KeyStoreError::Platform(e.to_string()))?;
    store.save(id, &key)?;
    Ok(key)
}

/// A [`KeyStore`] in memory, for tests and short-lived tools.
#[derive(Default)]
pub struct MemoryKeyStore(Mutex<HashMap<String, SecretKey>>);

impl std::fmt::Debug for MemoryKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ids: Vec<String> = self.0.lock().expect("poisoned").keys().cloned().collect();
        f.debug_tuple("MemoryKeyStore").field(&ids).finish()
    }
}

impl KeyStore for MemoryKeyStore {
    fn load(&self, id: &str) -> Result<Option<SecretKey>, KeyStoreError> {
        Ok(self.0.lock().expect("poisoned").get(id).cloned())
    }

    fn save(&self, id: &str, key: &SecretKey) -> Result<(), KeyStoreError> {
        self.0
            .lock()
            .expect("poisoned")
            .insert(id.to_owned(), key.clone());
        Ok(())
    }

    fn delete(&self, id: &str) -> Result<(), KeyStoreError> {
        self.0.lock().expect("poisoned").remove(id);
        Ok(())
    }
}

/// A [`KeyStore`] of PKCS#8 PEM files in one directory, one per id:
/// `<dir>/<id>.pem`. It reads the files `openssl genpkey -algorithm
/// ML-DSA-44` writes (App. A), and writes the seed-only form of App. B.
///
/// - On Unix the directory is created with mode 0700 and files are
///   written with mode 0600, through a temporary file and a rename.
///   Loading a file that group or others can read fails with
///   [`KeyStoreError::InsecurePermissions`], as ssh does.
/// - Ids are 1 to 255 characters of `a-z A-Z 0-9 . _ - @ ~ +`, not
///   starting with `.`, so an id is always one plain file name.
#[derive(Debug, Clone)]
pub struct FileKeyStore {
    dir: PathBuf,
}

impl FileKeyStore {
    /// A store in `dir`, which is created when the first key is saved.
    pub fn new(dir: impl Into<PathBuf>) -> FileKeyStore {
        FileKeyStore { dir: dir.into() }
    }

    /// The directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The file a key with this id is kept in.
    pub fn path(&self, id: &str) -> Result<PathBuf, KeyStoreError> {
        let ok = !id.is_empty()
            && id.len() <= 255
            && !id.starts_with('.')
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-@~+".contains(&b));
        if !ok {
            return Err(KeyStoreError::BadId(id.to_owned()));
        }
        Ok(self.dir.join(format!("{id}.pem")))
    }

    fn create_dir(&self) -> io::Result<()> {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        builder.create(&self.dir)
    }
}

impl KeyStore for FileKeyStore {
    fn load(&self, id: &str) -> Result<Option<SecretKey>, KeyStoreError> {
        let path = self.path(id)?;
        let pem = match fs::read_to_string(&path) {
            Ok(pem) => pem,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if fs::metadata(&path)?.permissions().mode() & 0o077 != 0 {
                return Err(KeyStoreError::InsecurePermissions(path));
            }
        }
        SecretKey::from_pkcs8_pem(&pem)
            .map(Some)
            .map_err(|_| KeyStoreError::BadKey(id.to_owned()))
    }

    fn save(&self, id: &str, key: &SecretKey) -> Result<(), KeyStoreError> {
        let path = self.path(id)?;
        self.create_dir()?;
        let mut suffix = [0u8; 8];
        getrandom::fill(&mut suffix).map_err(|e| KeyStoreError::Platform(e.to_string()))?;
        let suffix: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
        let tmp = self.dir.join(format!(".{id}.pem.{suffix}.tmp"));

        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let result = (|| {
            let mut file = options.open(&tmp)?;
            file.write_all(key.to_pkcs8_pem().as_bytes())?;
            file.sync_all()?;
            fs::rename(&tmp, &path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        Ok(result?)
    }

    fn delete(&self, id: &str) -> Result<(), KeyStoreError> {
        match fs::remove_file(self.path(id)?) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    // Appendix B.
    pub(crate) const PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
        MDQCAQAwCwYJYIZIAWUDBAMRBCKAIMEfrlxZLhO+Z9yW9uhQBNMukoYV968f06bF\n\
        2eoKtsuo\n\
        -----END PRIVATE KEY-----\n";
    pub(crate) const PUBLIC: &str = concat!(
        "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",
        "nnO/Wp68V/V/przmVp4j4g==",
    );
    pub(crate) const SIGNATURE: &str = concat!(
        "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",
        "AAAAAAAAAAAAAAAAAAAAAAkXJzM=",
    );

    fn appendix_b() -> SecretKey {
        SecretKey::from_pkcs8_pem(PEM).unwrap()
    }

    #[test]
    fn generated_keys_differ() {
        let a = generate_device_key().unwrap();
        let b = generate_device_key().unwrap();
        assert_ne!(a.public_key(), b.public_key());
    }

    #[test]
    fn appendix_b_key_line() {
        let key = appendix_b().public_key();
        assert_eq!(
            key_line(&key, Some("laptop")).unwrap(),
            format!("mldsa44 {PUBLIC} laptop")
        );
        assert_eq!(key_line(&key, None).unwrap(), format!("mldsa44 {PUBLIC}"));
        assert!(key_line(&key, Some("a\nb")).is_err());
    }

    #[test]
    fn key_input() {
        let key = appendix_b().public_key();
        let line = format!("mldsa44 {PUBLIC} old laptop");
        assert_eq!(
            parse_key_input(&format!("  {line}\n")).unwrap(),
            (key.clone(), Some("old laptop".to_owned()))
        );
        assert_eq!(
            parse_key_input(&format!("MLDSA44\t{PUBLIC}")).unwrap(),
            (key.clone(), None)
        );
        assert_eq!(parse_key_input(PUBLIC).unwrap(), (key.clone(), None));
        // Wrapped at 64 characters, as in Appendix B.
        let wrapped: Vec<&str> = PUBLIC
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        assert_eq!(
            parse_key_input(&wrapped.join("\n")).unwrap(),
            (key.clone(), None)
        );
        for bad in [
            "",
            "mldsa44",
            "ssh-ed25519 AAAA",
            "mldsa44 abc",
            &PUBLIC[1..],
        ] {
            assert!(parse_key_input(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn appendix_b_auth_command() {
        let nonce: Nonce = "6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e".parse().unwrap();
        let identity: Identity = "alice@example.org".parse().unwrap();
        let command = auth_command("chat.example.org", &nonce, &identity, &appendix_b());
        assert_eq!(
            risala_proto::command::Request::new(command).to_string(),
            format!("AUTH alice@example.org {SIGNATURE}")
        );
    }

    #[test]
    fn register_command_signs_the_new_uid() {
        let nonce: Nonce = "6f1c0a9e4b2d4c8f9a7e3b5d1c2f4a6e".parse().unwrap();
        let key = appendix_b();
        let command = register_command(
            "chat.example.org",
            &nonce,
            &"alice".parse().unwrap(),
            &"example.org".parse().unwrap(),
            &key,
        );
        let Command::Register {
            name,
            key: public,
            signature,
        } = command
        else {
            panic!()
        };
        assert_eq!(name.as_str(), "alice");
        assert_eq!(public, key.public_key());
        // The same bytes as AUTH for alice@example.org (4.6).
        assert_eq!(signature.to_string(), SIGNATURE);
    }

    #[test]
    fn memory_store() {
        let store = MemoryKeyStore::default();
        assert!(store.load("a@example.org").unwrap().is_none());
        let key = load_or_generate(&store, "a@example.org").unwrap();
        let again = load_or_generate(&store, "a@example.org").unwrap();
        assert_eq!(key.public_key(), again.public_key());
        store.delete("a@example.org").unwrap();
        assert!(store.load("a@example.org").unwrap().is_none());
        store.delete("a@example.org").unwrap();
    }

    #[test]
    fn file_store() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileKeyStore::new(dir.path().join("keys"));
        assert!(store.load("alice@example.org").unwrap().is_none());
        store.save("alice@example.org", &appendix_b()).unwrap();
        let path = store.path("alice@example.org").unwrap();
        // The file is the seed-only form of Appendix B, which openssl reads.
        assert_eq!(fs::read_to_string(&path).unwrap(), PEM);
        let loaded = store.load("alice@example.org").unwrap().unwrap();
        assert_eq!(loaded.public_key(), appendix_b().public_key());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&path), 0o600);
            assert_eq!(mode(store.dir()), 0o700);
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(matches!(
                store.load("alice@example.org"),
                Err(KeyStoreError::InsecurePermissions(_))
            ));
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        // Replacing keeps one file and no temporary files.
        let other = generate_device_key().unwrap();
        store.save("alice@example.org", &other).unwrap();
        assert_eq!(
            store
                .load("alice@example.org")
                .unwrap()
                .unwrap()
                .public_key(),
            other.public_key()
        );
        assert_eq!(fs::read_dir(store.dir()).unwrap().count(), 1);

        store.delete("alice@example.org").unwrap();
        assert!(store.load("alice@example.org").unwrap().is_none());
        store.delete("alice@example.org").unwrap();
    }

    #[test]
    fn file_store_rejects_bad_ids() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileKeyStore::new(dir.path());
        for id in [
            "",
            ".hidden",
            "../x",
            "a/b",
            "a b",
            "a\\b",
            &"x".repeat(256),
        ] {
            assert!(
                matches!(store.save(id, &appendix_b()), Err(KeyStoreError::BadId(_))),
                "{id}"
            );
        }
        assert!(store.path("~sam").is_ok());
    }

    #[test]
    fn file_store_bad_key() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileKeyStore::new(dir.path());
        let path = store.path("x").unwrap();
        fs::write(&path, "not a key").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(matches!(store.load("x"), Err(KeyStoreError::BadKey(_))));
    }
}
