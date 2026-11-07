//! Device keys (4.3-4.6, PLAN.md 3.3): generating them, storing them
//! through a platform trait, the key file line to publish, and the AUTH
//! and REGISTER commands signed with them.
//!
//! Each device has its own Ed25519 key. Apps keep keys in the platform's
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

/// The key file line for a device's key, `ed25519 <key> [<label>]`,
/// without its LF (4.4). The label is usually the device's name.
///
/// Fails with `BadSyntax` if the label has a line break or another
/// control character.
pub fn key_line(key: &PublicKey, label: Option<&str>) -> Result<String, ParseError> {
    Ok(KeyEntry::new(*key, label)?.to_string())
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
    /// A stored key is not a PKCS#8 Ed25519 key.
    #[error("stored key {0:?} is not a PKCS#8 Ed25519 private key")]
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

/// A [`KeyStore`] of PKCS#8 PEM files in one directory, as `openssl
/// genpkey -algorithm ed25519` writes them (App. A), one per id:
/// `<dir>/<id>.pem`.
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
mod tests {
    use super::*;

    // Appendix B.
    const PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
        MC4CAQAwBQYDK2VwBCIEIMEfrlxZLhO+Z9yW9uhQBNMukoYV968f06bF2eoKtsuo\n\
        -----END PRIVATE KEY-----\n";
    const SIGNATURE: &str =
        "Hk+S5Vd7ciW57dRNS3AhcvZkYNLmj+kkgJUxOYvCrbEQSBk0UDdH+cSBXF6YvCSU85FRVPaURwsQdbV/SAK0CQ==";

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
            "ed25519 J/KmupuUYcRd2C2yNZeKz61JIbIKbdRp/dL8lfquDYY= laptop"
        );
        assert_eq!(
            key_line(&key, None).unwrap(),
            "ed25519 J/KmupuUYcRd2C2yNZeKz61JIbIKbdRp/dL8lfquDYY="
        );
        assert!(key_line(&key, Some("a\nb")).is_err());
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
        // The file is what openssl genpkey writes (App. B).
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
