//! Device keys (4.3-4.6, PLAN.md 3.3): generating them, storing them
//! through a platform trait, the key file line to publish, and the AUTH
//! and REGISTER commands signed with them.
//!
//! Each device has its own ML-DSA-44 key. Apps keep keys in the platform's
//! store (Keychain, Android Keystore, libsecret) by implementing
//! [`PlatformKeyStore`], which passes a key as its 32-byte seed and so can
//! be written in Swift or Kotlin, and handing it to the client wrapped in
//! [`PlatformKeys`]. Rust code may implement [`KeyStore`] directly.
//! [`FileKeyStore`] keeps PEM files for the CLI and for Linux until
//! libsecret support exists, and [`MemoryKeyStore`] keeps keys in memory.
//!
//! Devices do not fetch key files yet. When they do, to check the members
//! of encrypted conversations (12.12, M5), a key counts as removed only
//! when a fetch returns a key file (200) that does not list it, or a gone
//! answer (404 or 410). Any other outcome, from a timeout or a DNS or TLS
//! error to a 5xx or a redirect, is a failed fetch: it keeps the cached
//! copy and removes nothing, however long it lasts (4.4).

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
    /// The platform's store refused access, for example a locked
    /// keychain, or the user said no.
    #[error("key store refused access: {0}")]
    Denied(String),
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

/// The length of a device key's seed, the ξ of FIPS 204 (App. B).
pub const SEED_LEN: usize = 32;

/// The DER of a seed-only PKCS#8 ML-DSA-44 key before the seed (App. B),
/// as [`SecretKey::to_pkcs8_pem`] writes it.
const SEED_PKCS8_PREFIX: [u8; 22] = [
    0x30, 0x34, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
    0x03, 0x11, 0x04, 0x22, 0x80, 0x20,
];

/// The 32-byte seed of `key`, wiped when dropped.
pub fn key_seed(key: &SecretKey) -> zeroize::Zeroizing<[u8; SEED_LEN]> {
    use base64::Engine as _;
    let pem = key.to_pkcs8_pem();
    let body: zeroize::Zeroizing<String> =
        zeroize::Zeroizing::new(pem.lines().filter(|l| !l.starts_with("-----")).collect());
    let der = zeroize::Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(body.as_bytes())
            .expect("to_pkcs8_pem writes base64"),
    );
    assert!(
        der.len() == SEED_PKCS8_PREFIX.len() + SEED_LEN && der.starts_with(&SEED_PKCS8_PREFIX),
        "to_pkcs8_pem writes the seed-only form"
    );
    let mut seed = zeroize::Zeroizing::new([0u8; SEED_LEN]);
    seed.copy_from_slice(&der[SEED_PKCS8_PREFIX.len()..]);
    seed
}

/// Why a [`PlatformKeyStore`] failed. Plain, with owned messages, so that
/// Swift and Kotlin code can return one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlatformKeyError {
    /// What is stored for the identity is not a 32-byte seed, or cannot
    /// be read as one.
    #[error("bad stored key: {message}")]
    BadKey {
        /// What went wrong, for logs.
        message: String,
    },
    /// The platform refused access: a locked keychain, a user who said
    /// no, or files other users can read.
    #[error("access refused: {message}")]
    Denied {
        /// What went wrong, for logs.
        message: String,
    },
    /// Anything else.
    #[error("{message}")]
    Failed {
        /// What went wrong, for logs.
        message: String,
    },
}

/// Where an app keeps device keys (PLAN.md 3.3): Keychain on Apple
/// platforms, an Android Keystore-wrapped key on Android, libsecret on
/// Linux. Its shape fits a UniFFI callback interface: owned strings and
/// bytes, no generics, and a plain error.
///
/// A key is its 32-byte ML-DSA-44 seed (App. B): everything else follows
/// from it. The seed is a secret: store it encrypted or protected at rest,
/// and wipe copies when done. Keys are found by identity, such as
/// `alice@example.org`. A device has one key per identity, used on every
/// server the identity signs in to and as its key in encrypted
/// conversations (4.4, 12.2), so the server is not part of the name.
///
/// Wrap it in [`PlatformKeys`] for [`ClientOptions::keys`](crate::client::ClientOptions::keys).
/// Calls may block for a moment: the client makes them off its async
/// threads.
pub trait PlatformKeyStore: Send + Sync {
    /// The seed stored for `identity`, if any.
    fn load(&self, identity: String) -> Result<Option<Vec<u8>>, PlatformKeyError>;
    /// Stores `seed` for `identity`, replacing any other.
    fn save(&self, identity: String, seed: Vec<u8>) -> Result<(), PlatformKeyError>;
    /// Deletes the key stored for `identity`. Deleting a missing key is
    /// not an error.
    fn delete(&self, identity: String) -> Result<(), PlatformKeyError>;
}

/// A [`PlatformKeyStore`] used as a [`KeyStore`].
#[derive(Clone)]
pub struct PlatformKeys(pub std::sync::Arc<dyn PlatformKeyStore>);

impl std::fmt::Debug for PlatformKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PlatformKeys").finish_non_exhaustive()
    }
}

impl From<PlatformKeyError> for KeyStoreError {
    fn from(e: PlatformKeyError) -> KeyStoreError {
        match e {
            PlatformKeyError::BadKey { message } => KeyStoreError::BadKey(message),
            PlatformKeyError::Denied { message } => KeyStoreError::Denied(message),
            PlatformKeyError::Failed { message } => KeyStoreError::Platform(message),
        }
    }
}

impl KeyStore for PlatformKeys {
    fn load(&self, id: &str) -> Result<Option<SecretKey>, KeyStoreError> {
        let Some(bytes) = self.0.load(id.to_owned())? else {
            return Ok(None);
        };
        let mut bytes = zeroize::Zeroizing::new(bytes);
        let seed: [u8; SEED_LEN] = bytes.as_slice().try_into().map_err(|_| {
            KeyStoreError::BadKey(format!("{id}: {} bytes, not a 32-byte seed", bytes.len()))
        })?;
        zeroize::Zeroize::zeroize(&mut *bytes);
        Ok(Some(SecretKey::from_seed(seed)))
    }

    fn save(&self, id: &str, key: &SecretKey) -> Result<(), KeyStoreError> {
        let seed = key_seed(key);
        Ok(self.0.save(id.to_owned(), seed.to_vec())?)
    }

    fn delete(&self, id: &str) -> Result<(), KeyStoreError> {
        Ok(self.0.delete(id.to_owned())?)
    }
}

/// A [`KeyStore`], such as [`FileKeyStore`] or [`MemoryKeyStore`], used as
/// a [`PlatformKeyStore`]: the other way round from [`PlatformKeys`].
#[derive(Clone)]
pub struct AsPlatform(pub std::sync::Arc<dyn KeyStore>);

impl std::fmt::Debug for AsPlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("AsPlatform").finish_non_exhaustive()
    }
}

impl PlatformKeyStore for AsPlatform {
    fn load(&self, identity: String) -> Result<Option<Vec<u8>>, PlatformKeyError> {
        let key = self.0.load(&identity).map_err(platform_error)?;
        Ok(key.map(|k| key_seed(&k).to_vec()))
    }

    fn save(&self, identity: String, seed: Vec<u8>) -> Result<(), PlatformKeyError> {
        let mut seed = zeroize::Zeroizing::new(seed);
        let bytes: [u8; SEED_LEN] =
            seed.as_slice()
                .try_into()
                .map_err(|_| PlatformKeyError::BadKey {
                    message: format!("{} bytes, not a 32-byte seed", seed.len()),
                })?;
        zeroize::Zeroize::zeroize(&mut *seed);
        self.0
            .save(&identity, &SecretKey::from_seed(bytes))
            .map_err(platform_error)
    }

    fn delete(&self, identity: String) -> Result<(), PlatformKeyError> {
        self.0.delete(&identity).map_err(platform_error)
    }
}

fn platform_error(e: KeyStoreError) -> PlatformKeyError {
    let message = e.to_string();
    match e {
        KeyStoreError::BadKey(_) => PlatformKeyError::BadKey { message },
        KeyStoreError::Denied(_) | KeyStoreError::InsecurePermissions(_) => {
            PlatformKeyError::Denied { message }
        }
        _ => PlatformKeyError::Failed { message },
    }
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
        let mut file = match fs::File::open(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if file.metadata()?.permissions().mode() & 0o077 != 0 {
                return Err(KeyStoreError::InsecurePermissions(path));
            }
        }
        // The PEM holds the secret: wiped when dropped. Room for all of it
        // up front, so that growing leaves no copy behind.
        let len = usize::try_from(file.metadata()?.len()).unwrap_or(0);
        let mut pem = zeroize::Zeroizing::new(String::with_capacity(len.saturating_add(1)));
        io::Read::read_to_string(&mut file, &mut pem)?;
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
        "0eS7OdclGDTKyqFlcGMJZOcRDKwNWe46pKczbvw1K6r08d/1QDbNxsCWmTMmGgol",
        "t6rEII7exIqtw+hXEXbaIenHtLLYgZcrFaL24Ef5aqSh/phIr9eh1p1NjBs/tlqy",
        "cpEzZ/nXdeWH2AL7tIIq3n3DS2fnZkKHeUiL/TwzwW8hh8yO3ZibXKiQMl4AOgnX",
        "fmrgBcslOSid4JG572ssA0hWMJa4+I/vWVKWY3I++y4DexyJzU5S2uks2QwsWLJp",
        "keA9gELCe0QnkZcqwZn8sRCk9zHCdsfVh+Thdc0eifSfxioL3LIl3wv8fO8ryjmB",
        "ogWeIR009sdh5n+1SEYno/vfVK4KPUV0LqMAYgqWCPpQR16DSxtTkKabj44TvV6e",
        "jKXci4jHeQtxuih8VUpJGz+xNdOIAlm8Kjj/7ggUpu0DPiq8YA201+yvwpuYZdVh",
        "P49x3N0ltKolxJ4dyAxm6SOHiqAvCLk8ELJ9AtZdHQN0Gs1z8grfv2dAyhPzC9qu",
        "eHbsU9qlWW2vgZaArhZQpqk78piCTNnS9FQq3COnS/mJHcOwGLvmpirKo8lHRNh2",
        "KToTE1oZTLB1qDuCy2TaBKqwes2N5ps/ws2B1/4lzh9wYS39CO2ucDsab480ez2H",
        "RmGEyTIPhNtr0peQxnLZ31BCzkK6KNyiXY0WdiyTyg12krjtkyR4l6pbm5tT71Zz",
        "ZhKrNOvjlyO3GgXXoCFuBvGQ6+J0CcbSHW1D1LgDq27D2W6lDy6YfPbDf23lMwmj",
        "FjU3m/2CIhcEk2FsXXMKL7qLuiUJW8LtucoH/uGoP/p50z9aPUTuOSGnRK3jHFaD",
        "xstPLojSouWLhNOqAfK6WDrEIwTPeEgCsrZ6aPaH7F5qbaaqVQX3WfhO82NQUeQr",
        "vS9ZeotxoI7p3lUYf1qWB6kzsrXxSa/+t1YA632Ec/dmWzgI1WTGqpmOAl5hm/ui",
        "WgLMQKkkKwdnOuMPJgc8GENjBbODESLzXCdKkQieNtoWcx5U5hMgC+tj9NiZwVMo",
        "N0ejGaRvuzXzGR7WRuLPImht5DOaIjkvkKgt1lE6Xfy2Fc9xZGUYlh2rAn1ekv01",
        "zLcuKq+KrcpuqMeyaJFK5L8dhhVwzE8lymJixGbR54mDiZLMQlLIJ3oi0OX/InK8",
        "9+AJwawKmsELa3HTuYHbzXjXtryYTz5ESivyWS6vibct6187IPVec2bmZAg+Y/4G",
        "pgxasek3zDp1c6ZyzvBz7NVqCr299gYHcbeFMAx5COyYGYKsnAASgN3ukC6qD6O+",
        "rMqWBm5e3XMYesyhpDqzqUGLPOUPeA1auS11CopxihafmFKuTBGZyOVut30xnPGJ",
        "nEj/cbaw6rAkK/pR8v2Mc2lks/P18A0/+/pjqmWX8qRUUdnHRGfV3vMC2+26ZQqo",
        "jExOU7bgeuWn9KSCq50D3Jsmh0xCWaPz//App1DGxtTHB/745jn39W96MdIct7AT",
        "bNnYjcOtjdI3+5RP0+1BSKptuFh6RwumXwO6rbLSNrYXvANs6By+PCH8L1anKe9H",
        "vd2EmW9W42bHwW7TZC7fIYGaU5gvuV7YifNPElHknSyvriU+vDPkbpCjfRPXZ+6o",
        "mLd8CeLwwARtLdq/KltBkrfJXhZg/DprrDZoDkIojD0qtK9hop19pPMCUEcB2pGX",
        "fCpGeWGhIVoheevb4zIH/9MHlZKaqdwDWEjSYOOxXlWGPumqNgviqRL4Om32TqtQ",
        "a61bPlV3Fn56APcAD0xWvkqOme6m74sJpZm+/evB0/Tvm0fZSEvEVmgPXCfnbOj+",
        "ljhiKO9d8e4f8pEElr18tz6p0BEUfByfL9tZSjQh/XxU0Bnhdwjrwl/itp14QIQy",
        "dsUq3+O7YBhGyHdDPQIMg3tVeXZNi1naOtryiYTFYll9XYfy/iw+CpjuVyiYA7aM",
        "917neTrG3XWs674YkcPOg94yEHq5fstqBqHKmKdsIJTyXWmL7gDYDTfgbWGUg9cg",
        "FQAY82ZFEOpkCVC47m3U+J3btaNPbg6itpdNTdYNy+74EQgJ2Z2snXQJE1Mkt75v",
        "80iveufZmaXYi0l4O2v3EV7StufMWLF+3Ys0JJC34IulK8xw+mbop0wsHXoLsUmA",
        "v+1rtrENYWIi2NI+2hs3OmPtB0Oh8OYfzDe90u3cexbv+Xu5iFv9CnUKFl8OpvDi",
        "IfWahA3Iym9rYftmLuYHZA/JDPElQcNRp0aSA6jjiwd1N04SUNNZHshLxHxQC6rB",
        "QxTxOXSVDiiEt9J/PD9FUs0OpvjhsnqYt9m32yEA6QSaTFRnyZ2E2T6BMLI9AnKO",
        "ccmxiwgP5JqCG36W9Mdoy6egJ0J4YTyR2qX6PQ2cSM4/ek5vqPVaoWuBd6/JxM+n",
        "r2d4xVGkmr10S6txu25Z0FDXtpUD5qtaw/pSYa5SaTmbj3XI65TxyUFXPnM2xm/0",
        "mzGIUMU9EuLAZWA01BCXrzLyvkALVGCe9OGZ++XTOWJO+snQzmnwrlXEumx2YPSh",
        "aP5ez4O4BYqvw+RuGZSVQWHmIFV0/JRuACRghfN3wvszaXc8c8b/h7/o9A9Vdo4p",
        "dk85TUI6FC7SvF1XvHa9oNab3akEs7kV7IiHJjrLO6PXVXvLmIgTAI81gv5PdXsp",
        "oHXs2T+90UvgraPU86W8xsUCAxedWZmbpqf2dLV2ajhnNAf44hIQSoVrcTibnKAZ",
        "Z5Cq+802OMtnrrcL3c/gOgCYRdvogS4LjJy7jBDElt5OTPdxRTApwt5kmsfY5N2Q",
        "OjfvV9wMC/jJh6fHo+yUUzzizd7waphmuy9M3ru1MR2AQQdBw4HQgOA8Uvw4p0zL",
        "+Xi/zqRdnJBK/e3h6YW+RCkMHkFrw4LCCgRkriu7YFRPgsHk0uow8sZ7X3QcZwvK",
        "O6AfFcSP386z9ReSlzHs2jxsU6L/DVKcWFnaqztnXYgoZwiPHNQV3p2ZDpiRYBGf",
        "BleeItv/QXXOBGdB3J0j1I7j8+XrwgBx1ObwZAL2qE3MfiMdQhM2h2dU98bufk/F",
        "Mc/dKqTUubjy1m3BhkGqAQlFzW9hHnIfbLv/P0uDNI2yoLzB5hk52MqMRrMcS451",
        "oN31ep7H7yr2IE8iA5xxL5bmF3asOLMhWxqZPZZWjxogLjl2gZaj6vcGHjpTVVxg",
        "YneMztbX2w8qOkFCXG1vfZOcpqyvs8MIJys9WF57iJ7K6+4AAAAAAAAAAAAAAAAA",
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
    fn seeds_come_from_the_key() {
        // Appendix B's seed, the 32 bytes after the PKCS#8 prefix.
        let seed = key_seed(&appendix_b());
        assert_eq!(seed[..4], [0xc1, 0x1f, 0xae, 0x5c]);
        assert_eq!(
            SecretKey::from_seed(*seed).public_key(),
            appendix_b().public_key()
        );
    }

    /// A platform store as an app writes it: seeds by identity.
    #[derive(Default)]
    struct Platform(Mutex<HashMap<String, Vec<u8>>>);

    impl PlatformKeyStore for Platform {
        fn load(&self, identity: String) -> Result<Option<Vec<u8>>, PlatformKeyError> {
            if identity == "locked@example.org" {
                return Err(PlatformKeyError::Denied {
                    message: "the keychain is locked".into(),
                });
            }
            Ok(self.0.lock().unwrap().get(&identity).cloned())
        }
        fn save(&self, identity: String, seed: Vec<u8>) -> Result<(), PlatformKeyError> {
            self.0.lock().unwrap().insert(identity, seed);
            Ok(())
        }
        fn delete(&self, identity: String) -> Result<(), PlatformKeyError> {
            self.0.lock().unwrap().remove(&identity);
            Ok(())
        }
    }

    #[test]
    fn platform_stores_keep_seeds() {
        let platform = std::sync::Arc::new(Platform::default());
        let keys = PlatformKeys(platform.clone());
        assert!(keys.load("alice@example.org").unwrap().is_none());
        keys.save("alice@example.org", &appendix_b()).unwrap();
        let stored = platform.0.lock().unwrap()["alice@example.org"].clone();
        assert_eq!(stored, key_seed(&appendix_b()).to_vec());
        let loaded = keys.load("alice@example.org").unwrap().unwrap();
        assert_eq!(loaded.public_key(), appendix_b().public_key());
        keys.delete("alice@example.org").unwrap();
        assert!(keys.load("alice@example.org").unwrap().is_none());

        // Errors keep their kind.
        platform
            .0
            .lock()
            .unwrap()
            .insert("short@example.org".into(), vec![1, 2, 3]);
        assert!(matches!(
            keys.load("short@example.org"),
            Err(KeyStoreError::BadKey(_))
        ));
        assert!(matches!(
            keys.load("locked@example.org"),
            Err(KeyStoreError::Denied(_))
        ));
    }

    #[test]
    fn rust_stores_are_platform_stores_too() {
        let dir = tempfile::tempdir().unwrap();
        let files = AsPlatform(std::sync::Arc::new(FileKeyStore::new(dir.path())));
        let seed = key_seed(&appendix_b()).to_vec();
        files
            .save("alice@example.org".into(), seed.clone())
            .unwrap();
        // The file is Appendix B's PEM.
        let path = FileKeyStore::new(dir.path())
            .path("alice@example.org")
            .unwrap();
        assert_eq!(fs::read_to_string(path).unwrap(), PEM);
        assert_eq!(files.load("alice@example.org".into()).unwrap(), Some(seed));
        let memory = AsPlatform(std::sync::Arc::new(MemoryKeyStore::default()));
        assert!(matches!(
            memory.save("x@example.org".into(), vec![0; 31]),
            Err(PlatformKeyError::BadKey { .. })
        ));
        // And back again.
        let wrapped = PlatformKeys(std::sync::Arc::new(memory));
        wrapped.save("x@example.org", &appendix_b()).unwrap();
        assert_eq!(
            wrapped.load("x@example.org").unwrap().unwrap().public_key(),
            appendix_b().public_key()
        );
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
