//! Publishing hosted identities' key files (4.6): the
//! [`KeyFilePublisher`] trait the hub uses, and [`KeyDir`], which writes
//! the files to a directory.
//!
//! The directory holds one file per hosted name, `<dir>/<name>`, readable
//! by everyone (mode 0644), so an operator can serve it as
//! `https://<identity domain>/.well-known/risala/` from nginx or Caddy.
//! `risalad`'s own HTTPS listener serves it too, when it is on.

use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use risala_proto::keyfile::KeyEntry;
use risala_proto::names::Name;

/// Publishes the key files of the identities the server hosts (4.6), at
/// the URL of 4.3.
///
/// The calls block (they write files), so the hub calls them off the
/// async runtime's worker threads, as it does the store.
pub trait KeyFilePublisher: Send + Sync + 'static {
    /// Publishes `name`'s key file with `keys`, in order, replacing the old
    /// one (4.6, 4.7). With no keys, the file is published empty, so the
    /// identity has no keys (10.5, ADMIN DELKEY of the last key).
    fn publish(&self, name: &Name, keys: &[KeyEntry]) -> io::Result<()>;

    /// Removes `name`'s key file (4.8, 10.5). Removing a file that does not
    /// exist succeeds.
    fn remove(&self, name: &Name) -> io::Result<()>;
}

/// Key files in a directory, `<dir>/<name>`, each replaced atomically.
///
/// The directory is made on the first publish, if it does not exist.
#[derive(Debug)]
pub struct KeyDir {
    dir: PathBuf,
    /// Held while a file is written, so two writes of one name do not share
    /// a temporary file.
    write: Mutex<()>,
}

impl KeyDir {
    /// Key files in `dir`.
    pub fn new(dir: impl Into<PathBuf>) -> KeyDir {
        KeyDir {
            dir: dir.into(),
            write: Mutex::new(()),
        }
    }

    /// The directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Where `name`'s key file is.
    pub fn path(&self, name: &Name) -> PathBuf {
        self.dir.join(name.as_str())
    }

    /// The text of a key file with `keys`: one line each, ending in LF
    /// (4.4).
    pub fn render(keys: &[KeyEntry]) -> String {
        keys.iter().map(|k| format!("{k}\n")).collect()
    }

    /// Reads `name`'s key file, or `None` if there is none. Blocks.
    pub fn read(&self, name: &Name) -> io::Result<Option<Vec<u8>>> {
        match fs::read(self.path(name)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn create_dir(&self) -> io::Result<()> {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o755);
        }
        builder.create(&self.dir)
    }
}

impl KeyFilePublisher for KeyDir {
    /// Writes `<dir>/.<name>.tmp`, then renames it over `<dir>/<name>`, so
    /// that a web server never serves half a file. Names never start with
    /// `.` (3.5), so the temporary file is never served as a key file.
    fn publish(&self, name: &Name, keys: &[KeyEntry]) -> io::Result<()> {
        let _write = self.write.lock().unwrap_or_else(|e| e.into_inner());
        self.create_dir()?;
        let path = self.path(name);
        let tmp = self.dir.join(format!(".{name}.tmp"));
        // A leftover from a crash would keep its old mode, so start afresh.
        match fs::remove_file(&tmp) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o644);
        }
        let mut file = options.open(&tmp)?;
        // The umask may have taken bits away; web servers must read it.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            file.set_permissions(fs::Permissions::from_mode(0o644))?;
        }
        let written = file
            .write_all(Self::render(keys).as_bytes())
            .and_then(|()| file.sync_all());
        drop(file);
        if let Err(e) = written.and_then(|()| fs::rename(&tmp, &path)) {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
        sync_dir(&self.dir);
        tracing::debug!(%name, keys = keys.len(), "published key file");
        Ok(())
    }

    fn remove(&self, name: &Name) -> io::Result<()> {
        let _write = self.write.lock().unwrap_or_else(|e| e.into_inner());
        match fs::remove_file(self.path(name)) {
            Ok(()) => {
                sync_dir(&self.dir);
                tracing::debug!(%name, "removed key file");
                Ok(())
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

/// Makes a rename or removal in `dir` durable, where the platform allows.
fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(dir) = fs::File::open(dir) {
        let _ = dir.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

#[cfg(test)]
mod tests {
    use super::*;
    use risala_proto::auth::SecretKey;
    use risala_proto::keyfile::KeyFile;

    fn entry(seed: u8, label: Option<&str>) -> KeyEntry {
        KeyEntry::new(SecretKey::from_seed([seed; 32]).public_key(), label).unwrap()
    }

    fn name(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn publish_replace_remove() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = KeyDir::new(tmp.path().join("keys"));
        let alice = name("alice");
        assert_eq!(dir.read(&alice).unwrap(), None);

        let keys = [entry(1, Some("laptop")), entry(2, None)];
        dir.publish(&alice, &keys).unwrap();
        let text = String::from_utf8(dir.read(&alice).unwrap().unwrap()).unwrap();
        assert_eq!(KeyFile::parse(&text).unwrap().keys(), &keys);
        assert!(text.ends_with('\n'));

        dir.publish(&alice, &keys[1..]).unwrap();
        let text = fs::read_to_string(tmp.path().join("keys/alice")).unwrap();
        assert_eq!(KeyFile::parse(&text).unwrap().keys(), &keys[1..]);

        // No keys: an empty file, which locks the identity.
        dir.publish(&alice, &[]).unwrap();
        assert_eq!(dir.read(&alice).unwrap(), Some(Vec::new()));

        dir.remove(&alice).unwrap();
        assert_eq!(dir.read(&alice).unwrap(), None);
        dir.remove(&alice).unwrap();

        // Only key files are left behind.
        dir.publish(&name("bob"), &keys).unwrap();
        let files: Vec<_> = fs::read_dir(dir.dir())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(files, ["bob"]);
    }

    #[cfg(unix)]
    #[test]
    fn files_are_world_readable() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let dir = KeyDir::new(tmp.path().join("a/b"));
        // A stale temporary file with other permissions is replaced.
        dir.create_dir().unwrap();
        let stale = tmp.path().join("a/b/.carol.tmp");
        fs::write(&stale, "junk").unwrap();
        fs::set_permissions(&stale, fs::Permissions::from_mode(0o600)).unwrap();

        dir.publish(&name("carol"), &[entry(3, None)]).unwrap();
        let mode = fs::metadata(dir.path(&name("carol")))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o644);
        assert!(!stale.exists());
    }
}
