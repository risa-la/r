//! Publishing hosted identities' key files (4.7): [`KeyDir`], the hub's
//! [`KeyFilePublisher`], which writes the files to a directory.
//!
//! The directory holds one file per hosted name, `<dir>/<name>`, readable
//! by everyone (mode 0644), so an operator can serve it as
//! `https://<identity domain>/.well-known/risala/` from nginx or Caddy.
//! `risalad`'s own HTTPS listener serves it too, when it is on.

use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use risala_proto::keyfile::KEY_FILE_HEADER;
use risala_proto::names::Name;

use crate::keyfiles::KeyFilePublisher;

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
    fn publish(&self, name: &Name, contents: &[u8]) -> io::Result<()> {
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
        let written = file.write_all(contents).and_then(|()| file.sync_all());
        drop(file);
        if let Err(e) = written.and_then(|()| fs::rename(&tmp, &path)) {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
        sync_dir(&self.dir);
        tracing::debug!(%name, bytes = contents.len(), "published key file");
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

    /// Removes the key files of names not in `hosted`. Operators may keep
    /// other files in the directory, such as an index page, so only a
    /// file this could have written is removed: a regular file, named as
    /// a name is (3.5), whose first line is a key file's (4.4).
    fn retain(&self, hosted: &[Name]) -> io::Result<()> {
        let _write = self.write.lock().unwrap_or_else(|e| e.into_inner());
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        let mut removed = false;
        for entry in entries {
            let entry = entry?;
            let Some(name) = entry
                .file_name()
                .to_str()
                .and_then(|n| n.parse::<Name>().ok())
            else {
                continue;
            };
            // A name parses case-insensitively, but a file of another case
            // is not one this wrote.
            if entry.file_name().to_str() != Some(name.as_str())
                || hosted.contains(&name)
                || !entry.file_type()?.is_file()
            {
                continue;
            }
            let path = entry.path();
            let bytes = fs::read(&path)?;
            if !is_key_file(&bytes) {
                continue;
            }
            fs::remove_file(&path)?;
            removed = true;
            tracing::info!(%name, "removed the key file of a name no longer hosted");
        }
        if removed {
            sync_dir(&self.dir);
        }
        Ok(())
    }
}

/// Whether `bytes` start like a key file of this version (4.4).
fn is_key_file(bytes: &[u8]) -> bool {
    bytes
        .strip_prefix(KEY_FILE_HEADER.as_bytes())
        .is_some_and(|rest| rest.starts_with(b"\n"))
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

    fn file(n: u8) -> Vec<u8> {
        format!("{KEY_FILE_HEADER}\n# file {n}\n").into_bytes()
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

        dir.publish(&alice, &file(1)).unwrap();
        assert_eq!(dir.read(&alice).unwrap(), Some(file(1)));
        dir.publish(&alice, &file(2)).unwrap();
        assert_eq!(fs::read(tmp.path().join("keys/alice")).unwrap(), file(2));

        dir.remove(&alice).unwrap();
        assert_eq!(dir.read(&alice).unwrap(), None);
        dir.remove(&alice).unwrap();

        // Only key files are left behind.
        dir.publish(&name("bob"), &file(1)).unwrap();
        let files: Vec<_> = fs::read_dir(dir.dir())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(files, ["bob"]);
    }

    /// Files of names no longer hosted go, and nothing else does.
    #[test]
    fn retain_removes_only_stale_key_files() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = KeyDir::new(tmp.path());
        dir.publish(&name("alice"), &file(1)).unwrap();
        dir.publish(&name("bob"), &file(2)).unwrap();
        dir.publish(&name("carol.x"), &file(3)).unwrap();
        let key_file = String::from_utf8(file(4)).unwrap();
        for (path, text) in [
            ("index.html", "<html></html>\n"),
            ("empty", ""),
            ("notes", "risala-keys/10\n"),
            ("Dave", key_file.as_str()),
            (".eve.tmp", key_file.as_str()),
        ] {
            fs::write(tmp.path().join(path), text).unwrap();
        }
        fs::create_dir(tmp.path().join("frank")).unwrap();

        dir.retain(&[name("alice")]).unwrap();
        let mut files: Vec<_> = fs::read_dir(dir.dir())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        files.sort();
        assert_eq!(
            files,
            [
                ".eve.tmp",
                "Dave",
                "alice",
                "empty",
                "frank",
                "index.html",
                "notes"
            ]
        );
        // A directory that does not exist yet has nothing to remove.
        KeyDir::new(tmp.path().join("none")).retain(&[]).unwrap();
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

        dir.publish(&name("carol"), &file(3)).unwrap();
        let mode = fs::metadata(dir.path(&name("carol")))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o644);
        assert!(!stale.exists());
    }
}
