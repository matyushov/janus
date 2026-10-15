//! StoreWorker is a process WITHOUT network: it sees only its machine's store (the
//! band storage directory). Isolation: nullfs/bind + cap-std Dir, a double defence,
//! so even a path-validation bug does not let anything out of the store.
//!
//! "store" is backend-neutral: an ordinary directory. Snapshots/rotation of points are
//! the appliance orchestration layer; the receiver knows nothing about them and only writes files.

#![allow(dead_code)] // part of the API appears before its callers

use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Executor of file operations inside a single machine store.
pub struct FileStore {
    // TODO(isolation): cap_std::fs::Dir instead of PathBuf, once cap-std arrives.
    root: PathBuf,
}

/// Metadata of an object in the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatInfo {
    pub rel_path: String,
    pub size: u64,
    pub directory: bool,
    pub mtime_unix_ns: i64,
    pub atime_unix_ns: Option<i64>,
    pub ctime_unix_ns: Option<i64>,
    pub btime_unix_ns: Option<i64>,
    pub read_only: bool,
    /// Inode where the platform has one, else 0.
    pub file_id: u64,
}

/// Machine-readable error class carried inside an `io::Error` (see `ErrClass`).
/// The service turns it into the `janus-error` trailer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrClass {
    /// A parent directory is missing (as opposed to the final component).
    PathNotFound,
}

impl std::fmt::Display for ErrClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrClass::PathNotFound => f.write_str("parent directory does not exist"),
        }
    }
}

impl std::error::Error for ErrClass {}

fn path_not_found() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::NotFound, ErrClass::PathNotFound)
}

fn denied(msg: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, msg)
}

impl FileStore {
    /// Open the store; the directory is created if it does not exist.
    pub fn open(root: impl Into<PathBuf>) -> std::io::Result<FileStore> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(FileStore { root })
    }

    /// Open a store that must already exist (read-only inspection; never creates anything).
    pub fn open_existing(root: impl Into<PathBuf>) -> std::io::Result<FileStore> {
        let root = root.into();
        if !root.is_dir() {
            return Err(std::io::Error::from(std::io::ErrorKind::NotFound));
        }
        Ok(FileStore { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// pwrite is idempotent by construction (the basis of client retries):
    /// repeating the same (offset, data) gives the same result.
    pub fn write_range(&self, rel: &str, offset: u64, data: &[u8]) -> std::io::Result<()> {
        let path = self.resolve(rel)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&path)?;
        // Writing past EOF is allowed: the file grows (sparse semantics of bands).
        f.seek(SeekFrom::Start(offset))?;
        f.write_all(data)?;
        Ok(())
    }

    /// Range read. Past EOF it returns as much as there is (a short read).
    pub fn read_range(&self, rel: &str, offset: u64, len: u32) -> std::io::Result<Vec<u8>> {
        let path = self.resolve(rel)?;
        let mut f = fs::File::open(&path)?;
        let size = f.metadata()?.len();
        if offset >= size {
            return Ok(Vec::new());
        }
        let to_read = std::cmp::min(len as u64, size - offset) as usize;
        f.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; to_read];
        f.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// scope=file → fsync of the file; scope=all → fsync of all store files.
    ///
    /// NB: `sync_all()` requires a WRITABLE DESCRIPTOR; on Windows, sync
    /// of a read-only handle gives "Access is denied" (caught by a test).
    /// TODO: track the dirty set and sync only what was touched (question R.3).
    pub fn fsync(&self, scope: FsyncScope) -> std::io::Result<()> {
        match scope {
            FsyncScope::File(rel) => {
                let path = self.resolve(&rel)?;
                fs::OpenOptions::new().write(true).open(&path)?.sync_all()
            }
            FsyncScope::AllBundle => {
                // We sync files recursively; directory sync is not portable everywhere
                // (not supported on Windows), so we do not treat it as an error.
                fn sync_dir(dir: &Path) -> std::io::Result<()> {
                    for entry in fs::read_dir(dir)? {
                        let entry = entry?;
                        let path = entry.path();
                        if entry.metadata()?.is_dir() {
                            sync_dir(&path)?;
                        } else if let Ok(f) = fs::OpenOptions::new().write(true).open(&path) {
                            f.sync_all()?;
                        }
                    }
                    Ok(())
                }
                sync_dir(&self.root)
            }
        }
    }

    /// `create_parents` keeps the rev-1 behaviour (missing parents are created); rev-2 clients
    /// pass `false` and get `path-not-found` instead. `exclusive` applies to directories too.
    pub fn create(
        &self,
        rel: &str,
        directory: bool,
        exclusive: bool,
        create_parents: bool,
    ) -> std::io::Result<()> {
        let path = self.resolve(rel)?;
        self.prepare_parent(&path, create_parents)?;
        if directory {
            return match fs::create_dir(&path) {
                Ok(()) => Ok(()),
                Err(_) if !exclusive && path.is_dir() => Ok(()),
                Err(e) => Err(e),
            };
        }
        // truncate(false) is EXPLICIT: CREATE must not zero an existing file
        // (otherwise a repeated CREATE of a band would erase the data already written).
        let res = fs::OpenOptions::new()
            .create_new(exclusive)
            .create(true)
            .write(true)
            .truncate(false)
            .open(&path);
        match res {
            Ok(_) => Ok(()),
            Err(e) if !exclusive && e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn prepare_parent(&self, path: &Path, create_parents: bool) -> std::io::Result<()> {
        let Some(parent) = path.parent() else {
            return Ok(());
        };
        if create_parents {
            fs::create_dir_all(parent)
        } else if parent.is_dir() {
            Ok(())
        } else {
            Err(path_not_found())
        }
    }

    /// `recursive` keeps the rev-1 behaviour; otherwise a non-empty directory fails with
    /// `DirectoryNotEmpty`.
    pub fn delete(&self, rel: &str, recursive: bool) -> std::io::Result<()> {
        let path = self.resolve(rel)?;
        let md = fs::symlink_metadata(&path)?;
        if md.is_dir() {
            if recursive {
                fs::remove_dir_all(path)
            } else {
                fs::remove_dir(path)
            }
        } else {
            fs::remove_file(path)
        }
    }

    pub fn rename(
        &self,
        from: &str,
        to: &str,
        replace: bool,
        create_parents: bool,
    ) -> std::io::Result<()> {
        let src = self.resolve(from)?;
        let dst = self.resolve(to)?;
        fs::symlink_metadata(&src)?; // NotFound for a missing source
        match fs::symlink_metadata(&dst) {
            Ok(md) => {
                if !replace {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        "destination exists",
                    ));
                }
                if md.is_dir() {
                    return Err(denied("cannot replace a directory"));
                }
            }
            Err(_) => self.prepare_parent(&dst, create_parents)?,
        }
        fs::rename(src, dst)
    }

    /// `None` leaves a field unchanged. Directories are best effort (a no-op), like the
    /// client's local reference backend.
    pub fn set_times(
        &self,
        rel: &str,
        atime_ns: Option<i64>,
        mtime_ns: Option<i64>,
    ) -> std::io::Result<()> {
        let path = self.resolve(rel)?;
        if fs::symlink_metadata(&path)?.is_dir() {
            return Ok(());
        }
        let mut t = fs::FileTimes::new();
        if let Some(a) = atime_ns {
            t = t.set_accessed(from_unix_ns(a));
        }
        if let Some(m) = mtime_ns {
            t = t.set_modified(from_unix_ns(m));
        }
        fs::OpenOptions::new().write(true).open(&path)?.set_times(t)
    }

    pub fn truncate(&self, rel: &str, new_len: u64) -> std::io::Result<()> {
        let path = self.resolve(rel)?;
        let f = fs::OpenOptions::new().write(true).open(&path)?;
        f.set_len(new_len)
    }

    /// `rel == ""` is the store root.
    pub fn stat(&self, rel: &str) -> std::io::Result<StatInfo> {
        let path = self.resolve_or_root(rel)?;
        let md = fs::symlink_metadata(&path)?;
        Ok(stat_info(rel.to_string(), &md))
    }

    pub fn list(&self, rel_dir: &str) -> std::io::Result<Vec<StatInfo>> {
        let path = self.resolve_or_root(rel_dir)?;
        let mut out = Vec::new();
        for entry in fs::read_dir(&path)? {
            let entry = entry?;
            let Ok(md) = entry.metadata() else { continue };
            if md.file_type().is_symlink() {
                continue; // never exposed
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            let rel = if rel_dir.is_empty() {
                name
            } else {
                format!("{}/{}", rel_dir.trim_end_matches('/'), name)
            };
            out.push(stat_info(rel, &md));
        }
        out.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
        Ok(out)
    }

    /// Total used volume (recursive), for StatFs.
    pub fn used_bytes(&self) -> std::io::Result<u64> {
        fn walk(dir: &Path) -> std::io::Result<u64> {
            let mut total = 0;
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let md = entry.metadata()?;
                total += if md.is_dir() {
                    walk(&entry.path())?
                } else {
                    md.len()
                };
            }
            Ok(total)
        }
        walk(&self.root)
    }

    /// The second line of path defence: forbid `..`, absolute paths, escaping the root and
    /// crossing symlinks.
    fn resolve(&self, rel: &str) -> std::io::Result<PathBuf> {
        self.validate(rel)?;
        let mut path = self.root.clone();
        for part in rel.split('/') {
            path.push(part);
            if let Ok(m) = fs::symlink_metadata(&path)
                && m.file_type().is_symlink()
            {
                return Err(denied("path crosses a symlink"));
            }
        }
        Ok(path)
    }

    fn resolve_or_root(&self, rel: &str) -> std::io::Result<PathBuf> {
        if rel.is_empty() {
            Ok(self.root.clone())
        } else {
            self.resolve(rel)
        }
    }

    fn validate(&self, rel: &str) -> std::io::Result<()> {
        let bad = rel.is_empty()
            || rel.starts_with('/')
            || rel.starts_with('\\')
            || rel.contains(':')
            || rel
                .split(['/', '\\'])
                .any(|c| c == ".." || c == "." || c.is_empty());
        if bad {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "path escapes store",
            ));
        }
        Ok(())
    }
}

fn unix_ns(t: std::io::Result<std::time::SystemTime>) -> Option<i64> {
    let t = t.ok()?;
    match t.duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_nanos()).ok(),
        Err(e) => i64::try_from(e.duration().as_nanos()).ok().map(|n| -n),
    }
}

fn from_unix_ns(ns: i64) -> std::time::SystemTime {
    use std::time::{Duration, UNIX_EPOCH};
    if ns >= 0 {
        UNIX_EPOCH + Duration::from_nanos(ns as u64)
    } else {
        UNIX_EPOCH - Duration::from_nanos(ns.unsigned_abs())
    }
}

#[cfg(unix)]
fn ctime_and_id(md: &fs::Metadata) -> (Option<i64>, u64) {
    use std::os::unix::fs::MetadataExt;
    (Some(md.ctime() * 1_000_000_000 + md.ctime_nsec()), md.ino())
}

#[cfg(not(unix))]
fn ctime_and_id(_md: &fs::Metadata) -> (Option<i64>, u64) {
    (None, 0)
}

fn stat_info(rel_path: String, md: &fs::Metadata) -> StatInfo {
    let (ctime, file_id) = ctime_and_id(md);
    StatInfo {
        rel_path,
        size: if md.is_dir() { 0 } else { md.len() },
        directory: md.is_dir(),
        mtime_unix_ns: unix_ns(md.modified()).unwrap_or(0),
        atime_unix_ns: unix_ns(md.accessed()),
        ctime_unix_ns: ctime,
        btime_unix_ns: unix_ns(md.created()),
        read_only: md.permissions().readonly(),
        file_id,
    }
}

pub enum FsyncScope {
    File(String),
    AllBundle,
}

/// Quota: the source of NoSpace → STATUS_DISK_FULL → thinning in TM (an end-to-end chain).
/// usage: a hybrid of "accounting in the worker + periodic backend reconciliation" (open question R.3).
#[derive(Debug, Default)]
pub struct QuotaMeter {
    pub quota_bytes: u64,
    pub used_bytes: u64,
}

/// Exceeding the quota → NoSpace → STATUS_DISK_FULL on the Mac.
#[derive(Debug)]
pub struct QuotaExceeded;

impl QuotaMeter {
    pub fn check(&self, add: u64) -> Result<(), QuotaExceeded> {
        if self.used_bytes.saturating_add(add) > self.quota_bytes {
            Err(QuotaExceeded)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_store() -> (FileStore, PathBuf) {
        // A counter, not just the clock: macOS time has ~1 µs granularity, so parallel
        // tests could get the same directory and delete each other's files.
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "janus-store-test-{}-{:?}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        (FileStore::open(&dir).unwrap(), dir)
    }

    #[test]
    fn write_read_roundtrip_with_offset() {
        let (store, dir) = tmp_store();
        store.write_range("bands/1a", 0, b"hello").unwrap();
        store.write_range("bands/1a", 5, b"world").unwrap();
        let got = store.read_range("bands/1a", 0, 100).unwrap();
        assert_eq!(&got, b"helloworld");
        // idempotence: repeating the same write does not change the result
        store.write_range("bands/1a", 5, b"world").unwrap();
        assert_eq!(store.read_range("bands/1a", 0, 100).unwrap(), b"helloworld");
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn path_traversal_rejected() {
        let (store, dir) = tmp_store();
        for bad in ["../escape", "/abs", "a/../../b", "", "C:/x"] {
            assert!(
                store.write_range(bad, 0, b"x").is_err(),
                "must be rejected: {bad}"
            );
        }
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn stat_list_and_used_bytes() {
        let (store, dir) = tmp_store();
        store.write_range("bands/1", 0, b"12345").unwrap();
        store.write_range("bands/2", 0, b"123").unwrap();
        let st = store.stat("bands/1").unwrap();
        assert_eq!(st.size, 5);
        assert!(!st.directory);
        let listing = store.list("bands").unwrap();
        assert_eq!(listing.len(), 2);
        assert_eq!(store.used_bytes().unwrap(), 8);
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn rename_delete_truncate() {
        let (store, dir) = tmp_store();
        store.write_range("a", 0, b"abcdef").unwrap();
        store.rename("a", "b", false, true).unwrap();
        assert!(store.stat("a").is_err());
        store.truncate("b", 3).unwrap();
        assert_eq!(store.read_range("b", 0, 10).unwrap(), b"abc");
        store.delete("b", true).unwrap();
        assert!(store.stat("b").is_err());
        fs::remove_dir_all(dir).ok();
    }
}
