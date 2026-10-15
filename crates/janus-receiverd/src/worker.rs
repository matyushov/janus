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
}

impl FileStore {
    /// Open the store; the directory is created if it does not exist.
    pub fn open(root: impl Into<PathBuf>) -> std::io::Result<FileStore> {
        let root = root.into();
        fs::create_dir_all(&root)?;
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

    pub fn create(&self, rel: &str, directory: bool, exclusive: bool) -> std::io::Result<()> {
        let path = self.resolve(rel)?;
        if directory {
            fs::create_dir_all(&path)?;
            return Ok(());
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
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

    pub fn delete(&self, rel: &str) -> std::io::Result<()> {
        let path = self.resolve(rel)?;
        if path.is_dir() {
            fs::remove_dir_all(path)
        } else {
            fs::remove_file(path)
        }
    }

    pub fn rename(&self, from: &str, to: &str, replace: bool) -> std::io::Result<()> {
        let src = self.resolve(from)?;
        let dst = self.resolve(to)?;
        if dst.exists() && !replace {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "destination exists",
            ));
        }
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::rename(src, dst)
    }

    pub fn truncate(&self, rel: &str, new_len: u64) -> std::io::Result<()> {
        let path = self.resolve(rel)?;
        let f = fs::OpenOptions::new().write(true).open(&path)?;
        f.set_len(new_len)
    }

    pub fn stat(&self, rel: &str) -> std::io::Result<StatInfo> {
        let path = self.resolve(rel)?;
        let md = fs::metadata(&path)?;
        Ok(StatInfo {
            rel_path: rel.to_string(),
            size: md.len(),
            directory: md.is_dir(),
            mtime_unix_ns: mtime_nanos(&md),
        })
    }

    pub fn list(&self, rel_dir: &str) -> std::io::Result<Vec<StatInfo>> {
        let path = if rel_dir.is_empty() {
            self.root.clone()
        } else {
            self.resolve(rel_dir)?
        };
        let mut out = Vec::new();
        for entry in fs::read_dir(&path)? {
            let entry = entry?;
            let md = entry.metadata()?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let rel = if rel_dir.is_empty() {
                name
            } else {
                format!("{}/{}", rel_dir.trim_end_matches('/'), name)
            };
            out.push(StatInfo {
                rel_path: rel,
                size: md.len(),
                directory: md.is_dir(),
                mtime_unix_ns: mtime_nanos(&md),
            });
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

    /// The second line of path defence: forbid `..`, absolute paths and escaping the root.
    fn resolve(&self, rel: &str) -> std::io::Result<PathBuf> {
        self.validate(rel)?;
        Ok(self.root.join(rel))
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

fn mtime_nanos(md: &fs::Metadata) -> i64 {
    md.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
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
        store.rename("a", "b", false).unwrap();
        assert!(store.stat("a").is_err());
        store.truncate("b", 3).unwrap();
        assert_eq!(store.read_range("b", 0, 10).unwrap(), b"abc");
        store.delete("b").unwrap();
        assert!(store.stat("b").is_err());
        fs::remove_dir_all(dir).ok();
    }
}
