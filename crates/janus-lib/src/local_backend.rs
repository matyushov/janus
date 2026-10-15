//! `LocalFsBackend`: an ordinary local folder as the share storage.
//!
//! Used by tests and as a reference against Samba (a real Time Machine run through
//! our server compared with Samba+vfs_fruit). All blocking filesystem calls run on the
//! tokio blocking pool. Symlinks are never followed (a path that crosses one is refused),
//! so a client cannot escape the root. The check is not race-free against a local
//! attacker who modifies the tree concurrently; this backend is not a security boundary
//! against local users.

use std::collections::HashMap;
use std::fs::{File, FileTimes, Metadata, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::vfs::{
    BackendError, BackendHandle, Disposition, FileStat, FsStats, Kind, OpenRequest, Opened, Result,
    SetTimes, StorageBackend,
};

/// Default share quota when none is configured (1 TiB).
const DEFAULT_QUOTA: u64 = 1 << 40;
/// How long a computed "used bytes" figure is reused.
const USED_CACHE: Duration = Duration::from_secs(2);

/// An open object.
struct Entry {
    /// Current path (updated by `rename`).
    path: Mutex<PathBuf>,
    /// `None` for directories.
    file: Option<File>,
    delete_on_close: AtomicBool,
}

impl Entry {
    fn path(&self) -> PathBuf {
        self.path.lock().expect("path poisoned").clone()
    }
}

pub struct LocalFsBackend {
    root: PathBuf,
    quota_bytes: u64,
    next_handle: AtomicU64,
    handles: Mutex<HashMap<u64, Arc<Entry>>>,
    used_cache: Mutex<Option<(Instant, u64)>>,
}

impl LocalFsBackend {
    /// The root is created when missing.
    pub fn new(root: impl Into<PathBuf>) -> std::io::Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        Ok(LocalFsBackend {
            root,
            quota_bytes: DEFAULT_QUOTA,
            next_handle: AtomicU64::new(1),
            handles: Mutex::new(HashMap::new()),
            used_cache: Mutex::new(None),
        })
    }

    pub fn with_quota(mut self, quota_bytes: u64) -> Self {
        self.quota_bytes = quota_bytes;
        self
    }

    /// Map a share-relative path to a filesystem path below the root.
    /// Refuses `.`/`..`, NUL, `\`, and symlinks; `:` (alternate data streams) is reported
    /// as not found.
    fn resolve(&self, rel: &str) -> Result<PathBuf> {
        let mut path = self.root.clone();
        for part in rel.split('/').filter(|p| !p.is_empty()) {
            if part == "." || part == ".." || part.contains('\0') || part.contains('\\') {
                return Err(BackendError::AccessDenied);
            }
            if part.contains(':') {
                return Err(BackendError::NotFound);
            }
            path.push(part);
            if let Ok(m) = std::fs::symlink_metadata(&path)
                && m.file_type().is_symlink()
            {
                return Err(BackendError::AccessDenied);
            }
        }
        Ok(path)
    }

    fn rel_of(&self, path: &Path) -> String {
        path.strip_prefix(&self.root)
            .map(|p| {
                p.components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/")
            })
            .unwrap_or_default()
    }

    fn entry(&self, h: BackendHandle) -> Result<Arc<Entry>> {
        self.handles
            .lock()
            .expect("handle table poisoned")
            .get(&h.0)
            .cloned()
            .ok_or(BackendError::BadHandle)
    }

    fn insert(&self, entry: Entry) -> BackendHandle {
        let id = self.next_handle.fetch_add(1, Ordering::Relaxed);
        self.handles
            .lock()
            .expect("handle table poisoned")
            .insert(id, Arc::new(entry));
        BackendHandle(id)
    }
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| BackendError::Io(std::io::Error::other(e)))?
}

fn map_io(e: std::io::Error) -> BackendError {
    use std::io::ErrorKind as K;
    match e.kind() {
        K::NotFound => BackendError::NotFound,
        K::AlreadyExists => BackendError::AlreadyExists,
        K::PermissionDenied => BackendError::AccessDenied,
        K::NotADirectory => BackendError::NotADirectory,
        K::IsADirectory => BackendError::IsADirectory,
        K::DirectoryNotEmpty => BackendError::DirectoryNotEmpty,
        K::StorageFull | K::QuotaExceeded => BackendError::NoSpace,
        _ => BackendError::Io(e),
    }
}

fn unix_ns(t: std::io::Result<SystemTime>) -> Option<i64> {
    let t = t.ok()?;
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_nanos()).ok(),
        Err(e) => i64::try_from(e.duration().as_nanos()).ok().map(|n| -n),
    }
}

fn from_unix_ns(ns: i64) -> SystemTime {
    if ns >= 0 {
        UNIX_EPOCH + Duration::from_nanos(ns as u64)
    } else {
        UNIX_EPOCH - Duration::from_nanos(ns.unsigned_abs())
    }
}

#[cfg(unix)]
fn ctime_and_id(m: &Metadata) -> (Option<i64>, u64) {
    use std::os::unix::fs::MetadataExt;
    (Some(m.ctime() * 1_000_000_000 + m.ctime_nsec()), m.ino())
}

#[cfg(not(unix))]
fn ctime_and_id(_m: &Metadata) -> (Option<i64>, u64) {
    (None, 0)
}

fn stat_of(rel: String, m: &Metadata) -> FileStat {
    let mtime = unix_ns(m.modified()).unwrap_or(0);
    let (ctime, file_id) = ctime_and_id(m);
    FileStat {
        name: rel.rsplit('/').next().unwrap_or("").to_owned(),
        rel_path: rel,
        size: if m.is_dir() { 0 } else { m.len() },
        directory: m.is_dir(),
        read_only: m.permissions().readonly(),
        mtime_unix_ns: mtime,
        atime_unix_ns: unix_ns(m.accessed()).unwrap_or(mtime),
        ctime_unix_ns: ctime.unwrap_or(mtime),
        btime_unix_ns: unix_ns(m.created()).unwrap_or(mtime),
        file_id,
    }
}

#[cfg(unix)]
fn read_at(f: &File, buf: &mut [u8], off: u64) -> std::io::Result<usize> {
    std::os::unix::fs::FileExt::read_at(f, buf, off)
}
#[cfg(windows)]
fn read_at(f: &File, buf: &mut [u8], off: u64) -> std::io::Result<usize> {
    std::os::windows::fs::FileExt::seek_read(f, buf, off)
}
#[cfg(unix)]
fn write_at(f: &File, buf: &[u8], off: u64) -> std::io::Result<usize> {
    std::os::unix::fs::FileExt::write_at(f, buf, off)
}
#[cfg(windows)]
fn write_at(f: &File, buf: &[u8], off: u64) -> std::io::Result<usize> {
    std::os::windows::fs::FileExt::seek_write(f, buf, off)
}

/// Result of `open_blocking` before a handle number is assigned.
struct Opening {
    entry: Entry,
    stat: FileStat,
    created: bool,
    overwritten: bool,
}

fn open_blocking(path: PathBuf, rel: String, req: OpenRequest) -> Result<Opening> {
    let existing = match std::fs::symlink_metadata(&path) {
        Ok(m) => Some(m),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(map_io(e)),
    };
    let truncating = matches!(
        req.disposition,
        Disposition::Overwrite | Disposition::OverwriteOrCreate | Disposition::Supersede
    );
    let created;
    let overwritten;
    let file = match existing {
        Some(m) => {
            if req.disposition == Disposition::Create {
                return Err(BackendError::AlreadyExists);
            }
            match (m.is_dir(), req.kind) {
                (true, Kind::File) => return Err(BackendError::IsADirectory),
                (false, Kind::Directory) => return Err(BackendError::NotADirectory),
                _ => {}
            }
            if m.is_dir() && truncating {
                return Err(BackendError::IsADirectory);
            }
            created = false;
            overwritten = truncating;
            if m.is_dir() {
                None
            } else {
                Some(
                    OpenOptions::new()
                        .read(true)
                        .write(req.write || truncating)
                        .truncate(truncating)
                        .open(&path)
                        .map_err(map_io)?,
                )
            }
        }
        None => {
            if matches!(req.disposition, Disposition::Open | Disposition::Overwrite) {
                return Err(BackendError::NotFound);
            }
            // A missing parent is a different error from a missing final component.
            if path.parent().is_some_and(|p| !p.is_dir()) {
                return Err(BackendError::PathNotFound);
            }
            created = true;
            overwritten = false;
            if req.kind == Kind::Directory {
                std::fs::create_dir(&path).map_err(map_io)?;
                None
            } else {
                Some(
                    OpenOptions::new()
                        .read(true)
                        .write(true)
                        .create_new(true)
                        .open(&path)
                        .map_err(map_io)?,
                )
            }
        }
    };
    let meta = match &file {
        Some(f) => f.metadata().map_err(map_io)?,
        None => std::fs::metadata(&path).map_err(map_io)?,
    };
    Ok(Opening {
        entry: Entry {
            path: Mutex::new(path),
            file,
            delete_on_close: req.delete_on_close.into(),
        },
        stat: stat_of(rel, &meta),
        created,
        overwritten,
    })
}

fn dir_size(dir: &Path) -> u64 {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    rd.flatten()
        .map(|e| match std::fs::symlink_metadata(e.path()) {
            Ok(m) if m.is_dir() => dir_size(&e.path()),
            Ok(m) => m.len(),
            Err(_) => 0,
        })
        .sum()
}

impl StorageBackend for LocalFsBackend {
    async fn open(&self, rel_path: &str, req: OpenRequest) -> Result<Opened> {
        let path = self.resolve(rel_path)?;
        let rel = self.rel_of(&path);
        let o = blocking(move || open_blocking(path, rel, req)).await?;
        Ok(Opened {
            handle: self.insert(o.entry),
            stat: o.stat,
            created: o.created,
            overwritten: o.overwritten,
        })
    }

    async fn stat_handle(&self, h: BackendHandle) -> Result<FileStat> {
        let e = self.entry(h)?;
        let path = e.path();
        let rel = self.rel_of(&path);
        blocking(move || {
            let m = match &e.file {
                Some(f) => f.metadata(),
                None => std::fs::metadata(&path),
            }
            .map_err(map_io)?;
            Ok(stat_of(rel, &m))
        })
        .await
    }

    async fn read(&self, h: BackendHandle, offset: u64, len: u32) -> Result<Vec<u8>> {
        let e = self.entry(h)?;
        blocking(move || {
            let f = e.file.as_ref().ok_or(BackendError::IsADirectory)?;
            // A range that would pass u64::MAX is simply short, never wrapped around.
            let len = (len as u64).min(u64::MAX - offset) as usize;
            let mut buf = vec![0u8; len];
            let mut filled = 0;
            while filled < buf.len() {
                let n = read_at(f, &mut buf[filled..], offset + filled as u64).map_err(map_io)?;
                if n == 0 {
                    break;
                }
                filled += n;
            }
            buf.truncate(filled);
            Ok(buf)
        })
        .await
    }

    async fn write(&self, h: BackendHandle, offset: u64, data: &[u8]) -> Result<()> {
        let e = self.entry(h)?;
        let data = data.to_vec();
        blocking(move || {
            let f = e.file.as_ref().ok_or(BackendError::IsADirectory)?;
            if offset.checked_add(data.len() as u64).is_none() {
                return Err(BackendError::Io(std::io::ErrorKind::InvalidInput.into()));
            }
            let mut done = 0;
            while done < data.len() {
                let n = write_at(f, &data[done..], offset + done as u64).map_err(map_io)?;
                if n == 0 {
                    return Err(BackendError::Io(std::io::ErrorKind::WriteZero.into()));
                }
                done += n;
            }
            Ok(())
        })
        .await
    }

    async fn flush(&self, h: BackendHandle, _fullfsync: bool) -> Result<()> {
        let e = self.entry(h)?;
        blocking(move || match &e.file {
            // On macOS std's sync_all issues F_FULLFSYNC, which is what the flag asks for.
            Some(f) => f.sync_all().map_err(map_io),
            None => Ok(()),
        })
        .await
    }

    async fn close(&self, h: BackendHandle) -> Result<()> {
        let e = self
            .handles
            .lock()
            .expect("handle table poisoned")
            .remove(&h.0)
            .ok_or(BackendError::BadHandle)?;
        blocking(move || {
            let delete = e.delete_on_close.load(Ordering::Relaxed);
            let path = e.path();
            let is_dir = e.file.is_none();
            drop(e); // release the file before unlinking (required on Windows)
            if delete {
                if is_dir {
                    std::fs::remove_dir(&path).map_err(map_io)?;
                } else {
                    std::fs::remove_file(&path).map_err(map_io)?;
                }
            }
            Ok(())
        })
        .await
    }

    async fn rename(&self, from: &str, to: &str, replace: bool) -> Result<()> {
        let (src, dst) = (self.resolve(from)?, self.resolve(to)?);
        let (src2, dst2) = (src.clone(), dst.clone());
        blocking(move || {
            if std::fs::symlink_metadata(&src2).is_err() {
                return Err(BackendError::NotFound);
            }
            match std::fs::symlink_metadata(&dst2) {
                Ok(m) => {
                    if !replace {
                        return Err(BackendError::AlreadyExists);
                    }
                    if m.is_dir() {
                        return Err(BackendError::AccessDenied);
                    }
                }
                Err(_) => {
                    if dst2.parent().is_some_and(|p| !p.is_dir()) {
                        return Err(BackendError::PathNotFound);
                    }
                }
            }
            std::fs::rename(&src2, &dst2).map_err(map_io)
        })
        .await?;
        // Open handles under the renamed path follow it.
        for e in self.handles.lock().expect("handle table poisoned").values() {
            let mut p = e.path.lock().expect("path poisoned");
            if let Ok(tail) = p.strip_prefix(&src) {
                *p = dst.join(tail);
            }
        }
        Ok(())
    }

    async fn set_delete_on_close(&self, h: BackendHandle, on: bool) -> Result<()> {
        let e = self.entry(h)?;
        if on && e.file.is_none() {
            let path = e.path();
            let empty =
                blocking(move || Ok(std::fs::read_dir(&path).map_err(map_io)?.next().is_none()))
                    .await?;
            if !empty {
                return Err(BackendError::DirectoryNotEmpty);
            }
        }
        e.delete_on_close.store(on, Ordering::Relaxed);
        Ok(())
    }

    async fn truncate(&self, h: BackendHandle, new_len: u64) -> Result<()> {
        let e = self.entry(h)?;
        blocking(move || {
            let f = e.file.as_ref().ok_or(BackendError::IsADirectory)?;
            f.set_len(new_len).map_err(map_io)
        })
        .await
    }

    async fn set_times(&self, h: BackendHandle, times: SetTimes) -> Result<()> {
        let e = self.entry(h)?;
        blocking(move || {
            // Directories are best effort: std has no path-based setter and a directory
            // cannot be opened as a File on every platform.
            let Some(f) = e.file.as_ref() else {
                return Ok(());
            };
            let mut t = FileTimes::new();
            if let Some(a) = times.atime_unix_ns {
                t = t.set_accessed(from_unix_ns(a));
            }
            if let Some(m) = times.mtime_unix_ns {
                t = t.set_modified(from_unix_ns(m));
            }
            f.set_times(t).map_err(map_io)
        })
        .await
    }

    async fn list(&self, rel_dir: &str) -> Result<Vec<FileStat>> {
        let dir = self.resolve(rel_dir)?;
        let base = self.rel_of(&dir);
        blocking(move || {
            let mut out = Vec::new();
            for ent in std::fs::read_dir(&dir).map_err(map_io)? {
                let ent = ent.map_err(map_io)?;
                let name = ent.file_name().to_string_lossy().into_owned();
                let Ok(m) = ent.metadata() else { continue };
                if m.file_type().is_symlink() {
                    continue; // never exposed
                }
                let rel = if base.is_empty() {
                    name
                } else {
                    format!("{base}/{name}")
                };
                out.push(stat_of(rel, &m));
            }
            out.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(out)
        })
        .await
    }

    async fn stat(&self, rel_path: &str) -> Result<FileStat> {
        let path = self.resolve(rel_path)?;
        let rel = self.rel_of(&path);
        blocking(move || {
            let m = std::fs::symlink_metadata(&path).map_err(map_io)?;
            Ok(stat_of(rel, &m))
        })
        .await
    }

    async fn statfs(&self) -> Result<FsStats> {
        let cached = *self.used_cache.lock().expect("cache poisoned");
        if let Some((at, used)) = cached
            && at.elapsed() < USED_CACHE
        {
            return Ok(FsStats {
                quota_bytes: self.quota_bytes,
                used_bytes: used,
            });
        }
        let root = self.root.clone();
        let used = blocking(move || Ok(dir_size(&root))).await?;
        *self.used_cache.lock().expect("cache poisoned") = Some((Instant::now(), used));
        Ok(FsStats {
            quota_bytes: self.quota_bytes,
            used_bytes: used,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Tmp {
            let mut r = [0u8; 8];
            getrandom::fill(&mut r).unwrap();
            let name = format!("janus-local-{tag}-{}", u64::from_le_bytes(r));
            Tmp(std::env::temp_dir().join(name))
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn req(d: Disposition, kind: Kind) -> OpenRequest {
        OpenRequest {
            disposition: d,
            kind,
            write: true,
            delete_on_close: false,
        }
    }

    fn backend(tag: &str) -> (Tmp, LocalFsBackend) {
        let tmp = Tmp::new(tag);
        let b = LocalFsBackend::new(&tmp.0).unwrap();
        (tmp, b)
    }

    #[tokio::test]
    async fn create_write_read_roundtrip() {
        let (_t, b) = backend("rw");
        let o = b
            .open("a.txt", req(Disposition::Create, Kind::File))
            .await
            .unwrap();
        assert!(o.created && !o.stat.directory);
        b.write(o.handle, 0, b"hello world").await.unwrap();
        b.write(o.handle, 6, b"WORLD").await.unwrap();
        assert_eq!(b.read(o.handle, 0, 100).await.unwrap(), b"hello WORLD");
        assert_eq!(b.read(o.handle, 6, 3).await.unwrap(), b"WOR");
        assert!(b.read(o.handle, 11, 10).await.unwrap().is_empty());
        assert!(b.read(o.handle, 500, 10).await.unwrap().is_empty());
        b.flush(o.handle, true).await.unwrap();
        assert_eq!(b.stat_handle(o.handle).await.unwrap().size, 11);
        b.close(o.handle).await.unwrap();
        assert!(matches!(
            b.read(o.handle, 0, 1).await,
            Err(BackendError::BadHandle)
        ));
    }

    #[tokio::test]
    async fn dispositions() {
        let (_t, b) = backend("disp");
        let r = |d| req(d, Kind::File);
        assert!(matches!(
            b.open("f", r(Disposition::Open)).await,
            Err(BackendError::NotFound)
        ));
        assert!(matches!(
            b.open("f", r(Disposition::Overwrite)).await,
            Err(BackendError::NotFound)
        ));
        let o = b.open("f", r(Disposition::OpenOrCreate)).await.unwrap();
        assert!(o.created);
        b.write(o.handle, 0, b"data").await.unwrap();
        b.close(o.handle).await.unwrap();
        assert!(matches!(
            b.open("f", r(Disposition::Create)).await,
            Err(BackendError::AlreadyExists)
        ));
        let o = b.open("f", r(Disposition::Open)).await.unwrap();
        assert!(!o.created && !o.overwritten && o.stat.size == 4);
        b.close(o.handle).await.unwrap();
        let o = b
            .open("f", r(Disposition::OverwriteOrCreate))
            .await
            .unwrap();
        assert!(!o.created && o.overwritten && o.stat.size == 0);
        b.close(o.handle).await.unwrap();
        assert!(matches!(
            b.open("no/such/f", r(Disposition::Create)).await,
            Err(BackendError::PathNotFound)
        ));
    }

    #[tokio::test]
    async fn directories_and_listing() {
        let (_t, b) = backend("dir");
        let d = b
            .open("sub", req(Disposition::Create, Kind::Directory))
            .await
            .unwrap();
        assert!(d.created && d.stat.directory);
        b.close(d.handle).await.unwrap();
        for n in ["sub/b", "sub/a"] {
            let o = b
                .open(n, req(Disposition::Create, Kind::File))
                .await
                .unwrap();
            b.close(o.handle).await.unwrap();
        }
        let l = b.list("sub").await.unwrap();
        assert_eq!(
            l.iter().map(|s| s.rel_path.as_str()).collect::<Vec<_>>(),
            ["sub/a", "sub/b"]
        );
        assert_eq!(l[0].name, "a");
        assert_eq!(b.list("").await.unwrap().len(), 1);
        assert!(matches!(
            b.open("sub", req(Disposition::Open, Kind::File)).await,
            Err(BackendError::IsADirectory)
        ));
        assert!(matches!(
            b.open("sub/a", req(Disposition::Open, Kind::Directory))
                .await,
            Err(BackendError::NotADirectory)
        ));
        assert!(matches!(
            b.open("sub", req(Disposition::Overwrite, Kind::Any)).await,
            Err(BackendError::IsADirectory)
        ));
    }

    #[tokio::test]
    async fn delete_on_close_and_non_empty_dir() {
        let (_t, b) = backend("del");
        let o = b
            .open("sub", req(Disposition::Create, Kind::Directory))
            .await
            .unwrap();
        let f = b
            .open("sub/f", req(Disposition::Create, Kind::File))
            .await
            .unwrap();
        assert!(matches!(
            b.set_delete_on_close(o.handle, true).await,
            Err(BackendError::DirectoryNotEmpty)
        ));
        b.set_delete_on_close(f.handle, true).await.unwrap();
        b.close(f.handle).await.unwrap();
        assert!(matches!(b.stat("sub/f").await, Err(BackendError::NotFound)));
        b.set_delete_on_close(o.handle, true).await.unwrap();
        b.close(o.handle).await.unwrap();
        assert!(matches!(b.stat("sub").await, Err(BackendError::NotFound)));
    }

    #[tokio::test]
    async fn rename_replace_and_open_handles_follow() {
        let (_t, b) = backend("ren");
        let a = b
            .open("a", req(Disposition::Create, Kind::File))
            .await
            .unwrap();
        b.write(a.handle, 0, b"A").await.unwrap();
        let c = b
            .open("c", req(Disposition::Create, Kind::File))
            .await
            .unwrap();
        b.close(c.handle).await.unwrap();
        assert!(matches!(
            b.rename("a", "c", false).await,
            Err(BackendError::AlreadyExists)
        ));
        // Replacing an existing file while another handle is open fails on Windows.
        #[cfg(unix)]
        {
            b.rename("a", "c", true).await.unwrap();
            assert_eq!(b.stat_handle(a.handle).await.unwrap().rel_path, "c");
            assert_eq!(b.stat("c").await.unwrap().size, 1);
            assert!(matches!(b.stat("a").await, Err(BackendError::NotFound)));
        }
        b.close(a.handle).await.unwrap();
    }

    #[tokio::test]
    async fn truncate_and_times() {
        let (_t, b) = backend("tt");
        let o = b
            .open("f", req(Disposition::Create, Kind::File))
            .await
            .unwrap();
        b.write(o.handle, 0, b"0123456789").await.unwrap();
        b.truncate(o.handle, 4).await.unwrap();
        assert_eq!(b.read(o.handle, 0, 100).await.unwrap(), b"0123");
        b.truncate(o.handle, 8).await.unwrap();
        assert_eq!(b.stat_handle(o.handle).await.unwrap().size, 8);
        let t = 1_600_000_000_000_000_000i64;
        b.set_times(
            o.handle,
            SetTimes {
                atime_unix_ns: Some(t),
                mtime_unix_ns: Some(t + 1_000),
            },
        )
        .await
        .unwrap();
        let st = b.stat_handle(o.handle).await.unwrap();
        assert_eq!(st.mtime_unix_ns, t + 1_000);
        b.close(o.handle).await.unwrap();
    }

    #[tokio::test]
    async fn paths_cannot_escape_the_root() {
        let (_t, b) = backend("esc");
        for p in ["../x", "a/../../x", "a\\b"] {
            assert!(
                matches!(b.stat(p).await, Err(BackendError::AccessDenied)),
                "{p}"
            );
        }
        // ADS-style names are simply absent
        assert!(matches!(
            b.open("f:stream", req(Disposition::Open, Kind::File)).await,
            Err(BackendError::NotFound)
        ));
        #[cfg(unix)]
        {
            let outside = Tmp::new("outside");
            std::fs::create_dir_all(&outside.0).unwrap();
            std::os::unix::fs::symlink(&outside.0, b.root.join("link")).unwrap();
            assert!(matches!(
                b.stat("link/x").await,
                Err(BackendError::AccessDenied)
            ));
            assert!(b.list("").await.unwrap().is_empty(), "symlinks hidden");
        }
    }

    #[tokio::test]
    async fn statfs_counts_used_bytes() {
        let (_t, b) = backend("fs");
        let b = b.with_quota(1000);
        let o = b
            .open("f", req(Disposition::Create, Kind::File))
            .await
            .unwrap();
        b.write(o.handle, 0, &[1u8; 300]).await.unwrap();
        let s = b.statfs().await.unwrap();
        assert_eq!((s.quota_bytes, s.used_bytes), (1000, 300));
    }
}
