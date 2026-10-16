//! One set of `StorageBackend` assertions, run against `LocalFsBackend` (the reference) and
//! against `GrpcBackend` talking to a real `janus-receiverd` on an ephemeral loopback port.
//!
//! The expectations come from the trait documentation and from the behaviour of the local
//! reference backend. A scenario that fails for one backend is either a bug there or a
//! documented difference (see the README of `janus-lib`); it is never adjusted to whatever
//! the implementation happens to do.

#![cfg(all(feature = "backend-local", feature = "backend-grpc"))]

use std::any::Any;
use std::path::{Path, PathBuf};

use janus_lib::grpc_backend::{GrpcBackend, JournalSettings};
use janus_lib::remote::{RemoteClient, RemoteConfig};
use janus_lib::vfs::{
    BackendError, Disposition, Kind, LocalFsBackend, OpenRequest, SetTimes, StorageBackend,
};
use janus_receiverd::testkit::TestServer;

const MIB: usize = 1 << 20;

struct Env {
    root: PathBuf,
    _guard: Box<dyn Any>,
}

struct LocalDir(PathBuf);
impl Drop for LocalDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn make_local() -> (LocalFsBackend, Env) {
    let mut r = [0u8; 8];
    getrandom::fill(&mut r).unwrap();
    let root = std::env::temp_dir().join(format!("janus-contract-{}", u64::from_le_bytes(r)));
    let b = LocalFsBackend::new(&root).unwrap();
    (
        b,
        Env {
            root: root.clone(),
            _guard: Box::new(LocalDir(root)),
        },
    )
}

async fn make_grpc() -> (GrpcBackend, Env) {
    let srv = TestServer::start("contract", 0).await.expect("receiver up");
    let remote = RemoteClient::connect_lazy(&RemoteConfig {
        endpoint: srv.addr.to_string(),
        ..Default::default()
    })
    .unwrap();
    let b = GrpcBackend::from_remote(&remote, 0);
    let root = srv.store.path().to_path_buf();
    (
        b,
        Env {
            root,
            _guard: Box::new(srv),
        },
    )
}

/// The journal mode: writes are acknowledged from the local journal and uploaded in the
/// background. The assertions are the same as for the other two backends.
async fn make_grpc_journal() -> (GrpcBackend, Env) {
    let srv = TestServer::start("contract-j", 0)
        .await
        .expect("receiver up");
    let remote = RemoteClient::connect_lazy(&RemoteConfig {
        endpoint: srv.addr.to_string(),
        ..Default::default()
    })
    .unwrap();
    let mut r = [0u8; 8];
    getrandom::fill(&mut r).unwrap();
    let jdir = std::env::temp_dir().join(format!("janus-contract-wal-{}", u64::from_le_bytes(r)));
    let b = GrpcBackend::from_remote(&remote, 0)
        .with_journal(
            &jdir,
            JournalSettings {
                max_backlog: 64 << 20,
                local_journal: false,
            },
        )
        .unwrap();
    let root = srv.store.path().to_path_buf();
    (
        b,
        Env {
            root,
            _guard: Box::new((srv, LocalDir(jdir))),
        },
    )
}

fn req(d: Disposition, kind: Kind) -> OpenRequest {
    OpenRequest {
        disposition: d,
        kind,
        write: true,
        delete_on_close: false,
    }
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i.wrapping_mul(31) % 251) as u8).collect()
}

// ---------------------------------------------------------------------------------------
// Scenarios: `async fn name<B: StorageBackend>(b: B, root: &Path)`.
// ---------------------------------------------------------------------------------------

async fn create_write_read_roundtrip<B: StorageBackend>(b: B, _root: &Path) {
    let o = b
        .open("a.txt", req(Disposition::Create, Kind::File))
        .await
        .unwrap();
    assert!(o.created && !o.stat.directory);
    assert_eq!(o.stat.name, "a.txt");
    assert_eq!(o.stat.rel_path, "a.txt");
    b.write(o.handle, 0, b"hello world").await.unwrap();
    b.write(o.handle, 6, b"WORLD").await.unwrap();
    assert_eq!(b.read(o.handle, 0, 100).await.unwrap(), b"hello WORLD");
    assert_eq!(b.read(o.handle, 6, 3).await.unwrap(), b"WOR");
    assert!(b.read(o.handle, 11, 10).await.unwrap().is_empty());
    assert!(b.read(o.handle, 500, 10).await.unwrap().is_empty());
    b.flush(o.handle, true).await.unwrap();
    b.flush(o.handle, false).await.unwrap();
    assert_eq!(b.stat_handle(o.handle).await.unwrap().size, 11);
    b.close(o.handle).await.unwrap();
    assert!(matches!(
        b.read(o.handle, 0, 1).await,
        Err(BackendError::BadHandle)
    ));
    assert!(matches!(
        b.write(o.handle, 0, b"x").await,
        Err(BackendError::BadHandle)
    ));
    assert!(matches!(
        b.stat_handle(o.handle).await,
        Err(BackendError::BadHandle)
    ));
    assert!(matches!(
        b.close(o.handle).await,
        Err(BackendError::BadHandle)
    ));
    // the data survived the close
    let o = b
        .open("a.txt", req(Disposition::Open, Kind::File))
        .await
        .unwrap();
    assert_eq!(b.read(o.handle, 0, 100).await.unwrap(), b"hello WORLD");
    b.close(o.handle).await.unwrap();
}

async fn dispositions<B: StorageBackend>(b: B, _root: &Path) {
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
    let o = b.open("g", r(Disposition::Supersede)).await.unwrap();
    assert!(o.created);
    b.write(o.handle, 0, b"zz").await.unwrap();
    b.close(o.handle).await.unwrap();
    let o = b.open("g", r(Disposition::Supersede)).await.unwrap();
    assert!(!o.created && o.overwritten && o.stat.size == 0);
    b.close(o.handle).await.unwrap();
    assert!(matches!(
        b.open("no/such/f", r(Disposition::Create)).await,
        Err(BackendError::PathNotFound)
    ));
    assert!(matches!(
        b.open("no/such/f", r(Disposition::Open)).await,
        Err(BackendError::NotFound)
    ));
}

async fn directories_and_listing<B: StorageBackend>(b: B, _root: &Path) {
    let d = b
        .open("sub", req(Disposition::Create, Kind::Directory))
        .await
        .unwrap();
    assert!(d.created && d.stat.directory);
    assert_eq!(d.stat.size, 0);
    b.close(d.handle).await.unwrap();
    for n in ["sub/b", "sub/a"] {
        let o = b
            .open(n, req(Disposition::Create, Kind::File))
            .await
            .unwrap();
        b.write(o.handle, 0, b"123").await.unwrap();
        b.close(o.handle).await.unwrap();
    }
    let l = b.list("sub").await.unwrap();
    assert_eq!(
        l.iter().map(|s| s.rel_path.as_str()).collect::<Vec<_>>(),
        ["sub/a", "sub/b"]
    );
    assert_eq!(l[0].name, "a");
    assert_eq!(l[0].size, 3);
    assert!(!l[0].directory);
    let top = b.list("").await.unwrap();
    assert_eq!(top.len(), 1);
    assert!(top[0].directory && top[0].name == "sub");
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
    assert!(matches!(
        b.open("sub", req(Disposition::Create, Kind::Directory))
            .await,
        Err(BackendError::AlreadyExists)
    ));
    let again = b
        .open("sub", req(Disposition::OpenOrCreate, Kind::Directory))
        .await
        .unwrap();
    assert!(!again.created);
    b.close(again.handle).await.unwrap();
    assert!(matches!(b.list("nope").await, Err(BackendError::NotFound)));
    // directory handles: data operations are refused
    let d = b
        .open("sub", req(Disposition::Open, Kind::Directory))
        .await
        .unwrap();
    assert!(matches!(
        b.read(d.handle, 0, 1).await,
        Err(BackendError::IsADirectory)
    ));
    assert!(matches!(
        b.write(d.handle, 0, b"x").await,
        Err(BackendError::IsADirectory)
    ));
    assert!(matches!(
        b.truncate(d.handle, 0).await,
        Err(BackendError::IsADirectory)
    ));
    b.flush(d.handle, false).await.unwrap();
    b.close(d.handle).await.unwrap();
}

async fn root_is_a_directory<B: StorageBackend>(b: B, _root: &Path) {
    let s = b.stat("").await.unwrap();
    assert!(s.directory && s.name.is_empty() && s.rel_path.is_empty());
    let o = b
        .open("", req(Disposition::Open, Kind::Directory))
        .await
        .unwrap();
    assert!(o.stat.directory);
    b.close(o.handle).await.unwrap();
    assert!(matches!(
        b.open("", req(Disposition::Open, Kind::File)).await,
        Err(BackendError::IsADirectory)
    ));
    assert!(matches!(
        b.open("", req(Disposition::Create, Kind::Directory)).await,
        Err(BackendError::AlreadyExists)
    ));
    assert!(b.list("/").await.unwrap().is_empty());
}

async fn delete_on_close_and_non_empty_dir<B: StorageBackend>(b: B, _root: &Path) {
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

async fn delete_on_close_can_be_withdrawn<B: StorageBackend>(b: B, _root: &Path) {
    let f = b
        .open("keep", req(Disposition::Create, Kind::File))
        .await
        .unwrap();
    b.set_delete_on_close(f.handle, true).await.unwrap();
    b.set_delete_on_close(f.handle, false).await.unwrap();
    b.close(f.handle).await.unwrap();
    assert!(b.stat("keep").await.is_ok());
    // requested at open time
    let f = b
        .open(
            "gone",
            OpenRequest {
                delete_on_close: true,
                ..req(Disposition::Create, Kind::File)
            },
        )
        .await
        .unwrap();
    b.close(f.handle).await.unwrap();
    assert!(matches!(b.stat("gone").await, Err(BackendError::NotFound)));
}

async fn rename_with_and_without_replace<B: StorageBackend>(b: B, _root: &Path) {
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
    assert!(matches!(
        b.rename("nope", "z", false).await,
        Err(BackendError::NotFound)
    ));
    assert!(matches!(
        b.rename("a", "no/dir/z", false).await,
        Err(BackendError::PathNotFound)
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
    // a plain rename, no handles open
    #[cfg(unix)]
    let from = "c";
    #[cfg(not(unix))]
    let from = "a";
    b.rename(from, "d", false).await.unwrap();
    assert!(b.stat("d").await.is_ok());
    // a directory is never a replace target
    let dir = b
        .open("dir", req(Disposition::Create, Kind::Directory))
        .await
        .unwrap();
    b.close(dir.handle).await.unwrap();
    assert!(matches!(
        b.rename("d", "dir", true).await,
        Err(BackendError::AccessDenied)
    ));
}

#[cfg(unix)]
async fn open_handles_follow_a_renamed_directory<B: StorageBackend>(b: B, _root: &Path) {
    let d = b
        .open("d", req(Disposition::Create, Kind::Directory))
        .await
        .unwrap();
    b.close(d.handle).await.unwrap();
    let f = b
        .open("d/f", req(Disposition::Create, Kind::File))
        .await
        .unwrap();
    b.write(f.handle, 0, b"payload").await.unwrap();
    // a sibling whose name merely starts with the same prefix must not move
    let sib = b
        .open("dd", req(Disposition::Create, Kind::File))
        .await
        .unwrap();
    b.rename("d", "e", false).await.unwrap();
    assert_eq!(b.stat_handle(f.handle).await.unwrap().rel_path, "e/f");
    assert_eq!(b.stat_handle(sib.handle).await.unwrap().rel_path, "dd");
    assert_eq!(b.read(f.handle, 0, 100).await.unwrap(), b"payload");
    b.close(f.handle).await.unwrap();
    b.close(sib.handle).await.unwrap();
}

async fn truncate_and_times<B: StorageBackend>(b: B, _root: &Path) {
    let o = b
        .open("f", req(Disposition::Create, Kind::File))
        .await
        .unwrap();
    b.write(o.handle, 0, b"0123456789").await.unwrap();
    b.truncate(o.handle, 4).await.unwrap();
    assert_eq!(b.read(o.handle, 0, 100).await.unwrap(), b"0123");
    b.truncate(o.handle, 8).await.unwrap();
    assert_eq!(b.stat_handle(o.handle).await.unwrap().size, 8);
    assert_eq!(
        b.read(o.handle, 0, 100).await.unwrap(),
        b"0123\0\0\0\0",
        "extension is zero-filled"
    );
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
    // only mtime: the other stays
    b.set_times(
        o.handle,
        SetTimes {
            atime_unix_ns: None,
            mtime_unix_ns: Some(t + 9_000),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        b.stat_handle(o.handle).await.unwrap().mtime_unix_ns,
        t + 9_000
    );
    b.close(o.handle).await.unwrap();
    // directories: accepted (best effort)
    let d = b
        .open("d", req(Disposition::Create, Kind::Directory))
        .await
        .unwrap();
    b.set_times(
        d.handle,
        SetTimes {
            atime_unix_ns: None,
            mtime_unix_ns: Some(t),
        },
    )
    .await
    .unwrap();
    b.close(d.handle).await.unwrap();
}

async fn paths_cannot_escape_the_root<B: StorageBackend>(b: B, root: &Path) {
    for p in ["../x", "a/../../x", "a\\b", "./x", ".."] {
        assert!(
            matches!(b.stat(p).await, Err(BackendError::AccessDenied)),
            "stat {p}"
        );
        assert!(
            matches!(
                b.open(p, req(Disposition::OpenOrCreate, Kind::File)).await,
                Err(BackendError::AccessDenied)
            ),
            "open {p}"
        );
        assert!(
            matches!(b.list(p).await, Err(BackendError::AccessDenied)),
            "list {p}"
        );
    }
    assert!(matches!(
        b.rename("a", "../b", true).await,
        Err(BackendError::AccessDenied)
    ));
    // ADS-style names are simply absent
    assert!(matches!(
        b.open("f:stream", req(Disposition::Open, Kind::File)).await,
        Err(BackendError::NotFound)
    ));
    assert!(matches!(
        b.open("f:stream", req(Disposition::Create, Kind::File))
            .await,
        Err(BackendError::NotFound)
    ));
    assert!(
        !root.parent().unwrap().join("x").exists(),
        "nothing created outside the root"
    );
    #[cfg(unix)]
    {
        let outside = root.parent().unwrap().join(format!(
            "janus-outside-{}",
            root.file_name().unwrap().to_string_lossy()
        ));
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret"), b"s").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        assert!(matches!(
            b.stat("link/secret").await,
            Err(BackendError::AccessDenied)
        ));
        assert!(matches!(
            b.open("link/secret", req(Disposition::Open, Kind::File))
                .await,
            Err(BackendError::AccessDenied)
        ));
        assert!(b.list("").await.unwrap().is_empty(), "symlinks hidden");
        let _ = std::fs::remove_dir_all(&outside);
    }
}

async fn odd_but_legal_names<B: StorageBackend>(b: B, _root: &Path) {
    for n in [
        "файл с пробелами ü.txt",
        "a b",
        "x.y.z",
        "-dash",
        "~tilde",
        "UPPER",
    ] {
        let o = b
            .open(n, req(Disposition::Create, Kind::File))
            .await
            .unwrap_or_else(|e| panic!("{n}: {e:?}"));
        b.write(o.handle, 0, n.as_bytes()).await.unwrap();
        b.close(o.handle).await.unwrap();
        assert_eq!(b.stat(n).await.unwrap().name, n);
    }
    assert_eq!(b.list("").await.unwrap().len(), 6);
}

async fn statfs_counts_used_bytes<B: StorageBackend>(b: B, _root: &Path) {
    let o = b
        .open("f", req(Disposition::Create, Kind::File))
        .await
        .unwrap();
    b.write(o.handle, 0, &[1u8; 300]).await.unwrap();
    let s = b.statfs().await.unwrap();
    assert_eq!(s.used_bytes, 300);
    assert!(s.quota_bytes >= 300, "a volume size must be reported");
}

async fn large_io_crosses_the_1mib_chunk_limit<B: StorageBackend>(b: B, _root: &Path) {
    let data = pattern(3 * MIB + 17);
    let o = b
        .open("big", req(Disposition::Create, Kind::File))
        .await
        .unwrap();
    b.write(o.handle, 0, &data).await.unwrap();
    assert_eq!(
        b.stat_handle(o.handle).await.unwrap().size,
        data.len() as u64
    );
    let back = b.read(o.handle, 0, data.len() as u32).await.unwrap();
    assert!(back == data, "whole-file read differs");
    // a read that straddles a chunk boundary
    let off = MIB - 5;
    assert_eq!(
        b.read(o.handle, off as u64, 10).await.unwrap(),
        &data[off..off + 10]
    );
    // a read longer than the file is short, not an error
    let tail = b.read(o.handle, (3 * MIB) as u64, 1000).await.unwrap();
    assert_eq!(tail, &data[3 * MIB..]);
    // an overwrite that straddles chunks
    let patch = vec![0xEEu8; 2 * MIB + 3];
    b.write(o.handle, (MIB / 2) as u64, &patch).await.unwrap();
    let mut expect = data.clone();
    expect[MIB / 2..MIB / 2 + patch.len()].copy_from_slice(&patch);
    let back = b.read(o.handle, 0, expect.len() as u32).await.unwrap();
    assert!(back == expect, "patched file differs");
    b.flush(o.handle, true).await.unwrap();
    b.close(o.handle).await.unwrap();
}

async fn writes_past_the_end_leave_a_zero_hole<B: StorageBackend>(b: B, _root: &Path) {
    let o = b
        .open("sparse", req(Disposition::Create, Kind::File))
        .await
        .unwrap();
    b.write(o.handle, (2 * MIB) as u64, b"tail").await.unwrap();
    assert_eq!(
        b.stat_handle(o.handle).await.unwrap().size,
        (2 * MIB + 4) as u64
    );
    assert_eq!(b.read(o.handle, 0, 16).await.unwrap(), vec![0u8; 16]);
    assert_eq!(
        b.read(o.handle, (2 * MIB) as u64, 16).await.unwrap(),
        b"tail"
    );
    b.close(o.handle).await.unwrap();
}

async fn range_arithmetic_never_panics_or_wraps<B: StorageBackend>(b: B, _root: &Path) {
    let o = b
        .open("edge", req(Disposition::Create, Kind::File))
        .await
        .unwrap();
    b.write(o.handle, 0, b"abc").await.unwrap();
    // empty write and empty read are no-ops
    b.write(o.handle, 0, &[]).await.unwrap();
    b.write(o.handle, u64::MAX, &[]).await.unwrap();
    assert!(b.read(o.handle, 0, 0).await.unwrap().is_empty());
    // offset + len beyond u64: an error, and the file is untouched (no wrap-around to 0)
    assert!(b.write(o.handle, u64::MAX - 2, b"12345").await.is_err());
    assert_eq!(b.read(o.handle, 0, 10).await.unwrap(), b"abc");
    // reading there is short (or an error), never a wrap-around read of the file start
    if let Ok(v) = b.read(o.handle, u64::MAX - 2, 10).await {
        assert!(v.len() <= 2);
    }
    assert!(b.truncate(o.handle, 3).await.is_ok());
    b.close(o.handle).await.unwrap();
}

async fn two_handles_see_each_others_writes<B: StorageBackend>(b: B, _root: &Path) {
    let w = b
        .open("shared", req(Disposition::Create, Kind::File))
        .await
        .unwrap();
    let r = b
        .open(
            "shared",
            OpenRequest {
                write: false,
                ..req(Disposition::Open, Kind::File)
            },
        )
        .await
        .unwrap();
    b.write(w.handle, 0, b"visible").await.unwrap();
    assert_eq!(b.read(r.handle, 0, 100).await.unwrap(), b"visible");
    assert!(
        b.write(r.handle, 0, b"nope").await.is_err(),
        "a read-only handle cannot write"
    );
    b.close(w.handle).await.unwrap();
    b.close(r.handle).await.unwrap();
}

async fn overwrite_truncates_existing_content<B: StorageBackend>(b: B, _root: &Path) {
    let o = b
        .open("f", req(Disposition::Create, Kind::File))
        .await
        .unwrap();
    b.write(o.handle, 0, &pattern(5000)).await.unwrap();
    b.close(o.handle).await.unwrap();
    let o = b
        .open("f", req(Disposition::Overwrite, Kind::File))
        .await
        .unwrap();
    assert!(o.overwritten && o.stat.size == 0);
    b.write(o.handle, 0, b"new").await.unwrap();
    assert_eq!(b.read(o.handle, 0, 100).await.unwrap(), b"new");
    b.close(o.handle).await.unwrap();
}

async fn opening_below_a_regular_file<B: StorageBackend>(b: B, _root: &Path) {
    let o = b
        .open("file", req(Disposition::Create, Kind::File))
        .await
        .unwrap();
    b.close(o.handle).await.unwrap();
    let r = b
        .open("file/child", req(Disposition::Create, Kind::File))
        .await;
    assert!(r.is_err());
    #[cfg(unix)]
    assert!(matches!(r, Err(BackendError::NotADirectory)));
}

macro_rules! scenarios {
    ($($(#[$m:meta])* $name:ident),* $(,)?) => {
        mod local {
            $(
                $(#[$m])*
                #[tokio::test]
                async fn $name() {
                    let (b, env) = super::make_local().await;
                    super::$name(b, &env.root).await;
                }
            )*
        }
        mod grpc_journal {
            $(
                $(#[$m])*
                #[tokio::test]
                async fn $name() {
                    let (b, env) = super::make_grpc_journal().await;
                    super::$name(b, &env.root).await;
                }
            )*
        }
        mod grpc {
            $(
                $(#[$m])*
                #[tokio::test]
                async fn $name() {
                    let (b, env) = super::make_grpc().await;
                    super::$name(b, &env.root).await;
                }
            )*
        }
    };
}

scenarios!(
    create_write_read_roundtrip,
    dispositions,
    directories_and_listing,
    root_is_a_directory,
    delete_on_close_and_non_empty_dir,
    delete_on_close_can_be_withdrawn,
    rename_with_and_without_replace,
    truncate_and_times,
    paths_cannot_escape_the_root,
    odd_but_legal_names,
    statfs_counts_used_bytes,
    large_io_crosses_the_1mib_chunk_limit,
    writes_past_the_end_leave_a_zero_hole,
    range_arithmetic_never_panics_or_wraps,
    two_handles_see_each_others_writes,
    overwrite_truncates_existing_content,
    opening_below_a_regular_file,
    #[cfg(unix)]
    open_handles_follow_a_renamed_directory,
);
