//! `GrpcBackend` with the write-ahead journal against a real receiver: what the journal
//! promises (acknowledge locally, read-your-writes, ordering of data and metadata, honest
//! fsync, backpressure, crash recovery) and what it must not (hide a dead receiver).
//!
//! The receiver sits behind a small TCP proxy that can freeze or cut the link; the uploader
//! can additionally be paused, which makes "the receiver does not have it yet" reproducible
//! while metadata operations still work.

#![cfg(feature = "backend-grpc")]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use janus_lib::grpc_backend::{GrpcBackend, JournalSettings};
use janus_lib::remote::{RemoteClient, RemoteConfig, Timeouts};
use janus_lib::vfs::{BackendError, BackendHandle, Disposition, Kind, OpenRequest, StorageBackend};
use janus_receiverd::testkit::TestServer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const MS: fn(u64) -> Duration = Duration::from_millis;
const MIB: usize = 1 << 20;

/// Forwards bytes to the receiver; `freeze` stalls them, `cut` kills every connection and
/// refuses new ones until `restore`.
struct Proxy {
    addr: SocketAddr,
    frozen: Arc<AtomicBool>,
    cut: Arc<AtomicBool>,
    conns: Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl Proxy {
    async fn start(upstream: SocketAddr) -> Proxy {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p = Proxy {
            addr: l.local_addr().unwrap(),
            frozen: Arc::default(),
            cut: Arc::default(),
            conns: Arc::default(),
        };
        let (frozen, cut, conns) = (p.frozen.clone(), p.cut.clone(), p.conns.clone());
        tokio::spawn(async move {
            loop {
                let Ok((down, _)) = l.accept().await else {
                    return;
                };
                if cut.load(Ordering::SeqCst) {
                    drop(down);
                    continue;
                }
                let Ok(up) = TcpStream::connect(upstream).await else {
                    continue;
                };
                let (frozen, conns2) = (frozen.clone(), conns.clone());
                let h = tokio::spawn(async move {
                    let (mut dr, mut dw) = down.into_split();
                    let (mut ur, mut uw) = up.into_split();
                    // one task, so that aborting it closes both sockets
                    tokio::select! {
                        _ = pipe(&mut dr, &mut uw, &frozen) => {}
                        _ = pipe(&mut ur, &mut dw, &frozen) => {}
                    }
                });
                conns2.lock().unwrap().push(h);
            }
        });
        p
    }

    fn freeze(&self) {
        self.frozen.store(true, Ordering::SeqCst);
    }
    fn thaw(&self) {
        self.frozen.store(false, Ordering::SeqCst);
    }
    fn cut(&self) {
        self.cut.store(true, Ordering::SeqCst);
        for h in self.conns.lock().unwrap().drain(..) {
            h.abort();
        }
    }
    fn restore(&self) {
        self.cut.store(false, Ordering::SeqCst);
    }
}

async fn pipe(
    r: &mut (impl AsyncReadExt + Unpin),
    w: &mut (impl AsyncWriteExt + Unpin),
    frozen: &AtomicBool,
) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        while frozen.load(Ordering::SeqCst) {
            tokio::time::sleep(MS(10)).await;
        }
        match r.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                while frozen.load(Ordering::SeqCst) {
                    tokio::time::sleep(MS(10)).await;
                }
                if w.write_all(&buf[..n]).await.is_err() {
                    return;
                }
            }
        }
    }
}

fn timeouts() -> Timeouts {
    Timeouts {
        connect: MS(300),
        request: MS(500),
        bulk_request: MS(800),
        degraded_probe: MS(200),
        fail_fast: MS(100),
        budget: MS(1500),
        barrier: MS(1500),
        keepalive_interval: MS(200),
        keepalive_timeout: MS(300),
    }
}

struct Rig {
    srv: TestServer,
    proxy: Proxy,
    dir: PathBuf,
    backend: GrpcBackend,
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn tmp_journal_dir(tag: &str) -> PathBuf {
    let mut r = [0u8; 4];
    getrandom::fill(&mut r).unwrap();
    std::env::temp_dir().join(format!(
        "janus-jb-{tag}-{}-{}",
        std::process::id(),
        u32::from_le_bytes(r)
    ))
}

fn backend_for(addr: SocketAddr, dir: &std::path::Path, max_backlog: u64) -> GrpcBackend {
    let remote = RemoteClient::connect_lazy(&RemoteConfig {
        endpoint: addr.to_string(),
        timeouts: timeouts(),
        ..Default::default()
    })
    .unwrap();
    GrpcBackend::from_remote(&remote, 0)
        .with_journal(
            dir,
            JournalSettings {
                max_backlog,
                local_journal: false,
            },
        )
        .unwrap()
}

async fn rig_with(tag: &str, quota: u64, max_backlog: u64) -> Rig {
    let srv = TestServer::start(tag, quota).await.unwrap();
    let proxy = Proxy::start(srv.addr).await;
    let dir = tmp_journal_dir(tag);
    let backend = backend_for(proxy.addr, &dir, max_backlog);
    Rig {
        srv,
        proxy,
        dir,
        backend,
    }
}

async fn rig(tag: &str) -> Rig {
    rig_with(tag, 0, 64 << 20).await
}

impl Rig {
    fn pause(&self, on: bool) {
        self.backend
            .journal_runtime()
            .unwrap()
            .uploader
            .set_paused(on);
    }
    fn backlog(&self) -> u64 {
        self.backend.journal_runtime().unwrap().journal.live_bytes()
    }
    async fn drain(&self) {
        let (ok, left) = self
            .backend
            .journal_runtime()
            .unwrap()
            .drain(Duration::from_secs(10))
            .await;
        assert!(ok, "drain left {left} bytes");
    }
    async fn create(&self, path: &str) -> BackendHandle {
        self.backend
            .open(path, req(Disposition::Create))
            .await
            .unwrap()
            .handle
    }
    fn on_receiver(&self, path: &str) -> Option<Vec<u8>> {
        self.srv
            .store
            .exists(path)
            .then(|| self.srv.store.read_file(path).unwrap())
    }
}

fn req(d: Disposition) -> OpenRequest {
    OpenRequest {
        disposition: d,
        kind: Kind::File,
        write: true,
        delete_on_close: false,
    }
}

fn pattern(n: usize, salt: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i.wrapping_mul(31) % 251) as u8 ^ salt)
        .collect()
}

#[tokio::test]
async fn writes_are_acknowledged_without_the_receiver_and_visible_at_once() {
    let r = rig("ryw").await;
    let h = r.create("f").await;
    r.pause(true);
    r.proxy.freeze();

    let data = pattern(3 * MIB + 5, 1);
    let t = Instant::now();
    r.backend.write(h, 0, &data).await.unwrap();
    assert!(
        t.elapsed() < MS(300),
        "acknowledged locally: {:?}",
        t.elapsed()
    );
    assert_eq!(r.backlog(), data.len() as u64);

    // read-your-writes, a window crossing the end, and stat / list sizes
    assert_eq!(r.backend.read(h, 0, data.len() as u32).await.unwrap(), data);
    assert_eq!(r.backend.read(h, 100, 50).await.unwrap(), &data[100..150]);
    assert_eq!(
        r.backend.read(h, data.len() as u64 - 3, 3).await.unwrap(),
        &data[data.len() - 3..]
    );
    assert_eq!(
        r.backend.stat_handle(h).await.unwrap().size,
        data.len() as u64
    );
    // metadata is synchronous: a frozen receiver is an error, not a guess
    assert!(r.backend.statfs().await.is_err());
    r.proxy.thaw();
    tokio::time::sleep(MS(400)).await; // the degraded-peer window of the link
    // with the link back but the upload still held, sizes include the journal
    assert_eq!(r.backend.stat("f").await.unwrap().size, data.len() as u64);
    let listed = r.backend.list("").await.unwrap();
    assert_eq!(listed[0].size, data.len() as u64);
    // a window that crosses the end needs the receiver to say the file ends there
    assert_eq!(
        r.backend.read(h, data.len() as u64 - 3, 100).await.unwrap(),
        &data[data.len() - 3..]
    );
    assert_eq!(
        r.backend.statfs().await.unwrap().used_bytes,
        data.len() as u64
    );
    r.pause(false);
    r.drain().await;
    assert_eq!(r.on_receiver("f").unwrap(), data);
    assert_eq!(r.backlog(), 0);
    // after the upload the answers are the same
    assert_eq!(r.backend.stat("f").await.unwrap().size, data.len() as u64);
    assert_eq!(r.backend.read(h, 0, data.len() as u32).await.unwrap(), data);
    assert_eq!(
        r.backend.statfs().await.unwrap().used_bytes,
        data.len() as u64
    );
}

#[tokio::test]
async fn sparse_writes_merge_with_the_receiver_data_and_zero_gaps() {
    let r = rig("sparse").await;
    let h = r.create("f").await;
    // 100 bytes are on the receiver already
    r.backend.write(h, 0, &[7; 100]).await.unwrap();
    r.backend.flush(h, true).await.unwrap();
    assert_eq!(r.backlog(), 0);
    r.pause(true);
    r.backend.write(h, 50, &[8; 10]).await.unwrap(); // overwrite inside
    r.backend.write(h, 300, &[9; 10]).await.unwrap(); // past the end: a gap
    let got = r.backend.read(h, 0, 1000).await.unwrap();
    assert_eq!(got.len(), 310);
    assert_eq!(&got[..50], &[7; 50][..]);
    assert_eq!(&got[50..60], &[8; 10][..]);
    assert_eq!(&got[60..100], &[7; 40][..]);
    assert!(got[100..300].iter().all(|b| *b == 0));
    assert_eq!(&got[300..], &[9; 10][..]);
    assert_eq!(r.backend.stat("f").await.unwrap().size, 310);
    // a window that starts in the gap
    assert_eq!(r.backend.read(h, 200, 4).await.unwrap(), vec![0; 4]);
    r.pause(false);
    r.drain().await;
    assert_eq!(r.on_receiver("f").unwrap(), got);
}

#[tokio::test]
async fn overwrite_before_upload_is_later_wins() {
    let r = rig("laterwins").await;
    let h = r.create("f").await;
    r.pause(true);
    r.backend.write(h, 0, &[1; 4096]).await.unwrap();
    r.backend.write(h, 1000, &[2; 1000]).await.unwrap();
    r.backend.write(h, 1500, &[3; 100]).await.unwrap();
    assert_eq!(r.backlog(), 4096, "overlaps collapse in the index");
    r.pause(false);
    r.drain().await;
    let got = r.on_receiver("f").unwrap();
    assert_eq!(got.len(), 4096);
    assert_eq!(&got[..1000], &[1; 1000][..]);
    assert_eq!(&got[1000..1500], &[2; 500][..]);
    assert_eq!(&got[1500..1600], &[3; 100][..]);
    assert_eq!(&got[1600..2000], &[2; 400][..]);
    assert_eq!(&got[2000..], &[1; 2096][..]);
}

#[tokio::test]
async fn truncate_to_zero_discards_unuploaded_data_for_good() {
    let r = rig("trunc0").await;
    let h = r.create("f").await;
    r.pause(true);
    r.backend.write(h, 0, &[5; 10_000]).await.unwrap();
    r.backend.truncate(h, 0).await.unwrap();
    assert_eq!(r.backlog(), 0);
    assert_eq!(r.backend.stat("f").await.unwrap().size, 0);
    assert!(r.backend.read(h, 0, 100).await.unwrap().is_empty());
    r.backend.write(h, 0, b"new").await.unwrap();
    r.pause(false);
    r.drain().await;
    assert_eq!(r.on_receiver("f").unwrap(), b"new");
}

#[tokio::test]
async fn truncate_to_a_length_and_rename_wait_for_the_data_first() {
    let r = rig("order").await;
    let h = r.create("f").await;
    r.pause(true);
    let data = pattern(10_000, 3);
    r.backend.write(h, 0, &data).await.unwrap();

    // the metadata operation does not complete before the data is on the receiver
    let rename = r.backend.rename("f", "g", false);
    tokio::pin!(rename);
    assert!(
        tokio::time::timeout(MS(300), &mut rename).await.is_err(),
        "rename must wait for the upload"
    );
    r.pause(false);
    // (the timed-out future was only polled, not cancelled: it resumes)
    rename.await.unwrap();
    assert_eq!(r.on_receiver("g").unwrap(), data);
    assert!(!r.srv.store.exists("f"));
    // the open handle follows the rename and reads/writes under the new name
    assert_eq!(r.backend.read(h, 0, 4).await.unwrap(), &data[..4]);

    r.pause(true);
    r.backend.write(h, 10_000, &[1; 500]).await.unwrap();
    let t = r.backend.truncate(h, 9_000);
    tokio::pin!(t);
    assert!(tokio::time::timeout(MS(300), &mut t).await.is_err());
    r.pause(false);
    t.await.unwrap();
    r.drain().await;
    assert_eq!(r.on_receiver("g").unwrap(), &data[..9_000]);
    assert_eq!(r.backend.stat("g").await.unwrap().size, 9_000);
}

#[tokio::test]
async fn delete_and_replacing_rename_discard_unuploaded_data() {
    let r = rig("delete").await;
    let a = r.create("a").await;
    let b = r.create("b").await;
    r.pause(true);
    r.backend.write(a, 0, &[1; 5000]).await.unwrap();
    r.backend.write(b, 0, &[2; 5000]).await.unwrap();
    // delete-on-close drops a's dirty bytes without uploading them
    r.backend.set_delete_on_close(a, true).await.unwrap();
    r.backend.close(a).await.unwrap();
    assert!(!r.srv.store.exists("a"));
    assert_eq!(r.backlog(), 5000);
    // renaming `c` over `b` discards b's bytes, c's data goes first
    let c = r.create("c").await;
    r.backend.write(c, 0, &[3; 100]).await.unwrap();
    r.pause(false);
    r.backend.rename("c", "b", true).await.unwrap();
    r.drain().await;
    assert_eq!(r.on_receiver("b").unwrap(), vec![3; 100]);
    assert!(!r.srv.store.exists("a"));
    assert!(!r.srv.store.exists("c"));
    r.backend.close(b).await.unwrap();
}

#[tokio::test]
async fn fsync_with_an_unreachable_receiver_is_an_error_not_a_false_success() {
    let r = rig("fsyncdead").await;
    let h = r.create("f").await;
    r.backend.write(h, 0, b"safe").await.unwrap();
    r.backend.flush(h, true).await.unwrap();

    r.proxy.freeze();
    r.backend.write(h, 4, &[1; 1000]).await.unwrap(); // acknowledged locally
    let t = Instant::now();
    let e = r.backend.flush(h, true).await.unwrap_err();
    assert!(matches!(e, BackendError::RemoteUnavailable), "{e:?}");
    assert!(
        t.elapsed() < MS(4000),
        "bounded by the budget: {:?}",
        t.elapsed()
    );
    assert_eq!(r.backlog(), 1000, "the data is still safe locally");
    // a close with dirty data is a barrier as well
    let e = r.backend.close(h).await.unwrap_err();
    assert!(matches!(e, BackendError::RemoteUnavailable), "{e:?}");

    // the link comes back: the gateway recovers by itself and delivers everything
    r.proxy.thaw();
    r.drain().await;
    assert_eq!(r.on_receiver("f").unwrap().len(), 1004);
}

#[tokio::test]
async fn close_of_a_dirty_file_waits_for_the_receiver() {
    let r = rig("closewait").await;
    let h = r.create("f").await;
    r.pause(true);
    r.backend.write(h, 0, &[4; 20_000]).await.unwrap();
    let close = r.backend.close(h);
    tokio::pin!(close);
    assert!(tokio::time::timeout(MS(300), &mut close).await.is_err());
    assert!(r.on_receiver("f").unwrap().is_empty());
    r.pause(false);
    close.await.unwrap();
    assert_eq!(r.on_receiver("f").unwrap(), vec![4; 20_000]);
}

#[tokio::test]
async fn a_full_backlog_is_backpressure_then_a_network_error_never_disk_full() {
    let r = rig_with("backlog", 0, MIB as u64).await;
    let h = r.create("f").await;
    r.pause(true);
    r.backend.write(h, 0, &vec![1; MIB]).await.unwrap(); // exactly fills the limit
    let t = Instant::now();
    let e = r
        .backend
        .write(h, MIB as u64, &[2; 1000])
        .await
        .unwrap_err();
    assert!(matches!(e, BackendError::RemoteUnavailable), "{e:?}");
    assert!(t.elapsed() < MS(4000), "does not hang: {:?}", t.elapsed());
    assert!(t.elapsed() >= MS(1000), "waited for room first");
    // reads still work, nothing was lost
    assert_eq!(r.backend.read(h, 0, 4).await.unwrap(), vec![1; 4]);
    // a waiting writer is let through as soon as the uploader makes room
    let w = r.backend.write(h, MIB as u64, &[2; 1000]);
    tokio::pin!(w);
    assert!(tokio::time::timeout(MS(200), &mut w).await.is_err());
    r.pause(false);
    w.await.unwrap();
    r.drain().await;
    assert_eq!(r.on_receiver("f").unwrap().len(), MIB + 1000);
}

#[tokio::test]
async fn a_write_that_cannot_fit_the_receiver_quota_gets_disk_full_at_once() {
    // quota 1 MiB on the receiver
    let r = rig_with("quota", MIB as u64, 64 << 20).await;
    let h = r.create("f").await;
    r.pause(true);
    // Time Machine asks for the volume size all the time; that fills the quota cache
    r.backend.statfs().await.unwrap();
    r.backend.write(h, 0, &vec![1; 600 * 1024]).await.unwrap();
    let t = Instant::now();
    let e = r
        .backend
        .write(h, 600 * 1024, &vec![1; 600 * 1024])
        .await
        .unwrap_err();
    assert!(matches!(e, BackendError::NoSpace), "{e:?}");
    assert!(t.elapsed() < MS(300), "immediately, not at fsync");
    // smaller writes still fit
    r.backend.write(h, 600 * 1024, &[1; 1000]).await.unwrap();
    r.pause(false);
    r.drain().await;
}

#[tokio::test]
async fn confirmed_writes_survive_a_crash_and_a_torn_tail_is_dropped() {
    let srv = TestServer::start("crash", 0).await.unwrap();
    let dir = tmp_journal_dir("crash");
    let data = pattern(2 * MIB + 77, 9);
    {
        let b = backend_for(srv.addr, &dir, 64 << 20);
        let h = b.open("f", req(Disposition::Create)).await.unwrap().handle;
        b.journal_runtime().unwrap().uploader.set_paused(true);
        b.write(h, 0, &data).await.unwrap();
        b.write(h, 50, &[0xAB; 20]).await.unwrap(); // part of the same file, later
        // "kill -9": nothing is drained, the journal stays as it is
    }
    // a torn record at the end of the last segment (the process died mid-append)
    let mut segs: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "wal"))
        .collect();
    segs.sort();
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(segs.last().unwrap())
            .unwrap();
        f.write_all(&[0xFF; 20]).unwrap();
    }
    let b = backend_for(srv.addr, &dir, 64 << 20);
    let (ok, left) = b
        .journal_runtime()
        .unwrap()
        .drain(Duration::from_secs(10))
        .await;
    assert!(ok, "left {left}");
    let mut expect = data.clone();
    expect[50..70].copy_from_slice(&[0xAB; 20]);
    assert_eq!(
        srv.store.read_file("f").unwrap(),
        expect,
        "no holes, no stale bytes"
    );
    // and the journal is empty now: another restart uploads nothing
    drop(b);
    let b = backend_for(srv.addr, &dir, 64 << 20);
    assert_eq!(b.journal_runtime().unwrap().journal.live_bytes(), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn a_deleted_file_is_not_resurrected_by_a_restart() {
    let srv = TestServer::start("resurrect", 0).await.unwrap();
    let dir = tmp_journal_dir("resurrect");
    {
        let b = backend_for(srv.addr, &dir, 64 << 20);
        let f = b.open("f", req(Disposition::Create)).await.unwrap().handle;
        b.write(f, 0, &[1; 1000]).await.unwrap();
        b.flush(f, true).await.unwrap();
        b.set_delete_on_close(f, true).await.unwrap();
        b.close(f).await.unwrap();
        assert!(!srv.store.exists("f"));
    }
    let b = backend_for(srv.addr, &dir, 64 << 20);
    let (ok, _) = b
        .journal_runtime()
        .unwrap()
        .drain(Duration::from_secs(10))
        .await;
    assert!(ok);
    assert!(
        !srv.store.exists("f"),
        "the replay must not recreate a deleted file"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn the_gateway_recovers_after_the_link_was_cut_without_a_restart() {
    let r = rig("linkcut").await;
    let h = r.create("f").await;
    r.proxy.cut();
    let data = pattern(MIB, 2);
    r.backend.write(h, 0, &data).await.unwrap(); // still acknowledged
    tokio::time::sleep(MS(500)).await;
    assert!(r.on_receiver("f").unwrap().is_empty());
    r.proxy.restore();
    r.drain().await;
    assert_eq!(r.on_receiver("f").unwrap(), data);
}

#[tokio::test]
async fn small_files_round_trip() {
    let r = rig("small").await;
    for i in 0..20 {
        let h = r.create(&format!("s{i}")).await;
        r.backend.write(h, 0, &vec![i as u8; 4096]).await.unwrap();
        r.backend.close(h).await.unwrap();
    }
    for i in 0..20 {
        assert_eq!(
            r.on_receiver(&format!("s{i}")).unwrap(),
            vec![i as u8; 4096]
        );
    }
    assert_eq!(r.backlog(), 0);
}
