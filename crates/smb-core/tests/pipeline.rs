//! Pipelined READ/WRITE: several backend calls of one connection in flight at once, with
//! the ordering rules that keep it safe. Real TCP, a `LocalFsBackend` made slow on purpose.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use janus_lib::control::DaemonState;
use janus_lib::credentials::CredentialStore;
use janus_lib::vfs::{
    BackendError, BackendHandle, FileStat, FsStats, LocalFsBackend, OpenRequest, Opened, Result,
    SetTimes, StorageBackend,
};
use smb_core::server::{DevServer, ServerConfig};
use smb_core::transport::{read_message, write_message};
use smb_wire::Command;
use smb_wire::create::disposition;
use smb_wire::testclient::{
    Client, Response, close_body, create_body_ex, create_reply_file_id, flush_body, read_body,
    read_reply_data, tree_connect_body, write_body,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

const USER: &str = "janus";
const PASSWORD: &str = "pipeline-test-password";
const RW: u32 = 0x0013_019F;
const OPT_FILE: u32 = 0x40;
const DELAY: Duration = Duration::from_millis(300);
const CHUNK: usize = 65536;

/// A local backend whose reads and writes take `DELAY`; the Nth write (1-based) can be made to
/// fail. Counts how many data calls run at the same time.
struct Slow {
    inner: LocalFsBackend,
    fail_write: u32,
    writes: AtomicU32,
    running: AtomicU32,
    max_running: AtomicU32,
}

impl Slow {
    async fn delayed(&self) {
        let now = self.running.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_running.fetch_max(now, Ordering::SeqCst);
        tokio::time::sleep(DELAY).await;
        self.running.fetch_sub(1, Ordering::SeqCst);
    }
}

impl StorageBackend for Slow {
    async fn open(&self, p: &str, r: OpenRequest) -> Result<Opened> {
        self.inner.open(p, r).await
    }
    async fn stat_handle(&self, h: BackendHandle) -> Result<FileStat> {
        self.inner.stat_handle(h).await
    }
    async fn read(&self, h: BackendHandle, o: u64, l: u32) -> Result<Vec<u8>> {
        self.delayed().await;
        self.inner.read(h, o, l).await
    }
    async fn write(&self, h: BackendHandle, o: u64, d: &[u8]) -> Result<()> {
        self.delayed().await;
        let n = self.writes.fetch_add(1, Ordering::SeqCst) + 1;
        if n == self.fail_write {
            return Err(BackendError::Io(std::io::Error::other("injected")));
        }
        self.inner.write(h, o, d).await
    }
    async fn flush(&self, h: BackendHandle, f: bool) -> Result<()> {
        self.inner.flush(h, f).await
    }
    async fn close(&self, h: BackendHandle) -> Result<()> {
        self.inner.close(h).await
    }
    async fn rename(&self, a: &str, b: &str, replace: bool) -> Result<()> {
        self.inner.rename(a, b, replace).await
    }
    async fn set_delete_on_close(&self, h: BackendHandle, on: bool) -> Result<()> {
        self.inner.set_delete_on_close(h, on).await
    }
    async fn truncate(&self, h: BackendHandle, n: u64) -> Result<()> {
        self.inner.truncate(h, n).await
    }
    async fn set_times(&self, h: BackendHandle, t: SetTimes) -> Result<()> {
        self.inner.set_times(h, t).await
    }
    async fn list(&self, d: &str) -> Result<Vec<FileStat>> {
        self.inner.list(d).await
    }
    async fn stat(&self, p: &str) -> Result<FileStat> {
        self.inner.stat(p).await
    }
    async fn statfs(&self) -> Result<FsStats> {
        self.inner.statfs().await
    }
}

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Rig {
    s: TcpStream,
    c: Client,
    tid: u32,
    backend: Arc<Slow>,
    root: Scratch,
}

async fn rig(fail_write: u32) -> Rig {
    let mut r = [0u8; 8];
    getrandom::fill(&mut r).unwrap();
    let dir = std::env::temp_dir().join(format!("janus-pipe-{}", u64::from_le_bytes(r)));
    let backend = Arc::new(Slow {
        inner: LocalFsBackend::new(&dir).unwrap(),
        fail_write,
        writes: AtomicU32::new(0),
        running: AtomicU32::new(0),
        max_running: AtomicU32::new(0),
    });
    let creds = Arc::new(CredentialStore::load(
        Some(USER.into()),
        Some(PASSWORD.into()),
        None,
    ));
    let server = Arc::new(DevServer::new(
        ServerConfig::default(),
        Arc::new(Mutex::new(DaemonState::default())),
        creds,
        Arc::clone(&backend),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { server.serve(listener).await });

    let mut s = TcpStream::connect(addr).await.unwrap();
    let mut c = Client::new(USER, PASSWORD);
    async fn raw(s: &mut TcpStream, req: &[u8]) -> Vec<u8> {
        write_message(s, req).await.unwrap();
        read_message(s).await.unwrap().expect("connection closed")
    }
    let r = raw(&mut s, &c.negotiate_request()).await;
    c.on_negotiate_response(&r);
    let r1 = raw(&mut s, &c.session_setup_1()).await;
    let req2 = c.session_setup_2(&r1).unwrap();
    assert_eq!(
        Response::parse(&raw(&mut s, &req2).await).unwrap().status(),
        0
    );
    let tc = raw(
        &mut s,
        &c.signed_request(
            Command::TreeConnect,
            0,
            &tree_connect_body("\\\\127.0.0.1\\backup"),
        ),
    )
    .await;
    let tc = Response::parse(&tc).unwrap();
    assert_eq!(tc.status(), 0);
    let tid = tc.header().tree_id;
    Rig {
        s,
        c,
        tid,
        backend,
        root: Scratch(dir),
    }
}

impl Rig {
    async fn call(&mut self, cmd: Command, body: &[u8]) -> Response {
        let req = self.c.signed_request(cmd, self.tid, body);
        write_message(&mut self.s, &req).await.unwrap();
        let r = read_message(&mut self.s).await.unwrap().unwrap();
        assert!(self.c.verify_response(&r));
        Response::parse(&r).unwrap()
    }

    async fn create(&mut self, path: &str) -> [u8; 16] {
        let r = self
            .call(
                Command::Create,
                &create_body_ex(path, RW, 0x80, disposition::CREATE, OPT_FILE, true),
            )
            .await;
        assert_eq!(r.status(), 0);
        create_reply_file_id(&r.message.body)
    }

    /// Send requests back to back without waiting for any reply.
    async fn send_all(&mut self, reqs: Vec<(Command, Vec<u8>)>) {
        for (cmd, body) in reqs {
            let req = self.c.signed_request(cmd, self.tid, &body);
            write_message(&mut self.s, &req).await.unwrap();
        }
    }

    async fn recv(&mut self) -> Response {
        let r = read_message(&mut self.s).await.unwrap().unwrap();
        assert!(self.c.verify_response(&r), "reply signature");
        Response::parse(&r).unwrap()
    }
}

fn chunk(i: usize) -> Vec<u8> {
    vec![i as u8 + 1; CHUNK]
}

#[tokio::test]
async fn writes_of_one_connection_run_concurrently() {
    let mut t = rig(0).await;
    let fid = t.create("f").await;
    let n = 6;
    let started = Instant::now();
    let reqs = (0..n)
        .map(|i| {
            (
                Command::Write,
                write_body(fid, (i * CHUNK) as u64, &chunk(i), 0),
            )
        })
        .collect();
    t.send_all(reqs).await;
    let mut ids = Vec::new();
    for _ in 0..n {
        let r = t.recv().await;
        assert_eq!(r.status(), 0);
        ids.push(r.header().message_id);
    }
    let took = started.elapsed();
    // serial would be n * DELAY (1.8 s); allow generous slack on a loaded machine
    assert!(took < DELAY * 4, "writes were serialized: {took:?}");
    assert!(t.backend.max_running.load(Ordering::SeqCst) >= 3);
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), n, "one reply per request");
    // the data is all there
    let on_disk = std::fs::read(t.root.0.join("f")).unwrap();
    let want: Vec<u8> = (0..n).flat_map(chunk).collect();
    assert_eq!(on_disk, want);
}

#[tokio::test]
async fn close_and_flush_wait_for_writes_in_flight() {
    let mut t = rig(0).await;
    let fid = t.create("f").await;
    let n = 4;
    let mut reqs: Vec<_> = (0..n)
        .map(|i| {
            (
                Command::Write,
                write_body(fid, (i * CHUNK) as u64, &chunk(i), 0),
            )
        })
        .collect();
    reqs.push((Command::Flush, flush_body(fid, true)));
    reqs.push((Command::Close, close_body(fid)));
    t.send_all(reqs).await;
    // the replies to the writes come first, then FLUSH, then CLOSE: a barrier, in order
    let mut cmds = Vec::new();
    for _ in 0..n + 2 {
        let r = t.recv().await;
        assert_eq!(r.status(), 0);
        cmds.push(r.header().command);
    }
    assert!(cmds[..n].iter().all(|c| *c == Command::Write), "{cmds:?}");
    assert_eq!(cmds[n], Command::Flush);
    assert_eq!(cmds[n + 1], Command::Close);
    assert_eq!(
        std::fs::metadata(t.root.0.join("f")).unwrap().len(),
        (n * CHUNK) as u64
    );
}

#[tokio::test]
async fn a_failed_write_fails_only_its_own_reply() {
    let mut t = rig(2).await; // the second write that reaches the backend fails
    let fid = t.create("f").await;
    let n = 4;
    let reqs = (0..n)
        .map(|i| {
            (
                Command::Write,
                write_body(fid, (i * CHUNK) as u64, &chunk(i), 0),
            )
        })
        .collect();
    t.send_all(reqs).await;
    let mut failed = 0;
    for _ in 0..n {
        if t.recv().await.status() != 0 {
            failed += 1;
        }
    }
    assert_eq!(failed, 1);
    // the connection is still usable
    let r = t.call(Command::Flush, &flush_body(fid, true)).await;
    assert_eq!(r.status(), 0);
}

#[tokio::test]
async fn reads_run_concurrently_and_return_their_own_ranges() {
    let mut t = rig(0).await;
    let fid = t.create("f").await;
    let n = 6;
    let data: Vec<u8> = (0..n).flat_map(chunk).collect();
    std::fs::write(t.root.0.join("f"), &data).unwrap();
    let started = Instant::now();
    let reqs = (0..n)
        .map(|i| {
            (
                Command::Read,
                read_body(fid, CHUNK as u32, (i * CHUNK) as u64),
            )
        })
        .collect();
    t.send_all(reqs).await;
    let mut got = vec![Vec::new(); n];
    for _ in 0..n {
        let r = t.recv().await;
        assert_eq!(r.status(), 0);
        let d = read_reply_data(&r.message.body);
        // each range holds a distinct byte value: it identifies the request it answers
        let i = usize::from(d[0]) - 1;
        got[i] = d;
    }
    assert!(started.elapsed() < DELAY * 4, "reads were serialized");
    assert_eq!(got.concat(), data);
}

#[tokio::test]
async fn sequential_reads_are_prefetched_and_stay_correct() {
    let mut t = rig(0).await;
    let fid = t.create("f").await;
    let n = 8;
    let data: Vec<u8> = (0..n).flat_map(chunk).collect();
    std::fs::write(t.root.0.join("f"), &data).unwrap();
    let started = Instant::now();
    let mut got = Vec::new();
    for i in 0..n {
        let r = t
            .call(
                Command::Read,
                &read_body(fid, CHUNK as u32, (i * CHUNK) as u64),
            )
            .await;
        assert_eq!(r.status(), 0, "read {i}");
        got.extend(read_reply_data(&r.message.body));
    }
    assert_eq!(got, data);
    // one at a time would be n * DELAY (2.4 s)
    assert!(
        started.elapsed() < DELAY * 5,
        "no readahead: {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn a_write_discards_prefetched_data() {
    let mut t = rig(0).await;
    let fid = t.create("f").await;
    let data: Vec<u8> = (0..6).flat_map(chunk).collect();
    std::fs::write(t.root.0.join("f"), &data).unwrap();
    let r = t
        .call(Command::Read, &read_body(fid, CHUNK as u32, 0))
        .await;
    assert_eq!(r.status(), 0);
    // chunk 1 is being prefetched now; overwrite it, then read it
    let new = vec![0xEE; CHUNK];
    let w = t
        .call(Command::Write, &write_body(fid, CHUNK as u64, &new, 0))
        .await;
    assert_eq!(w.status(), 0);
    let r = t
        .call(Command::Read, &read_body(fid, CHUNK as u32, CHUNK as u64))
        .await;
    assert_eq!(
        read_reply_data(&r.message.body),
        new,
        "stale prefetch served"
    );
}
