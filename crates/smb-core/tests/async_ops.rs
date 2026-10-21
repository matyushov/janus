//! Interim STATUS_PENDING for operations that wait for the backend (FLUSH, CLOSE, SET_INFO),
//! CANCEL, the wait ceiling, and the ordering of what arrives meanwhile. Real TCP, a local
//! backend whose FLUSH is held on a semaphore.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use janus_lib::control::DaemonState;
use janus_lib::credentials::CredentialStore;
use janus_lib::vfs::{
    BackendHandle, FileStat, FsStats, LocalFsBackend, OpenRequest, Opened, Result, SetTimes,
    StorageBackend,
};
use smb_core::conn::AsyncConfig;
use smb_core::server::{DevServer, ServerConfig};
use smb_core::transport::{read_message, write_message};
use smb_wire::Command;
use smb_wire::create::disposition;
use smb_wire::header::flags;
use smb_wire::testclient::{
    Client, Response, close_body, create_body_ex, create_reply_file_id, flush_body, frame,
    request_header, sign_frame, simple_body, tree_connect_body,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore};

const USER: &str = "janus";
const PASSWORD: &str = "async-test-password";
const RW: u32 = 0x0013_019F;
const OPT_FILE: u32 = 0x40;
const PENDING: u32 = 0x103;
const CANCELLED: u32 = 0xC000_0120;
const NETWORK_ERROR: u32 = 0xC000_00C4;
const INTERIM: Duration = Duration::from_millis(150);

/// FLUSH and CLOSE of a file wait for a permit (`gate`); everything else is the local backend.
struct Gated {
    inner: LocalFsBackend,
    gate: Semaphore,
    flushes_done: AtomicU32,
    closes_done: AtomicU32,
}

impl StorageBackend for Gated {
    async fn open(&self, p: &str, r: OpenRequest) -> Result<Opened> {
        self.inner.open(p, r).await
    }
    async fn stat_handle(&self, h: BackendHandle) -> Result<FileStat> {
        self.inner.stat_handle(h).await
    }
    async fn read(&self, h: BackendHandle, o: u64, l: u32) -> Result<Vec<u8>> {
        self.inner.read(h, o, l).await
    }
    async fn write(&self, h: BackendHandle, o: u64, d: &[u8]) -> Result<()> {
        self.inner.write(h, o, d).await
    }
    async fn flush(&self, h: BackendHandle, f: bool) -> Result<()> {
        self.gate.acquire().await.unwrap().forget();
        self.inner.flush(h, f).await?;
        self.flushes_done.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn close(&self, h: BackendHandle) -> Result<()> {
        self.gate.acquire().await.unwrap().forget();
        self.inner.close(h).await?;
        self.closes_done.fetch_add(1, Ordering::SeqCst);
        Ok(())
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
    backend: Arc<Gated>,
    _root: Scratch,
}

async fn rig(max_wait: Duration) -> Rig {
    let mut r = [0u8; 8];
    getrandom::fill(&mut r).unwrap();
    let dir = std::env::temp_dir().join(format!("janus-async-{}", u64::from_le_bytes(r)));
    let backend = Arc::new(Gated {
        inner: LocalFsBackend::new(&dir).unwrap(),
        gate: Semaphore::new(0),
        flushes_done: AtomicU32::new(0),
        closes_done: AtomicU32::new(0),
    });
    let creds = Arc::new(CredentialStore::load(
        Some(USER.into()),
        Some(PASSWORD.into()),
        None,
    ));
    let server = Arc::new(
        DevServer::new(
            ServerConfig::default(),
            Arc::new(Mutex::new(DaemonState::default())),
            creds,
            Arc::clone(&backend),
        )
        .with_async_config(AsyncConfig {
            interim_after: INTERIM,
            max_wait,
            ..AsyncConfig::default()
        }),
    );
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
        _root: Scratch(dir),
    }
}

impl Rig {
    async fn send(&mut self, cmd: Command, body: &[u8]) -> u64 {
        let req = self.c.signed_request(cmd, self.tid, body);
        let mid = u64::from_le_bytes(req[24..32].try_into().unwrap());
        write_message(&mut self.s, &req).await.unwrap();
        mid
    }

    /// The next packet; checks the signature unless it is an unsigned interim response.
    async fn recv(&mut self) -> (Response, Vec<u8>) {
        let r = tokio::time::timeout(Duration::from_secs(5), read_message(&mut self.s))
            .await
            .expect("reply in time")
            .unwrap()
            .expect("connection open");
        let p = Response::parse(&r).unwrap();
        if p.status() != PENDING {
            assert!(self.c.verify_response(&r), "reply signature");
        }
        (p, r)
    }

    async fn no_packet_within(&mut self, d: Duration) {
        assert!(
            tokio::time::timeout(d, read_message(&mut self.s))
                .await
                .is_err(),
            "unexpected packet"
        );
    }

    async fn create(&mut self, path: &str) -> [u8; 16] {
        let mid = self
            .send(
                Command::Create,
                &create_body_ex(path, RW, 0x80, disposition::CREATE, OPT_FILE, true),
            )
            .await;
        let (r, _) = self.recv().await;
        assert_eq!((r.status(), r.header().message_id), (0, mid));
        create_reply_file_id(&r.message.body)
    }

    /// CANCEL for a request: by AsyncId when given, else by MessageId. Never answered.
    async fn cancel(&mut self, message_id: u64, async_id: Option<u64>) {
        let mut h = request_header(Command::Cancel, message_id, self.c.session_id, self.tid);
        h.credit_req_grant = 0;
        if let Some(a) = async_id {
            h.flags |= flags::ASYNC_COMMAND;
            h.async_id = a;
            h.tree_id = 0;
        }
        let mut f = frame(&h, &[4, 0, 0, 0]);
        sign_frame(&mut f, &self.c.signing_key.unwrap());
        write_message(&mut self.s, &f).await.unwrap();
    }
}

fn is_async(r: &Response) -> bool {
    r.header().flags & flags::ASYNC_COMMAND != 0
}

#[tokio::test]
async fn slow_flush_gets_an_interim_response_then_the_final_one() {
    let mut t = rig(Duration::from_secs(60)).await;
    let fid = t.create("f").await;
    let mid = t.send(Command::Flush, &flush_body(fid, false)).await;

    let (interim, raw) = t.recv().await;
    let h = interim.header();
    assert_eq!(h.status, PENDING);
    assert_eq!((h.message_id, h.command), (mid, Command::Flush));
    assert!(is_async(&interim) && h.async_id != 0);
    assert_eq!(
        h.flags & flags::SIGNED,
        0,
        "interim responses are not signed"
    );
    assert!(
        h.credit_req_grant >= 1,
        "credits ride on the interim response"
    );
    assert_eq!(raw.len(), 64 + 8, "empty error body");
    let async_id = h.async_id;

    t.no_packet_within(Duration::from_millis(200)).await;
    t.backend.gate.add_permits(1);
    let (done, _) = t.recv().await;
    let h = done.header();
    assert_eq!(
        (done.status(), h.message_id, h.async_id),
        (0, mid, async_id)
    );
    assert!(is_async(&done));
    assert_eq!(h.credit_req_grant, 0, "final async response grants nothing");
    assert_ne!(h.flags & flags::SIGNED, 0, "the final response is signed");
    assert_eq!(t.backend.flushes_done.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn quick_flush_is_answered_synchronously() {
    let mut t = rig(Duration::from_secs(60)).await;
    let fid = t.create("f").await;
    t.backend.gate.add_permits(1);
    let mid = t.send(Command::Flush, &flush_body(fid, false)).await;
    let (r, _) = t.recv().await;
    assert_eq!((r.status(), r.header().message_id), (0, mid));
    assert!(!is_async(&r), "no interim response, no async header");
    assert!(r.header().credit_req_grant >= 1);
    t.no_packet_within(Duration::from_millis(300)).await;
}

#[tokio::test]
async fn echo_and_unrelated_io_are_served_while_an_operation_waits_and_the_rest_queues() {
    let mut t = rig(Duration::from_secs(60)).await;
    let a = t.create("a").await;
    let b = t.create("b").await;
    let flush_mid = t.send(Command::Flush, &flush_body(a, false)).await;
    let (interim, _) = t.recv().await;
    assert_eq!(interim.status(), PENDING);

    // ECHO and a READ of another file are answered at once.
    let echo = t.send(Command::Echo, &simple_body()).await;
    let (r, _) = t.recv().await;
    assert_eq!((r.status(), r.header().message_id), (0, echo));
    let read = t
        .send(Command::Read, &smb_wire::testclient::read_body(b, 10, 0))
        .await;
    let (r, _) = t.recv().await;
    assert_eq!(r.header().message_id, read, "READ passes the pending FLUSH");

    // A CREATE queues behind the pending operation and runs after it, in order.
    let create = t
        .send(
            Command::Create,
            &create_body_ex("c", RW, 0x80, disposition::CREATE, OPT_FILE, true),
        )
        .await;
    t.no_packet_within(Duration::from_millis(300)).await;
    t.backend.gate.add_permits(1);
    let (r1, _) = t.recv().await;
    assert_eq!(r1.header().message_id, flush_mid);
    let (r2, _) = t.recv().await;
    assert_eq!((r2.status(), r2.header().message_id), (0, create));
}

#[tokio::test]
async fn cancel_by_async_id_ends_the_wait_but_not_the_backend_call() {
    let mut t = rig(Duration::from_secs(60)).await;
    let fid = t.create("f").await;
    let mid = t.send(Command::Flush, &flush_body(fid, false)).await;
    let (interim, _) = t.recv().await;
    let async_id = interim.header().async_id;

    t.cancel(mid + 1, Some(async_id)).await;
    let (r, _) = t.recv().await;
    assert_eq!((r.status(), r.header().message_id), (CANCELLED, mid));
    assert!(is_async(&r));
    t.no_packet_within(Duration::from_millis(200)).await; // CANCEL itself is never answered

    // The flush was not abandoned: released later, it completes.
    assert_eq!(t.backend.flushes_done.load(Ordering::SeqCst), 0);
    t.backend.gate.add_permits(1);
    for _ in 0..50 {
        if t.backend.flushes_done.load(Ordering::SeqCst) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(t.backend.flushes_done.load(Ordering::SeqCst), 1);

    // The connection is healthy afterwards.
    let echo = t.send(Command::Echo, &simple_body()).await;
    let (r, _) = t.recv().await;
    assert_eq!((r.status(), r.header().message_id), (0, echo));
}

#[tokio::test]
async fn cancel_by_message_id_works_before_the_interim_response() {
    let mut t = rig(Duration::from_secs(60)).await;
    let fid = t.create("f").await;
    let mid = t.send(Command::Flush, &flush_body(fid, false)).await;
    t.cancel(mid, None).await;
    let (r, _) = t.recv().await;
    assert_eq!((r.status(), r.header().message_id), (CANCELLED, mid));
    assert!(
        !is_async(&r),
        "no interim was sent, so the reply is synchronous"
    );
}

#[tokio::test]
async fn cancel_of_something_unknown_is_ignored() {
    let mut t = rig(Duration::from_secs(60)).await;
    t.cancel(999, None).await;
    t.cancel(1, Some(77)).await;
    let echo = t.send(Command::Echo, &simple_body()).await;
    let (r, _) = t.recv().await;
    assert_eq!((r.status(), r.header().message_id), (0, echo));
}

#[tokio::test]
async fn the_wait_ceiling_ends_with_an_error_and_the_call_still_finishes() {
    let mut t = rig(Duration::from_millis(500)).await;
    let fid = t.create("f").await;
    let mid = t.send(Command::Flush, &flush_body(fid, false)).await;
    let (interim, _) = t.recv().await;
    assert_eq!(interim.status(), PENDING);
    let (r, _) = t.recv().await;
    assert_eq!((r.status(), r.header().message_id), (NETWORK_ERROR, mid));
    t.backend.gate.add_permits(1);
    for _ in 0..50 {
        if t.backend.flushes_done.load(Ordering::SeqCst) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(t.backend.flushes_done.load(Ordering::SeqCst), 1);
    let echo = t.send(Command::Echo, &simple_body()).await;
    assert_eq!(t.recv().await.0.header().message_id, echo);
}

#[tokio::test]
async fn slow_close_is_asynchronous_and_the_handle_is_gone_at_once() {
    let mut t = rig(Duration::from_secs(60)).await;
    let fid = t.create("f").await;
    let mid = t.send(Command::Close, &close_body(fid)).await;
    let (interim, _) = t.recv().await;
    assert_eq!(
        (interim.status(), interim.header().message_id),
        (PENDING, mid)
    );
    t.backend.gate.add_permits(1);
    let (r, _) = t.recv().await;
    assert_eq!((r.status(), r.header().message_id), (0, mid));
    assert_eq!(t.backend.closes_done.load(Ordering::SeqCst), 1);
    // closing again: the open is gone
    t.backend.gate.add_permits(1);
    t.send(Command::Close, &close_body(fid)).await;
    assert_eq!(t.recv().await.0.status(), 0xC000_0128);
}
