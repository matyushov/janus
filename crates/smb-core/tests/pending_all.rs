//! J4.1: every command that may wait for the backend (CREATE, QUERY_INFO, QUERY_DIRECTORY, READ,
//! alone or in a compound chain) gets an interim STATUS_PENDING and a final async reply, can be
//! cancelled, ends at the wait ceiling, and at `drop_after` makes the server drop the TCP
//! connection. Real TCP, a local backend whose open/stat/list/read are held on a semaphore.
//! The thresholds come from docs/macos-smb-client-timeouts.md.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
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
use smb_wire::create::{FILE_ID_RELATED, disposition};
use smb_wire::header::flags;
use smb_wire::testclient::{
    Client, Response, close_body, create_body_ex, create_reply_file_id, frame,
    query_directory_body, query_info_body, read_body, read_reply_data, request_header, sign_frame,
    simple_body, tree_connect_body, write_body,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore};

const USER: &str = "janus";
const PASSWORD: &str = "pending-all-test-password";
const RW: u32 = 0x0013_019F;
const OPT_FILE: u32 = 0x40;
const OPT_DIR: u32 = 0x01;
const PENDING: u32 = 0x103;
const CANCELLED: u32 = 0xC000_0120;
const NETWORK_ERROR: u32 = 0xC000_00C4;
const INTERIM: Duration = Duration::from_millis(150);

/// While `hold` is set, open / stat_handle / list / read wait for a permit of `gate`.
struct Gated {
    inner: LocalFsBackend,
    hold: AtomicBool,
    /// `open` is never held (to make a later command of a chain the slow one).
    open_free: AtomicBool,
    gate: Semaphore,
    entered: AtomicU32,
    finished: AtomicU32,
}

impl Gated {
    async fn pass(&self) {
        if self.hold.load(Ordering::SeqCst) {
            self.entered.fetch_add(1, Ordering::SeqCst);
            self.gate.acquire().await.unwrap().forget();
            self.finished.fetch_add(1, Ordering::SeqCst);
        }
    }
}

impl StorageBackend for Gated {
    async fn open(&self, p: &str, r: OpenRequest) -> Result<Opened> {
        if !self.open_free.load(Ordering::SeqCst) {
            self.pass().await;
        }
        self.inner.open(p, r).await
    }
    async fn stat_handle(&self, h: BackendHandle) -> Result<FileStat> {
        self.pass().await;
        self.inner.stat_handle(h).await
    }
    async fn read(&self, h: BackendHandle, o: u64, l: u32) -> Result<Vec<u8>> {
        self.pass().await;
        self.inner.read(h, o, l).await
    }
    async fn write(&self, h: BackendHandle, o: u64, d: &[u8]) -> Result<()> {
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
        self.pass().await;
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
    addr: std::net::SocketAddr,
    backend: Arc<Gated>,
    _root: Scratch,
}

async fn raw(s: &mut TcpStream, req: &[u8]) -> Vec<u8> {
    write_message(s, req).await.unwrap();
    read_message(s).await.unwrap().expect("connection closed")
}

async fn login(addr: std::net::SocketAddr) -> (TcpStream, Client, u32) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    let mut c = Client::new(USER, PASSWORD);
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
    (s, c, tc.header().tree_id)
}

async fn rig(max_wait: Duration, drop_after: Duration) -> Rig {
    let mut r = [0u8; 8];
    getrandom::fill(&mut r).unwrap();
    let dir = std::env::temp_dir().join(format!("janus-pending-{}", u64::from_le_bytes(r)));
    let backend = Arc::new(Gated {
        inner: LocalFsBackend::new(&dir).unwrap(),
        hold: AtomicBool::new(false),
        open_free: AtomicBool::new(false),
        gate: Semaphore::new(0),
        entered: AtomicU32::new(0),
        finished: AtomicU32::new(0),
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
            drop_after,
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { server.serve(listener).await });
    let (s, c, tid) = login(addr).await;
    Rig {
        s,
        c,
        tid,
        addr,
        backend,
        _root: Scratch(dir),
    }
}

fn is_async(r: &Response) -> bool {
    r.header().flags & flags::ASYNC_COMMAND != 0
}

impl Rig {
    async fn send(&mut self, cmd: Command, body: &[u8]) -> u64 {
        let req = self.c.signed_request(cmd, self.tid, body);
        let mid = u64::from_le_bytes(req[24..32].try_into().unwrap());
        write_message(&mut self.s, &req).await.unwrap();
        mid
    }

    /// A compound chain, each element signed; every element after the first is related.
    async fn send_chain(&mut self, items: &[(Command, Vec<u8>)]) -> Vec<u64> {
        let (sid, tid) = (self.c.session_id, self.tid);
        let mut chain = Vec::new();
        let mut ids = Vec::new();
        for (i, (cmd, body)) in items.iter().enumerate() {
            let mid = self.c.next_message_id();
            ids.push(mid);
            let related = i > 0;
            let mut h = request_header(
                *cmd,
                mid,
                if related { u64::MAX } else { sid },
                if related { u32::MAX } else { tid },
            );
            if related {
                h.flags |= flags::RELATED_OPERATIONS;
            }
            let mut f = frame(&h, body);
            if i + 1 < items.len() {
                let padded = f.len().next_multiple_of(8);
                f.resize(padded, 0);
                f[20..24].copy_from_slice(&(padded as u32).to_le_bytes());
            }
            sign_frame(&mut f, &self.c.signing_key.unwrap());
            chain.extend_from_slice(&f);
        }
        write_message(&mut self.s, &chain).await.unwrap();
        ids
    }

    /// The next packet; the signature is checked unless it is an unsigned interim response.
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

    /// Whether the server has closed the connection (within `d`).
    async fn closed_within(&mut self, d: Duration) -> bool {
        matches!(
            tokio::time::timeout(d, read_message(&mut self.s)).await,
            Ok(Ok(None)) | Ok(Err(_))
        )
    }

    async fn create(&mut self, path: &str, opts: u32) -> [u8; 16] {
        let mid = self
            .send(
                Command::Create,
                &create_body_ex(path, RW, 0x80, disposition::OPEN_IF, opts, true),
            )
            .await;
        let (r, _) = self.recv().await;
        assert_eq!((r.status(), r.header().message_id), (0, mid));
        create_reply_file_id(&r.message.body)
    }

    fn hold(&self) {
        self.backend.hold.store(true, Ordering::SeqCst);
    }

    fn release(&self, n: usize) {
        self.backend.gate.add_permits(n);
    }

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

const LONG: Duration = Duration::from_secs(60);

fn create_new(path: &str) -> Vec<u8> {
    create_body_ex(path, RW, 0x80, disposition::OPEN_IF, OPT_FILE, true)
}

#[tokio::test]
async fn slow_create_gets_an_interim_response_then_the_final_one() {
    let mut t = rig(LONG, LONG).await;
    t.hold();
    let mid = t.send(Command::Create, &create_new("f")).await;

    let (interim, raw) = t.recv().await;
    let h = interim.header();
    assert_eq!(h.status, PENDING);
    assert_eq!((h.message_id, h.command), (mid, Command::Create));
    assert!(is_async(&interim) && h.async_id != 0);
    assert_eq!(
        h.flags & flags::SIGNED,
        0,
        "interim responses are not signed"
    );
    assert_eq!(raw.len(), 64 + 8, "empty error body");
    let async_id = h.async_id;

    t.no_packet_within(Duration::from_millis(200)).await;
    // no handle exists yet: CLOSE of the (not yet granted) FileId is not even possible
    t.release(8);
    let (done, _) = t.recv().await;
    let h = done.header();
    assert_eq!(
        (done.status(), h.message_id, h.async_id),
        (0, mid, async_id)
    );
    assert!(is_async(&done));
    assert_ne!(h.flags & flags::SIGNED, 0);
    assert!(
        h.credit_req_grant >= 1,
        "credits arrive with the final reply"
    );
    let fid = create_reply_file_id(&done.message.body);
    t.backend.hold.store(false, Ordering::SeqCst);
    let c = t.send(Command::Close, &close_body(fid)).await;
    let (r, _) = t.recv().await;
    assert_eq!((r.status(), r.header().message_id), (0, c));
}

#[tokio::test]
async fn quick_create_is_answered_synchronously() {
    let mut t = rig(LONG, LONG).await;
    let mid = t.send(Command::Create, &create_new("f")).await;
    let (r, _) = t.recv().await;
    assert_eq!((r.status(), r.header().message_id), (0, mid));
    assert!(!is_async(&r), "no interim response, no async header");
    t.no_packet_within(Duration::from_millis(300)).await;
}

#[tokio::test]
async fn slow_create_in_a_compound_chain_keeps_the_chain_order_and_signatures() {
    let mut t = rig(LONG, LONG).await;
    t.hold();
    let ids = t
        .send_chain(&[
            (Command::Create, create_new("f")),
            (
                Command::QueryInfo,
                query_info_body(1, 4, 4096, FILE_ID_RELATED),
            ),
            (Command::Close, close_body(FILE_ID_RELATED)),
        ])
        .await;

    let (interim, _) = t.recv().await;
    assert_eq!(interim.status(), PENDING);
    assert_eq!(
        (interim.header().message_id, interim.header().command),
        (ids[0], Command::Create),
        "the interim response is for the command that is running"
    );
    let async_id = interim.header().async_id;
    t.no_packet_within(Duration::from_millis(200)).await;

    t.release(8);
    let (r0, _) = t.recv().await;
    assert_eq!((r0.status(), r0.header().message_id), (0, ids[0]));
    assert!(is_async(&r0) && r0.header().async_id == async_id);
    let (r1, _) = t.recv().await;
    assert_eq!((r1.status(), r1.header().message_id), (0, ids[1]));
    assert!(!is_async(&r1));
    let (r2, _) = t.recv().await;
    assert_eq!((r2.status(), r2.header().message_id), (0, ids[2]));
    t.no_packet_within(Duration::from_millis(200)).await;
}

#[tokio::test]
async fn the_command_that_is_running_gets_the_interim_response_in_a_chain() {
    let mut t = rig(LONG, LONG).await;
    // The CREATE is quick; only the QUERY_INFO (stat_handle) waits.
    t.backend.open_free.store(true, Ordering::SeqCst);
    t.hold();
    let ids = t
        .send_chain(&[
            (Command::Create, create_new("f")),
            (
                Command::QueryInfo,
                query_info_body(1, 4, 4096, FILE_ID_RELATED),
            ),
            (Command::Close, close_body(FILE_ID_RELATED)),
        ])
        .await;
    let (interim, _) = t.recv().await;
    assert_eq!(
        (interim.status(), interim.header().message_id),
        (PENDING, ids[1]),
        "the CREATE is done, the QUERY_INFO is the pending one"
    );
    t.release(8);
    // the elements before the pending one go out first, then the pending one, then the rest
    let (r0, _) = t.recv().await;
    assert_eq!((r0.status(), r0.header().message_id), (0, ids[0]));
    assert!(!is_async(&r0));
    let (r1, _) = t.recv().await;
    assert_eq!((r1.status(), r1.header().message_id), (0, ids[1]));
    assert!(is_async(&r1));
    let (r2, _) = t.recv().await;
    assert_eq!((r2.status(), r2.header().message_id), (0, ids[2]));
    assert!(!is_async(&r2));
}

#[tokio::test]
async fn slow_query_info_query_directory_and_read_are_asynchronous() {
    let mut t = rig(LONG, LONG).await;
    let file = t.create("f", OPT_FILE).await;
    let w = t
        .send(Command::Write, &write_body(file, 0, b"0123456789", 0))
        .await;
    assert_eq!(t.recv().await.0.header().message_id, w);
    let dir = t.create("d", OPT_DIR).await;
    t.hold();

    let q = t
        .send(Command::QueryInfo, &query_info_body(1, 4, 4096, file))
        .await;
    let (i, _) = t.recv().await;
    assert_eq!((i.status(), i.header().message_id), (PENDING, q));
    t.release(1);
    let (r, _) = t.recv().await;
    assert_eq!((r.status(), r.header().message_id), (0, q));
    assert!(is_async(&r));

    let d = t
        .send(Command::QueryDirectory, &query_directory_body(dir))
        .await;
    let (i, _) = t.recv().await;
    assert_eq!((i.status(), i.header().message_id), (PENDING, d));
    t.release(2);
    let (r, _) = t.recv().await;
    assert_eq!((r.status(), r.header().message_id), (0, d));
    assert!(is_async(&r));

    let rd = t.send(Command::Read, &read_body(file, 10, 0)).await;
    let (i, _) = t.recv().await;
    assert_eq!((i.status(), i.header().message_id), (PENDING, rd));
    t.release(1);
    let (r, _) = t.recv().await;
    assert_eq!((r.status(), r.header().message_id), (0, rd));
    assert!(is_async(&r));
    assert_eq!(read_reply_data(&r.message.body), b"0123456789");
}

#[tokio::test]
async fn cancel_of_a_pending_create_by_message_id_and_by_async_id() {
    let mut t = rig(LONG, LONG).await;
    t.hold();
    // before the interim response: by MessageId, the reply is synchronous
    let mid = t.send(Command::Create, &create_new("a")).await;
    t.cancel(mid, None).await;
    let (r, _) = t.recv().await;
    assert_eq!((r.status(), r.header().message_id), (CANCELLED, mid));
    assert!(!is_async(&r));

    // after it: by AsyncId, the reply is the async final response
    let mid = t.send(Command::Create, &create_new("b")).await;
    let (interim, _) = t.recv().await;
    let async_id = interim.header().async_id;
    t.cancel(mid + 1, Some(async_id)).await;
    let (r, _) = t.recv().await;
    assert_eq!((r.status(), r.header().message_id), (CANCELLED, mid));
    assert!(is_async(&r));
    t.no_packet_within(Duration::from_millis(200)).await; // CANCEL has no reply

    // the connection works afterwards
    t.backend.hold.store(false, Ordering::SeqCst);
    let echo = t.send(Command::Echo, &simple_body()).await;
    assert_eq!(t.recv().await.0.header().message_id, echo);
}

#[tokio::test]
async fn cancel_of_something_unknown_is_ignored_while_a_create_waits() {
    let mut t = rig(LONG, LONG).await;
    t.hold();
    let mid = t.send(Command::Create, &create_new("a")).await;
    let (interim, _) = t.recv().await;
    assert_eq!(interim.status(), PENDING);
    t.cancel(999_999, None).await;
    t.cancel(1, Some(77)).await;
    t.no_packet_within(Duration::from_millis(200)).await;
    t.release(8);
    let (r, _) = t.recv().await;
    assert_eq!((r.status(), r.header().message_id), (0, mid));
}

#[tokio::test]
async fn the_wait_ceiling_gives_one_final_error_and_the_connection_survives() {
    let mut t = rig(Duration::from_millis(500), LONG).await;
    t.hold();
    let mid = t.send(Command::Create, &create_new("a")).await;
    let (interim, _) = t.recv().await;
    assert_eq!(interim.status(), PENDING);
    let (r, _) = t.recv().await;
    assert_eq!((r.status(), r.header().message_id), (NETWORK_ERROR, mid));
    assert!(is_async(&r));
    t.no_packet_within(Duration::from_millis(300)).await; // one error, not two

    t.backend.hold.store(false, Ordering::SeqCst);
    let echo = t.send(Command::Echo, &simple_body()).await;
    assert_eq!(t.recv().await.0.header().message_id, echo);
    let again = t.send(Command::Create, &create_new("a")).await;
    let (r, _) = t.recv().await;
    assert_eq!((r.status(), r.header().message_id), (0, again));
}

#[tokio::test]
async fn at_drop_after_the_connection_is_closed_and_a_new_one_works() {
    let mut t = rig(LONG, Duration::from_millis(600)).await;
    t.hold();
    t.send(Command::Create, &create_new("a")).await;
    let (interim, _) = t.recv().await;
    assert_eq!(interim.status(), PENDING);
    assert!(
        t.closed_within(Duration::from_secs(3)).await,
        "the server drops the TCP connection"
    );

    // the client reconnects and repeats the request: with the backend back, it succeeds
    t.backend.hold.store(false, Ordering::SeqCst);
    let (s, c, tid) = login(t.addr).await;
    t.s = s;
    t.c = c;
    t.tid = tid;
    let mid = t.send(Command::Create, &create_new("a")).await;
    let (r, _) = t.recv().await;
    assert_eq!((r.status(), r.header().message_id), (0, mid));
}

#[tokio::test]
async fn echo_is_answered_at_once_and_other_packets_queue_in_order() {
    let mut t = rig(LONG, LONG).await;
    t.hold();
    let first = t.send(Command::Create, &create_new("a")).await;
    let (interim, _) = t.recv().await;
    assert_eq!(interim.status(), PENDING);
    // The client's keepalive must not go unanswered while a request waits (the macOS client
    // drops a connection whose ECHO is silent for ~90 s).
    let echo = t.send(Command::Echo, &simple_body()).await;
    let (r, _) = t.recv().await;
    assert_eq!((r.status(), r.header().message_id), (0, echo));
    assert!(!is_async(&r));
    let second = t.send(Command::Create, &create_new("b")).await;
    t.no_packet_within(Duration::from_millis(300)).await;

    t.backend.hold.store(false, Ordering::SeqCst);
    t.release(8);
    let order: Vec<u64> = vec![
        t.recv().await.0.header().message_id,
        t.recv().await.0.header().message_id,
    ];
    assert_eq!(order, [first, second], "arrival order is kept");
}

#[tokio::test]
async fn echo_is_answered_while_a_barrier_waits_for_a_pending_read() {
    let mut t = rig(LONG, LONG).await;
    let fid = t.create("f", OPT_FILE).await;
    let w = t
        .send(Command::Write, &write_body(fid, 0, b"0123456789", 0))
        .await;
    assert_eq!(t.recv().await.0.header().message_id, w);
    t.hold();
    let rd = t.send(Command::Read, &read_body(fid, 10, 0)).await;
    assert_eq!(t.recv().await.0.status(), PENDING);
    let c = t.send(Command::Create, &create_new("g")).await; // barrier behind the READ
    t.no_packet_within(Duration::from_millis(200)).await;
    let echo = t.send(Command::Echo, &simple_body()).await;
    let (r, _) = t.recv().await;
    assert_eq!((r.status(), r.header().message_id), (0, echo));
    t.backend.hold.store(false, Ordering::SeqCst);
    t.release(8);
    assert_eq!(t.recv().await.0.header().message_id, rd);
    assert_eq!(t.recv().await.0.header().message_id, c);
}

#[tokio::test]
async fn a_healthy_backend_never_produces_an_interim_response() {
    let mut t = rig(LONG, LONG).await;
    for i in 0..20 {
        let fid = t.create(&format!("f{i}"), OPT_FILE).await;
        let q = t
            .send(Command::QueryInfo, &query_info_body(1, 4, 4096, fid))
            .await;
        let (r, _) = t.recv().await;
        assert_eq!((r.status(), r.header().message_id), (0, q));
        assert!(!is_async(&r));
        let c = t.send(Command::Close, &close_body(fid)).await;
        let (r, _) = t.recv().await;
        assert_eq!((r.status(), r.header().message_id), (0, c));
        assert!(!is_async(&r));
    }
    t.no_packet_within(Duration::from_millis(300)).await;
}

#[tokio::test]
async fn a_pipelined_read_that_waits_too_long_drops_the_connection() {
    let mut t = rig(LONG, Duration::from_millis(600)).await;
    let fid = t.create("f", OPT_FILE).await;
    t.hold();
    let rd = t.send(Command::Read, &read_body(fid, 10, 0)).await;
    let (interim, _) = t.recv().await;
    assert_eq!(
        (interim.status(), interim.header().message_id),
        (PENDING, rd)
    );
    assert!(
        t.closed_within(Duration::from_secs(3)).await,
        "READ went past drop_after: the server closes the connection"
    );
}

#[tokio::test]
async fn a_request_behind_a_pending_read_waits_for_it_and_still_gets_the_timers() {
    let mut t = rig(LONG, LONG).await;
    let fid = t.create("f", OPT_FILE).await;
    let w = t
        .send(Command::Write, &write_body(fid, 0, b"0123456789", 0))
        .await;
    assert_eq!(t.recv().await.0.header().message_id, w);
    t.hold();
    let rd = t.send(Command::Read, &read_body(fid, 10, 0)).await;
    let (interim, _) = t.recv().await;
    assert_eq!(
        (interim.status(), interim.header().message_id),
        (PENDING, rd)
    );
    // A CREATE is a barrier: it waits for the READ in flight, which is already announced.
    let c = t.send(Command::Create, &create_new("g")).await;
    t.no_packet_within(Duration::from_millis(300)).await;
    t.backend.hold.store(false, Ordering::SeqCst);
    t.release(8);
    let (r1, _) = t.recv().await;
    assert_eq!((r1.status(), r1.header().message_id), (0, rd));
    assert!(is_async(&r1));
    let (r2, _) = t.recv().await;
    assert_eq!((r2.status(), r2.header().message_id), (0, c));
}
