//! J4 step 2 end-to-end: durable handles V2 (DH2Q/DH2C) and lease V2 over real TCP, with a
//! `DevServer` on a `LocalFsBackend` and the scripted client from `smb_wire::testclient`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use janus_lib::control::DaemonState;
use janus_lib::credentials::CredentialStore;
use janus_lib::journal::ParkedHandleStore;
use janus_lib::vfs::LocalFsBackend;
use smb_core::server::{DevServer, ServerConfig};
use smb_core::shared::Shared;
use smb_core::transport::{read_message, write_message};
use smb_wire::Command;
use smb_wire::create::disposition;
use smb_wire::testclient::{
    Client, Response, close_body, create_body_ctx, create_reply_contexts, create_reply_file_id,
    dh2c_data, dh2q_data, lease_ack_body, read_body, read_reply_data, rqls_v2_data,
    tree_connect_body, write_body,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

const USER: &str = "janus";
const PASSWORD: &str = "durable-test-password";
const RW: u32 = 0x0013_019F;
const RO: u32 = 0x0012_0089;
const OPT_FILE: u32 = 0x40;
const R: u32 = 1;
const H: u32 = 2;
const W: u32 = 4;
const KEY_A: [u8; 16] = [0xA1; 16];
const KEY_B: [u8; 16] = [0xB2; 16];
const GUID: [u8; 16] = [0x77; 16];
const STATUS_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_DENIED: u32 = 0xC000_0022;
const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let mut r = [0u8; 8];
        getrandom::fill(&mut r).unwrap();
        let p = std::env::temp_dir().join(format!("janus-{tag}-{}", u64::from_le_bytes(r)));
        std::fs::create_dir_all(&p).unwrap();
        Scratch(p)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Server {
    addr: std::net::SocketAddr,
    shared: Arc<Shared>,
    task: tokio::task::JoinHandle<()>,
}

impl Server {
    fn stop(&self) {
        self.task.abort();
    }
}

async fn start_server(root: &Path, shared: Arc<Shared>) -> Server {
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
            Arc::new(LocalFsBackend::new(root).unwrap()),
        )
        .with_shared(Arc::clone(&shared)),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let _ = server.serve(listener).await;
    });
    Server { addr, shared, task }
}

struct Session {
    s: TcpStream,
    c: Client,
    tid: u32,
}

impl Session {
    async fn connect(addr: std::net::SocketAddr) -> Session {
        Self::connect_as(addr, [0x42; 16]).await
    }

    async fn connect_as(addr: std::net::SocketAddr, client_guid: [u8; 16]) -> Session {
        let mut s = TcpStream::connect(addr).await.unwrap();
        let mut c = Client::new(USER, PASSWORD);
        c.client_guid = client_guid;
        let r = Self::raw(&mut s, &c.negotiate_request()).await;
        c.on_negotiate_response(&r);
        let r1 = Self::raw(&mut s, &c.session_setup_1()).await;
        let req2 = c.session_setup_2(&r1).unwrap();
        let fin = Response::parse(&Self::raw(&mut s, &req2).await).unwrap();
        assert_eq!(fin.status(), 0);
        let mut me = Session { s, c, tid: 0 };
        let tc = me
            .call(
                Command::TreeConnect,
                &tree_connect_body("\\\\127.0.0.1\\backup"),
            )
            .await;
        assert_eq!(tc.status(), 0);
        me.tid = tc.header().tree_id;
        me
    }

    async fn raw(s: &mut TcpStream, req: &[u8]) -> Vec<u8> {
        write_message(s, req).await.unwrap();
        read_message(s).await.unwrap().expect("connection closed")
    }

    async fn call(&mut self, cmd: Command, body: &[u8]) -> Response {
        let tid = if cmd == Command::TreeConnect {
            0
        } else {
            self.tid
        };
        let r = Self::raw(&mut self.s, &self.c.signed_request(cmd, tid, body)).await;
        assert!(self.c.verify_response(&r), "{cmd:?}: reply signature");
        Response::parse(&r).unwrap()
    }

    /// CREATE with explicit create contexts.
    async fn create(
        &mut self,
        path: &str,
        access: u32,
        disp: u32,
        ctxs: &[(&[u8; 4], Vec<u8>)],
    ) -> Response {
        self.call(
            Command::Create,
            &create_body_ctx(path, access, disp, OPT_FILE, ctxs),
        )
        .await
    }

    async fn write(&mut self, fid: [u8; 16], offset: u64, data: &[u8]) {
        let r = self
            .call(Command::Write, &write_body(fid, offset, data, 0))
            .await;
        assert_eq!(r.status(), 0);
    }

    async fn read(&mut self, fid: [u8; 16], len: u32) -> Vec<u8> {
        let r = self.call(Command::Read, &read_body(fid, len, 0)).await;
        assert_eq!(r.status(), 0);
        read_reply_data(&r.message.body)
    }
}

fn ctx_data(r: &Response, name: &[u8; 4]) -> Option<Vec<u8>> {
    create_reply_contexts(&r.message.body)
        .into_iter()
        .find(|(n, _)| n == name)
        .map(|(_, d)| d)
}

fn le32(d: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(d[at..at + 4].try_into().unwrap())
}

async fn until(what: &str, mut cond: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(5);
    while !cond() {
        assert!(Instant::now() < end, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// A durable file with lease RH, as `tmutil` asks for it.
async fn create_durable(s: &mut Session, path: &str, timeout_ms: u32) -> (Response, [u8; 16]) {
    let r = s
        .create(
            path,
            RW,
            disposition::CREATE,
            &[
                (b"DH2Q", dh2q_data(timeout_ms, GUID)),
                (b"RqLs", rqls_v2_data(KEY_A, R | H)),
            ],
        )
        .await;
    assert_eq!(r.status(), 0, "create {path}");
    let fid = create_reply_file_id(&r.message.body);
    (r, fid)
}

async fn reconnect(s: &mut Session, path: &str, fid: [u8; 16], guid: [u8; 16]) -> Response {
    s.create(
        path,
        RW,
        disposition::OPEN,
        &[
            (b"DH2C", dh2c_data(fid, guid)),
            (b"RqLs", rqls_v2_data(KEY_A, R | H)),
        ],
    )
    .await
}

#[tokio::test]
async fn durable_request_is_granted_with_the_timeout_and_a_lease() {
    let dir = Scratch::new("dh-grant");
    let srv = start_server(&dir.0, Arc::default()).await;
    let mut s = Session::connect(srv.addr).await;
    let (r, _) = create_durable(&mut s, "f", 30_000).await;
    assert_eq!(r.message.body[2], 0xFF, "OplockLevel = LEASE");
    let dh = ctx_data(&r, b"DH2Q").expect("DH2Q reply");
    assert_eq!((le32(&dh, 0), le32(&dh, 4)), (30_000, 0));
    let lease = ctx_data(&r, b"RqLs").expect("RqLs reply");
    assert_eq!(lease.len(), 52);
    assert_eq!(&lease[..16], &KEY_A);
    assert_eq!(le32(&lease, 16), R | H);
    // Timeout = 0 means the server default; a huge request is capped.
    let (r, _) = {
        let mut s2 = Session::connect(srv.addr).await;
        let r = s2
            .create(
                "g",
                RW,
                disposition::CREATE,
                &[
                    (b"DH2Q", dh2q_data(0, [1; 16])),
                    (b"RqLs", rqls_v2_data([5; 16], R | H)),
                ],
            )
            .await;
        let fid = create_reply_file_id(&r.message.body);
        (r, fid)
    };
    assert_eq!(le32(&ctx_data(&r, b"DH2Q").unwrap(), 0), 60_000);
}

#[tokio::test]
async fn durable_is_not_granted_without_handle_caching() {
    let dir = Scratch::new("dh-noh");
    let srv = start_server(&dir.0, Arc::default()).await;
    let mut s = Session::connect(srv.addr).await;
    let r = s
        .create(
            "f",
            RW,
            disposition::CREATE,
            &[
                (b"DH2Q", dh2q_data(30_000, GUID)),
                (b"RqLs", rqls_v2_data(KEY_A, R)),
            ],
        )
        .await;
    assert_eq!(r.status(), 0);
    assert!(ctx_data(&r, b"DH2Q").is_none());
    assert_eq!(le32(&ctx_data(&r, b"RqLs").unwrap(), 16), R);
    // and not at all without a lease
    let r = s
        .create(
            "g",
            RW,
            disposition::CREATE,
            &[(b"DH2Q", dh2q_data(30_000, [2; 16]))],
        )
        .await;
    assert_eq!(r.status(), 0);
    assert!(ctx_data(&r, b"DH2Q").is_none());
}

#[tokio::test]
async fn handle_survives_a_dropped_connection_and_is_reclaimed_by_dh2c() {
    let dir = Scratch::new("dh-reconnect");
    let srv = start_server(&dir.0, Arc::default()).await;
    let mut s = Session::connect(srv.addr).await;
    let (_, fid) = create_durable(&mut s, "band", 30_000).await;
    s.write(fid, 0, b"before the drop").await;
    drop(s); // TCP drop, no CLOSE
    until("the handle to be parked", || srv.shared.parked_len() == 1).await;
    assert_eq!(
        srv.shared.lease_state(&KEY_A),
        Some(R | H),
        "the lease is kept"
    );

    let mut s2 = Session::connect(srv.addr).await;
    let r = reconnect(&mut s2, "band", fid, GUID).await;
    assert_eq!(r.status(), 0, "DH2C");
    let fid2 = create_reply_file_id(&r.message.body);
    assert_eq!(srv.shared.parked_len(), 0);
    assert_eq!(s2.read(fid2, 64).await, b"before the drop");
    s2.write(fid2, 15, b"!").await;
    assert_eq!(s2.call(Command::Close, &close_body(fid2)).await.status(), 0);
    assert_eq!(
        std::fs::read(dir.0.join("band")).unwrap(),
        b"before the drop!"
    );
    assert_eq!(
        srv.shared.lease_state(&KEY_A),
        None,
        "closing releases the lease"
    );
}

#[tokio::test]
async fn reconnect_fails_for_a_wrong_guid_a_wrong_file_id_and_another_client() {
    let dir = Scratch::new("dh-wrong");
    let srv = start_server(&dir.0, Arc::default()).await;
    let mut s = Session::connect(srv.addr).await;
    let (_, fid) = create_durable(&mut s, "f", 30_000).await;
    drop(s);
    until("parked", || srv.shared.parked_len() == 1).await;

    let mut other = Session::connect_as(srv.addr, [0x99; 16]).await;
    assert_eq!(
        reconnect(&mut other, "f", fid, GUID).await.status(),
        STATUS_DENIED
    );
    let mut s2 = Session::connect(srv.addr).await;
    assert_eq!(
        reconnect(&mut s2, "f", fid, [3; 16]).await.status(),
        STATUS_NOT_FOUND
    );
    assert_eq!(
        reconnect(&mut s2, "f", [9; 16], GUID).await.status(),
        STATUS_NOT_FOUND
    );
    // none of the failed attempts consumed the handle
    assert_eq!(srv.shared.parked_len(), 1);
    assert_eq!(reconnect(&mut s2, "f", fid, GUID).await.status(), 0);
}

#[tokio::test]
async fn a_parked_handle_expires_and_is_closed() {
    let dir = Scratch::new("dh-expire");
    let srv = start_server(&dir.0, Arc::default()).await;
    let mut s = Session::connect(srv.addr).await;
    let (_, fid) = create_durable(&mut s, "gone", 300).await;
    // delete-on-close semantics are visible through the closed handle: write, then drop
    s.write(fid, 0, b"x").await;
    drop(s);
    until("parked", || srv.shared.parked_len() == 1).await;
    until("the timeout to pass and the sweeper to run", || {
        srv.shared.parked_len() == 0
    })
    .await;
    assert_eq!(srv.shared.lease_state(&KEY_A), None);
    let mut s2 = Session::connect(srv.addr).await;
    assert_eq!(
        reconnect(&mut s2, "gone", fid, GUID).await.status(),
        STATUS_NOT_FOUND
    );
    // the file itself stays: only the handle expired
    assert_eq!(std::fs::read(dir.0.join("gone")).unwrap(), b"x");
}

#[tokio::test]
async fn an_orderly_logoff_closes_durable_handles() {
    let dir = Scratch::new("dh-logoff");
    let srv = start_server(&dir.0, Arc::default()).await;
    let mut s = Session::connect(srv.addr).await;
    let _ = create_durable(&mut s, "f", 30_000).await;
    assert_eq!(s.call(Command::Logoff, &[4, 0, 0, 0]).await.status(), 0);
    drop(s);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(srv.shared.parked_len(), 0);
    assert_eq!(srv.shared.lease_state(&KEY_A), None);
}

#[tokio::test]
async fn a_parked_handle_survives_a_daemon_restart() {
    let dir = Scratch::new("dh-restart");
    let state = Scratch::new("dh-restart-state");
    let srv1 = start_server(
        &dir.0,
        Arc::new(Shared::new(ParkedHandleStore::in_dir(&state.0).unwrap())),
    )
    .await;
    let mut s = Session::connect(srv1.addr).await;
    let (_, fid) = create_durable(&mut s, "band", 30_000).await;
    s.write(fid, 0, b"persisted").await;
    drop(s);
    until("parked", || srv1.shared.parked_len() == 1).await;
    srv1.stop();
    drop(srv1);

    // A new daemon over the same share and state directory.
    let srv2 = start_server(
        &dir.0,
        Arc::new(Shared::new(ParkedHandleStore::in_dir(&state.0).unwrap())),
    )
    .await;
    assert_eq!(srv2.shared.parked_len(), 1);
    let mut s2 = Session::connect(srv2.addr).await;
    let r = reconnect(&mut s2, "band", fid, GUID).await;
    assert_eq!(r.status(), 0, "DH2C after restart");
    let fid2 = create_reply_file_id(&r.message.body);
    assert_eq!(s2.read(fid2, 64).await, b"persisted", "reopened by path");
    assert_eq!(
        le32(&ctx_data(&r, b"RqLs").unwrap(), 16),
        R | H,
        "lease restored"
    );
}

#[tokio::test]
async fn a_live_durable_handle_survives_a_crash_of_the_daemon() {
    let dir = Scratch::new("dh-crash");
    let state = Scratch::new("dh-crash-state");
    let srv1 = start_server(
        &dir.0,
        Arc::new(Shared::new(ParkedHandleStore::in_dir(&state.0).unwrap())),
    )
    .await;
    let mut s = Session::connect(srv1.addr).await;
    let (_, fid) = create_durable(&mut s, "band", 30_000).await;
    s.write(fid, 0, b"before the crash").await;
    assert_eq!(srv1.shared.live_len(), 1);
    assert_eq!(
        srv1.shared.parked_len(),
        0,
        "the connection is alive: nothing is parked"
    );
    srv1.shared.heartbeat(); // what the sweeper does every second
    // kill -9: no cleanup runs at all; the client's socket just stops answering
    srv1.stop();

    let srv2 = start_server(
        &dir.0,
        Arc::new(Shared::new(ParkedHandleStore::in_dir(&state.0).unwrap())),
    )
    .await;
    assert_eq!(
        srv2.shared.parked_len(),
        1,
        "revived from the heartbeat copy"
    );
    let mut s2 = Session::connect(srv2.addr).await;
    let r = reconnect(&mut s2, "band", fid, GUID).await;
    assert_eq!(r.status(), 0, "DH2C after a crash");
    let fid2 = create_reply_file_id(&r.message.body);
    assert_eq!(s2.read(fid2, 64).await, b"before the crash");
    // the reclaimed handle is durable again
    assert_eq!(srv2.shared.live_len(), 1);
    assert_eq!(s2.call(Command::Close, &close_body(fid2)).await.status(), 0);
    assert_eq!(srv2.shared.live_len(), 0, "closing forgets it");
    drop(s);
}

#[tokio::test]
async fn a_crashed_handle_expires_a_timeout_after_the_last_heartbeat() {
    let dir = Scratch::new("dh-crash-late");
    let state = Scratch::new("dh-crash-late-state");
    let srv1 = start_server(
        &dir.0,
        Arc::new(Shared::new(ParkedHandleStore::in_dir(&state.0).unwrap())),
    )
    .await;
    let mut s = Session::connect(srv1.addr).await;
    let _ = create_durable(&mut s, "band", 200).await;
    srv1.shared.heartbeat();
    srv1.stop();
    tokio::time::sleep(Duration::from_millis(400)).await; // the daemon was down longer than that
    let srv2 = start_server(
        &dir.0,
        Arc::new(Shared::new(ParkedHandleStore::in_dir(&state.0).unwrap())),
    )
    .await;
    assert_eq!(srv2.shared.parked_len(), 0);
    drop(s);
}

/// The first 64 bytes of an unsolicited message → (command, message id), and its body.
fn unsolicited(raw: &[u8]) -> (u16, u64, Vec<u8>) {
    (
        u16::from_le_bytes([raw[12], raw[13]]),
        u64::from_le_bytes(raw[24..32].try_into().unwrap()),
        raw[64..].to_vec(),
    )
}

async fn open_with_lease(s: &mut Session, path: &str, key: [u8; 16], state: u32) -> Response {
    open_with_lease_as(s, path, RW, key, state).await
}

async fn open_with_lease_as(
    s: &mut Session,
    path: &str,
    access: u32,
    key: [u8; 16],
    state: u32,
) -> Response {
    s.create(
        path,
        access,
        disposition::OPEN_IF,
        &[(b"RqLs", rqls_v2_data(key, state))],
    )
    .await
}

#[tokio::test]
async fn lease_break_between_two_connections_waits_for_the_ack() {
    let dir = Scratch::new("lease-break");
    let srv = start_server(&dir.0, Arc::default()).await;
    let mut a = Session::connect(srv.addr).await;
    let r = open_with_lease(&mut a, "f", KEY_A, R | H | W).await;
    assert_eq!(le32(&ctx_data(&r, b"RqLs").unwrap(), 16), R | H | W);

    let mut b = Session::connect(srv.addr).await;
    let started = Instant::now();
    let b_open = tokio::spawn(async move {
        let r = open_with_lease_as(&mut b, "f", RO, KEY_B, R | H | W).await;
        (b, r)
    });
    // A is told to give up W …
    let raw = read_message(&mut a.s).await.unwrap().unwrap();
    let (cmd, mid, body) = unsolicited(&raw);
    assert_eq!((cmd, mid), (0x12, u64::MAX), "lease break notification");
    assert_eq!(le32(&body, 4), 1, "ack required");
    assert_eq!(&body[8..24], &KEY_A);
    assert_eq!((le32(&body, 24), le32(&body, 28)), (R | H | W, R | H));
    // … and B waits for it
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        !b_open.is_finished(),
        "B's open waits for the acknowledgment"
    );
    let ack = a
        .call(Command::OplockBreak, &lease_ack_body(KEY_A, R | H))
        .await;
    assert_eq!(ack.status(), 0);
    assert_eq!(&ack.message.body[8..24], &KEY_A);
    let (_b, r) = b_open.await.unwrap();
    assert_eq!(r.status(), 0);
    assert!(started.elapsed() >= Duration::from_millis(150));
    // B shares the file with A: no write caching for it
    assert_eq!(le32(&ctx_data(&r, b"RqLs").unwrap(), 16), R | H);
    assert_eq!(srv.shared.lease_state(&KEY_A), Some(R | H));
    // a repeated or invalid acknowledgment is refused
    let again = a
        .call(Command::OplockBreak, &lease_ack_body(KEY_A, R | H))
        .await;
    assert_eq!(again.status(), STATUS_UNSUCCESSFUL);
}

#[tokio::test]
async fn silence_downgrades_the_lease_by_force() {
    let dir = Scratch::new("lease-silent");
    let shared = Arc::new(Shared::default().with_break_timeout(Duration::from_millis(300)));
    let srv = start_server(&dir.0, shared).await;
    let mut a = Session::connect(srv.addr).await;
    open_with_lease(&mut a, "f", KEY_A, R | H | W).await;
    let mut b = Session::connect(srv.addr).await;
    let started = Instant::now();
    let r = open_with_lease_as(&mut b, "f", RO, KEY_B, R).await;
    assert_eq!(r.status(), 0);
    assert!(
        started.elapsed() >= Duration::from_millis(250),
        "waited for the ack"
    );
    assert_eq!(
        srv.shared.lease_state(&KEY_A),
        Some(R | H),
        "downgraded by force"
    );
}

#[tokio::test]
async fn a_conflict_on_the_same_connection_does_not_block_it() {
    let dir = Scratch::new("lease-same");
    let srv = start_server(&dir.0, Arc::default()).await;
    let mut a = Session::connect(srv.addr).await;
    open_with_lease(&mut a, "f", KEY_A, R | H | W).await;
    // the same client opens the file again under another lease key
    let r = tokio::time::timeout(
        Duration::from_secs(2),
        open_with_lease_as(&mut a, "f", RO, KEY_B, R | H),
    )
    .await
    .expect("must not wait for an acknowledgment that could only arrive on this connection");
    assert_eq!(r.status(), 0);
    // the break notification still reaches the client (after the CREATE response)
    let raw = read_message(&mut a.s).await.unwrap().unwrap();
    assert_eq!(unsolicited(&raw).0, 0x12);
    let ack = a
        .call(Command::OplockBreak, &lease_ack_body(KEY_A, R | H))
        .await;
    assert_eq!(ack.status(), 0);
}

#[tokio::test]
async fn an_attribute_only_open_by_another_client_breaks_nothing() {
    let dir = Scratch::new("lease-attr");
    let srv = start_server(&dir.0, Arc::default()).await;
    let mut a = Session::connect(srv.addr).await;
    open_with_lease(&mut a, "f", KEY_A, R | H | W).await;
    let mut b = Session::connect(srv.addr).await;
    let r = tokio::time::timeout(
        Duration::from_secs(1),
        b.create("f", 0x0010_0080, disposition::OPEN, &[]),
    )
    .await
    .expect("no wait");
    assert_eq!(r.status(), 0);
    assert_eq!(srv.shared.lease_state(&KEY_A), Some(R | H | W));
}
