//! J2 end-to-end test: real TCP, `DevServer` over a `LocalFsBackend`, a scripted client from
//! `smb_wire::testclient`. It copies files onto the share and back and compares SHA-256
//! digests: the automated stand-in for "Finder copies files, the content matches". The manual
//! run with `mount_smbfs` is in the crate README.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use janus_lib::control::DaemonState;
use janus_lib::credentials::CredentialStore;
use janus_lib::vfs::LocalFsBackend;
use sha2::{Digest, Sha256};
use smb_core::server::{DevServer, ServerConfig};
use smb_core::transport::{read_message, write_message};
use smb_wire::Command;
use smb_wire::create::disposition;
use smb_wire::fileinfo::filetime_from_unix_ns;
use smb_wire::testclient::{
    Client, Response, basic_info, close_body, create_body_ex, create_reply_file_id,
    dir_entry_names, disposition_info, flush_body, query_directory_body_ex, read_body,
    read_reply_data, rename_info, set_info_body, tree_connect_body, write_body,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

const USER: &str = "janus";
const PASSWORD: &str = "files-test-password";
const RW: u32 = 0x0013_019F;
const RO: u32 = 0x0012_0089;
const OPT_FILE: u32 = 0x40;
const OPT_DIR: u32 = 0x01;
const OPT_DELETE_ON_CLOSE: u32 = 0x1000;
const CHUNK: usize = 65536;

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let mut r = [0u8; 8];
        getrandom::fill(&mut r).unwrap();
        Scratch(std::env::temp_dir().join(format!("janus-{tag}-{}", u64::from_le_bytes(r))))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn start_server(root: &Path) -> std::net::SocketAddr {
    let creds = Arc::new(CredentialStore::load(
        Some(USER.into()),
        Some(PASSWORD.into()),
        None,
    ));
    let server = Arc::new(DevServer::new(
        ServerConfig::default(),
        Arc::new(Mutex::new(DaemonState::default())),
        creds,
        Arc::new(LocalFsBackend::new(root).unwrap()),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { server.serve(listener).await });
    addr
}

/// A logged-in, tree-connected client.
struct Session {
    s: TcpStream,
    c: Client,
    tid: u32,
}

impl Session {
    async fn connect(addr: std::net::SocketAddr) -> Session {
        let mut s = TcpStream::connect(addr).await.unwrap();
        let mut c = Client::new(USER, PASSWORD);
        let r = Self::raw(&mut s, &c.negotiate_request()).await;
        c.on_negotiate_response(&r);
        let r1 = Self::raw(&mut s, &c.session_setup_1()).await;
        let req2 = c.session_setup_2(&r1).unwrap();
        let fin = Response::parse(&Self::raw(&mut s, &req2).await).unwrap();
        assert_eq!(fin.status(), 0);
        let mut me = Session { s, c, tid: 0 };
        let tc = me
            .call_on(
                0,
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

    async fn call_on(&mut self, tid: u32, cmd: Command, body: &[u8]) -> Response {
        let r = Self::raw(&mut self.s, &self.c.signed_request(cmd, tid, body)).await;
        assert!(self.c.verify_response(&r), "{cmd:?}: reply signature");
        Response::parse(&r).unwrap()
    }

    async fn call(&mut self, cmd: Command, body: &[u8]) -> Response {
        let tid = self.tid;
        self.call_on(tid, cmd, body).await
    }

    async fn open(&mut self, path: &str, access: u32, disp: u32, opts: u32) -> Response {
        self.call(
            Command::Create,
            &create_body_ex(path, access, 0x80, disp, opts, true),
        )
        .await
    }

    async fn open_ok(&mut self, path: &str, access: u32, disp: u32, opts: u32) -> [u8; 16] {
        let r = self.open(path, access, disp, opts).await;
        assert_eq!(r.status(), 0, "open {path}");
        create_reply_file_id(&r.message.body)
    }

    async fn close(&mut self, fid: [u8; 16]) {
        assert_eq!(
            self.call(Command::Close, &close_body(fid)).await.status(),
            0
        );
    }

    /// Copy `data` to `path` in 64 KiB writes (create, write, flush, close).
    async fn put(&mut self, path: &str, data: &[u8]) {
        let fid = self.open_ok(path, RW, disposition::CREATE, OPT_FILE).await;
        for (i, chunk) in data.chunks(CHUNK).enumerate() {
            let r = self
                .call(
                    Command::Write,
                    &write_body(fid, (i * CHUNK) as u64, chunk, 0),
                )
                .await;
            assert_eq!(r.status(), 0, "write {path} chunk {i}");
        }
        assert_eq!(
            self.call(Command::Flush, &flush_body(fid, true))
                .await
                .status(),
            0
        );
        self.close(fid).await;
    }

    /// Read a whole file back in 64 KiB reads.
    async fn get(&mut self, path: &str) -> Vec<u8> {
        let fid = self.open_ok(path, RO, disposition::OPEN, OPT_FILE).await;
        let mut out = Vec::new();
        loop {
            let r = self
                .call(
                    Command::Read,
                    &read_body(fid, CHUNK as u32, out.len() as u64),
                )
                .await;
            if r.status() == 0xC000_0011 {
                break;
            }
            assert_eq!(r.status(), 0);
            out.extend(read_reply_data(&r.message.body));
        }
        self.close(fid).await;
        out
    }

    async fn names(&mut self, path: &str) -> Vec<String> {
        let fid = self.open_ok(path, RO, disposition::OPEN, OPT_DIR).await;
        let mut all = Vec::new();
        let mut flags = 1u8;
        loop {
            let r = self
                .call(
                    Command::QueryDirectory,
                    &query_directory_body_ex(fid, 37, flags, "*", 4096),
                )
                .await;
            flags = 0;
            if r.status() != 0 {
                break;
            }
            all.extend(dir_entry_names(&r.message.body, 37));
        }
        self.close(fid).await;
        all.retain(|n| n != "." && n != "..");
        all.sort();
        all
    }
}

fn pseudo_random(n: usize, seed: u64) -> Vec<u8> {
    // xorshift64*: deterministic and not compressible.
    let mut x = seed | 1;
    (0..n)
        .map(|_| {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            (x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8
        })
        .collect()
}

fn digest(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

#[tokio::test]
async fn copy_files_onto_the_share_and_back_with_matching_hashes() {
    let root = Scratch::new("copy");
    let addr = start_server(&root.0).await;
    let mut s = Session::connect(addr).await;

    let dir = s.open_ok("Photos", RW, disposition::CREATE, OPT_DIR).await;
    s.close(dir).await;

    let sizes = [
        0usize, 1, 511, 4095, 4096, 4097, 65535, 65536, 65537, 1_000_003,
    ];
    for (i, &size) in sizes.iter().enumerate() {
        let data = pseudo_random(size, i as u64 + 1);
        let path = format!("Photos\\img_{i:02}.bin");
        s.put(&path, &data).await;
        // the bytes on the server's disk match what was sent
        let on_disk = std::fs::read(root.0.join(format!("Photos/img_{i:02}.bin"))).unwrap();
        assert_eq!(digest(&on_disk), digest(&data), "disk, size {size}");
        // and what comes back over SMB matches too
        let back = s.get(&path).await;
        assert_eq!(back.len(), size, "size {size}");
        assert_eq!(digest(&back), digest(&data), "read back, size {size}");
    }
    let names = s.names("Photos").await;
    assert_eq!(names.len(), sizes.len());
    assert_eq!(names[0], "img_00.bin");
    assert_eq!(s.names("").await, ["Photos"]);
}

#[tokio::test]
async fn finder_like_save_via_temp_name_rename_and_delete() {
    let root = Scratch::new("finder");
    let addr = start_server(&root.0).await;
    let mut s = Session::connect(addr).await;

    // write under a temporary name, set times, rename into place (atomic save)
    let data = pseudo_random(200_000, 99);
    let fid = s
        .open_ok("doc.tmp", RW, disposition::CREATE, OPT_FILE)
        .await;
    for (i, chunk) in data.chunks(CHUNK).enumerate() {
        s.call(
            Command::Write,
            &write_body(fid, (i * CHUNK) as u64, chunk, 0),
        )
        .await;
    }
    let t = filetime_from_unix_ns(1_700_000_000_000_000_000);
    let r = s
        .call(Command::SetInfo, &set_info_body(4, fid, &basic_info(t, t)))
        .await;
    assert_eq!(r.status(), 0, "touch");
    let r = s
        .call(
            Command::SetInfo,
            &set_info_body(10, fid, &rename_info("doc.txt", true)),
        )
        .await;
    assert_eq!(r.status(), 0, "rename");
    s.close(fid).await;
    assert_eq!(s.names("").await, ["doc.txt"]);
    assert_eq!(digest(&s.get("doc.txt").await), digest(&data));
    let mtime = std::fs::metadata(root.0.join("doc.txt"))
        .unwrap()
        .modified()
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    assert_eq!(mtime.as_secs(), 1_700_000_000);

    // delete
    let fid = s.open_ok("doc.txt", RW, disposition::OPEN, OPT_FILE).await;
    let r = s
        .call(
            Command::SetInfo,
            &set_info_body(13, fid, &disposition_info(true)),
        )
        .await;
    assert_eq!(r.status(), 0);
    s.close(fid).await;
    assert!(s.names("").await.is_empty());
    let r = s.open("doc.txt", RO, disposition::OPEN, OPT_FILE).await;
    assert_eq!(r.status(), 0xC000_0034);
}

#[tokio::test]
async fn parallel_clients_write_different_files() {
    let root = Scratch::new("parallel");
    let addr = start_server(&root.0).await;
    let mut tasks = Vec::new();
    for n in 0..4u64 {
        tasks.push(tokio::spawn(async move {
            let mut s = Session::connect(addr).await;
            let data = pseudo_random(400_000 + n as usize, n + 10);
            let name = format!("client{n}.bin");
            s.put(&name, &data).await;
            assert_eq!(digest(&s.get(&name).await), digest(&data));
            (name, digest(&data))
        }));
    }
    for t in tasks {
        let (name, want) = t.await.unwrap();
        assert_eq!(digest(&std::fs::read(root.0.join(name)).unwrap()), want);
    }
}

#[tokio::test]
async fn dropping_the_connection_releases_open_handles() {
    let root = Scratch::new("drop");
    let addr = start_server(&root.0).await;
    let mut s = Session::connect(addr).await;
    let _fid = s
        .open_ok(
            "scratch.tmp",
            RW,
            disposition::CREATE,
            OPT_FILE | OPT_DELETE_ON_CLOSE,
        )
        .await;
    assert!(root.0.join("scratch.tmp").exists());
    drop(s); // no CLOSE, no LOGOFF: the TCP connection just goes away
    for _ in 0..100 {
        if !root.0.join("scratch.tmp").exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the server did not close the handle of a dropped connection");
}

#[tokio::test]
async fn files_survive_reconnect_and_are_visible_to_a_second_client() {
    let root = Scratch::new("reconnect");
    let addr = start_server(&root.0).await;
    let data = pseudo_random(150_000, 5);
    {
        let mut s = Session::connect(addr).await;
        s.put("keep.bin", &data).await;
    }
    let mut s2 = Session::connect(addr).await;
    assert_eq!(s2.names("").await, ["keep.bin"]);
    assert_eq!(digest(&s2.get("keep.bin").await), digest(&data));
}
