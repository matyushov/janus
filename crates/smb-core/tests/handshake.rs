//! J1 end-to-end test: real TCP, `DevServer` and a scripted client built on the same
//! smb-wire primitives (`smb_wire::testclient`). Without a macOS client it checks the whole path
//! NEGOTIATE 3.1.1 → SESSION_SETUP (NTLMv2) → signed TREE_CONNECT/ECHO/
//! TREE_DISCONNECT/LOGOFF. The manual run with `mount_smbfs` is in the crate README.

use std::sync::Arc;

use janus_lib::control::DaemonState;
use janus_lib::credentials::CredentialStore;
use smb_core::server::{DevServer, ServerConfig};
use smb_core::transport::{read_message, write_message};
use smb_wire::Command;
use smb_wire::testclient::{
    Client, Response, frame, negotiate_body, request_header, simple_body, smb1_negotiate,
    tree_connect_body,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

const USER: &str = "janus";
const PASSWORD: &str = "integration-test-password";

async fn start_server() -> std::net::SocketAddr {
    let creds = Arc::new(CredentialStore::load(
        Some(USER.into()),
        Some(PASSWORD.into()),
        None,
    ));
    let server = Arc::new(DevServer::new(
        ServerConfig::default(),
        Arc::new(Mutex::new(DaemonState::default())),
        creds,
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { server.serve(listener).await });
    addr
}

async fn roundtrip(s: &mut TcpStream, req: &[u8]) -> Vec<u8> {
    write_message(s, req).await.unwrap();
    read_message(s)
        .await
        .unwrap()
        .expect("server closed the connection")
}

async fn login(s: &mut TcpStream, c: &mut Client) -> Response {
    let r = roundtrip(s, &c.negotiate_request()).await;
    c.on_negotiate_response(&r);
    let r1 = roundtrip(s, &c.session_setup_1()).await;
    let req2 = c.session_setup_2(&r1).unwrap();
    Response::parse(&roundtrip(s, &req2).await).unwrap()
}

#[tokio::test]
async fn full_session_over_tcp() {
    let addr = start_server().await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    let mut c = Client::new(USER, PASSWORD);

    let fin = login(&mut s, &mut c).await;
    assert_eq!(fin.status(), 0, "SESSION_SETUP");
    assert!(
        c.verify_response(&fin.raw),
        "signature of the final response"
    );

    // TREE_CONNECT to the default share ("backup", case-insensitive)
    let r = roundtrip(
        &mut s,
        &c.signed_request(
            Command::TreeConnect,
            0,
            &tree_connect_body("\\\\127.0.0.1\\Backup"),
        ),
    )
    .await;
    assert!(c.verify_response(&r));
    let tc = Response::parse(&r).unwrap();
    assert_eq!(tc.status(), 0, "TREE_CONNECT");
    let tid = tc.header().tree_id;
    assert_ne!(tid, 0);

    // unknown share
    let r = roundtrip(
        &mut s,
        &c.signed_request(
            Command::TreeConnect,
            0,
            &tree_connect_body("\\\\127.0.0.1\\nope"),
        ),
    )
    .await;
    assert_eq!(Response::parse(&r).unwrap().status(), 0xC000_00CC);

    // ECHO, TREE_DISCONNECT, LOGOFF: all replies are signed
    for (cmd, tree) in [
        (Command::Echo, 0),
        (Command::TreeDisconnect, tid),
        (Command::Logoff, 0),
    ] {
        let r = roundtrip(&mut s, &c.signed_request(cmd, tree, &simple_body())).await;
        assert!(c.verify_response(&r), "{cmd:?}");
        assert_eq!(Response::parse(&r).unwrap().status(), 0, "{cmd:?}");
    }
}

#[tokio::test]
async fn unsigned_request_after_login_is_rejected_over_tcp() {
    let addr = start_server().await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    let mut c = Client::new(USER, PASSWORD);
    assert_eq!(login(&mut s, &mut c).await.status(), 0);

    let h = request_header(Command::TreeConnect, c.next_message_id(), c.session_id, 0);
    let r = roundtrip(&mut s, &frame(&h, &tree_connect_body("\\\\h\\backup"))).await;
    assert_eq!(Response::parse(&r).unwrap().status(), 0xC000_0022);
}

#[tokio::test]
async fn wrong_password_fails_and_third_failure_drops_the_connection() {
    let addr = start_server().await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    let r = roundtrip(&mut s, &Client::new(USER, "x").negotiate_request()).await;
    assert_eq!(Response::parse(&r).unwrap().status(), 0);

    for attempt in 1..=3 {
        let mut c = Client::new(USER, "wrong");
        c.message_id = 1;
        let r1 = roundtrip(&mut s, &c.session_setup_1()).await;
        let req2 = c.session_setup_2(&r1).unwrap();
        let r = Response::parse(&roundtrip(&mut s, &req2).await).unwrap();
        assert_eq!(r.status(), 0xC000_006D, "attempt {attempt}");
    }
    // after the third failure the server closes the connection
    assert!(read_message(&mut s).await.unwrap().is_none());
}

#[tokio::test]
async fn client_without_311_is_refused() {
    let addr = start_server().await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    let h = request_header(Command::Negotiate, 0, 0, 0);
    let req = frame(
        &h,
        &negotiate_body(&[0x0202, 0x0210, 0x0300, 0x0302], false, &[]),
    );
    let r = roundtrip(&mut s, &req).await;
    assert_eq!(Response::parse(&r).unwrap().status(), 0xC000_00BB);
}

#[tokio::test]
async fn smb1_without_smb2_dialects_is_dropped() {
    let addr = start_server().await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    write_message(&mut s, &smb1_negotiate(&["NT LM 0.12"]))
        .await
        .unwrap();
    assert!(read_message(&mut s).await.unwrap().is_none());
}

/// How macOS `mount_smbfs` behaves: SMB1 multi-protocol NEGOTIATE → wildcard 0x02FF →
/// the real SMB2 NEGOTIATE 3.1.1 → SESSION_SETUP → TREE_CONNECT.
#[tokio::test]
async fn macos_style_start_with_smb1_multiprotocol_negotiate() {
    let addr = start_server().await;
    let mut s = TcpStream::connect(addr).await.unwrap();
    let r = roundtrip(
        &mut s,
        &smb1_negotiate(&["NT LM 0.12", "SMB 2.002", "SMB 2.???"]),
    )
    .await;
    let p = Response::parse(&r).unwrap();
    assert_eq!(
        u16::from_le_bytes([p.message.body[4], p.message.body[5]]),
        0x02FF
    );

    let mut c = Client::new(USER, PASSWORD);
    assert_eq!(login(&mut s, &mut c).await.status(), 0);
    let r = roundtrip(
        &mut s,
        &c.signed_request(
            Command::TreeConnect,
            0,
            &tree_connect_body("\\\\127.0.0.1\\backup"),
        ),
    )
    .await;
    assert!(c.verify_response(&r));
    assert_eq!(Response::parse(&r).unwrap().status(), 0);
}

#[tokio::test]
async fn parallel_connections_get_distinct_sessions() {
    let addr = start_server().await;
    let mut ids = Vec::new();
    for _ in 0..3 {
        let mut s = TcpStream::connect(addr).await.unwrap();
        let mut c = Client::new(USER, PASSWORD);
        assert_eq!(login(&mut s, &mut c).await.status(), 0);
        ids.push(c.session_id);
    }
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 3);
}
