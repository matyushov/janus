//! mTLS and per-machine isolation, end to end: `GrpcBackend`/`RemoteClient` against a real
//! production-mode receiver (TLS 1.3, client certificates, IdentityMap) on loopback, with a
//! throw-away PKI.

#![cfg(feature = "backend-grpc")]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use janus_lib::grpc_backend::{GrpcBackend, RetryPolicy};
use janus_lib::remote::{RemoteClient, RemoteConfig, RemoteError};
use janus_lib::vfs::{BackendError, Disposition, Kind, OpenRequest, StorageBackend};
use janus_receiverd::certs::{ClientIdentity, TestPki};
use janus_receiverd::identity::IdentityMap;
use janus_receiverd::router::Router;
use janus_receiverd::server::serve_router_on_listener;
use janus_receiverd::tls;

struct Rig {
    dir: PathBuf,
    pki: TestPki,
    addr: std::net::SocketAddr,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for Rig {
    fn drop(&mut self) {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn tmp(tag: &str) -> PathBuf {
    let mut r = [0u8; 8];
    getrandom::fill(&mut r).unwrap();
    let d = std::env::temp_dir().join(format!("janus-mtls-{tag}-{}", u64::from_le_bytes(r)));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// `machines`: (id, client identity, quota). Store of machine `id` is `<dir>/stores/<id>`.
async fn start(tag: &str, pki: TestPki, machines: &[(&str, &ClientIdentity, u64)]) -> Rig {
    let dir = tmp(tag);
    let paths = pki.write_server_files(&dir.join("tls"));
    let entries: Vec<String> = machines
        .iter()
        .map(|(id, c, q)| {
            format!(
                r#"{{"id":"{id}","fingerprint":"{}","store":"{id}","quota_bytes":{q}}}"#,
                c.fingerprint
            )
        })
        .collect();
    let json = format!(r#"{{"machines":[{}]}}"#, entries.join(","));
    let map = IdentityMap::from_json(json.as_bytes(), &dir.join("stores"), 0).unwrap();
    let router = Arc::new(Router::mapped(map));
    let cfg = tls::server_config(&paths).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = serve_router_on_listener(listener, router, Some(cfg), async {
            let _ = rx.await;
        })
        .await;
    });
    Rig {
        dir,
        pki,
        addr,
        stop: Some(tx),
    }
}

impl Rig {
    fn remote_cfg(&self, id: &ClientIdentity, stem: &str) -> RemoteConfig {
        let (cert, key) = id.write_files(&self.dir.join("client"), stem);
        RemoteConfig {
            endpoint: self.addr.to_string(),
            ca_pem: self.pki.ca_pem.clone().into_bytes(),
            client_cert_path: cert,
            client_key_path: key,
            ..Default::default()
        }
    }

    fn backend(&self, id: &ClientIdentity, stem: &str) -> GrpcBackend {
        let remote = RemoteClient::connect_lazy(&self.remote_cfg(id, stem)).unwrap();
        GrpcBackend::from_remote(&remote, 0).with_retry(RetryPolicy {
            attempts: 1,
            base_delay: Duration::from_millis(10),
        })
    }

    fn store(&self, id: &str) -> PathBuf {
        self.dir.join("stores").join(id)
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

async fn put(b: &GrpcBackend, path: &str, data: &[u8]) {
    let o = b
        .open(path, req(Disposition::Create, Kind::File))
        .await
        .unwrap();
    b.write(o.handle, 0, data).await.unwrap();
    b.close(o.handle).await.unwrap();
}

#[tokio::test]
async fn enrolled_client_works_over_mtls() {
    let pki = TestPki::new();
    let a = pki.issue_client("mac-a");
    let rig = start("ok", pki, &[("mac-a", &a, 0)]).await;

    let mut remote = RemoteClient::connect_lazy(&rig.remote_cfg(&a, "a")).unwrap();
    assert!(!remote.ping().await.unwrap().is_empty());

    let b = rig.backend(&a, "a");
    put(&b, "hello.txt", b"over mtls").await;
    assert_eq!(
        std::fs::read(rig.store("mac-a").join("hello.txt")).unwrap(),
        b"over mtls"
    );
}

#[tokio::test]
async fn client_without_a_certificate_is_rejected_by_tls() {
    let pki = TestPki::new();
    let a = pki.issue_client("mac-a");
    let rig = start("nocert", pki, &[("mac-a", &a, 0)]).await;

    // trusts the server CA, presents no identity
    let ch = tonic::transport::Endpoint::from_shared(format!("https://{}", rig.addr))
        .unwrap()
        .tls_config(
            tonic::transport::ClientTlsConfig::new()
                .ca_certificate(tonic::transport::Certificate::from_pem(&rig.pki.ca_pem)),
        )
        .unwrap()
        .connect_timeout(Duration::from_secs(5))
        .connect_lazy();
    let mut c = janus_proto::v1::band_transport_client::BandTransportClient::new(ch);
    let r = c
        .ping(janus_proto::v1::PingRequest {
            client_version: "t".into(),
        })
        .await;
    assert!(janus_lib::remote::is_transport_failure(&r.unwrap_err()));
    assert!(
        !rig.store("mac-a").exists(),
        "nothing reached the application"
    );
}

#[tokio::test]
async fn client_certificate_from_a_foreign_ca_is_rejected_by_tls() {
    let pki = TestPki::new();
    let a = pki.issue_client("mac-a");
    let rig = start("foreignclient", pki, &[("mac-a", &a, 0)]).await;

    let foreign = TestPki::new().issue_client("mac-a"); // same name, other CA
    let b = rig.backend(&foreign, "foreign");
    let e = b.stat("").await.unwrap_err();
    assert!(matches!(e, BackendError::RemoteUnavailable), "{e:?}");
    assert!(!rig.store("mac-a").exists());
}

#[tokio::test]
async fn client_rejects_a_server_certificate_from_an_unknown_ca() {
    let pki = TestPki::new();
    let a = pki.issue_client("mac-a");
    let rig = start("foreignserver", pki, &[("mac-a", &a, 0)]).await;

    let mut cfg = rig.remote_cfg(&a, "a");
    cfg.ca_pem = TestPki::new().ca_pem.into_bytes(); // client trusts someone else
    let mut remote = RemoteClient::connect_lazy(&cfg).unwrap();
    assert!(matches!(
        remote.ping().await,
        Err(RemoteError::Unreachable(_))
    ));
}

#[tokio::test]
async fn a_certificate_signed_by_our_ca_but_not_enrolled_is_permission_denied() {
    let pki = TestPki::new();
    let a = pki.issue_client("mac-a");
    let stranger = pki.issue_client("stranger");
    let rig = start("unenrolled", pki, &[("mac-a", &a, 0)]).await;

    let b = rig.backend(&stranger, "stranger");
    for r in [
        b.stat("").await.map(|_| ()),
        b.list("").await.map(|_| ()),
        b.statfs().await.map(|_| ()),
        b.open("f", req(Disposition::Create, Kind::File))
            .await
            .map(|_| ()),
    ] {
        assert!(matches!(r, Err(BackendError::AccessDenied)), "{r:?}");
    }
    assert!(!rig.store("stranger").exists());
    // and the enrolled one is unaffected
    assert!(rig.backend(&a, "a").stat("").await.is_ok());
}

#[tokio::test]
async fn machines_are_isolated_from_each_other() {
    let pki = TestPki::new();
    let a = pki.issue_client("mac-a");
    let b = pki.issue_client("mac-b");
    let rig = start(
        "isolation",
        pki,
        &[("mac-a", &a, 1000), ("mac-b", &b, 5000)],
    )
    .await;
    let (ba, bb) = (rig.backend(&a, "a"), rig.backend(&b, "b"));

    put(&ba, "secret.txt", b"A's data").await;
    ba.open("dir", req(Disposition::Create, Kind::Directory))
        .await
        .map(|o| o.handle)
        .unwrap();
    put(&bb, "own.txt", b"B's data!").await;

    // B does not see A's files, by listing or by name
    let names: Vec<_> = bb
        .list("")
        .await
        .unwrap()
        .into_iter()
        .map(|s| s.name)
        .collect();
    assert_eq!(names, ["own.txt"]);
    assert!(matches!(
        bb.stat("secret.txt").await,
        Err(BackendError::NotFound)
    ));
    assert!(matches!(
        bb.open("secret.txt", req(Disposition::Open, Kind::File))
            .await,
        Err(BackendError::NotFound)
    ));

    // ...nor by walking out of its store
    for p in [
        "../mac-a/secret.txt",
        "a/../../mac-a/secret.txt",
        "/mac-a/secret.txt",
        "..\\mac-a\\secret.txt",
    ] {
        let r = bb
            .open(p, req(Disposition::Open, Kind::File))
            .await
            .map(|_| ());
        assert!(
            matches!(
                r,
                Err(BackendError::AccessDenied) | Err(BackendError::NotFound)
            ),
            "{p}: {r:?}"
        );
        assert!(
            matches!(
                bb.list(p).await,
                Err(BackendError::AccessDenied) | Err(BackendError::NotFound)
            ),
            "list {p}"
        );
    }
    // raw wire requests bypass the client-side path checks: the server must hold the line too
    let remote_b = RemoteClient::connect_lazy(&rig.remote_cfg(&b, "b")).unwrap();
    let mut raw = remote_b.transport();
    for p in [
        "../mac-a/secret.txt",
        "/mac-a/secret.txt",
        "a/../../mac-a/secret.txt",
    ] {
        let r = raw
            .read_range(janus_proto::v1::ReadRangeRequest {
                file: Some(janus_proto::v1::FileRef { rel_path: p.into() }),
                offset: 0,
                length: 10,
            })
            .await;
        assert_eq!(r.unwrap_err().code(), tonic::Code::PermissionDenied, "{p}");
        let w = raw
            .write_range(janus_proto::v1::WriteRangeRequest {
                file: Some(janus_proto::v1::FileRef { rel_path: p.into() }),
                offset: 0,
                data: b"pwn".to_vec(),
                write_id: 1,
            })
            .await;
        assert_eq!(w.unwrap_err().code(), tonic::Code::PermissionDenied, "{p}");
    }
    assert_eq!(
        std::fs::read(rig.store("mac-a").join("secret.txt")).unwrap(),
        b"A's data"
    );

    // each machine's volume numbers are its own
    let (sa, sb) = (ba.statfs().await.unwrap(), bb.statfs().await.unwrap());
    assert_eq!((sa.quota_bytes, sa.used_bytes), (1000, 8));
    assert_eq!((sb.quota_bytes, sb.used_bytes), (5000, 9));

    // A's quota is A's alone
    let o = ba
        .open("big", req(Disposition::Create, Kind::File))
        .await
        .unwrap();
    assert!(matches!(
        ba.write(o.handle, 0, &[0u8; 2000]).await,
        Err(BackendError::NoSpace)
    ));
    let o = bb
        .open("big", req(Disposition::Create, Kind::File))
        .await
        .unwrap();
    bb.write(o.handle, 0, &[0u8; 2000]).await.unwrap();
}

#[tokio::test]
async fn two_clients_use_distinct_stores_on_disk() {
    let pki = TestPki::new();
    let a = pki.issue_client("mac-a");
    let b = pki.issue_client("mac-b");
    let rig = start("stores", pki, &[("mac-a", &a, 0), ("mac-b", &b, 0)]).await;
    put(&rig.backend(&a, "a"), "same-name", b"from a").await;
    put(&rig.backend(&b, "b"), "same-name", b"from b").await;
    assert_eq!(
        std::fs::read(rig.store("mac-a").join("same-name")).unwrap(),
        b"from a"
    );
    assert_eq!(
        std::fs::read(rig.store("mac-b").join("same-name")).unwrap(),
        b"from b"
    );
}

#[tokio::test]
async fn tls_1_2_only_clients_cannot_connect() {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};

    let pki = TestPki::new();
    let a = pki.issue_client("mac-a");
    let rig = start("tls12", pki, &[("mac-a", &a, 0)]).await;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(rig.pki.ca_pem.as_bytes()).unwrap())
        .unwrap();
    let chain = vec![CertificateDer::from_pem_slice(a.cert_pem.as_bytes()).unwrap()];
    let key = PrivateKeyDer::from_pem_slice(a.key_pem.as_bytes()).unwrap();
    let mk = |versions: &[&'static rustls::SupportedProtocolVersion]| {
        Arc::new(
            rustls::ClientConfig::builder_with_provider(provider.clone())
                .with_protocol_versions(versions)
                .unwrap()
                .with_root_certificates(roots.clone())
                .with_client_auth_cert(chain.clone(), key.clone_key())
                .unwrap(),
        )
    };
    let try_connect = |cfg: Arc<rustls::ClientConfig>| async move {
        let tcp = tokio::net::TcpStream::connect(rig.addr).await.unwrap();
        let name = ServerName::try_from("localhost").unwrap();
        tokio_rustls::TlsConnector::from(cfg)
            .connect(name, tcp)
            .await
            .map(|_| ())
    };
    assert!(try_connect(mk(&[&rustls::version::TLS12])).await.is_err());
    assert!(try_connect(mk(&[&rustls::version::TLS13])).await.is_ok());
}

#[tokio::test]
async fn garbage_and_plain_text_connections_do_not_hurt_the_server() {
    use tokio::io::AsyncWriteExt;
    let pki = TestPki::new();
    let a = pki.issue_client("mac-a");
    let rig = start("garbage", pki, &[("mac-a", &a, 0)]).await;

    for payload in [
        &b"GET / HTTP/1.1\r\n\r\n"[..],
        &[0u8; 64][..],
        &[0x16, 3, 3, 0xff, 0xff][..],
        &b""[..],
    ] {
        let mut s = tokio::net::TcpStream::connect(rig.addr).await.unwrap();
        let _ = s.write_all(payload).await;
        drop(s);
    }
    // a plain-gRPC client (the dev transport) is not served either
    let plain = RemoteClient::connect_lazy(&RemoteConfig {
        endpoint: rig.addr.to_string(),
        ..Default::default()
    })
    .unwrap();
    let mut plain = plain;
    assert!(plain.ping().await.is_err());

    // the real client still works
    assert!(rig.backend(&a, "a").stat("").await.is_ok());
}

#[tokio::test]
async fn tls_configuration_mistakes_are_errors_not_silent_downgrades() {
    let base = RemoteConfig {
        endpoint: "127.0.0.1:1".into(),
        ..Default::default()
    };
    // CA only
    let c = RemoteConfig {
        ca_pem: b"x".to_vec(),
        ..base.clone()
    };
    assert!(matches!(
        RemoteClient::connect_lazy(&c),
        Err(RemoteError::Tls(_))
    ));
    // https without any TLS material
    let c = RemoteConfig {
        endpoint: "https://127.0.0.1:1".into(),
        ..base.clone()
    };
    assert!(matches!(
        RemoteClient::connect_lazy(&c),
        Err(RemoteError::Tls(_))
    ));
    // TLS material with an http:// endpoint
    let c = RemoteConfig {
        endpoint: "http://127.0.0.1:1".into(),
        ca_pem: b"x".to_vec(),
        client_cert_path: "c".into(),
        client_key_path: "k".into(),
        ..Default::default()
    };
    assert!(matches!(
        RemoteClient::connect_lazy(&c),
        Err(RemoteError::Tls(_))
    ));
    // unreadable files
    let c = RemoteConfig {
        ca_pem: b"x".to_vec(),
        client_cert_path: "/nonexistent/c.pem".into(),
        client_key_path: "/nonexistent/k.pem".into(),
        ..base
    };
    assert!(matches!(
        RemoteClient::connect_lazy(&c),
        Err(RemoteError::Tls(_))
    ));
}

#[allow(dead_code)]
fn _unused(_: &Path) {}
