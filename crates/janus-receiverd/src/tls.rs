//! mTLS for the data plane: rustls (ring provider, **TLS 1.3 only**), a client certificate
//! signed by the configured CA is mandatory. The handshake is done here, not by tonic, so the
//! protocol floor is enforced and the peer certificate fingerprint can be attached to every
//! request (`PeerInfo`, read by the router for the IdentityMap lookup).
//!
//! Private keys are never logged. Key files wider than 0600 only produce a warning.

use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tonic::transport::server::Connected;

use crate::identity::{fingerprint_of, warn_if_group_or_world_accessible};

/// How long a peer may take to finish the TLS handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct TlsPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
    /// CA that signs the **client** certificates.
    pub ca: PathBuf,
}

/// Verified identity of the TLS peer, attached to every request on the connection.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// SHA-256 of the client certificate (DER), lowercase hex.
    pub fingerprint: String,
}

fn tls_err(what: &str, path: &Path, e: impl std::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{what} {}: {e}", path.display()),
    )
}

pub fn server_config(paths: &TlsPaths) -> io::Result<Arc<rustls::ServerConfig>> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(&paths.cert)
        .map_err(|e| tls_err("certificate", &paths.cert, e))?
        .collect::<Result<_, _>>()
        .map_err(|e| tls_err("certificate", &paths.cert, e))?;
    if certs.is_empty() {
        return Err(tls_err("certificate", &paths.cert, "no certificates found"));
    }
    warn_if_group_or_world_accessible(&paths.key);
    let key = PrivateKeyDer::from_pem_file(&paths.key)
        .map_err(|e| tls_err("private key", &paths.key, e))?;

    let mut roots = RootCertStore::empty();
    for ca in CertificateDer::pem_file_iter(&paths.ca).map_err(|e| tls_err("CA", &paths.ca, e))? {
        let ca = ca.map_err(|e| tls_err("CA", &paths.ca, e))?;
        roots.add(ca).map_err(|e| tls_err("CA", &paths.ca, e))?;
    }
    if roots.is_empty() {
        return Err(tls_err("CA", &paths.ca, "no certificates found"));
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|e| tls_err("CA", &paths.ca, e))?;
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(io::Error::other)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|e| tls_err("certificate/key", &paths.cert, e))?;
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Arc::new(cfg))
}

/// An accepted, authenticated connection for tonic.
pub struct TlsConn {
    inner: tokio_rustls::server::TlsStream<TcpStream>,
    info: PeerInfo,
}

impl Connected for TlsConn {
    type ConnectInfo = PeerInfo;
    fn connect_info(&self) -> PeerInfo {
        self.info.clone()
    }
}

impl AsyncRead for TlsConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Accept loop: every TCP connection gets its own handshake task, so a slow or hostile peer
/// cannot stall others, and a failed handshake (no/foreign client certificate, TLS < 1.3,
/// garbage) only drops that connection.
pub fn incoming(
    listener: TcpListener,
    cfg: Arc<rustls::ServerConfig>,
) -> tokio_stream::wrappers::ReceiverStream<io::Result<TlsConn>> {
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    let acceptor = TlsAcceptor::from(cfg);
    tokio::spawn(async move {
        loop {
            let (tcp, peer) = tokio::select! {
                r = listener.accept() => match r {
                    Ok(x) => x,
                    Err(e) => {
                        // EMFILE and friends: back off instead of spinning or dying.
                        eprintln!("janus-receiverd: accept failed: {e}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                },
                _ = tx.closed() => return,
            };
            let acceptor = acceptor.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let hs = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await;
                let stream = match hs {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        eprintln!("janus-receiverd: TLS handshake with {peer} failed: {e}");
                        return;
                    }
                    Err(_) => {
                        eprintln!("janus-receiverd: TLS handshake with {peer} timed out");
                        return;
                    }
                };
                let Some(cert) = stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .and_then(|c| c.first())
                else {
                    return; // cannot happen with a mandatory client verifier
                };
                let info = PeerInfo {
                    fingerprint: fingerprint_of(cert.as_ref()),
                };
                let _ = tx
                    .send(Ok(TlsConn {
                        inner: stream,
                        info,
                    }))
                    .await;
            });
        }
    });
    tokio_stream::wrappers::ReceiverStream::new(rx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certs::TestPki;

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("janus-tls-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn good_material_loads_and_is_tls13_only() {
        let d = dir("ok");
        let paths = TestPki::new().write_server_files(&d);
        let cfg = server_config(&paths).unwrap();
        assert_eq!(cfg.alpn_protocols, vec![b"h2".to_vec()]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn broken_material_is_a_clear_error_naming_the_file() {
        let d = dir("bad");
        let good = TestPki::new().write_server_files(&d);
        for (which, expect) in [
            ("cert", "server.pem"),
            ("key", "server.key"),
            ("ca", "ca.pem"),
        ] {
            let mut p = good.clone();
            match which {
                "cert" => p.cert = d.join("missing.pem"),
                "key" => p.key = d.join("missing.key"),
                _ => p.ca = d.join("missing-ca.pem"),
            }
            let e = server_config(&p).unwrap_err().to_string();
            assert!(e.contains("missing"), "{which}: {e}");
            let _ = expect;
        }
        // present but not PEM
        let mut p = good.clone();
        std::fs::write(&p.ca, b"not a certificate").unwrap();
        assert!(server_config(&p).is_err());
        p = good.clone();
        std::fs::write(&p.key, b"nope").unwrap();
        assert!(server_config(&p).is_err());
        // a key that does not belong to the certificate
        let other = TestPki::new();
        let p = good;
        std::fs::write(&p.key, &other.server_key_pem).unwrap();
        assert!(server_config(&p).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
