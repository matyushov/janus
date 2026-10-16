//! Client to the receiving side (`janus-receiverd`, the `BandTransport` service).
//!
//! The daemon does NOT look for the server itself and has no hard-wired addresses: the endpoint arrives in
//! `Configure` (the control plane), and the channel is built here.
//!
//! The connection is LAZY: there is no point holding TCP between backups. The channel opens on
//! the first operation or an explicit check (`EnsureReady` → `ping`).
//!
//! Transport security: with a CA and a client identity (`client_cert_path`/`client_key_path`
//! PEM files) the channel is mTLS (rustls, ring provider; the receiver insists on TLS 1.3 and a
//! client certificate signed by its CA). With none of the three set it is plain gRPC (dev
//! receiver). A partial set is a configuration error, never a silent downgrade.
//! UPGRADE(keychain): `tls_identity_ref` (client identity from the macOS Keychain) is not
//! implemented; only the file mode is.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use janus_proto::v1::PingRequest;
use janus_proto::v1::band_transport_client::BandTransportClient;
use tonic::codec::CompressionEncoding;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

/// Errors of communication with the receiver, in terms the control plane understands.
#[derive(Debug)]
pub enum RemoteError {
    /// Incorrect endpoint in the configuration.
    BadEndpoint(String),
    /// Incomplete or unreadable TLS material.
    Tls(String),
    /// The server is unreachable (no network, not running, TLS refusal).
    Unreachable(String),
    /// The server answered the request with an error. Boxed: `Status` is large and we do not
    /// want a bloated Err variant in hot signatures (clippy).
    Rpc(Box<tonic::Status>),
}

impl std::fmt::Display for RemoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RemoteError::BadEndpoint(e) => write!(f, "invalid endpoint: {e}"),
            RemoteError::Tls(e) => write!(f, "TLS configuration: {e}"),
            RemoteError::Unreachable(e) => write!(f, "receiver unreachable: {e}"),
            RemoteError::Rpc(s) => write!(f, "RPC error: {s}"),
        }
    }
}

impl std::error::Error for RemoteError {}

/// Time limits of the receiver link. Defaults are tuned so that one SMB operation, retries
/// included, fails well before the macOS SMB client gives up on its own (`max_resp_timeout`,
/// 30 s by default); see the `janus-lib` README for the reasoning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// TCP + TLS connect, per attempt.
    pub connect: Duration,
    /// One ordinary RPC attempt.
    pub request: Duration,
    /// One `ReadRange`/`WriteRange` attempt (payloads up to 1 MiB over a slow link).
    pub bulk_request: Duration,
    /// While the receiver is considered down (the last operation failed on transport), every
    /// call is a single probe of at most this long, so a retrying client burns through its
    /// attempts quickly instead of waiting a full budget each time. Any success clears it.
    pub degraded_probe: Duration,
    /// After a failed probe, calls fail immediately (no network) for this long, then the next
    /// call probes again. Keeps a client that retries in a loop from queueing probes.
    pub fail_fast: Duration,
    /// Total time for one backend operation, all attempts and backoff included.
    pub budget: Duration,
    /// HTTP/2 PING interval (also while idle, so a silent peer is noticed).
    pub keepalive_interval: Duration,
    /// How long to wait for the PING ack before the connection is declared dead.
    pub keepalive_timeout: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Timeouts {
            connect: DEFAULT_CONNECT_TIMEOUT,
            request: DEFAULT_REQUEST_TIMEOUT,
            bulk_request: DEFAULT_BULK_REQUEST_TIMEOUT,
            degraded_probe: DEFAULT_DEGRADED_PROBE,
            fail_fast: DEFAULT_FAIL_FAST,
            budget: DEFAULT_OPERATION_BUDGET,
            keepalive_interval: DEFAULT_KEEPALIVE_INTERVAL,
            keepalive_timeout: DEFAULT_KEEPALIVE_TIMEOUT,
        }
    }
}

pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(4);
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(6);
pub const DEFAULT_BULK_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_DEGRADED_PROBE: Duration = Duration::from_secs(2);
pub const DEFAULT_FAIL_FAST: Duration = Duration::from_secs(2);
/// Connections in the pool unless the config says otherwise.
pub const DEFAULT_CONNECTIONS: usize = 4;
/// Calls in flight per connection (tower limit; further calls wait for a slot).
const MAX_CALLS_PER_CONNECTION: usize = 128;
pub const DEFAULT_OPERATION_BUDGET: Duration = Duration::from_secs(18);
pub const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);
pub const DEFAULT_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(3);

/// Connection parameters (from `ConfigureRequest`).
#[derive(Debug, Clone, Default)]
pub struct RemoteConfig {
    pub endpoint: String,
    /// No zstd at all: requests are sent plain and compressed replies are not asked for.
    pub no_compression: bool,
    /// Parallel HTTP/2 connections to the receiver (0 = `DEFAULT_CONNECTIONS`). One TCP
    /// stream does not fill a lossy link; bulk calls are spread over the pool round-robin.
    pub connections: usize,
    /// UPGRADE(mTLS): CA + client identity.
    pub ca_pem: Vec<u8>,
    pub client_cert_path: String,
    pub client_key_path: String,
    pub timeouts: Timeouts,
}

impl RemoteConfig {
    pub fn from_share(cfg: &crate::config::ShareConfig) -> RemoteConfig {
        RemoteConfig {
            endpoint: cfg.appliance_endpoint.clone(),
            no_compression: false,
            connections: 0,
            ca_pem: cfg.ca_pem.clone(),
            client_cert_path: cfg.client_cert_path.clone(),
            client_key_path: cfg.client_key_path.clone(),
            timeouts: Timeouts::default(),
        }
    }

    pub fn tls_configured(&self) -> bool {
        !self.ca_pem.is_empty()
            && !self.client_cert_path.is_empty()
            && !self.client_key_path.is_empty()
    }

    fn tls_partially_configured(&self) -> bool {
        !self.tls_configured()
            && (!self.ca_pem.is_empty()
                || !self.client_cert_path.is_empty()
                || !self.client_key_path.is_empty())
    }
}

/// `true` when the status comes from the transport rather than from the receiver's code:
/// `UNAVAILABLE` (cannot connect) or tonic's `UNKNOWN: transport error` (connection lost, TLS
/// alert such as a rejected client certificate).
pub fn is_transport_failure(s: &tonic::Status) -> bool {
    s.code() == tonic::Code::Unavailable
        || (s.code() == tonic::Code::Unknown && s.message().starts_with("transport error"))
}

/// A private key readable by group/others deserves a warning (unix); never fatal.
fn warn_if_wide(path: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(md) = std::fs::metadata(path)
            && md.permissions().mode() & 0o077 != 0
        {
            eprintln!(
                "janus: warning: {path} is accessible by group/others (mode {:o}); expected 0600",
                md.permissions().mode() & 0o777
            );
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// The receiver says in its `Ping` reply that it can read zstd-compressed requests
/// (tonic itself only reports `grpc-accept-encoding` when it rejects an encoding).
pub fn accepts_zstd(md: &tonic::metadata::MetadataMap) -> bool {
    md.get("janus-accept-encoding")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|e| e.trim() == "zstd"))
}

/// Receiver client. Holds a lazy tonic channel (the real connection is made on
/// the first call).
pub struct RemoteClient {
    /// Never empty. Index 0 also serves control calls (`ping`).
    clients: Vec<BandTransportClient<Channel>>,
    /// The same channels, sending zstd-compressed requests. Used only once `zstd` is set.
    zstd_clients: Vec<BandTransportClient<Channel>>,
    /// The receiver advertised zstd in a reply (see `ping`).
    zstd: Arc<AtomicBool>,
    no_compression: bool,
    endpoint: String,
    timeouts: Timeouts,
}

impl RemoteClient {
    /// Build the client. The channel is lazy: the network is not touched here.
    pub fn connect_lazy(cfg: &RemoteConfig) -> Result<RemoteClient, RemoteError> {
        if cfg.tls_partially_configured() {
            return Err(RemoteError::Tls(
                "ca_pem, client_cert_path and client_key_path must be set together".into(),
            ));
        }
        let tls = cfg.tls_configured();
        // We add the scheme ourselves: in the config the user writes host:port.
        let uri = if let Some(rest) = cfg.endpoint.strip_prefix("https://") {
            if !tls {
                return Err(RemoteError::Tls(
                    "an https:// endpoint needs ca_pem, client_cert_path and client_key_path"
                        .into(),
                ));
            }
            format!("https://{rest}")
        } else if cfg.endpoint.starts_with("http://") {
            if tls {
                return Err(RemoteError::Tls(
                    "TLS material is configured but the endpoint is http://".into(),
                ));
            }
            cfg.endpoint.clone()
        } else if tls {
            format!("https://{}", cfg.endpoint)
        } else {
            format!("http://{}", cfg.endpoint)
        };

        let mut endpoint = Endpoint::from_shared(uri.clone())
            .map_err(|e| RemoteError::BadEndpoint(e.to_string()))?
            .connect_timeout(cfg.timeouts.connect)
            // Hard ceiling for any single request; the backend applies tighter per-attempt limits.
            .timeout(cfg.timeouts.budget)
            .http2_keep_alive_interval(cfg.timeouts.keepalive_interval)
            .keep_alive_timeout(cfg.timeouts.keepalive_timeout)
            .keep_alive_while_idle(true)
            .concurrency_limit(MAX_CALLS_PER_CONNECTION);

        if tls {
            let read = |what: &str, path: &str| {
                std::fs::read(path).map_err(|e| RemoteError::Tls(format!("{what} {path}: {e}")))
            };
            let cert = read("client certificate", &cfg.client_cert_path)?;
            warn_if_wide(&cfg.client_key_path);
            let key = read("client key", &cfg.client_key_path)?;
            endpoint = endpoint
                .tls_config(
                    ClientTlsConfig::new()
                        .ca_certificate(Certificate::from_pem(&cfg.ca_pem))
                        .identity(Identity::from_pem(cert, key)),
                )
                .map_err(|e| RemoteError::Tls(e.to_string()))?;
        }

        let n = match cfg.connections {
            0 => DEFAULT_CONNECTIONS,
            n => n,
        };
        // Each `connect_lazy` channel owns its own connection and reconnects by itself.
        let channels: Vec<Channel> = (0..n).map(|_| endpoint.connect_lazy()).collect();
        let no_zstd = cfg.no_compression;
        let plain = |c: &Channel| {
            let client = BandTransportClient::new(c.clone());
            if no_zstd {
                client
            } else {
                client.accept_compressed(CompressionEncoding::Zstd)
            }
        };
        let clients = channels.iter().map(plain).collect();
        let zstd_clients = channels
            .iter()
            .map(|c| plain(c).send_compressed(CompressionEncoding::Zstd))
            .collect();
        Ok(RemoteClient {
            clients,
            zstd_clients,
            zstd: Arc::new(AtomicBool::new(false)),
            no_compression: no_zstd,
            endpoint: cfg.endpoint.clone(),
            timeouts: cfg.timeouts,
        })
    }

    /// A cheap clone of the underlying (lazy, auto-reconnecting) transport client.
    pub fn transport(&self) -> BandTransportClient<Channel> {
        self.clients[0].clone()
    }

    /// Clones of every pooled transport client (see `RemoteConfig::connections`).
    pub fn transports(&self) -> Vec<BandTransportClient<Channel>> {
        self.clients.clone()
    }

    /// The pool again, sending compressed requests, with the switch that says whether the
    /// receiver is known to accept them (set by `ping`).
    pub fn compression_allowed(&self) -> bool {
        !self.no_compression
    }

    pub fn compressed_transports(&self) -> (Vec<BandTransportClient<Channel>>, Arc<AtomicBool>) {
        (self.zstd_clients.clone(), Arc::clone(&self.zstd))
    }

    pub fn timeouts(&self) -> Timeouts {
        self.timeouts
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Reachability check: the only operation done by
    /// `EnsureReady`. The first call is also what opens the connection.
    pub async fn ping(&mut self) -> Result<String, RemoteError> {
        let reply = self.clients[0]
            .ping(PingRequest {
                client_version: env!("CARGO_PKG_VERSION").to_string(),
            })
            .await
            .map_err(|s| {
                // Transport problems (including TLS refusals) arrive as a transport status.
                if is_transport_failure(&s) {
                    RemoteError::Unreachable(s.message().to_string())
                } else {
                    RemoteError::Rpc(Box::new(s))
                }
            })?;
        if !self.no_compression && accepts_zstd(reply.metadata()) {
            self.zstd.store(true, Ordering::Relaxed);
        }
        Ok(reply.into_inner().server_version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // connect_lazy needs a tokio context (hyper registers timers).
    #[tokio::test]
    async fn endpoint_gets_scheme_added() {
        let cfg = RemoteConfig {
            endpoint: "vault:7443".into(),
            ..Default::default()
        };
        // Must not panic and must accept host:port without a scheme.
        let client = RemoteClient::connect_lazy(&cfg).expect("lazy connect");
        assert_eq!(client.endpoint(), "vault:7443");
    }

    #[test]
    fn bad_endpoint_rejected() {
        let cfg = RemoteConfig {
            endpoint: "not a valid uri!!".into(),
            ..Default::default()
        };
        assert!(RemoteClient::connect_lazy(&cfg).is_err());
    }

    #[test]
    fn tls_configured_requires_all_three() {
        let mut cfg = RemoteConfig {
            endpoint: "x:1".into(),
            ..Default::default()
        };
        assert!(!cfg.tls_configured());
        cfg.ca_pem = b"ca".to_vec();
        cfg.client_cert_path = "c.pem".into();
        assert!(!cfg.tls_configured(), "without a key — not configured");
        cfg.client_key_path = "k.pem".into();
        assert!(cfg.tls_configured());
    }
}

#[cfg(test)]
mod pool_tests {
    use super::*;

    #[tokio::test]
    async fn pool_size_follows_the_config_and_is_never_empty() {
        let cfg = |connections| RemoteConfig {
            endpoint: "127.0.0.1:1".into(),
            connections,
            ..Default::default()
        };
        let n = |c| {
            RemoteClient::connect_lazy(&cfg(c))
                .unwrap()
                .transports()
                .len()
        };
        assert_eq!(n(3), 3);
        assert_eq!(n(1), 1);
        assert!(n(0) >= 1);
    }
}
