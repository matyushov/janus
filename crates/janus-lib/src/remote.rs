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

use std::time::Duration;

use janus_proto::v1::PingRequest;
use janus_proto::v1::band_transport_client::BandTransportClient;
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

/// Connection parameters (from `ConfigureRequest`).
#[derive(Debug, Clone, Default)]
pub struct RemoteConfig {
    pub endpoint: String,
    /// UPGRADE(mTLS): CA + client identity.
    pub ca_pem: Vec<u8>,
    pub client_cert_path: String,
    pub client_key_path: String,
}

impl RemoteConfig {
    pub fn from_share(cfg: &crate::config::ShareConfig) -> RemoteConfig {
        RemoteConfig {
            endpoint: cfg.appliance_endpoint.clone(),
            ca_pem: cfg.ca_pem.clone(),
            client_cert_path: cfg.client_cert_path.clone(),
            client_key_path: cfg.client_key_path.clone(),
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

/// Receiver client. Holds a lazy tonic channel (the real connection is made on
/// the first call).
pub struct RemoteClient {
    client: BandTransportClient<Channel>,
    endpoint: String,
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
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30));

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

        let channel = endpoint.connect_lazy();
        Ok(RemoteClient {
            client: BandTransportClient::new(channel),
            endpoint: cfg.endpoint.clone(),
        })
    }

    /// A cheap clone of the underlying (lazy, auto-reconnecting) transport client.
    pub fn transport(&self) -> BandTransportClient<Channel> {
        self.client.clone()
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Reachability check: the only operation done by
    /// `EnsureReady`. The first call is also what opens the connection.
    pub async fn ping(&mut self) -> Result<String, RemoteError> {
        let reply = self
            .client
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
            })?
            .into_inner();
        Ok(reply.server_version)
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
