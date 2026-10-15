//! Client to the receiving side (`janus-receiverd`, the `BandTransport` service).
//!
//! The daemon does NOT look for the server itself and has no hard-wired addresses: the endpoint arrives in
//! `Configure` (the control plane), and the channel is built here.
//!
//! The connection is LAZY: there is no point holding TCP between backups. The channel opens on
//! the first operation or an explicit check (`EnsureReady` → `ping`).
//!
//! MILESTONE (dev): plain gRPC. UPGRADE(mTLS): `ClientTlsConfig` with a CA + the client
//! identity (`tls_identity_ref` from the Keychain, or `client_cert_path`/
//! `client_key_path` for file mode).

use std::time::Duration;

use janus_proto::v1::PingRequest;
use janus_proto::v1::band_transport_client::BandTransportClient;
use tonic::transport::{Channel, Endpoint};

/// Errors of communication with the receiver, in terms the control plane understands.
#[derive(Debug)]
pub enum RemoteError {
    /// Incorrect endpoint in the configuration.
    BadEndpoint(String),
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
    pub fn tls_configured(&self) -> bool {
        !self.ca_pem.is_empty()
            && !self.client_cert_path.is_empty()
            && !self.client_key_path.is_empty()
    }
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
        // We add the scheme ourselves: in the config the user writes host:port.
        let uri = if cfg.endpoint.starts_with("http://") || cfg.endpoint.starts_with("https://") {
            cfg.endpoint.clone()
        } else {
            format!("http://{}", cfg.endpoint)
        };

        let endpoint = Endpoint::from_shared(uri.clone())
            .map_err(|e| RemoteError::BadEndpoint(e.to_string()))?
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30));

        // TODO(mTLS): when tls_configured(), endpoint.tls_config(ClientTlsConfig
        // ::new().ca_certificate(..).identity(Identity::from_pem(cert, key)))
        // and the https scheme.

        let channel = endpoint.connect_lazy();
        Ok(RemoteClient {
            client: BandTransportClient::new(channel),
            endpoint: cfg.endpoint.clone(),
        })
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
                // Transport problems arrive as a Status with the Unavailable code.
                if s.code() == tonic::Code::Unavailable {
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
