//! janus-proto: the shared protobuf contract (BandTransport + SmbFrontControl +
//! ReceiverControl), generated from proto/janus.proto via tonic/prost.
//!
//! Consumers: janus-smbd (server SmbFrontControl + client BandTransport),
//! janus-receiverd (server BandTransport + ReceiverControl), janus-cli
//! (client SmbFrontControl + ReceiverControl), the C++ agent (generates its own
//! from the same .proto).

/// Generated types of the `janus.v1` package.
pub mod v1 {
    tonic::include_proto!("janus.v1");
}

/// The contract text, for consumers outside Rust (the C++ agent compiles from it).
pub const JANUS_PROTO: &str = include_str!("../proto/janus.proto");

#[cfg(test)]
mod tests {
    #[test]
    fn generated_types_present() {
        // We try to construct a pair of types, which proves that codegen worked.
        let _ = super::v1::PingRequest {
            client_version: "test".into(),
        };
        let _ = super::v1::FlushPolicy::SyncThrough;
        let _ = super::v1::ClientProfile::TimeMachine;
    }
}
