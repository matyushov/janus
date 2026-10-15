//! Router is the only process with network access: it terminates mTLS, maps cert → machine
//! → worker, forwards calls to the worker over a unix socket (the same janus-proto,
//! no second internal protocol).

#![allow(dead_code)] // skeleton

use std::collections::HashMap;

/// Machine identity from the client cert (mTLS).
/// An unknown cert is rejected already at the TLS handshake and never reaches the application.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MachineId(pub String);

/// cert → machine → store root. Cert issuance is the agent's registration channel.
#[derive(Debug, Default)]
pub struct IdentityMap {
    by_fingerprint: HashMap<String, (MachineId, std::path::PathBuf)>,
}

impl IdentityMap {
    pub fn resolve(
        &self,
        _client_cert_fingerprint: &str,
    ) -> Option<&(MachineId, std::path::PathBuf)> {
        todo!("маппинг из конфигурации аплайенса")
    }
}

/// Worker pool: spawn on a machine's first call, stop when idle
/// (the lifecycle of jails is as in rsync-proxy).
#[derive(Debug, Default)]
pub struct WorkerPool;

impl WorkerPool {
    pub fn get_or_spawn(&self, _machine: &MachineId) -> WorkerHandle {
        todo!("FreeBSD: jail без сети + nullfs store; Linux: uid+mount-ns; канал — unix-сокет")
    }
}

#[derive(Debug)]
pub struct WorkerHandle {
    // unix socket to the StoreWorker (gRPC, the same janus-proto)
}
