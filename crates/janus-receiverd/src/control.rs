//! The receiver's control plane (`ReceiverControl`): this is where
//! `janus-cli server …` and appliance orchestration come.
//!
//! The daemon runs permanently and waits for instructions on a fixed loopback port
//! (50052). The data plane (`BandTransport`) is a separate network listener.

use std::sync::Arc;

use janus_proto::v1::receiver_control_server::ReceiverControl;
use janus_proto::v1::{
    Ack, DiagnosticsBundle, Empty, MachineInfo, MachineList, ReceiverEvent, ReceiverStatusReply,
};
use tonic::{Request, Response, Status};

use crate::router::Router;

/// Receiver state visible to the control plane.
pub struct ReceiverState {
    pub router: Arc<Router>,
    /// Daemon stop signal (on the Shutdown command).
    pub shutdown: tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

pub struct ReceiverControlService {
    state: Arc<ReceiverState>,
    version: &'static str,
}

impl ReceiverControlService {
    pub fn new(state: Arc<ReceiverState>) -> Self {
        ReceiverControlService {
            state,
            version: env!("CARGO_PKG_VERSION"),
        }
    }
}

#[tonic::async_trait]
impl ReceiverControl for ReceiverControlService {
    async fn status(&self, _req: Request<Empty>) -> Result<Response<ReceiverStatusReply>, Status> {
        let machines = self.state.router.snapshot();
        Ok(Response::new(ReceiverStatusReply {
            active_workers: self.state.router.active_workers() as u32,
            machines_known: self.state.router.machines_known() as u32,
            grpc_sessions: 0, // TODO(metrics): counter of active connections
            received_bytes_total: machines.iter().map(|m| m.used_bytes).sum(),
            write_errors: 0,
            version: self.version.to_string(),
        }))
    }

    async fn list_machines(&self, _req: Request<Empty>) -> Result<Response<MachineList>, Status> {
        Ok(Response::new(MachineList {
            machines: self
                .state
                .router
                .snapshot()
                .into_iter()
                .map(|m| MachineInfo {
                    machine_id: m.id,
                    store_path: m.store_path,
                    quota_bytes: m.quota_bytes,
                    used_bytes: m.used_bytes,
                    worker_active: m.worker_active,
                    last_activity_unix_ms: m.last_activity_unix_ms,
                })
                .collect(),
        }))
    }

    type WatchEventsStream =
        std::pin::Pin<Box<dyn tokio_stream::Stream<Item = Result<ReceiverEvent, Status>> + Send>>;

    async fn watch_events(
        &self,
        _req: Request<Empty>,
    ) -> Result<Response<Self::WatchEventsStream>, Status> {
        Err(Status::unimplemented("WatchEvents: TODO (event bus)"))
    }

    async fn get_diagnostics(
        &self,
        _req: Request<Empty>,
    ) -> Result<Response<DiagnosticsBundle>, Status> {
        Err(Status::unimplemented("GetDiagnostics: TODO"))
    }

    /// Stop the daemon. Drain is not needed: the receiver has no journal of its own,
    /// unfinished RPCs are answered to completion within the server's grace.
    async fn shutdown(&self, _req: Request<Empty>) -> Result<Response<Ack>, Status> {
        let mut guard = self.state.shutdown.lock().await;
        match guard.take() {
            Some(tx) => {
                let _ = tx.send(());
                Ok(Response::new(Ack {
                    ok: true,
                    error: String::new(),
                }))
            }
            None => Ok(Response::new(Ack {
                ok: false,
                error: "shutdown already requested".into(),
            })),
        }
    }
}
