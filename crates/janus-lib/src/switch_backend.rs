//! `SwitchBackend`: the backend `janus-smbd` serves the share with. It lets `Configure`
//! replace the `GrpcBackend` (new endpoint, certificates, quota) without restarting the daemon.
//!
//! Handles carry the generation of the backend that issued them (top 16 bits), so a handle
//! opened before a reconfiguration keeps talking to the backend it was opened on until it is
//! closed; new opens use the new backend. Superseded backends are dropped when their last
//! handle is closed. Before the first `Configure` every operation fails with
//! `RemoteUnavailable`.

use std::sync::{Arc, Mutex, RwLock};

use crate::grpc_backend::GrpcBackend;
use crate::remote::RemoteClient;
use crate::vfs::{
    BackendError, BackendHandle, FileStat, FsStats, OpenRequest, Opened, Result, SetTimes,
    StorageBackend,
};

const GEN_SHIFT: u32 = 48;
const INNER_MASK: u64 = (1 << GEN_SHIFT) - 1;

#[derive(Default)]
pub struct SwitchBackend {
    current: RwLock<Option<(u16, Arc<GrpcBackend>)>>,
    /// Superseded generations that still have open handles.
    old: Mutex<Vec<(u16, Arc<GrpcBackend>)>>,
    next_gen: Mutex<u16>,
}

impl SwitchBackend {
    pub fn new() -> SwitchBackend {
        SwitchBackend::default()
    }

    /// Install a backend built from `remote`; `fallback_quota` is the configured volume size.
    pub fn apply(&self, remote: &RemoteClient, fallback_quota: u64) {
        self.install(GrpcBackend::from_remote(remote, fallback_quota));
    }

    pub fn install(&self, backend: GrpcBackend) {
        let gen_ = {
            let mut g = self.next_gen.lock().expect("gen poisoned");
            *g = g.wrapping_add(1);
            *g
        };
        let prev = self
            .current
            .write()
            .expect("backend lock poisoned")
            .replace((gen_, Arc::new(backend)));
        if let Some(p) = prev {
            self.old.lock().expect("old poisoned").push(p);
        }
        self.prune();
    }

    pub fn is_configured(&self) -> bool {
        self.current
            .read()
            .expect("backend lock poisoned")
            .is_some()
    }

    fn prune(&self) {
        self.old
            .lock()
            .expect("old poisoned")
            .retain(|(_, b)| b.open_handles() > 0);
    }

    fn current(&self) -> Result<Arc<GrpcBackend>> {
        self.current
            .read()
            .expect("backend lock poisoned")
            .as_ref()
            .map(|(_, b)| Arc::clone(b))
            .ok_or(BackendError::RemoteUnavailable)
    }

    fn route(&self, h: BackendHandle) -> Result<(Arc<GrpcBackend>, BackendHandle)> {
        let gen_ = (h.0 >> GEN_SHIFT) as u16;
        let inner = BackendHandle(h.0 & INNER_MASK);
        if let Some((g, b)) = self.current.read().expect("backend lock poisoned").as_ref()
            && *g == gen_
        {
            return Ok((Arc::clone(b), inner));
        }
        self.old
            .lock()
            .expect("old poisoned")
            .iter()
            .find(|(g, _)| *g == gen_)
            .map(|(_, b)| (Arc::clone(b), inner))
            .ok_or(BackendError::BadHandle)
    }

    fn tag(gen_: u16, h: BackendHandle) -> BackendHandle {
        BackendHandle(((gen_ as u64) << GEN_SHIFT) | (h.0 & INNER_MASK))
    }

    fn current_gen(&self) -> u16 {
        self.current
            .read()
            .expect("backend lock poisoned")
            .as_ref()
            .map(|(g, _)| *g)
            .unwrap_or(0)
    }
}

impl StorageBackend for SwitchBackend {
    async fn open(&self, rel_path: &str, req: OpenRequest) -> Result<Opened> {
        // Capture generation and backend together: a switch in between must not mislabel.
        let (gen_, b) = {
            let c = self.current.read().expect("backend lock poisoned");
            let (g, b) = c.as_ref().ok_or(BackendError::RemoteUnavailable)?;
            (*g, Arc::clone(b))
        };
        let mut o = b.open(rel_path, req).await?;
        o.handle = Self::tag(gen_, o.handle);
        Ok(o)
    }

    async fn stat_handle(&self, h: BackendHandle) -> Result<FileStat> {
        let (b, h) = self.route(h)?;
        b.stat_handle(h).await
    }

    async fn read(&self, h: BackendHandle, offset: u64, len: u32) -> Result<Vec<u8>> {
        let (b, h) = self.route(h)?;
        b.read(h, offset, len).await
    }

    async fn write(&self, h: BackendHandle, offset: u64, data: &[u8]) -> Result<()> {
        let (b, h) = self.route(h)?;
        b.write(h, offset, data).await
    }

    async fn flush(&self, h: BackendHandle, fullfsync: bool) -> Result<()> {
        let (b, h) = self.route(h)?;
        b.flush(h, fullfsync).await
    }

    async fn close(&self, h: BackendHandle) -> Result<()> {
        let (b, inner) = self.route(h)?;
        let r = b.close(inner).await;
        self.prune();
        r
    }

    async fn rename(&self, from: &str, to: &str, replace: bool) -> Result<()> {
        self.current()?.rename(from, to, replace).await
    }

    async fn set_delete_on_close(&self, h: BackendHandle, on: bool) -> Result<()> {
        let (b, h) = self.route(h)?;
        b.set_delete_on_close(h, on).await
    }

    async fn truncate(&self, h: BackendHandle, new_len: u64) -> Result<()> {
        let (b, h) = self.route(h)?;
        b.truncate(h, new_len).await
    }

    async fn set_times(&self, h: BackendHandle, times: SetTimes) -> Result<()> {
        let (b, h) = self.route(h)?;
        b.set_times(h, times).await
    }

    async fn list(&self, rel_dir: &str) -> Result<Vec<FileStat>> {
        self.current()?.list(rel_dir).await
    }

    async fn stat(&self, rel_path: &str) -> Result<FileStat> {
        self.current()?.stat(rel_path).await
    }

    async fn statfs(&self) -> Result<FsStats> {
        self.current()?.statfs().await
    }
}
