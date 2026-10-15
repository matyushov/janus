//! Testkit: a real server + a mock gRPC client + a temporary store.
//!
//! The model by agreement: the **server is NOT mocked**; the tests start a
//! real `janus-receiverd` (the same code paths as in production), and the
//! CLIENT side is mocked: `MockClient` sends commands over gRPC and lets you compare
//! the result with the files on disk.
//!
//! The temporary store is created under the system temp and **removed on drop**
//! (`TempStore` is RAII), including when the test panicked.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use janus_proto::v1::band_transport_client::BandTransportClient;
use janus_proto::v1::{
    BundleOpReply, BundleOpRequest, CreateOp, DeleteOp, FileRef, FileStat, FsyncRequest, ListOp,
    PingReply, ReadRangeRequest, RenameOp, StatFsReply, StatFsRequest, StatOp, TruncateOp,
    WriteRangeRequest, bundle_op_reply, bundle_op_request, fsync_request,
};
use tokio::net::TcpListener;
use tonic::transport::Channel;

use crate::server::serve_on_listener;
use crate::worker::FileStore;

/// A temporary store directory: removed on drop (RAII), even if the test panics.
#[derive(Debug)]
pub struct TempStore {
    path: PathBuf,
}

impl TempStore {
    /// Create a unique temporary directory under the system temp.
    pub fn new(tag: &str) -> std::io::Result<TempStore> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "janus-test-{tag}-{}-{nanos}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path)?;
        Ok(TempStore { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read a file from the store directly (verifying the result of commands).
    pub fn read_file(&self, rel: &str) -> std::io::Result<Vec<u8>> {
        std::fs::read(self.path.join(rel))
    }

    pub fn exists(&self, rel: &str) -> bool {
        self.path.join(rel).exists()
    }
}

impl Drop for TempStore {
    fn drop(&mut self) {
        // Cleanup is mandatory and must not fail the test: errors are ignored.
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// A started server + a mock client. The server is stopped on drop (a shutdown signal),
/// the store is removed together with `TempStore`.
pub struct TestServer {
    pub store: TempStore,
    pub client: MockClient,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    join: Option<tokio::task::JoinHandle<()>>,
}

impl TestServer {
    /// Start a real server on an ephemeral port in a temporary store.
    pub async fn start(
        tag: &str,
        quota_bytes: u64,
    ) -> Result<TestServer, Box<dyn std::error::Error>> {
        let store_dir = TempStore::new(tag)?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let store = Arc::new(FileStore::open(store_dir.path())?);

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let join = tokio::spawn(async move {
            let _ = serve_on_listener(listener, store, quota_bytes, async {
                let _ = rx.await;
            })
            .await;
        });

        let client = MockClient::connect(addr).await?;
        Ok(TestServer {
            store: store_dir,
            client,
            shutdown: Some(tx),
            join: Some(join),
        })
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join.take() {
            join.abort();
        }
        // the store will be removed by its own Drop (TempStore).
    }
}

/// Mock of the client side: thin wrappers over the `BandTransport` RPCs,
/// so that tests are one line per command.
pub struct MockClient {
    inner: BandTransportClient<Channel>,
}

impl MockClient {
    pub async fn connect(
        addr: std::net::SocketAddr,
    ) -> Result<MockClient, Box<dyn std::error::Error>> {
        // Retry the connect: the server may not have started accepting yet.
        let endpoint = format!("http://{addr}");
        let mut last_err = None;
        for _ in 0..50 {
            match BandTransportClient::connect(endpoint.clone()).await {
                Ok(inner) => return Ok(MockClient { inner }),
                Err(e) => {
                    last_err = Some(e);
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            }
        }
        Err(Box::new(last_err.expect("at least one attempt")))
    }

    pub async fn ping(&mut self) -> Result<PingReply, tonic::Status> {
        Ok(self
            .inner
            .ping(janus_proto::v1::PingRequest {
                client_version: "testkit".into(),
            })
            .await?
            .into_inner())
    }

    pub async fn statfs(&mut self) -> Result<StatFsReply, tonic::Status> {
        Ok(self.inner.stat_fs(StatFsRequest {}).await?.into_inner())
    }

    pub async fn write(
        &mut self,
        rel: &str,
        offset: u64,
        data: &[u8],
    ) -> Result<(), tonic::Status> {
        self.inner
            .write_range(WriteRangeRequest {
                file: Some(FileRef {
                    rel_path: rel.into(),
                }),
                offset,
                data: data.to_vec(),
                write_id: 0,
            })
            .await?;
        Ok(())
    }

    pub async fn read(
        &mut self,
        rel: &str,
        offset: u64,
        len: u32,
    ) -> Result<Vec<u8>, tonic::Status> {
        Ok(self
            .inner
            .read_range(ReadRangeRequest {
                file: Some(FileRef {
                    rel_path: rel.into(),
                }),
                offset,
                length: len,
            })
            .await?
            .into_inner()
            .data)
    }

    pub async fn fsync_file(&mut self, rel: &str) -> Result<(), tonic::Status> {
        self.inner
            .fsync(FsyncRequest {
                scope: Some(fsync_request::Scope::File(FileRef {
                    rel_path: rel.into(),
                })),
            })
            .await?;
        Ok(())
    }

    pub async fn fsync_all(&mut self) -> Result<(), tonic::Status> {
        self.inner
            .fsync(FsyncRequest {
                scope: Some(fsync_request::Scope::AllBundle(true)),
            })
            .await?;
        Ok(())
    }

    async fn bundle_op(
        &mut self,
        op: bundle_op_request::Op,
    ) -> Result<BundleOpReply, tonic::Status> {
        Ok(self
            .inner
            .bundle_op(BundleOpRequest { op: Some(op) })
            .await?
            .into_inner())
    }

    pub async fn create(&mut self, rel: &str, directory: bool) -> Result<(), tonic::Status> {
        self.bundle_op(bundle_op_request::Op::Create(CreateOp {
            file: Some(FileRef {
                rel_path: rel.into(),
            }),
            directory,
            exclusive: false,
        }))
        .await?;
        Ok(())
    }

    pub async fn delete(&mut self, rel: &str) -> Result<(), tonic::Status> {
        self.bundle_op(bundle_op_request::Op::Delete(DeleteOp {
            file: Some(FileRef {
                rel_path: rel.into(),
            }),
        }))
        .await?;
        Ok(())
    }

    pub async fn rename(
        &mut self,
        from: &str,
        to: &str,
        replace: bool,
    ) -> Result<(), tonic::Status> {
        self.bundle_op(bundle_op_request::Op::Rename(RenameOp {
            from: Some(FileRef {
                rel_path: from.into(),
            }),
            to: Some(FileRef {
                rel_path: to.into(),
            }),
            replace,
        }))
        .await?;
        Ok(())
    }

    pub async fn truncate(&mut self, rel: &str, new_len: u64) -> Result<(), tonic::Status> {
        self.bundle_op(bundle_op_request::Op::Truncate(TruncateOp {
            file: Some(FileRef {
                rel_path: rel.into(),
            }),
            new_length: new_len,
        }))
        .await?;
        Ok(())
    }

    pub async fn list(&mut self, rel_dir: &str) -> Result<Vec<FileStat>, tonic::Status> {
        let reply = self
            .bundle_op(bundle_op_request::Op::List(ListOp {
                rel_dir: rel_dir.into(),
            }))
            .await?;
        match reply.result {
            Some(bundle_op_reply::Result::Listing(l)) => Ok(l.entries),
            other => Err(tonic::Status::internal(format!(
                "expected listing, got: {other:?}"
            ))),
        }
    }

    pub async fn stat(&mut self, rel: &str) -> Result<FileStat, tonic::Status> {
        let reply = self
            .bundle_op(bundle_op_request::Op::Stat(StatOp {
                file: Some(FileRef {
                    rel_path: rel.into(),
                }),
            }))
            .await?;
        match reply.result {
            Some(bundle_op_reply::Result::Stat(s)) => Ok(s),
            other => Err(tonic::Status::internal(format!(
                "expected stat, got: {other:?}"
            ))),
        }
    }
}
