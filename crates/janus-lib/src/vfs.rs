//! StorageBackend is the only door through which smb-core sees storage.
//! Implementations: `GrpcBackend` (production) and `LocalFsBackend` (tests / a reference against Samba).

use crate::journal::Journal;
use crate::model::SparsebundleModel;
use crate::uploader::UploaderHandle;

/// Handle of an open file on the backend side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BackendHandle(pub u64);

#[derive(Debug, Clone)]
pub struct FileStat {
    pub rel_path: String,
    pub size: u64,
    pub directory: bool,
    pub mtime_unix_ns: i64,
}

/// Share quota/usage → replies to backupd's FileFsSizeInformation.
/// TM makes thinning decisions from these numbers, so stubs are unacceptable.
#[derive(Debug, Clone, Copy)]
pub struct FsStats {
    pub quota_bytes: u64,
    pub used_bytes: u64,
}

/// Mapping to NTSTATUS is done by smb-core; critical: `NoSpace` → STATUS_DISK_FULL
/// (the thinning signal for TM).
#[derive(Debug)]
pub enum BackendError {
    NotFound,
    AlreadyExists,
    NoSpace,
    /// Backpressure (Quiesce / WAL overflow): smb-core slows down replies.
    Busy,
    RemoteUnavailable,
    Io(std::io::Error),
}

pub type Result<T> = std::result::Result<T, BackendError>;

#[derive(Debug, Clone, Copy)]
pub enum Disposition {
    Open,
    Create,
    OpenOrCreate,
    Overwrite,
}

/// Asynchronous storage interface.
///
/// NB: async fn in a trait → the trait is not dyn-compatible; smb-core is parameterized
/// by the generic `B: StorageBackend` (a Box/async_trait wrapper if needed).
pub trait StorageBackend: Send + Sync + 'static {
    fn open(
        &self,
        rel_path: &str,
        disposition: Disposition,
    ) -> impl Future<Output = Result<BackendHandle>> + Send;
    fn read(
        &self,
        h: BackendHandle,
        offset: u64,
        len: u32,
    ) -> impl Future<Output = Result<Vec<u8>>> + Send;
    fn write(
        &self,
        h: BackendHandle,
        offset: u64,
        data: &[u8],
    ) -> impl Future<Output = Result<()>> + Send;
    /// `fullfsync` is the forwarded F_FULLFSYNC flag (smb-core::apple).
    fn flush(&self, h: BackendHandle, fullfsync: bool) -> impl Future<Output = Result<()>> + Send;
    fn close(&self, h: BackendHandle) -> impl Future<Output = Result<()>> + Send;
    fn rename(
        &self,
        from: &str,
        to: &str,
        replace: bool,
    ) -> impl Future<Output = Result<()>> + Send;
    fn delete(&self, rel_path: &str) -> impl Future<Output = Result<()>> + Send;
    fn truncate(&self, h: BackendHandle, new_len: u64) -> impl Future<Output = Result<()>> + Send;
    fn list(&self, rel_dir: &str) -> impl Future<Output = Result<Vec<FileStat>>> + Send;
    fn stat(&self, rel_path: &str) -> impl Future<Output = Result<FileStat>> + Send;
    fn statfs(&self) -> impl Future<Output = Result<FsStats>> + Send;
}

/// Production backend: WAL + uploader + gRPC to the appliance.
/// READ answers through `Journal::read_overlay` (read-your-writes), reading through
/// the missing ranges by `ReadRange` from the appliance.
pub struct GrpcBackend {
    model: SparsebundleModel,
    journal: Journal,
    uploader: UploaderHandle,
    // remote: BandTransportClient will appear with janus-proto/tonic
}

/// Test backend: an ordinary local folder. Used for reference runs
/// of a real TM backup through our server and for comparing behaviour with Samba.
pub struct LocalFsBackend {
    root: std::path::PathBuf,
}
