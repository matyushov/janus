//! StorageBackend is the only door through which smb-core sees storage.
//! Implementations: `GrpcBackend` (production) and `LocalFsBackend` (tests / a reference against Samba).

use crate::journal::Journal;
use crate::model::SparsebundleModel;
use crate::uploader::UploaderHandle;

/// Handle of an open file on the backend side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BackendHandle(pub u64);

/// Metadata of a file or directory. Times are nanoseconds since the Unix epoch.
#[derive(Debug, Clone)]
pub struct FileStat {
    /// Last path component (empty for the share root).
    pub name: String,
    /// Path relative to the share root, `/`-separated.
    pub rel_path: String,
    pub size: u64,
    pub directory: bool,
    pub read_only: bool,
    pub mtime_unix_ns: i64,
    pub atime_unix_ns: i64,
    /// Change time (metadata change; falls back to mtime where the platform has none).
    pub ctime_unix_ns: i64,
    /// Creation time (falls back to mtime where the platform has none).
    pub btime_unix_ns: i64,
    /// Stable object identifier (inode where available), reported as FileId/IndexNumber.
    pub file_id: u64,
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
    /// The final component does not exist.
    NotFound,
    /// A parent directory does not exist.
    PathNotFound,
    AlreadyExists,
    NoSpace,
    NotADirectory,
    IsADirectory,
    DirectoryNotEmpty,
    AccessDenied,
    /// The handle is unknown (already closed).
    BadHandle,
    /// Backpressure (Quiesce / WAL overflow): smb-core slows down replies.
    Busy,
    RemoteUnavailable,
    Io(std::io::Error),
}

pub type Result<T> = std::result::Result<T, BackendError>;

/// What `open` does when the object exists or does not (SMB CreateDisposition).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Open an existing object; fail if missing.
    Open,
    /// Create a new object; fail if it exists.
    Create,
    /// Open, or create when missing.
    OpenOrCreate,
    /// Open and truncate; fail if missing.
    Overwrite,
    /// Open and truncate, or create when missing.
    OverwriteOrCreate,
    /// Replace: like `OverwriteOrCreate` (attributes are reset by smb-core).
    Supersede,
}

/// Which kind of object the caller expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Any,
    File,
    Directory,
}

#[derive(Debug, Clone, Copy)]
pub struct OpenRequest {
    pub disposition: Disposition,
    pub kind: Kind,
    /// The handle will be used to write (data, size or times).
    pub write: bool,
    /// Remove the object when the handle is closed.
    pub delete_on_close: bool,
}

#[derive(Debug, Clone)]
pub struct Opened {
    pub handle: BackendHandle,
    pub stat: FileStat,
    /// The object did not exist and was created.
    pub created: bool,
    /// An existing file was truncated.
    pub overwritten: bool,
}

/// Timestamps to set; `None` leaves a field unchanged.
#[derive(Debug, Clone, Copy, Default)]
pub struct SetTimes {
    pub atime_unix_ns: Option<i64>,
    pub mtime_unix_ns: Option<i64>,
}

/// Asynchronous storage interface.
///
/// NB: async fn in a trait → the trait is not dyn-compatible; smb-core is parameterized
/// by the generic `B: StorageBackend` (a Box/async_trait wrapper if needed).
///
/// Paths are relative to the share root, `/`-separated, without a leading slash; the empty
/// string is the root. Name matching semantics belong to the backend.
pub trait StorageBackend: Send + Sync + 'static {
    fn open(&self, rel_path: &str, req: OpenRequest)
    -> impl Future<Output = Result<Opened>> + Send;
    /// Fresh metadata of an open object.
    fn stat_handle(&self, h: BackendHandle) -> impl Future<Output = Result<FileStat>> + Send;
    /// Short reads happen only at end of file; an offset at or past the end gives an empty vector.
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
    /// Closes the handle and performs a pending delete-on-close.
    fn close(&self, h: BackendHandle) -> impl Future<Output = Result<()>> + Send;
    fn rename(
        &self,
        from: &str,
        to: &str,
        replace: bool,
    ) -> impl Future<Output = Result<()>> + Send;
    /// Mark/unmark the object for removal on close. Fails with `DirectoryNotEmpty` at once
    /// for a non-empty directory.
    fn set_delete_on_close(
        &self,
        h: BackendHandle,
        on: bool,
    ) -> impl Future<Output = Result<()>> + Send;
    fn truncate(&self, h: BackendHandle, new_len: u64) -> impl Future<Output = Result<()>> + Send;
    fn set_times(
        &self,
        h: BackendHandle,
        times: SetTimes,
    ) -> impl Future<Output = Result<()>> + Send;
    /// Whole directory listing (without `.` and `..`); smb-core snapshots it per open.
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

#[cfg(feature = "backend-local")]
pub use crate::local_backend::LocalFsBackend;
