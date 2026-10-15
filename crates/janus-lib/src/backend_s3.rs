//! S3Backend is an implementation of `StorageBackend` on top of any S3-compatible
//! storage. The final consumer is the bucket itself; `janus-receiverd` is not needed
//! (janus-smbd is an S3 client directly).
//!
//! Behind the `backend-s3` feature (the main build does not pull in `aws-sdk-s3`). Works with
//! AWS S3 and any S3-compatible endpoint (MinIO/R2/B2/Wasabi/Ceph) via
//! `endpoint_url`. The SDK is Apache-2.0/MIT, compatible with janus's MIT.
//!
//! The KEY design question is write semantics: SMB issues offset writes into
//! band files, while an S3 object is atomic (no partial overwrite). The decoupling is our
//! WAL journal + uploader: offset writes accumulate in the journal, the uploader uploads
//! objects in batches. The mapping fork (open until the PoC):
//!   - band = object: simple, but a read-modify-write of the whole band (~268 MB) on
//!     small changes is costly write amplification;
//!   - chunk = object: a band is cut into blocks (4–16 MB) → object; less
//!     amplification, but our own chunk indexing.

use crate::config::ShareConfig;

/// S3 backend parameters (from ShareConfig; filled in on configure).
#[derive(Debug, Clone, Default)]
pub struct S3Config {
    pub bucket: String,
    /// Key prefix (e.g. "<machine-id>/backup.sparsebundle/").
    pub key_prefix: String,
    /// Empty = AWS by region; otherwise an S3-compatible endpoint (MinIO/R2/…).
    pub endpoint_url: String,
    pub region: String,
}

impl S3Config {
    /// Extract from the common share configuration (once we add S3 fields to Configure).
    pub fn from_share(_cfg: &ShareConfig) -> S3Config {
        todo!("маппинг S3-полей ShareConfig → S3Config")
    }
}

/// A backend on top of a bucket. Implements `crate::vfs::StorageBackend` (see the TODO below).
pub struct S3Backend {
    config: S3Config,
    // client: aws_sdk_s3::Client, built in connect()
}

impl S3Backend {
    /// Build the client: `aws_config::load_from_env` + optional `endpoint_url`,
    /// credentials from the standard AWS chain (env / ~/.aws / IAM / SSO).
    pub async fn connect(_config: S3Config) -> std::io::Result<S3Backend> {
        todo!("aws_config::from_env().endpoint_url(...).load(); Client::new")
    }
}

// TODO(backend-s3): impl crate::vfs::StorageBackend for S3Backend —
// write goes through WAL+uploader (batched PutObject/multipart), read through
// GetObject with an overlay from the journal, statfs → a fictitious quota (S3 is unlimited;
// the ceiling is set by config). Needs a chosen mapping strategy (see above).
