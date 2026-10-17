//! janus-lib: the client side outside the SMB protocol:
//! - storage: `vfs` (the StorageBackend trait + backends), `model` (sparsebundle),
//!   `journal` (WAL), `uploader` (delivery to the backend);
//! - management: `control`, `config`, `bonjour`, `observability`.
//!
//! Storage backends are behind cargo features (implementations of `vfs::StorageBackend`):
//! `backend-local`, `backend-grpc`, `backend-s3` (see README, the Features section).
//!
//! Design: README.md (the Architecture section), the "Layer 1" and "Layer 3" sections.

#![allow(dead_code)] // skeleton

pub mod bonjour;
pub mod config;
pub mod control;
pub mod credentials;
#[cfg(feature = "backend-grpc")]
pub mod grpc_backend;
pub mod journal;
#[cfg(feature = "backend-local")]
pub mod local_backend;
pub mod log;
pub mod model;
pub mod observability;
pub mod profile;
pub mod remote;
#[cfg(feature = "backend-grpc")]
pub mod switch_backend;
pub mod uploader;
pub mod vfs;

/// S3 backend (any S3-compatible bucket). Only with the `backend-s3` feature.
#[cfg(feature = "backend-s3")]
pub mod backend_s3;
