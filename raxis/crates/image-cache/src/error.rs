//! `ImageResolverError` — failure-mode taxonomy from
//! `image-cache.md §9`. Every variant carries enough information
//! for the audit-record mapping
//! (`SecurityViolationDetected` for `DigestMismatch`,
//! `SessionSpawnFailed { reason: ... }` for the rest) to be
//! actionable without re-running the failing pull.

use std::path::PathBuf;

use crate::digest::OciDigestParseError;
use crate::OciDigest;

/// Errors the resolver can surface. Mapping to kernel `FAIL_*`
/// codes is documented inline.
#[derive(Debug, thiserror::Error)]
pub enum ImageResolverError {
    /// On-disk SHA-256 disagreed with the requested digest. The
    /// kernel maps this to `FAIL_OCI_IMAGE_DIGEST_MISMATCH` and
    /// emits `SecurityViolationDetected`.
    #[error("oci image digest mismatch: expected {expected}, got {actual}")]
    DigestMismatch {
        /// What the caller (policy / plan) committed to.
        expected: OciDigest,
        /// What the cached / streamed bytes actually hashed to.
        actual: OciDigest,
        /// The on-disk path the digest was computed over (for the
        /// audit record; useful when reasoning about a
        /// half-extracted cache entry).
        path: PathBuf,
    },

    /// Cache hit landed but the on-disk file is unreadable / wrong-
    /// shape (truncated, missing manifest, etc.). The kernel maps
    /// this to `FAIL_OCI_IMAGE_CACHE_CORRUPT` and the next call to
    /// `resolve` will re-stage from the registry — the corrupted
    /// entry is unlinked as a side effect.
    #[error("oci image cache entry is corrupted at {path}: {detail}")]
    CacheCorrupted {
        /// The path that failed verification.
        path: PathBuf,
        /// Human-readable detail (NOT shown to the agent; logged
        /// to the audit chain only).
        detail: String,
    },

    /// Cache miss and no registry hint or policy mapping was
    /// available to satisfy the pull. Distinct from
    /// `RegistryUnreachable` (registry was reachable but the
    /// kernel had no way to address it) so the operator-facing
    /// diagnostic distinguishes "your policy is silent on this
    /// digest's source" from "your policy named a registry that
    /// is down".
    #[error("oci image cache miss with no registry hint available for {digest}")]
    NoRegistryHint {
        /// The digest the resolver could not satisfy.
        digest: OciDigest,
    },

    /// Registry is unreachable. Maps to
    /// `FAIL_OCI_IMAGE_PULL_NETWORK`. Only emitted by the production
    /// resolver; the skeleton's `PrePopulatedResolver` returns this
    /// for any miss so kernel tests can exercise the failure path
    /// without a real network.
    #[error("oci registry {host} unreachable: {detail}")]
    RegistryUnreachable {
        /// Registry host that failed.
        host: String,
        /// Human-readable detail.
        detail: String,
    },

    /// Registry returned 401 / 403. Maps to `FAIL_OCI_IMAGE_AUTH`.
    #[error("oci registry rejected authentication for {host}/{repository}")]
    RegistryAuthRejected {
        /// Registry host.
        host: String,
        /// Repository path.
        repository: String,
    },

    /// Registry returned 404. Maps to `FAIL_OCI_IMAGE_NOT_FOUND`.
    #[error("oci registry has no image for {digest} at {host}/{repository}")]
    RegistryNotFound {
        /// Registry host.
        host: String,
        /// Repository path.
        repository: String,
        /// The digest that wasn't found.
        digest: OciDigest,
    },

    /// Registry returned 5xx after retries are exhausted. Maps to
    /// `FAIL_OCI_IMAGE_PULL_TRANSIENT`.
    #[error("oci registry server error from {host}: status {status}")]
    RegistryServerError {
        /// Registry host.
        host: String,
        /// HTTP status code observed on the final attempt.
        status: u16,
    },

    /// Image manifest declared an unsupported `mediaType`. V2 only
    /// supports `application/vnd.raxis.image.rootfs.v1+erofs`. Maps
    /// to `FAIL_OCI_IMAGE_UNSUPPORTED`.
    #[error("oci image media type {media_type} is not supported in V2")]
    UnsupportedMediaType {
        /// What the manifest declared.
        media_type: String,
    },

    /// Filesystem error during any phase. Maps to
    /// `FAIL_OCI_IMAGE_CACHE_IO`.
    #[error("oci image cache i/o error at {path}: {source}")]
    Io {
        /// The path the operation targeted.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// A malformed `OciDigest` reached the resolver. This is
    /// upstream-shift-left territory (approve_plan should have
    /// rejected it) and surfaces here only as defense in depth.
    #[error("malformed oci digest: {0}")]
    OciDigestParse(#[from] OciDigestParseError),
}
