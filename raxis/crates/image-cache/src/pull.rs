//! Phase 1–4 of the §6 pull-and-verify pipeline.
//!
//! Streams an OCI registry blob to an on-disk staging file, hashes
//! it on the fly, and atomically renames the verified file into the
//! cache. Phase 5 (extraction) lives in `extract.rs`.
//!
//! ## Why a separate module
//!
//! The pull side is the I/O-heavy + network-touching half; the
//! extract side is filesystem-only. Keeping them apart means the
//! production resolver can be tested with a stubbed pull (just
//! drop a known blob into the staging path) and a real extract,
//! and vice versa.
//!
//! ## File-locking note
//!
//! The §6 phase-1 `flock(2)` call is intentionally **not** used in
//! the production resolver — per `image-cache.md §7` "the kernel
//! (single binary, multiple sessions) does NOT depend on file
//! locking for in-process serialisation". The `ProductionResolver`
//! holds an in-memory `tokio::sync::Mutex` keyed by digest. The
//! file-lock convention exists for the cross-process case (a
//! `raxis doctor` invocation racing with a kernel-side pull) which
//! V2 marks as out-of-scope; the lock-file path on the layout is
//! still derived for the future cross-process implementation but
//! never opened in this iteration.

use std::path::{Path, PathBuf};

use futures::StreamExt;
use sha2::{Digest, Sha256};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

use crate::{ImageResolverError, OciDigest};

/// Build the OCI distribution-spec v2 blob URL.
///
/// `https://<host>/v2/<repo>/blobs/sha256:<hex>` per
/// <https://github.com/opencontainers/distribution-spec/blob/main/spec.md#pulling-blobs>.
pub fn build_blob_url(host: &str, repo: &str, digest: &OciDigest) -> String {
    let hex = hex::encode(digest.as_bytes());
    format!("https://{host}/v2/{repo}/blobs/sha256:{hex}")
}

/// Stream the registry blob into `staging_path` while computing its
/// SHA-256. On stream end the path holds the full body and the
/// returned `OciDigest` is what the body actually hashed to. The
/// caller MUST compare it against the policy-pinned digest before
/// renaming the file into the cache.
///
/// Errors map to the spec's failure-mode taxonomy:
/// * Network unreachable → `RegistryUnreachable`
/// * 401 / 403           → `RegistryAuthRejected`
/// * 404                 → `RegistryNotFound`
/// * 5xx                 → `RegistryServerError`
/// * I/O on staging file → `Io`
pub(crate) async fn stream_blob_to_staging(
    client:        &reqwest::Client,
    host:          &str,
    repository:    &str,
    digest:        &OciDigest,
    bearer_token:  Option<&str>,
    staging_path:  &Path,
) -> Result<OciDigest, ImageResolverError> {
    let url = build_blob_url(host, repository, digest);

    if let Some(parent) = staging_path.parent() {
        tokio::fs::create_dir_all(parent).await
            .map_err(|source| ImageResolverError::Io {
                path: parent.to_path_buf(), source,
            })?;
    }

    let mut req = client.get(&url);
    if let Some(token) = bearer_token {
        // Header value: `Bearer <token>`. We use `header()` so we
        // never log the token even at trace level (`tracing::warn!`
        // / `tracing::error!` calls in the surrounding code use the
        // url, not the headers).
        req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"));
    }
    // Distinguish kernel pulls in registry access logs.
    req = req.header(reqwest::header::USER_AGENT, "raxis-image-cache/v2");

    let resp = req.send().await.map_err(|e| ImageResolverError::RegistryUnreachable {
        host:   host.to_owned(),
        detail: format!("HTTP request failed: {e}"),
    })?;

    let status = resp.status();
    if status.is_client_error() {
        return Err(match status.as_u16() {
            401 | 403 => ImageResolverError::RegistryAuthRejected {
                host:       host.to_owned(),
                repository: repository.to_owned(),
            },
            404 => ImageResolverError::RegistryNotFound {
                host:       host.to_owned(),
                repository: repository.to_owned(),
                digest:     *digest,
            },
            _ => ImageResolverError::RegistryServerError {
                host:   host.to_owned(),
                status: status.as_u16(),
            },
        });
    }
    if status.is_server_error() {
        return Err(ImageResolverError::RegistryServerError {
            host:   host.to_owned(),
            status: status.as_u16(),
        });
    }
    if !status.is_success() {
        return Err(ImageResolverError::RegistryServerError {
            host:   host.to_owned(),
            status: status.as_u16(),
        });
    }

    // Stream the body to disk while hashing.
    let mut file = File::create(staging_path).await
        .map_err(|source| ImageResolverError::Io {
            path: staging_path.to_path_buf(), source,
        })?;

    let mut hasher = Sha256::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| ImageResolverError::RegistryUnreachable {
            host:   host.to_owned(),
            detail: format!("HTTP body chunk failed: {e}"),
        })?;
        hasher.update(&chunk);
        file.write_all(&chunk).await
            .map_err(|source| ImageResolverError::Io {
                path: staging_path.to_path_buf(), source,
            })?;
    }
    file.flush().await.map_err(|source| ImageResolverError::Io {
        path: staging_path.to_path_buf(), source,
    })?;
    file.sync_all().await.map_err(|source| ImageResolverError::Io {
        path: staging_path.to_path_buf(), source,
    })?;

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hasher.finalize());
    Ok(OciDigest::from_sha256_bytes(bytes))
}

/// Atomic phase-4 rename. On every supported filesystem (APFS, ext4,
/// XFS, btrfs, ZFS) `rename(2)` is atomic when source and target
/// live on the same device, which our cache layout guarantees
/// (everything lives under `<root>/blobs/sha256/<aa>/`).
pub(crate) async fn atomic_rename(
    from: &Path,
    to:   &PathBuf,
) -> Result<(), ImageResolverError> {
    if let Some(parent) = to.parent() {
        tokio::fs::create_dir_all(parent).await
            .map_err(|source| ImageResolverError::Io {
                path: parent.to_path_buf(), source,
            })?;
    }
    tokio::fs::rename(from, to).await.map_err(|source| ImageResolverError::Io {
        path: to.clone(), source,
    })
}

/// Best-effort cleanup of a partial staging file. Surfaces no error
/// — we already know the request failed; failing the cleanup
/// secondary is not informative.
pub(crate) async fn remove_if_exists(p: &Path) {
    let _ = tokio::fs::remove_file(p).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d() -> OciDigest {
        "sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
            .parse().unwrap()
    }

    #[test]
    fn build_blob_url_follows_oci_distribution_v2_spec() {
        let url = build_blob_url("ghcr.io", "operator/raxis-rust", &d());
        assert_eq!(
            url,
            "https://ghcr.io/v2/operator/raxis-rust/blobs/\
             sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
        );
    }
}
