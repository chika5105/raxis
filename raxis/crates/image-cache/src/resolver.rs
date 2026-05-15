//! `ImageResolver` — the trait the kernel session-spawn path
//! consumes (per `image-cache.md §5`).

use std::collections::HashSet;

use async_trait::async_trait;

use crate::{ImageResolverError, OciDigest, RegistryRef, ResolvedImage};

/// Resolver from a policy- / plan-pinned `oci_digest` to a path
/// the isolation backend can hand to its
/// `IsolationBackend::spawn(image_path = ...)` API.
///
/// Implementations are expected to be:
///
///   * concurrency-safe — multiple sessions resolving the same
///     digest concurrently must coalesce on a single pull (the
///     production resolver implements this with a digest-keyed
///     `tokio::sync::Mutex` map; the `flock(2)`-based on-disk
///     lock in [`crate::CacheLayout::lock_file_path`] handles the
///     inter-process case);
///   * digest-verifying — the bytes at the returned
///     [`ResolvedImage::rootfs_image_path`] MUST hash to exactly
///     the requested `oci_digest`;
///   * cancellation-safe — a `tokio::select!`-driven cancel must
///     leave on-disk state consistent (no half-extracted
///     `images/<digest>/` directories visible to a follow-up call).
#[async_trait]
pub trait ImageResolver: Send + Sync {
    /// Resolve `oci_digest` to a path the isolation backend can
    /// boot. Pulls from the configured registry on a cache miss.
    /// `registry_hint` is advisory; the production resolver may
    /// consult per-image overrides in `policy.toml` and ignore the
    /// hint.
    async fn resolve(
        &self,
        oci_digest: &OciDigest,
        registry_hint: Option<&RegistryRef>,
    ) -> Result<ResolvedImage, ImageResolverError>;

    /// Best-effort GC. Idempotent; must not panic on a missing
    /// cache. Returns the number of bytes freed. Pinned by
    /// `image-cache.md §8`.
    fn prune_unreferenced(
        &self,
        live_digests: &HashSet<OciDigest>,
    ) -> Result<u64, ImageResolverError>;
}
