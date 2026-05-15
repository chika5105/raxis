//! `PrePopulatedResolver` — resolves only digests already present
//! in the on-disk cache. Intended for kernel integration tests and
//! for offline-first deployments where the operator pre-stages
//! images out of band.
//!
//! Behaviour:
//!
//! * Cache hit (`rootfs.img` exists at the layout-derived path AND
//!   its SHA-256 matches the requested digest) → returns
//!   [`crate::ResolvedImage`] populated from
//!   [`crate::CacheLayout`].
//! * Cache hit but digest mismatch → returns
//!   [`crate::ImageResolverError::DigestMismatch`].
//! * Cache miss → returns
//!   [`crate::ImageResolverError::RegistryUnreachable`] with a
//!   detail clarifying that this resolver does not pull. The
//!   kernel session-spawn path can then map the failure to
//!   `FAIL_OCI_IMAGE_PULL_NETWORK` exactly as it would for the
//!   production resolver — the boundary is consistent.
//!
//! `prune_unreferenced` is a real implementation: it walks the
//! cache root and unlinks `rootfs.img` / `manifest.json` /
//! `config.json` files whose digest is NOT in the live set.

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use async_trait::async_trait;
use sha2::{Digest, Sha256};

use crate::{
    CacheLayout, ImageResolver, ImageResolverError, OciDigest, RegistryRef, ResolvedImage,
};

/// Test-friendly / offline-friendly resolver. See module docs.
#[derive(Debug, Clone)]
pub struct PrePopulatedResolver {
    layout: CacheLayout,
}

impl PrePopulatedResolver {
    /// Construct rooted at `cache_root` (in production this is
    /// `$RAXIS_DATA_DIR/oci-cache/`).
    pub fn new(cache_root: impl Into<PathBuf>) -> Self {
        Self {
            layout: CacheLayout::new(cache_root),
        }
    }

    /// Borrow the layout the resolver is operating against. Tests
    /// use this to address the on-disk paths directly when staging
    /// fixtures.
    pub fn layout(&self) -> &CacheLayout {
        &self.layout
    }
}

#[async_trait]
impl ImageResolver for PrePopulatedResolver {
    async fn resolve(
        &self,
        oci_digest: &OciDigest,
        _registry_hint: Option<&RegistryRef>,
    ) -> Result<ResolvedImage, ImageResolverError> {
        let rootfs = self.layout.rootfs_image_path(oci_digest);
        if !rootfs.exists() {
            return Err(ImageResolverError::RegistryUnreachable {
                host: "<pre-populated-only>".to_owned(),
                detail: format!(
                    "PrePopulatedResolver does not pull from a registry; \
                     rootfs.img missing at {}",
                    rootfs.display(),
                ),
            });
        }

        // Stream-hash the on-disk rootfs and compare against the
        // requested digest. Mirrors the production §6 phase-3
        // verification step; means a tampered cache (or an operator
        // that staged the wrong file) is detected at resolve time
        // rather than at boot time.
        let actual = compute_image_sha256(&rootfs)?;
        if &actual != oci_digest {
            return Err(ImageResolverError::DigestMismatch {
                expected: *oci_digest,
                actual,
                path: rootfs,
            });
        }

        Ok(ResolvedImage {
            rootfs_image_path: rootfs,
            oci_config_path: self.layout.oci_config_path(oci_digest),
            verified_digest: *oci_digest,
        })
    }

    fn prune_unreferenced(
        &self,
        live_digests: &HashSet<OciDigest>,
    ) -> Result<u64, ImageResolverError> {
        let mut bytes_freed = 0u64;

        // Walk <root>/images/sha256/<aa>/<full>/.
        let images_root = self.layout.root().join("images").join("sha256");
        if !images_root.exists() {
            return Ok(0);
        }

        for shard_entry in read_dir_or_empty(&images_root)? {
            let shard = shard_entry.map_err(|source| ImageResolverError::Io {
                path: images_root.clone(),
                source,
            })?;
            for digest_entry in read_dir_or_empty(&shard.path())? {
                let digest_dir = digest_entry.map_err(|source| ImageResolverError::Io {
                    path: shard.path(),
                    source,
                })?;
                let Some(name) = digest_dir.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                let canonical = format!("sha256:{name}");
                let Ok(digest) = canonical.parse::<OciDigest>() else {
                    continue;
                };
                if live_digests.contains(&digest) {
                    continue;
                }
                bytes_freed += dir_size(&digest_dir.path())?;
                fs::remove_dir_all(digest_dir.path()).map_err(|source| {
                    ImageResolverError::Io {
                        path: digest_dir.path(),
                        source,
                    }
                })?;
            }
        }

        Ok(bytes_freed)
    }
}

fn compute_image_sha256(path: &std::path::Path) -> Result<OciDigest, ImageResolverError> {
    use std::fs::File;
    use std::io::Read;

    let mut file = File::open(path).map_err(|source| ImageResolverError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|source| ImageResolverError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hasher.finalize());
    Ok(OciDigest::from_sha256_bytes(bytes))
}

fn read_dir_or_empty(p: &std::path::Path) -> Result<fs::ReadDir, ImageResolverError> {
    fs::read_dir(p).map_err(|source| ImageResolverError::Io {
        path: p.to_path_buf(),
        source,
    })
}

fn dir_size(p: &std::path::Path) -> Result<u64, ImageResolverError> {
    let mut total = 0u64;
    for entry in read_dir_or_empty(p)? {
        let entry = entry.map_err(|source| ImageResolverError::Io {
            path: p.to_path_buf(),
            source,
        })?;
        let meta = entry.metadata().map_err(|source| ImageResolverError::Io {
            path: entry.path(),
            source,
        })?;
        if meta.is_file() {
            total += meta.len();
        } else if meta.is_dir() {
            total += dir_size(&entry.path())?;
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::TempDir;

    /// Helper: stage `bytes` into the cache as the `rootfs.img` for
    /// `digest`. Returns the digest the bytes actually hash to (so
    /// the test can pin honest-vs-tampered digests).
    fn stage(layout: &CacheLayout, digest: &OciDigest, bytes: &[u8]) {
        let dir = layout.extracted_dir(digest);
        fs::create_dir_all(&dir).unwrap();
        let mut f = fs::File::create(dir.join("rootfs.img")).unwrap();
        f.write_all(bytes).unwrap();
        // Stage a placeholder config.json so resolve()'s return
        // value points at a file the kernel can later read.
        fs::write(dir.join("config.json"), b"{}").unwrap();
    }

    fn sha256_of(bytes: &[u8]) -> OciDigest {
        let mut h = Sha256::new();
        h.update(bytes);
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        OciDigest::from_sha256_bytes(out)
    }

    #[tokio::test]
    async fn resolve_returns_paths_for_pre_staged_digest() {
        let tmp = TempDir::new().unwrap();
        let resolver = PrePopulatedResolver::new(tmp.path());

        let bytes = b"deterministic-image-bytes" as &[u8];
        let digest = sha256_of(bytes);
        stage(resolver.layout(), &digest, bytes);

        let resolved = resolver.resolve(&digest, None).await.unwrap();
        assert_eq!(
            resolved.rootfs_image_path,
            resolver.layout().rootfs_image_path(&digest),
        );
        assert_eq!(
            resolved.oci_config_path,
            resolver.layout().oci_config_path(&digest),
        );
        assert_eq!(resolved.verified_digest, digest);
    }

    #[tokio::test]
    async fn resolve_returns_registry_unreachable_on_cache_miss() {
        let tmp = TempDir::new().unwrap();
        let resolver = PrePopulatedResolver::new(tmp.path());

        let digest: OciDigest =
            "sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
                .parse()
                .unwrap();
        let err = resolver.resolve(&digest, None).await.unwrap_err();
        match err {
            ImageResolverError::RegistryUnreachable { host, .. } => {
                assert_eq!(host, "<pre-populated-only>");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn resolve_returns_digest_mismatch_when_bytes_disagree() {
        let tmp = TempDir::new().unwrap();
        let resolver = PrePopulatedResolver::new(tmp.path());

        // Stage `rootfs.img` under digest A but with bytes that hash to digest B.
        let real_bytes = b"actual-bytes" as &[u8];
        let claimed: OciDigest =
            "sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
                .parse()
                .unwrap();
        let actual = sha256_of(real_bytes);
        assert_ne!(
            claimed, actual,
            "fixture sanity: claimed and actual must differ"
        );

        stage(resolver.layout(), &claimed, real_bytes);

        let err = resolver.resolve(&claimed, None).await.unwrap_err();
        match err {
            ImageResolverError::DigestMismatch {
                expected,
                actual: got,
                path: _,
            } => {
                assert_eq!(expected, claimed);
                assert_eq!(got, actual);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn prune_unreferenced_removes_dead_digests_only() {
        let tmp = TempDir::new().unwrap();
        let resolver = PrePopulatedResolver::new(tmp.path());

        let alive_bytes = b"alive" as &[u8];
        let dead_bytes = b"dead" as &[u8];
        let alive = sha256_of(alive_bytes);
        let dead = sha256_of(dead_bytes);
        stage(resolver.layout(), &alive, alive_bytes);
        stage(resolver.layout(), &dead, dead_bytes);

        let mut live = HashSet::new();
        live.insert(alive);

        let freed = resolver.prune_unreferenced(&live).unwrap();
        assert!(
            freed > 0,
            "prune should report some bytes freed for the dead digest"
        );

        // `alive` survives.
        assert!(resolver.layout().rootfs_image_path(&alive).exists());
        // `dead` is gone.
        assert!(!resolver.layout().rootfs_image_path(&dead).exists());
    }

    #[tokio::test]
    async fn prune_unreferenced_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let resolver = PrePopulatedResolver::new(tmp.path());
        let live = HashSet::new();

        // Empty cache: first call is a no-op (returns 0).
        let freed = resolver.prune_unreferenced(&live).unwrap();
        assert_eq!(freed, 0);

        // Second call still a no-op.
        let freed = resolver.prune_unreferenced(&live).unwrap();
        assert_eq!(freed, 0);
    }

    #[tokio::test]
    async fn prune_unreferenced_handles_missing_cache_root() {
        // Construct a resolver pointing at a path that doesn't
        // exist. prune must not panic; it must return 0.
        let resolver = PrePopulatedResolver::new("/tmp/raxis-image-cache-does-not-exist-xyz");
        let live = HashSet::new();
        let freed = resolver.prune_unreferenced(&live).unwrap();
        assert_eq!(freed, 0);
    }
}
