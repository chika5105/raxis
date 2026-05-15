//! `ProductionResolver` — registry-pull-backed [`crate::ImageResolver`].
//!
//! Wires `pull.rs` (phases 1–4) and `extract.rs` (phase 5) together
//! into the full §6 pipeline, with the §7 in-memory mutex map keyed
//! by digest so concurrent sessions resolving the same digest
//! coalesce on a single pull.
//!
//! ## Auth model
//!
//! V2 carries a single optional bearer token applied uniformly to
//! every registry request. Operators with multiple registries that
//! need distinct credentials should run a local mirror (the OCI
//! distribution spec supports mirroring transparently). Per-image
//! / per-registry auth is on the V3 roadmap (see
//! `image-cache.md §10`).
//!
//! ## Concurrency
//!
//! The resolver holds a `tokio::sync::Mutex<HashMap<OciDigest,
//! Arc<tokio::sync::Mutex<()>>>>`. The outer mutex protects the
//! map; the inner per-digest mutex serialises pulls of the same
//! digest. The map is bounded at 256 entries by an LRU sweep on
//! insert (the §7 cap); the eviction is correctness-safe because
//! pull state is reachable from the cache itself, not the in-memory
//! mutex.

use std::collections::HashMap;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use crate::{
    CacheLayout, ImageResolver, ImageResolverError, OciDigest, RegistryRef, ResolvedImage,
};

const PULL_LRU_CAP: usize = 256;

/// Production [`ImageResolver`] backed by a real HTTP registry.
pub struct ProductionResolver {
    layout: CacheLayout,
    client: reqwest::Client,
    /// Shared credential applied to every `Authorization: Bearer ...`
    /// header. `None` = unauthenticated registry.
    bearer_token: Option<String>,
    /// Default registry consulted when the kernel does not pass a
    /// `RegistryRef` hint. `None` = the resolver requires a hint
    /// per-call (kernel callers MUST surface
    /// `ImageResolverError::NoRegistryHint`).
    default_registry: Option<RegistryRef>,
    pulls: Mutex<HashMap<OciDigest, Arc<Mutex<()>>>>,
}

impl ProductionResolver {
    /// Construct a production resolver.
    ///
    /// * `cache_root` — `$RAXIS_DATA_DIR/oci-cache/`
    /// * `client`     — caller-owned `reqwest::Client` (the kernel
    ///                  shares one client with the gateway and the
    ///                  http-credential proxy adapter so the same
    ///                  TLS root store + connection pool are
    ///                  reused).
    /// * `bearer_token` — optional shared bearer token applied to
    ///                    every registry request.
    /// * `default_registry` — optional default `RegistryRef`. Used
    ///                        when the kernel calls
    ///                        [`ImageResolver::resolve`] without a
    ///                        registry hint.
    pub fn new(
        cache_root: impl Into<PathBuf>,
        client: reqwest::Client,
        bearer_token: Option<String>,
        default_registry: Option<RegistryRef>,
    ) -> Self {
        Self {
            layout: CacheLayout::new(cache_root),
            client,
            bearer_token,
            default_registry,
            pulls: Mutex::new(HashMap::new()),
        }
    }

    /// Borrow the cache layout the resolver is operating against.
    /// Tests use this to address on-disk paths directly.
    pub fn layout(&self) -> &CacheLayout {
        &self.layout
    }

    async fn acquire_pull_slot(&self, digest: &OciDigest) -> Arc<Mutex<()>> {
        let mut map = self.pulls.lock().await;

        if let Some(existing) = map.get(digest) {
            return Arc::clone(existing);
        }

        // §7 cap: drop the oldest entry on overflow. We do not track
        // timestamps for true LRU semantics; in practice the in-flight
        // set is tiny and the bound exists as a defensive limit
        // against runaway memory rather than as a strict eviction
        // policy. A removed entry is safe to drop because (a) any
        // task currently holding it owns its `Arc` independent of the
        // map, (b) a future pull of the same digest will re-insert.
        if map.len() >= PULL_LRU_CAP {
            if let Some(victim) = map.keys().next().cloned() {
                map.remove(&victim);
            }
        }

        let slot = Arc::new(Mutex::new(()));
        map.insert(*digest, Arc::clone(&slot));
        slot
    }

    /// Returns Ok(()) if the cache already holds a digest-verified
    /// extracted image; otherwise the caller must run the pull
    /// pipeline.
    async fn cache_hit_extracted(&self, digest: &OciDigest) -> bool {
        // Cheap heuristic: if `rootfs.img` is present we trust the
        // §4 atomic-rename invariant. Re-hashing on every call is
        // policy-sound but cripples warm-cache latency; the
        // `PrePopulatedResolver` re-hashes because it has no other
        // way to detect tampering, but the ProductionResolver's
        // §6 phase-3 verification on pull is sufficient.
        tokio::fs::try_exists(self.layout.rootfs_image_path(digest))
            .await
            .unwrap_or(false)
    }
}

#[async_trait]
impl ImageResolver for ProductionResolver {
    async fn resolve(
        &self,
        oci_digest: &OciDigest,
        registry_hint: Option<&RegistryRef>,
    ) -> Result<ResolvedImage, ImageResolverError> {
        // Fast cache-hit path: no pull lock, no network.
        if self.cache_hit_extracted(oci_digest).await {
            return Ok(ResolvedImage {
                rootfs_image_path: self.layout.rootfs_image_path(oci_digest),
                oci_config_path: self.layout.oci_config_path(oci_digest),
                verified_digest: *oci_digest,
            });
        }

        // Slow path: serialize concurrent pulls of the same digest.
        let slot = self.acquire_pull_slot(oci_digest).await;
        let _slot_guard = slot.lock().await;

        // Re-check the cache after acquiring the slot: a
        // concurrently-arriving pull may have completed while we
        // waited.
        if self.cache_hit_extracted(oci_digest).await {
            return Ok(ResolvedImage {
                rootfs_image_path: self.layout.rootfs_image_path(oci_digest),
                oci_config_path: self.layout.oci_config_path(oci_digest),
                verified_digest: *oci_digest,
            });
        }

        // Resolve the registry endpoint.
        let registry = registry_hint
            .cloned()
            .or_else(|| self.default_registry.clone())
            .ok_or(ImageResolverError::NoRegistryHint {
                digest: *oci_digest,
            })?;

        // Phase 1 (lock):    elided per §7 in-process design.
        // Phase 2 (stage):
        let staging_path = self.layout.blob_staging_path(oci_digest);
        let actual_digest = match crate::pull::stream_blob_to_staging(
            &self.client,
            &registry.host,
            &registry.repository,
            oci_digest,
            self.bearer_token.as_deref(),
            &staging_path,
        )
        .await
        {
            Ok(d) => d,
            Err(e) => {
                crate::pull::remove_if_exists(&staging_path).await;
                return Err(e);
            }
        };

        // Phase 3 (verify):
        if &actual_digest != oci_digest {
            crate::pull::remove_if_exists(&staging_path).await;
            return Err(ImageResolverError::DigestMismatch {
                expected: *oci_digest,
                actual: actual_digest,
                path: staging_path,
            });
        }

        // Phase 4 (atomic rename):
        let blob_path = self.layout.blob_path(oci_digest);
        crate::pull::atomic_rename(&staging_path, &blob_path).await?;

        // Phase 5 (extract):
        let extracted_dir = self.layout.extracted_dir(oci_digest);
        crate::extract::extract_into_images(&blob_path, &extracted_dir).await?;

        // Defense-in-depth: re-verify the extracted rootfs hashes to
        // the same digest. The copy in §6 phase 5 uses `tokio::fs::copy`
        // which is byte-faithful, but the cost of a single re-read
        // is small and the audit chain becomes self-evident.
        if let Err(e) =
            verify_rootfs_digest(&self.layout.rootfs_image_path(oci_digest), oci_digest).await
        {
            // Aggressive cleanup: remove the half-extracted dir so
            // a follow-up resolve re-tries from the cached blob.
            let _ = tokio::fs::remove_dir_all(&extracted_dir).await;
            return Err(e);
        }

        Ok(ResolvedImage {
            rootfs_image_path: self.layout.rootfs_image_path(oci_digest),
            oci_config_path: self.layout.oci_config_path(oci_digest),
            verified_digest: *oci_digest,
        })
    }

    fn prune_unreferenced(
        &self,
        live_digests: &HashSet<OciDigest>,
    ) -> Result<u64, ImageResolverError> {
        // Reuse the same prune logic as `PrePopulatedResolver` —
        // walk `images/sha256/<aa>/<full>/` and unlink any digest
        // not in the live set. Blobs under `blobs/sha256/<aa>/`
        // are GC'd in the same pass.
        prune_under(self.layout.root().join("images/sha256"), live_digests).and_then(
            |images_freed| {
                Ok(images_freed
                    + prune_blobs_under(self.layout.root().join("blobs/sha256"), live_digests)?)
            },
        )
    }
}

async fn verify_rootfs_digest(
    path: &std::path::Path,
    expected: &OciDigest,
) -> Result<(), ImageResolverError> {
    use tokio::io::AsyncReadExt;
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|source| ImageResolverError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .await
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
    let actual = OciDigest::from_sha256_bytes(bytes);
    if &actual != expected {
        return Err(ImageResolverError::CacheCorrupted {
            path: path.to_path_buf(),
            detail: format!("post-extract verify: expected {expected}, got {actual}",),
        });
    }
    Ok(())
}

fn prune_under(
    images_root: PathBuf,
    live_digests: &HashSet<OciDigest>,
) -> Result<u64, ImageResolverError> {
    use std::fs;
    if !images_root.exists() {
        return Ok(0);
    }
    let mut total = 0u64;
    for shard in fs::read_dir(&images_root).map_err(|source| ImageResolverError::Io {
        path: images_root.clone(),
        source,
    })? {
        let shard = shard.map_err(|source| ImageResolverError::Io {
            path: images_root.clone(),
            source,
        })?;
        for digest_entry in fs::read_dir(shard.path()).map_err(|source| ImageResolverError::Io {
            path: shard.path(),
            source,
        })? {
            let digest_dir = digest_entry.map_err(|source| ImageResolverError::Io {
                path: shard.path(),
                source,
            })?;
            let Some(name) = digest_dir.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Ok(digest) = format!("sha256:{name}").parse::<OciDigest>() else {
                continue;
            };
            if live_digests.contains(&digest) {
                continue;
            }
            total += dir_size(&digest_dir.path())?;
            fs::remove_dir_all(&digest_dir.path()).map_err(|source| ImageResolverError::Io {
                path: digest_dir.path(),
                source,
            })?;
        }
    }
    Ok(total)
}

fn prune_blobs_under(
    blobs_root: PathBuf,
    live_digests: &HashSet<OciDigest>,
) -> Result<u64, ImageResolverError> {
    use std::fs;
    if !blobs_root.exists() {
        return Ok(0);
    }
    let mut total = 0u64;
    for shard in fs::read_dir(&blobs_root).map_err(|source| ImageResolverError::Io {
        path: blobs_root.clone(),
        source,
    })? {
        let shard = shard.map_err(|source| ImageResolverError::Io {
            path: blobs_root.clone(),
            source,
        })?;
        for blob in fs::read_dir(shard.path()).map_err(|source| ImageResolverError::Io {
            path: shard.path(),
            source,
        })? {
            let blob = blob.map_err(|source| ImageResolverError::Io {
                path: shard.path(),
                source,
            })?;
            let Some(name) = blob.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            // Strip suffix to get the hex digest.
            let hex = name
                .strip_suffix(".tar.zst")
                .or_else(|| name.strip_suffix(".staging"))
                .or_else(|| name.strip_suffix(".json"))
                .unwrap_or(&name);
            let Ok(digest) = format!("sha256:{hex}").parse::<OciDigest>() else {
                continue;
            };
            if live_digests.contains(&digest) {
                continue;
            }
            let meta = blob.metadata().map_err(|source| ImageResolverError::Io {
                path: blob.path(),
                source,
            })?;
            if meta.is_file() {
                total += meta.len();
                fs::remove_file(blob.path()).map_err(|source| ImageResolverError::Io {
                    path: blob.path(),
                    source,
                })?;
            }
        }
    }
    Ok(total)
}

fn dir_size(p: &std::path::Path) -> Result<u64, ImageResolverError> {
    use std::fs;
    let mut total = 0u64;
    for entry in fs::read_dir(p).map_err(|source| ImageResolverError::Io {
        path: p.to_path_buf(),
        source,
    })? {
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
    use std::convert::Infallible;
    use std::net::SocketAddr;

    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::body::Incoming;
    use hyper::service::service_fn;
    use hyper::{Request, Response, StatusCode};
    use hyper_util::rt::TokioIo;
    use tempfile::TempDir;

    fn sha256_of(bytes: &[u8]) -> OciDigest {
        let mut h = Sha256::new();
        h.update(bytes);
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        OciDigest::from_sha256_bytes(out)
    }

    /// Spawn an in-process HTTP server that emulates the OCI
    /// distribution-spec `GET /v2/<repo>/blobs/<digest>` endpoint.
    /// Returns `(addr, registry_repo)` and a closure that yields
    /// the next configured response (so tests can stage 200, 404,
    /// 503, mismatch, etc).
    async fn spawn_oci_fixture(
        responses: Vec<(StatusCode, Vec<u8>)>,
    ) -> (SocketAddr, std::sync::Arc<std::sync::Mutex<usize>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let counter = std::sync::Arc::new(std::sync::Mutex::new(0usize));
        let counter_ret = counter.clone();
        let responses = std::sync::Arc::new(responses);
        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let counter = counter.clone();
                let responses = responses.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(
                            io,
                            service_fn(move |_req: Request<Incoming>| {
                                let counter = counter.clone();
                                let responses = responses.clone();
                                async move {
                                    let mut idx = counter.lock().unwrap();
                                    let i = *idx;
                                    *idx += 1;
                                    let (status, body) = responses
                                        .get(i)
                                        .cloned()
                                        .unwrap_or((StatusCode::OK, Vec::new()));
                                    Ok::<_, Infallible>(
                                        Response::builder()
                                            .status(status)
                                            .body(Full::new(Bytes::from(body)))
                                            .unwrap(),
                                    )
                                }
                            }),
                        )
                        .await;
                });
            }
        });
        (addr, counter_ret)
    }

    fn http_client_for_loopback() -> reqwest::Client {
        // Loopback fixture is HTTP, not HTTPS. Build a client that
        // tolerates the URL's scheme via `reqwest::Url` rewriting.
        // We use the danger flag because the URL builder hardcodes
        // https://; tests rewrite the host:port before calling the
        // resolver via `default_registry`.
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap()
    }

    /// Tests need to override the HTTPS scheme with HTTP for the
    /// loopback fixture. We do this by constructing a registry whose
    /// `host` is the literal `127.0.0.1:<port>` and patching the URL
    /// builder via a dedicated test resolver wrapper.
    struct TestResolver {
        inner: ProductionResolver,
        base_url: String,
    }

    impl TestResolver {
        async fn resolve_via_http(
            &self,
            digest: &OciDigest,
        ) -> Result<ResolvedImage, ImageResolverError> {
            // Manually drive the §6 pipeline against the http
            // fixture. We don't go through the production resolver
            // because its URL builder hardcodes https://.
            let staging = self.inner.layout.blob_staging_path(digest);
            if let Some(parent) = staging.parent() {
                tokio::fs::create_dir_all(parent).await.unwrap();
            }
            let resp = self
                .inner
                .client
                .get(&self.base_url)
                .send()
                .await
                .map_err(|e| ImageResolverError::RegistryUnreachable {
                    host: self.base_url.clone(),
                    detail: e.to_string(),
                })?;
            let status = resp.status();
            if status.is_client_error() {
                return Err(match status.as_u16() {
                    401 | 403 => ImageResolverError::RegistryAuthRejected {
                        host: self.base_url.clone(),
                        repository: "test".into(),
                    },
                    404 => ImageResolverError::RegistryNotFound {
                        host: self.base_url.clone(),
                        repository: "test".into(),
                        digest: *digest,
                    },
                    _ => ImageResolverError::RegistryServerError {
                        host: self.base_url.clone(),
                        status: status.as_u16(),
                    },
                });
            }
            if status.is_server_error() {
                return Err(ImageResolverError::RegistryServerError {
                    host: self.base_url.clone(),
                    status: status.as_u16(),
                });
            }
            let body = resp.bytes().await.unwrap();
            let mut hasher = Sha256::new();
            hasher.update(&body);
            tokio::fs::write(&staging, &body).await.unwrap();

            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&hasher.finalize());
            let actual = OciDigest::from_sha256_bytes(bytes);
            if &actual != digest {
                let _ = tokio::fs::remove_file(&staging).await;
                return Err(ImageResolverError::DigestMismatch {
                    expected: *digest,
                    actual,
                    path: staging,
                });
            }
            let blob = self.inner.layout.blob_path(digest);
            crate::pull::atomic_rename(&staging, &blob).await?;
            let dir = self.inner.layout.extracted_dir(digest);
            crate::extract::extract_into_images(&blob, &dir).await?;
            Ok(ResolvedImage {
                rootfs_image_path: self.inner.layout.rootfs_image_path(digest),
                oci_config_path: self.inner.layout.oci_config_path(digest),
                verified_digest: *digest,
            })
        }
    }

    #[tokio::test]
    async fn resolve_pulls_and_stages_a_correctly_hashed_blob() {
        let body = b"erofs-rootfs-bytes" as &[u8];
        let digest = sha256_of(body);

        let (addr, counter) = spawn_oci_fixture(vec![(StatusCode::OK, body.to_vec())]).await;

        let tmp = TempDir::new().unwrap();
        let inner = ProductionResolver::new(tmp.path(), http_client_for_loopback(), None, None);
        let test = TestResolver {
            inner,
            base_url: format!(
                "http://{addr}/v2/test/blobs/sha256:{}",
                hex::encode(digest.as_bytes())
            ),
        };

        let resolved = test.resolve_via_http(&digest).await.unwrap();
        assert_eq!(resolved.verified_digest, digest);
        assert!(resolved.rootfs_image_path.exists());
        assert!(resolved.oci_config_path.exists());
        assert_eq!(*counter.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn resolve_returns_digest_mismatch_when_body_disagrees() {
        let actual_body = b"surprise!" as &[u8];
        let claimed: OciDigest =
            "sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
                .parse()
                .unwrap();
        let actual_digest = sha256_of(actual_body);
        assert_ne!(claimed, actual_digest);

        let (addr, _) = spawn_oci_fixture(vec![(StatusCode::OK, actual_body.to_vec())]).await;

        let tmp = TempDir::new().unwrap();
        let inner = ProductionResolver::new(tmp.path(), http_client_for_loopback(), None, None);
        let test = TestResolver {
            inner,
            base_url: format!(
                "http://{addr}/v2/test/blobs/sha256:{}",
                hex::encode(claimed.as_bytes())
            ),
        };

        let err = test.resolve_via_http(&claimed).await.unwrap_err();
        match err {
            ImageResolverError::DigestMismatch {
                expected, actual, ..
            } => {
                assert_eq!(expected, claimed);
                assert_eq!(actual, actual_digest);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn resolve_returns_registry_not_found_on_404() {
        let digest: OciDigest =
            "sha256:11112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
                .parse()
                .unwrap();
        let (addr, _) =
            spawn_oci_fixture(vec![(StatusCode::NOT_FOUND, b"not found".to_vec())]).await;
        let tmp = TempDir::new().unwrap();
        let inner = ProductionResolver::new(tmp.path(), http_client_for_loopback(), None, None);
        let test = TestResolver {
            inner,
            base_url: format!(
                "http://{addr}/v2/test/blobs/sha256:{}",
                hex::encode(digest.as_bytes())
            ),
        };
        let err = test.resolve_via_http(&digest).await.unwrap_err();
        assert!(matches!(err, ImageResolverError::RegistryNotFound { .. }));
    }

    #[tokio::test]
    async fn resolve_returns_auth_rejected_on_401() {
        let digest: OciDigest =
            "sha256:22112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
                .parse()
                .unwrap();
        let (addr, _) =
            spawn_oci_fixture(vec![(StatusCode::UNAUTHORIZED, b"go away".to_vec())]).await;
        let tmp = TempDir::new().unwrap();
        let inner = ProductionResolver::new(tmp.path(), http_client_for_loopback(), None, None);
        let test = TestResolver {
            inner,
            base_url: format!(
                "http://{addr}/v2/test/blobs/sha256:{}",
                hex::encode(digest.as_bytes())
            ),
        };
        let err = test.resolve_via_http(&digest).await.unwrap_err();
        assert!(matches!(
            err,
            ImageResolverError::RegistryAuthRejected { .. }
        ));
    }

    #[tokio::test]
    async fn resolve_returns_server_error_on_503() {
        let digest: OciDigest =
            "sha256:33112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
                .parse()
                .unwrap();
        let (addr, _) =
            spawn_oci_fixture(vec![(StatusCode::SERVICE_UNAVAILABLE, b"down".to_vec())]).await;
        let tmp = TempDir::new().unwrap();
        let inner = ProductionResolver::new(tmp.path(), http_client_for_loopback(), None, None);
        let test = TestResolver {
            inner,
            base_url: format!(
                "http://{addr}/v2/test/blobs/sha256:{}",
                hex::encode(digest.as_bytes())
            ),
        };
        let err = test.resolve_via_http(&digest).await.unwrap_err();
        match err {
            ImageResolverError::RegistryServerError { status, .. } => {
                assert_eq!(status, 503);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn no_registry_hint_yields_no_registry_hint_error() {
        let digest: OciDigest =
            "sha256:44112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
                .parse()
                .unwrap();
        let tmp = TempDir::new().unwrap();
        let resolver = ProductionResolver::new(tmp.path(), http_client_for_loopback(), None, None);
        let err = resolver.resolve(&digest, None).await.unwrap_err();
        assert!(matches!(err, ImageResolverError::NoRegistryHint { .. }));
    }

    #[tokio::test]
    async fn cached_resolve_is_a_no_network_op() {
        // Pre-stage a digest-correct rootfs, then call resolve.
        let body = b"already-cached" as &[u8];
        let digest = sha256_of(body);

        let tmp = TempDir::new().unwrap();
        let resolver = ProductionResolver::new(
            tmp.path(),
            http_client_for_loopback(),
            None,
            None, // No default registry, no hint — yet resolve still succeeds.
        );

        let extracted = resolver.layout().extracted_dir(&digest);
        std::fs::create_dir_all(&extracted).unwrap();
        std::fs::write(extracted.join("rootfs.img"), body).unwrap();
        std::fs::write(extracted.join("config.json"), b"{}").unwrap();

        let resolved = resolver.resolve(&digest, None).await.unwrap();
        assert_eq!(resolved.verified_digest, digest);
        assert_eq!(
            resolved.rootfs_image_path,
            resolver.layout().rootfs_image_path(&digest)
        );
    }

    #[tokio::test]
    async fn prune_unreferenced_walks_both_blobs_and_images() {
        let alive = b"alive" as &[u8];
        let dead = b"dead" as &[u8];
        let alive_d = sha256_of(alive);
        let dead_d = sha256_of(dead);

        let tmp = TempDir::new().unwrap();
        let resolver = ProductionResolver::new(tmp.path(), http_client_for_loopback(), None, None);

        for (d, body) in [(alive_d, alive), (dead_d, dead)] {
            let dir = resolver.layout().extracted_dir(&d);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("rootfs.img"), body).unwrap();
            std::fs::write(dir.join("config.json"), b"{}").unwrap();
            std::fs::write(dir.join("manifest.json"), b"{}").unwrap();
            let blob = resolver.layout().blob_path(&d);
            if let Some(parent) = blob.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&blob, body).unwrap();
        }

        let mut live = HashSet::new();
        live.insert(alive_d);

        let freed = resolver.prune_unreferenced(&live).unwrap();
        assert!(freed > 0);
        assert!(resolver.layout().rootfs_image_path(&alive_d).exists());
        assert!(!resolver.layout().rootfs_image_path(&dead_d).exists());
        assert!(resolver.layout().blob_path(&alive_d).exists());
        assert!(!resolver.layout().blob_path(&dead_d).exists());
    }
}
