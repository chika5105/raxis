//! Phase 5 of the §6 pull-and-verify pipeline.
//!
//! For V2 the only supported `mediaType` is
//! `application/vnd.raxis.image.rootfs.v1+erofs` — a single-blob
//! EROFS rootfs that is "extracted" by copying the verified blob
//! verbatim to `<images-dir>/<digest>/rootfs.img`. Future V3
//! work (general OCI tar layers, squashfs, rootfs deltas) wires
//! additional `MediaType` arms into [`extract_into_images`].
//!
//! The §6-text says the blob path on disk is `<digest>.tar.zst` for
//! historical OCI-naming compatibility, but for the EROFS-direct
//! mediatype the suffix is informational only — the byte stream is
//! the EROFS blob, not a tar.zst archive.

use std::path::Path;

use crate::ImageResolverError;

/// Extract the verified blob at `verified_blob_path` into the
/// `images/<digest>/` directory derived from the cache layout.
///
/// On success the directory contains:
/// * `rootfs.img`   — the EROFS rootfs the isolation backend boots
/// * `manifest.json` — placeholder synthesised manifest (so the
///   extracted directory is self-describing for diagnostics)
/// * `config.json`  — placeholder synthesised OCI config
///
/// V2 rationale for synthesised sidecars: the trait surface only
/// surfaces `rootfs_image_path` and `oci_config_path`; the kernel
/// session-spawn path reads `config.json` for `Env`, `Entrypoint`,
/// `Cmd`. For the V2 EROFS-direct mediatype the upstream blob does
/// not carry an OCI config — the operator publishes the EROFS image
/// directly. We synthesise an empty-but-well-formed
/// `{"config":{}}` document so a kernel that defaults to "use the
/// in-image entrypoint" gets sensible no-op values without a None /
/// Option<&Path> code path. Operators that need a richer OCI config
/// can switch their image to a future tar+config mediatype when V3
/// adds support.
pub(crate) async fn extract_into_images(
    verified_blob_path: &Path,
    extracted_dir:      &Path,
) -> Result<(), ImageResolverError> {
    tokio::fs::create_dir_all(extracted_dir).await
        .map_err(|source| ImageResolverError::Io {
            path: extracted_dir.to_path_buf(), source,
        })?;

    let rootfs   = extracted_dir.join("rootfs.img");
    let manifest = extracted_dir.join("manifest.json");
    let config   = extracted_dir.join("config.json");

    // Copy is intentional, not rename — we want the cached blob to
    // stay addressable from `blobs/sha256/...` so a re-extract
    // (e.g. after a process kill mid-extract) can re-derive
    // `rootfs.img` without re-pulling.
    tokio::fs::copy(verified_blob_path, &rootfs).await
        .map_err(|source| ImageResolverError::Io {
            path: rootfs.clone(), source,
        })?;

    // Synthesised sidecars. See module docs for rationale.
    let manifest_doc = b"{\"schemaVersion\":2,\"mediaType\":\"application/vnd.raxis.image.rootfs.v1+erofs\"}";
    let config_doc   = b"{\"config\":{}}";
    tokio::fs::write(&manifest, manifest_doc).await
        .map_err(|source| ImageResolverError::Io {
            path: manifest, source,
        })?;
    tokio::fs::write(&config, config_doc).await
        .map_err(|source| ImageResolverError::Io {
            path: config, source,
        })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[tokio::test]
    async fn extract_writes_rootfs_and_synthesised_sidecars() {
        let tmp     = TempDir::new().unwrap();
        let blob    = tmp.path().join("blob.bin");
        let extract = tmp.path().join("images/abc");

        let mut f = std::fs::File::create(&blob).unwrap();
        f.write_all(b"erofs-bytes").unwrap();
        drop(f);

        extract_into_images(&blob, &extract).await.unwrap();

        let rootfs = std::fs::read(extract.join("rootfs.img")).unwrap();
        assert_eq!(rootfs, b"erofs-bytes");

        let manifest = std::fs::read(extract.join("manifest.json")).unwrap();
        assert!(String::from_utf8_lossy(&manifest)
            .contains("application/vnd.raxis.image.rootfs.v1+erofs"));

        let config = std::fs::read(extract.join("config.json")).unwrap();
        assert_eq!(config, b"{\"config\":{}}");
    }

    #[tokio::test]
    async fn extract_creates_intermediate_directories() {
        let tmp     = TempDir::new().unwrap();
        let blob    = tmp.path().join("blob.bin");
        let extract = tmp.path().join("nested/many/levels/images/abc");

        std::fs::write(&blob, b"data").unwrap();
        extract_into_images(&blob, &extract).await.unwrap();
        assert!(extract.join("rootfs.img").exists());
    }
}
