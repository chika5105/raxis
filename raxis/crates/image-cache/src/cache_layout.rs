//! `CacheLayout` — pure path-derivation helper for the on-disk
//! layout in `image-cache.md §4`. Has no I/O; the kernel uses it
//! to address pre-staged blobs without depending on a registry
//! client.
//!
//! The layout under `<root>` (in production this is
//! `$RAXIS_DATA_DIR/oci-cache/`) is:
//!
//! ```text
//! <root>/blobs/sha256/<aa>/<full>.tar.zst        — pulled image blob
//! <root>/blobs/sha256/<aa>/<full>.json           — parsed manifest
//! <root>/blobs/sha256/<aa>/<full>.staging        — in-flight pull (transient)
//! <root>/images/sha256/<aa>/<full>/rootfs.img    — extracted rootfs (kernel boot input)
//! <root>/images/sha256/<aa>/<full>/manifest.json — extracted manifest copy
//! <root>/images/sha256/<aa>/<full>/config.json   — extracted OCI config
//! <root>/locks/pulls/<aa>/<full>.lockfile        — flock(2) coordination
//! ```
//!
//! `<aa>` is the two-character shard prefix (the first two hex
//! chars of the digest). Keeps each directory under a few hundred
//! entries even for a long-running cache.

use std::path::{Path, PathBuf};

use crate::OciDigest;

const BLOBS_DIR: &str = "blobs/sha256";
const IMAGES_DIR: &str = "images/sha256";
const LOCKS_DIR: &str = "locks/pulls";

const BLOB_SUFFIX: &str = ".tar.zst";
const BLOB_MANIFEST: &str = ".json";
const BLOB_STAGING: &str = ".staging";
const ROOTFS_FILE: &str = "rootfs.img";
const MANIFEST_FILE: &str = "manifest.json";
const CONFIG_FILE: &str = "config.json";
const LOCK_FILE_SUFFIX: &str = ".lockfile";

/// Pure path derivation for the cache layout. Construct with
/// [`CacheLayout::new`]; no I/O happens until the kernel actually
/// stats / opens / reads the returned paths.
#[derive(Debug, Clone)]
pub struct CacheLayout {
    root: PathBuf,
}

impl CacheLayout {
    /// Construct rooted at `root` (in production
    /// `$RAXIS_DATA_DIR/oci-cache/`).
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Borrow the cache root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Path to the pulled image blob (`<root>/blobs/sha256/<aa>/<full>.tar.zst`).
    pub fn blob_path(&self, digest: &OciDigest) -> PathBuf {
        self.blob_path_with_suffix(digest, BLOB_SUFFIX)
    }

    /// Path to the parsed manifest sidecar (`<...>.json`).
    pub fn blob_manifest_path(&self, digest: &OciDigest) -> PathBuf {
        self.blob_path_with_suffix(digest, BLOB_MANIFEST)
    }

    /// Path to the in-flight staging file (`<...>.staging`).
    pub fn blob_staging_path(&self, digest: &OciDigest) -> PathBuf {
        self.blob_path_with_suffix(digest, BLOB_STAGING)
    }

    fn blob_path_with_suffix(&self, digest: &OciDigest, suffix: &str) -> PathBuf {
        let shard = digest.shard_prefix();
        let hex = hex::encode(digest.as_bytes());
        let mut p = self.root.join(BLOBS_DIR).join(shard);
        p.push(format!("{hex}{suffix}"));
        p
    }

    /// Directory holding the extracted image
    /// (`<root>/images/sha256/<aa>/<full>/`).
    pub fn extracted_dir(&self, digest: &OciDigest) -> PathBuf {
        let shard = digest.shard_prefix();
        let hex = hex::encode(digest.as_bytes());
        self.root.join(IMAGES_DIR).join(shard).join(hex)
    }

    /// Path to the extracted rootfs blob — the [`crate::ResolvedImage::rootfs_image_path`]
    /// production value.
    pub fn rootfs_image_path(&self, digest: &OciDigest) -> PathBuf {
        self.extracted_dir(digest).join(ROOTFS_FILE)
    }

    /// Path to the extracted manifest copy.
    pub fn manifest_path(&self, digest: &OciDigest) -> PathBuf {
        self.extracted_dir(digest).join(MANIFEST_FILE)
    }

    /// Path to the extracted OCI config.json — the [`crate::ResolvedImage::oci_config_path`]
    /// production value.
    pub fn oci_config_path(&self, digest: &OciDigest) -> PathBuf {
        self.extracted_dir(digest).join(CONFIG_FILE)
    }

    /// Path to the per-digest pull lockfile.
    pub fn lock_file_path(&self, digest: &OciDigest) -> PathBuf {
        let shard = digest.shard_prefix();
        let hex = hex::encode(digest.as_bytes());
        let mut p = self.root.join(LOCKS_DIR).join(shard);
        p.push(format!("{hex}{LOCK_FILE_SUFFIX}"));
        p
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d() -> OciDigest {
        // Hex starts with `ab`, so shard prefix is "ab".
        "sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
            .parse()
            .unwrap()
    }

    #[test]
    fn root_is_returned_verbatim() {
        let layout = CacheLayout::new("/tmp/raxis-cache");
        assert_eq!(layout.root(), Path::new("/tmp/raxis-cache"));
    }

    #[test]
    fn blob_path_uses_shard_prefix_and_full_hex() {
        let layout = CacheLayout::new("/cache");
        let p = layout.blob_path(&d());
        assert_eq!(
            p,
            PathBuf::from(
                "/cache/blobs/sha256/ab/\
                 abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234.tar.zst"
            ),
        );
    }

    #[test]
    fn manifest_and_staging_share_hex_prefix() {
        let layout = CacheLayout::new("/cache");
        let blob = layout.blob_path(&d());
        let manifest = layout.blob_manifest_path(&d());
        let staging = layout.blob_staging_path(&d());

        let blob_stem = blob
            .file_name()
            .unwrap()
            .to_string_lossy()
            .strip_suffix(".tar.zst")
            .unwrap()
            .to_string();
        let m_stem = manifest
            .file_name()
            .unwrap()
            .to_string_lossy()
            .strip_suffix(".json")
            .unwrap()
            .to_string();
        let s_stem = staging
            .file_name()
            .unwrap()
            .to_string_lossy()
            .strip_suffix(".staging")
            .unwrap()
            .to_string();

        assert_eq!(blob_stem, m_stem);
        assert_eq!(blob_stem, s_stem);
    }

    #[test]
    fn rootfs_and_config_live_in_extracted_dir() {
        let layout = CacheLayout::new("/cache");
        let dir = layout.extracted_dir(&d());
        assert_eq!(layout.rootfs_image_path(&d()), dir.join("rootfs.img"));
        assert_eq!(layout.oci_config_path(&d()), dir.join("config.json"));
        assert_eq!(layout.manifest_path(&d()), dir.join("manifest.json"));
    }

    #[test]
    fn lock_file_in_locks_dir_with_lockfile_suffix() {
        let layout = CacheLayout::new("/cache");
        let p = layout.lock_file_path(&d());
        assert!(p.starts_with("/cache/locks/pulls/ab"));
        assert!(p.to_string_lossy().ends_with(".lockfile"));
    }

    #[test]
    fn distinct_digests_get_distinct_paths() {
        let a: OciDigest =
            "sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
                .parse()
                .unwrap();
        let b: OciDigest =
            "sha256:11112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
                .parse()
                .unwrap();
        let layout = CacheLayout::new("/cache");
        assert_ne!(layout.blob_path(&a), layout.blob_path(&b));
        assert_ne!(layout.extracted_dir(&a), layout.extracted_dir(&b));
        assert_ne!(layout.lock_file_path(&a), layout.lock_file_path(&b));
    }

    #[test]
    fn shard_prefix_separates_digests_by_first_byte() {
        let a: OciDigest =
            "sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
                .parse()
                .unwrap();
        let b: OciDigest =
            "sha256:ff112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
                .parse()
                .unwrap();
        let layout = CacheLayout::new("/cache");
        // a goes under .../sha256/00/...; b goes under .../sha256/ff/...
        assert!(layout
            .blob_path(&a)
            .to_string_lossy()
            .contains("/sha256/00/"));
        assert!(layout
            .blob_path(&b)
            .to_string_lossy()
            .contains("/sha256/ff/"));
    }
}
