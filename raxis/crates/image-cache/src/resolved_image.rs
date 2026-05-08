//! `ResolvedImage` — return value from
//! [`ImageResolver::resolve`](crate::ImageResolver::resolve).

use std::path::PathBuf;

use crate::OciDigest;

/// **The kernel-visible product of a successful resolve.** Pinned
/// by `image-cache.md §5`.
///
/// All three paths are absolute. Every path's existence is the
/// resolver's contract; the kernel does NOT re-stat them before
/// handing them to the isolation backend.
#[derive(Debug, Clone)]
pub struct ResolvedImage {
    /// Absolute path to the EROFS / squashfs rootfs blob the
    /// isolation backend boots. Stable across the lifetime of the
    /// `oci_digest` (cache writes are atomic-rename per
    /// `image-cache.md §6`).
    pub rootfs_image_path: PathBuf,

    /// Absolute path to the OCI image's `config.json`. Used by the
    /// kernel session-spawn path to read `Env`, `Entrypoint`, and
    /// `Cmd` (the kernel composes its own `entrypoint_argv` but
    /// honours the image's `Env` for plan-defined environment).
    pub oci_config_path: PathBuf,

    /// The byte-equality-verified digest. Echoed back so the
    /// kernel can carry it into audit events without a second
    /// `compute_image_digest` pass.
    pub verified_digest: OciDigest,
}
