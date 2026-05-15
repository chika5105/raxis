//! Reproducible builder for the canonical RAXIS VM images.
//!
//! Normative reference:
//! `planner-harness.md §14.4 — Image-build pipeline` and
//! `planner-harness.md §14.2 — crates/raxis-image-builder/`.
//!
//! ## What this crate produces
//!
//! Given an in-tree `images/<role>/` directory containing:
//!
//! ```text
//! images/<role>/
//!     manifest.toml      # build inputs: source_date_epoch, role, kernel
//!                        #   version, tool versions, plus the path layout
//!                        #   for the source rootfs
//!     rootfs/            # the actual rootfs file tree (tracked in-tree
//!                        #   for the static portions; built artefacts
//!                        #   under build/ are excluded from VCS)
//!     verify.sh          # tooling-side smoke test the builder runs
//!                        #   after assembling the rootfs
//! ```
//!
//! the builder walks `rootfs/`, hashes every file, sorts the file list,
//! computes the bundle hash, signs it with the loaded Ed25519 key, and
//! writes `out/<role>.manifest.json`. The signed manifest is the
//! kernel-side source of truth.
//!
//! Not done by the library:
//!
//! 1. The `mkfs.erofs` invocation that turns `rootfs/` into the
//!    `<role>.erofs` rootfs blob — that is a thin shell-out in
//!    [`erofs_assemble`] and depends on the system `mkfs.erofs`. The
//!    builder runs it only when `--with-erofs` is set; tests assert
//!    determinism of the manifest, not the binary blob (the manifest
//!    is the trust anchor).
//! 2. Network access — every step is hermetic. The builder refuses to
//!    invoke `cargo`, `npm`, or any package manager. The expectation
//!    is that `rootfs/` is already populated by an out-of-band
//!    pipeline (e.g. a Dockerfile/Containerfile that runs once per
//!    release).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use ed25519_dalek::{Signer, SigningKey};
use raxis_image_manifest::{
    fingerprint_signing_key, sha256_file_hex, BuildEnv, ImageFormat, ImageManifest, ManifestError,
    ManifestFile, Role, SCHEMA_VERSION,
};
use std::path::{Path, PathBuf};

/// Canonical filename for the build-input manifest at the top of each
/// `images/<role>/` directory.
pub const INPUT_MANIFEST_NAME: &str = "manifest.toml";

/// Build-input shape (loaded from `images/<role>/manifest.toml`). The
/// fields populated here become the manifest's `build_env`; the
/// `files` list is recomputed by the builder.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct BuildInputs {
    /// Which canonical image this directory builds.
    pub role: Role,
    /// Kernel version this image is paired with.
    pub kernel_version: String,
    /// `SOURCE_DATE_EPOCH` for tar/erofs determinism.
    pub source_date_epoch: u64,
    /// Pinned mkfs.erofs version.
    pub erofs_version: String,
    /// Pinned tar implementation version.
    pub tar_version: String,
    /// Pinned zstd version.
    pub zstd_version: String,
    /// Rootfs on-disk shape this build emits. Defaults via
    /// `default_image_format` to `RootfsErofs` so existing
    /// `images/<role>/manifest.toml` files keep building unchanged
    /// (the dev-host pipeline overrides this to
    /// `RootfsInitramfsCpio`).
    #[serde(default = "default_image_format")]
    pub image_format: ImageFormat,
}

/// Default `image_format` for `BuildInputs` when the field is absent
/// from `images/<role>/manifest.toml`. Returns the production shape
/// (`RootfsErofs`); dev-host pipelines must opt in to
/// `RootfsInitramfsCpio` explicitly.
fn default_image_format() -> ImageFormat {
    ImageFormat::RootfsErofs
}

/// Top-level errors the builder can surface. Wraps `ManifestError`
/// for any per-file issue and adds builder-only failure modes.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    /// Underlying manifest-crate error.
    #[error("manifest error: {0}")]
    Manifest(#[from] ManifestError),

    /// Source dir does not exist or is not a directory.
    #[error("source rootfs at {path} is not a usable directory")]
    SourceUnusable {
        /// The bad path.
        path: String,
    },

    /// Walk produced no files. Empty rootfs is a bug.
    #[error("source rootfs at {path} is empty")]
    EmptyRootfs {
        /// The empty path.
        path: String,
    },

    /// `manifest.toml` parse failed.
    #[error("inputs manifest at {path} is malformed: {reason}")]
    InputsParse {
        /// The path.
        path: String,
        /// Underlying parse error (already a String for portability).
        reason: String,
    },

    /// I/O error reading inputs / rootfs.
    #[error("builder io at {path}: {source}")]
    Io {
        /// What we were reading.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

impl BuildError {
    fn io(path: impl Into<String>, e: std::io::Error) -> Self {
        BuildError::Io {
            path: path.into(),
            source: e,
        }
    }
}

/// Walk `rootfs_dir` recursively, hash every file, return a sorted
/// `Vec<ManifestFile>`. Symlinks, devices, and FIFOs are rejected —
/// the canonical images contain only regular files (the EROFS layer
/// reconstructs symlinks via the manifest input later).
pub fn enumerate_rootfs(rootfs_dir: &Path) -> Result<Vec<ManifestFile>, BuildError> {
    if !rootfs_dir.is_dir() {
        return Err(BuildError::SourceUnusable {
            path: rootfs_dir.display().to_string(),
        });
    }
    let mut files: Vec<ManifestFile> = Vec::new();
    walk(rootfs_dir, rootfs_dir, &mut files)?;
    if files.is_empty() {
        return Err(BuildError::EmptyRootfs {
            path: rootfs_dir.display().to_string(),
        });
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(files)
}

fn walk(root: &Path, cur: &Path, out: &mut Vec<ManifestFile>) -> Result<(), BuildError> {
    use std::os::unix::fs::PermissionsExt;

    let entries =
        std::fs::read_dir(cur).map_err(|e| BuildError::io(cur.display().to_string(), e))?;
    let mut sorted: Vec<_> = entries.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    sorted.sort();
    for path in sorted {
        let meta = std::fs::symlink_metadata(&path)
            .map_err(|e| BuildError::io(path.display().to_string(), e))?;
        if meta.file_type().is_symlink() {
            // Skip symlinks during the manifest pass: the canonical
            // images express symlinks via mkfs.erofs's directives,
            // not as host-side symlinks. (The verify.sh smoke test
            // catches accidental symlinks at build time.)
            continue;
        }
        if meta.is_dir() {
            walk(root, &path, out)?;
            continue;
        }
        if !meta.is_file() {
            // Block devices / FIFOs aren't valid in our rootfs. Flag
            // it instead of silently dropping.
            return Err(BuildError::SourceUnusable {
                path: format!("{} (not a regular file or directory)", path.display()),
            });
        }
        let rel = path
            .strip_prefix(root)
            .map_err(|_| BuildError::SourceUnusable {
                path: path.display().to_string(),
            })?;
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        let (sha, size) = sha256_file_hex(&path)?;
        let mode = meta.permissions().mode() & 0o7777;
        out.push(ManifestFile {
            path: rel_str,
            sha256: sha,
            size,
            mode,
        });
    }
    Ok(())
}

/// Build a typed manifest given the inputs and a freshly-enumerated
/// file list. Computes the bundle hash; does NOT sign yet (callers
/// pass the manifest to [`sign_manifest`] when they have a key).
///
/// `image_artefact_sha256_hex` must be the lowercase-hex SHA-256 of
/// the packed `<role>-<kernel_version>.img` blob (or a deterministic
/// placeholder like `"0".repeat(64)` for unit tests that do not
/// produce an .img). The kernel's manifest-trust verification refuses
/// any manifest whose `image_artefact_sha256` does not match the
/// streamed-from-disk digest of the on-disk .img.
pub fn assemble_manifest(
    inputs: &BuildInputs,
    files: Vec<ManifestFile>,
    signing_key_fp_hex: String,
    image_artefact_sha256_hex: String,
) -> Result<ImageManifest, BuildError> {
    let mut m = ImageManifest {
        schema_version: SCHEMA_VERSION,
        role: inputs.role,
        kernel_version: inputs.kernel_version.clone(),
        bundle_hash: String::new(),
        image_artefact_sha256: image_artefact_sha256_hex,
        image_format: inputs.image_format,
        build_env: BuildEnv {
            source_date_epoch: inputs.source_date_epoch,
            erofs_version: inputs.erofs_version.clone(),
            tar_version: inputs.tar_version.clone(),
            zstd_version: inputs.zstd_version.clone(),
        },
        files,
        signing_key_fp: signing_key_fp_hex,
        signature: "0".repeat(128),
    };
    let bh = m.recompute_bundle_hash()?;
    m.bundle_hash = hex::encode(bh);
    Ok(m)
}

/// Stream the file at `path`, return its SHA-256 as lowercase hex.
/// Convenience over [`raxis_image_manifest::sha256_file_hex`] for the
/// common builder pattern of "compute the artefact digest after EROFS
/// assembly, before signing".
pub fn compute_artefact_digest_hex(path: &Path) -> Result<String, BuildError> {
    let (hex, _size) = sha256_file_hex(path)?;
    Ok(hex)
}

/// Sign the manifest's bundle hash with `key`. Idempotent: re-signing
/// a manifest that was signed by the same key over the same hash
/// yields a manifest that still verifies (Ed25519 signatures are
/// deterministic).
pub fn sign_manifest(manifest: &mut ImageManifest, key: &SigningKey) -> Result<(), BuildError> {
    let bh = manifest.bundle_hash_bytes()?;
    let sig = key.sign(&bh);
    manifest.signature = hex::encode(sig.to_bytes());
    manifest.signing_key_fp = hex::encode(fingerprint_signing_key(&key.verifying_key()));
    Ok(())
}

/// Convenience wrapper: assemble + sign. Used by the test harness and
/// by the `raxis-image-builder build` CLI.
///
/// `image_artefact_sha256_hex` is the lowercase-hex SHA-256 of the
/// packed `<role>-<kernel_version>.img` blob; pass a fixture string
/// in tests that do not produce an .img.
pub fn build_and_sign(
    inputs: &BuildInputs,
    rootfs_dir: &Path,
    image_artefact_sha256_hex: String,
    signing_key: &SigningKey,
) -> Result<ImageManifest, BuildError> {
    let files = enumerate_rootfs(rootfs_dir)?;
    let mut m = assemble_manifest(
        inputs,
        files,
        hex::encode(fingerprint_signing_key(&signing_key.verifying_key())),
        image_artefact_sha256_hex,
    )?;
    sign_manifest(&mut m, signing_key)?;
    Ok(m)
}

/// Read `inputs.toml` from disk.
pub fn read_inputs(path: &Path) -> Result<BuildInputs, BuildError> {
    let s =
        std::fs::read_to_string(path).map_err(|e| BuildError::io(path.display().to_string(), e))?;
    toml::from_str(&s).map_err(|e| BuildError::InputsParse {
        path: path.display().to_string(),
        reason: e.to_string(),
    })
}

/// EROFS assembly placeholder. The real implementation shells out to
/// `mkfs.erofs` with `-z zstd -T <SOURCE_DATE_EPOCH>` flags; on hosts
/// without `mkfs.erofs` the builder skips this step and only emits
/// the manifest. Returns the path of the produced blob (or `None` if
/// `mkfs.erofs` was not available).
///
/// This is intentionally a separate concern from the manifest: the
/// manifest is the trust anchor; the EROFS blob is a transport
/// optimisation. The kernel verifies the manifest at boot, the
/// mounted rootfs is verified by `verity` at runtime.
pub fn erofs_assemble(
    rootfs_dir: &Path,
    out_blob: &Path,
    source_date_epoch: u64,
) -> Result<Option<PathBuf>, BuildError> {
    if !command_exists("mkfs.erofs") {
        return Ok(None);
    }
    let status = std::process::Command::new("mkfs.erofs")
        .arg("-z")
        .arg("zstd")
        .arg("-T")
        .arg(source_date_epoch.to_string())
        .arg(out_blob)
        .arg(rootfs_dir)
        .status()
        .map_err(|e| BuildError::io("mkfs.erofs spawn".to_string(), e))?;
    if !status.success() {
        return Err(BuildError::Io {
            path: out_blob.display().to_string(),
            source: std::io::Error::other(format!("mkfs.erofs failed: {status}")),
        });
    }
    Ok(Some(out_blob.to_path_buf()))
}

fn command_exists(name: &str) -> bool {
    if let Ok(path) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path) {
            if dir.join(name).is_file() {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::{rngs::OsRng, RngCore};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn gen_key() -> SigningKey {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        SigningKey::from_bytes(&bytes)
    }

    fn write_file(root: &Path, rel: &str, body: &[u8], mode: u32) {
        let p = root.join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&p, body).unwrap();
        let mut perms = fs::metadata(&p).unwrap().permissions();
        perms.set_mode(mode);
        fs::set_permissions(&p, perms).unwrap();
    }

    fn build_inputs() -> BuildInputs {
        BuildInputs {
            role: Role::Reviewer,
            kernel_version: "0.1.0".to_owned(),
            source_date_epoch: 1700000000,
            erofs_version: "1.7.1".to_owned(),
            tar_version: "1.34".to_owned(),
            zstd_version: "1.5.5".to_owned(),
            image_format: ImageFormat::RootfsErofs,
        }
    }

    #[test]
    fn enumerate_rootfs_walks_recursive_files_and_sorts() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_owned();
        write_file(&root, "init", b"#!/init\n", 0o755);
        write_file(&root, "usr/bin/sh", b"sh\n", 0o755);
        write_file(&root, "etc/conf", b"k=v\n", 0o644);

        let files = enumerate_rootfs(&root).unwrap();
        let paths: Vec<_> = files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, vec!["etc/conf", "init", "usr/bin/sh"]);
        assert_eq!(files.iter().find(|f| f.path == "init").unwrap().mode, 0o755);
        assert_eq!(
            files.iter().find(|f| f.path == "etc/conf").unwrap().mode,
            0o644
        );
    }

    /// Determinism: rebuild the same rootfs twice; bundle hash and
    /// per-file sha256 must be byte-identical. Pins the
    /// `cargo run -p raxis-image-builder` reproducibility contract
    /// from `planner-harness.md §14.4`.
    #[test]
    fn build_and_sign_is_byte_deterministic_for_identical_rootfs() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_owned();
        write_file(&root, "init", b"raxis-init", 0o755);
        write_file(&root, "raxis-planner", b"FAKE_BIN_BYTES", 0o755);

        let key = gen_key();
        let inputs = build_inputs();

        let m1 = build_and_sign(&inputs, &root, "1".repeat(64), &key).unwrap();
        let m2 = build_and_sign(&inputs, &root, "1".repeat(64), &key).unwrap();

        assert_eq!(
            m1.bundle_hash, m2.bundle_hash,
            "bundle_hash must be reproducible for identical rootfs"
        );
        assert_eq!(
            m1.signature, m2.signature,
            "Ed25519 signatures over identical messages must be byte-equal"
        );
        assert_eq!(m1.files.len(), m2.files.len());
    }

    /// Modifying a single byte in the rootfs flips the bundle hash.
    /// Pins the manifest's tamper-evidence guarantee.
    #[test]
    fn build_changes_bundle_hash_when_one_byte_changes() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_owned();
        write_file(&root, "init", b"v1", 0o755);

        let key = gen_key();
        let inputs = build_inputs();

        let m1 = build_and_sign(&inputs, &root, "1".repeat(64), &key).unwrap();
        write_file(&root, "init", b"v2", 0o755);
        let m2 = build_and_sign(&inputs, &root, "1".repeat(64), &key).unwrap();

        assert_ne!(m1.bundle_hash, m2.bundle_hash);
    }

    /// Changing the image-artefact digest while keeping the rootfs
    /// constant flips the bundle hash. Pins that the manifest commits
    /// to the .img blob, not just the source files.
    #[test]
    fn build_changes_bundle_hash_when_image_artefact_sha256_changes() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_owned();
        write_file(&root, "init", b"v1", 0o755);

        let key = gen_key();
        let inputs = build_inputs();

        let m1 = build_and_sign(&inputs, &root, "1".repeat(64), &key).unwrap();
        let m2 = build_and_sign(&inputs, &root, "2".repeat(64), &key).unwrap();

        assert_ne!(
            m1.bundle_hash, m2.bundle_hash,
            "bundle_hash must change when image_artefact_sha256 changes"
        );
        assert_ne!(
            m1.signature, m2.signature,
            "signature must change when bundle_hash changes"
        );
    }

    /// Manifest produced by the builder verifies against the
    /// matching public key — no off-by-one between `build_and_sign`
    /// and `raxis_image_manifest::verify`.
    #[test]
    fn build_and_sign_round_trips_through_manifest_verify() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_owned();
        write_file(&root, "init", b"hello", 0o755);

        let key = gen_key();
        let vk = key.verifying_key();
        let m = build_and_sign(&build_inputs(), &root, "1".repeat(64), &key).unwrap();
        raxis_image_manifest::verify(&m, &vk)
            .expect("freshly built+signed manifest must verify against the matching VK");
    }

    /// `compute_artefact_digest_hex` matches the manifest crate's
    /// streaming SHA-256 — pin the API surface that the CLI driver
    /// relies on so it cannot drift from `raxis_image_manifest::sha256_file_hex`.
    #[test]
    fn compute_artefact_digest_hex_matches_manifest_streaming_sha256() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"raxis-image-builder-artefact-test").unwrap();
        f.flush().unwrap();

        let from_helper = compute_artefact_digest_hex(f.path()).unwrap();
        let (from_manifest, _) = sha256_file_hex(f.path()).unwrap();
        assert_eq!(from_helper, from_manifest);
    }

    /// Empty rootfs surfaces a typed error rather than producing a
    /// trivially-passing manifest.
    #[test]
    fn build_rejects_empty_rootfs() {
        let tmp = tempfile::tempdir().unwrap();
        let key = gen_key();
        let err = build_and_sign(&build_inputs(), tmp.path(), "0".repeat(64), &key).unwrap_err();
        match err {
            BuildError::EmptyRootfs { .. } => {}
            other => panic!("expected EmptyRootfs, got {other:?}"),
        }
    }

    /// `read_inputs` round-trips a TOML file into the typed struct.
    #[test]
    fn read_inputs_parses_canonical_manifest_inputs() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("manifest.toml");
        let s = r#"
role = "Reviewer"
kernel_version    = "0.1.0"
source_date_epoch = 1700000000
erofs_version     = "1.7.1"
tar_version       = "1.34"
zstd_version      = "1.5.5"
"#;
        std::fs::write(&p, s).unwrap();
        let inputs = read_inputs(&p).unwrap();
        assert_eq!(inputs.role, Role::Reviewer);
        assert_eq!(inputs.kernel_version, "0.1.0");
        assert_eq!(inputs.source_date_epoch, 1700000000);
    }
}
