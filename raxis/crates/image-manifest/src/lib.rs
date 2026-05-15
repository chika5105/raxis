//! Typed `ImageManifest` for the canonical Reviewer, Orchestrator, and
//! Executor-starter VM images.
//!
//! Normative references:
//!
//! * `planner-harness.md §14.4 — Image-build pipeline` (the table that
//!   names the three manifest paths and the trust boundaries).
//! * `planner-harness.md §14.2` — the `crates/raxis-image-manifest`
//!   row of the workspace layout: typed struct + verifier, used both
//!   by the kernel boot path (admission) and by `cargo test` in CI
//!   (determinism assertions).
//! * `system-requirements.md §11.2` — kernel signing key shape; the
//!   Ed25519 signature in this crate's `ImageManifest` is over the
//!   manifest's `bundle_hash` using that key.
//!
//! ## What the manifest is
//!
//! A binding between **a set of files** (the rootfs source tree) and
//! **the kernel signing key**, surfaced as TOML so it can be inspected
//! out-of-band and so a kernel-version upgrade can ship a new manifest
//! without re-tooling the boot path. Every file in the image has its
//! SHA-256 recorded; the manifest's `bundle_hash` is the SHA-256 over
//! the canonicalised file list (sorted by path, hex-encoded digests,
//! newline-delimited). The `signature` is the Ed25519 signature over
//! `bundle_hash`.
//!
//! ## Why typed-not-just-TOML
//!
//! TOML alone leaves room for kernel-side parser bugs to silently
//! accept a malformed manifest. Routing every load through this crate
//! enforces:
//!
//! 1. The manifest's schema-version matches what the kernel binary
//!    knows how to validate (refuses unknown future versions —
//!    fail-closed at the trust boundary).
//! 2. The signing-key fingerprint matches the kernel's compiled-in
//!    expected fingerprint (otherwise the manifest is a different
//!    deployment's manifest and must be rejected).
//! 3. The signature actually verifies under that key.
//! 4. The `bundle_hash` recomputed from the per-file digests matches
//!    the value the manifest claims (catches accidental edits to the
//!    file list without re-signing).
//!
//! All four are checked atomically in [`verify`].
//!
//! ## What the manifest is NOT
//!
//! It is not a Docker / OCI manifest. The OCI image directory and the
//! EROFS rootfs blob produced by `raxis-image-builder` are
//! intermediate artefacts; the `ImageManifest` is the kernel-side
//! source of truth that survives air-gapped distribution.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use ed25519_dalek::{Signature, SignatureError, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Schema version; bumped on every breaking change to the manifest
/// shape. The kernel refuses to admit a manifest with a version it
/// does not know.
///
/// History:
///
/// * `1` — initial schema; `bundle_hash` covers file list only. No
///   commitment to the packed image artefact (`raxis-<role>-<kernel_version>.img`).
/// * `2` — adds `image_artefact_sha256: String` and folds it into
///   the canonical `bundle_hash` input. The kernel boot path can now
///   trust the manifest's `image_artefact_sha256` field to be the
///   signed-over expected SHA-256 of the on-disk .img bytes, which
///   is the kernel-pinned digest under the V2 manifest-trust model
///   (`planner-harness.md §14.4`).
/// * `3` — adds `image_format: ImageFormat` (one of `RootfsErofs` or
///   `RootfsInitramfsCpio`) and folds it into the canonical
///   `bundle_hash` input. The substrate dispatch path (AVF /
///   Firecracker) reads this field to decide whether to attach the
///   .img as a virtio-blk device (EROFS) or hand it to the boot
///   loader as an initial ramdisk (initramfs cpio.gz). Closes the
///   `mkfs.erofs`-on-macOS gap from `e2e-live-test-gap.md`: dev-host
///   builds emit the InitramfsCpio shape, production builds keep the
///   RootfsErofs shape — both are kernel-trusted via the same signed
///   manifest. No legacy fallback: a v2 manifest is rejected with
///   `SchemaVersionMismatch` on load (the trust anchor is currently
///   the all-zero placeholder so no v2 manifests have shipped to
///   production yet).
pub const SCHEMA_VERSION: u32 = 3;

/// Length of the bundle-hash digest in bytes. Public so callers that
/// surface this value (audit events, doctor output) do not redefine
/// the magic number.
pub const BUNDLE_HASH_LEN: usize = 32;

/// Length of an Ed25519 signature, in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// Length of an Ed25519 verifying-key fingerprint
/// (SHA-256 over the 32-byte raw public key).
pub const KEY_FP_LEN: usize = 32;

/// On-disk shape of the rootfs blob the manifest covers. The substrate
/// (`raxis-isolation-apple-vz`, `raxis-isolation-firecracker`) reads
/// this off the kernel-verified manifest to decide whether the
/// `image_artefact_sha256`-pinned bytes are an EROFS-formatted
/// virtio-blk image (production canonical layout) or an initramfs
/// `cpio.gz` (dev-host layout produced by `raxis-initramfs-builder`).
///
/// **The format is signed.** The substrate trusts whatever the
/// manifest says without re-probing the bytes; a tampered manifest
/// claiming the wrong shape is caught by signature verification before
/// the substrate sees the field.
///
/// `SCHEMA_VERSION = 3` addition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ImageFormat {
    /// EROFS-formatted virtio-blk device, mounted read-only as `/`.
    /// The production canonical shape per `planner-harness.md §14.4`.
    /// Substrate hands the .img path to AVF as a
    /// `VZDiskImageStorageDeviceAttachment` (virtio-blk) and to
    /// Firecracker as `PUT /drives { is_root_device: true }`.
    RootfsErofs,
    /// `cpio.gz` (newc) initramfs, unpacked by the Linux kernel itself
    /// at boot. The dev-host shape introduced to remove the
    /// `mkfs.erofs`-on-macOS dependency. Substrate hands the .img path
    /// to AVF as `VZLinuxBootLoader.initialRamdiskURL` and to
    /// Firecracker as `PUT /boot-source { initrd_path }` — NOT as a
    /// virtio-blk device.
    RootfsInitramfsCpio,
}

impl ImageFormat {
    /// Stable string surface for audit-event payloads, doctor output,
    /// and the canonical `bundle_hash` input. Lowercase-kebab-case so
    /// it matches the cli flag (`--format erofs|initramfs-cpio`).
    pub fn as_str(self) -> &'static str {
        match self {
            ImageFormat::RootfsErofs => "erofs",
            ImageFormat::RootfsInitramfsCpio => "initramfs-cpio",
        }
    }
}

/// Which canonical role this image targets. Matches
/// `raxis-types::Role` and the `[planner_role]` enum in the kernel
/// session schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Role {
    /// Kernel-canonical Reviewer image (`INV-PLANNER-HARNESS-02`).
    Reviewer,
    /// Kernel-canonical Orchestrator image (`INV-PLANNER-HARNESS-05`).
    Orchestrator,
    /// Opt-in Executor starter image (operator-elected via policy).
    ExecutorStarter,
}

impl Role {
    /// Stable string surface for audit events and on-disk path
    /// segments. Lower-kebab-case so it matches `images/<role>/`
    /// directory layout in `planner-harness.md §14.4`.
    pub fn as_dir_name(self) -> &'static str {
        match self {
            Role::Reviewer => "reviewer-core",
            Role::Orchestrator => "orchestrator-core",
            Role::ExecutorStarter => "executor-starter",
        }
    }

    /// Filename stem for the `<role>-<kernel_version>.img` artefact.
    pub fn artefact_stem(self) -> &'static str {
        match self {
            Role::Reviewer => "raxis-reviewer-core",
            Role::Orchestrator => "raxis-orchestrator-core",
            Role::ExecutorStarter => "raxis-executor-starter",
        }
    }
}

/// One entry in the manifest's `files` list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestFile {
    /// Path inside the rootfs (always forward-slash, never absolute on
    /// disk). The host-side builder rewrites paths during tarball
    /// assembly so the recorded form is the same on every platform.
    pub path: String,
    /// Lowercase-hex SHA-256 of the file's bytes.
    pub sha256: String,
    /// Size in bytes; redundant with the digest's coverage but useful
    /// for audit-side sanity checks and image-bloat budgets.
    pub size: u64,
    /// POSIX mode bits (e.g., `0o755` for executables).
    pub mode: u32,
}

/// Build-environment fingerprint pinned in every manifest. Operators
/// inspecting an artefact see exactly how it was produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildEnv {
    /// `SOURCE_DATE_EPOCH` propagated to the builder so timestamps in
    /// tar/erofs are deterministic.
    pub source_date_epoch: u64,
    /// Pinned mkfs.erofs version (e.g., "1.7.1"). Tools the builder
    /// shells out to are the largest non-determinism source — pinning
    /// the version is the minimum reproducibility contract.
    pub erofs_version: String,
    /// Pinned tar implementation (e.g., "GNU tar 1.34").
    pub tar_version: String,
    /// Pinned zstd version, if zstd is used to compress the OCI
    /// layers (`mkfs.erofs -z zstd`).
    pub zstd_version: String,
}

/// The kernel-pinned manifest structure. One TOML file per role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageManifest {
    /// Schema version — see [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Which canonical role this manifest covers.
    pub role: Role,
    /// Kernel version this image is paired with (e.g., "0.2.0").
    /// Validates the version-locking invariant called out in
    /// `INV-PLANNER-HARNESS-02` / `INV-PLANNER-HARNESS-05`.
    pub kernel_version: String,
    /// Bundle hash (`SCHEMA_VERSION = 2`): SHA-256 over the canonical
    /// bytes
    ///
    /// ```text
    /// "__image_artefact__\0{image_artefact_sha256}\n"
    ///   ++ for each (path, sha256) in sort(files): "{path}\0{sha256}\n"
    /// ```
    ///
    /// Stored hex-encoded so the manifest stays human-readable; the
    /// in-memory representation in [`ImageManifest::bundle_hash_bytes`]
    /// is the `[u8; 32]` form.
    pub bundle_hash: String,
    /// Lowercase-hex SHA-256 of the packed `raxis-<role>-<kernel_version>.img`
    /// blob (the rootfs the host hands to the hypervisor). The
    /// builder fills this in **after** rootfs assembly. Folding it
    /// into [`ImageManifest::recompute_bundle_hash`] means the
    /// signature covers the artefact bytes; the kernel boot path
    /// trusts this field to be the expected SHA-256 of the on-disk
    /// .img and refuses to launch a VM whose blob digest disagrees.
    ///
    /// `SCHEMA_VERSION = 2` addition.
    pub image_artefact_sha256: String,
    /// On-disk shape of the `image_artefact_sha256`-pinned bytes.
    /// See [`ImageFormat`] for the substrate-dispatch contract.
    /// `SCHEMA_VERSION = 3` addition.
    pub image_format: ImageFormat,
    /// Build-environment pin (timestamps, tool versions).
    pub build_env: BuildEnv,
    /// Per-file inventory; sorted by `path` after `recompute_bundle_hash`.
    pub files: Vec<ManifestFile>,
    /// SHA-256 fingerprint of the kernel signing key's verifying key
    /// (`Sha256(verifying_key.to_bytes())`). The kernel binary carries
    /// the expected value in `EXPECTED_KERNEL_SIGNING_KEY_FP` and
    /// rejects manifests bearing any other fingerprint.
    pub signing_key_fp: String,
    /// Ed25519 signature over [`ImageManifest::bundle_hash_bytes`].
    /// Hex-encoded.
    pub signature: String,
}

/// Errors `verify` and the deserialiser can surface.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    /// TOML deserialise failed — malformed input.
    #[error("manifest toml parse error: {0}")]
    TomlParse(#[from] toml::de::Error),

    /// Schema version not understood by this crate.
    #[error("manifest schema_version {found} is not supported (expected {expected})")]
    SchemaVersionMismatch {
        /// What we found in the manifest.
        found: u32,
        /// What we know how to validate.
        expected: u32,
    },

    /// `bundle_hash` field is not a 32-byte hex string.
    #[error("manifest bundle_hash is malformed (expected {} hex chars): {found}", BUNDLE_HASH_LEN * 2)]
    BundleHashMalformed {
        /// What was in the field.
        found: String,
    },

    /// Recomputed bundle hash does not equal the manifest's claim.
    #[error("manifest bundle_hash mismatch: recomputed {recomputed} vs claimed {claimed}")]
    BundleHashMismatch {
        /// What `recompute_bundle_hash` produced.
        recomputed: String,
        /// What the manifest claimed.
        claimed: String,
    },

    /// `signing_key_fp` is malformed.
    #[error("manifest signing_key_fp is malformed (expected {} hex chars)", KEY_FP_LEN * 2)]
    SigningKeyFpMalformed,

    /// `signing_key_fp` does not match the kernel's expected key.
    #[error("manifest signing_key_fp does not match kernel expected fingerprint")]
    SigningKeyFpMismatch,

    /// Signature is not 64 bytes hex-encoded.
    #[error("manifest signature is malformed (expected {} hex chars)", SIGNATURE_LEN * 2)]
    SignatureMalformed,

    /// Ed25519 verification failed.
    #[error("manifest signature verification failed: {0}")]
    SignatureFailed(#[from] SignatureError),

    /// A per-file `sha256` is malformed.
    #[error("manifest file digest is malformed at path {path}")]
    FileDigestMalformed {
        /// Which entry in the file list was bad.
        path: String,
    },

    /// `image_artefact_sha256` is not a 32-byte lowercase-hex string.
    #[error("manifest image_artefact_sha256 is malformed (expected {} lowercase-hex chars): {found}", BUNDLE_HASH_LEN * 2)]
    ImageArtefactSha256Malformed {
        /// What was in the field.
        found: String,
    },

    /// A per-file path is malformed (empty, contains backslash, or
    /// starts with `/`). All paths must be relative-form.
    #[error("manifest file path is malformed: {found}")]
    FilePathMalformed {
        /// The malformed path.
        found: String,
    },

    /// Two files share the same path. Rootfs paths must be unique.
    #[error("manifest contains duplicate path {0}")]
    DuplicatePath(String),

    /// I/O error reading a file from the source rootfs (used by the
    /// builder when computing `files`).
    #[error("manifest builder io error at {path}: {source}")]
    Io {
        /// Path the builder was reading.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

impl ImageManifest {
    /// Parse a manifest from its on-disk TOML representation.
    pub fn from_toml(s: &str) -> Result<Self, ManifestError> {
        let m: ImageManifest = toml::from_str(s)?;
        if m.schema_version != SCHEMA_VERSION {
            return Err(ManifestError::SchemaVersionMismatch {
                found: m.schema_version,
                expected: SCHEMA_VERSION,
            });
        }
        Ok(m)
    }

    /// Serialise to TOML — used by the builder to write the on-disk
    /// `manifest.json` after signing.
    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).expect("serialise typed manifest never fails")
    }

    /// Decode the manifest's claimed bundle hash into the binary form
    /// the kernel passes to `Verifier::verify`.
    pub fn bundle_hash_bytes(&self) -> Result<[u8; BUNDLE_HASH_LEN], ManifestError> {
        decode_hex_n::<BUNDLE_HASH_LEN>(&self.bundle_hash).ok_or_else(|| {
            ManifestError::BundleHashMalformed {
                found: self.bundle_hash.clone(),
            }
        })
    }

    /// Recompute the bundle hash from the manifest.
    ///
    /// Canonicalisation (`SCHEMA_VERSION = 3`):
    ///
    /// 1. Header line `"__image_artefact__\0{image_artefact_sha256}\n"`.
    /// 2. Format line `"__image_format__\0{image_format.as_str()}\n"`.
    /// 3. Sort `files` by `path`, then hash
    ///    `"{path}\0{lowercase-hex sha256}\n"` for each entry.
    ///
    /// The builder calls this after assembling `files` AND after
    /// computing the .img blob's digest; `verify` calls it when
    /// checking the signature. Folding `image_artefact_sha256` AND
    /// `image_format` into `bundle_hash` means the Ed25519 signature
    /// implicitly commits to both the packed artefact bytes and the
    /// rootfs shape the substrate must dispatch on — a tampered
    /// manifest claiming the wrong shape (e.g. swapping `RootfsErofs`
    /// for `RootfsInitramfsCpio` to slip an unsigned initramfs past
    /// the substrate's dispatch path) is caught here, before the
    /// substrate sees the field.
    pub fn recompute_bundle_hash(&self) -> Result<[u8; BUNDLE_HASH_LEN], ManifestError> {
        let mut hasher = Sha256::new();

        validate_artefact_sha256(&self.image_artefact_sha256)?;
        hasher.update(b"__image_artefact__\0");
        hasher.update(self.image_artefact_sha256.as_bytes());
        hasher.update(b"\n");

        hasher.update(b"__image_format__\0");
        hasher.update(self.image_format.as_str().as_bytes());
        hasher.update(b"\n");

        let mut sorted: Vec<&ManifestFile> = self.files.iter().collect();
        sorted.sort_by(|a, b| a.path.cmp(&b.path));

        for f in sorted {
            validate_path(&f.path)?;
            // Validate digest hex is 64 chars; we don't need to
            // decode here, just guard against malformed input.
            if f.sha256.len() != BUNDLE_HASH_LEN * 2
                || !f.sha256.bytes().all(|b| b.is_ascii_hexdigit())
                || f.sha256.bytes().any(|b| matches!(b, b'A'..=b'F'))
            {
                return Err(ManifestError::FileDigestMalformed {
                    path: f.path.clone(),
                });
            }
            hasher.update(f.path.as_bytes());
            hasher.update(b"\0");
            hasher.update(f.sha256.as_bytes());
            hasher.update(b"\n");
        }
        let out: [u8; BUNDLE_HASH_LEN] = hasher.finalize().into();
        Ok(out)
    }

    /// Decode the manifest's claimed image-artefact SHA-256 into the
    /// binary form the kernel compares against the on-disk .img bytes.
    pub fn image_artefact_sha256_bytes(&self) -> Result<[u8; BUNDLE_HASH_LEN], ManifestError> {
        validate_artefact_sha256(&self.image_artefact_sha256)?;
        decode_hex_n::<BUNDLE_HASH_LEN>(&self.image_artefact_sha256).ok_or_else(|| {
            ManifestError::ImageArtefactSha256Malformed {
                found: self.image_artefact_sha256.clone(),
            }
        })
    }

    /// Decode the signature.
    pub fn signature_bytes(&self) -> Result<[u8; SIGNATURE_LEN], ManifestError> {
        decode_hex_n::<SIGNATURE_LEN>(&self.signature).ok_or(ManifestError::SignatureMalformed)
    }

    /// Decode the signing-key fingerprint.
    pub fn signing_key_fp_bytes(&self) -> Result<[u8; KEY_FP_LEN], ManifestError> {
        decode_hex_n::<KEY_FP_LEN>(&self.signing_key_fp).ok_or(ManifestError::SigningKeyFpMalformed)
    }
}

/// Verify a manifest end-to-end against the kernel's expected signing
/// key.
///
/// 1. Schema version must equal [`SCHEMA_VERSION`] (already enforced
///    by [`ImageManifest::from_toml`], re-checked here defensively).
/// 2. Recompute `bundle_hash` from `files` and confirm it matches the
///    manifest's claim.
/// 3. `signing_key_fp` must equal `Sha256(expected_signing_key.to_bytes())`.
/// 4. `signature` must verify against `expected_signing_key` over the
///    binary `bundle_hash_bytes`.
pub fn verify(
    manifest: &ImageManifest,
    expected_signing_key: &VerifyingKey,
) -> Result<(), ManifestError> {
    if manifest.schema_version != SCHEMA_VERSION {
        return Err(ManifestError::SchemaVersionMismatch {
            found: manifest.schema_version,
            expected: SCHEMA_VERSION,
        });
    }

    detect_duplicate_paths(&manifest.files)?;

    let recomputed = manifest.recompute_bundle_hash()?;
    let claimed = manifest.bundle_hash_bytes()?;
    if recomputed != claimed {
        return Err(ManifestError::BundleHashMismatch {
            recomputed: hex::encode(recomputed),
            claimed: hex::encode(claimed),
        });
    }

    let mut hasher = Sha256::new();
    hasher.update(expected_signing_key.to_bytes());
    let expected_fp: [u8; KEY_FP_LEN] = hasher.finalize().into();
    let claimed_fp = manifest.signing_key_fp_bytes()?;
    if claimed_fp != expected_fp {
        return Err(ManifestError::SigningKeyFpMismatch);
    }

    let sig_bytes = manifest.signature_bytes()?;
    let signature = Signature::from_bytes(&sig_bytes);
    expected_signing_key.verify(&claimed, &signature)?;

    Ok(())
}

/// Compute the SHA-256 fingerprint of an Ed25519 verifying key. The
/// builder pins this in the manifest; the kernel pins the same value
/// in `EXPECTED_KERNEL_SIGNING_KEY_FP`.
pub fn fingerprint_signing_key(key: &VerifyingKey) -> [u8; KEY_FP_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(key.to_bytes());
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

fn validate_artefact_sha256(found: &str) -> Result<(), ManifestError> {
    if found.len() != BUNDLE_HASH_LEN * 2
        || !found.bytes().all(|b| b.is_ascii_hexdigit())
        || found.bytes().any(|b| matches!(b, b'A'..=b'F'))
    {
        return Err(ManifestError::ImageArtefactSha256Malformed {
            found: found.to_owned(),
        });
    }
    Ok(())
}

fn validate_path(path: &str) -> Result<(), ManifestError> {
    if path.is_empty() || path.starts_with('/') || path.contains('\\') || path.contains('\0') {
        return Err(ManifestError::FilePathMalformed {
            found: path.to_owned(),
        });
    }
    if path.split('/').any(|seg| seg == ".." || seg == ".") {
        return Err(ManifestError::FilePathMalformed {
            found: path.to_owned(),
        });
    }
    Ok(())
}

fn detect_duplicate_paths(files: &[ManifestFile]) -> Result<(), ManifestError> {
    let mut seen = std::collections::BTreeSet::new();
    for f in files {
        if !seen.insert(f.path.clone()) {
            return Err(ManifestError::DuplicatePath(f.path.clone()));
        }
    }
    Ok(())
}

fn decode_hex_n<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    if hex::decode_to_slice(s, &mut out).is_ok() {
        Some(out)
    } else {
        None
    }
}

/// Stream `path`'s bytes through SHA-256, returning the lowercase-hex
/// digest. Used by the builder when populating `ManifestFile.sha256`.
pub fn sha256_file_hex(path: &Path) -> Result<(String, u64), ManifestError> {
    use std::fs::File;
    use std::io::Read;

    let mut f = File::open(path).map_err(|e| ManifestError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = f.read(&mut buf).map_err(|e| ManifestError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    let digest: [u8; 32] = hasher.finalize().into();
    Ok((hex::encode(digest), total))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::{rngs::OsRng, RngCore};

    fn fixture_signing_key() -> (SigningKey, VerifyingKey) {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let sk = SigningKey::from_bytes(&bytes);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    /// Build a small in-memory manifest and exercise the sign-then-
    /// verify round trip.
    #[test]
    fn sign_then_verify_round_trip_succeeds() {
        let (sk, vk) = fixture_signing_key();

        let files = vec![
            ManifestFile {
                path: "init".to_owned(),
                sha256: "0".repeat(64),
                size: 100,
                mode: 0o755,
            },
            ManifestFile {
                path: "raxis-planner".to_owned(),
                sha256: "1".repeat(64),
                size: 2_000_000,
                mode: 0o755,
            },
        ];

        let mut m = ImageManifest {
            schema_version: SCHEMA_VERSION,
            role: Role::Reviewer,
            kernel_version: "0.1.0".to_owned(),
            bundle_hash: String::new(),
            image_artefact_sha256: "0".repeat(64),
            image_format: ImageFormat::RootfsErofs,
            build_env: BuildEnv {
                source_date_epoch: 1700000000,
                erofs_version: "1.7.1".to_owned(),
                tar_version: "1.34".to_owned(),
                zstd_version: "1.5.5".to_owned(),
            },
            files,
            signing_key_fp: hex::encode(fingerprint_signing_key(&vk)),
            signature: String::new(),
        };

        let recomputed = m.recompute_bundle_hash().unwrap();
        m.bundle_hash = hex::encode(recomputed);

        let sig: Signature = sk.sign(&recomputed);
        m.signature = hex::encode(sig.to_bytes());

        verify(&m, &vk).expect("freshly signed manifest must verify");
    }

    /// Bundle-hash mismatch (the file list got edited after signing
    /// without recomputing) is the most likely real-world tamper case.
    #[test]
    fn verify_rejects_post_signing_file_edit() {
        let (sk, vk) = fixture_signing_key();
        let files = vec![ManifestFile {
            path: "init".to_owned(),
            sha256: "a".repeat(64),
            size: 1,
            mode: 0o755,
        }];

        let mut m = ImageManifest {
            schema_version: SCHEMA_VERSION,
            role: Role::Reviewer,
            kernel_version: "0.1.0".to_owned(),
            bundle_hash: String::new(),
            image_artefact_sha256: "0".repeat(64),
            image_format: ImageFormat::RootfsErofs,
            build_env: BuildEnv {
                source_date_epoch: 1700000000,
                erofs_version: "1.7.1".to_owned(),
                tar_version: "1.34".to_owned(),
                zstd_version: "1.5.5".to_owned(),
            },
            files,
            signing_key_fp: hex::encode(fingerprint_signing_key(&vk)),
            signature: String::new(),
        };
        let bh = m.recompute_bundle_hash().unwrap();
        m.bundle_hash = hex::encode(bh);
        m.signature = hex::encode(sk.sign(&bh).to_bytes());

        // Edit the file list AFTER signing.
        m.files.push(ManifestFile {
            path: "raxis-planner".to_owned(),
            sha256: "b".repeat(64),
            size: 1,
            mode: 0o755,
        });

        match verify(&m, &vk).unwrap_err() {
            ManifestError::BundleHashMismatch { .. } => {}
            other => panic!("expected BundleHashMismatch, got {other:?}"),
        }
    }

    /// Manifest signed by key A is rejected when verified against
    /// key B's fingerprint. Pins the kernel-side trust boundary.
    #[test]
    fn verify_rejects_wrong_signing_key_fp() {
        let (sk_a, vk_a) = fixture_signing_key();
        let (_, vk_b) = fixture_signing_key();

        let files = vec![ManifestFile {
            path: "init".to_owned(),
            sha256: "a".repeat(64),
            size: 1,
            mode: 0o755,
        }];
        let mut m = ImageManifest {
            schema_version: SCHEMA_VERSION,
            role: Role::Reviewer,
            kernel_version: "0.1.0".to_owned(),
            bundle_hash: String::new(),
            image_artefact_sha256: "0".repeat(64),
            image_format: ImageFormat::RootfsErofs,
            build_env: BuildEnv {
                source_date_epoch: 1700000000,
                erofs_version: "1.7.1".to_owned(),
                tar_version: "1.34".to_owned(),
                zstd_version: "1.5.5".to_owned(),
            },
            files,
            signing_key_fp: hex::encode(fingerprint_signing_key(&vk_a)),
            signature: String::new(),
        };
        let bh = m.recompute_bundle_hash().unwrap();
        m.bundle_hash = hex::encode(bh);
        m.signature = hex::encode(sk_a.sign(&bh).to_bytes());

        // Verify against vk_b — different key entirely.
        match verify(&m, &vk_b).unwrap_err() {
            ManifestError::SigningKeyFpMismatch => {}
            other => panic!("expected SigningKeyFpMismatch, got {other:?}"),
        }
    }

    /// Bundle-hash recomputation is independent of file insertion
    /// order. The builder may insert files in walk order, but the
    /// canonical hash sorts by path before hashing.
    #[test]
    fn recompute_bundle_hash_is_insertion_order_independent() {
        let f1 = ManifestFile {
            path: "a".to_owned(),
            sha256: "0".repeat(64),
            size: 1,
            mode: 0o644,
        };
        let f2 = ManifestFile {
            path: "b".to_owned(),
            sha256: "1".repeat(64),
            size: 1,
            mode: 0o644,
        };
        let f3 = ManifestFile {
            path: "c".to_owned(),
            sha256: "2".repeat(64),
            size: 1,
            mode: 0o644,
        };

        let m_abc = ImageManifest {
            schema_version: SCHEMA_VERSION,
            role: Role::Reviewer,
            kernel_version: "0.1.0".to_owned(),
            bundle_hash: String::new(),
            image_artefact_sha256: "0".repeat(64),
            image_format: ImageFormat::RootfsErofs,
            build_env: BuildEnv {
                source_date_epoch: 1700000000,
                erofs_version: "1.7.1".to_owned(),
                tar_version: "1.34".to_owned(),
                zstd_version: "1.5.5".to_owned(),
            },
            files: vec![f1.clone(), f2.clone(), f3.clone()],
            signing_key_fp: "0".repeat(64),
            signature: String::new(),
        };
        let mut m_cba = m_abc.clone();
        m_cba.files = vec![f3, f2, f1];

        assert_eq!(
            m_abc.recompute_bundle_hash().unwrap(),
            m_cba.recompute_bundle_hash().unwrap(),
            "recompute_bundle_hash must be canonical (sorted) regardless of insertion order",
        );
    }

    /// TOML round-trip preserves bundle hash and signature.
    #[test]
    fn toml_round_trip_preserves_signed_state() {
        let (sk, vk) = fixture_signing_key();
        let files = vec![ManifestFile {
            path: "raxis-planner".to_owned(),
            sha256: "1".repeat(64),
            size: 2_000_000,
            mode: 0o755,
        }];
        let mut m = ImageManifest {
            schema_version: SCHEMA_VERSION,
            role: Role::Orchestrator,
            kernel_version: "0.1.0".to_owned(),
            bundle_hash: String::new(),
            image_artefact_sha256: "0".repeat(64),
            image_format: ImageFormat::RootfsErofs,
            build_env: BuildEnv {
                source_date_epoch: 1700000000,
                erofs_version: "1.7.1".to_owned(),
                tar_version: "1.34".to_owned(),
                zstd_version: "1.5.5".to_owned(),
            },
            files,
            signing_key_fp: hex::encode(fingerprint_signing_key(&vk)),
            signature: String::new(),
        };
        let bh = m.recompute_bundle_hash().unwrap();
        m.bundle_hash = hex::encode(bh);
        m.signature = hex::encode(sk.sign(&bh).to_bytes());

        let toml = m.to_toml();
        let parsed = ImageManifest::from_toml(&toml).unwrap();
        assert_eq!(parsed, m);
        verify(&parsed, &vk).expect("round-tripped manifest must still verify");
    }

    /// Path validation rejects every form of traversal / absolute
    /// reference. Pins the rootfs-relative-only contract.
    #[test]
    fn path_validation_rejects_absolute_traversal_and_dotty_paths() {
        for bad in [
            "",
            "/etc/passwd",
            "..",
            "a/../b",
            "./a",
            "a/./b",
            "a\\b",
            "a\0b",
        ] {
            assert!(
                validate_path(bad).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
        for ok in ["init", "usr/bin/sh", "raxis-planner"] {
            validate_path(ok).expect("expected ok path");
        }
    }

    /// Duplicate path detection — two entries for the same path is a
    /// builder bug, not a structural feature.
    #[test]
    fn verify_rejects_duplicate_paths() {
        let (_sk, vk) = fixture_signing_key();
        let m = ImageManifest {
            schema_version: SCHEMA_VERSION,
            role: Role::Reviewer,
            kernel_version: "0.1.0".to_owned(),
            bundle_hash: "0".repeat(64),
            image_artefact_sha256: "0".repeat(64),
            image_format: ImageFormat::RootfsErofs,
            build_env: BuildEnv {
                source_date_epoch: 1700000000,
                erofs_version: "1.7.1".to_owned(),
                tar_version: "1.34".to_owned(),
                zstd_version: "1.5.5".to_owned(),
            },
            files: vec![
                ManifestFile {
                    path: "init".to_owned(),
                    sha256: "0".repeat(64),
                    size: 1,
                    mode: 0o755,
                },
                ManifestFile {
                    path: "init".to_owned(),
                    sha256: "0".repeat(64),
                    size: 1,
                    mode: 0o755,
                },
            ],
            signing_key_fp: hex::encode(fingerprint_signing_key(&vk)),
            signature: "0".repeat(128),
        };
        match verify(&m, &vk).unwrap_err() {
            ManifestError::DuplicatePath(p) => assert_eq!(p, "init"),
            other => panic!("expected DuplicatePath, got {other:?}"),
        }
    }

    /// Folding `image_artefact_sha256` into `bundle_hash` is the
    /// V2-trust-model invariant: a tamperer who replaces the .img
    /// blob and rewrites the manifest's `image_artefact_sha256` field
    /// must also re-sign, which they cannot do without the kernel
    /// signing key. Verify that mutating `image_artefact_sha256`
    /// after signing surfaces `BundleHashMismatch`.
    #[test]
    fn verify_rejects_post_signing_image_artefact_sha256_edit() {
        let (sk, vk) = fixture_signing_key();
        let files = vec![ManifestFile {
            path: "init".to_owned(),
            sha256: "a".repeat(64),
            size: 1,
            mode: 0o755,
        }];
        let mut m = ImageManifest {
            schema_version: SCHEMA_VERSION,
            role: Role::Reviewer,
            kernel_version: "0.1.0".to_owned(),
            bundle_hash: String::new(),
            image_artefact_sha256: "1".repeat(64),
            image_format: ImageFormat::RootfsErofs,
            build_env: BuildEnv {
                source_date_epoch: 1700000000,
                erofs_version: "1.7.1".to_owned(),
                tar_version: "1.34".to_owned(),
                zstd_version: "1.5.5".to_owned(),
            },
            files,
            signing_key_fp: hex::encode(fingerprint_signing_key(&vk)),
            signature: String::new(),
        };
        let bh = m.recompute_bundle_hash().unwrap();
        m.bundle_hash = hex::encode(bh);
        m.signature = hex::encode(sk.sign(&bh).to_bytes());

        // Tamperer swaps the artefact digest WITHOUT re-signing. The
        // bundle-hash recomputation will now disagree with the
        // claimed bundle_hash → BundleHashMismatch.
        m.image_artefact_sha256 = "2".repeat(64);

        match verify(&m, &vk).unwrap_err() {
            ManifestError::BundleHashMismatch { .. } => {}
            other => panic!("expected BundleHashMismatch, got {other:?}"),
        }
    }

    /// `image_artefact_sha256` field validates as 32-byte
    /// lowercase-hex. Pins the contract that downstream code can
    /// `decode_hex_n::<32>` after `verify` succeeds.
    #[test]
    fn image_artefact_sha256_must_be_lowercase_hex_32_bytes() {
        for bad in [
            "",
            "deadbeef",
            "G".repeat(64).as_str(), // non-hex char
            "A".repeat(64).as_str(), // uppercase hex rejected (lowercase contract)
            "0".repeat(63).as_str(), // wrong length
            "0".repeat(65).as_str(), // wrong length
        ] {
            assert!(
                validate_artefact_sha256(bad).is_err(),
                "expected {bad:?} to be rejected as image_artefact_sha256",
            );
        }
        // Happy paths.
        validate_artefact_sha256(&"0".repeat(64)).unwrap();
        validate_artefact_sha256(&"a".repeat(64)).unwrap();
        validate_artefact_sha256(&"f".repeat(64)).unwrap();
        validate_artefact_sha256(
            "aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55",
        )
        .unwrap();
    }

    /// `image_artefact_sha256_bytes` round-trips a valid hex string
    /// into the `[u8; 32]` form the kernel compares against the
    /// streamed .img digest.
    #[test]
    fn image_artefact_sha256_bytes_round_trips_hex() {
        let m = ImageManifest {
            schema_version: SCHEMA_VERSION,
            role: Role::Reviewer,
            kernel_version: "0.1.0".to_owned(),
            bundle_hash: "0".repeat(64),
            image_artefact_sha256: "ab".repeat(32),
            image_format: ImageFormat::RootfsErofs,
            build_env: BuildEnv {
                source_date_epoch: 1700000000,
                erofs_version: "1.7.1".to_owned(),
                tar_version: "1.34".to_owned(),
                zstd_version: "1.5.5".to_owned(),
            },
            files: vec![],
            signing_key_fp: "0".repeat(64),
            signature: "0".repeat(128),
        };
        let bytes = m.image_artefact_sha256_bytes().unwrap();
        assert_eq!(bytes.len(), BUNDLE_HASH_LEN);
        for b in bytes.iter() {
            assert_eq!(*b, 0xab);
        }
    }

    /// Streaming SHA-256 of a temp file matches the one-shot Sha256
    /// digest. Pins the chunked-vs-one-shot equivalence.
    #[test]
    fn sha256_file_hex_matches_one_shot() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"raxis-image-manifest-test").unwrap();
        f.flush().unwrap();
        let (hex_str, size) = sha256_file_hex(f.path()).unwrap();
        assert_eq!(size, 25);
        // Compare with one-shot
        let mut hasher = Sha256::new();
        hasher.update(b"raxis-image-manifest-test");
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(hex_str, hex::encode(expected));
    }
}
