//! V2_GAPS §C5 — immutable artifact store (MVP).
//!
//! Closes the operator-grade leg of `immutable-artifact-store.md`:
//! a content-addressed, write-once, hash-verified file store rooted
//! at `<data_dir>/artifacts/<category>/<sha256>.<ext>`.
//!
//! ## What this crate ships
//!
//! * [`ArtifactStore`] — opens the store at a `<data_dir>/artifacts/`
//!   root, materialising the per-category sub-dirs lazily on first
//!   write.
//! * [`Category`] — the V2 category vocabulary (`policy`, `plans`,
//!   `keys`); each entry binds the on-disk sub-directory name and
//!   the canonical file extension the spec calls for.
//! * [`ArtifactStore::write`] — writes `body` to
//!   `<root>/<category>/<sha256>.<ext>` with `O_CREAT | O_EXCL`.
//!   Idempotent on identical bytes (two callers writing the same
//!   bytes both observe the file present, no corruption); a
//!   distinct callsite writing a *different* body to the same
//!   sha256 is impossible (collision-resistance of SHA-256).
//! * [`ArtifactStore::read`] — reads `<root>/<category>/<sha256>.<ext>`
//!   AND verifies the on-disk SHA-256 against the requested key.
//!   A mismatch surfaces as
//!   [`ArtifactStoreError::IntegrityMismatch`]; this is the
//!   "filesystem corruption / tamper" detector the spec calls for
//!   in §1.3.
//! * [`ArtifactStore::exists`] — non-destructive presence check.
//! * [`ArtifactStore::write_companion`] — write a non-content-
//!   addressed sidecar file (used for `plans/<sha256>.sig`); the
//!   sidecar's name shares the sha256 stem with its primary
//!   artifact.
//!
//! ## What this crate does NOT ship (deferred to V3)
//!
//! * **Symlink swap to `policy/policy.toml` / `operator_public.pem`.**
//!   The spec's "current pointer" semantics live with the kernel's
//!   policy / cert managers; the artifact store is the
//!   write-once primitive they call into.
//! * **Retention policy enforcement.** The default is
//!   `retention = "forever"`; configurable retention with a GC
//!   sweep is V3 work.
//! * **Audit-event integration** — the kernel emits
//!   `PolicyEpochAdvanced { new_policy_sha256, … }` from its own
//!   handler; the artifact store does not write to the audit
//!   chain.
//! * **CLI surfaces** (`raxis policy history`, `raxis plan show
//!   <sha256>`, `raxis keys list`) — these compose on top of
//!   `read` / `exists` once they land.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::fs::OpenOptions;
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Category
// ---------------------------------------------------------------------------

/// V2 artifact-store category vocabulary. Each entry binds the
/// on-disk sub-directory name and the canonical file extension.
///
/// Adding a new category requires a `immutable-artifact-store.md`
/// spec amendment — the on-disk layout under
/// `<data_dir>/artifacts/<category>/` is operator-visible and
/// surveyed by `raxis doctor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Category {
    /// `<root>/policy/<sha256>.toml` — every policy bundle ever
    /// active is preserved (`§2.1`).
    Policy,
    /// `<root>/plans/<sha256>.toml` — every approved plan is
    /// preserved (`§2.2`). Companion `.sig` file written via
    /// [`ArtifactStore::write_companion`].
    Plans,
    /// `<root>/keys/<sha256>.pem` — every operator public key ever
    /// registered is preserved (`§2.3`). The "sha256" key for
    /// this category is the SHA-256 of the DER-encoded public key
    /// bytes; callers compute it themselves and pass it as
    /// [`ArtifactKey`].
    Keys,
}

impl Category {
    /// On-disk sub-directory name under `<root>/artifacts/`.
    pub const fn sub_dir(self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::Plans => "plans",
            Self::Keys => "keys",
        }
    }

    /// Canonical file extension the spec assigns to this category's
    /// primary artifact.
    pub const fn ext(self) -> &'static str {
        match self {
            Self::Policy => "toml",
            Self::Plans => "toml",
            Self::Keys => "pem",
        }
    }
}

// ---------------------------------------------------------------------------
// ArtifactKey
// ---------------------------------------------------------------------------

/// 32-byte SHA-256 over the artifact's bytes (the spec's
/// "content-address"), with a hex projection. Construct via
/// [`ArtifactKey::compute`] (writer side) or
/// [`ArtifactKey::parse_hex`] (reader side).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ArtifactKey([u8; 32]);

impl ArtifactKey {
    /// Compute the key from a payload.
    pub fn compute(body: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(body);
        let bytes: [u8; 32] = h.finalize().into();
        Self(bytes)
    }

    /// Construct from a 32-byte raw digest.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Construct from a 64-char lowercase-hex string.
    pub fn parse_hex(hex: &str) -> Result<Self, ArtifactStoreError> {
        if hex.len() != 64 {
            return Err(ArtifactStoreError::InvalidKey {
                reason: format!("expected 64 hex chars, got {}", hex.len()),
            });
        }
        let mut out = [0u8; 32];
        ::hex::decode_to_slice(hex, &mut out).map_err(|e| ArtifactStoreError::InvalidKey {
            reason: format!("hex decode: {e}"),
        })?;
        Ok(Self(out))
    }

    /// 64-char lowercase-hex projection (the on-disk filename stem).
    pub fn as_hex(&self) -> String {
        ::hex::encode(self.0)
    }

    /// Raw 32-byte digest.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors specific to the artifact store.
#[derive(Debug, Error)]
pub enum ArtifactStoreError {
    /// Invalid key (wrong length, non-hex chars).
    #[error("invalid artifact key: {reason}")]
    InvalidKey {
        /// Human-readable reason.
        reason: String,
    },
    /// Underlying I/O error.
    #[error("io error at {path}: {source}")]
    Io {
        /// Path the operation targeted.
        path: PathBuf,
        /// Source error.
        #[source]
        source: std::io::Error,
    },
    /// On-disk artifact's hash does not match its filename. This is
    /// the corruption / tamper detector — the kernel surfaces it
    /// as an `OperatorAttentionRequired { kind: ArtifactCorruption }`
    /// audit event.
    #[error("integrity mismatch at {path}: stored={stored_sha:?}, expected={expected_sha:?}")]
    IntegrityMismatch {
        /// Path the integrity check ran against.
        path: PathBuf,
        /// SHA-256 actually present on disk.
        stored_sha: String,
        /// SHA-256 the caller asked for.
        expected_sha: String,
    },
    /// `O_CREAT | O_EXCL` write observed an existing file with a
    /// different body. Logically equivalent to
    /// [`ArtifactStoreError::IntegrityMismatch`] but distinguishes
    /// "two callers wrote the same key, second saw the existing
    /// file with the same bytes" (idempotent — Ok) from "two callers
    /// wrote the same key with different bytes" (impossible under
    /// SHA-256 unless the on-disk bytes were tampered with).
    #[error("artifact present but bytes differ at {path}")]
    BytesDiverge {
        /// Path the divergent write was observed against.
        path: PathBuf,
    },
}

// ---------------------------------------------------------------------------
// ArtifactStore
// ---------------------------------------------------------------------------

/// Handle to the on-disk artifact store rooted at
/// `<data_dir>/artifacts/`.
#[derive(Debug, Clone)]
pub struct ArtifactStore {
    root: PathBuf,
}

impl ArtifactStore {
    /// Open the store at `<data_dir>/artifacts/`. The directory is
    /// created with mode 0700 (best-effort on Unix; Windows uses
    /// the platform default) if it does not exist.
    pub fn open(data_dir: impl AsRef<Path>) -> Result<Self, ArtifactStoreError> {
        let root = data_dir.as_ref().join("artifacts");
        if !root.exists() {
            std::fs::create_dir_all(&root).map_err(|e| ArtifactStoreError::Io {
                path: root.clone(),
                source: e,
            })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700));
            }
        }
        Ok(Self { root })
    }

    /// On-disk root, for callers that need the path (e.g. for
    /// CLI status or `raxis doctor` enumeration).
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Compute the on-disk path for a given key + category.
    pub fn path_for(&self, category: Category, key: &ArtifactKey) -> PathBuf {
        self.root
            .join(category.sub_dir())
            .join(format!("{}.{}", key.as_hex(), category.ext()))
    }

    /// Compute the path for a sidecar file sharing `key`'s stem,
    /// with the supplied extension. Used for `plans/<sha256>.sig`.
    pub fn companion_path(&self, category: Category, key: &ArtifactKey, ext: &str) -> PathBuf {
        self.root
            .join(category.sub_dir())
            .join(format!("{}.{}", key.as_hex(), ext))
    }

    /// Write `body` to the artifact store. Returns the key + path.
    ///
    /// Idempotent on identical bytes: a second writer of the same
    /// bytes observes the file present and returns the same key.
    /// A second writer with *different* bytes for the same SHA-256
    /// is cryptographically impossible; if the on-disk bytes have
    /// been tampered with after a previous write, the call surfaces
    /// [`ArtifactStoreError::BytesDiverge`].
    pub fn write(
        &self,
        category: Category,
        body: &[u8],
    ) -> Result<(ArtifactKey, PathBuf), ArtifactStoreError> {
        let key = ArtifactKey::compute(body);
        let dir = self.root.join(category.sub_dir());
        if !dir.exists() {
            std::fs::create_dir_all(&dir).map_err(|e| ArtifactStoreError::Io {
                path: dir.clone(),
                source: e,
            })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
            }
        }
        let path = self.path_for(category, &key);
        let res = OpenOptions::new().write(true).create_new(true).open(&path);
        match res {
            Ok(mut f) => {
                f.write_all(body).map_err(|e| ArtifactStoreError::Io {
                    path: path.clone(),
                    source: e,
                })?;
                f.sync_all().map_err(|e| ArtifactStoreError::Io {
                    path: path.clone(),
                    source: e,
                })?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
                }
                Ok((key, path))
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                // Verify the on-disk bytes hash to the same key.
                let on_disk = std::fs::read(&path).map_err(|e| ArtifactStoreError::Io {
                    path: path.clone(),
                    source: e,
                })?;
                let actual = ArtifactKey::compute(&on_disk);
                if actual == key {
                    Ok((key, path))
                } else {
                    Err(ArtifactStoreError::BytesDiverge { path })
                }
            }
            Err(e) => Err(ArtifactStoreError::Io { path, source: e }),
        }
    }

    /// Write a non-content-addressed sidecar file
    /// (e.g. `plans/<sha256>.sig`). The sidecar's `key` is the
    /// matching primary artifact's key; `ext` is the sidecar
    /// extension. Same idempotency contract as [`write`].
    ///
    /// [`write`]: ArtifactStore::write
    pub fn write_companion(
        &self,
        category: Category,
        key: &ArtifactKey,
        ext: &str,
        body: &[u8],
    ) -> Result<PathBuf, ArtifactStoreError> {
        let path = self.companion_path(category, key, ext);
        let dir = path.parent().expect("companion_path has a parent");
        if !dir.exists() {
            std::fs::create_dir_all(dir).map_err(|e| ArtifactStoreError::Io {
                path: dir.to_path_buf(),
                source: e,
            })?;
        }
        let res = OpenOptions::new().write(true).create_new(true).open(&path);
        match res {
            Ok(mut f) => {
                f.write_all(body).map_err(|e| ArtifactStoreError::Io {
                    path: path.clone(),
                    source: e,
                })?;
                f.sync_all().map_err(|e| ArtifactStoreError::Io {
                    path: path.clone(),
                    source: e,
                })?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
                }
                Ok(path)
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                let on_disk = std::fs::read(&path).map_err(|e| ArtifactStoreError::Io {
                    path: path.clone(),
                    source: e,
                })?;
                if on_disk == body {
                    Ok(path)
                } else {
                    Err(ArtifactStoreError::BytesDiverge { path })
                }
            }
            Err(e) => Err(ArtifactStoreError::Io { path, source: e }),
        }
    }

    /// Read the artifact at `(category, key)` and verify the
    /// on-disk SHA-256 matches `key`. A mismatch surfaces as
    /// [`ArtifactStoreError::IntegrityMismatch`]. Returns the body.
    pub fn read(
        &self,
        category: Category,
        key: &ArtifactKey,
    ) -> Result<Vec<u8>, ArtifactStoreError> {
        let path = self.path_for(category, key);
        let mut f = std::fs::File::open(&path).map_err(|e| ArtifactStoreError::Io {
            path: path.clone(),
            source: e,
        })?;
        let mut body = Vec::new();
        f.read_to_end(&mut body)
            .map_err(|e| ArtifactStoreError::Io {
                path: path.clone(),
                source: e,
            })?;
        let actual = ArtifactKey::compute(&body);
        if &actual != key {
            return Err(ArtifactStoreError::IntegrityMismatch {
                path,
                stored_sha: actual.as_hex(),
                expected_sha: key.as_hex(),
            });
        }
        Ok(body)
    }

    /// Non-destructive presence check.
    pub fn exists(&self, category: Category, key: &ArtifactKey) -> bool {
        self.path_for(category, key).exists()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_store() -> (tempfile::TempDir, ArtifactStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(dir.path()).unwrap();
        (dir, store)
    }

    #[test]
    fn artifact_key_round_trips_through_hex() {
        let body = b"hello raxis";
        let k1 = ArtifactKey::compute(body);
        let k2 = ArtifactKey::parse_hex(&k1.as_hex()).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn artifact_key_rejects_short_hex() {
        let err = ArtifactKey::parse_hex("dead").unwrap_err();
        assert!(matches!(err, ArtifactStoreError::InvalidKey { .. }));
    }

    #[test]
    fn write_then_read_round_trips() {
        let (_t, store) = fresh_store();
        let body = b"some-policy-toml-bytes";
        let (key, path) = store.write(Category::Policy, body).unwrap();
        assert!(
            path.exists(),
            "write must materialise the artifact at the computed path"
        );
        let read_back = store.read(Category::Policy, &key).unwrap();
        assert_eq!(read_back, body);
    }

    #[test]
    fn write_is_idempotent_on_identical_bytes() {
        let (_t, store) = fresh_store();
        let body = b"identical-bytes";
        let (k1, p1) = store.write(Category::Policy, body).unwrap();
        let (k2, p2) = store.write(Category::Policy, body).unwrap();
        assert_eq!(k1, k2);
        assert_eq!(p1, p2);
    }

    #[test]
    fn write_detects_post_write_tampering_via_bytes_diverge() {
        let (_t, store) = fresh_store();
        let body = b"original-bytes";
        let (key, path) = store.write(Category::Policy, body).unwrap();
        // Tamper: overwrite the file with different bytes that hash
        // to a different sha256. The next `write(body)` call must
        // surface BytesDiverge — otherwise corruption goes silent.
        std::fs::write(&path, b"tampered-bytes").unwrap();
        let err = store.write(Category::Policy, body).unwrap_err();
        match err {
            ArtifactStoreError::BytesDiverge { path: p } => {
                assert_eq!(p, store.path_for(Category::Policy, &key));
            }
            other => panic!("expected BytesDiverge, got {other:?}"),
        }
    }

    #[test]
    fn read_surfaces_integrity_mismatch_on_tampering() {
        let (_t, store) = fresh_store();
        let body = b"trusted-bytes";
        let (key, path) = store.write(Category::Policy, body).unwrap();
        std::fs::write(&path, b"tampered-bytes").unwrap();
        let err = store.read(Category::Policy, &key).unwrap_err();
        match err {
            ArtifactStoreError::IntegrityMismatch { expected_sha, .. } => {
                assert_eq!(expected_sha, key.as_hex());
            }
            other => panic!("expected IntegrityMismatch, got {other:?}"),
        }
    }

    #[test]
    fn exists_returns_true_for_written_only() {
        let (_t, store) = fresh_store();
        let body = b"present";
        let (key, _) = store.write(Category::Policy, body).unwrap();
        assert!(store.exists(Category::Policy, &key));
        let other_key = ArtifactKey::compute(b"absent");
        assert!(!store.exists(Category::Policy, &other_key));
    }

    #[test]
    fn write_companion_writes_sidecar_with_matching_stem() {
        let (_t, store) = fresh_store();
        let body = b"plan-bytes";
        let sig = b"signature-bytes";
        let (key, _) = store.write(Category::Plans, body).unwrap();
        let sig_path = store
            .write_companion(Category::Plans, &key, "sig", sig)
            .unwrap();
        assert!(sig_path.exists());
        assert_eq!(std::fs::read(&sig_path).unwrap(), sig);
        // The companion's stem must match the artifact's hex sha256.
        let stem = sig_path.file_stem().unwrap().to_str().unwrap();
        assert_eq!(stem, key.as_hex());
    }

    #[test]
    fn category_pinning_does_not_collide() {
        let (_t, store) = fresh_store();
        let body = b"shared-bytes";
        let (k_pol, p1) = store.write(Category::Policy, body).unwrap();
        let (k_plan, p2) = store.write(Category::Plans, body).unwrap();
        assert_eq!(
            k_pol, k_plan,
            "the SHA-256 is content-addressed and identical regardless of category"
        );
        assert_ne!(
            p1, p2,
            "the on-disk path MUST differ across categories — even \
             with an identical key — so accidental cross-category \
             collisions cannot happen"
        );
    }

    #[test]
    fn paths_use_canonical_extension_per_category() {
        assert_eq!(Category::Policy.ext(), "toml");
        assert_eq!(Category::Plans.ext(), "toml");
        assert_eq!(Category::Keys.ext(), "pem");
        assert_eq!(Category::Policy.sub_dir(), "policy");
        assert_eq!(Category::Plans.sub_dir(), "plans");
        assert_eq!(Category::Keys.sub_dir(), "keys");
    }
}
