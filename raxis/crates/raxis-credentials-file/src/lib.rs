//! `raxis-credentials-file` — the V2 default `CredentialBackend` impl.
//!
//! Normative reference: `extensibility-traits.md §4.2`.
//!
//! # File layout
//!
//! Two parallel root directories under `<data_dir>/`:
//!
//!   * `<data_dir>/credentials/<name>.env`   — agent-bound credentials
//!     (DB passwords, kubeconfigs, AWS / GCP / Azure service-account
//!     blobs). Read by the credential proxies in
//!     `raxis-credential-proxy/*` at session activation.
//!
//!   * `<data_dir>/providers/<name>.toml`    — gateway-bound provider
//!     credentials (Anthropic API key, OpenAI API key). Read by
//!     `raxis-gateway` at boot + on `EpochAdvanced`.
//!
//! Both are flat-file plaintext; both are required to be `chmod 0600`
//! and owned by the kernel's OS user. The backend distinguishes the
//! two via the `<name>` form: anything starting with `providers.`
//! resolves under `providers/` (with `<name>.toml` as the on-disk
//! filename); everything else resolves under `credentials/` (with
//! `<name>.env`). This naming convention is pinned by tests.
//!
//! # Atomicity contract
//!
//! `rotate(name, new)` is required to be atomic against concurrent
//! `resolve(name)`s — readers see either the pre-state or the
//! post-state, never a torn read. The implementation:
//!
//!   1. Writes `<path>.tmp.<rand>` with mode 0600 and the new bytes.
//!   2. `fsync(2)` the file.
//!   3. `rename(2)` over the existing file (POSIX-atomic on the
//!      same FS).
//!   4. `fsync(2)` the parent directory.
//!
//! Concurrent readers either open the old inode (whose contents are
//! the pre-rotation bytes) or the new inode (whose contents are the
//! post-rotation bytes). Linux's directory-entry rename guarantees
//! exactly one inode is reachable through the path at any moment.
//!
//! # Mode/UID validation
//!
//! On every `resolve`, the backend stat()s the file and rejects with
//! `CredentialError::Malformed` if either:
//!
//!   * the mode is not `0600` (other-readable credential bytes are
//!     considered compromised), OR
//!   * the file is owned by a UID different from the kernel's UID
//!     (a different user's filesystem-injected file is rejected).
//!
//! `exists` performs the same checks, returning `false` rather than
//! erroring. This lets `raxis doctor` flag misconfigured credentials
//! at preflight without aborting the kernel.
//!
//! # Why a separate crate
//!
//! Same pattern as `raxis-isolation-apple-vz` /
//! `raxis-isolation-firecracker`: one trait crate
//! (`raxis-credentials`) and one impl crate per substrate. Tests of
//! the gateway, the credential proxies, and the kernel can all depend
//! on the impl crate without extra backends in builds that don't
//! need them.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::io::Write;
use std::path::{Path, PathBuf};

use raxis_credentials::{
    ConsumerIdentity, CredentialBackend, CredentialError, CredentialName, CredentialValue,
    OperatorId,
};

mod path;

pub use path::{
    credential_file_path, credential_metadata_file_path, validate_path_security, ResolvedPath,
};

// ---------------------------------------------------------------------------
// FileCredentialBackend
// ---------------------------------------------------------------------------

/// File-based `CredentialBackend`. Construct with [`Self::open`] at
/// kernel boot, wrap in `AuditingBackend`, hand the resulting
/// `Arc<dyn CredentialBackend>` to `HandlerContext`.
pub struct FileCredentialBackend {
    /// `<data_dir>` root. Credential paths are computed relative to
    /// this on every `resolve` so a future `data_dir`-rebind (rare —
    /// only the operator-driven `raxis migrate` path) takes effect
    /// without rebuilding the backend.
    data_dir: PathBuf,

    /// Kernel-process UID, captured at construction time. Used by
    /// the mode/uid validator to reject foreign-owned credential
    /// files. `None` means "skip uid check" (only ever set on
    /// platforms where uid is meaningless; in practice always
    /// `Some(getuid())` on Unix, the only platform we support).
    expected_uid: Option<u32>,
}

impl FileCredentialBackend {
    /// Construct a backend rooted at `data_dir`. The data dir
    /// must already exist; the backend does NOT create
    /// `credentials/` or `providers/` — those are created by
    /// `bootstrap.rs` at genesis time.
    ///
    /// On Unix, the backend captures the kernel's effective UID so
    /// the mode/uid validator can reject files owned by other users
    /// (typical attacker plant-and-wait pattern). On non-Unix
    /// platforms (none currently shipped) the UID check is skipped.
    pub fn open(data_dir: impl Into<PathBuf>) -> Self {
        let data_dir = data_dir.into();
        let expected_uid = current_uid();
        Self {
            data_dir,
            expected_uid,
        }
    }

    /// Construct a backend without the uid check. Tests use this
    /// when the test runner's UID does not match the file owner
    /// for some sandboxing reason. Production code MUST NOT call
    /// this — `open` is always correct on a real kernel.
    pub fn open_without_uid_check(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: data_dir.into(),
            expected_uid: None,
        }
    }
}

impl CredentialBackend for FileCredentialBackend {
    fn resolve(
        &self,
        name: &CredentialName,
        _consumer: ConsumerIdentity<'_>,
    ) -> Result<CredentialValue, CredentialError> {
        let path = credential_file_path(&self.data_dir, name);
        validate_path_security(&path, name, self.expected_uid)?;
        let bytes = std::fs::read(&path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => CredentialError::NotFound(name.clone()),
            _ => CredentialError::BackendUnavailable {
                reason: format!("read {}: {e}", path.display()),
            },
        })?;
        Ok(CredentialValue::from_bytes(bytes))
    }

    fn rotate(
        &self,
        name: &CredentialName,
        new: CredentialValue,
        _actor: OperatorId,
    ) -> Result<(), CredentialError> {
        let final_path = credential_file_path(&self.data_dir, name);
        let parent = final_path
            .parent()
            .ok_or_else(|| CredentialError::Malformed {
                name: name.clone(),
                reason: format!(
                    "computed credential path {} has no parent directory",
                    final_path.display(),
                ),
            })?;

        // Step 1: write `<path>.tmp.<pid>.<rand>` with mode 0600.
        // We use `pid + nanos` rather than uuid to keep the deps
        // tight; collisions across the same kernel rotating the
        // same credential within a nanosecond are not a real
        // concern.
        let tmp_name = format!(
            "{}.tmp.{}.{}",
            final_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("cred"),
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        );
        let tmp_path = parent.join(tmp_name);

        let bytes = new.into_bytes();
        write_file_mode_0600(&tmp_path, &bytes).map_err(|e| {
            CredentialError::BackendUnavailable {
                reason: format!("write tmp {}: {e}", tmp_path.display()),
            }
        })?;

        // Step 3: atomic rename.
        std::fs::rename(&tmp_path, &final_path).map_err(|e| {
            // Best effort: clean up the tmp file we just wrote.
            // The `_ = ...` is intentional — the caller already
            // has a fatal error; failing to clean up tmp is
            // not worse.
            let _ = std::fs::remove_file(&tmp_path);
            CredentialError::BackendUnavailable {
                reason: format!(
                    "rename {} -> {}: {e}",
                    tmp_path.display(),
                    final_path.display(),
                ),
            }
        })?;

        // Step 4: fsync the parent directory so the rename
        // metadata is durable.
        fsync_dir(parent).map_err(|e| CredentialError::BackendUnavailable {
            reason: format!("fsync parent dir {}: {e}", parent.display()),
        })?;

        Ok(())
    }

    fn exists(&self, name: &CredentialName) -> bool {
        let path = credential_file_path(&self.data_dir, name);
        if !path.exists() {
            return false;
        }
        validate_path_security(&path, name, self.expected_uid).is_ok()
    }

    fn backend_kind(&self) -> &'static str {
        "file"
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn current_uid() -> Option<u32> {
    // SAFETY: `getuid` is a thread-safe libc function.
    #[allow(unsafe_code)]
    let uid = unsafe { libc::getuid() };
    Some(uid)
}

#[cfg(not(unix))]
fn current_uid() -> Option<u32> {
    None
}

/// Write `bytes` to `path` with mode 0600, fsync, and close.
/// Used by `rotate`. On Unix we set the mode at create time via
/// `OpenOptions::mode`; on other platforms we fall back to
/// `set_permissions` after creation (best-effort).
fn write_file_mode_0600(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(())
    }
}

/// `fsync(2)` the directory entry. Required after a rename to make
/// the rename durable on power loss.
#[cfg(unix)]
fn fsync_dir(dir: &Path) -> std::io::Result<()> {
    use std::fs::OpenOptions;
    let f = OpenOptions::new().read(true).open(dir)?;
    f.sync_all()
}

#[cfg(not(unix))]
fn fsync_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}
