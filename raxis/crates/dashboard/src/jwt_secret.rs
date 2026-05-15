//! `raxis-dashboard::jwt_secret` — persistent HS256 signing secret.
//!
//! Normative reference:
//! `specs/v2/dashboard-hardening.md §INV-DASHBOARD-JWT-SECRET-PERSISTENT-01`
//! `specs/v2/self-healing-supervisor.md §10` (Operator session
//! continuity across supervisor-triggered restarts).
//
// **Why this module exists.**
//
// Pre-V2.5 the dashboard's HS256 JWT secret was minted via
// `OsRng` on every kernel boot and discarded on shutdown. That
// invariant was operator-friendly when the *only* way the kernel
// restarted was an operator-initiated stop+start (rare,
// expected). After `self-healing-supervisor.md` the kernel can
// auto-restart on deadlock detection — at which point operators
// in the middle of reviewing an initiative would silently lose
// their session and bounce to `/login`, with no signal that
// "this was an automatic restart, not your fault".
//
// V2.5 fixes this by persisting the HS256 secret to
// `<data_dir>/auth/dashboard_jwt.secret` with `0600` permissions.
// The secret survives any number of deadlock-restarts, panic-
// restarts, OOM-restarts, and graceful operator restarts. The
// session continuity invariant
// (`INV-SUPERVISOR-OPERATOR-CONTINUITY-01`) holds because the
// new kernel's `JwtSigner` loads the same bytes on the way up.
//
// **Rotation.** A `secret_generation: u32` counter is bound into
// every JWT claim (`gen`). The `JwtSigner::verify` path rejects
// any token whose `gen` is not the current generation. Operators
// rotate the secret via the `raxis dashboard rotate-jwt-secret`
// CLI command, which bumps the on-disk generation and mints
// fresh bytes — every pre-rotation token immediately stops
// verifying. This is the explicit "kick everyone out" lever the
// operator reaches for after a suspected secret compromise; it
// is NOT triggered by an auto-restart.
//
// **Threat model.** With the secret on disk, an attacker who can
// read `<data_dir>/auth/dashboard_jwt.secret` can forge JWTs.
// Mitigations:
//
//   1. The file is `0600` (owner read/write only), enforced on
//      every write (`set_secret_file_permissions`).
//   2. The file lives under the kernel's existing `<data_dir>/`
//      threat boundary — the same boundary the audit chain,
//      worktree storage, and operator certs already trust.
//      Compromise of `<data_dir>` is already a P0
//      ("attacker has the keys to everything") event, so this
//      module does not introduce a new sensitivity tier.
//   3. The generation-bound `gen` claim lets the operator
//      mechanically invalidate every pre-rotation token after
//      a forensic event without rebooting the kernel.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// On-disk file format. JSON-serialised so future-compat fields
/// can be added without breaking older kernels (every field
/// `serde(default)`).
///
/// **Wire shape.** Pretty-printed JSON for human-debuggability.
/// The file is small (<200 bytes) and read once per boot, so the
/// serialisation overhead is negligible.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretFile {
    /// Schema version of the on-disk file. Currently always `1`.
    /// A future migration would bump this and gate parsing on
    /// the value.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    /// Monotonic generation counter. Starts at `1` on initial
    /// mint; bumped by every rotate-jwt-secret invocation.
    /// Bound into every JWT claim's `gen` field; verify rejects
    /// stale generations.
    pub generation: u32,
    /// 32-byte HMAC-SHA-256 signing key, hex-encoded for the
    /// JSON wire (the bytes themselves are random + opaque, so
    /// hex round-trips cleanly via serde without needing
    /// base64).
    pub secret_hex: String,
    /// Unix-seconds wallclock the file was last (re)written.
    /// Forensic-only; not consulted by the auth path.
    #[serde(default)]
    pub updated_at_unix_secs: i64,
}

fn default_schema_version() -> u32 {
    1
}

impl SecretFile {
    /// 32-byte signing key, decoded from `secret_hex`.
    /// `Err(LoadError::Corrupt)` if the hex doesn't decode to
    /// exactly 32 bytes.
    pub fn secret_bytes(&self) -> Result<[u8; 32], LoadError> {
        let raw = hex::decode(&self.secret_hex)
            .map_err(|e| LoadError::Corrupt(format!("hex decode: {e}")))?;
        if raw.len() != 32 {
            return Err(LoadError::Corrupt(format!(
                "secret length {} != 32",
                raw.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        Ok(out)
    }
}

/// Errors surfaced by [`load_or_mint`] / [`rotate`].
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// File-system read / write / rename / permission set failed.
    /// The wrapped `io::Error` carries the OS-level reason; the
    /// CLI / kernel boot path adds the file path for context.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// `getrandom::getrandom` could not produce 32 bytes. On
    /// Unix this is a near-impossible condition (kernel CSPRNG
    /// would have to be unavailable). Surfaces as a hard error
    /// rather than a silent fallback per the security spec —
    /// no bytes is better than predictable bytes.
    #[error("rng: {0}")]
    Rng(String),
    /// On-disk JSON parse / hex-decode / length-check failure.
    /// Operator should `rm <data_dir>/auth/dashboard_jwt.secret`
    /// and let the next kernel boot mint a fresh file (this
    /// will invalidate every existing operator JWT, but a corrupt
    /// secret already locks them out so the cost is zero).
    #[error("corrupt secret file: {0}")]
    Corrupt(String),
    /// `chmod` to `0600` (file) / `0700` (auth dir) failed. We
    /// surface this as a hard error rather than silently shipping
    /// a world-readable secret — the operator-friendly recovery
    /// is to fix the underlying file-system / mount / SELinux
    /// constraint and retry.
    #[error("permission tightening failed: {0}")]
    PermissionTighten(String),
}

/// Filename relative to `<data_dir>/auth/`.
pub const SECRET_FILENAME: &str = "dashboard_jwt.secret";

/// Auth subdirectory under the kernel data dir.
pub const AUTH_SUBDIR: &str = "auth";

/// Full path to the secret file.
pub fn secret_path(data_dir: &Path) -> PathBuf {
    data_dir.join(AUTH_SUBDIR).join(SECRET_FILENAME)
}

/// Outcome of [`load_or_mint`]. Tells the caller whether they
/// just minted a fresh secret (first boot for this data_dir) or
/// reloaded a pre-existing one. Boot logging surfaces this so
/// operators can confirm "first boot mint" vs "subsequent boot
/// reload" in the kernel stderr.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadOutcome {
    /// File did not exist; we minted a fresh secret + wrote the
    /// file at generation `1`.
    Minted,
    /// File existed; we read it back successfully.
    Reloaded,
}

/// Load the persisted secret, or mint a fresh one and persist it
/// if no file exists yet.
///
/// Per `INV-DASHBOARD-JWT-SECRET-PERSISTENT-01`:
///
///   * The file is created at `0700` (auth dir) +
///     `0600` (secret file) on Unix.
///   * Mint uses `getrandom::getrandom`, surfacing RNG failure as
///     `LoadError::Rng` (no silent fallback).
///   * Generation starts at `1` for a freshly-minted file.
///   * The on-disk format is forward-compatible (every field
///     `serde(default)`).
///
/// Returns the loaded/minted [`SecretFile`] alongside a
/// [`LoadOutcome`] so the caller can log the outcome.
pub fn load_or_mint(data_dir: &Path) -> Result<(SecretFile, LoadOutcome), LoadError> {
    let path = secret_path(data_dir);
    match std::fs::read(&path) {
        Ok(bytes) => {
            let file: SecretFile = serde_json::from_slice(&bytes)
                .map_err(|e| LoadError::Corrupt(format!("JSON: {e}")))?;
            // Sanity-check the secret bytes can decode at the
            // expected length so the caller never sees a
            // corrupt file as `Reloaded`.
            let _ = file.secret_bytes()?;
            Ok((file, LoadOutcome::Reloaded))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let file = mint_fresh(1)?;
            write_secret_file(&path, &file)?;
            Ok((file, LoadOutcome::Minted))
        }
        Err(e) => Err(LoadError::Io(e)),
    }
}

/// Operator-initiated rotation. Bumps `generation` and mints a
/// fresh `secret_hex`. Returns the new [`SecretFile`].
///
/// Rotation is the explicit "kick everyone out" lever. After a
/// successful rotate, every pre-rotation JWT fails verification
/// because its `gen` claim no longer matches the current
/// generation.
///
/// Errors:
///   * `LoadError::Io` if the file cannot be read or written.
///   * `LoadError::Rng` if RNG fails.
///   * `LoadError::Corrupt` if the existing file cannot be
///     parsed (operator should remove the file and re-mint via
///     a kernel boot).
pub fn rotate(data_dir: &Path) -> Result<SecretFile, LoadError> {
    let path = secret_path(data_dir);
    let prev_generation = match std::fs::read(&path) {
        Ok(bytes) => {
            let file: SecretFile = serde_json::from_slice(&bytes)
                .map_err(|e| LoadError::Corrupt(format!("JSON: {e}")))?;
            file.generation
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(e) => return Err(LoadError::Io(e)),
    };
    let next_generation = prev_generation.saturating_add(1);
    let file = mint_fresh(next_generation)?;
    write_secret_file(&path, &file)?;
    Ok(file)
}

fn mint_fresh(generation: u32) -> Result<SecretFile, LoadError> {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf).map_err(|e| LoadError::Rng(e.to_string()))?;
    Ok(SecretFile {
        schema_version: 1,
        generation,
        secret_hex: hex::encode(buf),
        updated_at_unix_secs: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
    })
}

fn write_secret_file(path: &Path, file: &SecretFile) -> Result<(), LoadError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        // Tighten the auth dir to 0700 on Unix. The kernel's
        // umask might leave it group/world-readable otherwise,
        // and the secret file inside MUST be operator-only.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(parent)?.permissions();
            perms.set_mode(0o700);
            std::fs::set_permissions(parent, perms)
                .map_err(|e| LoadError::PermissionTighten(format!("auth dir 0700: {e}")))?;
        }
    }
    let bytes = serde_json::to_vec_pretty(file)
        .map_err(|e| LoadError::Corrupt(format!("JSON serialize: {e}")))?;
    let tmp = path.with_extension("secret.tmp");
    std::fs::write(&tmp, &bytes)?;
    // Tighten the tempfile to 0600 BEFORE the rename so the
    // final file's permissions are correct from the moment it
    // becomes visible at the canonical name.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&tmp, perms)
            .map_err(|e| LoadError::PermissionTighten(format!("secret file 0600: {e}")))?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn load_or_mint_creates_file_on_first_call() {
        let dir = tempdir().unwrap();
        let path = secret_path(dir.path());
        assert!(!path.exists());
        let (file, outcome) = load_or_mint(dir.path()).expect("mint");
        assert_eq!(outcome, LoadOutcome::Minted);
        assert_eq!(file.generation, 1);
        assert_eq!(file.schema_version, 1);
        assert_eq!(file.secret_hex.len(), 64);
        assert!(path.exists());
    }

    /// Witness for `INV-SUPERVISOR-OPERATOR-CONTINUITY-01`:
    /// reloading the file returns the SAME secret bytes + the
    /// SAME generation. JWT minted by an earlier kernel boot
    /// will verify under the next boot's signer.
    #[test]
    fn load_or_mint_reloads_existing_file_byte_identical() {
        let dir = tempdir().unwrap();
        let (first, outcome1) = load_or_mint(dir.path()).expect("mint");
        assert_eq!(outcome1, LoadOutcome::Minted);
        let (second, outcome2) = load_or_mint(dir.path()).expect("reload");
        assert_eq!(outcome2, LoadOutcome::Reloaded);
        assert_eq!(first, second, "reloaded secret must be byte-identical");
        assert_eq!(first.generation, second.generation);
        assert_eq!(first.secret_hex, second.secret_hex);
    }

    /// Witness for the rotation contract: bumps generation +
    /// mints fresh bytes.
    #[test]
    fn rotate_bumps_generation_and_changes_secret_bytes() {
        let dir = tempdir().unwrap();
        let (first, _) = load_or_mint(dir.path()).expect("mint");
        let rotated = rotate(dir.path()).expect("rotate");
        assert_eq!(rotated.generation, first.generation.saturating_add(1));
        assert_ne!(
            rotated.secret_hex, first.secret_hex,
            "rotation must change secret bytes",
        );
        // A subsequent load returns the rotated state.
        let (after, outcome) = load_or_mint(dir.path()).expect("reload");
        assert_eq!(outcome, LoadOutcome::Reloaded);
        assert_eq!(after, rotated);
    }

    #[test]
    fn rotate_on_empty_dir_starts_at_generation_1() {
        let dir = tempdir().unwrap();
        let rotated = rotate(dir.path()).expect("rotate");
        // No prior file → prev_generation=0, next=1.
        assert_eq!(rotated.generation, 1);
    }

    /// Witness for the file permissions invariant: 0600 on Unix.
    #[cfg(unix)]
    #[test]
    fn secret_file_is_0600_after_mint() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let _ = load_or_mint(dir.path()).unwrap();
        let path = secret_path(dir.path());
        let perms = std::fs::metadata(&path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600, "secret file MUST be 0600",);
    }

    /// Witness for the auth dir permissions: 0700 on Unix.
    #[cfg(unix)]
    #[test]
    fn auth_dir_is_0700_after_mint() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let _ = load_or_mint(dir.path()).unwrap();
        let auth_dir = dir.path().join(AUTH_SUBDIR);
        let perms = std::fs::metadata(&auth_dir).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o700, "auth dir MUST be 0700",);
    }

    #[test]
    fn corrupt_file_surfaces_as_load_error() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(AUTH_SUBDIR)).unwrap();
        std::fs::write(secret_path(dir.path()), b"{ not valid json").unwrap();
        let err = load_or_mint(dir.path()).unwrap_err();
        match err {
            LoadError::Corrupt(_) => {}
            other => panic!("expected Corrupt, got {other:?}"),
        }
    }

    #[test]
    fn corrupt_secret_length_surfaces_as_load_error() {
        let dir = tempdir().unwrap();
        let bad = SecretFile {
            schema_version: 1,
            generation: 1,
            secret_hex: "ab".to_owned(), // not 32 bytes
            updated_at_unix_secs: 0,
        };
        std::fs::create_dir_all(dir.path().join(AUTH_SUBDIR)).unwrap();
        std::fs::write(secret_path(dir.path()), serde_json::to_vec(&bad).unwrap()).unwrap();
        let err = load_or_mint(dir.path()).unwrap_err();
        match err {
            LoadError::Corrupt(_) => {}
            other => panic!("expected Corrupt, got {other:?}"),
        }
    }

    #[test]
    fn unknown_future_field_is_silently_ignored() {
        let dir = tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(AUTH_SUBDIR)).unwrap();
        let raw = serde_json::json!({
            "schema_version": 1,
            "generation": 7,
            "secret_hex": "ab".repeat(32),
            "updated_at_unix_secs": 100,
            "future_field": "ignored",
        });
        std::fs::write(secret_path(dir.path()), serde_json::to_vec(&raw).unwrap()).unwrap();
        let (file, outcome) = load_or_mint(dir.path()).unwrap();
        assert_eq!(outcome, LoadOutcome::Reloaded);
        assert_eq!(file.generation, 7);
    }
}
