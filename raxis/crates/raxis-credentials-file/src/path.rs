//! Canonical credential-path resolver and mode/uid validator.
//!
//! The `<name>` form decides the layout:
//!   * `providers.<id>` → `<data_dir>/providers/<id>.toml`
//!   * `<name>`         → `<data_dir>/credentials/<name>.env`
//!   * metadata sidecars live beside the secret as
//!     `<stem>.metadata.toml`
//!
//! Anything that breaks out of the `<data_dir>/credentials/` or
//! `<data_dir>/providers/` subtrees (`..`, absolute paths, embedded
//! `/`) is rejected with `CredentialError::Malformed` at validation
//! time so a malformed `[[permitted_credentials]].name` cannot
//! traverse the filesystem.

use std::path::{Path, PathBuf};

use raxis_credentials::{CredentialError, CredentialName};

/// The shape returned by `credential_file_path`. Carries the
/// computed on-disk path plus a marker for which subtree the file
/// belongs to (`credentials/` vs `providers/`). The marker is
/// useful for tests that want to assert the layout without
/// inspecting the path string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPath {
    /// Absolute path the backend will read or write.
    pub path: PathBuf,
    /// True iff the credential lives under `<data_dir>/providers/`.
    pub is_provider: bool,
}

impl ResolvedPath {
    /// Borrow the resolved on-disk path.
    pub fn as_path(&self) -> &Path {
        &self.path
    }
}

/// Compute the on-disk path for a credential name. Does NOT touch
/// the filesystem — purely a string-shape decision. The kernel
/// admission pipeline already validated `name` against the
/// policy's `[[permitted_credentials]]` allowlist, so we trust the
/// shape here; security validation (mode, uid) happens in
/// `validate_path_security` AFTER the path is computed.
pub fn credential_file_path(data_dir: &Path, name: &CredentialName) -> PathBuf {
    let raw = name.as_str();
    if let Some(provider_id) = raw.strip_prefix("providers.") {
        data_dir
            .join("providers")
            .join(format!("{provider_id}.toml"))
    } else {
        data_dir.join("credentials").join(format!("{raw}.env"))
    }
}

/// Compute the non-secret metadata sidecar path for a credential.
///
/// The sidecar stores operator-facing catalog fields such as
/// `proxy_type`, `environment`, and `description`; it never stores
/// credential bytes. Keeping this path logic beside
/// [`credential_file_path`] prevents the dashboard and CLI from
/// drifting on the on-disk contract.
pub fn credential_metadata_file_path(data_dir: &Path, name: &CredentialName) -> PathBuf {
    let raw = name.as_str();
    if let Some(provider_id) = raw.strip_prefix("providers.") {
        data_dir
            .join("providers")
            .join(format!("{provider_id}.metadata.toml"))
    } else {
        data_dir
            .join("credentials")
            .join(format!("{raw}.metadata.toml"))
    }
}

/// Validate that the resolved path is safe to read or write:
///   1. The path component derived from `name` does NOT contain
///      `..`, absolute path components, or path-separators
///      (defence-in-depth against a corrupted policy that bypassed
///      shape checks).
///   2. The file (if it exists) is `chmod 0600`.
///   3. The file (if it exists) is owned by `expected_uid` (when
///      that argument is `Some`).
///
/// Returns `Ok(())` when the file does not yet exist (so `resolve`
/// can return `NotFound` from the read step that follows; we don't
/// want to short-circuit on missing). Returns `Err(Malformed)` on
/// path-shape violations and on mode/uid mismatches.
pub fn validate_path_security(
    path: &Path,
    name: &CredentialName,
    expected_uid: Option<u32>,
) -> Result<(), CredentialError> {
    // Path-shape: the credential `<name>` must not contain
    // separators or traversal segments. We re-check here even
    // though the kernel admission pipeline should have caught
    // them; defence in depth.
    let raw = name.as_str();
    if raw.contains('/') || raw.contains('\\') || raw.contains("..") {
        return Err(CredentialError::Malformed {
            name: name.clone(),
            reason: "name contains path separator or traversal segment".into(),
        });
    }

    // If the file does not yet exist, there is nothing to check
    // beyond shape. The caller's read will surface `NotFound`.
    let metadata = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(CredentialError::BackendUnavailable {
                reason: format!("stat {}: {e}", path.display()),
            });
        }
    };

    // Mode: 0600 only. Anything readable by group or other is
    // rejected.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = metadata.mode() & 0o777;
        if mode != 0o600 {
            return Err(CredentialError::Malformed {
                name: name.clone(),
                reason: format!(
                    "{} has mode 0{mode:o}, expected 0600 (chmod 0600 the file)",
                    path.display(),
                ),
            });
        }
        // UID: must match the kernel process's UID when supplied.
        // None means "don't check" — only set in tests where the
        // sandboxing renders the check meaningless.
        if let Some(want) = expected_uid {
            let got = metadata.uid();
            if got != want {
                return Err(CredentialError::Malformed {
                    name: name.clone(),
                    reason: format!(
                        "{} owned by uid {got}, expected uid {want} (run `chown {want} <path>`)",
                        path.display(),
                    ),
                });
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_without_dot_resolves_under_credentials_dot_env() {
        let p = credential_file_path(Path::new("/r"), &CredentialName::from("postgres-staging"));
        assert!(p.ends_with("credentials/postgres-staging.env"));
    }

    #[test]
    fn provider_name_resolves_under_providers_dot_toml() {
        let p = credential_file_path(
            Path::new("/r"),
            &CredentialName::from("providers.anthropic-prod"),
        );
        assert!(p.ends_with("providers/anthropic-prod.toml"));
    }

    #[test]
    fn metadata_path_resolves_beside_secret_without_secret_extension() {
        let p = credential_metadata_file_path(
            Path::new("/r"),
            &CredentialName::from("postgres-staging"),
        );
        assert!(p.ends_with("credentials/postgres-staging.metadata.toml"));

        let p = credential_metadata_file_path(
            Path::new("/r"),
            &CredentialName::from("providers.openai-prod"),
        );
        assert!(p.ends_with("providers/openai-prod.metadata.toml"));
    }

    #[test]
    fn validate_rejects_name_with_path_separator() {
        let err = validate_path_security(
            Path::new("/r/credentials/x.env"),
            &CredentialName::from("a/b"),
            None,
        )
        .unwrap_err();
        match err {
            CredentialError::Malformed { reason, .. } => {
                assert!(reason.contains("path separator"), "{reason}");
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_traversal_segment() {
        let err = validate_path_security(
            Path::new("/r/credentials/x.env"),
            &CredentialName::from("..foo"),
            None,
        )
        .unwrap_err();
        assert!(matches!(err, CredentialError::Malformed { .. }));
    }
}
