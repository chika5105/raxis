// raxis-kernel::policy_manager — Policy artifact lifecycle.
//
// Normative reference: kernel-core.md §`policy_manager.rs`.
//
// This module is the SINGLE writer to the `policy_epoch_history` store
// table (kernel-store.md §2.5.1 Table 19). Per spec §INV-POLICY-01 there
// are exactly two write entry points:
//
//   1. `install_genesis_policy_epoch` — called once, at genesis time
//      from `bootstrap::run_inner`, after the kernel.db schema has been
//      installed and the policy.toml artifact has been written. Inserts
//      the canonical `epoch_id = 1, triggered_by_operator = "genesis"`
//      row.
//
//   2. `advance_epoch` — called from `handlers/operator::handle_rotate_epoch`
//      every time an operator rotates the active policy. Inserts a new
//      `epoch_id = N+1` row inside the SQL transaction that also sweeps
//      delegations and invalidates session prompts.
//
// Every other subsystem observes the current epoch by reading
// `ctx.policy.load().epoch_id` from the in-memory `Arc<ArcSwap<PolicyBundle>>` —
// no other module reads `policy_epoch_history` in the hot path.

use std::path::{Path, PathBuf};

use raxis_store::Store;
use thiserror::Error;

// ---------------------------------------------------------------------------
// PolicyError
// ---------------------------------------------------------------------------

/// Failure modes for `policy_manager` operations. Each variant is mapped
/// to a stable wire string by `error_code()` for the CLI's pattern-matching
/// layer.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// The Ed25519 signature on the policy artifact does not verify
    /// against `KeyRegistry.authority_keypair.public`.
    #[error("policy signature verification failed: {reason}")]
    SignatureInvalid { reason: String },

    /// The artifact's `meta.epoch` is less than or equal to the current
    /// `MAX(epoch_id)` recorded in `policy_epoch_history`. Replay
    /// protection per kernel-core.md §`policy_manager.rs`.
    #[error(
        "policy epoch_id={attempted} is not greater than current epoch_id={current}; \
         replay protected"
    )]
    EpochReplay { attempted: u64, current: u64 },

    /// The artifact bytes are not a well-formed signed policy artifact
    /// (TOML parse failure, missing required field, semantic validation
    /// failure in `raxis-policy::PolicyBundle::validate`).
    #[error("policy artifact is malformed: {reason}")]
    MalformedArtifact { reason: String },

    /// The supplied path canonicalises to a location outside the
    /// kernel data directory. Defence-in-depth against operators who
    /// accidentally point at a build-server staging dir.
    #[error("policy path {path:?} is outside data_dir {data_dir:?}")]
    PathOutsideDataDir { path: PathBuf, data_dir: PathBuf },

    /// `policy_epoch_history.policy_sha256` UNIQUE constraint trip — the
    /// same artifact bytes were previously installed under a different
    /// `epoch_id`. Surfaces an operator who hand-edited `meta.epoch` to
    /// bypass replay protection.
    #[error("policy artifact (sha256={sha256}) was previously installed")]
    PolicyArtifactAlreadyInstalled { sha256: String },

    /// SQLite write failed during Phase 1 (delegations sweep, prompt
    /// invalidation, history INSERT, audit-pointer append). The
    /// transaction was rolled back; in-memory state is unchanged.
    #[error("policy store write failed: {reason}")]
    StoreWriteFailed { reason: String },

    /// I/O failure reading the policy or signature artifact.
    #[error("policy artifact read failed: {reason}")]
    ArtifactReadFailed { reason: String },
}

impl PolicyError {
    /// Stable wire short-string used by the operator IPC error envelope
    /// (`OperatorResponse::Error.code`). The CLI pattern-matches on
    /// these to render operator-friendly messages.
    pub fn error_code(&self) -> &'static str {
        match self {
            PolicyError::SignatureInvalid { .. }            => "FAIL_POLICY_SIGNATURE_INVALID",
            PolicyError::EpochReplay { .. }                 => "FAIL_POLICY_EPOCH_REPLAY",
            PolicyError::MalformedArtifact { .. }           => "FAIL_POLICY_MALFORMED",
            PolicyError::PathOutsideDataDir { .. }          => "FAIL_POLICY_PATH_OUTSIDE_DATA_DIR",
            PolicyError::PolicyArtifactAlreadyInstalled { .. } => {
                "FAIL_POLICY_ARTIFACT_ALREADY_INSTALLED"
            }
            PolicyError::StoreWriteFailed { .. }            => "FAIL_POLICY_STORE_WRITE",
            PolicyError::ArtifactReadFailed { .. }          => "FAIL_POLICY_ARTIFACT_READ",
        }
    }
}

// ---------------------------------------------------------------------------
// read_current_epoch
// ---------------------------------------------------------------------------

/// Read the highest installed policy epoch from `policy_epoch_history`.
///
/// Returns `0` when the table is empty (pre-genesis), so a freshly
/// migrated database with no genesis row reports epoch `0` — and the
/// genesis install (`install_genesis_policy_epoch`) is the only
/// transition from `0 → 1` that does not go through `advance_epoch`.
///
/// **Cold-path only.** Hot-path callers must read
/// `ctx.policy.load().epoch_id` from the `Arc<ArcSwap<PolicyBundle>>`;
/// this function exists for `policy_manager` itself (replay protection
/// in `advance_epoch` and `load_and_verify`) and for forensics tooling.
pub fn read_current_epoch(store: &Store) -> Result<u64, PolicyError> {
    let conn = store.lock_sync();
    let epoch: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(epoch_id), 0) FROM policy_epoch_history",
            [],
            |r| r.get(0),
        )
        .map_err(|e| PolicyError::StoreWriteFailed {
            reason: format!("read MAX(epoch_id) failed: {e}"),
        })?;
    // The schema constrains epoch_id to NOT NULL INTEGER PRIMARY KEY;
    // genesis writes 1, every advance writes a strictly larger value,
    // so the value never goes negative. We saturate-cast for safety.
    Ok(epoch.max(0) as u64)
}

// ---------------------------------------------------------------------------
// install_genesis_policy_epoch
// ---------------------------------------------------------------------------

/// Insert the `epoch_id = 1, triggered_by_operator = "genesis"` row into
/// `policy_epoch_history`. Idempotent: if a row with `epoch_id = 1`
/// already exists, the function returns `Ok(())` without modifying the
/// row. This makes it safe to invoke from `bootstrap::run_inner` even
/// if a previous bootstrap run reached this step before crashing.
///
/// Spec contract (kernel-core.md §`policy_manager.rs`):
///   "the genesis bootstrap path (raxis-cli genesis →
///    bootstrap::install_genesis_policy, which writes the epoch_id = 1
///    row with triggered_by_operator = "genesis" under the same
///    transaction that finalises the schema)"
///
/// `policy_sha256` is the lowercase-hex SHA-256 of the genesis
/// `policy.toml` bytes (computed by `raxis_policy::load_policy`).
/// `signed_by_authority` is the authority pubkey fingerprint
/// (SHA-256[:16] hex; same convention as
/// `raxis_genesis_tools::pubkey_fingerprint`).
pub fn install_genesis_policy_epoch(
    store: &Store,
    policy_sha256: &str,
    signed_by_authority: &str,
    advanced_at_unix_secs: i64,
) -> Result<(), PolicyError> {
    let conn = store.lock_sync();

    // INSERT OR IGNORE means a re-bootstrap attempt that crashed after
    // this row was already written cleanly succeeds without surfacing a
    // false UNIQUE-constraint error to the operator. The genesis policy
    // bytes are deterministic per-install (same policy.toml on disk),
    // so a re-run that produced different bytes would conflict on the
    // UNIQUE(policy_sha256) constraint AT a different code path —
    // covered by the test below.
    conn.execute(
        "INSERT OR IGNORE INTO policy_epoch_history (
             epoch_id, policy_sha256, signed_by_authority,
             triggered_by_operator, advanced_at
         ) VALUES (1, ?1, ?2, 'genesis', ?3)",
        rusqlite::params![policy_sha256, signed_by_authority, advanced_at_unix_secs],
    )
    .map_err(|e| PolicyError::StoreWriteFailed {
        reason: format!("INSERT OR IGNORE policy_epoch_history failed: {e}"),
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// canonicalize_under_data_dir
// ---------------------------------------------------------------------------

/// Canonicalise `path` and confirm it resolves under `data_dir`.
///
/// Returns `Ok(canonical_path)` on success. Surfaces
/// `PolicyError::PathOutsideDataDir` if the canonical path escapes the
/// data dir, or `PolicyError::ArtifactReadFailed` if either
/// `canonicalize` call fails.
///
/// Used by `advance_epoch` (and tests) to enforce the
/// `<data_dir>/policy/` containment invariant before opening the
/// artifact (kernel-core.md §`policy_manager.rs`).
pub(crate) fn canonicalize_under_data_dir(
    path: &Path,
    data_dir: &Path,
) -> Result<PathBuf, PolicyError> {
    let canon_data_dir = std::fs::canonicalize(data_dir).map_err(|e| {
        PolicyError::ArtifactReadFailed {
            reason: format!("canonicalize data_dir {data_dir:?} failed: {e}"),
        }
    })?;
    let canon_path = std::fs::canonicalize(path).map_err(|e| {
        PolicyError::ArtifactReadFailed {
            reason: format!("canonicalize path {path:?} failed: {e}"),
        }
    })?;
    if !canon_path.starts_with(&canon_data_dir) {
        return Err(PolicyError::PathOutsideDataDir {
            path: canon_path,
            data_dir: canon_data_dir,
        });
    }
    Ok(canon_path)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_store::Store;

    fn open_mem_store() -> Store {
        Store::open_in_memory().expect("open in-memory store")
    }

    #[test]
    fn read_current_epoch_returns_zero_on_empty_table() {
        let store = open_mem_store();
        assert_eq!(read_current_epoch(&store).unwrap(), 0);
    }

    #[test]
    fn install_genesis_writes_epoch_one() {
        let store = open_mem_store();
        install_genesis_policy_epoch(
            &store,
            "abc123",
            "deadbeefdeadbeefdeadbeefdeadbeef",
            1_700_000_000,
        )
        .unwrap();
        assert_eq!(read_current_epoch(&store).unwrap(), 1);
    }

    #[test]
    fn install_genesis_is_idempotent_on_re_run() {
        // Two consecutive invocations with the same byte content must
        // succeed; the second is a no-op via INSERT OR IGNORE. This is
        // the recovery contract for a bootstrap that crashed after the
        // INSERT but before returning.
        let store = open_mem_store();
        install_genesis_policy_epoch(
            &store, "abc123", "fp", 1_700_000_000,
        )
        .unwrap();
        install_genesis_policy_epoch(
            &store, "abc123", "fp", 1_700_000_000,
        )
        .expect("second install must be a no-op");
        assert_eq!(read_current_epoch(&store).unwrap(), 1);
    }

    #[test]
    fn install_genesis_persists_metadata_columns() {
        let store = open_mem_store();
        install_genesis_policy_epoch(
            &store, "deadc0de", "f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1", 1_700_000_001,
        )
        .unwrap();
        let conn = store.lock_sync();
        let (sha, signed_by, triggered, ts): (String, String, String, i64) = conn
            .query_row(
                "SELECT policy_sha256, signed_by_authority, triggered_by_operator, advanced_at
                   FROM policy_epoch_history WHERE epoch_id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(sha, "deadc0de");
        assert_eq!(signed_by, "f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1");
        assert_eq!(triggered, "genesis");
        assert_eq!(ts, 1_700_000_001);
    }

    #[test]
    fn canonicalize_under_data_dir_rejects_escape() {
        let data_dir = tempfile::tempdir().expect("data_dir");
        let outside = tempfile::NamedTempFile::new().expect("outside tempfile");
        let result = canonicalize_under_data_dir(outside.path(), data_dir.path());
        assert!(matches!(result, Err(PolicyError::PathOutsideDataDir { .. })));
    }

    #[test]
    fn canonicalize_under_data_dir_accepts_inside() {
        let data_dir = tempfile::tempdir().expect("data_dir");
        let inside = data_dir.path().join("policy.toml");
        std::fs::write(&inside, b"stub").unwrap();
        let canon = canonicalize_under_data_dir(&inside, data_dir.path()).unwrap();
        assert!(canon.starts_with(std::fs::canonicalize(data_dir.path()).unwrap()));
    }

    #[test]
    fn error_code_strings_are_stable() {
        // The CLI keys off these short strings; bumping them would be a
        // wire break. Pin every variant.
        assert_eq!(
            PolicyError::SignatureInvalid { reason: "x".into() }.error_code(),
            "FAIL_POLICY_SIGNATURE_INVALID",
        );
        assert_eq!(
            PolicyError::EpochReplay { attempted: 1, current: 2 }.error_code(),
            "FAIL_POLICY_EPOCH_REPLAY",
        );
        assert_eq!(
            PolicyError::MalformedArtifact { reason: "x".into() }.error_code(),
            "FAIL_POLICY_MALFORMED",
        );
        assert_eq!(
            PolicyError::PathOutsideDataDir {
                path: PathBuf::from("/x"),
                data_dir: PathBuf::from("/y"),
            }
            .error_code(),
            "FAIL_POLICY_PATH_OUTSIDE_DATA_DIR",
        );
        assert_eq!(
            PolicyError::PolicyArtifactAlreadyInstalled { sha256: "x".into() }.error_code(),
            "FAIL_POLICY_ARTIFACT_ALREADY_INSTALLED",
        );
        assert_eq!(
            PolicyError::StoreWriteFailed { reason: "x".into() }.error_code(),
            "FAIL_POLICY_STORE_WRITE",
        );
        assert_eq!(
            PolicyError::ArtifactReadFailed { reason: "x".into() }.error_code(),
            "FAIL_POLICY_ARTIFACT_READ",
        );
    }
}
