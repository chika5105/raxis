// raxis-store::genesis — Writers for one-time genesis-ceremony rows.
//
// Normative reference:
//   * specs/v1/cli-ceremony.md §4.2 step "install genesis policy_epoch_history row"
//   * specs/v1/kernel-core.md §`policy_manager.rs` "two writers" contract
//
// Why this lives in `raxis-store`
// ───────────────────────────────
// `policy_epoch_history` is owned by the store crate (DDL in `migration.rs`,
// reads in `views/policy_history.rs`). The genesis row is the cold-path
// inverse of that — a single INSERT performed exactly once per data dir,
// during the genesis ceremony.
//
// Until this module landed, the row was written from
// `kernel/src/policy_manager.rs::install_genesis_policy_epoch`, which is
// only reachable from `bootstrap::run_inner` (i.e. the
// `RAXIS_BOOTSTRAP=1 raxis-kernel` self-bootstrap path). The operator-facing
// `raxis genesis` CLI command silently skipped this step, leaving the
// kernel.db without the genesis row — which then made the very first
// `RotateEpoch` record `epoch_id = 1` instead of `epoch_id = 2`,
// orphaning the genesis artifact in the policy-history audit trail
// (and, for v1, also producing a kernel boot that exited
// `BOOT_ERR_AUDIT_CHAIN` because the CLI also did not write
// `audit/segment-000.jsonl`).
//
// Hosting the writer here lets both genesis paths (kernel-side bootstrap and
// CLI-side `raxis genesis`) call one implementation, so a future schema
// rename or column addition is a single-file change and cannot drift.

use crate::{Store, StoreError, Table};

/// Insert the canonical `epoch_id = 1, triggered_by_operator = "genesis"`
/// row into `policy_epoch_history`.
///
/// Idempotent: if a row with `epoch_id = 1` already exists, the function
/// returns `Ok(())` without modifying anything. This makes it safe to
/// invoke from a re-bootstrap that crashed after this row was written
/// previously (the deterministic-input fixture in the kernel's
/// `bootstrap::integration` tests pins this property).
///
/// Inputs (all caller-supplied so the function stays pure / clock-free):
///   * `policy_sha256`         — lowercase-hex SHA-256 of the genesis
///                                `policy.toml` bytes (computed by
///                                `raxis_policy::load_policy`).
///   * `signed_by_authority`   — the authority pubkey fingerprint
///                                (SHA-256[:16] hex; same convention as
///                                `raxis_genesis_tools::pubkey_fingerprint`).
///   * `advanced_at_unix_secs` — wall-clock timestamp the genesis row
///                                records as `advanced_at`. Caller controls
///                                the clock so tests can pin this value.
pub fn install_genesis_policy_epoch_row(
    store: &Store,
    policy_sha256: &str,
    signed_by_authority: &str,
    advanced_at_unix_secs: i64,
) -> Result<(), StoreError> {
    let conn = store.lock_sync();
    let table = Table::PolicyEpochHistory.as_str();

    // INSERT OR IGNORE so a re-bootstrap that crashed after this row was
    // already committed surfaces as a clean Ok(()) rather than a UNIQUE
    // constraint error. The genesis bytes are deterministic per-install
    // (same authority key + policy.toml on disk), so a re-run that
    // produced different bytes would conflict on UNIQUE(policy_sha256)
    // — which is detected at a different code path (the kernel's
    // `bootstrap::integration::genesis_install_is_idempotent_under_force_re_run`
    // pins this).
    conn.execute(
        &format!(
            "INSERT OR IGNORE INTO {table} (
                 epoch_id, policy_sha256, signed_by_authority,
                 triggered_by_operator, advanced_at
             ) VALUES (1, ?1, ?2, 'genesis', ?3)"
        ),
        rusqlite::params![policy_sha256, signed_by_authority, advanced_at_unix_secs],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{open_ro, Store};
    use tempfile::TempDir;

    fn fresh_store() -> (TempDir, Store) {
        let tmp = TempDir::new().expect("tempdir");
        let store = Store::open(&tmp.path().join("kernel.db")).expect("Store::open");
        (tmp, store)
    }

    #[test]
    fn writes_epoch_one_row_with_genesis_marker() {
        let (tmp, store) = fresh_store();
        install_genesis_policy_epoch_row(
            &store,
            "deadbeef",
            "ffeeddcc",
            1_700_000_000,
        )
        .expect("install");
        // Drop the writer handle before opening RO so RO does not race the WAL.
        drop(store);

        let conn = open_ro(tmp.path()).expect("open_ro");
        let (epoch, sha, by, triggered, ts): (i64, String, String, String, i64) = conn
            .query_row(
                "SELECT epoch_id, policy_sha256, signed_by_authority, \
                        triggered_by_operator, advanced_at \
                   FROM policy_epoch_history",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .expect("genesis row must be present");
        assert_eq!(epoch, 1);
        assert_eq!(sha, "deadbeef");
        assert_eq!(by, "ffeeddcc");
        assert_eq!(triggered, "genesis");
        assert_eq!(ts, 1_700_000_000);
    }

    #[test]
    fn second_call_with_identical_inputs_is_idempotent() {
        let (tmp, store) = fresh_store();
        install_genesis_policy_epoch_row(&store, "deadbeef", "ffeeddcc", 100)
            .expect("first install");
        install_genesis_policy_epoch_row(&store, "deadbeef", "ffeeddcc", 200)
            .expect("second install must succeed (INSERT OR IGNORE)");
        drop(store);

        let conn = open_ro(tmp.path()).expect("open_ro");
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM policy_epoch_history",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "INSERT OR IGNORE must not duplicate the genesis row");
        // The second timestamp (200) is ignored — the original row stands.
        let ts: i64 = conn
            .query_row(
                "SELECT advanced_at FROM policy_epoch_history WHERE epoch_id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(ts, 100, "first-write timestamp wins under INSERT OR IGNORE");
    }
}
