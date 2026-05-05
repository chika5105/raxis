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

use raxis_policy::PolicyBundle;

use crate::views::operator_certificates;
use crate::{Store, StoreError, Table};

/// Insert the canonical `epoch_id = 1, triggered_by_operator = "genesis"`
/// row into `policy_epoch_history` AND repopulate
/// `operator_certificates` with the bundle's operator entries —
/// atomically, in one BEGIN IMMEDIATE transaction.
///
/// Idempotent: if a row with `epoch_id = 1` already exists, the function
/// returns `Ok(())` without modifying anything (including
/// `operator_certificates`). This makes it safe to invoke from a
/// re-bootstrap that crashed after this row was written previously
/// (the deterministic-input fixture in the kernel's
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
///   * `bundle`                — the validated policy bundle the
///                                genesis ceremony just produced. Cert
///                                is mandatory (INV-CERT-01); the
///                                bundle's operator entries are
///                                mirrored into `operator_certificates`
///                                inside the SAME transaction as the
///                                genesis row INSERT, so the two
///                                tables come up either both populated
///                                or both empty. There is no
///                                `Option<&PolicyBundle>` legacy path:
///                                without a bundle we have no cert
///                                table to populate, and an empty
///                                cert table is itself a boot-time
///                                failure (`raxis doctor` reports
///                                `[FAIL]`).
pub fn install_genesis_policy_epoch_row(
    store: &Store,
    policy_sha256: &str,
    signed_by_authority: &str,
    advanced_at_unix_secs: i64,
    bundle: &PolicyBundle,
) -> Result<(), StoreError> {
    let mut conn = store.lock_sync();
    let table = Table::PolicyEpochHistory.as_str();

    // BEGIN IMMEDIATE so both the genesis row INSERT and the cert
    // repopulate either commit-together or rollback-together. Without
    // the transaction, a power-loss between the two would leave a
    // post-genesis kernel.db with no operator_certificates rows even
    // though the policy.toml on disk declares them — which would then
    // cause the kernel's first cert lookup to silently classify a
    // cert-bound operator as "legacy", breaking the audit chain
    // (cli-ceremony.md §4.2 step "atomic genesis").
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

    // INSERT OR IGNORE so a re-bootstrap that crashed after this row was
    // already committed surfaces as a clean Ok(()) rather than a UNIQUE
    // constraint error. The genesis bytes are deterministic per-install
    // (same authority key + policy.toml on disk), so a re-run that
    // produced different bytes would conflict on UNIQUE(policy_sha256)
    // — which is detected at a different code path (the kernel's
    // `bootstrap::integration::genesis_install_is_idempotent_under_force_re_run`
    // pins this).
    let n_inserted = tx.execute(
        &format!(
            "INSERT OR IGNORE INTO {table} (
                 epoch_id, policy_sha256, signed_by_authority,
                 triggered_by_operator, advanced_at
             ) VALUES (1, ?1, ?2, 'genesis', ?3)"
        ),
        rusqlite::params![policy_sha256, signed_by_authority, advanced_at_unix_secs],
    )?;

    // Only repopulate certs when we actually inserted the genesis row.
    // For an idempotent second-call (n_inserted == 0) the table is
    // already populated from the first call, and re-running repopulate
    // would clobber rows whose `installed_at` should reflect the
    // ORIGINAL install timestamp. This mirrors the "first-write
    // timestamp wins" contract that
    // `second_call_with_identical_inputs_is_idempotent` already pins
    // for `policy_epoch_history.advanced_at`.
    if n_inserted > 0 {
        operator_certificates::repopulate(&tx, bundle, 1, advanced_at_unix_secs).map_err(|e| {
            StoreError::Invariant(format!(
                "operator_certificates repopulate at genesis failed: {e}",
            ))
        })?;
    }

    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{open_ro, Store};
    use tempfile::TempDir;

    // Mirror the production module's typed-table-name discipline in the
    // test fixtures so a future column-rename in `migration_*` only has
    // to touch the `Table` enum, not every hand-rolled test SQL string.
    const POLICY_EPOCH_HISTORY:    &str = Table::PolicyEpochHistory.as_str();
    const OPERATOR_CERTIFICATES:   &str = Table::OperatorCertificates.as_str();

    fn fresh_store() -> (TempDir, Store) {
        let tmp = TempDir::new().expect("tempdir");
        let store = Store::open(&tmp.path().join("kernel.db")).expect("Store::open");
        (tmp, store)
    }

    use ed25519_dalek::SigningKey;
    use raxis_crypto::cert::sign_cert;
    use raxis_policy::{OperatorEntry, PolicyBundle};
    use raxis_types::operator_cert::{CertKind, OperatorCert};
    use sha2::{Digest, Sha256};

    fn signing_key() -> SigningKey { SigningKey::from_bytes(&[7u8; 32]) }
    fn pk_hex() -> String { hex::encode(signing_key().verifying_key().to_bytes()) }
    fn fp() -> String {
        let mut h = Sha256::new();
        h.update(hex::decode(pk_hex()).unwrap());
        hex::encode(&h.finalize()[..16])
    }

    fn signed_cert() -> OperatorCert {
        let mut c = OperatorCert {
            kind:                    CertKind::Standard,
            display_name:            "genesis-op".to_owned(),
            pubkey_hex:              pk_hex(),
            not_before:              1_700_000_000,
            not_after:               1_731_536_000,
            warn_before_expiry_days: 30,
            grace_period_days:       7,
            permitted_ops:           vec!["RotateEpoch".to_owned()],
            contact_info:            None,
            self_sig_hex:            String::new(),
        };
        c.self_sig_hex = sign_cert(&c, &signing_key());
        c
    }

    fn bundle_with_cert() -> PolicyBundle {
        PolicyBundle::for_tests_with_operators(vec![OperatorEntry {
            pubkey_fingerprint:     fp(),
            display_name:           "genesis-op".to_owned(),
            pubkey_hex:             pk_hex(),
            permitted_ops:          vec!["RotateEpoch".to_owned()],
            cert:                   signed_cert(),
            force_misconfig_bypass: false,
        }])
    }

    #[test]
    fn writes_epoch_one_row_with_genesis_marker() {
        let (tmp, store) = fresh_store();
        let bundle = bundle_with_cert();
        install_genesis_policy_epoch_row(
            &store,
            "deadbeef",
            "ffeeddcc",
            1_700_000_000,
            &bundle,
        )
        .expect("install");
        // Drop the writer handle before opening RO so RO does not race the WAL.
        drop(store);

        let conn = open_ro(tmp.path()).expect("open_ro");
        let (epoch, sha, by, triggered, ts): (i64, String, String, String, i64) = conn
            .query_row(
                &format!(
                    "SELECT epoch_id, policy_sha256, signed_by_authority, \
                            triggered_by_operator, advanced_at \
                       FROM {POLICY_EPOCH_HISTORY}"
                ),
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
        let bundle = bundle_with_cert();
        install_genesis_policy_epoch_row(&store, "deadbeef", "ffeeddcc", 100, &bundle)
            .expect("first install");
        install_genesis_policy_epoch_row(&store, "deadbeef", "ffeeddcc", 200, &bundle)
            .expect("second install must succeed (INSERT OR IGNORE)");
        drop(store);

        let conn = open_ro(tmp.path()).expect("open_ro");
        let count: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {POLICY_EPOCH_HISTORY}"),
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "INSERT OR IGNORE must not duplicate the genesis row");
        // The second timestamp (200) is ignored — the original row stands.
        let ts: i64 = conn
            .query_row(
                &format!(
                    "SELECT advanced_at FROM {POLICY_EPOCH_HISTORY} WHERE epoch_id = 1"
                ),
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(ts, 100, "first-write timestamp wins under INSERT OR IGNORE");
    }

    /// Genesis must mirror the operator entries into
    /// `operator_certificates` atomically — i.e. opening RO right
    /// after the call must observe BOTH the policy_epoch_history row
    /// AND the cert row. With cert-mandatory (INV-CERT-01), this is
    /// the only genesis path; there is no cert-less / Option<&Bundle>
    /// fallback.
    #[test]
    fn genesis_installs_certs_atomically_with_policy_row() {
        let (tmp, store) = fresh_store();
        let bundle = bundle_with_cert();
        install_genesis_policy_epoch_row(
            &store,
            "deadbeef",
            "ffeeddcc",
            1_700_000_000,
            &bundle,
        )
        .expect("install");
        drop(store);

        let conn = open_ro(tmp.path()).expect("open_ro");

        // Genesis row is present.
        let n_epoch: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {POLICY_EPOCH_HISTORY}"),
                [], |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n_epoch, 1);

        // Cert row is present, scoped to epoch_id = 1.
        let (cert_fp, cert_epoch, cert_kind): (String, i64, String) = conn
            .query_row(
                &format!(
                    "SELECT pubkey_fingerprint, epoch_id, kind \
                       FROM {OPERATOR_CERTIFICATES}"
                ),
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .expect("operator_certificates row must be present after genesis");
        assert_eq!(cert_fp, fp());
        assert_eq!(cert_epoch, 1, "cert must be scoped to genesis epoch");
        assert_eq!(cert_kind, "Standard");
    }

    /// A re-bootstrap (second call after a successful first call)
    /// must NOT re-populate the certs table. The first-write-wins
    /// contract for `advanced_at` already covered this for the
    /// genesis row; this pins the same contract for the certs table.
    #[test]
    fn second_call_does_not_re_repopulate_certs() {
        let (tmp, store) = fresh_store();
        let bundle = bundle_with_cert();
        install_genesis_policy_epoch_row(
            &store, "deadbeef", "ffeeddcc", 100,
            &bundle,
        ).expect("first install");
        // Same call again — even with a DIFFERENT (empty) bundle — must
        // be a no-op because n_inserted = 0 ⇒ skip repopulate. (In
        // production the bundle bytes are identical because the
        // policy.toml on disk hasn't changed; this test exercises the
        // weaker "second-call repopulate is a no-op" property.)
        let empty = PolicyBundle::for_tests_with_operators(vec![]);
        install_genesis_policy_epoch_row(
            &store, "deadbeef", "ffeeddcc", 200,
            &empty,
        ).expect("idempotent re-install must succeed");
        drop(store);
        let conn = open_ro(tmp.path()).expect("open_ro");
        let n: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {OPERATOR_CERTIFICATES}"),
                [], |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1,
            "second call's empty bundle must not erase first call's certs");
        // installed_at on the cert MUST still be 100 (the first-call
        // timestamp), not 200.
        let installed_at: i64 = conn
            .query_row(
                &format!("SELECT installed_at FROM {OPERATOR_CERTIFICATES}"),
                [], |r| r.get(0),
            )
            .unwrap();
        assert_eq!(installed_at, 100,
            "first-call installed_at wins (matches the policy_epoch_history.advanced_at contract)");
    }
}
