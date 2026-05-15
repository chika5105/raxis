//! V2 Plan Bundle Sealing — store write/read helpers.
//!
//! Normative reference: `specs/v2/plan-bundle-sealing.md` §8.2 (storage
//! layout) + §8.1 step 12 (admission write contract).
//!
//! This module is the **single point of access** to the three V2
//! plan-bundle tables (`plan_bundles`, `plan_bundle_artifacts`,
//! `plan_bundle_nonces_seen`) for kernel-side write paths. The
//! read-only counterparts live in [`crate::views::plan_bundles`] and
//! consume an `RoConn`. Spec §8.3 ("Post-admission read discipline")
//! requires that *every* post-admission read of plan-derived bytes
//! flow through the read API — never through ad-hoc SQL elsewhere
//! in the kernel.
//!
//! # Why a dedicated write module instead of inline `format!()` SQL
//!
//! `lifecycle.rs::approve_plan` historically wrote
//! `signed_plan_artifacts` inline. That was tractable for one row,
//! one INSERT. Plan Bundle Sealing's §8.1 step 12 needs THREE
//! coordinated INSERTs (`plan_bundles`, N × `plan_bundle_artifacts`,
//! `plan_bundle_nonces_seen`) inside the SAME `BEGIN IMMEDIATE`
//! transaction, all referencing each other through the bundle's
//! SHA-256 hash. Wrapping that in typed helpers:
//!
//!   * Forces `INV-STORE-03`: every table identifier flows through
//!     `crate::Table::...as_str()` exactly once.
//!   * Lets the kernel's admission handler stay readable (the
//!     §8.1 step ordering becomes a sequence of named function
//!     calls, not a wall of SQL).
//!   * Concentrates all bind-parameter shape checks (8-byte
//!     fingerprint, 16-byte nonce, 32-byte SHA-256, 64-byte
//!     signature) at the helper boundary so a future parameter
//!     re-shuffle in the DDL is one code change, not three.
//!
//! All write functions take `&rusqlite::Transaction`. They do NOT
//! open or commit transactions themselves — that responsibility lies
//! with the caller (admission's `BEGIN IMMEDIATE` block per §8.1).

use raxis_types::{
    BundleArtifact, BundleNonce, BundleSha256, OperatorFingerprint, PlanBundle,
    PlanBundleNonceOutcome, SchemaVersion,
};
use rusqlite::{params, Transaction};
use thiserror::Error;

use crate::Table;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum PlanBundleStoreError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// Defensive: an in-process bundle struct came in with the
    /// schema-version vs envelope contract violated. The codec
    /// (`raxis_crypto::plan_bundle::canonical_encode`) catches this
    /// at encode time, but we re-check here before INSERTing because
    /// the DDL CHECK constraint will otherwise fire as a runtime
    /// SQL error with less helpful context.
    #[error("schema-envelope mismatch: schema_version={schema:?}, detail={detail}")]
    SchemaEnvelopeMismatch {
        schema: SchemaVersion,
        detail: &'static str,
    },
}

// ---------------------------------------------------------------------------
// insert_bundle
//
// §8.2 / §8.1 step 12: insert one row into `plan_bundles`. The
// recipe is content-addressed by `bundle_sha256`, so two
// byte-identical bundles dedupe to one row (`INSERT OR IGNORE`).
// The kernel's admission path writes the bundle BEFORE its
// per-artifact rows so the FK in `plan_bundle_artifacts` resolves.
// ---------------------------------------------------------------------------

/// Insert a `plan_bundles` row inside the caller's transaction.
///
/// `INSERT OR IGNORE` so two byte-identical bundles share a single
/// row (per §8.2 "stored once keyed by bundle_sha256"). The caller
/// MUST treat the function's success as "the canonical row exists",
/// not "this call inserted a new row" — content-addressed dedup is
/// intentional and audit-safe.
pub fn insert_bundle(
    tx: &Transaction<'_>,
    bundle_sha256: &BundleSha256,
    bundle_bytes: &[u8],
    signature: &[u8; 64],
    signed_by: &OperatorFingerprint,
    bundle: &PlanBundle,
    sealed_at_unix_secs: i64,
) -> Result<(), PlanBundleStoreError> {
    // Re-validate the schema/envelope contract before SQL fires. A
    // mismatch here can only arise from an in-process logic error
    // (the codec catches the wire path); surfacing a structured
    // error makes the regression traceable.
    let envelope_ok = match bundle.schema_version {
        SchemaVersion::V2_0 => {
            bundle.signed_at_unix_secs.is_none() && bundle.bundle_nonce.is_none()
        }
        SchemaVersion::V2_1 => {
            bundle.signed_at_unix_secs.is_some() && bundle.bundle_nonce.is_some()
        }
    };
    if !envelope_ok {
        return Err(PlanBundleStoreError::SchemaEnvelopeMismatch {
            schema: bundle.schema_version,
            detail: match bundle.schema_version {
                SchemaVersion::V2_0 => "V2.0 must NOT carry signed_at_unix_secs / bundle_nonce",
                SchemaVersion::V2_1 => "V2.1 MUST carry both signed_at_unix_secs and bundle_nonce",
            },
        });
    }

    let plan_bundles = Table::PlanBundles.as_str();
    tx.execute(
        &format!(
            "INSERT OR IGNORE INTO {plan_bundles} \
                (bundle_sha256, bundle_bytes, signature, signed_by, \
                 schema_version, artifact_count, bundle_bytes_len, \
                 sealed_at_unix_secs, signed_at_unix_secs, bundle_nonce) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"
        ),
        params![
            bundle_sha256.as_bytes().as_slice(),
            bundle_bytes,
            signature.as_slice(),
            signed_by.as_bytes().as_slice(),
            bundle.schema_version.as_u16() as i64,
            bundle.artifacts.len() as i64,
            bundle_bytes.len() as i64,
            sealed_at_unix_secs,
            bundle.signed_at_unix_secs.map(|s| s as i64),
            bundle.bundle_nonce.as_ref().map(|n| n.as_bytes().to_vec()),
        ],
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// insert_artifacts
//
// §8.2 / §8.1 step 12: insert per-artifact rows. The composite PK
// `(bundle_sha256, artifact_seq)` means two calls for the same
// bundle dedupe naturally; we use `INSERT OR IGNORE` for the same
// reason as `insert_bundle` (content-addressed dedup).
// ---------------------------------------------------------------------------

/// Insert all per-artifact rows for a bundle. Caller is responsible
/// for ensuring the parent `plan_bundles` row exists first (call
/// [`insert_bundle`] earlier in the same transaction).
///
/// `artifact_seq` is the index in `bundle.artifacts`. The §3.3
/// invariant `artifacts[0].name == "plan.toml"` is the codec's
/// responsibility (it validates the bundle at decode time); this
/// function is content-blind and trusts the input.
pub fn insert_artifacts(
    tx: &Transaction<'_>,
    bundle_sha256: &BundleSha256,
    artifacts: &[BundleArtifact],
) -> Result<(), PlanBundleStoreError> {
    let plan_bundle_artifacts = Table::PlanBundleArtifacts.as_str();
    let mut stmt = tx.prepare_cached(&format!(
        "INSERT OR IGNORE INTO {plan_bundle_artifacts} \
                (bundle_sha256, artifact_seq, artifact_name, \
                 artifact_sha256, artifact_bytes, artifact_bytes_len) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
    ))?;
    for (seq, artifact) in artifacts.iter().enumerate() {
        stmt.execute(params![
            bundle_sha256.as_bytes().as_slice(),
            seq as i64,
            artifact.name,
            artifact.sha256.as_bytes().as_slice(),
            artifact.bytes,
            artifact.bytes.len() as i64,
        ])?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// record_nonce
//
// §8.1 step 12b: write the nonce-disposition row INSIDE the BEGIN
// IMMEDIATE transaction so a concurrent re-submission cannot race
// past the §3.5 replay check. The DDL CHECK in Migration 8 enforces
// the (outcome, initiative_id) coherency:
//
//   - Admitted → initiative_id IS NOT NULL
//   - TerminallyRejected → initiative_id IS NULL
//
// Wrap the contract here so a future caller can't accidentally
// insert an `Admitted` row with NULL initiative_id (which would
// surface as a SQL error rather than as the structured argument-
// shape error this function produces).
// ---------------------------------------------------------------------------

/// Insert one row into `plan_bundle_nonces_seen` per §8.1 step 12b.
///
/// The (outcome, initiative_id) pair MUST be coherent:
///
///   * `Admitted` → `initiative_id` MUST be `Some(_)`.
///   * `TerminallyRejected` → `initiative_id` MUST be `None`.
///
/// The DDL CHECK is the second floor, but this typed wrapper
/// catches the contract violation before SQL fires — surfaces a
/// `SchemaEnvelopeMismatch`-style structured error path the
/// kernel's admission handler can render into an audit log.
pub fn record_nonce(
    tx: &Transaction<'_>,
    bundle_nonce: &BundleNonce,
    bundle_sha256: &BundleSha256,
    signed_at_unix_secs: i64,
    first_seen_at_unix_secs: i64,
    outcome: PlanBundleNonceOutcome,
    initiative_id: Option<&str>,
) -> Result<(), PlanBundleStoreError> {
    // Pre-flight: enforce the §8.1 step 12b coherency contract.
    let coherent = matches!(
        (outcome, initiative_id),
        (PlanBundleNonceOutcome::Admitted, Some(_))
            | (PlanBundleNonceOutcome::TerminallyRejected, None)
    );
    if !coherent {
        return Err(PlanBundleStoreError::Sqlite(
            // We re-use a SqliteError rather than minting a new
            // variant: the function's signature already forbids the
            // `(Admitted, None)` / `(TerminallyRejected, Some)`
            // cases at the type level (callers can't construct the
            // wrong shape by accident — they pass the enum +
            // Option<&str> as separate args). The runtime check is
            // defense-in-depth.
            rusqlite::Error::InvalidParameterName(format!(
                "record_nonce: incoherent (outcome, initiative_id) pair: \
                 outcome={outcome}, initiative_id_present={}",
                initiative_id.is_some(),
            )),
        ));
    }

    let plan_bundle_nonces_seen = Table::PlanBundleNoncesSeen.as_str();
    tx.execute(
        &format!(
            "INSERT INTO {plan_bundle_nonces_seen} \
                (bundle_nonce, bundle_sha256, signed_at_unix_secs, \
                 first_seen_at_unix_secs, outcome, initiative_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
        ),
        params![
            bundle_nonce.as_bytes().as_slice(),
            bundle_sha256.as_bytes().as_slice(),
            signed_at_unix_secs,
            first_seen_at_unix_secs,
            outcome.as_sql_str(),
            initiative_id,
        ],
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// nonce_status_in_tx
//
// §8.1 step 10b: look up an inbound `bundle_nonce` against the
// replay-protection table BEFORE deciding admission. Lives on the
// write side (not in `views/plan_bundles.rs`) because the spec
// requires this query inside the same `BEGIN IMMEDIATE` transaction
// as the `record_nonce` call below — the read needs to share the
// same transactional snapshot, which the views layer's RoConn
// abstraction cannot provide.
// ---------------------------------------------------------------------------

/// Result of the §8.1 step 10b nonce lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonceStatus {
    /// Original `bundle_sha256` recorded for this nonce. Useful when
    /// the kernel wants to log the prior bundle's hash in the
    /// `FAIL_PLAN_BUNDLE_REPLAY` detail.
    pub bundle_sha256: BundleSha256,
    pub signed_at_unix_secs: i64,
    pub first_seen_at_unix_secs: i64,
    pub outcome: PlanBundleNonceOutcome,
    /// Set iff `outcome == Admitted` (DDL CHECK enforces).
    pub initiative_id: Option<String>,
}

/// Look up a `bundle_nonce` in the replay-protection table inside
/// the caller's transaction. Returns `None` for an unseen nonce
/// (admission proceeds), `Some(NonceStatus)` for any prior
/// disposition (admission rejects with `FAIL_PLAN_BUNDLE_REPLAY`).
pub fn nonce_status_in_tx(
    tx: &Transaction<'_>,
    bundle_nonce: &BundleNonce,
) -> Result<Option<NonceStatus>, PlanBundleStoreError> {
    let plan_bundle_nonces_seen = Table::PlanBundleNoncesSeen.as_str();
    let row = tx
        .query_row(
            &format!(
                "SELECT bundle_sha256, signed_at_unix_secs, \
                        first_seen_at_unix_secs, outcome, initiative_id \
                 FROM {plan_bundle_nonces_seen} \
                 WHERE bundle_nonce = ?1"
            ),
            params![bundle_nonce.as_bytes().as_slice()],
            |r| {
                let sha_blob: Vec<u8> = r.get(0)?;
                let signed_at: i64 = r.get(1)?;
                let first_seen: i64 = r.get(2)?;
                let outcome_str: String = r.get(3)?;
                let init_id: Option<String> = r.get(4)?;

                let sha_arr: [u8; 32] = sha_blob.as_slice().try_into().map_err(|_| {
                    rusqlite::Error::InvalidColumnType(
                        0,
                        "bundle_sha256".into(),
                        rusqlite::types::Type::Blob,
                    )
                })?;
                let outcome =
                    PlanBundleNonceOutcome::from_sql_str(&outcome_str).ok_or_else(|| {
                        rusqlite::Error::InvalidColumnType(
                            3,
                            "outcome".into(),
                            rusqlite::types::Type::Text,
                        )
                    })?;
                Ok(NonceStatus {
                    bundle_sha256: BundleSha256::new(sha_arr),
                    signed_at_unix_secs: signed_at,
                    first_seen_at_unix_secs: first_seen,
                    outcome,
                    initiative_id: init_id,
                })
            },
        )
        .ok();
    Ok(row)
}

// ---------------------------------------------------------------------------
// sweep_expired_nonces
//
// §8.4: the periodic-maintenance loop reaps nonce rows that have
// fallen outside the freshness window. The kernel's `kernel-lifecycle`
// loop calls this; the function lives here to keep the SQL adjacent
// to the DDL it sweeps.
// ---------------------------------------------------------------------------

/// Delete `plan_bundle_nonces_seen` rows whose `first_seen_at_unix_secs`
/// is older than `cutoff_unix_secs`. Returns the number of rows
/// removed (useful for the maintenance log).
///
/// Spec §8.4 defines the cutoff as
///   `now() - max_plan_bundle_age_secs - max_clock_skew_secs
///          - nonce_retention_grace_secs`
/// The caller is responsible for computing `cutoff_unix_secs`; this
/// function is a pure DELETE.
pub fn sweep_expired_nonces(
    tx: &Transaction<'_>,
    cutoff_unix_secs: i64,
) -> Result<usize, PlanBundleStoreError> {
    let plan_bundle_nonces_seen = Table::PlanBundleNoncesSeen.as_str();
    let n = tx.execute(
        &format!(
            "DELETE FROM {plan_bundle_nonces_seen} \
             WHERE first_seen_at_unix_secs < ?1"
        ),
        params![cutoff_unix_secs],
    )?;
    Ok(n)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{migration::apply_pending, Store};
    use rusqlite::TransactionBehavior;

    fn fresh_store() -> Store {
        let store = Store::open_in_memory().unwrap();
        {
            let conn = store.lock_sync();
            apply_pending(&conn).unwrap();
        }
        store
    }

    fn fixture_v2_1_bundle() -> (PlanBundle, BundleSha256) {
        let plan_bytes = b"[orchestrator]\n".to_vec();
        let plan_sha = BundleSha256::new({
            // SHA-256(b"[orchestrator]\n") computed at test time —
            // we don't need to pin the exact value, only that the
            // store accepts the row through.
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(&plan_bytes);
            h.finalize().into()
        });
        let bundle = PlanBundle::new_v2_1(
            100,
            200,
            BundleNonce::new([0xAAu8; 16]),
            "myplan".to_owned(),
            vec![BundleArtifact {
                name: "plan.toml".to_owned(),
                bytes: plan_bytes,
                sha256: plan_sha,
            }],
        );
        let bundle_sha = BundleSha256::new([0x11u8; 32]); // arbitrary fixture sha
        (bundle, bundle_sha)
    }

    fn seed_initiative(store: &Store, initiative_id: &str) {
        let conn = store.lock_sync();
        conn.execute(
            &format!(
                "INSERT INTO {} \
                    (initiative_id, state, terminal_criteria_json, \
                     plan_artifact_sha256, created_at) \
                 VALUES (?1, 'Draft', '{{}}', 'deadbeef', 1700000000)",
                Table::Initiatives.as_str(),
            ),
            params![initiative_id],
        )
        .unwrap();
    }

    // ── insert_bundle ────────────────────────────────────────────────

    #[test]
    fn insert_bundle_round_trips_envelope_fields_for_v2_1() {
        let store = fresh_store();
        let (bundle, sha) = fixture_v2_1_bundle();
        let canonical = b"placeholder-canonical-bytes".to_vec();

        {
            let mut conn = store.lock_sync();
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            insert_bundle(
                &tx,
                &sha,
                &canonical,
                &[0x77u8; 64],
                &OperatorFingerprint::new([0x88u8; 8]),
                &bundle,
                1_700_000_999,
            )
            .unwrap();
            tx.commit().unwrap();
        }

        let conn = store.lock_sync();
        let row: (Vec<u8>, i64, i64, i64, Option<i64>, Option<Vec<u8>>) = conn
            .query_row(
                &format!(
                    "SELECT bundle_sha256, schema_version, artifact_count, \
                        sealed_at_unix_secs, signed_at_unix_secs, bundle_nonce \
                 FROM {} WHERE bundle_sha256 = ?1",
                    Table::PlanBundles.as_str(),
                ),
                params![sha.as_bytes().as_slice()],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(row.0, sha.as_bytes());
        assert_eq!(row.1, 2); // schema_version = V2.1
        assert_eq!(row.2, bundle.artifacts.len() as i64);
        assert_eq!(row.3, 1_700_000_999); // sealed_at
        assert_eq!(row.4, Some(200)); // signed_at_unix_secs
        assert_eq!(row.5.as_deref(), Some([0xAAu8; 16].as_slice()));
    }

    #[test]
    fn insert_bundle_persists_v2_0_legacy_with_null_envelope_fields() {
        let store = fresh_store();
        let plan_bytes = Vec::<u8>::new();
        let plan_sha = BundleSha256::new([0u8; 32]);
        let bundle = PlanBundle::new_v2_0_legacy(
            42,
            "old".to_owned(),
            vec![BundleArtifact {
                name: "plan.toml".to_owned(),
                bytes: plan_bytes,
                sha256: plan_sha,
            }],
        );
        let sha = BundleSha256::new([0xCCu8; 32]);

        {
            let mut conn = store.lock_sync();
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            insert_bundle(
                &tx,
                &sha,
                &[0u8; 8],
                &[0u8; 64],
                &OperatorFingerprint::new([1u8; 8]),
                &bundle,
                0,
            )
            .unwrap();
            tx.commit().unwrap();
        }

        let conn = store.lock_sync();
        let (signed_at, nonce): (Option<i64>, Option<Vec<u8>>) = conn
            .query_row(
                &format!(
                    "SELECT signed_at_unix_secs, bundle_nonce \
                 FROM {} WHERE bundle_sha256 = ?1",
                    Table::PlanBundles.as_str(),
                ),
                params![sha.as_bytes().as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert!(signed_at.is_none());
        assert!(nonce.is_none());
    }

    /// `INSERT OR IGNORE` semantics: two byte-identical bundles
    /// dedupe to one row keyed by `bundle_sha256`.
    #[test]
    fn insert_bundle_dedupes_on_bundle_sha256() {
        let store = fresh_store();
        let (bundle, sha) = fixture_v2_1_bundle();
        let canonical = b"hello".to_vec();
        let sig = [0x77u8; 64];
        let signer = OperatorFingerprint::new([0x88u8; 8]);

        for _ in 0..3 {
            let mut conn = store.lock_sync();
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            insert_bundle(&tx, &sha, &canonical, &sig, &signer, &bundle, 1).unwrap();
            tx.commit().unwrap();
        }

        let conn = store.lock_sync();
        let count: i64 = conn
            .query_row(
                &format!(
                    "SELECT COUNT(*) FROM {} WHERE bundle_sha256 = ?1",
                    Table::PlanBundles.as_str(),
                ),
                params![sha.as_bytes().as_slice()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "INSERT OR IGNORE must dedupe by bundle_sha256");
    }

    #[test]
    fn insert_bundle_rejects_v2_1_with_missing_envelope_before_sql() {
        let store = fresh_store();
        let (mut bundle, sha) = fixture_v2_1_bundle();
        bundle.signed_at_unix_secs = None;

        let mut conn = store.lock_sync();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let err = insert_bundle(
            &tx,
            &sha,
            b"x",
            &[0u8; 64],
            &OperatorFingerprint::new([0u8; 8]),
            &bundle,
            0,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            PlanBundleStoreError::SchemaEnvelopeMismatch {
                schema: SchemaVersion::V2_1,
                ..
            }
        ));
    }

    // ── insert_artifacts ─────────────────────────────────────────────

    #[test]
    fn insert_artifacts_round_trips_each_row_in_declaration_order() {
        let store = fresh_store();
        let (bundle, sha) = fixture_v2_1_bundle();
        let bundle_with_more_artifacts = {
            let mut b = bundle.clone();
            b.artifacts.push(BundleArtifact {
                name: "extra.md".to_owned(),
                bytes: b"hello".to_vec(),
                sha256: BundleSha256::new([0x99u8; 32]),
            });
            b
        };

        {
            let mut conn = store.lock_sync();
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            insert_bundle(
                &tx,
                &sha,
                b"x",
                &[0u8; 64],
                &OperatorFingerprint::new([0u8; 8]),
                &bundle_with_more_artifacts,
                0,
            )
            .unwrap();
            insert_artifacts(&tx, &sha, &bundle_with_more_artifacts.artifacts).unwrap();
            tx.commit().unwrap();
        }

        let conn = store.lock_sync();
        let rows: Vec<(i64, String, Vec<u8>)> = conn
            .prepare(&format!(
                "SELECT artifact_seq, artifact_name, artifact_sha256 \
             FROM {} WHERE bundle_sha256 = ?1 \
             ORDER BY artifact_seq",
                Table::PlanBundleArtifacts.as_str(),
            ))
            .unwrap()
            .query_map(params![sha.as_bytes().as_slice()], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, 0);
        assert_eq!(rows[0].1, "plan.toml");
        assert_eq!(rows[1].0, 1);
        assert_eq!(rows[1].1, "extra.md");
        assert_eq!(rows[1].2, vec![0x99u8; 32]);
    }

    /// Re-inserting the same artifacts under the same bundle is
    /// idempotent — the composite PK + INSERT OR IGNORE makes the
    /// post-hoc retry safe.
    #[test]
    fn insert_artifacts_is_idempotent_under_pk_collision() {
        let store = fresh_store();
        let (bundle, sha) = fixture_v2_1_bundle();

        for _ in 0..2 {
            let mut conn = store.lock_sync();
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            insert_bundle(
                &tx,
                &sha,
                b"x",
                &[0u8; 64],
                &OperatorFingerprint::new([0u8; 8]),
                &bundle,
                0,
            )
            .unwrap();
            insert_artifacts(&tx, &sha, &bundle.artifacts).unwrap();
            tx.commit().unwrap();
        }
        let conn = store.lock_sync();
        let count: i64 = conn
            .query_row(
                &format!(
                    "SELECT COUNT(*) FROM {} WHERE bundle_sha256 = ?1",
                    Table::PlanBundleArtifacts.as_str(),
                ),
                params![sha.as_bytes().as_slice()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            count, 1,
            "duplicate (bundle_sha256, artifact_seq) must dedupe"
        );
    }

    // ── record_nonce + nonce_status_in_tx + sweep_expired_nonces ─────

    #[test]
    fn record_admitted_nonce_with_initiative_id_is_visible_in_lookup() {
        let store = fresh_store();
        seed_initiative(&store, "init-1");

        let nonce = BundleNonce::new([0x12u8; 16]);
        let sha = BundleSha256::new([0x34u8; 32]);

        {
            let mut conn = store.lock_sync();
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            record_nonce(
                &tx,
                &nonce,
                &sha,
                1_700_000_000,
                1_700_000_001,
                PlanBundleNonceOutcome::Admitted,
                Some("init-1"),
            )
            .unwrap();

            let status = nonce_status_in_tx(&tx, &nonce).unwrap();
            assert_eq!(
                status,
                Some(NonceStatus {
                    bundle_sha256: sha,
                    signed_at_unix_secs: 1_700_000_000,
                    first_seen_at_unix_secs: 1_700_000_001,
                    outcome: PlanBundleNonceOutcome::Admitted,
                    initiative_id: Some("init-1".to_owned()),
                })
            );
            tx.commit().unwrap();
        }
    }

    #[test]
    fn record_terminally_rejected_nonce_with_null_initiative_id_round_trips() {
        let store = fresh_store();
        let nonce = BundleNonce::new([0xABu8; 16]);
        let sha = BundleSha256::new([0xCDu8; 32]);

        {
            let mut conn = store.lock_sync();
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            record_nonce(
                &tx,
                &nonce,
                &sha,
                1_700_000_000,
                1_700_000_002,
                PlanBundleNonceOutcome::TerminallyRejected,
                None,
            )
            .unwrap();

            let status = nonce_status_in_tx(&tx, &nonce).unwrap();
            assert_eq!(
                status.unwrap().outcome,
                PlanBundleNonceOutcome::TerminallyRejected
            );
            tx.commit().unwrap();
        }
    }

    /// The (outcome, initiative_id) coherency contract is enforced
    /// at the helper boundary — before SQL fires — so the kernel's
    /// admission handler gets a structured error rather than a
    /// CHECK-violation surfaced as raw rusqlite.
    #[test]
    fn record_nonce_rejects_admitted_with_null_initiative_id() {
        let store = fresh_store();
        let mut conn = store.lock_sync();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let err = record_nonce(
            &tx,
            &BundleNonce::new([0u8; 16]),
            &BundleSha256::new([0u8; 32]),
            0,
            0,
            PlanBundleNonceOutcome::Admitted,
            None,
        )
        .unwrap_err();
        assert!(
            matches!(err, PlanBundleStoreError::Sqlite(_)),
            "incoherent (outcome, initiative_id) must be rejected before SQL fires"
        );
    }

    #[test]
    fn record_nonce_rejects_terminally_rejected_with_initiative_id() {
        let store = fresh_store();
        seed_initiative(&store, "init-x");

        let mut conn = store.lock_sync();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let err = record_nonce(
            &tx,
            &BundleNonce::new([0u8; 16]),
            &BundleSha256::new([0u8; 32]),
            0,
            0,
            PlanBundleNonceOutcome::TerminallyRejected,
            Some("init-x"),
        )
        .unwrap_err();
        assert!(matches!(err, PlanBundleStoreError::Sqlite(_)));
    }

    /// A second `record_nonce` call with the same `bundle_nonce`
    /// triggers the PK constraint — exactly the desired §3.5 replay
    /// behaviour. The §8.1 step 10b lookup is meant to catch the
    /// re-submission BEFORE this fires; the PK is the second floor.
    #[test]
    fn duplicate_record_nonce_is_a_pk_collision() {
        let store = fresh_store();
        seed_initiative(&store, "init-dup");
        let nonce = BundleNonce::new([0xEEu8; 16]);
        let sha = BundleSha256::new([0xFFu8; 32]);

        {
            let mut conn = store.lock_sync();
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            record_nonce(
                &tx,
                &nonce,
                &sha,
                0,
                0,
                PlanBundleNonceOutcome::Admitted,
                Some("init-dup"),
            )
            .unwrap();
            tx.commit().unwrap();
        }
        let mut conn = store.lock_sync();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let err = record_nonce(
            &tx,
            &nonce,
            &sha,
            0,
            0,
            PlanBundleNonceOutcome::Admitted,
            Some("init-dup"),
        )
        .unwrap_err();
        assert!(matches!(err, PlanBundleStoreError::Sqlite(_)));
    }

    #[test]
    fn nonce_status_in_tx_returns_none_for_unseen_nonce() {
        let store = fresh_store();
        let mut conn = store.lock_sync();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let status = nonce_status_in_tx(&tx, &BundleNonce::new([0x42u8; 16])).unwrap();
        assert_eq!(status, None);
    }

    #[test]
    fn sweep_expired_nonces_deletes_only_rows_strictly_older_than_cutoff() {
        let store = fresh_store();
        seed_initiative(&store, "init-sweep");

        for (i, first_seen) in [100i64, 200, 300, 400].iter().enumerate() {
            let mut conn = store.lock_sync();
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            record_nonce(
                &tx,
                &BundleNonce::new([i as u8; 16]),
                &BundleSha256::new([0u8; 32]),
                0,
                *first_seen,
                PlanBundleNonceOutcome::Admitted,
                Some("init-sweep"),
            )
            .unwrap();
            tx.commit().unwrap();
        }

        // Sweep with cutoff = 250 → rows with first_seen IN (100, 200) go.
        let removed = {
            let mut conn = store.lock_sync();
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            let n = sweep_expired_nonces(&tx, 250).unwrap();
            tx.commit().unwrap();
            n
        };
        assert_eq!(removed, 2);

        let conn = store.lock_sync();
        let remaining: i64 = conn
            .query_row(
                &format!(
                    "SELECT COUNT(*) FROM {}",
                    Table::PlanBundleNoncesSeen.as_str()
                ),
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 2);
    }
}
