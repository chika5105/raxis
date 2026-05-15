//! `plan_bundles` / `plan_bundle_artifacts` read view (V2 Plan
//! Bundle Sealing storage layout, `plan-bundle-sealing.md §8.2`).
//!
//! # Surface
//!
//! Three read functions, each tightly scoped to one §8.3 use case:
//!
//!   * [`header_by_sha256`] — return the non-byte fields of one
//!     `plan_bundles` row (schema_version, signed_by, sealed_at,
//!     freshness envelope). Sufficient for `raxis initiative show`
//!     to render "Bundle: 12ab… (V2.1, signed_by abcd…, sealed
//!     2026-04-…)" without hauling the bundle bytes onto the wire.
//!   * [`read_artifact`] — return the raw bytes of one artifact in
//!     a bundle, keyed by `(bundle_sha256, artifact_seq)`. This is
//!     the §8.3 "sole API for initiative-execution code to read
//!     plan-derived bytes" — the function the kernel's
//!     `approve_plan` re-verification, KSB rendering, and recovery
//!     replay all flow through.
//!   * [`list_artifact_names`] — return the (artifact_seq, name)
//!     pairs for one bundle. Inspection helper for `raxis
//!     initiative show --artifacts`. Bytes-free; safe to render.
//!
//! # Why this is a `views/` module despite returning bundle bytes
//!
//! Spec §8.3 mandates "every subsequent operation reads from
//! plan_bundles / plan_bundle_artifacts". The kernel's runtime
//! callers (KSB rendering, recovery, audit replay) all run on the
//! kernel's read+write `Store`, but they do NOT need a write
//! transaction for these reads — and an `RoConn`-typed accessor is
//! the right fit for the CLI's `inspect` surface in any case. We
//! therefore expose these here, taking `&RoConn`, and the kernel
//! re-uses them via the sibling `Store::lock_sync()` lock acquired
//! in read-mode (no separate connection needed).
//!
//! Future redaction: §8.5 mentions a `--bundle` extraction surface;
//! that lives in `raxis-cli`, not here.

use raxis_types::{BundleSha256, OperatorFingerprint, PlanBundleNonceOutcome, SchemaVersion};
use rusqlite::{params, OptionalExtension};
use thiserror::Error;

use crate::ro::RoConn;
use crate::Table;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum PlanBundleViewError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// A column in `plan_bundles` decoded to a malformed value
    /// (e.g. a `schema_version` of 3, or a `signed_by` that is not
    /// 8 bytes). The DDL CHECKs prevent this from arising in
    /// production; the variant exists so a corrupted row surfaces
    /// as a structured error rather than a panic.
    #[error("malformed {field}: {detail}")]
    MalformedColumn { field: &'static str, detail: String },
}

// ---------------------------------------------------------------------------
// Public row shapes
// ---------------------------------------------------------------------------

/// Non-byte projection of one `plan_bundles` row.
///
/// `bundle_bytes` and `signature` are deliberately omitted —
/// callers that need them go through [`read_artifact`] (the
/// `bundle_bytes` round-trip is a debug aid, not a runtime path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanBundleHeader {
    pub bundle_sha256: BundleSha256,
    pub schema_version: SchemaVersion,
    pub artifact_count: usize,
    pub bundle_bytes_len: usize,
    pub signed_by: OperatorFingerprint,
    pub sealed_at_unix_secs: i64,
    /// `Some` for V2.1, `None` for legacy V2.0 envelopes.
    pub signed_at_unix_secs: Option<i64>,
    /// `Some` for V2.1, `None` for legacy V2.0 envelopes.
    pub bundle_nonce: Option<[u8; 16]>,
}

/// One row of `plan_bundle_artifacts` projected to (seq, name).
/// Returned by [`list_artifact_names`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanBundleArtifactName {
    pub artifact_seq: usize,
    pub artifact_name: String,
}

/// One `plan_bundle_nonces_seen` row, projected from the read path.
/// The §8.1 step 10b transactional lookup uses
/// [`crate::plan_bundles::nonce_status_in_tx`]; this RO variant is
/// for the operator-facing `raxis log` / forensic surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonceRow {
    pub bundle_nonce: [u8; 16],
    pub bundle_sha256: BundleSha256,
    pub signed_at_unix_secs: i64,
    pub first_seen_at_unix_secs: i64,
    pub outcome: PlanBundleNonceOutcome,
    pub initiative_id: Option<String>,
}

// ---------------------------------------------------------------------------
// header_by_sha256
// ---------------------------------------------------------------------------

/// Fetch the non-byte projection of one `plan_bundles` row.
/// `None` for an unknown `bundle_sha256` (the operator passed a
/// stale or mistyped digest).
pub fn header_by_sha256(
    conn: &RoConn,
    bundle_sha256: &BundleSha256,
) -> Result<Option<PlanBundleHeader>, PlanBundleViewError> {
    let plan_bundles = Table::PlanBundles.as_str();
    let row = conn
        .query_row(
            &format!(
                "SELECT bundle_sha256, schema_version, artifact_count, \
                        bundle_bytes_len, signed_by, sealed_at_unix_secs, \
                        signed_at_unix_secs, bundle_nonce \
                 FROM {plan_bundles} WHERE bundle_sha256 = ?1"
            ),
            params![bundle_sha256.as_bytes().as_slice()],
            decode_header_row,
        )
        .optional()?;
    Ok(row.transpose()?)
}

fn decode_header_row(
    r: &rusqlite::Row<'_>,
) -> rusqlite::Result<Result<PlanBundleHeader, PlanBundleViewError>> {
    // The `Result<Result<...>>` pattern lets `query_row` keep its
    // rusqlite::Result wrapper while we surface a structured
    // PlanBundleViewError for any post-fetch decode failure (e.g.
    // a malformed schema_version on a corrupted row).
    let sha_blob: Vec<u8> = r.get(0)?;
    let schema_int: i64 = r.get(1)?;
    let artifact_count: i64 = r.get(2)?;
    let bundle_bytes_len: i64 = r.get(3)?;
    let signed_by_blob: Vec<u8> = r.get(4)?;
    let sealed_at: i64 = r.get(5)?;
    let signed_at: Option<i64> = r.get(6)?;
    let nonce_blob: Option<Vec<u8>> = r.get(7)?;

    let sha_arr: [u8; 32] = match sha_blob.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => {
            return Ok(Err(PlanBundleViewError::MalformedColumn {
                field: "bundle_sha256",
                detail: format!("expected 32 bytes, got {}", sha_blob.len()),
            }))
        }
    };
    let schema = match SchemaVersion::from_u16(schema_int as u16) {
        Some(s) => s,
        None => {
            return Ok(Err(PlanBundleViewError::MalformedColumn {
                field: "schema_version",
                detail: format!("unknown wire value {schema_int}"),
            }))
        }
    };
    let signed_by_arr: [u8; 8] = match signed_by_blob.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => {
            return Ok(Err(PlanBundleViewError::MalformedColumn {
                field: "signed_by",
                detail: format!("expected 8 bytes, got {}", signed_by_blob.len()),
            }))
        }
    };
    let nonce: Option<[u8; 16]> = match nonce_blob {
        None => None,
        Some(b) => match b.as_slice().try_into() {
            Ok(a) => Some(a),
            Err(_) => {
                return Ok(Err(PlanBundleViewError::MalformedColumn {
                    field: "bundle_nonce",
                    detail: format!("expected 16 bytes, got {}", b.len()),
                }))
            }
        },
    };

    Ok(Ok(PlanBundleHeader {
        bundle_sha256: BundleSha256::new(sha_arr),
        schema_version: schema,
        artifact_count: artifact_count as usize,
        bundle_bytes_len: bundle_bytes_len as usize,
        signed_by: OperatorFingerprint::new(signed_by_arr),
        sealed_at_unix_secs: sealed_at,
        signed_at_unix_secs: signed_at,
        bundle_nonce: nonce,
    }))
}

// ---------------------------------------------------------------------------
// read_artifact — §8.3 sole API for plan-derived bytes
// ---------------------------------------------------------------------------

/// Return the raw bytes of one artifact in a bundle.
///
/// `None` for either an unknown `bundle_sha256` or an out-of-range
/// `artifact_seq`. Callers that need the difference (i.e. to
/// distinguish "wrong bundle hash" from "wrong seq within a known
/// bundle") MUST first call [`header_by_sha256`].
///
/// This is the §8.3 sole API for plan-derived byte access. Any
/// kernel module that wants to render `plan.toml` or a host-path
/// artifact MUST call this function — not open files under the
/// plan root, not read `bundle_bytes` directly out of `plan_bundles`.
pub fn read_artifact(
    conn: &RoConn,
    bundle_sha256: &BundleSha256,
    artifact_seq: usize,
) -> Result<Option<Vec<u8>>, PlanBundleViewError> {
    let plan_bundle_artifacts = Table::PlanBundleArtifacts.as_str();
    let bytes = conn
        .query_row(
            &format!(
                "SELECT artifact_bytes FROM {plan_bundle_artifacts} \
                 WHERE bundle_sha256 = ?1 AND artifact_seq = ?2"
            ),
            params![bundle_sha256.as_bytes().as_slice(), artifact_seq as i64],
            |r| r.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// list_artifact_names
// ---------------------------------------------------------------------------

/// Return the (artifact_seq, name) projection for every artifact in
/// one bundle, ordered by `artifact_seq` ascending. Empty list for
/// an unknown bundle.
pub fn list_artifact_names(
    conn: &RoConn,
    bundle_sha256: &BundleSha256,
) -> Result<Vec<PlanBundleArtifactName>, PlanBundleViewError> {
    let plan_bundle_artifacts = Table::PlanBundleArtifacts.as_str();
    let mut stmt = conn.prepare(&format!(
        "SELECT artifact_seq, artifact_name FROM {plan_bundle_artifacts} \
             WHERE bundle_sha256 = ?1 \
             ORDER BY artifact_seq ASC"
    ))?;
    let rows = stmt.query_map(params![bundle_sha256.as_bytes().as_slice()], |r| {
        Ok(PlanBundleArtifactName {
            artifact_seq: r.get::<_, i64>(0)? as usize,
            artifact_name: r.get(1)?,
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// nonce_row_by_nonce — RO companion to `plan_bundles::nonce_status_in_tx`
// ---------------------------------------------------------------------------

/// Read-only lookup of one `plan_bundle_nonces_seen` row. Used by
/// the operator-facing `raxis log --filter` surface and forensic
/// post-mortems; the §8.1 transactional lookup MUST go through
/// [`crate::plan_bundles::nonce_status_in_tx`] so the read shares
/// the admission transaction's snapshot.
pub fn nonce_row_by_nonce(
    conn: &RoConn,
    bundle_nonce: &[u8; 16],
) -> Result<Option<NonceRow>, PlanBundleViewError> {
    let plan_bundle_nonces_seen = Table::PlanBundleNoncesSeen.as_str();
    let row = conn
        .query_row(
            &format!(
                "SELECT bundle_nonce, bundle_sha256, signed_at_unix_secs, \
                        first_seen_at_unix_secs, outcome, initiative_id \
                 FROM {plan_bundle_nonces_seen} WHERE bundle_nonce = ?1"
            ),
            params![bundle_nonce.as_slice()],
            |r| {
                let nonce_blob: Vec<u8> = r.get(0)?;
                let sha_blob: Vec<u8> = r.get(1)?;
                let signed_at: i64 = r.get(2)?;
                let first_seen: i64 = r.get(3)?;
                let outcome_str: String = r.get(4)?;
                let init_id: Option<String> = r.get(5)?;
                Ok((
                    nonce_blob,
                    sha_blob,
                    signed_at,
                    first_seen,
                    outcome_str,
                    init_id,
                ))
            },
        )
        .optional()?;

    let Some((n_blob, s_blob, signed_at, first_seen, outcome_str, init_id)) = row else {
        return Ok(None);
    };

    let n_arr: [u8; 16] =
        n_blob
            .as_slice()
            .try_into()
            .map_err(|_| PlanBundleViewError::MalformedColumn {
                field: "bundle_nonce",
                detail: format!("expected 16 bytes, got {}", n_blob.len()),
            })?;
    let s_arr: [u8; 32] =
        s_blob
            .as_slice()
            .try_into()
            .map_err(|_| PlanBundleViewError::MalformedColumn {
                field: "bundle_sha256",
                detail: format!("expected 32 bytes, got {}", s_blob.len()),
            })?;
    let outcome = PlanBundleNonceOutcome::from_sql_str(&outcome_str).ok_or_else(|| {
        PlanBundleViewError::MalformedColumn {
            field: "outcome",
            detail: format!("unknown sql string {outcome_str:?}"),
        }
    })?;

    Ok(Some(NonceRow {
        bundle_nonce: n_arr,
        bundle_sha256: BundleSha256::new(s_arr),
        signed_at_unix_secs: signed_at,
        first_seen_at_unix_secs: first_seen,
        outcome,
        initiative_id: init_id,
    }))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ro::open as open_ro, Store};
    use raxis_types::{
        BundleArtifact, BundleNonce, OperatorFingerprint, PlanBundle, PlanBundleNonceOutcome,
    };
    use tempfile::TempDir;

    /// Seed a temp DB with one initiative + one V2.1 bundle + two
    /// artifacts. Returns the temp dir (caller keeps it alive while
    /// it holds RoConn handles).
    fn fresh_seeded_store() -> (TempDir, BundleSha256) {
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("kernel.db");
        let store = Store::open(&db).unwrap();

        // Seed initiative for the FK target on the nonce row.
        {
            let conn = store.lock_sync();
            conn.execute(
                &format!(
                    "INSERT INTO {} \
                       (initiative_id, state, terminal_criteria_json, \
                        plan_artifact_sha256, created_at) \
                     VALUES ('init-1', 'Draft', '{{}}', 'deadbeef', 1700000000)",
                    Table::Initiatives.as_str(),
                ),
                [],
            )
            .unwrap();
        }

        let plan_bytes = b"[orchestrator]\n".to_vec();
        let plan_sha = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(&plan_bytes);
            BundleSha256::new(h.finalize().into())
        };
        let extra_bytes = b"hello".to_vec();
        let extra_sha = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(&extra_bytes);
            BundleSha256::new(h.finalize().into())
        };

        let bundle = PlanBundle::new_v2_1(
            100,
            200,
            BundleNonce::new([0xAAu8; 16]),
            "myplan".to_owned(),
            vec![
                BundleArtifact {
                    name: "plan.toml".into(),
                    bytes: plan_bytes,
                    sha256: plan_sha,
                },
                BundleArtifact {
                    name: "ref.md".into(),
                    bytes: extra_bytes,
                    sha256: extra_sha,
                },
            ],
        );
        let bundle_sha = BundleSha256::new([0x11u8; 32]);

        // Insert via the typed helpers from `crate::plan_bundles`.
        {
            let mut conn = store.lock_sync();
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .unwrap();
            crate::plan_bundles::insert_bundle(
                &tx,
                &bundle_sha,
                b"placeholder-canonical-bytes",
                &[0x77u8; 64],
                &OperatorFingerprint::new([0x88u8; 8]),
                &bundle,
                1_700_000_999,
            )
            .unwrap();
            crate::plan_bundles::insert_artifacts(&tx, &bundle_sha, &bundle.artifacts).unwrap();
            crate::plan_bundles::record_nonce(
                &tx,
                &BundleNonce::new([0xAAu8; 16]),
                &bundle_sha,
                200,
                1_700_000_999,
                PlanBundleNonceOutcome::Admitted,
                Some("init-1"),
            )
            .unwrap();
            tx.commit().unwrap();
        }

        (tmp, bundle_sha)
    }

    // ── header_by_sha256 ─────────────────────────────────────────────

    #[test]
    fn header_by_sha256_round_trips_v2_1_envelope_fields() {
        let (tmp, sha) = fresh_seeded_store();
        let conn = open_ro(tmp.path()).unwrap();
        let header = header_by_sha256(&conn, &sha)
            .unwrap()
            .expect("seeded bundle must be present");
        assert_eq!(header.bundle_sha256, sha);
        assert_eq!(header.schema_version, SchemaVersion::V2_1);
        assert_eq!(header.artifact_count, 2);
        assert_eq!(header.signed_by.as_bytes(), &[0x88u8; 8]);
        assert_eq!(header.sealed_at_unix_secs, 1_700_000_999);
        assert_eq!(header.signed_at_unix_secs, Some(200));
        assert_eq!(header.bundle_nonce, Some([0xAAu8; 16]));
    }

    #[test]
    fn header_by_sha256_returns_none_for_unknown_bundle() {
        let (tmp, _) = fresh_seeded_store();
        let conn = open_ro(tmp.path()).unwrap();
        let other = BundleSha256::new([0xFFu8; 32]);
        assert!(header_by_sha256(&conn, &other).unwrap().is_none());
    }

    // ── read_artifact ────────────────────────────────────────────────

    #[test]
    fn read_artifact_returns_byte_for_byte_payload_for_known_seq() {
        let (tmp, sha) = fresh_seeded_store();
        let conn = open_ro(tmp.path()).unwrap();
        let plan = read_artifact(&conn, &sha, 0).unwrap().unwrap();
        assert_eq!(plan, b"[orchestrator]\n");
        let extra = read_artifact(&conn, &sha, 1).unwrap().unwrap();
        assert_eq!(extra, b"hello");
    }

    #[test]
    fn read_artifact_returns_none_for_out_of_range_seq() {
        let (tmp, sha) = fresh_seeded_store();
        let conn = open_ro(tmp.path()).unwrap();
        assert!(read_artifact(&conn, &sha, 99).unwrap().is_none());
    }

    #[test]
    fn read_artifact_returns_none_for_unknown_bundle() {
        let (tmp, _) = fresh_seeded_store();
        let conn = open_ro(tmp.path()).unwrap();
        let other = BundleSha256::new([0xCCu8; 32]);
        assert!(read_artifact(&conn, &other, 0).unwrap().is_none());
    }

    // ── list_artifact_names ──────────────────────────────────────────

    #[test]
    fn list_artifact_names_orders_by_artifact_seq_ascending() {
        let (tmp, sha) = fresh_seeded_store();
        let conn = open_ro(tmp.path()).unwrap();
        let names = list_artifact_names(&conn, &sha).unwrap();
        assert_eq!(names.len(), 2);
        assert_eq!(
            names[0],
            PlanBundleArtifactName {
                artifact_seq: 0,
                artifact_name: "plan.toml".to_owned(),
            }
        );
        assert_eq!(
            names[1],
            PlanBundleArtifactName {
                artifact_seq: 1,
                artifact_name: "ref.md".to_owned(),
            }
        );
    }

    #[test]
    fn list_artifact_names_returns_empty_for_unknown_bundle() {
        let (tmp, _) = fresh_seeded_store();
        let conn = open_ro(tmp.path()).unwrap();
        let other = BundleSha256::new([0xCCu8; 32]);
        assert!(list_artifact_names(&conn, &other).unwrap().is_empty());
    }

    // ── nonce_row_by_nonce ───────────────────────────────────────────

    #[test]
    fn nonce_row_by_nonce_round_trips_an_admitted_row() {
        let (tmp, sha) = fresh_seeded_store();
        let conn = open_ro(tmp.path()).unwrap();
        let row = nonce_row_by_nonce(&conn, &[0xAAu8; 16])
            .unwrap()
            .expect("seeded nonce row");
        assert_eq!(row.bundle_nonce, [0xAAu8; 16]);
        assert_eq!(row.bundle_sha256, sha);
        assert_eq!(row.signed_at_unix_secs, 200);
        assert_eq!(row.first_seen_at_unix_secs, 1_700_000_999);
        assert_eq!(row.outcome, PlanBundleNonceOutcome::Admitted);
        assert_eq!(row.initiative_id.as_deref(), Some("init-1"));
    }

    #[test]
    fn nonce_row_by_nonce_returns_none_for_unknown_nonce() {
        let (tmp, _) = fresh_seeded_store();
        let conn = open_ro(tmp.path()).unwrap();
        assert!(nonce_row_by_nonce(&conn, &[0u8; 16]).unwrap().is_none());
    }
}
