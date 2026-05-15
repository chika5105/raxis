//! `signed_plan_artifacts` read view (kernel-store.md §2.5.1
//! Table 3, §2.5.3 plan-signing contract).
//!
//! # Surface
//!
//! Currently a single read function — [`header_by_initiative`] —
//! that returns the **non-secret header** of a sealed plan
//! artifact: the operator fingerprint that signed the plan and
//! the wall-clock when the row was stored. This is the join
//! `raxis initiative show <init_id>` needs to render
//! "signed_by: Chika (abc12345…)  signed_at: …" without ever
//! reading the BLOB plan_bytes column.
//!
//! # Why a header-only reader
//!
//! `signed_plan_artifacts.plan_bytes` is the canonical sealed copy
//! of the operator-signed `plan.toml`. The bytes themselves are
//! audit-grade material — leaking them through a CLI render
//! surface would violate the §5.4.2 path-redaction contract
//! (cli-readonly.md). A header-only read is safe because:
//!
//! - `signed_by_fingerprint` is the public-key fingerprint of an
//!   operator already enumerated in `policy.operators[]`;
//!   exposing it adds no information beyond `raxis cert list`.
//! - `stored_at` is a wall-clock timestamp; not secret.
//! - We deliberately **do not** expose `plan_sig` (the Ed25519
//!   detached signature). It is not secret either, but surfacing
//!   raw signature bytes through `inspect` invites confusion with
//!   the `plan_bytes` redaction contract — operators who need it
//!   read `signed_plan_artifacts` directly via `raxis-store-tools`
//!   in v2 (forensic surface), not the CLI.
//!
//! Future extensions (full reveal under a `--reveal-plan` flag
//! that emits a `PathReadAccessed`-style audit event, mirroring
//! `views::plan_fields::reveal_for_task`) are tracked under
//! cli-readonly.md §5.4.2.

use rusqlite::OptionalExtension;
use thiserror::Error;

use crate::ro::RoConn;
use crate::Table;

/// Non-secret header of one row in `signed_plan_artifacts`.
///
/// Returned by [`header_by_initiative`]. Field names mirror the
/// underlying DDL (kernel-store.md §2.5.1 Table 3 + the
/// `signed_by_fingerprint` column added in migration 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPlanArtifactHeader {
    /// The initiative this plan was sealed for. Equal to the
    /// query argument; included for callers that want a single
    /// owned struct for downstream rendering.
    pub initiative_id: String,
    /// Operator pubkey_fingerprint (32 hex chars, SHA-256[:16] of
    /// the operator's Ed25519 pubkey) that signed `plan.toml`.
    /// `None` for legacy rows inserted under migration 1/2 before
    /// the column was backfill-able. v1 callers MUST handle
    /// `None` by rendering "(legacy: pre-migration-3 row)" rather
    /// than crashing.
    pub signed_by_fingerprint: Option<String>,
    /// Wall-clock seconds (Unix epoch) when the kernel sealed this
    /// row into the store. NOT the moment the operator signed —
    /// for that, the plan signature TOML carries `signed_at` (see
    /// kernel-store.md §2.5.3 "plan.sig format").
    pub stored_at: i64,
}

#[derive(Debug, Error)]
pub enum SignedPlanArtifactViewError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

/// Look up the header (no `plan_bytes`, no `plan_sig`) for one
/// initiative. Returns `None` when no row exists — for example
/// `raxis initiative show` is run against an `init_id` that
/// was created but never had a plan submitted (effectively
/// impossible in v1 because `create_initiative` and the seal
/// share a transaction, but the function still tolerates the
/// missing case rather than panic).
pub fn header_by_initiative(
    conn: &RoConn,
    initiative_id: &str,
) -> Result<Option<SignedPlanArtifactHeader>, SignedPlanArtifactViewError> {
    let table = Table::SignedPlanArtifacts.as_str();
    let row = conn
        .query_row(
            &format!(
                "SELECT initiative_id, signed_by_fingerprint, stored_at \
                 FROM {table} WHERE initiative_id = ?1"
            ),
            rusqlite::params![initiative_id],
            |r| {
                Ok(SignedPlanArtifactHeader {
                    initiative_id: r.get(0)?,
                    signed_by_fingerprint: r.get(1)?,
                    stored_at: r.get(2)?,
                })
            },
        )
        .optional()?;
    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ro::open as open_ro, Store};
    use tempfile::TempDir;

    /// Seed one initiative + one signed_plan_artifacts row so the
    /// header reader has something to find. Keep the seed inline
    /// rather than fishing it out of the e2e helper crate so this
    /// test is hermetic — it only exercises the SELECT.
    fn fresh_store_with_seed() -> TempDir {
        const INITIATIVES: &str = Table::Initiatives.as_str();
        const SPA: &str = Table::SignedPlanArtifacts.as_str();
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("kernel.db");
        let store = Store::open(&db).unwrap();
        let guard = store.lock_sync();
        guard
            .execute(
                &format!(
                    "INSERT INTO {INITIATIVES} \
                     (initiative_id, state, terminal_criteria_json, plan_artifact_sha256, created_at) \
                     VALUES ('init-1', 'Executing', '{{}}', 'sha-1', 1)"
                ),
                [],
            )
            .unwrap();
        guard
            .execute(
                &format!(
                    "INSERT INTO {SPA} \
                     (initiative_id, plan_bytes, plan_sig, stored_at, signed_by_fingerprint) \
                     VALUES ('init-1', X'00', X'00', 1700000000, 'abcd1234abcd1234abcd1234abcd1234')"
                ),
                [],
            )
            .unwrap();
        // Second initiative WITHOUT a signed_by_fingerprint to
        // pin the legacy-row backward-compat path.
        guard
            .execute(
                &format!(
                    "INSERT INTO {INITIATIVES} \
                     (initiative_id, state, terminal_criteria_json, plan_artifact_sha256, created_at) \
                     VALUES ('init-legacy', 'Completed', '{{}}', 'sha-2', 2)"
                ),
                [],
            )
            .unwrap();
        guard
            .execute(
                &format!(
                    "INSERT INTO {SPA} \
                     (initiative_id, plan_bytes, plan_sig, stored_at, signed_by_fingerprint) \
                     VALUES ('init-legacy', X'00', X'00', 1700000001, NULL)"
                ),
                [],
            )
            .unwrap();
        tmp
    }

    #[test]
    fn header_by_initiative_returns_signed_by_and_stored_at() {
        let tmp = fresh_store_with_seed();
        let conn = open_ro(tmp.path()).unwrap();
        let h = header_by_initiative(&conn, "init-1")
            .unwrap()
            .expect("present");
        assert_eq!(h.initiative_id, "init-1");
        assert_eq!(
            h.signed_by_fingerprint.as_deref(),
            Some("abcd1234abcd1234abcd1234abcd1234"),
            "fingerprint MUST round-trip exactly — it is the join key downstream renderers use",
        );
        assert_eq!(h.stored_at, 1_700_000_000);
    }

    #[test]
    fn header_by_initiative_returns_none_for_unknown_initiative() {
        let tmp = fresh_store_with_seed();
        let conn = open_ro(tmp.path()).unwrap();
        let h = header_by_initiative(&conn, "init-does-not-exist").unwrap();
        assert!(
            h.is_none(),
            "missing row MUST return None, not error — the CLI's renderer turns None into '(no signed plan)' rather than a hard failure",
        );
    }

    /// The legacy-row path: a `signed_plan_artifacts` row inserted
    /// before migration 3 has `signed_by_fingerprint = NULL`.
    /// Pinned because operators upgrading from v0.x will have
    /// these rows and the renderer MUST tolerate them.
    #[test]
    fn header_by_initiative_returns_none_fingerprint_for_legacy_row() {
        let tmp = fresh_store_with_seed();
        let conn = open_ro(tmp.path()).unwrap();
        let h = header_by_initiative(&conn, "init-legacy")
            .unwrap()
            .expect("present");
        assert_eq!(h.initiative_id, "init-legacy");
        assert!(
            h.signed_by_fingerprint.is_none(),
            "legacy row's NULL fingerprint MUST surface as None, not as an empty string",
        );
        assert_eq!(h.stored_at, 1_700_000_001);
    }
}
