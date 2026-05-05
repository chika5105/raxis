//! Operator-certificate view-table reads + the `advance_epoch`-time
//! writer that rebuilds the table from the freshly-loaded
//! `PolicyBundle`.
//!
//! Normative reference (forthcoming): kernel-store.md §2.5.7
//! "Operator Certificates" (added in step 12).
//!
//! # Module shape
//!
//! Unlike the other `views/` modules (which are read-only and take
//! `&RoConn`), this one ALSO exposes a writer: [`repopulate`] called
//! by `policy_manager::advance_epoch` inside the same write
//! transaction that updates `policy_epoch_history`. We keep the
//! writer here rather than in a separate `writers/` module because:
//!
//!   - The schema for `operator_certificates` lives in
//!     `migration::render_migration_2_ddl`; both the read and the
//!     write code reference the same column shape and putting them
//!     side by side keeps drift loud.
//!   - The repopulation logic IS the cert table — there's no other
//!     code path that writes to it, so colocating the writer with
//!     the readers means a future column addition only has to touch
//!     two functions in one file.
//!
//! # Atomicity contract
//!
//! `repopulate` MUST run inside a `BEGIN EXCLUSIVE` transaction
//! opened by the caller (`advance_epoch`). The combination of:
//!
//! 1. INSERT into `policy_epoch_history` (new row, MAX(epoch_id) bump)
//! 2. DELETE FROM `operator_certificates` (clear stale view)
//! 3. INSERT INTO `operator_certificates` (one per cert-bound entry)
//!
//! all commit-or-rollback atomically. A power-loss between (1) and
//! (3) leaves the kernel running with stale certs at boot — the
//! transaction boundary closes that window.
//!
//! Cert is mandatory (INV-CERT-01); every `OperatorEntry` carries a
//! fully self-signed `OperatorCert` and produces exactly one row in
//! this table per epoch. There is no cert-less / "legacy" path — the
//! kernel boot fails closed on an empty table (see `raxis doctor`'s
//! cert-empty check), and policy.toml is rejected at deserialise
//! time when the `[operators.entries.cert]` sub-table is missing.

use rusqlite::{params, Connection};
use thiserror::Error;

use raxis_policy::PolicyBundle;
use raxis_types::operator_cert::{CertKind, OperatorCert};

use crate::ro::RoConn;
use crate::Table;

// ---------------------------------------------------------------------------
// OperatorCertRow — one denormalised row.
// ---------------------------------------------------------------------------

/// Typed read-side row of `operator_certificates`. Mirrors the
/// migration-2 column shape exactly. Returned by [`get_by_fingerprint`]
/// and [`list_all`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorCertRow {
    pub pubkey_fingerprint:      String,
    pub epoch_id:                u64,
    pub kind:                    CertKind,
    pub display_name:            String,
    pub pubkey_hex:              String,
    pub not_before:              i64,
    pub not_after:               i64,
    pub warn_before_expiry_days: u32,
    pub grace_period_days:       u32,
    /// Decoded back from `permitted_ops_json`. Empty list is preserved
    /// verbatim (it would be a structural validation error in the
    /// policy bundle but we don't second-guess what's in the DB).
    pub permitted_ops:           Vec<String>,
    pub contact_info:            Option<String>,
    pub self_sig_hex:            String,
    pub force_misconfig_bypass:  bool,
    pub installed_at:            i64,
}

impl OperatorCertRow {
    /// Reconstruct an [`OperatorCert`] from a row. The reconstructed
    /// cert is byte-identical to what was originally embedded in
    /// `policy.toml`, so it round-trips through
    /// `raxis_crypto::cert::verify_cert_self_signature`.
    pub fn into_operator_cert(self) -> OperatorCert {
        OperatorCert {
            kind:                    self.kind,
            display_name:            self.display_name,
            pubkey_hex:              self.pubkey_hex,
            not_before:              self.not_before,
            not_after:               self.not_after,
            warn_before_expiry_days: self.warn_before_expiry_days,
            grace_period_days:       self.grace_period_days,
            permitted_ops:           self.permitted_ops,
            contact_info:            self.contact_info,
            self_sig_hex:            self.self_sig_hex,
        }
    }
}

#[derive(Debug, Error)]
pub enum OperatorCertViewError {
    #[error("sqlite error during operator_certificates view operation: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("operator_certificates row {fingerprint:?} has malformed permitted_ops_json: {parse_error}")]
    MalformedPermittedOps { fingerprint: String, parse_error: String },

    #[error("operator_certificates row {fingerprint:?} has unknown kind {kind:?}")]
    UnknownKind { fingerprint: String, kind: String },
}

// ---------------------------------------------------------------------------
// Writer: repopulate the view table from a freshly-loaded PolicyBundle.
// ---------------------------------------------------------------------------

/// Rebuild `operator_certificates` from the cert-bound entries of
/// `bundle`, scoping every row to `epoch_id`.
///
/// MUST be called inside the SAME write transaction that just inserted
/// the matching `policy_epoch_history` row. The caller (`advance_epoch`)
/// owns the `BEGIN EXCLUSIVE ... COMMIT` boundary.
///
/// **Behaviour:**
///   - Truncates the table (`DELETE FROM operator_certificates`); the
///     view is rebuilt-from-scratch on every epoch advance.
///   - For every operator entry, inserts one row scoped to `epoch_id`
///     and `installed_at_unix_secs`. Cert is mandatory (INV-CERT-01)
///     so there is no skip-cert-less branch.
///
/// Returns the number of rows inserted, so the caller can include
/// it in the `PolicyEpochAdvanced` audit metadata.
pub fn repopulate(
    conn:                    &Connection,
    bundle:                  &PolicyBundle,
    epoch_id:                u64,
    installed_at_unix_secs:  i64,
) -> Result<usize, OperatorCertViewError> {
    let table = Table::OperatorCertificates.as_str();

    // Step 1 — truncate. We rebuild the view from scratch on every
    // advance; there's no incremental-diff because the source of
    // truth (the policy bundle) is itself rebuilt from a freshly
    // parsed `policy.toml`.
    conn.execute(
        &format!("DELETE FROM {table}"),
        [],
    )?;

    // Step 2 — insert one row per cert-bound entry.
    let mut stmt = conn.prepare(&format!(
        "INSERT INTO {table} (\
            pubkey_fingerprint, epoch_id, kind, display_name, pubkey_hex, \
            not_before, not_after, warn_before_expiry_days, grace_period_days, \
            permitted_ops_json, contact_info, self_sig_hex, \
            force_misconfig_bypass, installed_at\
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)"
    ))?;

    let mut inserted = 0usize;
    for entry in bundle.operators() {
        let cert = &entry.cert;
        let permitted_ops_json = serde_json::to_string(&cert.permitted_ops)
            // `permitted_ops` is `Vec<String>` — serde_json cannot fail
            // on this shape; we still propagate to avoid panic.
            .map_err(|e| OperatorCertViewError::MalformedPermittedOps {
                fingerprint:  entry.pubkey_fingerprint.clone(),
                parse_error:  e.to_string(),
            })?;
        stmt.execute(params![
            entry.pubkey_fingerprint,
            epoch_id as i64,
            cert.kind.as_str(),
            cert.display_name,
            cert.pubkey_hex,
            cert.not_before,
            cert.not_after,
            cert.warn_before_expiry_days as i64,
            cert.grace_period_days as i64,
            permitted_ops_json,
            cert.contact_info,
            cert.self_sig_hex,
            entry.force_misconfig_bypass as i64,
            installed_at_unix_secs,
        ])?;
        inserted += 1;
    }

    Ok(inserted)
}

// ---------------------------------------------------------------------------
// Readers
// ---------------------------------------------------------------------------

/// Same column projection used by every reader in this module. Kept
/// in one constant so a future column addition only needs to touch
/// `render_migration_2_ddl` and this string.
const SELECT_ALL_COLS: &str =
    "pubkey_fingerprint, epoch_id, kind, display_name, pubkey_hex, \
     not_before, not_after, warn_before_expiry_days, grace_period_days, \
     permitted_ops_json, contact_info, self_sig_hex, \
     force_misconfig_bypass, installed_at";

/// Drain a `MappedRows` whose closure is [`row_to_operator_cert_row`]
/// — flattens the nested `rusqlite::Result<Result<_, ViewError>>`
/// into a single `Result<Vec<_>, ViewError>`. The two error variants
/// can't be unified with `and_then` because they are different types,
/// hence this manual loop.
fn collect_rows<I>(rows: I) -> Result<Vec<OperatorCertRow>, OperatorCertViewError>
where
    I: Iterator<Item = rusqlite::Result<Result<OperatorCertRow, OperatorCertViewError>>>,
{
    let mut out = Vec::new();
    for row in rows {
        match row {
            Ok(Ok(r))  => out.push(r),
            Ok(Err(e)) => return Err(e),
            Err(e)     => return Err(e.into()),
        }
    }
    Ok(out)
}

/// Look up an operator cert by `pubkey_fingerprint`. Returns `None`
/// when the operator is on the legacy flow (no cert installed) OR
/// when the fingerprint is unknown — the caller distinguishes the
/// two cases via the policy bundle's `operator_entry`.
pub fn get_by_fingerprint(
    conn:                &RoConn,
    pubkey_fingerprint:  &str,
) -> Result<Option<OperatorCertRow>, OperatorCertViewError> {
    let table = Table::OperatorCertificates.as_str();
    let mut stmt = conn.prepare(&format!(
        "SELECT {SELECT_ALL_COLS} FROM {table} \
         WHERE pubkey_fingerprint = ?1 LIMIT 1"
    ))?;
    let mapped = stmt.query_map(params![pubkey_fingerprint], row_to_operator_cert_row)?;
    let rows = collect_rows(mapped)?;
    Ok(rows.into_iter().next())
}

/// Enumerate every cert in the table, ordered by display_name for
/// deterministic CLI output (`raxis cert list` consumes this).
pub fn list_all(conn: &RoConn) -> Result<Vec<OperatorCertRow>, OperatorCertViewError> {
    let table = Table::OperatorCertificates.as_str();
    let mut stmt = conn.prepare(&format!(
        "SELECT {SELECT_ALL_COLS} FROM {table} ORDER BY display_name ASC"
    ))?;
    let mapped = stmt.query_map([], row_to_operator_cert_row)?;
    collect_rows(mapped)
}

/// Enumerate certs whose Standard `not_after` is at or before
/// `now_unix_secs`. Used by `raxis doctor` and the `cert_check`
/// expiry sweep. EmergencyRecovery certs are excluded by the
/// partial index (they have not_after = 0 sentinel and ignore
/// expiry).
pub fn list_expiring_or_expired(
    conn:           &RoConn,
    now_unix_secs:  i64,
) -> Result<Vec<OperatorCertRow>, OperatorCertViewError> {
    let table = Table::OperatorCertificates.as_str();
    let mut stmt = conn.prepare(&format!(
        "SELECT {SELECT_ALL_COLS} FROM {table} \
         WHERE kind = 'Standard' AND not_after <= ?1 \
         ORDER BY not_after ASC"
    ))?;
    let mapped = stmt.query_map(params![now_unix_secs], row_to_operator_cert_row)?;
    collect_rows(mapped)
}

/// Enumerate every EmergencyRecovery cert. Used by `raxis doctor`
/// for the "break-glass keys are present" check.
pub fn list_emergency(
    conn: &RoConn,
) -> Result<Vec<OperatorCertRow>, OperatorCertViewError> {
    let table = Table::OperatorCertificates.as_str();
    let mut stmt = conn.prepare(&format!(
        "SELECT {SELECT_ALL_COLS} FROM {table} \
         WHERE kind = 'EmergencyRecovery' \
         ORDER BY display_name ASC"
    ))?;
    let mapped = stmt.query_map([], row_to_operator_cert_row)?;
    collect_rows(mapped)
}

// ---------------------------------------------------------------------------
// Row decoder
// ---------------------------------------------------------------------------

/// Decode one row of `operator_certificates`. Returns
/// `Result<Result<OperatorCertRow, OperatorCertViewError>, rusqlite::Error>`
/// so the iterator pattern can distinguish row-fetch errors from
/// row-decode errors.
fn row_to_operator_cert_row(
    r: &rusqlite::Row<'_>,
) -> rusqlite::Result<Result<OperatorCertRow, OperatorCertViewError>> {
    let fingerprint:        String        = r.get(0)?;
    let epoch_id_i:         i64           = r.get(1)?;
    let kind_s:             String        = r.get(2)?;
    let display_name:       String        = r.get(3)?;
    let pubkey_hex:         String        = r.get(4)?;
    let not_before:         i64           = r.get(5)?;
    let not_after:          i64           = r.get(6)?;
    let warn_days_i:        i64           = r.get(7)?;
    let grace_days_i:       i64           = r.get(8)?;
    let permitted_ops_json: String        = r.get(9)?;
    let contact_info:       Option<String> = r.get(10)?;
    let self_sig_hex:       String        = r.get(11)?;
    let force_bypass_i:     i64           = r.get(12)?;
    let installed_at:       i64           = r.get(13)?;

    let kind = match CertKind::parse(&kind_s) {
        Some(k) => k,
        None => return Ok(Err(OperatorCertViewError::UnknownKind {
            fingerprint: fingerprint.clone(),
            kind:        kind_s,
        })),
    };
    let permitted_ops: Vec<String> = match serde_json::from_str(&permitted_ops_json) {
        Ok(v) => v,
        Err(e) => return Ok(Err(OperatorCertViewError::MalformedPermittedOps {
            fingerprint:  fingerprint.clone(),
            parse_error:  e.to_string(),
        })),
    };

    Ok(Ok(OperatorCertRow {
        pubkey_fingerprint:      fingerprint,
        epoch_id:                epoch_id_i.max(0) as u64,
        kind,
        display_name,
        pubkey_hex,
        not_before,
        not_after,
        warn_before_expiry_days: warn_days_i.max(0) as u32,
        grace_period_days:       grace_days_i.max(0) as u32,
        permitted_ops,
        contact_info,
        self_sig_hex,
        force_misconfig_bypass:  force_bypass_i != 0,
        installed_at,
    }))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ro::open as open_ro, Store};
    use ed25519_dalek::SigningKey;
    use raxis_crypto::cert::sign_cert;
    use raxis_policy::OperatorEntry;
    use sha2::{Digest, Sha256};
    use tempfile::TempDir;
    // `PolicyBundle` and `OperatorCert` come through `super::*`.

    const TEST_SEED: [u8; 32] = [0x42u8; 32];

    fn signing_key() -> SigningKey { SigningKey::from_bytes(&TEST_SEED) }
    fn pk_hex() -> String { hex::encode(signing_key().verifying_key().to_bytes()) }
    fn fp() -> String {
        let raw = hex::decode(pk_hex()).unwrap();
        let mut h = Sha256::new();
        h.update(&raw);
        hex::encode(&h.finalize()[..16])
    }

    fn signed_standard(perms: Vec<&str>) -> OperatorCert {
        let mut c = OperatorCert {
            kind:                    CertKind::Standard,
            display_name:            "Chika".to_owned(),
            pubkey_hex:              pk_hex(),
            not_before:              1_700_000_000,
            not_after:               1_731_536_000,
            warn_before_expiry_days: 30,
            grace_period_days:       7,
            permitted_ops:           perms.into_iter().map(str::to_owned).collect(),
            contact_info:            Some("chika@example.com".to_owned()),
            self_sig_hex:            String::new(),
        };
        c.self_sig_hex = sign_cert(&c, &signing_key());
        c
    }

    fn signed_emergency() -> OperatorCert {
        let mut c = OperatorCert {
            kind:                    CertKind::EmergencyRecovery,
            display_name:            "break-glass".to_owned(),
            pubkey_hex:              pk_hex(),
            not_before:              0,
            not_after:               0,
            warn_before_expiry_days: 0,
            grace_period_days:       0,
            permitted_ops:           vec!["RotateEpoch".to_owned()],
            contact_info:            None,
            self_sig_hex:            String::new(),
        };
        c.self_sig_hex = sign_cert(&c, &signing_key());
        c
    }

    fn entry(cert: OperatorCert, force_bypass: bool) -> OperatorEntry {
        OperatorEntry {
            pubkey_fingerprint: fp(),
            display_name:       "Chika".to_owned(),
            pubkey_hex:         pk_hex(),
            permitted_ops:      vec!["CreateInitiative".to_owned()],
            cert,
            force_misconfig_bypass: force_bypass,
        }
    }

    fn bundle_with_entries(entries: Vec<OperatorEntry>) -> PolicyBundle {
        PolicyBundle::for_tests_with_operators(entries)
    }

    fn fresh_store_with_seed_epoch() -> TempDir {
        const POLICY_EPOCH_HISTORY: &str = Table::PolicyEpochHistory.as_str();
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("kernel.db");
        let store = Store::open(&db).unwrap();
        let guard = store.lock_sync();
        // Seed a policy_epoch_history row so the FK constraint passes.
        guard.execute(
            &format!(
                "INSERT INTO {POLICY_EPOCH_HISTORY} \
                 (epoch_id, policy_sha256, signed_by_authority, \
                  triggered_by_operator, advanced_at) \
                 VALUES (1, 'sha-1', 'auth-fp', 'op-fp', 100)"
            ),
            [],
        ).unwrap();
        tmp
    }

    // ── Repopulate happy path ───────────────────────────────────────

    #[test]
    fn repopulate_inserts_one_row_per_entry() {
        let tmp = fresh_store_with_seed_epoch();
        let store = Store::open(&tmp.path().join("kernel.db")).unwrap();
        let bundle = bundle_with_entries(vec![entry(signed_standard(vec!["AbortTask"]), false)]);

        let n = {
            let guard = store.lock_sync();
            repopulate(&guard, &bundle, 1, 1_700_000_500).unwrap()
        };
        assert_eq!(n, 1);

        let conn = open_ro(tmp.path()).unwrap();
        let row = get_by_fingerprint(&conn, &fp()).unwrap().expect("row exists");
        assert_eq!(row.kind, CertKind::Standard);
        assert_eq!(row.display_name, "Chika");
        assert_eq!(row.permitted_ops, vec!["AbortTask".to_owned()]);
        assert_eq!(row.epoch_id, 1);
        assert_eq!(row.installed_at, 1_700_000_500);
        assert!(!row.force_misconfig_bypass);
        assert_eq!(row.contact_info.as_deref(), Some("chika@example.com"));
    }

    #[test]
    fn repopulate_truncates_before_inserting_so_stale_rows_disappear() {
        let tmp = fresh_store_with_seed_epoch();
        let store = Store::open(&tmp.path().join("kernel.db")).unwrap();

        // First epoch: one cert.
        {
            let guard = store.lock_sync();
            let bundle = bundle_with_entries(vec![entry(signed_standard(vec!["A"]), false)]);
            repopulate(&guard, &bundle, 1, 0).unwrap();
        }
        // Second epoch: empty bundle (operator removed the entry — e.g.
        // ahead of `epoch advance` after deleting the operator block).
        {
            let guard = store.lock_sync();
            let bundle = bundle_with_entries(vec![]);
            repopulate(&guard, &bundle, 1, 0).unwrap();
        }

        let conn = open_ro(tmp.path()).unwrap();
        assert!(list_all(&conn).unwrap().is_empty(),
            "after second repopulate the stale row from epoch-1 is gone");
    }

    #[test]
    fn repopulate_with_force_bypass_records_the_flag() {
        let tmp = fresh_store_with_seed_epoch();
        let store = Store::open(&tmp.path().join("kernel.db")).unwrap();
        let bundle = bundle_with_entries(vec![
            entry(signed_emergency(), true),
        ]);
        {
            let guard = store.lock_sync();
            repopulate(&guard, &bundle, 1, 0).unwrap();
        }
        let conn = open_ro(tmp.path()).unwrap();
        let row = get_by_fingerprint(&conn, &fp()).unwrap().unwrap();
        assert!(row.force_misconfig_bypass,
            "force_misconfig_bypass=true on entry must persist into the table");
    }

    // ── Round-trip through into_operator_cert ──────────────────────

    /// The reconstructed cert MUST self-verify. This pins that the
    /// round-trip loses no signed bytes — if a future column shape
    /// change drops a field, the signature breaks here.
    #[test]
    fn row_round_trips_through_into_operator_cert_and_self_verifies() {
        use raxis_crypto::cert::verify_cert_self_signature;
        let tmp = fresh_store_with_seed_epoch();
        let store = Store::open(&tmp.path().join("kernel.db")).unwrap();
        let original = signed_standard(vec!["AbortTask", "ApprovePlan"]);
        let bundle = bundle_with_entries(vec![entry(original.clone(), false)]);

        {
            let guard = store.lock_sync();
            repopulate(&guard, &bundle, 1, 0).unwrap();
        }
        let conn = open_ro(tmp.path()).unwrap();
        let row = get_by_fingerprint(&conn, &fp()).unwrap().unwrap();
        let reconstructed = row.into_operator_cert();
        verify_cert_self_signature(&reconstructed)
            .expect("reconstructed cert must self-verify (round-trip preserves signed bytes)");
        // Same bytes too (round-trip is lossless).
        // Note: the in-memory PolicyBundle's `validate_operator_certs`
        // will overwrite `permitted_ops` for an entry with cert; here
        // we used `for_tests_with_operators` which bypasses validate
        // and preserves the original cert verbatim.
        assert_eq!(reconstructed.permitted_ops, original.permitted_ops);
    }

    // ── Read accessors ──────────────────────────────────────────────

    #[test]
    fn list_expiring_or_expired_excludes_emergency_certs() {
        let tmp = fresh_store_with_seed_epoch();
        let store = Store::open(&tmp.path().join("kernel.db")).unwrap();
        let bundle = bundle_with_entries(vec![
            entry(signed_emergency(), false),
        ]);
        {
            let guard = store.lock_sync();
            repopulate(&guard, &bundle, 1, 0).unwrap();
        }
        let conn = open_ro(tmp.path()).unwrap();
        // Far-future `now`: would expire any Standard cert; emergency
        // MUST be excluded by the partial index / WHERE clause.
        assert!(list_expiring_or_expired(&conn, 99_999_999_999).unwrap().is_empty(),
            "emergency cert must NOT show up in the Standard expiry sweep");
    }

    #[test]
    fn list_expiring_or_expired_returns_standard_cert_past_not_after() {
        let tmp = fresh_store_with_seed_epoch();
        let store = Store::open(&tmp.path().join("kernel.db")).unwrap();
        let bundle = bundle_with_entries(vec![
            entry(signed_standard(vec!["AbortTask"]), false),
        ]);
        {
            let guard = store.lock_sync();
            repopulate(&guard, &bundle, 1, 0).unwrap();
        }
        let conn = open_ro(tmp.path()).unwrap();
        // signed_standard's not_after = 1_731_536_000.
        // now > not_after ⇒ included.
        let rows = list_expiring_or_expired(&conn, 1_731_536_001).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, CertKind::Standard);

        // now < not_after ⇒ excluded.
        let rows = list_expiring_or_expired(&conn, 1_700_000_001).unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn list_emergency_returns_only_emergency_certs() {
        let tmp = fresh_store_with_seed_epoch();
        let store = Store::open(&tmp.path().join("kernel.db")).unwrap();
        let bundle = bundle_with_entries(vec![
            entry(signed_emergency(), false),
        ]);
        {
            let guard = store.lock_sync();
            repopulate(&guard, &bundle, 1, 0).unwrap();
        }
        let conn = open_ro(tmp.path()).unwrap();
        let rows = list_emergency(&conn).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, CertKind::EmergencyRecovery);
    }

    #[test]
    fn get_by_fingerprint_returns_none_for_unknown_fp() {
        let tmp = fresh_store_with_seed_epoch();
        let store = Store::open(&tmp.path().join("kernel.db")).unwrap();
        let bundle = bundle_with_entries(vec![entry(signed_standard(vec!["A"]), false)]);
        {
            let guard = store.lock_sync();
            repopulate(&guard, &bundle, 1, 0).unwrap();
        }
        let conn = open_ro(tmp.path()).unwrap();
        assert!(get_by_fingerprint(&conn, "no-such-fp").unwrap().is_none(),
            "an unknown fingerprint returns None");
    }
}
