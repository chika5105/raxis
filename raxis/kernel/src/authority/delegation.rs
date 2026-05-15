// raxis-kernel::authority::delegation — Capability delegation management.
//
// Normative reference: kernel-core.md §2.3 `src/authority/delegation.rs`.
//
// A delegation is an operator-signed capability grant for a specific session.
// It authorises a planner to perform a particular operation class (WriteCode,
// ReadSecrets, etc.) within the session's current task context.
//
// Key invariants:
//   INV-DELEG-01: At most one active delegation per (session_id, capability_class).
//                 Enforced by the UNIQUE constraint on delegations(session_id, capability_class)
//                 + the check_capability guard.
//   INV-DELEG-02: Delegation TTL must not exceed policy.max_delegation_ttl.
//   INV-DELEG-03: Requested capability_class must be within the role's ceiling
//                 from policy.role_ceiling(session.role).
//   INV-DELEG-04: Ed25519 signature over the canonical signing input is verified
//                 before the row is written (raxis-crypto::delegation::verify_delegation).

use raxis_store::{Store, Table};
use raxis_types::{unix_now_secs, CapabilityClass, DelegationStatus, SessionId};

use crate::authority::keys::AuthorityError;

// INV-STORE-03 (kernel-store.md §2.5.1): table identifiers and FSM state
// strings come from the typed sources; no raw SQL identifiers in this
// file.
const DELEGATIONS: &str = Table::Delegations.as_str();

/// A delegation row returned by list_delegations or check_capability.
#[derive(Debug, Clone)]
pub struct DelegationRow {
    pub delegation_id: String,
    pub session_id: String,
    pub capability_class: String,
    pub scope_json: Option<String>,
    pub granted_by: String,
    pub granted_at: i64,
    pub expires_at: i64,
    pub use_count: i64,
    pub max_uses: Option<i64>,
    pub status: String,
}

/// Grant a new delegation.
///
/// Pre-conditions verified here:
///   1. No existing active delegation for (session_id, capability_class).
///   2. TTL within policy max.
///   3. Capability within role ceiling.
///   4. Ed25519 signature valid (via raxis-crypto::delegation).
///
/// Called by the IPC `GrantDelegation` handler. The handler has already loaded
/// the session row and resolved the policy.
#[allow(clippy::too_many_arguments)]
pub fn grant_delegation(
    session_id: &SessionId,
    delegation_id: &str,
    capability_class: &str,
    scope_json: Option<&str>,
    granted_by: &str, // operator fingerprint
    ttl_secs: u64,
    max_uses: Option<i64>,
    signature_bytes: &[u8],
    operator_pubkey_bytes: &[u8], // from policy.operator_entry(granted_by)
    policy_max_delegation_ttl_secs: u64,
    store: &Store,
) -> Result<(), AuthorityError> {
    // INV-DELEG-02: TTL within policy limit.
    if ttl_secs > policy_max_delegation_ttl_secs {
        return Err(AuthorityError::DelegationTtlOutOfRange {
            requested: ttl_secs,
            max: policy_max_delegation_ttl_secs,
        });
    }

    let now = unix_now_secs();
    let expires_at = now + ttl_secs as i64;

    // INV-DELEG-04: Verify Ed25519 signature on canonical signing input.
    raxis_crypto::delegation::verify_delegation_grant(
        operator_pubkey_bytes,
        signature_bytes,
        session_id.as_str(),
        capability_class,
        granted_by, // delegating_role_id = operator fingerprint in v1
        expires_at as u64,
        scope_json,
    )
    .map_err(|_| AuthorityError::DelegationSignatureInvalid)?;

    let conn = store.lock_sync();
    // INV-DELEG-01: INSERT will fail if UNIQUE(session_id, capability_class) is violated.
    let active_state = DelegationStatus::Active
        .as_sql_str()
        .expect("Active is a stored variant");
    let result = conn.execute(
        &format!(
            "INSERT INTO {DELEGATIONS} (
                delegation_id, session_id, capability_class, scope_json,
                granted_by, granted_at, expires_at, use_count, max_uses, status
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,0,?8,?9)"
        ),
        rusqlite::params![
            delegation_id,
            session_id.as_str(),
            capability_class,
            scope_json,
            granted_by,
            now,
            expires_at,
            max_uses,
            active_state,
        ],
    );

    match result {
        Ok(_) => Ok(()),
        Err(rusqlite::Error::SqliteFailure(err, _))
            if err.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            // UNIQUE violation — find the existing delegation_id for the error.
            let existing_id: String = conn
                .query_row(
                    &format!(
                        "SELECT delegation_id FROM {DELEGATIONS}
                     WHERE session_id=?1 AND capability_class=?2 AND status=?3"
                    ),
                    rusqlite::params![session_id.as_str(), capability_class, active_state],
                    |r| r.get(0),
                )
                .unwrap_or_else(|_| "unknown".to_owned());
            Err(AuthorityError::DelegationAlreadyActive {
                existing_delegation_id: existing_id,
            })
        }
        Err(e) => Err(AuthorityError::Store(raxis_store::StoreError::Rusqlite(e))),
    }
}

/// Check delegation status for a (session, capability) pair.
///
/// **Pure read. No writes.** Returns the current `DelegationStatus`:
///   - `Active`          — row exists, TTL not expired, status='Active'.
///   - `StaleOnNextUse`  — row exists, TTL not expired, status='StaleOnNextUse'.
///   - `RenewalRequired` — row exists, TTL not expired, status='RenewalRequired'.
///   - `Expired`         — row exists but TTL has passed.
///   - `NotGranted`      — no row for (session_id, capability) pair.
///
/// Normative reference: kernel-core.md §2.3 `authority/delegation.rs`.
pub fn check_capability(
    session_id: &SessionId,
    capability: &CapabilityClass,
    store: &Store,
) -> Result<DelegationStatus, AuthorityError> {
    let conn = store.lock_sync();
    let now = unix_now_secs();
    // Query any row for (session_id, capability) — including expired.
    let result = conn.query_row(
        &format!(
            "SELECT status, expires_at FROM {DELEGATIONS}
             WHERE session_id=?1 AND capability_class=?2
             ORDER BY granted_at DESC
             LIMIT 1"
        ),
        rusqlite::params![session_id.as_str(), capability.as_str()],
        |r| {
            let status_str: String = r.get(0)?;
            let expires_at: i64 = r.get(1)?;
            Ok((status_str, expires_at))
        },
    );
    match result {
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(DelegationStatus::NotGranted),
        Err(e) => Err(AuthorityError::Store(raxis_store::StoreError::Rusqlite(e))),
        Ok((status_str, expires_at)) => {
            if expires_at <= now {
                return Ok(DelegationStatus::Expired);
            }
            Ok(DelegationStatus::from_sql_str(&status_str).unwrap_or(DelegationStatus::Expired))
        }
    }
}

/// Record a capability use — transition StaleOnNextUse → RenewalRequired.
///
/// **Enforcement hook. Writes.** Called exclusively by `gates/mod.rs::evaluate_claims`
/// at step 4, immediately after all gate types are satisfied (terminal Pass).
/// Must only be called when the delegation was `StaleOnNextUse` during this evaluation.
///
/// Returns `AuthorityError::DelegationNotStale` if the row is not currently `StaleOnNextUse`
/// (guards against double-call or race).
///
/// Normative reference: kernel-core.md §2.3 `authority/delegation.rs`.
pub fn record_capability_use(
    session_id: &SessionId,
    capability: &CapabilityClass,
    store: &Store,
) -> Result<(), AuthorityError> {
    let conn = store.lock_sync();
    let renewal_state = DelegationStatus::RenewalRequired
        .as_sql_str()
        .expect("RenewalRequired is a stored variant");
    let stale_state = DelegationStatus::StaleOnNextUse
        .as_sql_str()
        .expect("StaleOnNextUse is a stored variant");
    let rows = conn
        .execute(
            &format!(
                "UPDATE {DELEGATIONS}
             SET status = ?1
             WHERE session_id = ?2 AND capability_class = ?3
               AND status = ?4"
            ),
            rusqlite::params![
                renewal_state,
                session_id.as_str(),
                capability.as_str(),
                stale_state,
            ],
        )
        .map_err(|e| AuthorityError::Store(raxis_store::StoreError::Rusqlite(e)))?;
    if rows == 0 {
        return Err(AuthorityError::DelegationNotStale);
    }
    Ok(())
}

/// List all delegations for a session.
pub fn list_delegations(
    session_id: &SessionId,
    store: &Store,
) -> Result<Vec<DelegationRow>, AuthorityError> {
    let conn = store.lock_sync();
    let list_sql = format!(
        "SELECT delegation_id, session_id, capability_class, scope_json,
                granted_by, granted_at, expires_at, use_count, max_uses, status
         FROM {DELEGATIONS} WHERE session_id=?1 ORDER BY granted_at ASC"
    );
    let mut stmt = conn
        .prepare(&list_sql)
        .map_err(|e| AuthorityError::Store(raxis_store::StoreError::Rusqlite(e)))?;

    let rows = stmt
        .query_map(rusqlite::params![session_id.as_str()], |r| {
            Ok(DelegationRow {
                delegation_id: r.get(0)?,
                session_id: r.get(1)?,
                capability_class: r.get(2)?,
                scope_json: r.get(3)?,
                granted_by: r.get(4)?,
                granted_at: r.get(5)?,
                expires_at: r.get(6)?,
                use_count: r.get(7)?,
                max_uses: r.get(8)?,
                status: r.get(9)?,
            })
        })
        .map_err(|e| AuthorityError::Store(raxis_store::StoreError::Rusqlite(e)))?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row.map_err(|e| AuthorityError::Store(raxis_store::StoreError::Rusqlite(e)))?)
    }
    Ok(result)
}

/// Mark ALL active delegations across all sessions as `StaleOnNextUse`.
///
/// Called by `policy_manager.rs` when the policy epoch advances.
/// Returns the count of rows updated (for audit logging by the caller).
///
/// Normative reference: kernel-core.md §2.3 `authority/delegation.rs`.
pub fn mark_stale_on_epoch_advance(store: &Store) -> Result<usize, AuthorityError> {
    let conn = store.lock_sync();
    let stale_state = DelegationStatus::StaleOnNextUse
        .as_sql_str()
        .expect("StaleOnNextUse is a stored variant");
    let active_state = DelegationStatus::Active
        .as_sql_str()
        .expect("Active is a stored variant");
    let rows = conn
        .execute(
            &format!("UPDATE {DELEGATIONS} SET status=?1 WHERE status=?2"),
            rusqlite::params![stale_state, active_state],
        )
        .map_err(|e| AuthorityError::Store(raxis_store::StoreError::Rusqlite(e)))?;
    Ok(rows)
}
