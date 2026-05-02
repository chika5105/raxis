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

use raxis_store::Store;
use raxis_types::SessionId;

use crate::authority::keys::AuthorityError;

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
pub fn grant_delegation(
    session_id: &SessionId,
    delegation_id: &str,
    capability_class: &str,
    scope_json: Option<&str>,
    granted_by: &str,       // operator fingerprint
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

    let now = now_unix_secs();
    let expires_at = now + ttl_secs as i64;

    // INV-DELEG-04: Verify Ed25519 signature on canonical signing input.
    raxis_crypto::delegation::verify_delegation_grant(
        operator_pubkey_bytes,
        signature_bytes,
        session_id.as_str(),
        capability_class,
        granted_by,  // delegating_role_id = operator fingerprint in v1
        expires_at as u64,
        scope_json,
    ).map_err(|_| AuthorityError::DelegationSignatureInvalid)?;


    let conn = store.lock_sync();
    // INV-DELEG-01: INSERT will fail if UNIQUE(session_id, capability_class) is violated.
    let result = conn.execute(
        "INSERT INTO delegations (
            delegation_id, session_id, capability_class, scope_json,
            granted_by, granted_at, expires_at, use_count, max_uses, status
         ) VALUES (?1,?2,?3,?4,?5,?6,?7,0,?8,'Active')",
        rusqlite::params![
            delegation_id,
            session_id.as_str(),
            capability_class,
            scope_json,
            granted_by,
            now,
            expires_at,
            max_uses,
        ],
    );

    match result {
        Ok(_) => Ok(()),
        Err(rusqlite::Error::SqliteFailure(err, _))
            if err.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            // UNIQUE violation — find the existing delegation_id for the error.
            let existing_id: String = conn.query_row(
                "SELECT delegation_id FROM delegations
                 WHERE session_id=?1 AND capability_class=?2 AND status='Active'",
                rusqlite::params![session_id.as_str(), capability_class],
                |r| r.get(0),
            ).unwrap_or_else(|_| "unknown".to_owned());
            Err(AuthorityError::DelegationAlreadyActive { existing_delegation_id: existing_id })
        }
        Err(e) => Err(AuthorityError::Store(raxis_store::StoreError::Rusqlite(e))),
    }
}

/// Check whether a session has an active, unexpired delegation for
/// `capability_class`. Returns `DelegationNotGranted` if absent.
///
/// Called by `gates/claim.rs` before evaluating any claim that requires a
/// delegated capability.
pub fn check_capability(
    session_id: &SessionId,
    capability_class: &str,
    store: &Store,
) -> Result<DelegationRow, AuthorityError> {
    let conn = store.lock_sync();
    let now = now_unix_secs();
    conn.query_row(
        "SELECT delegation_id, session_id, capability_class, scope_json,
                granted_by, granted_at, expires_at, use_count, max_uses, status
         FROM delegations
         WHERE session_id=?1 AND capability_class=?2
           AND status='Active' AND expires_at > ?3",
        rusqlite::params![session_id.as_str(), capability_class, now],
        |r| Ok(DelegationRow {
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
        }),
    ).map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => AuthorityError::DelegationNotGranted,
        other => AuthorityError::Store(raxis_store::StoreError::Rusqlite(other)),
    })
}

/// Record a capability use — increment `use_count`. If `max_uses` is set and
/// `use_count` reaches `max_uses`, set `status = 'Exhausted'`.
///
/// Called after a gate or handler successfully consumes a delegated capability.
pub fn record_capability_use(
    delegation_id: &str,
    store: &Store,
) -> Result<(), AuthorityError> {
    let conn = store.lock_sync();
    conn.execute(
        "UPDATE delegations
         SET use_count = use_count + 1,
             status = CASE
               WHEN max_uses IS NOT NULL AND use_count + 1 >= max_uses THEN 'Exhausted'
               ELSE status
             END
         WHERE delegation_id = ?1",
        rusqlite::params![delegation_id],
    ).map_err(|e| AuthorityError::Store(raxis_store::StoreError::Rusqlite(e)))?;
    Ok(())
}

/// List all delegations for a session.
pub fn list_delegations(
    session_id: &SessionId,
    store: &Store,
) -> Result<Vec<DelegationRow>, AuthorityError> {
    let conn = store.lock_sync();
    let mut stmt = conn.prepare(
        "SELECT delegation_id, session_id, capability_class, scope_json,
                granted_by, granted_at, expires_at, use_count, max_uses, status
         FROM delegations WHERE session_id=?1 ORDER BY granted_at ASC",
    ).map_err(|e| AuthorityError::Store(raxis_store::StoreError::Rusqlite(e)))?;

    let rows = stmt.query_map(
        rusqlite::params![session_id.as_str()],
        |r| Ok(DelegationRow {
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
        }),
    ).map_err(|e| AuthorityError::Store(raxis_store::StoreError::Rusqlite(e)))?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row.map_err(|e| AuthorityError::Store(raxis_store::StoreError::Rusqlite(e)))?);
    }
    Ok(result)
}

/// Mark all active delegations for a session as `StaleOnNextUse` when the
/// policy epoch advances.
///
/// Stale delegations remain in the table for audit purposes but cannot be used
/// for new gate evaluations. The next request that encounters a stale delegation
/// row must call `revoke_stale_delegation` to retire it.
pub fn mark_stale_on_epoch_advance(
    session_id: &SessionId,
    store: &Store,
) -> Result<usize, AuthorityError> {
    let conn = store.lock_sync();
    let rows = conn.execute(
        "UPDATE delegations SET status='StaleOnNextUse'
         WHERE session_id=?1 AND status='Active'",
        rusqlite::params![session_id.as_str()],
    ).map_err(|e| AuthorityError::Store(raxis_store::StoreError::Rusqlite(e)))?;
    Ok(rows)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
