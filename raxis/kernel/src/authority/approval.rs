// raxis-kernel::authority::approval — Human-issued signed approval tokens.
//
// Normative reference: kernel-core.md §2.3 `src/authority/approval.rs`.
//
// Approval tokens are operator-signed credentials that authorise the kernel to
// take a specific action on behalf of the operator (e.g. approving an
// escalation). They are validated by checking the Ed25519 signature against
// the operator's public key from the policy artifact.
//
// Key design points:
//   - The operator's PRIVATE key is never held by the kernel. The operator
//     signs the approval token locally (via raxis-cli escalation approve) and
//     sends the signed token struct over the operator socket.
//   - The kernel looks up the operator's PUBLIC key via
//     ctx.policy.operator_entry(token.issued_by).
//   - Revocation is pre-signature: revoked tokens return Err immediately
//     without evaluating the signature or any other field.

use crate::authority::keys::AuthorityError;
use raxis_store::Store;
use raxis_types::unix_now_secs;

/// A signed approval token received from the operator.
/// All fields are validated before any policy decision.
#[derive(Debug, Clone)]
pub struct ApprovalToken {
    /// UUID v4 identifying this specific approval instance.
    pub approval_id: String,
    /// SHA-256[:16] fingerprint of the operator's public key.
    pub issued_by: String,
    /// Unix seconds when the token was signed.
    pub issued_at: i64,
    /// Seconds until expiry from `issued_at`.
    pub valid_for_secs: u64,
    /// Scope predicate — defines the dimensions of actions this token permits.
    pub scope: ApprovalScope,
    /// Maximum number of times this token can be used (None = unlimited in v1,
    /// but the spec recommends operators always set this).
    pub max_uses: Option<i64>,
    /// Ed25519 signature over the canonical byte representation of the token
    /// fields above.
    pub signature: Vec<u8>,
}

/// Scope predicate for an approval token.
/// An action is in-scope if it satisfies ALL dimensions.
#[derive(Debug, Clone)]
pub struct ApprovalScope {
    /// If set, the token is only valid for this specific escalation_id.
    pub escalation_id: Option<String>,
    /// If set, the token is only valid for this initiative_id.
    pub initiative_id: Option<String>,
    /// If set, the token is only valid for this task_id.
    pub task_id: Option<String>,
}

/// A proposed action — the thing the planner wants the kernel to do under
/// escalation authority. Compared against `ApprovalScope` by `check_scope`.
#[derive(Debug, Clone)]
pub struct ProposedAction {
    pub escalation_id: Option<String>,
    pub initiative_id: Option<String>,
    pub task_id: Option<String>,
}

/// Approval status returned by `validate_approval_token` on a valid token.
/// Returned as `Ok(ApprovalStatus)` — the caller branches on status for
/// admission decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalStatus {
    /// Token is valid and the proposed action is within scope.
    Valid,
    /// Token is valid but the proposed action is outside the scope predicate.
    ScopeExceeded,
    /// Token has expired.
    Expired,
    /// Token has reached its max_uses limit.
    Exhausted,
}

/// Validate an approval token against a proposed action.
///
/// 8-step check sequence per kernel-core.md §2.3 approval.rs:
///   Step 0: Revocation pre-check — if revoked, Err(ApprovalRevoked).
///   Step 1: Signature — if invalid, Err(SignatureInvalid).
///   Step 2: Expiry — Ok(Expired) if past.
///   Step 3: Max-uses — Ok(Exhausted) if use_count >= max_uses.
///   Step 4: Scope — Ok(ScopeExceeded) if action ∉ scope.
///   Steps 5–7: Reserved for v2 (additional predicate dimensions).
///   Result: Ok(Valid).
///
/// The operator public key is retrieved from `policy_bundle` via `issued_by`.
pub fn validate_approval_token(
    token: &ApprovalToken,
    action: &ProposedAction,
    policy_bundle: &raxis_policy::PolicyBundle,
    store: &Store,
) -> Result<ApprovalStatus, AuthorityError> {
    // Step 0: Revocation pre-check.
    if is_revoked(&token.approval_id, store)? {
        return Err(AuthorityError::ApprovalRevoked);
    }

    // Step 1: Signature verification.
    let operator_entry = policy_bundle
        .operator_entry(&token.issued_by)
        .ok_or_else(|| AuthorityError::SessionInvalid {
            reason: format!("operator fingerprint '{}' not in policy", token.issued_by),
        })?;
    let pubkey_bytes =
        hex::decode(&operator_entry.pubkey_hex).map_err(|_| AuthorityError::SignatureInvalid)?;

    let signing_input = approval_signing_input(token);
    raxis_crypto::verify::verify_ed25519(&pubkey_bytes, &signing_input, &token.signature)
        .map_err(|_| AuthorityError::SignatureInvalid)?;

    // Step 2: Expiry.
    let now = unix_now_secs();
    let expires_at = token.issued_at + token.valid_for_secs as i64;
    if now > expires_at {
        return Ok(ApprovalStatus::Expired);
    }

    // Step 3: Max-uses.
    if let Some(max_uses) = token.max_uses {
        let use_count = get_use_count(&token.approval_id, store)?;
        if use_count >= max_uses {
            return Ok(ApprovalStatus::Exhausted);
        }
    }

    // Step 4: Scope check.
    if !check_scope(&token.scope, action) {
        return Ok(ApprovalStatus::ScopeExceeded);
    }

    Ok(ApprovalStatus::Valid)
}

/// Returns `true` if `action ⊆ scope` — every non-None dimension of the scope
/// must match the corresponding field of the action.
pub fn check_scope(scope: &ApprovalScope, action: &ProposedAction) -> bool {
    if let Some(eid) = &scope.escalation_id {
        if action.escalation_id.as_deref() != Some(eid.as_str()) {
            return false;
        }
    }
    if let Some(iid) = &scope.initiative_id {
        if action.initiative_id.as_deref() != Some(iid.as_str()) {
            return false;
        }
    }
    if let Some(tid) = &scope.task_id {
        if action.task_id.as_deref() != Some(tid.as_str()) {
            return false;
        }
    }
    true
}

/// Add `approval_id` to the approval revocation set.
///
/// Subsequent `validate_approval_token` calls return `Err(ApprovalRevoked)`
/// at step 0 before any signature evaluation.
pub fn revoke_approval(
    approval_id: &str,
    revoked_by: &str,
    store: &Store,
) -> Result<(), AuthorityError> {
    let now = unix_now_secs();
    let conn = store.lock_sync();
    conn.execute(
        "INSERT OR IGNORE INTO approval_revocations
            (approval_id, revoked_by, revoked_at)
         VALUES (?1, ?2, ?3)",
        rusqlite::params![approval_id, revoked_by, now],
    )
    .map_err(|e| AuthorityError::Store(raxis_store::StoreError::Rusqlite(e)))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn is_revoked(approval_id: &str, store: &Store) -> Result<bool, AuthorityError> {
    let conn = store.lock_sync();
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM approval_revocations WHERE approval_id=?1",
            rusqlite::params![approval_id],
            |r| r.get(0),
        )
        .map_err(|e| AuthorityError::Store(raxis_store::StoreError::Rusqlite(e)))?;
    Ok(count > 0)
}

fn get_use_count(approval_id: &str, store: &Store) -> Result<i64, AuthorityError> {
    let conn = store.lock_sync();
    // Count how many times this approval token has been accepted in the actions table.
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM approval_uses WHERE approval_id=?1",
            rusqlite::params![approval_id],
            |r| r.get(0),
        )
        .unwrap_or(0);
    Ok(count)
}

/// Compute the canonical signing input for an approval token.
///
/// Format: `approval|<approval_id>|<issued_by>|<issued_at>|<valid_for_secs>|<scope_json>`
/// Matches what the CLI's `raxis-cli escalation approve` writes before signing.
fn approval_signing_input(token: &ApprovalToken) -> Vec<u8> {
    let scope_json = serde_json::json!({
        "escalation_id": token.scope.escalation_id,
        "initiative_id": token.scope.initiative_id,
        "task_id": token.scope.task_id,
    })
    .to_string();
    format!(
        "approval|{}|{}|{}|{}|{}",
        token.approval_id, token.issued_by, token.issued_at, token.valid_for_secs, scope_json,
    )
    .into_bytes()
}
