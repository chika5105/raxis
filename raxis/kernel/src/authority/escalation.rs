// raxis-kernel::authority::escalation — Operator escalation review.
//
// Normative reference:
//   - kernel-store.md §2.5.5 "Escalation approval on the operator socket"
//   - kernel-core.md §2.3 `handle_approve_escalation` / `handle_deny_escalation`
//   - cli-ceremony.md §"Approve / deny escalation"
//
// Two state transitions on the `escalations` row:
//
//   ApproveEscalation : Pending → Approved
//     - verifies operator_sig over the canonical signing input;
//     - mints a fresh `approval_token_id` (UUIDv4), nonce (16 raw bytes
//       hex-encoded), and high-entropy raw token (32 raw bytes hex);
//     - inserts `approval_tokens` row (Table 9) with token_hash =
//       sha256(raw);
//     - flips `escalations.status` from Pending to Approved with
//       `resolved_at = now`.
//     - All in one SQL transaction so a partial write is impossible.
//
//   DenyEscalation : Pending → Denied
//     - flips `escalations.status` to Denied with `resolved_at = now`,
//       `resolution_notes = reason`. No approval artifact is written
//       (the audit event is the only durable record per §2.5.5).
//
// Both functions return only the FSM error variant + the data the
// dispatcher needs to build the operator response. Audit emission is
// the dispatcher's responsibility and MUST follow a successful return
// (kernel-store.md §2.5.2 SQLite-then-audit ordering).

use rusqlite::params;

use crate::authority::keys::AuthorityError;
use raxis_crypto::{token, verify};
use raxis_policy::PolicyBundle;
use raxis_store::{Store, Table};
use raxis_types::{operator_wire::ApprovalScopeWire, unix_now_secs, EscalationStatus};

// INV-STORE-03 (kernel-store.md §2.5.1): table names + state strings come
// from the typed sources; no raw SQL identifiers anywhere in this file.
const ESCALATIONS:     &str = Table::Escalations.as_str();
const APPROVAL_TOKENS: &str = Table::ApprovalTokens.as_str();

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors specific to the escalation review handlers. Each variant maps
/// to a stable `FAIL_*` operator-response code via `error_code()` so the
/// CLI can pattern-match on the wire and surface a useful message.
#[derive(Debug, thiserror::Error)]
pub enum EscalationError {
    #[error("escalation '{escalation_id}' not found")]
    NotFound { escalation_id: String },

    #[error(
        "escalation '{escalation_id}' is in status '{current_status}'; \
         only Pending escalations may be approved or denied"
    )]
    NotPending {
        escalation_id:  String,
        current_status: String,
    },

    #[error(
        "approval_scope is invalid: {reason} \
         (kernel-store.md §2.5.5 — approval_scope semantics)"
    )]
    InvalidScope { reason: String },

    #[error(
        "operator '{fingerprint}' has no entry in policy.operators \
         — cannot verify operator_sig"
    )]
    OperatorUnknown { fingerprint: String },

    #[error("operator '{fingerprint}' has malformed pubkey_hex in policy: {reason}")]
    OperatorPubkeyMalformed { fingerprint: String, reason: String },

    #[error(
        "operator_sig is not a valid Ed25519 signature over the canonical \
         (escalation_id || approval_scope) signing input"
    )]
    SignatureInvalid,

    #[error(transparent)]
    Authority(#[from] AuthorityError),

    #[error(transparent)]
    Store(#[from] raxis_store::StoreError),

    #[error(transparent)]
    Sql(#[from] rusqlite::Error),

    #[error(transparent)]
    Crypto(#[from] raxis_crypto::CryptoError),
}

impl EscalationError {
    /// Stable wire `code` string for the operator `Error` envelope.
    /// CLI keys off this exact value — do not reuse strings across
    /// distinct error semantics.
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::NotFound                    { .. } => "FAIL_ESCALATION_NOT_FOUND",
            Self::NotPending                  { .. } => "FAIL_ESCALATION_NOT_PENDING",
            Self::InvalidScope                { .. } => "FAIL_APPROVAL_SCOPE_INVALID",
            Self::OperatorUnknown             { .. } => "FAIL_OPERATOR_UNKNOWN",
            Self::OperatorPubkeyMalformed     { .. } => "FAIL_POLICY_OPERATOR_PUBKEY_INVALID",
            Self::SignatureInvalid                   => "FAIL_OPERATOR_SIGNATURE_INVALID",
            Self::Authority(_)                       => "FAIL_APPROVE_ESCALATION",
            Self::Store(_) | Self::Sql(_)            => "FAIL_STORE",
            Self::Crypto(_)                          => "FAIL_CRYPTO",
        }
    }
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Successful return of `approve_escalation`. The dispatcher mirrors
/// these fields (plus `escalation_id`) into `OperatorResponse::EscalationApproved`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApproveResult {
    pub approval_token_id:  String,
    /// Hex-encoded high-entropy token (32 bytes → 64 hex chars). The
    /// kernel does not store this value; only `sha256(raw)` ends up in
    /// `approval_tokens.token_hash`. Operators must treat it as a
    /// secret.
    pub approval_token_raw: String,
    pub expires_at:         i64,
}

/// Successful return of `deny_escalation`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenyResult {
    pub denied_at: i64,
}

// ---------------------------------------------------------------------------
// Canonical signing input
// ---------------------------------------------------------------------------

/// Bytes the operator MUST sign before submitting an `ApproveEscalation`.
///
/// **Delegates to `raxis_crypto::escalation::approval_scope_signing_input`** —
/// that function is the single source of truth for the canonical byte
/// layout and is shared with the CLI. Keeping this thin wrapper means
/// callers can pass the typed `ApprovalScopeWire` straight through
/// without manually expanding the four scope fields at every call
/// site.
pub fn approval_scope_signing_input(
    escalation_id: &str,
    scope:         &ApprovalScopeWire,
) -> Vec<u8> {
    raxis_crypto::escalation::approval_scope_signing_input(
        escalation_id,
        &scope.capability_class,
        scope.max_uses,
        scope.valid_for_seconds,
    )
}

// ---------------------------------------------------------------------------
// approve_escalation
// ---------------------------------------------------------------------------

/// Approve a `Pending` escalation. See module docs for the contract.
///
/// All state mutation happens inside one SQLite transaction so partial
/// writes are impossible: either both the `approval_tokens` row and
/// the `escalations` UPDATE land, or neither does.
pub fn approve_escalation(
    escalation_id:    &str,
    approval_scope:   &ApprovalScopeWire,
    operator_sig:     &[u8],
    operator_fp:      &str,
    policy_epoch:     u64,
    policy:           &PolicyBundle,
    store:            &Store,
) -> Result<ApproveResult, EscalationError> {
    validate_scope(approval_scope)?;

    let pubkey_bytes = lookup_operator_pubkey(policy, operator_fp)?;
    let signing_input = approval_scope_signing_input(escalation_id, approval_scope);
    verify::verify_ed25519(&pubkey_bytes, &signing_input, operator_sig)
        .map_err(|_| EscalationError::SignatureInvalid)?;

    let approval_token_id  = uuid::Uuid::new_v4().to_string();
    let nonce              = token::generate_approval_nonce()?;
    let raw_bytes: [u8; 32] = token::try_random_array()?;
    let approval_token_raw = hex::encode(raw_bytes);
    let token_hash         = token::sha256_hex(&raw_bytes);
    let scope_json         = serde_json::to_string(approval_scope)
        .expect("ApprovalScopeWire is always JSON-serialisable");
    let now_secs           = unix_now_secs();
    let expires_at         = now_secs.saturating_add(approval_scope.valid_for_seconds as i64);

    let mut conn = store.lock_sync();
    let tx = conn.transaction()?;

    let pending_state  = EscalationStatus::Pending.as_sql_str();
    let approved_state = EscalationStatus::Approved.as_sql_str();

    let current_status: String = tx.query_row(
        &format!("SELECT status FROM {ESCALATIONS} WHERE escalation_id = ?1"),
        params![escalation_id],
        |r| r.get(0),
    ).map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => EscalationError::NotFound {
            escalation_id: escalation_id.to_owned(),
        },
        other => EscalationError::Sql(other),
    })?;

    if current_status.as_str() != pending_state {
        return Err(EscalationError::NotPending {
            escalation_id:  escalation_id.to_owned(),
            current_status,
        });
    }

    tx.execute(
        &format!(
            "INSERT INTO {APPROVAL_TOKENS} (
                approval_token_id, escalation_id, scope_json,
                issued_by_operator_id, policy_epoch, token_hash, nonce,
                issued_at, expires_at, consumed
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0)"
        ),
        params![
            approval_token_id,
            escalation_id,
            scope_json,
            operator_fp,
            policy_epoch as i64,
            token_hash,
            nonce,
            now_secs,
            expires_at,
        ],
    )?;

    let updated = tx.execute(
        &format!(
            "UPDATE {ESCALATIONS}
                SET status = ?1, resolved_at = ?2
              WHERE escalation_id = ?3 AND status = ?4"
        ),
        params![approved_state, now_secs, escalation_id, pending_state],
    )?;
    if updated != 1 {
        return Err(EscalationError::Sql(rusqlite::Error::QueryReturnedNoRows));
    }

    tx.commit()?;
    Ok(ApproveResult { approval_token_id, approval_token_raw, expires_at })
}

// ---------------------------------------------------------------------------
// deny_escalation
// ---------------------------------------------------------------------------

/// Deny a `Pending` escalation. No approval artifact is created.
pub fn deny_escalation(
    escalation_id: &str,
    reason:        Option<&str>,
    _denied_by_fp: &str,
    store:         &Store,
) -> Result<DenyResult, EscalationError> {
    let now = unix_now_secs();
    let conn = store.lock_sync();

    let pending_state = EscalationStatus::Pending.as_sql_str();
    let denied_state  = EscalationStatus::Denied.as_sql_str();

    let current_status: String = conn.query_row(
        &format!("SELECT status FROM {ESCALATIONS} WHERE escalation_id = ?1"),
        params![escalation_id],
        |r| r.get(0),
    ).map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => EscalationError::NotFound {
            escalation_id: escalation_id.to_owned(),
        },
        other => EscalationError::Sql(other),
    })?;

    if current_status.as_str() != pending_state {
        return Err(EscalationError::NotPending {
            escalation_id:  escalation_id.to_owned(),
            current_status,
        });
    }

    let updated = conn.execute(
        &format!(
            "UPDATE {ESCALATIONS}
                SET status = ?1, resolved_at = ?2, resolution_notes = ?3
              WHERE escalation_id = ?4 AND status = ?5"
        ),
        params![denied_state, now, reason, escalation_id, pending_state],
    )?;
    if updated != 1 {
        // Race: another caller approved/denied between our SELECT and
        // UPDATE. The constraint above protects integrity; we surface
        // it as NotPending so the operator gets a clear error message.
        return Err(EscalationError::NotPending {
            escalation_id:  escalation_id.to_owned(),
            current_status: format!("{pending_state} (race)"),
        });
    }
    Ok(DenyResult { denied_at: now })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn validate_scope(scope: &ApprovalScopeWire) -> Result<(), EscalationError> {
    if scope.capability_class.trim().is_empty() {
        return Err(EscalationError::InvalidScope {
            reason: "capability_class must be non-empty".to_owned(),
        });
    }
    if scope.max_uses <= 0 {
        return Err(EscalationError::InvalidScope {
            reason: format!("max_uses must be > 0 (got {})", scope.max_uses),
        });
    }
    if scope.valid_for_seconds == 0 {
        return Err(EscalationError::InvalidScope {
            reason: "valid_for_seconds must be > 0".to_owned(),
        });
    }
    Ok(())
}

fn lookup_operator_pubkey(
    policy:      &PolicyBundle,
    fingerprint: &str,
) -> Result<Vec<u8>, EscalationError> {
    let entry = policy.operator_entry(fingerprint)
        .ok_or_else(|| EscalationError::OperatorUnknown {
            fingerprint: fingerprint.to_owned(),
        })?;
    hex::decode(&entry.pubkey_hex).map_err(|e| {
        EscalationError::OperatorPubkeyMalformed {
            fingerprint: fingerprint.to_owned(),
            reason:      e.to_string(),
        }
    })
}

// ---------------------------------------------------------------------------
// Tests
//
// Two test surfaces:
//   1. `signing_input_tests` — pure-function pins for the canonical
//      signing-input byte layout. A change here MUST be matched by an
//      identical change on the CLI side; the tests catch any drift at
//      build time.
//   2. `escalation_db_tests` — drives `approve_escalation` /
//      `deny_escalation` against an in-memory store + a fixture
//      escalation row, covering every FSM edge and error variant.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use raxis_policy::{OperatorEntry, PolicyBundle};
    use raxis_store::Store;

    // ── helpers ───────────────────────────────────────────────────────

    fn fixture_keypair() -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    fn fixture_scope() -> ApprovalScopeWire {
        ApprovalScopeWire {
            capability_class:  "WriteSecrets".into(),
            max_uses:          3,
            valid_for_seconds: 1800,
        }
    }

    fn policy_with_operator(fp: &str, pubkey_hex: String) -> PolicyBundle {
        PolicyBundle::for_tests_with_operators(vec![OperatorEntry {
            pubkey_fingerprint: fp.to_owned(),
            display_name:       fp.to_owned(),
            pubkey_hex,
            permitted_ops:      vec![],
        }])
    }

    /// Insert a minimal escalation row in `Pending` status. Bypasses
    /// the planner submission path (no `sessions` / `tasks` rows
    /// required because the FK columns are `TEXT`, not constrained).
    fn insert_pending_escalation(store: &Store, escalation_id: &str) {
        // The escalations table has FOREIGN KEYs into sessions, tasks
        // and initiatives. We disable FK enforcement just for the
        // fixture insert, then re-enable, so the test exercises the
        // status transition logic in isolation.
        //
        // Class + status strings come from the typed enums per
        // INV-STORE-03; the rest are free-form text columns.
        let conn = store.lock_sync();
        conn.execute("PRAGMA foreign_keys = OFF", []).unwrap();
        conn.execute(
            &format!(
                "INSERT INTO {ESCALATIONS} (
                    escalation_id, session_id, task_id, lineage_id, initiative_id,
                    class, requested_scope_json, justification, idempotency_key,
                    status, created_at, timeout_at
                 ) VALUES (?1, 'sess-1', 'task-1', 'lin-1', 'init-1',
                           ?2,
                           '{{\"kind\":\"CapabilityUpgrade\",\"capability\":\"WriteSecrets\"}}',
                           'unit-test', ?3, ?4, ?5, ?6)"
            ),
            params![
                escalation_id,
                raxis_types::EscalationClass::CapabilityUpgrade.as_sql_str(),
                escalation_id, // unique idempotency_key per escalation
                EscalationStatus::Pending.as_sql_str(),
                unix_now_secs(),
                unix_now_secs() + 3600,
            ],
        ).unwrap();
        conn.execute("PRAGMA foreign_keys = ON", []).unwrap();
    }

    fn force_status(store: &Store, escalation_id: &str, status: EscalationStatus) {
        let conn = store.lock_sync();
        conn.execute(
            &format!("UPDATE {ESCALATIONS} SET status = ?1 WHERE escalation_id = ?2"),
            params![status.as_sql_str(), escalation_id],
        ).unwrap();
    }

    fn read_status(store: &Store, escalation_id: &str) -> String {
        let conn = store.lock_sync();
        conn.query_row(
            &format!("SELECT status FROM {ESCALATIONS} WHERE escalation_id = ?1"),
            params![escalation_id],
            |r| r.get(0),
        ).unwrap()
    }

    // ── signing_input_tests ───────────────────────────────────────────

    #[test]
    fn canonical_signing_input_byte_layout() {
        // Pin the EXACT byte sequence the kernel will verify against.
        // A drift on either side (kernel changes the format / CLI
        // changes the format) is caught here at build time.
        let scope = ApprovalScopeWire {
            capability_class:  "WriteSecrets".into(),
            max_uses:          3,
            valid_for_seconds: 1800,
        };
        let bytes = approval_scope_signing_input("esc-abc", &scope);
        assert_eq!(
            std::str::from_utf8(&bytes).unwrap(),
            "approval|esc-abc|WriteSecrets|3|1800",
        );
    }

    #[test]
    fn signing_input_uses_escalation_id_verbatim() {
        // Verifies the kernel does NOT lowercase / trim — operators
        // must sign the exact bytes they put on the wire.
        let scope = ApprovalScopeWire {
            capability_class:  "WriteCode".into(),
            max_uses:          1,
            valid_for_seconds: 60,
        };
        let bytes = approval_scope_signing_input("Esc With Spaces", &scope);
        assert!(std::str::from_utf8(&bytes).unwrap()
                .starts_with("approval|Esc With Spaces|"));
    }

    // ── approve_escalation ────────────────────────────────────────────

    #[test]
    fn approve_escalation_happy_path_writes_token_and_flips_status() {
        let store = Store::open_in_memory().unwrap();
        let (sk, pk) = fixture_keypair();
        let pubkey_hex = hex::encode(pk);
        let policy = policy_with_operator("op-prime", pubkey_hex);
        let scope = fixture_scope();

        insert_pending_escalation(&store, "esc-1");

        let sig = sk.sign(&approval_scope_signing_input("esc-1", &scope))
            .to_bytes()
            .to_vec();

        let result = approve_escalation(
            "esc-1", &scope, &sig, "op-prime", 7, &policy, &store,
        ).expect("happy-path approval must succeed");

        assert_eq!(result.approval_token_raw.len(), 64,
            "raw token must be 32 bytes hex-encoded (64 chars)");
        assert!(uuid::Uuid::parse_str(&result.approval_token_id).is_ok(),
            "approval_token_id must be a UUID");
        assert!(result.expires_at > unix_now_secs(),
            "expires_at must be in the future");

        assert_eq!(read_status(&store, "esc-1"), EscalationStatus::Approved.as_sql_str());

        // approval_tokens row was inserted with token_hash = sha256(raw).
        let conn = store.lock_sync();
        let (stored_hash, stored_epoch): (String, i64) = conn.query_row(
            &format!(
                "SELECT token_hash, policy_epoch FROM {APPROVAL_TOKENS}
                  WHERE escalation_id = ?1"
            ),
            params!["esc-1"],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ).unwrap();
        let raw_bytes = hex::decode(&result.approval_token_raw).unwrap();
        assert_eq!(stored_hash, token::sha256_hex(&raw_bytes),
            "token_hash MUST equal sha256(raw)");
        assert_eq!(stored_epoch, 7,
            "policy_epoch MUST equal the value passed by the dispatcher");
    }

    #[test]
    fn approve_escalation_rejects_when_escalation_missing() {
        let store = Store::open_in_memory().unwrap();
        let (sk, pk) = fixture_keypair();
        let policy = policy_with_operator("op-prime", hex::encode(pk));
        let scope = fixture_scope();
        let sig = sk.sign(&approval_scope_signing_input("ghost", &scope)).to_bytes().to_vec();

        let err = approve_escalation(
            "ghost", &scope, &sig, "op-prime", 1, &policy, &store,
        ).unwrap_err();

        assert!(matches!(err, EscalationError::NotFound { .. }));
        assert_eq!(err.error_code(), "FAIL_ESCALATION_NOT_FOUND");
    }

    #[test]
    fn approve_escalation_rejects_when_not_pending() {
        // Escalation already moved to Denied — operator's approval
        // attempt MUST be rejected with NotPending so the operator
        // sees a clear error rather than a confusing race.
        for terminal_status in [
            EscalationStatus::Approved,
            EscalationStatus::Denied,
            EscalationStatus::TimedOut,
            EscalationStatus::Consumed,
            EscalationStatus::TokenExpired,
        ] {
            let store = Store::open_in_memory().unwrap();
            let (sk, pk) = fixture_keypair();
            let policy = policy_with_operator("op-prime", hex::encode(pk));
            let scope = fixture_scope();
            insert_pending_escalation(&store, "esc-x");
            force_status(&store, "esc-x", terminal_status);
            let sig = sk.sign(&approval_scope_signing_input("esc-x", &scope))
                .to_bytes().to_vec();

            let err = approve_escalation(
                "esc-x", &scope, &sig, "op-prime", 1, &policy, &store,
            ).unwrap_err();

            match err {
                EscalationError::NotPending { current_status, .. } => {
                    assert_eq!(current_status, terminal_status.as_sql_str(),
                        "error must surface the actual current_status");
                }
                other => panic!("expected NotPending, got {other:?}"),
            }
        }
    }

    #[test]
    fn approve_escalation_rejects_invalid_scope() {
        let store = Store::open_in_memory().unwrap();
        let (sk, pk) = fixture_keypair();
        let policy = policy_with_operator("op-prime", hex::encode(pk));
        insert_pending_escalation(&store, "esc-1");

        // case 1: empty capability_class
        let bad = ApprovalScopeWire {
            capability_class:  "".into(),
            max_uses:          1,
            valid_for_seconds: 60,
        };
        let sig = sk.sign(&approval_scope_signing_input("esc-1", &bad)).to_bytes().to_vec();
        let err = approve_escalation(
            "esc-1", &bad, &sig, "op-prime", 1, &policy, &store,
        ).unwrap_err();
        assert!(matches!(err, EscalationError::InvalidScope { .. }));

        // case 2: max_uses = 0
        let bad = ApprovalScopeWire {
            capability_class:  "WriteCode".into(),
            max_uses:          0,
            valid_for_seconds: 60,
        };
        let sig = sk.sign(&approval_scope_signing_input("esc-1", &bad)).to_bytes().to_vec();
        let err = approve_escalation(
            "esc-1", &bad, &sig, "op-prime", 1, &policy, &store,
        ).unwrap_err();
        assert!(matches!(err, EscalationError::InvalidScope { .. }));

        // case 3: valid_for_seconds = 0
        let bad = ApprovalScopeWire {
            capability_class:  "WriteCode".into(),
            max_uses:          1,
            valid_for_seconds: 0,
        };
        let sig = sk.sign(&approval_scope_signing_input("esc-1", &bad)).to_bytes().to_vec();
        let err = approve_escalation(
            "esc-1", &bad, &sig, "op-prime", 1, &policy, &store,
        ).unwrap_err();
        assert!(matches!(err, EscalationError::InvalidScope { .. }));
    }

    #[test]
    fn approve_escalation_rejects_unknown_operator() {
        let store = Store::open_in_memory().unwrap();
        let (sk, _pk) = fixture_keypair();
        // Policy has operator 'op-other', NOT 'op-prime'.
        let policy = policy_with_operator("op-other", hex::encode([0u8; 32]));
        let scope = fixture_scope();
        insert_pending_escalation(&store, "esc-1");
        let sig = sk.sign(&approval_scope_signing_input("esc-1", &scope))
            .to_bytes().to_vec();

        let err = approve_escalation(
            "esc-1", &scope, &sig, "op-prime", 1, &policy, &store,
        ).unwrap_err();
        assert!(matches!(err, EscalationError::OperatorUnknown { .. }));
        assert_eq!(err.error_code(), "FAIL_OPERATOR_UNKNOWN");
    }

    #[test]
    fn approve_escalation_rejects_bad_signature() {
        let store = Store::open_in_memory().unwrap();
        let (sk, pk) = fixture_keypair();
        let policy = policy_with_operator("op-prime", hex::encode(pk));
        let scope = fixture_scope();
        insert_pending_escalation(&store, "esc-1");

        // Sign over a DIFFERENT escalation id — kernel must reject
        // because the signing input includes the escalation_id.
        let bogus_sig = sk.sign(&approval_scope_signing_input("other-id", &scope))
            .to_bytes().to_vec();

        let err = approve_escalation(
            "esc-1", &scope, &bogus_sig, "op-prime", 1, &policy, &store,
        ).unwrap_err();
        assert!(matches!(err, EscalationError::SignatureInvalid));
        assert_eq!(err.error_code(), "FAIL_OPERATOR_SIGNATURE_INVALID");
        assert_eq!(read_status(&store, "esc-1"), "Pending",
            "row MUST stay Pending when signature verification fails");
    }

    #[test]
    fn approve_escalation_rejects_when_signed_with_wrong_key() {
        let store = Store::open_in_memory().unwrap();
        let (_, pk_real) = fixture_keypair();
        let policy = policy_with_operator("op-prime", hex::encode(pk_real));
        let scope = fixture_scope();
        insert_pending_escalation(&store, "esc-1");

        // Attacker has a different private key.
        let sk_attacker = SigningKey::from_bytes(&[42u8; 32]);
        let sig = sk_attacker.sign(&approval_scope_signing_input("esc-1", &scope))
            .to_bytes().to_vec();

        let err = approve_escalation(
            "esc-1", &scope, &sig, "op-prime", 1, &policy, &store,
        ).unwrap_err();
        assert!(matches!(err, EscalationError::SignatureInvalid));
        assert_eq!(read_status(&store, "esc-1"), EscalationStatus::Pending.as_sql_str());
    }

    #[test]
    fn approve_escalation_does_not_partial_write_on_status_mismatch() {
        // Force status to TimedOut between the SELECT inside
        // approve_escalation and the UPDATE: in practice this is a
        // race, but our fixture forces the simpler shape (row is in
        // 'Approved' before approve_escalation is called).
        let store = Store::open_in_memory().unwrap();
        let (sk, pk) = fixture_keypair();
        let policy = policy_with_operator("op-prime", hex::encode(pk));
        let scope = fixture_scope();
        insert_pending_escalation(&store, "esc-1");
        force_status(&store, "esc-1", EscalationStatus::Approved);
        let sig = sk.sign(&approval_scope_signing_input("esc-1", &scope))
            .to_bytes().to_vec();

        let err = approve_escalation(
            "esc-1", &scope, &sig, "op-prime", 1, &policy, &store,
        ).unwrap_err();
        assert!(matches!(err, EscalationError::NotPending { .. }));

        // Crucial invariant: NO approval_tokens row was written.
        let conn = store.lock_sync();
        let n: i64 = conn.query_row(
            &format!("SELECT COUNT(*) FROM {APPROVAL_TOKENS} WHERE escalation_id = 'esc-1'"),
            [], |r| r.get(0),
        ).unwrap();
        assert_eq!(n, 0,
            "rejected approve_escalation MUST NOT leave an orphaned approval_tokens row");
    }

    // ── deny_escalation ───────────────────────────────────────────────

    #[test]
    fn deny_escalation_happy_path_with_reason() {
        let store = Store::open_in_memory().unwrap();
        insert_pending_escalation(&store, "esc-1");

        let result = deny_escalation(
            "esc-1", Some("scope too broad"), "op-prime", &store,
        ).expect("happy-path denial must succeed");

        assert!(result.denied_at > 0);
        assert_eq!(read_status(&store, "esc-1"), EscalationStatus::Denied.as_sql_str());

        let conn = store.lock_sync();
        let notes: Option<String> = conn.query_row(
            &format!("SELECT resolution_notes FROM {ESCALATIONS} WHERE escalation_id = 'esc-1'"),
            [], |r| r.get(0),
        ).unwrap();
        assert_eq!(notes.as_deref(), Some("scope too broad"));
    }

    #[test]
    fn deny_escalation_happy_path_without_reason() {
        let store = Store::open_in_memory().unwrap();
        insert_pending_escalation(&store, "esc-1");

        deny_escalation("esc-1", None, "op-prime", &store).unwrap();

        assert_eq!(read_status(&store, "esc-1"), EscalationStatus::Denied.as_sql_str());
        let conn = store.lock_sync();
        let notes: Option<String> = conn.query_row(
            &format!("SELECT resolution_notes FROM {ESCALATIONS} WHERE escalation_id = 'esc-1'"),
            [], |r| r.get(0),
        ).unwrap();
        assert_eq!(notes, None);
    }

    #[test]
    fn deny_escalation_rejects_when_missing() {
        let store = Store::open_in_memory().unwrap();
        let err = deny_escalation("ghost", None, "op-prime", &store).unwrap_err();
        assert!(matches!(err, EscalationError::NotFound { .. }));
        assert_eq!(err.error_code(), "FAIL_ESCALATION_NOT_FOUND");
    }

    #[test]
    fn deny_escalation_rejects_when_not_pending() {
        // Cover every non-Pending variant the schema CHECK constraint
        // permits — keeps lock-step with the EscalationStatus enum so
        // a future variant addition forces this test to be updated.
        for terminal_status in [
            EscalationStatus::Approved,
            EscalationStatus::Denied,
            EscalationStatus::TimedOut,
            EscalationStatus::Consumed,
            EscalationStatus::TokenExpired,
        ] {
            let store = Store::open_in_memory().unwrap();
            insert_pending_escalation(&store, "esc-x");
            force_status(&store, "esc-x", terminal_status);
            let err = deny_escalation("esc-x", None, "op-prime", &store).unwrap_err();
            assert!(matches!(err, EscalationError::NotPending { .. }));
            assert_eq!(err.error_code(), "FAIL_ESCALATION_NOT_PENDING");
        }
    }

    #[test]
    fn deny_escalation_does_not_create_approval_token() {
        // INV-ESC: no approval artifact on denial.
        let store = Store::open_in_memory().unwrap();
        insert_pending_escalation(&store, "esc-1");
        deny_escalation("esc-1", Some("nope"), "op-prime", &store).unwrap();
        let conn = store.lock_sync();
        let n: i64 = conn.query_row(
            &format!("SELECT COUNT(*) FROM {APPROVAL_TOKENS} WHERE escalation_id = 'esc-1'"),
            [], |r| r.get(0),
        ).unwrap();
        assert_eq!(n, 0, "denial MUST NOT issue an approval token");
    }
}
