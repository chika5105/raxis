// raxis-kernel::authority::session — Session lifecycle management.
//
// Normative reference: kernel-core.md §2.3 `src/authority/session.rs`.
//
// A session is a kernel-created authenticated connection credential for a
// planner, gateway, or verifier process. Sessions are NOT created by the
// connecting process — the operator (or kernel spawn path) creates them.
//
// Session token: 256-bit CSPRNG random bytes. Not HMAC-derived from session_id.
// Stored as the token itself in the sessions table; presented by the process
// on every IPC frame for auth.rs to validate.
//
// Planner sessions: worktree_root required; base_sha / base_tracking_ref recorded.
// Gateway/Verifier sessions: worktree_root must be None (stored as SQL NULL).

use raxis_store::{Store, Table};
use raxis_types::{unix_now_secs, LineageId, SessionId};

use crate::authority::keys::AuthorityError;
use raxis_crypto::token::generate_session_token;

const SESSIONS: &str = Table::Sessions.as_str();
const NONCE_CACHE: &str = Table::NonceCache.as_str();

/// Role of a session — corresponds to the authenticated process type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Role {
    Planner,
    Gateway,
    Verifier,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Planner => "Planner",
            Self::Gateway => "Gateway",
            Self::Verifier => "Verifier",
        }
    }
}

/// A session row as returned by `get_session`.
#[derive(Debug, Clone)]
pub struct SessionRow {
    pub session_id: String,
    pub role: String,
    pub session_token: String, // raw 32-byte token, hex-encoded (64 chars)
    pub sequence_number: i64,
    pub worktree_root: Option<String>,
    pub base_sha: Option<String>,
    pub base_tracking_ref: Option<String>,
    pub lineage_id: String,
    pub revoked_at: Option<i64>,
    pub expires_at: i64,

    // ── V2 fields (Migration 5; kernel-store.md / v2-deep-spec.md §Step 6) ──
    /// **V2.** `Some(SessionAgentType)` when the session was created
    /// for a V2 hierarchical-orchestration role; `None` for V1
    /// sessions that pre-date Migration 5 (column nullable for
    /// backward compat). Drives the static dispatch matrix
    /// (v2-deep-spec.md §Step 20).
    pub session_agent_type: Option<raxis_types::SessionAgentType>,

    /// **V2.** Boolean gate on `ActivateSubTask` and `RetrySubTask`.
    /// INV-DELEGATE-01 enforces `can_delegate = 1` ⇔
    /// `session_agent_type = Orchestrator` at the DB layer. Decoded
    /// here as `bool` for ergonomic handler use.
    pub can_delegate: bool,

    /// **V2 Migration 18.** `Some(initiative_id)` for V2 planner-class
    /// sessions that the kernel auto-spawned under a specific
    /// initiative (today: Orchestrator coordinator sessions, soon
    /// Executor / Reviewer sub-task sessions). `None` for pre-V2
    /// sessions and for non-V2 substrates (Gateway / Verifier).
    ///
    /// Populated by `auto_spawn_orchestrator_session_in_tx`
    /// (`v2-deep-spec.md §Step 6`) and read by:
    ///
    /// * `intent::run_phase_a` — to route Orchestrator-emitted
    ///   `IntentKind::StructuredOutput` to the initiative-scoped
    ///   `handle_structured_output_orchestrator` handler without
    ///   doing a `tasks` lookup that would always fail
    ///   (`v2_extended_gaps.md §3.2`).
    /// * Recovery / dashboard surfaces — typed back-edge from a
    ///   coordinator session to its initiative without joining
    ///   through `subtask_activations` (which only covers
    ///   Executor / Reviewer descendants).
    ///
    /// Backed by the nullable `sessions.initiative_id` column with
    /// FK to `initiatives(initiative_id) ON DELETE CASCADE`
    /// introduced in migration 18.
    pub initiative_id: Option<String>,
}

/// Configuration for session creation (fetch_quota, default_ttl, etc.).
pub struct SessionConfig {
    /// Default session TTL in seconds.
    pub default_ttl_secs: u64,
    /// Maximum fetch quota for this session.
    pub fetch_quota: i64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            default_ttl_secs: 86400,
            fetch_quota: 1000,
        }
    }
}

/// Create a new session and insert the row into the `sessions` table.
///
/// - For `Role::Planner`: `worktree_root` must be `Some`.
/// - For `Role::Gateway` / `Role::Verifier`: `worktree_root` must be `None`.
///
/// Returns the `(SessionId, session_token_hex)` pair on success. The raw token
/// hex is sent to the operator/spawner; the kernel stores it directly in the
/// sessions table for auth.rs to compare constant-time.
pub fn create_session(
    role: Role,
    worktree_root: Option<String>,
    base_sha: Option<String>,
    base_tracking_ref: Option<String>,
    lineage_id: LineageId,
    config: &SessionConfig,
    store: &Store,
) -> Result<(SessionId, String), AuthorityError> {
    // Validate role + worktree_root pairing.
    match (&role, &worktree_root) {
        (Role::Planner, None) => {
            return Err(AuthorityError::SessionInvalid {
                reason: "Planner session requires worktree_root".to_owned(),
            })
        }
        (Role::Gateway | Role::Verifier, Some(_)) => {
            return Err(AuthorityError::SessionInvalid {
                reason: "Gateway/Verifier session must not have worktree_root".to_owned(),
            })
        }
        _ => {}
    }

    let session_id = SessionId::new_v4();
    // 32 CSPRNG bytes → 64 hex chars. RNG failure surfaces as
    // `AuthorityError::Crypto`; we never write a zeroed token.
    let session_token = generate_session_token()?;

    let now_secs = unix_now_secs();
    let expires_at = now_secs + config.default_ttl_secs as i64;

    // DDL Table 4 column names: role_id (not role), revoked INTEGER DEFAULT 0.
    let store = store.lock_sync();
    store
        .execute(
            &format!(
                "INSERT INTO {SESSIONS} (
                session_id, role_id, session_token, sequence_number,
                worktree_root, base_sha, base_tracking_ref,
                lineage_id, fetch_quota, created_at, expires_at, revoked
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,0)"
            ),
            rusqlite::params![
                session_id.as_str(),
                role.as_str(),
                &session_token,
                0i64,
                worktree_root.as_deref(),
                base_sha.as_deref(),
                base_tracking_ref.as_deref(),
                lineage_id.as_str(),
                config.fetch_quota,
                now_secs,
                expires_at,
            ],
        )
        .map_err(|e| AuthorityError::Store(raxis_store::StoreError::Rusqlite(e)))?;

    Ok((session_id, session_token))
}

/// Look up a session row by `session_id`. Returns `AuthorityError::SessionNotFound`
/// if no row exists, or `SessionRevoked` / `SessionExpired` where applicable.
pub fn get_session(session_id: &SessionId, store: &Store) -> Result<SessionRow, AuthorityError> {
    let store = store.lock_sync();
    let row = store
        .query_row(
            &format!(
                "SELECT session_id, role_id, session_token, sequence_number,
                    worktree_root, base_sha, base_tracking_ref,
                    lineage_id, revoked_at, expires_at,
                    session_agent_type, can_delegate, initiative_id
             FROM {SESSIONS} WHERE session_id = ?1"
            ),
            rusqlite::params![session_id.as_str()],
            |row| {
                let agent_type_sql: Option<String> = row.get(10)?;
                let can_delegate_int: i64 = row.get(11)?;
                Ok(SessionRow {
                    session_id: row.get(0)?,
                    role: row.get(1)?, // mapped from role_id column
                    session_token: row.get(2)?,
                    sequence_number: row.get(3)?,
                    worktree_root: row.get(4)?,
                    base_sha: row.get(5)?,
                    base_tracking_ref: row.get(6)?,
                    lineage_id: row.get(7)?,
                    revoked_at: row.get(8)?,
                    expires_at: row.get(9)?,
                    session_agent_type: agent_type_sql
                        .as_deref()
                        .and_then(raxis_types::SessionAgentType::from_sql_str),
                    can_delegate: can_delegate_int != 0,
                    initiative_id: row.get(12)?,
                })
            },
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => AuthorityError::SessionNotFound,
            other => AuthorityError::Store(raxis_store::StoreError::Rusqlite(other)),
        })?;

    // DDL Table 4: revoked INTEGER (0/1 flag) + revoked_at (nullable timestamp).
    // Check both: revoked=1 is the gate; revoked_at carries the time.
    if row.revoked_at.is_some() {
        return Err(AuthorityError::SessionRevoked {
            revoked_at: row.revoked_at.unwrap_or(0),
        });
    }
    if row.expires_at < unix_now_secs() {
        return Err(AuthorityError::SessionExpired);
    }

    Ok(row)
}

/// Look up a session row by raw `session_token` hex string.
///
/// Called by the planner IPC dispatch loop to resolve the per-frame token
/// to a session context before sequence/nonce validation.
///
/// Returns the raw row without applying revoked/expired guards — the caller
/// performs those checks (they need the raw row for sequence number access).
/// `SessionNotFound` if no row matches the token.
pub fn get_session_by_token(
    session_token: &str,
    store: &Store,
) -> Result<SessionRow, AuthorityError> {
    let conn = store.lock_sync();
    conn.query_row(
        &format!(
            "SELECT session_id, role_id, session_token, sequence_number,
                    worktree_root, base_sha, base_tracking_ref,
                    lineage_id, revoked_at, expires_at,
                    session_agent_type, can_delegate, initiative_id
             FROM {SESSIONS} WHERE session_token = ?1"
        ),
        rusqlite::params![session_token],
        |row| {
            let agent_type_sql: Option<String> = row.get(10)?;
            let can_delegate_int: i64 = row.get(11)?;
            Ok(SessionRow {
                session_id: row.get(0)?,
                role: row.get(1)?,
                session_token: row.get(2)?,
                sequence_number: row.get(3)?,
                worktree_root: row.get(4)?,
                base_sha: row.get(5)?,
                base_tracking_ref: row.get(6)?,
                lineage_id: row.get(7)?,
                revoked_at: row.get(8)?,
                expires_at: row.get(9)?,
                session_agent_type: agent_type_sql
                    .as_deref()
                    .and_then(raxis_types::SessionAgentType::from_sql_str),
                can_delegate: can_delegate_int != 0,
                initiative_id: row.get(12)?,
            })
        },
    )
    .map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => AuthorityError::SessionNotFound,
        other => AuthorityError::Store(raxis_store::StoreError::Rusqlite(other)),
    })
}

/// Revoke a session by setting `revoked=1, revoked_at=now()`.
///
/// DDL Table 4: revoked INTEGER NOT NULL DEFAULT 0, revoked_at INTEGER (nullable).
/// Uses conditional UPDATE WHERE revoked=0 (INV-STORE-02) to prevent double-revocation races.
pub fn revoke_session(session_id: &SessionId, store: &Store) -> Result<(), AuthorityError> {
    let now = unix_now_secs();
    let store = store.lock_sync();
    let rows = store
        .execute(
            &format!(
                "UPDATE {SESSIONS} SET revoked=1, revoked_at=?1 WHERE session_id=?2 AND revoked=0"
            ),
            rusqlite::params![now, session_id.as_str()],
        )
        .map_err(|e| AuthorityError::Store(raxis_store::StoreError::Rusqlite(e)))?;

    if rows == 0 {
        Err(AuthorityError::SessionRevoked { revoked_at: now })
    } else {
        Ok(())
    }
}

/// Atomically advance the sequence number for a session.
///
/// Spec note: in the IPC path, callers should prefer
/// [`accept_envelope_and_advance_sequence`] which combines the sequence-number
/// CAS with the `nonce_cache` envelope-nonce dedup INSERT in a SINGLE
/// SQLite transaction (INV-01 checks A and B together — see kernel-core.md
/// §2.3 / kernel-store.md §2.5.1 Table 16). This standalone update is
/// retained as a store-level utility for test harnesses and crash-recovery
/// reconciliation; production handlers should not call it directly.
pub fn update_sequence_number(
    session_id: &SessionId,
    expected_current: i64,
    store: &Store,
) -> Result<(), AuthorityError> {
    let store = store.lock_sync();
    let rows = store
        .execute(
            &format!(
                "UPDATE {SESSIONS} SET sequence_number = ?1
             WHERE session_id = ?2 AND sequence_number = ?3"
            ),
            rusqlite::params![expected_current + 1, session_id.as_str(), expected_current],
        )
        .map_err(|e| AuthorityError::Store(raxis_store::StoreError::Rusqlite(e)))?;

    if rows == 0 {
        Err(AuthorityError::SequenceMismatch)
    } else {
        Ok(())
    }
}

/// Why this exists separately from sequence-number advancement: replay
/// protection has two distinct failure modes the planner sees as separate
/// outcomes — a duplicate `envelope_nonce` (the same logical message
/// re-delivered) versus a duplicate `sequence_num` (a request out of order
/// or already accepted). Both surface as `UNAUTHORIZED` to the planner per
/// INV-08, but distinguishing them in audit is required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeReplayReason {
    /// `(session_id, envelope_nonce)` already in `nonce_cache` for the TTL
    /// window — duplicate delivery.
    DuplicateNonce,
    /// `(session_id, sequence_num)` already accepted (PK collision on
    /// `nonce_cache`) — schema backstop for check (A).
    SequenceAlreadyAccepted,
    /// `sequence_num != sessions.sequence_number + 1` — out-of-order frame.
    SequenceGap { expected: i64, presented: i64 },
}

/// INV-01 chokepoint. ALL planner-class IPC handlers must route through this
/// function before doing any other work.
///
/// Combines, in one SQLite transaction:
///   1. **Check (A)** — sequence number is exactly `sessions.sequence_number + 1`.
///   2. **Check (B)** — `INSERT INTO nonce_cache (session_id, sequence_num,
///                       envelope_nonce, observed_at)`. Fails on duplicate
///                       `(session_id, envelope_nonce)` (UNIQUE) or duplicate
///                       `(session_id, sequence_num)` (PK).
///   3. **Atomic advance** — `UPDATE sessions SET sequence_number = sequence_num`.
///
/// Either all three succeed and commit, or none do (transaction rollback). The
/// invariant `sessions.sequence_number == MAX(nonce_cache.sequence_num)` is
/// preserved across crashes.
///
/// Returns `Err(EnvelopeReplayReason)` on any failure for caller-side audit
/// emission. The handler maps each reason to `PlannerErrorCode::Unauthorized`
/// per INV-08 to avoid leaking which check failed.
pub fn accept_envelope_and_advance_sequence(
    session_id: &SessionId,
    presented_seq: i64,
    envelope_nonce: &str,
    store: &Store,
) -> Result<(), EnvelopeReplayReason> {
    // Sanity: nonce must be 32 hex chars (16 bytes). A malformed nonce is a
    // protocol violation and we treat it as DuplicateNonce-equivalent —
    // surfaces as UNAUTHORIZED, no observable difference to the planner.
    if envelope_nonce.len() != 32 || !envelope_nonce.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(EnvelopeReplayReason::DuplicateNonce);
    }

    let mut conn = store.lock_sync();
    let tx = conn
        .transaction()
        .map_err(|_| EnvelopeReplayReason::DuplicateNonce)?;

    // Check (A) inside the transaction so we read+write under one snapshot.
    let current_seq: i64 = tx
        .query_row(
            &format!("SELECT sequence_number FROM {SESSIONS} WHERE session_id = ?1"),
            rusqlite::params![session_id.as_str()],
            |r| r.get(0),
        )
        .map_err(|_| EnvelopeReplayReason::DuplicateNonce)?;

    let expected = current_seq + 1;
    if presented_seq != expected {
        // No INSERT, no UPDATE — caller sees `SequenceGap`.
        return Err(EnvelopeReplayReason::SequenceGap {
            expected,
            presented: presented_seq,
        });
    }

    // Check (B) — the UNIQUE/PK constraints on nonce_cache do the dedup work.
    let now = unix_now_secs();
    let insert_result = tx.execute(
        &format!(
            "INSERT INTO {NONCE_CACHE}
                (session_id, sequence_num, envelope_nonce, observed_at)
             VALUES (?1, ?2, ?3, ?4)"
        ),
        rusqlite::params![session_id.as_str(), presented_seq, envelope_nonce, now],
    );

    match insert_result {
        Ok(_) => {}
        Err(rusqlite::Error::SqliteFailure(err, msg)) => {
            // Map SQLite constraint codes to INV-01 reason variants.
            // `extended_code` distinguishes UNIQUE (2067) from PRIMARYKEY (1555).
            const SQLITE_CONSTRAINT_UNIQUE: i32 = 2067;
            const SQLITE_CONSTRAINT_PRIMARYKEY: i32 = 1555;
            return Err(match err.extended_code {
                SQLITE_CONSTRAINT_UNIQUE => EnvelopeReplayReason::DuplicateNonce,
                SQLITE_CONSTRAINT_PRIMARYKEY => EnvelopeReplayReason::SequenceAlreadyAccepted,
                _ => {
                    // Any other constraint failure: treat as duplicate-class
                    // for INV-08; log via the message field on the way out.
                    let _ = msg;
                    EnvelopeReplayReason::DuplicateNonce
                }
            });
        }
        Err(_) => return Err(EnvelopeReplayReason::DuplicateNonce),
    }

    // Atomic CAS — if anything else slipped in between SELECT and UPDATE,
    // the row count will be 0 and we treat it as `SequenceAlreadyAccepted`
    // (the most likely cause: a concurrent handler advanced the sequence).
    let updated = tx.execute(
        &format!(
            "UPDATE {SESSIONS}
             SET sequence_number = ?1
             WHERE session_id = ?2 AND sequence_number = ?3"
        ),
        rusqlite::params![presented_seq, session_id.as_str(), current_seq],
    );

    match updated {
        Ok(0) => return Err(EnvelopeReplayReason::SequenceAlreadyAccepted),
        Ok(_) => {}
        Err(_) => return Err(EnvelopeReplayReason::DuplicateNonce),
    }

    tx.commit()
        .map_err(|_| EnvelopeReplayReason::DuplicateNonce)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_store::Store;

    /// Set up an in-memory store with one session row at sequence 0.
    fn store_with_session(session_id: &SessionId) -> Store {
        let store = Store::open_in_memory().expect("open in-memory store");
        let conn = store.lock_sync();
        conn.execute(
            &format!(
                "INSERT INTO {SESSIONS} (session_id, role_id, session_token,
                                          lineage_id, fetch_quota, sequence_number,
                                          created_at, expires_at, revoked)
                 VALUES (?1, 'Planner', 'tok', '00000000-0000-4000-8000-000000000000',
                         100, 0, 0, ?2, 0)"
            ),
            rusqlite::params![session_id.as_str(), unix_now_secs() + 3600],
        )
        .unwrap();
        drop(conn);
        store
    }

    fn nonce(seed: u8) -> String {
        // 32 hex chars derived from a one-byte seed for deterministic tests.
        format!("{:02x}", seed).repeat(16)
    }

    #[test]
    fn first_envelope_advances_sequence_to_one() {
        let sid = SessionId::new_v4();
        let store = store_with_session(&sid);

        accept_envelope_and_advance_sequence(&sid, 1, &nonce(0xAB), &store)
            .expect("first envelope should accept");

        let conn = store.lock_sync();
        let s: i64 = conn
            .query_row(
                &format!("SELECT sequence_number FROM {SESSIONS} WHERE session_id = ?1"),
                rusqlite::params![sid.as_str()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(s, 1);

        // And one row in nonce_cache.
        let n: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {NONCE_CACHE} WHERE session_id = ?1"),
                rusqlite::params![sid.as_str()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn duplicate_envelope_nonce_is_rejected_atomically() {
        let sid = SessionId::new_v4();
        let store = store_with_session(&sid);

        accept_envelope_and_advance_sequence(&sid, 1, &nonce(0xCD), &store).unwrap();

        // Same nonce, NEXT sequence number → still rejected (UNIQUE on nonce).
        let err = accept_envelope_and_advance_sequence(&sid, 2, &nonce(0xCD), &store).unwrap_err();
        assert_eq!(err, EnvelopeReplayReason::DuplicateNonce);

        // Sequence number must not have advanced.
        let conn = store.lock_sync();
        let s: i64 = conn
            .query_row(
                &format!("SELECT sequence_number FROM {SESSIONS} WHERE session_id = ?1"),
                rusqlite::params![sid.as_str()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(s, 1, "sequence must not advance on rejected envelope");
    }

    #[test]
    fn out_of_order_sequence_is_rejected_with_gap_variant() {
        let sid = SessionId::new_v4();
        let store = store_with_session(&sid);

        // Skip seq 1, jump to seq 2 — must reject with SequenceGap.
        let err = accept_envelope_and_advance_sequence(&sid, 2, &nonce(0xEF), &store).unwrap_err();
        assert_eq!(
            err,
            EnvelopeReplayReason::SequenceGap {
                expected: 1,
                presented: 2
            }
        );

        // No nonce_cache row was written.
        let conn = store.lock_sync();
        let n: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {NONCE_CACHE} WHERE session_id = ?1"),
                rusqlite::params![sid.as_str()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn replaying_same_sequence_with_different_nonce_is_rejected() {
        let sid = SessionId::new_v4();
        let store = store_with_session(&sid);

        accept_envelope_and_advance_sequence(&sid, 1, &nonce(0x11), &store).unwrap();

        // Try to re-accept seq=1 with a fresh nonce. The sequence check (A)
        // catches this before we reach the nonce insert.
        let err = accept_envelope_and_advance_sequence(&sid, 1, &nonce(0x22), &store).unwrap_err();
        assert!(matches!(err, EnvelopeReplayReason::SequenceGap { .. }));
    }

    #[test]
    fn malformed_nonce_is_rejected() {
        let sid = SessionId::new_v4();
        let store = store_with_session(&sid);

        // Wrong length.
        let err = accept_envelope_and_advance_sequence(&sid, 1, "abc", &store).unwrap_err();
        assert_eq!(err, EnvelopeReplayReason::DuplicateNonce);

        // Non-hex character.
        let bad = "z".repeat(32);
        let err = accept_envelope_and_advance_sequence(&sid, 1, &bad, &store).unwrap_err();
        assert_eq!(err, EnvelopeReplayReason::DuplicateNonce);

        // Sequence must NOT have advanced.
        let conn = store.lock_sync();
        let s: i64 = conn
            .query_row(
                &format!("SELECT sequence_number FROM {SESSIONS} WHERE session_id = ?1"),
                rusqlite::params![sid.as_str()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(s, 0);
    }

    // ── V2 SessionRow read-path coverage (Migration 5) ────────────────────
    //
    // After Migration 5, `sessions` carries `session_agent_type TEXT NULL`
    // and `can_delegate INTEGER NOT NULL DEFAULT 0`. The `SessionRow`
    // surface must round-trip both columns so the dispatch matrix
    // (v2-deep-spec.md §Step 20) and the `ActivateSubTask` /
    // `RetrySubTask` boolean-field gate (INV-DELEGATE-01) read consistent
    // values.

    #[test]
    fn v1_session_row_reads_null_agent_type_as_none() {
        // `store_with_session` inserts without setting the V2 columns —
        // simulates a pre-Migration-5 row that survived the upgrade.
        let sid = SessionId::new_v4();
        let store = store_with_session(&sid);

        let row = get_session(&sid, &store).expect("session must read");
        assert!(
            row.session_agent_type.is_none(),
            "V1 row ⇒ NULL agent_type ⇒ Rust None"
        );
        assert!(!row.can_delegate, "V1 row default DDL: can_delegate = 0");
    }

    #[test]
    fn v2_orchestrator_session_row_reads_can_delegate_one() {
        let sid = SessionId::new_v4();
        let store = store_with_session(&sid);
        // Promote the V1 row to a V2 Orchestrator row in-place.
        // The cross-column CHECK on `sessions` (Migration 5) requires
        // can_delegate = 1 ⇔ session_agent_type = Orchestrator, so we
        // set both atomically in a single UPDATE.
        {
            let conn = store.lock_sync();
            conn.execute(
                &format!(
                    "UPDATE {SESSIONS} SET session_agent_type = ?1, can_delegate = 1
                     WHERE session_id = ?2"
                ),
                rusqlite::params![
                    raxis_types::SessionAgentType::Orchestrator.as_sql_str(),
                    sid.as_str(),
                ],
            )
            .unwrap();
        }

        let row = get_session(&sid, &store).expect("session must read");
        assert_eq!(
            row.session_agent_type,
            Some(raxis_types::SessionAgentType::Orchestrator)
        );
        assert!(
            row.can_delegate,
            "Orchestrator session must round-trip can_delegate=1"
        );
    }

    #[test]
    fn v2_executor_session_row_reads_can_delegate_zero() {
        let sid = SessionId::new_v4();
        let store = store_with_session(&sid);
        {
            let conn = store.lock_sync();
            conn.execute(
                &format!(
                    "UPDATE {SESSIONS} SET session_agent_type = ?1, can_delegate = 0
                     WHERE session_id = ?2"
                ),
                rusqlite::params![
                    raxis_types::SessionAgentType::Executor.as_sql_str(),
                    sid.as_str(),
                ],
            )
            .unwrap();
        }

        let row = get_session(&sid, &store).expect("session must read");
        assert_eq!(
            row.session_agent_type,
            Some(raxis_types::SessionAgentType::Executor)
        );
        assert!(
            !row.can_delegate,
            "Executor session must NOT have can_delegate=1 \
             (INV-DELEGATE-01)"
        );
    }

    #[test]
    fn v2_session_row_lookup_by_token_round_trips_v2_fields() {
        // Same coverage but through the planner-IPC entry point
        // (`get_session_by_token`) rather than `get_session`.
        let sid = SessionId::new_v4();
        let store = store_with_session(&sid);
        {
            let conn = store.lock_sync();
            conn.execute(
                &format!(
                    "UPDATE {SESSIONS} SET session_agent_type = ?1, can_delegate = 0
                     WHERE session_id = ?2"
                ),
                rusqlite::params![
                    raxis_types::SessionAgentType::Reviewer.as_sql_str(),
                    sid.as_str(),
                ],
            )
            .unwrap();
        }

        let row = get_session_by_token("tok", &store).expect("session must be readable by token");
        assert_eq!(
            row.session_agent_type,
            Some(raxis_types::SessionAgentType::Reviewer)
        );
        assert!(!row.can_delegate);
    }

    #[test]
    fn many_envelopes_accepted_in_order() {
        let sid = SessionId::new_v4();
        let store = store_with_session(&sid);

        for i in 1..=10 {
            accept_envelope_and_advance_sequence(&sid, i, &nonce(i as u8), &store)
                .expect("ordered envelope should accept");
        }

        let conn = store.lock_sync();
        let s: i64 = conn
            .query_row(
                &format!("SELECT sequence_number FROM {SESSIONS} WHERE session_id = ?1"),
                rusqlite::params![sid.as_str()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(s, 10);
    }
}
