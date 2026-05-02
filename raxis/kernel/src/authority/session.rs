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

use raxis_store::Store;
use raxis_types::{SessionId, LineageId};

use crate::authority::keys::AuthorityError;
use raxis_crypto::token::generate_session_token;

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
    pub session_token: String,  // raw 32-byte token, hex-encoded (64 chars)
    pub sequence_number: i64,
    pub worktree_root: Option<String>,
    pub base_sha: Option<String>,
    pub base_tracking_ref: Option<String>,
    pub lineage_id: String,
    pub revoked_at: Option<i64>,
    pub expires_at: i64,
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
        Self { default_ttl_secs: 86400, fetch_quota: 1000 }
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
    let session_token = generate_session_token(); // 32 bytes → 64 hex chars

    let now_secs = now_unix_secs();
    let expires_at = now_secs + config.default_ttl_secs as i64;

    // DDL Table 4 column names: role_id (not role), revoked INTEGER DEFAULT 0.
    let store = store.lock_sync();
    store.execute(
        "INSERT INTO sessions (
            session_id, role_id, session_token, sequence_number,
            worktree_root, base_sha, base_tracking_ref,
            lineage_id, fetch_quota, created_at, expires_at, revoked
         ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,0)",
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
    ).map_err(|e| AuthorityError::Store(raxis_store::StoreError::Rusqlite(e)))?;

    Ok((session_id, session_token))
}

/// Look up a session row by `session_id`. Returns `AuthorityError::SessionNotFound`
/// if no row exists, or `SessionRevoked` / `SessionExpired` where applicable.
pub fn get_session(session_id: &SessionId, store: &Store) -> Result<SessionRow, AuthorityError> {
    let store = store.lock_sync();
    let row = store.query_row(
        "SELECT session_id, role_id, session_token, sequence_number,
                worktree_root, base_sha, base_tracking_ref,
                lineage_id, revoked_at, expires_at
         FROM sessions WHERE session_id = ?1",
        rusqlite::params![session_id.as_str()],
        |row| {
            Ok(SessionRow {
                session_id:        row.get(0)?,
                role:              row.get(1)?,  // mapped from role_id column
                session_token:     row.get(2)?,
                sequence_number:   row.get(3)?,
                worktree_root:     row.get(4)?,
                base_sha:          row.get(5)?,
                base_tracking_ref: row.get(6)?,
                lineage_id:        row.get(7)?,
                revoked_at:        row.get(8)?,
                expires_at:        row.get(9)?,
            })
        },
    ).map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => AuthorityError::SessionNotFound,
        other => AuthorityError::Store(raxis_store::StoreError::Rusqlite(other)),
    })?;

    // DDL Table 4: revoked INTEGER (0/1 flag) + revoked_at (nullable timestamp).
    // Check both: revoked=1 is the gate; revoked_at carries the time.
    if row.revoked_at.is_some() {
        return Err(AuthorityError::SessionRevoked { revoked_at: row.revoked_at.unwrap_or(0) });
    }
    if row.expires_at < now_unix_secs() {
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
pub fn get_session_by_token(session_token: &str, store: &Store) -> Result<SessionRow, AuthorityError> {
    let conn = store.lock_sync();
    conn.query_row(
        "SELECT session_id, role_id, session_token, sequence_number,
                worktree_root, base_sha, base_tracking_ref,
                lineage_id, revoked_at, expires_at
         FROM sessions WHERE session_token = ?1",
        rusqlite::params![session_token],
        |row| Ok(SessionRow {
            session_id:        row.get(0)?,
            role:              row.get(1)?,  // mapped from role_id column
            session_token:     row.get(2)?,
            sequence_number:   row.get(3)?,
            worktree_root:     row.get(4)?,
            base_sha:          row.get(5)?,
            base_tracking_ref: row.get(6)?,
            lineage_id:        row.get(7)?,
            revoked_at:        row.get(8)?,
            expires_at:        row.get(9)?,
        }),
    ).map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => AuthorityError::SessionNotFound,
        other => AuthorityError::Store(raxis_store::StoreError::Rusqlite(other)),
    })
}

/// Revoke a session by setting `revoked=1, revoked_at=now()`.
///
/// DDL Table 4: revoked INTEGER NOT NULL DEFAULT 0, revoked_at INTEGER (nullable).
/// Uses conditional UPDATE WHERE revoked=0 (INV-STORE-02) to prevent double-revocation races.
pub fn revoke_session(session_id: &SessionId, store: &Store) -> Result<(), AuthorityError> {
    let now = now_unix_secs();
    let store = store.lock_sync();
    let rows = store.execute(
        "UPDATE sessions SET revoked=1, revoked_at=?1 WHERE session_id=?2 AND revoked=0",
        rusqlite::params![now, session_id.as_str()],
    ).map_err(|e| AuthorityError::Store(raxis_store::StoreError::Rusqlite(e)))?;

    if rows == 0 {
        Err(AuthorityError::SessionRevoked { revoked_at: now })
    } else {
        Ok(())
    }
}

/// Atomically advance the sequence number for a session.
///
/// Spec note: in the IPC path, auth.rs does this inside the nonce_cache INSERT
/// transaction. This function is retained as a store-level utility for test
/// harnesses and crash-recovery reconciliation (kernel-core.md §2.3).
pub fn update_sequence_number(
    session_id: &SessionId,
    expected_current: i64,
    store: &Store,
) -> Result<(), AuthorityError> {
    let store = store.lock_sync();
    let rows = store.execute(
        "UPDATE sessions SET sequence_number = ?1
         WHERE session_id = ?2 AND sequence_number = ?3",
        rusqlite::params![expected_current + 1, session_id.as_str(), expected_current],
    ).map_err(|e| AuthorityError::Store(raxis_store::StoreError::Rusqlite(e)))?;

    if rows == 0 {
        Err(AuthorityError::SequenceMismatch)
    } else {
        Ok(())
    }
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
