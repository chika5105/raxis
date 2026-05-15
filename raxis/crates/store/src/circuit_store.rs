//! `SqliteCircuitStore` — persistent circuit-breaker state backed by
//! `kernel.db`'s `provider_circuit_state` table (migration 15,
//! `provider-failure-handling.md §6.4`).
//!
//! Every state mutation executes inside a single `BEGIN IMMEDIATE`
//! transaction. The caller is responsible for also inserting the
//! `CircuitBreakerStateChanged` audit event inside the same
//! transaction (INV-PROVIDER-08) — the `transition_in_tx` helper
//! returns a `CircuitTransition` struct when a state-class change
//! occurred, giving the caller all the fields it needs to construct
//! the audit event.
//!
//! # Type-safe state values
//!
//! All SQL column values for `state` come from
//! `CircuitBreakerState::as_sql_str()` — there is exactly one source
//! of truth (the enum in `raxis-types::fsm`). No hardcoded state
//! strings appear anywhere in this module.
//!
//! # Thread safety
//!
//! `SqliteCircuitStore` wraps a `Mutex<Connection>`. SQLite's own
//! `BEGIN IMMEDIATE` serialises writers at the file-lock level, but
//! holding the Rust mutex across the transaction prevents the
//! `SQLITE_BUSY` retry dance entirely — acceptable because circuit
//! breaker writes are extremely infrequent (one per failed/succeeded
//! inference attempt, at most once per multi-second model call).
//!
//! ## Lock contract (single-lock-per-operation)
//!
//! Every public method on this store acquires `self.conn` **exactly
//! once** for the full duration of the operation:
//!
//! - `load`, `list_all`, `try_acquire_probe`, `release_probe` each
//!   take a single read/write lock and release it on return.
//! - `record_failure`, `record_success`, `maybe_promote`,
//!   `manual_reset` each take **one** write lock that wraps the
//!   `BEGIN IMMEDIATE` transaction *and* the post-commit read-back.
//!   The post-commit read-back is performed via the private
//!   `load_with_conn(&Connection, …)` helper which reuses the
//!   already-held guard — `Mutex<Connection>` is **not** re-entrant
//!   on the same thread, so any attempt to re-lock from within a
//!   guarded scope (as the May-10 `8524f50` shape did via
//!   `self.load(...)`) parks the thread in `__psynch_mutexwait`.
//!
//! Public-API behaviour is unchanged; this is purely a deadlock
//! correctness contract.

use rusqlite::{params, Connection};
use std::sync::Mutex;

use raxis_types::CircuitBreakerState;

use crate::table::Table;

// Convenience aliases for the three state SQL strings.
fn closed_str() -> &'static str {
    CircuitBreakerState::Closed.as_sql_str()
}
fn open_str() -> &'static str {
    CircuitBreakerState::Open.as_sql_str()
}
fn half_open_str() -> &'static str {
    CircuitBreakerState::HalfOpen.as_sql_str()
}

// ---------------------------------------------------------------------------
// CircuitTransition — returned when a state-class change occurred.
// ---------------------------------------------------------------------------

/// Describes a state-class change so the caller can emit the matching
/// `CircuitBreakerStateChanged` audit event.
#[derive(Debug, Clone)]
pub struct CircuitTransition {
    pub provider: String,
    pub model: String,
    pub from_state: CircuitBreakerState,
    pub to_state: CircuitBreakerState,
    pub consecutive_failures: u32,
    pub last_failure_kind: Option<String>,
    pub open_expires_at_ms: Option<u64>,
    pub trigger: String,
}

// ---------------------------------------------------------------------------
// CircuitRowSqlite — read-back snapshot from the SQLite row.
// ---------------------------------------------------------------------------

/// Snapshot of a single `provider_circuit_state` row.
#[derive(Debug, Clone)]
pub struct CircuitRowSqlite {
    pub provider: String,
    pub model: String,
    pub state: CircuitBreakerState,
    pub consecutive_failures: u32,
    pub last_failure_at_ms: Option<i64>,
    pub last_failure_kind: Option<String>,
    pub last_failure_http_code: Option<i32>,
    pub opened_at_ms: Option<i64>,
    pub open_expires_at_ms: Option<i64>,
    pub half_open_inflight: i32,
    pub last_success_at_ms: Option<i64>,
    pub last_state_change_at_ms: i64,
}

impl CircuitRowSqlite {
    /// A default "Closed" row for a (provider, model) pair that has
    /// never been seen before.
    pub fn default_closed(provider: &str, model: &str, now_ms: i64) -> Self {
        Self {
            provider: provider.to_owned(),
            model: model.to_owned(),
            state: CircuitBreakerState::Closed,
            consecutive_failures: 0,
            last_failure_at_ms: None,
            last_failure_kind: None,
            last_failure_http_code: None,
            opened_at_ms: None,
            open_expires_at_ms: None,
            half_open_inflight: 0,
            last_success_at_ms: None,
            last_state_change_at_ms: now_ms,
        }
    }
}

/// Parse the SQL state string back to enum, defaulting to Closed
/// for any unrecognised value (defense-in-depth).
fn parse_state(s: &str) -> CircuitBreakerState {
    CircuitBreakerState::from_sql_str(s).unwrap_or(CircuitBreakerState::Closed)
}

/// Helper: read a row from a rusqlite row reference and parse state.
fn row_from_rusqlite(r: &rusqlite::Row<'_>) -> rusqlite::Result<CircuitRowSqlite> {
    let state_str: String = r.get(2)?;
    Ok(CircuitRowSqlite {
        provider: r.get(0)?,
        model: r.get(1)?,
        state: parse_state(&state_str),
        consecutive_failures: r.get(3)?,
        last_failure_at_ms: r.get(4)?,
        last_failure_kind: r.get(5)?,
        last_failure_http_code: r.get(6)?,
        opened_at_ms: r.get(7)?,
        open_expires_at_ms: r.get(8)?,
        half_open_inflight: r.get(9)?,
        last_success_at_ms: r.get(10)?,
        last_state_change_at_ms: r.get(11)?,
    })
}

/// The 12-column SELECT for reading circuit state rows.
fn select_columns(tbl: &str) -> String {
    format!(
        "SELECT provider, model, state, consecutive_failures,
                last_failure_at_ms, last_failure_kind,
                last_failure_http_code, opened_at_ms,
                open_expires_at_ms, half_open_inflight,
                last_success_at_ms, last_state_change_at_ms
         FROM {tbl}"
    )
}

// ---------------------------------------------------------------------------
// SqliteCircuitStore
// ---------------------------------------------------------------------------

/// Persistent circuit-breaker store backed by
/// `provider_circuit_state` in `kernel.db`.
pub struct SqliteCircuitStore {
    conn: Mutex<Connection>,
}

impl SqliteCircuitStore {
    /// Wrap an existing connection.
    ///
    /// The caller MUST have already applied migration 15 on `conn`.
    pub fn new(conn: Connection) -> Self {
        Self {
            conn: Mutex::new(conn),
        }
    }

    /// Read the current state for `(provider, model)`.
    ///
    /// Returns a default `Closed` row if no entry exists yet.
    ///
    /// Lock contract: acquires `self.conn` once for the duration of
    /// the read and releases it on return. Internal callers that
    /// already hold the guard MUST use `Self::load_with_conn` to
    /// avoid re-entering the non-reentrant `Mutex<Connection>`.
    pub fn load(&self, provider: &str, model: &str) -> CircuitRowSqlite {
        let conn = self.conn.lock().unwrap();
        Self::load_with_conn(&conn, provider, model)
    }

    /// Read the current state using an already-held connection.
    ///
    /// Internal helper used by mutating methods after they commit
    /// their transaction but while still holding `self.conn`. The
    /// public [`Self::load`] wraps this with a single lock
    /// acquisition; mutating sites call this directly so the read
    /// reuses the outer guard (one lock per public operation).
    fn load_with_conn(conn: &Connection, provider: &str, model: &str) -> CircuitRowSqlite {
        let tbl = Table::ProviderCircuitState.as_str();
        let sql = format!("{} WHERE provider = ?1 AND model = ?2", select_columns(tbl),);
        let result = conn.query_row(&sql, params![provider, model], row_from_rusqlite);
        match result {
            Ok(row) => row,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                CircuitRowSqlite::default_closed(provider, model, now_ms())
            }
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"CircuitStoreLoadFailed\",\
                     \"provider\":\"{provider}\",\"model\":\"{model}\",\
                     \"error\":\"{e}\"}}"
                );
                CircuitRowSqlite::default_closed(provider, model, now_ms())
            }
        }
    }

    /// Atomically record a retryable failure.
    ///
    /// If the failure count reaches `trip_threshold`, transitions to
    /// `Open` and returns `Some(CircuitTransition)`.
    ///
    /// Lock contract: acquires `self.conn` **once** for the
    /// `BEGIN IMMEDIATE` transaction *and* the post-commit
    /// read-back; the read-back uses `Self::load_with_conn` to
    /// reuse the outer guard (the underlying `Mutex<Connection>`
    /// is not re-entrant on the same thread).
    pub fn record_failure(
        &self,
        provider: &str,
        model: &str,
        failure_kind: &str,
        http_code: Option<i32>,
        trip_threshold: u32,
        open_duration_ms: u64,
    ) -> (CircuitRowSqlite, Option<CircuitTransition>) {
        let mut conn = self.conn.lock().unwrap();
        let tbl = Table::ProviderCircuitState.as_str();
        let now = now_ms();
        let tx = conn.transaction().unwrap();

        // Upsert: increment consecutive_failures, stamp failure details.
        let upsert_sql = format!(
            "INSERT INTO {tbl}
                 (provider, model, state, consecutive_failures,
                  last_failure_at_ms, last_failure_kind,
                  last_failure_http_code, last_state_change_at_ms)
             VALUES (?1, ?2, ?6, 1, ?3, ?4, ?5, ?3)
             ON CONFLICT (provider, model) DO UPDATE SET
                 consecutive_failures = consecutive_failures + 1,
                 last_failure_at_ms   = ?3,
                 last_failure_kind    = ?4,
                 last_failure_http_code = ?5"
        );
        tx.execute(
            &upsert_sql,
            params![provider, model, now, failure_kind, http_code, closed_str(),],
        )
        .unwrap();

        // Read back the current row.
        let select_sql = format!("{} WHERE provider = ?1 AND model = ?2", select_columns(tbl),);
        let row: CircuitRowSqlite = tx
            .query_row(&select_sql, params![provider, model], row_from_rusqlite)
            .unwrap();

        // Check if we should trip to Open.
        let mut transition = None;
        if row.consecutive_failures >= trip_threshold && row.state != CircuitBreakerState::Open {
            let from_state = row.state;
            let expires = now + open_duration_ms as i64;
            let trip_sql = format!(
                "UPDATE {tbl} SET
                     state = ?3,
                     opened_at_ms = ?4,
                     open_expires_at_ms = ?5,
                     last_state_change_at_ms = ?4
                 WHERE provider = ?1 AND model = ?2"
            );
            tx.execute(
                &trip_sql,
                params![provider, model, open_str(), now, expires,],
            )
            .unwrap();

            transition = Some(CircuitTransition {
                provider: provider.to_owned(),
                model: model.to_owned(),
                from_state,
                to_state: CircuitBreakerState::Open,
                consecutive_failures: row.consecutive_failures,
                last_failure_kind: Some(failure_kind.to_owned()),
                open_expires_at_ms: Some(expires as u64),
                trigger: "FailureThreshold".to_owned(),
            });
        }

        tx.commit().unwrap();

        // Re-read final state using the still-held guard.
        let final_row = Self::load_with_conn(&conn, provider, model);
        (final_row, transition)
    }

    /// Atomically record a success. Resets failures and closes if
    /// the previous state was `HalfOpen`.
    ///
    /// Lock contract: acquires `self.conn` **once** for the
    /// transaction and the post-commit read-back (see
    /// `record_failure` for the rationale).
    pub fn record_success(
        &self,
        provider: &str,
        model: &str,
    ) -> (CircuitRowSqlite, Option<CircuitTransition>) {
        let mut conn = self.conn.lock().unwrap();
        let tbl = Table::ProviderCircuitState.as_str();
        let now = now_ms();
        let tx = conn.transaction().unwrap();

        // Read current state first.
        let select_sql = format!("SELECT state FROM {tbl} WHERE provider = ?1 AND model = ?2");
        let prev_state: Option<CircuitBreakerState> = tx
            .query_row(&select_sql, params![provider, model], |r| {
                let s: String = r.get(0)?;
                Ok(parse_state(&s))
            })
            .ok();

        let upsert_sql = format!(
            "INSERT INTO {tbl}
                 (provider, model, state, consecutive_failures,
                  last_success_at_ms, last_state_change_at_ms)
             VALUES (?1, ?2, ?3, 0, ?4, ?4)
             ON CONFLICT (provider, model) DO UPDATE SET
                 state = ?3,
                 consecutive_failures = 0,
                 opened_at_ms = NULL,
                 open_expires_at_ms = NULL,
                 half_open_inflight = 0,
                 last_success_at_ms = ?4,
                 last_state_change_at_ms = CASE
                     WHEN state != ?3 THEN ?4
                     ELSE last_state_change_at_ms
                 END"
        );
        tx.execute(&upsert_sql, params![provider, model, closed_str(), now,])
            .unwrap();

        let mut transition = None;
        if let Some(prev) = prev_state {
            if prev != CircuitBreakerState::Closed {
                transition = Some(CircuitTransition {
                    provider: provider.to_owned(),
                    model: model.to_owned(),
                    from_state: prev,
                    to_state: CircuitBreakerState::Closed,
                    consecutive_failures: 0,
                    last_failure_kind: None,
                    open_expires_at_ms: None,
                    trigger: "ProbeSuccess".to_owned(),
                });
            }
        }

        tx.commit().unwrap();
        let final_row = Self::load_with_conn(&conn, provider, model);
        (final_row, transition)
    }

    /// Try to acquire the half-open probe slot (CAS 0 → 1).
    pub fn try_acquire_probe(&self, provider: &str, model: &str) -> bool {
        let conn = self.conn.lock().unwrap();
        let tbl = Table::ProviderCircuitState.as_str();
        let sql = format!(
            "UPDATE {tbl} SET half_open_inflight = 1
             WHERE provider = ?1 AND model = ?2
               AND state = ?3
               AND half_open_inflight = 0"
        );
        let changed = conn
            .execute(&sql, params![provider, model, half_open_str(),])
            .unwrap_or(0);
        changed > 0
    }

    /// Release the half-open probe slot.
    pub fn release_probe(&self, provider: &str, model: &str) {
        let conn = self.conn.lock().unwrap();
        let tbl = Table::ProviderCircuitState.as_str();
        let sql = format!(
            "UPDATE {tbl} SET half_open_inflight = 0
             WHERE provider = ?1 AND model = ?2"
        );
        let _ = conn.execute(&sql, params![provider, model]);
    }

    /// Lazily promote `Open → HalfOpen` if the open window has elapsed.
    ///
    /// Lock contract: acquires `self.conn` **once** for the
    /// transaction and the post-commit read-back (see
    /// `record_failure` for the rationale).
    pub fn maybe_promote(
        &self,
        provider: &str,
        model: &str,
    ) -> (CircuitRowSqlite, Option<CircuitTransition>) {
        let mut conn = self.conn.lock().unwrap();
        let tbl = Table::ProviderCircuitState.as_str();
        let now = now_ms();
        let tx = conn.transaction().unwrap();

        let sql = format!(
            "UPDATE {tbl} SET
                 state = ?3,
                 last_state_change_at_ms = ?4
             WHERE provider = ?1 AND model = ?2
               AND state = ?5
               AND open_expires_at_ms <= ?4"
        );
        let changed = tx
            .execute(
                &sql,
                params![provider, model, half_open_str(), now, open_str(),],
            )
            .unwrap_or(0);

        let mut transition = None;
        if changed > 0 {
            transition = Some(CircuitTransition {
                provider: provider.to_owned(),
                model: model.to_owned(),
                from_state: CircuitBreakerState::Open,
                to_state: CircuitBreakerState::HalfOpen,
                consecutive_failures: 0,
                last_failure_kind: None,
                open_expires_at_ms: None,
                trigger: "OpenWindowElapsed".to_owned(),
            });
        }

        tx.commit().unwrap();
        let final_row = Self::load_with_conn(&conn, provider, model);
        (final_row, transition)
    }

    /// Manual operator reset: force the breaker to `Closed`.
    ///
    /// Lock contract: acquires `self.conn` **once** for the
    /// transaction and the post-commit read-back (see
    /// `record_failure` for the rationale).
    pub fn manual_reset(
        &self,
        provider: &str,
        model: &str,
    ) -> (CircuitRowSqlite, Option<CircuitTransition>) {
        let mut conn = self.conn.lock().unwrap();
        let tbl = Table::ProviderCircuitState.as_str();
        let now = now_ms();
        let tx = conn.transaction().unwrap();

        // Read current state.
        let select_sql = format!(
            "SELECT state, consecutive_failures FROM {tbl}
             WHERE provider = ?1 AND model = ?2"
        );
        let prev: Option<(CircuitBreakerState, u32)> = tx
            .query_row(&select_sql, params![provider, model], |r| {
                let s: String = r.get(0)?;
                Ok((parse_state(&s), r.get(1)?))
            })
            .ok();

        let upsert_sql = format!(
            "INSERT INTO {tbl}
                 (provider, model, state, consecutive_failures,
                  last_state_change_at_ms)
             VALUES (?1, ?2, ?3, 0, ?4)
             ON CONFLICT (provider, model) DO UPDATE SET
                 state = ?3,
                 consecutive_failures = 0,
                 opened_at_ms = NULL,
                 open_expires_at_ms = NULL,
                 half_open_inflight = 0,
                 last_state_change_at_ms = ?4"
        );
        tx.execute(&upsert_sql, params![provider, model, closed_str(), now,])
            .unwrap();

        let mut transition = None;
        if let Some((prev_state, prev_failures)) = prev {
            if prev_state != CircuitBreakerState::Closed {
                transition = Some(CircuitTransition {
                    provider: provider.to_owned(),
                    model: model.to_owned(),
                    from_state: prev_state,
                    to_state: CircuitBreakerState::Closed,
                    consecutive_failures: prev_failures,
                    last_failure_kind: None,
                    open_expires_at_ms: None,
                    trigger: "ManualReset".to_owned(),
                });
            }
        }

        tx.commit().unwrap();
        let final_row = Self::load_with_conn(&conn, provider, model);
        (final_row, transition)
    }

    /// List all circuit breaker rows. Used by `raxis providers status`.
    ///
    /// Lock contract: acquires `self.conn` once for the duration of
    /// the read.
    pub fn list_all(&self) -> Vec<CircuitRowSqlite> {
        let conn = self.conn.lock().unwrap();
        let tbl = Table::ProviderCircuitState.as_str();
        let sql = format!("{} ORDER BY provider, model", select_columns(tbl),);
        let mut stmt = conn.prepare(&sql).unwrap();
        let rows = stmt.query_map([], row_from_rusqlite).unwrap();
        rows.filter_map(|r| r.ok()).collect()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::apply_pending;

    fn test_store() -> SqliteCircuitStore {
        let conn = Connection::open_in_memory().unwrap();
        apply_pending(&conn).unwrap();
        SqliteCircuitStore::new(conn)
    }

    #[test]
    fn load_returns_closed_for_unknown_provider() {
        let store = test_store();
        let row = store.load("anthropic", "claude-4");
        assert_eq!(row.state, CircuitBreakerState::Closed);
        assert_eq!(row.consecutive_failures, 0);
    }

    #[test]
    fn record_failure_increments_counter() {
        let store = test_store();
        let (row, transition) =
            store.record_failure("anthropic", "claude-4", "Unavailable", Some(503), 5, 60_000);
        assert_eq!(row.consecutive_failures, 1);
        assert_eq!(row.state, CircuitBreakerState::Closed);
        assert!(transition.is_none(), "shouldn't trip at 1/5");
    }

    #[test]
    fn record_failure_trips_at_threshold() {
        let store = test_store();
        for i in 0..4 {
            let (_, t) =
                store.record_failure("anthropic", "claude-4", "Unavailable", Some(503), 5, 60_000);
            assert!(t.is_none(), "shouldn't trip at {}/5", i + 1);
        }
        let (row, transition) =
            store.record_failure("anthropic", "claude-4", "Unavailable", Some(503), 5, 60_000);
        assert_eq!(row.state, CircuitBreakerState::Open);
        let t = transition.expect("should trip at 5/5");
        assert_eq!(t.from_state, CircuitBreakerState::Closed);
        assert_eq!(t.to_state, CircuitBreakerState::Open);
        assert_eq!(t.trigger, "FailureThreshold");
    }

    #[test]
    fn record_success_closes_circuit() {
        let store = test_store();
        // Trip it open first.
        for _ in 0..5 {
            store.record_failure("anthropic", "claude-4", "Unavailable", Some(503), 5, 60_000);
        }
        let row = store.load("anthropic", "claude-4");
        assert_eq!(row.state, CircuitBreakerState::Open);

        let (row, transition) = store.record_success("anthropic", "claude-4");
        assert_eq!(row.state, CircuitBreakerState::Closed);
        assert_eq!(row.consecutive_failures, 0);
        let t = transition.expect("should emit transition Open → Closed");
        assert_eq!(t.from_state, CircuitBreakerState::Open);
        assert_eq!(t.to_state, CircuitBreakerState::Closed);
    }

    #[test]
    fn try_acquire_probe_returns_false_when_not_half_open() {
        let store = test_store();
        assert!(!store.try_acquire_probe("anthropic", "claude-4"));
    }

    #[test]
    fn manual_reset_forces_closed() {
        let store = test_store();
        for _ in 0..5 {
            store.record_failure("anthropic", "claude-4", "Unavailable", Some(503), 5, 60_000);
        }
        let (row, transition) = store.manual_reset("anthropic", "claude-4");
        assert_eq!(row.state, CircuitBreakerState::Closed);
        assert_eq!(row.consecutive_failures, 0);
        let t = transition.expect("should emit ManualReset transition");
        assert_eq!(t.trigger, "ManualReset");
    }

    #[test]
    fn list_all_returns_all_providers() {
        let store = test_store();
        // Trip two providers.
        for _ in 0..5 {
            store.record_failure("anthropic", "claude-4", "Unavailable", Some(503), 5, 60_000);
        }
        for _ in 0..5 {
            store.record_failure("openai", "gpt-5", "Timeout", None, 5, 60_000);
        }
        let all = store.list_all();
        assert_eq!(all.len(), 2);
        assert!(all.iter().any(|r| r.provider == "anthropic"));
        assert!(all.iter().any(|r| r.provider == "openai"));
    }

    /// Ensure the SQL strings used by the store are exactly the
    /// canonical enum values — no hardcoded strings.
    #[test]
    fn state_strings_come_from_enum() {
        assert_eq!(closed_str(), "Closed");
        assert_eq!(open_str(), "Open");
        assert_eq!(half_open_str(), "HalfOpen");
    }
}
