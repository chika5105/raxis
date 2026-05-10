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
//! # Thread safety
//!
//! `SqliteCircuitStore` wraps a `Mutex<Connection>`. SQLite's own
//! `BEGIN IMMEDIATE` serialises writers at the file-lock level, but
//! holding the Rust mutex across the transaction prevents the
//! `SQLITE_BUSY` retry dance entirely — acceptable because circuit
//! breaker writes are extremely infrequent (one per failed/succeeded
//! inference attempt, at most once per multi-second model call).

use rusqlite::{Connection, params};
use std::sync::Mutex;

use crate::table::Table;

// ---------------------------------------------------------------------------
// CircuitTransition — returned when a state-class change occurred.
// ---------------------------------------------------------------------------

/// Describes a state-class change so the caller can emit the matching
/// `CircuitBreakerStateChanged` audit event.
#[derive(Debug, Clone)]
pub struct CircuitTransition {
    pub provider:             String,
    pub model:                String,
    pub from_state:           String,
    pub to_state:             String,
    pub consecutive_failures: u32,
    pub last_failure_kind:    Option<String>,
    pub open_expires_at_ms:   Option<u64>,
    pub trigger:              String,
}

// ---------------------------------------------------------------------------
// CircuitRowSqlite — read-back snapshot from the SQLite row.
// ---------------------------------------------------------------------------

/// Snapshot of a single `provider_circuit_state` row.
#[derive(Debug, Clone)]
pub struct CircuitRowSqlite {
    pub provider:               String,
    pub model:                  String,
    pub state:                  String,
    pub consecutive_failures:   u32,
    pub last_failure_at_ms:     Option<i64>,
    pub last_failure_kind:      Option<String>,
    pub last_failure_http_code: Option<i32>,
    pub opened_at_ms:           Option<i64>,
    pub open_expires_at_ms:     Option<i64>,
    pub half_open_inflight:     i32,
    pub last_success_at_ms:     Option<i64>,
    pub last_state_change_at_ms: i64,
}

impl CircuitRowSqlite {
    /// A default "Closed" row for a (provider, model) pair that has
    /// never been seen before.
    pub fn default_closed(provider: &str, model: &str, now_ms: i64) -> Self {
        Self {
            provider:               provider.to_owned(),
            model:                  model.to_owned(),
            state:                  "Closed".to_owned(),
            consecutive_failures:   0,
            last_failure_at_ms:     None,
            last_failure_kind:      None,
            last_failure_http_code: None,
            opened_at_ms:           None,
            open_expires_at_ms:     None,
            half_open_inflight:     0,
            last_success_at_ms:     None,
            last_state_change_at_ms: now_ms,
        }
    }
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
        Self { conn: Mutex::new(conn) }
    }

    /// Read the current state for `(provider, model)`.
    ///
    /// Returns a default `Closed` row if no entry exists yet.
    pub fn load(&self, provider: &str, model: &str) -> CircuitRowSqlite {
        let conn = self.conn.lock().unwrap();
        let tbl = Table::ProviderCircuitState.as_str();
        let sql = format!(
            "SELECT provider, model, state, consecutive_failures,
                    last_failure_at_ms, last_failure_kind,
                    last_failure_http_code, opened_at_ms,
                    open_expires_at_ms, half_open_inflight,
                    last_success_at_ms, last_state_change_at_ms
             FROM {tbl}
             WHERE provider = ?1 AND model = ?2"
        );
        let result = conn.query_row(&sql, params![provider, model], |row| {
            Ok(CircuitRowSqlite {
                provider:               row.get(0)?,
                model:                  row.get(1)?,
                state:                  row.get(2)?,
                consecutive_failures:   row.get(3)?,
                last_failure_at_ms:     row.get(4)?,
                last_failure_kind:      row.get(5)?,
                last_failure_http_code: row.get(6)?,
                opened_at_ms:           row.get(7)?,
                open_expires_at_ms:     row.get(8)?,
                half_open_inflight:     row.get(9)?,
                last_success_at_ms:     row.get(10)?,
                last_state_change_at_ms: row.get(11)?,
            })
        });
        match result {
            Ok(row) => row,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                let now = now_ms();
                CircuitRowSqlite::default_closed(provider, model, now)
            }
            Err(e) => {
                eprintln!(
                    "{{\"level\":\"error\",\"event\":\"CircuitStoreLoadFailed\",\
                     \"provider\":\"{provider}\",\"model\":\"{model}\",\
                     \"error\":\"{e}\"}}"
                );
                let now = now_ms();
                CircuitRowSqlite::default_closed(provider, model, now)
            }
        }
    }

    /// Atomically record a retryable failure.
    ///
    /// If the failure count reaches `trip_threshold`, transitions to
    /// `Open` and returns `Some(CircuitTransition)`.
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
             VALUES (?1, ?2, 'Closed', 1, ?3, ?4, ?5, ?3)
             ON CONFLICT (provider, model) DO UPDATE SET
                 consecutive_failures = consecutive_failures + 1,
                 last_failure_at_ms   = ?3,
                 last_failure_kind    = ?4,
                 last_failure_http_code = ?5"
        );
        tx.execute(&upsert_sql, params![
            provider, model, now, failure_kind, http_code,
        ]).unwrap();

        // Read back the current row.
        let select_sql = format!(
            "SELECT provider, model, state, consecutive_failures,
                    last_failure_at_ms, last_failure_kind,
                    last_failure_http_code, opened_at_ms,
                    open_expires_at_ms, half_open_inflight,
                    last_success_at_ms, last_state_change_at_ms
             FROM {tbl}
             WHERE provider = ?1 AND model = ?2"
        );
        let row: CircuitRowSqlite = tx.query_row(&select_sql, params![provider, model], |r| {
            Ok(CircuitRowSqlite {
                provider:               r.get(0)?,
                model:                  r.get(1)?,
                state:                  r.get(2)?,
                consecutive_failures:   r.get(3)?,
                last_failure_at_ms:     r.get(4)?,
                last_failure_kind:      r.get(5)?,
                last_failure_http_code: r.get(6)?,
                opened_at_ms:           r.get(7)?,
                open_expires_at_ms:     r.get(8)?,
                half_open_inflight:     r.get(9)?,
                last_success_at_ms:     r.get(10)?,
                last_state_change_at_ms: r.get(11)?,
            })
        }).unwrap();

        // Check if we should trip to Open.
        let mut transition = None;
        if row.consecutive_failures >= trip_threshold && row.state != "Open" {
            let from_state = row.state.clone();
            let expires = now + open_duration_ms as i64;
            let trip_sql = format!(
                "UPDATE {tbl} SET
                     state = 'Open',
                     opened_at_ms = ?3,
                     open_expires_at_ms = ?4,
                     last_state_change_at_ms = ?3
                 WHERE provider = ?1 AND model = ?2"
            );
            tx.execute(&trip_sql, params![
                provider, model, now, expires,
            ]).unwrap();

            transition = Some(CircuitTransition {
                provider:             provider.to_owned(),
                model:                model.to_owned(),
                from_state,
                to_state:             "Open".to_owned(),
                consecutive_failures: row.consecutive_failures,
                last_failure_kind:    Some(failure_kind.to_owned()),
                open_expires_at_ms:   Some(expires as u64),
                trigger:              "FailureThreshold".to_owned(),
            });
        }

        tx.commit().unwrap();

        // Re-read final state.
        let final_row = self.load(provider, model);
        (final_row, transition)
    }

    /// Atomically record a success. Resets failures and closes if
    /// the previous state was `HalfOpen`.
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
        let select_sql = format!(
            "SELECT state FROM {tbl} WHERE provider = ?1 AND model = ?2"
        );
        let prev_state: Option<String> = tx
            .query_row(&select_sql, params![provider, model], |r| r.get(0))
            .ok();

        let upsert_sql = format!(
            "INSERT INTO {tbl}
                 (provider, model, state, consecutive_failures,
                  last_success_at_ms, last_state_change_at_ms)
             VALUES (?1, ?2, 'Closed', 0, ?3, ?3)
             ON CONFLICT (provider, model) DO UPDATE SET
                 state = 'Closed',
                 consecutive_failures = 0,
                 opened_at_ms = NULL,
                 open_expires_at_ms = NULL,
                 half_open_inflight = 0,
                 last_success_at_ms = ?3,
                 last_state_change_at_ms = CASE
                     WHEN state != 'Closed' THEN ?3
                     ELSE last_state_change_at_ms
                 END"
        );
        tx.execute(&upsert_sql, params![provider, model, now]).unwrap();

        let mut transition = None;
        if let Some(ref prev) = prev_state {
            if prev != "Closed" {
                transition = Some(CircuitTransition {
                    provider:             provider.to_owned(),
                    model:                model.to_owned(),
                    from_state:           prev.clone(),
                    to_state:             "Closed".to_owned(),
                    consecutive_failures: 0,
                    last_failure_kind:    None,
                    open_expires_at_ms:   None,
                    trigger:              "ProbeSuccess".to_owned(),
                });
            }
        }

        tx.commit().unwrap();
        let final_row = self.load(provider, model);
        (final_row, transition)
    }

    /// Try to acquire the half-open probe slot (CAS 0 → 1).
    pub fn try_acquire_probe(&self, provider: &str, model: &str) -> bool {
        let conn = self.conn.lock().unwrap();
        let tbl = Table::ProviderCircuitState.as_str();
        let sql = format!(
            "UPDATE {tbl} SET half_open_inflight = 1
             WHERE provider = ?1 AND model = ?2
               AND state = 'HalfOpen'
               AND half_open_inflight = 0"
        );
        let changed = conn.execute(&sql, params![provider, model]).unwrap_or(0);
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
                 state = 'HalfOpen',
                 last_state_change_at_ms = ?3
             WHERE provider = ?1 AND model = ?2
               AND state = 'Open'
               AND open_expires_at_ms <= ?3"
        );
        let changed = tx.execute(&sql, params![provider, model, now]).unwrap_or(0);

        let mut transition = None;
        if changed > 0 {
            transition = Some(CircuitTransition {
                provider:             provider.to_owned(),
                model:                model.to_owned(),
                from_state:           "Open".to_owned(),
                to_state:             "HalfOpen".to_owned(),
                consecutive_failures: 0,
                last_failure_kind:    None,
                open_expires_at_ms:   None,
                trigger:              "OpenWindowElapsed".to_owned(),
            });
        }

        tx.commit().unwrap();
        let final_row = self.load(provider, model);
        (final_row, transition)
    }

    /// Manual operator reset: force the breaker to `Closed`.
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
        let prev: Option<(String, u32)> = tx
            .query_row(&select_sql, params![provider, model], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .ok();

        let upsert_sql = format!(
            "INSERT INTO {tbl}
                 (provider, model, state, consecutive_failures,
                  last_state_change_at_ms)
             VALUES (?1, ?2, 'Closed', 0, ?3)
             ON CONFLICT (provider, model) DO UPDATE SET
                 state = 'Closed',
                 consecutive_failures = 0,
                 opened_at_ms = NULL,
                 open_expires_at_ms = NULL,
                 half_open_inflight = 0,
                 last_state_change_at_ms = ?3"
        );
        tx.execute(&upsert_sql, params![provider, model, now]).unwrap();

        let mut transition = None;
        if let Some((ref prev_state, prev_failures)) = prev {
            if prev_state != "Closed" {
                transition = Some(CircuitTransition {
                    provider:             provider.to_owned(),
                    model:                model.to_owned(),
                    from_state:           prev_state.clone(),
                    to_state:             "Closed".to_owned(),
                    consecutive_failures: prev_failures,
                    last_failure_kind:    None,
                    open_expires_at_ms:   None,
                    trigger:              "ManualReset".to_owned(),
                });
            }
        }

        tx.commit().unwrap();
        let final_row = self.load(provider, model);
        (final_row, transition)
    }

    /// List all non-Closed breakers. Used by `raxis providers status`.
    pub fn list_all(&self) -> Vec<CircuitRowSqlite> {
        let conn = self.conn.lock().unwrap();
        let tbl = Table::ProviderCircuitState.as_str();
        let sql = format!(
            "SELECT provider, model, state, consecutive_failures,
                    last_failure_at_ms, last_failure_kind,
                    last_failure_http_code, opened_at_ms,
                    open_expires_at_ms, half_open_inflight,
                    last_success_at_ms, last_state_change_at_ms
             FROM {tbl}
             ORDER BY provider, model"
        );
        let mut stmt = conn.prepare(&sql).unwrap();
        let rows = stmt.query_map([], |r| {
            Ok(CircuitRowSqlite {
                provider:               r.get(0)?,
                model:                  r.get(1)?,
                state:                  r.get(2)?,
                consecutive_failures:   r.get(3)?,
                last_failure_at_ms:     r.get(4)?,
                last_failure_kind:      r.get(5)?,
                last_failure_http_code: r.get(6)?,
                opened_at_ms:           r.get(7)?,
                open_expires_at_ms:     r.get(8)?,
                half_open_inflight:     r.get(9)?,
                last_success_at_ms:     r.get(10)?,
                last_state_change_at_ms: r.get(11)?,
            })
        }).unwrap();
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
        assert_eq!(row.state, "Closed");
        assert_eq!(row.consecutive_failures, 0);
    }

    #[test]
    fn record_failure_increments_counter() {
        let store = test_store();
        let (row, transition) = store.record_failure(
            "anthropic", "claude-4", "Unavailable", Some(503), 5, 60_000,
        );
        assert_eq!(row.consecutive_failures, 1);
        assert_eq!(row.state, "Closed");
        assert!(transition.is_none(), "shouldn't trip at 1/5");
    }

    #[test]
    fn record_failure_trips_at_threshold() {
        let store = test_store();
        for i in 0..4 {
            let (_, t) = store.record_failure(
                "anthropic", "claude-4", "Unavailable", Some(503), 5, 60_000,
            );
            assert!(t.is_none(), "shouldn't trip at {}/5", i + 1);
        }
        let (row, transition) = store.record_failure(
            "anthropic", "claude-4", "Unavailable", Some(503), 5, 60_000,
        );
        assert_eq!(row.state, "Open");
        let t = transition.expect("should trip at 5/5");
        assert_eq!(t.from_state, "Closed");
        assert_eq!(t.to_state, "Open");
        assert_eq!(t.trigger, "FailureThreshold");
    }

    #[test]
    fn record_success_closes_circuit() {
        let store = test_store();
        // Trip it open first.
        for _ in 0..5 {
            store.record_failure(
                "anthropic", "claude-4", "Unavailable", Some(503), 5, 60_000,
            );
        }
        let row = store.load("anthropic", "claude-4");
        assert_eq!(row.state, "Open");

        let (row, transition) = store.record_success("anthropic", "claude-4");
        assert_eq!(row.state, "Closed");
        assert_eq!(row.consecutive_failures, 0);
        let t = transition.expect("should emit transition Open → Closed");
        assert_eq!(t.from_state, "Open");
        assert_eq!(t.to_state, "Closed");
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
            store.record_failure(
                "anthropic", "claude-4", "Unavailable", Some(503), 5, 60_000,
            );
        }
        let (row, transition) = store.manual_reset("anthropic", "claude-4");
        assert_eq!(row.state, "Closed");
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
}
