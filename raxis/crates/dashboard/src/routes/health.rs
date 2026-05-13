//! `GET /api/health` — kernel health snapshot.
//! `GET /api/health/subsystems` — per-subsystem health cards.
//! `GET /api/health/kernel-lifecycle` — supervisor sentinel view.
//!
//! Spec §4.2 grants the `admin` role to read `/api/health`
//! because the kernel-health surface contains operational
//! metadata (active session counts, doctor-style checks). All
//! other operators get a sanitized `{ status: "ok" }` shape.
//!
//! The subsystem-health surface gates on `read` like every
//! other privileged-read view, and emits an
//! `OperatorHealthQueried` audit event per
//! `INV-AUDIT-OPERATOR-ACTION-01`. Verdicts come from the
//! kernel's own bookkeeping — the dashboard never invents a
//! status (`INV-DASHBOARD-VALIDATE-01`).
//!
//! V2.5 `self-healing-supervisor.md §5.2`: the kernel-lifecycle
//! handler reads the supervisor's atomic sentinel file
//! (`<data_dir>/kernel_lifecycle_status.json`) and returns it
//! as a typed JSON response with a `fresh` flag for staleness.
//! Missing file ⇒ `{ status: "Healthy", fresh: true }` (the
//! supervisor isn't in play; kernel running directly is healthy
//! by definition since this very handler is responding). Stale
//! file (older than 2× window) AND supervisor PID gone ⇒
//! `{ status: "Halted", sub_state: "SupervisorGone", fresh: false }`.

use std::path::PathBuf;

use axum::extract::State;
use axum::Json;
use raxis_audit_tools::AuditEventKind;
use serde::Serialize;

use crate::auth::DashboardRole;
use crate::data::{operator_outcome, HealthSnapshot, SubsystemHealthResponse};
use crate::error::{ApiError, ApiResult};
use crate::server::{AppState, AuthorizedOperator};

/// `GET /api/health` — full health snapshot for `admin` operators,
/// sanitized snapshot for everyone else.
pub async fn health<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
) -> ApiResult<Json<HealthSnapshot>>
where
    D: crate::data::DashboardData,
{
    let full = state.data.health();
    if op.has_role(DashboardRole::Admin) {
        return Ok(Json(full));
    }
    if !op.has_role(DashboardRole::Read) {
        return Err(ApiError::Forbidden { required: "read".into() });
    }
    // Sanitize for non-admins: keep the coarse status + active
    // counts, drop the per-check details.
    Ok(Json(HealthSnapshot {
        status: full.status,
        checks: vec![],
        kernel_booted_at: full.kernel_booted_at,
        policy_epoch: full.policy_epoch,
        active_initiatives: full.active_initiatives,
        active_sessions: full.active_sessions,
        pending_escalations: full.pending_escalations,
    }))
}

/// `GET /api/health/subsystems` — per-subsystem cards for the
/// dashboard Health tab. Honours `INV-AUDIT-OPERATOR-ACTION-01`
/// (audit emit on success and on each rejection path) and
/// `INV-DASHBOARD-VALIDATE-01` (validate auth + permission
/// before any privileged read).
pub async fn subsystems<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
) -> ApiResult<Json<SubsystemHealthResponse>>
where
    D: crate::data::DashboardData,
{
    if !op.has_role(DashboardRole::Read) {
        let err = ApiError::Forbidden { required: "read".into() };
        emit_health_audit(
            &*state.data,
            &op,
            operator_outcome::outcome_from_api_error(&err),
        );
        return Err(err);
    }
    let snapshot = match state.data.subsystem_health() {
        Ok(s) => s,
        Err(err) => {
            emit_health_audit(
                &*state.data,
                &op,
                operator_outcome::outcome_from_api_error(&err),
            );
            return Err(err);
        }
    };
    state
        .data
        .emit_operator_audit(AuditEventKind::OperatorHealthQueried {
            operator_fingerprint: op.fingerprint.clone(),
            outcome:              operator_outcome::ACCEPTED.into(),
        })?;
    Ok(Json(snapshot))
}

fn emit_health_audit<D>(data: &D, op: &AuthorizedOperator, outcome: &'static str)
where
    D: crate::data::DashboardData + ?Sized,
{
    let _ = data.emit_operator_audit(AuditEventKind::OperatorHealthQueried {
        operator_fingerprint: op.fingerprint.clone(),
        outcome:              outcome.into(),
    });
}

// ---------------------------------------------------------------------------
// V2.5 self-healing-supervisor.md §5.2 — kernel-lifecycle handler.
// ---------------------------------------------------------------------------

/// Wire-pinned response shape for `GET /api/health/kernel-lifecycle`.
///
/// Mirrors the on-disk sentinel file the `raxis-supervisor`
/// writes (`crates/supervisor::sentinel::Sentinel`) plus a
/// `fresh` boolean the dashboard handler synthesises from
/// staleness detection. The FE matches on `status` +
/// `sub_state` to render the banner; every field is optional
/// so the same shape survives a missing or partial sentinel.
#[derive(Debug, Clone, Serialize)]
pub struct KernelLifecycleResponse {
    /// `Healthy` / `Restarting` / `Halted`. Always set.
    pub status: String,
    /// Sub-state for `Halted` (`CircuitOpen` / `OperatorStop`
    /// / `OperatorStopForced` / `SupervisorGone`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_state: Option<String>,
    /// 1-indexed restart attempt within the current window.
    pub attempt_n: u32,
    /// Operator-policy ceiling at the time of the most recent
    /// restart.
    pub max_attempts: u32,
    /// PascalCase reason for the most recent restart, mirrors
    /// `Outcome::reason_str()` in the supervisor crate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_restart_reason: Option<String>,
    /// Unix-seconds of the most recent restart attempt.
    pub last_restart_unix_ts: i64,
    /// Restart attempts inside the trailing window.
    pub attempts_in_window: u32,
    /// Sliding-window width (seconds).
    pub window_secs: u32,
    /// Supervisor process PID. `0` ⇒ no supervisor in play.
    pub supervisor_pid: u32,
    /// Currently-spawned kernel process PID. `0` ⇒ no kernel.
    pub kernel_pid: u32,
    /// Wallclock unix-seconds of the most recent sentinel write.
    pub updated_at_unix_secs: i64,
    /// `true` iff the sentinel file exists AND its
    /// `updated_at_unix_secs` is within `2 * window_secs` of
    /// now AND the supervisor PID is alive (or zero, indicating
    /// no supervisor is in play). The dashboard banner uses
    /// `!fresh` to render an additional "Sentinel data is stale"
    /// note next to the status banner.
    pub fresh: bool,
}

/// Sentinel view used by the handler. Deliberately a private
/// type so a future supervisor revision can extend the on-disk
/// schema without breaking the handler — every field is
/// `serde(default)`.
#[derive(serde::Deserialize)]
struct SentinelView {
    #[serde(default = "default_status_healthy")]
    status: String,
    #[serde(default)]
    sub_state: Option<String>,
    #[serde(default)]
    attempt_n: u32,
    #[serde(default)]
    max_attempts: u32,
    #[serde(default)]
    last_restart_reason: Option<String>,
    #[serde(default)]
    last_restart_unix_ts: i64,
    #[serde(default)]
    attempts_in_window: u32,
    #[serde(default)]
    window_secs: u32,
    #[serde(default)]
    supervisor_pid: u32,
    #[serde(default)]
    kernel_pid: u32,
    #[serde(default)]
    updated_at_unix_secs: i64,
}

fn default_status_healthy() -> String { "Healthy".to_owned() }

/// `GET /api/health/kernel-lifecycle` — supervisor sentinel view.
///
/// Polled by the `KernelLifecycleBanner` React component every
/// 5 seconds (`self-healing-supervisor.md §5.4`). Gated on the
/// `read` role like every other privileged-read view, emits one
/// `OperatorHealthQueried` audit row per request per
/// `INV-AUDIT-OPERATOR-ACTION-01`.
pub async fn kernel_lifecycle<D>(
    State(state): State<AppState<D>>,
    op: AuthorizedOperator,
) -> ApiResult<Json<KernelLifecycleResponse>>
where
    D: crate::data::DashboardData,
{
    if !op.has_role(DashboardRole::Read) {
        let err = ApiError::Forbidden { required: "read".into() };
        emit_health_audit(
            &*state.data,
            &op,
            operator_outcome::outcome_from_api_error(&err),
        );
        return Err(err);
    }
    let response = read_kernel_lifecycle_response(state.config.data_dir.as_deref());
    state
        .data
        .emit_operator_audit(AuditEventKind::OperatorHealthQueried {
            operator_fingerprint: op.fingerprint.clone(),
            outcome:              operator_outcome::ACCEPTED.into(),
        })?;
    Ok(Json(response))
}

/// Public-for-tests core: reads the sentinel file at
/// `<data_dir>/kernel_lifecycle_status.json` (if any) and
/// translates it into a [`KernelLifecycleResponse`] +
/// freshness flag. `data_dir = None` ⇒ supervisor not
/// configured ⇒ `Healthy { fresh: true }` (the dashboard is
/// itself the witness).
pub fn read_kernel_lifecycle_response(data_dir: Option<&str>) -> KernelLifecycleResponse {
    let now = unix_now_secs();
    let Some(data_dir) = data_dir else {
        return KernelLifecycleResponse {
            status: "Healthy".to_owned(),
            sub_state: None,
            attempt_n: 0,
            max_attempts: 0,
            last_restart_reason: None,
            last_restart_unix_ts: 0,
            attempts_in_window: 0,
            window_secs: 0,
            supervisor_pid: 0,
            kernel_pid: 0,
            updated_at_unix_secs: now,
            fresh: true,
        };
    };
    let sentinel_path = PathBuf::from(data_dir).join("kernel_lifecycle_status.json");
    let bytes = match std::fs::read(&sentinel_path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return KernelLifecycleResponse {
                status: "Healthy".to_owned(),
                sub_state: None,
                attempt_n: 0,
                max_attempts: 0,
                last_restart_reason: None,
                last_restart_unix_ts: 0,
                attempts_in_window: 0,
                window_secs: 0,
                supervisor_pid: 0,
                kernel_pid: 0,
                updated_at_unix_secs: now,
                fresh: true,
            };
        }
        Err(_e) => {
            // Read error other than NotFound — return a Halted
            // / SupervisorGone view so the banner surfaces the
            // problem.
            return KernelLifecycleResponse {
                status: "Halted".to_owned(),
                sub_state: Some("SupervisorGone".to_owned()),
                attempt_n: 0,
                max_attempts: 0,
                last_restart_reason: None,
                last_restart_unix_ts: 0,
                attempts_in_window: 0,
                window_secs: 0,
                supervisor_pid: 0,
                kernel_pid: 0,
                updated_at_unix_secs: now,
                fresh: false,
            };
        }
    };
    let view: SentinelView = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_e) => {
            return KernelLifecycleResponse {
                status: "Halted".to_owned(),
                sub_state: Some("SupervisorGone".to_owned()),
                attempt_n: 0,
                max_attempts: 0,
                last_restart_reason: None,
                last_restart_unix_ts: 0,
                attempts_in_window: 0,
                window_secs: 0,
                supervisor_pid: 0,
                kernel_pid: 0,
                updated_at_unix_secs: now,
                fresh: false,
            };
        }
    };
    // Staleness window: 2× the supervisor's `window_secs` (default
    // 60 s ⇒ 120 s). Below that the data is considered fresh.
    // Staleness detection only matters when the supervisor IS in
    // play (`supervisor_pid != 0`) — when the supervisor is
    // absent, the kernel is running directly and the sentinel
    // file MAY be ancient (from a prior supervised run); we
    // still report the status it carries but mark `fresh: true`
    // so the dashboard doesn't shout about an absent supervisor.
    let staleness_window = if view.window_secs == 0 {
        120
    } else {
        2 * i64::from(view.window_secs)
    };
    let age_secs = now.saturating_sub(view.updated_at_unix_secs);
    let pid_alive = view.supervisor_pid == 0
        || supervisor_pid_alive(view.supervisor_pid);
    let fresh = age_secs <= staleness_window && pid_alive;
    let (status, sub_state) = if !fresh && view.supervisor_pid != 0 {
        // Supervisor PID we know about is gone OR the file
        // hasn't been updated for >2 windows. Either way: surface
        // `Halted{SupervisorGone}` so the operator knows the
        // sentinel data is stale.
        ("Halted".to_owned(), Some("SupervisorGone".to_owned()))
    } else {
        (view.status.clone(), view.sub_state.clone())
    };
    KernelLifecycleResponse {
        status,
        sub_state,
        attempt_n: view.attempt_n,
        max_attempts: view.max_attempts,
        last_restart_reason: view.last_restart_reason,
        last_restart_unix_ts: view.last_restart_unix_ts,
        attempts_in_window: view.attempts_in_window,
        window_secs: view.window_secs,
        supervisor_pid: view.supervisor_pid,
        kernel_pid: view.kernel_pid,
        updated_at_unix_secs: view.updated_at_unix_secs,
        fresh,
    }
}

fn unix_now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(unix)]
fn supervisor_pid_alive(pid: u32) -> bool {
    // `kill(pid, 0)` is the POSIX-portable way to ask "is this
    // process still alive AND can I signal it?". `Errno::ESRCH`
    // means the process is gone; `Errno::EPERM` means it exists
    // but we can't signal it — both are "not under our control"
    // but for liveness only `ESRCH` is conclusive. Treat any
    // success or `EPERM` as alive (the supervisor might be
    // running as a different uid in some operator setups).
    use nix::errno::Errno;
    let raw = i32::try_from(pid).unwrap_or(0);
    match nix::sys::signal::kill(nix::unistd::Pid::from_raw(raw), None) {
        Ok(()) => true,
        Err(Errno::EPERM) => true,
        Err(_) => false,
    }
}

#[cfg(not(unix))]
fn supervisor_pid_alive(_pid: u32) -> bool {
    // Non-unix targets: skip liveness probing. The dashboard
    // crate is unix-deployed in practice, but keeping the
    // `cfg(not(unix))` arm here avoids a build break if a
    // future PR adds Windows / wasm32 build matrix.
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn missing_sentinel_returns_healthy_fresh() {
        let dir = tempdir().unwrap();
        let resp = read_kernel_lifecycle_response(Some(
            dir.path().to_str().unwrap(),
        ));
        assert_eq!(resp.status, "Healthy");
        assert!(resp.sub_state.is_none());
        assert!(resp.fresh);
    }

    #[test]
    fn missing_data_dir_returns_healthy_fresh() {
        let resp = read_kernel_lifecycle_response(None);
        assert_eq!(resp.status, "Healthy");
        assert!(resp.fresh);
    }

    #[test]
    fn fresh_healthy_sentinel_passes_through() {
        let dir = tempdir().unwrap();
        let now = unix_now_secs();
        let raw = serde_json::json!({
            "schema_version": 1,
            "status": "Healthy",
            "supervisor_pid": std::process::id(),
            "kernel_pid": 12346,
            "updated_at_unix_secs": now,
            "window_secs": 60,
        });
        std::fs::write(
            dir.path().join("kernel_lifecycle_status.json"),
            serde_json::to_vec(&raw).unwrap(),
        )
        .unwrap();
        let resp = read_kernel_lifecycle_response(Some(
            dir.path().to_str().unwrap(),
        ));
        assert_eq!(resp.status, "Healthy");
        assert!(resp.fresh);
        assert_eq!(resp.supervisor_pid, std::process::id());
    }

    #[test]
    fn fresh_restarting_sentinel_passes_through() {
        let dir = tempdir().unwrap();
        let now = unix_now_secs();
        let raw = serde_json::json!({
            "schema_version": 1,
            "status": "Restarting",
            "attempt_n": 2,
            "max_attempts": 3,
            "last_restart_unix_ts": now,
            "last_restart_reason": "DeadlockDetected",
            "prev_run_exit_code": 70,
            "attempts_in_window": 2,
            "window_secs": 60,
            "supervisor_pid": std::process::id(),
            "kernel_pid": 12346,
            "updated_at_unix_secs": now,
        });
        std::fs::write(
            dir.path().join("kernel_lifecycle_status.json"),
            serde_json::to_vec(&raw).unwrap(),
        )
        .unwrap();
        let resp = read_kernel_lifecycle_response(Some(
            dir.path().to_str().unwrap(),
        ));
        assert_eq!(resp.status, "Restarting");
        assert_eq!(resp.attempt_n, 2);
        assert_eq!(resp.max_attempts, 3);
        assert_eq!(resp.last_restart_reason.as_deref(), Some("DeadlockDetected"));
        assert!(resp.fresh);
    }

    #[test]
    fn fresh_halted_circuit_open_sentinel_passes_through() {
        let dir = tempdir().unwrap();
        let now = unix_now_secs();
        let raw = serde_json::json!({
            "schema_version": 1,
            "status": "Halted",
            "sub_state": "CircuitOpen",
            "attempt_n": 4,
            "max_attempts": 3,
            "last_restart_unix_ts": now,
            "last_restart_reason": "DeadlockDetected",
            "attempts_in_window": 4,
            "window_secs": 60,
            "supervisor_pid": std::process::id(),
            "kernel_pid": 0,
            "updated_at_unix_secs": now,
        });
        std::fs::write(
            dir.path().join("kernel_lifecycle_status.json"),
            serde_json::to_vec(&raw).unwrap(),
        )
        .unwrap();
        let resp = read_kernel_lifecycle_response(Some(
            dir.path().to_str().unwrap(),
        ));
        assert_eq!(resp.status, "Halted");
        assert_eq!(resp.sub_state.as_deref(), Some("CircuitOpen"));
        assert!(resp.fresh);
    }

    /// Stale sentinel + supervisor PID known to be gone (PID 0
    /// is treated as "no supervisor in play" → fresh; PID 99999999
    /// is almost certainly invalid → not fresh).
    #[test]
    fn stale_sentinel_with_dead_supervisor_pid_reports_supervisor_gone() {
        let dir = tempdir().unwrap();
        let raw = serde_json::json!({
            "schema_version": 1,
            "status": "Restarting",
            "attempt_n": 1,
            "max_attempts": 3,
            "window_secs": 60,
            "supervisor_pid": 99_999_999_u32,
            "kernel_pid": 12346,
            "updated_at_unix_secs": 0_i64,
        });
        std::fs::write(
            dir.path().join("kernel_lifecycle_status.json"),
            serde_json::to_vec(&raw).unwrap(),
        )
        .unwrap();
        let resp = read_kernel_lifecycle_response(Some(
            dir.path().to_str().unwrap(),
        ));
        assert_eq!(resp.status, "Halted");
        assert_eq!(resp.sub_state.as_deref(), Some("SupervisorGone"));
        assert!(!resp.fresh);
    }

    #[test]
    fn corrupted_sentinel_returns_supervisor_gone_no_panic() {
        let dir = tempdir().unwrap();
        std::fs::write(
            dir.path().join("kernel_lifecycle_status.json"),
            b"{ this is not json ",
        )
        .unwrap();
        let resp = read_kernel_lifecycle_response(Some(
            dir.path().to_str().unwrap(),
        ));
        assert_eq!(resp.status, "Halted");
        assert_eq!(resp.sub_state.as_deref(), Some("SupervisorGone"));
        assert!(!resp.fresh);
    }

    #[test]
    fn unknown_future_field_silently_ignored() {
        let dir = tempdir().unwrap();
        let now = unix_now_secs();
        let raw = serde_json::json!({
            "status": "Healthy",
            "supervisor_pid": std::process::id(),
            "updated_at_unix_secs": now,
            "window_secs": 60,
            "future_field": "schema_v2_added_this",
        });
        std::fs::write(
            dir.path().join("kernel_lifecycle_status.json"),
            serde_json::to_vec(&raw).unwrap(),
        )
        .unwrap();
        let resp = read_kernel_lifecycle_response(Some(
            dir.path().to_str().unwrap(),
        ));
        assert_eq!(resp.status, "Healthy");
        assert!(resp.fresh);
    }
}
