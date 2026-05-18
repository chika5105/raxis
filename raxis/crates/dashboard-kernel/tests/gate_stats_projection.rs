//! `INV-DASHBOARD-GATE-STATS-PER-GATE-ROLLUP-01` witness suite.
//!
//! Pin the BE-side wire shape for `GET /api/gates/stats`. The
//! endpoint is the operator's per-gate health rollup; the
//! dashboard's Gates page renders it as a minimal table +
//! sparkline strip and pivots on `pass_count` /
//! `fail_count` / `inconclusive_count` / `fixup_loop_count`
//! without applying any client-side classification.
//!
//! Three pinned scenarios:
//!
//!   1. **Empty kernel** — no `witness_records` rows ⇒ empty
//!      `gates` array, non-zero `generated_at`.
//!   2. **Mixed-outcome rollup** — two gates with a mix of
//!      Pass / Fail / Inconclusive across multiple tasks.
//!      MUST sum per gate, MUST surface the highest
//!      `recorded_at`, MUST be alphabetically ordered.
//!   3. **Fixup-loop counter** — `tasks.last_gate_type` +
//!      `tasks.gate_fixup_attempts` columns flow into the
//!      `fixup_loop_count` field per gate. A non-zero counter
//!      for a gate that has no `witness_records` row (witness
//!      never landed because the verifier crashed) MUST still
//!      surface as a row with zero counts but non-zero
//!      `fixup_loop_count`.

use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use raxis_dashboard::data::DashboardData;
use raxis_dashboard_kernel::KernelDashboardData;
use raxis_policy::PolicyBundle;
use raxis_store::Store;
use tempfile::TempDir;

/// Build a fresh in-memory kernel store + KernelDashboardData
/// pair backed by a tempdir. The kernel store is opened with
/// every migration applied (Store::open runs them).
fn fixture_kernel_data() -> (Arc<KernelDashboardData>, Arc<Store>, TempDir) {
    let dir = TempDir::new().expect("tempdir");
    let data_dir: PathBuf = dir.path().join("kernel-data");
    std::fs::create_dir_all(data_dir.join("audit")).unwrap();
    let store = Arc::new(Store::open(&data_dir.join("kernel.db")).expect("open kernel.db"));
    let policy = Arc::new(ArcSwap::new(Arc::new(
        PolicyBundle::for_tests_with_operators(Vec::new()),
    )));
    let policy_path = data_dir.join("policy.toml");
    let data = Arc::new(
        KernelDashboardData::new(
            Arc::clone(&store),
            Arc::clone(&policy),
            data_dir,
            policy_path,
            0,
        )
        .expect("KernelDashboardData::new"),
    );
    (data, store, dir)
}

/// Seed one `verifier_run_tokens` + `witness_records` pair.
/// `recorded_at` is Unix-seconds.
fn seed_witness(
    store: &Store,
    task_id: &str,
    initiative_id: &str,
    gate_type: &str,
    result_class: &str,
    recorded_at: i64,
    run_id: &str,
) {
    let conn = store.lock_sync();
    // The witness FK chain: witness_records.verifier_run_id →
    // verifier_run_tokens.verifier_run_id → tasks.task_id.
    // We need a tasks row too; seed an Admitted skeleton.
    let task_exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM tasks WHERE task_id = ?1",
            rusqlite::params![task_id],
            |r| r.get(0),
        )
        .unwrap();
    if task_exists == 0 {
        let init_exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM initiatives WHERE initiative_id = ?1",
                rusqlite::params![initiative_id],
                |r| r.get(0),
            )
            .unwrap();
        if init_exists == 0 {
            conn.execute(
                "INSERT INTO initiatives \
                    (initiative_id, state, terminal_criteria_json, \
                     plan_artifact_sha256, created_at) \
                 VALUES (?1, 'Executing', '{}', 'deadbeef', 1)",
                rusqlite::params![initiative_id],
            )
            .unwrap();
        }
        conn.execute(
            "INSERT INTO tasks \
                (task_id, initiative_id, lane_id, state, actor, \
                 policy_epoch, admitted_at, transitioned_at, \
                 actual_cost) \
             VALUES (?1, ?2, 'default', 'Admitted', 'kernel', \
                     0, 1, 1, 0)",
            rusqlite::params![task_id, initiative_id],
        )
        .unwrap();
    }

    conn.execute(
        "INSERT INTO verifier_run_tokens \
            (verifier_run_id, task_id, gate_type, evaluation_sha, \
             token_hash, issued_at, expires_at, consumed, consumed_at) \
         VALUES (?1, ?2, ?3, 'deadbeef', 'tokhash', 1, 9999, 0, NULL)",
        rusqlite::params![run_id, task_id, gate_type],
    )
    .unwrap();

    conn.execute(
        "INSERT INTO witness_records \
            (verifier_run_id, evaluation_sha, task_id, gate_type, \
             result_class, blob_sha256, blob_path, recorded_at) \
         VALUES (?1, 'deadbeef', ?2, ?3, ?4, 'sha-x', '/dev/null', ?5)",
        rusqlite::params![run_id, task_id, gate_type, result_class, recorded_at],
    )
    .unwrap();
}

/// Mark a parent task as having gone through a gate fixup loop:
/// set `last_gate_type` (the witness handler does this) and
/// bump `gate_fixup_attempts` (the admit pipeline does this).
fn mark_fixup_attempts(store: &Store, task_id: &str, gate_type: &str, attempts: i64) {
    let conn = store.lock_sync();
    conn.execute(
        "UPDATE tasks \
            SET last_gate_type = ?1, gate_fixup_attempts = ?2 \
          WHERE task_id = ?3",
        rusqlite::params![gate_type, attempts, task_id],
    )
    .unwrap();
}

#[test]
fn gate_stats_empty_kernel_returns_empty_array_with_generated_at() {
    let (data, _store, _td) = fixture_kernel_data();
    let resp = data.gate_stats().expect("gate_stats");
    assert!(
        resp.gates.is_empty(),
        "empty kernel MUST surface gates: [], got {:?}",
        resp.gates
    );
    assert!(
        resp.generated_at > 0,
        "generated_at MUST be the server wall clock (Unix-seconds), got {}",
        resp.generated_at
    );
}

#[test]
fn gate_stats_aggregates_across_classes_and_orders_alphabetically() {
    let (data, store, _td) = fixture_kernel_data();
    // NoSecretStrings: 2 Pass + 1 Fail across two tasks.
    seed_witness(
        &store,
        "task-a",
        "init-1",
        "NoSecretStrings",
        "Pass",
        100,
        "r-1",
    );
    seed_witness(
        &store,
        "task-b",
        "init-1",
        "NoSecretStrings",
        "Pass",
        150,
        "r-2",
    );
    seed_witness(
        &store,
        "task-c",
        "init-1",
        "NoSecretStrings",
        "Fail",
        200,
        "r-3",
    );
    // SchemaValid: 1 Pass + 1 Inconclusive.
    seed_witness(&store, "task-d", "init-1", "SchemaValid", "Pass", 50, "r-4");
    seed_witness(
        &store,
        "task-e",
        "init-1",
        "SchemaValid",
        "Inconclusive",
        75,
        "r-5",
    );

    let resp = data.gate_stats().expect("gate_stats");
    assert_eq!(
        resp.gates.len(),
        2,
        "two distinct gates MUST surface two rows, got {:?}",
        resp.gates
    );
    // Alphabetical ordering — `NoSecretStrings` < `SchemaValid`.
    assert_eq!(resp.gates[0].gate_type, "NoSecretStrings");
    assert_eq!(resp.gates[1].gate_type, "SchemaValid");

    let ns = &resp.gates[0];
    assert_eq!(ns.pass_count, 2);
    assert_eq!(ns.fail_count, 1);
    assert_eq!(ns.inconclusive_count, 0);
    assert_eq!(
        ns.last_seen_at,
        Some(200),
        "last_seen_at MUST be MAX(recorded_at) across all outcomes"
    );
    assert_eq!(ns.fixup_loop_count, 0, "no fixups admitted yet");

    let sv = &resp.gates[1];
    assert_eq!(sv.pass_count, 1);
    assert_eq!(sv.fail_count, 0);
    assert_eq!(sv.inconclusive_count, 1);
    assert_eq!(sv.last_seen_at, Some(75));
    assert_eq!(sv.fixup_loop_count, 0);
}

#[test]
fn gate_stats_surfaces_fixup_loop_counter_even_without_witness_rows() {
    let (data, store, _td) = fixture_kernel_data();
    // A witness row to anchor the gate on the rollup AND a
    // separate task that bumped `gate_fixup_attempts` after a
    // verifier-crash path (no witness landed).
    seed_witness(
        &store,
        "task-w",
        "init-2",
        "NoSecretStrings",
        "Fail",
        300,
        "r-w",
    );
    mark_fixup_attempts(&store, "task-w", "NoSecretStrings", 2);

    // A second task whose verifier ran but never recorded a
    // witness (Inconclusive route on the orchestrator side)
    // yet the fixup loop still admitted 1 attempt before the
    // gate-fixup-budget cut in. The rollup MUST sum these
    // across all parent tasks for the same gate.
    {
        let conn = store.lock_sync();
        conn.execute(
            "INSERT INTO tasks \
                (task_id, initiative_id, lane_id, state, actor, \
                 policy_epoch, admitted_at, transitioned_at, \
                 actual_cost, last_gate_type, gate_fixup_attempts) \
             VALUES ('task-x', 'init-2', 'default', 'Failed', \
                     'kernel', 0, 1, 1, 0, 'NoSecretStrings', 1)",
            [],
        )
        .unwrap();
    }

    let resp = data.gate_stats().expect("gate_stats");
    assert_eq!(
        resp.gates.len(),
        1,
        "one distinct gate, got {:?}",
        resp.gates
    );
    let row = &resp.gates[0];
    assert_eq!(row.gate_type, "NoSecretStrings");
    assert_eq!(row.fail_count, 1, "the single Fail witness counts once");
    assert_eq!(
        row.fixup_loop_count, 3,
        "fixup_loop_count = SUM(gate_fixup_attempts) over both parent tasks (2 + 1)"
    );
}
