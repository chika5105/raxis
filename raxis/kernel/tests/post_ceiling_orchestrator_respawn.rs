//! Post-ceiling orchestrator-respawn regression test
//! (`INV-FSM-POST-CEILING-RESPAWN-01`).
//!
//! ## What this file pins
//!
//! The historical iter15 / iter16 deadlock that motivated the
//! `c986e6d` + `3e3605e` + `d7ca482` + `aafd4f2` + `6237618` chain
//! had a ~30-minute reproduction wall-clock: the kernel only
//! deadlocked AFTER an executor exhausted its `max_crash_retries`
//! budget AND the FSM transitioned that activation row through
//! its terminal close-out AND the orchestrator's post-exit
//! respawn hook ran AND the storm-guard preflight skipped /
//! fired correctly. By the time iter*.log surfaced the wedge,
//! the operator had already burned 30 minutes.
//!
//! This test collapses that 30-minute repro into a single
//! mock-planner end-to-end pass that runs in <60 seconds against
//! the real `raxis-kernel` binary, with a hard
//! `tokio::time::timeout(Duration::from_secs(60), ...)` wall.
//!
//! ## What the scenario exercises
//!
//! Per the iter18-deadlock task brief:
//!
//!   1. Pre-seed a "post-ceiling" SQL state — an Executor session
//!      bound to a `subtask_activations` row in `Active` with
//!      `crash_retry_count` already at one short of the kernel
//!      default `max_crash_retries = 3` (`v2-deep-spec.md §Step 12`,
//!      `initiatives::plan_registry::DEFAULT_MAX_CRASH_RETRIES`),
//!      with a sibling initiative also `Executing` and a
//!      `PendingActivation` row waiting for orchestrator pickup.
//!   2. As the executor, submit `IntentKind::ReportFailure`. The
//!      kernel's `handle_report_failure` MUST:
//!        * accept the intent (`Admitted`/`Running` → `Failed`,
//!          `kernel/src/handlers/intent.rs §"V2.5 — accept both
//!           Admitted and Running states"`);
//!        * bump `subtask_activations.crash_retry_count` from
//!          `default - 1 → default` inside the same SQL
//!          transaction (`6237618` —
//!          `bump_executor_crash_retry_count_in_tx`);
//!        * cascade-close the matching `Active` activation row
//!          to `Failed` with `terminated_at IS NOT NULL`
//!          (`c986e6d` — `transition_task_in_tx`'s
//!          `INV-ACT-01` block);
//!        * fire the orchestrator-respawn EarlyResponse hook
//!          (`handle_inner` line ~376
//!          `respawn_kinds = ReportFailure | CompleteTask |
//!          SubmitReview`).
//!   3. Verify each of the four side-effects above lands within
//!      the test deadline.
//!   4. Assert the kernel did NOT log
//!      `event = "deadlock_detected"` — the
//!      `INV-LOCK-07` watcher (also added in this commit batch)
//!      fires within 2 seconds of any `parking_lot` lock-graph
//!      cycle, so a clean stderr is the watcher's positive
//!      signal that the post-ceiling FSM transition holds the
//!      single-lock-per-public-call invariant.
//!
//! ## What this test deliberately does NOT exercise
//!
//! Two pieces of the post-ceiling FSM live below the planner-
//! socket surface and require a real isolation substrate (a
//! firecracker / AVF VM with the canonical orchestrator image):
//!
//!   * The `d7ca482` post-exit respawn hook lives inside
//!     `spawn_planner_dispatcher`'s tokio task in
//!     `kernel/src/session_spawn_orchestrator.rs`. That task is
//!     wired around the substrate-spawned planner VM lifecycle,
//!     not around raw planner.sock connections. Driving it from
//!     a synthetic mock planner would require a stub
//!     `IsolationBackend` impl injected into `HandlerContext`,
//!     which is out of scope for a kernel-binary integration
//!     test (the binary's substrate selector
//!     `isolation_select.rs` does not accept a test-only
//!     stub-via-env-var hook).
//!   * The `aafd4f2` storm-guard `pending && !active` preflight
//!     lives inside that same post-exit hook closure.
//!
//! Coverage for both lives in
//! `extended_e2e_realistic_scenario.rs` under `RAXIS_LIVE_E2E=1`,
//! which DOES spin a real substrate. THIS test is the fast-path
//! regression check that catches every other piece of the
//! post-ceiling chain in <60 seconds, so future iter*.log runs
//! that go red on those paths fail the unit test surface
//! immediately rather than waiting for the live-e2e wall-clock
//! deadline. Coverage for the substrate-bound post-exit hook
//! is documented as out-of-scope in `INV-FSM-POST-CEILING-
//! RESPAWN-01`'s rationale (`raxis/specs/invariants.md §11.x`).
//!
//! ## Scenario topology
//!
//!   initiative `it-sibling`   (Executing)
//!     └── task `task-sibling`  (Running)
//!         └── activation `act-sibling`  (Active,
//!                                        crash_retry_count = 2,
//!                                        bound to executor session)
//!
//!   initiative `it-primary`    (Executing)
//!     └── task `task-primary`  (Admitted)
//!         └── activation `act-primary`  (PendingActivation —
//!                                        waiting for an
//!                                        orchestrator-driven
//!                                        ActivateSubTask that
//!                                        will never come from
//!                                        the dead sibling tier)
//!
//! The mock planner connects with the executor's session token
//! and submits `ReportFailure` for `task-sibling`. The kernel
//! drives the post-ceiling FSM transition; we observe it
//! through (a) the typed IntentResponse, (b) the post-commit
//! SQLite state, (c) the structured stderr log lines.

mod common;

use std::path::Path;
use std::time::{Duration, Instant};

use raxis_ipc::{read_frame, write_frame, IpcMessage};
use raxis_types::{IntentKind, IntentOutcome, IntentRequest, TaskId, TaskState};
use rusqlite::Connection;
use tokio::net::UnixStream;
use uuid::Uuid;

use common::kernel_harness::KernelInstance;

// ---------------------------------------------------------------------------
// Test deadlines
// ---------------------------------------------------------------------------
// The brief mandates a hard 60-second wall (`tokio::time::timeout`).
// The per-step budgets below are deliberately generous within that
// envelope — the goal is to fail FAST on regression, not to time
// race the per-frame cadence.

/// Hard outer wall — the ENTIRE test (bootstrap + spawn + ready +
/// seed + ReportFailure round-trip + assertions + graceful
/// shutdown) MUST finish inside this budget. If it doesn't, we panic
/// with a timeout — exactly the "kernel deadlocked" signal the
/// iter18 task brief asked for.
const HARD_WALL: Duration = Duration::from_secs(60);

/// Generous per-stage deadlines — kernel boot + cargo-built binary
/// startup on a busy CI host occasionally takes 5+ seconds; we keep
/// each step at ~10s so the failure mode "step N hung" is legible.
const READY_DEADLINE: Duration = Duration::from_secs(15);
const ROUND_TRIP_DEADLINE: Duration = Duration::from_secs(10);
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(15);

/// Window the test waits for the orchestrator-respawn EarlyResponse
/// log line to surface on stderr after the IntentResponse returns.
/// The respawn helper is `tokio::spawn`'d so its logging is
/// post-IntentResponse; 5 seconds is generous (the path has zero
/// await points beyond a single `lock_sync` read on the cold-warm
/// store mutex).
const POST_RESPONSE_LOG_DEADLINE: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Pre-seeded SQL identifiers — kept in module-scope constants so the
// helpers and the assertions stay in lock-step. Renaming any of these
// requires updating both the seed_post_ceiling_state() block AND the
// per-row read-back queries below.
// ---------------------------------------------------------------------------

const SIBLING_INITIATIVE: &str = "it-sibling";
const PRIMARY_INITIATIVE: &str = "it-primary";
const SIBLING_TASK: &str = "task-sibling";
const PRIMARY_TASK: &str = "task-primary";
const SIBLING_ACTIVATION: &str = "act-sibling";
const PRIMARY_ACTIVATION: &str = "act-primary";
const SIBLING_SESSION: &str = "11111111-1111-1111-1111-111111111111";
const SIBLING_LINEAGE: &str = "lineage-sibling";

/// Seeded `crash_retry_count` value — one short of the kernel
/// default `DEFAULT_MAX_CRASH_RETRIES = 3`
/// (`raxis/kernel/src/initiatives/plan_registry.rs §
/// DEFAULT_MAX_CRASH_RETRIES`). After the ReportFailure under test
/// lands, the bump in `bump_executor_crash_retry_count_in_tx` MUST
/// take it to `3`, putting the activation at the ceiling.
const SEED_CRASH_RETRY_COUNT_AT_NEAR_CEILING: i64 = 2;
const EXPECTED_CRASH_RETRY_COUNT_POST_REPORT: i64 = 3;

// ---------------------------------------------------------------------------
// Test entry point
// ---------------------------------------------------------------------------

/// `INV-FSM-POST-CEILING-RESPAWN-01` regression witness.
///
/// Driven from the brief's "Total test runtime must be under 60
/// seconds" requirement: the entire test body — including kernel
/// bootstrap, binary spawn, sockets-bound ready-wait, SQL seed,
/// ReportFailure round-trip, post-commit DB read-back, stderr
/// log scrape, and graceful SIGTERM shutdown — runs inside one
/// `tokio::time::timeout(HARD_WALL, ...)`. A timeout panic is the
/// canonical "kernel deadlocked" signal.
///
/// NOT `#[ignore]` — the brief is explicit on this. The deadlock-
/// watcher self-test in `kernel/src/main.rs::deadlock_watcher_self_test`
/// IS `#[ignore]` because it intentionally panics; THIS test must
/// run by default so every `cargo test -p raxis-kernel
/// --test post_ceiling_orchestrator_respawn` invocation is the
/// fast-path regression check the task brief mandated.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn post_ceiling_deadlock_respawn() {
    let started = Instant::now();
    let outcome =
        tokio::time::timeout(HARD_WALL, async move { run_post_ceiling_scenario().await }).await;

    match outcome {
        Ok(()) => {
            let elapsed = started.elapsed();
            assert!(
                elapsed < HARD_WALL,
                "post-ceiling regression test must complete in <60s; \
                 elapsed = {elapsed:?}",
            );
        }
        Err(_) => {
            panic!(
                "post-ceiling regression test exceeded the hard wall \
                 of {HARD_WALL:?} — this is the canonical 'kernel \
                 deadlocked during post-ceiling FSM transition' \
                 signal. Inspect the kernel.stderr captured by the \
                 harness (KernelInstance::captured_stderr) for the \
                 INV-LOCK-07 deadlock_detected event. If the watcher \
                 surfaced a cycle the kernel will have already \
                 exited non-zero with backtraces in stderr; if not, \
                 the wedge is in tokio (not parking_lot) and a \
                 sample(1) of the kernel pid will pinpoint the \
                 parked worker.",
            );
        }
    }
}

async fn run_post_ceiling_scenario() {
    // ── Phase 1: bring up a fresh kernel under a tempdir-data-dir.
    //
    // `KernelInstance::bootstrap_and_spawn` runs the same bootstrap
    // ceremony any operator would (genesis policy + ephemeral cert),
    // then spawns the kernel binary and tees its stderr into an
    // in-memory ring we grep below for structured event lines.
    let mut kernel = KernelInstance::bootstrap_and_spawn();
    kernel.wait_until_ready_or_panic(READY_DEADLINE);
    let data_dir = kernel.data_dir().to_owned();

    // ── Phase 2: seed the post-ceiling SQL state directly.
    //
    // We pre-seed via rusqlite-on-the-side (the same shape
    // `mock_planner_end_to_end::intent_with_real_session_token_clears_step2_envelope_acceptance`
    // uses, see that test's comment block on why direct DB
    // insertion is admissible here despite the kernel holding its
    // own connection). The kernel runs in WAL mode so a transient
    // second writer for a few inserts is safe, and going through
    // the operator socket would require the full operator-signing
    // ceremony — overkill for an SQL-shape regression guard.
    let session_token = mint_session_token();
    seed_post_ceiling_state(&data_dir, &session_token);

    // ── Phase 3: as the sibling executor, submit ReportFailure for
    //    `task-sibling`. The kernel drives the post-ceiling FSM
    //    transition end-to-end on this single round-trip.
    let mut planner = MockExecutor::connect(&kernel.planner_socket(), &session_token)
        .await
        .unwrap_or_else(|e| {
            panic!(
                "connect to planner.sock failed: {e}; kernel stderr:\n{}",
                kernel.captured_stderr(),
            );
        });

    let req = planner.build_report_failure(SIBLING_TASK);
    let req_seq = req.sequence_number;
    let resp = planner.round_trip(&IpcMessage::IntentRequest(req)).await;

    // ── Phase 4: assertions on the typed IntentResponse.
    match resp {
        IpcMessage::KernelIntentResponse(ir) => {
            assert_eq!(
                ir.sequence_number, req_seq,
                "IntentResponse must echo the request seq on the post-ceiling path",
            );
            assert_eq!(
                ir.task_state,
                TaskState::Failed,
                "ReportFailure must terminate the task in `Failed`; got {:?}",
                ir.task_state,
            );
            match ir.outcome {
                IntentOutcome::Accepted { .. } => { /* expected */ }
                IntentOutcome::Rejected { error_code, .. } => panic!(
                    "ReportFailure must be Accepted on a Running task at near-ceiling; \
                     got Rejected({error_code:?}). Kernel stderr:\n{}",
                    kernel.captured_stderr(),
                ),
            }
        }
        other => panic!(
            "expected KernelIntentResponse, got {:?}; kernel stderr:\n{}",
            describe(&other),
            kernel.captured_stderr(),
        ),
    }

    // ── Phase 5: assertions on the post-commit SQLite state.
    //
    // Two invariants the c986e6d/6237618 fixes pinned, captured
    // here by direct SQL read-back (the kernel's own assertions
    // are in unit tests; we want the binary-level confirmation):
    //
    //   * tasks.state              = Failed           (FSM transition)
    //   * subtask_activations.activation_state = Failed   (cascade)
    //   * subtask_activations.terminated_at IS NOT NULL   (cascade)
    //   * subtask_activations.crash_retry_count = 3       (bump)
    {
        let conn =
            Connection::open(data_dir.join("kernel.db")).expect("open kernel.db for read-back");

        let task_state: String = conn
            .query_row(
                "SELECT state FROM tasks WHERE task_id = ?1",
                rusqlite::params![SIBLING_TASK],
                |r| r.get(0),
            )
            .expect("read sibling task state");
        assert_eq!(
            task_state,
            TaskState::Failed.as_sql_str(),
            "sibling task must be Failed after ReportFailure; got {task_state:?}",
        );

        let (act_state, terminated_at, crash_retry_count): (String, Option<i64>, i64) = conn
            .query_row(
                "SELECT activation_state, terminated_at, crash_retry_count
                   FROM subtask_activations WHERE activation_id = ?1",
                rusqlite::params![SIBLING_ACTIVATION],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .expect("read sibling activation row");
        assert_eq!(
            act_state, "Failed",
            "c986e6d cascade: activation row must be Failed after task → Failed; \
             got {act_state:?}",
        );
        assert!(
            terminated_at.is_some(),
            "c986e6d cascade: terminated_at must be stamped on the cascade-closed \
             activation (Migration 5 CHECK constraint); got NULL",
        );
        assert_eq!(
            crash_retry_count, EXPECTED_CRASH_RETRY_COUNT_POST_REPORT,
            "6237618 bump: crash_retry_count must increment from \
             {SEED_CRASH_RETRY_COUNT_AT_NEAR_CEILING} → \
             {EXPECTED_CRASH_RETRY_COUNT_POST_REPORT} on ReportFailure; \
             got {crash_retry_count}. The bump and the cascade close MUST \
             ride the same SQLite transaction (handlers/intent.rs \
             §\"V2 §Step 12 — bump the crash-retry counter…\").",
        );
    }

    // ── Phase 6: structured stderr assertions.
    //
    // We poll the harness's stderr ring with a deadline because
    // the orchestrator-respawn EarlyResponse path (`handle_inner`
    // line ~378 `respawn_kinds`) spawns the respawn check on a
    // tokio task that returns AFTER the IntentResponse round-trip.
    // The respawn helper itself logs `orchestrator_respawn_*` and
    // the cascade emits `ActivationCascadeTerminated` from inside
    // the FSM transition — both should land within ~5 seconds.
    wait_for_stderr_substring(
        &kernel,
        "\"event\":\"TaskFailed\"",
        POST_RESPONSE_LOG_DEADLINE,
    );

    // Pin the FSM-edge log line that `transition_task_in_tx` emits
    // (the same function that also runs the c986e6d cascade close
    // INSIDE the same transaction — the cascade itself is a SQL
    // UPDATE with no eprintln, so we pin its execution by reading
    // back the post-commit `subtask_activations` row above. The
    // `TaskTransitioned` line is the lightweight "we reached the
    // FSM mutation site" witness; the DB read-back is the
    // structural witness of the cascade.).
    wait_for_stderr_substring(
        &kernel,
        // Match the JSON field shape verbatim — `transition_task_in_tx`
        // emits `event":"TaskTransitioned","task_id":"<id>","from":"Running","to":"Failed"`.
        "\"event\":\"TaskTransitioned\",\"task_id\":\"task-sibling\",\
         \"from\":\"Running\",\"to\":\"Failed\"",
        POST_RESPONSE_LOG_DEADLINE,
    );

    // d7ca482 EarlyResponse-driven respawn — the helper logs one of
    // these three skip variants in our test environment because the
    // sibling initiative has no plan-registry entry (we did not run
    // the full approve_plan ceremony). Any of them is the positive
    // signal that the EarlyResponse hook FIRED — what we're guarding
    // against is the hook silently skipping (not even reaching the
    // helper).
    wait_for_stderr_substring_any(
        &kernel,
        &[
            "\"event\":\"orchestrator_respawn_skipped\"",
            "\"event\":\"orchestrator_respawn_ok\"",
            "\"event\":\"orchestrator_respawn_failed\"",
        ],
        POST_RESPONSE_LOG_DEADLINE,
    );

    // ── Phase 7: deadlock-watcher cross-check (INV-LOCK-07).
    //
    // The `runtime-deadlock-detection` cargo feature is on by
    // default (kernel/Cargo.toml `default = [...]`), so the
    // background watcher is running inside the kernel binary the
    // harness just spawned. A clean stderr (no `deadlock_detected`
    // line) is the positive signal that the post-ceiling FSM
    // transition holds the single-lock-per-public-call invariant
    // (`concurrency-and-locking.md §INV-LOCK-01`). If the watcher
    // had fired, the kernel would have aborted before we reached
    // this assertion — but we belt-and-braces check anyway so a
    // future "the watcher logged but didn't actually exit" bug is
    // caught here too.
    let stderr = kernel.captured_stderr();
    assert!(
        !stderr.contains("\"event\":\"deadlock_detected\""),
        "INV-LOCK-07: kernel logged a deadlock_detected event during the \
         post-ceiling FSM transition. Full stderr:\n{stderr}",
    );

    // Drop the planner connection cleanly so the kernel sees EOF
    // on the per-connection task BEFORE we send SIGTERM. This
    // mirrors the production planner-VM lifecycle (planner exits,
    // accept loop sees EOF) and exercises the same stderr-line
    // path the post-exit hook would log on a real spawn.
    drop(planner);

    // ── Phase 8: graceful shutdown.
    let status = kernel.shutdown_with(libc::SIGTERM, SHUTDOWN_DEADLINE);
    assert!(
        status.success(),
        "kernel must exit cleanly after SIGTERM (post-ceiling teardown); \
         got {:?}. Kernel stderr:\n{}",
        status,
        kernel.captured_stderr(),
    );
}

// ---------------------------------------------------------------------------
// Mock executor — connects with a real session token, builds + sends
// a single ReportFailure intent.
// ---------------------------------------------------------------------------

struct MockExecutor {
    stream: UnixStream,
    next_seq: u64,
    next_nonce_seed: u128,
    token: String,
}

impl MockExecutor {
    async fn connect<P: AsRef<std::path::Path>>(
        socket_path: P,
        token: &str,
    ) -> std::io::Result<Self> {
        let stream = UnixStream::connect(socket_path).await?;
        Ok(Self {
            stream,
            next_seq: 1,
            next_nonce_seed: u128::from_le_bytes(*Uuid::new_v4().as_bytes()),
            token: token.to_owned(),
        })
    }

    fn next_nonce(&mut self) -> String {
        let n = self.next_nonce_seed;
        self.next_nonce_seed = self.next_nonce_seed.wrapping_add(1);
        format!("{n:032x}")
    }

    fn build_report_failure(&mut self, task_id_str: &str) -> IntentRequest {
        let seq = self.next_seq;
        self.next_seq = seq.wrapping_add(1);
        IntentRequest {
            session_token: self.token.clone(),
            sequence_number: seq,
            envelope_nonce: self.next_nonce(),
            intent_kind: IntentKind::ReportFailure,
            task_id: TaskId::parse(task_id_str)
                .expect("seed task_id satisfies TaskId::parse invariants"),
            base_sha: None,
            head_sha: None,
            submitted_claims: vec![],
            justification: Some(
                "post-ceiling-regression: synthetic ReportFailure to drive crash_retry_count \
                 from 2 → 3 (kernel default ceiling). Mirrors the iter15/16 deadlock state \
                 the c986e6d + 6237618 chain fixed."
                    .to_owned(),
            ),
            idempotency_key: None,
            approval_token: None,
            approved: None,
            critique: None,
            resolved_via_escalation: None,
            tokens_used: None,
            structured_output: None,
            sub_task_kind: None,
            parent_gate_failure_task_id: None,
            parent_gate_failure_type: None,
        }
    }

    async fn round_trip(&mut self, msg: &IpcMessage) -> IpcMessage {
        write_frame(&mut self.stream, msg)
            .await
            .expect("write_frame to planner.sock");
        match tokio::time::timeout(ROUND_TRIP_DEADLINE, read_frame(&mut self.stream)).await {
            Ok(Ok(reply)) => reply,
            Ok(Err(e)) => {
                panic!("kernel did not return a frame on the post-ceiling round-trip: {e}",)
            }
            Err(_) => panic!(
                "kernel did not reply within {ROUND_TRIP_DEADLINE:?} — \
                 likely the post-ceiling deadlock the INV-LOCK-07 watcher \
                 exists to surface.",
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// SQL seeding helpers
// ---------------------------------------------------------------------------

/// 64-hex-char session token in the same shape
/// `authority::session::create_session` produces. Random per-test so
/// concurrent test runs (cargo nextest, etc.) don't collide on the
/// `sessions.session_token UNIQUE` constraint.
fn mint_session_token() -> String {
    format!(
        "{:032x}{:032x}",
        Uuid::new_v4().as_u128(),
        Uuid::new_v4().as_u128(),
    )
}

/// Open a side-channel rusqlite handle to `<data_dir>/kernel.db`
/// and lay down the entire post-ceiling fixture in ONE
/// transaction so a partial seed cannot leave the kernel observing
/// a half-applied state.
fn seed_post_ceiling_state(data_dir: &Path, session_token: &str) {
    let db_path = data_dir.join("kernel.db");
    let mut conn =
        Connection::open(&db_path).unwrap_or_else(|e| panic!("open kernel.db at {db_path:?}: {e}"));
    let tx = conn.transaction().expect("begin seed tx");

    let now: i64 = raxis_types::clock::unix_now_secs();
    let far_expiry: i64 = now + 86_400;

    // ── initiatives ──────────────────────────────────────────────
    // Both initiatives in `Executing` so the orchestrator-respawn
    // preflight (`session_spawn_orchestrator::respawn_orchestrator_for_initiative`
    // §"Step 1: skip-checks") sees them as candidates rather than
    // skipping with `not_executing`. `terminal_criteria_json` is a
    // bare `{}` because the test does NOT exercise the terminal-
    // criteria evaluator; the column is NOT NULL so we satisfy the
    // schema with a parseable empty object.
    for init in [SIBLING_INITIATIVE, PRIMARY_INITIATIVE] {
        tx.execute(
            "INSERT INTO initiatives
                (initiative_id, state, terminal_criteria_json,
                 plan_artifact_sha256, created_at)
             VALUES (?1, 'Executing', '{}', 'deadbeef', ?2)",
            rusqlite::params![init, now],
        )
        .unwrap_or_else(|e| panic!("insert initiative {init}: {e}"));
    }

    // ── sibling task in Running ─────────────────────────────────
    // V2 task FSM: `Running` is the only state from which
    // `ReportFailure` can transition `→ Failed` without the
    // `Admitted → Running` auto-promote (`handle_report_failure`
    // V2.5 leniency; we exercise the canonical Running → Failed
    // edge to keep the assertions tight). `actor = 'kernel'` is
    // the Migration 0 default for kernel-admitted rows.
    tx.execute(
        "INSERT INTO tasks
            (task_id, initiative_id, lane_id, state, actor,
             policy_epoch, admitted_at, transitioned_at, actual_cost)
         VALUES (?1, ?2, 'default', ?3, 'kernel', 1, ?4, ?4, 0)",
        rusqlite::params![
            SIBLING_TASK,
            SIBLING_INITIATIVE,
            TaskState::Running.as_sql_str(),
            now,
        ],
    )
    .expect("insert sibling task");

    // ── primary task in Admitted ────────────────────────────────
    // Pre-seeded so the post-exit-respawn preflight reads
    // `pending_exists = true` if it ever runs against this
    // initiative. Even though THIS test does not exercise the
    // d7ca482 post-exit hook (see file-level docs), seeding the
    // shape makes the SQL fixture realistic for the brief's
    // "primary orchestrator must respawn" half — extending the
    // test to the live-substrate post-exit path can reuse the
    // same seed verbatim.
    tx.execute(
        "INSERT INTO tasks
            (task_id, initiative_id, lane_id, state, actor,
             policy_epoch, admitted_at, transitioned_at, actual_cost)
         VALUES (?1, ?2, 'default', ?3, 'kernel', 1, ?4, ?4, 0)",
        rusqlite::params![
            PRIMARY_TASK,
            PRIMARY_INITIATIVE,
            TaskState::Admitted.as_sql_str(),
            now,
        ],
    )
    .expect("insert primary task");

    // ── sibling executor session ────────────────────────────────
    // Includes Migration 5's `session_agent_type` + Migration 18's
    // `initiative_id` back-edge so the kernel's session-load path
    // (`authority::session::get_session_by_token`) returns a
    // SessionRow whose `session_agent_type = Executor`. The
    // dispatch matrix (`authority::dispatch_matrix::evaluate_dispatch`)
    // accepts ReportFailure from Executor; an Executor session
    // also bypasses the `can_delegate` clause via its CHECK
    // (Executor MUST have can_delegate = 0). `worktree_root` is
    // required for Planner-class roles per `create_session`'s
    // role/worktree pairing — we set it to the test's tempdir so
    // the row passes the table CHECK
    // `worktree_root IS NOT NULL OR base_sha IS NULL`.
    let worktree_root = data_dir.join("test-worktree-sibling");
    let _ = std::fs::create_dir_all(&worktree_root);
    tx.execute(
        "INSERT INTO sessions (
            session_id, role_id, session_token, sequence_number,
            worktree_root, base_sha, base_tracking_ref,
            lineage_id, fetch_quota, created_at, expires_at, revoked,
            session_agent_type, can_delegate, initiative_id
         ) VALUES (?1, 'Planner', ?2, 0, ?3, NULL, NULL,
                   ?4, 1000, ?5, ?6, 0, 'Executor', 0, ?7)",
        rusqlite::params![
            SIBLING_SESSION,
            session_token,
            worktree_root.to_string_lossy().to_string(),
            SIBLING_LINEAGE,
            now,
            far_expiry,
            SIBLING_INITIATIVE,
        ],
    )
    .expect("insert sibling executor session");

    // ── sibling activation in Active ────────────────────────────
    // The Migration 5 CHECK (`Active ⇒ session_id IS NOT NULL AND
    // activated_at IS NOT NULL AND terminated_at IS NULL`) is
    // satisfied: bound to SIBLING_SESSION above, activated_at =
    // now, terminated_at NULL. crash_retry_count seeded ONE SHORT
    // of the kernel default ceiling so the
    // `bump_executor_crash_retry_count_in_tx` call on
    // ReportFailure pushes us EXACTLY to the ceiling — the
    // post-bump activation row is then "post-ceiling" by
    // construction.
    tx.execute(
        "INSERT INTO subtask_activations (
            activation_id, task_id, initiative_id, activation_state,
            session_id, evaluation_sha,
            crash_retry_count, review_reject_count,
            created_at, activated_at, terminated_at
         ) VALUES (?1, ?2, ?3, 'Active', ?4, NULL, ?5, 0, ?6, ?6, NULL)",
        rusqlite::params![
            SIBLING_ACTIVATION,
            SIBLING_TASK,
            SIBLING_INITIATIVE,
            SIBLING_SESSION,
            SEED_CRASH_RETRY_COUNT_AT_NEAR_CEILING,
            now,
        ],
    )
    .expect("insert sibling subtask_activations row");

    // ── primary activation in PendingActivation ─────────────────
    // CHECK (`PendingActivation ⇒ session_id IS NULL AND
    // activated_at IS NULL AND terminated_at IS NULL`). This row
    // makes the brief's "primary orchestrator must respawn"
    // intent topologically real — a future extension that pipes
    // a stub substrate through `HandlerContext` can reuse this
    // exact seed to drive the d7ca482 post-exit hook against it.
    tx.execute(
        "INSERT INTO subtask_activations (
            activation_id, task_id, initiative_id, activation_state,
            session_id, evaluation_sha,
            crash_retry_count, review_reject_count,
            created_at, activated_at, terminated_at
         ) VALUES (?1, ?2, ?3, 'PendingActivation', NULL, NULL, 0, 0, ?4, NULL, NULL)",
        rusqlite::params![PRIMARY_ACTIVATION, PRIMARY_TASK, PRIMARY_INITIATIVE, now,],
    )
    .expect("insert primary subtask_activations row");

    tx.commit().expect("commit seed tx");
}

// ---------------------------------------------------------------------------
// Stderr-grep helper
// ---------------------------------------------------------------------------

fn wait_for_stderr_substring(kernel: &KernelInstance, needle: &str, deadline: Duration) {
    let start = Instant::now();
    loop {
        let body = kernel.captured_stderr();
        if body.contains(needle) {
            return;
        }
        if start.elapsed() > deadline {
            panic!(
                "kernel stderr did not include {needle:?} within {deadline:?}; \
                 captured stderr:\n{body}",
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn wait_for_stderr_substring_any(kernel: &KernelInstance, needles: &[&str], deadline: Duration) {
    let start = Instant::now();
    loop {
        let body = kernel.captured_stderr();
        if needles.iter().any(|n| body.contains(n)) {
            return;
        }
        if start.elapsed() > deadline {
            panic!(
                "kernel stderr did not include any of {needles:?} within \
                 {deadline:?}; captured stderr:\n{body}",
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

/// Friendly variant name for the "expected KernelIntentResponse, got X"
/// panic message in `run_post_ceiling_scenario`.
///
/// Every variant of `raxis_ipc::IpcMessage` MUST appear here so the match
/// stays compiler-exhaustive: any future variant addition will surface as
/// an E0004 here and force the test author to make a deliberate decision
/// about whether the new variant could ever appear on the planner-socket
/// reply path this scenario exercises.
///
/// Note on the Path-A3 admission variants
/// (`TproxyAdmissionRequest` / `KernelTproxyAdmissionResponse` /
/// `DnsResolveRequest` / `KernelDnsResolveResponse`,
/// `airgap-architecture.md §3`): the post-ceiling scenario only
/// drives a single `IntentRequest(ReportFailure)` round-trip; the
/// kernel cannot lawfully respond with any A3 admission variant
/// to that request (it would be a wire-protocol violation caught
/// by `ipc/auth.rs`). These arms exist purely to keep the match
/// exhaustive — if one ever appeared the test would still panic
/// with a legible variant name rather than fail to compile.
fn describe(msg: &IpcMessage) -> &'static str {
    match msg {
        IpcMessage::IntentRequest(_) => "IntentRequest",
        IpcMessage::EscalationRequest(_) => "EscalationRequest",
        IpcMessage::PlannerFetchRequest(_) => "PlannerFetchRequest",
        IpcMessage::PlannerExitNotice { .. } => "PlannerExitNotice",
        IpcMessage::KernelIntentResponse(_) => "KernelIntentResponse",
        IpcMessage::KernelEscalationResponse(_) => "KernelEscalationResponse",
        IpcMessage::KernelPlannerFetchResponse(_) => "KernelPlannerFetchResponse",
        IpcMessage::KernelPlannerExitNoticeAck => "KernelPlannerExitNoticeAck",
        IpcMessage::TproxyAdmissionRequest(_) => "TproxyAdmissionRequest",
        IpcMessage::KernelTproxyAdmissionResponse(_) => "KernelTproxyAdmissionResponse",
        IpcMessage::DnsResolveRequest(_) => "DnsResolveRequest",
        IpcMessage::KernelDnsResolveResponse(_) => "KernelDnsResolveResponse",
        IpcMessage::WitnessSubmission(_) => "WitnessSubmission",
        IpcMessage::WitnessAck { .. } => "WitnessAck",
        IpcMessage::OperatorRequest(_) => "OperatorRequest",
        IpcMessage::OperatorResponse(_) => "OperatorResponse",
    }
}
