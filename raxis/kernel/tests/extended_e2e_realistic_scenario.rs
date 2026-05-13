//! Realistic-scenario RAXIS V2 end-to-end driver — layers the
//! `rich-multilang-001` seed under the executor's worktree and
//! drives the full realism-extended plan
//! ([`extended_e2e_support::plan_realistic::realistic_plan_toml`])
//! plus a sibling initiative
//! ([`extended_e2e_support::multi_initiative::sibling_plan_toml`])
//! through a real RAXIS kernel + the live LLM.
//!
//! Normative reference: `raxis/specs/v2/e2e-extended-scenario.md`
//! ("Future work" bullets that this realism expansion closes).
//!
//! ## Why this file exists alongside `extended_e2e_concurrent_lifecycle.rs`
//!
//! `extended_e2e_concurrent_lifecycle.rs` pins the concurrent
//! fan-out + reviewer-disagreement + prompt-injection lifecycle on
//! an essentially empty worktree (one materializer + three small
//! fan-outs + one injection task). The realistic-scenario driver
//! adds seven new categories of behaviour the extended scenario
//! could not reach with its empty-worktree fixture:
//!
//!   * `xfile-refactor` — cross-file rename across Rust / TS /
//!     Python under language-specific linters
//!     (`P3-2 cross_file_refactor.md`).
//!   * `lint-defect` — executor introduces ONE real lint defect
//!     that the reviewer must catch substantively, exercising the
//!     reviewer-disagreement re-review path against a REAL
//!     critique target rather than a directive prompt
//!     (`P3-3 lint_defect.md`).
//!   * `allowlist-positive-codegen` — POSITIVE path-allowlist
//!     witness: the executor legitimately writes to
//!     `target/codegen/` under an allowlist that admits exactly
//!     that path (`P3-4 allowlist_positive.md`).
//!   * sibling-initiative — submitted in parallel to the primary
//!     realistic initiative, asserts per-initiative audit-chain
//!     isolation (no shared `task_id`/`session_id`)
//!     (`P3-6 multi_initiative.rs`).
//!   * `review-lint-defect-A/B` — non-directive Reviewers whose
//!     substantive critique must name the file with the lint
//!     defect (`P3-7 reviewer_substantive_disagreement.rs`).
//!   * crash-recovery — driver SIGTERMs the kernel mid-task and
//!     restarts; witness asserts the post-crash audit chain
//!     carries the expected recovery signature
//!     (`P3-8 crash_recovery.rs`).
//!
//! ## Gating
//!
//! Two-level:
//!
//!   * `RAXIS_LIVE_E2E=1` — same gate as the extended scenario.
//!     Required for any actual kernel-driven flow (real microVMs,
//!     real LLM, real DBs).
//!   * `RAXIS_LIVE_E2E_REALISTIC=1` — additional gate for the
//!     SEED-OVERLAY behaviour the realistic flow needs. Setting
//!     it implies a manual operator has already vetted that the
//!     `materialize_seed.sh` overlay timing is wired into the
//!     local kernel build (see the comment on
//!     [`materialise_realistic_seed`] for the remaining timing
//!     question).
//!
//! When neither gate is set (default for `cargo test -p
//! raxis-kernel`), the test runs the **wiring smoke test**: it
//! constructs each witness, drives it against a hand-built
//! synthetic chain, and asserts the wiring + diagnostics behave
//! correctly. This guards against build-time regressions in any
//! of the witness modules.

#![allow(clippy::too_many_lines)]

mod common;
mod extended_e2e_support;

use std::path::{Path, PathBuf};
use std::time::Duration;

use raxis_audit_tools::{AuditEvent, AuditEventKind};

use common::kernel_harness::acquire_test_lock;
use extended_e2e_support::{
    audit_chain::AuditChainWitness,
    crash_recovery::CrashRecoveryWitness,
    kernel_driver::{
        bootstrap_with_custom_cert, build_operator_key,
        enable_gateway_in_policy, locate_executor_worktree,
        locate_session_id_for_task, poll_for_dual_lifecycle_completion,
        realistic_lifecycle_deadline, require_anthropic_dev_key,
        require_canonical_images, require_gateway_binary, require_gcp_adc,
        require_tcp_reachable, spawn_kernel_normal, walk_chain_or_panic,
        write_credentials, write_provider_credentials, OperatorIpc,
        LIVE_E2E_GATE, READY_DEADLINE, REALISTIC_OPERATOR_SEED,
        SHUTDOWN_DEADLINE,
    },
    multi_initiative::{
        sibling_plan_toml, MultiInitiativeIsolationWitness,
        SIBLING_LANE_ID, TASK_SIBLING_MATERIALIZE,
    },
    path_allowlist::PathAllowlistPositiveWitness,
    plan_realistic::{
        realistic_plan_toml, SEED_SCENARIO_ID, TASK_ALLOWLIST_POSITIVE,
        TASK_LINT_DEFECT, TASK_MATERIALIZE,
        TASK_SERVICE_ROUND_TRIP, TASK_TRANSPARENT_PROXY_REALSCRIPTS,
        TASK_XFILE_REFACTOR,
    },
    reviewer_substantive_disagreement::ReviewerSubstantiveDisagreementWitness,
    seeds::{MONGO_HOST_PORT, PG_HOST_PORT},
    service_evidence::{
        assert_mssql_round_trip, assert_mysql_round_trip,
        collect_active_witness_failures, render_failures, seed_mongodb,
        seed_mssql, seed_mysql, seed_postgres, seed_redis, seed_smtp,
        WitnessScope,
    },
    transparent_proxy_evidence::{
        self as tp_evidence,
        TransparentProxyExpectations, WRAPPER_SUMMARY_PATH,
    },
    witnesses::{
        EnforcementWitness, NoSecurityViolationWitness,
    },
};

use common::dashboard::{
    configured_dashboard_port, mutate_dashboard_block_in_policy,
    open_dashboard_with_autologin,
};
use common::tier3_artifacts::Tier3Reporter;

const REALISTIC_GATE: &str = "RAXIS_LIVE_E2E_REALISTIC";

// ---------------------------------------------------------------------------
// Top-level test entry.
// ---------------------------------------------------------------------------

#[test]
fn realistic_session_lifecycle() {
    // Decide which mode we're in. The smoke-test path is the
    // default; the live-driven path requires BOTH gates.
    let live_gate_on =
        std::env::var(LIVE_E2E_GATE).as_deref()  == Ok("1");
    let realistic_gate_on =
        std::env::var(REALISTIC_GATE).as_deref() == Ok("1");

    if !(live_gate_on && realistic_gate_on) {
        eprintln!(
            "[realism-e2e] gates off (LIVE_E2E_GATE={live_gate_on}, \
             REALISTIC_GATE={realistic_gate_on}); running wiring smoke \
             test against synthetic audit chains. To run the live-driven \
             flow:\n  \
             1. docker compose -f live-e2e/docker-compose.extended.e2e.yml \
             up -d --wait\n  \
             2. ensure raxis/.env carries ANTHROPIC-API-DEV-KEY=sk-ant-...\n  \
             3. ensure ~/.config/gcloud/application_default_credentials.json \
             exists\n  \
             4. RAXIS_LIVE_E2E=1 RAXIS_LIVE_E2E_REALISTIC=1 cargo test -p \
             raxis-kernel --test extended_e2e_realistic_scenario -- --nocapture",
        );
        wiring_smoke_test();
        return;
    }

    let _build_lock = acquire_test_lock();

    // ── Preflight ─────────────────────────────────────────────
    require_tcp_reachable(PG_HOST_PORT,    "Postgres docker container");
    require_tcp_reachable(MONGO_HOST_PORT, "MongoDB docker container");
    require_anthropic_dev_key();
    require_gcp_adc();
    require_gateway_binary();
    require_canonical_images();
    eprintln!("[realism-e2e] preflight clean");

    // ── Bootstrap the kernel ─────────────────────────────────
    let (signing_key, fingerprint) = build_operator_key(&REALISTIC_OPERATOR_SEED);
    let (kernel_bin, data_dir)     = bootstrap_with_custom_cert(&signing_key);
    eprintln!("[realism-e2e] kernel bootstrapped, data_dir={}", data_dir.display());

    let gateway_binary = require_gateway_binary();
    enable_gateway_in_policy(&data_dir, &gateway_binary);
    // Re-bind the dashboard to a non-default test port (default
    // 19820, override via RAXIS_E2E_DASHBOARD_PORT) and inject
    // the React `dashboard-fe/dist` static_dir when built. Without
    // this the kernel binds at the spec default 9820 which would
    // collide with a developer daemon, AND it would serve only
    // the JSON API (no UI) since no `static_dir` is set in the
    // genesis policy. Idempotent against repeated test runs in
    // the same process: the helper rewrites the policy.toml once
    // before the kernel daemon spawns and reads it.
    mutate_dashboard_block_in_policy(&data_dir);
    write_credentials(&data_dir);
    write_provider_credentials(&data_dir);

    let install_dir = PathBuf::from(
        std::env::var("RAXIS_INSTALL_DIR").expect("preflight verified RAXIS_INSTALL_DIR"),
    );

    // Tier-3 reporter: created BEFORE the kernel spawn so an early
    // failure still emits the artifact block on Drop. `mark_success()`
    // at the bottom of the happy path enables the workdir-keep
    // policy's success cleanup branch. `.with_observability_urls()`
    // wires the same Grafana / Prometheus / OTel URL block the
    // `cargo xtask observability urls` command renders, so an
    // operator scanning the post-run stderr capture finds both the
    // artifact paths AND the metric dashboards in one block.
    let mut tier3 = Tier3Reporter::new(
        "realism-e2e", &install_dir, &data_dir,
    )
    .with_observability_urls();

    // Print the observability URL block at startup too so the
    // operator can paste a Grafana URL into their browser the
    // moment the test starts emitting OTLP, rather than waiting
    // for Drop. Cheap (≤ four 250ms TCP probes); the helper
    // never panics and never fails the test.
    common::tier3_artifacts::print_observability_urls_inline("realism-e2e");

    // Seed every in-scope service BEFORE the executor wakes up. The
    // round-trip task runs late in the plan dependency graph, so we
    // have ample lead time, but we still seed eagerly so the harness
    // fails closed on missing containers before burning LLM tokens.
    let pg_seed = seed_postgres()
        .unwrap_or_else(|e| panic!("postgres seed failed: {e}"));
    let mongo_seed = seed_mongodb()
        .unwrap_or_else(|e| panic!("mongodb seed failed: {e}"));
    let redis_seed = seed_redis()
        .unwrap_or_else(|e| panic!("redis seed failed: {e}"));
    let smtp_seed = seed_smtp()
        .unwrap_or_else(|e| panic!("smtp seed failed: {e}"));
    // Opt-in seeds are bypassed by their own helpers when the env
    // var is unset; calling them unconditionally keeps the surface
    // wired so a future env flip becomes active with no code change.
    let _mysql_seed = seed_mysql()
        .unwrap_or_else(|e| panic!("mysql seed (opt-in) failed: {e}"));
    let _mssql_seed = seed_mssql()
        .unwrap_or_else(|e| panic!("mssql seed (opt-in) failed: {e}"));
    eprintln!(
        "[realism-e2e] service-evidence seeds installed:          postgres rows={}, mongo docs={}, redis keys={}, smtp subject={}",
        pg_seed.rows.len(),
        mongo_seed.docs.len(),
        redis_seed.entries.len(),
        smtp_seed.subject,
    );

    let mut kernel = spawn_kernel_normal(&kernel_bin, data_dir.clone(), &install_dir);
    kernel.wait_until_ready_or_panic(READY_DEADLINE);
    eprintln!("[realism-e2e] kernel daemon up, accepting operator IPC");

    // ── (visual-debug) — open the operator dashboard with an
    //    autologin URL so the QA worker can attach a browser to
    //    the live realistic-scenario run. Best-effort: a missing
    //    FE bundle / port collision / missing `open(1)` is
    //    logged and skipped, never fatal — the test must still
    //    pass headless on CI / SSH. The URL is also threaded
    //    into the Tier-3 reporter so the post-run artifact block
    //    surfaces it for offline triage.
    let dashboard_port = configured_dashboard_port();
    if let Some(url) = open_dashboard_with_autologin(
        &signing_key, dashboard_port, "realism-e2e",
    ) {
        tier3.set_dashboard_url(url);
    }

    // ── Submit BOTH initiatives back-to-back ─────────────────
    let initiative_primary = uuid::Uuid::now_v7().to_string();
    let initiative_sibling = uuid::Uuid::now_v7().to_string();
    let op_socket = kernel.operator_socket();
    {
        let mut conn = OperatorIpc::connect(
            &op_socket, &signing_key,
            REALISTIC_OPERATOR_SEED, &fingerprint,
        );
        let plan_primary = realistic_plan_toml();
        conn.submit_plan(&initiative_primary, &plan_primary);
        eprintln!("[realism-e2e] primary plan submitted, initiative_id={initiative_primary}");
        conn.approve_plan(&initiative_primary, &fingerprint);

        let plan_sibling = sibling_plan_toml();
        conn.submit_plan(&initiative_sibling, &plan_sibling);
        eprintln!("[realism-e2e] sibling plan submitted, initiative_id={initiative_sibling} \
                   (lane={SIBLING_LANE_ID}, task={TASK_SIBLING_MATERIALIZE})");
        conn.approve_plan(&initiative_sibling, &fingerprint);
    }

    // ── Materialise the rich-multilang seed into the primary
    //    materializer's worktree. The kernel creates
    //    `<data_dir>/worktrees/<initiative>/<task>/` lazily; we poll
    //    for it and overlay the seed once present, before the
    //    executor's first IntentAccepted{CommitDelta} lands.
    materialise_realistic_seed(
        kernel.data_dir(),
        &initiative_primary,
        TASK_XFILE_REFACTOR,
    );

    // ── Stage the stock-Python scripts into the
    //    transparent-proxy executor's worktree. The kernel will
    //    eventually materialise that worktree once the upstream
    //    `service-round-trip` task completes; we poll for the
    //    directory to appear (gated by the same long deadline as
    //    `materialise_realistic_seed`) and then copy the seed
    //    scripts in. The scripts have no raxis-specific symbols;
    //    they simply consume the env vars (`DATABASE_URL`,
    //    `MONGO_URL`, …) the credential-proxy manager injects.
    stage_transparent_proxy_scripts(
        kernel.data_dir(),
        &initiative_primary,
        TASK_TRANSPARENT_PROXY_REALSCRIPTS,
    );

    // ── Wait for both initiatives to merge ───────────────────
    let chain = poll_for_dual_lifecycle_completion(
        kernel.data_dir(),
        [&initiative_primary, &initiative_sibling],
        realistic_lifecycle_deadline(),
    );
    eprintln!(
        "[realism-e2e] both lifecycles complete; chain has {} events",
        chain.len(),
    );

    // ── Apply every realism witness ──────────────────────────
    let primary_workdir = locate_executor_worktree(
        kernel.data_dir(), &initiative_primary, TASK_XFILE_REFACTOR,
    );
    let positive_workdir = locate_executor_worktree(
        kernel.data_dir(), &initiative_primary, TASK_ALLOWLIST_POSITIVE,
    );
    let lint_session_id = locate_session_id_for_task(&chain, TASK_LINT_DEFECT)
        .unwrap_or_else(|| {
            panic!("no SessionVmSpawned for {TASK_LINT_DEFECT}; \
                    reviewer-substantive witness cannot attribute critique")
        });
    eprintln!("[realism-e2e] lint-defect session_id={lint_session_id}");

    let sqlite_path = kernel.data_dir().join("kernel.db");
    let reviewer_witness =
        ReviewerSubstantiveDisagreementWitness::for_realistic_plan(&sqlite_path);
    let reviewer_report = reviewer_witness.evaluate(&chain);
    assert!(
        reviewer_report.is_pass(),
        "ReviewerSubstantiveDisagreementWitness failed: {reviewer_report:#?}",
    );
    eprintln!("[realism-e2e] reviewer-substantive witness satisfied");

    let isolation = MultiInitiativeIsolationWitness::new(
        &initiative_primary, &initiative_sibling,
    );

    let crash_witness = CrashRecoveryWitness::new(TASK_MATERIALIZE);

    let global_witnesses: Vec<Box<dyn EnforcementWitness>> = vec![
        Box::new(NoSecurityViolationWitness),
        Box::new(PathAllowlistPositiveWitness::for_realistic_plan(&positive_workdir)),
        Box::new(isolation),
        Box::new(crash_witness),
    ];
    extended_e2e_support::witnesses::assert_all_satisfied(
        &global_witnesses, &chain,
    );
    eprintln!("[realism-e2e] all chain-side + on-disk witnesses satisfied");

    // ── Service-evidence per-protocol round-trip ─────────────
    let service_workdir = locate_executor_worktree(
        kernel.data_dir(), &initiative_primary, TASK_SERVICE_ROUND_TRIP,
    );
    let service_scope = WitnessScope::new(
        initiative_primary.clone(),
        TASK_SERVICE_ROUND_TRIP.to_owned(),
    );
    let active_failures = collect_active_witness_failures(
        &chain,
        &service_workdir,
        &pg_seed,
        &mongo_seed,
        &redis_seed,
        &smtp_seed,
        &service_scope,
    );
    assert!(
        active_failures.is_empty(),
        "[realism-e2e] service-evidence witnesses failed:\n{}",
        render_failures(&active_failures),
    );
    // Opt-in helpers: invoked unconditionally so the call surface
    // is exercised. Their helpers short-circuit when the env var
    // is unset (emitting one informational `eprintln!`). When the
    // operator flips `RAXIS_LIVE_MYSQL_URL` / `RAXIS_LIVE_MSSQL_URL`
    // the round-trip assertion becomes active with no code change.
    if let Err(e) = assert_mysql_round_trip(
        &chain, &service_workdir, &_mysql_seed, &service_scope,
    ) { panic!("[realism-e2e] mysql round-trip failed: {e}"); }
    if let Err(e) = assert_mssql_round_trip(
        &chain, &service_workdir, &_mssql_seed, &service_scope,
    ) { panic!("[realism-e2e] mssql round-trip failed: {e}"); }
    eprintln!("[realism-e2e] service-evidence round-trip witnesses satisfied");

    // ── Transparent-proxy round-trip ─────────────────────────
    // Companion witness to `service_evidence`: asserts the
    // executor used stock client libraries against stock env vars
    // (no raxis shims) AND that the kernel refused any direct-
    // upstream egress (proxy is the only path). Together with the
    // service-evidence pass above this proves the transparency
    // contract end-to-end.
    let tp_workdir = locate_executor_worktree(
        kernel.data_dir(),
        &initiative_primary,
        TASK_TRANSPARENT_PROXY_REALSCRIPTS,
    );
    let tp_scope = WitnessScope::new(
        initiative_primary.clone(),
        TASK_TRANSPARENT_PROXY_REALSCRIPTS.to_owned(),
    );
    let tp_expectations = TransparentProxyExpectations {
        postgres: pg_seed.clone(),
        mongodb:  mongo_seed.clone(),
        redis:    redis_seed.clone(),
        smtp:     smtp_seed.clone(),
        mysql:    _mysql_seed.clone(),
        mssql:    _mssql_seed.clone(),
    };
    let tp_failures = tp_evidence::collect_active_witness_failures(
        &chain,
        &tp_workdir,
        &tp_expectations,
        &tp_scope,
    );
    assert!(
        tp_failures.is_empty(),
        "[realism-e2e] transparent-proxy witnesses failed:\n{}",
        tp_evidence::render_failures(&tp_failures),
    );
    eprintln!("[realism-e2e] transparent-proxy round-trip witnesses satisfied");

    tier3.add_worktree(
        format!("primary-xfile ({})", &initiative_primary),
        &primary_workdir,
    );
    tier3.add_worktree(
        format!("primary-services ({})", &initiative_primary),
        &service_workdir,
    );
    // Surface the transparent-proxy worktree so an operator
    // inspecting a Tier-3 failure can `cat
    // <workdir>/out/services/*.txt` and
    // `<workdir>/scripts/last_run_summary.txt` directly. We use a
    // label suffix that names the two notable paths so the
    // copy-pasteable line tells the operator exactly what to look
    // for without needing a separate note entry.
    tier3.add_worktree(
        format!(
            "primary-transparent-proxy ({}; out/services/ + {WRAPPER_SUMMARY_PATH})",
            &initiative_primary,
        ),
        &tp_workdir,
    );
    // ── Graceful shutdown ────────────────────────────────────
    let status = kernel.shutdown_with(libc::SIGTERM, SHUTDOWN_DEADLINE);
    assert!(
        status.success(),
        "kernel must exit cleanly (got {:?}); stderr:\n{}",
        status,
        kernel.captured_stderr(),
    );

    // ── Post-mortem chain integrity ──────────────────────────
    let final_chain = walk_chain_or_panic(kernel.data_dir());
    let audit_witness = AuditChainWitness::for_data_dir(kernel.data_dir());
    let structural_report = audit_witness.assert_structural();
    eprintln!(
        "[realism-e2e] AuditChainWitness::walk_structural: {} records walked, \
         last_seq={}, {} segment(s), {} distinct event_kind(s)",
        structural_report.records_walked,
        structural_report.last_seq,
        structural_report.segments.len(),
        structural_report.kinds_seen.len(),
    );
    eprintln!(
        "[realism-e2e] final chain integrity verified ({} events; \
         primary={initiative_primary}, sibling={initiative_sibling}; \
         primary_workdir={})",
        final_chain.len(),
        primary_workdir.display(),
    );

    tier3.mark_success();
    // `tier3` Drop runs here (or unwinds via a panic above), emitting
    // the post-run artifact block exactly once.
}

// ---------------------------------------------------------------------------
// Wiring smoke test — exercises every realism witness against a
// hand-built synthetic chain so the wiring is mechanically
// validated even when neither gate is set.
// ---------------------------------------------------------------------------

fn wiring_smoke_test() {
    use extended_e2e_support::{
        crash_recovery, multi_initiative, path_allowlist,
        reviewer_substantive_disagreement,
    };

    eprintln!("[realism-e2e] wiring smoke test: constructing each realism witness");

    // PathAllowlistPositive: tempdir + seeded file.
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("target/codegen")).unwrap();
    std::fs::write(
        tmp.path().join("target/codegen/build_meta.txt"),
        b"rich-multilang-001\n",
    ).unwrap();
    let path_witness = PathAllowlistPositiveWitness {
        task_id:       TASK_ALLOWLIST_POSITIVE.to_owned(),
        workdir:       tmp.path().to_path_buf(),
        expected_path: PathBuf::from(path_allowlist::EXPECTED_GENERATED_PATH),
    };
    assert!(path_witness.disk_positive(), "smoke: positive path witness disk seed");
    eprintln!("[realism-e2e] smoke: PathAllowlistPositiveWitness constructed");

    // MultiInitiativeIsolation: two-event chain with non-overlapping task_ids.
    let chain = synthetic_multi_initiative_chain();
    let iso_witness =
        MultiInitiativeIsolationWitness::new("init-primary", "init-sibling");
    assert!(
        iso_witness.satisfied_by(&chain),
        "smoke: isolation witness on synthetic chain: {}",
        iso_witness.diagnostic(&chain),
    );
    eprintln!("[realism-e2e] smoke: MultiInitiativeIsolationWitness satisfied");

    // CrashRecovery: synthetic chain with a respawn-as-recovery.
    let crash_chain = synthetic_crash_recovery_chain(TASK_MATERIALIZE);
    let crash_witness = CrashRecoveryWitness::new(TASK_MATERIALIZE);
    assert!(
        crash_witness.satisfied_by(&crash_chain),
        "smoke: crash-recovery witness on synthetic chain: {}",
        crash_witness.diagnostic(&crash_chain),
    );
    eprintln!("[realism-e2e] smoke: CrashRecoveryWitness satisfied");

    // ReviewerSubstantiveDisagreement: synthetic chain + a fixture tasks.db.
    let db_path = seed_minimal_tasks_db(tmp.path(), TASK_LINT_DEFECT,
        "rejected: greeting.rs introduces clippy::useless_conversion");
    let reviewer_witness = ReviewerSubstantiveDisagreementWitness {
        executor_task_id:   TASK_LINT_DEFECT.to_owned(),
        reviewer_a_task_id: reviewer_substantive_disagreement::TASK_REVIEW_LINT_A
                                .to_owned(),
        reviewer_b_task_id: reviewer_substantive_disagreement::TASK_REVIEW_LINT_B
                                .to_owned(),
        sqlite_path:        db_path,
    };
    let reviewer_chain = synthetic_reviewer_chain(TASK_LINT_DEFECT);
    let reviewer_report = reviewer_witness.evaluate(&reviewer_chain);
    assert!(
        reviewer_report.is_pass(),
        "smoke: reviewer-substantive witness: {reviewer_report:#?}",
    );
    eprintln!("[realism-e2e] smoke: ReviewerSubstantiveDisagreementWitness satisfied");

    let _ = crash_recovery::CrashRecoveryWitness::new("placeholder");
    let _ = multi_initiative::sibling_plan_toml();
    let _ = realistic_plan_toml();

    // TransparentProxyEvidence: hand-built worktree fixture +
    // synthetic chain. Validates the witness wires end-to-end and
    // catches a proxy-bypass denial on the negative path. We use
    // a SECOND tempdir so the earlier path-allowlist fixture writes
    // do not collide with the canonical out/services tree this
    // helper lays down.
    let tp_tmp = tempfile::tempdir().unwrap();
    let tp_expectations = tp_evidence::default_expectations();
    tp_evidence::write_canonical_outputs_for_smoke(
        tp_tmp.path(), &tp_expectations,
    ).expect("smoke: write_canonical_outputs_for_smoke");
    let tp_scope = WitnessScope::new(
        "init-primary".to_owned(),
        TASK_TRANSPARENT_PROXY_REALSCRIPTS.to_owned(),
    );
    let tp_chain = tp_evidence::synthetic_transparent_chain(
        "init-primary",
        TASK_TRANSPARENT_PROXY_REALSCRIPTS,
        "sess-tp-smoke",
    );
    let tp_failures = tp_evidence::collect_active_witness_failures(
        &tp_chain, tp_tmp.path(), &tp_expectations, &tp_scope,
    );
    assert!(
        tp_failures.is_empty(),
        "smoke: transparent-proxy witness on synthetic chain:\n{}",
        tp_evidence::render_failures(&tp_failures),
    );
    eprintln!("[realism-e2e] smoke: transparent-proxy witness satisfied");

    eprintln!("[realism-e2e] wiring smoke test passed");
}

// ---------------------------------------------------------------------------
// Synthetic chain builders for the smoke test.
// ---------------------------------------------------------------------------

fn synthetic_multi_initiative_chain() -> Vec<AuditEvent> {
    vec![
        synthetic_event(0, Some("init-primary"), Some("task-A-1"), Some("sess-A-1")),
        synthetic_event(1, Some("init-primary"), Some("task-A-2"), Some("sess-A-2")),
        synthetic_event(2, Some("init-sibling"), Some("task-B-1"), Some("sess-B-1")),
    ]
}

fn synthetic_crash_recovery_chain(task_id: &str) -> Vec<AuditEvent> {
    // Consecutive seqs: the CrashRecoveryWitness fails closed on
    // any unreconciled gap (`unreconciled_gaps`), so the synthetic
    // chain pretends the kernel respawned in the immediately
    // following audit slot. The real-driven test path inserts the
    // genuine post-SIGTERM events in their natural order; only the
    // smoke fixture needs the artificial contiguity.
    vec![
        synthetic_vm_spawn(10, task_id),
        synthetic_vm_spawn(11, task_id),
    ]
}

fn synthetic_reviewer_chain(executor_task_id: &str) -> Vec<AuditEvent> {
    use extended_e2e_support::reviewer_substantive_disagreement::{
        TASK_REVIEW_LINT_A, TASK_REVIEW_LINT_B,
    };
    vec![
        synthetic_intent_accepted(
            0, TASK_REVIEW_LINT_A, "SubmitReview",
        ),
        synthetic_vm_spawn(1, executor_task_id),
        synthetic_intent_accepted(
            2, TASK_REVIEW_LINT_B, "SubmitReview",
        ),
        synthetic_aggregation_pass(3, executor_task_id),
    ]
}

fn synthetic_event(
    seq: u64,
    initiative_id: Option<&str>,
    task_id: Option<&str>,
    session_id: Option<&str>,
) -> AuditEvent {
    AuditEvent {
        seq,
        event_id:      uuid::Uuid::nil(),
        event_kind:    "IntentAccepted".to_owned(),
        session_id:    session_id.map(str::to_owned),
        task_id:       task_id.map(str::to_owned),
        initiative_id: initiative_id.map(str::to_owned),
        payload:       serde_json::to_value(&AuditEventKind::IntentAccepted {
            task_id:         task_id.unwrap_or("").to_owned(),
            session_id:      session_id.unwrap_or("").to_owned(),
            intent_kind:     "Lifecycle".to_owned(),
            base_sha:        None,
            head_sha:        None,
            sequence_number: 1,
            remaining_units: 99,
        }).unwrap(),
        emitted_at:    1700000000 + seq as i64,
        prev_sha256:   "0".repeat(64),
    }
}

fn synthetic_vm_spawn(seq: u64, task_id: &str) -> AuditEvent {
    let payload = AuditEventKind::SessionVmSpawned {
        session_id:         format!("sess-{task_id}-{seq}"),
        task_id:            Some(task_id.to_owned()),
        initiative_id:      "init-primary".to_owned(),
        backend_id:         "test-backend".to_owned(),
        egress_tier:        "Tier1Tproxy".to_owned(),
        admission_loopback: "127.0.0.1:0".to_owned(),
        credential_proxies: 0,
    };
    AuditEvent {
        seq,
        event_id:      uuid::Uuid::nil(),
        event_kind:    "SessionVmSpawned".to_owned(),
        session_id:    Some(format!("sess-{task_id}-{seq}")),
        task_id:       Some(task_id.to_owned()),
        initiative_id: Some("init-primary".to_owned()),
        payload:       serde_json::to_value(&payload).unwrap(),
        emitted_at:    1700000000 + seq as i64,
        prev_sha256:   "0".repeat(64),
    }
}

fn synthetic_intent_accepted(
    seq: u64, task_id: &str, intent_kind: &str,
) -> AuditEvent {
    let payload = AuditEventKind::IntentAccepted {
        task_id:         task_id.to_owned(),
        session_id:      format!("sess-{task_id}"),
        intent_kind:     intent_kind.to_owned(),
        base_sha:        None,
        head_sha:        None,
        sequence_number: 1,
        remaining_units: 99,
    };
    AuditEvent {
        seq,
        event_id:      uuid::Uuid::nil(),
        event_kind:    "IntentAccepted".to_owned(),
        session_id:    Some(format!("sess-{task_id}")),
        task_id:       Some(task_id.to_owned()),
        initiative_id: Some("init-primary".to_owned()),
        payload:       serde_json::to_value(&payload).unwrap(),
        emitted_at:    1700000000 + seq as i64,
        prev_sha256:   "0".repeat(64),
    }
}

fn synthetic_aggregation_pass(seq: u64, executor_task_id: &str) -> AuditEvent {
    use extended_e2e_support::reviewer_substantive_disagreement::TASK_REVIEW_LINT_B;
    let payload = AuditEventKind::ReviewAggregationCompleted {
        executor_task_id:              executor_task_id.to_owned(),
        triggered_by_reviewer_task_id: TASK_REVIEW_LINT_B.to_owned(),
        reviewer_count:                2,
        verdict:                       "AllPassed".to_owned(),
    };
    AuditEvent {
        seq,
        event_id:      uuid::Uuid::nil(),
        event_kind:    "ReviewAggregationCompleted".to_owned(),
        session_id:    None,
        task_id:       Some(executor_task_id.to_owned()),
        initiative_id: Some("init-primary".to_owned()),
        payload:       serde_json::to_value(&payload).unwrap(),
        emitted_at:    1700000000 + seq as i64,
        prev_sha256:   "0".repeat(64),
    }
}

fn seed_minimal_tasks_db(
    tmpdir: &Path, executor_task: &str, critique: &str,
) -> PathBuf {
    use raxis_store::Table;
    let db_path = tmpdir.join("smoke.db");
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let tasks = Table::Tasks.as_str();
    conn.execute_batch(&format!(
        "CREATE TABLE {tasks} (\
            task_id TEXT PRIMARY KEY,\
            last_critique TEXT\
        );",
    )).unwrap();
    conn.execute(
        &format!(
            "INSERT INTO {tasks} (task_id, last_critique) VALUES (?1, ?2)",
        ),
        rusqlite::params![executor_task, critique],
    ).unwrap();
    db_path
}

// ---------------------------------------------------------------------------
// Seed-overlay helper.
//
// The kernel creates `<data_dir>/worktrees/<initiative>/<task>/`
// lazily, after PlanApproved + OrchestratorSpawned. The realistic
// scenario needs the rich-multilang-001 seed history to be present
// in the worktree BEFORE the xfile-refactor executor first reads
// the tree. We poll for the worktree to exist and then invoke
// `materialize_seed.sh` against it.
//
// TIMING CAVEAT: the kernel may have already started the executor
// VM between our poll and our overlay write. In practice the
// realistic plan dependency chain (Orchestrator plans before
// `xfile-refactor` admits) gives us a few hundred milliseconds of
// slack; the executor's first `cargo metadata` read happens after
// the worktree-provisioning step completes. A future commit on
// this branch should wire a `pre-task` hook so the seed overlay
// can run *inside* the provisioning step deterministically.
// ---------------------------------------------------------------------------

fn materialise_realistic_seed(
    data_dir: &Path,
    initiative_id: &str,
    task_id: &str,
) {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let workdir: PathBuf = loop {
        if std::time::Instant::now() > deadline {
            panic!(
                "timed out waiting for worktree at \
                 <data_dir>/worktrees/{initiative_id}/{task_id}/",
            );
        }
        let candidate = data_dir.join("worktrees")
            .join(initiative_id)
            .join(task_id);
        if candidate.exists() {
            break candidate;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    eprintln!("[realism-e2e] worktree appeared at {}; overlaying seed",
        workdir.display());

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let seed_script = manifest_dir
        .parent()
        .map(|p| p.join("live-e2e/seed/repo")
                    .join(SEED_SCENARIO_ID)
                    .join("scripts/materialize_seed.sh"))
        .expect("workspace parent dir present");

    let status = std::process::Command::new(&seed_script)
        .arg(&workdir)
        .status()
        .expect("invoke materialize_seed.sh");
    assert!(
        status.success(),
        "materialize_seed.sh exited non-zero: {status:?}",
    );

    eprintln!("[realism-e2e] seed materialised into {}", workdir.display());
}

// ---------------------------------------------------------------------------
// Transparent-proxy script overlay.
//
// The `transparent-proxy-realscripts` executor task expects the
// stock-Python service-integrity scripts to be present at
// `<worktree>/scripts/` BEFORE it wakes up. The scripts live
// under `live-e2e/seed/scripts/transparent_proxy/` in the
// repository; this helper polls for the executor's worktree to
// materialise, then asks the witness module to copy every pinned
// script into it.
//
// We delegate to `tp_evidence::stage_scripts_into_worktree` so the
// list of staged files lives in exactly ONE place (the witness's
// `STAGED_SCRIPT_NAMES` constant) — the staging path and the
// witness-side test both consult the same source-of-truth list.
// ---------------------------------------------------------------------------

fn stage_transparent_proxy_scripts(
    data_dir: &Path,
    initiative_id: &str,
    task_id: &str,
) {
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    let workdir: PathBuf = loop {
        if std::time::Instant::now() > deadline {
            panic!(
                "timed out waiting for transparent-proxy worktree at \
                 <data_dir>/worktrees/{initiative_id}/{task_id}/ — \
                 the kernel never materialised the executor's tree; \
                 staging the stock-Python scripts is impossible",
            );
        }
        let candidate = data_dir.join("worktrees")
            .join(initiative_id)
            .join(task_id);
        if candidate.exists() {
            break candidate;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    eprintln!(
        "[realism-e2e] transparent-proxy worktree appeared at {}; \
         staging stock-Python check_*.py + run_all_services.sh + requirements.txt",
        workdir.display(),
    );

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .expect("workspace parent dir present")
        .to_path_buf();

    let staged = tp_evidence::stage_scripts_into_worktree(
        &workdir,
        &workspace_root,
    ).unwrap_or_else(|e| {
        panic!(
            "failed to stage transparent-proxy scripts into {}: {e}",
            workdir.display(),
        )
    });
    eprintln!(
        "[realism-e2e] staged {} stock-Python file(s) into {}/scripts/",
        staged.len(),
        workdir.display(),
    );
}
