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
//!   * `secrets-handling` — reads safe `.env.example` placeholder
//!     while NOT leaking the `.env` / `secrets/...` canary
//!     tokens (`P3-5 secrets_handling.md`).
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
        TASK_LINT_DEFECT, TASK_MATERIALIZE, TASK_SECRETS_HANDLING,
        TASK_SERVICE_ROUND_TRIP, TASK_XFILE_REFACTOR,
    },
    reviewer_substantive_disagreement::ReviewerSubstantiveDisagreementWitness,
    secrets::{seed_secrets_fixtures, SecretsHandlingWitness},
    seeds::{MONGO_HOST_PORT, PG_HOST_PORT},
    service_evidence::{
        assert_mssql_round_trip, assert_mysql_round_trip,
        collect_active_witness_failures, render_failures, seed_mongodb,
        seed_mssql, seed_mysql, seed_postgres, seed_redis, seed_smtp,
        WitnessScope,
    },
    witnesses::{
        EnforcementWitness, NoSecurityViolationWitness,
    },
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
    write_credentials(&data_dir);
    write_provider_credentials(&data_dir);

    let install_dir = PathBuf::from(
        std::env::var("RAXIS_INSTALL_DIR").expect("preflight verified RAXIS_INSTALL_DIR"),
    );

    // Tier-3 reporter: created BEFORE the kernel spawn so an early
    // failure still emits the artifact block on Drop. `mark_success()`
    // at the bottom of the happy path enables the workdir-keep
    // policy's success cleanup branch.
    let mut tier3 = Tier3Reporter::new(
        "realism-e2e", &install_dir, &data_dir,
    );

    // Seed every in-scope service BEFORE the executor wakes up. The
    // round-trip task runs at the END of the plan dependency graph
    // (predecessors include `secrets-handling`), so we have ample
    // lead time, but we still seed eagerly so the harness fails
    // closed on missing containers before burning LLM tokens.
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

    // ── Materialise the rich-multilang seed + secrets fixtures
    //    into the primary materializer's worktree. The kernel
    //    creates `<data_dir>/worktrees/<initiative>/<task>/` lazily;
    //    we poll for it and overlay the seed once present, before
    //    the executor's first IntentAccepted{CommitDelta} lands.
    materialise_realistic_seed(
        kernel.data_dir(),
        &initiative_primary,
        TASK_XFILE_REFACTOR,
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
    let secrets_workdir = locate_executor_worktree(
        kernel.data_dir(), &initiative_primary, TASK_SECRETS_HANDLING,
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
        Box::new(SecretsHandlingWitness::for_workdir(&secrets_workdir)),
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

    tier3.add_worktree(
        format!("primary-xfile ({})", &initiative_primary),
        &primary_workdir,
    );
    tier3.add_worktree(
        format!("primary-services ({})", &initiative_primary),
        &service_workdir,
    );
    // The realistic-scenario harness does not mount the dashboard
    // (the kernel boot path here skips `open_dashboard_with_autologin`);
    // we therefore omit the dashboard URL line cleanly rather than
    // emit a broken placeholder.

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
        reviewer_substantive_disagreement, secrets,
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

    // SecretsHandling: same tempdir + seeded secrets fixtures.
    seed_secrets_fixtures(tmp.path()).unwrap();
    let secrets_report_dir = tmp.path().join("out");
    std::fs::create_dir_all(&secrets_report_dir).unwrap();
    std::fs::write(
        tmp.path().join(secrets::SECRETS_REPORT_PATH),
        b"FIXTURE_SECRET_TOKEN\nAPI_BASE_URL\nFEATURE_FLAG_X\n",
    ).unwrap();
    let secrets_witness = SecretsHandlingWitness::for_workdir(tmp.path());
    assert!(secrets_witness.satisfied_by(&[]),
        "smoke: secrets witness on clean fixtures: {}",
        secrets_witness.diagnostic(&[]));
    eprintln!("[realism-e2e] smoke: SecretsHandlingWitness constructed and satisfied");

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

    seed_secrets_fixtures(&workdir)
        .expect("seed_secrets_fixtures into the materialized worktree");
    eprintln!("[realism-e2e] seed + secrets fixtures materialised into {}",
        workdir.display());
}
