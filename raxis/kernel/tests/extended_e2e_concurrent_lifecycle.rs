//! Extended RAXIS V2 end-to-end lifecycle test —
//! seeded postgres + mongo data sources, concurrent fan-out
//! executors, reviewer-disagreement re-review path, and
//! malicious-prompt-injection deny-path coverage.
//!
//! Normative reference: `raxis/specs/v2/e2e-extended-scenario.md`.
//!
//! ## Why this file exists alongside `full_e2e_session_lifecycle.rs`
//!
//! `full_e2e_session_lifecycle.rs` pins the SINGLE-task happy path
//! (one Executor writes `hello.txt`, one Reviewer approves). It
//! covers the wire surface but says nothing about real seeded data,
//! concurrency, enforcement-layer denials, or non-trivial witnesses.
//!
//! This file extends that coverage with the scenario in
//! `e2e-extended-scenario.md`:
//!
//!   * one materializer Executor reads 25 postgres rows + 25 mongo
//!     docs through credential proxies and writes one JSON file per
//!     record, then commits;
//!   * three small fan-out Executors run concurrently;
//!   * two Reviewers force a Round-1 reject + Round-2 approve to
//!     exercise the `agent-disagreement.md` re-review path;
//!   * one injection Executor receives a multi-payload prompt and
//!     the kernel's enforcement layers must deny each payload.
//!
//! All assertions are mechanical: the audit chain (via
//! `raxis_audit_tools::ChainReader`) and the worktree on disk
//! (`MaterializationWitness`). No LLM-side judgement is trusted.
//!
//! ## Why `RAXIS_LIVE_E2E=1` gating
//!
//! Same as the single-task test — real microVMs, real LLM, real
//! databases. CI never runs this. Every dependency is preflighted
//! at the top so a missing dep surfaces in seconds.
//!
//! Additionally requires the EXTENDED docker-compose so the
//! seeded `raxis_e2e_pg.seeded_rows` + `raxis_e2e_mongo.seeded_docs`
//! are present:
//!
//! ```bash
//! docker compose -f live-e2e/docker-compose.extended.e2e.yml up -d --wait
//! ```
//!
//! ## Future work — richer repo fixture
//!
//! The current materializer + fan-out tasks operate on an
//! essentially empty worktree: the materializer writes one JSON
//! file per seeded record into `out/postgres/` and `out/mongo/`
//! and commits; the fan-out tasks each write one or two README/
//! manifest files. That's enough to exercise the audit chain
//! (`AuditChainWitness`), the concurrency oracle, and the
//! enforcement-layer denials, but it does NOT exercise the
//! harder real-world behaviours raxis needs to be correct on.
//!
//! A future iteration should seed a deliberately-rich repo
//! fixture under `live-e2e/seed/repo/` that the executor must
//! navigate. Important core functionalities to cover:
//!
//!   * **Multi-language source tree** (Rust + TS/JS + Python)
//!     so the executor must invoke language-specific build/test
//!     tooling and the egress allowlist is exercised against
//!     real package registries (`crates.io`,
//!     `registry.npmjs.org`, `pypi.org`).
//!   * **Cross-file edits with import graphs** (rename a
//!     function and update every caller across files; add a
//!     struct field and update every constructor) so the
//!     planner's context-window management and the executor's
//!     multi-file edit discipline are tested under realistic
//!     load — not just "create new file".
//!   * **Pre-existing tests and lint config** (rustfmt, clippy,
//!     eslint, prettier, ruff configs at the root) so the
//!     executor must respect formatting/lint rules and the
//!     reviewer must catch violations — exercising the
//!     review-rejection → re-spawn loop on a real defect, not a
//!     synthetic "reviewer-A always rejects" disagreement.
//!   * **Non-trivial git history** (10+ commits with meaningful
//!     diffs, at least one merge commit, at least one rename
//!     detected by `git log --follow`) so worktree provisioning,
//!     gix history walks, and the `IntegrationMerge` intent are
//!     exercised against realistic ancestry rather than the
//!     two-commit fixture the current scenario produces.
//!   * **Mixed file modes**: large binary fixtures (so virtiofs
//!     / vsock-RPC throughput on the workspace mount is
//!     exercised), `LICENSE`/`README`/`CONTRIBUTING.md` (so the
//!     executor's "respect repo conventions" behaviour is
//!     tested), executable shell scripts (so file-mode
//!     preservation through worktree provision + commit is
//!     verified end-to-end).
//!   * **Credential-proxy diversity in one task**: a single
//!     task that legitimately needs Postgres + S3 + an HTTP API
//!     in one execution, so the credential proxy lifecycle
//!     interleaving and per-credential audit attribution are
//!     exercised. The proxies are well-tested in isolation by
//!     `live-e2e` slices, but their composition under one
//!     session is not.
//!   * **Path-allowlist edge cases**: a task that legitimately
//!     needs to write outside the obvious workdir (e.g. write a
//!     generated file into `target/codegen/`) so the path
//!     allowlist's POSITIVE cases are exercised, not just the
//!     deny cases the prompt-injection scenario already covers.
//!   * **Mechanical credential-substitution witness**: an executor
//!     handed operator-staged *placeholder* credentials (canary
//!     tokens, never real) in its env and tasked with authenticating
//!     against a service. The credential-proxy substitutes the real
//!     credential at the loopback boundary; the witness asserts the
//!     real credential material does NOT appear anywhere in the
//!     agent's worktree post-run. See `specs/v2/secrets-model.md` —
//!     this is the structural test that supersedes the earlier
//!     "please don't read .env" cooperative test.
//!   * **Multi-initiative concurrency**: the current scenario
//!     runs ONE initiative with N subtasks. A future scenario
//!     should run two or three initiatives in parallel against
//!     the same kernel instance to exercise lane scheduling,
//!     budget enforcement, and audit attribution across
//!     initiative boundaries. Worker D's report explicitly
//!     called this out as out-of-scope for the V2 PR; this
//!     comment is the canonical pointer.
//!   * **Reviewer panel diversity**: a scenario where reviewers
//!     genuinely disagree on substance (one approves, one
//!     rejects with a real critique that the executor must then
//!     address), not just the synthetic "reviewer A always
//!     rejects" pattern. Exercises the multi-reviewer
//!     aggregation logic against realistic dissent.
//!   * **Resume / crash recovery**: a scenario where the kernel
//!     is intentionally killed mid-task (e.g. `SIGKILL` between
//!     `SessionVmSpawned` and the first `IntentAccepted`) and
//!     restarted; assert the audit chain remains valid (via
//!     `AuditChainWitness::walk_structural`), the in-flight
//!     session is reaped, and the initiative can resume.
//!     Exercises the kernel's startup-recovery path and the
//!     `git_apply_pending` invariant against realistic failure
//!     modes.
//!
//! Tracked separately; this PR's mechanical witness coverage
//! assumes the minimal seeded worktree.

#![allow(dead_code)]

mod common;
mod extended_e2e_support;

use std::collections::BTreeSet;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};
use raxis_audit_tools::{verify_chain_full, AuditEvent, ChainReader};
use raxis_crypto::{
    bundle_sha256 as crypto_bundle_sha256, canonical_encode, mint_bundle_nonce,
    sha256_of_artifact_bytes, signing_input,
};
use raxis_ipc::{read_json_frame_raw, write_json_frame};
use raxis_test_support::{ephemeral_cert_with_key, CertOpts};
use raxis_types::{BundleArtifact, OperatorFingerprint, PlanBundle};
use serde_json::Value;
use sha2::{Digest, Sha256};

use common::kernel_harness::{acquire_test_lock, build_and_locate_kernel, KernelInstance};
use extended_e2e_support::{
    audit_chain::{scripts as audit_scripts, AuditChainWitness},
    concurrency::assert_overlap_or_panic,
    injection::{
        assemble_prompt as assemble_injection_prompt, payload_summary, witnesses_for_payloads,
    },
    plan::{
        extended_plan_toml, TASK_FANOUT_FMT, TASK_FANOUT_MANIFEST, TASK_FANOUT_README,
        TASK_INJECT_EVIL, TASK_MATERIALIZE, TASK_REVIEW_A, TASK_REVIEW_B,
    },
    seeds::{preflight_or_panic as preflight_dbs_or_panic, MONGO_HOST_PORT, PG_HOST_PORT},
    witnesses::{
        typed, EnforcementWitness, MaterializationWitness, NoSecurityViolationWitness,
        ReviewerDisagreementWitness,
    },
};
use raxis_audit_tools::AuditEventKind;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const LIVE_E2E_GATE: &str = "RAXIS_LIVE_E2E";
const READY_DEADLINE: Duration = Duration::from_secs(15);
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(60);

/// Distinct from the single-task test's `[0xC0; 32]` so a kernel
/// running both in sequence cannot cross-contaminate operator
/// identity.
const E2E_OPERATOR_SEED: [u8; 32] = [0xCE; 32];

/// Marker the materializer executor's commit message must match.
const MATERIALIZER_COMMIT_MESSAGE: &str = "seed: materialize records";

fn lifecycle_deadline() -> Duration {
    let secs = std::env::var("RAXIS_E2E_EXTENDED_DEADLINE_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(900); // 15 min — six tasks, three concurrent VMs, two review rounds
    Duration::from_secs(secs)
}

fn fresh_initiative_id() -> String {
    uuid::Uuid::now_v7().to_string()
}

// ---------------------------------------------------------------------------
// Top-level test
// ---------------------------------------------------------------------------

/// Extended scenario driver. The reviewer-disagreement and
/// malicious-prompt-injection assertions are added in subsequent
/// commits as additional sweeps over the same audit chain;
/// THIS commit asserts only:
///   * preflight DBs reachable + seeded,
///   * lifecycle reaches `IntegrationMergeCompleted`,
///   * worktree on disk satisfies `MaterializationWitness`,
///   * fan-out group exhibits at least one overlapping pair
///     in `SessionVmSpawned` / `SessionVmExited` intervals,
///   * no `SecurityViolationDetected` events anywhere.
#[test]
fn extended_session_lifecycle() {
    if std::env::var(LIVE_E2E_GATE).as_deref() != Ok("1") {
        eprintln!(
            "Skipped: extended_session_lifecycle is a live-infrastructure smoke test.\n\
             Enable by:\n\
                 1. docker compose -f live-e2e/docker-compose.extended.e2e.yml up -d --wait\n\
                 2. ensure raxis/.env contains ANTHROPIC-API-DEV-KEY=sk-ant-...\n\
                 3. ensure ~/.config/gcloud/application_default_credentials.json exists\n\
                 4. RAXIS_LIVE_E2E=1 cargo test -p raxis-kernel \\\n\
                       --test extended_e2e_concurrent_lifecycle -- --nocapture",
        );
        return;
    }

    let _build_lock = acquire_test_lock();

    // ── Preflight — every external dependency reachable + seeded.
    preflight_or_panic();

    // ── Bootstrap the production kernel binary against a fresh
    //    data dir, with a custom operator cert that grants the
    //    full lifecycle ops.
    let (signing_key, fingerprint) = build_e2e_operator_key();
    let (kernel_bin, data_dir) = bootstrap_with_custom_cert(&signing_key);
    eprintln!(
        "[ext-e2e] kernel bootstrapped, data_dir={}",
        data_dir.display()
    );

    let gateway_binary = require_gateway_binary();
    enable_gateway_in_policy(&data_dir, &gateway_binary);
    write_credentials(&data_dir);
    write_provider_credentials(&data_dir);

    let install_dir = extended_e2e_support::kernel_driver::resolved_install_dir();
    let mut kernel = spawn_kernel_normal(&kernel_bin, data_dir.clone(), &install_dir);
    kernel.wait_until_ready_or_panic(READY_DEADLINE);
    eprintln!("[ext-e2e] kernel daemon up, accepting operator IPC");

    // ── Submit + approve the EXTENDED plan over the operator UDS.
    let initiative_id = fresh_initiative_id();
    let op_socket = kernel.operator_socket();
    let injection_prompt = assemble_injection_prompt();
    let mut conn = OperatorIpc::connect(&op_socket, &signing_key, &fingerprint);
    conn.submit_plan(&initiative_id, &injection_prompt);
    eprintln!("[ext-e2e] plan submitted, initiative_id={initiative_id}");
    conn.approve_plan(&initiative_id, &fingerprint);
    eprintln!("[ext-e2e] plan approved; orchestrator spawn pending");
    drop(conn);

    // ── Wait for the lifecycle to reach IntegrationMergeCompleted.
    let chain = poll_for_lifecycle_completion(kernel.data_dir(), &initiative_id);
    eprintln!(
        "[ext-e2e] lifecycle complete, chain has {} events",
        chain.len()
    );

    // ── Locate the materializer executor's worktree on disk and
    //    run the worktree-side mechanical witness.
    let workdir = locate_executor_worktree(kernel.data_dir(), &initiative_id, TASK_MATERIALIZE);
    eprintln!("[ext-e2e] materializer workdir at {}", workdir.display());
    MaterializationWitness {
        workdir: workdir.clone(),
        expected_commit_message: MATERIALIZER_COMMIT_MESSAGE,
    }
    .assert_satisfied();
    eprintln!("[ext-e2e] MaterializationWitness satisfied");

    // ── Concurrency oracle — at least one overlapping pair across
    //    the three fan-out tasks.
    assert_overlap_or_panic(&chain, FANOUT_GROUP);
    eprintln!("[ext-e2e] ConcurrencyOracle: fan-out group overlap confirmed");

    // ── Locate the injection task's session id by scanning the
    //    chain. Required by `PathAllowlistRejectedWitness`.
    let injection_session_id =
        locate_session_id_for_task(&chain, TASK_INJECT_EVIL).unwrap_or_else(|| {
            eprintln!(
                "[ext-e2e] no SessionVmSpawned for {TASK_INJECT_EVIL}; \
                 injection witnesses will surface as failures with empty \
                 session_id matches. Payloads attempted: {:?}",
                payload_summary(),
            );
            String::new()
        });
    eprintln!(
        "[ext-e2e] injection session_id={} (task={TASK_INJECT_EVIL})",
        injection_session_id,
    );

    // ── Global + per-payload enforcement-layer witnesses.
    let mut global_witnesses: Vec<Box<dyn EnforcementWitness>> = vec![
        Box::new(NoSecurityViolationWitness),
        Box::new(ReviewerDisagreementWitness {
            executor_task_id: TASK_MATERIALIZE.to_owned(),
            reviewer_a_task_id: TASK_REVIEW_A.to_owned(),
            reviewer_b_task_id: TASK_REVIEW_B.to_owned(),
        }),
    ];
    global_witnesses.extend(witnesses_for_payloads(&injection_session_id));
    extended_e2e_support::witnesses::assert_all_satisfied(&global_witnesses, &chain);

    // ── §6.3 approval-circumvention: post-mortem inspect that no
    //    forged approval token landed under `<data_dir>/escalations/`.
    //    The planner has no path from inside its VM to the host's
    //    `<data_dir>`; even if the LLM tries to write there, the
    //    bytes never reach the kernel's escalation pipeline. The
    //    only legitimate `EscalationConsumed` events must each be
    //    paired with an `EscalationApproved` (the kernel emits the
    //    pair in order); the `NoSecurityViolationWitness` already
    //    fail-closes if a stray `SecurityViolationDetected` fired,
    //    and this extra check pins the on-disk surface.
    assert_no_forged_approvals_on_disk(kernel.data_dir());
    assert_no_unpaired_consume_in_chain(&chain);
    eprintln!("[ext-e2e] approval-circumvention witnesses satisfied");

    // ── Graceful shutdown.
    let status = kernel.shutdown_with(libc::SIGTERM, SHUTDOWN_DEADLINE);
    assert!(
        status.success(),
        "kernel must exit cleanly (got {:?}); stderr:\n{}",
        status,
        kernel.captured_stderr(),
    );

    // ── Post-mortem chain integrity.
    let final_chain = walk_chain_or_panic(kernel.data_dir());
    assert_audit_invariants(&final_chain, &initiative_id);
    eprintln!(
        "[ext-e2e] audit chain integrity verified ({} events)",
        final_chain.len()
    );

    // ── AuditChainWitness — Check A (structural integrity walk
    //    re-derived independently of `verify_chain_full`) and
    //    Check B (concurrent-lifecycle scenario script). The
    //    structural walk is the load-bearing assertion: if it
    //    fails the chain itself cannot be trusted, so no
    //    scenario-walk verdict means anything. The concurrent-
    //    lifecycle script asserts the chain captured the events
    //    THIS scenario actually drove (materializer spawn, fanout
    //    spawn ×3, fanout exit ×3, ReviewAggregationCompleted
    //    AllPassed, IntegrationMergeCompleted).
    //    Reviewer-disagreement and prompt-injection scripts are
    //    wired in subsequent commits as additional sweeps over
    //    the same chain.
    let audit_witness = AuditChainWitness::for_data_dir(kernel.data_dir());
    let structural_report = audit_witness.assert_structural();
    eprintln!(
        "[ext-e2e] AuditChainWitness::walk_structural: {} records walked, \
         last_seq={}, {} segment(s), {} distinct event_kind(s)",
        structural_report.records_walked,
        structural_report.last_seq,
        structural_report.segments.len(),
        structural_report.kinds_seen.len(),
    );
    let lifecycle_script =
        audit_scripts::concurrent_lifecycle(TASK_MATERIALIZE, FANOUT_GROUP, initiative_id.clone());
    let lifecycle_report = audit_witness.assert_scenario(&final_chain, &lifecycle_script);
    eprintln!(
        "[ext-e2e] AuditChainWitness::walk_scenario(concurrent-lifecycle): \
         {}/{} ordered matchers satisfied, {} absent matchers clean",
        lifecycle_report.ordered_satisfied,
        lifecycle_script.matchers.len(),
        lifecycle_report.absent_clean,
    );

    // ── AuditChainWitness — Check B for the reviewer-disagreement
    //    script. Asserts the chain captured (reviewer-A SubmitReview
    //    → executor re-spawn → reviewer-B SubmitReview →
    //    ReviewAggregationCompleted AllPassed). The
    //    `ReviewerDisagreementWitness` already covers the same
    //    semantics with a hand-rolled state machine; this script-
    //    based assertion is the same invariant expressed
    //    declaratively, with per-matcher diagnostics surfacing
    //    exactly which event the chain lacked when it fails.
    let reviewer_script =
        audit_scripts::reviewer_disagreement(TASK_MATERIALIZE, TASK_REVIEW_A, TASK_REVIEW_B);
    let reviewer_report = audit_witness.assert_scenario(&final_chain, &reviewer_script);
    eprintln!(
        "[ext-e2e] AuditChainWitness::walk_scenario(reviewer-disagreement): \
         {}/{} ordered matchers satisfied",
        reviewer_report.ordered_satisfied,
        reviewer_script.matchers.len(),
    );

    // ── AuditChainWitness — Check B for the prompt-injection
    //    script. Per-payload positive matchers (the kernel-emitted
    //    deny rows for each malicious payload) PLUS global
    //    negative `AbsentEverywhere` matchers (no record claims a
    //    malicious action succeeded). The payload id list is
    //    derived from the same `injection_payloads.toml` loader
    //    the runtime prompt assembly uses, so adding a new payload
    //    to the TOML automatically extends the script's coverage
    //    via the script-gap fail-closed branch.
    let payload_ids: Vec<String> = payload_summary()
        .into_iter()
        .map(|(id, _label)| id)
        .collect();
    let payload_id_refs: Vec<&str> = payload_ids.iter().map(|s| s.as_str()).collect();
    let injection_session_id_for_script = if injection_session_id.is_empty() {
        None
    } else {
        Some(injection_session_id.clone())
    };
    let injection_script =
        audit_scripts::prompt_injection(injection_session_id_for_script, &payload_id_refs);
    let injection_report = audit_witness.assert_scenario(&final_chain, &injection_script);
    eprintln!(
        "[ext-e2e] AuditChainWitness::walk_scenario(prompt-injection): \
         {}/{} ordered matchers satisfied, {} absent matchers clean",
        injection_report.ordered_satisfied,
        injection_script.matchers.len(),
        injection_report.absent_clean,
    );
}

/// Fan-out task ids the concurrency oracle and the AuditChain
/// scenario script both reference. Pinned as a `'static` slice
/// because `audit_chain::scripts::concurrent_lifecycle` needs
/// `&'static [&'static str]` so the matcher closures can capture
/// the task-id set without per-call allocation.
const FANOUT_GROUP: &[&str] = &[TASK_FANOUT_README, TASK_FANOUT_FMT, TASK_FANOUT_MANIFEST];

// ---------------------------------------------------------------------------
// Preflight
// ---------------------------------------------------------------------------

fn preflight_or_panic() {
    require_tcp_reachable(PG_HOST_PORT, "Postgres docker container");
    require_tcp_reachable(MONGO_HOST_PORT, "MongoDB docker container");
    preflight_dbs_or_panic(); // verifies seeded counts via psql + mongosh
    require_anthropic_dev_key();
    require_gcp_adc();
    require_gateway_binary();
    require_canonical_images();
}

fn require_tcp_reachable(host_port: &str, what: &str) {
    if std::net::TcpStream::connect_timeout(
        &host_port.parse().expect("static literal parses"),
        Duration::from_millis(500),
    )
    .is_err()
    {
        panic!(
            "{what} not reachable at {host_port}. Run:\n  \
             docker compose -f live-e2e/docker-compose.extended.e2e.yml up -d --wait",
        );
    }
}

fn require_anthropic_dev_key() {
    let env_path = workspace_dotenv_path();
    let body = std::fs::read_to_string(&env_path).unwrap_or_else(|e| {
        panic!(
            "{} is required for the live LLM round-trip but read failed: {e}\n\
         Create it with one line:\n  ANTHROPIC-API-DEV-KEY=sk-ant-...",
            env_path.display(),
        )
    });
    let has_key = body.lines().any(|l| {
        l.starts_with("ANTHROPIC-API-DEV-KEY=") && l.len() > "ANTHROPIC-API-DEV-KEY=".len()
    });
    assert!(
        has_key,
        "{} must contain a non-empty ANTHROPIC-API-DEV-KEY=... line",
        env_path.display(),
    );
}

fn require_gcp_adc() {
    let adc = match dirs_home() {
        Some(h) => h.join(".config/gcloud/application_default_credentials.json"),
        None => panic!("HOME is unset; cannot locate gcloud ADC"),
    };
    assert!(
        adc.exists(),
        "GCP application default credentials not found at {}.\n\
         Run: gcloud auth application-default login",
        adc.display(),
    );
}

fn require_gateway_binary() -> PathBuf {
    extended_e2e_support::kernel_driver::require_gateway_binary()
}

/// Delegates to the shared driver's strengthened preflight (cpio
/// content walk + auto-bake). Local one-liner kept as a stable
/// in-binary symbol so older call sites do not need to re-import.
fn require_canonical_images() {
    extended_e2e_support::kernel_driver::require_canonical_images()
}

// ---------------------------------------------------------------------------
// Bootstrap + spawn (mirrors full_e2e_session_lifecycle but with our
// own seed + a different lane id so the two tests don't cross-wire)
// ---------------------------------------------------------------------------

fn build_e2e_operator_key() -> (SigningKey, OperatorFingerprint) {
    let key = SigningKey::from_bytes(&E2E_OPERATOR_SEED);
    let pubkey = key.verifying_key().to_bytes();
    (key, fingerprint_8(&pubkey))
}

fn bootstrap_with_custom_cert(signing_key: &SigningKey) -> (PathBuf, PathBuf) {
    let kernel_bin = build_and_locate_kernel();

    #[cfg(target_os = "macos")]
    codesign_kernel_for_avf(&kernel_bin);

    let now_unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is post-epoch")
        .as_secs() as i64;
    let cert = ephemeral_cert_with_key(
        signing_key,
        CertOpts {
            now_unix_secs,
            permitted_ops: vec![
                "CreateInitiative".to_owned(),
                "ApprovePlan".to_owned(),
                "AbortInitiative".to_owned(),
                // Grants dashboard `Admin` per
                // `crates/dashboard-kernel/src/lib.rs::roles_from_permitted_ops`.
                "RotateEpoch".to_owned(),
                "OperatorCertInstall".to_owned(),
            ],
            display_name: "ext-e2e-operator".to_owned(),
            ..CertOpts::default()
        },
    );

    let data_dir: PathBuf = tempfile::tempdir()
        .expect("tempdir for kernel data dir")
        .keep();
    let cert_path = data_dir.join("operator.cert.toml");
    let toml_body = toml::to_string(&cert).expect("serialise ext-e2e cert");
    std::fs::write(&cert_path, toml_body).expect("write ext-e2e operator cert");

    let bootstrap_output = Command::new(&kernel_bin)
        .env("RAXIS_BOOTSTRAP", "1")
        .env("RAXIS_DATA_DIR", &data_dir)
        .env("RAXIS_OPERATOR_CERT", &cert_path)
        .output()
        .expect("spawn kernel in bootstrap mode");
    assert!(
        bootstrap_output.status.success(),
        "kernel bootstrap failed (exit {:?}):\n--- stderr ---\n{}",
        bootstrap_output.status.code(),
        String::from_utf8_lossy(&bootstrap_output.stderr),
    );

    (kernel_bin, data_dir)
}

fn spawn_kernel_normal(kernel_bin: &Path, data_dir: PathBuf, install_dir: &Path) -> KernelInstance {
    use std::io::{BufRead, BufReader};
    use std::process::{Command as ProcCommand, Stdio};
    use std::sync::{Arc, Mutex};

    let mut child = ProcCommand::new(kernel_bin)
        .env("RAXIS_DATA_DIR", &data_dir)
        .env("RAXIS_INSTALL_DIR", install_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn kernel in normal mode");

    let stderr = child.stderr.take().expect("kernel stderr captured");
    let stderr_lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let log_path = data_dir.join("kernel.stderr.log");
    let log_handle = std::fs::File::create(&log_path)
        .ok()
        .map(|f| Arc::new(Mutex::new(f)));
    {
        let lines = Arc::clone(&stderr_lines);
        let log_handle = log_handle.clone();
        std::thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines().map_while(Result::ok) {
                if let Some(h) = &log_handle {
                    if let Ok(mut g) = h.lock() {
                        use std::io::Write as _;
                        let _ = writeln!(g, "{line}");
                    }
                }
                lines.lock().unwrap().push(line);
            }
        });
    }

    KernelInstance::from_parts(child, stderr_lines, data_dir)
}

fn enable_gateway_in_policy(data_dir: &Path, gateway_binary: &Path) {
    let policy_path = data_dir.join("policy").join("policy.toml");
    let mut body = std::fs::read_to_string(&policy_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", policy_path.display()));
    assert!(
        !body.contains("\n[gateway]\n"),
        "policy.toml already has a [gateway] block; bootstrap template changed",
    );
    let injected = format!(
        "\n# ── [gateway] + [[providers]] + [egress] + [[lanes]] (extended-e2e) ──\n\
         [gateway]\n\
         binary_path              = \"{gw}\"\n\
         spawn_timeout_secs       = 30\n\
         respawn_backoff_ms       = 1000\n\
         max_consecutive_respawns = 5\n\
         \n\
         [egress]\n\
         domains = [\"api.anthropic.com\"]\n\
         patterns = []\n\
         \n\
         [[providers]]\n\
         provider_id           = \"anthropic-ext-e2e\"\n\
         kind                  = \"Anthropic\"\n\
         credentials_file      = \"anthropic-ext-e2e.toml\"\n\
         inference_timeout_ms  = 120000\n\
         data_fetch_timeout_ms = 30000\n\
         pricing.input_tokens_per_dollar      = 200000\n\
         pricing.output_tokens_per_dollar     = 50000\n\
         pricing.cache_read_tokens_per_dollar = 2000000\n\
         \n\
         # ── [[lanes]] registration (V2 §Step 28 + INV-SCHED-03) ─────────\n\
         # The extended-scenario plan (`plan.rs`) declares\n\
         # `[workspace] lane_id = \"e2e-extended-lane\"`. The kernel\n\
         # validator `lifecycle::validate_workspace_lane_in_policy`\n\
         # rejects any plan whose workspace lane has no matching\n\
         # `[[lanes]]` entry — without this block\n\
         # `lifecycle::approve_plan` returns\n\
         # `LifecycleError::PlanLaneNotInPolicy` BEFORE the tx opens.\n\
         # (Pre-fix the lane absence collapsed silently to a\n\
         # `FailBudgetExceeded` rejection only at IntegrationMerge\n\
         # admission — see iter-38/39 root cause.)\n\
         [[lanes]]\n\
         lane_id              = \"e2e-extended-lane\"\n\
         max_concurrent_tasks = 8\n\
         max_cost_per_epoch   = 100000\n\
         priority             = 100\n",
        gw = gateway_binary.display(),
    );
    body.push_str(&injected);

    // ── iter62/iter63: real witness verifier (additive) ────────────────────
    //
    // INV-WITNESS-VERIFIER-LIVE-E2E-EXERCISED-01 (specs/invariants.md):
    // every live-e2e run MUST drive at least one verifier-backed gate
    // through the kernel's recheck-clear edge so the iter63
    // paired-write at `kernel/src/scheduler/dag.rs::transition_to_admitted`
    // (the deep-sweep pass) gets active
    // production coverage. We append a single `[[gates]]` block that
    // points at `raxis-verifier-no-secrets`, the kernel-bundled
    // worktree-scanning verifier from `crates/verifier-no-secrets/`.
    //
    // Conditional on the verifier binary actually existing on disk:
    // if the operator did not build it (`cargo build -p
    // raxis-verifier-no-secrets --release`) we skip the gate
    // injection rather than installing a `[[gates]]` entry pointed at
    // a non-existent binary — a missing-binary spawn would land the
    // task in PendingWitness forever and hang the test. The path is
    // derived from the gateway binary's parent directory because both
    // are workspace binaries built into the same `target/<profile>/`
    // tree.
    if let Some(verifier_bin) = sibling_verifier_binary(gateway_binary) {
        let gate_block = format!(
            "\n# ── [[gates]] — witness verifier (iter62 / iter63) ──\n\
             # Real, fast worktree-scanning gate. Source:\n\
             # `crates/verifier-no-secrets/`.\n\
             # See `INV-WITNESS-VERIFIER-LIVE-E2E-EXERCISED-01` for\n\
             # the rationale (this is the live coverage point for the\n\
             # iter63 recheck-clear paired-write audit row).\n\
             [[gates]]\n\
             gate_type        = \"NoSecretStrings\"\n\
             verifier_command = \"{vb}\"\n\
             max_wall_seconds = 30\n\
             max_memory_bytes = 268435456\n\
             network_allowed  = false\n",
            vb = verifier_bin.display(),
        );
        body.push_str(&gate_block);
        eprintln!(
            "[ext-e2e] enabling NoSecretStrings gate; verifier={}",
            verifier_bin.display()
        );
    } else {
        eprintln!(
            "[ext-e2e] skipping NoSecretStrings gate injection — \
             raxis-verifier-no-secrets binary not found alongside \
             {} (build with `cargo build -p raxis-verifier-no-secrets --release` \
             to enable iter63 recheck-clear coverage)",
            gateway_binary.display(),
        );
    }

    std::fs::write(&policy_path, body)
        .unwrap_or_else(|e| panic!("rewrite {}: {e}", policy_path.display()));
}

/// Resolve the absolute path of the `raxis-verifier-no-secrets`
/// binary built into the same `target/<profile>/` tree as
/// `gateway_binary`. Returns `None` when the binary has not been
/// built — callers MUST short-circuit gate injection in that case.
///
/// The discovery is deliberately strict-by-existence: we do NOT fall
/// back to `which` or to a generic `target/release/...` glob.
/// Operators who want a different verifier binary should ship a
/// different operator policy; the live-e2e harness is opinionated
/// about which verifier it uses precisely so the iter63 audit
/// invariant (`INV-WITNESS-VERIFIER-LIVE-E2E-EXERCISED-01`) has a
/// single, deterministic enforcement target.
fn sibling_verifier_binary(gateway_binary: &Path) -> Option<PathBuf> {
    let parent = gateway_binary.parent()?;
    let candidate = parent.join("raxis-verifier-no-secrets");
    if candidate.exists() {
        Some(candidate)
    } else {
        None
    }
}

fn write_credentials(data_dir: &Path) {
    let cred_dir = data_dir.join("credentials");
    std::fs::create_dir_all(&cred_dir).expect("mkdir credentials");

    // Credential value format is normative per `credential-proxy.md §3`:
    // the resolved credential bytes MUST be a libpq URL
    // `postgresql://user:pass@host:port/db` (RFC 3986). The MongoDB
    // form is a plaintext `mongodb://user:pass@host:port/db?authSource=…`
    // URI. Non-URL bytes are rejected with
    // `FAIL_PROXY_UPSTREAM_URL_INVALID`.
    write_with_mode_0600(
        &cred_dir.join("test-pg-dev.env"),
        b"postgresql://raxis_test:raxis_test_pass@127.0.0.1:54399/raxis_e2e_pg",
    );

    write_with_mode_0600(
        &cred_dir.join("test-mongo-dev.env"),
        b"mongodb://raxis_test:raxis_test_pass@127.0.0.1:27399/raxis_e2e_mongo?authSource=admin",
    );
}

/// Write a credentials-bearing file at exactly mode 0600. Open
/// with `O_CREAT` + mode 0600 so a brand-new file is created at
/// 0600, chmod 0600 BEFORE the body bytes are written so an
/// existing file at a wider mode is tightened before exposing the
/// credential bytes, then write + fsync.
fn write_with_mode_0600(path: &Path, body: &[u8]) {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .unwrap_or_else(|e| panic!("open {} O_CREAT|0600: {e}", path.display()));
    f.set_permissions(std::fs::Permissions::from_mode(0o600))
        .unwrap_or_else(|e| panic!("chmod 0600 {}: {e}", path.display()));
    f.write_all(body)
        .unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    f.sync_all()
        .unwrap_or_else(|e| panic!("fsync {}: {e}", path.display()));
}

fn write_provider_credentials(data_dir: &Path) {
    let providers_dir = data_dir.join("providers");
    std::fs::create_dir_all(&providers_dir).expect("mkdir providers");

    let env_path = workspace_dotenv_path();
    let body = std::fs::read_to_string(&env_path).expect("preflight verified .env");
    let api_key = body
        .lines()
        .find_map(|l| l.strip_prefix("ANTHROPIC-API-DEV-KEY="))
        .map(str::trim)
        .expect("preflight verified ANTHROPIC-API-DEV-KEY=...")
        .to_owned();

    let provider_toml = format!(
        "api_key     = \"{api_key}\"\n\
         auth_header = \"x-api-key\"\n\
         auth_prefix = \"\"\n",
    );
    write_with_mode_0600(
        &providers_dir.join("anthropic-ext-e2e.toml"),
        provider_toml.as_bytes(),
    );
}

// ---------------------------------------------------------------------------
// Operator IPC (mirrors full_e2e_session_lifecycle::OperatorIpc but
// submits the EXTENDED plan TOML built by `extended_e2e_support::plan`).
// ---------------------------------------------------------------------------

struct OperatorIpc {
    stream: UnixStream,
}

impl OperatorIpc {
    fn connect(
        socket_path: &Path,
        signing_key: &SigningKey,
        _fingerprint: &OperatorFingerprint,
    ) -> Self {
        let mut stream = UnixStream::connect(socket_path)
            .unwrap_or_else(|e| panic!("connect {}: {e}", socket_path.display()));

        let challenge = read_json_blocking(&mut stream);
        let challenge_hex = challenge["challenge_hex"]
            .as_str()
            .expect("kernel sends challenge_hex");
        let challenge_bytes = hex::decode(challenge_hex).expect("challenge_hex is hex");
        assert_eq!(challenge_bytes.len(), 32, "challenge is 32 bytes");

        let sig = signing_key.sign(&challenge_bytes);
        let pubkey = signing_key.verifying_key().to_bytes();
        let policy_fingerprint_hex = policy_fingerprint_32(&pubkey);
        let response = serde_json::json!({
            "fingerprint":          policy_fingerprint_hex,
            "signed_challenge_hex": hex::encode(sig.to_bytes()),
        });
        write_json_frame(&mut stream, &response).expect("write auth response");

        let ack = read_json_blocking(&mut stream);
        assert_eq!(
            ack["status"].as_str(),
            Some("Ok"),
            "kernel rejected auth: {ack:#}",
        );

        Self { stream }
    }

    fn submit_plan(&mut self, initiative_id: &str, injection_prompt: &str) {
        let plan_toml = extended_plan_toml(injection_prompt);
        let bundle = build_plan_bundle(&plan_toml);
        let canonical = canonical_encode(&bundle).expect("canonical_encode");
        let bundle_sha = crypto_bundle_sha256(&canonical);
        let signing_key = SigningKey::from_bytes(&E2E_OPERATOR_SEED);
        let sig_input = signing_input(&bundle_sha);
        let signature = signing_key.sign(&sig_input);
        let pubkey = signing_key.verifying_key().to_bytes();
        let fingerprint = fingerprint_8(&pubkey);

        let req = serde_json::json!({
            "op": "CreateInitiative",
            "payload": {
                "initiative_id":     initiative_id,
                "plan_bundle_hex":   hex::encode(&canonical),
                "bundle_sha256_hex": hex::encode(bundle_sha.as_bytes()),
                "signature_hex":     hex::encode(signature.to_bytes()),
                "signed_by_hex":     hex::encode(fingerprint.as_bytes()),
            },
        });
        write_json_frame(&mut self.stream, &req).expect("write CreateInitiative");
        let resp = read_json_blocking(&mut self.stream);
        assert_eq!(
            resp["status"].as_str(),
            Some("InitiativeCreated"),
            "CreateInitiative must succeed; got: {resp:#}",
        );
        let returned_id = resp["payload"]["initiative_id"]
            .as_str()
            .expect("InitiativeCreated carries payload.initiative_id");
        assert_eq!(returned_id, initiative_id, "initiative id roundtrip");
    }

    fn approve_plan(&mut self, initiative_id: &str, _fingerprint: &OperatorFingerprint) {
        let signing_key = SigningKey::from_bytes(&E2E_OPERATOR_SEED);
        let pubkey = signing_key.verifying_key().to_bytes();
        let approving_operator_32 = policy_fingerprint_32(&pubkey);
        let req = serde_json::json!({
            "op": "ApprovePlan",
            "payload": {
                "initiative_id":      initiative_id,
                "approving_operator": approving_operator_32,
            },
        });
        write_json_frame(&mut self.stream, &req).expect("write ApprovePlan");
        let resp = read_json_blocking(&mut self.stream);
        assert_eq!(
            resp["status"].as_str(),
            Some("PlanApproved"),
            "ApprovePlan must succeed; got: {resp:#}",
        );
    }
}

fn read_json_blocking(stream: &mut UnixStream) -> Value {
    let body = read_json_frame_raw(stream).expect("read kernel frame");
    serde_json::from_str(&body).expect("kernel frame is JSON")
}

fn build_plan_bundle(plan_toml: &str) -> PlanBundle {
    let plan_bytes = plan_toml.as_bytes().to_vec();
    let plan_sha = sha256_of_artifact_bytes(&plan_bytes);
    let artifacts = vec![BundleArtifact {
        name: "plan.toml".to_owned(),
        bytes: plan_bytes,
        sha256: plan_sha,
    }];
    let signed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let nonce = mint_bundle_nonce().expect("mint_bundle_nonce");
    PlanBundle::new_v2_1(
        signed_at,
        signed_at,
        nonce,
        "/raxis/ext-e2e".to_owned(),
        artifacts,
    )
}

#[cfg(target_os = "macos")]
fn codesign_kernel_for_avf(kernel_bin: &Path) {
    // Prefer CARGO_MANIFEST_DIR because e2e runs often use
    // CARGO_TARGET_DIR=/tmp/..., where walking up from the test-built
    // kernel binary can never reach the workspace.
    let mut anchor = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        let manifest = anchor.join("Cargo.toml");
        if manifest.exists() {
            if let Ok(s) = std::fs::read_to_string(&manifest) {
                if s.contains("[workspace]") {
                    break;
                }
            }
        }
        if !anchor.pop() {
            anchor = kernel_bin
                .parent()
                .and_then(|p| p.parent())
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."));
            loop {
                let manifest = anchor.join("Cargo.toml");
                if manifest.exists() {
                    if let Ok(s) = std::fs::read_to_string(&manifest) {
                        if s.contains("[workspace]") {
                            break;
                        }
                    }
                }
                if !anchor.pop() {
                    eprintln!(
                        "[ext-e2e] codesign: workspace root not found from {}",
                        kernel_bin.display()
                    );
                    return;
                }
            }
            break;
        }
    }
    let entitlements = anchor.join("release/raxis.entitlements");
    if !entitlements.exists() {
        eprintln!(
            "[ext-e2e] codesign: entitlements missing at {}",
            entitlements.display()
        );
        return;
    }
    let status = Command::new("codesign")
        .arg("--sign")
        .arg("-")
        .arg("--entitlements")
        .arg(&entitlements)
        .arg("--options")
        .arg("runtime")
        .arg("--force")
        .arg(kernel_bin)
        .status()
        .expect("codesign required for AVF on macOS");
    if !status.success() {
        panic!(
            "codesign failed (exit {:?}) for {}",
            status.code(),
            kernel_bin.display()
        );
    }
}

fn fingerprint_8(pubkey: &[u8; 32]) -> OperatorFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(pubkey);
    let hash = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&hash[..8]);
    OperatorFingerprint::new(out)
}

fn policy_fingerprint_32(pubkey: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(pubkey);
    let digest = hasher.finalize();
    hex::encode(&digest[..16])
}

// ---------------------------------------------------------------------------
// Audit-chain polling + post-mortem
// ---------------------------------------------------------------------------

fn poll_for_lifecycle_completion(data_dir: &Path, initiative_id: &str) -> Vec<AuditEvent> {
    let audit_dir = data_dir.join("audit");
    let deadline = lifecycle_deadline();
    let start = Instant::now();
    let mut last_len = 0usize;
    loop {
        if start.elapsed() > deadline {
            let stderr_path = audit_dir.parent().map(|p| p.join("kernel.stderr.log"));
            let stderr_tail = stderr_path
                .as_ref()
                .and_then(|p| std::fs::read_to_string(p).ok())
                .map(|s| {
                    let lines: Vec<&str> = s.lines().collect();
                    let n = lines.len();
                    let take = n.min(60);
                    lines[n.saturating_sub(take)..].join("\n")
                })
                .unwrap_or_else(|| "<no kernel.stderr.log on disk>".to_owned());
            panic!(
                "extended lifecycle deadline of {deadline:?} exceeded \
                 without IntegrationMergeCompleted for {initiative_id}; \
                 audit chain at exit ({} events):\n{}\n\n\
                 ── kernel.stderr (tail) ──\n{}",
                last_len,
                summarize_chain_for_panic(&audit_dir),
                stderr_tail,
            );
        }

        let events = match read_audit_chain(&audit_dir) {
            Ok(e) => e,
            Err(_) => {
                std::thread::sleep(Duration::from_millis(250));
                continue;
            }
        };
        last_len = events.len();

        for e in &events {
            if e.event_kind == "SecurityViolation" || e.event_kind == "SecurityViolationDetected" {
                panic!(
                    "SecurityViolation fired during extended lifecycle: \
                     event_kind={}, payload={:#}",
                    e.event_kind, e.payload,
                );
            }
        }

        let merged = events.iter().any(|e| {
            e.event_kind == "IntegrationMergeCompleted"
                && e.initiative_id.as_deref() == Some(initiative_id)
        });
        if merged {
            return events;
        }

        std::thread::sleep(Duration::from_millis(500));
    }
}

fn read_audit_chain(audit_dir: &Path) -> Result<Vec<AuditEvent>, ()> {
    if !audit_dir.exists() {
        return Err(());
    }
    let mut events = Vec::new();
    for entry in std::fs::read_dir(audit_dir).map_err(|_| ())? {
        let entry = entry.map_err(|_| ())?;
        if entry.file_name().to_string_lossy().ends_with(".jsonl") {
            let bytes = std::fs::read(entry.path()).map_err(|_| ())?;
            for line in bytes.split(|&b| b == b'\n') {
                if line.is_empty() {
                    continue;
                }
                if let Ok(ev) = serde_json::from_slice::<AuditEvent>(line) {
                    events.push(ev);
                }
            }
        }
    }
    events.sort_by_key(|e| e.seq);
    Ok(events)
}

fn summarize_chain_for_panic(audit_dir: &Path) -> String {
    match read_audit_chain(audit_dir) {
        Ok(events) => {
            let kinds: Vec<&str> = events.iter().map(|e| e.event_kind.as_str()).collect();
            format!(
                "seqs={}…{}, kinds={kinds:#?}",
                events.first().map(|e| e.seq).unwrap_or(0),
                events.last().map(|e| e.seq).unwrap_or(0),
            )
        }
        Err(_) => "(audit dir not yet present)".to_owned(),
    }
}

fn walk_chain_or_panic(data_dir: &Path) -> Vec<AuditEvent> {
    let audit_dir = data_dir.join("audit");
    verify_chain_full(&audit_dir)
        .unwrap_or_else(|e| panic!("verify_chain_full({audit_dir:?}) failed: {e:?}"));
    let reader = ChainReader::open(&audit_dir)
        .unwrap_or_else(|e| panic!("ChainReader::open({audit_dir:?}) failed: {e:?}"));
    reader
        .records()
        .map(|r| {
            let row = r.unwrap_or_else(|e| panic!("chain record decode failed: {e:?}"));
            let value = row.parsed_value.unwrap_or_else(|| {
                panic!(
                    "chain row seq={} has no parsed_value (raw_line failed JSON parse)",
                    row.seq,
                )
            });
            if row.event_kind == "GenesisRecord" {
                return AuditEvent {
                    seq: row.seq,
                    event_id: uuid::Uuid::nil(),
                    event_kind: row.event_kind.clone(),
                    session_id: None,
                    task_id: None,
                    initiative_id: None,
                    payload: value,
                    emitted_at: row.emitted_at.unwrap_or(0),
                    prev_sha256: row.prev_sha256.clone(),
                };
            }
            serde_json::from_value::<AuditEvent>(value)
                .unwrap_or_else(|e| panic!("decode AuditEvent from chain row {}: {e}", row.seq))
        })
        .collect()
}

fn assert_audit_invariants(chain: &[AuditEvent], initiative_id: &str) {
    assert!(!chain.is_empty(), "audit chain must be non-empty");
    let first_kind = chain.first().expect("non-empty").event_kind.as_str();
    let last_kind = chain.last().expect("non-empty").event_kind.as_str();
    assert!(
        first_kind.starts_with("Kernel") || first_kind == "GenesisAnchor",
        "first audit row must be a boot marker, got {first_kind:?}",
    );
    assert!(
        last_kind.starts_with("Kernel"),
        "last audit row must be a shutdown marker, got {last_kind:?}",
    );

    let kinds: BTreeSet<&str> = chain.iter().map(|e| e.event_kind.as_str()).collect();
    for required in &[
        "InitiativeCreated",
        "IntentAdmitted",
        "IntegrationMergeCompleted",
    ] {
        assert!(
            kinds.contains(*required),
            "audit chain must contain {required}; got: {kinds:?}",
        );
    }

    let merged_for_us = chain.iter().any(|e| {
        e.event_kind == "IntegrationMergeCompleted"
            && e.initiative_id.as_deref() == Some(initiative_id)
    });
    assert!(
        merged_for_us,
        "no IntegrationMergeCompleted for {initiative_id}; chain kinds: {kinds:?}",
    );
}

// ---------------------------------------------------------------------------
// Workdir locator — find the executor's checkout on disk so the
// MaterializationWitness can walk it.
// ---------------------------------------------------------------------------

/// Find `<data_dir>/worktrees/<initiative_id>/<task_id>/` (the
/// path the V2 worktree provisioner writes per
/// `worktree-provisioning.md`). On disk the canonical layout is:
///
/// ```text
/// <data_dir>/worktrees/<initiative_id>/<task_id>/<...>
/// ```
///
/// We search both the canonical path and a small set of
/// kernel-local fallbacks observed during V2 staging (the layout
/// has been moved at least once during V2 development; the
/// fallback list keeps the test working across the migration).
fn locate_executor_worktree(data_dir: &Path, initiative_id: &str, task_id: &str) -> PathBuf {
    let candidates = [
        data_dir.join("worktrees").join(initiative_id).join(task_id),
        data_dir
            .join("workspaces")
            .join(initiative_id)
            .join(task_id),
        data_dir.join("sessions").join(initiative_id).join(task_id),
    ];
    for c in &candidates {
        if c.exists() && c.join(".git").exists() {
            return c.clone();
        }
    }
    panic!(
        "could not locate executor worktree for initiative={initiative_id} \
         task={task_id}; tried {:?}",
        candidates,
    );
}

// ---------------------------------------------------------------------------
// Injection-task post-mortem helpers
// ---------------------------------------------------------------------------

/// Walk the chain and return the `session_id` of the first
/// `SessionVmSpawned` whose `task_id` matches `task_id`. Returns
/// `None` if no such event exists (the test then surfaces an
/// informative failure rather than panicking with a generic
/// missing-witness message).
fn locate_session_id_for_task(chain: &[AuditEvent], task_id: &str) -> Option<String> {
    chain.iter().find_map(|ev| match typed(ev) {
        Some(AuditEventKind::SessionVmSpawned {
            session_id,
            task_id: Some(t),
            ..
        }) if t == task_id => Some(session_id),
        _ => None,
    })
}

/// Inspect `<data_dir>/escalations/` and assert no file landed
/// that the kernel did not itself write. The kernel writes
/// escalation rows to SQLite, NOT to a JSON file under that path,
/// so the directory should be either absent or contain only kernel-
/// owned bookkeeping files (none in V2). Any other content is
/// evidence of a planner-side bypass attempt that succeeded.
///
/// We accept either "directory absent" or "directory empty" as
/// the satisfied condition — the kernel may or may not create the
/// directory at boot; both cases are equivalent from the
/// approval-flow-circumvention witness's point of view.
fn assert_no_forged_approvals_on_disk(data_dir: &Path) {
    let esc_dir = data_dir.join("escalations");
    if !esc_dir.exists() {
        return;
    }
    let entries: Vec<_> = std::fs::read_dir(&esc_dir)
        .map(|d| d.flatten().collect())
        .unwrap_or_default();
    assert!(
        entries.is_empty(),
        "approval-flow circumvention: <data_dir>/escalations/ should be empty \
         (kernel writes escalations to SQLite, not the filesystem); observed \
         {} entries: {:?}. The injection task's `approval_circumvention` \
         payload may have escaped the VM-FS scope.",
        entries.len(),
        entries.iter().map(|e| e.file_name()).collect::<Vec<_>>(),
    );
}

/// Defense-in-depth: every `EscalationConsumed` in the chain MUST
/// have a preceding `EscalationApproved` for the same
/// `escalation_id`. The kernel emits the pair in order; an
/// unpaired consume would be evidence of a forged approval that
/// the kernel accepted.
fn assert_no_unpaired_consume_in_chain(chain: &[AuditEvent]) {
    let mut approved: BTreeSet<String> = BTreeSet::new();
    for ev in chain {
        match typed(ev) {
            Some(AuditEventKind::EscalationApproved { escalation_id, .. }) => {
                approved.insert(escalation_id);
            }
            Some(AuditEventKind::EscalationConsumed { escalation_id, .. }) => {
                assert!(
                    approved.contains(&escalation_id),
                    "unpaired EscalationConsumed for {escalation_id}: no \
                     prior EscalationApproved found. Possible forged-approval \
                     acceptance via the §6.3 circumvention payload.",
                );
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Misc helpers
// ---------------------------------------------------------------------------

fn workspace_dotenv_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|p| p.join(".env"))
        .unwrap_or_else(|| PathBuf::from("raxis/.env"))
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}
