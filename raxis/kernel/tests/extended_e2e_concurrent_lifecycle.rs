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
        assemble_prompt as assemble_injection_prompt, payload_summary,
        witnesses_for_payloads,
    },
    plan::{
        extended_plan_toml, TASK_FANOUT_FMT, TASK_FANOUT_MANIFEST,
        TASK_FANOUT_README, TASK_INJECT_EVIL, TASK_MATERIALIZE,
        TASK_REVIEW_A, TASK_REVIEW_B,
    },
    seeds::{
        preflight_or_panic as preflight_dbs_or_panic, MONGO_HOST_PORT, PG_HOST_PORT,
    },
    witnesses::{
        typed, EnforcementWitness, MaterializationWitness,
        NoSecurityViolationWitness, ReviewerDisagreementWitness,
    },
};
use raxis_audit_tools::AuditEventKind;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const LIVE_E2E_GATE: &str = "RAXIS_LIVE_E2E";
const READY_DEADLINE:    Duration = Duration::from_secs(15);
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
    eprintln!("[ext-e2e] kernel bootstrapped, data_dir={}", data_dir.display());

    let gateway_binary = require_gateway_binary();
    enable_gateway_in_policy(&data_dir, &gateway_binary);
    write_credentials(&data_dir);
    write_provider_credentials(&data_dir);

    let install_dir = PathBuf::from(
        std::env::var("RAXIS_INSTALL_DIR").expect("preflight verified RAXIS_INSTALL_DIR"),
    );
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
    eprintln!("[ext-e2e] lifecycle complete, chain has {} events", chain.len());

    // ── Locate the materializer executor's worktree on disk and
    //    run the worktree-side mechanical witness.
    let workdir = locate_executor_worktree(kernel.data_dir(), &initiative_id, TASK_MATERIALIZE);
    eprintln!("[ext-e2e] materializer workdir at {}", workdir.display());
    MaterializationWitness {
        workdir: workdir.clone(),
        expected_commit_message: MATERIALIZER_COMMIT_MESSAGE,
    }.assert_satisfied();
    eprintln!("[ext-e2e] MaterializationWitness satisfied");

    // ── Concurrency oracle — at least one overlapping pair across
    //    the three fan-out tasks.
    assert_overlap_or_panic(&chain, FANOUT_GROUP);
    eprintln!("[ext-e2e] ConcurrencyOracle: fan-out group overlap confirmed");

    // ── Locate the injection task's session id by scanning the
    //    chain. Required by `PathAllowlistRejectedWitness`.
    let injection_session_id = locate_session_id_for_task(&chain, TASK_INJECT_EVIL)
        .unwrap_or_else(|| {
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
            executor_task_id:   TASK_MATERIALIZE.to_owned(),
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
    eprintln!("[ext-e2e] audit chain integrity verified ({} events)", final_chain.len());

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
    let lifecycle_script = audit_scripts::concurrent_lifecycle(
        TASK_MATERIALIZE,
        FANOUT_GROUP,
        initiative_id.clone(),
    );
    let lifecycle_report =
        audit_witness.assert_scenario(&final_chain, &lifecycle_script);
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
    let reviewer_script = audit_scripts::reviewer_disagreement(
        TASK_MATERIALIZE,
        TASK_REVIEW_A,
        TASK_REVIEW_B,
    );
    let reviewer_report =
        audit_witness.assert_scenario(&final_chain, &reviewer_script);
    eprintln!(
        "[ext-e2e] AuditChainWitness::walk_scenario(reviewer-disagreement): \
         {}/{} ordered matchers satisfied",
        reviewer_report.ordered_satisfied,
        reviewer_script.matchers.len(),
    );
}

/// Fan-out task ids the concurrency oracle and the AuditChain
/// scenario script both reference. Pinned as a `'static` slice
/// because `audit_chain::scripts::concurrent_lifecycle` needs
/// `&'static [&'static str]` so the matcher closures can capture
/// the task-id set without per-call allocation.
const FANOUT_GROUP: &[&str] = &[
    TASK_FANOUT_README,
    TASK_FANOUT_FMT,
    TASK_FANOUT_MANIFEST,
];

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
    ).is_err() {
        panic!(
            "{what} not reachable at {host_port}. Run:\n  \
             docker compose -f live-e2e/docker-compose.extended.e2e.yml up -d --wait",
        );
    }
}

fn require_anthropic_dev_key() {
    let env_path = workspace_dotenv_path();
    let body = std::fs::read_to_string(&env_path).unwrap_or_else(|e| panic!(
        "{} is required for the live LLM round-trip but read failed: {e}\n\
         Create it with one line:\n  ANTHROPIC-API-DEV-KEY=sk-ant-...",
        env_path.display(),
    ));
    let has_key = body
        .lines()
        .any(|l| l.starts_with("ANTHROPIC-API-DEV-KEY=")
            && l.len() > "ANTHROPIC-API-DEV-KEY=".len());
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
    let raw = std::env::var("RAXIS_GATEWAY_BINARY").unwrap_or_else(|_| panic!(
        "RAXIS_GATEWAY_BINARY env var is required; build the gateway and \
         export the path:\n  cargo build -p raxis-gateway --release\n  \
         export RAXIS_GATEWAY_BINARY=$(pwd)/target/release/raxis-gateway",
    ));
    let p = PathBuf::from(&raw);
    assert!(p.is_absolute(), "RAXIS_GATEWAY_BINARY must be absolute; got {raw:?}");
    assert!(p.exists(), "RAXIS_GATEWAY_BINARY={raw:?} does not exist");
    p
}

fn require_canonical_images() {
    let install_dir_raw = std::env::var("RAXIS_INSTALL_DIR").unwrap_or_else(|_| panic!(
        "RAXIS_INSTALL_DIR env var is required",
    ));
    let install_dir = PathBuf::from(&install_dir_raw);
    let kernel_version = env!("CARGO_PKG_VERSION");
    for role in &["orchestrator-core", "executor-starter", "reviewer-core"] {
        let img = install_dir.join("images")
            .join(format!("raxis-{role}-{kernel_version}.img"));
        let manifest = install_dir.join("images")
            .join(format!("raxis-{role}-{kernel_version}.manifest.toml"));
        assert!(img.exists(), "missing canonical image {}", img.display());
        assert!(manifest.exists(), "missing canonical manifest {}", manifest.display());
    }
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
    let cert = ephemeral_cert_with_key(signing_key, CertOpts {
        now_unix_secs,
        permitted_ops: vec![
            "CreateInitiative".to_owned(),
            "CreateInitiativeV2".to_owned(),
            "ApprovePlan".to_owned(),
            "AbortInitiative".to_owned(),
        ],
        display_name: "ext-e2e-operator".to_owned(),
        ..CertOpts::default()
    });

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
    let log_handle = std::fs::File::create(&log_path).ok().map(|f| Arc::new(Mutex::new(f)));
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
        "\n# ── [gateway] + [[providers]] + [egress] (extended-e2e) ──\n\
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
         pricing.cache_read_tokens_per_dollar = 2000000\n",
        gw = gateway_binary.display(),
    );
    body.push_str(&injected);
    std::fs::write(&policy_path, body)
        .unwrap_or_else(|e| panic!("rewrite {}: {e}", policy_path.display()));
}

fn write_credentials(data_dir: &Path) {
    let cred_dir = data_dir.join("credentials");
    std::fs::create_dir_all(&cred_dir).expect("mkdir credentials");

    write_with_mode_0600(
        &cred_dir.join("test-pg-dev.env"),
        b"PGHOST=127.0.0.1\n\
          PGPORT=54399\n\
          PGUSER=raxis_test\n\
          PGPASSWORD=raxis_test_pass\n\
          PGDATABASE=raxis_e2e_pg\n\
          PGSSLMODE=disable\n",
    );

    write_with_mode_0600(
        &cred_dir.join("test-mongo-dev.env"),
        b"MONGO_HOST=127.0.0.1\n\
          MONGO_PORT=27399\n\
          MONGO_USER=raxis_test\n\
          MONGO_PASSWORD=raxis_test_pass\n\
          MONGO_AUTH_DB=admin\n\
          MONGO_DATABASE=raxis_e2e_mongo\n",
    );
}

fn write_with_mode_0600(path: &Path, body: &[u8]) {
    std::fs::write(path, body)
        .unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .unwrap_or_else(|e| panic!("chmod 0600 {}: {e}", path.display()));
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
    fn connect(socket_path: &Path, signing_key: &SigningKey, _fingerprint: &OperatorFingerprint) -> Self {
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
            ack["status"].as_str(), Some("Ok"),
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
            "op": "CreateInitiativeV2",
            "payload": {
                "initiative_id":     initiative_id,
                "plan_bundle_hex":   hex::encode(&canonical),
                "bundle_sha256_hex": hex::encode(bundle_sha.as_bytes()),
                "signature_hex":     hex::encode(signature.to_bytes()),
                "signed_by_hex":     hex::encode(fingerprint.as_bytes()),
            },
        });
        write_json_frame(&mut self.stream, &req).expect("write CreateInitiativeV2");
        let resp = read_json_blocking(&mut self.stream);
        assert_eq!(
            resp["status"].as_str(), Some("InitiativeCreated"),
            "CreateInitiativeV2 must succeed; got: {resp:#}",
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
            resp["status"].as_str(), Some("PlanApproved"),
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
        name:   "plan.toml".to_owned(),
        bytes:  plan_bytes,
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
    let mut anchor = kernel_bin
        .parent()
        .and_then(|p| p.parent())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    loop {
        let manifest = anchor.join("Cargo.toml");
        if manifest.exists() {
            if let Ok(s) = std::fs::read_to_string(&manifest) {
                if s.contains("[workspace]") { break; }
            }
        }
        if !anchor.pop() {
            eprintln!("[ext-e2e] codesign: workspace root not found from {}",
                kernel_bin.display());
            return;
        }
    }
    let entitlements = anchor.join("release/raxis.entitlements");
    if !entitlements.exists() {
        eprintln!("[ext-e2e] codesign: entitlements missing at {}", entitlements.display());
        return;
    }
    let status = Command::new("codesign")
        .arg("--sign").arg("-")
        .arg("--entitlements").arg(&entitlements)
        .arg("--options").arg("runtime")
        .arg("--force")
        .arg(kernel_bin)
        .status()
        .expect("codesign required for AVF on macOS");
    if !status.success() {
        panic!("codesign failed (exit {:?}) for {}", status.code(), kernel_bin.display());
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
            if e.event_kind == "SecurityViolation"
                || e.event_kind == "SecurityViolationDetected"
            {
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
    if !audit_dir.exists() { return Err(()); }
    let mut events = Vec::new();
    for entry in std::fs::read_dir(audit_dir).map_err(|_| ())? {
        let entry = entry.map_err(|_| ())?;
        if entry.file_name().to_string_lossy().ends_with(".jsonl") {
            let bytes = std::fs::read(entry.path()).map_err(|_| ())?;
            for line in bytes.split(|&b| b == b'\n') {
                if line.is_empty() { continue; }
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
            format!("seqs={}…{}, kinds={kinds:#?}",
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
    let reader = ChainReader::open(&audit_dir).unwrap_or_else(|e| {
        panic!("ChainReader::open({audit_dir:?}) failed: {e:?}")
    });
    reader
        .records()
        .map(|r| {
            let row = r.unwrap_or_else(|e| panic!("chain record decode failed: {e:?}"));
            let value = row.parsed_value.unwrap_or_else(|| panic!(
                "chain row seq={} has no parsed_value", row.seq,
            ));
            serde_json::from_value::<AuditEvent>(value).unwrap_or_else(|e| {
                panic!("decode AuditEvent from chain row {}: {e}", row.seq)
            })
        })
        .collect()
}

fn assert_audit_invariants(chain: &[AuditEvent], initiative_id: &str) {
    assert!(!chain.is_empty(), "audit chain must be non-empty");
    let first_kind = chain.first().expect("non-empty").event_kind.as_str();
    let last_kind  = chain.last().expect("non-empty").event_kind.as_str();
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
fn locate_executor_worktree(
    data_dir: &Path,
    initiative_id: &str,
    task_id: &str,
) -> PathBuf {
    let candidates = [
        data_dir.join("worktrees").join(initiative_id).join(task_id),
        data_dir.join("workspaces").join(initiative_id).join(task_id),
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
            session_id, task_id: Some(t), ..
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
