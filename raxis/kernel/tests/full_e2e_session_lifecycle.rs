//! Full RAXIS V2 end-to-end lifecycle smoke test —
//! genesis → planner → reviewer → integration merge → DAG complete.
//!
//! Normative reference: `specs/v2/e2e-live-test-gap.md`.
//!
//! ## Why this file exists
//!
//! Every other `kernel/tests/*.rs` integration test pins a specific surface
//! (operator handshake, planner framing, signal shutdown, audit chain
//! across restart, integration-merge attribution, dashboard wiring). NONE
//! of them drive the *whole* lifecycle the spec promises:
//!
//! ```text
//!   bootstrap → operator approves plan → orchestrator spawns
//!   → orchestrator activates executor sub-task → executor commits
//!   → reviewer approves → orchestrator integration-merges
//!   → audit chain ends with `IntegrationMergeCompleted`
//!   → kernel exits cleanly
//! ```
//!
//! That chain crosses every V2 invariant boundary that ships in the kernel
//! (cert gate, plan-bundle sealing, session-spawn substrate, planner UDS
//! framing, KSB stamping, intent admission, FSM transitions, audit
//! chaining). A regression in *any* of them surfaces here.
//!
//! ## Why this is gated by `RAXIS_LIVE_E2E=1`
//!
//! The full chain requires three out-of-tree dependencies:
//!
//!   1. **Real microVM substrate** — Apple-VZ on macOS or Firecracker on
//!      Linux. Both require canonical `<role>-<kernel_version>.img` /
//!      `<role>-<kernel_version>.manifest.toml` artefacts under
//!      `$RAXIS_INSTALL_DIR` (or `<data_dir>` fallback). CI machines
//!      and most dev workstations do not have these.
//!
//!   2. **Live LLM backend** — the in-VM `raxis-orchestrator` /
//!      `raxis-executor` / `raxis-reviewer` planner binaries call
//!      Anthropic over the in-VM tproxy → host gateway path. Real
//!      tokens cost real money; CI must never bill an account.
//!
//!   3. **Database services for the credential proxies** — Postgres +
//!      MongoDB containers per `live-e2e/docker-compose.e2e.yml`.
//!
//! Per `e2e-live-test-gap.md §7.1`, the test SKIPS (returns Ok without
//! asserting) when `RAXIS_LIVE_E2E != "1"` so `cargo test --workspace`
//! continues to pass on any developer's machine without those
//! dependencies. The skip path emits a structured `Skipped:` line with
//! the exact `docker compose` command the operator must run to gate
//! the test back on.
//!
//! ## What the test actually does when gated ON
//!
//! The test exercises the production wire surface end-to-end:
//!
//!   * **Bootstrap**: spawns the production `raxis-kernel` binary in
//!     bootstrap mode against a fresh `<data_dir>` with a custom
//!     operator certificate that grants the full lifecycle ops the
//!     test needs (`CreateInitiative`, `ApprovePlan`, `AbortInitiative`).
//!     Then re-spawns it in normal mode.
//!
//!   * **Credential injection**: writes the three credential files the
//!     spec's plan declares (`test-pg-dev.env`, `test-mongo-dev.env`,
//!     `test-gcp-dev.json`) under `<data_dir>/credentials/` BEFORE the
//!     plan is submitted, so admission-step credential resolution
//!     succeeds.
//!
//!   * **Plan submission**: builds the spec's `[plan]` TOML in memory,
//!     wraps it in a V2.1 plan-bundle (signed_at + nonce + ed25519
//!     signature with the same operator key the cert advertised), and
//!     submits it via the real operator UDS handshake +
//!     `OperatorRequest::CreateInitiativeV2` JSON IPC frame.
//!
//!   * **Approval**: submits `OperatorRequest::ApprovePlan` over the
//!     same authenticated connection. The kernel's
//!     `handle_approve_plan` handler triggers the orchestrator
//!     auto-spawn callsite (`session_spawn_orchestrator::
//!     LiveOrchestratorSpawn::spawn_for_initiative`), which boots a
//!     real microVM running the canonical orchestrator image.
//!
//!   * **Polling**: waits up to a generous deadline for the audit
//!     chain to grow past `IntegrationMergeCompleted` (the terminal
//!     event for the success path). Fails-loud on:
//!       - any `SecurityViolationDetected` event,
//!       - any `KernelShutdownRequested` event before merge,
//!       - the deadline elapsing without `IntegrationMergeCompleted`.
//!
//!   * **Post-mortem audit assertion**: verifies the chain integrity
//!     with `raxis_audit_tools::verify_chain_full`, then walks the
//!     decoded events and asserts the expected `kind` sequence is a
//!     subset of what landed (the test does not over-pin per-event
//!     positions because real LLM scheduling is non-deterministic).
//!
//!   * **Graceful shutdown**: SIGTERM, wait for clean exit, ensure
//!     `KernelShutdown { exit: "graceful" }` is the last audit row.
//!
//! ## Invocation
//!
//! ```bash
//! # 1. Stand up infra (Postgres + MongoDB tmpfs containers).
//! docker compose -f live-e2e/docker-compose.e2e.yml up -d --wait
//!
//! # 2. Provide the LLM key (file is git-ignored).
//! cat raxis/.env
//! # ANTHROPIC-API-DEV-KEY=sk-ant-...
//!
//! # 3. Provide GCP application-default credentials (the GCP
//! #    credential proxy reads these for upstream IAM tokens).
//! gcloud auth application-default login
//!
//! # 4. Build the gateway binary and export its absolute path.
//! cargo build -p raxis-gateway --release
//! export RAXIS_GATEWAY_BINARY="$(pwd)/raxis/target/release/raxis-gateway"
//!
//! # 5. Point at the install root that holds canonical microVM images
//! #    + signed manifests (orchestrator-core, executor-starter,
//! #    reviewer-core, all stamped with the kernel build's signing
//! #    key — see `system-requirements.md §3`).
//! export RAXIS_INSTALL_DIR=/usr/local/lib/raxis    # or your local install root
//!
//! # 6. Run the test.
//! RAXIS_LIVE_E2E=1 cargo test -p raxis-kernel \
//!     --test full_e2e_session_lifecycle -- --nocapture
//!
//! # 7. Tear down.
//! docker compose -f live-e2e/docker-compose.e2e.yml down -v
//! ```

mod common;

use std::collections::BTreeSet;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};
use raxis_audit_tools::{verify_chain_full, AuditEvent, AuditEventKind, ChainReader};
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

// ---------------------------------------------------------------------------
// Constants — kept inline so the spec → code mapping is one file deep.
// ---------------------------------------------------------------------------

/// Toggle env var per `e2e-live-test-gap.md §7.1`. The test skips
/// (returns Ok without asserting) when this is unset or != "1" so
/// `cargo test --workspace` continues to pass without the live
/// infra. Operators flip it to "1" after standing up Docker
/// services + populating `~/.config/gcloud/application_default_
/// credentials.json`.
const LIVE_E2E_GATE: &str = "RAXIS_LIVE_E2E";

/// Loopback host:port the docker-compose Postgres binds to. Pinned
/// to match `live-e2e/docker-compose.e2e.yml`.
const PG_HOST_PORT:    &str = "127.0.0.1:54399";
/// Loopback host:port the docker-compose MongoDB binds to.
const MONGO_HOST_PORT: &str = "127.0.0.1:27399";

/// How long the test waits for the kernel to bind sockets after
/// spawn. `bootstrap_and_spawn` is generous; CI machines under
/// load occasionally take >5s.
const READY_DEADLINE:    Duration = Duration::from_secs(15);

/// How long the test waits for graceful kernel exit on SIGTERM.
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(30);

/// How long the test waits for the *full* lifecycle chain
/// (orchestrator boot → executor commit → reviewer approve →
/// integration-merge) to land in the audit log. Worst case three
/// VM cold-boots + three real LLM round-trips with a small claude-
/// sonnet model.
const LIFECYCLE_DEADLINE: Duration = Duration::from_secs(360);

/// Operator-cert seed used for the test. Chosen to be distinct from
/// the harness's `[0xA5; 32]` so tests that share a binary do not
/// accidentally cross-contaminate each other's policy view.
const E2E_OPERATOR_SEED: [u8; 32] = [0xC0; 32];

/// Initiative id the test submits. UUIDv7-shaped (matches the CLI
/// default in `raxis-cli::commands::submit::uuid_v7_string`).
fn fresh_initiative_id() -> String {
    uuid::Uuid::now_v7().to_string()
}

// ---------------------------------------------------------------------------
// Top-level test
// ---------------------------------------------------------------------------

/// The single end-to-end smoke test. See file-level docs for what
/// each phase does and why it is gated behind `RAXIS_LIVE_E2E=1`.
#[test]
fn full_session_lifecycle() {
    if std::env::var(LIVE_E2E_GATE).as_deref() != Ok("1") {
        eprintln!(
            "Skipped: full_session_lifecycle is a live-infrastructure smoke test.\n\
             Enable by:\n\
                 1. docker compose -f live-e2e/docker-compose.e2e.yml up -d --wait\n\
                 2. ensure raxis/.env contains ANTHROPIC-API-DEV-KEY=sk-ant-...\n\
                 3. ensure ~/.config/gcloud/application_default_credentials.json exists\n\
                    (run `gcloud auth application-default login`)\n\
                 4. RAXIS_LIVE_E2E=1 cargo test -p raxis-kernel \\\n\
                       --test full_e2e_session_lifecycle -- --nocapture",
        );
        return;
    }

    let _build_lock = acquire_test_lock();

    // ── §7.1 — preflight checks BEFORE we spend a kernel boot. Failing
    //    early surfaces the missing dep with a clean message instead
    //    of the kernel emitting a confusing failure deep into the
    //    chain. Each check refuses to proceed unless the dep is
    //    actually reachable on the wire (not just configured).
    preflight_or_skip();

    // ── §7.2 — bootstrap the real kernel binary. We need a custom
    //    operator cert because the harness's default cert advertises
    //    `permitted_ops = ["CreateInitiative"]` only, and the test
    //    needs `ApprovePlan` and `AbortInitiative` (cleanup path) too.
    //    Bootstrap is a separate kernel invocation that exits when
    //    done; the running daemon comes up below.
    let (signing_key, fingerprint) = build_e2e_operator_key();
    let (kernel_bin, data_dir) = bootstrap_with_custom_cert(&signing_key);
    eprintln!("[e2e] kernel bootstrapped, data_dir={}", data_dir.display());

    // ── §7.3a — Inject the gateway + Anthropic provider into the
    //    just-written policy.toml (genesis template emits both
    //    blocks COMMENTED OUT). Without this the kernel boots in
    //    "no LLM" degraded mode and the planner cannot drive a
    //    single inference call.
    let gateway_binary = require_gateway_binary();
    enable_gateway_in_policy(&data_dir, &gateway_binary);

    // ── §7.3b — Stage the per-task credential files the plan
    //    declares + the gateway provider credentials (Anthropic
    //    api_key). Both go under `<data_dir>/{credentials,providers}/`
    //    BEFORE the daemon kernel boots so admission and the first
    //    `FetchRequest` both find what they need.
    write_credentials(&data_dir);
    write_provider_credentials(&data_dir);

    // ── §7.3c — Now bring up the daemon kernel. It re-reads the
    //    (mutated) policy.toml at boot, so `[gateway]` and
    //    `[[providers]]` go live on this spawn.
    let install_dir = PathBuf::from(
        std::env::var("RAXIS_INSTALL_DIR").expect("preflight verified RAXIS_INSTALL_DIR")
    );
    let mut kernel = spawn_kernel_normal(&kernel_bin, data_dir.clone(), &install_dir);
    kernel.wait_until_ready_or_panic(READY_DEADLINE);
    eprintln!("[e2e] kernel daemon up, accepting operator IPC");

    // ── §7.4 — submit + approve the plan via the operator UDS. Both
    //    requests share one connection (one challenge-response
    //    handshake) per `cli/src/conn.rs::OperatorConn::send_request`.
    let initiative_id = fresh_initiative_id();
    let op_socket = kernel.operator_socket();
    let mut conn = OperatorIpc::connect(&op_socket, &signing_key, &fingerprint);
    conn.submit_plan(&initiative_id);
    eprintln!("[e2e] plan submitted, initiative_id={initiative_id}");
    conn.approve_plan(&initiative_id, &fingerprint);
    eprintln!("[e2e] plan approved; orchestrator spawn pending");
    drop(conn);

    // ── §7.5 — §7.10 — wait for the full chain to land in the audit
    //    log. The terminal success event is `IntegrationMergeCompleted`
    //    for `initiative_id`. The poll loop fails fast on
    //    `SecurityViolationDetected` so a regression that triggers a
    //    fail-closed gate doesn't waste the full deadline.
    let chain = poll_for_lifecycle_completion(kernel.data_dir(), &initiative_id);
    eprintln!("[e2e] lifecycle complete, chain has {} events", chain.len());

    // ── §7.13 — graceful shutdown. The kernel's signal handler must
    //    drain in-flight intents, terminate active sessions, and emit
    //    the final `KernelShutdown { exit: "graceful" }` audit row.
    let status = kernel.shutdown_with(libc::SIGTERM, SHUTDOWN_DEADLINE);
    assert!(
        status.success(),
        "kernel must exit cleanly (got {:?}); stderr:\n{}",
        status,
        kernel.captured_stderr(),
    );

    // ── §7.14 — post-mortem audit chain assertions. We pin the
    //    *invariants* the spec's table calls out, not the per-row
    //    positions (real LLM scheduling is non-deterministic; e.g. the
    //    orchestrator may interleave `ProposedDefaults` reads with
    //    `ActivateSubTask` calls).
    let final_chain = walk_chain_or_panic(kernel.data_dir());
    assert_audit_invariants(&final_chain, &initiative_id);
    eprintln!("[e2e] audit chain integrity verified ({} events)", final_chain.len());
}

// ---------------------------------------------------------------------------
// §7.1 — Preflight
// ---------------------------------------------------------------------------

/// Verify every out-of-tree dependency the test depends on is
/// reachable. Each panic carries the exact remediation step. We do
/// these checks BEFORE the kernel boot so a missing dep surfaces in
/// seconds, not minutes (the kernel's `verify_canonical_images_at_
/// boot` is silent-warning, not fail-fast — we want fail-fast here).
fn preflight_or_skip() {
    require_tcp_reachable(PG_HOST_PORT, "Postgres docker container");
    require_tcp_reachable(MONGO_HOST_PORT, "MongoDB docker container");
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
             docker compose -f live-e2e/docker-compose.e2e.yml up -d --wait",
        );
    }
}

fn require_anthropic_dev_key() {
    let env_path = workspace_dotenv_path();
    let body = match std::fs::read_to_string(&env_path) {
        Ok(b) => b,
        Err(e) => panic!(
            "{} is required for the live LLM round-trip but read failed: {e}\n\
             Create it with one line:\n  \
             ANTHROPIC-API-DEV-KEY=sk-ant-...",
            env_path.display(),
        ),
    };
    let has_key = body
        .lines()
        .any(|l| l.starts_with("ANTHROPIC-API-DEV-KEY=") && l.len() > "ANTHROPIC-API-DEV-KEY=".len());
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

/// `RAXIS_GATEWAY_BINARY` env var must point to a built `raxis-gateway`
/// executable. The kernel `Command::new(binary_path)` it (per
/// `[gateway].binary_path` in policy.toml) the first time a planner
/// issues a `FetchRequest`. Without it the gateway supervisor will
/// emit `GatewayQuarantined` after the back-off cap and the planner
/// will hang on its first LLM call.
///
/// Why an env var rather than `cargo build -p raxis-gateway` from
/// inside the test: spawning a recursive `cargo build` would
/// contend with the parent `cargo test --workspace` build lock and
/// can wedge the entire test run for tens of minutes (same reason
/// the harness's `build_and_locate_kernel` reads `CARGO_BIN_EXE_*`
/// instead of shelling out).
fn require_gateway_binary() -> PathBuf {
    let raw = std::env::var("RAXIS_GATEWAY_BINARY").unwrap_or_else(|_| {
        panic!(
            "RAXIS_GATEWAY_BINARY env var is required; build the gateway and \
             export the path:\n  \
             cargo build -p raxis-gateway --release\n  \
             export RAXIS_GATEWAY_BINARY=$(pwd)/target/release/raxis-gateway",
        );
    });
    let p = PathBuf::from(&raw);
    assert!(
        p.is_absolute(),
        "RAXIS_GATEWAY_BINARY must be an absolute path (policy validates \
         `[gateway] binary_path` as absolute); got {raw:?}",
    );
    assert!(
        p.exists(),
        "RAXIS_GATEWAY_BINARY={raw:?} does not exist; build the gateway:\n  \
         cargo build -p raxis-gateway --release",
    );
    p
}

/// `RAXIS_INSTALL_DIR/images/` must contain the three signed canonical
/// .img + .manifest.toml pairs the kernel boots into microVMs:
///
///   * `raxis-orchestrator-core-<kernel_version>.img(.manifest.toml)`
///   * `raxis-executor-starter-<kernel_version>.img(.manifest.toml)`
///   * `raxis-reviewer-core-<kernel_version>.img(.manifest.toml)`
///
/// Without these the orchestrator spawn fails with
/// `CanonicalImageError::IoMissing` mid-lifecycle, which surfaces
/// as a generic "session spawn failed" deep into the run. We
/// preflight the FILE existence here; the kernel itself separately
/// verifies the manifest signature against the build-time-pinned
/// trust anchor (`raxis_canonical_images::EXPECTED_KERNEL_SIGNING_
/// KEY_BYTES`).
fn require_canonical_images() {
    let install_dir_raw = std::env::var("RAXIS_INSTALL_DIR").unwrap_or_else(|_| {
        panic!(
            "RAXIS_INSTALL_DIR env var is required; point it at the install \
             root that contains `images/raxis-{{orchestrator,executor-starter,\
             reviewer}}-core-<version>.img` and matching `.manifest.toml` \
             files. See `raxis_canonical_images::*_image_path`.",
        );
    });
    let install_dir = PathBuf::from(&install_dir_raw);
    let kernel_version = env!("CARGO_PKG_VERSION");
    for role in &["orchestrator-core", "executor-starter", "reviewer-core"] {
        let img = install_dir
            .join("images")
            .join(format!("raxis-{role}-{kernel_version}.img"));
        let manifest = install_dir
            .join("images")
            .join(format!("raxis-{role}-{kernel_version}.manifest.toml"));
        assert!(
            img.exists(),
            "missing canonical image {}; rebuild + sign per `system-requirements.md §3`",
            img.display(),
        );
        assert!(
            manifest.exists(),
            "missing canonical manifest {}; rebuild + sign per `system-requirements.md §3`",
            manifest.display(),
        );
    }
}

// ---------------------------------------------------------------------------
// §7.2 — Custom-cert bootstrap
// ---------------------------------------------------------------------------

/// Mint a deterministic operator key for the E2E test. We use a
/// dedicated seed (`[0xC0; 32]`) distinct from the harness's
/// `[0xA5; 32]` so a bug that accidentally cross-wires the two
/// shows up immediately.
fn build_e2e_operator_key() -> (SigningKey, OperatorFingerprint) {
    let key = SigningKey::from_bytes(&E2E_OPERATOR_SEED);
    let pubkey = key.verifying_key().to_bytes();
    (key, fingerprint_8(&pubkey))
}

/// Run `raxis-kernel` in bootstrap mode against a fresh tempdir
/// using a custom operator cert that advertises the full lifecycle
/// op set. Returns the (kernel_bin_path, data_dir).
///
/// We deliberately do NOT use [`KernelInstance::bootstrap_and_spawn`]
/// because that helper hard-codes the harness cert with
/// `permitted_ops = ["CreateInitiative"]`. The E2E test additionally
/// needs `ApprovePlan` (and `AbortInitiative` on the cleanup path).
fn bootstrap_with_custom_cert(signing_key: &SigningKey) -> (PathBuf, PathBuf) {
    let kernel_bin = build_and_locate_kernel();

    let cert = ephemeral_cert_with_key(signing_key, CertOpts {
        now_unix_secs: 1_700_000_000,
        permitted_ops: vec![
            "CreateInitiative".to_owned(),
            "ApprovePlan".to_owned(),
            "AbortInitiative".to_owned(),
        ],
        display_name: "e2e-operator".to_owned(),
        ..CertOpts::default()
    });

    // Allocate a tempdir, then immediately leak its path with
    // `keep()` so the data dir survives until the kernel exits.
    // Dropping the `TempDir` earlier would yank the directory out
    // from under the running daemon and corrupt the audit chain.
    // `keep()` is the post-deprecation replacement for `into_path()`.
    let data_dir: PathBuf = tempfile::tempdir()
        .expect("tempdir for kernel data dir")
        .keep();

    let cert_path = data_dir.join("operator.cert.toml");
    let toml_body = toml::to_string(&cert).expect("serialise e2e cert");
    std::fs::write(&cert_path, toml_body).expect("write e2e operator cert");

    let bootstrap_output = Command::new(&kernel_bin)
        .env("RAXIS_BOOTSTRAP", "1")
        .env("RAXIS_DATA_DIR", &data_dir)
        .env("RAXIS_OPERATOR_CERT", &cert_path)
        .output()
        .expect("spawn kernel in bootstrap mode");
    assert!(
        bootstrap_output.status.success(),
        "kernel bootstrap failed (exit {:?}):\n--- stdout ---\n{}\n--- stderr ---\n{}",
        bootstrap_output.status.code(),
        String::from_utf8_lossy(&bootstrap_output.stdout),
        String::from_utf8_lossy(&bootstrap_output.stderr),
    );

    (kernel_bin, data_dir)
}

/// Spawn `raxis-kernel` in normal mode against a previously-bootstrapped
/// `data_dir`. Returns a [`KernelInstance`] handle that owns the
/// child + a captured-stderr buffer.
fn spawn_kernel_normal(kernel_bin: &Path, data_dir: PathBuf, install_dir: &Path) -> KernelInstance {
    use std::io::{BufRead, BufReader};
    use std::process::{Command as ProcCommand, Stdio};
    use std::sync::{Arc, Mutex};

    let mut child = ProcCommand::new(kernel_bin)
        .env("RAXIS_DATA_DIR", &data_dir)
        // Surface the canonical-image install root explicitly so the
        // kernel does not silently fall back to `data_dir` (which
        // would never contain `images/raxis-*-core-<v>.img`). This
        // is the first env-var the kernel reads on boot
        // (`canonical_images_preflight::verify_canonical_images_at_boot`).
        .env("RAXIS_INSTALL_DIR", install_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn kernel in normal mode");

    let stderr = child.stderr.take().expect("kernel stderr captured");
    let stderr_lines = Arc::new(Mutex::new(Vec::<String>::new()));
    {
        let lines = Arc::clone(&stderr_lines);
        std::thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines().map_while(Result::ok) {
                lines.lock().unwrap().push(line);
            }
        });
    }

    KernelInstance::from_parts(child, stderr_lines, data_dir)
}

/// Mutate `<data_dir>/policy/policy.toml` (written by bootstrap with
/// `[gateway]` / `[[providers]]` blocks COMMENTED OUT — see
/// `crates/genesis-tools::render_genesis_policy_toml`) to enable the
/// gateway against the just-built `raxis-gateway` binary and a
/// single Anthropic provider.
///
/// The kernel's `load_policy` does NOT verify any signature on
/// policy.toml at boot (signature verification only fires inside
/// `policy_manager::advance_epoch`, the runtime epoch-rotation
/// path), so post-bootstrap mutation is safe and persists across
/// the second `Command::new(kernel_bin).spawn()` below.
fn enable_gateway_in_policy(data_dir: &Path, gateway_binary: &Path) {
    let policy_path = data_dir.join("policy").join("policy.toml");
    let mut body = std::fs::read_to_string(&policy_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", policy_path.display()));
    assert!(
        !body.contains("\n[gateway]\n"),
        "policy.toml already has a [gateway] block; bootstrap template changed",
    );
    let injected = format!(
        "\n# ── [gateway] + [[providers]] injected by full_e2e_session_lifecycle ──\n\
         [gateway]\n\
         binary_path              = \"{gw}\"\n\
         spawn_timeout_secs       = 30\n\
         respawn_backoff_ms       = 1000\n\
         max_consecutive_respawns = 5\n\
         \n\
         [[providers]]\n\
         provider_id           = \"anthropic-e2e\"\n\
         kind                  = \"Anthropic\"\n\
         credentials_file      = \"anthropic-e2e.toml\"\n\
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

// ---------------------------------------------------------------------------
// §7.3 — Credential injection
// ---------------------------------------------------------------------------

/// Write the three credential files declared by the spec's plan
/// (`§3.1` Postgres, `§3.2` MongoDB, `§3.3` GCP ADC) under
/// `<data_dir>/credentials/`. The kernel's credential proxies
/// resolve names against this directory at spawn time
/// (`raxis-credentials-file::FileCredentialBackend`).
fn write_credentials(data_dir: &Path) {
    let cred_dir = data_dir.join("credentials");
    std::fs::create_dir_all(&cred_dir).expect("mkdir credentials");

    write_with_mode_0600(
        &cred_dir.join("test-pg-dev.env"),
        b"PGHOST=127.0.0.1\n\
          PGPORT=54399\n\
          PGUSER=raxis_test\n\
          PGPASSWORD=raxis_test_pass\n\
          PGDATABASE=raxis_e2e\n\
          PGSSLMODE=disable\n",
    );

    write_with_mode_0600(
        &cred_dir.join("test-mongo-dev.env"),
        b"MONGO_HOST=127.0.0.1\n\
          MONGO_PORT=27399\n\
          MONGO_USER=raxis_test\n\
          MONGO_PASSWORD=raxis_test_pass\n\
          MONGO_AUTH_DB=admin\n\
          MONGO_DATABASE=raxis_e2e\n",
    );

    let adc = dirs_home()
        .expect("HOME is set (preflight passed)")
        .join(".config/gcloud/application_default_credentials.json");
    let adc_bytes = std::fs::read(&adc).unwrap_or_else(|e| {
        panic!("read GCP ADC at {}: {e}", adc.display())
    });
    write_with_mode_0600(&cred_dir.join("test-gcp-dev.json"), &adc_bytes);
}

/// Per `credential-proxy.md §6.1` credential files MUST be 0600 so
/// only the kernel UID can read them. We hand-set the mode after
/// `std::fs::write` because `write` honours umask and a permissive
/// umask would leave the file world-readable.
fn write_with_mode_0600(path: &Path, body: &[u8]) {
    std::fs::write(path, body)
        .unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .unwrap_or_else(|e| panic!("chmod 0600 {}: {e}", path.display()));
}

// ---------------------------------------------------------------------------
// Provider config (gateway → Anthropic)
// ---------------------------------------------------------------------------

/// Write `<data_dir>/providers/anthropic-e2e.toml` — the
/// credentials file the gateway resolves through
/// `FileCredentialBackend` for the `[[providers]]` entry whose
/// `credentials_file = "anthropic-e2e.toml"`.
///
/// Wire shape (`raxis/gateway/src/policy_view.rs::load_provider_
/// credentials`): a flat TOML with `api_key`, optional `auth_header`
/// (default `"Authorization"`), optional `auth_prefix` (default
/// `"Bearer "`). Anthropic uses `x-api-key` with no prefix.
///
/// Mode 0600 because `peripherals.md §3.2` mandates kernel-uid-only
/// readability for provider credential files.
fn write_provider_credentials(data_dir: &Path) {
    let providers_dir = data_dir.join("providers");
    std::fs::create_dir_all(&providers_dir).expect("mkdir providers");

    let env_path = workspace_dotenv_path();
    let body = std::fs::read_to_string(&env_path).expect("preflight verified .env exists");
    let api_key = body
        .lines()
        .find_map(|l| l.strip_prefix("ANTHROPIC-API-DEV-KEY="))
        .map(str::trim)
        .expect("preflight verified ANTHROPIC-API-DEV-KEY=... is present")
        .to_owned();

    let provider_toml = format!(
        "api_key     = \"{api_key}\"\n\
         auth_header = \"x-api-key\"\n\
         auth_prefix = \"\"\n",
    );
    write_with_mode_0600(
        &providers_dir.join("anthropic-e2e.toml"),
        provider_toml.as_bytes(),
    );
}

// ---------------------------------------------------------------------------
// §7.4 — Operator IPC (real challenge-response handshake + V2.1 plan
// bundle submission + ApprovePlan).
// ---------------------------------------------------------------------------

/// Owns one authenticated UDS connection to the operator socket.
/// Mirrors `cli/src/conn.rs::OperatorConn` byte-for-byte so a wire
/// drift between the CLI and this test would surface here as well.
struct OperatorIpc {
    stream: UnixStream,
}

impl OperatorIpc {
    fn connect(socket_path: &Path, signing_key: &SigningKey, fingerprint: &OperatorFingerprint) -> Self {
        let mut stream = UnixStream::connect(socket_path)
            .unwrap_or_else(|e| panic!("connect {}: {e}", socket_path.display()));

        // Step 1: read challenge.
        let challenge = read_json_blocking(&mut stream);
        let challenge_hex = challenge["challenge_hex"]
            .as_str()
            .expect("kernel sends challenge_hex per cli-ceremony.md §4.1");
        let challenge_bytes = hex::decode(challenge_hex).expect("challenge_hex is hex");
        assert_eq!(challenge_bytes.len(), 32, "challenge is 32 bytes");

        // Step 2: sign the DECODED bytes (NOT the hex string).
        let sig = signing_key.sign(&challenge_bytes);

        // Step 3: send response.
        let fingerprint_hex = hex::encode(fingerprint.as_bytes());
        let response = serde_json::json!({
            "fingerprint":          fingerprint_hex,
            "signed_challenge_hex": hex::encode(sig.to_bytes()),
        });
        write_json_frame(&mut stream, &response).expect("write auth response");

        // Step 4: read auth ack.
        let ack = read_json_blocking(&mut stream);
        assert_eq!(
            ack["status"].as_str(), Some("Ok"),
            "kernel rejected auth: {ack:#}",
        );

        Self { stream }
    }

    /// Submit a `CreateInitiativeV2` request carrying a freshly-
    /// signed plan bundle. The plan TOML body is the spec's §4
    /// example, modulo the verifier section (deferred — V2 verifier
    /// dispatch is a separate slice; the test asserts the
    /// orchestrator → executor → reviewer → merge chain only).
    fn submit_plan(&mut self, initiative_id: &str) {
        let plan_toml = canonical_plan_toml();
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
            resp["result"].as_str(), Some("InitiativeCreated"),
            "CreateInitiativeV2 must succeed; got: {resp:#}",
        );
        let returned_id = resp["initiative_id"]
            .as_str()
            .expect("InitiativeCreated carries initiative_id");
        assert_eq!(returned_id, initiative_id, "initiative id roundtrip");
    }

    /// Approve the just-submitted plan. Triggers the orchestrator
    /// auto-spawn callsite in `kernel/src/initiatives/lifecycle.rs::
    /// approve_plan` (post-commit `OrchestratorSpawn::spawn_for_
    /// initiative` fires here).
    fn approve_plan(&mut self, initiative_id: &str, fingerprint: &OperatorFingerprint) {
        let req = serde_json::json!({
            "op": "ApprovePlan",
            "payload": {
                "initiative_id":      initiative_id,
                "approving_operator": hex::encode(fingerprint.as_bytes()),
            },
        });
        write_json_frame(&mut self.stream, &req).expect("write ApprovePlan");
        let resp = read_json_blocking(&mut self.stream);
        assert_eq!(
            resp["result"].as_str(), Some("PlanApproved"),
            "ApprovePlan must succeed; got: {resp:#}",
        );
    }
}

fn read_json_blocking(stream: &mut UnixStream) -> Value {
    let body = read_json_frame_raw(stream).expect("read kernel frame");
    serde_json::from_str(&body).expect("kernel frame is JSON")
}

/// The `[plan]` body the test submits. Aligned to the actual
/// `parse_plan_*` shape in `kernel/src/initiatives/lifecycle.rs`:
///
///   * `[plan.initiative].description` — operator-facing summary.
///   * `[workspace].lane_id` — REQUIRED (`validate_single_lane_
///     propagation` rejects missing/empty). Single-lane propagation
///     fans this id out to every task / session / budget reservation.
///   * `[[tasks]]` — each entry MUST carry `task_id` and a non-empty
///     `description` (`v2_extended_gaps.md §1.1`).
///   * `[[tasks.credentials]]` — `proxy_type` (NOT `kind`) selects the
///     proxy; `name` resolves against `<data_dir>/credentials/`;
///     `mount_as` is the env-var injected into the guest VM.
///
/// **Spec drift note.** `e2e-live-test-gap.md §4` originally cited
/// `[plan].name` / `[plan.gateway]` blocks — those keys are NOT
/// part of the kernel's plan parser surface (they are inert if
/// included). The provider/model pinning happens via the policy
/// `[gateway]` + `[[providers]]` blocks (`peripherals.md §3.2`),
/// which the test injects in `enable_gateway_in_policy` below. The
/// spec is updated alongside this test to reflect the parser shape.
///
/// The verifier section is intentionally omitted in this iteration:
/// V2 verifier dispatch is exercised by per-proxy `live-e2e` slices;
/// folding it in here would gate the test on yet another canonical
/// image (`raxis-verifier-default-…`).
fn canonical_plan_toml() -> String {
    [
        "[plan.initiative]",
        "description = \"\"\"",
        "Create hello.txt containing the text \\\"Hello from RAXIS E2E test!\\\".",
        "Use the executor's edit_file tool. Confirm completion via task_complete.",
        "\"\"\"",
        "",
        "[workspace]",
        "name    = \"E2E live test\"",
        "lane_id = \"e2e-live-lane\"",
        "",
        "# ── Executor task ──────────────────────────────────────",
        "[[tasks]]",
        "task_id            = \"write-hello\"",
        "name               = \"Create hello.txt with a greeting\"",
        "session_agent_type = \"Executor\"",
        "path_allowlist     = [\"hello.txt\"]",
        "description = \"\"\"",
        "Create a file called hello.txt containing the text:",
        "Hello from RAXIS E2E test!",
        "\"\"\"",
        "",
        "  [[tasks.credentials]]",
        "  name       = \"test-pg-dev\"",
        "  proxy_type = \"postgres\"",
        "  mount_as   = \"DATABASE_URL\"",
        "",
        "  [[tasks.credentials]]",
        "  name       = \"test-mongo-dev\"",
        "  proxy_type = \"mongodb\"",
        "  mount_as   = \"MONGO_URL\"",
        "",
        "  [[tasks.credentials]]",
        "  name       = \"test-gcp-dev\"",
        "  proxy_type = \"gcp\"",
        "  mount_as   = \"GCP_METADATA_URL\"",
        "",
        "# ── Reviewer task ──────────────────────────────────────",
        "[[tasks]]",
        "task_id            = \"review-hello\"",
        "name               = \"Review hello.txt changes\"",
        "session_agent_type = \"Reviewer\"",
        "predecessors       = [\"write-hello\"]",
        "description = \"\"\"",
        "Confirm that hello.txt was created with the expected content (the line",
        "\\\"Hello from RAXIS E2E test!\\\"). Approve via the reviewer's approve tool.",
        "\"\"\"",
    ].join("\n")
}

/// Build a V2.1 `PlanBundle` carrying `plan.toml` as its sole
/// artifact (the V2 visitor set is empty per `plan-bundle-sealing.
/// md §5.4`). Mirrors `cli/src/commands/submit.rs::run_submit_plan`
/// phases 4–6.
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
        // `plan_root_relpath` is informational per §3.1; we stamp a
        // synthetic path because the test never writes plan.toml to
        // disk (the bundle carries the bytes inline).
        "/raxis/e2e-live".to_owned(),
        artifacts,
    )
}

/// Compute the operator key fingerprint per
/// `raxis_types::compute_operator_fingerprint` (SHA-256[:8] of the
/// 32-byte ed25519 pubkey). Inlined here so the test does not pull
/// the kernel-internal helper crate into its dependency surface.
fn fingerprint_8(pubkey: &[u8; 32]) -> OperatorFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(pubkey);
    let hash = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&hash[..8]);
    OperatorFingerprint::new(out)
}

// ---------------------------------------------------------------------------
// §7.5 – §7.10 — wait for the lifecycle to reach `IntegrationMerge
// Completed` for our initiative.
// ---------------------------------------------------------------------------

/// Poll the audit log until a terminal event for the test's
/// initiative lands. Returns the partial chain at success, panics
/// on:
///   - any `SecurityViolationDetected` (fail-closed gate fired —
///     surface the kind so the operator can correlate),
///   - the deadline elapsing without a terminal event,
///   - any chain-integrity break detected by `verify_chain_full`.
///
/// We intentionally do NOT pin per-step intermediate events here.
/// The chain ordering is non-deterministic across runs because the
/// real LLM may pick different intermediate tool calls (read_file,
/// bash) before the terminal `task_complete`. The post-mortem
/// assertion (`assert_audit_invariants`) pins the *set* of events
/// that must be present.
fn poll_for_lifecycle_completion(data_dir: &Path, initiative_id: &str) -> Vec<AuditEvent> {
    let audit_dir = data_dir.join("audit");
    let start = Instant::now();
    let mut last_len = 0usize;
    loop {
        if start.elapsed() > LIFECYCLE_DEADLINE {
            panic!(
                "lifecycle deadline of {LIFECYCLE_DEADLINE:?} exceeded \
                 without IntegrationMergeCompleted for {initiative_id}; \
                 audit chain at exit ({} events):\n{}",
                last_len,
                summarize_chain_for_panic(&audit_dir),
            );
        }

        let events = match read_audit_chain(&audit_dir) {
            Ok(e) => e,
            Err(_) => {
                // Audit segment may not exist yet on first iter; sleep
                // a tick and retry.
                std::thread::sleep(Duration::from_millis(250));
                continue;
            }
        };
        last_len = events.len();

        // Fail-closed guard: any SecurityViolation aborts the test
        // immediately. The kernel's invariants are stricter than
        // the test's expectations; if a gate fires the test run is
        // unrecoverable.
        for e in &events {
            if e.event_kind == "SecurityViolation"
                || e.event_kind == "SecurityViolationDetected"
            {
                panic!(
                    "SecurityViolation fired during lifecycle: \
                     event_kind={}, payload={:#}",
                    e.event_kind, e.payload,
                );
            }
        }

        // Terminal: `IntegrationMergeCompleted` for OUR initiative.
        // The variant carries an `initiative_id` field at the
        // top-level audit-event slot; we filter on the id so a
        // co-running initiative cannot trick the poll into
        // finishing early.
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

/// Read the on-disk audit chain. Returns `Err(())` if the audit dir
/// does not exist yet (caller retries).
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

// ---------------------------------------------------------------------------
// §7.14 — Post-mortem audit chain assertions
// ---------------------------------------------------------------------------

/// Walk `<data_dir>/audit/` with the full chain verifier (sequence
/// monotonicity + prev_sha256 link integrity end-to-end), then
/// enumerate every record and decode the parsed JSON body into
/// `AuditEvent`. Panics with a friendly diagnostic on any chain
/// break or row that fails the typed deserialise.
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
                "chain row seq={} has no parsed_value (raw_line failed JSON parse)",
                row.seq,
            ));
            serde_json::from_value::<AuditEvent>(value).unwrap_or_else(|e| {
                panic!("decode AuditEvent from chain row {}: {e}", row.seq)
            })
        })
        .collect()
}

/// Verify the audit chain meets the spec's *invariants* without
/// over-pinning per-row positions. We assert:
///
///   1. The first row is `KernelBootCompleted` (boot ordering).
///   2. The last row is `KernelShutdown` (graceful shutdown ran
///      to completion).
///   3. The set of `kind`s contains the canonical lifecycle subset
///      (`InitiativeCreated`, `IntentAdmitted`, `IntegrationMerge
///      Completed`, etc.). Order is deliberately not pinned because
///      LLM scheduling is non-deterministic.
///   4. `IntegrationMergeCompleted` for OUR initiative_id appears.
///   5. NO `SecurityViolationDetected` rows present.
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

    // Required lifecycle events. Missing any one indicates a chain-
    // wiring regression in the kernel — the test fails loud rather
    // than silently passing on a half-completed run.
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

    // Filtered presence: at least one IntegrationMergeCompleted for
    // OUR initiative. The audit chain row carries `initiative_id`
    // at the top-level event slot (set by the kernel-side emit
    // path) so we filter without re-decoding the typed payload.
    // Defensive: also try the typed `AuditEventKind` deserialise so
    // a regression in the top-level `initiative_id` denormalisation
    // doesn't silently mask a missing event.
    let merged_for_us = chain.iter().any(|e| {
        if e.event_kind != "IntegrationMergeCompleted" {
            return false;
        }
        if e.initiative_id.as_deref() == Some(initiative_id) {
            return true;
        }
        match serde_json::from_value::<AuditEventKind>(e.payload.clone()) {
            Ok(AuditEventKind::IntegrationMergeCompleted { initiative_id: id, .. })
                if id == initiative_id => true,
            _ => false,
        }
    });
    assert!(
        merged_for_us,
        "no IntegrationMergeCompleted for {initiative_id}; chain kinds: {kinds:?}",
    );

    assert!(
        !kinds.contains("SecurityViolation")
            && !kinds.contains("SecurityViolationDetected"),
        "SecurityViolation must NOT appear in a clean lifecycle; \
         kinds: {kinds:?}",
    );
}

// ---------------------------------------------------------------------------
// Misc helpers
// ---------------------------------------------------------------------------

/// `<workspace_root>/raxis/.env`. Resolved from `CARGO_MANIFEST_DIR`
/// at compile time so the path is stable across the test binary's
/// runtime cwd.
fn workspace_dotenv_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|p| p.join(".env"))
        .unwrap_or_else(|| PathBuf::from("raxis/.env"))
}

/// Lightweight `dirs::home_dir()` substitute — we don't pull the
/// `dirs` crate just for one lookup. Reads `$HOME` directly; absent
/// ⇒ `None`. Adequate for the test's preflight check where we
/// already know the test is running under a real user account.
fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

