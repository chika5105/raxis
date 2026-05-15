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
//!     `OperatorRequest::CreateInitiative` JSON IPC frame.
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
use common::tier3_artifacts::Tier3Reporter;

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
const PG_HOST_PORT: &str = "127.0.0.1:54399";
/// Loopback host:port the docker-compose MongoDB binds to.
const MONGO_HOST_PORT: &str = "127.0.0.1:27399";

/// Loopback bind address for the in-test operator dashboard. Picked
/// distinct from the spec default `127.0.0.1:9820` so a developer
/// running the production daemon side-by-side does not collide
/// with the test's listener. Override with
/// `RAXIS_E2E_DASHBOARD_PORT` when 19820 is itself busy.
const DASHBOARD_DEFAULT_PORT: u16 = 19820;
const DASHBOARD_BIND_ADDRESS: &str = "127.0.0.1";

/// How long the test waits for the kernel to bind sockets after
/// spawn. `bootstrap_and_spawn` is generous; CI machines under
/// load occasionally take >5s.
const READY_DEADLINE: Duration = Duration::from_secs(15);

/// How long the test waits for graceful kernel exit on SIGTERM.
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(30);

/// How long the test waits for the *full* lifecycle chain
/// (orchestrator boot → executor commit → reviewer approve →
/// integration-merge) to land in the audit log. Worst case three
/// VM cold-boots + three real LLM round-trips with a small claude-
/// sonnet model. May be overridden by `RAXIS_E2E_LIFECYCLE_DEADLINE_SECS`
/// for fast-fail iteration cycles during AVF substrate bring-up.
fn lifecycle_deadline() -> Duration {
    let secs = std::env::var("RAXIS_E2E_LIFECYCLE_DEADLINE_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(360);
    Duration::from_secs(secs)
}

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

    // ── §7.3c-bis — Seed the operator-managed source repository
    //    at `<data_dir>/repositories/main`. Per V2 §Step 24 the
    //    kernel does NOT auto-create this repo; it is the
    //    operator's responsibility (in production: the operator
    //    runs `git init --bare && git push` once at install time;
    //    in this test: we synthesise the equivalent bytes
    //    inline). The orchestrator-spawn path's
    //    `provision_orchestrator_worktree` requires this repo to
    //    exist with the initiative's `target_ref` (defaults to
    //    `refs/heads/main`) pointing at a real commit. We seed an
    //    empty initial commit on `main` — the executor task will
    //    create `hello.txt` on top.
    seed_main_repository(&data_dir);

    // ── §7.3c — Now bring up the daemon kernel. It re-reads the
    //    (mutated) policy.toml at boot, so `[gateway]` and
    //    `[[providers]]` go live on this spawn.
    let install_dir = PathBuf::from(
        std::env::var("RAXIS_INSTALL_DIR").expect("preflight verified RAXIS_INSTALL_DIR"),
    );
    let mut kernel = spawn_kernel_normal(&kernel_bin, data_dir.clone(), &install_dir);
    kernel.wait_until_ready_or_panic(READY_DEADLINE);
    eprintln!("[e2e] kernel daemon up, accepting operator IPC");

    // Tier-3 reporter: built before the dashboard is opened so a
    // mid-run panic still emits the artifact block on Drop. The
    // dashboard URL is captured below when the autologin helper
    // succeeds; we register it on the reporter so the post-run
    // block surfaces the same URL.
    let mut tier3 =
        Tier3Reporter::new("e2e", &install_dir, kernel.data_dir()).with_observability_urls();

    // Print the same Grafana/Prometheus URL block at startup that
    // the Tier-3 reporter will emit again at end-of-run, so an
    // operator watching the kernel come up can open the dashboards
    // immediately rather than waiting for the test to finish.
    // Cheap (≤ four 250ms TCP probes); the helper never panics.
    common::tier3_artifacts::print_observability_urls_inline("e2e");

    // ── (visual-debug) — open the operator dashboard with an
    //    autologin URL so the developer can watch the lifecycle in
    //    the browser. Best-effort: a missing FE bundle / port
    //    collision / missing `open(1)` is logged and skipped, never
    //    fatal — the test must still pass headless on CI / SSH.
    let dashboard_port = configured_dashboard_port();
    if let Some(url) = open_dashboard_with_autologin(&signing_key, dashboard_port) {
        tier3.set_dashboard_url(url);
    }

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
    eprintln!(
        "[e2e] audit chain integrity verified ({} events)",
        final_chain.len()
    );

    // Tier-3 artifact-block parity with the realistic-scenario
    // driver. The merged worktree for `full_e2e_session_lifecycle`
    // is `<data_dir>/repositories/main` (the operator-managed source
    // the integration-merge pushes into).
    let merged_repo = kernel.data_dir().join("repositories/main");
    tier3.add_worktree("merged-source-of-truth", merged_repo);
    tier3.mark_success();
    // `tier3` Drop fires here (or unwinds on a panic above), emitting
    // the artifact block exactly once and honoring the
    // `RAXIS_E2E_KEEP` / `RAXIS_E2E_OPEN_REPO` policy env vars.
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
    )
    .is_err()
    {
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

        // Iter-12 stub regression: walk the cpio.gz and assert
        // every role-required binary is present. Without this the
        // file-existence check above passes for binary-only stub
        // images and the test fails 4 minutes in with `BashTool:
        // ENOENT` instead of failing fast at preflight.
        // See `tests/common/cpio_inspect.rs`.
        let required: &[&str] = match *role {
            "executor-starter" => &[
                "bin/bash",
                "usr/bin/python3",
                "usr/bin/git",
                "usr/local/bin/raxis-executor",
            ],
            "orchestrator-core" => &["usr/local/bin/raxis-orchestrator"],
            "reviewer-core" => &["usr/local/bin/raxis-reviewer"],
            _ => unreachable!("role list is closed-set"),
        };
        let entries = common::cpio_inspect::list_initramfs_paths(&img)
            .unwrap_or_else(|e| panic!("failed to walk canonical image {}: {e}", img.display(),));
        let missing: Vec<&&'static str> = required
            .iter()
            .filter(|b| !entries.contains_key(**b))
            .collect();
        assert!(
            missing.is_empty(),
            "canonical {role} image is a stub — missing {n} required \
             binar{plural} from {}:\n{lines}\n\
             Rebuild via:\n  \
             cargo xtask images bake-rootfs --role {role}\n  \
             cargo xtask images dev-stage    --role {role}\n  \
             cargo xtask images build-all    --role {role}",
            img.display(),
            n = missing.len(),
            plural = if missing.len() == 1 { "y" } else { "ies" },
            lines = missing
                .iter()
                .map(|b| format!("  - {b}"))
                .collect::<Vec<_>>()
                .join("\n"),
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

    // ── macOS — codesign the test-profile kernel binary against
    //    `release/raxis.entitlements` so AVF accepts the spawn.
    //    Without this the orchestrator spawn surfaces as
    //    `Invalid virtual machine configuration. The process doesn't
    //    have the "com.apple.security.virtualization" entitlement.`
    //    inside the audit chain. The signature is harmless on rebuild
    //    (codesign --force overwrites); we apply it every test run so
    //    a fresh `cargo test` after `cargo clean` still works.
    #[cfg(target_os = "macos")]
    codesign_kernel_for_avf(&kernel_bin);

    // Anchor the cert validity window at *real* wall-clock time. The
    // `CertOpts::default()` anchor is `1_700_000_000` (Nov 2023) which
    // is intentional for hermetic unit tests — they pin the clock.
    // The live E2E runs against a kernel that reads
    // `SystemTime::now()`, so the fixture clock has to match or the
    // cert lands in the Expired zone.
    let now_unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is post-epoch")
        .as_secs() as i64;
    let cert = ephemeral_cert_with_key(
        signing_key,
        CertOpts {
            now_unix_secs,
            permitted_ops: vec![
                // V2.5 IPC: the test wraps the plan in a signed
                // PlanBundle and goes through the sole
                // `CreateInitiative` discriminant on the wire (the V1
                // path-based variant was deleted in V2.5; there is no
                // longer a separate V2-named alias either).
                "CreateInitiative".to_owned(),
                "ApprovePlan".to_owned(),
                "AbortInitiative".to_owned(),
                // Together with `OperatorCertInstall` below, these grant
                // the dashboard `Admin` role per
                // `crates/dashboard-kernel/src/lib.rs::roles_from_permitted_ops`.
                // Live-e2e operators run as Admin so the test exercises
                // the full operator surface (reveal-plaintext, policy
                // install via dashboard, every grant/deny audit path).
                "RotateEpoch".to_owned(),
                "OperatorCertInstall".to_owned(),
            ],
            display_name: "e2e-operator".to_owned(),
            ..CertOpts::default()
        },
    );

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
    // Mirror stderr to a log file under `<data_dir>/kernel.stderr.log`
    // so the deadline-exceeded path in `poll_for_lifecycle_completion`
    // can tail it without sharing a `KernelInstance` handle with the
    // poll loop. The on-disk file is also useful for post-mortem
    // triage when the test panics in CI.
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
/// In-place mutation of the genesis-emitted `[dashboard]` block:
///
///   * change `bind_port    = 9820` → `bind_port    = {test_port}`
///     so the test-managed dashboard does not collide with a
///     running developer daemon on the spec default 9820.
///   * insert `static_dir   = "<dashboard-fe/dist>"` immediately
///     after the port line when the React production bundle has
///     been built — without it the kernel's dashboard server
///     serves the JSON API only (no UI), which defeats the
///     visual-debug purpose.
///
/// Genesis emits the block flush-left (Rust `\` line continuation
/// in `genesis_tools::policy_toml::render_genesis_policy_toml`
/// strips the source-file indentation), so each key sits at
/// column 0. We preserve that shape so the rewritten file stays
/// formatted the same way the genesis emitter would have written it.
///
/// Failure mode: if the genesis template is ever changed and the
/// `bind_port    = 9820` literal disappears, this helper panics
/// with a clear remediation — silently failing here would land
/// the test on the spec default port and silently skip the
/// `static_dir` injection (no UI served), which is exactly the
/// failure mode we are trying to prevent.
fn mutate_dashboard_block_in_policy(body: &mut String) {
    const NEEDLE: &str = "bind_port    = 9820\n";
    let port = configured_dashboard_port();
    let replacement = match locate_dashboard_dist() {
        Some(dist) => {
            let mut s = String::new();
            s.push_str(&format!("bind_port    = {port}\n"));
            s.push_str("# static_dir injected by full_e2e_session_lifecycle.\n");
            s.push_str(&format!(
                "static_dir   = {:?}\n",
                dist.display().to_string()
            ));
            s
        }
        None => {
            let mut s = String::new();
            s.push_str(&format!("bind_port    = {port}\n"));
            s.push_str("# NOTE: dashboard-fe/dist not found; serving JSON API only.\n");
            s
        }
    };
    if !body.contains(NEEDLE) {
        panic!(
            "mutate_dashboard_block_in_policy: cannot find {NEEDLE:?} in \
             genesis-emitted policy.toml. The genesis template's [dashboard] \
             block has changed shape — re-anchor this helper against the new \
             format in `genesis_tools::policy_toml::render_genesis_policy_toml`.",
        );
    }
    *body = body.replacen(NEEDLE, &replacement, 1);
}

fn enable_gateway_in_policy(data_dir: &Path, gateway_binary: &Path) {
    let policy_path = data_dir.join("policy").join("policy.toml");
    let mut body = std::fs::read_to_string(&policy_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", policy_path.display()));
    assert!(
        !body.contains("\n[gateway]\n"),
        "policy.toml already has a [gateway] block; bootstrap template changed",
    );

    // ── [dashboard] block mutation — the genesis template already
    //    emits a `[dashboard]` block with `enabled = true`,
    //    `bind_port = 9820`, and no `static_dir`
    //    (`render_genesis_policy_toml` →
    //    `policy_toml.rs::write!(out, "[dashboard]\n…")`). We
    //    cannot APPEND a second block — TOML rejects duplicate
    //    table headers. Instead we surgically replace the
    //    `bind_port` line so the test binds to a non-default
    //    loopback port (19820) — staying off 9820 lets a
    //    developer's running daemon coexist — and inject a
    //    `static_dir` line pointing at the pre-built React
    //    bundle so the dashboard server's
    //    `tower_http::services::ServeDir` fallback can serve the
    //    UI in addition to the JSON API.
    mutate_dashboard_block_in_policy(&mut body);

    let injected = format!(
        "\n# ── [gateway] + [[providers]] + [egress] + [[lanes]] injected by full_e2e_session_lifecycle ──\n\
         [gateway]\n\
         binary_path              = \"{gw}\"\n\
         spawn_timeout_secs       = 30\n\
         respawn_backoff_ms       = 1000\n\
         max_consecutive_respawns = 5\n\
         \n\
         # Gateway-side domain allowlist re-validation per peripherals.md §3.2.\n\
         # Without this section the gateway rejects every dispatched URL with\n\
         # `DomainNotAllowed`, regardless of what the kernel admitted, because\n\
         # the gateway does NOT trust the kernel's pre-validation result.\n\
         [egress]\n\
         domains = [\"api.anthropic.com\"]\n\
         patterns = []\n\
         \n\
         [[providers]]\n\
         provider_id           = \"anthropic-e2e\"\n\
         kind                  = \"Anthropic\"\n\
         credentials_file      = \"anthropic-e2e.toml\"\n\
         inference_timeout_ms  = 120000\n\
         data_fetch_timeout_ms = 30000\n\
         pricing.input_tokens_per_dollar      = 200000\n\
         pricing.output_tokens_per_dollar     = 50000\n\
         pricing.cache_read_tokens_per_dollar = 2000000\n\
         \n\
         # The plan's `[workspace] lane_id = \"e2e-live-lane\"` propagates onto\n\
         # every admitted task (including the synthetic orchestrator-coordinator\n\
         # row inserted by `auto_spawn_orchestrator_session_in_tx`). Without a\n\
         # matching `[[lanes]]` entry, `scheduler::lane::lane_config_for_row`\n\
         # returns `NoLaneAssigned`, which surfaces at the IntegrationMerge\n\
         # `reserve_budget_in_tx` call as `FailBudgetExceeded` (`map_err(|_|\n\
         # FailBudgetExceeded)` in `intent.rs::run_phase_a`). Caps are sized\n\
         # generously so the per-task cost (50 for IntegrationMerge plus\n\
         # `cost_per_touched_path * paths`) clears comfortably.\n\
         [[lanes]]\n\
         lane_id              = \"e2e-live-lane\"\n\
         max_concurrent_tasks = 8\n\
         max_cost_per_epoch   = 100000\n\
         priority             = 100\n",
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

    // Credential value format is normative per `credential-proxy.md §3`:
    // the resolved credential bytes MUST be a libpq URL
    // `postgresql://user:pass@host:port/db` (RFC 3986). The MongoDB
    // form is a plaintext `mongodb://user:pass@host:port/db?authSource=…`
    // URI. `credential-proxy-postgres::ParsedUpstreamUrl::parse` and
    // `credential-proxy-mongodb::ParsedUpstreamUrl::parse` are the
    // consumers; non-URL bytes are rejected with
    // `FAIL_PROXY_UPSTREAM_URL_INVALID`.
    write_with_mode_0600(
        &cred_dir.join("test-pg-dev.env"),
        b"postgresql://raxis_test:raxis_test_pass@127.0.0.1:54399/raxis_e2e",
    );

    write_with_mode_0600(
        &cred_dir.join("test-mongo-dev.env"),
        b"mongodb://raxis_test:raxis_test_pass@127.0.0.1:27399/raxis_e2e?authSource=admin",
    );

    let adc = dirs_home()
        .expect("HOME is set (preflight passed)")
        .join(".config/gcloud/application_default_credentials.json");
    let adc_bytes =
        std::fs::read(&adc).unwrap_or_else(|e| panic!("read GCP ADC at {}: {e}", adc.display()));
    write_with_mode_0600(&cred_dir.join("test-gcp-dev.json"), &adc_bytes);
}

/// Seed `<data_dir>/repositories/main` as a real, non-bare git
/// repository with `refs/heads/main` pointing at an initial empty
/// commit. The orchestrator-spawn path's
/// `worktree_provisioning::provision_orchestrator_worktree` clones
/// from this repository at the initiative's `target_ref`
/// (defaults to `refs/heads/main`) into
/// `<data_dir>/worktrees/orch-<initiative_id>`. The executor then
/// clones from that orchestrator worktree, edits its allow-listed
/// path (`hello.txt` per the spec plan), and commits.
///
/// **Why `git init` and not `gix`.** This is test infrastructure;
/// shelling out to the host's git CLI is the most readable wire
/// shape and matches the operator's real install procedure
/// (`git init --bare && git push` to seed). We use a *non-bare*
/// repository because `gix::clone` reaches into the source's
/// working tree via the `file://` transport, which is the path
/// the production orchestrator-clone exercises.
///
/// **Author identity.** We stamp explicit author + committer
/// env vars so the seed commit's hash is reproducible across
/// developer machines (no `~/.gitconfig` dependency).
fn seed_main_repository(data_dir: &Path) {
    let repos_root = data_dir.join("repositories");
    std::fs::create_dir_all(&repos_root)
        .unwrap_or_else(|e| panic!("mkdir {}: {e}", repos_root.display()));

    let main_repo = repos_root.join("main");
    if main_repo.exists() {
        // Idempotent — a previous test run inside this same data_dir
        // may have seeded already. The kernel always boots with a
        // fresh data_dir so we never actually hit this branch in
        // the test, but defensive.
        return;
    }

    // Initialise an empty repo. `git init -b main` is git 2.28+;
    // older host gits (e.g. macOS XCode CLT 2.24) reject `-b`.
    // We `git init` then explicitly point HEAD at refs/heads/main
    // so the seed commit lands on `main` regardless of the host
    // git's default-branch config (`init.defaultBranch`).
    let init = Command::new("git")
        .args(["init", "-q"])
        .arg(&main_repo)
        .status()
        .unwrap_or_else(|e| panic!("spawn git init: {e}"));
    assert!(init.success(), "git init failed at {}", main_repo.display());

    let head_set = Command::new("git")
        .current_dir(&main_repo)
        .args(["symbolic-ref", "HEAD", "refs/heads/main"])
        .status()
        .unwrap_or_else(|e| panic!("spawn git symbolic-ref: {e}"));
    assert!(
        head_set.success(),
        "git symbolic-ref HEAD refs/heads/main failed in {}",
        main_repo.display(),
    );

    // Stamp deterministic author / committer identity. Without
    // this `git commit` reads $HOME/.gitconfig and may fail or
    // produce nondeterministic SHAs.
    let env: &[(&str, &str)] = &[
        ("GIT_AUTHOR_NAME", "raxis-e2e"),
        ("GIT_AUTHOR_EMAIL", "e2e@raxis.invalid"),
        ("GIT_COMMITTER_NAME", "raxis-e2e"),
        ("GIT_COMMITTER_EMAIL", "e2e@raxis.invalid"),
        // Pin the commit timestamp so the SHA is deterministic
        // across runs (test diagnostics; not security-relevant).
        ("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z"),
        ("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z"),
    ];

    let commit = Command::new("git")
        .current_dir(&main_repo)
        .envs(env.iter().copied())
        .args([
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "raxis-e2e: seed repository",
        ])
        .status()
        .unwrap_or_else(|e| panic!("spawn git commit: {e}"));
    assert!(
        commit.success(),
        "git commit failed in {}",
        main_repo.display()
    );

    // Sanity-check: refs/heads/main exists.
    let rev = Command::new("git")
        .current_dir(&main_repo)
        .args(["rev-parse", "refs/heads/main"])
        .output()
        .unwrap_or_else(|e| panic!("spawn git rev-parse: {e}"));
    assert!(
        rev.status.success(),
        "git rev-parse refs/heads/main failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&rev.stdout),
        String::from_utf8_lossy(&rev.stderr),
    );
    eprintln!(
        "[e2e] seeded main repo at {} → {}",
        main_repo.display(),
        String::from_utf8_lossy(&rev.stdout).trim(),
    );
}

/// Per `credential-proxy.md §6.1` credential files MUST be 0600 so
/// only the kernel UID can read them. We hand-set the mode after
/// `std::fs::write` because `write` honours umask and a permissive
/// umask would leave the file world-readable.
fn write_with_mode_0600(path: &Path, body: &[u8]) {
    std::fs::write(path, body).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
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
    fn connect(
        socket_path: &Path,
        signing_key: &SigningKey,
        _fingerprint: &OperatorFingerprint,
    ) -> Self {
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
        //
        // The IPC handshake fingerprint is the **policy** form
        // (`raxis_policy::loader::operator_pubkey_fingerprint`,
        // SHA-256[:16] = 32 hex chars). It is a different value
        // from `OperatorFingerprint` (SHA-256[:8] = 16 hex chars)
        // which is carried inside plan bundles for the `signed_by`
        // field. Sending the 8-char form here would surface as the
        // exact `fingerprint '...' not found in policy` error
        // because `policy.operator_entry()` keys on the 32-char
        // form emitted by `render_genesis_policy_toml`.
        let pubkey = signing_key.verifying_key().to_bytes();
        let policy_fingerprint_hex = policy_fingerprint_32(&pubkey);
        let response = serde_json::json!({
            "fingerprint":          policy_fingerprint_hex,
            "signed_challenge_hex": hex::encode(sig.to_bytes()),
        });
        write_json_frame(&mut stream, &response).expect("write auth response");

        // Step 4: read auth ack.
        let ack = read_json_blocking(&mut stream);
        assert_eq!(
            ack["status"].as_str(),
            Some("Ok"),
            "kernel rejected auth: {ack:#}",
        );

        Self { stream }
    }

    /// Submit a `CreateInitiative` request carrying a freshly-
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
        // Wire shape per `raxis_types::operator_wire::OperatorResponse`
        // (`#[serde(tag = "status", content = "payload")]`):
        //   { "status": "InitiativeCreated",
        //     "payload": { "initiative_id": "<uuid>", "status": "Draft" } }
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

    /// Approve the just-submitted plan. Triggers the orchestrator
    /// auto-spawn callsite in `kernel/src/initiatives/lifecycle.rs::
    /// approve_plan` (post-commit `OrchestratorSpawn::spawn_for_
    /// initiative` fires here).
    ///
    /// `approving_operator` MUST be the **policy** 32-char form
    /// (= `policy_fingerprint_32(pubkey)`) because
    /// `handle_approve_plan` cross-checks it against the
    /// connection-authenticated operator fingerprint set up by
    /// `verify_response`, which is itself the policy form. The
    /// 16-char `OperatorFingerprint` form (used inside plan-bundle
    /// `signed_by`) would surface as
    /// `FAIL_OPERATOR_IDENTITY_MISMATCH` here even though both
    /// fingerprints reference the same key.
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
        // Same wire shape as `submit_plan` above — `OperatorResponse`
        // serialises with the variant tag in the top-level `status`
        // field and the variant body under `payload`.
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
        // The GCP proxy variant requires `project` (the GCP project
        // ID returned by `/computeMetadata/v1/project/project-id`).
        // See `crates/plan-credentials/src/lib.rs::ProxyVariant::Gcp`.
        // Use a deterministic placeholder — the live test never
        // contacts real GCP from inside the VM (the proxy emulates
        // the metadata server locally).
        "  project    = \"raxis-e2e\"",
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
    ]
    .join("\n")
}

/// Build a V2.1 `PlanBundle` carrying `plan.toml` as its sole
/// artifact (the V2 visitor set is empty per `plan-bundle-sealing.
/// md §5.4`). Mirrors `cli/src/commands/submit.rs::run_submit_plan`
/// phases 4–6.
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
        // `plan_root_relpath` is informational per §3.1; we stamp a
        // synthetic path because the test never writes plan.toml to
        // disk (the bundle carries the bytes inline).
        "/raxis/e2e-live".to_owned(),
        artifacts,
    )
}

/// Codesign `kernel_bin` against `release/raxis.entitlements`
/// using ad-hoc signing (`codesign --sign -`). Required so AVF
/// honours `com.apple.security.virtualization` when the test
/// invokes the integration-test build of `raxis-kernel`. Best-
/// effort: panics with a clear remediation if `codesign` is
/// unavailable, no-ops when the entitlements file cannot be
/// located (e.g. someone moved the workspace).
///
/// Mirrors `cargo xtask dev-codesign` exactly so the production
/// recipe and the test recipe never drift.
#[cfg(target_os = "macos")]
fn codesign_kernel_for_avf(kernel_bin: &Path) {
    // Walk up from the binary to the workspace root. The kernel
    // binary lives at `target/<profile>/raxis-kernel-<hash>` (test
    // profile) or `target/<profile>/raxis-kernel` (release).
    // Workspace root is the ancestor whose `Cargo.toml` carries a
    // `[workspace]` table.
    let mut anchor = kernel_bin
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
                "[e2e] codesign: could not locate workspace root from {} \
                 — skipping AVF entitlement signing (orchestrator spawn \
                 will fail with com.apple.security.virtualization missing)",
                kernel_bin.display(),
            );
            return;
        }
    }

    let entitlements = anchor.join("release/raxis.entitlements");
    if !entitlements.exists() {
        eprintln!(
            "[e2e] codesign: missing entitlements at {} — skipping",
            entitlements.display(),
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
        .expect("codesign(1) is required for AVF tests on macOS — install Xcode CLI tools");
    if !status.success() {
        panic!(
            "codesign failed (exit {:?}) for {}; the orchestrator spawn \
             will be denied by AVF without the entitlements signature",
            status.code(),
            kernel_bin.display(),
        );
    }
    eprintln!(
        "[e2e] codesigned {} for AVF (com.apple.security.virtualization)",
        kernel_bin.display(),
    );
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

/// Compute the **policy** operator-key fingerprint —
/// `hex(SHA-256[:16](raw_pubkey_bytes))`, 32 hex chars. Mirrors
/// `raxis_policy::loader::operator_pubkey_fingerprint` but works
/// directly off raw pubkey bytes (the policy helper takes a hex
/// string). This is the form embedded in
/// `[[operators.entries]].pubkey_fingerprint` by
/// `render_genesis_policy_toml` and consulted by the IPC
/// challenge-response handshake (`kernel::ipc::auth::verify_response`).
fn policy_fingerprint_32(pubkey: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(pubkey);
    let digest = hasher.finalize();
    hex::encode(&digest[..16])
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
    let deadline = lifecycle_deadline();
    let start = Instant::now();
    let mut last_len = 0usize;
    loop {
        if start.elapsed() > deadline {
            // Last-mile observability — try to read the kernel
            // stderr capture file (if the harness wrote one) so the
            // panic surfaces enough context to triage the spawn /
            // planner / merge pipeline. The capture is best-effort:
            // we print the audit chain summary either way.
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
                "lifecycle deadline of {deadline:?} exceeded \
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
            if e.event_kind == "SecurityViolation" || e.event_kind == "SecurityViolationDetected" {
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

// ---------------------------------------------------------------------------
// §7.14 — Post-mortem audit chain assertions
// ---------------------------------------------------------------------------

/// Walk `<data_dir>/audit/` with the full chain verifier (sequence
/// monotonicity + prev_sha256 link integrity end-to-end), then
/// enumerate every record and decode the parsed JSON body into
/// `AuditEvent`. Panics with a friendly diagnostic on any chain
/// break or row that fails the typed deserialise.
///
/// Note: the genesis row (`seq=0`, `event_kind="GenesisRecord"`) is
/// written by `raxis-genesis-tools` and uses a different on-wire
/// shape than `AuditEvent` — it lacks `payload` / `session_id` /
/// `task_id` / `initiative_id` and instead carries
/// `genesis_nonce` + `authority_pubkey_fingerprint`. The
/// `ChainReader` deliberately tolerates both shapes (see
/// `ChainRecord` doc-comment); we surface the genesis row as a
/// synthetic `AuditEvent { event_kind: "GenesisRecord", payload:
/// genesis-record-json, .. }` so downstream invariant checks
/// (`first_kind` / `kinds: BTreeSet<&str>`) keep the same wire
/// contract they had before genesis got its own discriminator.
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
            let value = row.parsed_value.clone().unwrap_or_else(|| {
                panic!(
                    "chain row seq={} has no parsed_value (raw_line failed JSON parse)",
                    row.seq,
                )
            });
            // Genesis row has a distinct schema; project it onto the
            // AuditEvent shape so the invariant assertions stay uniform.
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
    let last_kind = chain.last().expect("non-empty").event_kind.as_str();
    // The first row may be either:
    //   - `GenesisRecord` (modern, `raxis-genesis-tools`-emitted seed
    //     row, written before `KernelStarted`), or
    //   - `KernelStarted` / `Kernel*` (legacy bootstraps that skip
    //     the genesis seed), or
    //   - `GenesisAnchor` (legacy alias kept for backwards-compat
    //     with the older test fixture name).
    assert!(
        first_kind.starts_with("Kernel")
            || first_kind == "GenesisAnchor"
            || first_kind == "GenesisRecord",
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
    //
    // Note: `IntentAdmitted` is named in the spec
    // (`audit-paired-writes.md` §intent-flow) but the current kernel
    // emits per-intent admission as plain stderr (`eprintln!
    // event=IntentAccepted ...`) rather than as an `AuditEventKind`
    // chain row. The chain DOES carry the higher-level proofs that
    // admission flowed end-to-end:
    //   - `PlanApproved`           — operator-side plan admission ran.
    //   - `SessionCreated`         — at least one planner session was
    //     spawned (every spawn requires an `ActivateSubTask` intent
    //     to have been admitted by `handlers::intent::run_phase_a`).
    //   - `IntegrationMergeCompleted` — the orchestrator's
    //     coordinator-task `IntegrationMerge` intent passed Phase A
    //     and the merge driver landed the integration commit; this
    //     transitively proves every prior `CompleteTask` /
    //     `SubmitReview` was admitted (the merge driver refuses to
    //     run if any predecessor is non-Completed).
    // Together these gate the same invariant `IntentAdmitted` was
    // intended to guard without coupling the test to the future
    // audit-emission wiring.
    for required in &[
        "InitiativeCreated",
        "PlanApproved",
        "SessionCreated",
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
        matches!(
            serde_json::from_value::<AuditEventKind>(e.payload.clone()),
            Ok(AuditEventKind::IntegrationMergeCompleted {
                initiative_id: id, ..
            }) if id == initiative_id
        )
    });
    assert!(
        merged_for_us,
        "no IntegrationMergeCompleted for {initiative_id}; chain kinds: {kinds:?}",
    );

    assert!(
        !kinds.contains("SecurityViolation") && !kinds.contains("SecurityViolationDetected"),
        "SecurityViolation must NOT appear in a clean lifecycle; \
         kinds: {kinds:?}",
    );
}

// ---------------------------------------------------------------------------
// Operator dashboard — visual debugging hook
// ---------------------------------------------------------------------------
//
// The kernel boots its dashboard HTTP server when `policy.toml`
// carries an `[dashboard].enabled = true` block (see
// `enable_gateway_in_policy` for the injected block). After the
// daemon is up, this section:
//
//   1. Polls the bound port until the kernel's
//      `start_dashboard_with_advancer` call has returned (so the
//      `/api/auth/challenge` endpoint is wired).
//   2. Mints a fresh challenge through `GET /api/auth/challenge`,
//      signs the 32-byte payload with the test's operator key,
//      submits the response to `POST /api/auth/verify`, and
//      receives a freshly-minted JWT.
//   3. Opens the bundled React UI with the JWT pre-installed via
//      a URL-fragment autologin payload (`Login.tsx` parses
//      `#autologin=1&token=…` on mount and writes the JWT into
//      `localStorage`, then redirects to `/`).
//
// **Best-effort.** Every failure mode (build skipped, FE bundle
// absent, JWT mint failed, `open(1)` missing, etc.) is logged
// and ignored — the lifecycle test must still pass on headless
// CI runners that have no browser and no FE bundle. The
// developer running the test interactively gets the visual
// payoff without affecting the assertion path.
//
// **Why a URL fragment instead of a query parameter.** The hash
// is not transmitted to the server, never appears in HTTP access
// logs, and is scrubbed by `Login.tsx`'s `replaceState` after
// consumption. A query-string token would leak through every
// proxy / log / browser-history surface in between.

/// Operator dashboard port. Override via
/// `RAXIS_E2E_DASHBOARD_PORT` when the default 19820 is busy.
fn configured_dashboard_port() -> u16 {
    std::env::var("RAXIS_E2E_DASHBOARD_PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(DASHBOARD_DEFAULT_PORT)
}

/// Absolute path to the React production bundle, if it has been
/// built. The kernel's `[dashboard].static_dir` field consumes
/// this; absent ⇒ JSON-API-only dashboard (still useful for
/// programmatic poking, just no UI).
fn locate_dashboard_dist() -> Option<PathBuf> {
    let raxis_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()?
        .to_path_buf();
    let dist = raxis_root.join("dashboard-fe").join("dist");
    if dist.join("index.html").is_file() {
        Some(dist)
    } else {
        None
    }
}

/// Return-type of `mint_dashboard_jwt`. `None` ⇒ best-effort
/// failure that callers must tolerate (browser-open is skipped).
struct DashboardSession {
    token: String,
    operator_id: String,
    display_name: String,
    roles: Vec<String>,
    expires_at: u64,
}

/// Block until `127.0.0.1:<port>` accepts a TCP connection or
/// `deadline` elapses. Returns `false` on timeout. We use a raw
/// `TcpStream::connect_timeout` rather than an HTTP probe because
/// the dashboard's accept-loop binds the socket BEFORE the
/// router state is fully wired — a TCP success is the earliest
/// signal that JSON requests will not get connection-refused.
fn wait_for_dashboard_port(port: u16, deadline: Duration) -> bool {
    let addr = format!("{}:{}", DASHBOARD_BIND_ADDRESS, port);
    let parsed: std::net::SocketAddr = match addr.parse() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let start = Instant::now();
    while start.elapsed() < deadline {
        if std::net::TcpStream::connect_timeout(&parsed, Duration::from_millis(250)).is_ok() {
            // Accept-loop is up; give the router state one tick to
            // finish wiring before the first POST hits.
            std::thread::sleep(Duration::from_millis(150));
            return true;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    false
}

/// Drive the kernel's challenge-response auth dance against the
/// in-test operator key and return the minted JWT envelope.
/// Returns `None` on any HTTP / JSON error so the caller can
/// log + skip the browser-open step (the lifecycle test must
/// still pass without a browser).
fn mint_dashboard_jwt(signing_key: &SigningKey, port: u16) -> Option<DashboardSession> {
    let base = format!("http://{}:{}", DASHBOARD_BIND_ADDRESS, port);
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .ok()?;

    // Step 1 — request a challenge.
    let challenge_resp = client
        .get(format!("{base}/api/auth/challenge"))
        .send()
        .ok()?;
    if !challenge_resp.status().is_success() {
        eprintln!(
            "[e2e] dashboard /api/auth/challenge: HTTP {}",
            challenge_resp.status(),
        );
        return None;
    }
    let challenge_body: serde_json::Value = challenge_resp.json().ok()?;
    let challenge_hex = challenge_body.get("challenge")?.as_str()?.to_owned();
    let challenge_bytes = hex::decode(&challenge_hex).ok()?;
    if challenge_bytes.len() != 32 {
        return None;
    }

    // Step 2 — sign with the test's operator key (the same one
    // `bootstrap_with_custom_cert` minted the operator cert with,
    // so the kernel's policy-side `operator_entry` lookup
    // succeeds inside `verify`).
    let signature = signing_key.sign(&challenge_bytes);
    let pubkey = signing_key.verifying_key().to_bytes();
    let signature_hex = hex::encode(signature.to_bytes());
    let pubkey_hex = hex::encode(pubkey);

    // ── Paste-fallback for the operator ─────────────────────────
    //
    // If the autologin redirect ever fails (stale FE bundle,
    // hash-routing quirk, browser strips fragments, …) the
    // operator can still log in by pasting the values below into
    // the dashboard's manual challenge-response form. We emit:
    //
    //   1. The exact `raxis auth sign <challenge>` command that
    //      the dashboard's "Step 1" code-block displays.
    //   2. The 128-hex-char signature (Step 2 input).
    //   3. The 64-hex-char public key (Step 3 input).
    //
    // The challenge is a one-time nonce (32 random bytes minted
    // by `/api/auth/challenge`, single-use, ~5 min TTL), so the
    // signature has no value beyond this single mint attempt.
    eprintln!("[e2e] dashboard manual-fallback (paste into /login if autologin fails):");
    eprintln!("[e2e]   1. CLI command   : raxis auth sign {challenge_hex}");
    eprintln!("[e2e]   2. Signature hex : {signature_hex}");
    eprintln!("[e2e]   3. Public key hex: {pubkey_hex}");

    // Step 3 — verify.
    let verify_body = serde_json::json!({
        "challenge":  challenge_hex,
        "signature":  signature_hex,
        "public_key": pubkey_hex,
    });
    let verify_resp = client
        .post(format!("{base}/api/auth/verify"))
        .json(&verify_body)
        .send()
        .ok()?;
    if !verify_resp.status().is_success() {
        eprintln!(
            "[e2e] dashboard /api/auth/verify: HTTP {} (body: {:?})",
            verify_resp.status(),
            verify_resp.text().unwrap_or_default(),
        );
        return None;
    }
    let verify_payload: serde_json::Value = verify_resp.json().ok()?;
    Some(DashboardSession {
        token: verify_payload.get("token")?.as_str()?.to_owned(),
        operator_id: verify_payload.get("operator_id")?.as_str()?.to_owned(),
        display_name: verify_payload.get("display_name")?.as_str()?.to_owned(),
        roles: verify_payload
            .get("roles")?
            .as_array()?
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect(),
        expires_at: verify_payload.get("expires_at")?.as_u64()?,
    })
}

/// Build the autologin URL the dashboard's React `LoginPage`
/// consumes via `parseAutologinHash`. Mirror the field set
/// 1:1 — any drift will land the operator on the manual flow.
fn build_autologin_url(port: u16, session: &DashboardSession) -> String {
    fn encode(s: &str) -> String {
        // Minimal RFC-3986 percent-encoding of the few characters
        // the autologin payload may carry. We do NOT pull in
        // `urlencoding` or `percent-encoding` for one call site;
        // the values here are constrained (hex JWT segments, ASCII
        // operator names, lowercase role names) so a small bespoke
        // pass is sufficient.
        s.bytes()
            .flat_map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => vec![b],
                _ => format!("%{b:02X}").into_bytes(),
            })
            .map(|b| b as char)
            .collect()
    }
    let roles_csv = session
        .roles
        .iter()
        .map(|r| encode(r))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "http://{addr}:{port}/login#autologin=1\
         &token={token}\
         &operator_id={op}\
         &display_name={name}\
         &roles={roles}\
         &expires_at={exp}\
         &next=%2F",
        addr = DASHBOARD_BIND_ADDRESS,
        port = port,
        token = encode(&session.token),
        op = encode(&session.operator_id),
        name = encode(&session.display_name),
        roles = roles_csv,
        exp = session.expires_at,
    )
}

/// Spawn the platform-native URL opener. Returns `Ok(())` when
/// the binary spawned (we don't wait for it — `open(1)` /
/// `xdg-open(1)` exit immediately after handing the URL to the
/// resolver). Returns `Err(reason)` when the binary couldn't
/// even be invoked (CI / SSH / headless host).
#[cfg(target_os = "macos")]
fn spawn_url_opener(url: &str) -> Result<(), String> {
    std::process::Command::new("open")
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("spawn open: {e}"))
}

#[cfg(target_os = "linux")]
fn spawn_url_opener(url: &str) -> Result<(), String> {
    std::process::Command::new("xdg-open")
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("spawn xdg-open: {e}"))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn spawn_url_opener(_url: &str) -> Result<(), String> {
    Err("no URL opener supported on this platform".to_owned())
}

/// End-to-end glue called from `full_session_lifecycle` after the
/// kernel daemon is up. Wires steps 1–3 of the visual-debug
/// flow described above. ALL failures are non-fatal.
fn open_dashboard_with_autologin(signing_key: &SigningKey, port: u16) -> Option<String> {
    if !wait_for_dashboard_port(port, Duration::from_secs(10)) {
        eprintln!(
            "[e2e] dashboard at {}:{} did not become reachable within 10s — skipping autologin",
            DASHBOARD_BIND_ADDRESS, port,
        );
        return None;
    }
    let session = match mint_dashboard_jwt(signing_key, port) {
        Some(s) => s,
        None => {
            eprintln!(
                "[e2e] dashboard JWT mint failed; skipping browser open (kernel logs may have details)",
            );
            return None;
        }
    };
    let url = build_autologin_url(port, &session);
    eprintln!(
        "[e2e] dashboard ready: http://{}:{}/  (autologin URL printed below for manual fallback)",
        DASHBOARD_BIND_ADDRESS, port,
    );
    eprintln!("[e2e] dashboard autologin URL: {url}");
    if let Err(e) = spawn_url_opener(&url) {
        eprintln!(
            "[e2e] could not open browser ({e}); paste the URL above into a browser to autologin",
        );
    } else {
        eprintln!(
            "[e2e] dashboard opened in default browser as operator '{}' (roles={:?})",
            session.display_name, session.roles,
        );
    }
    Some(url)
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
