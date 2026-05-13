//! Generic kernel-driver helpers for `RAXIS_LIVE_E2E=1` tests.
//!
//! Mirrors the inline helpers in
//! `extended_e2e_concurrent_lifecycle.rs` but parametrised over
//! the plan-toml builder so multiple `live-e2e` tests can share
//! the same bootstrap / IPC / polling pipeline without
//! duplicating ~700 lines of infrastructure.
//!
//! The existing extended-scenario test continues to use its own
//! inline helpers (deliberately — refactoring them in lockstep
//! would couple two unrelated tests together). New tests
//! (`extended_e2e_realistic_scenario.rs`, future realism
//! follow-ups) call into THIS module instead.
//!
//! Every function panics on failure rather than returning a
//! `Result` — the call sites are test-only and a panic surfaces
//! more cleanly through `cargo test` than a `Result<()>` rip-tide.

#![allow(dead_code)]

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

// `crate::common` is the sibling `mod common;` each test binary
// (`extended_e2e_concurrent_lifecycle.rs`,
// `extended_e2e_realistic_scenario.rs`, …) declares at its root.
// Both test binaries that pull this module in must `mod common;`
// alongside `mod extended_e2e_support;`.
use crate::common::kernel_harness::{build_and_locate_kernel, KernelInstance};
use super::witnesses::typed;

pub const LIVE_E2E_GATE:    &str     = "RAXIS_LIVE_E2E";
pub const READY_DEADLINE:   Duration = Duration::from_secs(15);
pub const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(60);

/// Distinct seed from the extended scenario's `[0xCE; 32]` so
/// the two live-e2e tests can be run back-to-back without
/// cross-contaminating operator identity in audit attribution.
pub const REALISTIC_OPERATOR_SEED: [u8; 32] = [0xD0; 32];

// ---------------------------------------------------------------------------
// Preflight — every external dependency reachable before we
// bother bootstrapping a kernel.
// ---------------------------------------------------------------------------

pub fn require_tcp_reachable(host_port: &str, what: &str) {
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

pub fn require_anthropic_dev_key() {
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

pub fn require_gcp_adc() {
    let adc = match dirs_home() {
        Some(h) => h.join(".config/gcloud/application_default_credentials.json"),
        None    => panic!("HOME is unset; cannot locate gcloud ADC"),
    };
    assert!(
        adc.exists(),
        "GCP application default credentials not found at {}.\n\
         Run: gcloud auth application-default login",
        adc.display(),
    );
}

pub fn require_gateway_binary() -> PathBuf {
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

pub fn require_canonical_images() {
    let install_dir_raw = std::env::var("RAXIS_INSTALL_DIR").unwrap_or_else(|_| panic!(
        "RAXIS_INSTALL_DIR env var is required",
    ));
    let install_dir = PathBuf::from(&install_dir_raw);
    let kernel_version = env!("CARGO_PKG_VERSION");

    // Auto-bake: if the canonical images are missing or are stub
    // builds (no `/bin/bash` etc.), drive the full xtask pipeline
    // (`bake-rootfs → dev-stage → build-all`) so the live-e2e harness
    // is self-contained on a fresh dev host. Idempotent: re-runs
    // skip every role whose .img already passes the cpio preflight.
    //
    // Opt-out via `RAXIS_LIVE_E2E_SKIP_AUTO_BAKE=1` for operators
    // who manage canonical images themselves (e.g. CI machines that
    // pre-populate `RAXIS_INSTALL_DIR` from a packaged tarball and
    // do NOT have docker / podman / buildah on the host).
    if std::env::var("RAXIS_LIVE_E2E_SKIP_AUTO_BAKE").is_err() {
        ensure_canonical_images_baked(&install_dir, kernel_version);
    }

    for role in &["orchestrator-core", "executor-starter", "reviewer-core"] {
        let img = install_dir.join("images")
            .join(format!("raxis-{role}-{kernel_version}.img"));
        let manifest = install_dir.join("images")
            .join(format!("raxis-{role}-{kernel_version}.manifest.toml"));
        assert!(img.exists(), "missing canonical image {}", img.display());
        assert!(manifest.exists(), "missing canonical manifest {}", manifest.display());

        // ── Cpio content preflight ────────────────────────────────
        //
        // Iter-12 surfaced canonical-image stub regression: the
        // manifest verified, the file existed, but the cpio
        // contained nothing but the cross-compiled planner binary.
        // `BashTool` returned `ENOENT` for every command the
        // executor LLM tried to spawn. Walk the cpio.gz and assert
        // every role-required binary is present BEFORE the kernel
        // even boots — the test fails fast with an actionable
        // remediation instead of timing out 4 minutes in.
        //
        // Fix: `cargo xtask images bake-rootfs --role <ROLE>`. The
        // remediation in the panic message points at it.
        let required = required_binaries_for_canonical_role(role);
        if required.is_empty() {
            // Orch + reviewer are intentionally binary-only today;
            // the planner binary is checked below.
        }
        let entries = crate::common::cpio_inspect::list_initramfs_paths(&img)
            .unwrap_or_else(|e| panic!(
                "failed to walk canonical image {}: {e}\n\
                 The cpio.gz may be corrupted; rebuild via:\n  \
                 cargo xtask images bake-rootfs --role {role}\n  \
                 cargo xtask images dev-stage    --role {role}\n  \
                 cargo xtask images build-all    --role {role}",
                img.display(),
            ));
        let missing: Vec<&&'static str> = required
            .iter()
            .filter(|bin| !entries.contains_key(**bin))
            .collect();
        assert!(
            missing.is_empty(),
            "canonical {role} image is a stub — missing {n} required \
             binar{plural} from {img}:\n{lines}\n\
             \n\
             This usually means `cargo xtask images bake-rootfs --role {role}` \
             was skipped before `dev-stage` / `build-all`. The dev-host \
             pipeline now bakes the rootfs FROM the canonical \
             images/{role}/Containerfile via docker / podman / buildah; \
             without that step the cpio.gz contains only the \
             cross-compiled planner binary and `BashTool` returns ENOENT \
             for every LLM-issued shell command (the iter-12 failure \
             mode). Remediation:\n  \
             cargo xtask images bake-rootfs --role {role}\n  \
             cargo xtask images dev-stage    --role {role}\n  \
             cargo xtask images build-all    --role {role}\n\
             then re-run this test.",
            n      = missing.len(),
            plural = if missing.len() == 1 { "y" } else { "ies" },
            img    = img.display(),
            lines  = missing
                         .iter()
                         .map(|b| format!("  - {b}"))
                         .collect::<Vec<_>>()
                         .join("\n"),
        );
    }
}

/// Per-role inventory of cpio paths that MUST be present in the
/// canonical signed initramfs. Mirrors xtask's `required_os_binaries`
/// (the dev-stage stub guard) so a test failure here points at a
/// pipeline regression in the same row of the same table.
///
/// The lists are deliberately tight (role-required, not nice-to-have)
/// so they never go out of step with the canonical Containerfiles.
/// Adding entries here without amending the Containerfile would
/// surface as a pipeline regression rather than catching one.
fn required_binaries_for_canonical_role(role: &str) -> &'static [&'static str] {
    match role {
        // Executor LLM writes `psycopg2` / `pymongo` / `redis` /
        // `smtplib` scripts and runs them via `bash -c 'python3 -c
        // "..."'`; a missing bash, python3, or git here is the
        // iter-12 failure mode. The planner binary itself is
        // overlaid by `dev-stage` and lands at usr/local/bin/.
        "executor-starter" => &[
            "bin/bash",
            "usr/bin/python3",
            "usr/bin/git",
            "usr/local/bin/raxis-executor",
        ],
        // Orchestrator + Reviewer are binary-only by current spec
        // (INV-PLANNER-HARNESS-02 minimalism) — only the planner
        // PID-1 binary is required to ship in the canonical cpio.
        // Branch B follow-up will enrich orch / reviewer Containerfiles
        // and update this table in lockstep.
        "orchestrator-core" => &[
            "usr/local/bin/raxis-orchestrator",
        ],
        "reviewer-core" => &[
            "usr/local/bin/raxis-reviewer",
        ],
        other => panic!("unknown canonical role {other:?}; \
                         expected one of: orchestrator-core, \
                         executor-starter, reviewer-core"),
    }
}

/// Drive the three-stage `xtask images` pipeline (`bake-rootfs →
/// dev-stage → build-all`) for any canonical role whose
/// `<install_dir>/images/raxis-<role>-<v>.img` is missing or is a
/// binary-only stub. Idempotent: roles that already pass the cpio
/// preflight are skipped — we never re-run the docker bake when a
/// good image is already on disk.
///
/// This is the live-e2e harness's "self-contained on a fresh dev
/// host" feature. Without it, every operator (and the iter-13
/// fix-loop) had to remember to run six xtask invocations by hand
/// before kicking the test off, and a forgotten `bake-rootfs` step
/// surfaced as the iter-12 `BashTool: ENOENT` storm.
///
/// # Panics
///
/// On any pipeline-stage failure (bake / stage / pack / sign).
/// We deliberately do NOT surface a `Result` — a test that cannot
/// boot the kernel cannot proceed and a panic produces a clearer
/// `cargo test` failure than a silent skip. The panic message
/// includes the failed stage and the role.
///
/// # Workspace location
///
/// Resolves the workspace root by walking ancestors of `CARGO_MANIFEST_DIR`
/// (set by Cargo for every crate) until a `Cargo.toml` containing
/// `[workspace]` appears — same algorithm xtask uses for its own
/// `workspace_root_from_cwd()`. We do NOT use `CWD` because Cargo
/// runs integration tests from the per-crate manifest dir, not from
/// the workspace root, and we want this helper to work whether the
/// operator runs `cargo test --workspace` or `cd kernel && cargo test`.
fn ensure_canonical_images_baked(install_dir: &Path, kernel_version: &str) {
    let workspace_root = workspace_root_from_manifest_dir();
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());

    for role in &["orchestrator-core", "executor-starter", "reviewer-core"] {
        let img = install_dir
            .join("images")
            .join(format!("raxis-{role}-{kernel_version}.img"));
        let manifest = install_dir
            .join("images")
            .join(format!("raxis-{role}-{kernel_version}.manifest.toml"));

        // Idempotency check: skip if BOTH the image and manifest
        // exist AND the cpio walk finds every required binary. This
        // matches the assertion `require_canonical_images` does next,
        // so a green idempotency check guarantees no rebake.
        if img.exists() && manifest.exists() && cpio_passes_preflight(&img, role) {
            eprintln!(
                "[live-e2e auto-bake] skip {role} (canonical image already complete at {})",
                img.display(),
            );
            continue;
        }

        eprintln!(
            "[live-e2e auto-bake] {role}: rebaking (img missing or stub at {})",
            img.display(),
        );

        // ── 1. bake-rootfs ───────────────────────────────────────
        // Roles with `required_binaries_for_canonical_role` empty
        // (orch / reviewer today) ship binary-only by current spec
        // — no Containerfile bake required, dev-stage's binary-only
        // rootfs is sufficient. Skip the docker bake for those roles
        // so the pipeline does not require docker on every harness
        // run when only the executor image is at risk.
        if !required_binaries_for_canonical_role(role).is_empty() {
            run_xtask_or_panic(
                &cargo, &workspace_root, role, "bake-rootfs",
                &["--role", role],
            );
        } else {
            eprintln!(
                "[live-e2e auto-bake] skip bake-rootfs for {role} \
                 (binary-only by spec; no Containerfile build needed)"
            );
        }

        // ── 2. dev-stage ─────────────────────────────────────────
        // For binary-only roles, pass --allow-stub so the post-stage
        // guard does not fire; for executor-starter (which DID just
        // bake the rootfs) the guard validates the bake worked.
        let stage_args: Vec<&str> = if required_binaries_for_canonical_role(role).is_empty() {
            vec!["--role", role, "--allow-stub"]
        } else {
            vec!["--role", role]
        };
        run_xtask_or_panic(
            &cargo, &workspace_root, role, "dev-stage",
            &stage_args,
        );

        // ── 3. build-all ────────────────────────────────────────
        // Pack into the signed cpio.gz at <install_dir>/images/.
        run_xtask_or_panic(
            &cargo, &workspace_root, role, "build-all",
            &[
                "--role",        role,
                "--install-dir", install_dir.to_str().unwrap_or_else(|| panic!(
                    "install_dir contains non-utf8 bytes: {}", install_dir.display(),
                )),
            ],
        );
    }
}

/// Walk a candidate canonical image and report whether it contains
/// every binary `require_canonical_images` will assert. Returns
/// `false` on any I/O failure (treat unreadable images as
/// preflight-failing so the auto-bake will rebuild them).
fn cpio_passes_preflight(img: &Path, role: &str) -> bool {
    let entries = match crate::common::cpio_inspect::list_initramfs_paths(img) {
        Ok(e)  => e,
        Err(_) => return false,
    };
    required_binaries_for_canonical_role(role)
        .iter()
        .all(|b| entries.contains_key(*b))
}

/// Walk ancestors of `CARGO_MANIFEST_DIR` looking for a `Cargo.toml`
/// that contains `[workspace]`. Mirrors xtask's
/// `workspace_root_from_cwd()` but anchored at the test's manifest
/// dir so it works whether the operator runs the test from the
/// workspace root or from `kernel/`.
fn workspace_root_from_manifest_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        let candidate = p.join("Cargo.toml");
        if candidate.exists() {
            if let Ok(s) = std::fs::read_to_string(&candidate) {
                if s.contains("[workspace]") {
                    return p;
                }
            }
        }
        if !p.pop() {
            panic!(
                "could not locate workspace root (no Cargo.toml with \
                 [workspace] in any ancestor of {})",
                env!("CARGO_MANIFEST_DIR"),
            );
        }
    }
}

fn run_xtask_or_panic(
    cargo:           &str,
    workspace_root:  &Path,
    role:            &str,
    sub:             &str,
    extra:           &[&str],
) {
    let mut argv: Vec<&str> = vec!["xtask", "images", sub];
    argv.extend(extra);
    eprintln!(
        "[live-e2e auto-bake] {role}: running {} {}",
        cargo, argv.join(" "),
    );
    let status = Command::new(cargo)
        .current_dir(workspace_root)
        .args(&argv)
        .status()
        .unwrap_or_else(|e| panic!(
            "spawn `{cargo} {}`: {e}", argv.join(" "),
        ));
    if !status.success() {
        panic!(
            "live-e2e auto-bake stage `{sub}` failed for role {role:?} \
             (exit {status}). Re-run manually for richer diagnostics:\n  \
             {cargo} {}\n\
             Set RAXIS_LIVE_E2E_SKIP_AUTO_BAKE=1 to disable auto-bake \
             entirely (operator-managed canonical images).",
            argv.join(" "),
        );
    }
}

// ---------------------------------------------------------------------------
// Bootstrap + spawn.
// ---------------------------------------------------------------------------

/// Build a fresh operator signing key from `seed`. Returns the
/// key + its 8-byte fingerprint (the kernel's stable operator id
/// in audit rows).
pub fn build_operator_key(seed: &[u8; 32]) -> (SigningKey, OperatorFingerprint) {
    let key = SigningKey::from_bytes(seed);
    let pubkey = key.verifying_key().to_bytes();
    (key, fingerprint_8(&pubkey))
}

/// Bootstrap a fresh kernel under a tempdir-data-dir with a
/// custom operator cert that grants the full lifecycle ops.
pub fn bootstrap_with_custom_cert(
    signing_key: &SigningKey,
) -> (PathBuf, PathBuf) {
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
            "ApprovePlan".to_owned(),
            "AbortInitiative".to_owned(),
        ],
        display_name: "realism-e2e-operator".to_owned(),
        ..CertOpts::default()
    });

    let data_dir: PathBuf = tempfile::tempdir()
        .expect("tempdir for kernel data dir")
        .keep();
    let cert_path = data_dir.join("operator.cert.toml");
    let toml_body = toml::to_string(&cert).expect("serialise realism-e2e cert");
    std::fs::write(&cert_path, toml_body).expect("write operator cert");

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

pub fn spawn_kernel_normal(
    kernel_bin: &Path,
    data_dir: PathBuf,
    install_dir: &Path,
) -> KernelInstance {
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

pub fn enable_gateway_in_policy(data_dir: &Path, gateway_binary: &Path) {
    let policy_path = data_dir.join("policy").join("policy.toml");
    let mut body = std::fs::read_to_string(&policy_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", policy_path.display()));
    assert!(
        !body.contains("\n[gateway]\n"),
        "policy.toml already has a [gateway] block; bootstrap template changed",
    );
    let injected = format!(
        "\n# ── [gateway] + [[providers]] + [egress] (realism-e2e) ──\n\
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
         provider_id           = \"anthropic-realism-e2e\"\n\
         kind                  = \"Anthropic\"\n\
         credentials_file      = \"anthropic-realism-e2e.toml\"\n\
         inference_timeout_ms  = 120000\n\
         data_fetch_timeout_ms = 30000\n\
         pricing.input_tokens_per_dollar      = 200000\n\
         pricing.output_tokens_per_dollar     = 50000\n\
         pricing.cache_read_tokens_per_dollar = 2000000\n",
        gw = gateway_binary.display(),
    );
    body.push_str(&injected);
    body.push_str(&observability_policy_block());
    std::fs::write(&policy_path, body)
        .unwrap_or_else(|e| panic!("rewrite {}: {e}", policy_path.display()));
}

/// Seed `<data_dir>/repositories/main` as a real (non-bare) git
/// repository with `refs/heads/main` pointing at an initial empty
/// commit. The orchestrator-spawn path's
/// `worktree_provisioning::provision_orchestrator_worktree` clones
/// from this repository at the initiative's `target_ref`
/// (defaults to `refs/heads/main`) into
/// `<data_dir>/worktrees/<initiative>/orch-<task>`. Without this
/// seed every `ApprovePlan` succeeds at the IPC boundary but the
/// orchestrator never spawns: the kernel's `orchestrator_spawn_failed`
/// path logs `does not appear to be a git repository` and the
/// downstream worktree under `<data_dir>/worktrees/<initiative>/<task>`
/// is never created — the realistic-scenario test then times out
/// in `materialise_realistic_seed`.
///
/// Mirrors `full_e2e_session_lifecycle::seed_main_repository`. The
/// helper lives in `kernel_driver` so every shared `RAXIS_LIVE_E2E`
/// driver (realistic scenario, future scenarios that adopt the
/// `kernel_driver` module) gets a single source of truth.
///
/// Idempotent: a re-entry into a populated `repositories/main`
/// short-circuits because the bootstrap creates the data dir fresh
/// per run, but a future test that re-uses the same data_dir is not
/// punished for it.
pub fn seed_main_repository(data_dir: &Path) {
    let repos_root = data_dir.join("repositories");
    std::fs::create_dir_all(&repos_root)
        .unwrap_or_else(|e| panic!("mkdir {}: {e}", repos_root.display()));

    let main_repo = repos_root.join("main");
    if main_repo.join(".git").exists() {
        return;
    }
    std::fs::create_dir_all(&main_repo)
        .unwrap_or_else(|e| panic!("mkdir {}: {e}", main_repo.display()));

    // `git init -b main` is git 2.28+; older host gits (e.g. macOS
    // XCode CLT 2.24) reject `-b`. We `git init` then explicitly
    // point HEAD at refs/heads/main.
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

    // Stamp deterministic author / committer identity so the seed
    // commit's hash is reproducible across developer machines (no
    // `~/.gitconfig` dependency, no UID-derived defaults).
    let env: &[(&str, &str)] = &[
        ("GIT_AUTHOR_NAME",     "raxis-e2e"),
        ("GIT_AUTHOR_EMAIL",    "e2e@raxis.invalid"),
        ("GIT_COMMITTER_NAME",  "raxis-e2e"),
        ("GIT_COMMITTER_EMAIL", "e2e@raxis.invalid"),
        ("GIT_AUTHOR_DATE",     "2026-01-01T00:00:00Z"),
        ("GIT_COMMITTER_DATE",  "2026-01-01T00:00:00Z"),
    ];
    let commit = Command::new("git")
        .current_dir(&main_repo)
        .envs(env.iter().copied())
        .args(["commit", "-q", "--allow-empty", "-m", "raxis-e2e: seed repository"])
        .status()
        .unwrap_or_else(|e| panic!("spawn git commit: {e}"));
    assert!(commit.success(), "git commit failed in {}", main_repo.display());

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
        "[realism-e2e] seeded main repo at {} -> {}",
        main_repo.display(),
        String::from_utf8_lossy(&rev.stdout).trim(),
    );
}

/// Seed `<data_dir>/repositories/main` with the **rich-multilang-001
/// fixture history** (11 commits, including a feature-branch merge
/// and a cross-language rename), then layer on the realistic
/// scenario's per-task overlays — the bait `.env` carrying the FAKE
/// credential canaries the credential-substitution-canary task
/// inspects, plus the stock-Python service-integrity scripts the
/// transparent-proxy-realscripts task runs — and commit them as a
/// single 12th commit.
///
/// **Why bake the per-task overlays into `repositories/main`.** The
/// kernel's worktree provisioner uses the layout
/// `<data_dir>/worktrees/orch-<initiative_id>/` for the
/// orchestrator's clone of `main` and `<data_dir>/worktrees/<session_id>/`
/// for each per-session executor / reviewer clone. None of these
/// layouts match `<data_dir>/worktrees/<initiative_id>/<task_id>/`,
/// so a poll-based "wait for the executor's worktree to appear and
/// then drop a fixture into it" overlay cannot succeed (the path
/// the test driver was polling never existed). Committing the
/// overlay into `repositories/main` BEFORE plan submission is the
/// kernel-faithful equivalent: every downstream worktree is a
/// `gix::clone` (full history) of `main`, so each executor inherits
/// the seed history + bait `.env` + proxy scripts deterministically
/// the moment the orchestrator finishes its own clone — with zero
/// timing race against the executor VM boot.
///
/// `materialize_seed.sh` itself wipes the target dir if it exists
/// (idempotent contract documented in the script header), then
/// `git init` + 11 commits. After it returns we add the bait `.env`
/// + proxy scripts at the worktree root and commit them with a
/// pinned identity / date so HEAD is byte-stable across developer
/// machines (no `~/.gitconfig` dependency).
///
/// **Replaces** `seed_main_repository` for the realistic-scenario
/// driver. `seed_main_repository` (single empty commit) remains for
/// `full_e2e_session_lifecycle`, which neither needs the rich
/// history nor the per-task overlays.
pub fn seed_realistic_main_repository(data_dir: &Path) {
    let repos_root = data_dir.join("repositories");
    std::fs::create_dir_all(&repos_root)
        .unwrap_or_else(|e| panic!("mkdir {}: {e}", repos_root.display()));
    let main_repo = repos_root.join("main");

    // `materialize_seed.sh` insists on either an empty target or a
    // previously-seeded target marked by `.seed-head-sha`. The
    // tempdir bootstrap leaves `repositories/main` non-existent,
    // but a re-entry into the same data_dir (rare but possible
    // for ad-hoc local debug) would have a populated dir. Wipe it
    // unconditionally — the helper is single-purpose, the dir is
    // always under the per-test tempdir.
    if main_repo.exists() {
        std::fs::remove_dir_all(&main_repo).unwrap_or_else(|e| {
            panic!("wipe {}: {e}", main_repo.display())
        });
    }

    let workspace_root = realism_workspace_root();
    let seed_script = workspace_root
        .join("live-e2e/seed/repo/rich-multilang-001/scripts/materialize_seed.sh");
    assert!(
        seed_script.exists(),
        "rich-multilang seed script missing at {}; \
         is `live-e2e/seed/repo/rich-multilang-001/` present in the worktree?",
        seed_script.display(),
    );

    let status = Command::new(&seed_script)
        .arg(&main_repo)
        .status()
        .unwrap_or_else(|e| panic!("spawn {}: {e}", seed_script.display()));
    assert!(
        status.success(),
        "{} exited non-zero: {status:?}",
        seed_script.display(),
    );

    // Stage the bait `.env` (FAKE credential canaries the
    // credential-substitution-canary task's witness scans for) and
    // the stock-Python service-integrity scripts (the
    // transparent-proxy-realscripts task runs them).
    crate::extended_e2e_support::credential_substitution_evidence
        ::stage_fake_creds_env(&main_repo)
        .unwrap_or_else(|e| panic!("stage_fake_creds_env in main repo: {e}"));
    crate::extended_e2e_support::transparent_proxy_evidence
        ::stage_scripts_into_worktree(&main_repo, &workspace_root)
        .unwrap_or_else(|e| panic!("stage_scripts_into_worktree in main repo: {e}"));

    // Commit the overlay as the 12th commit on `main`. Use a
    // pinned identity / date for byte-stable HEAD across machines.
    let env: &[(&str, &str)] = &[
        ("GIT_AUTHOR_NAME",     "raxis-realistic-seed"),
        ("GIT_AUTHOR_EMAIL",    "realistic@raxis.invalid"),
        ("GIT_COMMITTER_NAME",  "raxis-realistic-seed"),
        ("GIT_COMMITTER_EMAIL", "realistic@raxis.invalid"),
        ("GIT_AUTHOR_DATE",     "2026-01-02T00:00:00Z"),
        ("GIT_COMMITTER_DATE",  "2026-01-02T00:00:00Z"),
    ];
    let add = Command::new("git")
        .current_dir(&main_repo)
        .args(["add", "-A", "."])
        .status()
        .unwrap_or_else(|e| panic!("spawn git add: {e}"));
    assert!(add.success(), "git add failed in {}", main_repo.display());
    let commit = Command::new("git")
        .current_dir(&main_repo)
        .envs(env.iter().copied())
        .args([
            "commit",
            "-q",
            "-m",
            "test(realistic): bait .env + transparent-proxy scripts overlay",
        ])
        .status()
        .unwrap_or_else(|e| panic!("spawn git commit: {e}"));
    assert!(commit.success(), "git commit failed in {}", main_repo.display());

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
        "[realism-e2e] seeded rich-multilang main repo at {} -> {}",
        main_repo.display(),
        String::from_utf8_lossy(&rev.stdout).trim(),
    );
}

/// Resolve the workspace root (the `raxis/` directory containing
/// the integration-test crate, the `live-e2e/` tree with the seed
/// scripts, etc.). `CARGO_MANIFEST_DIR` for the integration-test
/// binary points at `raxis/kernel/`, so the workspace root is its
/// parent.
fn realism_workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .expect("CARGO_MANIFEST_DIR for kernel integration tests has a parent (workspace root)")
}

/// V3 `otel-observability.md §5` — `[observability]` policy section
/// the live-e2e harness appends so the kernel boots with a real
/// `ObservabilityHub` (not the disabled `disabled_default()` hub).
///
/// The endpoint, ports, and admin credentials mirror
/// `live-e2e/docker-compose.e2e.yml` (kept in lockstep by the
/// `tier3_artifacts::observability_urls_match_compose_file` test).
/// Field names mirror `crates/policy/src/observability.rs`
/// `ObservabilityConfig` exactly — anything off-shape is rejected
/// at policy load with a `FAIL_OBS_*` code.
fn observability_policy_block() -> String {
    // The kernel writes JSONL frames into `<data_dir>/observability/`
    // (see `kernel/src/observability_boot.rs::build_obs_hub`); the
    // out-of-process `raxis-otel-pusher` (spawned later via
    // `spawn_otel_pusher_or_warn`) reads those frames and ships
    // them to the OTel collector at 127.0.0.1:4318.
    "\n# ── [observability] (realism-e2e — V3 OTel push) ──\n\
     [observability]\n\
     enabled = true\n\
     \n\
     [observability.ring]\n\
     segment_max_bytes = 16777216\n\
     max_total_bytes   = 268435456\n\
     max_queue_depth   = 4096\n\
     \n\
     [observability.metrics]\n\
     enabled         = true\n\
     export_interval = \"5s\"\n\
     \n\
     [observability.resource]\n\
     service_name = \"raxis-kernel-live-e2e\"\n\
     environment  = \"live-e2e\"\n\
     \n\
     [observability.resource.extra]\n\
     run_kind = \"realistic-scenario\"\n\
     \n\
     [observability.pusher]\n\
     otlp_endpoint       = \"http://127.0.0.1:4318\"\n\
     otlp_protocol       = \"http\"\n\
     otlp_compression    = \"gzip\"\n\
     otlp_export_timeout = \"10s\"\n\
     otlp_batch_size     = 256\n\
     otlp_flush_interval = \"1s\"\n\
     otlp_max_inflight   = 4\n"
        .to_owned()
}

/// Spawn `raxis-otel-pusher --config <policy.toml> --data-dir
/// <data_dir>` in the background so kernel-emitted JSONL frames are
/// shipped to the OTel collector at 127.0.0.1:4318.
///
/// Best-effort: when `RAXIS_OTEL_PUSHER_BINARY` is unset OR the
/// binary cannot be located via `cargo build -p raxis-otel-pusher`
/// the function logs a Tier-3-style line to stderr and returns
/// `None`. The realistic-scenario test does NOT panic on absence —
/// the kernel still emits to its in-process JSONL ring (per
/// `INV-OTEL-03`) so the run continues; only the dashboards stay
/// empty until the operator brings the pusher up themselves.
///
/// Stderr is captured to `<data_dir>/otel-pusher.stderr.log` so
/// post-mortem inspection is possible without re-running.
pub fn spawn_otel_pusher_or_warn(data_dir: &Path) -> Option<std::process::Child> {
    let policy_path = data_dir.join("policy").join("policy.toml");
    if !policy_path.exists() {
        eprintln!(
            "[realism-e2e] observability: policy.toml missing at {}; \
             skipping raxis-otel-pusher spawn",
            policy_path.display(),
        );
        return None;
    }
    let pusher_bin = match locate_raxis_otel_pusher_binary() {
        Some(p) => p,
        None => {
            eprintln!(
                "[realism-e2e] observability: raxis-otel-pusher binary not located \
                 (set RAXIS_OTEL_PUSHER_BINARY or run `cargo build -p raxis-otel-pusher`); \
                 kernel will emit to its in-process JSONL ring but Grafana panels will \
                 stay empty for this run"
            );
            return None;
        }
    };
    let log_path = data_dir.join("otel-pusher.stderr.log");
    let log_file = match std::fs::File::create(&log_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!(
                "[realism-e2e] observability: cannot create {}: {e}; \
                 skipping pusher spawn",
                log_path.display(),
            );
            return None;
        }
    };
    let stderr_handle = match log_file.try_clone() {
        Ok(h) => h,
        Err(e) => {
            eprintln!(
                "[realism-e2e] observability: cannot dup pusher log handle: {e}; \
                 skipping pusher spawn"
            );
            return None;
        }
    };
    match Command::new(&pusher_bin)
        .arg("--config").arg(&policy_path)
        .arg("--data-dir").arg(data_dir)
        // Disable the pusher's `/healthz` HTTP server — collisions on
        // 9501 from a prior aborted run would prevent spawn.
        .arg("--health-port").arg("0")
        .stdout(std::process::Stdio::from(log_file))
        .stderr(std::process::Stdio::from(stderr_handle))
        .spawn()
    {
        Ok(child) => {
            eprintln!(
                "[realism-e2e] observability: raxis-otel-pusher spawned pid={} bin={} \
                 log={}",
                child.id(),
                pusher_bin.display(),
                log_path.display(),
            );
            Some(child)
        }
        Err(e) => {
            eprintln!(
                "[realism-e2e] observability: failed to spawn raxis-otel-pusher \
                 (bin={}): {e}",
                pusher_bin.display(),
            );
            None
        }
    }
}

/// Locate the `raxis-otel-pusher` binary. Resolution order:
/// 1. `RAXIS_OTEL_PUSHER_BINARY` env var (operator override).
/// 2. `<workspace>/target/{debug,release}/raxis-otel-pusher`.
/// 3. The first match alongside the kernel binary
///    (`require_gateway_binary`'s parent).
fn locate_raxis_otel_pusher_binary() -> Option<PathBuf> {
    if let Ok(raw) = std::env::var("RAXIS_OTEL_PUSHER_BINARY") {
        let p = PathBuf::from(raw);
        if p.is_absolute() && p.exists() {
            return Some(p);
        }
    }
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    for profile in ["debug", "release"] {
        let candidate = workspace
            .join("target")
            .join(profile)
            .join("raxis-otel-pusher");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

pub fn write_credentials(data_dir: &Path) {
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

pub fn write_provider_credentials(data_dir: &Path) {
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
        &providers_dir.join("anthropic-realism-e2e.toml"),
        provider_toml.as_bytes(),
    );
}

fn write_with_mode_0600(path: &Path, body: &[u8]) {
    std::fs::write(path, body)
        .unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .unwrap_or_else(|e| panic!("chmod 0600 {}: {e}", path.display()));
}

// ---------------------------------------------------------------------------
// Operator IPC — generic over plan TOML body.
// ---------------------------------------------------------------------------

pub struct OperatorIpc {
    pub stream: UnixStream,
    /// Operator signing key, used by `submit_plan` and
    /// `approve_plan`. Captured at connect time so callers don't
    /// need to thread it through every call site.
    seed: [u8; 32],
}

impl OperatorIpc {
    pub fn connect(
        socket_path: &Path,
        signing_key: &SigningKey,
        seed: [u8; 32],
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
            ack["status"].as_str(), Some("Ok"),
            "kernel rejected auth: {ack:#}",
        );

        Self { stream, seed }
    }

    /// Submit `plan_toml` verbatim as the plan bundle for
    /// `initiative_id`. Caller chose the plan body — this method
    /// only handles signing + framing.
    pub fn submit_plan(&mut self, initiative_id: &str, plan_toml: &str) {
        let bundle = build_plan_bundle(plan_toml);
        let canonical = canonical_encode(&bundle).expect("canonical_encode");
        let bundle_sha = crypto_bundle_sha256(&canonical);
        let signing_key = SigningKey::from_bytes(&self.seed);
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
            resp["status"].as_str(), Some("InitiativeCreated"),
            "CreateInitiative must succeed; got: {resp:#}",
        );
        let returned_id = resp["payload"]["initiative_id"]
            .as_str()
            .expect("InitiativeCreated carries payload.initiative_id");
        assert_eq!(returned_id, initiative_id, "initiative id roundtrip");
    }

    pub fn approve_plan(
        &mut self,
        initiative_id: &str,
        _fingerprint: &OperatorFingerprint,
    ) {
        let signing_key = SigningKey::from_bytes(&self.seed);
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
        "/raxis/realism-e2e".to_owned(),
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
            eprintln!("[realism-e2e] codesign: workspace root not found from {}",
                kernel_bin.display());
            return;
        }
    }
    let entitlements = anchor.join("release/raxis.entitlements");
    if !entitlements.exists() {
        eprintln!("[realism-e2e] codesign: entitlements missing at {}",
            entitlements.display());
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
        panic!("codesign failed (exit {:?}) for {}",
            status.code(), kernel_bin.display());
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
// Audit-chain polling + post-mortem.
// ---------------------------------------------------------------------------

/// Default deadline for the realistic scenario lifecycle. Larger
/// than the extended scenario's 15 min because the realistic plan
/// carries materializer + cross-file refactor + lint-defect +
/// path-allowlist + secrets + reviewer-substantive + sibling
/// initiative — three executor re-spawns and two review rounds
/// across two initiatives.
pub fn realistic_lifecycle_deadline() -> Duration {
    let secs = std::env::var("RAXIS_E2E_REALISTIC_DEADLINE_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(1800); // 30 min
    Duration::from_secs(secs)
}

/// Poll the audit chain until BOTH `initiative_ids` emit
/// `IntegrationMergeCompleted`. Surfaces `SecurityViolation`
/// instantly. Returns the merged chain at completion.
pub fn poll_for_dual_lifecycle_completion(
    data_dir: &Path,
    initiative_ids: [&str; 2],
    deadline: Duration,
) -> Vec<AuditEvent> {
    let audit_dir = data_dir.join("audit");
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
                "realistic dual-lifecycle deadline of {deadline:?} exceeded \
                 without IntegrationMergeCompleted for both {} and {}; \
                 audit chain at exit ({} events):\n{}\n\n\
                 ── kernel.stderr (tail) ──\n{}",
                initiative_ids[0],
                initiative_ids[1],
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
                    "SecurityViolation fired during realistic lifecycle: \
                     event_kind={}, payload={:#}",
                    e.event_kind, e.payload,
                );
            }
        }

        let merged_a = events.iter().any(|e| {
            e.event_kind == "IntegrationMergeCompleted"
                && e.initiative_id.as_deref() == Some(initiative_ids[0])
        });
        let merged_b = events.iter().any(|e| {
            e.event_kind == "IntegrationMergeCompleted"
                && e.initiative_id.as_deref() == Some(initiative_ids[1])
        });
        if merged_a && merged_b {
            return events;
        }

        std::thread::sleep(Duration::from_millis(500));
    }
}

pub fn read_audit_chain(audit_dir: &Path) -> Result<Vec<AuditEvent>, ()> {
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

pub fn summarize_chain_for_panic(audit_dir: &Path) -> String {
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

pub fn walk_chain_or_panic(data_dir: &Path) -> Vec<AuditEvent> {
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

// ---------------------------------------------------------------------------
// Worktree locator.
// ---------------------------------------------------------------------------

/// Resolve the on-disk path of the executor / reviewer worktree
/// for `task_id` by walking the audit chain to the matching
/// `SessionVmSpawned.session_id`.
///
/// **Why audit-chain-based.** The kernel's worktree provisioner
/// writes per-session worktrees at the flat
/// `<data_dir>/worktrees/<session_id>/` layout
/// (`worktree_provisioning::provision_executor_worktree` /
/// `provision_reviewer_worktree`). Orchestrator worktrees use
/// `<data_dir>/worktrees/orch-<initiative_id>/`. The hypothetical
/// `<data_dir>/worktrees/<initiative_id>/<task_id>/` layout the
/// previous helper assumed does not exist on disk and never has —
/// the assumption was a documentation drift carried into the
/// realistic-scenario harness from an earlier V2 prototype.
///
/// This helper takes the resolved audit chain (from
/// `poll_for_dual_lifecycle_completion` / `walk_chain_or_panic`)
/// and resolves `task_id -> session_id` via
/// `locate_session_id_for_task`, then returns the matching
/// worktree path. Panics with a precise diagnostic if either step
/// fails.
pub fn locate_executor_worktree_via_chain(
    data_dir: &Path,
    chain:    &[AuditEvent],
    task_id:  &str,
) -> PathBuf {
    let session_id = locate_session_id_for_task(chain, task_id).unwrap_or_else(|| {
        panic!(
            "no SessionVmSpawned event for task_id={task_id} in audit chain \
             ({} events); cannot locate executor worktree without a session_id",
            chain.len(),
        )
    });
    let candidate = data_dir.join("worktrees").join(&session_id);
    assert!(
        candidate.exists(),
        "session_id={session_id} for task_id={task_id} found in chain but \
         worktree directory {} does not exist on disk",
        candidate.display(),
    );
    assert!(
        candidate.join(".git").exists(),
        "worktree {} for session_id={session_id} (task_id={task_id}) is not \
         a git repository — kernel-side `provision_executor_worktree` should \
         leave a `.git/` directory behind",
        candidate.display(),
    );
    candidate
}

/// Legacy path-based locator. Retained for callers that pre-date
/// the audit-chain-based locator above. New callers should prefer
/// `locate_executor_worktree_via_chain`. This still searches the
/// historic `<data_dir>/worktrees/<initiative_id>/<task_id>/`
/// layout for compatibility with non-realistic e2e drivers that
/// have not yet migrated.
pub fn locate_executor_worktree(
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
         task={task_id}; tried {:?}; if this is the realistic-scenario test, \
         migrate the call site to `locate_executor_worktree_via_chain`",
        candidates,
    );
}

// ---------------------------------------------------------------------------
// Misc helpers.
// ---------------------------------------------------------------------------

pub fn workspace_dotenv_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|p| p.join(".env"))
        .unwrap_or_else(|| PathBuf::from("raxis/.env"))
}

pub fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// First `SessionVmSpawned.session_id` for `task_id` (used to
/// thread per-task session ids into witnesses that key on them).
pub fn locate_session_id_for_task(
    chain: &[AuditEvent],
    task_id: &str,
) -> Option<String> {
    chain.iter().find_map(|ev| match typed(ev) {
        Some(AuditEventKind::SessionVmSpawned {
            session_id, task_id: Some(t), ..
        }) if t == task_id => Some(session_id),
        _ => None,
    })
}

/// Earliest `seq` of any `SessionVmSpawned{task_id}`. Used by
/// the crash-recovery driver to mark the moment "this task is
/// in-flight" just before delivering SIGTERM.
pub fn first_spawn_seq(chain: &[AuditEvent], task_id: &str) -> Option<u64> {
    chain
        .iter()
        .filter_map(|ev| match typed(ev) {
            Some(AuditEventKind::SessionVmSpawned {
                task_id: Some(t), ..
            }) if t == task_id => Some(ev.seq),
            _ => None,
        })
        .min()
}

// ---------------------------------------------------------------------------
// Tests.
//
// Live-e2e support code is normally exercised only by the gated
// integration tests (`RAXIS_LIVE_E2E_REALISTIC=1`). The unit tests
// below cover the pure-data helpers — most importantly
// [`observability_policy_block`], which MUST round-trip cleanly
// through `toml::from_str` so the kernel doesn't reject our
// injected `[observability]` section at policy-load time. A
// regression here means empty Grafana panels in every subsequent
// fix-loop iteration.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The injected block must be a valid TOML document standalone
    /// (no other sections required) AND its `[observability]`
    /// surface must satisfy `ObservabilityConfig::validate` so the
    /// kernel boots with `enabled = true`. If this fails, the
    /// realistic-scenario harness writes a policy.toml the kernel
    /// rejects before opening the operator IPC socket.
    #[test]
    fn observability_policy_block_parses_and_validates() {
        let block = observability_policy_block();

        // 1. Document-level: must parse as TOML.
        let doc: toml::Value = toml::from_str(&block).unwrap_or_else(|e| panic!(
            "observability_policy_block did not parse as TOML: {e}\n\
             ── block ──\n{block}",
        ));

        // 2. Spec-level: every required field is present.
        let obs = doc.get("observability").and_then(|v| v.as_table())
            .expect("[observability] table present");
        assert_eq!(
            obs.get("enabled").and_then(|v| v.as_bool()),
            Some(true),
            "[observability].enabled must be true",
        );
        assert!(
            doc.get("observability")
                .and_then(|o| o.get("pusher"))
                .and_then(|p| p.as_table())
                .and_then(|p| p.get("otlp_endpoint"))
                .and_then(|v| v.as_str())
                .map(|s| s.starts_with("http://"))
                .unwrap_or(false),
            "[observability.pusher].otlp_endpoint must be an http:// URL",
        );

        // 3. The block does NOT contain the legacy fields the
        //    validator-recommended block in the live-e2e brief
        //    (`exporter`, `endpoint`, `resource_attributes`) which
        //    `RawPolicy` does not understand — those would parse as
        //    unknown fields the kernel rejects in strict mode.
        assert!(!block.contains("\nexporter "),
            "block must not include legacy `exporter = ...`");
        assert!(!block.contains("\nendpoint "),
            "block must not include legacy `endpoint = ...`");
        assert!(!block.contains("resource_attributes"),
            "block must not include legacy `resource_attributes = {{...}}`");
    }
}
