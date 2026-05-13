//! `vm-capabilities` slice — drive the real
//! `raxis_planner_core::vm_capabilities` probe against this live
//! Linux process and assert the structural invariants pinned by
//! `INV-EXEC-DISCOVERY-01`.
//!
//! ## What this slice proves end-to-end against real bytes
//!
//!   1. The **in-guest probe** (`probe_capabilities`) runs against
//!      a real PATH walk + real `--version` subprocesses + real
//!      `dist-info` reads on a real Linux filesystem (NOT the
//!      mocked-env unit-test harness). On any reasonable Linux
//!      host the probe returns a manifest with at least `bash` on
//!      PATH, a populated `filesystem.workdir`, and an `image_role`
//!      of `Executor` (the slice stamps `RAXIS_PLANNER_ROLE` to
//!      simulate kernel-side spawn metadata).
//!
//!   2. The **kernel-private redaction** predicate
//!      (`is_kernel_private_env`) holds against a real
//!      `std::env::vars()` enumeration: the slice writes a sentinel
//!      payload (`live-e2e-loopback-plan-payload-MUST-NOT-LEAK`)
//!      into `RAXIS_VSOCK_LOOPBACK_PLAN`, into `RAXIS_SESSION_TOKEN`,
//!      and into `RAXIS_PLANNER_SIDECAR_HMAC_SECRET`, then asserts
//!      neither the env keys NOR the sentinel value byte sequence
//!      appears anywhere in the serialised manifest. Negative test
//!      for `INV-EXEC-DISCOVERY-01`'s redaction clause.
//!
//!   3. The **credential-proxy URL passthrough** holds against the
//!      same enumeration: stamping `DATABASE_URL`, `MONGO_URL`,
//!      `REDIS_URL`, and `SMTP_URL` to canonical loopback URLs
//!      makes them surface in `manifest.env` verbatim. The LLM
//!      needs these to write scripts that connect through the
//!      proxies; redacting them would break the whole architecture.
//!
//!   4. The **system-prompt hint** (`build_capability_hint`)
//!      produces a coherent string: contains the `## VM Environment`
//!      header, the `Image:` line, the `No outbound network`
//!      warning, and the credential-proxy env-var NAMES (never
//!      their values — the hint is a name-only summary so the
//!      provider's prompt cache is value-stable). Same probe
//!      backs both surfaces, so this also pins the byte-coherence
//!      property the invariant requires for prompt caching.
//!
//!   5. The **canonical Python DB-client subset** assertion
//!      (`psycopg2-binary` / `pymongo` / `redis` / `PyMySQL` /
//!      `pymssql`) is **opt-in**, gated on
//!      `RAXIS_LIVE_CANONICAL_EXECUTOR_IMAGE=1`. The five
//!      packages are a property of the canonical
//!      `raxis-executor-starter` image only (`planner-harness.md
//!      §10.6`) — a generic CI host without those `pip install`s
//!      done would fail the assertion. CI jobs that wire the
//!      canonical image (or a Docker container that mirrors its
//!      pip surface) flip the env var on; everyone else gets
//!      structural assertions only. Pattern follows the existing
//!      `_real_endpoint` slices' opt-in shape.
//!
//! ## Why a live-e2e binary, not a `cargo test` integration test
//!
//! `INV-EXEC-DISCOVERY-01` requires the manifest to be
//! deterministic for a given `(image, env)` pair. A `cargo test`
//! integration test cannot provide a stable image dimension —
//! every developer's host has a different binary set. The live-e2e
//! slice instead asserts the *invariants that hold across every
//! Linux host* (binaries non-empty, redaction holds, proxy URLs
//! pass through, hint coherent), and gates the image-specific
//! package-list assertion behind an explicit opt-in env var so
//! canonical-image CI can flip it on without forcing every
//! developer to install the canonical pip set.

use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use raxis_planner_core::{
    build_capability_hint, is_kernel_private_env, probe_capabilities, ImageRole,
};

/// Sentinel payload stamped into kernel-private env vars. The slice
/// asserts this byte sequence does NOT appear in the serialised
/// manifest (negative redaction test). Includes both ASCII and a
/// non-ASCII `█` so a naïve `to_string` substring search catches a
/// regression that double-encodes Unicode.
const KERNEL_PRIVATE_SENTINEL: &str =
    "live-e2e-loopback-plan-payload-MUST-NOT-LEAK-█";

/// Env vars the slice mutates on the live process. Recorded so the
/// epilogue can restore the host environment when the slice runs
/// alongside other slices via the `all` subcommand.
const STAGED_KEYS: &[&str] = &[
    "RAXIS_VSOCK_LOOPBACK_PLAN",
    "RAXIS_SESSION_TOKEN",
    "RAXIS_PLANNER_SIDECAR_HMAC_SECRET",
    "RAXIS_PLANNER_KSB",
    "RAXIS_PLANNER_TASK_PROMPT",
    "ANTHROPIC_API_KEY",
    "GITHUB_TOKEN",
    "POSTGRES_PASSWORD",
    "DATABASE_URL",
    "MONGO_URL",
    "REDIS_URL",
    "SMTP_URL",
    "RAXIS_PLANNER_ROLE",
    "RAXIS_VM_IMAGE_DIGEST",
];

pub async fn run() -> Result<()> {
    tracing::info!("slice vm-capabilities: starting");

    // Stage env on the live process. `probe_env` (and therefore
    // `probe_capabilities`) reads from `std::env::vars()` directly
    // — the closure only OVERRIDES already-collected names, it
    // doesn't seed new ones — so the slice MUST mutate the live
    // process env to assert against the credential-proxy / kernel-
    // private staging shape an in-VM session would see. We capture
    // and restore the prior values so the slice composes cleanly
    // with other slices in the `all` subcommand.
    let saved: Vec<(String, Option<String>)> = STAGED_KEYS
        .iter()
        .map(|k| ((*k).to_owned(), std::env::var(*k).ok()))
        .collect();

    // SAFETY: `set_var` is unsound when other threads call
    // libc::getenv concurrently. The live-e2e binary is the same
    // process the rest of the slices already mutate via
    // `set_var("RAXIS_TEST_HARNESS", "1")` (see
    // `slice_session_spawn`); slices are run serially from
    // `tokio::main`'s top-level `match`, no concurrent reader
    // exists during this window.
    unsafe {
        for k in [
            "RAXIS_VSOCK_LOOPBACK_PLAN",
            "RAXIS_SESSION_TOKEN",
            "RAXIS_PLANNER_SIDECAR_HMAC_SECRET",
            "RAXIS_PLANNER_KSB",
            "RAXIS_PLANNER_TASK_PROMPT",
        ] {
            std::env::set_var(k, KERNEL_PRIVATE_SENTINEL);
        }
        std::env::set_var(
            "ANTHROPIC_API_KEY",
            format!("api-key-{KERNEL_PRIVATE_SENTINEL}"),
        );
        std::env::set_var(
            "GITHUB_TOKEN",
            format!("github-token-{KERNEL_PRIVATE_SENTINEL}"),
        );
        std::env::set_var(
            "POSTGRES_PASSWORD",
            format!("pg-pwd-{KERNEL_PRIVATE_SENTINEL}"),
        );
        std::env::set_var(
            "DATABASE_URL",
            "postgres://raxis@127.0.0.1:54121/livee2e",
        );
        std::env::set_var(
            "MONGO_URL",
            "mongodb://127.0.0.1:54122/livee2e",
        );
        std::env::set_var("REDIS_URL", "redis://127.0.0.1:54123/0");
        std::env::set_var("SMTP_URL", "smtp://127.0.0.1:54124");
        std::env::set_var("RAXIS_PLANNER_ROLE", "executor");
        std::env::set_var(
            "RAXIS_VM_IMAGE_DIGEST",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        );
    }

    // ── Stage cwd. Real probe reads this for `filesystem.workdir`,
    //    `git_initialized`, `head_commit`. Use a tempdir without git
    //    init so the assertion is host-stable.
    let staged_cwd = std::env::temp_dir().join(format!(
        "raxis-live-e2e-vm-caps-{}",
        std::process::id()
    ));
    if !staged_cwd.exists() {
        std::fs::create_dir_all(&staged_cwd)
            .with_context(|| format!("create staged cwd {}", staged_cwd.display()))?;
    }

    // Run the real probe. Closure reads from the live process env.
    let env_reader = |k: &str| std::env::var(k).ok();
    let manifest = probe_capabilities(&env_reader, &staged_cwd);

    let assertion_outcome = run_assertions(&manifest, &staged_cwd);

    // ── Cleanup the staged cwd + restore the env regardless of
    //    whether the assertions passed or not.
    let _ = std::fs::remove_dir_all(&staged_cwd);
    // SAFETY: same as above — we are still single-threaded with
    // respect to env mutation.
    unsafe {
        for (k, prior) in saved {
            match prior {
                Some(v) => std::env::set_var(&k, v),
                None    => std::env::remove_var(&k),
            }
        }
    }

    assertion_outcome?;
    tracing::info!("slice vm-capabilities: PASSED");
    Ok(())
}

fn run_assertions(
    manifest:   &raxis_planner_core::CapabilityManifest,
    staged_cwd: &Path,
) -> Result<()> {

    // ── Assertion 1: image_role + image_digest reflect the kernel
    //    spawn metadata.
    if manifest.image_role != ImageRole::Executor {
        bail!(
            "INV-EXEC-DISCOVERY-01: image_role MUST be Executor when \
             RAXIS_PLANNER_ROLE=executor; got {:?}",
            manifest.image_role,
        );
    }
    let digest = manifest
        .image_digest
        .as_deref()
        .ok_or_else(|| anyhow!("image_digest MUST be Some when RAXIS_VM_IMAGE_DIGEST is set"))?;
    if !digest.starts_with("sha256:") {
        bail!("image_digest MUST be sha256-prefixed; got {digest:?}");
    }
    tracing::info!(image_role = ?manifest.image_role, image_digest = %digest,
        "vm-capabilities: spawn metadata stamped correctly");

    // ── Assertion 2: binaries non-empty + at least one toolchain
    //    binary present (any reasonable Linux host has bash; the
    //    slice deliberately picks the smallest possible canonical
    //    binary so the assertion holds in minimal containers too).
    let binary_names: Vec<&str> = manifest
        .binaries
        .iter()
        .map(|b| b.name.as_str())
        .collect();
    if binary_names.is_empty() {
        bail!(
            "INV-EXEC-DISCOVERY-01: binaries MUST be non-empty on a real \
             Linux host; got empty manifest.binaries"
        );
    }
    if !binary_names.iter().any(|n| *n == "bash" || *n == "sh") {
        bail!(
            "INV-EXEC-DISCOVERY-01: at least one of bash/sh MUST be on PATH; \
             got binaries: {binary_names:?}"
        );
    }
    tracing::info!(n_binaries = manifest.binaries.len(),
        "vm-capabilities: PATH walk found binaries");

    // ── Assertion 3: workdir reflects the staged cwd verbatim.
    if manifest.filesystem.workdir != staged_cwd.to_string_lossy().into_owned() {
        bail!(
            "filesystem.workdir MUST equal staged cwd; expected {}, got {}",
            staged_cwd.display(),
            manifest.filesystem.workdir,
        );
    }
    if manifest.filesystem.git_initialized {
        bail!(
            "filesystem.git_initialized MUST be false for the non-git tempdir; \
             got true"
        );
    }
    if manifest.filesystem.head_commit.is_some() {
        bail!(
            "filesystem.head_commit MUST be None for the non-git tempdir; got {:?}",
            manifest.filesystem.head_commit
        );
    }

    // ── Assertion 4: credential-proxy URLs surface verbatim.
    for (key, expected) in [
        ("DATABASE_URL", "postgres://raxis@127.0.0.1:54121/livee2e"),
        ("MONGO_URL",    "mongodb://127.0.0.1:54122/livee2e"),
        ("REDIS_URL",    "redis://127.0.0.1:54123/0"),
        ("SMTP_URL",     "smtp://127.0.0.1:54124"),
    ] {
        let got = manifest.env.get(key).ok_or_else(|| {
            anyhow!(
                "INV-EXEC-DISCOVERY-01: {key} MUST surface in manifest.env (the LLM \
                 needs this to write scripts that connect through the credential proxy); \
                 got env keys: {:?}",
                manifest.env.keys().collect::<Vec<_>>(),
            )
        })?;
        if got != expected {
            bail!(
                "{key} MUST surface verbatim; expected {expected:?}, got {got:?}"
            );
        }
    }
    tracing::info!("vm-capabilities: credential-proxy URLs surface verbatim");

    // ── Assertion 5: NEGATIVE redaction test. None of the
    //    kernel-private env keys appear in manifest.env, AND the
    //    sentinel byte sequence does NOT appear anywhere in the
    //    serialised manifest JSON (catches a future bug where a
    //    redacted value leaks through some other field, e.g. a
    //    binary's `version` if a probe shells out and an env var
    //    leaks into stderr).
    for key in [
        "RAXIS_VSOCK_LOOPBACK_PLAN",
        "RAXIS_SESSION_TOKEN",
        "RAXIS_PLANNER_SIDECAR_HMAC_SECRET",
        "RAXIS_PLANNER_KSB",
        "RAXIS_PLANNER_TASK_PROMPT",
        "ANTHROPIC_API_KEY",
        "GITHUB_TOKEN",
        "POSTGRES_PASSWORD",
    ] {
        if manifest.env.contains_key(key) {
            bail!(
                "INV-EXEC-DISCOVERY-01: kernel-private env key {key:?} MUST NOT \
                 appear in manifest.env; this is the redaction-clause negative \
                 test. is_kernel_private_env({key:?}) returns {}",
                is_kernel_private_env(key)
            );
        }
        if !is_kernel_private_env(key) {
            bail!(
                "is_kernel_private_env({key:?}) MUST return true for a value the \
                 redaction predicate is supposed to drop"
            );
        }
    }
    let manifest_json = serde_json::to_string(&manifest)
        .context("serialise manifest for sentinel scan")?;
    if manifest_json.contains(KERNEL_PRIVATE_SENTINEL) {
        bail!(
            "INV-EXEC-DISCOVERY-01: kernel-private sentinel \
             {KERNEL_PRIVATE_SENTINEL:?} leaked into the serialised manifest. \
             First 400 bytes of the manifest: {}",
            &manifest_json[..manifest_json.len().min(400)]
        );
    }
    tracing::info!("vm-capabilities: kernel-private sentinel does NOT leak");

    // ── Assertion 6: system-prompt hint coherence.
    let hint = build_capability_hint(&manifest);
    for needle in [
        "## VM Environment",
        // Pinned by `build_capability_hint`. If a future change
        // re-formats this header, update the slice in lockstep.
        "Image role:",
        "No outbound network",
        // env-var NAMES surface in the hint (so the LLM knows which
        // proxies are wired) — but never their VALUES (so the hint
        // is value-stable for prompt caching across sessions that
        // only differ in proxy port allocation).
        "DATABASE_URL",
        "MONGO_URL",
        "REDIS_URL",
        "SMTP_URL",
    ] {
        if !hint.contains(needle) {
            bail!(
                "INV-EXEC-DISCOVERY-01: capability hint MUST contain {needle:?}; \
                 got hint: {hint}"
            );
        }
    }
    // Hint MUST NOT carry the proxy URL VALUES (prompt-cache
    // stability) — only the names above.
    for value in [
        "postgres://raxis@127.0.0.1:54121/livee2e",
        "mongodb://127.0.0.1:54122/livee2e",
        "redis://127.0.0.1:54123/0",
        "smtp://127.0.0.1:54124",
    ] {
        if hint.contains(value) {
            bail!(
                "INV-EXEC-DISCOVERY-01: capability hint MUST NOT carry the proxy \
                 URL VALUE {value:?} (prompt-cache stability); got hint: {hint}"
            );
        }
    }
    if hint.contains(KERNEL_PRIVATE_SENTINEL) {
        bail!(
            "INV-EXEC-DISCOVERY-01: capability hint MUST NOT carry the \
             kernel-private sentinel; got hint: {hint}"
        );
    }
    tracing::info!("vm-capabilities: capability hint coherent and value-redacted");

    // ── Assertion 7 (OPT-IN): canonical executor image's
    //    Python DB-client subset is present.
    if std::env::var("RAXIS_LIVE_CANONICAL_EXECUTOR_IMAGE").as_deref() == Ok("1") {
        let py = manifest.python.as_ref().ok_or_else(|| {
            anyhow!(
                "RAXIS_LIVE_CANONICAL_EXECUTOR_IMAGE=1 but the probe found no \
                 python interpreter on PATH"
            )
        })?;
        let installed: Vec<&str> = py.packages.iter().map(|p| p.name.as_str()).collect();
        for required in CANONICAL_EXECUTOR_PYTHON_DB_CLIENTS {
            if !installed.iter().any(|name| name.eq_ignore_ascii_case(required)) {
                bail!(
                    "canonical-executor opt-in: required Python DB client \
                     {required:?} MUST be present (planner-harness.md §10.6); \
                     installed packages: {installed:?}"
                );
            }
        }
        tracing::info!(
            python_pkg_count = py.packages.len(),
            "vm-capabilities (canonical opt-in): all 5 DB clients present"
        );
    } else {
        tracing::info!(
            "vm-capabilities: skipping canonical-executor pip-set assertion \
             (set RAXIS_LIVE_CANONICAL_EXECUTOR_IMAGE=1 to enable)"
        );
    }

    Ok(())
}

/// Canonical `raxis-executor-starter` image's Python DB-client set
/// per `planner-harness.md §10.6`. Names match what `pip` would
/// install (case-insensitive comparison handles `psycopg2-binary`
/// vs `Psycopg2-binary`, and dist-info case quirks).
const CANONICAL_EXECUTOR_PYTHON_DB_CLIENTS: &[&str] = &[
    "psycopg2-binary",
    "pymongo",
    "redis",
    "PyMySQL",
    "pymssql",
];
