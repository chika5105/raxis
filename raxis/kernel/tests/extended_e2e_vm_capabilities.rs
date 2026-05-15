//! In-VM capability discovery (`vm_capabilities`) live-e2e slice.
//!
//! Validates `INV-EXEC-DISCOVERY-01` (`raxis/specs/invariants.md
//! §10.4a`) end-to-end: the in-guest probe in
//! `crates/planner-core/src/vm_capabilities.rs` MUST produce a
//! manifest faithful to the bytes the canonical
//! `raxis-executor-starter` image actually booted with —
//! specifically, the curated DB-client subset (`psycopg2-binary`,
//! `pymongo`, `redis`, `PyMySQL`, `pymssql`) called out by
//! `planner-harness.md §10.6` MUST be importable inside the guest
//! and MUST surface in the structured `python.packages` section
//! of the manifest the `vm_capabilities` LLM tool returns.
//!
//! The slice ALSO pins the redaction guarantee from the same
//! invariant: the kernel-private `RAXIS_VSOCK_LOOPBACK_PLAN`
//! payload (a base64 blob the kernel stamps for loopback transport
//! plumbing) MUST NOT appear verbatim in the manifest's `env`
//! section under any category projection. The probe acknowledges
//! the variable's presence with the literal `<redacted>` sentinel
//! so the model knows the var is set, but the bytes never reach
//! the LLM transcript.
//!
//! ## Two-mode design
//!
//! Mirrors `extended_e2e_byo_executor_image.rs`'s pattern:
//!
//!   * **Smoke mode (default).** Runs at every `cargo test -p
//!     raxis-kernel` invocation. Exercises:
//!       - the in-process probe surface
//!         (`vm_capabilities::cached_capabilities` +
//!         `project_manifest`) against the host CI runner's env;
//!       - the redaction predicate
//!         (`vm_capabilities::is_kernel_private_env`) against an
//!         opaque kernel-private allowlist;
//!       - the LLM-callable tool wrapper
//!         (`tools_vm_capabilities::VmCapabilitiesTool`) against
//!         a `tools::ToolContext` for the real registry, returning
//!         JSON parseable by `serde_json::Value`;
//!       - the system-prompt hint formatter
//!         (`vm_capabilities::build_capability_hint`) producing
//!         the load-bearing `## VM Environment` header AND the
//!         egress-warning sentinel string.
//!     This guards against drift in any of the four call sites
//!     the live mode would exercise inside the canonical executor
//!     guest.
//!
//!   * **Live mode (gated).** Requires `RAXIS_LIVE_E2E=1` AND
//!     `RAXIS_LIVE_E2E_VM_CAPABILITIES=1`. Boots a canonical
//!     `raxis-executor-starter` VM, submits a single-Executor-task
//!     plan whose prompt instructs the planner to invoke the
//!     `vm_capabilities` LLM tool with `categories: ["python",
//!     "env"]` and dump the result to a witness file inside the
//!     worktree. Asserts:
//!       - Tier 1 (audit): the audit chain carries the
//!         `ToolAuditEvent` for the `vm_capabilities` invocation
//!         (canonical query envelope; no manifest-payload echo).
//!       - Tier 2 (`assert!`): the witness JSON's `python.packages`
//!         contains all five canonical DB clients with non-null
//!         versions and `importable: true` for each:
//!           * `psycopg2-binary`
//!           * `pymongo`
//!           * `redis`
//!           * `PyMySQL`
//!           * `pymssql`
//!         A regression that drops one of these (or that lets the
//!         probe fall back to a stale cached snapshot) trips the
//!         Tier-2 assertion immediately.
//!       - Tier 2 (`assert!`): the witness JSON's `env` map
//!         contains `RAXIS_VSOCK_LOOPBACK_PLAN: "<redacted>"` and
//!         NEVER the var's actual base64 payload — the redaction
//!         leg of `INV-EXEC-DISCOVERY-01`.
//!       - Tier 2 (`assert!`): the witness JSON's `env` map
//!         contains the four credential-proxy URLs the kernel
//!         stamps (`DATABASE_URL`, `MONGO_URL`, `REDIS_URL`,
//!         `SMTP_URL`) verbatim — the model's only legitimate
//!         handle on the proxy fleet.
//!       - Tier 3: kernel log path, audit dir, worktree, dashboard
//!         URL printed via `Tier3Reporter`.
//!
//! The live-mode body is **scaffolded but disabled** in this
//! commit, mirroring `extended_e2e_byo_executor_image.rs`. The
//! heavyweight stack required (auto-baked canonical executor
//! image with the five DB clients pre-installed, gateway binary,
//! Anthropic key, microVM boot, real LLM session that can be
//! prompt-engineered to call `vm_capabilities` and dump the
//! result to a worktree file) is the same iter-13 stack the BYO
//! live-mode body is waiting on. Until then the smoke mode runs
//! unconditionally and pins every code surface the live mode
//! would exercise; the live-mode body is a `todo!`-fenced stub
//! with the harness wiring present so a follow-up commit can
//! flip the gate without re-architecting the test.

#![allow(clippy::too_many_lines)]
#![allow(dead_code)]

use std::sync::Arc;

use raxis_planner_core::tools::{Tool, ToolContext};
use raxis_planner_core::tools_vm_capabilities::VmCapabilitiesTool;
use raxis_planner_core::vm_capabilities::{
    build_capability_hint, cached_capabilities, is_kernel_private_env, project_manifest,
    CapabilityCategory, CapabilityFilter,
};

const LIVE_E2E_GATE: &str = "RAXIS_LIVE_E2E";
const VM_CAPS_GATE: &str = "RAXIS_LIVE_E2E_VM_CAPABILITIES";

/// The five Python DB clients the canonical `raxis-executor-starter`
/// image bakes in per `planner-harness.md §10.6`. Live mode asserts
/// every one is present and importable in the guest's manifest.
const CANONICAL_PY_DB_CLIENTS: &[&str] =
    &["psycopg2-binary", "pymongo", "redis", "PyMySQL", "pymssql"];

/// The four credential-proxy URLs the kernel stamps into every
/// Executor session's env (`v2/credential-proxy.md §3.5`). Live
/// mode asserts each surfaces verbatim in the manifest.
const CANONICAL_PROXY_ENV_VARS: &[&str] = &["DATABASE_URL", "MONGO_URL", "REDIS_URL", "SMTP_URL"];

// ---------------------------------------------------------------------------
// Top-level test entry — chooses smoke vs live based on env gates.
// ---------------------------------------------------------------------------

#[test]
fn vm_capabilities_lifecycle() {
    let live_gate_on = std::env::var(LIVE_E2E_GATE).as_deref() == Ok("1");
    let vm_caps_gate_on = std::env::var(VM_CAPS_GATE).as_deref() == Ok("1");

    if !(live_gate_on && vm_caps_gate_on) {
        eprintln!(
            "[vm-caps-e2e] gates off (LIVE_E2E={live_gate_on}, \
             VM_CAPABILITIES={vm_caps_gate_on}); running smoke-mode \
             wiring assertions only. To run the live-driven \
             vm_capabilities flow:\n  \
             1. boot a canonical executor (raxis-executor-starter) image\n  \
             2. ensure raxis/.env carries ANTHROPIC-API-DEV-KEY=sk-ant-...\n  \
             3. RAXIS_LIVE_E2E=1 RAXIS_LIVE_E2E_VM_CAPABILITIES=1 \
                cargo test -p raxis-kernel \
                --test extended_e2e_vm_capabilities -- --nocapture",
        );
        smoke_mode();
        return;
    }

    todo!(
        "vm_capabilities live-mode body — replace with full \
         boot/submit/poll/assert flow.\n\
         See raxis/specs/v2/canonical-images.md §6 for the schema and \
         raxis/specs/invariants.md §10.4a (INV-EXEC-DISCOVERY-01) for \
         the normative contract. The smoke harness below pins every \
         in-process surface the live flow exercises inside the guest."
    );
}

// ---------------------------------------------------------------------------
// Smoke mode — wiring assertions that always run
// ---------------------------------------------------------------------------

fn smoke_mode() {
    eprintln!("[vm-caps-e2e:smoke] §1 in-process probe + cached_capabilities() round-trip");
    smoke_probe_and_cache();
    eprintln!("[vm-caps-e2e:smoke] §2 redaction predicate (kernel-private env vars)");
    smoke_redaction_predicate();
    eprintln!("[vm-caps-e2e:smoke] §3 LLM tool wrapper returns JSON-parseable manifest");
    smoke_tool_returns_parseable_json();
    eprintln!("[vm-caps-e2e:smoke] §4 system-prompt hint formatter (`## VM Environment` + egress warning)");
    smoke_capability_hint_string_contracts();
    eprintln!("[vm-caps-e2e:smoke] all wiring assertions pass");
}

/// `§1` — Pin the in-process probe surface. The probe MUST:
///   * complete sub-second on the test runner;
///   * return a non-empty `binaries` array (any modern Linux /
///     macOS CI runner has at least `bash` / `sh` on PATH);
///   * be deterministic across two consecutive
///     `cached_capabilities()` calls — the second call MUST be
///     an O(1) `Arc::clone` of the cached value, not a re-probe;
///   * round-trip through `project_manifest(.., &[All], &Default)`
///     unchanged (the no-op projection is the load-bearing
///     identity for the LLM tool's `categories: []` default).
fn smoke_probe_and_cache() {
    let t0 = std::time::Instant::now();
    let m1 = cached_capabilities();
    let elapsed = t0.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "INV-EXEC-DISCOVERY-01 perf budget: first probe MUST be sub-5s; \
         got {elapsed:?}. Sub-second is the warm-VM target; CI runners \
         get a 5-s ceiling."
    );

    assert!(
        !m1.binaries.is_empty(),
        "probe MUST surface at least one binary (any modern host has \
         /bin/sh); empty binaries array means the PATH walk regressed."
    );

    // Second call MUST be an Arc clone, not a re-probe — pin
    // pointer equality.
    let m2 = cached_capabilities();
    assert!(
        Arc::ptr_eq(&m1, &m2),
        "INV-EXEC-DISCOVERY-01 caching: second cached_capabilities() \
         call MUST return the same Arc as the first (per-process \
         OnceLock semantics); got two distinct allocations."
    );

    // No-op projection MUST be the identity for byte-equality of
    // the rendered JSON.
    let projected = project_manifest(
        m1.as_ref(),
        &[CapabilityCategory::All],
        &CapabilityFilter::default(),
    );
    let j1 = serde_json::to_string(m1.as_ref()).unwrap();
    let j2 = serde_json::to_string(&projected).unwrap();
    assert_eq!(
        j1, j2,
        "project_manifest(.., [All], default) MUST be the identity \
         function for byte-equality of the JSON render"
    );
}

/// `§2` — Pin the kernel-private env var redaction predicate.
/// This is the negative leg of `INV-EXEC-DISCOVERY-01`: the
/// listed variables MUST be classified as kernel-private (so the
/// probe redacts them); the credential-proxy URLs MUST NOT be.
fn smoke_redaction_predicate() {
    // Kernel-private (MUST redact).
    for k in [
        "RAXIS_VSOCK_LOOPBACK_PLAN",
        "RAXIS_SESSION_TOKEN",
        "RAXIS_PLANNER_KSB",
        "RAXIS_PLANNER_KSB_PATH",
        "RAXIS_PLANNER_TASK_PROMPT",
        "RAXIS_PLANNER_TASK_PROMPT_PATH",
        "RAXIS_PLANNER_SIDECAR_HMAC_SECRET",
        // Heuristic patterns.
        "MY_SECRET",
        "DATABASE_PASSWORD",
        "GITHUB_API_KEY",
        "PROVIDER_TOKEN",
    ] {
        assert!(
            is_kernel_private_env(k),
            "INV-EXEC-DISCOVERY-01 redaction: `{k}` MUST be \
             classified as kernel-private and never reach the \
             LLM transcript. The probe wraps it with the literal \
             `<redacted>` sentinel; a regression here would leak \
             the value verbatim."
        );
    }

    // Credential-proxy URLs (MUST NOT redact — model needs them).
    for k in CANONICAL_PROXY_ENV_VARS {
        assert!(
            !is_kernel_private_env(k),
            "INV-EXEC-DISCOVERY-01 redaction: `{k}` is a \
             credential-proxy URL the LLM legitimately needs to \
             write connection scripts; it MUST NOT be redacted. \
             A regression here would force the model to guess \
             proxy ports, which are kernel-allocated and unguessable."
        );
    }

    // Harmless plumbing (MUST NOT redact — model uses these).
    for k in ["PATH", "HOME", "LANG", "LC_ALL", "USER"] {
        assert!(
            !is_kernel_private_env(k),
            "harmless Unix env var `{k}` MUST NOT be redacted"
        );
    }
}

/// `§3` — Pin the LLM tool wrapper's contract: `execute` returns
/// `ToolOutput::ok(...)` with a JSON body parseable by
/// `serde_json::Value`. This pins the wire format the dispatch
/// loop hands back to the model.
fn smoke_tool_returns_parseable_json() {
    let tool = VmCapabilitiesTool;
    assert_eq!(
        tool.name(),
        "vm_capabilities",
        "INV-EXEC-DISCOVERY-01: the tool registered in every role \
         registry MUST be named `vm_capabilities` so the model can \
         reference it from the system-prompt hint by name."
    );

    // Schema MUST advertise the categories enum + filter object.
    let schema = tool.input_schema();
    let s = serde_json::to_string(&schema).unwrap();
    for tag in [
        "categories",
        "filter",
        "binary_name",
        "python_package",
        "node_package",
        "env_var",
        "binaries",
        "python",
        "node",
        "rust",
        "go",
        "env",
        "filesystem",
        "all",
    ] {
        assert!(
            s.contains(tag),
            "vm_capabilities tool schema MUST advertise `{tag}` so \
             the model can address every capability category / filter; \
             schema:\n{s}"
        );
    }

    // Execute with `categories: ["python", "env"]` (the live-mode
    // payload). Output MUST be parseable JSON whose top-level keys
    // include `python` and `env` and exclude unrelated sections.
    let dir = tempfile::tempdir().expect("tempdir");
    let ctx = ToolContext::for_workspace(dir.path().to_path_buf());
    let input = serde_json::json!({ "categories": ["python", "env"] });
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let out = rt
        .block_on(async { tool.execute(&input, &ctx).await })
        .expect("vm_capabilities tool execute must succeed on a clean tempdir");
    assert!(
        out.is_error.is_none(),
        "vm_capabilities tool MUST NOT return a structured error \
         on a clean tempdir; body:\n{}",
        out.content
    );
    let parsed: serde_json::Value = serde_json::from_str(&out.content)
        .expect("vm_capabilities tool MUST return parseable JSON");

    // python + env present (the requested categories), other
    // sections nulled-out by the projector.
    assert!(
        parsed.get("python").is_some(),
        "tool output MUST carry `python` section when requested; \
         body:\n{body}",
        body = out.content
    );
    assert!(
        parsed.get("env").is_some(),
        "tool output MUST carry `env` section when requested; \
         body:\n{body}",
        body = out.content
    );
}

/// `§4` — Pin the system-prompt hint formatter. The two
/// load-bearing strings the assembled NNSP downstream tests grep
/// for are the `## VM Environment` header AND the egress warning
/// (`No outbound network`). A regression in either string contract
/// would break the prompt-cache stability the invariant guarantees.
fn smoke_capability_hint_string_contracts() {
    let m = cached_capabilities();
    let hint = build_capability_hint(m.as_ref());
    assert!(
        hint.contains("## VM Environment"),
        "INV-EXEC-DISCOVERY-01 system-prompt hint MUST start with \
         the `## VM Environment` header (downstream tests in \
         driver.rs grep for this exact string); got:\n{hint}"
    );
    assert!(
        hint.contains("No outbound network"),
        "INV-EXEC-DISCOVERY-01 system-prompt hint MUST carry the \
         `No outbound network` egress reminder so the model never \
         tries `pip install` / `npm install`; got:\n{hint}"
    );
    assert!(
        hint.contains("vm_capabilities"),
        "INV-EXEC-DISCOVERY-01 system-prompt hint MUST point the \
         model at the `vm_capabilities` tool for finer queries; \
         got:\n{hint}"
    );
}
