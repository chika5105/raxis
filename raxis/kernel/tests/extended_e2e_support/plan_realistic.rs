//! Plan-TOML builder for the **realistic** extended e2e scenario
//! ([`kernel/tests/extended_e2e_realistic_scenario.rs`]).
//!
//! This is the sibling of [`super::plan`], which builds the
//! minimal-worktree scenario asserted by
//! `extended_e2e_concurrent_lifecycle.rs`. The realistic scenario
//! is layered on top of the `rich-multilang-001` repo seed
//! (`raxis/live-e2e/seed/repo/rich-multilang-001/`, materialised
//! into the executor's worktree by `scripts/materialize_seed.sh`)
//! and drives a sequence of operator workflows the empty-worktree
//! scenario does not exercise:
//!
//!   * `materialize-records` — the original 50-file materializer
//!     (re-used verbatim from `super::plan`) so the realistic
//!     scenario still asserts the canonical materialization
//!     witness alongside the new ones.
//!   * `xfile-refactor` — the cross-file rename described by
//!     `live-e2e/seed/prompts/cross_file_refactor.md`. Executor
//!     must rename `render_greeting` / `greet` across Rust + TS +
//!     Python under a `path_allowlist` that admits the three
//!     language trees but rejects writes to `scripts/`,
//!     `fixtures/`, `LICENSE`, `README.md`, `.gitignore`.
//!
//! Subsequent realism commits on this branch extend this module
//! with `lint-defect`, `xfile-refactor-reviewer-A/B`, secrets and
//! path-allowlist-positive helpers, and a multi-initiative
//! companion plan; the convention is "one task block per commit"
//! so the per-commit diff stays small and reviewable.
//!
//! Like `super::plan`, the whole TOML is built from constant
//! `&str` slices so a reviewer can audit the wire shape without
//! running the test.

#![allow(dead_code)]

// ---------------------------------------------------------------------------
// Stable task ids — pinned because witness validators key on them.
// ---------------------------------------------------------------------------

/// Materializer task id — re-used from [`super::plan::TASK_MATERIALIZE`]
/// so the existing witnesses continue to apply unmodified.
pub const TASK_MATERIALIZE: &str = "materialize-records";

/// Cross-file refactor executor task id (P3-2).
pub const TASK_XFILE_REFACTOR: &str = "xfile-refactor";

/// Lint-defect executor task id (P3-3) — the executor deliberately
/// introduces ONE real lint defect (Rust / TS / Python — choice
/// is the executor's) that the reviewer must catch.
pub const TASK_LINT_DEFECT: &str = "lint-defect";

/// Per-language lint-runner Executor task ids — each child
/// captures the strict-lint verdict for ONE language tree into a
/// dedicated capture file and commits it for the downstream
/// Reviewer panel. The Reviewer's `raxis-reviewer-core` VM image
/// ships only `raxis-planner` and `ripgrep`
/// (`INV-PLANNER-HARNESS-02`, `planner-harness.md §4.5`);
/// execution of any script — language lint runners included — is
/// structurally impossible from inside the Reviewer harness, so
/// the in-image Executor stage is the only legitimate surface for
/// the Reviewers' read-only rule-on-the-diff step.
///
/// **Per-language split (iter55 — supersedes iter54 budget bump).**
/// Iter54's bumping of the monolithic `lint-runner`'s `max_turns`
/// `30 → 90` papered over the symptom but kept the structural
/// over-broad scope: ONE Executor session was asked to repair
/// defects across Rust + TypeScript + Python in a single budget,
/// and the introduce-vs-repair asymmetry deterministically burned
/// `max_crash_retries=3` on the repair pass. The structural fix
/// is per-language children, each with a smaller, focused budget
/// matched to ONE language's worth of work:
///
/// * `lint-runner-python` — runs `python -m ruff check` against
///   `py-pkg/`, captures to `out/lint/check-python.txt`. Dual
///   Reviewer pair (`review-lint-defect-A`/`-B`) — preserves the
///   substantive-disagreement scenario asserted by
///   [`super::reviewer_substantive_disagreement::ReviewerSubstantiveDisagreementWitness`].
/// * `lint-runner-rust`   — runs `cargo fmt --check` + `cargo
///   clippy -- -D warnings` against `rust-crate/`, captures to
///   `out/lint/check-rust.txt`. Single rubber-stamp Reviewer.
/// * `lint-runner-js`     — runs `npx --no-install eslint` +
///   `prettier --check` + `tsc --noEmit` inside `ts-pkg/`,
///   captures to `out/lint/check-js.txt`. Single rubber-stamp
///   Reviewer.
///
/// The dual-Reviewer disagreement pair is pinned to
/// `lint-runner-python` and the upstream `lint-defect` prompt is
/// pinned to the Python target (`py-pkg/src/sample_py/greet.py`
/// ruff F401 unused-import). The pinning is a necessary corollary
/// of Option C in the iter55 fan-in design: per-language children
/// only ever see their own language's lint, so for the
/// substantive-disagreement aggregation to fire DETERMINISTICALLY
/// against the dual pair, the defect MUST live in the language
/// whose child carries that pair. Sibling children
/// (`lint-runner-rust`, `-js`) run their own lint cleanly, get
/// approved by their single Reviewer in one round, and contribute
/// the per-language coverage without amplifying the
/// disagreement-aggregation surface.
///
/// On a Reviewer rejection the kernel's
/// `INV-RETRY-FROM-COMPLETED-REVIEW-REJECTED-01` anchor lands on
/// the Reviewer's immediate Executor predecessor — i.e. the
/// per-language child whose Reviewer rejected — and that child's
/// `path_allowlist` admits BOTH `out/lint/` (capture file) AND
/// its own language source tree, so the Round-2 re-spawn driven
/// by a substantive critique can land a corrected diff in scope.
/// See [`super::reviewer_substantive_disagreement`] for the
/// witness shape the round-2 path on `lint-runner-python`
/// satisfies.
pub const TASK_LINT_RUNNER_PYTHON: &str = "lint-runner-python";

/// Per-language lint-runner for Rust — see
/// [`TASK_LINT_RUNNER_PYTHON`] docstring for the iter55 split
/// rationale and Option C fan-in choice.
pub const TASK_LINT_RUNNER_RUST: &str = "lint-runner-rust";

/// Per-language lint-runner for TypeScript / JavaScript — see
/// [`TASK_LINT_RUNNER_PYTHON`] docstring for the iter55 split
/// rationale and Option C fan-in choice.
pub const TASK_LINT_RUNNER_JS: &str = "lint-runner-js";

/// Positive path-allowlist executor task id (P3-4) — the
/// executor legitimately writes to `target/codegen/` under an
/// allowlist that admits exactly that path. Witness asserts both
/// (a) the chain admitted the commit AND (b) the file landed on
/// disk AND (c) the path-allowlist did not falsely reject the
/// task. See [`super::path_allowlist::PathAllowlistPositiveWitness`].
pub const TASK_ALLOWLIST_POSITIVE: &str = super::path_allowlist::TASK_ALLOWLIST_POSITIVE;

/// Service-evidence round-trip executor task id -- exercises the
/// per-protocol credential proxies against the real backing
/// services (postgres / mongodb / redis / smtp; mysql / mssql
/// opt-in via `RAXIS_LIVE_MYSQL_URL` / `RAXIS_LIVE_MSSQL_URL`)
/// and commits the per-service canonical output files under
/// `out/services/`. Witness lives in
/// [`super::service_evidence`].
pub const TASK_SERVICE_ROUND_TRIP: &str = super::service_evidence::TASK_SERVICE_ROUND_TRIP;

/// Credential-substitution-canary executor task id.
///
/// The structural test of the proxy substitution discipline (see
/// `specs/v2/secrets-model.md §2.5` / `INV-SECRET-05`). The
/// executor is handed FAKE-credential canaries via a `.env` file
/// staged into its worktree by the test driver, and instructed to
/// authenticate against Postgres using them. The proxy substitutes
/// the real credentials at the loopback boundary; the witness in
/// [`super::credential_substitution_evidence`] mechanically
/// verifies the agent's worktree contains zero bytes of the real
/// credential material post-run.
pub const TASK_CREDENTIAL_SUBSTITUTION_CANARY: &str =
    super::credential_substitution_evidence::TASK_CREDENTIAL_SUBSTITUTION_CANARY;

/// Dep-fetch-evidence executor task id — the first end-to-end
/// exercise of the kernel's Path A3 mediated-egress stack
/// (in-VM tproxy → vsock → kernel admission → upstream TCP →
/// byte tunnel) under a real agent's `python3 http.client` GET
/// to `https://example.com/`. The executor writes a JSON
/// evidence file to `out/deps/install-evidence.json` and commits
/// it; the witness in
/// [`super::dep_fetch_evidence::DepFetchEvidenceWitness`] pins
/// (a) `TproxyAdmissionGranted{host_or_sni="example.com",port=443}`
/// scoped to the executor's session, (b) zero
/// `TproxyAdmissionDenied` for that host on the same session,
/// (c) the on-disk evidence carries `http_status=200` +
/// `body_contains_example_domain=true`.
pub const TASK_DEP_FETCH_EVIDENCE: &str = super::dep_fetch_evidence::TASK_DEP_FETCH_EVIDENCE;

/// Transparent-proxy real-scripts executor task id (P3-10).
///
/// Companion to `service-round-trip`: the executor is handed a
/// normal "run these Python scripts and commit their outputs"
/// task. The scripts (`check_postgres.py`, `check_mongodb.py`,
/// `check_redis.py`, `check_smtp.py`, `check_mysql.py`,
/// `check_mssql.py` + a `run_all_services.sh` wrapper) use stock
/// client libraries (`psycopg2`, `pymongo`, `redis-py`, `pymysql`,
/// `pymssql`, stdlib `smtplib`) against stock environment
/// variables (`DATABASE_URL`, `MONGO_URL`, `REDIS_URL`,
/// `SMTP_URL`, `MYSQL_URL`, `MSSQL_URL`) and have no raxis-aware
/// branching. The credential proxies must be the only reachable
/// path to the upstreams.
///
/// Witness lives in [`super::transparent_proxy_evidence`]; it
/// asserts both that the proxy was started for the executor's
/// session AND that no direct-upstream egress (the kernel's
/// `TransparentProxyDenied{reason: "proxy_target_bypass"}`
/// signature) ever fired.
pub const TASK_TRANSPARENT_PROXY_REALSCRIPTS: &str =
    super::transparent_proxy_evidence::TASK_TRANSPARENT_PROXY_REALSCRIPTS;

/// Lint-defect dual-Reviewer pair (P3-7). Plain-prompted
/// reviewers (no directive) attached to `lint-runner-python` —
/// the per-language child carrying the substantive-disagreement
/// scenario. Both Reviewers' critique must name the Python
/// lint-defect target file (`greet.py`) for the witness in
/// [`super::reviewer_substantive_disagreement::ReviewerSubstantiveDisagreementWitness`]
/// to satisfy.
pub const TASK_REVIEW_LINT_A: &str = super::reviewer_substantive_disagreement::TASK_REVIEW_LINT_A;
pub const TASK_REVIEW_LINT_B: &str = super::reviewer_substantive_disagreement::TASK_REVIEW_LINT_B;

/// Single rubber-stamp Reviewer for `lint-runner-rust`. Plain
/// prompt — read the captured `out/lint/check-rust.txt`, observe
/// the `raxis_check_sh_exit_code=` sentinel, decide. No
/// disagreement scenario on this child (per iter55 Option C
/// fan-in choice — see [`TASK_LINT_RUNNER_PYTHON`] docstring).
pub const TASK_REVIEW_LINT_RUST: &str = "review-lint-defect-rust";

/// Single rubber-stamp Reviewer for `lint-runner-js`. Mirrors
/// [`TASK_REVIEW_LINT_RUST`] for the TypeScript / JavaScript
/// per-language child.
pub const TASK_REVIEW_LINT_JS: &str = "review-lint-defect-js";

/// Lane id for the realistic scenario. Distinct from
/// `super::plan::LANE_ID` so the realistic-scenario test and the
/// existing extended-scenario test can co-exist in a single kernel
/// run without contaminating each other's budget reservations.
pub const LANE_ID: &str = "e2e-realistic-lane";

/// Seed-fixture directory name under
/// `raxis/live-e2e/seed/repo/<scenario_id>/`. Picked up by the
/// test driver to resolve the materializer script path.
pub const SEED_SCENARIO_ID: &str = "rich-multilang-001";

// ---------------------------------------------------------------------------
// Embedded prompt text — `include_str!` so the test binary needs no
// runtime path to the seed prompts directory.
// ---------------------------------------------------------------------------

/// Materializer prompt (re-used verbatim from
/// [`super::plan::MATERIALIZER_PROMPT_MD`] via re-export so the
/// realistic plan and the original plan share one canonical source
/// of truth).
pub const MATERIALIZER_PROMPT_MD: &str = super::plan::MATERIALIZER_PROMPT_MD;

/// Cross-file refactor prompt. Drives the executor through a
/// rename that must propagate across the Rust / TS / Python trees.
pub const XFILE_REFACTOR_PROMPT_MD: &str =
    include_str!("../../../live-e2e/seed/prompts/cross_file_refactor.md");

/// Lint-defect prompt. Drives the executor through introducing
/// exactly one real lint defect that the reviewer must catch on
/// round 1.
pub const LINT_DEFECT_PROMPT_MD: &str =
    include_str!("../../../live-e2e/seed/prompts/lint_defect.md");

/// Positive path-allowlist prompt. Drives the executor through
/// writing `target/codegen/build_meta.txt` under an allowlist
/// that admits only `target/codegen/`.
pub const ALLOWLIST_POSITIVE_PROMPT_MD: &str =
    include_str!("../../../live-e2e/seed/prompts/allowlist_positive.md");

/// Service-evidence round-trip prompt. Drives the executor
/// through reading the per-service seed via each credential proxy
/// and writing one canonical-form file per service into
/// `out/services/`. See [`super::service_evidence`] for the
/// canonical-bytes formulas the witness recomputes.
pub const SERVICE_ROUND_TRIP_PROMPT_MD: &str =
    include_str!("../../../live-e2e/seed/prompts/service_round_trip.md");

/// Transparent-proxy real-scripts prompt. Operator-realistic
/// phrasing — does NOT mention raxis or "credential proxy". The
/// witness in [`super::transparent_proxy_evidence`] asserts the
/// prompt does not leak.
pub const TRANSPARENT_PROXY_REALSCRIPTS_PROMPT_MD: &str =
    include_str!("../../../live-e2e/seed/prompts/transparent_proxy_real_scripts.md");

/// Credential-substitution-canary prompt. Operator-realistic — the
/// agent is told the staged `.env` carries production credentials,
/// and is instructed to use them via `$DATABASE_URL`. The proxy
/// substitutes the real credentials transparently; the witness
/// verifies the structural property mechanically.
pub const CREDENTIAL_SUBSTITUTION_CANARY_PROMPT_MD: &str =
    include_str!("../../../live-e2e/seed/prompts/credential_substitution_canary.md");

/// Dep-fetch-evidence prompt. Drives the executor through one
/// real HTTPS `GET https://example.com/` via Python stdlib
/// `http.client` and a commit of the parsed evidence to
/// `out/deps/install-evidence.json`. The prompt body is the
/// source of truth for the endpoint pinning + the evidence
/// schema; the matching witness in [`super::dep_fetch_evidence`]
/// reads the same constants.
pub const DEP_FETCH_EVIDENCE_PROMPT_MD: &str =
    include_str!("../../../live-e2e/seed/prompts/dep_fetch_evidence.md");

// ---------------------------------------------------------------------------
// Plan-TOML builder.
// ---------------------------------------------------------------------------

/// Build the realistic-scenario `[plan]` TOML body the test
/// submits via `OperatorIpc::submit_plan`. The current shape
/// includes `materialize-records` + `xfile-refactor`; subsequent
/// commits on this branch extend it.
pub fn realistic_plan_toml() -> String {
    let materializer = MATERIALIZER_PROMPT_MD;
    let xfile = XFILE_REFACTOR_PROMPT_MD;
    let lint = LINT_DEFECT_PROMPT_MD;
    let allowlist = ALLOWLIST_POSITIVE_PROMPT_MD;
    let service_rt = SERVICE_ROUND_TRIP_PROMPT_MD;
    let transparent_rt = TRANSPARENT_PROXY_REALSCRIPTS_PROMPT_MD;
    let cred_sub = CREDENTIAL_SUBSTITUTION_CANARY_PROMPT_MD;
    let dep_fetch = DEP_FETCH_EVIDENCE_PROMPT_MD;
    let mut s = String::new();
    s.push_str(REALISTIC_PLAN_HEADER);
    s.push_str("\n\n");
    s.push_str(REALISTIC_PLAN_MATERIALIZER_HEAD);
    s.push_str(materializer);
    s.push_str("\n\"\"\"\n");
    s.push_str(REALISTIC_PLAN_MATERIALIZER_CREDS);
    s.push_str("\n\n");
    s.push_str(REALISTIC_PLAN_XFILE_HEAD);
    s.push_str(xfile);
    s.push_str("\n\"\"\"\n");
    s.push_str("\n\n");
    s.push_str(REALISTIC_PLAN_LINT_DEFECT_HEAD);
    s.push_str(lint);
    s.push_str("\n\"\"\"\n");
    s.push_str("\n\n");
    s.push_str(REALISTIC_PLAN_LINT_RUNNER_PYTHON);
    s.push_str("\n\n");
    s.push_str(REALISTIC_PLAN_LINT_RUNNER_RUST);
    s.push_str("\n\n");
    s.push_str(REALISTIC_PLAN_LINT_RUNNER_JS);
    s.push_str("\n\n");
    s.push_str(REALISTIC_PLAN_LINT_REVIEWERS);
    s.push_str("\n\n");
    s.push_str(REALISTIC_PLAN_ALLOWLIST_POSITIVE_HEAD);
    s.push_str(allowlist);
    s.push_str("\n\"\"\"\n");
    s.push_str("\n\n");
    s.push_str(REALISTIC_PLAN_SERVICE_ROUND_TRIP_HEAD);
    s.push_str(service_rt);
    s.push_str("\n\"\"\"\n");
    s.push_str(REALISTIC_PLAN_SERVICE_ROUND_TRIP_CREDS);
    s.push_str("\n\n");
    s.push_str(REALISTIC_PLAN_TRANSPARENT_PROXY_HEAD);
    s.push_str(transparent_rt);
    s.push_str("\n\"\"\"\n");
    s.push_str(REALISTIC_PLAN_TRANSPARENT_PROXY_CREDS);
    s.push_str("\n\n");
    s.push_str(REALISTIC_PLAN_CREDENTIAL_SUBSTITUTION_HEAD);
    s.push_str(cred_sub);
    s.push_str("\n\"\"\"\n");
    s.push_str(REALISTIC_PLAN_CREDENTIAL_SUBSTITUTION_CREDS);
    s.push_str("\n\n");
    s.push_str(REALISTIC_PLAN_DEP_FETCH_EVIDENCE_HEAD);
    s.push_str(dep_fetch);
    s.push_str("\n\"\"\"\n");
    s
}

const REALISTIC_PLAN_HEADER: &str = r#"[plan.initiative]
description = """
Extended e2e realistic scenario per raxis/specs/v2/e2e-extended-scenario.md
(future-work bullet "Multi-language source tree" + follow-ups).

The realistic scenario layers the `rich-multilang-001` repo seed
under the executor worktree (Rust + TS + Python trees with pinned
tooling configs, a non-trivial git history, an executable script,
and a binary fixture) and drives a sequence of cross-cutting
operator workflows on top: the original 50-file materializer plus
a real cross-file refactor that must propagate consistently across
all three language trees.

Cloud connections (S3 / GCP / Azure) are explicitly out of scope.
"""

[workspace]
name    = "E2E realistic scenario"
lane_id = "e2e-realistic-lane""#;

const REALISTIC_PLAN_MATERIALIZER_HEAD: &str = r#"# ── Materializer Executor (re-used from extended scenario) ──
[[tasks]]
task_id            = "materialize-records"
name               = "Materialize seeded postgres rows + mongo docs to JSON files"
session_agent_type = "Executor"
# 25 postgres rows + 25 mongo docs + 50 file writes + commit + verify.
# `DEFAULT_PLANNER_MAX_TURNS` was bumped 20→50→100 specifically because
# this task reproducibly exhausted lower budgets at iter25 + iter31.
# 150 gives ~50% headroom over the 100-turn floor for natural tool-error
# retry cycles. Per `INV-PLANNER-MAX-TURNS-PRECEDENCE-01`.
max_turns          = 150
path_allowlist     = ["out/postgres/", "out/mongo/", "out/manifest.json"]
description = """
"#;

const REALISTIC_PLAN_MATERIALIZER_CREDS: &str = r#"
  [[tasks.credentials]]
  name       = "test-pg-dev"
  proxy_type = "postgres"
  mount_as   = "DATABASE_URL"

  [[tasks.credentials]]
  name       = "test-mongo-dev"
  proxy_type = "mongodb"
  mount_as   = "MONGO_URL""#;

const REALISTIC_PLAN_XFILE_HEAD: &str = r#"# ── Cross-file refactor Executor (P3-2) ─────────────────
[[tasks]]
task_id            = "xfile-refactor"
name               = "Cross-file rename across Rust / TS / Python"
session_agent_type = "Executor"
# Mechanical cross-file rename across 3 language trees: read 3 files,
# rewrite each, verify with grep, commit. ~5 turns per file × 3 = 15
# plus retry/iteration headroom = 40. Per `INV-PLANNER-MAX-TURNS-PRECEDENCE-01`.
max_turns          = 40
path_allowlist     = ["rust-crate/", "ts-pkg/", "py-pkg/"]
description = """
"#;

const REALISTIC_PLAN_LINT_DEFECT_HEAD: &str = r#"# ── Lint-defect Executor (P3-3) ─────────────────────────
[[tasks]]
task_id            = "lint-defect"
name               = "Introduce exactly one real Python lint defect (iter55 pin)"
session_agent_type = "Executor"
predecessors       = ["xfile-refactor"]
# Single-edit task: open `py-pkg/src/sample_py/greet.py` (iter55
# pin — see prompt), append an unused `import os`, commit. Trivially
# small natural budget (~5 turns); iter55 budget audit bumps the
# ceiling 25 → 35 for headroom against the lint-defect prompt's
# "no suggestive commit message" constraint (the planner may
# retry the commit step once or twice if it accidentally
# mentions "lint" or "defect" in the message). Per
# `INV-PLANNER-MAX-TURNS-PRECEDENCE-01`.
max_turns          = 35
path_allowlist     = ["py-pkg/"]
description = """
"#;

// ── Per-language Lint-runner Executors (captures language-scoped lint output) ──
//
// Iter55 SPLIT — what was a single monolithic `lint-runner`
// task asked to introduce/repair lint defects across Rust +
// TypeScript + Python in a single budget is now THREE focused
// per-language children. Iter54 surfaced the under-sizing:
// the introduce path comfortably fit in 30 turns, but the
// repair path (read critique + edit defective file + re-run
// the full check.sh) deterministically exhausted the budget
// at the same wall on every retry, burning the crash-retry
// slot with zero forward progress. The structural fix is
// per-language scope:
//
//   * `lint-runner-python` — `python -m ruff check` + format
//     against `py-pkg/`, capture to `out/lint/check-python.txt`.
//   * `lint-runner-rust`   — `cargo fmt --check` + `cargo clippy
//     -- -D warnings` against `rust-crate/`, capture to
//     `out/lint/check-rust.txt`.
//   * `lint-runner-js`     — `npx --no-install eslint` + prettier
//     + `tsc --noEmit` inside `ts-pkg/`, capture to
//     `out/lint/check-js.txt`.
//
// Each child's `path_allowlist` admits BOTH the capture path
// (`out/lint/`) AND its OWN language source tree only, so a
// Round-2 re-spawn driven by a substantive Reviewer rejection
// can land a corrective edit narrowly inside the scope.
//
// **Bash dropped (or folded).** The rich-multilang-001 fixture
// has Bash scripts (`scripts/check.sh`, `scripts/materialize_seed.sh`)
// but NO Bash-language lint target — `check.sh` is a RUNNER
// that exercises Rust/TS/Python tooling, not itself linted.
// A `lint-runner-bash` would have zero defect surface; iter55
// folds it (no fourth child).
//
// **Option C fan-in (iter55).** Of the three per-language
// children, ONLY `lint-runner-python` carries the dual-Reviewer
// pair (`review-lint-defect-A`/`-B`) that drives the
// substantive-disagreement scenario the
// [`super::reviewer_substantive_disagreement::ReviewerSubstantiveDisagreementWitness`]
// asserts. The other two children carry a single rubber-stamp
// Reviewer each — adequate per-language coverage without
// amplifying the disagreement-aggregation surface. The pinning
// of the upstream `lint-defect` to the Python target is a
// necessary structural corollary: per-language children only
// see their own language's lint, so for the dual-Reviewer
// rejection on `lint-runner-python` to fire DETERMINISTICALLY,
// the defect MUST live in `py-pkg/src/sample_py/greet.py`. See
// the `LINT_DEFECT_PROMPT_MD` prompt for the explicit pin.
//
// **Budget sizing (per-task `max_turns = 60`, iter55 + Fix 2).**
// The original 30-turn ceiling covered all four languages on
// the introduce path (~7 turns per language); per-language
// children at 60 turns give 8× per-language headroom on
// introduce, 2-3× on repair. Combined with the kernel-side
// progressive max_turns bump (`INV-PLANNER-MAX-TURNS-PROGRESSIVE-ON-RETRY-01`
// — Fix 2, kernel-side `base + (attempt-1) * step` with default
// `step = base/2`): retry #1 yields 90, retry #2 yields 120.
// Comfortable on both introduce and repair, with margin for
// occasional planner exploration.
const REALISTIC_PLAN_LINT_RUNNER_PYTHON: &str = r#"# ── Lint-runner Executor — Python (P3-3 / iter55 split) ──
[[tasks]]
task_id            = "lint-runner-python"
name               = "Capture python -m ruff check output for the Python Reviewer panel"
session_agent_type = "Executor"
predecessors       = ["lint-defect"]
# Iter55 per-language split (supersedes the iter54-N cold-start
# bump on the monolithic `lint-runner` task — that task is gone,
# replaced by this per-language child). Scope: ONE language
# (Python). Budget: 60 turns covers Round 1 (~5 turns:
# `mkdir -p out/lint`, `cd py-pkg && python -m ruff check . &&
# python -m ruff format --check .` wrapped to capture
# stdout+stderr+exit, `git add`, `git commit`, `task_complete`)
# AND Round 2 (~15 turns: read critique, edit
# `py-pkg/src/sample_py/greet.py`, re-run capture, commit) with
# 8× headroom over the per-language introduce slice. The
# iter54-N cold-start observation still applies: each crash
# retry boots a FRESH executor VM with zero prior context — but
# at per-language scope the cold-start work is now ONE language
# tree, not three, so 60 turns is comfortable rather than
# marginal. The kernel-side progressive bump on retry
# (`INV-PLANNER-MAX-TURNS-PROGRESSIVE-ON-RETRY-01`, Fix 2)
# elasticates this further on review-rejection paths: retry #1 →
# 90, retry #2 → 120. Per `INV-PLANNER-MAX-TURNS-PRECEDENCE-01`.
max_turns          = 60
path_allowlist     = ["out/lint/", "py-pkg/"]
description = """
You are the RAXIS lint-runner-python executor. The diff from
`lint-defect` is already committed on the working branch; your
job is to surface the strict-Python-lint verdict (`ruff check`
+ `ruff format --check`) to the downstream Reviewer panel.

The Reviewer VM image (`raxis-reviewer-core`) is structurally
forbidden from executing scripts: it ships ONLY `raxis-planner`
and `ripgrep` per `INV-PLANNER-HARNESS-02` (no shell, no
language runtimes, no `git`, no network utilities). The
Reviewers therefore cannot run `python -m ruff check` themselves
— they read its captured output from a committed artifact you
produce here.

## Round 1 — capture

1. Create the capture directory: `mkdir -p out/lint`.
2. Run the Python lint stack inside `py-pkg/` and capture
   stdout + stderr + the exit code in a single file at the
   fixed path `out/lint/check-python.txt`:
   ```bash
   {
     ( cd py-pkg && python -m ruff check . && python -m ruff format --check . ) 2>&1
     echo "raxis_check_sh_exit_code=$?"
   } > out/lint/check-python.txt
   ```
   The trailing `raxis_check_sh_exit_code=<n>` line is the
   wire signal the Reviewers key on; do NOT omit it. The
   wrapping `{ … ; echo … } > file` form (NOT `set -e`-killing
   pipefail) means the script captures both a passing AND a
   failing exit code honestly — `lint-defect` is pinned to
   Python (`py-pkg/src/sample_py/greet.py` ruff F401 unused-
   import) so on Round 1 the captured exit code WILL be
   non-zero.
3. `git add out/lint/check-python.txt`
4. `git commit -m "chore: capture python ruff output for reviewer panel"`
5. Call `task_complete` with a one-line summary that includes
   the captured exit code.

## Round 2+ — substantive critique fix-up

If your prior round was rejected by the Reviewer panel, the
critique appended to your prompt names the defective Python
file (`py-pkg/src/sample_py/greet.py`). Your `path_allowlist`
includes `py-pkg/` precisely so you can land the fix here:

1. Edit `py-pkg/src/sample_py/greet.py` to remove the lint
   diagnostic the critique names (e.g. drop the unused
   `import os` introduced upstream).
2. Re-run the capture step above. `out/lint/check-python.txt`
   should now end with `raxis_check_sh_exit_code=0`.
3. `git add` the fixed file AND `out/lint/check-python.txt`.
4. `git commit -m "fix: <one-line lint repair> + refresh
   python check-output capture"`.
5. `task_complete`.

## Constraints

* The capture MUST live at the exact path
  `out/lint/check-python.txt`. The Python Reviewer prompts
  hard-code that path; any other location is a witness failure.
* Do NOT touch `rust-crate/`, `ts-pkg/`, `scripts/`,
  `fixtures/`, or any file outside `out/lint/` + `py-pkg/`.
  Writes outside the allowlist trip `FailPathPolicyViolation`
  at `task_complete`.
* Do NOT swallow the failing exit code on Round 1. The whole
  point of the round is to surface the lint failure honestly —
  wrapping with `|| true` or stripping the exit-code tail
  defeats the Reviewer's substantive check.
"""

"#;

const REALISTIC_PLAN_LINT_RUNNER_RUST: &str = r#"# ── Lint-runner Executor — Rust (P3-3 / iter55 split) ────
[[tasks]]
task_id            = "lint-runner-rust"
name               = "Capture cargo clippy + fmt output for the Rust Reviewer"
session_agent_type = "Executor"
predecessors       = ["lint-defect"]
# Iter55 per-language split. Scope: ONE language (Rust). Budget:
# 60 turns — same sizing rationale as `lint-runner-python` (see
# its comment block). With `lint-defect` pinned to Python the
# Rust capture is expected clean on Round 1; the budget headroom
# is for the off-nominal case where the planner explores or the
# capture wrapper itself misbehaves. Per
# `INV-PLANNER-MAX-TURNS-PRECEDENCE-01`.
max_turns          = 60
# `Cargo.lock` MUST be in this allowlist: cargo always materialises
# the workspace lockfile at the workspace root (`<worktree>/Cargo.lock`)
# the FIRST time any cargo command runs against an unlocked workspace,
# regardless of the cwd cargo is invoked from. The rich-multilang-001
# fixture ships an unlocked `[workspace]` Cargo.toml at the worktree
# root (members = ["rust-crate"]); the very first `cargo fmt --check`
# / `cargo clippy` invocation here writes a fresh `Cargo.lock` next to
# it. Without `Cargo.lock` admitted, the executor's `task_complete`
# trips `CompleteTaskAdmitPathViolation` (path-scope check at admit
# time, `kernel/src/handlers/intent.rs:2311`) — the iter57 failure
# mode. Allowing `Cargo.lock` is canonical: it is a workspace-root
# artefact by cargo design and the Reviewer's diff-review surface
# tolerates it (the lockfile is a one-way function of the workspace
# manifest tree). The Python and JS sister tasks do NOT need a
# matching expansion: ruff / eslint / prettier / tsc do not produce
# workspace-root artefacts, so their narrower allowlists stay tight.
path_allowlist     = ["out/lint/", "rust-crate/", "Cargo.lock"]
description = """
You are the RAXIS lint-runner-rust executor. Your job is to
surface the strict-Rust-lint verdict (`cargo fmt --all --
--check` + `cargo clippy --all-targets -- -D warnings`) to the
downstream Reviewer.

The Reviewer VM image (`raxis-reviewer-core`) is structurally
forbidden from executing scripts: it ships ONLY `raxis-planner`
and `ripgrep` per `INV-PLANNER-HARNESS-02`. The Reviewer
therefore cannot run `cargo clippy` themselves — they read its
captured output from a committed artifact you produce here.

## Round 1 — capture

1. Create the capture directory: `mkdir -p out/lint`.
2. Run the Rust lint stack and capture stdout + stderr + the
   exit code in a single file at the fixed path
   `out/lint/check-rust.txt`:
   ```bash
   {
     cargo fmt --all -- --check 2>&1
     cargo clippy --all-targets -- -D warnings 2>&1
     echo "raxis_check_sh_exit_code=$?"
   } > out/lint/check-rust.txt
   ```
3. Stage the capture file AND the workspace lockfile (cargo
   materialises a fresh `Cargo.lock` at the worktree root the
   first time it resolves the workspace; the `path_allowlist`
   admits it explicitly, so `git add` it if `git status` shows it):
   ```bash
   git add out/lint/check-rust.txt
   if git status --porcelain | grep -q '^?? Cargo\\.lock$\\|^.M Cargo\\.lock$'; then
     git add Cargo.lock
   fi
   ```
4. `git commit -m "chore: capture cargo clippy output for reviewer"`
5. Call `task_complete` with a one-line summary that includes
   the captured exit code.

## Round 2+ — substantive critique fix-up

If your prior round was rejected, the critique names a file
inside `rust-crate/` carrying the diagnostic. Edit it, re-run
the capture, commit, `task_complete`. Your `path_allowlist`
admits `rust-crate/` for this purpose.

## Constraints

* The capture MUST live at `out/lint/check-rust.txt`.
* Do NOT touch `py-pkg/`, `ts-pkg/`, `scripts/`, `fixtures/`.
  Writes outside the allowlist trip `FailPathPolicyViolation`.
* Do NOT swallow the failing exit code on Round 1.
"""

"#;

const REALISTIC_PLAN_LINT_RUNNER_JS: &str = r#"# ── Lint-runner Executor — JS / TS (P3-3 / iter55 split) ─
[[tasks]]
task_id            = "lint-runner-js"
name               = "Capture eslint + prettier + tsc output for the JS / TS Reviewer"
session_agent_type = "Executor"
predecessors       = ["lint-defect"]
# Iter55 per-language split. Scope: ONE language (TypeScript /
# JavaScript). Budget: 60 turns — same sizing rationale as
# `lint-runner-python` (see its comment block). With
# `lint-defect` pinned to Python the JS capture is expected
# clean on Round 1; budget headroom is for off-nominal cases.
# Per `INV-PLANNER-MAX-TURNS-PRECEDENCE-01`.
max_turns          = 60
path_allowlist     = ["out/lint/", "ts-pkg/"]
description = """
You are the RAXIS lint-runner-js executor. Your job is to
surface the strict-JS-lint verdict (`npx --no-install eslint
--max-warnings 0` + `npx --no-install prettier --check` +
`npx --no-install tsc --noEmit`) to the downstream Reviewer.

The Reviewer VM image (`raxis-reviewer-core`) is structurally
forbidden from executing scripts: it ships ONLY `raxis-planner`
and `ripgrep` per `INV-PLANNER-HARNESS-02`. The Reviewer
therefore cannot run `eslint` themselves — they read its
captured output from a committed artifact you produce here.

## Round 1 — capture

1. Create the capture directory: `mkdir -p out/lint`.
2. Run the JS/TS lint stack inside `ts-pkg/` and capture
   stdout + stderr + the exit code in a single file at the
   fixed path `out/lint/check-js.txt`:
   ```bash
   {
     ( cd ts-pkg && \
       npx --no-install eslint --max-warnings 0 . && \
       npx --no-install prettier --check . && \
       npx --no-install tsc --noEmit ) 2>&1
     echo "raxis_check_sh_exit_code=$?"
   } > out/lint/check-js.txt
   ```
3. `git add out/lint/check-js.txt`
4. `git commit -m "chore: capture eslint/tsc output for reviewer"`
5. Call `task_complete` with a one-line summary that includes
   the captured exit code.

## Round 2+ — substantive critique fix-up

If your prior round was rejected, the critique names a file
inside `ts-pkg/` carrying the diagnostic. Edit it, re-run the
capture, commit, `task_complete`. Your `path_allowlist` admits
`ts-pkg/` for this purpose.

## Constraints

* The capture MUST live at `out/lint/check-js.txt`.
* Do NOT touch `py-pkg/`, `rust-crate/`, `scripts/`,
  `fixtures/`. Writes outside the allowlist trip
  `FailPathPolicyViolation`.
* Do NOT swallow the failing exit code on Round 1.
"""

"#;

const REALISTIC_PLAN_LINT_REVIEWERS: &str = r#"# ── Lint-defect Reviewers (P3-7 / iter55 Option C fan-in) ─
#
# Reviewer fan-in: Option C — `lint-runner-python` carries the
# dual-Reviewer pair (`review-lint-defect-A`/`-B`) that drives
# the substantive-disagreement scenario asserted by
# `ReviewerSubstantiveDisagreementWitness`; `lint-runner-rust`
# and `lint-runner-js` each carry a single rubber-stamp
# Reviewer that gates the upstream Executor's pipeline on the
# captured-clean exit code. The `lint-defect` prompt is pinned
# to Python so the per-language disagreement deterministically
# fires on the dual pair (see plan_realistic.rs::TASK_LINT_RUNNER_PYTHON
# docstring for the structural rationale).
[[tasks]]
task_id            = "review-lint-defect-A"
name               = "Reviewer A — substantive review of lint-defect diff (Python pair)"
session_agent_type = "Reviewer"
predecessors       = ["lint-runner-python"]
# Reviewer is mechanical: read_file the captured artifact, observe the
# raxis_check_sh_exit_code sentinel line, decide. The Reviewer VM image
# (`raxis-reviewer-core`) ships ONLY raxis-planner + ripgrep per
# `INV-PLANNER-HARNESS-02`, so there's no shell, no language runtime,
# no tool that could legitimately need many turns. Iter55 bumped the
# reviewer ceiling 10 → 30 (per the user-confirmed budget audit) for
# headroom over the round-1 read + decide path, with the kernel-side
# progressive max_turns bump on retry
# (`INV-PLANNER-MAX-TURNS-PROGRESSIVE-ON-RETRY-01`) elasticating
# further on round-2 if needed. Per `INV-PLANNER-MAX-TURNS-PRECEDENCE-01`.
max_turns          = 30
description = """
You are the FIRST Reviewer in a panel reviewing the rich-
multilang-001 Python lint-defect pipeline. The upstream
`lint-defect` Executor introduced exactly one real Python lint
defect in `py-pkg/src/sample_py/greet.py` (per the iter55
per-language-split pin: the lint-defect prompt offers only the
Python `F401 unused-import` option — `import os` appended at
the top of the file but never referenced).

The `lint-runner-python` Executor has ALREADY committed
`out/lint/check-python.txt` containing the captured stdout +
stderr of `python -m ruff check` + `ruff format --check`,
terminated by a sentinel line `raxis_check_sh_exit_code=<n>`
carrying the exit code.

Your job is mechanical: `read_file` the captured artifact,
observe the exit code, and rule on the diff. If the captured
`raxis_check_sh_exit_code` is non-zero, submit `SubmitReview`
with `approved = false` and a critique whose text NAMES the
file that produced the failing lint diagnostic
(`py-pkg/src/sample_py/greet.py` — the captured output names it
verbatim, often shortened to `greet.py`). If the captured exit
code is zero, submit `SubmitReview` with `approved = true`.

You MUST NOT attempt to execute `python -m ruff` yourself —
your VM image (`raxis-reviewer-core`) ships ONLY
`raxis-planner` and `ripgrep` per `INV-PLANNER-HARNESS-02`;
there is no shell, no `cargo`, no `npx`, no `python`. Use
`read_file` for `out/lint/check-python.txt` and any diff hunk
you want to confirm, and `grep_search` to locate the failing
file's mention inside the captured output.

As Reviewer A you take a STRICT stance on lint failures: any
non-zero exit code in the captured artifact is a hard reject
naming the specific failing file (`greet.py` in this scenario).
Do NOT invent defects, do NOT reject for vibes, do NOT cite a
file that did not appear in the captured output. The witness
verifies the critique mentions one of the lint-defect target
basenames (`greet.py`) verbatim.
"""

[[tasks]]
task_id            = "review-lint-defect-B"
name               = "Reviewer B — substantive review of lint-defect diff (Python pair)"
session_agent_type = "Reviewer"
predecessors       = ["lint-runner-python"]
# Same shape + budget as Reviewer A — mechanical read_file + decide.
# Iter55: 10 → 30 reviewer-ceiling bump (see Reviewer A comment).
# Per `INV-PLANNER-MAX-TURNS-PRECEDENCE-01`.
max_turns          = 30
description = """
You are the SECOND Reviewer in a panel reviewing the rich-
multilang-001 Python lint-defect pipeline. The
`lint-runner-python` Executor has committed
`out/lint/check-python.txt` (stdout + stderr +
`raxis_check_sh_exit_code=<n>` sentinel) capturing the strict
output of `python -m ruff check` + `ruff format --check`.

Your job is mechanical: `read_file` the captured artifact,
observe the exit code, and rule on the diff. If
`raxis_check_sh_exit_code` is non-zero, submit `SubmitReview`
with `approved = false` and a critique whose text NAMES the
specific failing file (`py-pkg/src/sample_py/greet.py` —
shortened to `greet.py` is fine). If the exit code is zero,
approve.

You MUST NOT attempt to execute `python -m ruff` yourself —
your VM image (`raxis-reviewer-core`) has no shell, no
language runtimes, and no `git`. Use `read_file` for the
captured artifact and `grep_search` / `read_file` for the diff
itself.

Reviewer B is the SLIGHTLY-LENIENT counterweight to Reviewer A:
cosmetic-only diagnostics (e.g. a stray trailing whitespace
that does NOT trip ruff's strict gate, or a `ruff format`
nit on a file that does NOT also trigger a `ruff check`
diagnostic) are NOT by themselves a reject. The substantive
line is "did the captured exit_code surface a real linter
ERROR against a target file". If yes, reject and name the
file; if no, approve. The aggregator marks the upstream
Executor pipeline `AllPassed` only when BOTH Reviewers
approve, which on the substantive path requires
`lint-runner-python` to land a corrected diff in response to
the Round-1 rejection.
"""

[[tasks]]
task_id            = "review-lint-defect-rust"
name               = "Reviewer — Rust lint-runner (single, rubber-stamp on clean)"
session_agent_type = "Reviewer"
predecessors       = ["lint-runner-rust"]
# Single-Reviewer fan-in for the Rust child (Option C). Same
# mechanical read_file + decide shape as the dual pair on
# lint-runner-python. With lint-defect pinned to Python the Rust
# capture is expected clean and this Reviewer is rubber-stamp;
# the budget headroom (30) is for the off-nominal case where
# the executor's capture wrapper itself misbehaves. Per
# `INV-PLANNER-MAX-TURNS-PRECEDENCE-01`.
max_turns          = 30
description = """
You are the sole Reviewer for the `lint-runner-rust` Executor.
The captured artifact at `out/lint/check-rust.txt` carries the
stdout + stderr of `cargo fmt --check` + `cargo clippy --all-targets
-- -D warnings`, terminated by `raxis_check_sh_exit_code=<n>`.

`read_file out/lint/check-rust.txt`; if the trailing exit code
is zero, submit `SubmitReview { approved = true }`. If it is
non-zero, submit `SubmitReview { approved = false }` with a
critique naming the file inside `rust-crate/` that the captured
output points at.

You MUST NOT attempt to execute `cargo` yourself — your VM
image ships only `raxis-planner` + `ripgrep` per
`INV-PLANNER-HARNESS-02`.
"""

[[tasks]]
task_id            = "review-lint-defect-js"
name               = "Reviewer — JS / TS lint-runner (single, rubber-stamp on clean)"
session_agent_type = "Reviewer"
predecessors       = ["lint-runner-js"]
# Single-Reviewer fan-in for the JS / TS child (Option C). Same
# mechanical read_file + decide shape. Per
# `INV-PLANNER-MAX-TURNS-PRECEDENCE-01`.
max_turns          = 30
description = """
You are the sole Reviewer for the `lint-runner-js` Executor.
The captured artifact at `out/lint/check-js.txt` carries the
stdout + stderr of `npx eslint --max-warnings 0` + `prettier
--check` + `tsc --noEmit`, terminated by
`raxis_check_sh_exit_code=<n>`.

`read_file out/lint/check-js.txt`; if the trailing exit code is
zero, submit `SubmitReview { approved = true }`. If it is
non-zero, submit `SubmitReview { approved = false }` with a
critique naming the file inside `ts-pkg/` that the captured
output points at.

You MUST NOT attempt to execute `npx` / `tsc` yourself — your
VM image ships only `raxis-planner` + `ripgrep` per
`INV-PLANNER-HARNESS-02`.
"""

"#;

const REALISTIC_PLAN_ALLOWLIST_POSITIVE_HEAD: &str = r#"# ── Positive path-allowlist Executor (P3-4) ─────────────
[[tasks]]
task_id            = "allowlist-positive-codegen"
name               = "Generate a build-meta file into target/codegen/"
session_agent_type = "Executor"
# Trivial single-file generation task; write build_meta.txt under the
# allowlisted path, commit. ~5 turns natural; iter55 budget audit
# bumps the ceiling 15 → 25 for retry headroom (the `-f` flag on
# `git add` against the `target/` gitignore entry is a common
# misremember that costs one cycle to recover). Per
# `INV-PLANNER-MAX-TURNS-PRECEDENCE-01`.
max_turns          = 25
path_allowlist     = ["target/codegen/"]
description = """
"#;

const REALISTIC_PLAN_SERVICE_ROUND_TRIP_HEAD: &str = r#"# -- Service-evidence round-trip Executor (P3-9) ----------
[[tasks]]
task_id            = "service-round-trip"
name               = "Round-trip every credential-proxy upstream + commit per-service canonical outputs"
session_agent_type = "Executor"
predecessors       = ["allowlist-positive-codegen"]
# Round-trip 4 service proxies (postgres + mongodb + redis + smtp) and
# commit one canonical output file per service. ~12 turns per service
# (auth + query + format + write) × 4 = ~48; 60 gives headroom for
# auth retry on the historically-flaky SMTP path (iter34 root cause).
# Per `INV-PLANNER-MAX-TURNS-PRECEDENCE-01`.
max_turns          = 60
path_allowlist     = ["out/services/"]
description = """
"#;

// `upstream_host_port` for the redis + smtp variants is mandatory in
// `raxis-plan-credentials::ProxyDecl::{Redis, Smtp}`; the values
// pin to `live-e2e/docker-compose.extended.e2e.yml`'s loopback bindings
// (mirrored as constants in `extended_e2e_support::service_evidence::SE_*`).
const REALISTIC_PLAN_SERVICE_ROUND_TRIP_CREDS: &str = r#"
  [[tasks.credentials]]
  name       = "test-pg-dev"
  proxy_type = "postgres"
  mount_as   = "DATABASE_URL"

  [[tasks.credentials]]
  name       = "test-mongo-dev"
  proxy_type = "mongodb"
  mount_as   = "MONGO_URL"

  [[tasks.credentials]]
  name               = "test-redis-dev"
  proxy_type         = "redis"
  mount_as           = "REDIS_URL"
  upstream_host_port = "127.0.0.1:63799"

  [[tasks.credentials]]
  name               = "test-smtp-dev"
  proxy_type         = "smtp"
  mount_as           = "SMTP_URL"
  upstream_host_port = "127.0.0.1:25199"

    # `auth_mode.user` MUST match the SASL username configured in
    # `live-e2e/seed/smtp/postfix-accounts.cf`
    # (`raxis-tenant@live-e2e.test`). Without it the proxy's
    # `drive_auth_through_quit` synthesises
    # `AUTH PLAIN base64("\0\0<password>")` (empty user), the
    # docker-mailserver SASL daemon (`saslauthd`) rejects it with
    # `535 5.7.8 Error: authentication failed`, and the executor
    # task fails with `451 4.4.0 upstream relay failed`
    # (live-e2e iter34 root cause).
    [tasks.credentials.auth_mode]
    kind = "plain"
    user = "raxis-tenant@live-e2e.test""#;

const REALISTIC_PLAN_TRANSPARENT_PROXY_HEAD: &str = r#"# -- Transparent-proxy real-scripts Executor (P3-10) ------
[[tasks]]
task_id            = "transparent-proxy-realscripts"
name               = "Run stock-Python service-integrity scripts; commit per-service outputs"
session_agent_type = "Executor"
predecessors       = ["service-round-trip"]
# Run 4 stock-Python service-integrity scripts + the run_all_services.sh
# wrapper, commit per-service outputs + last_run_summary.txt. ~10 turns
# per script × 4 = ~40 + summary write + retry headroom = 60.
# Per `INV-PLANNER-MAX-TURNS-PRECEDENCE-01`.
max_turns          = 60
path_allowlist     = ["out/services/", "scripts/last_run_summary.txt"]
description = """
"#;

// `upstream_host_port` mirrors `REALISTIC_PLAN_SERVICE_ROUND_TRIP_CREDS`.
const REALISTIC_PLAN_TRANSPARENT_PROXY_CREDS: &str = r#"
  [[tasks.credentials]]
  name       = "test-pg-dev"
  proxy_type = "postgres"
  mount_as   = "DATABASE_URL"

  [[tasks.credentials]]
  name       = "test-mongo-dev"
  proxy_type = "mongodb"
  mount_as   = "MONGO_URL"

  [[tasks.credentials]]
  name               = "test-redis-dev"
  proxy_type         = "redis"
  mount_as           = "REDIS_URL"
  upstream_host_port = "127.0.0.1:63799"

  [[tasks.credentials]]
  name               = "test-smtp-dev"
  proxy_type         = "smtp"
  mount_as           = "SMTP_URL"
  upstream_host_port = "127.0.0.1:25199"

    # See `REALISTIC_PLAN_SERVICE_ROUND_TRIP_CREDS` for the
    # iter34 rationale: empty SMTP user trips
    # `535 5.7.8 Error: authentication failed` upstream.
    [tasks.credentials.auth_mode]
    kind = "plain"
    user = "raxis-tenant@live-e2e.test""#;

/// Credential-substitution-canary executor task block. Runs last in
/// the dependency graph, predecessors include the upstream
/// transparent-proxy task so the seeded `service_evidence` table is
/// fully populated by the time this task wakes up. The test driver
/// stages a bait `.env` file into this task's worktree before the
/// executor's first IntentAccepted{CommitDelta} lands; the prompt
/// instructs the executor to authenticate using those fake creds
/// against `$DATABASE_URL`.
///
/// `path_allowlist` admits exactly the substituted-creds output
/// file. The credential mount is the same `test-pg-dev` postgres
/// credential the upstream tasks use — what the test exercises is
/// the proxy's substitution discipline, not a fresh credential.
const REALISTIC_PLAN_CREDENTIAL_SUBSTITUTION_HEAD: &str = r#"# -- Credential-substitution canary Executor --------------
[[tasks]]
task_id            = "credential-substitution-canary"
name               = "Authenticate via operator-staged FAKE .env creds; proxy substitutes real creds upstream"
session_agent_type = "Executor"
predecessors       = ["service-round-trip"]
# Multi-step task: parse .env for DATABASE_USER/PASSWORD/NAME, parse
# host:port from $DATABASE_URL, open a psycopg2 connection through
# the substituting proxy, SELECT, format pipe-delimited output,
# write to out/services/postgres-fake-creds.txt, git add, commit.
# ~10 turns natural; iter55 budget audit bumps the ceiling 25 → 40
# for headroom on first-pass auth retry + the URL-parsing
# variant where `urlparse` returns None for the port and the
# planner has to default to 5432. Per
# `INV-PLANNER-MAX-TURNS-PRECEDENCE-01`.
max_turns          = 40
path_allowlist     = ["out/services/postgres-fake-creds.txt"]
description = """
"#;

const REALISTIC_PLAN_CREDENTIAL_SUBSTITUTION_CREDS: &str = r#"
  [[tasks.credentials]]
  name       = "test-pg-dev"
  proxy_type = "postgres"
  mount_as   = "DATABASE_URL""#;

// -- Dep-fetch-evidence Executor (mediated egress, iter65) ------
//
// First end-to-end exercise of Path A3 from inside a real executor
// agent: one `python3 http.client` HTTPS GET to the IANA-reserved
// `example.com` page (stable across years, public DNS, deterministic
// substring `Example Domain` in the body), then commit a small JSON
// evidence file. No package manager, no second host, no retry loop.
//
// `path_allowlist` is tight (`out/deps/`) so a leaky implementation
// that writes anywhere else will trip
// `FAIL_TASK_PATH_NOT_ALLOWED` and the witness will see the chain
// admission go missing.
//
// **Budget sizing (iter69 — supersedes the pre-iter69 30-turn
// ceiling).** The prompt grew an additional `pip install certifi
// --report` arm on top of the original `example.com` HTTPS GET so
// the witness can verify the full multi-host PyPI flow
// (`pypi.org` index lookup + `files.pythonhosted.org` wheel
// fetch) end-to-end. Natural turn budget under the new prompt:
//
//   mkdir                              1
//   python3 http.client GET → partial  1
//   python3 -m pip install certifi     1   (multi-second, network)
//   python3 merge partial + report     1
//   cat verify                         1
//   git add                            1
//   git commit                         1
//   task_complete                      1
//                                      = 8 happy-path turns
//
// Real planners burn additional turns on `ls`/`cat` verification
// checkpoints, on re-reading the partial JSON before merge, and
// on parsing pip output if the first install hits a transient
// PyPI 5xx (we observed iter69 attempt-1 exhaust 30 turns
// without ever reaching task_complete — that surfaced as a
// `MaxTurnsReached{used:30,limit:30}` premature-exit + a
// crash-retry cycle). 90 gives ~11× the natural ceiling on the
// happy path and ~2× headroom on a retry-heavy path, in line
// with `materialize-records` (150) and `service-round-trip` /
// `transparent-proxy-realscripts` (60 each, but those don't pip
// install). Per `INV-PLANNER-MAX-TURNS-PRECEDENCE-01`; the
// kernel-side `INV-PLANNER-MAX-TURNS-PROGRESSIVE-ON-RETRY-01`
// elasticates further on retry (attempt 2 → 135, attempt 3 →
// 180, both ≤ the 240 hard ceiling).
//
// `predecessors` is intentionally empty: the dep-fetch task is
// independent of the other realism workloads, so it can run in
// parallel with `materialize-records` / `xfile-refactor` and
// surface egress wiring breakage early (failing this task does
// NOT block the rest of the plan; the witness fires terminally
// at the end of the run alongside the other global witnesses).
const REALISTIC_PLAN_DEP_FETCH_EVIDENCE_HEAD: &str = r#"# -- Dep-fetch-evidence Executor (Path A3 mediated egress) ----
[[tasks]]
task_id            = "dep-fetch-evidence"
name               = "Fetch example.com over HTTPS + pip install certifi from PyPI (Path A3 mediated egress)"
session_agent_type = "Executor"
# iter69 — bumped from 30 → 90 to absorb the additional pip
# install arm (multi-host: pypi.org → files.pythonhosted.org).
# Happy path is ~8 turns; the 11× headroom covers planner
# verification checkpoints + a single transient PyPI retry. Per
# `INV-PLANNER-MAX-TURNS-PRECEDENCE-01`.
max_turns          = 90
path_allowlist     = ["out/deps/"]
description = """
"#;

// ---------------------------------------------------------------------------
// Tests — sanity-check the TOML decodes and pins the task list.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn realistic_toml_decodes_and_carries_executors() {
        let toml_text = realistic_plan_toml();
        let v: toml::Value = toml::from_str(&toml_text).expect("realistic plan must be valid TOML");
        let tasks = v
            .get("tasks")
            .and_then(|t| t.as_array())
            .expect("[[tasks]] array present");
        let ids: Vec<&str> = tasks
            .iter()
            .filter_map(|t| t.get("task_id").and_then(|i| i.as_str()))
            .collect();
        for needle in [
            TASK_MATERIALIZE,
            TASK_XFILE_REFACTOR,
            TASK_LINT_DEFECT,
            TASK_LINT_RUNNER_PYTHON,
            TASK_LINT_RUNNER_RUST,
            TASK_LINT_RUNNER_JS,
            TASK_REVIEW_LINT_A,
            TASK_REVIEW_LINT_B,
            TASK_REVIEW_LINT_RUST,
            TASK_REVIEW_LINT_JS,
            TASK_ALLOWLIST_POSITIVE,
            TASK_SERVICE_ROUND_TRIP,
            TASK_TRANSPARENT_PROXY_REALSCRIPTS,
            TASK_CREDENTIAL_SUBSTITUTION_CANARY,
            TASK_DEP_FETCH_EVIDENCE,
        ] {
            assert!(
                ids.contains(&needle),
                "expected task_id `{needle}` in realistic plan; got {ids:?}",
            );
        }

        // Iter55 — the monolithic `lint-runner` must be GONE (the
        // per-language split replaces it). A regression that
        // reintroduces it would re-create the iter54 over-broad-budget
        // failure mode the split was designed to eliminate.
        assert!(
            !ids.contains(&"lint-runner"),
            "monolithic `lint-runner` MUST NOT appear after the iter55 \
             per-language split; got {ids:?}",
        );

        let lane = v
            .get("workspace")
            .and_then(|w| w.get("lane_id"))
            .and_then(|l| l.as_str());
        assert_eq!(lane, Some(LANE_ID));
    }

    #[test]
    fn xfile_refactor_prompt_mentions_all_three_languages() {
        let prompt = XFILE_REFACTOR_PROMPT_MD;
        for needle in ["Rust", "TypeScript", "Python"] {
            assert!(
                prompt.contains(needle),
                "xfile-refactor prompt must mention {needle} (got len={})",
                prompt.len(),
            );
        }
    }

    /// Iter55: the lint-defect prompt is PINNED to the Python
    /// target so the dual-Reviewer pair on `lint-runner-python`
    /// fires the substantive-disagreement scenario
    /// deterministically. The Rust and TS options have been
    /// removed (per-language children only see their own
    /// language's lint — see `TASK_LINT_RUNNER_PYTHON` docstring).
    #[test]
    fn lint_defect_prompt_is_pinned_to_python_only() {
        let prompt = LINT_DEFECT_PROMPT_MD;
        // The Python tooling reference MUST remain — Reviewers
        // and the witness ground on `ruff` + `greet.py`.
        for needle in ["ruff", "greet.py", "F401"] {
            assert!(
                prompt.contains(needle),
                "pinned lint-defect prompt must reference `{needle}` \
                 (got len={})",
                prompt.len(),
            );
        }
        // The Rust / TS options MUST NOT be offered as a "pick
        // one" choice anymore — keeping them as available defects
        // would let the planner pick a language whose per-language
        // child carries only a single rubber-stamp Reviewer, and
        // the substantive-disagreement witness would never fire
        // (the dual pair lives on `lint-runner-python` only).
        assert!(
            !prompt.contains("Pick exactly ONE"),
            "iter55 pinned lint-defect prompt MUST NOT offer a \
             multi-language pick; got prompt of len {}",
            prompt.len(),
        );
    }

    /// Iter55 — pins the per-language split: three Executor
    /// children (`lint-runner-python`, `-rust`, `-js`), each
    /// scoped to one language tree, with dual Reviewers on the
    /// Python child (substantive-disagreement scenario) and
    /// single Reviewers on the Rust + JS children (Option C
    /// fan-in). The Reviewer VM image (`raxis-reviewer-core`)
    /// is still barred from executing language linters
    /// (`INV-PLANNER-HARNESS-02`); each per-language Executor
    /// runs its own lint stack in-image and commits a dedicated
    /// capture file the Reviewer reads via `read_file`. The
    /// witness in [`super::reviewer_substantive_disagreement`]
    /// tracks `ExecutorRespawnFromReviewRejection { task_id =
    /// "lint-runner-python" }` per the kernel's reverse-DAG
    /// resolution in `handle_activate_sub_task`.
    #[test]
    fn lint_runners_bridge_lint_defect_and_reviewers() {
        let toml_text = realistic_plan_toml();
        let v: toml::Value = toml::from_str(&toml_text).unwrap();
        let tasks = v
            .get("tasks")
            .and_then(|t| t.as_array())
            .expect("[[tasks]] array present");

        // Per-child structural checks: each child is an Executor,
        // depends on lint-defect, admits out/lint/ + its OWN
        // language tree only, and carries the expected reviewer
        // fan-in shape (dual for python, single for rust / js).
        let cases: &[(&str, &str, &[&str], &[&str])] = &[
            (
                TASK_LINT_RUNNER_PYTHON,
                "out/lint/check-python.txt",
                &["out/lint/", "py-pkg/"],
                &[TASK_REVIEW_LINT_A, TASK_REVIEW_LINT_B],
            ),
            (
                TASK_LINT_RUNNER_RUST,
                "out/lint/check-rust.txt",
                // `Cargo.lock` is admitted alongside `rust-crate/`
                // because the workspace cargo invocations rewrite the
                // lockfile at the worktree root on every `cargo fmt
                // --check` / `cargo clippy` invocation; the fixture
                // (search "Cargo.lock MUST be in this allowlist")
                // documents the rationale.
                &["out/lint/", "rust-crate/", "Cargo.lock"],
                &[TASK_REVIEW_LINT_RUST],
            ),
            (
                TASK_LINT_RUNNER_JS,
                "out/lint/check-js.txt",
                &["out/lint/", "ts-pkg/"],
                &[TASK_REVIEW_LINT_JS],
            ),
        ];
        for (runner_id, capture_path, expected_allowlist, reviewer_ids) in cases {
            let runner = tasks
                .iter()
                .find(|t| t.get("task_id").and_then(|i| i.as_str()) == Some(*runner_id))
                .unwrap_or_else(|| panic!("`{runner_id}` task present"));

            assert_eq!(
                runner.get("session_agent_type").and_then(|s| s.as_str()),
                Some("Executor"),
                "`{runner_id}` MUST be an Executor — the whole point of \
                 the iter55 split is that the Reviewer VM image cannot \
                 execute language linters (INV-PLANNER-HARNESS-02)",
            );

            let preds: Vec<&str> = runner
                .get("predecessors")
                .and_then(|p| p.as_array())
                .unwrap_or_else(|| panic!("`{runner_id}`.predecessors array"))
                .iter()
                .filter_map(|v| v.as_str())
                .collect();
            assert!(
                preds.contains(&TASK_LINT_DEFECT),
                "`{runner_id}` must depend on lint-defect; got {preds:?}",
            );

            let allowlist: Vec<&str> = runner
                .get("path_allowlist")
                .and_then(|a| a.as_array())
                .unwrap_or_else(|| panic!("`{runner_id}`.path_allowlist present"))
                .iter()
                .filter_map(|v| v.as_str())
                .collect();
            assert_eq!(
                &allowlist[..],
                *expected_allowlist,
                "`{runner_id}`.path_allowlist MUST be scoped to ONE language \
                 + out/lint/ (iter55 per-language split); got {allowlist:?}",
            );

            // Prompt must reference the per-child capture path.
            let desc = runner
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or_else(|| panic!("`{runner_id}` description present"));
            assert!(
                desc.contains(capture_path),
                "`{runner_id}` prompt MUST reference its capture path \
                 `{capture_path}` verbatim; got desc of len {}",
                desc.len(),
            );

            // Reviewer fan-in.
            for reviewer_task_id in reviewer_ids.iter() {
                let reviewer = tasks
                    .iter()
                    .find(|t| t.get("task_id").and_then(|i| i.as_str()) == Some(*reviewer_task_id))
                    .unwrap_or_else(|| panic!("reviewer task `{reviewer_task_id}` present"));
                let rev_preds: Vec<&str> = reviewer
                    .get("predecessors")
                    .and_then(|p| p.as_array())
                    .unwrap_or_else(|| panic!("`{reviewer_task_id}`.predecessors array"))
                    .iter()
                    .filter_map(|v| v.as_str())
                    .collect();
                assert_eq!(
                    rev_preds,
                    vec![*runner_id],
                    "`{reviewer_task_id}` MUST depend on `{runner_id}` so the \
                     kernel's reverse-DAG evaluation_sha resolution \
                     returns the SHA carrying `{capture_path}`; got {rev_preds:?}",
                );
            }
        }
    }

    /// Reviewer prompts MUST point at their child's per-language
    /// captured artifact, NOT at the OLD monolithic
    /// `out/lint/check-output.txt` path (gone since iter55).
    /// They MUST NOT instruct the planner to execute language
    /// linters — the Reviewer VM image (`raxis-reviewer-core`)
    /// has no shell or runtimes per `INV-PLANNER-HARNESS-02`.
    #[test]
    fn reviewer_prompts_point_at_captured_artifact_not_script_execution() {
        let toml_text = realistic_plan_toml();
        let v: toml::Value = toml::from_str(&toml_text).unwrap();
        let tasks = v
            .get("tasks")
            .and_then(|t| t.as_array())
            .expect("[[tasks]] array present");

        let cases: &[(&str, &str)] = &[
            (TASK_REVIEW_LINT_A, "out/lint/check-python.txt"),
            (TASK_REVIEW_LINT_B, "out/lint/check-python.txt"),
            (TASK_REVIEW_LINT_RUST, "out/lint/check-rust.txt"),
            (TASK_REVIEW_LINT_JS, "out/lint/check-js.txt"),
        ];
        for (reviewer_task_id, capture_path) in cases {
            let reviewer = tasks
                .iter()
                .find(|t| t.get("task_id").and_then(|i| i.as_str()) == Some(*reviewer_task_id))
                .unwrap_or_else(|| panic!("reviewer task `{reviewer_task_id}` present"));
            let desc = reviewer
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or_else(|| panic!("`{reviewer_task_id}` description present"));

            assert!(
                desc.contains(capture_path),
                "`{reviewer_task_id}` prompt MUST reference the \
                 per-language captured artifact `{capture_path}` verbatim \
                 — that's the only path the Reviewer's read_file can \
                 target; got prompt of len {}",
                desc.len(),
            );
            assert!(
                !desc.contains("run `scripts/check.sh`") && !desc.contains("run scripts/check.sh"),
                "`{reviewer_task_id}` prompt MUST NOT tell the Reviewer \
                 to run scripts/check.sh — the Reviewer VM image \
                 (raxis-reviewer-core) ships only raxis-planner + ripgrep \
                 per INV-PLANNER-HARNESS-02; prompt leak found",
            );
            // The old monolithic capture path is GONE after the iter55
            // split — guard against a regression that drops back to
            // it on any per-language Reviewer.
            assert!(
                !desc.contains("out/lint/check-output.txt"),
                "`{reviewer_task_id}` prompt MUST NOT reference the OLD \
                 monolithic capture path `out/lint/check-output.txt` \
                 (gone since iter55 per-language split)",
            );
        }
    }

    #[test]
    fn lint_defect_task_depends_on_xfile_refactor() {
        let toml_text = realistic_plan_toml();
        let v: toml::Value = toml::from_str(&toml_text).unwrap();
        let tasks = v
            .get("tasks")
            .and_then(|t| t.as_array())
            .expect("[[tasks]] array present");
        let lint = tasks
            .iter()
            .find(|t| t.get("task_id").and_then(|i| i.as_str()) == Some(TASK_LINT_DEFECT))
            .expect("lint-defect task present");
        let predecessors = lint
            .get("predecessors")
            .and_then(|p| p.as_array())
            .expect("lint-defect.predecessors array");
        let names: Vec<&str> = predecessors.iter().filter_map(|v| v.as_str()).collect();
        assert!(
            names.contains(&TASK_XFILE_REFACTOR),
            "lint-defect must depend on xfile-refactor; got {names:?}",
        );
    }
    #[test]
    fn service_round_trip_task_carries_all_required_credentials() {
        let toml_text = realistic_plan_toml();
        let v: toml::Value = toml::from_str(&toml_text)
            .expect("realistic plan must be valid TOML even with service-round-trip wired");
        let tasks = v
            .get("tasks")
            .and_then(|t| t.as_array())
            .expect("[[tasks]] array present");
        let srt = tasks
            .iter()
            .find(|t| t.get("task_id").and_then(|i| i.as_str()) == Some(TASK_SERVICE_ROUND_TRIP))
            .expect("service-round-trip task present");
        let allowlist = srt
            .get("path_allowlist")
            .and_then(|a| a.as_array())
            .expect("service-round-trip path_allowlist present");
        let paths: Vec<&str> = allowlist.iter().filter_map(|v| v.as_str()).collect();
        assert_eq!(
            paths,
            vec!["out/services/"],
            "service-round-trip must be scoped to out/services/ only",
        );
        let creds = srt
            .get("credentials")
            .and_then(|c| c.as_array())
            .expect("service-round-trip credentials present");
        let mounts: Vec<&str> = creds
            .iter()
            .filter_map(|c| c.get("mount_as").and_then(|m| m.as_str()))
            .collect();
        for needle in ["DATABASE_URL", "MONGO_URL", "REDIS_URL", "SMTP_URL"] {
            assert!(
                mounts.contains(&needle),
                "service-round-trip must mount {needle}; got {mounts:?}",
            );
        }
    }

    #[test]
    fn service_round_trip_prompt_lists_every_in_scope_service() {
        let prompt = SERVICE_ROUND_TRIP_PROMPT_MD;
        for needle in [
            "out/services/postgres.txt",
            "out/services/mongodb.txt",
            "out/services/redis.txt",
            "out/services/smtp.txt",
            "pg_seed_row_1",
            "mongo_seed_doc_1",
            "redis_seed_key_1",
            "smtp_seed_subject_1",
        ] {
            assert!(
                prompt.contains(needle),
                "service-round-trip prompt must mention `{needle}` (len={})",
                prompt.len(),
            );
        }
    }

    #[test]
    fn transparent_proxy_task_runs_after_service_round_trip() {
        let toml_text = realistic_plan_toml();
        let v: toml::Value = toml::from_str(&toml_text)
            .expect("realistic plan must be valid TOML with transparent-proxy task wired");
        let tasks = v
            .get("tasks")
            .and_then(|t| t.as_array())
            .expect("[[tasks]] array present");
        let tp = tasks
            .iter()
            .find(|t| {
                t.get("task_id").and_then(|i| i.as_str())
                    == Some(TASK_TRANSPARENT_PROXY_REALSCRIPTS)
            })
            .expect("transparent-proxy-realscripts task present");

        let predecessors = tp
            .get("predecessors")
            .and_then(|p| p.as_array())
            .expect("transparent-proxy-realscripts.predecessors array");
        let preds: Vec<&str> = predecessors.iter().filter_map(|v| v.as_str()).collect();
        assert!(
            preds.contains(&TASK_SERVICE_ROUND_TRIP),
            "transparent-proxy task must run AFTER service-round-trip; \
             got predecessors {preds:?}",
        );

        let allowlist = tp
            .get("path_allowlist")
            .and_then(|a| a.as_array())
            .expect("transparent-proxy-realscripts path_allowlist present");
        let paths: Vec<&str> = allowlist.iter().filter_map(|v| v.as_str()).collect();
        assert!(
            paths.contains(&"out/services/"),
            "transparent-proxy task must allow writes to out/services/; \
             got {paths:?}",
        );
        assert!(
            paths.contains(&"scripts/last_run_summary.txt"),
            "transparent-proxy task must allow writing scripts/last_run_summary.txt; \
             got {paths:?}",
        );

        let creds = tp
            .get("credentials")
            .and_then(|c| c.as_array())
            .expect("transparent-proxy-realscripts credentials present");
        let mounts: Vec<&str> = creds
            .iter()
            .filter_map(|c| c.get("mount_as").and_then(|m| m.as_str()))
            .collect();
        for needle in ["DATABASE_URL", "MONGO_URL", "REDIS_URL", "SMTP_URL"] {
            assert!(
                mounts.contains(&needle),
                "transparent-proxy task must mount {needle} via the proxy; \
                 got {mounts:?}",
            );
        }
    }

    #[test]
    fn transparent_proxy_prompt_is_operator_realistic() {
        // The whole point of this validation tier is "operator
        // writes a normal Python script with no awareness of
        // raxis." The prompt for this task must therefore not
        // leak raxis-internal vocabulary; the witness in
        // `transparent_proxy_evidence` keys on this property.
        let prompt = TRANSPARENT_PROXY_REALSCRIPTS_PROMPT_MD;
        let forbidden = ["raxis", "credential proxy", "loopback", "tproxy"];
        for word in forbidden {
            assert!(
                !prompt.to_lowercase().contains(word),
                "transparent-proxy prompt MUST NOT mention `{word}` \
                 (operator-realistic phrasing); leak found in prompt",
            );
        }
        // Positive checks — the prompt should clearly point at the
        // scripts directory and the per-service output convention.
        for needle in [
            "scripts/",
            "out/services/",
            "last_run_summary.txt",
            "check_postgres.py",
        ] {
            assert!(
                prompt.contains(needle),
                "transparent-proxy prompt must mention `{needle}` (len={})",
                prompt.len(),
            );
        }
    }
}
