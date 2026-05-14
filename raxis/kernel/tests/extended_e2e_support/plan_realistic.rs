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

/// Lint-runner executor task id — captures `scripts/check.sh`
/// stdout/stderr/exit_code into `out/lint/check-output.txt` and
/// commits it for the downstream Reviewer panel. The Reviewer's
/// `raxis-reviewer-core` VM image ships only `raxis-planner` and
/// `ripgrep` (`INV-PLANNER-HARNESS-02`, `planner-harness.md
/// §4.5`); execution of any script — `scripts/check.sh` included
/// — is structurally impossible from inside the Reviewer harness.
/// This task is the in-image execution stage so the Reviewer's
/// rule-on-the-diff step can stay read-only.
///
/// The Reviewer also gets respawned via this task on rejection
/// (the kernel's `INV-RETRY-FROM-COMPLETED-REVIEW-REJECTED-01`
/// anchor lands on the reviewer's immediate Executor predecessor
/// — which is `lint-runner`, not `lint-defect`). The task's
/// `path_allowlist` therefore covers BOTH `out/lint/` (the
/// capture file) AND the three language source trees, so the
/// Round-2 re-spawn driven by a substantive Reviewer critique can
/// land a corrected diff. See [`super::reviewer_substantive_disagreement`]
/// for the witness shape the round-2 path satisfies.
pub const TASK_LINT_RUNNER: &str = "lint-runner";

/// Positive path-allowlist executor task id (P3-4) — the
/// executor legitimately writes to `target/codegen/` under an
/// allowlist that admits exactly that path. Witness asserts both
/// (a) the chain admitted the commit AND (b) the file landed on
/// disk AND (c) the path-allowlist did not falsely reject the
/// task. See [`super::path_allowlist::PathAllowlistPositiveWitness`].
pub const TASK_ALLOWLIST_POSITIVE: &str =
    super::path_allowlist::TASK_ALLOWLIST_POSITIVE;

/// Service-evidence round-trip executor task id -- exercises the
/// per-protocol credential proxies against the real backing
/// services (postgres / mongodb / redis / smtp; mysql / mssql
/// opt-in via `RAXIS_LIVE_MYSQL_URL` / `RAXIS_LIVE_MSSQL_URL`)
/// and commits the per-service canonical output files under
/// `out/services/`. Witness lives in
/// [`super::service_evidence`].
pub const TASK_SERVICE_ROUND_TRIP: &str =
    super::service_evidence::TASK_SERVICE_ROUND_TRIP;

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

/// Lint-defect reviewer task ids (P3-7). Plain-prompted reviewers
/// (no directive) whose substantive critique must name one of the
/// lint-defect target files. Witness:
/// [`super::reviewer_substantive_disagreement::ReviewerSubstantiveDisagreementWitness`].
pub const TASK_REVIEW_LINT_A: &str =
    super::reviewer_substantive_disagreement::TASK_REVIEW_LINT_A;
pub const TASK_REVIEW_LINT_B: &str =
    super::reviewer_substantive_disagreement::TASK_REVIEW_LINT_B;

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
pub const XFILE_REFACTOR_PROMPT_MD: &str = include_str!(
    "../../../live-e2e/seed/prompts/cross_file_refactor.md"
);

/// Lint-defect prompt. Drives the executor through introducing
/// exactly one real lint defect that the reviewer must catch on
/// round 1.
pub const LINT_DEFECT_PROMPT_MD: &str = include_str!(
    "../../../live-e2e/seed/prompts/lint_defect.md"
);

/// Positive path-allowlist prompt. Drives the executor through
/// writing `target/codegen/build_meta.txt` under an allowlist
/// that admits only `target/codegen/`.
pub const ALLOWLIST_POSITIVE_PROMPT_MD: &str = include_str!(
    "../../../live-e2e/seed/prompts/allowlist_positive.md"
);

/// Service-evidence round-trip prompt. Drives the executor
/// through reading the per-service seed via each credential proxy
/// and writing one canonical-form file per service into
/// `out/services/`. See [`super::service_evidence`] for the
/// canonical-bytes formulas the witness recomputes.
pub const SERVICE_ROUND_TRIP_PROMPT_MD: &str = include_str!(
    "../../../live-e2e/seed/prompts/service_round_trip.md"
);

/// Transparent-proxy real-scripts prompt. Operator-realistic
/// phrasing — does NOT mention raxis or "credential proxy". The
/// witness in [`super::transparent_proxy_evidence`] asserts the
/// prompt does not leak.
pub const TRANSPARENT_PROXY_REALSCRIPTS_PROMPT_MD: &str = include_str!(
    "../../../live-e2e/seed/prompts/transparent_proxy_real_scripts.md"
);

/// Credential-substitution-canary prompt. Operator-realistic — the
/// agent is told the staged `.env` carries production credentials,
/// and is instructed to use them via `$DATABASE_URL`. The proxy
/// substitutes the real credentials transparently; the witness
/// verifies the structural property mechanically.
pub const CREDENTIAL_SUBSTITUTION_CANARY_PROMPT_MD: &str = include_str!(
    "../../../live-e2e/seed/prompts/credential_substitution_canary.md"
);

// ---------------------------------------------------------------------------
// Plan-TOML builder.
// ---------------------------------------------------------------------------

/// Build the realistic-scenario `[plan]` TOML body the test
/// submits via `OperatorIpc::submit_plan`. The current shape
/// includes `materialize-records` + `xfile-refactor`; subsequent
/// commits on this branch extend it.
pub fn realistic_plan_toml() -> String {
    let materializer    = MATERIALIZER_PROMPT_MD;
    let xfile           = XFILE_REFACTOR_PROMPT_MD;
    let lint            = LINT_DEFECT_PROMPT_MD;
    let allowlist       = ALLOWLIST_POSITIVE_PROMPT_MD;
    let service_rt      = SERVICE_ROUND_TRIP_PROMPT_MD;
    let transparent_rt  = TRANSPARENT_PROXY_REALSCRIPTS_PROMPT_MD;
    let cred_sub        = CREDENTIAL_SUBSTITUTION_CANARY_PROMPT_MD;
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
    s.push_str(REALISTIC_PLAN_LINT_RUNNER);
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
path_allowlist     = ["rust-crate/", "ts-pkg/", "py-pkg/"]
description = """
"#;

const REALISTIC_PLAN_LINT_DEFECT_HEAD: &str = r#"# ── Lint-defect Executor (P3-3) ─────────────────────────
[[tasks]]
task_id            = "lint-defect"
name               = "Introduce exactly one real lint defect"
session_agent_type = "Executor"
predecessors       = ["xfile-refactor"]
path_allowlist     = ["rust-crate/", "ts-pkg/", "py-pkg/"]
description = """
"#;

// ── Lint-runner Executor (captures scripts/check.sh output) ──
//
// Inserted between `lint-defect` and the two substantive
// Reviewers so the Reviewer panel reads a captured artifact
// rather than attempting in-VM script execution: the Reviewer
// VM image (`raxis-reviewer-core`) ships only `raxis-planner`
// and `ripgrep` per `INV-PLANNER-HARNESS-02`
// (`specs/v2/planner-harness.md §4.5`) — no `bash`, no
// `cargo`, no `npx`, no `python`. Telling the Reviewer to
// "run scripts/check.sh" instructs a behavior the architecture
// forbids; the captured-output handoff is the only coherent
// alternative.
//
// `path_allowlist` admits BOTH the capture path (`out/lint/`)
// AND the three language source trees. The defect-bearing diff
// lives upstream on `lint-defect`'s commit; on a Reviewer
// rejection the kernel's
// `ExecutorRespawnFromReviewRejection` anchor fires for the
// Reviewer's *immediate* Executor predecessor (this task), so
// the Round-2 path that responds to the critique by editing
// the defective file must land HERE. The witness in
// [`super::reviewer_substantive_disagreement`] tracks
// `lint-runner` for that reason.
const REALISTIC_PLAN_LINT_RUNNER: &str = r#"# ── Lint-runner Executor (captures check.sh output) ─────
[[tasks]]
task_id            = "lint-runner"
name               = "Capture scripts/check.sh output for the Reviewer panel"
session_agent_type = "Executor"
predecessors       = ["lint-defect"]
path_allowlist     = ["out/lint/", "rust-crate/", "ts-pkg/", "py-pkg/"]
description = """
You are the RAXIS lint-runner executor. The diff from
`lint-defect` is already committed on the working branch; your
job is to surface its strict-lint verdict to the downstream
Reviewer panel.

The Reviewer VM image (`raxis-reviewer-core`) is structurally
forbidden from executing scripts: it ships ONLY `raxis-planner`
and `ripgrep` per `INV-PLANNER-HARNESS-02` (no shell, no
language runtimes, no `git`, no network utilities). The
Reviewers therefore cannot run `scripts/check.sh` themselves —
they read its captured output from a committed artifact you
produce here.

## Round 1 — capture

1. Create the capture directory: `mkdir -p out/lint`.
2. Run `scripts/check.sh` and capture stdout + stderr + the
   exit code in a single file:
   ```bash
   {
     bash scripts/check.sh 2>&1
     echo "raxis_check_sh_exit_code=$?"
   } > out/lint/check-output.txt
   ```
   The trailing `raxis_check_sh_exit_code=<n>` line is the
   wire signal the Reviewers key on; do NOT omit it. Use
   `bash scripts/check.sh` (not `./scripts/check.sh`) so the
   script's `set -euo pipefail` does not abort the wrapping
   shell when `check.sh` exits non-zero (which it WILL — the
   `lint-defect` task by construction introduced one real lint
   defect).
3. `git add out/lint/check-output.txt`
4. `git commit -m "chore: capture check.sh output for reviewer panel"`
5. Call `task_complete` with a one-line summary that includes
   the captured exit code.

## Round 2+ — substantive critique fix-up

If your prior round was rejected by the Reviewer panel, the
critique appended to your prompt names a specific defective
file (one of `rust-crate/src/greeting.rs`,
`ts-pkg/src/greet.ts`, `py-pkg/src/sample_py/greet.py`). Your
`path_allowlist` includes the three language source trees
precisely so you can land the fix on this round:

1. Edit the defective file to remove the lint diagnostic the
   critique names (e.g. drop a `useless_conversion`, restore
   `const`-over-`let`, remove an unused import).
2. Re-run the capture step above. `out/lint/check-output.txt`
   should now end with `raxis_check_sh_exit_code=0`.
3. `git add` the fixed file AND `out/lint/check-output.txt`.
4. `git commit -m "fix: <one-line lint repair> + refresh
   check-output capture"` (your commit message MAY name the
   defect on the fix round; the lint-defect's "no suggestive
   commit message" constraint applies only to its own commit).
5. `task_complete`.

## Constraints

* The capture MUST live at the exact path
  `out/lint/check-output.txt`. The Reviewer prompts hard-code
  that path; any other location is a witness failure.
* Do NOT modify `scripts/check.sh` itself, or any file outside
  the four allowed roots. Writes to `scripts/`, `fixtures/`,
  `.gitignore`, `README.md`, etc. trip
  `FailPathPolicyViolation` at `task_complete`.
* Do NOT swallow the failing exit code on Round 1. The whole
  point of the round is to surface the lint failure honestly
  — wrapping with `|| true` or stripping the exit-code tail
  defeats the Reviewer's substantive check.
"""

"#;

const REALISTIC_PLAN_LINT_REVIEWERS: &str = r#"# ── Lint-defect substantive Reviewers (P3-7) ────────────
[[tasks]]
task_id            = "review-lint-defect-A"
name               = "Reviewer A — substantive review of lint-defect diff"
session_agent_type = "Reviewer"
predecessors       = ["lint-runner"]
description = """
You are the FIRST Reviewer in a panel reviewing the rich-
multilang-001 lint-defect pipeline. The upstream `lint-defect`
Executor introduced exactly one real lint defect in one of:
  * `rust-crate/src/greeting.rs`  (clippy: `cargo clippy -- -D warnings`)
  * `ts-pkg/src/greet.ts`         (eslint: `npx eslint --max-warnings 0`)
  * `py-pkg/src/sample_py/greet.py` (ruff: `python -m ruff check`)
A single `scripts/check.sh` runs all three.

The `lint-runner` Executor has ALREADY committed
`out/lint/check-output.txt` containing the captured stdout +
stderr of `scripts/check.sh`, terminated by a sentinel line
`raxis_check_sh_exit_code=<n>` carrying the script's exit code.

Your job is mechanical: `read_file` the captured artifact,
observe the exit code, and rule on the diff. If the captured
`raxis_check_sh_exit_code` is non-zero, submit `SubmitReview`
with `approved = false` and a critique whose text NAMES the
file that produced the failing lint diagnostic (one of the
three listed above — the captured output names it verbatim).
If the captured exit code is zero, submit `SubmitReview` with
`approved = true`.

You MUST NOT attempt to execute `scripts/check.sh` yourself —
your VM image (`raxis-reviewer-core`) ships ONLY
`raxis-planner` and `ripgrep` per `INV-PLANNER-HARNESS-02`;
there is no shell, no `cargo`, no `npx`, no `python`. Use
`read_file` for `out/lint/check-output.txt` and any diff hunk
you want to confirm, and `grep_search` to locate the failing
file's mention inside the captured output.

As Reviewer A you take a STRICT stance on lint failures: any
non-zero exit code in the captured artifact is a hard reject
naming the specific failing file. Do NOT invent defects, do
NOT reject for vibes, do NOT cite a file that did not appear
in the captured output. The witness verifies the critique
mentions one of the three filenames verbatim.
"""

[[tasks]]
task_id            = "review-lint-defect-B"
name               = "Reviewer B — substantive review of lint-defect diff"
session_agent_type = "Reviewer"
predecessors       = ["lint-runner"]
description = """
You are the SECOND Reviewer in a panel reviewing the rich-
multilang-001 lint-defect pipeline. The `lint-runner` Executor
has committed `out/lint/check-output.txt` (stdout + stderr +
`raxis_check_sh_exit_code=<n>` sentinel) capturing the strict
output of `scripts/check.sh`.

Your job is mechanical: `read_file` the captured artifact,
observe the exit code, and rule on the diff. If
`raxis_check_sh_exit_code` is non-zero, submit `SubmitReview`
with `approved = false` and a critique whose text NAMES the
specific failing file (one of `rust-crate/src/greeting.rs`,
`ts-pkg/src/greet.ts`, `py-pkg/src/sample_py/greet.py`). If the
exit code is zero, approve.

You MUST NOT attempt to execute `scripts/check.sh` yourself —
your VM image (`raxis-reviewer-core`) has no shell, no
language runtimes, and no `git`. Use `read_file` for the
captured artifact and `grep_search` / `read_file` for the diff
itself.

Reviewer B is the SLIGHTLY-LENIENT counterweight to Reviewer A:
cosmetic-only diagnostics (e.g. a stray trailing whitespace
that does NOT trip the strict-warnings gate at `cargo clippy
-- -D warnings`, or a `prettier` whitespace nit on a file
that does NOT also trigger an eslint diagnostic) are NOT by
themselves a reject. The substantive line is "did the captured
exit_code surface a real linter ERROR against a target file".
If yes, reject and name the file; if no, approve. The
aggregator marks the upstream Executor pipeline `AllPassed`
only when BOTH Reviewers approve, which on the substantive
path requires `lint-runner` to land a corrected diff in
response to the Round-1 rejection.
"""

"#;

const REALISTIC_PLAN_ALLOWLIST_POSITIVE_HEAD: &str = r#"# ── Positive path-allowlist Executor (P3-4) ─────────────
[[tasks]]
task_id            = "allowlist-positive-codegen"
name               = "Generate a build-meta file into target/codegen/"
session_agent_type = "Executor"
path_allowlist     = ["target/codegen/"]
description = """
"#;

const REALISTIC_PLAN_SERVICE_ROUND_TRIP_HEAD: &str = r#"# -- Service-evidence round-trip Executor (P3-9) ----------
[[tasks]]
task_id            = "service-round-trip"
name               = "Round-trip every credential-proxy upstream + commit per-service canonical outputs"
session_agent_type = "Executor"
predecessors       = ["allowlist-positive-codegen"]
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
path_allowlist     = ["out/services/postgres-fake-creds.txt"]
description = """
"#;

const REALISTIC_PLAN_CREDENTIAL_SUBSTITUTION_CREDS: &str = r#"
  [[tasks.credentials]]
  name       = "test-pg-dev"
  proxy_type = "postgres"
  mount_as   = "DATABASE_URL""#;

// ---------------------------------------------------------------------------
// Tests — sanity-check the TOML decodes and pins the task list.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn realistic_toml_decodes_and_carries_executors() {
        let toml_text = realistic_plan_toml();
        let v: toml::Value =
            toml::from_str(&toml_text).expect("realistic plan must be valid TOML");
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
            TASK_LINT_RUNNER,
            TASK_REVIEW_LINT_A,
            TASK_REVIEW_LINT_B,
            TASK_ALLOWLIST_POSITIVE,
            TASK_SERVICE_ROUND_TRIP,
            TASK_TRANSPARENT_PROXY_REALSCRIPTS,
            TASK_CREDENTIAL_SUBSTITUTION_CANARY,
        ] {
            assert!(
                ids.contains(&needle),
                "expected task_id `{needle}` in realistic plan; got {ids:?}",
            );
        }

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

    #[test]
    fn lint_defect_prompt_lists_one_per_language() {
        let prompt = LINT_DEFECT_PROMPT_MD;
        for needle in ["clippy", "eslint", "ruff"] {
            assert!(
                prompt.contains(needle),
                "lint-defect prompt must reference {needle} (got len={})",
                prompt.len(),
            );
        }
    }

    /// Pins the in-image execution stage between `lint-defect`
    /// and the two substantive Reviewers: the Reviewer VM image
    /// (`raxis-reviewer-core`) is barred from executing
    /// `scripts/check.sh` (no `bash`, no language runtimes —
    /// `INV-PLANNER-HARNESS-02`); the Executor `lint-runner`
    /// runs the script in-image and commits the captured output
    /// for the Reviewers to read. The witness in
    /// [`super::reviewer_substantive_disagreement`] keys on the
    /// new task being the Reviewer's immediate predecessor (it
    /// tracks `ExecutorRespawnFromReviewRejection { task_id =
    /// "lint-runner" }` per the kernel's reverse-DAG resolution
    /// in `handle_activate_sub_task`'s reviewer evaluation_sha
    /// lookup).
    #[test]
    fn lint_runner_bridges_lint_defect_and_reviewers() {
        let toml_text = realistic_plan_toml();
        let v: toml::Value = toml::from_str(&toml_text).unwrap();
        let tasks = v
            .get("tasks")
            .and_then(|t| t.as_array())
            .expect("[[tasks]] array present");

        let runner = tasks
            .iter()
            .find(|t| {
                t.get("task_id").and_then(|i| i.as_str()) == Some(TASK_LINT_RUNNER)
            })
            .expect("lint-runner task present");

        assert_eq!(
            runner
                .get("session_agent_type")
                .and_then(|s| s.as_str()),
            Some("Executor"),
            "lint-runner MUST be an Executor — the whole point of \
             this task is that the Reviewer VM image cannot execute \
             scripts (INV-PLANNER-HARNESS-02)",
        );

        let runner_preds: Vec<&str> = runner
            .get("predecessors")
            .and_then(|p| p.as_array())
            .expect("lint-runner.predecessors array")
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(
            runner_preds.contains(&TASK_LINT_DEFECT),
            "lint-runner must depend on lint-defect; got {runner_preds:?}",
        );

        let runner_allowlist: Vec<&str> = runner
            .get("path_allowlist")
            .and_then(|a| a.as_array())
            .expect("lint-runner.path_allowlist present")
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(
            runner_allowlist.contains(&"out/lint/"),
            "lint-runner must admit out/lint/ for the capture file; \
             got {runner_allowlist:?}",
        );
        for tree in ["rust-crate/", "ts-pkg/", "py-pkg/"] {
            assert!(
                runner_allowlist.contains(&tree),
                "lint-runner must admit {tree} so the Round-2 \
                 re-spawn after a Reviewer rejection can land a \
                 corrected diff on the defective file (the witness \
                 in reviewer_substantive_disagreement.rs keys on \
                 AllPassed); got {runner_allowlist:?}",
            );
        }

        for reviewer_task_id in [TASK_REVIEW_LINT_A, TASK_REVIEW_LINT_B] {
            let reviewer = tasks
                .iter()
                .find(|t| {
                    t.get("task_id").and_then(|i| i.as_str())
                        == Some(reviewer_task_id)
                })
                .unwrap_or_else(|| {
                    panic!("reviewer task `{reviewer_task_id}` present")
                });
            let preds: Vec<&str> = reviewer
                .get("predecessors")
                .and_then(|p| p.as_array())
                .unwrap_or_else(|| {
                    panic!("{reviewer_task_id}.predecessors array")
                })
                .iter()
                .filter_map(|v| v.as_str())
                .collect();
            assert_eq!(
                preds,
                vec![TASK_LINT_RUNNER],
                "{reviewer_task_id} MUST depend on lint-runner so the \
                 kernel's reverse-DAG evaluation_sha resolution \
                 (handle_activate_sub_task) returns the SHA carrying \
                 out/lint/check-output.txt; got {preds:?}",
            );
        }
    }

    /// The Reviewer prompts MUST NOT instruct the planner to
    /// execute `scripts/check.sh` (the original-bug witness for
    /// this commit). The Reviewer VM image
    /// (`raxis-reviewer-core`) has no shell or runtimes per
    /// `INV-PLANNER-HARNESS-02`; the captured artifact at
    /// `out/lint/check-output.txt` is the only legitimate
    /// surface for the Reviewer panel.
    #[test]
    fn reviewer_prompts_point_at_captured_artifact_not_script_execution() {
        let toml_text = realistic_plan_toml();
        let v: toml::Value = toml::from_str(&toml_text).unwrap();
        let tasks = v
            .get("tasks")
            .and_then(|t| t.as_array())
            .expect("[[tasks]] array present");

        for reviewer_task_id in [TASK_REVIEW_LINT_A, TASK_REVIEW_LINT_B] {
            let reviewer = tasks
                .iter()
                .find(|t| {
                    t.get("task_id").and_then(|i| i.as_str())
                        == Some(reviewer_task_id)
                })
                .unwrap_or_else(|| {
                    panic!("reviewer task `{reviewer_task_id}` present")
                });
            let desc = reviewer
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or_else(|| {
                    panic!("{reviewer_task_id} description present")
                });

            assert!(
                desc.contains("out/lint/check-output.txt"),
                "{reviewer_task_id} prompt MUST reference the \
                 captured artifact path verbatim — that's the only \
                 path the Reviewer's read_file can target; got prompt \
                 of len {}",
                desc.len(),
            );
            assert!(
                !desc.contains("run `scripts/check.sh`")
                    && !desc.contains("run scripts/check.sh"),
                "{reviewer_task_id} prompt MUST NOT tell the \
                 Reviewer to run scripts/check.sh — the Reviewer VM \
                 image (raxis-reviewer-core) ships only \
                 raxis-planner + ripgrep per INV-PLANNER-HARNESS-02; \
                 prompt leak found",
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
            .find(|t| {
                t.get("task_id").and_then(|i| i.as_str()) == Some(TASK_LINT_DEFECT)
            })
            .expect("lint-defect task present");
        let predecessors = lint
            .get("predecessors")
            .and_then(|p| p.as_array())
            .expect("lint-defect.predecessors array");
        let names: Vec<&str> = predecessors
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
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
            .find(|t| {
                t.get("task_id").and_then(|i| i.as_str())
                    == Some(TASK_SERVICE_ROUND_TRIP)
            })
            .expect("service-round-trip task present");
        let allowlist = srt
            .get("path_allowlist")
            .and_then(|a| a.as_array())
            .expect("service-round-trip path_allowlist present");
        let paths: Vec<&str> = allowlist
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
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
        let preds: Vec<&str> = predecessors
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(
            preds.contains(&TASK_SERVICE_ROUND_TRIP),
            "transparent-proxy task must run AFTER service-round-trip; \
             got predecessors {preds:?}",
        );

        let allowlist = tp
            .get("path_allowlist")
            .and_then(|a| a.as_array())
            .expect("transparent-proxy-realscripts path_allowlist present");
        let paths: Vec<&str> = allowlist
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
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
