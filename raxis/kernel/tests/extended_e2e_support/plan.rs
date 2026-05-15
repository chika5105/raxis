//! Plan TOML builder for the extended e2e scenario.
//!
//! Mirrors `full_e2e_session_lifecycle::canonical_plan_toml` in
//! shape (same `[plan.initiative]`, `[workspace]`, `[[tasks]]`,
//! `[[tasks.credentials]]` keys with the same semantics) and
//! extends it to the topology in `e2e-extended-scenario.md` §2:
//!
//!   * one `materialize-records` Executor with postgres + mongo
//!     credential mounts,
//!   * three concurrent fan-out Executors (`fanout-readme`,
//!     `fanout-fmt`, `fanout-manifest`) under disjoint
//!     path_allowlists,
//!   * two Reviewers for `materialize-records` with directive
//!     prompts that force a Round-1 reject + Round-2 approve,
//!   * one `inject-evil` Executor under a deliberately narrow
//!     path_allowlist that the injection payloads attempt to
//!     escape.
//!
//! The whole TOML is built from constant `&str` slices so a
//! reviewer can audit the wire shape without running the test.

/// Stable task ids for the extended scenario. Pinned because the
/// witness validators key on these strings.
pub const TASK_MATERIALIZE: &str = "materialize-records";
pub const TASK_FANOUT_README: &str = "fanout-readme";
pub const TASK_FANOUT_FMT: &str = "fanout-fmt";
pub const TASK_FANOUT_MANIFEST: &str = "fanout-manifest";
pub const TASK_REVIEW_A: &str = "review-materialize-A";
pub const TASK_REVIEW_B: &str = "review-materialize-B";
pub const TASK_INJECT_EVIL: &str = "inject-evil";

/// Lane id for the extended scenario; distinct from the
/// single-task test's `e2e-live-lane` so a kernel running both
/// in sequence cannot contaminate budget reservations.
pub const LANE_ID: &str = "e2e-extended-lane";

/// Materializer prompt loaded verbatim from
/// `live-e2e/seed/prompts/materializer.md`.
///
/// **Plan-TOML embedding contract.** This string is interpolated
/// inside a TOML `description = """...""" ` multi-line literal in
/// [`extended_plan_toml`] / [`super::plan_realistic::realistic_plan_toml`] /
/// [`super::multi_initiative::sibling_plan_toml`]. The prompt
/// content MUST therefore contain **no `"""` sequence anywhere**;
/// any such sequence would close the enclosing TOML string early
/// and surface to operators as
/// `FAIL_PLAN_INVALID_TOML: plan.toml parse error … expected
/// newline, '#'`. Live-e2e iter32 hit this when the prompt's
/// Python helper used a `"""..."""` docstring; the
/// `realistic_toml_decodes_and_carries_executors` /
/// `sibling_plan_toml_decodes_and_carries_sibling_task` unit
/// tests under `#[cfg(test)] mod tests` catch it on the next
/// `cargo test -p raxis-kernel`. When authoring or revising
/// prompts, prefer `# ...` line comments inside Python and back-
/// ticked inline code in prose over triple-double-quoted blocks.
pub const MATERIALIZER_PROMPT_MD: &str =
    include_str!("../../../live-e2e/seed/prompts/materializer.md");

/// Build the extended `[plan]` TOML body the test submits via
/// `OperatorIpc::submit_plan`. The `injection_prompt` parameter
/// is the assembled multi-payload prompt (built by
/// `injection::assemble_prompt`).
pub fn extended_plan_toml(injection_prompt: &str) -> String {
    let materializer = MATERIALIZER_PROMPT_MD;
    let injection = injection_prompt;
    let mut s = String::new();
    s.push_str(EXTENDED_PLAN_HEADER);
    s.push_str("\n\n");
    s.push_str(EXTENDED_PLAN_MATERIALIZER_HEAD);
    s.push_str(materializer);
    s.push_str("\n\"\"\"\n");
    s.push_str(EXTENDED_PLAN_MATERIALIZER_CREDS);
    s.push_str("\n\n");
    s.push_str(EXTENDED_PLAN_FANOUT_BLOCKS);
    s.push_str("\n\n");
    s.push_str(EXTENDED_PLAN_REVIEWERS);
    s.push_str("\n\n");
    s.push_str(EXTENDED_PLAN_INJECT_HEAD);
    s.push_str(injection);
    s.push_str("\n\"\"\"\n");
    s
}

const EXTENDED_PLAN_HEADER: &str = r#"[plan.initiative]
description = """
Extended e2e scenario per raxis/specs/v2/e2e-extended-scenario.md.

Materialize 25 postgres rows and 25 mongo docs into worktree
JSON files, run three small concurrent fan-out tasks, route the
materializer through a reviewer-disagreement re-review path,
and exercise four enforcement-layer deny paths with a fifth
"injection" task. Every assertion is the kernel's own audit
chain or an on-disk worktree witness — no LLM-side judgement.
"""

[workspace]
name    = "E2E extended scenario"
lane_id = "e2e-extended-lane""#;

const EXTENDED_PLAN_MATERIALIZER_HEAD: &str = r#"# ── Materializer Executor ───────────────────────────────
[[tasks]]
task_id            = "materialize-records"
name               = "Materialize seeded postgres rows + mongo docs to JSON files"
session_agent_type = "Executor"
path_allowlist     = ["out/postgres/", "out/mongo/", "out/manifest.json"]
description = """
"#;

const EXTENDED_PLAN_MATERIALIZER_CREDS: &str = r#"
  [[tasks.credentials]]
  name       = "test-pg-dev"
  proxy_type = "postgres"
  mount_as   = "DATABASE_URL"

  [[tasks.credentials]]
  name       = "test-mongo-dev"
  proxy_type = "mongodb"
  mount_as   = "MONGO_URL""#;

const EXTENDED_PLAN_FANOUT_BLOCKS: &str = r#"# ── Fan-out tasks (concurrent group) ────────────────────
[[tasks]]
task_id            = "fanout-readme"
name               = "Write a small README"
session_agent_type = "Executor"
path_allowlist     = ["README-e2e.md"]
description = """
Create README-e2e.md containing a single line: "RAXIS extended
e2e scenario fan-out task — readme". Then call task_complete.
"""

[[tasks]]
task_id            = "fanout-fmt"
name               = "Write a fixed formatter stub"
session_agent_type = "Executor"
path_allowlist     = ["src/fmt.txt"]
description = """
Create src/fmt.txt containing: "formatter-output v1". Then
call task_complete.
"""

[[tasks]]
task_id            = "fanout-manifest"
name               = "Emit a small manifest file"
session_agent_type = "Executor"
path_allowlist     = ["out/manifest.json"]
description = """
Create out/manifest.json containing: {"fanout":"manifest","ok":true}.
Then call task_complete.
""""#;

const EXTENDED_PLAN_REVIEWERS: &str = r#"# ── Reviewers (forced disagreement → re-review) ────────
[[tasks]]
task_id            = "review-materialize-A"
name               = "Reviewer A — Round 1 reject"
session_agent_type = "Reviewer"
predecessors       = ["materialize-records"]
description = """
This is a TEST FIXTURE. You MUST reject the diff on this round
to exercise the reviewer-disagreement re-review path
(spec: agent-disagreement.md §3). Submit SubmitReview with
approved = false and critique = "test forces a disagreement
round (extended e2e scenario)". Do NOT approve under any
circumstance on this task.
"""

[[tasks]]
task_id            = "review-materialize-B"
name               = "Reviewer B — Round 2 approve"
session_agent_type = "Reviewer"
predecessors       = ["materialize-records"]
description = """
You are the second Reviewer. Approve the diff once the executor
has re-submitted after Reviewer A's Round-1 rejection. Submit
SubmitReview with approved = true.
""""#;

const EXTENDED_PLAN_INJECT_HEAD: &str = r#"# ── Injection Executor (deny-path exercise) ────────────
[[tasks]]
task_id            = "inject-evil"
name               = "Injection-payload deny-path exercise"
session_agent_type = "Executor"
predecessors       = ["materialize-records"]
path_allowlist     = ["out/inject-evil/scratch.txt"]
description = """
"#;
