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

// ---------------------------------------------------------------------------
// Plan-TOML builder.
// ---------------------------------------------------------------------------

/// Build the realistic-scenario `[plan]` TOML body the test
/// submits via `OperatorIpc::submit_plan`. The current shape
/// includes `materialize-records` + `xfile-refactor`; subsequent
/// commits on this branch extend it.
pub fn realistic_plan_toml() -> String {
    let materializer = MATERIALIZER_PROMPT_MD;
    let xfile        = XFILE_REFACTOR_PROMPT_MD;
    let lint         = LINT_DEFECT_PROMPT_MD;
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
        for needle in [TASK_MATERIALIZE, TASK_XFILE_REFACTOR, TASK_LINT_DEFECT] {
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
}
