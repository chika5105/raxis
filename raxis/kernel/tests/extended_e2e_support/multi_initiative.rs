//! Multi-initiative concurrency witness.
//!
//! The extended scenario runs a single initiative end-to-end. The
//! realistic scenario submits TWO initiatives in parallel (the
//! primary `e2e-realistic-lane` initiative plus a sibling
//! `e2e-realistic-sibling-lane`) to exercise the contract that
//! initiative-level state cannot bleed across initiatives — task
//! ids declared by initiative A must NEVER show up under
//! initiative B in the audit chain, even when both initiatives
//! interleave their executor / reviewer sessions on the same
//! kernel.
//!
//! This is a separate concern from the per-task lane budget
//! reservations the extended scenario already exercises
//! ([`super::concurrency::two_independent_initiatives`] documents
//! the budgeting model). Lane budgets are about *resource*
//! isolation; this witness is about *audit-chain* isolation —
//! specifically, the contract that the audit chain row for an
//! event whose initiative_id is "A" carries only task_ids /
//! session_ids that belong to initiative A.
//!
//! Spec references:
//!   * `raxis/specs/v2/e2e-extended-scenario.md` §3 (multi-
//!     initiative interleaving as a future-work bullet).
//!   * `raxis/raxis-concepts/03-initiative-model.md` (per-
//!     initiative isolation invariants).
//!
//! ## What [`MultiInitiativeIsolationWitness`] asserts
//!
//! Given an expected pair `(initiative_a, initiative_b)`:
//!
//! 1. **Both initiatives observed.** The audit chain contains at
//!    least one event with `initiative_id == Some(initiative_a)`
//!    AND at least one with `initiative_id == Some(initiative_b)`.
//!    Without this, the witness cannot draw any conclusion about
//!    isolation (a no-op second initiative would otherwise
//!    trivially "satisfy" the predicate).
//!
//! 2. **Task-id partitioning.** For every event with
//!    `initiative_id == Some(_)` AND `task_id == Some(_)`, that
//!    task_id appears under EXACTLY ONE initiative_id across the
//!    whole chain. Any task_id that shows up under both
//!    initiatives is a real isolation violation.
//!
//! 3. **Session-id partitioning.** Same shape as (2) but for
//!    `session_id` instead of `task_id`. Session ids carry
//!    capability handles, so cross-initiative reuse of a
//!    session_id is even worse than a task_id collision.
//!
//! Events with `initiative_id == None` (e.g. kernel-global
//! lifecycle events such as `DashboardReady`) are exempt from
//! (2) and (3): they aren't owned by any initiative and may
//! reference no task/session at all.

use std::collections::{BTreeMap, BTreeSet};

use raxis_audit_tools::AuditEvent;

use super::witnesses::EnforcementWitness;

// ---------------------------------------------------------------------------
// Pinned initiative + lane ids.
// ---------------------------------------------------------------------------

/// Lane id used by the SECONDARY (sibling) initiative the
/// realistic-scenario test submits in parallel with the primary
/// initiative. Distinct from
/// [`super::plan_realistic::LANE_ID`] so the two initiatives'
/// budget reservations are independent.
pub const SIBLING_LANE_ID: &str = "e2e-realistic-sibling-lane";

/// Pinned task id under the sibling initiative. Lives in a
/// distinct `task_id` namespace from the primary plan so the
/// task-id partitioning assertion is materially testable.
pub const TASK_SIBLING_MATERIALIZE: &str = "sibling-materialize-records";

// ---------------------------------------------------------------------------
// Sibling plan TOML — a single-task initiative reusing the
// existing materializer prompt so it doesn't add a new prompt
// dependency.
// ---------------------------------------------------------------------------

/// Build the sibling initiative's plan TOML (single materializer
/// executor task under a distinct lane). Submitted by the
/// realistic-scenario test driver in parallel with
/// [`super::plan_realistic::realistic_plan_toml`].
pub fn sibling_plan_toml() -> String {
    let mut s = String::new();
    s.push_str(SIBLING_PLAN_HEADER);
    s.push_str("\n\n");
    s.push_str(SIBLING_PLAN_MATERIALIZER_HEAD);
    s.push_str(&sibling_materializer_prompt());
    s.push_str("\n\"\"\"\n");
    s.push_str(SIBLING_PLAN_MATERIALIZER_CREDS);
    s
}

fn sibling_materializer_prompt() -> String {
    super::plan_realistic::MATERIALIZER_PROMPT_MD
        .replace("out/postgres", "out/sibling/postgres")
        .replace("out/mongo", "out/sibling/mongo")
        .replace("out/manifest.json", "out/sibling/manifest.json")
}

const SIBLING_PLAN_HEADER: &str = r#"[plan.initiative]
description = """
Realistic-scenario sibling initiative — submitted in parallel
with the primary realistic initiative to assert per-initiative
audit-chain isolation and conflict-free concurrent target-ref
composition.

Distinct lane id ensures budget reservations cannot interleave
across initiatives. Distinct task_id namespace
("sibling-materialize-records") ensures the
`MultiInitiativeIsolationWitness` partitioning predicate is
materially testable. Distinct output paths keep the sibling's
evidence subtree disjoint from the primary materializer while both
initiatives still publish to refs/heads/main.
"""

[workspace]
name = "E2E realistic sibling"
lane_id = "e2e-realistic-sibling-lane"
repository = "main"
target_ref = "refs/heads/main""#;

// V2.7 `INV-PLANNER-MAX-TURNS-PRECEDENCE-01` parity guard. Iter52
// surfaced a drift between this Rust source-of-truth and the
// auto-refreshed example bundle at
// `raxis/live-e2e/examples/plan_sibling.toml`: commit `5946b18`
// landed `max_turns = 150` on the example but missed this constant,
// so the kernel resolved `sibling-materialize-records` via the
// compiled-default arm (`source=compiled-default, resolved=100`,
// visible in iter52's `PlannerMaxTurnsResolved` log lines) instead
// of the per-task arm. The TOML comment block below is byte-stable
// against the example bundle so a future
// `RAXIS_E2E_REFRESH_EXAMPLES=1` produces a no-op diff. The
// `sibling_plan_toml_carries_max_turns_150` test below is the
// witness pin against the regression returning.
const SIBLING_PLAN_MATERIALIZER_HEAD: &str = r#"# ── Sibling materializer Executor (P3-6) ────────────────
[[tasks]]
task_id            = "sibling-materialize-records"
name               = "Sibling-initiative materializer (audit-chain isolation witness)"
session_agent_type = "Executor"
clone_strategy     = "blobless"
# Same workload as `materialize-records` (25 pg rows + 25 mongo docs +
# 50 file writes + commit), but written under `out/sibling/` so the
# shared refs/heads/main integration path exercises concurrent
# target-ref preservation without an intentional add/add conflict
# against the primary materializer. 150 mirrors the primary
# materializer for `INV-PLANNER-MAX-TURNS-PRECEDENCE-01`.
max_turns          = 150
path_allowlist     = ["out/sibling/postgres/", "out/sibling/mongo/", "out/sibling/manifest.json"]
description        = "Materialize sibling postgres rows and mongo docs to JSON files."
prompt = """
"#;

const SIBLING_PLAN_MATERIALIZER_CREDS: &str = r#"
  [[tasks.credentials]]
  name       = "test-pg-dev"
  proxy_type = "postgres"
  mount_as   = "DATABASE_URL"

  [[tasks.credentials]]
  name       = "test-mongo-dev"
  proxy_type = "mongodb"
  mount_as   = "MONGO_URL""#;

// ---------------------------------------------------------------------------
// MultiInitiativeIsolationWitness.
// ---------------------------------------------------------------------------

/// Multi-initiative audit-chain isolation witness. See module docs.
pub struct MultiInitiativeIsolationWitness {
    pub initiative_a: String,
    pub initiative_b: String,
}

impl MultiInitiativeIsolationWitness {
    #[must_use]
    pub fn new(initiative_a: &str, initiative_b: &str) -> Self {
        Self {
            initiative_a: initiative_a.to_owned(),
            initiative_b: initiative_b.to_owned(),
        }
    }

    /// Map every distinct (event_field == self.fieldname) value
    /// to the set of `initiative_id`s that have ever referenced
    /// that value in the chain. Returns a map of "fieldvalue ->
    /// initiative_id-set". A clean run produces a map in which
    /// every value's set has exactly one element.
    fn fanout_by<F>(&self, chain: &[AuditEvent], extract: F) -> BTreeMap<String, BTreeSet<String>>
    where
        F: Fn(&AuditEvent) -> Option<&str>,
    {
        let mut map: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for ev in chain {
            let (Some(init), Some(value)) = (ev.initiative_id.as_deref(), extract(ev)) else {
                continue;
            };
            map.entry(value.to_owned())
                .or_default()
                .insert(init.to_owned());
        }
        map
    }

    fn both_initiatives_present(&self, chain: &[AuditEvent]) -> bool {
        let mut saw_a = false;
        let mut saw_b = false;
        for ev in chain {
            match ev.initiative_id.as_deref() {
                Some(s) if s == self.initiative_a => saw_a = true,
                Some(s) if s == self.initiative_b => saw_b = true,
                _ => {}
            }
        }
        saw_a && saw_b
    }
}

impl EnforcementWitness for MultiInitiativeIsolationWitness {
    fn name(&self) -> &'static str {
        "multi-initiative-isolation"
    }

    fn satisfied_by(&self, chain: &[AuditEvent]) -> bool {
        if !self.both_initiatives_present(chain) {
            return false;
        }
        let task_fanout = self.fanout_by(chain, |ev| ev.task_id.as_deref());
        let session_fanout = self.fanout_by(chain, |ev| ev.session_id.as_deref());

        // A "leak" is any task_id / session_id whose initiative
        // set has more than one element AND whose initiative set
        // intersects {a, b} non-trivially (we don't want a
        // dashboard-only task_id to false-positive against a
        // third unrelated initiative).
        let crosses_ab = |inits: &BTreeSet<String>| -> bool {
            inits.contains(&self.initiative_a) && inits.contains(&self.initiative_b)
        };

        let task_leak = task_fanout.values().any(crosses_ab);
        let session_leak = session_fanout.values().any(crosses_ab);

        !(task_leak || session_leak)
    }

    fn diagnostic(&self, chain: &[AuditEvent]) -> String {
        let task_fanout = self.fanout_by(chain, |ev| ev.task_id.as_deref());
        let session_fanout = self.fanout_by(chain, |ev| ev.session_id.as_deref());

        let mut task_leaks: Vec<&String> = task_fanout
            .iter()
            .filter(|(_, inits)| {
                inits.contains(&self.initiative_a) && inits.contains(&self.initiative_b)
            })
            .map(|(k, _)| k)
            .collect();
        task_leaks.sort();

        let mut session_leaks: Vec<&String> = session_fanout
            .iter()
            .filter(|(_, inits)| {
                inits.contains(&self.initiative_a) && inits.contains(&self.initiative_b)
            })
            .map(|(k, _)| k)
            .collect();
        session_leaks.sort();

        let mut saw_a = 0usize;
        let mut saw_b = 0usize;
        let mut total_with_init = 0usize;
        for ev in chain {
            match ev.initiative_id.as_deref() {
                Some(s) if s == self.initiative_a => {
                    saw_a += 1;
                }
                Some(s) if s == self.initiative_b => {
                    saw_b += 1;
                }
                Some(_) => {}
                None => continue,
            }
            total_with_init += 1;
        }

        format!(
            "MultiInitiativeIsolation[{a} vs {b}]:\n  \
             events with initiative_id = {a}: {saw_a}\n  \
             events with initiative_id = {b}: {saw_b}\n  \
             events with any initiative_id:    {total_with_init}\n  \
             task_ids shared across both initiatives:     {task_leaks:?}\n  \
             session_ids shared across both initiatives:  {session_leaks:?}",
            a = self.initiative_a,
            b = self.initiative_b,
        )
    }
}

// ---------------------------------------------------------------------------
// Unit tests — drive the witness against hand-built audit chains.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use raxis_audit_tools::{AuditEvent, AuditEventKind};
    use uuid::Uuid;

    fn ev(
        seq: u64,
        initiative_id: Option<&str>,
        task_id: Option<&str>,
        session_id: Option<&str>,
    ) -> AuditEvent {
        AuditEvent {
            seq,
            event_id: Uuid::nil(),
            event_kind: "IntentAccepted".to_owned(),
            session_id: session_id.map(str::to_owned),
            task_id: task_id.map(str::to_owned),
            initiative_id: initiative_id.map(str::to_owned),
            payload: serde_json::to_value(&AuditEventKind::IntentAccepted {
                task_id: task_id.unwrap_or("").to_owned(),
                session_id: session_id.unwrap_or("").to_owned(),
                intent_kind: "Lifecycle".to_owned(),
                base_sha: None,
                head_sha: None,
                sequence_number: 1,
                remaining_units: 99,
            })
            .unwrap(),
            emitted_at: 1700000000 + seq as i64,
            prev_sha256: "0".repeat(64),
        }
    }

    #[test]
    fn sibling_plan_toml_decodes_and_carries_sibling_task() {
        let toml_text = sibling_plan_toml();
        let v: toml::Value = toml::from_str(&toml_text).expect("sibling plan must decode");
        let tasks = v
            .get("tasks")
            .and_then(|t| t.as_array())
            .expect("[[tasks]] array");
        let ids: Vec<&str> = tasks
            .iter()
            .filter_map(|t| t.get("task_id").and_then(|i| i.as_str()))
            .collect();
        assert_eq!(ids, vec![TASK_SIBLING_MATERIALIZE]);

        let lane = v
            .get("workspace")
            .and_then(|w| w.get("lane_id"))
            .and_then(|l| l.as_str());
        assert_eq!(lane, Some(SIBLING_LANE_ID));
    }

    #[test]
    fn sibling_plan_uses_disjoint_output_paths_on_shared_target_ref() {
        let toml_text = sibling_plan_toml();
        let v: toml::Value = toml::from_str(&toml_text).expect("sibling plan must decode");
        let workspace = v
            .get("workspace")
            .and_then(|w| w.as_table())
            .expect("[workspace]");
        assert_eq!(
            workspace.get("target_ref").and_then(|r| r.as_str()),
            Some("refs/heads/main"),
            "sibling initiative intentionally shares the primary target ref \
             so the live e2e exercises conflict-free concurrent target-ref \
             composition"
        );

        let task = v
            .get("tasks")
            .and_then(|t| t.as_array())
            .and_then(|tasks| tasks.first())
            .expect("sibling task");
        let allowlist: Vec<&str> = task
            .get("path_allowlist")
            .and_then(|a| a.as_array())
            .expect("path_allowlist")
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert_eq!(
            allowlist,
            vec![
                "out/sibling/postgres/",
                "out/sibling/mongo/",
                "out/sibling/manifest.json",
            ]
        );

        let prompt = task.get("prompt").and_then(|p| p.as_str()).expect("prompt");
        assert!(prompt.contains("out/sibling/postgres/<id>.json"));
        assert!(prompt.contains("out/sibling/mongo/<doc_id>.json"));
        assert!(
            !prompt.contains("out/postgres/<id>.json")
                && !prompt.contains("out/mongo/<doc_id>.json"),
            "sibling helper must not write the primary materializer paths; \
             that creates deterministic add/add conflicts at IntegrationMerge"
        );
    }

    /// Iter52 parity guard for `INV-PLANNER-MAX-TURNS-PRECEDENCE-01`.
    ///
    /// The sibling initiative carries the same materializer workload
    /// shape as the primary plan's `materialize-records` task (25 pg
    /// rows + 25 mongo docs + 50 file writes + commit), but under a
    /// disjoint `out/sibling/` subtree so both initiatives can compose
    /// on the same target ref. The primary task declares `max_turns = 150` in
    /// `super::plan_realistic::REALISTIC_PLAN_MATERIALIZER_HEAD`;
    /// the sibling task MUST declare the same ceiling so the audit-
    /// chain isolation witness compares two initiatives that have
    /// converged under matching budgets.
    ///
    /// Iter52 surfaced a parity gap where the auto-refreshed example
    /// bundle at `live-e2e/examples/plan_sibling.toml` had been
    /// updated to `max_turns = 150` (commit `5946b18`) but this Rust
    /// source-of-truth was missed; the kernel then resolved the
    /// sibling task's ceiling via the compiled-default arm
    /// (`PlannerMaxTurnsResolved {source=compiled-default,
    /// resolved=100}` — visible in the iter52 partial-run kernel log)
    /// instead of the per-task arm. This test guards against the
    /// regression returning by asserting on the post-decode value.
    #[test]
    fn sibling_plan_toml_carries_max_turns_150() {
        let toml_text = sibling_plan_toml();
        let v: toml::Value = toml::from_str(&toml_text).expect("sibling plan must decode");
        let tasks = v
            .get("tasks")
            .and_then(|t| t.as_array())
            .expect("[[tasks]] array");
        let max_turns_per_task: Vec<(&str, i64)> = tasks
            .iter()
            .map(|t| {
                let id = t.get("task_id").and_then(|i| i.as_str()).expect("task_id");
                let mt = t.get("max_turns").and_then(|m| m.as_integer()).expect(
                    "INV-PLANNER-MAX-TURNS-PRECEDENCE-01 parity: \
                         every sibling-plan task MUST declare an explicit \
                         max_turns; iter52 partial-run showed the kernel \
                         falling back to compiled-default=100 when this \
                         was omitted",
                );
                (id, mt)
            })
            .collect();
        assert_eq!(
            max_turns_per_task,
            vec![(TASK_SIBLING_MATERIALIZE, 150)],
            "sibling-materialize-records MUST declare max_turns = 150 \
             (parity with primary plan_realistic.rs `materialize-records`)",
        );
    }

    #[test]
    fn clean_run_with_two_disjoint_initiatives_satisfies() {
        let chain = vec![
            ev(0, Some("init-a"), Some("task-a-1"), Some("sess-a-1")),
            ev(1, Some("init-a"), Some("task-a-1"), Some("sess-a-1")),
            ev(2, Some("init-b"), Some("task-b-1"), Some("sess-b-1")),
            ev(3, Some("init-b"), Some("task-b-2"), Some("sess-b-1")),
            ev(4, None, None, None),
        ];
        let w = MultiInitiativeIsolationWitness::new("init-a", "init-b");
        assert!(w.satisfied_by(&chain), "{}", w.diagnostic(&chain));
    }

    #[test]
    fn missing_second_initiative_fails() {
        let chain = vec![
            ev(0, Some("init-a"), Some("task-a-1"), Some("sess-a-1")),
            ev(1, Some("init-a"), Some("task-a-2"), Some("sess-a-2")),
        ];
        let w = MultiInitiativeIsolationWitness::new("init-a", "init-b");
        assert!(!w.satisfied_by(&chain));
        let diag = w.diagnostic(&chain);
        assert!(diag.contains("events with initiative_id = init-b: 0"));
    }

    #[test]
    fn task_id_shared_across_initiatives_fails() {
        let chain = vec![
            ev(0, Some("init-a"), Some("shared-task"), Some("sess-a-1")),
            ev(1, Some("init-b"), Some("shared-task"), Some("sess-b-1")),
        ];
        let w = MultiInitiativeIsolationWitness::new("init-a", "init-b");
        assert!(!w.satisfied_by(&chain));
        let diag = w.diagnostic(&chain);
        assert!(diag.contains("task_ids shared across both initiatives"));
        assert!(diag.contains("shared-task"));
    }

    #[test]
    fn session_id_shared_across_initiatives_fails() {
        let chain = vec![
            ev(0, Some("init-a"), Some("task-a"), Some("shared-sess")),
            ev(1, Some("init-b"), Some("task-b"), Some("shared-sess")),
        ];
        let w = MultiInitiativeIsolationWitness::new("init-a", "init-b");
        assert!(!w.satisfied_by(&chain));
        let diag = w.diagnostic(&chain);
        assert!(diag.contains("session_ids shared across both initiatives"));
        assert!(diag.contains("shared-sess"));
    }

    #[test]
    fn third_unrelated_initiative_does_not_false_positive() {
        let chain = vec![
            ev(0, Some("init-a"), Some("task-a-1"), Some("sess-a-1")),
            ev(1, Some("init-b"), Some("task-b-1"), Some("sess-b-1")),
            // A third initiative reuses init-a's task_id. We
            // expect the (a, b) witness to ignore this row
            // because it doesn't cross init-a AND init-b.
            ev(2, Some("init-c"), Some("task-a-1"), Some("sess-c-1")),
        ];
        let w = MultiInitiativeIsolationWitness::new("init-a", "init-b");
        assert!(
            w.satisfied_by(&chain),
            "third-initiative reuse must not poison the (a,b) witness: {}",
            w.diagnostic(&chain),
        );
    }
}
