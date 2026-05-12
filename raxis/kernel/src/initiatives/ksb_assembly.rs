//! Kernel-side KSB (Kernel-State-Block) assembler.
//!
//! Closes V2 `v2_extended_gaps.md §2.4` by reading the live kernel
//! state for an initiative + task at session-spawn time and projecting
//! it into a [`raxis_ksb::KsbSnapshot`]. The result is JSON-serialized
//! and stamped into the spawned planner binary's env at
//! `RAXIS_PLANNER_KSB` (constant [`raxis_ksb::PLANNER_KSB_ENV`]).
//!
//! ## Why this lives in `initiatives/`
//!
//! The KSB is a per-initiative-and-per-task projection. Every input
//! field comes from rows the lifecycle subsystem already owns
//! (`plan_registry`, `tasks`, `escalations`, `task_credential_proxies`),
//! so co-locating the assembler keeps the read paths in one module
//! and avoids forcing every IPC handler to learn the schema.
//!
//! ## Trust + redaction boundary
//!
//! This is the **only** place where operator-supplied free-form text
//! (task descriptions, reviewer critiques, escalation summaries) is
//! projected into the LLM's system prompt. The
//! [`TASK_DESCRIPTION_MAX_BYTES`] cap is the kernel-side defence; the
//! `raxis-ksb` renderer additionally rejects any text containing the
//! `KSB_DELIMITER_CLOSE` byte sequence (defense-in-depth INV-KSB-01).
//!
//! ## Failure model
//!
//! The assembler is fail-soft: it returns `Result<KsbSnapshot, …>`.
//! A read failure on an optional field (e.g. `escalations` table
//! query times out) returns the error to the caller; the caller (the
//! spawn path) MAY decide to spawn without a KSB rather than refuse
//! the spawn. The current spawn-side wiring `unwrap_or_default()`s a
//! minimum-bootable snapshot on read failure so a transient SQLite
//! lock contention does not block the operator's plan from
//! activating.

use rusqlite::{Connection, OptionalExtension};
use thiserror::Error;

use raxis_ksb::{
    CredentialPort, DagRow, KsbSnapshot, PendingEscalation,
    KSB_SCHEMA_VERSION,
};
use raxis_store::Table;

use crate::initiatives::plan_registry::{PlanRegistry, TaskKey};

/// V2 `v2_extended_gaps.md §2.4` — `task_description` cap. The kernel
/// truncates `[[tasks]] description` (already capped at admission
/// against an upstream limit; this is the projection-time backstop)
/// to this size before stamping it into the rendered KSB. The model
/// will see at most this many bytes of operator-authored prompt
/// material per turn.
pub const TASK_DESCRIPTION_MAX_BYTES: usize = 4096;

/// Failure modes for the assembler.
#[derive(Debug, Error)]
pub enum KsbAssemblyError {
    /// SQLite read failed. Surfaces the underlying `rusqlite::Error`
    /// verbatim so dashboards can pivot on the `code()` projection.
    #[error("sqlite read failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// JSON serialization failed. Practically unreachable — every
    /// field of [`KsbSnapshot`] is `Serialize`-derived — but kept
    /// in the error enum so the spawn path's `?` operator stays
    /// honest.
    #[error("serde_json failed to serialise KsbSnapshot: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// Role the spawn is targeting. Mirrors the lower-case ASCII values
/// the [`raxis_ksb::KsbSnapshot::role`] field carries.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KsbRole {
    Executor,
    Reviewer,
    Orchestrator,
}

impl KsbRole {
    /// Wire-stable role string. The renderer + every downstream
    /// LLM prompt template pivots on this verbatim — DO NOT
    /// rename without bumping [`KSB_SCHEMA_VERSION`].
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Executor    => "executor",
            Self::Reviewer    => "reviewer",
            Self::Orchestrator=> "orchestrator",
        }
    }
}

/// Assembled inputs the kernel passes to [`assemble_ksb_snapshot`].
///
/// Bundled into a struct so future fields (token-cost estimator,
/// witness DAG snapshot, …) can be appended without breaking every
/// call-site.
pub struct KsbInputs<'a> {
    pub initiative_id: &'a str,
    pub task_id:       Option<&'a str>,
    pub role:          KsbRole,
    /// Per-task token budget remaining, in LLM tokens. The kernel's
    /// budget subsystem feeds this; `0` is a valid value (the
    /// model is expected to terminate via `report_failure`).
    pub token_budget_remaining: u64,
    /// Per-task wall-clock budget remaining, seconds. `0` means the
    /// caller did not have a wall-clock budget to declare (the
    /// model treats `0` as "no enforced ceiling").
    pub wallclock_budget_remaining_s: u64,
    /// Credential proxy port assignments resolved at spawn time
    /// (one row per `[[tasks.credentials]]` decl). Empty for the
    /// reviewer (which cannot consume credentials —
    /// `INV-PLANNER-HARNESS-02`) and for tasks with no decls.
    pub credential_ports: Vec<CredentialPort>,
}

/// Assemble the KSB snapshot the kernel will stamp into
/// `RAXIS_PLANNER_KSB`.
///
/// **Reads.**
///
///   * `tasks` — for the per-task `evaluation_sha` + per-initiative
///     DAG snapshot (every row of the initiative).
///   * `plan_registry` — for the `target_ref`, the per-task path
///     allowlist + description, and the per-initiative orchestrator
///     description.
///   * `escalations` — for the `pending_escalations` block (status
///     filter `Pending`, scoped to this initiative).
///   * `subtask_activations` (currently unused — reviewer verdicts
///     would be sourced here; placeholder for V3).
///
/// **Pure projection.** No mutations; safe to call from a
/// `spawn_blocking` context with the sync `Connection` lock.
pub fn assemble_ksb_snapshot(
    conn:     &Connection,
    registry: &PlanRegistry,
    inputs:   &KsbInputs<'_>,
) -> Result<KsbSnapshot, KsbAssemblyError> {
    let task_id = inputs.task_id.unwrap_or("");

    // ── Plan-registry projections ────────────────────────────────
    let task_fields = inputs.task_id
        .map(|tid| TaskKey::new(inputs.initiative_id.to_owned(), tid.to_owned()))
        .and_then(|key| registry.get(&key));
    let orch_fields = registry.orchestrator(inputs.initiative_id);

    let target_ref = orch_fields.as_ref()
        .map(|o| o.target_ref.clone())
        .unwrap_or_default();

    let path_allowlist = task_fields.as_ref()
        .map(|t| t.path_allowlist.clone())
        .unwrap_or_default();

    let task_description = match inputs.role {
        KsbRole::Orchestrator => {
            // Orchestrator: source from `[plan.initiative]
            // description` (held on `OrchestratorPlanFields`).
            orch_fields.as_ref()
                .map(|o| truncate_to_bytes(&o.description, TASK_DESCRIPTION_MAX_BYTES))
                .unwrap_or_default()
        }
        KsbRole::Executor | KsbRole::Reviewer => {
            // Executor / reviewer: source from per-task
            // `[[tasks]].description`.
            task_fields.as_ref()
                .map(|t| truncate_to_bytes(&t.description, TASK_DESCRIPTION_MAX_BYTES))
                .unwrap_or_default()
        }
    };

    // ── Per-task evaluation_sha ──────────────────────────────────
    let evaluation_sha = if !task_id.is_empty() {
        read_evaluation_sha(conn, task_id)?.unwrap_or_default()
    } else {
        String::new()
    };

    // ── DAG snapshot (executor sees nothing; reviewer + orchestrator
    //    see the full per-initiative DAG) ───────────────────────
    let dag_rows = match inputs.role {
        KsbRole::Executor => Vec::new(),
        KsbRole::Reviewer | KsbRole::Orchestrator => {
            read_dag_rows_for_initiative(conn, inputs.initiative_id, registry)?
        }
    };

    // ── Pending escalations scoped to this initiative ────────────
    let pending_escalations = read_pending_escalations(conn, inputs.initiative_id)?;

    // ── Initiative anchor `base_sha` ─────────────────────────────
    //
    // V2.5: every per-initiative session (orchestrator, executor,
    // reviewer) is anchored at the same base SHA — the SHA the
    // orchestrator's worktree was provisioned at by
    // `worktree_provisioning::provision_orchestrator_worktree`.
    // The orchestrator's `integration_merge` tool call cites this
    // verbatim as `base_sha`. We source it from the live
    // orchestrator session row so a respawn re-attached to the
    // existing anchor surfaces the same SHA without reading the
    // on-disk worktree (which would race the spawn).
    //
    // A miss surfaces as an empty string; the renderer emits the
    // literal `<unset>` and the agent fails-loud per
    // `kernel-mechanics-prompt.md` ("never invent a SHA").
    let base_sha = read_initiative_anchor_base_sha(conn, inputs.initiative_id)?
        .unwrap_or_default();

    Ok(KsbSnapshot {
        version:                       KSB_SCHEMA_VERSION,
        initiative_id:                 inputs.initiative_id.to_owned(),
        task_id:                       inputs.task_id.map(str::to_owned),
        role:                          inputs.role.as_str().to_owned(),
        evaluation_sha,
        path_allowlist,
        token_budget_remaining:        inputs.token_budget_remaining,
        wallclock_budget_remaining_s:  inputs.wallclock_budget_remaining_s,
        dag_rows,
        task_description,
        target_ref,
        base_sha,
        // V3 placeholder. Wiring up the reviewer-verdict feed
        // requires plumbing the witness-aggregation crate
        // (`review_aggregation`) into this projection; left for the
        // KSB v2 → v3 follow-up.
        reviewer_verdicts:             Vec::new(),
        pending_escalations,
        credential_ports:              inputs.credential_ports.clone(),
    })
}

/// Read the per-initiative anchor `base_sha` from the live
/// orchestrator session row. The orchestrator session is the
/// canonical source — every executor / reviewer session for the
/// initiative was cloned from that anchor.
///
/// Returns `Ok(None)` when no orchestrator row exists yet (boot
/// race) or the row's `base_sha` is `NULL` (the spawn path's
/// post-provisioning UPDATE has not landed yet). The caller falls
/// back to the literal `<unset>` rendering.
fn read_initiative_anchor_base_sha(
    conn:          &Connection,
    initiative_id: &str,
) -> Result<Option<String>, rusqlite::Error> {
    use raxis_types::SessionAgentType;
    let sql = format!(
        "SELECT base_sha FROM {sessions} \
          WHERE initiative_id      = ?1 \
            AND session_agent_type = ?2 \
            AND base_sha IS NOT NULL \
          ORDER BY created_at DESC \
          LIMIT 1",
        sessions = Table::Sessions.as_str(),
    );
    conn.query_row(
        &sql,
        rusqlite::params![initiative_id, SessionAgentType::Orchestrator.as_sql_str()],
        |r| r.get::<_, Option<String>>(0),
    )
    .or_else(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => Ok(None),
        other => Err(other),
    })
}

/// Truncate `s` to at most `max_bytes` bytes, falling on a UTF-8
/// codepoint boundary. Empty when `s` is empty.
fn truncate_to_bytes(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_owned()
}

fn read_evaluation_sha(
    conn:    &Connection,
    task_id: &str,
) -> Result<Option<String>, rusqlite::Error> {
    let sql = format!(
        "SELECT evaluation_sha FROM {tasks} WHERE task_id = ?1",
        tasks = Table::Tasks.as_str(),
    );
    conn.query_row(&sql, rusqlite::params![task_id], |r| r.get::<_, Option<String>>(0))
        .optional()
        .map(|o| o.flatten())
}

fn read_dag_rows_for_initiative(
    conn:          &Connection,
    initiative_id: &str,
    registry:      &PlanRegistry,
) -> Result<Vec<DagRow>, rusqlite::Error> {
    // V2.5 §11.4-adjacent — the DAG-row projection now includes
    // `evaluation_sha` so the Orchestrator's KSB-rendered `dag=`
    // block carries the per-task commit SHA the
    // `integration_merge` tool needs to cite as `head_sha`.
    // Without this projection the Orchestrator agent has no
    // wire-visible source for the SHA — it would have to invent
    // one or call `read_file` against `.git/refs/heads/...`,
    // both of which would round-trip incorrect (or empty)
    // values into the kernel.
    let sql = format!(
        "SELECT task_id, state, evaluation_sha FROM {tasks} \
         WHERE initiative_id = ?1 \
         ORDER BY admitted_at ASC, task_id ASC",
        tasks = Table::Tasks.as_str(),
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(rusqlite::params![initiative_id], |r| {
            let task_id:        String         = r.get(0)?;
            let state:          String         = r.get(1)?;
            let evaluation_sha: Option<String> = r.get(2)?;
            Ok((task_id, state, evaluation_sha))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(rows.into_iter().map(|(task_id, state, evaluation_sha)| {
        let title = registry
            .get(&TaskKey::new(initiative_id.to_owned(), task_id.clone()))
            .map(|t| {
                t.description.lines().next().unwrap_or("").to_owned()
            })
            .unwrap_or_default();
        DagRow {
            task_id,
            state: state.to_lowercase(),
            title,
            // Reviewer count is V3 work — would require a join
            // against `subtask_activations` filtered to reviewer
            // sessions. Reported as `0` for now; the renderer
            // tolerates this verbatim.
            reviewers: 0,
            evaluation_sha: evaluation_sha.unwrap_or_default(),
        }
    }).collect())
}

fn read_pending_escalations(
    conn:          &Connection,
    initiative_id: &str,
) -> Result<Vec<PendingEscalation>, rusqlite::Error> {
    let sql = format!(
        "SELECT escalation_id, class, justification \
           FROM {esc} \
          WHERE initiative_id = ?1 AND status = 'Pending' \
          ORDER BY created_at ASC, escalation_id ASC",
        esc = Table::Escalations.as_str(),
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(rusqlite::params![initiative_id], |r| {
            Ok(PendingEscalation {
                escalation_id: r.get(0)?,
                class:         r.get(1)?,
                summary:       r.get::<_, String>(2)?
                    .lines().next().unwrap_or("").to_owned(),
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// V2 `v2_extended_gaps.md §2.4` — placeholder used by the spawn
/// paths when the assembler returns an error: a minimum-bootable
/// snapshot whose required fields are populated and whose optional
/// fields default to empty. The driver still gets a non-empty
/// `RAXIS_PLANNER_KSB` env var so the dispatch loop produces a
/// meaningful prompt; the model sees no DAG / verdict context, but
/// the kernel-state-block delimiters are still present so the LLM
/// trusts the rest of the prompt.
pub fn fallback_snapshot(
    initiative_id: &str,
    task_id:       Option<&str>,
    role:          KsbRole,
) -> KsbSnapshot {
    KsbSnapshot {
        version:                       KSB_SCHEMA_VERSION,
        initiative_id:                 initiative_id.to_owned(),
        task_id:                       task_id.map(str::to_owned),
        role:                          role.as_str().to_owned(),
        evaluation_sha:                String::new(),
        path_allowlist:                Vec::new(),
        token_budget_remaining:        0,
        wallclock_budget_remaining_s:  0,
        dag_rows:                      Vec::new(),
        task_description:              String::new(),
        target_ref:                    crate::initiatives::OrchestratorPlanFields::DEFAULT_TARGET_REF.to_owned(),
        base_sha:                      String::new(),
        reviewer_verdicts:             Vec::new(),
        pending_escalations:           Vec::new(),
        credential_ports:              Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::initiatives::plan_registry::{
        OrchestratorPlanFields, TaskPlanFields,
    };
    use raxis_store::Store;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn fresh_store() -> (Arc<Store>, TempDir) {
        let dir = TempDir::new().expect("tempdir");
        let store = Store::open(&dir.path().join("kernel.db"))
            .expect("open kernel.db");
        (Arc::new(store), dir)
    }

    fn populate_registry(
        registry:      &PlanRegistry,
        initiative_id: &str,
        task_id:       &str,
    ) {
        let key = TaskKey::new(initiative_id.to_owned(), task_id.to_owned());
        registry.insert(key, TaskPlanFields {
            path_allowlist:            vec!["src/lib.rs".to_owned(), "src/main.rs".to_owned()],
            description:               "Land the typed enum on top of the executor lane.".to_owned(),
            ..Default::default()
        });
        registry.insert_orchestrator(initiative_id.to_owned(), OrchestratorPlanFields {
            cross_cutting_artifacts: vec![],
            description:             "Drive the typed-enum refactor across the executor lane.".to_owned(),
            target_ref:              "refs/heads/feature/typed-enum".to_owned(),
            elastic:                 None,
        });
    }

    #[test]
    fn assemble_executor_snapshot_carries_task_description_and_paths() {
        let (store, _dir) = fresh_store();
        let registry = PlanRegistry::new();
        populate_registry(&registry, "init-1", "task-a");

        let conn = store.lock_sync();
        let snap = assemble_ksb_snapshot(
            &*conn,
            &registry,
            &KsbInputs {
                initiative_id: "init-1",
                task_id:       Some("task-a"),
                role:          KsbRole::Executor,
                token_budget_remaining: 12_345,
                wallclock_budget_remaining_s: 600,
                credential_ports: Vec::new(),
            },
        ).expect("assemble snapshot");

        assert_eq!(snap.initiative_id,  "init-1");
        assert_eq!(snap.task_id.as_deref(), Some("task-a"));
        assert_eq!(snap.role,           "executor");
        assert_eq!(snap.target_ref,     "refs/heads/feature/typed-enum");
        assert_eq!(snap.path_allowlist, vec!["src/lib.rs", "src/main.rs"]);
        assert!(snap.task_description.starts_with("Land the typed enum"),
            "executor MUST source description from per-task plan field, got: {}",
            snap.task_description);
        assert_eq!(snap.token_budget_remaining,        12_345);
        assert_eq!(snap.wallclock_budget_remaining_s, 600);
        // Executor's DAG view is intentionally empty (it sees only
        // its own task), so a missing `tasks` row in the store does
        // not surface a populated DAG row by mistake.
        assert!(snap.dag_rows.is_empty(),
            "executor's KSB MUST NOT carry a DAG view");
    }

    #[test]
    fn assemble_orchestrator_snapshot_sources_description_from_initiative_field() {
        let (store, _dir) = fresh_store();
        let registry = PlanRegistry::new();
        populate_registry(&registry, "init-1", "task-a");

        let conn = store.lock_sync();
        let snap = assemble_ksb_snapshot(
            &*conn,
            &registry,
            &KsbInputs {
                initiative_id: "init-1",
                task_id:       None,
                role:          KsbRole::Orchestrator,
                token_budget_remaining: 0,
                wallclock_budget_remaining_s: 0,
                credential_ports: Vec::new(),
            },
        ).expect("assemble orchestrator snapshot");

        assert_eq!(snap.role, "orchestrator");
        assert!(snap.task_id.is_none(),
            "orchestrator KSB MUST omit task_id (the orchestrator is per-initiative, not per-task)");
        assert_eq!(snap.target_ref, "refs/heads/feature/typed-enum");
        assert!(snap.task_description.starts_with("Drive the typed-enum refactor"),
            "orchestrator MUST source description from `[plan.initiative] description`, got: {}",
            snap.task_description);
    }

    #[test]
    fn assembler_renders_through_raxis_ksb_round_trip() {
        let (store, _dir) = fresh_store();
        let registry = PlanRegistry::new();
        populate_registry(&registry, "init-1", "task-a");

        let conn = store.lock_sync();
        let snap = assemble_ksb_snapshot(
            &*conn,
            &registry,
            &KsbInputs {
                initiative_id: "init-1",
                task_id:       Some("task-a"),
                role:          KsbRole::Executor,
                token_budget_remaining: 0,
                wallclock_budget_remaining_s: 0,
                credential_ports: Vec::new(),
            },
        ).expect("assemble snapshot");
        drop(conn);

        // V2 `v2_extended_gaps.md §2.4` — JSON wire shape MUST
        // round-trip cleanly so the kernel-side serialise + the
        // driver-side deserialise pair produce a byte-identical
        // render. This is the load-bearing pin against schema
        // drift between the two sides of the env-var contract.
        let json = serde_json::to_string(&snap).expect("serialise");
        let decoded: KsbSnapshot = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(snap, decoded);

        let rendered = raxis_ksb::render_ksb(&decoded).expect("render");
        assert!(rendered.contains("initiative_id=init-1"));
        assert!(rendered.contains("task_id=task-a"));
        assert!(rendered.contains("role=executor"));
        assert!(rendered.contains("target_ref=refs/heads/feature/typed-enum"));
        assert!(rendered.contains("- src/lib.rs"));
        assert!(rendered.contains("Land the typed enum"));
    }

    #[test]
    fn truncates_oversized_task_description_at_byte_boundary() {
        let (store, _dir) = fresh_store();
        let registry = PlanRegistry::new();
        let huge = "a".repeat(TASK_DESCRIPTION_MAX_BYTES + 1024);
        let key = TaskKey::new("init-1".to_owned(), "task-a".to_owned());
        registry.insert(key, TaskPlanFields {
            description: huge,
            ..Default::default()
        });
        registry.insert_orchestrator("init-1".to_owned(), OrchestratorPlanFields::default());

        let conn = store.lock_sync();
        let snap = assemble_ksb_snapshot(
            &*conn,
            &registry,
            &KsbInputs {
                initiative_id: "init-1",
                task_id:       Some("task-a"),
                role:          KsbRole::Executor,
                token_budget_remaining: 0,
                wallclock_budget_remaining_s: 0,
                credential_ports: Vec::new(),
            },
        ).expect("assemble snapshot");

        assert!(snap.task_description.len() <= TASK_DESCRIPTION_MAX_BYTES,
            "oversized description MUST be truncated to TASK_DESCRIPTION_MAX_BYTES, \
             got len={}", snap.task_description.len());
    }

    #[test]
    fn fallback_snapshot_carries_required_fields_for_renderer() {
        let snap = fallback_snapshot("init-x", Some("task-y"), KsbRole::Executor);
        assert_eq!(snap.initiative_id, "init-x");
        assert_eq!(snap.role,          "executor");
        // The fallback MUST satisfy `render_ksb`'s required-field
        // checks (initiative_id + role non-empty, no delimiter
        // injection) so the spawn path can stamp it without a
        // second-order failure on the driver side.
        let r = raxis_ksb::render_ksb(&snap).expect("render fallback");
        assert!(r.contains("initiative_id=init-x"));
        assert!(r.contains("role=executor"));
    }
}
