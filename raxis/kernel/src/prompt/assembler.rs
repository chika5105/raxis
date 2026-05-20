//! Planner system-prompt assembler (kernel-core.md §2.3
//! `prompt/assembler.rs`, peripherals.md §3.1, T1.8).
//!
//! # Public surface
//!
//! [`assemble`] is the only entry point. It takes a [`SessionId`]
//! and a [`PromptCtx`] (a thin borrow of `Store + PolicyBundle +
//! EpochBinding`) and returns an [`AssembledPrompt`] — a structured
//! object with one field per spec-defined block plus the canonical
//! `planner-api.md` body. Callers render the final text via
//! [`AssembledPrompt::render`].
//!
//! # Why a structured object (not a `String`)
//!
//! Returning the structured form keeps three properties testable in
//! isolation: (a) every block was populated, (b) no block depends on
//! another's text, (c) the planner-api body is included verbatim
//! (the `==` test against `PLANNER_API_BODY` would silently fail if
//! we did string interpolation upstream of `render`).
//!
//! # Inputs the assembler reads
//!
//! Per spec step list:
//!
//! 1. `epoch_binding::session_prompt_valid` — was an epoch advance
//!    missed since the last assembly? (logged, doesn't fail the call.)
//! 2. `authority::get_session` — role / worktree_root / base_sha /
//!    lineage_id / token expiry.
//! 3. `authority::list_delegations` — capability summary.
//! 4. Initiative context — `SELECT DISTINCT initiative_id FROM
//!    tasks WHERE session_id = ?` + per-initiative state, then
//!    per-initiative task list (id, state).
//! 5. `PolicyBundle` — `epoch`, `signed_by`, `egress_domains` count,
//!    rate-limit summary.
//! 6. Compose `AssembledPrompt`. No free-form text generation.
//!
//! # The api_body field
//!
//! The full `planner-api.md` is `include_str!`ed at compile time so:
//!
//! * Every kernel build embeds the exact body the planner sees —
//!   no run-time file I/O, no risk of file/spec drift.
//! * Tests can byte-compare the rendered prompt's tail against
//!   `PLANNER_API_BODY` to catch any accidental modification.
//! * Operators rebuilding the kernel pick up planner-api.md edits
//!   automatically; there is no additional install step.
//!
//! # Errors
//!
//! [`PromptError`] distinguishes:
//!
//! * `SessionNotFound` — `session_id` is not in the sessions table.
//! * `WrongRole` — the session is not a Planner (Gateway/Verifier
//!   sessions never call `assemble`; this is a kernel bug if it
//!   happens).
//! * `Authority` — wraps `AuthorityError` for any underlying lookup.
//! * `Store` — wraps `StoreError` for the initiative-context query
//!   (the only direct store read in this module).

use std::sync::Arc;

use raxis_policy::PolicyBundle;
use raxis_store::{Store, StoreError, Table};
use raxis_types::{Role, SessionId};

use crate::authority::{
    keys::AuthorityError,
    session::{get_session, SessionRow},
};

use super::epoch_binding::EpochBinding;

/// Verbatim canonical content the planner must obey. Embedded at
/// compile time from the spec source-of-truth so kernel and contract
/// can never drift.
pub const PLANNER_API_BODY: &str = include_str!("../../../specs/v1/planner-api.md");

// ────────────────────────────────────────────────────────────────────
// Public types
// ────────────────────────────────────────────────────────────────────

/// Borrowed inputs the assembler needs. Constructing this from the
/// kernel's `HandlerContext` is a one-line wrapper at the call site;
/// keeping the assembler dependent only on a thin borrow keeps unit
/// tests from having to fake a full handler context.
#[derive(Clone, Copy)]
pub struct PromptCtx<'a> {
    pub store: &'a Arc<Store>,
    pub policy: &'a PolicyBundle,
    pub binding: &'a EpochBinding,
    pub now_secs: u64,
}

/// One assembled prompt, exactly the fields kernel-core.md §2.3
/// step 6 enumerates plus the embedded API body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssembledPrompt {
    pub epoch_id: u64,
    pub session_id: SessionId,
    pub role_block: String,
    pub capability_block: String,
    pub initiative_block: String,
    pub constraint_block: String,
    pub assembled_at: u64,
    /// `true` iff the binding said this session's prompt was
    /// invalidated by an epoch advance since the last assembly. The
    /// kernel uses this to emit `AuditEventKind::PromptReassembled`.
    pub epoch_advance_observed: bool,
    /// Static API body (`include_str!("planner-api.md")`).
    pub api_body: &'static str,
}

impl AssembledPrompt {
    /// Concatenate all blocks plus the API body into the final
    /// prompt the planner sees. The order is fixed by spec: identity
    /// → capabilities → initiative → constraints → API contract.
    pub fn render(&self) -> String {
        let mut s = String::with_capacity(
            self.role_block.len()
                + self.capability_block.len()
                + self.initiative_block.len()
                + self.constraint_block.len()
                + self.api_body.len()
                + 256,
        );
        s.push_str(&self.role_block);
        s.push_str("\n\n");
        s.push_str(&self.capability_block);
        s.push_str("\n\n");
        s.push_str(&self.initiative_block);
        s.push_str("\n\n");
        s.push_str(&self.constraint_block);
        s.push_str("\n\n---\n\n");
        s.push_str(self.api_body);
        s
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PromptError {
    #[error("session not found: {0}")]
    SessionNotFound(SessionId),

    #[error("session {session_id} has role {role} but assemble() requires Planner")]
    WrongRole { session_id: SessionId, role: String },

    #[error("authority lookup failed: {0}")]
    Authority(#[from] AuthorityError),

    #[error("store read failed: {0}")]
    Store(#[from] StoreError),
}

// ────────────────────────────────────────────────────────────────────
// Entry point
// ────────────────────────────────────────────────────────────────────

pub fn assemble(
    session_id: &SessionId,
    ctx: &PromptCtx<'_>,
) -> Result<AssembledPrompt, PromptError> {
    // Step 1 — epoch validity check (informational; doesn't gate).
    let was_valid = ctx.binding.session_prompt_valid(session_id);
    let epoch_advance_observed = !was_valid;
    // Clear the flag; the caller will log PromptReassembled this
    // round. Don't gate on whether we logged — repeated calls within
    // the same epoch must NOT keep re-firing the audit event.
    if epoch_advance_observed {
        ctx.binding.clear(session_id);
    }

    // Step 2 — load the session row. The map_err converts the
    // authority-layer "no such session" into our domain error so
    // callers can match precisely.
    let session = get_session(session_id, ctx.store).map_err(|e| match e {
        AuthorityError::SessionNotFound => PromptError::SessionNotFound(session_id.clone()),
        other => PromptError::Authority(other),
    })?;

    if session.role != Role::Planner.as_sql_str() {
        return Err(PromptError::WrongRole {
            session_id: session_id.clone(),
            role: session.role,
        });
    }

    // Step 3 — capabilities (delegations). We query the delegations
    // table directly (rather than via `authority::list_delegations`)
    // because the spec returns a planner-facing view (capability,
    // status, expiry) that does not need `operator_signature` or the
    // `delegating_role_id` / `delegate_role_id` audit fields. Reading
    // only the columns we render also keeps this function decoupled
    // from any future authority-side row reshape.
    let delegations = load_delegation_brief(session_id, ctx.store)?;

    // Step 4 — initiative context.
    let initiatives = load_initiative_context(session_id, ctx.store)?;

    // Step 5 + 6 — render block strings.
    let role_block = build_role_block(session_id, &session, ctx.now_secs);
    let capability_block = build_capability_block(&delegations, ctx.now_secs);
    let initiative_block = build_initiative_block(&initiatives);
    let constraint_block = build_constraint_block(ctx.policy);

    Ok(AssembledPrompt {
        epoch_id: ctx.policy.epoch(),
        session_id: session_id.clone(),
        role_block,
        capability_block,
        initiative_block,
        constraint_block,
        assembled_at: ctx.now_secs,
        epoch_advance_observed,
        api_body: PLANNER_API_BODY,
    })
}

// ────────────────────────────────────────────────────────────────────
// Block builders
// ────────────────────────────────────────────────────────────────────

fn build_role_block(session_id: &SessionId, session: &SessionRow, now_secs: u64) -> String {
    let worktree = session.worktree_root.as_deref().unwrap_or("<unset>");
    let base_sha = session.base_sha.as_deref().unwrap_or("<unset>");
    let ttl_remaining = session.expires_at.saturating_sub(now_secs as i64).max(0);
    format!(
        "## Identity\n\
         \n\
         You are a RAXIS planner.\n\
         \n\
         - session_id:        {sid}\n\
         - role:              Planner\n\
         - lineage_id:        {lineage}\n\
         - worktree_root:     {worktree}\n\
         - base_sha:          {base}\n\
         - sequence_number:   {seq} (next intent must use {next})\n\
         - session ttl:       {ttl}s remaining (until unix={exp})",
        sid = session_id.as_str(),
        lineage = session.lineage_id,
        worktree = worktree,
        base = base_sha,
        seq = session.sequence_number,
        next = session.sequence_number.saturating_add(1),
        ttl = ttl_remaining,
        exp = session.expires_at,
    )
}

fn build_capability_block(delegations: &[DelegationBrief], now_secs: u64) -> String {
    if delegations.is_empty() {
        return "## Capabilities\n\nNo delegations active for this session.".to_owned();
    }
    let mut s =
        String::from("## Capabilities\n\nActive delegations (one row per capability_class):\n\n");
    for d in delegations {
        let remaining = d.expires_at.saturating_sub(now_secs as i64).max(0);
        s.push_str(&format!(
            "- {cls:<24} status={st:<14} expires_in={rem}s\n",
            cls = d.capability_class,
            st = d.status,
            rem = remaining,
        ));
    }
    s
}

fn build_initiative_block(initiatives: &[InitiativeContext]) -> String {
    if initiatives.is_empty() {
        return "## Initiative\n\nNo tasks have been assigned to this session yet. \
                Wait for the operator to admit your initiative."
            .to_owned();
    }
    let mut s = String::from("## Initiative\n\n");
    for init in initiatives {
        s.push_str(&format!(
            "- initiative_id:   {id}\n  state:           {state}\n  tasks ({n}):\n",
            id = init.initiative_id,
            state = init.state,
            n = init.tasks.len(),
        ));
        for t in &init.tasks {
            s.push_str(&format!(
                "    - {tid:<40} state={st}\n",
                tid = t.task_id,
                st = t.state,
            ));
        }
    }
    s
}

fn build_constraint_block(policy: &PolicyBundle) -> String {
    format!(
        "## Constraints (epoch {epoch})\n\
         \n\
         - Active policy epoch:           {epoch}\n\
         - Policy signed_by:              {by}\n\
         - Lanes defined:                 {lanes}\n\
         - Gates defined:                 {gates}\n\
         - Egress domains allowlisted:    {egress}\n\
         - Providers configured:          {providers}\n\
         \n\
         Refer to the API contract below for the rules that govern intent \
         submission, escalation, and budget. Do not attempt to discover \
         policy details that are not exposed here.",
        epoch = policy.epoch(),
        by = policy.signed_by(),
        lanes = policy.lanes().len(),
        gates = policy.gates().len(),
        egress = policy.egress_domains().len(),
        providers = policy.providers().len(),
    )
}

// ────────────────────────────────────────────────────────────────────
// Delegation summary query
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DelegationBrief {
    pub capability_class: String,
    pub status: String,
    pub expires_at: i64,
}

fn load_delegation_brief(
    session_id: &SessionId,
    store: &Arc<Store>,
) -> Result<Vec<DelegationBrief>, PromptError> {
    let delegations_tbl = Table::Delegations.as_str();
    let conn = store.lock_sync();
    let sql = format!(
        "SELECT capability_class, status, expires_at \
         FROM {delegations_tbl} \
         WHERE session_id = ?1 AND revoked_at IS NULL \
         ORDER BY effective_from ASC, capability_class ASC"
    );
    let mut stmt = conn.prepare(&sql).map_err(StoreError::from)?;
    let rows = stmt
        .query_map([session_id.as_str()], |r| {
            Ok(DelegationBrief {
                capability_class: r.get::<_, String>(0)?,
                status: r.get::<_, String>(1)?,
                expires_at: r.get::<_, i64>(2)?,
            })
        })
        .map_err(StoreError::from)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(StoreError::from)?;
    Ok(rows)
}

// ────────────────────────────────────────────────────────────────────
// Initiative context query
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InitiativeContext {
    pub initiative_id: String,
    pub state: String,
    pub tasks: Vec<TaskBrief>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TaskBrief {
    pub task_id: String,
    pub state: String,
}

fn load_initiative_context(
    session_id: &SessionId,
    store: &Arc<Store>,
) -> Result<Vec<InitiativeContext>, PromptError> {
    // INV-STORE-03: every table identifier comes from the typed
    // `Table` enum; no hard-coded SQL names.
    let tasks_tbl = Table::Tasks.as_str();
    let initiatives_tbl = Table::Initiatives.as_str();

    let conn = store.lock_sync();

    // Step 4a: distinct initiative_id values for this session.
    let initiative_sql = format!(
        "SELECT DISTINCT initiative_id FROM {tasks_tbl} \
         WHERE session_id = ?1 ORDER BY initiative_id ASC"
    );
    let mut init_stmt = conn.prepare(&initiative_sql).map_err(StoreError::from)?;
    let init_ids: Vec<String> = init_stmt
        .query_map([session_id.as_str()], |r| r.get::<_, String>(0))
        .map_err(StoreError::from)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(StoreError::from)?;
    drop(init_stmt);

    let mut out = Vec::with_capacity(init_ids.len());
    for init_id in init_ids {
        // Step 4b: initiative state.
        let state_sql = format!("SELECT state FROM {initiatives_tbl} WHERE initiative_id = ?1");
        let state: Option<String> = conn
            .query_row(&state_sql, [init_id.as_str()], |r| r.get::<_, String>(0))
            .map(Some)
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })
            .map_err(StoreError::from)?;
        let state = state.unwrap_or_else(|| "<unknown>".to_owned());

        // Step 4c: per-initiative task brief.
        let tasks_sql = format!(
            "SELECT task_id, state FROM {tasks_tbl} \
             WHERE session_id = ?1 AND initiative_id = ?2 \
             ORDER BY admitted_at ASC, task_id ASC"
        );
        let mut tasks_stmt = conn.prepare(&tasks_sql).map_err(StoreError::from)?;
        let task_rows: Vec<TaskBrief> = tasks_stmt
            .query_map([session_id.as_str(), init_id.as_str()], |r| {
                Ok(TaskBrief {
                    task_id: r.get::<_, String>(0)?,
                    state: r.get::<_, String>(1)?,
                })
            })
            .map_err(StoreError::from)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)?;
        drop(tasks_stmt);

        out.push(InitiativeContext {
            initiative_id: init_id,
            state,
            tasks: task_rows,
        });
    }
    Ok(out)
}

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_policy::PolicyBundle;
    use raxis_store::Store;
    use std::sync::Arc;

    fn empty_ctx_test_setup() -> (Arc<Store>, PolicyBundle, EpochBinding) {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let policy = PolicyBundle::for_tests_with_operators(Vec::new());
        let binding = EpochBinding::new();
        (store, policy, binding)
    }

    #[test]
    fn planner_api_body_contains_required_anchor_text() {
        // Catch silent edits to the embedded contract.
        assert!(PLANNER_API_BODY.contains("RAXIS Planner API"));
        assert!(PLANNER_API_BODY.contains("kernel-bound session"));
        assert!(PLANNER_API_BODY.contains("FAIL_PATH_POLICY_VIOLATION"));
    }

    #[test]
    fn render_concatenates_blocks_in_spec_order() {
        let p = AssembledPrompt {
            epoch_id: 7,
            session_id: SessionId::new_v4(),
            role_block: "ROLE".to_owned(),
            capability_block: "CAP".to_owned(),
            initiative_block: "INIT".to_owned(),
            constraint_block: "CON".to_owned(),
            assembled_at: 0,
            epoch_advance_observed: false,
            api_body: "API",
        };
        let s = p.render();
        let r = s.find("ROLE").unwrap();
        let c = s.find("CAP").unwrap();
        let i = s.find("INIT").unwrap();
        let n = s.find("CON").unwrap();
        let a = s.find("API").unwrap();
        assert!(r < c && c < i && i < n && n < a, "order broken: {s}");
    }

    #[test]
    fn build_capability_block_says_none_when_empty() {
        let s = build_capability_block(&[], 0);
        assert!(s.contains("No delegations"));
    }

    #[test]
    fn build_capability_block_lists_each_delegation() {
        let dels = vec![
            DelegationBrief {
                capability_class: "WriteSecrets".to_owned(),
                status: "Active".to_owned(),
                expires_at: 1_000,
            },
            DelegationBrief {
                capability_class: "NetworkEgress".to_owned(),
                status: "Active".to_owned(),
                expires_at: 2_000,
            },
        ];
        let s = build_capability_block(&dels, 100);
        assert!(s.contains("WriteSecrets"));
        assert!(s.contains("NetworkEgress"));
        // expires_in = expires_at - now_secs; 1000 - 100 = 900s.
        assert!(s.contains("expires_in=900s"));
        assert!(s.contains("expires_in=1900s"));
    }

    #[test]
    fn build_initiative_block_says_none_when_empty() {
        let s = build_initiative_block(&[]);
        assert!(s.contains("No tasks"));
    }

    #[test]
    fn build_initiative_block_lists_initiatives_and_tasks() {
        let inits = vec![InitiativeContext {
            initiative_id: "init-A".to_owned(),
            state: "Executing".to_owned(),
            tasks: vec![
                TaskBrief {
                    task_id: "task-1".to_owned(),
                    state: "Running".to_owned(),
                },
                TaskBrief {
                    task_id: "task-2".to_owned(),
                    state: "Admitted".to_owned(),
                },
            ],
        }];
        let s = build_initiative_block(&inits);
        assert!(s.contains("init-A"));
        assert!(s.contains("Executing"));
        assert!(s.contains("task-1"));
        assert!(s.contains("Running"));
        assert!(s.contains("task-2"));
        assert!(s.contains("Admitted"));
    }

    #[test]
    fn build_constraint_block_includes_epoch_and_counts() {
        let policy = PolicyBundle::for_tests_with_operators(Vec::new());
        let s = build_constraint_block(&policy);
        // for_tests_with_operators sets epoch=0; signed_by=""; etc.
        assert!(s.contains("epoch 0"));
        assert!(s.contains("Lanes defined:"));
        assert!(s.contains("Gates defined:"));
        assert!(s.contains("Egress domains allowlisted:"));
    }

    #[test]
    fn assemble_returns_session_not_found_for_unknown_session() {
        let (store, policy, binding) = empty_ctx_test_setup();
        let ctx = PromptCtx {
            store: &store,
            policy: &policy,
            binding: &binding,
            now_secs: 1,
        };
        let unknown = SessionId::new_v4();
        let err = assemble(&unknown, &ctx).unwrap_err();
        assert!(
            matches!(err, PromptError::SessionNotFound(_)),
            "got: {err:?}"
        );
    }

    #[test]
    fn epoch_advance_observed_flag_flips_on_invalidation_then_clears() {
        let (store, policy, binding) = empty_ctx_test_setup();

        // Create a real planner session so assemble() succeeds.
        use crate::authority::session::{create_session, Role as SessionRole, SessionConfig};
        use raxis_types::LineageId;
        let lineage = LineageId::new_v4();
        let (sid, _tok) = create_session(
            SessionRole::Planner,
            Some("/tmp/wt".to_owned()),
            None,
            None,
            lineage,
            &SessionConfig::default(),
            &store,
        )
        .unwrap();

        binding.invalidate(&sid);
        let ctx = PromptCtx {
            store: &store,
            policy: &policy,
            binding: &binding,
            now_secs: 1,
        };

        let p1 = assemble(&sid, &ctx).unwrap();
        assert!(
            p1.epoch_advance_observed,
            "first call should report epoch advance"
        );

        let p2 = assemble(&sid, &ctx).unwrap();
        assert!(!p2.epoch_advance_observed, "second call must NOT re-report");
    }

    #[test]
    fn assemble_succeeds_for_real_planner_session() {
        let (store, policy, binding) = empty_ctx_test_setup();
        use crate::authority::session::{create_session, Role as SessionRole, SessionConfig};
        use raxis_types::LineageId;
        let lineage = LineageId::new_v4();
        let (sid, _tok) = create_session(
            SessionRole::Planner,
            Some("/tmp/wt".to_owned()),
            None,
            None,
            lineage,
            &SessionConfig::default(),
            &store,
        )
        .unwrap();

        let ctx = PromptCtx {
            store: &store,
            policy: &policy,
            binding: &binding,
            now_secs: 42,
        };
        let p = assemble(&sid, &ctx).unwrap();
        assert_eq!(p.session_id, sid);
        assert_eq!(p.assembled_at, 42);
        assert!(p.role_block.contains("Planner"));
        assert!(p.role_block.contains(sid.as_str()));
        assert!(p.capability_block.contains("No delegations"));
        assert!(p.initiative_block.contains("No tasks"));
        assert!(p.constraint_block.contains("epoch 0"));
        assert!(!p.epoch_advance_observed);

        // Rendered prompt ends with the canonical API body verbatim.
        let rendered = p.render();
        assert!(
            rendered.ends_with(PLANNER_API_BODY),
            "API body must be the suffix"
        );
    }
}
