//! Generalised permanent-failure escalation helper for kernel-side
//! audit-event emit sites.
//!
//! Normative reference:
//!   * `specs/invariants.md §INV-INITIATIVE-PERMANENT-FAILURE-ESCALATION-COVERAGE-01`
//!   * `specs/v2/audit-paired-writes.md §4` (paired-write order)
//!   * `specs/v2/dashboard-hardening.md` (escalation lifecycle)
//!
//! ## Why this module exists
//!
//! Iter65 wired the `LogicalDeadlock` paired-write escalation for
//! ONE permanent-failure event class:
//! `OrchestratorRespawnCeilingExceeded`. The user's iter65-review
//! directive: **"Any type of permanent failure in the initiative
//! should trigger a notification or escalation as the case may be
//! to the operator."**
//!
//! This module generalises Bug 3's pattern. Every kernel-side emit
//! of a permanent-stall audit event calls
//! [`escalate_initiative_on_permanent_failure`], which:
//!
//!   1. Inserts a `LogicalDeadlock` escalation row + flips
//!      `initiatives.state = 'Failed'` in ONE SQLite transaction
//!      (paired-write per `audit-paired-writes.md §4`), with an
//!      idempotency key derived from
//!      `(initiative_id, cause_kind, cause_seq)` so a re-fire of
//!      the same cause cannot double-insert.
//!   2. Emits the chain-side audit anchor
//!      [`AuditEventKind::InitiativePermanentFailureEscalated`]
//!      AFTER the commit, carrying the cause discriminator + the
//!      escalation_id. Notification priority is `Critical` per
//!      `INV-NOTIFICATION-PRIORITY-PARITY-01` (the dispatch gate
//!      sees the new variant as Critical regardless of how the
//!      underlying cause is individually classified).
//!
//! The `LogicalDeadlock` escalation class is reused (rather than
//! introducing a new `EscalationClass::PermanentFailure` variant)
//! because:
//!
//!   * Adding a new class requires a SQLite migration (the
//!     `escalations.class` column has a `CHECK (class IN (...))`
//!     constraint), a new operator-approve handler arm, and a wire
//!     change in `RequestedEscalationScope`. None of those are in
//!     scope for a single-PR review-and-extend pass.
//!
//!   * The existing `LogicalDeadlock` semantics ("kernel observed
//!     a structural condition the operator must clear") generalise
//!     cleanly across every in-scope cause: the operator's
//!     approve-vs-deny decision is the same shape (approve =
//!     "retry; the cause has cleared", deny = "preserve Failed
//!     terminal state; the cause is not recoverable from this
//!     surface").
//!
//!   * The cause discriminator is preserved on the chain-side
//!     anchor (`InitiativePermanentFailureEscalated.cause_kind`)
//!     so dashboards + audit-replay tools can pivot by cause
//!     without losing structural information.
//!
//! ## Recovery semantics
//!
//! [`PermanentFailureCause::recoverable_via_approve`] documents
//! whether the cause's underlying condition CAN be cleared by an
//! operator-approve action. The shared
//! `approve_logical_deadlock_escalation_in_tx` handler (in
//! `orch_respawn_ceiling.rs`) always:
//!
//!   1. Flips the escalation `Pending → Approved`.
//!   2. Resets `initiatives.orchestrator_no_progress_respawn_count`
//!      to 0.
//!   3. Transitions `initiatives.state = 'Failed' → 'Executing'`
//!      (when the row is in `'Failed'`).
//!
//! For recoverable causes (capacity-pressure cleared, transient
//! VM failure resolved, operator unblocked the egress stall),
//! step (3) lets the next orchestrator decision-cycle pick up
//! work. For non-recoverable causes (plan schema error, hard
//! merge conflict the kernel cannot resolve), step (3) is a
//! no-op-but-still-clears-the-block — the next orchestrator
//! decision-cycle will hit the same condition and trip a fresh
//! permanent-failure escalation. The
//! `recoverable_via_approve = false` signal is surfaced on the
//! audit anchor so operators can choose Deny as the
//! semantically-correct response and the dashboard can render a
//! "non-recoverable" badge. See
//! `INV-OPERATOR-APPROVE-RECOVERY-SEMANTICS-01`.

use std::sync::Arc;

use raxis_audit_tools::AuditEventKind;
use raxis_store::Table;
use raxis_types::unix_now_secs;

use crate::ipc::context::HandlerContext;

/// Closed enum of in-scope permanent-failure causes the helper
/// recognises. Adding a new variant requires:
///
///   1. Mapping the new variant's `as_kind_str()` to the matching
///      `AuditEventKind::as_str()` value.
///   2. Wiring the helper into the new variant's emit site.
///   3. Documenting the recovery semantics in
///      `specs/v2/dashboard-hardening.md` under the
///      "Permanent-failure recovery semantics" table.
///   4. Adding the corresponding test in
///      `kernel/tests/initiative_permanent_failure_escalation.rs`.
///
/// Pinned by
/// `INV-INITIATIVE-PERMANENT-FAILURE-ESCALATION-COVERAGE-01`.
#[derive(Debug, Clone)]
pub enum PermanentFailureCause {
    /// `SessionVmFailedFinal` — VM spawn exhausted its retry budget
    /// or hit an explicit `IsolationFailureClass::Permanent`. The
    /// initiative cannot proceed because the substrate refused to
    /// spawn the planner. Recovery via operator-approve is
    /// possible if the underlying cause was transient host
    /// pressure (fresh retry succeeds); for permanent-class
    /// failures (signature mismatch, image corruption) the
    /// operator should Deny.
    SessionVmFailedFinal {
        /// Carries through to the audit anchor's `cause_summary`.
        /// Typically the `final_reason` field from the underlying
        /// `SessionVmFailedFinal` event (e.g. `"kvm_oom"`,
        /// `"signature_mismatch"`).
        final_reason: String,
        /// Total spawn attempts (1-indexed) before exhaustion.
        /// Used as the cause-seq half of the idempotency key so a
        /// successive failure on the same initiative inserts a
        /// fresh escalation rather than dedup'ing against the
        /// prior one.
        total_attempts: u32,
    },
    /// `PlanRejected` — admission validator refused the plan. The
    /// initiative never reaches `Executing`. Recovery via
    /// operator-approve is structurally impossible (the rejected
    /// plan needs to be re-submitted; approve does not re-run
    /// admission); the operator should Deny + open a fresh plan.
    PlanRejected {
        /// Reason text from the admission validator. Inlined into
        /// the escalation justification so the operator can act
        /// without chain-walking.
        reason: String,
    },
    /// `EscalationTimedOut` — a previously-pending operator
    /// escalation passed its `timeout_at_unix` without resolution.
    /// The initiative remains blocked behind whatever the
    /// underlying escalation requested. Recoverable: the operator
    /// can re-approve via this fresh anchor.
    EscalationTimedOut {
        /// The original escalation that timed out. Surfaces in the
        /// new anchor's justification so the operator can correlate
        /// against the original request.
        original_escalation_id: String,
    },
    /// `EscalationRateLimitExceeded` — operator-facing storm
    /// protection tripped. The kernel will not fire further
    /// escalations on this lineage until the rate-limit window
    /// clears, and the in-flight work is therefore stuck behind
    /// the storm. Critical because the operator cannot SEE the
    /// underlying escalations through the muted channel; this
    /// anchor is the bypass signal that surfaces in the inbox via
    /// the dispatch-gate Critical filter regardless of the
    /// rate-limit mute. Not recoverable via approve in the usual
    /// sense — the operator should investigate the underlying
    /// storm pattern.
    EscalationRateLimitExceeded {
        /// Lineage that tripped the rate limit. Inlined for
        /// operator triage.
        lineage_id: String,
    },
    /// `SessionEgressStallDetected` — sustained no-progress on a
    /// session's egress stream while the session is on the
    /// initiative's critical path. Recoverable if the operator
    /// adjusts policy to admit the stalled destination.
    SessionEgressStallDetected {
        /// Session whose egress stalled.
        session_id: String,
        /// Stall reason text from the underlying detector
        /// (e.g. `"repeated_TransparentProxyDenied"`). Inlined.
        reason: String,
    },
    /// `MergeFastForwardFailed` — Orchestrator's fast-forward
    /// merge of a Reviewer-approved branch onto the integration
    /// ref failed (typically because the integration ref advanced
    /// since the worktree was checked out). Recoverable if the
    /// operator rebases manually or approves the existing
    /// `MergeConflict` escalation; the permanent-failure anchor
    /// surfaces in addition to the planner-side `MergeConflict`
    /// escalation so a Critical-only filter still pages.
    MergeFastForwardFailed {
        /// The integration ref the FF target. Inlined.
        target_ref: String,
        /// The category text from the underlying audit event
        /// (e.g. `"non_fast_forward"`, `"unrelated_histories"`).
        category: String,
    },
    /// `PushFailed` — the kernel-side push of an
    /// integration-merge commit to the remote failed and exhausted
    /// any retry budget. Recoverable if the operator addresses
    /// the network / auth condition + retries via a fresh
    /// orchestrator decision cycle.
    PushFailed {
        /// Remote name + refspec the push was attempting.
        remote: String,
        refspec: String,
        /// Reason text from the push attempt. Inlined.
        reason: String,
    },
    /// `InitiativeStateChanged { new_state: Failed }` from any
    /// non-operator-driven cause. Catch-all backstop for
    /// permanent failures that did NOT fire one of the more
    /// specific variants above (e.g. a future audit kind that
    /// transitions an initiative to Failed without going through
    /// any of the wired emit sites). Recoverable depends on the
    /// underlying cause; the helper conservatively flags as
    /// recoverable so the inbox surfaces a "may approve" affordance.
    InitiativeStateChangedToFailed {
        /// Whatever the from_state was. Inlined for forensic
        /// correlation against the audit chain.
        from_state: String,
    },
}

impl PermanentFailureCause {
    /// The `AuditEventKind::as_str()` value of the underlying
    /// audit event. Stamped verbatim onto
    /// [`AuditEventKind::InitiativePermanentFailureEscalated::cause_kind`]
    /// so dashboard pivots by cause do not need to reverse-engineer
    /// the justification text.
    pub fn as_kind_str(&self) -> &'static str {
        match self {
            Self::SessionVmFailedFinal { .. } => "SessionVmFailedFinal",
            Self::PlanRejected { .. } => "PlanRejected",
            Self::EscalationTimedOut { .. } => "EscalationTimedOut",
            Self::EscalationRateLimitExceeded { .. } => "EscalationRateLimitExceeded",
            Self::SessionEgressStallDetected { .. } => "SessionEgressStallDetected",
            Self::MergeFastForwardFailed { .. } => "MergeFastForwardFailed",
            Self::PushFailed { .. } => "PushFailed",
            Self::InitiativeStateChangedToFailed { .. } => "InitiativeStateChanged",
        }
    }

    /// Stable per-cause-instance string used as the cause-seq half
    /// of the helper's idempotency key. Distinct from the
    /// invariant-level cause_kind: two `PushFailed` events on the
    /// same initiative with different remotes get two different
    /// escalation rows, while a re-fire of the same cause shape
    /// (same remote + same refspec) dedup's against the first.
    pub fn cause_seq(&self) -> String {
        match self {
            Self::SessionVmFailedFinal { total_attempts, .. } => {
                format!("attempts={total_attempts}")
            }
            Self::PlanRejected { reason } => {
                format!("reason_sha={}", short_hash(reason))
            }
            Self::EscalationTimedOut {
                original_escalation_id,
            } => format!("orig={original_escalation_id}"),
            Self::EscalationRateLimitExceeded { lineage_id } => {
                format!("lineage={lineage_id}")
            }
            Self::SessionEgressStallDetected { session_id, .. } => {
                format!("session={session_id}")
            }
            Self::MergeFastForwardFailed {
                target_ref,
                category,
            } => format!("ref={target_ref};cat={category}"),
            Self::PushFailed {
                remote, refspec, ..
            } => format!("remote={remote};ref={refspec}"),
            Self::InitiativeStateChangedToFailed { from_state } => {
                format!("from={from_state}")
            }
        }
    }

    /// Operator-facing short-form text inlined into the
    /// escalation justification + the chain-side anchor's
    /// `cause_summary`. Truncated to 1 KiB to bound the audit row
    /// size.
    pub fn cause_summary(&self) -> String {
        let raw = match self {
            Self::SessionVmFailedFinal {
                final_reason,
                total_attempts,
            } => format!(
                "VM spawn permanent failure after {total_attempts} attempts: {final_reason}"
            ),
            Self::PlanRejected { reason } => {
                format!("plan admission rejected: {reason}")
            }
            Self::EscalationTimedOut {
                original_escalation_id,
            } => format!("escalation {original_escalation_id} timed out before operator response"),
            Self::EscalationRateLimitExceeded { lineage_id } => format!(
                "escalation rate limit exceeded on lineage {lineage_id}; \
                 underlying escalations are muted"
            ),
            Self::SessionEgressStallDetected { session_id, reason } => {
                format!("session {session_id} egress stalled on critical path: {reason}")
            }
            Self::MergeFastForwardFailed {
                target_ref,
                category,
            } => format!("merge fast-forward to {target_ref} failed: {category}"),
            Self::PushFailed {
                remote,
                refspec,
                reason,
            } => format!("push to {remote} {refspec} failed: {reason}"),
            Self::InitiativeStateChangedToFailed { from_state } => format!(
                "initiative transitioned {from_state} → Failed via non-operator-driven cause"
            ),
        };
        if raw.len() > 1024 {
            let mut end = 1024;
            while end > 0 && !raw.is_char_boundary(end) {
                end -= 1;
            }
            return raw[..end].to_owned();
        }
        raw
    }

    /// Whether the cause's underlying condition CAN be cleared by
    /// an operator-approve action. See module-level docs for the
    /// per-cause matrix; `INV-OPERATOR-APPROVE-RECOVERY-SEMANTICS-01`
    /// pins the contract.
    pub fn recoverable_via_approve(&self) -> bool {
        match self {
            // Recoverable: the underlying transient condition (host
            // pressure, network blip) may have cleared by the time
            // the operator approves.
            Self::SessionVmFailedFinal { .. }
            | Self::EscalationTimedOut { .. }
            | Self::SessionEgressStallDetected { .. }
            | Self::MergeFastForwardFailed { .. }
            | Self::PushFailed { .. }
            | Self::InitiativeStateChangedToFailed { .. } => true,
            // Non-recoverable from the approve surface: the operator
            // must take an out-of-band action (re-submit plan,
            // investigate the storm pattern). Approve still flips
            // the FSM but the next decision-cycle will re-trip.
            Self::PlanRejected { .. } | Self::EscalationRateLimitExceeded { .. } => false,
        }
    }
}

/// Compute a short hex hash of an arbitrary string. Used to
/// derive a stable cause-seq from variable-length reason text
/// (e.g. plan rejection reasons) without bloating the
/// idempotency key. Not security-sensitive — collisions are
/// merely a deduplication issue, and the cause text is operator-
/// provided not adversary-provided.
fn short_hash(s: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    format!("{:016x}", h.finish())
}

/// Outcome of a single helper invocation. Mostly informational —
/// callers should NOT branch on this value (the helper is best-
/// effort and a failure to insert the escalation row does not
/// release the caller from any other obligation), but tests pin
/// the outcome shape so a regression in the helper is observable.
#[derive(Debug, Clone)]
pub enum EscalateOutcome {
    /// The escalation row was inserted, the initiative was
    /// transitioned to `Failed`, and the chain-side anchor was
    /// emitted. Carries the new escalation_id for forensic
    /// correlation against the chain.
    Escalated { escalation_id: String },
    /// The helper observed an existing escalation row with the
    /// same idempotency key (the cause has already fired on this
    /// initiative). No new row was inserted; no audit anchor was
    /// emitted. Operators see the original escalation; this is
    /// the deduplication path.
    AlreadyEscalated,
    /// The initiative was already in a terminal state at the time
    /// the helper ran (e.g. an operator-driven `Aborted` raced the
    /// permanent-failure emit). The helper is a no-op; the audit
    /// chain still carries the underlying permanent-failure event
    /// from the caller.
    InitiativeAlreadyTerminal,
    /// Both FK-anchor lookup tiers failed (no worker session, no
    /// orchestrator session). The escalation row was NOT inserted
    /// (the FK constraint would refuse). The chain-side anchor
    /// IS still emitted with `escalation_id = None` so the
    /// permanent-failure signal reaches the inbox via the
    /// Critical-priority dispatch path; the
    /// `LogicalDeadlockEscalationSkippedNoFkAnchor` warn log is
    /// the structured-log counterpart for forensic readers.
    AnchorlessEscalation,
    /// SQL or audit-emit failure. Surfaced for observability;
    /// callers MUST NOT depend on a successful escalation for
    /// correctness — the helper is a best-effort defense-in-depth
    /// surface, not an authoritative state-mutation.
    Failed { reason: String },
}

/// Fire the paired-write escalation + audit anchor for a
/// permanent-stall event on `initiative_id`.
///
/// **Idempotency.** The helper's idempotency key is
/// `kernel-initiative-permanent-failure:{initiative_id}:{cause_kind}:{cause_seq}`,
/// so a re-fire of the same cause shape on the same initiative
/// dedup's against the original row (the
/// `escalations.UNIQUE(session_id, idempotency_key)` index
/// short-circuits the INSERT). Successive distinct causes (e.g.
/// two different `PushFailed` events with different refspecs)
/// each get their own row.
///
/// **Non-blocking on caller failures.** The helper returns
/// [`EscalateOutcome`] for observability but the caller should NOT
/// branch on it — the underlying audit event for the cause has
/// already been emitted at the call site, and the helper's
/// best-effort failure to insert the escalation row does not
/// invalidate the caller's correctness. The chain-side anchor +
/// escalation row are operator-attention enrichment; the underlying
/// permanent-failure event already lives in the chain.
///
/// **Paired-write order.** Same shape as Bug 3:
///   1. INSERT `escalations` (LogicalDeadlock, Kernel, Pending) +
///      UPDATE `initiatives.state = 'Failed'` in ONE SQLite
///      transaction.
///   2. Post-commit, emit
///      `AuditEventKind::InitiativePermanentFailureEscalated`.
///
/// This matches `audit-paired-writes.md §4`: the audit emit runs
/// post-commit; a crash between commit + emit leaves a consistent
/// SQLite state with a missing chain-side anchor, recovered by the
/// advisory `INV-AUDIT-PAIRED-06` sweep.
pub async fn escalate_initiative_on_permanent_failure(
    ctx: Arc<HandlerContext>,
    initiative_id: String,
    cause: PermanentFailureCause,
) -> EscalateOutcome {
    let cause_kind = cause.as_kind_str().to_owned();
    let cause_seq = cause.cause_seq();
    let cause_summary = cause.cause_summary();
    let recoverable_via_approve = cause.recoverable_via_approve();

    let policy_epoch_for_escalation: i64 = ctx.policy.load_full().epoch() as i64;
    let escalation_timeout_secs = ctx.policy.load_full().escalation_timeout().as_secs() as i64;

    let init_for_tx = initiative_id.clone();
    let cause_kind_for_tx = cause_kind.clone();
    let cause_seq_for_tx = cause_seq.clone();
    let cause_summary_for_tx = cause_summary.clone();

    let store_for_tx = Arc::clone(&ctx.store);

    // ── Step 1: paired-write transaction. ──────────────────────────
    //
    // Mirrors `respawn_orchestrator_for_initiative`'s Step 1b
    // structure but without the orch-respawn-counter increment
    // (that lives in the orch-respawn-ceiling helper because it is
    // specific to that cause). The two writes share one tx so a
    // crash between them leaves the store internally consistent;
    // the subsequent audit emit is post-commit per
    // `audit-paired-writes.md §4`.
    let outcome = tokio::task::spawn_blocking(
        move || -> Result<TxOutcome, rusqlite::Error> {
            let mut conn = store_for_tx.lock_sync();
            let tx = conn.transaction()?;

            // ── 1a: skip-checks. The initiative MUST be in a
            //        non-terminal state for the helper to do
            //        anything; an operator-driven Aborted /
            //        Completed already settled the FSM and the
            //        helper's Failed transition would be a
            //        regression.
            let current_state: Option<String> = tx
                .query_row(
                    &format!(
                        "SELECT state FROM {init} WHERE initiative_id = ?1",
                        init = Table::Initiatives.as_str(),
                    ),
                    rusqlite::params![&init_for_tx],
                    |r| r.get::<_, String>(0),
                )
                .ok();
            let Some(state) = current_state else {
                return Ok(TxOutcome::InitiativeMissing);
            };
            // Terminal states the helper refuses to overwrite. The
            // strings track the `InitiativeState` enum's `as_str`
            // implementation; if the kernel adds a new terminal
            // state it MUST be added here, otherwise the helper
            // will spuriously flip a terminal-Completed initiative
            // to Failed (paired-write violation).
            const TERMINAL_STATES: &[&str] = &["Completed", "Failed", "Cancelled", "Aborted"];
            if TERMINAL_STATES.contains(&state.as_str()) {
                return Ok(TxOutcome::AlreadyTerminal);
            }

            // ── 1b: insert the LogicalDeadlock escalation row.
            //        Reuses the iter65 `insert_logical_deadlock_escalation_in_tx`
            //        helper (which already has the two-tier FK
            //        anchor lookup + the truncate-to-1KiB bound)
            //        but with cause-specific
            //        `last_intent_kind` / `last_rejection_reason`
            //        text + a cause-keyed idempotency key.
            //
            //        We override the idempotency key by passing a
            //        custom one through the helper-level wrapper
            //        below; the upstream helper's default key
            //        (`kernel-orch-respawn-ceiling:{init}:{att}`)
            //        would collide with the orch-respawn ceiling
            //        path on the same initiative if we used it
            //        verbatim.
            let now_secs = unix_now_secs();
            let timeout_at = now_secs.saturating_add(escalation_timeout_secs);
            let idempotency_key = format!(
                "kernel-initiative-permanent-failure:{init_for_tx}:{cause_kind_for_tx}:{cause_seq_for_tx}",
            );

            let escalation_id_opt = insert_permanent_failure_escalation_in_tx(
                &tx,
                &init_for_tx,
                &cause_kind_for_tx,
                &cause_summary_for_tx,
                &idempotency_key,
                timeout_at,
                now_secs,
                policy_epoch_for_escalation,
            )?;

            // ── 1c: flip the initiative to `Failed`. The cascade
            //        of in-flight tasks to `Failed` happens via
            //        the standard `transition_task_in_tx` path on
            //        the next orchestrator decision-cycle; the
            //        helper does NOT mass-fail tasks here because
            //        per-cause fan-out semantics differ (e.g. a
            //        `PushFailed` only stalls the merge task; a
            //        `SessionVmFailedFinal` may strand multiple
            //        executor tasks). The cascade is the caller's
            //        responsibility on the in-scope kinds where
            //        it is applicable.
            tx.execute(
                &format!(
                    "UPDATE {init}
                        SET state        = 'Failed',
                            completed_at = strftime('%s','now')
                      WHERE initiative_id = ?1
                        AND state NOT IN ('Completed','Failed','Cancelled','Aborted')",
                    init = Table::Initiatives.as_str(),
                ),
                rusqlite::params![&init_for_tx],
            )?;

            tx.commit()?;
            Ok(TxOutcome::Committed { escalation_id_opt })
        },
    )
    .await;

    let tx_result = match outcome {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => {
            return EscalateOutcome::Failed {
                reason: format!("sql: {e}"),
            };
        }
        Err(e) => {
            return EscalateOutcome::Failed {
                reason: format!("spawn_blocking join: {e}"),
            };
        }
    };

    let escalation_id_opt = match tx_result {
        TxOutcome::Committed { escalation_id_opt } => escalation_id_opt,
        TxOutcome::AlreadyTerminal => {
            eprintln!(
                "{{\"level\":\"info\",\
                 \"event\":\"initiative_permanent_failure_escalation_skipped\",\
                 \"initiative_id\":\"{initiative_id}\",\
                 \"reason\":\"initiative_already_terminal\",\
                 \"cause_kind\":\"{cause_kind}\"}}",
            );
            return EscalateOutcome::InitiativeAlreadyTerminal;
        }
        TxOutcome::InitiativeMissing => {
            eprintln!(
                "{{\"level\":\"warn\",\
                 \"event\":\"initiative_permanent_failure_escalation_skipped\",\
                 \"initiative_id\":\"{initiative_id}\",\
                 \"reason\":\"initiative_row_missing\",\
                 \"cause_kind\":\"{cause_kind}\"}}",
            );
            return EscalateOutcome::Failed {
                reason: "initiative_row_missing".to_owned(),
            };
        }
    };

    // Detect the dedup case: the helper returned
    // `Some(escalation_id)` when it inserted a fresh row, but the
    // ON CONFLICT path returns `Ok(None)` from the underlying
    // helper; the cause was already escalated.
    let outcome_for_audit = match &escalation_id_opt {
        Some(_) => EscalateOutcome::Escalated {
            escalation_id: escalation_id_opt.clone().unwrap(),
        },
        None => {
            // Either the dedup case or the anchor-less case. We
            // distinguish by re-reading the escalations table for
            // the cause-keyed idempotency key — if a row already
            // exists, dedup; if not, anchor-less.
            let store_for_lookup = Arc::clone(&ctx.store);
            let init_for_lookup = initiative_id.clone();
            let cause_kind_for_lookup = cause_kind.clone();
            let cause_seq_for_lookup = cause_seq.clone();
            let existing = tokio::task::spawn_blocking(move || -> Option<String> {
                let conn = store_for_lookup.lock_sync();
                let key = format!(
                    "kernel-initiative-permanent-failure:{init_for_lookup}:{cause_kind_for_lookup}:{cause_seq_for_lookup}",
                );
                conn.query_row(
                    &format!(
                        "SELECT escalation_id FROM {esc}
                          WHERE idempotency_key = ?1
                            AND initiative_id   = ?2
                          ORDER BY created_at DESC LIMIT 1",
                        esc = Table::Escalations.as_str(),
                    ),
                    rusqlite::params![&key, &init_for_lookup],
                    |r| r.get::<_, String>(0),
                )
                .ok()
            })
            .await
            .ok()
            .flatten();
            if existing.is_some() {
                eprintln!(
                    "{{\"level\":\"info\",\
                     \"event\":\"initiative_permanent_failure_escalation_dedup\",\
                     \"initiative_id\":\"{initiative_id}\",\
                     \"cause_kind\":\"{cause_kind}\",\
                     \"cause_seq\":\"{cause_seq}\"}}",
                );
                return EscalateOutcome::AlreadyEscalated;
            }
            eprintln!(
                "{{\"level\":\"warn\",\
                 \"event\":\"LogicalDeadlockEscalationSkippedNoFkAnchor\",\
                 \"initiative_id\":\"{initiative_id}\",\
                 \"cause_kind\":\"{cause_kind}\",\
                 \"invariant\":\"INV-INITIATIVE-PERMANENT-FAILURE-ESCALATION-COVERAGE-01\"}}",
            );
            EscalateOutcome::AnchorlessEscalation
        }
    };

    // ── Step 2: chain-side audit anchor. Always emitted (even on
    //   the anchor-less path) so the inbox surfaces the
    //   permanent-failure signal regardless of whether the
    //   FK-anchor lookup succeeded. The anchor's
    //   `escalation_id: Option<String>` carries the (None) on the
    //   anchor-less path so dashboards can render a
    //   "no operator-actionable surface; chain-only" badge.
    if let Err(e) = ctx.audit.emit(
        AuditEventKind::InitiativePermanentFailureEscalated {
            initiative_id: initiative_id.clone(),
            cause_kind: cause_kind.clone(),
            cause_summary: cause_summary.clone(),
            escalation_id: escalation_id_opt.clone(),
            recoverable_via_approve,
        },
        None,
        None,
        Some(initiative_id.as_str()),
    ) {
        eprintln!(
            "{{\"level\":\"warn\",\
             \"event\":\"InitiativePermanentFailureEscalatedAuditEmitFailed\",\
             \"initiative_id\":\"{initiative_id}\",\
             \"cause_kind\":\"{cause_kind}\",\
             \"error\":\"{e}\"}}",
        );
    }

    outcome_for_audit
}

/// Internal result shape for the spawn_blocking transaction.
enum TxOutcome {
    Committed { escalation_id_opt: Option<String> },
    AlreadyTerminal,
    InitiativeMissing,
}

/// Wrapper around the iter65 `insert_logical_deadlock_escalation_in_tx`
/// shape that lets the permanent-failure helper override the
/// idempotency key. The upstream helper hard-codes
/// `kernel-orch-respawn-ceiling:{init}:{att}`; the permanent-
/// failure path needs its own key namespace
/// (`kernel-initiative-permanent-failure:...`) so the two paths
/// don't collide on the same initiative.
///
/// Same two-tier FK-anchor lookup as the upstream:
///   * Tier 1: most-recently FSM-touched task with a non-NULL
///     session_id.
///   * Tier 2: any task on the initiative + most-recent
///     Orchestrator session row.
///
/// Returns `Ok(Some(escalation_id))` on insert, `Ok(None)` on
/// either the dedup case (ON CONFLICT) or the no-FK-anchor case.
/// Caller distinguishes the two by re-reading the escalations
/// table for the idempotency key (see the helper above).
#[allow(clippy::too_many_arguments)]
fn insert_permanent_failure_escalation_in_tx(
    tx: &rusqlite::Connection,
    initiative_id: &str,
    cause_kind: &str,
    cause_summary: &str,
    idempotency_key: &str,
    timeout_at_unix: i64,
    now_unix: i64,
    policy_epoch: i64,
) -> Result<Option<String>, rusqlite::Error> {
    use raxis_types::{EscalationClass, EscalationStatus, RequestedEscalationScope};
    use rusqlite::OptionalExtension;

    let tasks = Table::Tasks.as_str();
    let sessions = Table::Sessions.as_str();
    let escalations = Table::Escalations.as_str();

    // Two-tier FK lookup, identical to
    // `orch_respawn_ceiling::insert_logical_deadlock_escalation_in_tx`.
    let triple: Option<(String, String, String)> = match tx
        .query_row(
            &format!(
                "SELECT t.task_id, s.session_id, s.lineage_id
                   FROM {tasks} t
                   JOIN {sessions} s ON s.session_id = t.session_id
                  WHERE t.initiative_id = ?1
                    AND t.session_id IS NOT NULL
                  ORDER BY t.transitioned_at DESC
                  LIMIT 1"
            ),
            rusqlite::params![initiative_id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?
    {
        Some(t) => Some(t),
        None => {
            let any_task: Option<String> = tx
                .query_row(
                    &format!(
                        "SELECT task_id FROM {tasks}
                          WHERE initiative_id = ?1
                       ORDER BY transitioned_at DESC
                          LIMIT 1"
                    ),
                    rusqlite::params![initiative_id],
                    |r| r.get::<_, String>(0),
                )
                .optional()?;
            let orch_session: Option<(String, String)> = tx
                .query_row(
                    &format!(
                        "SELECT session_id, lineage_id FROM {sessions}
                          WHERE initiative_id     = ?1
                            AND session_agent_type = 'Orchestrator'
                       ORDER BY created_at DESC
                          LIMIT 1"
                    ),
                    rusqlite::params![initiative_id],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
                )
                .optional()?;
            match (any_task, orch_session) {
                (Some(t), Some((s, l))) => Some((t, s, l)),
                _ => None,
            }
        }
    };

    let Some((task_id, session_id, lineage_id)) = triple else {
        return Ok(None);
    };

    let escalation_id = uuid::Uuid::new_v4().to_string();
    let initiative_uuid = match raxis_types::InitiativeId::parse(initiative_id) {
        Ok(id) => id,
        Err(_) => return Ok(None),
    };

    // The scope JSON re-uses the LogicalDeadlock variant — the
    // structural shape (initiative-scoped escalation with
    // attempts + window + last_intent_kind + last_rejection_reason
    // text) is identical for the permanent-failure use case, with
    // the cause_kind + cause_summary substituted into the text
    // fields. `attempts` is `1` for the first fire (the cause has
    // happened once); successive cause-seq-keyed re-fires
    // dedup against this row.
    let scope = RequestedEscalationScope::LogicalDeadlock {
        initiative_id: initiative_uuid,
        attempts: 1,
        window_secs: 0,
        last_intent_kind: cause_kind.to_owned(),
        last_rejection_reason: cause_summary.to_owned(),
    };
    let scope_json = serde_json::to_string(&scope)
        .expect("RequestedEscalationScope is always JSON-serialisable");

    let justification = format!(
        "Initiative permanent-failure escalation triggered by audit \
         event {cause_kind}: {cause_summary}. Operator approval \
         resets the orchestrator no-progress respawn counter and \
         transitions the initiative back to `Executing`; deny to \
         preserve the `Failed` terminal state. See \
         INV-INITIATIVE-PERMANENT-FAILURE-ESCALATION-COVERAGE-01 \
         for per-cause recovery semantics."
    );

    let inserted = tx.execute(
        &format!(
            "INSERT INTO {escalations} (
                escalation_id, session_id, task_id, lineage_id, initiative_id,
                class, requested_scope_json, justification, idempotency_key,
                status, created_at, timeout_at, initiator
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 'Kernel')
             ON CONFLICT(session_id, idempotency_key) DO NOTHING"
        ),
        rusqlite::params![
            escalation_id,
            session_id,
            task_id,
            lineage_id,
            initiative_id,
            EscalationClass::LogicalDeadlock.as_sql_str(),
            scope_json,
            justification,
            idempotency_key,
            EscalationStatus::Pending.as_sql_str(),
            now_unix,
            timeout_at_unix,
        ],
    )?;
    let _ = policy_epoch;

    if inserted == 0 {
        return Ok(None);
    }
    Ok(Some(escalation_id))
}
