// raxis-kernel::handlers::escalation — Planner-side EscalationRequest handler.
//
// Normative reference:
//   - kernel-core.md §2.3 `src/ipc/handlers/escalation.rs`
//   - peripherals.md §3.1 "EscalationRequest wire shape"
//   - planner-api.md §"Escalating for higher authority"
//   - kernel-store.md §2.5.1 Table 9 (`escalations`)
//   - kernel-store.md §2.5.5 "Escalation submission" (rate-limit + quarantine)
//
// Called by `accept_planner_loop` for every IpcMessage::EscalationRequest
// frame received on `planner.sock`.
//
// 7-step pipeline:
//
//   1. Resolve session_token → SessionRow (identity gate).
//   2. Validate the wire payload (justification non-empty + ≤ 4096 chars,
//      `class` matches `requested_scope.kind`, idempotency_key non-nil).
//   3. Look up the task → recover initiative_id; verify the task is owned
//      by *this* session's lineage (no cross-lineage escalations).
//   4. Idempotency: if a row with (session_id, idempotency_key) already
//      exists return AlreadyPending { escalation_id }. We do this BEFORE
//      the rate-limit check so an idempotent retry is free, per
//      planner-api.md "Every new submission with a different key counts
//      toward the rate-limit window" — duplicates do not.
//   5. Lineage rate-limit + quarantine check (kernel-store.md §2.5.5):
//        - if quarantined=1 → Rejected { LineageQuarantined } and STOP.
//        - if window expired → reset window; escalation_count = 0.
//        - if escalation_count + 1 > max_per_window:
//            * advance quarantine_trigger_count;
//            * if it crosses quarantine_threshold → set quarantined=1,
//              emit LineageQuarantined audit, return Rejected { LineageQuarantined };
//            * otherwise emit EscalationRateLimitExceeded audit and return
//              Rejected { RateLimitExceeded }.
//        - otherwise: escalation_count += 1.
//   6. INSERT the escalations row (status='Pending') in the same SQL
//      transaction as step 5's UPDATE so a partial write is impossible.
//   7. Commit. After commit, emit `EscalationSubmitted` audit and return
//      `Submitted { escalation_id, timeout_at }`.
//
// All blocking SQLite work is done inside `tokio::task::spawn_blocking`
// because `Store::lock_sync()` would otherwise panic the tokio worker
// thread (same pattern as handlers::intent and the operator handlers).

use std::sync::Arc;

use raxis_audit_tools::AuditEventKind;
use raxis_store::Table;
use raxis_types::{
    unix_now_secs, EscalationId, EscalationRejectionReason, EscalationRequest,
    EscalationResponse, EscalationStatus,
};

use crate::authority;
use crate::ipc::context::HandlerContext;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Maximum justification length per peripherals.md §3.1
/// "justification — required, non-empty, max 4096 chars".
const JUSTIFICATION_MAX_BYTES: usize = 4096;

// INV-STORE-03 (kernel-store.md §2.5.1): "no raw SQL table-name literals
// in raxis/kernel/src; use Table enum + .as_str()". Same posture for
// status strings — sourced from the typed enum's `.as_sql_str()` so
// any future rename in `raxis-types` propagates by compile error rather
// than silent SQL drift.
const ESCALATIONS:          &str = Table::Escalations.as_str();
const TASKS:                &str = Table::Tasks.as_str();
const SESSIONS:             &str = Table::Sessions.as_str();
const LINEAGE_RATE_LIMITS:  &str = Table::LineageRateLimits.as_str();
const INITIATIVES:          &str = Table::Initiatives.as_str();

/// Dispatch one EscalationRequest and return the EscalationResponse.
///
/// Never panics. Any internal error (transport, store, policy) is
/// converted to a Rejected response — the connection stays open so the
/// planner can retry with fresh idempotency_key.
///
/// The connection-level dispatcher is responsible for writing the
/// returned `IpcMessage::KernelEscalationResponse` frame back to the
/// planner.
pub async fn handle(req: EscalationRequest, ctx: &Arc<HandlerContext>) -> EscalationResponse {
    match handle_inner(req, ctx).await {
        Ok(resp) => resp,
        Err(rej) => EscalationResponse::Rejected { reason: rej },
    }
}

// ---------------------------------------------------------------------------
// Inner pipeline
// ---------------------------------------------------------------------------

/// Internal failure shape — every variant maps to either a Rejected
/// response (with one of the two on-wire reasons) or, in catch-all
/// cases, a `RateLimitExceeded` rejection so the planner can back off
/// rather than mistake a transport failure for a permanent denial.
async fn handle_inner(
    req: EscalationRequest,
    ctx: &Arc<HandlerContext>,
) -> Result<EscalationResponse, EscalationRejectionReason> {
    // ── Step 1: resolve session_token ─────────────────────────────────
    // Cheap: a single keyed SELECT under the store mutex.
    let store_for_session = Arc::clone(&ctx.store);
    let token_owned = req.session_token.clone();
    let session = tokio::task::spawn_blocking(move || {
        authority::session::get_session_by_token(&token_owned, &store_for_session)
    })
    .await
    .map_err(|_| EscalationRejectionReason::RateLimitExceeded)?
    .map_err(|_| EscalationRejectionReason::RateLimitExceeded)?;

    // Defence in depth: revoked or expired sessions cannot escalate.
    let now_secs = unix_now_secs();
    if session.revoked_at.is_some() || session.expires_at <= now_secs {
        return Err(EscalationRejectionReason::RateLimitExceeded);
    }

    // ── Step 2: validate wire payload ─────────────────────────────────
    if req.justification.trim().is_empty()
        || req.justification.len() > JUSTIFICATION_MAX_BYTES
    {
        return Err(EscalationRejectionReason::RateLimitExceeded);
    }
    if req.requested_scope.class() != req.class {
        return Err(EscalationRejectionReason::RateLimitExceeded);
    }
    if req.idempotency_key.is_nil() {
        return Err(EscalationRejectionReason::RateLimitExceeded);
    }

    // ── Step 3-7: do the rest of the work in one spawn_blocking ──────
    // We bundle steps 3-6 into one blocking scope so the lineage
    // rate-limit UPDATE, the optional quarantine UPDATE, and the
    // escalations INSERT all happen under a single transaction —
    // partial writes are impossible.
    let ctx_outer = Arc::clone(ctx);
    let session_id_str = session.session_id.clone();
    let lineage_id_str = session.lineage_id.clone();
    let req_owned = req;

    let SubmitOutcome {
        response,
        audit_after,
    } = tokio::task::spawn_blocking(move || {
        submit_escalation_blocking(
            &ctx_outer,
            &session_id_str,
            &lineage_id_str,
            req_owned,
        )
    })
    .await
    .map_err(|_| EscalationRejectionReason::RateLimitExceeded)??;

    // ── audit-after-commit (kernel-store.md §2.5.2) ───────────────────
    // We emit AFTER the SQLite transaction has committed. If the audit
    // write itself fails the kernel logs and continues — the wire
    // response is still correct.
    for event in audit_after {
        let (kind, sid, init) = event;
        if let Err(e) = ctx.audit.emit(kind, sid.as_deref(), None, init.as_deref()) {
            eprintln!(
                "{{\"level\":\"error\",\"message\":\"escalation audit emit failed\",\"error\":\"{e}\"}}"
            );
        }
    }

    Ok(response)
}

// ---------------------------------------------------------------------------
// Blocking submission step (steps 3-6 above)
// ---------------------------------------------------------------------------

/// What `submit_escalation_blocking` returns: the wire response plus
/// the audit events to emit after commit. We hand both back so the
/// async caller controls audit ordering (and so the SQLite transaction
/// is fully released before any audit-sink I/O happens).
struct SubmitOutcome {
    response: EscalationResponse,
    /// (kind, session_id, initiative_id) tuples — task_id is never
    /// supplied for these events; the per-event `escalation_id` /
    /// `lineage_id` payload carries enough context.
    audit_after: Vec<(AuditEventKind, Option<String>, Option<String>)>,
}

fn submit_escalation_blocking(
    ctx:            &HandlerContext,
    session_id_str: &str,
    lineage_id_str: &str,
    req:            EscalationRequest,
) -> Result<SubmitOutcome, EscalationRejectionReason> {
    use rusqlite::params;

    let mut conn = ctx.store.lock_sync();
    let tx = conn
        .transaction()
        .map_err(|_| EscalationRejectionReason::RateLimitExceeded)?;

    // ── Step 3: task lookup + ownership ───────────────────────────────
    // We pull the task's initiative_id and the *session*'s lineage of
    // the task's owning session (via tasks.session_id → sessions.lineage_id)
    // to reject cross-lineage escalations defence-in-depth.
    let task_row: Option<(String, Option<String>)> = tx
        .query_row(
            &format!(
                "SELECT t.initiative_id, s.lineage_id
                   FROM {TASKS} t
              LEFT JOIN {SESSIONS} s ON s.session_id = t.session_id
                  WHERE t.task_id = ?1"
            ),
            params![req.task_id.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok();
    let Some((initiative_id_str, task_lineage_opt)) = task_row else {
        // Task does not exist — surface as a rate-limit-style rejection
        // because the wire reason enum has only two variants. The
        // planner can correlate via its own task table.
        return Err(EscalationRejectionReason::RateLimitExceeded);
    };
    if let Some(task_lineage) = task_lineage_opt {
        if task_lineage != lineage_id_str {
            // Cross-lineage escalation — reject without leaking which
            // lineage actually owns the task.
            return Err(EscalationRejectionReason::RateLimitExceeded);
        }
    }

    // ── Step 4: idempotency probe (BEFORE rate-limit) ─────────────────
    // Idempotent retries (same (session_id, idempotency_key)) MUST be
    // free per planner-api.md "Every new submission with a different
    // key counts toward the rate-limit window". Probing before the
    // rate-limit decision means a planner that legitimately retries
    // a single escalation never burns slots and never trips quarantine.
    let idem_key = req.idempotency_key.to_string();
    let existing_id: Option<String> = tx
        .query_row(
            &format!(
                "SELECT escalation_id FROM {ESCALATIONS}
                  WHERE session_id = ?1 AND idempotency_key = ?2"
            ),
            params![session_id_str, idem_key],
            |r| r.get::<_, String>(0),
        )
        .ok();
    if let Some(eid) = existing_id {
        // Read-only transaction — drop without committing so no
        // lineage_rate_limits row is created/touched.
        drop(tx);
        let escalation_id = EscalationId::parse(&eid)
            .map_err(|_| EscalationRejectionReason::RateLimitExceeded)?;
        return Ok(SubmitOutcome {
            response:    EscalationResponse::AlreadyPending { escalation_id },
            audit_after: Vec::new(),
        });
    }

    // ── Step 5: lineage rate-limit + quarantine ───────────────────────
    // Pin one snapshot of the policy bundle for the rest of the
    // pipeline so the rate-limit, quarantine, and timeout reads all
    // see the same epoch (INV-POLICY-01).
    let policy_snapshot = ctx.policy.load_full();
    let now_secs = unix_now_secs() as i64;
    let max_per_window = policy_snapshot.escalation_max_per_window() as i64;
    let window_secs    = policy_snapshot.escalation_window().as_secs() as i64;
    let quarantine_threshold = policy_snapshot.escalation_quarantine_threshold() as i64;

    // Existing lineage_rate_limits row, if any.
    let existing: Option<(i64, i64, i64, i64)> = tx
        .query_row(
            &format!(
                "SELECT window_start, escalation_count, quarantined, quarantine_trigger_count
                   FROM {LINEAGE_RATE_LIMITS} WHERE lineage_id = ?1"
            ),
            params![lineage_id_str],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .ok();

    let mut audit_after: Vec<(AuditEventKind, Option<String>, Option<String>)> = Vec::new();

    let (mut window_start, mut escalation_count, quarantined, mut trigger_count) =
        existing.unwrap_or((now_secs, 0i64, 0i64, 0i64));

    if quarantined == 1 {
        // Already quarantined — no new escalations, no counter advance,
        // no fresh audit (the LineageQuarantined event was already
        // emitted on the trigger transition).
        return Ok(SubmitOutcome {
            response:    EscalationResponse::Rejected {
                reason: EscalationRejectionReason::LineageQuarantined,
            },
            audit_after: Vec::new(),
        });
    }

    // Window roll-over.
    if window_secs > 0 && now_secs >= window_start.saturating_add(window_secs) {
        window_start     = now_secs;
        escalation_count = 0;
    }

    let attempted = escalation_count + 1;
    if attempted > max_per_window {
        // Rate-limit hit. Advance the trigger counter and decide
        // whether this attempt also crosses the quarantine threshold.
        trigger_count = trigger_count.saturating_add(1);
        let now_quarantined = trigger_count >= quarantine_threshold;
        let new_quarantined_flag = if now_quarantined { 1i64 } else { 0i64 };

        // Persist the counter changes either way so future attempts
        // see the advanced trigger_count / quarantined flag.
        upsert_lineage_rate_limits(
            &tx,
            lineage_id_str,
            window_start,
            escalation_count, // unchanged — the rejected attempt does NOT consume a slot
            new_quarantined_flag,
            trigger_count,
            if now_quarantined { Some(now_secs) } else { None },
        )?;

        tx.commit()
            .map_err(|_| EscalationRejectionReason::RateLimitExceeded)?;

        if now_quarantined {
            audit_after.push((
                AuditEventKind::LineageQuarantined {
                    lineage_id:    lineage_id_str.to_owned(),
                    trigger_count: trigger_count as u64,
                },
                Some(session_id_str.to_owned()),
                Some(initiative_id_str),
            ));
            return Ok(SubmitOutcome {
                response: EscalationResponse::Rejected {
                    reason: EscalationRejectionReason::LineageQuarantined,
                },
                audit_after,
            });
        }
        audit_after.push((
            AuditEventKind::EscalationRateLimitExceeded {
                lineage_id:      lineage_id_str.to_owned(),
                attempted_count: attempted as u64,
                window_start,
            },
            Some(session_id_str.to_owned()),
            Some(initiative_id_str),
        ));
        return Ok(SubmitOutcome {
            response: EscalationResponse::Rejected {
                reason: EscalationRejectionReason::RateLimitExceeded,
            },
            audit_after,
        });
    }

    // ── Step 6: INSERT escalations row + UPDATE counter ────────────────
    let escalation_id_str = uuid::Uuid::new_v4().to_string();
    let timeout_at = now_secs.saturating_add(
        policy_snapshot.escalation_timeout().as_secs() as i64,
    );
    let scope_json = serde_json::to_string(&req.requested_scope)
        .expect("RequestedEscalationScope is always JSON-serialisable");

    tx.execute(
        &format!(
            "INSERT INTO {ESCALATIONS} (
                escalation_id, session_id, task_id, lineage_id, initiative_id,
                class, requested_scope_json, justification, idempotency_key,
                status, created_at, timeout_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)"
        ),
        params![
            escalation_id_str,
            session_id_str,
            req.task_id.as_str(),
            lineage_id_str,
            initiative_id_str,
            req.class.as_sql_str(),
            scope_json,
            req.justification,
            idem_key,
            EscalationStatus::Pending.as_sql_str(),
            now_secs,
            timeout_at,
        ],
    )
    .map_err(|_| EscalationRejectionReason::RateLimitExceeded)?;

    // Advance the rate-limit counter only after the INSERT succeeds.
    upsert_lineage_rate_limits(
        &tx,
        lineage_id_str,
        window_start,
        attempted, // = escalation_count + 1
        quarantined,
        trigger_count,
        None,
    )?;

    tx.commit()
        .map_err(|_| EscalationRejectionReason::RateLimitExceeded)?;

    audit_after.push((
        AuditEventKind::EscalationSubmitted {
            escalation_id: escalation_id_str.clone(),
            task_id:       req.task_id.as_str().to_owned(),
            class:         req.class.as_sql_str().to_owned(),
            lineage_id:    lineage_id_str.to_owned(),
        },
        Some(session_id_str.to_owned()),
        Some(initiative_id_str),
    ));

    let escalation_id = EscalationId::parse(&escalation_id_str)
        .map_err(|_| EscalationRejectionReason::RateLimitExceeded)?;
    Ok(SubmitOutcome {
        response: EscalationResponse::Submitted {
            escalation_id,
            timeout_at: raxis_types::id::UnixSeconds(timeout_at),
        },
        audit_after,
    })
}

/// UPSERT helper for `lineage_rate_limits` rows.
///
/// The DDL declares `lineage_id` as PRIMARY KEY, so we use SQLite's
/// `ON CONFLICT (lineage_id) DO UPDATE` clause which keeps the
/// statement single-shot and atomic with the surrounding transaction.
fn upsert_lineage_rate_limits(
    tx:                &rusqlite::Transaction,
    lineage_id:        &str,
    window_start:      i64,
    escalation_count:  i64,
    quarantined:       i64,
    trigger_count:     i64,
    quarantined_at:    Option<i64>,
) -> Result<(), EscalationRejectionReason> {
    use rusqlite::params;
    tx.execute(
        &format!(
            "INSERT INTO {LINEAGE_RATE_LIMITS} (
                lineage_id, window_start, escalation_count,
                quarantined, quarantine_trigger_count, quarantined_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(lineage_id) DO UPDATE SET
                window_start             = excluded.window_start,
                escalation_count         = excluded.escalation_count,
                quarantined              = excluded.quarantined,
                quarantine_trigger_count = excluded.quarantine_trigger_count,
                quarantined_at           = COALESCE(
                                              {LINEAGE_RATE_LIMITS}.quarantined_at,
                                              excluded.quarantined_at
                                           )"
        ),
        params![
            lineage_id,
            window_start,
            escalation_count,
            quarantined,
            trigger_count,
            quarantined_at,
        ],
    )
    .map_err(|_| EscalationRejectionReason::RateLimitExceeded)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
//
// The handler is exercised end-to-end against an in-memory store with
// real session, task, and initiative rows seeded by the test. Each test
// drives one branch of the pipeline so a regression points at exactly
// the failing FSM edge.
//
// Test surfaces:
//   - happy path (Submitted)
//   - validation rejections (justification, class mismatch, nil idempotency_key)
//   - session token rejections (unknown, revoked, expired)
//   - task lookup rejections (missing task, cross-lineage task)
//   - idempotency (AlreadyPending on duplicate (session_id, idempotency_key))
//   - rate-limit (Rejected { RateLimitExceeded } + audit emit)
//   - rate-limit window roll-over (count resets after window_secs)
//   - quarantine trigger (Rejected { LineageQuarantined } + audit emit)
//   - sticky quarantine (subsequent submissions short-circuit)
//   - audit ordering (no audit on rejected validation, audit only after
//     successful commit)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;
    use std::sync::Arc;

    use raxis_audit_tools::FakeAuditSink;
    use raxis_policy::{EscalationPolicyForTests, OperatorEntry, PolicyBundle};
    use raxis_store::Store;
    use raxis_types::{
        EscalationClass, EscalationRequest, EscalationResponse, InitiativeState,
        RequestedEscalationScope, Role, TaskState,
    };

    use crate::authority::keys::KeyRegistry;
    use crate::initiatives::PlanRegistry;
    use crate::ipc::context::HandlerContext;

    use std::time::Duration;

    // ── fixtures ──────────────────────────────────────────────────────

    const SESSION_TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const SESSION_ID:    &str = "00000000-0000-0000-0000-000000000001";
    const LINEAGE_ID:    &str = "lin-prime";
    const INITIATIVE_ID: &str = "00000000-0000-0000-0000-0000000000aa";
    const TASK_ID:       &str = "00000000-0000-0000-0000-0000000000bb";
    // INV-STORE-03: tests share the production const aliases for table
    // names (visible because `mod tests` is `use super::*`).

    /// Build a HandlerContext with a non-zero escalation policy so the
    /// rate-limit branch can fire deterministically. Returns the ctx
    /// AND a strong reference to the underlying FakeAuditSink so tests
    /// can read captured events without trying to downcast through
    /// the trait object.
    fn build_ctx(
        escalation_policy: EscalationPolicyForTests,
    ) -> (Arc<HandlerContext>, Arc<FakeAuditSink>) {
        let store  = Store::open_in_memory().unwrap();
        // Stub cert: this fixture exercises the escalation handler's
        // rate-limit / quarantine branches and never goes through the
        // cert-validation gate. See `notifications::sink::tests::bundle`
        // for the rationale on `stub_cert_for_pubkey`.
        let pubkey_hex = hex::encode([7u8; 32]);
        let cert = raxis_test_support::stub_cert_for_pubkey(pubkey_hex.clone());
        let policy = PolicyBundle::for_tests_with_operators_and_escalation_policy(
            vec![OperatorEntry {
                pubkey_fingerprint: "op-prime".into(),
                display_name:       "op-prime".into(),
                pubkey_hex,
                permitted_ops:      vec![],
                cert,
                force_misconfig_bypass: false,
            }],
            escalation_policy,
        );
        let sink = Arc::new(FakeAuditSink::new());
        let ctx  = Arc::new(HandlerContext::new(
            Arc::new(arc_swap::ArcSwap::from_pointee(policy)),
            Arc::new(KeyRegistry::stub_for_tests()),
            Arc::new(store),
            sink.clone(),
            PathBuf::from("/tmp/raxis-escalation-test"),
            Arc::new(PlanRegistry::new()),
            Arc::new(crate::gateway::client::GatewayClient::new()),
            Arc::new(crate::prompt::EpochBinding::new()),
        ));
        (ctx, sink)
    }

    /// Insert sessions, initiatives, tasks rows the planner-side
    /// EscalationRequest handler joins against.
    ///
    /// Wraps the synchronous store mutex in `spawn_blocking` so it
    /// can be called from `#[tokio::test]` bodies without panicking
    /// on `Cannot block the current thread from within a runtime`
    /// (kernel-store.md §2.5.1 sync-store contract).
    async fn seed_session_and_task(ctx: Arc<HandlerContext>) {
        tokio::task::spawn_blocking(move || {
            let conn = ctx.store.lock_sync();
            let now  = unix_now_secs();
            // Role/actor strings ("planner", "kernel") are free-form
            // value columns (not finite enums), so they remain inline.
            // Initiative/task FSM state strings come from the typed
            // enum's `.as_sql_str()` per INV-STORE-03.
            conn.execute(
                &format!(
                    "INSERT INTO {SESSIONS} (
                        session_id, role_id, session_token, lineage_id,
                        worktree_root, base_sha, base_tracking_ref,
                        fetch_quota, sequence_number,
                        created_at, expires_at, revoked, revoked_at
                     ) VALUES (?1, ?2, ?3, ?4, NULL, NULL, NULL,
                               0, 0,
                               ?5, ?6, 0, NULL)"
                ),
                rusqlite::params![
                    SESSION_ID,
                    Role::Planner.as_sql_str(),
                    SESSION_TOKEN, LINEAGE_ID, now, now + 3600,
                ],
            ).unwrap();
            conn.execute(
                &format!(
                    "INSERT INTO {INITIATIVES}
                        (initiative_id, state, terminal_criteria_json,
                         plan_artifact_sha256, created_at)
                     VALUES (?1, ?2, '{{}}', 'deadbeef', ?3)"
                ),
                rusqlite::params![
                    INITIATIVE_ID, InitiativeState::Executing.as_sql_str(), now,
                ],
            ).unwrap();
            conn.execute(
                &format!(
                    "INSERT INTO {TASKS}
                        (task_id, initiative_id, lane_id, state, actor,
                         policy_epoch, admitted_at, transitioned_at, session_id,
                         actual_cost)
                     VALUES (?1, ?2, 'default', ?3, 'kernel',
                             1, ?4, ?4, ?5, 0)"
                ),
                rusqlite::params![
                    TASK_ID, INITIATIVE_ID,
                    TaskState::Running.as_sql_str(),
                    now, SESSION_ID,
                ],
            ).unwrap();
        }).await.unwrap();
    }

    /// Run a closure against the store from a tokio test context.
    async fn with_store_blocking<F, T>(ctx: &Arc<HandlerContext>, f: F) -> T
    where
        F: FnOnce(&rusqlite::Connection) -> T + Send + 'static,
        T: Send + 'static,
    {
        let store = Arc::clone(&ctx.store);
        tokio::task::spawn_blocking(move || {
            let conn = store.lock_sync();
            f(&conn)
        }).await.unwrap()
    }

    fn make_request(idempotency_key: uuid::Uuid) -> EscalationRequest {
        EscalationRequest {
            session_token: SESSION_TOKEN.into(),
            task_id:       raxis_types::TaskId::parse(TASK_ID).unwrap(),
            class:         EscalationClass::CapabilityUpgrade,
            requested_scope: RequestedEscalationScope::CapabilityUpgrade {
                capability: raxis_types::CapabilityClass::WriteSecrets,
            },
            justification: "valid because integration tests need it".into(),
            idempotency_key,
        }
    }


    // ── happy path ────────────────────────────────────────────────────

    #[tokio::test]
    async fn submitted_happy_path_returns_typed_response_and_emits_audit() {
        let (ctx, sink) = build_ctx(EscalationPolicyForTests {
            timeout:              Duration::from_secs(1800),
            window:               Duration::from_secs(60),
            max_per_window:       10,
            quarantine_threshold: 100,
        });
        seed_session_and_task(Arc::clone(&ctx)).await;

        let req  = make_request(uuid::Uuid::new_v4());
        let resp = handle(req.clone(), &ctx).await;

        match resp {
            EscalationResponse::Submitted { escalation_id, timeout_at } => {
                assert!(uuid::Uuid::parse_str(escalation_id.as_str()).is_ok());
                assert!(timeout_at.0 > unix_now_secs(),
                    "timeout_at must be in the future");
            }
            other => panic!("expected Submitted, got {other:?}"),
        }
        assert!(sink.event_kinds().contains(&"EscalationSubmitted"),
            "happy path MUST emit EscalationSubmitted audit");
    }

    // ── validation rejections (no audit, no DB write) ─────────────────

    #[tokio::test]
    async fn rejects_empty_justification() {
        let (ctx, sink) = build_ctx(EscalationPolicyForTests {
            max_per_window: 1, window: Duration::from_secs(60), ..Default::default()
        });
        seed_session_and_task(Arc::clone(&ctx)).await;

        let mut req = make_request(uuid::Uuid::new_v4());
        req.justification = "   ".into();

        let resp = handle(req, &ctx).await;
        assert!(matches!(resp, EscalationResponse::Rejected { .. }));
        assert!(sink.event_kinds().is_empty(),
            "validation rejection MUST NOT emit audit");
    }

    #[tokio::test]
    async fn rejects_oversize_justification() {
        let (ctx, _sink) = build_ctx(EscalationPolicyForTests {
            max_per_window: 1, window: Duration::from_secs(60), ..Default::default()
        });
        seed_session_and_task(Arc::clone(&ctx)).await;

        let mut req = make_request(uuid::Uuid::new_v4());
        req.justification = "x".repeat(JUSTIFICATION_MAX_BYTES + 1);

        let resp = handle(req, &ctx).await;
        assert!(matches!(resp, EscalationResponse::Rejected { .. }));
    }

    #[tokio::test]
    async fn accepts_justification_at_exactly_max_bytes() {
        let (ctx, _sink) = build_ctx(EscalationPolicyForTests {
            timeout: Duration::from_secs(60), window: Duration::from_secs(60),
            max_per_window: 1, quarantine_threshold: 100,
        });
        seed_session_and_task(Arc::clone(&ctx)).await;
        let mut req = make_request(uuid::Uuid::new_v4());
        req.justification = "x".repeat(JUSTIFICATION_MAX_BYTES);
        let resp = handle(req, &ctx).await;
        assert!(matches!(resp, EscalationResponse::Submitted { .. }),
            "justification at the cap is admissible");
    }

    #[tokio::test]
    async fn rejects_class_mismatched_with_scope() {
        let (ctx, _sink) = build_ctx(EscalationPolicyForTests {
            max_per_window: 1, window: Duration::from_secs(60), ..Default::default()
        });
        seed_session_and_task(Arc::clone(&ctx)).await;

        let mut req = make_request(uuid::Uuid::new_v4());
        req.class = EscalationClass::BudgetException;
        // scope discriminant is still CapabilityUpgrade — mismatch.

        let resp = handle(req, &ctx).await;
        assert!(matches!(resp, EscalationResponse::Rejected { .. }));
    }

    #[tokio::test]
    async fn rejects_nil_idempotency_key() {
        let (ctx, _sink) = build_ctx(EscalationPolicyForTests {
            max_per_window: 1, window: Duration::from_secs(60), ..Default::default()
        });
        seed_session_and_task(Arc::clone(&ctx)).await;
        let req = make_request(uuid::Uuid::nil());
        let resp = handle(req, &ctx).await;
        assert!(matches!(resp, EscalationResponse::Rejected { .. }));
    }

    // ── auth-style rejections ─────────────────────────────────────────

    #[tokio::test]
    async fn rejects_unknown_session_token() {
        let (ctx, _sink) = build_ctx(EscalationPolicyForTests::default());
        seed_session_and_task(Arc::clone(&ctx)).await;
        let mut req = make_request(uuid::Uuid::new_v4());
        req.session_token = "deadbeef".repeat(8); // 64 chars but not the seeded one
        let resp = handle(req, &ctx).await;
        assert!(matches!(resp, EscalationResponse::Rejected { .. }));
    }

    #[tokio::test]
    async fn rejects_revoked_session() {
        let (ctx, _sink) = build_ctx(EscalationPolicyForTests {
            timeout: Duration::from_secs(60), window: Duration::from_secs(60),
            max_per_window: 1, quarantine_threshold: 100,
        });
        seed_session_and_task(Arc::clone(&ctx)).await;
        with_store_blocking(&ctx, |conn| {
            conn.execute(
                &format!("UPDATE {SESSIONS} SET revoked_at = ?1 WHERE session_id = ?2"),
                rusqlite::params![unix_now_secs(), SESSION_ID],
            ).unwrap();
        }).await;
        let resp = handle(make_request(uuid::Uuid::new_v4()), &ctx).await;
        assert!(matches!(resp, EscalationResponse::Rejected { .. }));
    }

    #[tokio::test]
    async fn rejects_expired_session() {
        let (ctx, _sink) = build_ctx(EscalationPolicyForTests {
            timeout: Duration::from_secs(60), window: Duration::from_secs(60),
            max_per_window: 1, quarantine_threshold: 100,
        });
        seed_session_and_task(Arc::clone(&ctx)).await;
        with_store_blocking(&ctx, |conn| {
            conn.execute(
                &format!("UPDATE {SESSIONS} SET expires_at = ?1 WHERE session_id = ?2"),
                rusqlite::params![unix_now_secs() - 1, SESSION_ID],
            ).unwrap();
        }).await;
        let resp = handle(make_request(uuid::Uuid::new_v4()), &ctx).await;
        assert!(matches!(resp, EscalationResponse::Rejected { .. }));
    }

    // ── task-lookup rejections ────────────────────────────────────────

    #[tokio::test]
    async fn rejects_unknown_task() {
        let (ctx, _sink) = build_ctx(EscalationPolicyForTests {
            timeout: Duration::from_secs(60), window: Duration::from_secs(60),
            max_per_window: 1, quarantine_threshold: 100,
        });
        seed_session_and_task(Arc::clone(&ctx)).await;
        let mut req = make_request(uuid::Uuid::new_v4());
        req.task_id = raxis_types::TaskId::parse(
            "00000000-0000-0000-0000-0000000000ff",
        ).unwrap();
        let resp = handle(req, &ctx).await;
        assert!(matches!(resp, EscalationResponse::Rejected { .. }));
    }

    #[tokio::test]
    async fn rejects_cross_lineage_task() {
        let (ctx, _sink) = build_ctx(EscalationPolicyForTests {
            timeout: Duration::from_secs(60), window: Duration::from_secs(60),
            max_per_window: 1, quarantine_threshold: 100,
        });
        seed_session_and_task(Arc::clone(&ctx)).await;
        // Add a SECOND session in a different lineage that owns a different task.
        let other_session_id = "00000000-0000-0000-0000-000000000002";
        let other_task_id    = "00000000-0000-0000-0000-0000000000cc";
        with_store_blocking(&ctx, move |conn| {
            let now = unix_now_secs();
            conn.execute(
                &format!(
                    "INSERT INTO {SESSIONS} (
                        session_id, role_id, session_token, lineage_id,
                        worktree_root, base_sha, base_tracking_ref,
                        fetch_quota, sequence_number,
                        created_at, expires_at, revoked, revoked_at
                     ) VALUES (?1, ?2, 'tok2', 'lin-other', NULL, NULL, NULL,
                               0, 0, ?3, ?4, 0, NULL)"
                ),
                rusqlite::params![
                    other_session_id, Role::Planner.as_sql_str(),
                    now, now + 3600,
                ],
            ).unwrap();
            conn.execute(
                &format!(
                    "INSERT INTO {TASKS}
                        (task_id, initiative_id, lane_id, state, actor,
                         policy_epoch, admitted_at, transitioned_at, session_id,
                         actual_cost)
                     VALUES (?1, ?2, 'default', ?3, 'kernel',
                             1, ?4, ?4, ?5, 0)"
                ),
                rusqlite::params![
                    other_task_id, INITIATIVE_ID,
                    TaskState::Running.as_sql_str(),
                    now, other_session_id,
                ],
            ).unwrap();
        }).await;

        // Submit using SESSION_TOKEN (lineage = LINEAGE_ID) but
        // pointing at the other task (owned by lin-other) — must be
        // rejected, defence-in-depth.
        let mut req = make_request(uuid::Uuid::new_v4());
        req.task_id = raxis_types::TaskId::parse(other_task_id).unwrap();
        let resp = handle(req, &ctx).await;
        assert!(matches!(resp, EscalationResponse::Rejected { .. }),
            "cross-lineage escalation MUST be rejected");
    }

    // ── idempotency ───────────────────────────────────────────────────

    #[tokio::test]
    async fn duplicate_idempotency_key_returns_already_pending_without_consuming_slot() {
        let (ctx, _sink) = build_ctx(EscalationPolicyForTests {
            timeout: Duration::from_secs(60), window: Duration::from_secs(60),
            max_per_window: 1, quarantine_threshold: 100,
        });
        seed_session_and_task(Arc::clone(&ctx)).await;
        let key = uuid::Uuid::new_v4();
        let first = handle(make_request(key), &ctx).await;
        let first_id = match first {
            EscalationResponse::Submitted { escalation_id, .. } => escalation_id,
            other => panic!("expected Submitted, got {other:?}"),
        };
        let second = handle(make_request(key), &ctx).await;
        match second {
            EscalationResponse::AlreadyPending { escalation_id } => {
                assert_eq!(escalation_id.as_str(), first_id.as_str(),
                    "AlreadyPending MUST surface the original escalation_id");
            }
            other => panic!("expected AlreadyPending, got {other:?}"),
        }
        let count: i64 = with_store_blocking(&ctx, |conn| {
            conn.query_row(
                &format!("SELECT escalation_count FROM {LINEAGE_RATE_LIMITS} WHERE lineage_id = ?1"),
                rusqlite::params![LINEAGE_ID],
                |r| r.get(0),
            ).unwrap()
        }).await;
        assert_eq!(count, 1, "idempotent retry MUST NOT consume a rate-limit slot");
    }

    // ── rate limit ────────────────────────────────────────────────────

    #[tokio::test]
    async fn rejects_with_rate_limit_exceeded_when_max_per_window_hit() {
        let (ctx, sink) = build_ctx(EscalationPolicyForTests {
            timeout: Duration::from_secs(60), window: Duration::from_secs(3600),
            max_per_window: 2, quarantine_threshold: 100,
        });
        seed_session_and_task(Arc::clone(&ctx)).await;

        let _ = handle(make_request(uuid::Uuid::new_v4()), &ctx).await;
        let _ = handle(make_request(uuid::Uuid::new_v4()), &ctx).await;
        let third = handle(make_request(uuid::Uuid::new_v4()), &ctx).await;

        match third {
            EscalationResponse::Rejected { reason } => {
                assert_eq!(reason, EscalationRejectionReason::RateLimitExceeded);
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
        assert!(sink.event_kinds().contains(&"EscalationRateLimitExceeded"),
            "rate-limit overflow MUST emit EscalationRateLimitExceeded audit");

        let count: i64 = with_store_blocking(&ctx, |conn| {
            conn.query_row(
                &format!("SELECT escalation_count FROM {LINEAGE_RATE_LIMITS} WHERE lineage_id = ?1"),
                rusqlite::params![LINEAGE_ID],
                |r| r.get(0),
            ).unwrap()
        }).await;
        assert_eq!(count, 2, "rejected attempt MUST NOT consume a slot");
    }

    #[tokio::test]
    async fn quarantine_triggers_after_threshold_overflows() {
        let (ctx, sink) = build_ctx(EscalationPolicyForTests {
            timeout: Duration::from_secs(60), window: Duration::from_secs(3600),
            max_per_window: 1, quarantine_threshold: 2,
        });
        seed_session_and_task(Arc::clone(&ctx)).await;

        // Slot 1: accepted.
        let _ = handle(make_request(uuid::Uuid::new_v4()), &ctx).await;
        // Slot 2: overflow → trigger 1, audit EscalationRateLimitExceeded.
        let _ = handle(make_request(uuid::Uuid::new_v4()), &ctx).await;
        // Slot 3: overflow → trigger 2 == threshold → quarantine.
        let third = handle(make_request(uuid::Uuid::new_v4()), &ctx).await;
        match third {
            EscalationResponse::Rejected { reason } => {
                assert_eq!(reason, EscalationRejectionReason::LineageQuarantined);
            }
            other => panic!("expected LineageQuarantined, got {other:?}"),
        }
        assert!(sink.event_kinds().contains(&"LineageQuarantined"),
            "crossing the threshold MUST emit LineageQuarantined audit");

        // Sticky: a fourth attempt also gets LineageQuarantined and
        // does NOT emit a fresh audit (already quarantined branch).
        let prior_kinds = sink.event_kinds();
        let fourth = handle(make_request(uuid::Uuid::new_v4()), &ctx).await;
        assert!(matches!(fourth, EscalationResponse::Rejected {
            reason: EscalationRejectionReason::LineageQuarantined,
        }));
        let new_kinds = sink.event_kinds();
        assert_eq!(new_kinds.len(), prior_kinds.len(),
            "sticky-quarantine path MUST NOT emit additional audit events");
    }

    // ── window roll-over ──────────────────────────────────────────────

    #[tokio::test]
    async fn window_rolls_over_after_window_secs_elapses() {
        let (ctx, _sink) = build_ctx(EscalationPolicyForTests {
            timeout: Duration::from_secs(60), window: Duration::from_secs(60),
            max_per_window: 1, quarantine_threshold: 100,
        });
        seed_session_and_task(Arc::clone(&ctx)).await;

        let first = handle(make_request(uuid::Uuid::new_v4()), &ctx).await;
        assert!(matches!(first, EscalationResponse::Submitted { .. }));

        // Force the window_start back so the next attempt sees an
        // expired window and resets the counter.
        with_store_blocking(&ctx, |conn| {
            conn.execute(
                &format!("UPDATE {LINEAGE_RATE_LIMITS} SET window_start = ?1 WHERE lineage_id = ?2"),
                rusqlite::params![unix_now_secs() - 600, LINEAGE_ID],
            ).unwrap();
        }).await;
        let second = handle(make_request(uuid::Uuid::new_v4()), &ctx).await;
        assert!(matches!(second, EscalationResponse::Submitted { .. }),
            "fresh window MUST allow another submission");
    }
}

