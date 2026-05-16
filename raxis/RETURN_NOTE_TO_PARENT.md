# Return note — `worker/iter62-deep-sweep-2`

Branch: `worker/iter62-deep-sweep-2`
Base: `origin/main` (`f01b23c`)
Scope: iter62 deep-sweep dimensions D3..D10 plus a net-new D1 reservation-leak finding the parent's pass missed.

## Findings table

| Dim | Found | Fixed (this branch) | Deferred to parent / iter63 |
|-----|-------|---------------------|----------------------------|
| D1  | 1     | 1 (lane-reservation recovery sweep + 4 witness tests) | — |
| D2  | 0     | 0 | gateway/credential-proxy logs all clean (4 warns total, all `FailInvalidDiff` from one task) |
| D3  | 0     | 0 | spot-checked 5 guests; no panics, no OOM (matches parent's earlier finding) |
| D4  | 1     | 0 | 13 `CredentialProxyStarted` / 0 `CredentialProxyStopped` in iter62 audit — explained by kernel-kill before graceful teardown; flag below |
| D5  | 0     | 0 | iter62 had no audit events with `latency_ms > 60000`; planner_fetch p99 ~5s; no outliers worth chasing |
| D6  | 12    | 12 (disk_watchdog ×3, recovery.rs ×3, gateway/supervisor.rs ×6 — all silent `let _ = audit.emit(...)` converted to logged failures) | — |
| D7  | 0     | 0 | parent's deep-sweep already swept most spec-only IDs; nothing iter63-blocking left in the scope I checked |
| D8  | 0     | 0 | no high-confidence TOCTOU; flagged one low-confidence below |
| D9  | 2     | 0 | both in parent's territory (`ipc/operator.rs`) — see below |
| D10 | 0     | 0 | nothing else iter63-blocking surfaced |

## Commit list

(Pushed to `worker/iter62-deep-sweep-2`.)

1. `8577d80` — `D1` — lane-reservation recovery sweep
   (`reconcile_orphan_lane_reservations` in `kernel/src/recovery.rs`)
   + main.rs boot-log line + bootstrap.rs assertion + 5 witness
   tests + INV-DEEP-SWEEP-D1-LANE-RESERVATION-LEAK-01 in
   `specs/invariants.md §12.62`. Closes the iter62 forensic finding
   "Completed task `019e2dc0-3160-7a52-919b-e18785a3ec1e` still
   holds a 100-unit `lane_budget_reservations` row".
2. `7b83974` — `D6` — convert 12 silent `let _ = audit.emit(...)`
   sites to logged audit-emit failure across `disk_watchdog.rs`
   (3 sites), `recovery.rs` git-event helpers (3 sites), and
   `gateway/supervisor.rs` (6 sites) + INV-DEEP-SWEEP-D6-CRITICAL-
   AUDIT-EMIT-NEVER-SILENT-01.

## Cross-worker routing requests (deferred fixes)

### D4 — `CredentialProxyStarted` not paired with `CredentialProxyStopped` on kernel kill

Forensic observation: 13 `CredentialProxyStarted` audit events, 0 `CredentialProxyStopped` in the iter62 chain. Trace says `terminate_session` in `crates/session-spawn/src/lib.rs` (Worker 1 territory) does call `cred_handles.shutdown()` which emits the paired event, but the iter62 dump ended mid-orchestrator-respawn — the kernel was killed by the test harness before any session reached its graceful-teardown branch. The `Drop` impl on `SessionProxyHandles` aborts the listeners but cannot emit audit (no `&AuditSink` in scope from `Drop`).

This is a structural pairing gap on kernel-kill paths. Routing options:
- Live-e2e harness change (Worker 4 territory): SIGTERM rather than SIGKILL so the kernel runs its graceful-shutdown path → flushes `terminate_session` for every active session → paired `Stopped` events land before exit. Probably the cheapest fix.
- Audit-on-Drop via a synchronous bounded sender into a kernel-wide audit thread (kernel/src/main.rs + crates/audit) — much heavier; defer.

No code change here; flagging for parent + Worker 4. iter63 will still see this gap if the harness keeps SIGKILL'ing.

### D9 — `handle_revoke_session` does not emit `SessionRevoked` audit event

`kernel/src/authority/session.rs::revoke_session` performs `UPDATE sessions SET revoked=1, revoked_at=?` but the caller `kernel/src/ipc/operator.rs::handle_revoke_session` only returns `OperatorResponse::SessionRevoked` to the operator — there is no `ctx.audit.emit(AuditEventKind::SessionRevoked { ... })` post-commit. This violates the paired-write contract the parent already enforces on `transition_to_admitted` / `abort_task` / `abort_initiative`.

Fix shape (parent's territory, `kernel/src/ipc/operator.rs:1107`):
1. After the `spawn_blocking` returns `Ok(())`, emit `AuditEventKind::SessionRevoked { session_id, role_id, lineage_id, revoked_at, reason: "operator_revoke", operator_fingerprint }`.
2. Log on emit failure (per the new INV-DEEP-SWEEP-D6 contract).
3. Witness test in `kernel/tests/full_e2e_session_lifecycle.rs` is Worker 4's territory but should pin "operator revoke emits exactly one `SessionRevoked` event".

INV entry already drafted: `INV-DEEP-SWEEP-D9-OPERATOR-REVOKE-SESSION-AUDIT-EMIT-01` in `specs/invariants.md` §12.62.

### D9 — `handle_approve_logical_deadlock` does not emit `InitiativeStateChanged`

`kernel/src/ipc/operator.rs::handle_approve_logical_deadlock` (line ~2277) calls `approve_logical_deadlock_escalation_in_tx` which inside one tx does:
1. UPDATE `escalations.status = 'Approved'`
2. UPDATE `initiatives.orchestrator_no_progress_respawn_count = 0`
3. UPDATE `initiatives.state = 'Executing', completed_at = NULL` WHERE state='Failed'

Post-commit it emits only `OperatorApprovedRespawnEscalation`. The initiative FSM `Failed → Executing` transition silently lacks an `InitiativeStateChanged` event. Dashboards that build the initiative-state timeline from `InitiativeStateChanged` see an unexplained "still Failed" reading until the next task transition lands.

Fix shape (parent's territory):
1. After `tx.commit()`, check whether the `approve_logical_deadlock_escalation_in_tx` SELECT phase returned `prev_state == 'Failed'`. (Requires plumbing the prior state out of that helper — the helper returns `Option<String>` initiative_id today; change to `Option<(String, String /*prev_state*/)>` so the caller knows whether to emit.)
2. If `prev_state == 'Failed'`, emit `AuditEventKind::InitiativeStateChanged { initiative_id, from: "Failed", to: "Executing", actor: "operator", reason: format!("respawn-escalation-approved by {}", operator.fingerprint) }`.

The `deny_logical_deadlock` path does NOT need this — it doesn't change initiative state.

INV entry already drafted: `INV-DEEP-SWEEP-D9-LOGICAL-DEADLOCK-APPROVE-EMITS-INITIATIVE-STATE-CHANGED-01`.

## Low-confidence findings (evidence-only)

### D1 — Two `Admitted` tasks frozen at admission_at (suspicious but inconclusive)

Tasks `review-lint-defect-rust` and `019e2dc0-3160-7a52-919b-e17bd4c85f86` are in state `Admitted` with `admitted_at == transitioned_at == 1778884030`. Lane `e2e-realistic-lane`. They never advanced to `Running` despite the kernel running for ~31 minutes more after that timestamp. Likely caused by the related `lint-runner-python` task hitting the kernel-side scheduling bug recorded in its `block_reason`:

> "session_spawn_orchestrator: executor VM reported a CleanCompletion exit notice but the activation row is still Active — the EarlyResponse cascade on the terminal intent should have closed it. This is a kernel-side scheduling bug, not a planner gap"

This bug class is in Worker 1's territory (`session_spawn_orchestrator.rs`). Not fixable here.

### D5 — Forensic latency outlier scan

No audit event in the iter62 chain has `latency_ms > 60000`. Maximum I saw was 5085 ms on a `planner_fetch_response`. The `subtask_activations.terminated_at - created_at` deltas all fit comfortably under the 600 s threshold. No outliers worth chasing.

### D8 — Low-confidence: `tokio::spawn` post-approval respawn at `ipc/operator.rs:2345`

The respawn-orchestrator-after-approve path spawns a fire-and-forget tokio task whose result is silently discarded with `let _ = …`. If the respawn fails, the operator's UI shows "approved" but the kernel never re-enters `Executing` and no audit event fires. Not a TOCTOU per se; flagging as a potential UX bug. Parent territory.

### D10 — `task_credential_proxies` rows have no terminated-at column

13 `task_credential_proxies` rows in `kernel.db` exactly mirror the 13 `CredentialProxyStarted` audit events, but the schema has no `terminated_at` / `revoked_at` column — the row is effectively eternal once written. This isn't a bug per se (the audit chain carries the lifecycle), but combined with D4 above (no `Stopped` events from kernel-kill), the SQL state is permanently "13 proxies bound" with no way to query "which are still bound". If a future operator dashboard wants to render live proxies, the source-of-truth has to be the audit chain delta, not the SQL row. Flag for iter63+ schema decision; no fix here.

### D10 — Schema-version count = 20, matches origin/main

Forensic `kernel.db` has `schema_version` rows 1..20, which is exactly the migration set on `origin/main`. Worker 1's new 0021 + 0022 are not yet present in the iter62 dump, so backwards-compat across iter62 → iter63 is just "apply 0021 + 0022 on top of a 20-version baseline" — no rollback hazard from anything in this branch.

## Notes on parent's iter62 deep-sweep evidence

I did not have direct access to the parent's `RETURN_NOTE` from the in-flight `worker/iter62-deep-sweep`, so I re-derived everything from the iter62 forensic dir + the `origin/main` snapshot. If the parent already flagged any of the deferred items above (D4, the two D9 items, the low-confidence D8), prefer the parent's framing — these are independently derived and may have a different vocabulary.

## Sweep dimensions left fully covered by parent

- D1.audit-chain integrity (parent swept).
- D1.paired-write violations on operator-driven aborts + gate-recheck-clear (parent swept).
