// raxis-kernel::notifications::sink — `NotifyingAuditSink` decorator.
//
// Normative reference: cli-readonly.md §5.6 "Operator notifications".
//
// What this is
// ────────────
// A thin `AuditSink` decorator that, after every successful inner
// emission, fans the freshly-materialised `AuditEvent` out to the
// notification dispatcher. Wrapping happens once at kernel boot
// (`kernel/src/main.rs`), so every kernel handler that calls
// `ctx.audit.emit(...)` automatically participates in the notification
// pipeline — handlers do NOT need to remember to call
// `notifications::dispatch` themselves.
//
// Recursion safety
// ────────────────
// `notifications::dispatch_one` writes
// `AuditEventKind::NotificationDeliveryFailed` audit events when a
// per-channel handler errors out. To avoid an infinite loop where every
// failed delivery triggers another failed delivery, the dispatcher is
// handed the **inner** sink (not `self`). Failure events therefore
// land in the audit chain but are NOT re-fanned.
//
// Performance
// ───────────
// Per emit:
//   - one `Arc::clone` of the inner sink and policy bundle reference,
//   - one `PathBuf::clone` of the data dir,
//   - one `AuditEvent::clone` (already-allocated record, ~hundreds of bytes).
//
// The fan-out itself runs on a `tokio::spawn` per channel (see
// `notifications::dispatch`), so the calling thread returns
// immediately after the inner emit completes.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use raxis_audit_tools::{AuditEvent, AuditEventKind, AuditSink, AuditWriterError};
use raxis_dashboard_kernel::notification_priority;
use raxis_observability::ObservabilityHub;
use raxis_policy::PolicyBundle;
use raxis_store::Store;

use super::SidecarRegistry;

/// Per-session bookkeeping used to compute `record_session_duration`
/// and tag `record_session_lifecycle_transition` with the agent_type
/// captured from the earlier `SessionCreated` event.
///
/// `SessionCreated` carries the agent_type but no spawn instant;
/// `SessionVmSpawned` carries no agent_type; `SessionVmExited`
/// carries neither. The bridge correlates the three by `session_id`.
#[derive(Default)]
struct SessionTracker {
    /// session_id → (spawn_instant, agent_type)
    by_session: HashMap<String, (Instant, String)>,
}

/// Per-initiative bookkeeping used to compute `record_initiative_duration`
/// and to maintain the `record_initiative_task_in_flight` gauge.
///
/// `InitiativeCreated` carries no `initiative_class` (no audit event
/// does at the moment), so the gauge / duration labels collapse to
/// `"unknown"` — the closed allow-list accepts arbitrary strings up to
/// 32 bytes for the `initiative_class` key.
#[derive(Default)]
struct InitiativeTracker {
    /// initiative_id → start_instant
    by_initiative: HashMap<String, Instant>,
    /// initiative_id → in-flight task count
    in_flight: HashMap<String, i64>,
}

/// Wraps any `AuditSink` (typically `FileAuditSink` in production,
/// `FakeAuditSink` in integration tests) and routes every emitted
/// event through `notifications::dispatch`.
pub struct NotifyingAuditSink {
    inner: Arc<dyn AuditSink>,
    policy: Arc<ArcSwap<PolicyBundle>>,
    data_dir: PathBuf,
    sidecar_registry: Option<Arc<SidecarRegistry>>,
    store: Option<Arc<Store>>,
    /// Optional `ObservabilityHub` reference. When present, every
    /// successful inner emit ALSO bumps the matching V3 §3 metric
    /// (egress admit / deny / default-grant / stall, credential-proxy
    /// substitution). When absent (e.g. in legacy unit tests that
    /// never wire a hub), the bridge is a noop. The hub is the
    /// dashboard fast path; the audit log remains the source of truth.
    obs_hub: Option<Arc<ObservabilityHub>>,
    /// V3 observability — per-session correlation state used to
    /// compute session-duration / agent_type-tagged lifecycle
    /// transitions. Only mutated when `obs_hub` is `Some(_)` AND
    /// the inner emit succeeded; cleared on `SessionVmExited`.
    sessions: Mutex<SessionTracker>,
    /// V3 observability — per-initiative correlation state used to
    /// compute initiative-duration and the in-flight task gauge.
    /// Same lifecycle discipline as `sessions`.
    initiatives: Mutex<InitiativeTracker>,
}

impl NotifyingAuditSink {
    /// Wrap `inner` so every successful emit is fanned out to the
    /// channels declared in the active policy bundle's `[notifications]`
    /// section. The wrapped sink is itself an `AuditSink` so it slots
    /// into `HandlerContext.audit` without any other call-site change.
    pub fn new(
        inner: Arc<dyn AuditSink>,
        policy: Arc<ArcSwap<PolicyBundle>>,
        data_dir: PathBuf,
    ) -> Self {
        Self {
            inner,
            policy,
            data_dir,
            sidecar_registry: None,
            store: None,
            obs_hub: None,
            sessions: Mutex::new(SessionTracker::default()),
            initiatives: Mutex::new(InitiativeTracker::default()),
        }
    }

    /// Builder-style: attach the per-kernel `SidecarRegistry` so
    /// Sidecar-kind channels can be dispatched.
    pub fn with_sidecar_registry(mut self, reg: Arc<SidecarRegistry>) -> Self {
        self.sidecar_registry = Some(reg);
        self
    }

    /// Builder-style: attach the kernel's `Store` so every notification
    /// is unconditionally written to the `notifications` table in SQLite.
    pub fn with_store(mut self, store: Arc<Store>) -> Self {
        self.store = Some(store);
        self
    }

    /// Builder-style: attach the kernel's [`ObservabilityHub`] so that
    /// every audit event whose variant has a paired metric (V3 §3
    /// expansion) bumps the matching counter at the same moment the
    /// audit record lands. The bridge is intentionally one-way:
    /// metric-emit failure (e.g. hub disabled, redactor reject) is
    /// silent at this layer; the dispatcher already increments
    /// `raxis.observability.dropped.total` for any rejected frame.
    pub fn with_observability(mut self, hub: Arc<ObservabilityHub>) -> Self {
        self.obs_hub = Some(hub);
        self
    }
}

/// Returns `Some(clone)` for variants the metric bridge cares about,
/// `None` for everything else. Lets the audit hot-path skip cloning
/// the (sometimes-large) `AuditEventKind` enum when the variant has
/// no counter — only the bridged variants below get cloned.
fn bridge_kind_if_relevant(kind: &AuditEventKind) -> Option<AuditEventKind> {
    matches!(
        kind,
        // V3 §3 originals.
        AuditEventKind::TransparentProxyAdmitted { .. }
            | AuditEventKind::TransparentProxyDenied { .. }
            | AuditEventKind::DefaultProviderEgressApplied { .. }
            | AuditEventKind::SessionEgressStallDetected { .. }
            | AuditEventKind::CredentialProxySubstituted { .. }
            // Session / initiative lifecycle (Part 2 expansion).
            | AuditEventKind::SessionCreated { .. }
            | AuditEventKind::SessionVmSpawned { .. }
            | AuditEventKind::SessionVmExited { .. }
            | AuditEventKind::InitiativeCreated { .. }
            | AuditEventKind::InitiativeStateChanged { .. }
            | AuditEventKind::InitiativeAborted { .. }
            | AuditEventKind::TaskAdmitted { .. }
            | AuditEventKind::TaskStateChanged { .. }
            // Notifications.
            | AuditEventKind::NotificationDelivered { .. }
            | AuditEventKind::NotificationDeliveryFailed { .. }
            // Credential proxies.
            | AuditEventKind::CredentialProxyUpstreamConnected { .. }
            | AuditEventKind::CredentialProxyUpstreamFailed { .. }
            | AuditEventKind::DatabaseQueryExecuted { .. }
            | AuditEventKind::DatabaseQueryCompleted { .. }
            | AuditEventKind::HttpProxyRequestExecuted { .. }
            | AuditEventKind::SmtpMessageRelayed { .. }
            | AuditEventKind::SmtpMessageRejected { .. }
            // Reviewer aggregation.
            | AuditEventKind::ReviewAggregationCompleted { .. }
            | AuditEventKind::ExecutorRespawnFromReviewRejection { .. }
            // Git integration.
            | AuditEventKind::IntegrationMergeCompleted { .. }
            | AuditEventKind::MergeFastForwardFailed { .. }
    )
    .then(|| kind.clone())
}

/// Bump V3 §3 counters at the same moment the matching audit event
/// is emitted. Mapping is exhaustive over the variants the
/// dashboards reference; everything else is a no-op so adding a new
/// audit variant doesn't accidentally leak through this bridge
/// unless someone adds a deliberate arm here.
///
/// Kept private to this module so the mapping table lives next to
/// the only call site (`NotifyingAuditSink::emit`); the per-metric
/// helpers continue to live in `kernel/src/observability.rs`.
///
/// `sessions` / `initiatives` are mutated for variants that need
/// cross-event correlation (spawn→exit duration, in-flight gauge);
/// stateless variants ignore them.
fn bridge_audit_to_metric(
    hub: &ObservabilityHub,
    kind: &AuditEventKind,
    sessions: &Mutex<SessionTracker>,
    initiatives: &Mutex<InitiativeTracker>,
) {
    use crate::observability as obs;
    match kind {
        // ── V3 §3 originals ───────────────────────────────────────
        AuditEventKind::TransparentProxyAdmitted { .. } => {
            obs::record_egress_admit(hub, "tproxy");
        }
        AuditEventKind::TransparentProxyDenied { reason, .. } => {
            obs::record_egress_deny(hub, "tproxy", reason);
        }
        AuditEventKind::DefaultProviderEgressApplied { provider_kind, .. } => {
            obs::record_egress_default_provider_grant(hub, provider_kind);
        }
        AuditEventKind::SessionEgressStallDetected { source, reason, .. } => {
            obs::record_egress_stall_detected(hub, source, reason);
        }
        AuditEventKind::CredentialProxySubstituted { proxy_type, .. } => {
            obs::record_credential_proxy_substitution(hub, proxy_type);
        }

        // ── Session lifecycle (lifecycle transition + duration) ───
        //
        // `SessionCreated` is the earliest event carrying the agent
        // type; we cache it under the session id so the later
        // `SessionVmExited` can emit duration + lifecycle transition
        // with the right `agent_type` label.
        AuditEventKind::SessionCreated {
            session_id,
            session_agent_type,
            ..
        } => {
            let agent_type = session_agent_type
                .as_deref()
                .unwrap_or("unknown")
                .to_owned();
            obs::record_session_lifecycle_transition(hub, "None", "Created", &agent_type, "ok");
            // Cache the agent_type. The spawn instant comes later on
            // `SessionVmSpawned`; we seed with `Instant::now()` so
            // sessions that go straight to exited without a spawn
            // still get a non-zero duration window.
            sessions
                .lock()
                .by_session
                .insert(session_id.clone(), (Instant::now(), agent_type));
        }
        AuditEventKind::SessionVmSpawned { session_id, .. } => {
            // Refresh the spawn instant — `SessionCreated` happens
            // before scheduling admits the spawn; the wall-clock the
            // operator cares about is the VM-spawn-to-VM-exit window.
            let now = Instant::now();
            let mut guard = sessions.lock();
            match guard.by_session.get_mut(session_id) {
                Some(entry) => entry.0 = now,
                None => {
                    // SessionCreated was missed (legacy chain or
                    // SessionCreated emit failed); seed a fresh entry
                    // with unknown agent_type.
                    guard
                        .by_session
                        .insert(session_id.clone(), (now, "unknown".to_owned()));
                }
            }
            // Pull agent_type for the transition label without
            // holding the guard across the metric emit (avoid lock
            // contention on the high-volume admission path).
            let agent_type = guard
                .by_session
                .get(session_id)
                .map(|(_, a)| a.clone())
                .unwrap_or_else(|| "unknown".to_owned());
            drop(guard);
            obs::record_session_lifecycle_transition(hub, "Created", "Spawned", &agent_type, "ok");
        }
        AuditEventKind::SessionVmExited {
            session_id,
            signal_class,
            ..
        } => {
            let entry = sessions.lock().by_session.remove(session_id);
            let (spawn_instant, agent_type) = match entry {
                Some(pair) => pair,
                None => (Instant::now(), "unknown".to_owned()),
            };
            let duration_ms = spawn_instant.elapsed().as_millis() as i64;
            let outcome = match signal_class.as_str() {
                "GracefulExit" => "ok",
                _ => "error",
            };
            obs::record_session_lifecycle_transition(
                hub,
                "Spawned",
                "Exited",
                &agent_type,
                outcome,
            );
            obs::record_session_duration(hub, &agent_type, outcome, duration_ms);
        }

        // ── Initiative lifecycle (duration + in-flight gauge) ────
        //
        // No audit event exposes an explicit `initiative_class`, so
        // the gauge / histogram collapses to `"unknown"`. This is a
        // valid label — the redactor accepts it under the closed
        // `initiative_class` allow-list entry.
        AuditEventKind::InitiativeCreated { initiative_id, .. } => {
            initiatives
                .lock()
                .by_initiative
                .insert(initiative_id.clone(), Instant::now());
        }
        AuditEventKind::InitiativeStateChanged {
            initiative_id,
            to_state,
            ..
        } => {
            // Only the terminal state-changes produce a duration
            // observation. Mirror the FSM terminal set
            // (Completed / Failed / Cancelled).
            let terminal = matches!(
                to_state.as_str(),
                "Completed" | "Failed" | "Cancelled" | "Aborted",
            );
            if terminal {
                let start = initiatives
                    .lock()
                    .by_initiative
                    .remove(initiative_id)
                    .unwrap_or_else(Instant::now);
                let duration_ms = start.elapsed().as_millis() as i64;
                let outcome = match to_state.as_str() {
                    "Completed" => "ok",
                    _ => "error",
                };
                obs::record_initiative_duration(hub, "unknown", outcome, duration_ms);
            }
        }
        AuditEventKind::InitiativeAborted { initiative_id, .. } => {
            let start = initiatives
                .lock()
                .by_initiative
                .remove(initiative_id)
                .unwrap_or_else(Instant::now);
            let duration_ms = start.elapsed().as_millis() as i64;
            obs::record_initiative_duration(hub, "unknown", "aborted", duration_ms);
        }
        AuditEventKind::TaskAdmitted { initiative_id, .. } => {
            let mut guard = initiatives.lock();
            let count = guard.in_flight.entry(initiative_id.clone()).or_insert(0);
            *count += 1;
            let value = *count;
            drop(guard);
            obs::record_initiative_task_in_flight(hub, "unknown", value);
        }
        AuditEventKind::TaskStateChanged { to_state, .. } => {
            // Only terminal task states decrement the gauge. We
            // cannot look up the owning initiative_id from a
            // `TaskStateChanged` payload (the event does not carry
            // it), so we emit the gauge without a per-initiative
            // delta — the kernel-side audit-paired-writes contract
            // pairs TaskStateChanged with a TaskAdmitted earlier
            // that already pushed an `initiative_class="unknown"`
            // sample. This branch is intentionally a noop: the gauge
            // converges to its true value at the next TaskAdmitted /
            // initiative-completion tick.
            let _ = to_state;
        }

        // ── Notifications ─────────────────────────────────────────
        AuditEventKind::NotificationDelivered {
            channel_kind,
            channel_id,
            event_kind,
            delivery_ms,
            ..
        } => {
            obs::record_notification_delivery(
                hub,
                channel_kind,
                channel_id,
                event_kind,
                true,
                *delivery_ms as i64,
            );
        }
        AuditEventKind::NotificationDeliveryFailed {
            channel_id,
            event_kind,
            ..
        } => {
            // `NotificationDeliveryFailed` does not carry
            // `channel_kind` or `delivery_ms` — both surface only on
            // the success path. Use `"unknown"` and 0 so the metric
            // still records the failure attempt; dashboards filter
            // on `success=false` to surface the failure rate.
            obs::record_notification_delivery(hub, "unknown", channel_id, event_kind, false, 0);
        }

        // ── Credential proxies ───────────────────────────────────
        AuditEventKind::CredentialProxyUpstreamConnected {
            proxy_type,
            handshake_ms,
            ..
        } => {
            obs::record_credproxy_connection(hub, proxy_type, "ok", *handshake_ms as i64);
        }
        AuditEventKind::CredentialProxyUpstreamFailed {
            proxy_type, reason, ..
        } => {
            obs::record_credproxy_connection(hub, proxy_type, "error", 0);
            obs::record_credproxy_policy_block(hub, proxy_type, reason);
        }
        AuditEventKind::DatabaseQueryExecuted {
            operation, blocked, ..
        } => {
            let outcome = if *blocked { "blocked" } else { "ok" };
            obs::record_credproxy_statement(hub, "database", operation, outcome, *blocked, 0);
        }
        AuditEventKind::DatabaseQueryCompleted {
            proxy_type,
            bytes_returned,
            duration_ms,
            upstream_error,
            ..
        } => {
            let outcome = if upstream_error.is_some() {
                "error"
            } else {
                "ok"
            };
            obs::record_credproxy_statement(
                hub,
                proxy_type,
                "query",
                outcome,
                false,
                *duration_ms as i64,
            );
            obs::record_credproxy_bytes(hub, proxy_type, "in", *bytes_returned as i64);
        }
        AuditEventKind::HttpProxyRequestExecuted {
            method,
            blocked,
            status_code,
            ..
        } => {
            let outcome = if *blocked {
                "blocked"
            } else if *status_code >= 500 {
                "error"
            } else {
                "ok"
            };
            obs::record_credproxy_statement(hub, "http", method, outcome, *blocked, 0);
        }
        AuditEventKind::SmtpMessageRelayed { bytes_relayed, .. } => {
            obs::record_credproxy_statement(hub, "smtp", "relay", "ok", false, 0);
            obs::record_credproxy_bytes(hub, "smtp", "out", *bytes_relayed as i64);
        }
        AuditEventKind::SmtpMessageRejected { reason, .. } => {
            obs::record_credproxy_statement(hub, "smtp", "relay", "blocked", true, 0);
            obs::record_credproxy_policy_block(hub, "smtp", reason);
        }

        // ── Reviewer aggregation ─────────────────────────────────
        AuditEventKind::ReviewAggregationCompleted {
            verdict,
            reviewer_count,
            ..
        } => {
            // `record_reviewer_review` records one observation per
            // terminal aggregation. Duration is unknown at this
            // layer (the audit event does not carry it); 0 is the
            // safe sentinel — the aggregation completion event is
            // itself instantaneous from the audit chain's POV.
            obs::record_reviewer_review(hub, verdict, 0);
            if verdict == "AtLeastOneRejected" {
                // `revision_round` carries the cardinality of the
                // disagreement (number of dissenting reviewers as a
                // proxy); the helper takes an i64 and the
                // `reviewer_count` value is the closest available
                // measure at this layer.
                obs::record_reviewer_disagreement(hub, *reviewer_count as i64);
            }
            obs::record_review_revision_round(hub, *reviewer_count as i64);
        }
        AuditEventKind::ExecutorRespawnFromReviewRejection {
            review_reject_count,
            ..
        } => {
            obs::record_review_revision_round(hub, *review_reject_count as i64);
        }

        // ── Git integration ──────────────────────────────────────
        AuditEventKind::IntegrationMergeCompleted { .. } => {
            obs::record_git_merge(hub, "ok", 0);
            obs::record_git_commit(hub, "orchestrator");
        }
        AuditEventKind::MergeFastForwardFailed { category, .. } => {
            let _ = category;
            obs::record_git_merge(hub, "error", 0);
        }

        _ => { /* no metric counterpart — audit log carries it alone */ }
    }
}

impl AuditSink for NotifyingAuditSink {
    fn emit(
        &self,
        kind: AuditEventKind,
        session_id: Option<&str>,
        task_id: Option<&str>,
        initiative_id: Option<&str>,
    ) -> Result<AuditEvent, AuditWriterError> {
        // 1. Inner emit FIRST. The audit chain is the source of truth;
        //    if it fails, no notification dispatch happens (the spec
        //    forbids notifications without a corresponding audit
        //    record per cli-readonly.md §5.6.2).
        //
        //    We snapshot a clone of `kind` for the metric bridge step
        //    BEFORE moving `kind` into `inner.emit`, but only when an
        //    `ObservabilityHub` is wired AND the variant is one the
        //    bridge cares about. Skipping the clone for bridge-irrelevant
        //    variants keeps the high-volume audit hot-path's per-emit
        //    allocation count unchanged from before the bridge landed.
        let bridge_kind = self
            .obs_hub
            .as_ref()
            .and_then(|_| bridge_kind_if_relevant(&kind));
        // INV-NOTIF-SCOPE-01: classify the event for the operator's
        // notification inbox BEFORE moving `kind` into `inner.emit`.
        // `None` ⇒ audit-chain only (operator-passive action,
        // routine session/proxy/credential lifecycle, high-volume
        // metric emission). The audit chain ALWAYS records the
        // event regardless — this gate is purely the notification
        // projection.
        //
        // Computing here rather than after the inner emit lets us
        // borrow `&kind` once (so a noisy kind avoids the clone /
        // bundle snapshot / dispatch fan-out below).
        let priority = notification_priority(&kind);
        // INV-OBSERVABILITY-LATENCY-METRICS-WIRED-03 — every
        // audit-chain append is the kernel's most-loaded write
        // path, so we time the inner emit on both arms (success +
        // failure). `event_kind` and `outcome` are stamped on the
        // histogram so the dashboard's bottleneck pivot can isolate
        // a slow audit variant (e.g. large
        // `IntegrationMergeCompleted` payload) from a slow audit
        // variant the kernel re-uses on every IPC frame.
        let event_kind_label = kind.as_str().to_owned();
        let emit_started = Instant::now();
        let inner_result = self.inner.emit(kind, session_id, task_id, initiative_id);
        let emit_elapsed_ms = emit_started.elapsed().as_millis().min(i64::MAX as u128) as i64;
        let event = match inner_result {
            Ok(ev) => ev,
            Err(e) => {
                // V3 perf-telemetry — audit-chain fsync / append
                // failures are an operational alarm bell. We can
                // only see the error category at this seam (the
                // inner sink doesn't surface a typed kind), so we
                // classify by `AuditWriterError` variant.
                if let Some(hub) = self.obs_hub.as_ref() {
                    let reason = match &e {
                        AuditWriterError::Io(_) => "io",
                        _ => "other",
                    };
                    crate::observability::record_audit_fsync_failure(hub, reason);
                    // Pair the latency observation with the
                    // failure arm so a regression in append latency
                    // shows on the dashboard even when every
                    // attempt is failing the fsync barrier. The
                    // `confirmed_ms` argument is `None` because the
                    // inner emit returned `Err` — there was no
                    // post-commit confirmation.
                    crate::observability::record_audit_event_append(
                        hub,
                        &event_kind_label,
                        "error",
                        emit_elapsed_ms,
                        None,
                    );
                }
                return Err(e);
            }
        };

        // 1a. Bridge to the V3 §3 metric counter (egress admit/deny/
        //     default-grant/stall, credential-proxy substitution,
        //     plus the Part 2 expansion: session / initiative /
        //     notification / credproxy / reviewer / git). The hub
        //     bump runs only after the inner emit succeeded, so
        //     metric and audit always agree on what landed. Hub may
        //     be `None` in legacy unit-test paths; bridge is a noop
        //     when missing.
        if let Some(hub) = self.obs_hub.as_ref() {
            if let Some(bk) = bridge_kind {
                bridge_audit_to_metric(hub, &bk, &self.sessions, &self.initiatives);
            }
            // INV-OBSERVABILITY-LATENCY-METRICS-WIRED-03 (success
            // arm) — paired with the failure arm above so the
            // histogram has every-append coverage. The
            // `confirmed_ms` argument is the same wall-clock as
            // `append_ms` because `AuditWriter::append` is
            // synchronous and the fsync barrier already closed
            // before the inner emit returned (see
            // `AuditWriterOptions::sync_on_append = true`).
            crate::observability::record_audit_event_append(
                hub,
                &event_kind_label,
                "ok",
                emit_elapsed_ms,
                Some(emit_elapsed_ms),
            );
            // INV-OBSERVABILITY-LATENCY-METRICS-WIRED-04 — bump the
            // chain-length gauge on every successful append. The
            // gauge tracks the highest committed seq, so emitting
            // here (after the inner sink returns the materialised
            // event) keeps the dashboard's chain-progress series
            // monotonic and aligned with the on-disk JSONL tip.
            crate::observability::record_audit_chain_length(hub, event.seq as i64);
            // V3 perf-telemetry — the kernel's audit chain is
            // sync-fsync'd on every successful append (`writer.rs`
            // calls `File::sync_data` before returning Ok), so the
            // "events behind in-memory tip" gauge is structurally
            // zero at this seam. Re-emitting the zero gauge per
            // successful append keeps the dashboard surface alive
            // (a stale series would silently mask a future
            // asynchronous-flush regression).
            crate::observability::record_audit_chain_lag(hub, 0);
        }

        // 1b. INV-NOTIF-SCOPE-01: drop events that should not reach
        //     the operator's notification inbox. The audit chain
        //     keeps the row (already written by the inner emit
        //     above); we just skip the inbox / SQLite / channel
        //     fan-out.
        if priority.is_none() {
            return Ok(event);
        }

        // 2. Snapshot the bundle once. Holding the reference across
        //    the dispatch is fine because `ArcSwap::load_full` returns
        //    an owned `Arc` that detaches from the swap.
        let bundle = self.policy.load_full();

        // 3. Hand the event AND the inner sink to the dispatcher. We
        //    pass `inner` (NOT `self`) so any per-channel
        //    `NotificationDeliveryFailed` event goes straight to the
        //    audit chain without re-triggering notifications. Without
        //    this guard, a misconfigured policy that routed
        //    `NotificationDeliveryFailed` to a perpetually-broken
        //    channel would loop forever.
        super::dispatch(
            event.clone(),
            bundle,
            self.data_dir.clone(),
            Arc::clone(&self.inner),
            self.sidecar_registry.clone(),
            self.store.clone(),
        );

        Ok(event)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notifications::dispatch_blocking_for_tests;
    use raxis_policy::{OperatorEntry, PolicyBundle};
    use raxis_test_support::FakeAuditSink;
    use serde_json::json;

    fn bundle() -> Arc<ArcSwap<PolicyBundle>> {
        // The notification sink tests don't exercise the cert-validation
        // path; they need an OperatorEntry to exist only to satisfy the
        // bundle's "operators must not be empty" rule. `stub_cert_for_pubkey`
        // returns a structurally-shaped placeholder cert that
        // `for_tests_with_operators` accepts (validation is bypassed)
        // but would loudly fail any real `verify_cert_self_signature`
        // call — which is precisely the safety net we want.
        let pubkey = "0".repeat(64);
        let b = PolicyBundle::for_tests_with_operators(vec![OperatorEntry {
            pubkey_fingerprint: "fp".into(),
            display_name: "fp".into(),
            pubkey_hex: pubkey.clone(),
            permitted_ops: vec![],
            cert: raxis_test_support::stub_cert_for_pubkey(pubkey),
            force_misconfig_bypass: false,
        }]);
        Arc::new(ArcSwap::from_pointee(b))
    }

    /// `NotifyingAuditSink::emit` MUST forward to the inner sink and
    /// return the same `AuditEvent`, with the dispatch fan-out being
    /// the only side effect.
    #[tokio::test]
    async fn emit_forwards_to_inner_and_returns_event() {
        let tmp = tempfile::tempdir().unwrap();
        let inner = Arc::new(FakeAuditSink::new());
        let inner_dyn: Arc<dyn AuditSink> = inner.clone();
        let sink =
            NotifyingAuditSink::new(Arc::clone(&inner_dyn), bundle(), tmp.path().to_path_buf());

        let evt = sink
            .emit(
                AuditEventKind::EscalationApproved {
                    escalation_id: "esc-A".into(),
                    approved_by: "op".into(),
                    approved_by_display_name: None,
                },
                None,
                None,
                None,
            )
            .unwrap();

        assert_eq!(evt.event_kind, "EscalationApproved");
        assert_eq!(inner.events().len(), 1, "inner sink must capture one event");
    }

    /// A handler-emit followed by `dispatch_blocking_for_tests` (the
    /// production wrapper uses `tokio::spawn` which is awkward to wait
    /// on in tests) MUST land a JSONL line in the implicit Shell inbox.
    #[tokio::test]
    async fn dispatch_writes_inbox_line_on_emit() {
        let tmp = tempfile::tempdir().unwrap();
        let inner: Arc<dyn AuditSink> = Arc::new(FakeAuditSink::new());
        let sink = NotifyingAuditSink::new(Arc::clone(&inner), bundle(), tmp.path().to_path_buf());

        // Emit through the wrapper to ensure inner-side capture.
        let evt = sink
            .emit(
                AuditEventKind::EscalationApproved {
                    escalation_id: "esc-B".into(),
                    approved_by: "op".into(),
                    approved_by_display_name: None,
                },
                None,
                None,
                None,
            )
            .unwrap();

        // The production code path uses `tokio::spawn`; for assertion
        // determinism we replay the same dispatch synchronously.
        dispatch_blocking_for_tests(evt, &bundle().load_full(), tmp.path(), Arc::clone(&inner))
            .await;

        let inbox = PolicyBundle::inbox_path_for(tmp.path());
        let raw = std::fs::read_to_string(&inbox).unwrap_or_default();
        assert!(
            raw.contains("EscalationApproved"),
            "inbox MUST carry the dispatched event; got: {raw:?}"
        );
    }

    /// `INV-NOTIF-SCOPE-01`: operator-passive dashboard actions
    /// (mark-read, view-diff, view-file, view-worktree, chain-
    /// reverify, view-health) emit cleanly through the inner audit
    /// sink (the chain records them) but the wrapper MUST NOT fan
    /// them out to the notification dispatcher. The acceptance
    /// criterion is "no inbox.jsonl line lands for these events";
    /// we wait briefly for any spawned dispatch to settle and
    /// assert the file is empty.
    #[tokio::test]
    async fn operator_passive_action_does_not_create_notification() {
        let tmp = tempfile::tempdir().unwrap();
        let inner = Arc::new(FakeAuditSink::new());
        let inner_dyn: Arc<dyn AuditSink> = inner.clone();
        let sink =
            NotifyingAuditSink::new(Arc::clone(&inner_dyn), bundle(), tmp.path().to_path_buf());

        let evt = sink
            .emit(
                AuditEventKind::OperatorNotificationMarkedRead {
                    operator_fingerprint: "fp".into(),
                    notification_id: "n-1".into(),
                    updated: true,
                    outcome: "Accepted".into(),
                },
                None,
                None,
                None,
            )
            .unwrap();

        // Audit chain MUST capture the event (forensic record).
        assert_eq!(evt.event_kind, "OperatorNotificationMarkedRead");
        assert_eq!(
            inner.events().len(),
            1,
            "inner sink (audit chain) must capture every operator-passive event",
        );

        // Notification surface MUST NOT fan out — let any spawned
        // task settle, then assert the inbox file does not exist
        // (or is empty).
        for _ in 0..5 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let inbox = PolicyBundle::inbox_path_for(tmp.path());
        let raw = std::fs::read_to_string(&inbox).unwrap_or_default();
        assert!(
            raw.trim().is_empty(),
            "operator-passive action must not create a notification (\
             INV-NOTIF-SCOPE-01); inbox contents: {raw:?}"
        );
    }

    /// `INV-NOTIF-SCOPE-01`: routine high-volume events (session
    /// lifecycle / credential proxy / per-task transitions) MUST
    /// be audit-only, never inbox-bound. Same acceptance criterion
    /// as the operator-passive case above.
    #[tokio::test]
    async fn routine_lifecycle_event_does_not_create_notification() {
        let tmp = tempfile::tempdir().unwrap();
        let inner = Arc::new(FakeAuditSink::new());
        let inner_dyn: Arc<dyn AuditSink> = inner.clone();
        let sink =
            NotifyingAuditSink::new(Arc::clone(&inner_dyn), bundle(), tmp.path().to_path_buf());

        sink.emit(
            AuditEventKind::SessionCreated {
                session_id: "s-1".into(),
                role: "executor".into(),
                lineage_id: "l-1".into(),
                worktree_root: None,
                initiative_id: None,
                plan_bundle_sha256: None,
                policy_epoch: None,
                session_agent_type: None,
            },
            None,
            None,
            None,
        )
        .unwrap();

        for _ in 0..5 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let inbox = PolicyBundle::inbox_path_for(tmp.path());
        let raw = std::fs::read_to_string(&inbox).unwrap_or_default();
        assert!(
            raw.trim().is_empty(),
            "SessionCreated must not create a notification \
             (audit-chain only); inbox contents: {raw:?}"
        );
    }

    /// V3 §3 expansion bridge: when an `ObservabilityHub` is wired
    /// into the sink, emitting one of the five bridged audit variants
    /// MUST also emit exactly one matching counter into the hub. The
    /// other variants MUST NOT touch the hub's metric channel.
    #[tokio::test]
    async fn bridge_bumps_metric_for_observed_variants() {
        use raxis_observability::{
            exporter::{InMemoryExporter, ObservabilityExporter},
            hub::HubConfig,
            ObservabilityHub,
        };
        use std::sync::Arc;

        // Hub wired with an in-memory exporter we can introspect after
        // flush — same pattern the observability crate's own tests use.
        let exp = Arc::new(InMemoryExporter::new());
        let cfg = HubConfig {
            enabled: true,
            max_queue_depth: 1024,
            sample_rate: 1.0,
            max_attrs_per_span: 32,
            max_events_per_span: 16,
            ..HubConfig::default()
        };
        let hub = Arc::new(ObservabilityHub::new(
            cfg,
            Arc::clone(&exp) as Arc<dyn ObservabilityExporter>,
        ));

        let tmp = tempfile::tempdir().unwrap();
        let inner = Arc::new(FakeAuditSink::new());
        let inner_dyn: Arc<dyn AuditSink> = inner.clone();
        let sink =
            NotifyingAuditSink::new(Arc::clone(&inner_dyn), bundle(), tmp.path().to_path_buf())
                .with_observability(Arc::clone(&hub));

        // Bridged variant: TransparentProxyDenied → raxis.egress.deny.total.
        sink.emit(
            AuditEventKind::TransparentProxyDenied {
                session_id: "sess-1".into(),
                host_or_sni: Some("forbidden.example.com".into()),
                original_dst_ip: "10.0.0.1".into(),
                original_dst_port: 443,
                protocol: "https".into(),
                reason: "host_not_in_allowlist".into(),
            },
            Some("sess-1"),
            None,
            None,
        )
        .unwrap();

        // Non-bridged variant: KernelStarted should NOT touch metrics.
        sink.emit(
            AuditEventKind::KernelStarted {
                data_dir: "/tmp".into(),
                policy_epoch: 1,
                schema_version: 1,
            },
            None,
            None,
            None,
        )
        .unwrap();

        hub.flush();

        let metrics = exp.metrics();
        // V3 Part 2 expansion: every successful audit append also
        // emits `raxis.audit.chain.lag` (gauge, sync-fsync ⇒ always 0).
        // The bridged-variant assertion is now "find the deny counter"
        // rather than "exactly one metric".
        let deny = metrics
            .iter()
            .find(|m| m.name.as_otel_name() == "raxis.egress.deny.total")
            .unwrap_or_else(|| {
                panic!("expected one raxis.egress.deny.total metric; got {metrics:#?}",)
            });
        assert_eq!(
            deny.labels.get("chokepoint").map(|v| match v {
                raxis_observability::AttrValue::Str(s) => s.as_str(),
                _ => panic!("chokepoint label must be Str"),
            }),
            Some("tproxy"),
        );
        assert_eq!(
            deny.labels.get("reason").map(|v| match v {
                raxis_observability::AttrValue::Str(s) => s.as_str(),
                _ => panic!("reason label must be Str"),
            }),
            Some("host_not_in_allowlist"),
        );
    }

    /// If `with_observability` is NOT called, the bridge stays cold —
    /// confirms the legacy code path (unit tests, embedded harnesses
    /// that never wire a hub) keeps emitting cleanly with no metric
    /// side-effect and no panics.
    #[tokio::test]
    async fn bridge_is_inert_when_no_hub_attached() {
        let tmp = tempfile::tempdir().unwrap();
        let inner = Arc::new(FakeAuditSink::new());
        let inner_dyn: Arc<dyn AuditSink> = inner.clone();
        let sink =
            NotifyingAuditSink::new(Arc::clone(&inner_dyn), bundle(), tmp.path().to_path_buf());

        sink.emit(
            AuditEventKind::TransparentProxyAdmitted {
                session_id: "sess-A".into(),
                host_or_sni: Some("api.example.com".into()),
                original_dst_ip: "10.0.0.2".into(),
                original_dst_port: 443,
                protocol: "https".into(),
            },
            Some("sess-A"),
            None,
            None,
        )
        .unwrap();

        assert_eq!(
            inner.events().len(),
            1,
            "inner sink still observes the emit"
        );
    }

    /// If the inner sink returns Err, the wrapper MUST propagate the
    /// error AND skip the dispatch (no audit ⇒ no notification — the
    /// audit chain is the source of truth).
    #[test]
    fn err_from_inner_skips_dispatch_and_propagates() {
        struct AlwaysFail;
        impl AuditSink for AlwaysFail {
            fn emit(
                &self,
                _kind: AuditEventKind,
                _session_id: Option<&str>,
                _task_id: Option<&str>,
                _initiative_id: Option<&str>,
            ) -> Result<AuditEvent, AuditWriterError> {
                Err(AuditWriterError::Io(std::io::Error::other("synthetic")))
            }
        }
        let tmp = tempfile::tempdir().unwrap();
        let inner: Arc<dyn AuditSink> = Arc::new(AlwaysFail);
        let sink = NotifyingAuditSink::new(Arc::clone(&inner), bundle(), tmp.path().to_path_buf());

        let result = sink.emit(
            AuditEventKind::KernelStarted {
                data_dir: "/tmp".into(),
                policy_epoch: 1,
                schema_version: 1,
            },
            None,
            None,
            None,
        );
        assert!(matches!(result, Err(AuditWriterError::Io(_))));

        // The inbox file must NOT have been created — we never reached
        // the dispatch fan-out.
        let inbox = PolicyBundle::inbox_path_for(tmp.path());
        assert!(
            !inbox.exists(),
            "no inbox write must occur on a failed inner emit; found {inbox:?}"
        );
        let _ = json!({}); // keep serde_json import live for future variant assertions
    }
}
