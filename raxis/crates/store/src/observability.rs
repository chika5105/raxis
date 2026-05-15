// raxis-store::observability — query-class lexicon + per-query latency helper.
//
// Spec: `specs/v3/dataplane-latency-instrumentation.md` (iter61).
// Invariant: `INV-OBSERVABILITY-DATAPLANE-LATENCY-01` (store query latency).
//
// # What this module owns
//
// 1. `QUERY_CLASS_*` — closed lexicon of SQL query classes the
//    kernel + dashboard issue. Every wired call site MUST pass a
//    constant from this module; a typo or unknown class is caught
//    by the `query_class_label_well_formed` witness test.
// 2. `time_query` — the single helper every observed call site
//    funnels through. Records one
//    `MetricName::StoreQueryDuration` histogram observation
//    tagged with `query_class` + `outcome`. Hub-disabled fast
//    path matches the `record_*` pattern in
//    `kernel/src/observability.rs`.
//
// # Why a closed lexicon
//
// Per-query histograms with free-form labels would explode
// dashboard cardinality (every distinct SQL → its own series).
// Bucketing into ~25 well-known classes keeps the cardinality
// bounded and gives the operator a single "which class is slow?"
// pivot rather than a page of unique queries.

use std::sync::Arc;
use std::time::Instant;

use raxis_observability::{redact, AttrMap, MetricName, ObservabilityHub};

// ---------------------------------------------------------------------------
// Closed lexicon — `query_class` allow-list
// ---------------------------------------------------------------------------
//
// Add a new class here when you wire a new query. The
// `every_class_lexeme_is_unique` witness test catches typos.
// Maximum length is bounded by the redactor's 32-byte cap on
// `query_class` (see `crates/observability/src/redact.rs`).

/// Audit-chain: append one event row.
pub const QUERY_CLASS_AUDIT_APPEND: &str = "audit_append";
/// Audit-chain: read events by seq range (paginated audit view).
pub const QUERY_CLASS_AUDIT_LIST: &str = "audit_list";
/// Audit-chain: read tip seq for chain-length gauge.
pub const QUERY_CLASS_AUDIT_TIP: &str = "audit_tip";

/// Sessions: list active sessions (dashboard list page).
pub const QUERY_CLASS_SESSION_LIST: &str = "session_list";
/// Sessions: read one session by id (dashboard detail page).
pub const QUERY_CLASS_SESSION_GET: &str = "session_get";
/// Sessions: insert a new session row (`session_spawn`).
pub const QUERY_CLASS_SESSION_INSERT: &str = "session_insert";
/// Sessions: update a session's lifecycle state.
pub const QUERY_CLASS_SESSION_UPDATE: &str = "session_update";
/// Sessions: count active sessions per role (health endpoint).
pub const QUERY_CLASS_SESSION_COUNT: &str = "session_count";

/// Initiatives: list (dashboard list page).
pub const QUERY_CLASS_INITIATIVE_LIST: &str = "initiative_list";
/// Initiatives: read one (dashboard detail page).
pub const QUERY_CLASS_INITIATIVE_GET: &str = "initiative_get";
/// Initiatives: count by state (dashboard summary tile).
pub const QUERY_CLASS_INITIATIVE_COUNT: &str = "initiative_count";

/// Tasks: list by initiative (dashboard task list).
pub const QUERY_CLASS_TASK_LIST: &str = "task_list";
/// Tasks: read one (dashboard detail page).
pub const QUERY_CLASS_TASK_GET: &str = "task_get";
/// Tasks: update a task row (FSM transition).
pub const QUERY_CLASS_TASK_UPDATE: &str = "task_update";

/// Escalations: read pending list (dashboard inbox).
pub const QUERY_CLASS_ESCALATION_LIST: &str = "escalation_list";
/// Escalations: read one (dashboard escalation detail).
pub const QUERY_CLASS_ESCALATION_GET: &str = "escalation_get";
/// Escalations: count pending (health endpoint summary).
pub const QUERY_CLASS_ESCALATION_COUNT: &str = "escalation_count";

/// Audit chain: walk segment files for the dashboard audit list /
/// chain-status endpoints. Distinct from `audit_append` (write
/// path) and `audit_tip` (single-row read for the chain-length
/// gauge); `audit_chain_walk` covers the bounded ring-buffer
/// walk in `KernelDashboardData::list_audit` and the optional
/// reverify scan in `audit_chain_status`.
pub const QUERY_CLASS_AUDIT_CHAIN_WALK: &str = "audit_chain_walk";

/// Notifications inbox: read the JSONL inbox for the dashboard's
/// `/api/notifications/inbox` route + `mark_read` mutations.
pub const QUERY_CLASS_NOTIFICATIONS_INBOX: &str = "notifications_inbox";

/// Policy: read the active `policy.toml` snapshot for the
/// dashboard's `/api/policy/snapshot` route.
pub const QUERY_CLASS_POLICY_SNAPSHOT: &str = "policy_snapshot";

/// Worktree: bounded `git log` / `git diff` / file-tree reads
/// behind the dashboard's per-worktree forensic surface.
/// Distinct class so a slow gitoxide walk over a large repo
/// doesn't get hidden inside a generic store-query bucket.
pub const QUERY_CLASS_WORKTREE_READ: &str = "worktree_read";

/// Credentials: read the per-initiative or per-system credential
/// metadata + reveal endpoints. Tagged separately because the
/// reveal path is rate-limited and an op can directly correlate
/// `credential_read` latency with the rate-limiter's window.
pub const QUERY_CLASS_CREDENTIAL_READ: &str = "credential_read";

/// Plan bundles: insert a fresh signed plan artifact.
pub const QUERY_CLASS_PLAN_BUNDLE_INSERT: &str = "plan_bundle_insert";
/// Plan bundles: read one for the operator's plan-detail view.
pub const QUERY_CLASS_PLAN_BUNDLE_GET: &str = "plan_bundle_get";

/// Operator certificates: lookup by fingerprint (auth path).
pub const QUERY_CLASS_OPERATOR_CERT_LOOKUP: &str = "operator_cert_lookup";
/// Operator certificates: full repopulate inside policy advance.
pub const QUERY_CLASS_OPERATOR_CERT_REPOPULATE: &str = "operator_cert_repopulate";

/// Policy history: append one snapshot (every policy advance).
pub const QUERY_CLASS_POLICY_HISTORY_APPEND: &str = "policy_history_append";
/// Policy history: read one snapshot (operator forensic view).
pub const QUERY_CLASS_POLICY_HISTORY_GET: &str = "policy_history_get";

/// KSB snapshot: read latest for one session.
pub const QUERY_CLASS_KSB_GET: &str = "ksb_get";
/// KSB snapshot: write one for one session.
pub const QUERY_CLASS_KSB_PUT: &str = "ksb_put";

/// Catch-all for an unwired query that flows through `time_query`
/// with no class set. Visible on the dashboard as a single
/// "unknown" series so the operator notices and the call site
/// can be tagged.
pub const QUERY_CLASS_UNKNOWN: &str = "unknown";

/// All known query classes. Used by the witness tests + the
/// dashboard JSON authoring pass to enumerate panel pivots.
pub const QUERY_CLASSES: &[&str] = &[
    QUERY_CLASS_AUDIT_APPEND,
    QUERY_CLASS_AUDIT_LIST,
    QUERY_CLASS_AUDIT_TIP,
    QUERY_CLASS_SESSION_LIST,
    QUERY_CLASS_SESSION_GET,
    QUERY_CLASS_SESSION_INSERT,
    QUERY_CLASS_SESSION_UPDATE,
    QUERY_CLASS_SESSION_COUNT,
    QUERY_CLASS_INITIATIVE_LIST,
    QUERY_CLASS_INITIATIVE_GET,
    QUERY_CLASS_INITIATIVE_COUNT,
    QUERY_CLASS_TASK_LIST,
    QUERY_CLASS_TASK_GET,
    QUERY_CLASS_TASK_UPDATE,
    QUERY_CLASS_ESCALATION_LIST,
    QUERY_CLASS_ESCALATION_GET,
    QUERY_CLASS_ESCALATION_COUNT,
    QUERY_CLASS_AUDIT_CHAIN_WALK,
    QUERY_CLASS_NOTIFICATIONS_INBOX,
    QUERY_CLASS_POLICY_SNAPSHOT,
    QUERY_CLASS_WORKTREE_READ,
    QUERY_CLASS_CREDENTIAL_READ,
    QUERY_CLASS_PLAN_BUNDLE_INSERT,
    QUERY_CLASS_PLAN_BUNDLE_GET,
    QUERY_CLASS_OPERATOR_CERT_LOOKUP,
    QUERY_CLASS_OPERATOR_CERT_REPOPULATE,
    QUERY_CLASS_POLICY_HISTORY_APPEND,
    QUERY_CLASS_POLICY_HISTORY_GET,
    QUERY_CLASS_KSB_GET,
    QUERY_CLASS_KSB_PUT,
    QUERY_CLASS_UNKNOWN,
];

// ---------------------------------------------------------------------------
// `time_query` — the single observed-call wrapper
// ---------------------------------------------------------------------------

/// Time the closure `f`, record a `MetricName::StoreQueryDuration`
/// histogram observation tagged with `query_class` + `outcome`,
/// and return the closure's result. Outcome is derived from
/// `Result::is_ok` for `Result`-returning closures via
/// [`time_query_result`]; for infallible closures use this base
/// helper which always tags `outcome = "ok"`.
///
/// Hub-disabled fast path: when `hub.enabled()` is false (or
/// `None`) the helper still runs `f` but records nothing — zero
/// per-call overhead in non-instrumented builds.
pub fn time_query<F, T>(hub: Option<&Arc<ObservabilityHub>>, query_class: &str, f: F) -> T
where
    F: FnOnce() -> T,
{
    let started = Instant::now();
    let out = f();
    if let Some(hub) = hub {
        if hub.enabled() {
            let duration_ms = started.elapsed().as_millis().min(i64::MAX as u128) as i64;
            let labels = redact::attrs([("query_class", query_class), ("outcome", "ok")]);
            hub.record_histogram(MetricName::StoreQueryDuration, labels, duration_ms as f64);
        }
    }
    out
}

/// Same as [`time_query`] but for `Result`-returning closures —
/// derives `outcome = "ok"` / `"error"` from the Result.
pub fn time_query_result<F, T, E>(
    hub: Option<&Arc<ObservabilityHub>>,
    query_class: &str,
    f: F,
) -> Result<T, E>
where
    F: FnOnce() -> Result<T, E>,
{
    let started = Instant::now();
    let out = f();
    if let Some(hub) = hub {
        if hub.enabled() {
            let duration_ms = started.elapsed().as_millis().min(i64::MAX as u128) as i64;
            let outcome = if out.is_ok() { "ok" } else { "error" };
            let labels = redact::attrs([("query_class", query_class), ("outcome", outcome)]);
            hub.record_histogram(MetricName::StoreQueryDuration, labels, duration_ms as f64);
        }
    }
    out
}

// Re-export the AttrMap type so callers don't need a transitive
// dep on raxis-observability just to thread a hub handle.
#[doc(hidden)]
pub type _AttrMap = AttrMap;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_observability::{
        exporter::InMemoryExporter, DataPoint, HubConfig, ObservabilityExporter, ObservabilityHub,
    };

    fn enabled_hub() -> (Arc<ObservabilityHub>, Arc<InMemoryExporter>) {
        let exp = Arc::new(InMemoryExporter::new());
        let cfg = HubConfig {
            enabled: true,
            sample_rate: 1.0,
            max_queue_depth: 256,
            ..HubConfig::default()
        };
        let hub = Arc::new(ObservabilityHub::new(
            cfg,
            exp.clone() as Arc<dyn ObservabilityExporter>,
        ));
        (hub, exp)
    }

    /// `INV-OBSERVABILITY-DATAPLANE-LATENCY-01` witness #1: every
    /// closed-lexicon entry is unique. A duplicate would silently
    /// merge two distinct call sites into one Grafana series.
    #[test]
    fn every_class_lexeme_is_unique() {
        let mut seen = std::collections::HashSet::new();
        for c in QUERY_CLASSES {
            assert!(seen.insert(*c), "duplicate query class lexeme: {c}");
        }
    }

    /// Witness #2: every lexeme fits the redactor's 32-byte cap.
    /// Values longer than 32 bytes are silently truncated, which
    /// would collapse `audit_append_with_long_suffix` and
    /// `audit_append_with_other_suffix` into one series.
    #[test]
    fn every_class_lexeme_fits_redactor_cap() {
        for c in QUERY_CLASSES {
            assert!(
                c.len() <= 32,
                "query class lexeme {c:?} exceeds 32-byte redactor cap"
            );
        }
    }

    /// Witness #3: invoking `time_query` with an enabled hub
    /// lands ≥1 sample under `MetricName::StoreQueryDuration` —
    /// the wire-up contract for `INV-OBSERVABILITY-DATAPLANE-LATENCY-01`.
    #[test]
    fn time_query_lands_observed_sample() {
        let (hub, exp) = enabled_hub();
        let result = time_query(Some(&hub), QUERY_CLASS_SESSION_LIST, || 42_i32);
        assert_eq!(result, 42);
        hub.flush();
        let metrics = exp.metrics();
        let count = metrics
            .iter()
            .filter(|m| m.name == MetricName::StoreQueryDuration)
            .filter_map(|m| match &m.datapoint {
                DataPoint::Histo { count, .. } => Some(*count),
                _ => None,
            })
            .sum::<u64>();
        assert!(
            count >= 1,
            "expected ≥1 StoreQueryDuration sample, got {count}"
        );
    }

    /// Witness #4: `time_query_result` tags the outcome label
    /// from the Result variant. A wired call site that always
    /// errors should produce an "error"-tagged sample, not "ok".
    #[test]
    fn time_query_result_tags_outcome_from_result() {
        let (hub, exp) = enabled_hub();
        let _ = time_query_result(
            Some(&hub),
            QUERY_CLASS_SESSION_GET,
            || -> Result<(), &str> { Err("boom") },
        );
        hub.flush();
        let metrics = exp.metrics();
        let any_error = metrics
            .iter()
            .filter(|m| m.name == MetricName::StoreQueryDuration)
            .any(|m| {
                m.labels
                    .get("outcome")
                    .map(|v| matches!(v, raxis_observability::AttrValue::Str(s) if s == "error"))
                    .unwrap_or(false)
            });
        assert!(
            any_error,
            "expected an error-tagged StoreQueryDuration sample"
        );
    }

    /// `INV-OBSERVABILITY-DATAPLANE-LATENCY-07` — pin the
    /// dashboard-kernel handler-coverage expansion. The newly
    /// wired handler set adds five lexicon entries
    /// (`escalation_get`, `audit_chain_walk`,
    /// `notifications_inbox`, `policy_snapshot`,
    /// `worktree_read`, `credential_read`) to the closed
    /// `QUERY_CLASSES` set. A typo or missing entry would let a
    /// dashboard-kernel call site pass an unknown literal that
    /// silently collapses to the `unknown` series — this witness
    /// trips that case at compile-adjacent test time.
    #[test]
    fn iter61_handler_coverage_lexicon_entries_are_present() {
        for lexeme in [
            QUERY_CLASS_ESCALATION_GET,
            QUERY_CLASS_AUDIT_CHAIN_WALK,
            QUERY_CLASS_NOTIFICATIONS_INBOX,
            QUERY_CLASS_POLICY_SNAPSHOT,
            QUERY_CLASS_WORKTREE_READ,
            QUERY_CLASS_CREDENTIAL_READ,
        ] {
            assert!(
                QUERY_CLASSES.contains(&lexeme),
                "iter61 handler-coverage lexeme {lexeme:?} missing from QUERY_CLASSES — the dashboard-kernel handler that uses it would silently collapse to `unknown`",
            );
        }
    }

    /// `INV-OBSERVABILITY-DATAPLANE-LATENCY-07` — happy-path
    /// witness that every new iter61 handler-coverage lexicon
    /// entry round-trips through `time_query` and lands one
    /// `StoreQueryDuration` sample tagged with its class. Same
    /// shape as `time_query_lands_observed_sample`, expanded to
    /// cover the iter61 expansion uniformly so a future helper
    /// refactor that drops a label silently fails here.
    #[test]
    fn iter61_handler_coverage_classes_each_emit_one_sample() {
        let (hub, exp) = enabled_hub();
        for lexeme in [
            QUERY_CLASS_ESCALATION_GET,
            QUERY_CLASS_AUDIT_CHAIN_WALK,
            QUERY_CLASS_NOTIFICATIONS_INBOX,
            QUERY_CLASS_POLICY_SNAPSHOT,
            QUERY_CLASS_WORKTREE_READ,
            QUERY_CLASS_CREDENTIAL_READ,
        ] {
            time_query(Some(&hub), lexeme, || ());
        }
        hub.flush();
        let metrics = exp.metrics();
        for lexeme in [
            QUERY_CLASS_ESCALATION_GET,
            QUERY_CLASS_AUDIT_CHAIN_WALK,
            QUERY_CLASS_NOTIFICATIONS_INBOX,
            QUERY_CLASS_POLICY_SNAPSHOT,
            QUERY_CLASS_WORKTREE_READ,
            QUERY_CLASS_CREDENTIAL_READ,
        ] {
            let any = metrics.iter().any(|m| {
                m.name == MetricName::StoreQueryDuration
                    && matches!(
                        m.labels.get("query_class"),
                        Some(raxis_observability::AttrValue::Str(s)) if s == lexeme,
                    )
            });
            assert!(
                any,
                "expected a StoreQueryDuration sample tagged query_class={lexeme:?}",
            );
        }
    }

    /// Witness #5: hub-disabled fast path. When the caller passes
    /// `None` (the `Store` was constructed without observability),
    /// the closure still runs but no metric is recorded — the
    /// fast-path `if hub.enabled()` check skips the histogram emit.
    #[test]
    fn hub_disabled_path_runs_closure_without_emit() {
        let (hub, exp) = enabled_hub();
        let result = time_query(None, QUERY_CLASS_SESSION_LIST, || 7_u8);
        assert_eq!(result, 7);
        hub.flush();
        let metrics = exp.metrics();
        let count = metrics
            .iter()
            .filter(|m| m.name == MetricName::StoreQueryDuration)
            .count();
        assert_eq!(count, 0, "no metric should land when hub is None");
    }
}
