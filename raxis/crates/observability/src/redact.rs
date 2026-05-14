//! Redaction layer — closed allow-list / explicit denylist enforcement
//! for span and metric attributes.
//!
//! Spec: `v3/otel-observability.md §10`. Companion CI lint at
//! `xtask::otel_attribute_check`.
//!
//! ## Why a closed allow-list and not a regex blocklist
//!
//! Regex-style "block keys named like `*token*` or `*key*`" leaves
//! unknown unknowns: a developer adding `prompt_seed` is not blocked,
//! a developer adding `bearer_assertion` is not blocked, etc. A
//! closed allow-list reverses the burden of proof: the only way an
//! attribute key ever leaves the kernel is if it is in this file,
//! and the only way it lands in this file is via a security review
//! of the PR that adds it.
//!
//! ## Runtime behaviour
//!
//! Any attribute outside the allow-list (or in the denylist) causes
//! [`Redactor::sanitize`] to drop the **entire** span / metric —
//! never a partial frame. The hub increments
//! [`crate::hub::DropReason::RedactionFailure`] so the operator's
//! dashboard surfaces the bug via `raxis.observability.dropped.total`.

use std::collections::BTreeMap;

use thiserror::Error;

use crate::types::{AttrMap, AttrValue, MetricData, SpanData};

// ---------------------------------------------------------------------------
// Allow-list and denylist
// ---------------------------------------------------------------------------

/// Per-attribute schema entry: type and (for strings) max byte length
/// after sanitisation.
#[derive(Debug, Clone, Copy)]
pub struct AttrSchema {
    /// Expected attribute type tag.
    pub ty:        AttrTy,
    /// Maximum byte length after sanitisation (0 for non-string types).
    pub max_bytes: usize,
}

/// Type tags the redactor checks; mirror of [`AttrValue`] discriminants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum AttrTy { Str, I64, F64, Bool }

/// Closed allow-list for span and metric attribute keys.
///
/// Add new keys to this map only after reading
/// `v3/otel-observability.md §10` and the security-review checklist.
/// Adding a non-trivial key (URL, identifier of an external entity,
/// numeric quantity that could be a side-channel) requires an explicit
/// reviewer sign-off in the PR description.
///
/// Implementation: a simple `&'static [(name, schema)]` with linear
/// lookup. The list stays small (~50 keys); a perfect-hash crate is
/// overkill at this size and would add a build dep.
const ALLOW_LIST: &[(&str, AttrSchema)] = &[
    ("intent_kind",       AttrSchema { ty: AttrTy::Str,  max_bytes: 32  }),
    ("task_id",           AttrSchema { ty: AttrTy::Str,  max_bytes: 64  }),
    ("session_id",        AttrSchema { ty: AttrTy::Str,  max_bytes: 64  }),
    ("initiative_id",     AttrSchema { ty: AttrTy::Str,  max_bytes: 64  }),
    ("verdict",           AttrSchema { ty: AttrTy::Str,  max_bytes: 16  }),
    ("verdict_reason",    AttrSchema { ty: AttrTy::Str,  max_bytes: 32  }),
    ("policy_epoch",      AttrSchema { ty: AttrTy::I64,  max_bytes: 0   }),
    ("latency_ms",        AttrSchema { ty: AttrTy::I64,  max_bytes: 0   }),
    ("provider",          AttrSchema { ty: AttrTy::Str,  max_bytes: 32  }),
    ("model",             AttrSchema { ty: AttrTy::Str,  max_bytes: 64  }),
    ("status_code",       AttrSchema { ty: AttrTy::I64,  max_bytes: 0   }),
    ("bytes_in",          AttrSchema { ty: AttrTy::I64,  max_bytes: 0   }),
    ("bytes_out",         AttrSchema { ty: AttrTy::I64,  max_bytes: 0   }),
    ("cached",            AttrSchema { ty: AttrTy::Bool, max_bytes: 0   }),
    ("circuit_state",     AttrSchema { ty: AttrTy::Str,  max_bytes: 16  }),
    ("verifier_name",     AttrSchema { ty: AttrTy::Str,  max_bytes: 64  }),
    ("gate_type",         AttrSchema { ty: AttrTy::Str,  max_bytes: 64  }),
    ("final_status",      AttrSchema { ty: AttrTy::Str,  max_bytes: 16  }),
    ("exit_code",         AttrSchema { ty: AttrTy::I64,  max_bytes: 0   }),
    ("proxy_type",        AttrSchema { ty: AttrTy::Str,  max_bytes: 16  }),
    ("proxy_name",        AttrSchema { ty: AttrTy::Str,  max_bytes: 64  }),
    ("method",            AttrSchema { ty: AttrTy::Str,  max_bytes: 8   }),
    // url_prefix is `scheme://host[:port]` only — never path/query.
    // The redactor verifies the absence of `?`, `#`, and trailing
    // path segments before passing the value through.
    ("url_prefix",        AttrSchema { ty: AttrTy::Str,  max_bytes: 128 }),
    ("channel_kind",      AttrSchema { ty: AttrTy::Str,  max_bytes: 16  }),
    ("channel_id",        AttrSchema { ty: AttrTy::Str,  max_bytes: 64  }),
    ("event_kind",        AttrSchema { ty: AttrTy::Str,  max_bytes: 64  }),
    ("delivery_ms",       AttrSchema { ty: AttrTy::I64,  max_bytes: 0   }),
    ("success",           AttrSchema { ty: AttrTy::Bool, max_bytes: 0   }),
    ("command_kind",      AttrSchema { ty: AttrTy::Str,  max_bytes: 32  }),
    ("accepted",          AttrSchema { ty: AttrTy::Bool, max_bytes: 0   }),
    ("escalation_id",     AttrSchema { ty: AttrTy::Str,  max_bytes: 64  }),
    ("from_state",        AttrSchema { ty: AttrTy::Str,  max_bytes: 16  }),
    ("to_state",          AttrSchema { ty: AttrTy::Str,  max_bytes: 16  }),
    ("class",             AttrSchema { ty: AttrTy::Str,  max_bytes: 32  }),
    ("role",              AttrSchema { ty: AttrTy::Str,  max_bytes: 16  }),
    ("image_alias",       AttrSchema { ty: AttrTy::Str,  max_bytes: 64  }),
    ("duration_ms",       AttrSchema { ty: AttrTy::I64,  max_bytes: 0   }),
    ("outcome",           AttrSchema { ty: AttrTy::Str,  max_bytes: 16  }),
    ("from_epoch",        AttrSchema { ty: AttrTy::I64,  max_bytes: 0   }),
    ("to_epoch",          AttrSchema { ty: AttrTy::I64,  max_bytes: 0   }),
    ("reason",            AttrSchema { ty: AttrTy::Str,  max_bytes: 64  }),
    ("seq",               AttrSchema { ty: AttrTy::I64,  max_bytes: 0   }),
    ("latency_ns",        AttrSchema { ty: AttrTy::I64,  max_bytes: 0   }),
    ("lane_id",           AttrSchema { ty: AttrTy::Str,  max_bytes: 32  }),
    ("activation_id",     AttrSchema { ty: AttrTy::Str,  max_bytes: 64  }),
    ("expires_at_unix",   AttrSchema { ty: AttrTy::I64,  max_bytes: 0   }),
    ("activated_by_count", AttrSchema { ty: AttrTy::I64, max_bytes: 0   }),
    ("circuit_open",      AttrSchema { ty: AttrTy::Bool, max_bytes: 0   }),
    ("direction",         AttrSchema { ty: AttrTy::Str,  max_bytes: 8   }),
    ("state",             AttrSchema { ty: AttrTy::Str,  max_bytes: 16  }),
    ("drop_reason",       AttrSchema { ty: AttrTy::Str,  max_bytes: 32  }),
    // ---- V3 perf-telemetry expansion (specs/v3/observability-prometheus.md) ----
    ("backend",           AttrSchema { ty: AttrTy::Str,  max_bytes: 32  }),
    ("image_kind",        AttrSchema { ty: AttrTy::Str,  max_bytes: 32  }),
    ("failure_class",     AttrSchema { ty: AttrTy::Str,  max_bytes: 32  }),
    ("agent_type",        AttrSchema { ty: AttrTy::Str,  max_bytes: 16  }),
    ("tool_name",         AttrSchema { ty: AttrTy::Str,  max_bytes: 64  }),
    ("service",           AttrSchema { ty: AttrTy::Str,  max_bytes: 32  }),
    ("operation",         AttrSchema { ty: AttrTy::Str,  max_bytes: 32  }),
    ("blocked",           AttrSchema { ty: AttrTy::Bool, max_bytes: 0   }),
    ("route",             AttrSchema { ty: AttrTy::Str,  max_bytes: 64  }),
    ("http_method",       AttrSchema { ty: AttrTy::Str,  max_bytes: 8   }),
    ("http_status",       AttrSchema { ty: AttrTy::I64,  max_bytes: 0   }),
    ("revision_round",    AttrSchema { ty: AttrTy::I64,  max_bytes: 0   }),
    ("author_role",       AttrSchema { ty: AttrTy::Str,  max_bytes: 16  }),
    ("attempt",           AttrSchema { ty: AttrTy::I64,  max_bytes: 0   }),
    ("final_outcome",     AttrSchema { ty: AttrTy::Str,  max_bytes: 16  }),
    ("streaming",         AttrSchema { ty: AttrTy::Bool, max_bytes: 0   }),
    ("initiative_class",  AttrSchema { ty: AttrTy::Str,  max_bytes: 32  }),
    ("phase",             AttrSchema { ty: AttrTy::Str,  max_bytes: 32  }),
    // ---- V3 §3 expansion: egress admit/deny/default-grant/stall + cred-proxy substitution
    // (see worker/reviewer-orch-egress-defaults @ 4d8f5dc and
    //  worker/secrets-model-realignment @ 6114f49). The values are
    //  closed lexicons of operational chokepoint / provider-kind labels;
    //  no PII flows through these keys (they describe code-paths, not data).
    ("chokepoint",        AttrSchema { ty: AttrTy::Str,  max_bytes: 32  }),
    ("provider_kind",     AttrSchema { ty: AttrTy::Str,  max_bytes: 32  }),
    // iter44 / `INV-OBS-RESPAWN-KIND-LABEL-01`: disambiguates
    // `IsolationRespawnAttemptedTotal` between vm_crash transient
    // retries, orchestrator no-progress respawns, and reviewer
    // rejection respawns. Closed lexicon — no PII.
    ("respawn_kind",      AttrSchema { ty: AttrTy::Str,  max_bytes: 32  }),
    // iter44: `IntentAdmitPredicateEvaluatedTotal` carries a boolean
    // `admissible` (true → predicate accepted, false → kernel
    // rejected the intent). The matching `reason` label is already
    // covered by the generic `reason` schema above.
    ("admissible",        AttrSchema { ty: AttrTy::Bool, max_bytes: 0   }),
    // iter44 / `INV-OBS-KERNEL-RESPAWN-COVERAGE-01`: the
    // `KernelRespawn{Total,Duration}` family carries a closed
    // `trigger` lexicon
    // { `deadlock`, `sigsegv`, `sigabrt`, `exit_70`, `other` }
    // disambiguating the operator-visible cause of every
    // supervisor-driven kernel respawn. Outcome (`ok` /
    // `refused_ceiling` / `refused_other`) reuses the generic
    // `outcome` schema above. `message_kind` (4b) and `role` (4b)
    // are also closed lexicons whose schemas already exist
    // (`reason`/`role`).
    ("trigger",           AttrSchema { ty: AttrTy::Str,  max_bytes: 16  }),
    // iter44 slice 4b — `KernelSubstrateIpc*` family carries a
    // closed `message_kind` lexicon
    // { `intent_request`, `witness_submission`, `escalation_request`,
    //   `planner_fetch_request`, `planner_exit_notice`, `unexpected` }
    // pinned by
    // `kernel/src/observability.rs::KERNEL_SUBSTRATE_IPC_MESSAGE_KIND_CLOSED_SET`
    // and the exhaustive match arm in `kernel_substrate_ipc_route`
    // per `INV-OBS-IPC-ROUNDTRIP-COVERAGE-01`. The lexeme is the
    // snake_case projection of the dispatched `IpcMessage` request
    // variant; every non-dispatched variant collapses to
    // `unexpected` so the dashboard pivots on a stable set even as
    // new wire variants are added. Paired with `role` (`planner` /
    // `verifier` / `gateway` / `unknown`) on counter + histogram
    // emit sites; gauge sites carry `role` only.
    ("message_kind",      AttrSchema { ty: AttrTy::Str,  max_bytes: 32  }),
];

/// Explicit denylist. Defense-in-depth: even if a key accidentally
/// gets added to the allow-list, it must NOT collide with any of
/// these. The CI lint checks both directions.
const DENY_LIST: &[&str] = &[
    "session_token",
    "api_key",
    "credential_value",
    "password",
    "plan_bytes",
    "policy_sig",
    "operator_key",
    "operator_private_key",
    "prompt_text",
    "response_text",
    "model_input",
    "model_output",
    "diff_bytes",
    "file_content",
    "blob_bytes",
    "url",          // forbidden — only `url_prefix` is allowed
    "secret",
    "token",
    "bearer",
    "auth",
    "authorization",
    "cookie",
];

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Reason a span / metric was rejected by the redactor.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RedactError {
    /// An attribute key was not in the closed allow-list.
    #[error("attribute key not in allow-list: {key}")]
    UnknownAttribute {
        /// The offending key.
        key: String,
    },

    /// An attribute key matched the explicit denylist.
    #[error("attribute key on denylist: {key}")]
    DenyListed {
        /// The offending key.
        key: String,
    },

    /// The attribute value's type did not match the schema.
    #[error("attribute {key} expected type {expected:?} but got {got}")]
    TypeMismatch {
        /// The offending key.
        key:      String,
        /// Expected type tag.
        expected: AttrTy,
        /// Actual variant name.
        got:      String,
    },

    /// A floating-point value was non-finite.
    #[error("attribute {key} is non-finite (NaN or ±Inf)")]
    NonFinite {
        /// The offending key.
        key: String,
    },

    /// A string value contained more than the per-key budget after
    /// sanitisation.
    #[error("attribute {key} exceeds {max_bytes}-byte limit")]
    Oversize {
        /// The offending key.
        key:       String,
        /// The applicable per-key limit.
        max_bytes: usize,
    },

    /// `url_prefix` value contained path / query / fragment fragments.
    #[error("url_prefix must be scheme://host[:port] only; got {value:?}")]
    UrlPrefixNotPrefix {
        /// The offending value.
        value: String,
    },

    /// Histogram / metric structure violated invariants (bucket count
    /// mismatch, non-monotone boundaries, etc.).
    #[error("malformed metric {name}: {reason}")]
    MalformedMetric {
        /// Metric name.
        name: String,
        /// Human-readable failure reason.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// Redactor
// ---------------------------------------------------------------------------

/// Pure redactor; no I/O, no time. Every check is a deterministic
/// function of the input. Constructed once and held by the hub.
#[derive(Debug, Default, Clone, Copy)]
pub struct Redactor;

impl Redactor {
    /// Sanitise a span in-place. Returns the (possibly modified) span
    /// on success, or the first encountered violation.
    pub fn sanitize_span(&self, mut span: SpanData) -> Result<SpanData, RedactError> {
        // Status message size cap. We sanitise as if it were a
        // string attribute with key "__status_message" and a 256-byte
        // budget; any non-ASCII / control char becomes `?`.
        if let Some(msg) = span.status_message.as_mut() {
            sanitise_string_in_place(msg, 256);
        }
        // Attribute map.
        sanitise_attr_map(&mut span.attrs)?;
        // Within-span events.
        for ev in &mut span.events {
            sanitise_attr_map(&mut ev.attrs)?;
        }
        Ok(span)
    }

    /// Sanitise a metric in-place. The labels are checked against the
    /// same allow-list as span attributes; the data point is
    /// shape-checked against `MetricType` and `DataPoint`.
    pub fn sanitize_metric(&self, mut metric: MetricData) -> Result<MetricData, RedactError> {
        sanitise_attr_map(&mut metric.labels)?;
        check_datapoint(&metric)?;
        Ok(metric)
    }

    /// Best-effort name/key check. Used by tests and lint surfaces;
    /// the runtime checker is `sanitize_span` / `sanitize_metric`.
    pub fn is_known_key(&self, key: &str) -> bool {
        ALLOW_LIST.iter().any(|(k, _)| *k == key)
    }

    /// True iff the key is on the explicit denylist.
    pub fn is_deny_listed(&self, key: &str) -> bool {
        DENY_LIST.iter().any(|k| *k == key)
    }
}

/// In-place sanitisation of a string. Caps at `max_bytes` (counting
/// raw bytes, not chars; we truncate at a char boundary to keep the
/// result valid UTF-8). Replaces control chars / NUL with `?`.
fn sanitise_string_in_place(s: &mut String, max_bytes: usize) {
    let original = std::mem::take(s);
    // Byte-length truncate at a char boundary.
    let trunc_to = original
        .char_indices()
        .take_while(|(i, _)| *i + original[*i..].chars().next().map(|c| c.len_utf8()).unwrap_or(0) <= max_bytes)
        .last()
        .map(|(i, c)| i + c.len_utf8())
        .unwrap_or(0);
    let truncated = &original[..trunc_to];
    let mut out = String::with_capacity(trunc_to);
    for ch in truncated.chars() {
        if ch == '\0' || (ch.is_control() && ch != '\n' && ch != '\r' && ch != '\t') {
            out.push('?');
        } else if ch == '\n' || ch == '\r' || ch == '\t' {
            // Strip embedded line breaks / tabs from a one-line label.
            out.push(' ');
        } else {
            out.push(ch);
        }
    }
    *s = out;
}

/// Walk an attribute map and check every (key, value) pair against
/// the allow-list and per-key schema. On the first violation, return
/// `Err`; the entire span/metric is dropped at the call site.
fn sanitise_attr_map(map: &mut AttrMap) -> Result<(), RedactError> {
    let keys: Vec<String> = map.keys().cloned().collect();
    for key in keys {
        if let Some(schema) = ALLOW_LIST.iter().find(|(k, _)| *k == key.as_str()).map(|(_, s)| *s) {
            // Defense-in-depth: never let a denylist key through even
            // if it (somehow) made it onto the allow-list.
            if DENY_LIST.iter().any(|k| *k == key.as_str()) {
                return Err(RedactError::DenyListed { key });
            }
            let val = map.get_mut(&key).expect("key was present in iteration");
            sanitise_value(&key, val, schema)?;
        } else if DENY_LIST.iter().any(|k| *k == key.as_str()) {
            return Err(RedactError::DenyListed { key });
        } else {
            return Err(RedactError::UnknownAttribute { key });
        }
    }
    Ok(())
}

/// Type-check + size-cap a single attribute value.
fn sanitise_value(key: &str, val: &mut AttrValue, schema: AttrSchema) -> Result<(), RedactError> {
    match (&schema.ty, &*val) {
        (AttrTy::Str, AttrValue::Str(_))   => {}
        (AttrTy::I64, AttrValue::I64(_))   => return Ok(()),
        (AttrTy::F64, AttrValue::F64(f)) => {
            if !f.is_finite() {
                return Err(RedactError::NonFinite { key: key.to_owned() });
            }
            return Ok(());
        }
        (AttrTy::Bool, AttrValue::Bool(_)) => return Ok(()),
        (expected, actual) => {
            return Err(RedactError::TypeMismatch {
                key: key.to_owned(),
                expected: *expected,
                got: variant_name(actual).to_owned(),
            });
        }
    }
    // For Str: sanitise + cap at the per-key budget.
    if let AttrValue::Str(ref mut s) = val {
        sanitise_string_in_place(s, schema.max_bytes);
        if s.len() > schema.max_bytes {
            // Should be impossible after `sanitise_string_in_place`
            // truncated to `max_bytes`, but guard against
            // multibyte-rounding edge cases anyway.
            return Err(RedactError::Oversize {
                key: key.to_owned(),
                max_bytes: schema.max_bytes,
            });
        }
        // url_prefix integrity: forbid path / query / fragment.
        if key == "url_prefix" {
            for ch in ['?', '#', ' '] {
                if s.contains(ch) {
                    return Err(RedactError::UrlPrefixNotPrefix { value: s.clone() });
                }
            }
            // Must end at host[:port] — no trailing path segments.
            // Heuristic: at most two slashes, both right after the scheme.
            let slashes = s.matches('/').count();
            if slashes > 2 {
                return Err(RedactError::UrlPrefixNotPrefix { value: s.clone() });
            }
            if slashes > 0 && !s.contains("://") {
                return Err(RedactError::UrlPrefixNotPrefix { value: s.clone() });
            }
        }
    }
    Ok(())
}

fn variant_name(v: &AttrValue) -> &'static str {
    match v {
        AttrValue::Str(_)  => "Str",
        AttrValue::I64(_)  => "I64",
        AttrValue::F64(_)  => "F64",
        AttrValue::Bool(_) => "Bool",
    }
}

/// Histogram / counter / gauge structural checks.
fn check_datapoint(metric: &MetricData) -> Result<(), RedactError> {
    use crate::types::{DataPoint, MetricType};
    match (&metric.metric_type, &metric.datapoint) {
        (MetricType::Histogram, DataPoint::Histo { buckets, counts, sum, count, min, max }) => {
            if buckets.is_empty() {
                return Err(RedactError::MalformedMetric {
                    name: metric.name.as_otel_name().to_owned(),
                    reason: "histogram buckets must not be empty".to_owned(),
                });
            }
            if counts.len() != buckets.len() + 1 {
                return Err(RedactError::MalformedMetric {
                    name: metric.name.as_otel_name().to_owned(),
                    reason: format!(
                        "histogram counts length {} != buckets length + 1 ({})",
                        counts.len(), buckets.len() + 1,
                    ),
                });
            }
            let mut prev = f64::NEG_INFINITY;
            for &b in buckets {
                if !b.is_finite() || b <= prev {
                    return Err(RedactError::MalformedMetric {
                        name: metric.name.as_otel_name().to_owned(),
                        reason: "histogram boundaries must be finite, positive, strictly increasing".to_owned(),
                    });
                }
                prev = b;
            }
            for v in [*sum, *min, *max] {
                if !v.is_finite() {
                    return Err(RedactError::MalformedMetric {
                        name: metric.name.as_otel_name().to_owned(),
                        reason: "histogram sum/min/max must be finite".to_owned(),
                    });
                }
            }
            // count must equal sum of buckets
            let total: u64 = counts.iter().sum();
            if total != *count {
                return Err(RedactError::MalformedMetric {
                    name: metric.name.as_otel_name().to_owned(),
                    reason: format!("histogram count={} but bucket sum={}", count, total),
                });
            }
            Ok(())
        }
        (MetricType::Counter, DataPoint::Sum { value })
        | (MetricType::Gauge,   DataPoint::Sum { value }) => {
            if !value.is_finite() {
                return Err(RedactError::MalformedMetric {
                    name: metric.name.as_otel_name().to_owned(),
                    reason: "counter/gauge value must be finite".to_owned(),
                });
            }
            Ok(())
        }
        (mt, dp) => Err(RedactError::MalformedMetric {
            name: metric.name.as_otel_name().to_owned(),
            reason: format!(
                "metric_type {mt:?} does not match data_point shape {}",
                std::any::type_name_of_val(dp),
            ),
        }),
    }
}

// Re-exports for the CI lint harness in `xtask`.
#[doc(hidden)]
pub fn allow_list_keys() -> impl Iterator<Item = &'static str> {
    ALLOW_LIST.iter().map(|(k, _)| *k)
}

#[doc(hidden)]
pub fn deny_list_keys() -> impl Iterator<Item = &'static str> {
    DENY_LIST.iter().copied()
}

// ---------------------------------------------------------------------------
// Helper: build a sorted attr map from key/value pairs.
// ---------------------------------------------------------------------------

/// Convenience builder used by emit sites; type-hints `AttrValue::From`
/// at every call without requiring an explicit `.into()`.
pub fn attrs<const N: usize, V: Into<AttrValue>>(pairs: [(&str, V); N]) -> AttrMap {
    let mut m = BTreeMap::new();
    for (k, v) in pairs {
        m.insert(k.to_owned(), v.into());
    }
    m
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        AttrValue, DataPoint, MetricData, MetricName, MetricType, SpanData, SpanKind,
        SpanName, SpanStatus, Unit,
    };

    fn span_with_attrs(attrs: AttrMap) -> SpanData {
        SpanData {
            trace_id:         [1; 16],
            span_id:          [2; 8],
            parent_span_id:   None,
            name:             SpanName::IntentAdmission,
            kind:             SpanKind::Internal,
            start_unix_nanos: 0,
            end_unix_nanos:   1_000_000,
            status:           SpanStatus::Ok,
            status_message:   None,
            attrs,
            events:           vec![],
        }
    }

    #[test]
    fn redactor_accepts_known_attributes() {
        let r = Redactor;
        let attrs = attrs([
            ("intent_kind", AttrValue::Str("CompleteTask".into())),
            ("verdict",     AttrValue::Str("Accepted".into())),
            ("latency_ms",  AttrValue::I64(42)),
            ("cached",      AttrValue::Bool(true)),
        ]);
        r.sanitize_span(span_with_attrs(attrs)).expect("known attributes pass");
    }

    #[test]
    fn redactor_rejects_unknown_key() {
        let r = Redactor;
        let attrs = attrs([("prompt_text", AttrValue::Str("hello".into()))]);
        let err = r.sanitize_span(span_with_attrs(attrs)).unwrap_err();
        // Note: `prompt_text` is on the deny list AND not on the allow
        // list; the deny check fires first inside `sanitise_attr_map`.
        assert!(matches!(err, RedactError::DenyListed { .. } | RedactError::UnknownAttribute { .. }));
    }

    #[test]
    fn redactor_rejects_denylisted_key() {
        let r = Redactor;
        for bad in ["session_token", "api_key", "url", "password", "secret", "bearer", "authorization"] {
            let attrs = attrs([(bad, AttrValue::Str("x".into()))]);
            let err = r.sanitize_span(span_with_attrs(attrs)).unwrap_err();
            assert!(matches!(err, RedactError::DenyListed { .. } | RedactError::UnknownAttribute { .. }),
                "key {bad}: {err:?}");
        }
    }

    #[test]
    fn redactor_rejects_type_mismatch() {
        let r = Redactor;
        let attrs = attrs([("latency_ms", AttrValue::Str("not-a-number".into()))]);
        let err = r.sanitize_span(span_with_attrs(attrs)).unwrap_err();
        assert!(matches!(err, RedactError::TypeMismatch { .. }));
    }

    #[test]
    fn redactor_truncates_oversize_string() {
        let r = Redactor;
        let mut s = String::new();
        // verdict has max_bytes=16; build a 100-byte string.
        for _ in 0..100 { s.push('a'); }
        let attrs = attrs([("verdict", AttrValue::Str(s))]);
        let span = r.sanitize_span(span_with_attrs(attrs)).expect("truncates, not rejects");
        if let AttrValue::Str(out) = span.attrs.get("verdict").unwrap() {
            assert!(out.len() <= 16, "got len {}", out.len());
        } else {
            panic!("verdict should still be a string");
        }
    }

    #[test]
    fn redactor_replaces_control_chars() {
        let r = Redactor;
        let attrs = attrs([("verdict", AttrValue::Str("a\0b\nc".into()))]);
        let span = r.sanitize_span(span_with_attrs(attrs)).expect("ok");
        if let AttrValue::Str(out) = span.attrs.get("verdict").unwrap() {
            assert_eq!(out, "a?b c", "NUL → ?, newline → space");
        }
    }

    #[test]
    fn redactor_rejects_url_prefix_with_path() {
        let r = Redactor;
        let attrs = attrs([("url_prefix", AttrValue::Str("https://api.example.com/v1/foo".into()))]);
        let err = r.sanitize_span(span_with_attrs(attrs)).unwrap_err();
        assert!(matches!(err, RedactError::UrlPrefixNotPrefix { .. }));
    }

    #[test]
    fn redactor_rejects_url_prefix_with_query() {
        let r = Redactor;
        let attrs = attrs([("url_prefix", AttrValue::Str("https://api.example.com?key=v".into()))]);
        let err = r.sanitize_span(span_with_attrs(attrs)).unwrap_err();
        assert!(matches!(err, RedactError::UrlPrefixNotPrefix { .. }));
    }

    #[test]
    fn redactor_accepts_url_prefix_host_port() {
        let r = Redactor;
        let attrs = attrs([("url_prefix", AttrValue::Str("https://api.example.com:443".into()))]);
        r.sanitize_span(span_with_attrs(attrs)).expect("scheme://host:port is allowed");
    }

    #[test]
    fn redactor_rejects_non_finite_float() {
        // We don't have an F64-typed allow-list key right now, but exercise the path
        // synthetically by routing through `sanitise_value`.
        let mut v = AttrValue::F64(f64::NAN);
        let schema = AttrSchema { ty: AttrTy::F64, max_bytes: 0 };
        let err = sanitise_value("synthetic", &mut v, schema).unwrap_err();
        assert!(matches!(err, RedactError::NonFinite { .. }));
    }

    #[test]
    fn redactor_validates_histogram_shape() {
        let r = Redactor;
        let m = MetricData {
            name:        MetricName::IntentAdmissionDuration,
            metric_type: MetricType::Histogram,
            unit:        Unit::Milliseconds,
            labels:      AttrMap::new(),
            datapoint:   DataPoint::Histo {
                buckets: vec![1.0, 5.0, 10.0],
                counts:  vec![0, 1, 0, 0],
                sum:     3.5,
                count:   1,
                min:     3.5,
                max:     3.5,
            },
            unix_nanos:  0,
        };
        r.sanitize_metric(m).expect("well-formed histogram");
    }

    #[test]
    fn redactor_rejects_histogram_count_mismatch() {
        let r = Redactor;
        let m = MetricData {
            name:        MetricName::IntentAdmissionDuration,
            metric_type: MetricType::Histogram,
            unit:        Unit::Milliseconds,
            labels:      AttrMap::new(),
            datapoint:   DataPoint::Histo {
                buckets: vec![1.0, 5.0, 10.0],
                counts:  vec![0, 1, 0, 0],   // sums to 1
                sum:     3.5,
                count:   2,                  // declares 2 — mismatch
                min:     3.5,
                max:     3.5,
            },
            unix_nanos:  0,
        };
        let err = r.sanitize_metric(m).unwrap_err();
        assert!(matches!(err, RedactError::MalformedMetric { .. }));
    }

    #[test]
    fn redactor_rejects_histogram_non_monotone_buckets() {
        let r = Redactor;
        let m = MetricData {
            name:        MetricName::IntentAdmissionDuration,
            metric_type: MetricType::Histogram,
            unit:        Unit::Milliseconds,
            labels:      AttrMap::new(),
            datapoint:   DataPoint::Histo {
                buckets: vec![5.0, 3.0, 10.0],   // not monotone
                counts:  vec![0, 0, 0, 0],
                sum:     0.0,
                count:   0,
                min:     0.0,
                max:     0.0,
            },
            unix_nanos:  0,
        };
        let err = r.sanitize_metric(m).unwrap_err();
        assert!(matches!(err, RedactError::MalformedMetric { .. }));
    }

    #[test]
    fn allow_list_does_not_collide_with_denylist() {
        let allow_set: std::collections::HashSet<&str> = allow_list_keys().collect();
        for d in deny_list_keys() {
            assert!(!allow_set.contains(d), "denylist key {d:?} also on allow list");
        }
    }
}
