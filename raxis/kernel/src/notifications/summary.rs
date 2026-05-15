// raxis-kernel::notifications::summary — per-event-kind human formatter.
//
// Normative reference: cli-readonly.md §5.6.4 — the Shell channel
// writes one JSON line per event, including a `human_summary` field
// that is the same string `raxis log` would render for that event.
//
// The formatter takes an `AuditEvent` and returns a single-line
// human-readable string describing it. Empty / unknown event kinds
// fall back to a generic "<EventKind> (no summary)" string so the
// notification record still has a sensible `human_summary`.
//
// We deliberately format from the JSON payload (`AuditEvent.payload`)
// rather than re-deserialising into `AuditEventKind` to keep the
// summary layer decoupled from the audit-event enum (an audit kind
// added to `raxis-audit-tools` without a summary update produces a
// generic line, never a panic).

use raxis_audit_tools::AuditEvent;
use serde_json::Value;

/// Render a single-line human summary for `event`. Always succeeds —
/// unknown event kinds get a generic fallback string. Single-line
/// guarantee: the returned string contains no `'\n'` characters
/// (callers embed it in a JSONL record).
pub fn render(event: &AuditEvent) -> String {
    let kind = event.event_kind.as_str();
    let p = &event.payload;
    let s = match kind {
        "EscalationSubmitted" => format!(
            "Escalation {esc_id} submitted from task {task_id} ({class}, lineage {lineage_id})",
            esc_id = json_str(p, "escalation_id"),
            task_id = json_str(p, "task_id"),
            class = json_str(p, "class"),
            lineage_id = json_str(p, "lineage_id"),
        ),
        "EscalationApproved" => format!(
            "Escalation {esc_id} APPROVED by {approver}",
            esc_id = json_str(p, "escalation_id"),
            approver = operator_label(p, "approved_by", "approved_by_display_name"),
        ),
        "EscalationDenied" => {
            let reason = p.get("reason").and_then(Value::as_str);
            let denier = operator_label(p, "denied_by", "denied_by_display_name");
            match reason {
                Some(r) if !r.is_empty() => format!(
                    "Escalation {esc_id} DENIED by {denier}: {r}",
                    esc_id = json_str(p, "escalation_id"),
                ),
                _ => format!(
                    "Escalation {esc_id} DENIED by {denier}",
                    esc_id = json_str(p, "escalation_id"),
                ),
            }
        }
        "EscalationTimedOut" => format!(
            "Escalation {esc_id} TIMED OUT (no operator decision in window)",
            esc_id = json_str(p, "escalation_id"),
        ),
        "EscalationRateLimitExceeded" => format!(
            "Lineage {lineage_id} hit escalation rate limit (count={count})",
            lineage_id = json_str(p, "lineage_id"),
            count = json_num(p, "attempted_count"),
        ),
        "LineageQuarantined" => format!(
            "Lineage {lineage_id} QUARANTINED after {trigger_count} rate-limit triggers",
            lineage_id = json_str(p, "lineage_id"),
            trigger_count = json_num(p, "trigger_count"),
        ),
        "PolicyEpochAdvanced" => format!(
            "Policy advanced to epoch {epoch} by {by} \
             ({stale} delegations marked stale, {sess} sessions invalidated)",
            epoch = json_num(p, "new_epoch_id"),
            by = operator_label(p, "triggered_by", "triggered_by_display_name"),
            stale = json_num(p, "delegations_marked_stale"),
            sess = json_num(p, "sessions_invalidated"),
        ),
        "PolicyAdvanceRejected" => format!(
            "Policy advance REJECTED: {reason}",
            reason = json_str(p, "reason"),
        ),
        "PolicyAdvanceFailed" => format!(
            "Policy advance FAILED at epoch {epoch}: {reason}",
            epoch = json_num(p, "new_epoch_id"),
            reason = json_str(p, "reason"),
        ),
        "PathScopeOverrideApplied" => format!(
            "Initiative {init_id} task {task_id}: PATH SCOPE OVERRIDE applied by {approver}",
            init_id = json_str(p, "initiative_id"),
            task_id = json_str(p, "task_id"),
            approver = operator_label(p, "approving_operator", "approving_operator_display_name"),
        ),
        "TaskStateChanged" => format!(
            "Task {task_id}: {from} → {to} (actor {actor})",
            task_id = json_str(p, "task_id"),
            from = json_str(p, "from_state"),
            to = json_str(p, "to_state"),
            actor = json_str(p, "actor"),
        ),
        "InitiativeStateChanged" => format!(
            "Initiative {init_id}: {from} → {to}",
            init_id = json_str(p, "initiative_id"),
            from = json_str(p, "from_state"),
            to = json_str(p, "to_state"),
        ),
        "GatewayCrashed" => format!(
            "Gateway crashed (attempt #{attempt}, exit_code={exit})",
            attempt = json_num(p, "attempt"),
            exit = p
                .get("exit_code")
                .and_then(Value::as_i64)
                .map(|i| i.to_string())
                .unwrap_or_else(|| "n/a".to_owned()),
        ),
        "GatewayQuarantined" => format!(
            "Gateway QUARANTINED after {n} attempts: {reason}",
            n = json_num(p, "total_attempts"),
            reason = json_str(p, "reason"),
        ),
        // Catch-all: emit a stable identifier so the operator can see
        // *something* meaningful in `raxis inbox` even before this
        // formatter knows the variant.
        _ => format!("{kind} (no summary)"),
    };
    sanitize_single_line(&s)
}

fn json_str(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| "<?>".to_owned())
}

/// Render an operator-bearing payload field as `"Display (fp_prefix)"`
/// when both the fingerprint and the embedded display-name snapshot
/// are present, falling back to just the fingerprint (full or
/// `<?>`) when the snapshot is missing or empty. See `kernel-store.md`
/// §2.5.2 "Operator display-name fields" for the cross-variant
/// convention; this is the inbox-summary equivalent of the CLI's
/// `operator_display::format_operator_with_lookup` helper. We do
/// NOT do a live cert-table lookup here because the summary runs
/// at audit-emit time when the kernel already knows the live
/// state — if the fingerprint resolved, the embedded name is set;
/// if it didn't, neither will be.
///
/// `fp_field` is the canonical fingerprint key (e.g.
/// `"approved_by"`); `name_field` is the snapshot key (e.g.
/// `"approved_by_display_name"`).
fn operator_label(v: &Value, fp_field: &str, name_field: &str) -> String {
    let fp = v.get(fp_field).and_then(Value::as_str);
    let name = v
        .get(name_field)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());
    match (fp, name) {
        (Some(fp), Some(name)) => {
            // 8 hex chars = 4 bytes of entropy is plenty to disambiguate
            // operators in any realistic deployment; matches the CLI's
            // `FINGERPRINT_DISPLAY_PREFIX_LEN` so the summary reads
            // identically to `raxis log`.
            let prefix_len = 8.min(fp.len());
            format!("{name} ({})", &fp[..prefix_len])
        }
        (Some(fp), None) => fp.to_owned(),
        (None, _) => "<?>".to_owned(),
    }
}

fn json_num(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(|x| {
            x.as_u64()
                .map(|n| n.to_string())
                .or_else(|| x.as_i64().map(|n| n.to_string()))
        })
        .unwrap_or_else(|| "<?>".to_owned())
}

/// Replace any newline / carriage return with a single space so the
/// rendered string is safe to embed in a JSONL record. Also collapses
/// runs of whitespace (defensive against operator-supplied strings
/// like `EscalationDenied.reason`).
fn sanitize_single_line(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_was_space = false;
    for ch in s.chars() {
        let c = if matches!(ch, '\n' | '\r' | '\t') {
            ' '
        } else {
            ch
        };
        if c == ' ' {
            if !last_was_space {
                out.push(' ');
            }
            last_was_space = true;
        } else {
            out.push(c);
            last_was_space = false;
        }
    }
    out.trim().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use raxis_audit_tools::AuditEvent;
    use uuid::Uuid;

    fn make_event(kind: &str, payload: Value) -> AuditEvent {
        AuditEvent {
            seq: 1,
            event_id: Uuid::nil(),
            event_kind: kind.to_owned(),
            session_id: None,
            task_id: None,
            initiative_id: None,
            payload,
            emitted_at: 0,
            prev_sha256: "0".repeat(64),
        }
    }

    #[test]
    fn escalation_submitted_renders_compact_summary() {
        let e = make_event(
            "EscalationSubmitted",
            serde_json::json!({
                "escalation_id": "esc-1",
                "task_id":       "task-A",
                "class":         "CapabilityUpgrade",
                "lineage_id":    "lin-1",
            }),
        );
        let s = render(&e);
        assert!(s.contains("esc-1"));
        assert!(s.contains("task-A"));
        assert!(s.contains("CapabilityUpgrade"));
        assert!(s.contains("lin-1"));
        assert!(!s.contains('\n'), "must be single-line");
    }

    #[test]
    fn escalation_approved_includes_approver() {
        // Legacy event (no embedded display name): the formatter
        // falls back to the bare fingerprint so the summary still
        // identifies the actor.
        let e = make_event(
            "EscalationApproved",
            serde_json::json!({
                "escalation_id": "esc-2",
                "approved_by":   "op-prime",
            }),
        );
        let s = render(&e);
        assert!(s.contains("APPROVED"));
        assert!(s.contains("op-prime"));
    }

    /// §2.5.2 "Operator display-name fields" — when the embedded
    /// snapshot is present, the inbox summary MUST surface the
    /// human-readable name with the fingerprint prefix in
    /// parentheses, not just the bare fingerprint.
    #[test]
    fn escalation_approved_uses_embedded_display_name_when_present() {
        let e = make_event(
            "EscalationApproved",
            serde_json::json!({
                "escalation_id":            "esc-2",
                "approved_by":              "abcd1234abcd1234abcd1234abcd1234",
                "approved_by_display_name": "Chika",
            }),
        );
        let s = render(&e);
        assert!(
            s.contains("APPROVED by Chika (abcd1234)"),
            "summary must read 'Chika (abcd1234)' when display-name snapshot is present; got: {s}"
        );
        assert!(!s.contains("abcd1234abcd1234abcd1234abcd1234"),
            "the full fingerprint MUST NOT appear in the human summary when the prefix form is available; got: {s}");
    }

    #[test]
    fn escalation_denied_with_reason_includes_reason() {
        let e = make_event(
            "EscalationDenied",
            serde_json::json!({
                "escalation_id":           "esc-3",
                "denied_by":               "abcd1234abcd1234abcd1234abcd1234",
                "denied_by_display_name":  "Chika",
                "reason":                  "scope too broad",
            }),
        );
        let s = render(&e);
        assert!(s.contains("DENIED"));
        assert!(s.contains("Chika (abcd1234)"));
        assert!(s.contains("scope too broad"));
    }

    #[test]
    fn escalation_denied_without_reason_omits_colon_clause() {
        let e = make_event(
            "EscalationDenied",
            serde_json::json!({
                "escalation_id":           "esc-4",
                "denied_by":               "abcd1234abcd1234abcd1234abcd1234",
                "denied_by_display_name":  "Chika",
                "reason":                  Value::Null,
            }),
        );
        let s = render(&e);
        assert!(s.contains("DENIED by Chika (abcd1234)"));
        assert!(!s.contains(": "), "no reason ⇒ no colon clause; got: {s}");
    }

    #[test]
    fn unknown_event_kind_falls_back_to_generic_summary() {
        let e = make_event("SomeFutureEventKind", serde_json::json!({}));
        let s = render(&e);
        assert_eq!(s, "SomeFutureEventKind (no summary)");
    }

    #[test]
    fn newlines_in_operator_supplied_reason_are_sanitised() {
        // Defence: operator-controlled `EscalationDenied.reason` could
        // try to inject a newline that breaks JSONL framing. The
        // formatter MUST collapse it to a single space.
        let e = make_event(
            "EscalationDenied",
            serde_json::json!({
                "escalation_id":           "esc-5",
                "denied_by":               "op",
                "reason":                  "line1\nline2\rline3\tline4",
            }),
        );
        let s = render(&e);
        assert!(!s.contains('\n'));
        assert!(!s.contains('\r'));
        assert!(!s.contains('\t'));
        assert!(
            s.contains("line1 line2 line3 line4"),
            "newlines/tabs ⇒ single spaces; got: {s}"
        );
    }

    #[test]
    fn missing_payload_fields_use_question_mark_placeholder() {
        // Forensic-friendly: a malformed payload still produces a
        // line-shaped summary so the inbox stays scannable.
        let e = make_event("EscalationApproved", serde_json::json!({}));
        let s = render(&e);
        assert!(s.contains("APPROVED"));
        assert!(s.contains("<?>"));
    }
}
