// Best-effort extraction of a `FailureInfo` reason from an
// audit-event payload (the same shape we receive on the
// Notifications, AuditChain, Escalations + per-session SSE
// surfaces).
//
// Why this lives on the FE
//
//   The kernel audit chain already carries every detail an
//   operator needs to diagnose a failure (`exit_code`, `reason`,
//   `failure_class`, `target_host`, `block_count_in_window`, …),
//   but the dashboard hasn't yet wired a kernel-side projection
//   that walks the chain and attaches a structured `failure`
//   reference to each entity view. Until that V3 step lands, the
//   FE pulls the same data out of the audit-bridge payload on the
//   surfaces that DO receive payloads (Notifications, Audit,
//   Escalations) so the operator gets the reason inline rather
//   than a bare red badge.
//
//   Source of truth for the field names is
//   `crates/audit/src/event.rs` (`AuditEventKind`). The mapping
//   below covers every `*Failed` / `*Rejected` / `*Denied` /
//   `*StallDetected` / `*Aborted` / `*Crashed` / `*Quarantined` /
//   `*Disagreement` variant the kernel emits today.
//
// Anchors `INV-DASHBOARD-FAILURE-VISIBILITY-01`.

import type { FailureField, FailureInfo } from "@/types/api";

interface AuditMeta {
  /// Audit-chain sequence (kernel-side row id) when known.
  seq?: number | null;
  /// Audit-chain event_id (b64) when known.
  eventId?: string | null;
  /// Unix-seconds observation timestamp (`at` on the audit row,
  /// `created_at` on the notification, …). 0 when unknown.
  observedAt?: number;
}

/// Returns a `FailureInfo` synthesised from the audit payload, or
/// `null` when the event kind is not a failure-bearing one. The
/// caller is expected to render `<FailureReasonPanel reason={…}>` /
/// `<FailurePill failed reason={…}>`.
///
/// Best-effort: when the payload is missing the conventional
/// fields the helper still returns a `FailureInfo` whose `kind` =
/// `eventKind` so the panel renders the badge + (often empty)
/// `message`. That triggers the panel's "(no message)" /
/// "No reason supplied — kernel bug" affordances so the gap is
/// operator-visible instead of swallowed.
export function failureFromAuditEvent(
  eventKind: string,
  payload: unknown,
  meta: AuditMeta = {},
): FailureInfo | null {
  const obj = isObject(payload) ? payload : {};
  if (!isFailureAuditKindWithPayload(eventKind, obj)) {
    return null;
  }
  // Per-kind field whitelists (kept in sync with `crates/audit/
  // src/event.rs`). For any kind not enumerated below we fall
  // back to a generic field extraction that grabs the most-common
  // payload keys.
  const fields: FailureField[] = [];
  let message = "";
  switch (eventKind) {
    case "SessionVmFailedFinal": {
      message =
        str(obj, "final_reason") ?? str(obj, "reason") ?? "VM scaling exhausted";
      pushField(fields, "failure_class", str(obj, "failure_class"));
      pushField(fields, "total_attempts", numStr(obj, "total_attempts"));
      pushField(fields, "session_id", str(obj, "session_id"));
      pushField(fields, "task_id", str(obj, "task_id"));
      pushField(fields, "last_attempt_backend", str(obj, "last_attempt_backend"));
      break;
    }
    case "SessionVmExited": {
      message =
        str(obj, "backend_error") ??
        str(obj, "reason") ??
        "Session VM exited";
      pushField(fields, "signal_class", str(obj, "signal_class"));
      pushField(fields, "exit_code", numStr(obj, "exit_code"));
      pushField(fields, "session_id", str(obj, "session_id"));
      pushField(fields, "backend_id", str(obj, "backend_id"));
      break;
    }
    case "TaskBlockedForRecovery": {
      message =
        str(obj, "block_reason") ??
        str(obj, "reason") ??
        "Task blocked pending recovery";
      pushField(fields, "task_id", str(obj, "task_id"));
      pushField(fields, "initiative_id", str(obj, "initiative_id"));
      break;
    }
    case "InitiativeAborted": {
      message =
        str(obj, "reason") ?? "Initiative aborted by operator/kernel";
      pushField(fields, "initiative_id", str(obj, "initiative_id"));
      pushField(fields, "aborted_by", str(obj, "aborted_by"));
      break;
    }
    case "WitnessRejected":
    case "ReviewerRejected":
    case "EscalationDenied":
    case "PolicyAdvanceRejected":
    case "PolicyAdvanceFailed":
    case "ReplayRejected":
    case "GatewayQuarantined":
    case "NotificationDeliveryFailed": {
      // `INV-FAILURE-REASON-CONCRETE-01` — leave `message`
      // empty when neither `reason` nor `detail` is populated.
      // The panel's `(no message)` / `⚠ KERNEL BUG` empty-
      // state then fires, surfacing the gap as a kernel bug
      // instead of hiding it behind a hedged fallback
      // placeholder. The forbidden-phrase regex in the
      // kernel sweep test treats the hedged fallback as a
      // concrete-reason violation.
      message = str(obj, "reason") ?? str(obj, "detail") ?? "";
      pushField(fields, "reviewer_session_id", str(obj, "reviewer_session_id"));
      pushField(fields, "verdict", str(obj, "verdict"));
      pushField(fields, "initiative_id", str(obj, "initiative_id"));
      pushField(fields, "task_id", str(obj, "task_id"));
      pushField(fields, "session_id", str(obj, "session_id"));
      pushField(fields, "escalation_id", str(obj, "escalation_id"));
      pushField(fields, "notification_id", str(obj, "notification_id"));
      pushField(fields, "channel", str(obj, "channel"));
      break;
    }
    case "TransparentProxyDenied":
    case "SessionEgressDenied": {
      message = str(obj, "reason") ?? "Egress denied at chokepoint";
      pushField(fields, "host_or_sni", str(obj, "host_or_sni"));
      pushField(fields, "original_dst_ip", str(obj, "original_dst_ip"));
      pushField(fields, "original_dst_port", numStr(obj, "original_dst_port"));
      pushField(fields, "protocol", str(obj, "protocol"));
      pushField(fields, "chokepoint", str(obj, "chokepoint"));
      pushField(fields, "session_id", str(obj, "session_id"));
      pushField(fields, "policy_provider", str(obj, "policy_provider"));
      break;
    }
    case "SessionEgressStallDetected": {
      message =
        str(obj, "reason") ?? "Repeated egress denials tripped the stall threshold";
      pushField(fields, "source", str(obj, "source"));
      pushField(fields, "block_count_in_window", numStr(obj, "block_count_in_window"));
      pushField(fields, "window_seconds", numStr(obj, "window_seconds"));
      pushField(fields, "session_id", str(obj, "session_id"));
      pushField(fields, "host_or_sni", str(obj, "host_or_sni"));
      pushField(fields, "port", numStr(obj, "port"));
      break;
    }
    case "CredentialProxyUpstreamFailed":
    case "CredentialProxyConnectionFailed": {
      message = str(obj, "reason") ?? str(obj, "detail") ?? "Upstream service failure";
      pushField(fields, "detail", str(obj, "detail"));
      pushField(fields, "proxy_type", str(obj, "proxy_type"));
      pushField(fields, "credential_name", str(obj, "credential_name"));
      pushField(fields, "upstream_host", str(obj, "upstream_host"));
      pushField(fields, "upstream_port", numStr(obj, "upstream_port"));
      break;
    }
    case "PushFailed":
    case "MergeFastForwardFailed": {
      message = str(obj, "reason") ?? str(obj, "category") ?? "Git operation failed";
      pushField(fields, "category", str(obj, "category"));
      pushField(fields, "remote", str(obj, "remote"));
      pushField(fields, "branch", str(obj, "branch"));
      pushField(fields, "initiative_id", str(obj, "initiative_id"));
      break;
    }
    case "VerifierProcessFailed": {
      message = str(obj, "reason") ?? "Verifier process failed";
      pushField(fields, "exit_code", numStr(obj, "exit_code"));
      pushField(fields, "stage", str(obj, "stage"));
      break;
    }
    case "GatewayCrashed":
    case "GatewaySignalFailed": {
      message = str(obj, "reason") ?? "Gateway crashed";
      pushField(fields, "exit_code", numStr(obj, "exit_code"));
      pushField(fields, "signal", str(obj, "signal"));
      pushField(fields, "gateway_id", str(obj, "gateway_id"));
      break;
    }
    case "WorktreeProvisionFailed": {
      message = str(obj, "reason") ?? str(obj, "detail") ?? "Worktree provisioning failed";
      pushField(fields, "task_id", str(obj, "task_id"));
      pushField(fields, "session_id", str(obj, "session_id"));
      pushField(fields, "worktree_path", str(obj, "worktree_path"));
      pushField(fields, "exit_code", numStr(obj, "exit_code"));
      break;
    }
    case "ReviewerDisagreement": {
      message =
        str(obj, "summary") ??
        "Reviewers returned conflicting verdicts";
      pushField(fields, "task_id", str(obj, "task_id"));
      pushField(fields, "initiative_id", str(obj, "initiative_id"));
      pushField(fields, "n_reviewers", numStr(obj, "n_reviewers"));
      break;
    }
    case "OperatorApprovalDenied": {
      message =
        str(obj, "reason") ?? "Operator denied approval";
      pushField(fields, "operator_id", str(obj, "operator_id"));
      pushField(fields, "initiative_id", str(obj, "initiative_id"));
      pushField(fields, "approval_id", str(obj, "approval_id"));
      break;
    }
    case "IntentRejected": {
      message = str(obj, "error_message") ?? str(obj, "error_code") ?? "Intent rejected";
      pushField(fields, "error_code", str(obj, "error_code"));
      pushField(fields, "task_id", str(obj, "task_id"));
      pushField(fields, "session_id", str(obj, "session_id"));
      break;
    }
    default: {
      // Operator-action outcomes (`Operator*`) and any other
      // failure-shaped kind: pluck the common keys.
      const outcome = str(obj, "outcome");
      if (outcome && outcome !== "Accepted") {
        message =
          str(obj, "reason") ??
          str(obj, "error_message") ??
          `Operator action ${outcome}`;
        pushField(fields, "outcome", outcome);
        pushField(fields, "operator_id", str(obj, "operator_id"));
        pushField(fields, "action", str(obj, "action"));
      } else {
        message =
          str(obj, "reason") ??
          str(obj, "message") ??
          str(obj, "error_message") ??
          str(obj, "detail") ??
          "";
      }
      pushField(fields, "initiative_id", str(obj, "initiative_id"));
      pushField(fields, "task_id", str(obj, "task_id"));
      pushField(fields, "session_id", str(obj, "session_id"));
      break;
    }
  }

  return {
    kind: eventKind,
    message,
    fields: fields.length > 0 ? fields : undefined,
    seq: meta.seq ?? null,
    event_id: meta.eventId ?? null,
    observed_at: meta.observedAt ?? 0,
  };
}

/// True when the audit event kind represents a hard failure /
/// rejection that the dashboard MUST surface a reason for.
/// Mirrors the kernel-side classifier in `event.rs`.
///
/// Note: `Operator*` audit events carry a separate `outcome`
/// discriminator (`Accepted` vs.
/// `RejectedValidation` / `RejectedPermission` / `InternalError`).
/// Use `isFailureAuditEvent` for the payload-aware variant when
/// you have both the kind and the payload.
export function isFailureAuditKind(eventKind: string): boolean {
  return FAILURE_KINDS.has(eventKind) || looksLikeFailureKind(eventKind);
}

/// Payload-aware classifier. Returns true when the (kind,
/// payload) pair represents a failure that MUST surface a reason
/// — i.e. either the kind is in the failure set above OR it's an
/// `Operator*` event with `outcome != "Accepted"`. Use this from
/// surfaces that have the payload in hand (Notifications, Audit,
/// per-session SSE).
///
/// `SessionVmExited` and similar dual-mode events are routed
/// through `isPayloadGracefulNonFailure` so a clean
/// `signal_class: "GracefulExit"`, `exit_code: 0` exit never
/// shows up as a "failure event" in the audit feed. The kind-only
/// classifier (`isFailureAuditKind`) is intentionally STRICTER
/// (kind alone is enough), so call sites that have the payload
/// MUST use this function to avoid the false-positive.
export function isFailureAuditEvent(
  eventKind: string,
  payload: unknown,
): boolean {
  const obj = isObject(payload) ? payload : null;
  if (obj && isPayloadGracefulNonFailure(eventKind, obj)) {
    return false;
  }
  if (isFailureAuditKind(eventKind)) return true;
  if (!eventKind.startsWith("Operator")) return false;
  if (!obj) return false;
  const outcome = str(obj, "outcome");
  return outcome !== null && outcome !== "Accepted";
}

function isFailureAuditKindWithPayload(
  eventKind: string,
  obj: Record<string, unknown>,
): boolean {
  if (isPayloadGracefulNonFailure(eventKind, obj)) {
    return false;
  }
  if (FAILURE_KINDS.has(eventKind) || looksLikeFailureKind(eventKind)) {
    return true;
  }
  if (eventKind.startsWith("Operator")) {
    const outcome = str(obj, "outcome");
    return outcome !== null && outcome !== "Accepted";
  }
  return false;
}

/// Audit events whose KIND looks failure-shaped but whose PAYLOAD
/// declares a clean terminal. The dashboard treats these as
/// non-failures so the operator's "Failure events" feed isn't
/// polluted with normal session lifecycle.
///
///   * `SessionVmExited` with `signal_class: "GracefulExit"` and
///     `exit_code: 0` — the guest PID 1 returned cleanly. This is
///     literally the success terminal for an executor session.
///     Kernel emits the same event kind for every VM exit (clean
///     OR signaled), so the kind alone is ambiguous.
///
/// `SessionRevoked` and `OperatorCertRevoked` are handled higher
/// up: `looksLikeFailureKind` no longer matches the `Revoked`
/// suffix, so they never even reach this function.
function isPayloadGracefulNonFailure(
  eventKind: string,
  obj: Record<string, unknown>,
): boolean {
  if (eventKind === "SessionVmExited") {
    const signalClass = str(obj, "signal_class");
    const exitCode = obj["exit_code"];
    if (signalClass === "GracefulExit" && exitCode === 0) {
      return true;
    }
  }
  return false;
}

const FAILURE_KINDS = new Set<string>([
  // Lifecycle terminals — `SessionVmExited` is dual-mode
  // (graceful OR signaled) and the payload-aware classifier
  // (`isFailureAuditEvent`) gates it through
  // `isPayloadGracefulNonFailure` BEFORE this set is consulted,
  // so a clean `GracefulExit` + `exit_code: 0` exit never trips
  // the failure feed. Non-graceful exits and the kind-only
  // classifier (`isFailureAuditKind`, used by callers without
  // the payload) still treat it as a failure.
  "SessionVmFailedFinal",
  "SessionVmExited",
  "TaskBlockedForRecovery",
  "InitiativeAborted",
  "WorktreeProvisionFailed",
  // Review
  "WitnessRejected",
  "ReviewerRejected",
  "ReviewerDisagreement",
  "VerifierProcessFailed",
  // Egress / proxy
  "TransparentProxyDenied",
  "SessionEgressDenied",
  "SessionEgressStallDetected",
  "CredentialProxyUpstreamFailed",
  "CredentialProxyConnectionFailed",
  // Approval / escalation
  "EscalationDenied",
  "OperatorApprovalDenied",
  // Policy
  "PolicyAdvanceRejected",
  "PolicyAdvanceFailed",
  "ReplayRejected",
  // Git
  "PushFailed",
  "MergeFastForwardFailed",
  // Runtime
  "GatewayCrashed",
  "GatewaySignalFailed",
  "GatewayQuarantined",
  // Delivery
  "NotificationDeliveryFailed",
  // Intent
  "IntentRejected",
]);

// Suffix fallback for `Operator*` and any kernel-side variant the
// FE hasn't enumerated yet — keeps the panel rendering through a
// future schema bump even before the FE is rebuilt.
//
// `Revoked` is intentionally NOT in this regex: the only kernel
// events ending in `Revoked` today are `SessionRevoked` (clean
// session terminal) and `OperatorCertRevoked` (deliberate admin
// action with `reason` already populated). Treating either as a
// failure-shaped event drove the dashboard to surface clean
// terminals under "Failure events" and to fire the
// `INV-FAILURE-REASON-MANDATORY-01` kernel-bug badge on
// reason-less but-perfectly-fine `SessionRevoked` rows.
function looksLikeFailureKind(kind: string): boolean {
  return /(Failed|FailedFinal|Crashed|Denied|Rejected|Refused|Quarantined|Aborted|StallDetected|ProcessFailed|TimedOut)$/.test(
    kind,
  );
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function str(p: Record<string, unknown>, key: string): string | null {
  const v = p[key];
  return typeof v === "string" && v.length > 0 ? v : null;
}

function numStr(p: Record<string, unknown>, key: string): string | null {
  const v = p[key];
  if (typeof v === "number" && Number.isFinite(v)) return String(v);
  if (typeof v === "string" && v.length > 0) return v;
  return null;
}

function pushField(
  out: FailureField[],
  label: string,
  value: string | null,
): void {
  if (value === null || value === undefined) return;
  if (value.length === 0) return;
  out.push({ label, value });
}
