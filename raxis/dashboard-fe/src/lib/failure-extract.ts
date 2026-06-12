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

import type {
  DiagnosticAction,
  FailureField,
  FailureInfo,
  FailureRecovery,
} from "@/types/api";

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
/// "(no reason recorded)" affordances so the gap is
/// operator-visible without screaming KERNEL BUG.
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
  const actions: DiagnosticAction[] = [];
  let recovery: FailureRecovery | undefined;
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
      recovery = diagnosisOnly(
        "Session failure captured",
        "This VM/session has ended. Inspect the owning task or initiative for the recoverable action, if one exists.",
      );
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
      recovery = diagnosisOnly(
        "Session exit captured",
        "This session is no longer running. Inspect the owning task for retry or recovery disposition.",
      );
      break;
    }
    case "TaskBlockedForRecovery": {
      message =
        str(obj, "block_reason") ??
        str(obj, "reason") ??
        "Task blocked pending recovery";
      pushField(fields, "task_id", str(obj, "task_id"));
      pushField(fields, "initiative_id", str(obj, "initiative_id"));
      pushTaskRecoveryActions(actions, str(obj, "task_id"));
      recovery = {
        status: "recoverable",
        label: "Task can be resumed",
        detail:
          "Review the block reason, then run the resume command. The kernel will reset stale runtime state and re-check authority.",
      };
      break;
    }
    case "InitiativeAborted": {
      message =
        str(obj, "reason") ?? "Initiative aborted by operator/kernel";
      pushField(fields, "initiative_id", str(obj, "initiative_id"));
      pushField(fields, "aborted_by", str(obj, "aborted_by"));
      recovery = unrecoverable(
        "Initiative is terminal",
        "Aborted initiatives are preserved as terminal records. Start a new initiative or use an explicit fork/amendment path instead of resuming in place.",
      );
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
      // The panel's `(no message)` / `(no reason recorded)`
      // empty-states then fire, surfacing the gap as a calm
      // muted affordance (the audit chain enforces the actual
      // invariant). Crucially we do NOT plant a hedged
      // fallback placeholder here — the forbidden-phrase
      // regex in the kernel sweep test treats those as a
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
      recovery = diagnosisOnly(
        "Diagnosis available",
        "Use the structured reason and linked entity pages to inspect the failure. No in-place recovery command is attached to this event.",
      );
      break;
    }
    case "TransparentProxyDenied":
    case "TproxyAdmissionDenied":
    case "SessionEgressDenied": {
      message = str(obj, "reason") ?? "Egress denied at chokepoint";
      pushField(fields, "host_or_sni", str(obj, "host_or_sni"));
      pushField(fields, "original_dst_ip", str(obj, "original_dst_ip"));
      pushField(fields, "original_dst_port", numStr(obj, "original_dst_port"));
      pushField(fields, "protocol", str(obj, "protocol"));
      pushField(fields, "chokepoint", str(obj, "chokepoint"));
      pushField(fields, "session_id", str(obj, "session_id"));
      pushField(fields, "policy_provider", str(obj, "policy_provider"));
      recovery = diagnosisOnly(
        "Policy denied egress",
        "The network request was blocked correctly. Update the signed plan or policy only if the host should be allowed.",
      );
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
      recovery = diagnosisOnly(
        "Repeated denied egress",
        "The session repeatedly attempted blocked network access. Inspect the task prompt and allowlist before retrying.",
      );
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
      recovery = diagnosisOnly(
        "Credential proxy upstream failed",
        "Inspect the upstream service and registered credential. Retry happens through the owning task or a new initiative.",
      );
      break;
    }
    case "PushFailed":
    case "MergeFastForwardFailed": {
      message = str(obj, "reason") ?? str(obj, "category") ?? "Git operation failed";
      pushField(fields, "category", str(obj, "category"));
      pushField(fields, "commit_sha", str(obj, "commit_sha"));
      pushField(fields, "target_ref", str(obj, "target_ref"));
      pushField(fields, "remote", str(obj, "remote"));
      pushField(fields, "branch", str(obj, "branch"));
      pushField(fields, "initiative_id", str(obj, "initiative_id"));
      actions.push({
        label:
          eventKind === "MergeFastForwardFailed"
            ? "Open recovery escalations"
            : "Open initiative",
        kind: "route",
        target:
          eventKind === "MergeFastForwardFailed"
            ? "/escalations"
            : routeFor("initiative", str(obj, "initiative_id")),
      });
      recovery =
        eventKind === "MergeFastForwardFailed"
          ? {
              status: "operator_action_required",
              label: "Merge recovery required",
              detail:
                "The target ref changed or could not advance safely. Review the managed repo state and use the recovery escalation path.",
            }
          : {
              status: "operator_action_required",
              label: "Publish failed",
              detail:
                "The managed repo may still contain the merge. Inspect the initiative and retry publish after fixing remote credentials or branch state.",
            };
      break;
    }
    case "OrchestratorRespawnCeilingExceeded": {
      const attempts = numStr(obj, "attempts");
      const maxAttempts = numStr(obj, "max_attempts");
      message =
        str(obj, "reason") ??
        (attempts && maxAttempts
          ? `Orchestrator respawn ceiling exceeded (${attempts}/${maxAttempts}). Operator recovery approval is required.`
          : "Orchestrator respawn ceiling exceeded. Operator recovery approval is required.");
      pushField(fields, "initiative_id", str(obj, "initiative_id"));
      pushField(fields, "attempts", attempts);
      pushField(fields, "max_attempts", maxAttempts);
      actions.push({
        label: "Open recovery escalations",
        kind: "route",
        target: "/escalations",
      });
      recovery = {
        status: "operator_action_required",
        label: "Recovery approval required",
        detail:
          "The orchestrator exhausted its respawn budget. Review the causal failure and approve or deny the recovery escalation.",
      };
      break;
    }
    case "ReviewRejectionCeilingExceeded": {
      const rejectCount = numStr(obj, "review_reject_count");
      const maxRejects = numStr(obj, "max_review_rejections");
      message =
        str(obj, "critique") ??
        (rejectCount && maxRejects
          ? `Reviewer rejection ceiling exceeded (${rejectCount}/${maxRejects}).`
          : "Reviewer rejection ceiling exceeded.");
      pushField(fields, "initiative_id", str(obj, "initiative_id"));
      pushField(fields, "executor_task_id", str(obj, "executor_task_id"));
      pushField(
        fields,
        "triggered_by_reviewer_task_id",
        str(obj, "triggered_by_reviewer_task_id"),
      );
      pushField(fields, "review_reject_count", rejectCount);
      pushField(fields, "max_review_rejections", maxRejects);
      pushField(fields, "critique", str(obj, "critique"));
      const executorTaskId = str(obj, "executor_task_id");
      const reviewerTaskId = str(obj, "triggered_by_reviewer_task_id");
      if (executorTaskId) {
        actions.push({
          label: "Open executor task",
          kind: "route",
          target: routeFor("task", executorTaskId),
        });
      }
      if (reviewerTaskId) {
        actions.push({
          label: "Open reviewer task",
          kind: "route",
          target: routeFor("task", reviewerTaskId),
        });
      }
      recovery = unrecoverable(
        "Review retry budget exhausted",
        "This task loop is terminal in place. Inspect the reviewer critique and start a corrected initiative or signed amendment/fork.",
      );
      break;
    }
    case "EscalationRateLimitExceeded": {
      const attemptedCount = numStr(obj, "attempted_count");
      message =
        attemptedCount !== null
          ? `Escalation rate limit exceeded after ${attemptedCount} attempts in the current window.`
          : "Escalation rate limit exceeded.";
      pushField(fields, "lineage_id", str(obj, "lineage_id"));
      pushField(fields, "attempted_count", attemptedCount);
      pushField(fields, "window_start", numStr(obj, "window_start"));
      actions.push({
        label: "Open recovery escalations",
        kind: "route",
        target: "/escalations",
      });
      recovery = {
        status: "operator_action_required",
        label: "Escalation throttle hit",
        detail:
          "Recovery escalation creation was rate-limited. Wait for the window to clear or adjust policy before retrying.",
      };
      break;
    }
    case "InitiativePermanentFailureEscalated": {
      const recoverable = boolStr(obj, "recoverable_via_approve");
      message =
        str(obj, "cause_summary") ??
        str(obj, "reason") ??
        "Initiative requires operator recovery disposition";
      pushField(fields, "initiative_id", str(obj, "initiative_id"));
      pushField(fields, "cause_kind", str(obj, "cause_kind"));
      pushField(fields, "cause_summary", str(obj, "cause_summary"));
      pushField(fields, "escalation_id", str(obj, "escalation_id"));
      pushField(fields, "recoverable_via_approve", recoverable);
      pushEscalationRecoveryActions(
        actions,
        str(obj, "escalation_id"),
        recoverable === "true",
      );
      recovery =
        recoverable === "true"
          ? {
              status: "operator_action_required",
              label: "Recovery approval required",
              detail:
                "The initiative is terminal until an operator approves or denies the recovery escalation.",
            }
          : unrecoverable(
              "Not recoverable in place",
              "This permanent failure cannot be resumed by approving the escalation. Preserve the failed state and fork/amend/new-run instead.",
            );
      break;
    }
    case "VerifierProcessFailed": {
      message = str(obj, "reason") ?? "Verifier process failed";
      pushField(fields, "exit_code", numStr(obj, "exit_code"));
      pushField(fields, "stage", str(obj, "stage"));
      recovery = diagnosisOnly(
        "Verifier failed",
        "Inspect verifier identity, exit code, artifact paths, and the owning task before retrying.",
      );
      break;
    }
    case "GatewayCrashed":
    case "GatewaySignalFailed": {
      message = str(obj, "reason") ?? "Gateway crashed";
      pushField(fields, "exit_code", numStr(obj, "exit_code"));
      pushField(fields, "signal", str(obj, "signal"));
      pushField(fields, "gateway_id", str(obj, "gateway_id"));
      recovery = diagnosisOnly(
        "Gateway runtime failed",
        "Inspect provider credentials and gateway health. The owning task or kernel health page carries the recovery action when available.",
      );
      break;
    }
    case "WorktreeProvisionFailed": {
      message = str(obj, "reason") ?? str(obj, "detail") ?? "Worktree provisioning failed";
      pushField(fields, "task_id", str(obj, "task_id"));
      pushField(fields, "session_id", str(obj, "session_id"));
      pushField(fields, "worktree_path", str(obj, "worktree_path"));
      pushField(fields, "exit_code", numStr(obj, "exit_code"));
      recovery = diagnosisOnly(
        "Worktree provisioning failed",
        "Inspect disk space, repository state, and path validity. Retry through the owning task when it is marked recoverable.",
      );
      break;
    }
    case "ReviewerDisagreement": {
      message =
        str(obj, "summary") ??
        "Reviewers returned conflicting verdicts";
      pushField(fields, "task_id", str(obj, "task_id"));
      pushField(fields, "initiative_id", str(obj, "initiative_id"));
      pushField(fields, "n_reviewers", numStr(obj, "n_reviewers"));
      recovery = diagnosisOnly(
        "Reviewer disagreement",
        "Inspect reviewer verdicts and critiques before deciding whether to amend, fork, or rerun.",
      );
      break;
    }
    case "OperatorApprovalDenied": {
      message =
        str(obj, "reason") ?? "Operator denied approval";
      pushField(fields, "operator_id", str(obj, "operator_id"));
      pushField(fields, "initiative_id", str(obj, "initiative_id"));
      pushField(fields, "approval_id", str(obj, "approval_id"));
      recovery = diagnosisOnly(
        "Operator approval denied",
        "The operator or policy denied this request. Submit a new signed request if the decision should change.",
      );
      break;
    }
    case "IntentRejected": {
      message = str(obj, "error_message") ?? str(obj, "error_code") ?? "Intent rejected";
      pushField(fields, "error_code", str(obj, "error_code"));
      pushField(fields, "task_id", str(obj, "task_id"));
      pushField(fields, "session_id", str(obj, "session_id"));
      recovery = diagnosisOnly(
        "Intent rejected",
        "The kernel rejected the action. Inspect the error code, task state, and policy before retrying.",
      );
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
      recovery = defaultRecoveryForEventKind(eventKind, actions);
      break;
    }
  }

  appendCommonNavigationActions(actions, obj);
  recovery ??= defaultRecoveryForEventKind(eventKind, actions);

  return {
    kind: eventKind,
    message,
    fields: fields.length > 0 ? fields : undefined,
    actions: actions.length > 0 ? dedupeActions(actions) : undefined,
    recovery,
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

function defaultRecoveryForEventKind(
  eventKind: string,
  actions: DiagnosticAction[],
): FailureRecovery {
  if (
    actions.some(
      (a) => a.kind === "command" && /resume task/i.test(a.label),
    )
  ) {
    return {
      status: "recoverable",
      label: "Task can be resumed",
      detail:
        "Review the failure, then run the resume command. The kernel re-checks authority before admitting the retry.",
    };
  }
  if (
    actions.some(
      (a) =>
        /approve recovery/i.test(a.label) ||
        /open recovery escalations/i.test(a.label),
    )
  ) {
    return {
      status: "operator_action_required",
      label: "Operator action required",
      detail:
        "Open the recovery escalation, review the cause, then approve or deny the signed recovery disposition.",
    };
  }
  if (/Aborted|Cancelled|PermanentFailure|CeilingExceeded/.test(eventKind)) {
    return unrecoverable(
      "Not recoverable in place",
      "This failure is terminal for the current execution attempt. Preserve the record and use a new run, fork, or signed amendment path.",
    );
  }
  return diagnosisOnly(
    "Diagnosis available",
    "The dashboard has enough structured context to inspect the cause. No direct in-place recovery command is attached to this event.",
  );
}

function diagnosisOnly(label: string, detail: string): FailureRecovery {
  return {
    status: "diagnosis_only",
    label,
    detail,
  };
}

function unrecoverable(label: string, detail: string): FailureRecovery {
  return {
    status: "unrecoverable",
    label,
    detail,
  };
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
  "InitiativePermanentFailureEscalated",
  "OrchestratorRespawnCeilingExceeded",
  "ReviewRejectionCeilingExceeded",
  "EscalationRateLimitExceeded",
  "InitiativeAborted",
  "WorktreeProvisionFailed",
  // Review
  "WitnessRejected",
  "ReviewerRejected",
  "ReviewerDisagreement",
  "VerifierProcessFailed",
  // Egress / proxy
  "TransparentProxyDenied",
  "TproxyAdmissionDenied",
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
// terminals under "Failure events" and to fire a no-reason
// empty-state on reason-less but-perfectly-fine `SessionRevoked`
// rows.
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

function boolStr(p: Record<string, unknown>, key: string): string | null {
  const v = p[key];
  if (typeof v === "boolean") return v ? "true" : "false";
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

function pushTaskRecoveryActions(
  out: DiagnosticAction[],
  taskId: string | null,
): void {
  if (!taskId) return;
  out.push({
    label: "Open task",
    kind: "route",
    target: routeFor("task", taskId),
  });
  out.push({
    label: "Resume task",
    kind: "command",
    target: `raxis task resume ${shellQuote(taskId)}`,
  });
}

function pushEscalationRecoveryActions(
  out: DiagnosticAction[],
  escalationId: string | null,
  recoverable: boolean,
): void {
  if (!escalationId) {
    out.push({
      label: "Open recovery escalations",
      kind: "route",
      target: "/escalations",
    });
    return;
  }
  out.push({
    label: "Open recovery escalations",
    kind: "route",
    target: "/escalations",
  });
  if (recoverable) {
    out.push({
      label: "Approve recovery",
      kind: "command",
      target:
        `raxis --operator-key "$RAXIS_OPERATOR_KEY" escalation approve ${shellQuote(escalationId)} ` +
        "--scope LogicalDeadlock --max-uses 1 --valid-for 600",
    });
  }
  out.push({
    label: recoverable ? "Deny recovery" : "Preserve failed state",
    kind: "command",
    target:
      `raxis --operator-key "$RAXIS_OPERATOR_KEY" escalation deny ${shellQuote(escalationId)} ` +
      '--reason "Preserve failed state"',
  });
}

function appendCommonNavigationActions(
  out: DiagnosticAction[],
  obj: Record<string, unknown>,
): void {
  const initiativeId = str(obj, "initiative_id");
  const taskId = str(obj, "task_id");
  const sessionId = str(obj, "session_id");
  if (initiativeId) {
    out.push({
      label: "Open initiative",
      kind: "route",
      target: routeFor("initiative", initiativeId),
    });
  }
  if (taskId) {
    out.push({
      label: "Open task",
      kind: "route",
      target: routeFor("task", taskId),
    });
  }
  if (sessionId) {
    out.push({
      label: "Open session",
      kind: "route",
      target: routeFor("session", sessionId),
    });
  }
}

function routeFor(
  kind: "initiative" | "task" | "session",
  id: string | null,
): string {
  if (!id) {
    if (kind === "initiative") return "/initiatives";
    if (kind === "task") return "/tasks";
    return "/sessions";
  }
  if (kind === "initiative") return `/initiatives/${encodeURIComponent(id)}`;
  if (kind === "task") return `/tasks/${encodeURIComponent(id)}`;
  return `/sessions/${encodeURIComponent(id)}`;
}

function dedupeActions(actions: DiagnosticAction[]): DiagnosticAction[] {
  const seen = new Set<string>();
  const out: DiagnosticAction[] = [];
  for (const action of actions) {
    const key = `${action.kind}\0${action.label}\0${action.target}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(action);
  }
  return out;
}

function shellQuote(value: string): string {
  if (/^[A-Za-z0-9._:/@%+=,-]+$/.test(value)) return value;
  return `'${value.replace(/'/g, "'\"'\"'")}'`;
}
