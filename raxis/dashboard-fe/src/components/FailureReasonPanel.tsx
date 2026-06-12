import clsx from "clsx";
import { useMemo, useState } from "react";

import type { DiagnosticAction, FailureInfo, FailureRecovery } from "@/types/api";
import { CopyButton } from "@/components/CopyButton";

interface FailureReasonPanelProps {
  /// Structured failure payload from the backend. Pass `null` /
  /// `undefined` to surface a calm "(no reason recorded)" empty
  /// state when the parent KNOWS the entity is in a terminal-
  /// failure state but the backend didn't ship a reason. Pass
  /// nothing (omit the prop) when the entity isn't failed — the
  /// panel returns `null` and renders nothing.
  reason: FailureInfo | null | undefined;
  /// Controls the empty-state behaviour:
  ///   * "missing-reason-bug" (default for Failed entities) — the
  ///     parent confirms the entity IS in a terminal-failure state
  ///     so a missing reason should still be visible. Renders a
  ///     muted `(no reason recorded — see audit chain)` card. The
  ///     enum tag is kept for backward compatibility with callers
  ///     who imported the literal; the visual treatment is now
  ///     intentionally low-key (the previous "KERNEL BUG" banner
  ///     was operator-hostile noise — the audit chain already
  ///     enforces the underlying invariant).
  ///   * "absent" — the entity is NOT failed; return `null` so the
  ///     panel adds zero visual weight.
  ///   * "no-error-reported" — explicit "no error reported, look
  ///     elsewhere" affordance for surfaces where the operator
  ///     might MISTAKENLY think a missing reason is silent failure
  ///     (e.g. the in-flight `Running` state).
  whenMissing?: "missing-reason-bug" | "absent" | "no-error-reported";
  /// When true the structured-field block + artifacts + copy
  /// button are collapsed behind a "Show details" disclosure. The
  /// panel headline + message stay visible. Used on dense list
  /// surfaces (Sessions, Tasks) where the panel competes with
  /// other rows for vertical space. Defaults to false (everything
  /// expanded).
  collapsible?: boolean;
  /// Heading label rendered above the kind. Defaults to "Failure
  /// reason"; some surfaces (review rejection rows) pass a more
  /// specific label like "Reviewer rejection".
  heading?: string;
  className?: string;
}

/// Operator-experience contract — `INV-DASHBOARD-FAILURE-VISIBILITY-01`:
/// every Failed / Rejected / Revoked entity in the dashboard MUST
/// surface its reason. This component is the single rendering
/// surface used across every page (Sessions, SessionDetail,
/// Tasks, TaskDetail, InitiativeDetail, Health, Notifications,
/// Escalations, the DAG side panel) so the UX is consistent and
/// the operator never has to grep kernel.stderr.log.
///
/// Layout:
///
///   ┌───────────────────────────────────────────────┐
///   │ ! Failure reason                       [copy] │  ← header
///   │   WorktreeProvisionFailed                     │  ← kind
///   │   ENOSPC: no space left on device             │  ← message
///   │   ┌─────────────────────────────────────────┐ │
///   │   │ exit_code     │ 28                      │ │  ← fields
///   │   │ worktree_path │ /var/lib/raxis/wts/…    │ │  ← (dl)
///   │   └─────────────────────────────────────────┘ │
///   │   Artifacts:                                  │  ← artifacts
///   │     • kernel.stderr.log                       │
///   │     • Audit row seq=12345                     │
///   │                                               │
///   │   observed 12:34:56  ⋅ event abcd1234…       │  ← footer
///   └───────────────────────────────────────────────┘
export function FailureReasonPanel({
  reason,
  whenMissing = "missing-reason-bug",
  collapsible = false,
  heading = "Failure reason",
  className,
}: FailureReasonPanelProps) {
  // `details` controls the disclosure when `collapsible` is true.
  // Default-open so an operator scanning a single SessionDetail
  // sees the full reason at first glance; collapse only matters
  // on list surfaces where the caller explicitly opts in.
  const [open, setOpen] = useState(true);

  const copyBlob = useMemo(() => buildCopyBlob(reason), [reason]);

  if (!reason) {
    if (whenMissing === "absent") return null;

    if (whenMissing === "missing-reason-bug") {
      // Operator-experience contract: the entity IS in a terminal-
      // failure state so the gap is real, but the dashboard does
      // NOT accuse the kernel of a bug in the operator's face.
      // The kernel-side audit chain already enforces
      // INV-FAILURE-REASON-MANDATORY-01; if it really fired the
      // forensic trail lives there. Render a calm muted card and
      // point the operator at the audit chain.
      const label = "(no reason recorded)";
      const tooltip =
        "The kernel did not surface a structured reason for this " +
        "transition. Inspect the audit chain for the originating " +
        "event and the kernel.stderr.log for any non-structured " +
        "diagnostics that landed alongside it.";
      return (
        <div
          role="status"
          aria-live="polite"
          data-failure-empty="missing-reason-bug"
          data-testid="failure-no-reason"
          className={clsx(
            "card border-edge p-3 text-sm text-ink-muted",
            className,
          )}
        >
          <div className="flex items-start gap-2">
            <span aria-hidden="true" className="text-ink-subtle">
              ⓘ
            </span>
            <div className="min-w-0">
              <p className="text-xs uppercase tracking-wide text-ink-subtle font-medium">
                {heading}
              </p>
              <p className="text-ink-muted break-words" title={tooltip}>
                {label}
              </p>
            </div>
          </div>
        </div>
      );
    }

    const label = "No error reported";
    const tooltip =
      "The kernel did not surface an error for this entity. " +
      "Look at the audit chain for the originating event if " +
      "you expected one.";
    return (
      <div
        role="status"
        aria-live="polite"
        data-failure-empty={whenMissing}
        className={clsx(
          "card border-edge p-3 text-sm text-ink-muted",
          className,
        )}
      >
        <div className="flex items-start gap-2">
          <span aria-hidden="true" className="text-ink-subtle">
            ⓘ
          </span>
          <span title={tooltip}>{label}</span>
        </div>
      </div>
    );
  }

  const showDetails = !collapsible || open;
  const fields = reason.fields ?? [];
  const artifacts = reason.artifacts ?? [];
  const actions = reason.actions ?? [];
  const recovery = deriveRecovery(reason, actions);
  const hasDetails = fields.length > 0 || artifacts.length > 0;
  const eventAnchor = reason.event_id ?? null;
  const seqAnchor = reason.seq ?? null;
  const observedAt = reason.observed_at ?? 0;

  return (
    <section
      role="alert"
      aria-live="assertive"
      data-failure-kind={reason.kind}
      className={clsx(
        "card border-bad/40 bg-bad/5 p-3 text-sm space-y-2",
        className,
      )}
    >
      <header className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-2 min-w-0">
          <span aria-hidden="true" className="text-bad font-bold leading-none mt-0.5">
            !
          </span>
          <div className="min-w-0">
            <p className="text-xs uppercase tracking-wide text-bad/90 font-medium">
              {heading}
            </p>
            <p
              className="font-mono text-[13px] text-bad break-words"
              data-testid="failure-kind"
            >
              {reason.kind || "UnknownFailure"}
            </p>
            {recovery && (
              <RecoveryStatusBadge recovery={recovery} className="mt-1" />
            )}
          </div>
        </div>
        <div className="flex items-center gap-1 shrink-0">
          {collapsible && (
            <button
              type="button"
              className="text-xs text-ink-muted hover:text-accent px-2 py-0.5 rounded"
              onClick={() => setOpen((v) => !v)}
              aria-expanded={open}
              aria-controls="failure-details"
            >
              {open ? "Hide details" : "Show details"}
            </button>
          )}
          <CopyButton value={copyBlob} label="Copy failure details" />
        </div>
      </header>

      <p
        className="text-ink whitespace-pre-wrap break-words"
        data-testid="failure-message"
      >
        {reason.message?.trim() ? reason.message : "(no message)"}
      </p>

      {(recovery || actions.length > 0) && (
        <RecoveryActions recovery={recovery} actions={actions} />
      )}

      {showDetails && hasDetails && (
        <div id="failure-details" className="space-y-2">
          {fields.length > 0 && (
            <dl
              className="grid min-w-0 max-w-full grid-cols-[max-content_minmax(0,1fr)] gap-x-3 gap-y-1 text-[12.5px] bg-panel-raised rounded p-2 border border-edge"
              data-testid="failure-fields"
            >
              {fields.map((f, i) => (
                <FieldRow key={`${f.label}-${i}`} label={f.label} value={f.value} />
              ))}
            </dl>
          )}
          {artifacts.length > 0 && (
            <div className="text-[12.5px]" data-testid="failure-artifacts">
              <p className="text-ink-muted mb-1">Artifacts</p>
              <ul className="space-y-0.5">
                {artifacts.map((a, i) => (
                  <li key={`${a.href}-${i}`} className="flex items-start gap-2">
                    <span className="text-ink-subtle mt-1">•</span>
                    <ArtifactLink label={a.label} href={a.href} />
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {(observedAt > 0 || eventAnchor !== null || seqAnchor !== null) && (
        <footer className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-ink-muted pt-1 border-t border-edge">
          {observedAt > 0 && (
            <span>
              observed{" "}
              <time dateTime={new Date(observedAt * 1000).toISOString()}>
                {formatTimestamp(observedAt)}
              </time>
            </span>
          )}
          {seqAnchor !== null && (
            <span>
              audit seq{" "}
              <code className="font-mono">{seqAnchor}</code>
            </span>
          )}
          {eventAnchor && (
            <span className="truncate" title={eventAnchor}>
              event{" "}
              <code className="font-mono">{shortEvent(eventAnchor)}</code>
            </span>
          )}
        </footer>
      )}
    </section>
  );
}

function RecoveryActions({
  recovery,
  actions,
}: {
  recovery: FailureRecovery | null;
  actions: DiagnosticAction[];
}) {
  return (
    <div
      className={clsx(
        "rounded border p-2",
        recoverySurfaceClass(recovery?.status),
      )}
      data-testid="failure-recovery-actions"
    >
      <div className="mb-1 flex flex-wrap items-center gap-2">
        <p className="text-[11px] font-semibold uppercase tracking-wide text-ink-muted">
          Recovery status
        </p>
        {recovery && <RecoveryStatusBadge recovery={recovery} />}
      </div>
      {recovery && (
        <div className="mb-2 space-y-0.5 text-[12.5px]">
          <p className="font-medium text-ink">{recovery.label}</p>
          <p className="text-ink-muted">{recovery.detail}</p>
        </div>
      )}
      <div className="space-y-2">
        {actions.length > 0 ? (
          actions.map((action, index) => (
            <RecoveryAction
              key={`${action.kind}-${action.target}-${index}`}
              action={action}
            />
          ))
        ) : (
          <p className="text-[12px] text-ink-muted">
            No in-place recovery command is available for this failure.
          </p>
        )}
      </div>
    </div>
  );
}

function RecoveryStatusBadge({
  recovery,
  className,
}: {
  recovery: FailureRecovery;
  className?: string;
}) {
  return (
    <span
      className={clsx(
        "inline-flex w-fit items-center rounded border px-2 py-0.5 text-[11px] font-semibold",
        recoveryBadgeClass(recovery.status),
        className,
      )}
      data-testid="failure-recovery-status"
      data-recovery-status={recovery.status}
      title={recovery.detail}
    >
      {recoveryLabel(recovery.status)}
    </span>
  );
}

function RecoveryAction({ action }: { action: DiagnosticAction }) {
  if (action.kind === "command") {
    return (
      <div className="grid min-w-0 gap-1 sm:grid-cols-[8rem_minmax(0,1fr)_auto] sm:items-start">
        <span className="text-[11px] font-medium text-ink-muted">
          {action.label}
        </span>
        <code className="min-w-0 whitespace-pre-wrap break-all rounded border border-edge bg-panel px-2 py-1.5 font-mono text-[11px] leading-relaxed text-ink [overflow-wrap:anywhere]">
          {action.target}
        </code>
        <CopyButton
          value={action.target}
          label={`Copy ${action.label.toLowerCase()} command`}
        />
      </div>
    );
  }

  const isExternal =
    action.kind === "external" || /^(https?:|mailto:)/i.test(action.target);
  const isRoute = action.kind === "route" || action.target.startsWith("/");

  if (isExternal || isRoute) {
    return (
      <a
        href={action.target}
        className="inline-flex max-w-full items-center gap-1 rounded border border-edge bg-panel px-2 py-1 text-[12px] font-medium text-accent hover:bg-panel-high hover:underline"
        rel={isExternal ? "noopener noreferrer" : undefined}
        target={isExternal ? "_blank" : undefined}
      >
        <span className="min-w-0 truncate">{action.label}</span>
        <span aria-hidden="true">→</span>
      </a>
    );
  }

  return (
    <div className="min-w-0 text-[12px] text-ink-muted">
      <span className="font-medium text-ink">{action.label}: </span>
      <code className="font-mono break-all [overflow-wrap:anywhere]">
        {action.target}
      </code>
    </div>
  );
}

function FieldRow({ label, value }: { label: string; value: string }) {
  // Render long single-line values as monospace so file paths /
  // hashes / exit codes are scannable. Multi-line values fall
  // through to whitespace-pre-wrap so stack traces stay readable.
  const isMonoCandidate =
    value.length > 0 &&
    !value.includes("\n") &&
    /^[/\w.@:!=\-+,()[\]{}]+$/.test(value);
  return (
    <>
      <dt className="text-ink-muted font-medium">{label}</dt>
      <dd
        className={clsx(
          "text-ink min-w-0",
          isMonoCandidate
            ? "font-mono break-all"
            : "whitespace-pre-wrap break-words",
        )}
      >
        {value}
      </dd>
    </>
  );
}

function ArtifactLink({ label, href }: { label: string; href: string }) {
  // Heuristic: relative paths (no scheme + no leading slash) and
  // absolute filesystem paths (`/…`) get rendered as monospace
  // un-linked text — the dashboard doesn't host arbitrary files.
  // Anything starting with `http(s):`, `mailto:`, `audit:` or
  // `/api/`, `/initiatives/`, etc. is rendered as a real link.
  const isLinkable =
    /^(https?:|mailto:|audit:|raxis:)/i.test(href) ||
    href.startsWith("/api/") ||
    href.startsWith("/initiatives/") ||
    href.startsWith("/sessions/") ||
    href.startsWith("/tasks/") ||
    href.startsWith("/audit/") ||
    href.startsWith("/health/") ||
    href.startsWith("/escalations/") ||
    href.startsWith("/worktrees/");
  if (isLinkable) {
    return (
      <a
        href={href}
        className="text-accent hover:underline break-all"
        rel={href.startsWith("http") ? "noopener noreferrer" : undefined}
        target={href.startsWith("http") ? "_blank" : undefined}
      >
        {label}
      </a>
    );
  }
  return (
    <span className="min-w-0">
      <span className="text-ink">{label}</span>{" "}
      <code className="font-mono text-ink-muted break-all">{href}</code>
    </span>
  );
}

function buildCopyBlob(reason: FailureInfo | null | undefined): string {
  if (!reason) return "";
  const lines: string[] = [];
  const recovery = deriveRecovery(reason, reason.actions ?? []);
  lines.push(`kind: ${reason.kind}`);
  if (reason.message) lines.push(`message: ${reason.message}`);
  if (recovery) {
    lines.push(`recovery_status: ${recovery.status}`);
    lines.push(`recovery_label: ${recovery.label}`);
    lines.push(`recovery_detail: ${recovery.detail}`);
  }
  for (const f of reason.fields ?? []) {
    lines.push(`${f.label}: ${f.value}`);
  }
  for (const a of reason.artifacts ?? []) {
    lines.push(`${a.label}: ${a.href}`);
  }
  for (const action of reason.actions ?? []) {
    lines.push(`${action.label} (${action.kind}): ${action.target}`);
  }
  if (reason.event_id) lines.push(`event_id: ${reason.event_id}`);
  if (reason.seq !== undefined && reason.seq !== null)
    lines.push(`seq: ${reason.seq}`);
  if (reason.observed_at && reason.observed_at > 0)
    lines.push(`observed_at: ${formatTimestamp(reason.observed_at)}`);
  return lines.join("\n");
}

function deriveRecovery(
  reason: FailureInfo,
  actions: DiagnosticAction[],
): FailureRecovery | null {
  if (reason.recovery) {
    if (
      reason.recovery.status === "unrecoverable" &&
      hasRecoveryEscalationAction(actions)
    ) {
      return {
        status: "operator_action_required",
        label: "Parent initiative recovery available",
        detail:
          "This task is not directly retryable, but a recovery escalation is available. Open Escalations to review the cause and approve or deny the signed resume disposition.",
      };
    }
    return reason.recovery;
  }

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
    hasRecoveryEscalationAction(actions)
  ) {
    return {
      status: "operator_action_required",
      label: "Operator action required",
      detail:
        "Open the recovery escalation, review the cause, then approve or deny the signed recovery disposition.",
    };
  }

  if (actions.length > 0) {
    return {
      status: "diagnosis_only",
      label: "Diagnosis available",
      detail:
        "Use the linked dashboard surfaces to inspect the cause. No direct resume command was attached.",
    };
  }

  return null;
}

function hasRecoveryEscalationAction(actions: DiagnosticAction[]): boolean {
  return actions.some(
    (a) =>
      /approve recovery/i.test(a.label) ||
      /open recovery escalations/i.test(a.label),
  );
}

function recoveryLabel(status: string): string {
  switch (status) {
    case "recoverable":
      return "Recoverable";
    case "operator_action_required":
      return "Operator action required";
    case "unrecoverable":
      return "Unrecoverable in place";
    case "diagnosis_only":
      return "Diagnosis only";
    default:
      return status
        .replace(/_/g, " ")
        .replace(/\b\w/g, (ch) => ch.toUpperCase());
  }
}

function recoveryBadgeClass(status: string): string {
  switch (status) {
    case "recoverable":
      return "border-good/40 bg-good/10 text-good";
    case "operator_action_required":
      return "border-warn/40 bg-warn/10 text-warn";
    case "unrecoverable":
      return "border-bad/50 bg-bad/10 text-bad";
    case "diagnosis_only":
      return "border-accent/35 bg-accent/10 text-accent";
    default:
      return "border-edge bg-panel-raised text-ink-muted";
  }
}

function recoverySurfaceClass(status: string | undefined): string {
  switch (status) {
    case "recoverable":
      return "border-good/30 bg-good/5";
    case "operator_action_required":
      return "border-warn/30 bg-warn/5";
    case "unrecoverable":
      return "border-bad/35 bg-bad/5";
    case "diagnosis_only":
      return "border-accent/25 bg-accent/5";
    default:
      return "border-warn/30 bg-warn/5";
  }
}

function formatTimestamp(unixSeconds: number): string {
  if (!Number.isFinite(unixSeconds) || unixSeconds <= 0) return "—";
  const d = new Date(unixSeconds * 1000);
  return d.toLocaleString();
}

function shortEvent(id: string): string {
  if (id.length <= 12) return id;
  return `${id.slice(0, 8)}…${id.slice(-4)}`;
}

interface FailurePillProps {
  /// Whether the entity is in a terminal-failure state. The pill
  /// renders nothing when false.
  failed: boolean;
  /// Reason payload, when available. Used to populate the hover
  /// tooltip / click-to-expand summary.
  reason: FailureInfo | null | undefined;
  /// Compact form (no "Reason:" prefix), used in tight ribbons /
  /// audit rows. Defaults to false.
  compact?: boolean;
  className?: string;
}

/// One-line companion to `<FailureReasonPanel>` for tight surfaces
/// like list rows + the audit-chain ribbon. Shows the first ~80
/// chars of `message` inline + a native `title` tooltip with the
/// full reason. Always pairs with a `<FailureReasonPanel>` on the
/// detail page so the operator can drill in.
export function FailurePill({
  failed,
  reason,
  compact = false,
  className,
}: FailurePillProps) {
  if (!failed) return null;
  // When the kernel did not surface a structured reason we fall
  // back to a calm muted pill (rather than the previous loud
  // KERNEL BUG affordance) — the underlying invariant lives in
  // the audit chain, not in the operator's face.
  const haveReason = Boolean(
    reason && (reason.message?.trim() || reason.kind?.trim()),
  );
  const summary = reason?.message?.trim()
    ? truncate(reason.message.trim(), compact ? 60 : 100)
    : reason?.kind?.trim() || "(no reason recorded)";
  const tooltip = haveReason
    ? [reason?.kind, reason?.message].filter(Boolean).join("\n")
    : "The kernel did not surface a structured reason for this " +
      "transition. Inspect the audit chain for the originating " +
      "event.";
  return (
    <span
      className={clsx(
        "inline-flex items-center gap-1 px-2 py-0.5 rounded border text-[12px]",
        haveReason
          ? "border-bad/40 bg-bad/10 text-bad"
          : "border-edge bg-panel-raised text-ink-muted",
        className,
      )}
      title={tooltip}
      data-failure-kind={reason?.kind ?? "NoReasonRecorded"}
    >
      <span aria-hidden="true" className="font-bold">
        {haveReason ? "!" : "ⓘ"}
      </span>
      {!compact && (
        <span className={haveReason ? "text-bad/90" : "text-ink-subtle"}>
          {haveReason ? "Reason:" : "Note:"}
        </span>
      )}
      <span className="truncate max-w-[28ch]">{summary}</span>
    </span>
  );
}

function truncate(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}
