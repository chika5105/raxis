import { Link } from "react-router-dom";
import clsx from "clsx";
import type { ReactNode } from "react";

import { CopyButton } from "@/components/CopyButton";
import { Empty } from "@/components/Empty";
import { Mono } from "@/components/Mono";
import { fmtAbsolute, fmtRelative } from "@/lib/format";
import type { DiagnosticAction, DiagnosticFinding } from "@/types/api";

interface DiagnosticFindingsPanelProps {
  findings: DiagnosticFinding[];
  compact?: boolean;
}

export function DiagnosticFindingsPanel({
  findings,
  compact = false,
}: DiagnosticFindingsPanelProps) {
  if (findings.length === 0) {
    return (
      <div className="card p-0 overflow-hidden">
        <Empty
          title="No active diagnostics."
          hint="Raxis did not find an actionable health, policy, audit, gateway, or orchestration issue in the current scope."
        />
      </div>
    );
  }

  return (
    <div className={compact ? "space-y-2" : "space-y-3"}>
      {findings.map((finding) => (
        <article
          key={finding.finding_id}
          className={clsx(
            "card overflow-hidden",
            severityBorder(finding.severity),
          )}
          data-diagnostic-severity={finding.severity}
          data-diagnostic-scope={finding.scope}
        >
          <div className={compact ? "p-3" : "p-4"}>
            <header className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span
                    className={clsx(
                      "badge uppercase text-[10px]",
                      severityBadge(finding.severity),
                    )}
                  >
                    {finding.severity}
                  </span>
                  <span className="badge bg-panel-high border-edge text-ink-muted">
                    {finding.scope}
                  </span>
                  {finding.status !== "active" && (
                    <span className="badge bg-panel-high border-edge text-ink-muted">
                      {finding.status}
                    </span>
                  )}
                </div>
                <h3 className="mt-2 text-sm font-semibold text-ink">
                  {finding.title}
                </h3>
              </div>
              {finding.observed_at ? (
                <time
                  className="text-[11px] text-ink-subtle whitespace-nowrap"
                  dateTime={new Date(finding.observed_at * 1000).toISOString()}
                  title={fmtAbsolute(finding.observed_at)}
                >
                  {fmtRelative(finding.observed_at)}
                </time>
              ) : null}
            </header>

            <p className="mt-2 text-xs text-ink-muted leading-relaxed">
              {finding.summary}
            </p>

            <div className="mt-3 grid grid-cols-1 xl:grid-cols-2 gap-3">
              <dl className="space-y-1 text-[11px]">
                {finding.initiative_id && (
                  <DiagnosticRow
                    label="Initiative"
                    value={
                      <Link
                        to={`/initiatives/${finding.initiative_id}`}
                        className="text-accent hover:underline"
                      >
                        <Mono>{finding.initiative_id}</Mono>
                      </Link>
                    }
                  />
                )}
                {finding.task_id && (
                  <DiagnosticRow
                    label="Task"
                    value={
                      <Link
                        to={`/tasks/${finding.task_id}`}
                        className="text-accent hover:underline"
                      >
                        <Mono>{finding.task_id}</Mono>
                      </Link>
                    }
                  />
                )}
                {finding.session_id && (
                  <DiagnosticRow
                    label="Session"
                    value={
                      <Link
                        to={`/sessions/${finding.session_id}`}
                        className="text-accent hover:underline"
                      >
                        <Mono>{finding.session_id}</Mono>
                      </Link>
                    }
                  />
                )}
                {finding.seq && (
                  <DiagnosticRow
                    label="Audit"
                    value={
                      <Link
                        to={`/audit?search=${encodeURIComponent(String(finding.seq))}`}
                        className="text-accent hover:underline"
                      >
                        #{finding.seq}
                      </Link>
                    }
                  />
                )}
                {(finding.evidence ?? []).map((row) => (
                  <DiagnosticRow
                    key={`${finding.finding_id}-${row.label}-${row.value}`}
                    label={row.label}
                    value={
                      row.href ? (
                        <span className="inline-flex items-center gap-1 min-w-0">
                          <span className="truncate">{row.value}</span>
                          <CopyButton value={row.href} />
                        </span>
                      ) : (
                        row.value
                      )
                    }
                  />
                ))}
              </dl>

              {(finding.actions ?? []).length > 0 && (
                <div className="flex flex-wrap items-start gap-2">
                  {(finding.actions ?? []).map((action) => (
                    <DiagnosticActionButton
                      key={`${finding.finding_id}-${action.kind}-${action.target}`}
                      action={action}
                    />
                  ))}
                </div>
              )}
            </div>
          </div>
        </article>
      ))}
    </div>
  );
}

function DiagnosticRow({
  label,
  value,
}: {
  label: string;
  value: ReactNode;
}) {
  return (
    <div className="grid grid-cols-[96px_minmax(0,1fr)] gap-2">
      <dt className="uppercase tracking-wide text-ink-subtle">{label}</dt>
      <dd className="min-w-0 text-ink-muted truncate">{value}</dd>
    </div>
  );
}

function DiagnosticActionButton({ action }: { action: DiagnosticAction }) {
  if (action.kind === "route") {
    return (
      <Link to={action.target} className="btn text-xs py-1">
        {action.label}
      </Link>
    );
  }
  if (action.kind === "external") {
    return (
      <a
        href={action.target}
        target="_blank"
        rel="noreferrer"
        className="btn text-xs py-1"
      >
        {action.label}
      </a>
    );
  }
  return (
    <span className="inline-flex items-center gap-1">
      <code className="rounded border border-edge bg-panel-high px-2 py-1 text-[11px] text-ink">
        {action.target}
      </code>
      <CopyButton value={action.target} />
    </span>
  );
}

function severityBadge(severity: string): string {
  switch (severity) {
    case "critical":
      return "border-bad bg-bad-muted/30 text-bad";
    case "high":
      return "border-warn bg-warn-muted/30 text-warn";
    case "medium":
      return "border-info bg-info-muted/30 text-info";
    case "low":
      return "border-edge bg-panel-high text-ink-muted";
    default:
      return "border-edge bg-panel-high text-ink-muted";
  }
}

function severityBorder(severity: string): string {
  switch (severity) {
    case "critical":
      return "border-bad/50";
    case "high":
      return "border-warn/50";
    case "medium":
      return "border-info/40";
    default:
      return "border-edge";
  }
}
