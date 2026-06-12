import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import clsx from "clsx";

import { dashboardApi } from "@/api/client";
import { CopyButton } from "@/components/CopyButton";
import { DiagnosticFindingsPanel } from "@/components/DiagnosticFindingsPanel";
import { Empty } from "@/components/Empty";
import { ErrorBox } from "@/components/ErrorBox";
import { Mono } from "@/components/Mono";
import { PageSpinner } from "@/components/Spinner";
import { StateBadge } from "@/components/StateBadge";
import { fmtAbsolute, fmtRelative } from "@/lib/format";
import type {
  DiagnosticFinding,
  SessionCaptureView,
  VmCommandDiagnosticView,
  VmDiagnosticsView,
  VmSessionDiagnosticView,
} from "@/types/api";

const DIAGNOSTICS_POLL_MS = 10_000;

type CaptureTarget = {
  sessionId: string;
  command?: VmCommandDiagnosticView;
};

export function DiagnosticsPage() {
  const [params, setParams] = useSearchParams();
  const initiativeId = params.get("initiative_id") ?? undefined;
  const severity = params.get("severity") ?? "all";
  const tab = params.get("tab") ?? "findings";

  const q = useQuery({
    queryKey: ["diagnostics", initiativeId ?? "all"],
    queryFn: ({ signal }) =>
      dashboardApi.diagnostics.list(
        { initiative_id: initiativeId, limit: 100 },
        signal,
      ),
    refetchInterval: DIAGNOSTICS_POLL_MS,
    refetchIntervalInBackground: true,
  });

  const findings = useMemo(() => q.data?.findings ?? [], [q.data?.findings]);
  const vm = q.data?.vm ?? { sessions: [], commands: [] };
  const counts = useMemo(() => countSeverities(findings), [findings]);
  const filtered = useMemo(() => {
    if (severity === "all") return findings;
    return findings.filter((f) => f.severity === severity);
  }, [findings, severity]);

  const setSeverity = (next: string) => {
    const sp = new URLSearchParams(params);
    if (next === "all") sp.delete("severity");
    else sp.set("severity", next);
    setParams(sp, { replace: true });
  };
  const setTab = (next: string) => {
    const sp = new URLSearchParams(params);
    if (next === "findings") sp.delete("tab");
    else sp.set("tab", next);
    setParams(sp, { replace: true });
  };

  if (q.isPending) return <PageSpinner />;
  if (q.error) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;

  return (
    <div className="space-y-5">
      <header className="flex items-start justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-xl font-semibold text-ink">Diagnostics</h1>
          <p className="text-sm text-ink-muted max-w-3xl">
            Root-cause hints assembled from health, policy validation, audit,
            notifications, sessions, and kernel logs. Use this when something
            failed and you need the next useful place to look.
          </p>
          {initiativeId && (
            <div className="mt-2 text-xs text-ink-subtle">
              Focused on initiative <Mono>{initiativeId}</Mono>
            </div>
          )}
        </div>
        <div className="text-right text-xs text-ink-subtle">
          <div>Auto-refresh {Math.round(DIAGNOSTICS_POLL_MS / 1000)}s</div>
          <div title={fmtAbsolute(q.data?.generated_at ?? 0)}>
            Generated {fmtRelative(q.data?.generated_at ?? 0)}
          </div>
          {q.isFetching && <div className="text-accent">refreshing…</div>}
        </div>
      </header>

      <section className="card p-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <TabButton
              active={tab === "findings"}
              onClick={() => setTab("findings")}
              label="Findings"
              count={findings.length}
            />
            <TabButton
              active={tab === "vm"}
              onClick={() => setTab("vm")}
              label="VM"
              count={vm.commands.length + vm.sessions.length}
            />
          </div>
          {tab === "findings" && (
            <div className="flex flex-wrap items-center gap-2">
              {["all", "critical", "high", "medium", "low"].map((s) => (
                <button
                  key={s}
                  type="button"
                  onClick={() => setSeverity(s)}
                  className={clsx(
                    "btn text-xs py-1 capitalize",
                    severity === s && "border-accent text-accent bg-accent/10",
                  )}
                >
                  {s}{" "}
                  <span className="text-ink-subtle">
                    {s === "all" ? findings.length : counts[s] ?? 0}
                  </span>
                </button>
              ))}
            </div>
          )}
        </div>
      </section>

      {tab === "vm" ? (
        <VmDiagnosticsPanel vm={vm} />
      ) : (
        <DiagnosticFindingsPanel findings={filtered} />
      )}
    </div>
  );
}

function countSeverities(findings: DiagnosticFinding[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const finding of findings) {
    out[finding.severity] = (out[finding.severity] ?? 0) + 1;
  }
  return out;
}

function TabButton({
  active,
  onClick,
  label,
  count,
}: {
  active: boolean;
  onClick: () => void;
  label: string;
  count: number;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={clsx(
        "btn text-xs py-1.5",
        active && "border-accent text-accent bg-accent/10",
      )}
    >
      {label} <span className="text-ink-subtle">{count}</span>
    </button>
  );
}

function VmDiagnosticsPanel({ vm }: { vm: VmDiagnosticsView }) {
  const [captureTarget, setCaptureTarget] = useState<CaptureTarget | null>(null);

  return (
    <div className="space-y-5">
      <section className="card p-4">
        <div className="flex items-start justify-between gap-3 flex-wrap">
          <div>
            <h2 className="text-sm font-semibold text-ink">VM sessions</h2>
            <p className="text-xs text-ink-subtle max-w-3xl">
              Recent active and historical VM-backed sessions. Open a session
              for stream capture, LLM turns, environment visibility, and
              post-mortem detail.
            </p>
          </div>
          <span className="text-xs text-ink-subtle tabular">
            {vm.sessions.length} {vm.sessions.length === 1 ? "session" : "sessions"}
          </span>
        </div>
        {vm.sessions.length === 0 ? (
          <Empty
            title="No VM sessions found."
            hint="Sessions appear after the kernel spawns an orchestrator, executor, reviewer, or verifier VM."
          />
        ) : (
          <ul className="mt-3 divide-y divide-edge border border-edge rounded">
            {vm.sessions.map((session) => (
              <VmSessionRow
                key={session.session_id}
                session={session}
                onOpenCapture={() =>
                  setCaptureTarget({ sessionId: session.session_id })
                }
              />
            ))}
          </ul>
        )}
      </section>

      <section className="card p-4">
        <div className="flex items-start justify-between gap-3 flex-wrap">
          <div>
            <h2 className="text-sm font-semibold text-ink">VM command and tool activity</h2>
            <p className="text-xs text-ink-subtle max-w-3xl">
              Audit-backed command telemetry for guest subprocesses, host
              subprocesses, host MCP, and remote MCP calls. This view shows
              outcomes, captured byte counts, hashes, truncation flags, and
              structured errors; raw output bodies remain scoped to capture or
              artifact surfaces.
            </p>
          </div>
          <span className="text-xs text-ink-subtle tabular">
            {vm.commands.length} {vm.commands.length === 1 ? "call" : "calls"}
          </span>
        </div>
        {vm.commands.length === 0 ? (
          <Empty
            title="No command telemetry recorded."
            hint="Custom tools and MCP calls appear here once the kernel emits CustomToolInvoked audit rows."
          />
        ) : (
          <ul className="mt-3 space-y-3">
            {vm.commands.map((command) => (
              <VmCommandCard
                key={`${command.seq}-${command.event_id}`}
                command={command}
                onOpenCapture={
                  command.session_id
                    ? () =>
                        setCaptureTarget({
                          sessionId: command.session_id ?? "",
                          command,
                        })
                    : undefined
                }
              />
            ))}
          </ul>
        )}
      </section>

      {captureTarget && (
        <CaptureArtifactViewer
          target={captureTarget}
          onClose={() => setCaptureTarget(null)}
        />
      )}
    </div>
  );
}

function VmSessionRow({
  session,
  onOpenCapture,
}: {
  session: VmSessionDiagnosticView;
  onOpenCapture: () => void;
}) {
  return (
    <li className="p-3">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="badge bg-panel-high border-edge text-ink-muted">
              {session.role}
            </span>
            <StateBadge state={session.state} />
            <Link
              to={`/sessions/${session.session_id}`}
              className="text-accent hover:underline font-mono text-xs break-all"
            >
              {shortId(session.session_id)}
            </Link>
            <CopyButton value={session.session_id} />
          </div>
          <div className="mt-1 flex items-center gap-2 flex-wrap text-[11px] text-ink-subtle">
            {session.initiative_id && (
              <Link
                to={`/initiatives/${session.initiative_id}`}
                className="text-accent hover:underline"
              >
                {session.initiative_display_name?.trim() || shortId(session.initiative_id)}
              </Link>
            )}
            {session.task_id && (
              <>
                <span>·</span>
                <Link
                  to={`/tasks/${session.task_id}`}
                  className="text-accent hover:underline"
                >
                  {session.task_name?.trim() || shortId(session.task_id)}
                </Link>
              </>
            )}
            <span>·</span>
            <span>updated {fmtRelative(session.updated_at)}</span>
          </div>
        </div>
        <div className="text-xs text-ink-muted tabular text-right space-y-2">
          <div>
            <div>{session.provider || "provider unknown"}</div>
            <div>{session.model || "model unknown"}</div>
            <div>
              in {session.input_tokens.toLocaleString()} · out{" "}
              {session.output_tokens.toLocaleString()}
            </div>
          </div>
          <button type="button" className="btn text-xs py-1" onClick={onOpenCapture}>
            Open capture
          </button>
        </div>
      </div>
    </li>
  );
}

function VmCommandCard({
  command,
  onOpenCapture,
}: {
  command: VmCommandDiagnosticView;
  onOpenCapture?: () => void;
}) {
  return (
    <li className="border border-edge rounded p-3">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={toolOutcomeBadge(command.outcome)}>
              {command.outcome || "Unknown"}
            </span>
            <Mono className="text-sm break-all">{command.tool_name}</Mono>
            <span className="badge bg-panel-high border-edge text-ink-muted">
              {command.execution_locality || "locality unknown"}
            </span>
          </div>
          <div className="mt-1 flex items-center gap-2 flex-wrap text-[11px] text-ink-subtle">
            <span>profile</span>
            <Mono>{command.profile_name || "unknown"}</Mono>
            <span>·</span>
            <span>{fmtAbsolute(command.at)}</span>
            {command.session_id && (
              <>
                <span>·</span>
                <Link
                  to={`/sessions/${command.session_id}`}
                  className="text-accent hover:underline"
                >
                  session {shortId(command.session_id)}
                </Link>
              </>
            )}
            {command.task_id && (
              <>
                <span>·</span>
                <Link
                  to={`/tasks/${command.task_id}`}
                  className="text-accent hover:underline"
                >
                  {command.task_name?.trim() || shortId(command.task_id)}
                </Link>
              </>
            )}
            <span>·</span>
            <Link
              to={`/audit?search=${encodeURIComponent(
                command.event_id || `CustomToolInvoked ${command.seq}`,
              )}`}
              className="text-accent hover:underline"
            >
              Audit #{command.seq}
            </Link>
          </div>
        </div>
        <div className="text-right text-xs text-ink-muted tabular space-y-2">
          <div>
            <div>{command.duration_ms.toLocaleString()} ms</div>
            <div>timeout {command.timeout_ms.toLocaleString()} ms</div>
          </div>
          {onOpenCapture && (
            <button
              type="button"
              className="btn text-xs py-1"
              onClick={onOpenCapture}
            >
              Open capture
            </button>
          )}
        </div>
      </div>

      <dl className="mt-3 grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
        <Metric label="Exit" value={formatExit(command)} />
        <Metric label="stdin" value={formatBytes(command.stdin_bytes_total)} />
        <Metric
          label="stdout"
          value={formatByteCapture(
            command.stdout_bytes_captured,
            command.stdout_bytes_total,
            command.stdout_truncated,
          )}
        />
        <Metric
          label="stderr"
          value={formatByteCapture(
            command.stderr_bytes_captured,
            command.stderr_bytes_total,
            command.stderr_truncated,
          )}
        />
      </dl>

      {command.error && (
        <div className="mt-3 rounded border border-bad/40 bg-bad-muted/20 px-3 py-2 text-xs text-bad whitespace-pre-wrap break-words">
          {command.error}
        </div>
      )}

      <div className="mt-3 grid grid-cols-1 md:grid-cols-3 gap-2 text-[11px]">
        <HashField label="argv sha" value={command.command_argv_sha256} />
        <HashField label="stdout sha" value={command.stdout_sha256} />
        <HashField label="stderr sha" value={command.stderr_sha256} />
      </div>
    </li>
  );
}

function CaptureArtifactViewer({
  target,
  onClose,
}: {
  target: CaptureTarget;
  onClose: () => void;
}) {
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
      }
    };
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    window.addEventListener("keydown", onKeyDown);
    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [onClose]);

  const q = useQuery({
    queryKey: ["diagnostics-session-capture", target.sessionId],
    queryFn: ({ signal }) =>
      dashboardApi.sessions.capture(target.sessionId, { limit: 500 }, signal),
    enabled: target.sessionId.length > 0,
    staleTime: 1_000,
  });
  const records = q.data ?? [];
  const command = target.command;
  const matching = command
    ? records.filter((record) => captureMatchesCommand(record, command))
    : records;
  const displayRecords = command && matching.length > 0 ? matching : records;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/45 p-4"
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="diagnostics-capture-title"
        className="card flex max-h-[min(88vh,900px)] w-full max-w-6xl flex-col overflow-hidden p-0 shadow-xl"
      >
        <header className="shrink-0 border-b border-edge px-4 py-3">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <h2
                id="diagnostics-capture-title"
                className="text-sm font-semibold text-ink"
              >
                Capture / artifacts
              </h2>
              <p className="mt-1 text-xs text-ink-subtle max-w-3xl">
                Session capture records persisted by the kernel, plus retained
                command evidence. Use this when you need to diagnose what
                happened inside the VM boundary without opening raw kernel logs.
              </p>
              <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px] text-ink-subtle">
                <span>session</span>
                <Link
                  to={`/sessions/${target.sessionId}`}
                  className="text-accent hover:underline font-mono break-all"
                >
                  {target.sessionId}
                </Link>
                <CopyButton value={target.sessionId} />
                {target.command && (
                  <>
                    <span>·</span>
                    <span>command</span>
                    <Mono>{target.command.tool_name}</Mono>
                    <span>·</span>
                    <Link
                      to={`/audit?search=${encodeURIComponent(
                        target.command.event_id ||
                          `CustomToolInvoked ${target.command.seq}`,
                      )}`}
                      className="text-accent hover:underline"
                    >
                      Audit #{target.command.seq}
                    </Link>
                  </>
                )}
              </div>
            </div>
            <button type="button" className="btn text-xs py-1" onClick={onClose}>
              Close
            </button>
          </div>
        </header>

        <div className="min-h-0 flex-1 overflow-y-auto">
          {target.command && <CommandArtifactSummary command={target.command} />}

          <div className="px-4 py-3 border-t border-edge/60">
            <div className="flex items-center justify-between gap-3 flex-wrap">
              <h3 className="text-xs font-semibold uppercase tracking-wide text-ink-muted">
                Session capture records
              </h3>
              <span className="text-[11px] text-ink-subtle tabular">
                {q.isFetching
                  ? "refreshing"
                  : `${displayRecords.length} shown${
                      target.command && matching.length > 0
                        ? ` · ${records.length} total`
                        : ""
                    }`}
              </span>
            </div>
            {q.isPending ? (
              <div className="mt-3 text-sm text-ink-muted">Loading capture…</div>
            ) : q.error ? (
              <div className="mt-3">
                <ErrorBox error={q.error} onRetry={() => q.refetch()} />
              </div>
            ) : displayRecords.length === 0 ? (
              <Empty
                title="No capture records retained."
                hint="The session capture ring may not have been wired for this kernel, or the bounded ring may have rolled."
              />
            ) : (
              <ul className="mt-3 divide-y divide-edge/40 border border-edge rounded overflow-hidden">
                {displayRecords.map((record, idx) => (
                  <CaptureRecordRow
                    key={`${record.ts_unix}-${idx}`}
                    record={record}
                    highlighted={
                      !!target.command &&
                      captureMatchesCommand(record, target.command)
                    }
                  />
                ))}
              </ul>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function CommandArtifactSummary({ command }: { command: VmCommandDiagnosticView }) {
  return (
    <div className="px-4 py-3 bg-panel-high/60">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-ink-muted">
        Command evidence
      </h3>
      <div className="mt-3 grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
        <StreamEvidence
          label="stdin"
          total={command.stdin_bytes_total}
          captured={command.stdin_bytes_total}
          sha={command.stdin_sha256}
          truncated={false}
        />
        <StreamEvidence
          label="stdout"
          total={command.stdout_bytes_total}
          captured={command.stdout_bytes_captured}
          sha={command.stdout_sha256}
          truncated={command.stdout_truncated}
        />
        <StreamEvidence
          label="stderr"
          total={command.stderr_bytes_total}
          captured={command.stderr_bytes_captured}
          sha={command.stderr_sha256}
          truncated={command.stderr_truncated}
        />
      </div>
      <p className="mt-3 text-xs text-ink-subtle leading-relaxed">
        This binary records stream sizes, retained-byte counts, truncation
        state, hashes, and structured errors in the audit chain. Raw stdout and
        stderr bodies are not yet retained by the custom-tool IPC envelope; once
        that retention lands, this viewer is where the scoped body preview will
        appear.
      </p>
      {command.error && (
        <div className="mt-3 rounded border border-bad/40 bg-bad-muted/20 px-3 py-2 text-xs text-bad whitespace-pre-wrap break-words">
          {command.error}
        </div>
      )}
    </div>
  );
}

function StreamEvidence({
  label,
  total,
  captured,
  sha,
  truncated,
}: {
  label: string;
  total: number;
  captured: number;
  sha: string;
  truncated: boolean;
}) {
  return (
    <div className="rounded border border-edge bg-panel px-3 py-2 min-w-0">
      <div className="flex items-center justify-between gap-2">
        <span className="uppercase tracking-wide text-ink-subtle">{label}</span>
        {truncated && (
          <span className="badge bg-warn-muted/30 border-warn text-warn">
            truncated
          </span>
        )}
      </div>
      <div className="mt-2 font-mono text-ink-muted">
        {formatByteCapture(captured, total, truncated)}
      </div>
      {sha && (
        <div className="mt-2 flex items-center gap-1 min-w-0 text-[11px]">
          <Mono className="truncate">{shortHash(sha)}</Mono>
          <CopyButton value={sha} />
        </div>
      )}
    </div>
  );
}

function CaptureRecordRow({
  record,
  highlighted,
}: {
  record: SessionCaptureView;
  highlighted: boolean;
}) {
  return (
    <li
      className={clsx(
        "px-3 py-2.5 flex items-start gap-3",
        highlighted && "bg-accent/5",
      )}
    >
      <Mono className="text-[11px] text-ink-subtle w-32 shrink-0 mt-1">
        {fmtAbsolute(record.ts_unix)}
      </Mono>
      <span
        className={clsx(
          "badge text-[11px] shrink-0",
          record.kind === "audit_event"
            ? "bg-panel border-edge text-ink"
            : record.kind === "fsm_transition"
              ? "bg-accent/15 border-accent/30 text-accent"
              : "bg-panel-high border-edge text-ink-muted",
        )}
      >
        {record.kind}
      </span>
      <div className="flex-1 min-w-0">
        <div className="flex flex-wrap items-center gap-2 text-[11px] text-ink-subtle">
          {typeof record.payload.event_kind === "string" && (
            <Mono>{record.payload.event_kind}</Mono>
          )}
          {typeof record.payload.seq === "number" && (
            <span>audit #{record.payload.seq}</span>
          )}
          {typeof record.payload.event_id === "string" && (
            <Mono>{shortId(record.payload.event_id)}</Mono>
          )}
        </div>
        <pre className="mt-1 text-[11px] text-ink-muted whitespace-pre-wrap break-words leading-snug font-mono min-w-0">
          {JSON.stringify(record.payload, null, 2)}
        </pre>
      </div>
    </li>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="uppercase tracking-wide text-ink-subtle">{label}</dt>
      <dd className="mt-1 font-mono text-ink-muted break-words">{value}</dd>
    </div>
  );
}

function HashField({ label, value }: { label: string; value?: string | null }) {
  if (!value) return null;
  return (
    <div className="rounded border border-edge bg-panel-high px-2 py-1.5 min-w-0">
      <div className="text-ink-subtle uppercase tracking-wide">{label}</div>
      <div className="mt-1 flex items-center gap-1 min-w-0">
        <Mono className="truncate">{shortHash(value)}</Mono>
        <CopyButton value={value} />
      </div>
    </div>
  );
}

function toolOutcomeBadge(outcome: string) {
  const normalized = outcome.toLowerCase();
  if (normalized === "success" || normalized === "passed") {
    return "badge bg-ok-muted/30 border-ok text-ok";
  }
  if (normalized.includes("timeout") || normalized.includes("timed")) {
    return "badge bg-warn-muted/30 border-warn text-warn";
  }
  if (normalized.includes("fail") || normalized.includes("error")) {
    return "badge bg-bad-muted/30 border-bad text-bad";
  }
  return "badge bg-panel-high border-edge text-ink-muted";
}

function formatExit(command: VmCommandDiagnosticView): string {
  if (typeof command.exit_code === "number") return String(command.exit_code);
  if (typeof command.signal === "number") return `signal ${command.signal}`;
  return "n/a";
}

function formatByteCapture(captured: number, total: number, truncated: boolean): string {
  const body = `${formatBytes(captured)} / ${formatBytes(total)}`;
  return truncated ? `${body} truncated` : body;
}

function formatBytes(value: number): string {
  return `${value.toLocaleString()} B`;
}

function captureMatchesCommand(
  record: SessionCaptureView,
  command: VmCommandDiagnosticView,
): boolean {
  const payload = record.payload ?? {};
  return (
    payload.event_id === command.event_id ||
    payload.seq === command.seq ||
    payload.audit_seq === command.seq
  );
}

function shortHash(value: string): string {
  if (value.length <= 16) return value;
  return `${value.slice(0, 12)}…${value.slice(-8)}`;
}

function shortId(value: string): string {
  if (value.length <= 16) return value;
  return `${value.slice(0, 8)}…${value.slice(-4)}`;
}
