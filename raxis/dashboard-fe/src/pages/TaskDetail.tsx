import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";

import { dashboardApi } from "@/api/client";
import { CopyButton } from "@/components/CopyButton";
import { Empty } from "@/components/Empty";
import { ErrorBox } from "@/components/ErrorBox";
import { FailureReasonPanel } from "@/components/FailureReasonPanel";
import { LifecycleTimeline } from "@/components/lifecycle/LifecycleTimeline";
import { ReviewerVerdictPanel } from "@/components/lifecycle/ReviewerVerdictPanel";
import { Mono } from "@/components/Mono";
import { PageSpinner } from "@/components/Spinner";
import { StateBadge } from "@/components/StateBadge";
import { TaskLlmTurns } from "@/components/TaskLlmTurns";
import { TaskWitnesses } from "@/components/TaskWitnesses";
import { TaskWorktreeSnapshots } from "@/components/TaskWorktreeSnapshots";
import { fmtAbsolute, fmtRelative } from "@/lib/format";
import {
  isTerminalFailureState,
  taskDisplayId,
} from "@/lib/state-color";
import type { CustomToolCallView } from "@/types/api";

export function TaskDetailPage() {
  const { id = "" } = useParams<{ id: string }>();

  const q = useQuery({
    queryKey: ["task", id],
    queryFn: ({ signal }) => dashboardApi.tasks.get(id, signal),
    refetchInterval: 4_000,
    enabled: id.length > 0,
  });
  const initiativeId = q.data?.initiative_id ?? "";
  const initiativeQ = useQuery({
    queryKey: ["initiative", initiativeId],
    queryFn: ({ signal }) => dashboardApi.initiatives.get(initiativeId, signal),
    enabled: initiativeId.length > 0,
    staleTime: 10_000,
  });

  if (q.isPending) return <PageSpinner />;
  if (q.error) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  const t = q.data;
  const initiativeName =
    t.initiative_display_name.trim() ||
    initiativeQ.data?.display_name?.trim() ||
    "Initiative";
  const customToolCalls = t.custom_tool_calls ?? [];

  return (
    <div className="space-y-5">
      <header className="flex items-start justify-between gap-4 flex-wrap">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-sm text-ink-subtle">
            <Link to="/initiatives" className="hover:text-accent">Workspaces</Link>
            <span>/</span>
            <Link
              to={`/initiatives/${t.initiative_id}`}
              className="hover:text-accent"
              title={t.initiative_id}
            >
              {initiativeName}
            </Link>
            <span>/</span>
            {/* INV-DASHBOARD-INTEGRATION-MERGE-VISIBLE-OR-EXCLUDED-01:
                render the stable `«integration-merge»` display id for
                the synthetic coordinator row instead of the verbatim
                initiative UUID. Copy + routing stay on `t.task_id` so
                wire identifiers remain stable. */}
            <Mono className="text-ink-muted">
              {taskDisplayId(t.task_id, t.initiative_id)}
            </Mono>
            <CopyButton value={t.task_id} />
          </div>
          <div className="mt-1 flex items-center gap-2 text-[11px] text-ink-subtle">
            <span>Workspace</span>
            <Mono>{t.initiative_id}</Mono>
            <CopyButton value={t.initiative_id} />
          </div>
          <h1 className="mt-1 text-xl font-semibold text-ink text-balance">
            {t.title}
          </h1>
          <div className="mt-2 flex items-center gap-2">
            <span className="badge bg-panel border-edge text-ink-muted">
              {t.agent_type}
            </span>
            <StateBadge
              state={
                t.is_active && t.state === "Admitted" ? "Running" : t.state
              }
              pulse={t.is_active || t.state === "Running"}
            />
            <span className="text-xs text-ink-subtle">
              created {fmtRelative(t.created_at)}
              {" · "}updated {fmtRelative(t.updated_at)}
            </span>
          </div>
        </div>
        {t.session_id && (
          <Link to={`/sessions/${t.session_id}`} className="btn-primary">
            Open session →
          </Link>
        )}
      </header>

      {(isTerminalFailureState(t.state) || t.failure) && (
        <FailureReasonPanel
          reason={t.failure ?? null}
          heading="Task failure reason"
        />
      )}

      {/* `<ReviewerVerdictPanel>` surfaces tasks.review_verdict +
          tasks.last_critique above the fold so the operator sees
          an iter62-style `Rejected` verdict immediately instead
          of having to drill into per-reviewer rows.
          `INV-DASHBOARD-LIFECYCLE-CAUSALITY-01`. */}
      <ReviewerVerdictPanel
        verdict={t.review_verdict ?? null}
        critique={t.last_critique ?? null}
        entries={t.reviewer_panel_results ?? []}
      />

      {/* Lifecycle timeline — retries, revokes, gaps in
          kernel-emit order. `INV-DASHBOARD-LIFECYCLE-CAUSALITY-01`. */}
      <LifecycleTimeline
        annotations={t.annotations ?? []}
        showEmpty={false}
        heading="Lifecycle timeline"
      />

      {t.blocked_downstream && t.blocked_downstream.length > 0 && (
        <section className="card border-warn/40 bg-warn/5 p-3 text-sm">
          <h2 className="text-xs uppercase tracking-wide text-warn font-medium">
            Downstream tasks blocked by this failure
          </h2>
          <ul className="mt-2 flex flex-wrap gap-2">
            {t.blocked_downstream.map((tid) => (
              <li key={tid}>
                <Link
                  to={`/tasks/${tid}`}
                  className="badge bg-warn-muted/30 border-warn text-warn hover:bg-warn hover:text-white font-mono text-[11px]"
                >
                  {tid}
                </Link>
              </li>
            ))}
          </ul>
        </section>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
        <section className="card p-4">
          <h2 className="text-sm font-semibold text-ink mb-3">Reviewer verdicts</h2>
          {t.reviewer_verdicts.length === 0 ? (
            <Empty
              title="No reviewer verdicts yet."
              hint="The reviewer driver will append verdicts here as they are emitted."
            />
          ) : (
            <ul className="space-y-3">
              {t.reviewer_verdicts.map((v, i) => (
                <li key={`${v.reviewer_session_id}-${i}`} className="border border-edge rounded p-3">
                  <div className="flex items-center justify-between gap-2">
                    <span
                      className={`badge ${
                        v.verdict.toLowerCase() === "approved"
                          ? "bg-ok-muted/30 border-ok text-ok"
                          : "bg-bad-muted/30 border-bad text-bad"
                      }`}
                    >
                      {v.verdict}
                    </span>
                    <span className="text-[11px] text-ink-subtle">
                      {fmtAbsolute(v.at)}
                    </span>
                  </div>
                  <Link
                    to={`/sessions/${v.reviewer_session_id}`}
                    className="text-xs text-accent hover:underline mt-1 inline-block"
                  >
                    <Mono>{v.reviewer_session_id}</Mono>
                  </Link>
                  {v.critique && (
                    <pre className="mt-2 text-[12px] whitespace-pre-wrap text-ink leading-relaxed font-sans">
                      {v.critique}
                    </pre>
                  )}
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="card p-4">
          <h2 className="text-sm font-semibold text-ink mb-3">Structured outputs</h2>
          {t.structured_outputs.length === 0 ? (
            <Empty
              title="No structured outputs."
              hint={<>Outputs land here when the executor calls <code className="font-mono">structured_output</code>.</>}
            />
          ) : (
            <ul className="space-y-3">
              {t.structured_outputs.map((o, i) => (
                <li key={i} className="border border-edge rounded p-3">
                  <div className="flex items-center justify-between gap-2">
                    <span className="badge bg-info-muted/30 border-info text-info">
                      {o.kind}
                    </span>
                    <span className="text-[11px] text-ink-subtle">
                      {fmtAbsolute(o.at)}
                    </span>
                  </div>
                  <pre className="mt-2 text-[11px] font-mono text-ink-muted overflow-x-auto overscroll-x-auto scroll-thin max-h-64">
                    {JSON.stringify(o.payload, null, 2)}
                  </pre>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>

      <CustomToolCallsPanel
        calls={customToolCalls}
        initiativeId={t.initiative_id}
      />

      {/* `<TaskLlmTurns>` consumes
          `GET /api/tasks/:task_id/llm-turns` and renders one
          collapsible card per turn with usage + cache-hit
          ratio colour coding. The endpoint exists today;
          rows arrive once the kernel-side tap is wired to
          pass `Some(task_id)` to `gateway.fetch(...)`. */}
      <TaskLlmTurns taskId={t.task_id} />

      {/* iter68 — `<TaskWitnesses>` renders every witness
          submission recorded against the task, newest first.
          Pulls from `GET /api/tasks/:id/witnesses`. */}
      <TaskWitnesses taskId={t.task_id} />

      {/* iter68 — `<TaskWorktreeSnapshots>` renders the
          per-task content-addressed snapshot timeline
          captured by `kernel::worktree_snapshot`. Each row
          is a point-in-time projection of the worktree
          (diff / log / tree / porcelain) the operator can
          drill into without re-running the executor.
          `specs/v3/worktree-snapshots.md`. */}
      <TaskWorktreeSnapshots taskId={t.task_id} />

      <section className="card p-4">
        <h2 className="text-sm font-semibold text-ink mb-3">Path scope (allowlist)</h2>
        {t.path_allowlist.length === 0 ? (
          <p className="text-xs text-ink-subtle">No paths in the allowlist.</p>
        ) : (
          <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
            {t.path_allowlist.map((p) => (
              <code
                key={p}
                className="font-mono text-[11px] px-2 py-1.5 rounded border border-edge bg-panel-high text-ink-muted truncate"
                title={p}
              >
                {p}
              </code>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}

function CustomToolCallsPanel({
  calls,
  initiativeId,
}: {
  calls: CustomToolCallView[];
  initiativeId: string;
}) {
  return (
    <section className="card p-4">
      <div className="flex items-center justify-between gap-3 mb-3">
        <div>
          <h2 className="text-sm font-semibold text-ink">Custom tool calls</h2>
          <p className="text-xs text-ink-subtle">
            Kernel-audited tool invocations for subprocesses and MCP-backed tools.
          </p>
        </div>
        <span className="text-xs text-ink-subtle tabular">
          {calls.length} {calls.length === 1 ? "call" : "calls"}
        </span>
      </div>
      {calls.length === 0 ? (
        <Empty
          title="No custom tool calls recorded."
          hint="Tool calls appear here when this task invokes a configured subprocess, host MCP, or remote MCP tool."
        />
      ) : (
        <ul className="space-y-3">
          {calls.map((call) => (
            <li key={`${call.seq}-${call.tool_name}`} className="border border-edge rounded p-3">
              <div className="flex items-start justify-between gap-3 flex-wrap">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={toolOutcomeBadge(call.outcome)}>
                      {call.outcome || "Unknown"}
                    </span>
                    <Mono className="text-sm">{call.tool_name}</Mono>
                    <span className="badge bg-panel-high border-edge text-ink-muted">
                      {call.execution_locality || "locality unknown"}
                    </span>
                  </div>
                  <div className="mt-1 flex items-center gap-2 flex-wrap text-[11px] text-ink-subtle">
                    <span>profile</span>
                    <Mono>{call.profile_name || "unknown"}</Mono>
                    <span>·</span>
                    <span>{fmtAbsolute(call.at)}</span>
                    <span>·</span>
                    <Link
                      to={`/audit?highlight_initiative_id=${encodeURIComponent(
                        initiativeId,
                      )}&search=${encodeURIComponent(
                        `CustomToolInvoked ${call.tool_name} ${call.seq}`,
                      )}`}
                      className="text-accent hover:underline"
                    >
                      Audit #{call.seq}
                    </Link>
                  </div>
                </div>
                <div className="text-right text-xs text-ink-muted tabular">
                  <div>{call.duration_ms} ms</div>
                  <div>timeout {call.timeout_ms} ms</div>
                </div>
              </div>

              <dl className="mt-3 grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                <ToolMetric label="Exit" value={formatExit(call)} />
                <ToolMetric
                  label="stdin"
                  value={`${call.stdin_bytes_total.toLocaleString()} B`}
                />
                <ToolMetric
                  label="stdout"
                  value={formatByteCapture(
                    call.stdout_bytes_captured,
                    call.stdout_bytes_total,
                    call.stdout_truncated,
                  )}
                />
                <ToolMetric
                  label="stderr"
                  value={formatByteCapture(
                    call.stderr_bytes_captured,
                    call.stderr_bytes_total,
                    call.stderr_truncated,
                  )}
                />
              </dl>

              {call.error && (
                <div className="mt-3 rounded border border-bad/40 bg-bad-muted/20 px-3 py-2 text-xs text-bad">
                  {call.error}
                </div>
              )}

              <div className="mt-3 grid grid-cols-1 md:grid-cols-3 gap-2 text-[11px]">
                <HashField label="argv sha" value={call.command_argv_sha256} />
                <HashField label="stdout sha" value={call.stdout_sha256} />
                <HashField label="stderr sha" value={call.stderr_sha256} />
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function ToolMetric({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="uppercase tracking-wide text-ink-subtle">{label}</dt>
      <dd className="mt-1 font-mono text-ink-muted">{value}</dd>
    </div>
  );
}

function HashField({ label, value }: { label: string; value: string }) {
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

function formatExit(call: CustomToolCallView): string {
  if (typeof call.exit_code === "number") return String(call.exit_code);
  if (typeof call.signal === "number") return `signal ${call.signal}`;
  return "n/a";
}

function formatByteCapture(captured: number, total: number, truncated: boolean): string {
  const body = `${captured.toLocaleString()} / ${total.toLocaleString()} B`;
  return truncated ? `${body} truncated` : body;
}

function shortHash(value: string): string {
  if (value.length <= 16) return value;
  return `${value.slice(0, 12)}…${value.slice(-8)}`;
}
