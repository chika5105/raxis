import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import clsx from "clsx";

import { dashboardApi } from "@/api/client";
import { CopyButton } from "@/components/CopyButton";
import { CredentialsView } from "@/components/CredentialsView";
import { DiagnosticFindingsPanel } from "@/components/DiagnosticFindingsPanel";
import { useOperatorRoles } from "@/components/useOperatorRoles";
import { DagGraph, type DagGraphNode } from "@/components/DagGraph";
import { Empty } from "@/components/Empty";
import { ErrorBox } from "@/components/ErrorBox";
import {
  FailurePill,
  FailureReasonPanel,
} from "@/components/FailureReasonPanel";
import { InitiativePlanView } from "@/components/InitiativePlanView";
import {
  lifecycleDotClass,
  lifecycleSummary,
} from "@/components/lifecycle/LifecycleAnnotation";
import { Mono } from "@/components/Mono";
import { PageSpinner } from "@/components/Spinner";
import { StateBadge } from "@/components/StateBadge";
import {
  isIntegrationMergeTask,
  isTerminalFailureState,
  effectiveTaskState,
  orderedTaskStatusCounts,
  taskDisplayId,
  toneClasses,
  type StateBadgeTone,
} from "@/lib/state-color";
import {
  StatusFilterPills,
  StatusLegend,
} from "@/components/StatusLegend";
import {
  fmtAbsolute,
  fmtRelative,
  fmtTokens,
  plural,
  shortFingerprint,
  shortSha,
} from "@/lib/format";
import {
  parseStatusParam,
  serializeStatusParam,
  toggleStatus,
} from "@/lib/status-filter";
import type {
  DagNode,
  InitiativeRunSummary,
  TaskView,
  WorktreeSnapshotView,
} from "@/types/api";

/// Project an initiative's `TaskView[]` payload onto the
/// minimal `DagGraphNode[]` shape the embedded DAG renderer
/// consumes. Kept as a named, exported helper (not inlined
/// inside the JSX) so the regression test in
/// `dashboard-fe/src/test/initiative-detail-dag-bridge.test.ts`
/// can assert the bridge preserves `is_active` — the field
/// whose absence on iter69 caused every actively-executing
/// task to render as a static `Admitted` chip in the DAG. The
/// renderer itself already lifts `Admitted + is_active` to
/// `Running` (see `DagGraph::effectiveState`); the bug was
/// the page never forwarding the flag.
///
/// We deliberately copy ONLY the fields the renderer reads:
/// every extra field would dilute the contract this helper
/// pins. New visual signals (gate dots, error pills, …) are
/// added here field-by-field as the DAG renderer learns to
/// consume them.
// eslint-disable-next-line react-refresh/only-export-components
export function mapTasksToDagNodes(tasks: TaskView[]): DagGraphNode[] {
  return tasks.map((t) => ({
    task_id: t.task_id,
    task_name: t.task_name,
    title: t.title,
    agent_type: t.agent_type,
    state: t.state,
    is_active: t.is_active,
    review_verdict: t.review_verdict,
    review_reject_count: t.review_reject_count,
    max_review_rejections: t.max_review_rejections,
    review_retry_exhausted: t.review_retry_exhausted,
  }));
}

export function InitiativeDetailPage() {
  const { id = "" } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [selectedTask, setSelectedTask] = useState<string | null>(null);
  const [taskSearch, setTaskSearch] = useState("");

  // URL-driven status filter — same `?status=Running,Completed`
  // shape as the rest of the dashboard. Reads survive reload and
  // are copy-link-shareable; other URL params (focus, future
  // additions) are preserved across toggles.
  const [searchParams, setSearchParams] = useSearchParams();
  const activeStatuses = useMemo(
    () => parseStatusParam(searchParams.get("status")),
    [searchParams],
  );

  // Plan-panel open/closed state. Driven by `?plan=open` so the
  // "Plan TOML" affordance is link-shareable: an operator can
  // paste a URL with the panel pre-expanded into a postmortem.
  // Default-collapsed keeps the page light for operators who are
  // mostly here for the DAG / task tables.
  const planPanelOpen = searchParams.get("plan") === "open";
  const togglePlanPanel = () => {
    const sp = new URLSearchParams(searchParams);
    if (planPanelOpen) sp.delete("plan");
    else sp.set("plan", "open");
    setSearchParams(sp, { replace: true });
  };

  // Credentials panel — same `?credentials=open` URL-driven
  // pattern so an operator can deep-link into the masked
  // listing for a given initiative. Default-collapsed both
  // because credentials are a low-frequency surface AND
  // because rendering the listing audits it
  // (`OperatorListedCredentials`); we don't want every
  // initiative-detail visit to bake a row.
  const credentialsPanelOpen = searchParams.get("credentials") === "open";
  const toggleCredentialsPanel = () => {
    const sp = new URLSearchParams(searchParams);
    if (credentialsPanelOpen) sp.delete("credentials");
    else sp.set("credentials", "open");
    setSearchParams(sp, { replace: true });
  };
  const summaryPanelOpen = searchParams.get("summary") !== "closed";
  const toggleSummaryPanel = () => {
    const sp = new URLSearchParams(searchParams);
    if (summaryPanelOpen) sp.set("summary", "closed");
    else sp.delete("summary");
    setSearchParams(sp, { replace: true });
  };
  const diagnosisPanelOpen = searchParams.get("diagnosis") !== "closed";
  const toggleDiagnosisPanel = () => {
    const sp = new URLSearchParams(searchParams);
    if (diagnosisPanelOpen) sp.set("diagnosis", "closed");
    else sp.delete("diagnosis");
    setSearchParams(sp, { replace: true });
  };
  const operatorRoles = useOperatorRoles();
  const writeStatuses = (next: string[]) => {
    const sp = new URLSearchParams(searchParams);
    if (next.length === 0) sp.delete("status");
    else sp.set("status", serializeStatusParam(next));
    setSearchParams(sp, { replace: true });
  };
  const handleToggle = (status: string, multiSelect: boolean) =>
    writeStatuses(toggleStatus(activeStatuses, status, multiSelect));
  const handleClear = () => writeStatuses([]);
  const handleRemove = (status: string) =>
    writeStatuses(activeStatuses.filter((s) => s !== status));

  const q = useQuery({
    queryKey: ["initiative", id],
    queryFn: ({ signal }) => dashboardApi.initiatives.get(id, signal),
    refetchInterval: 4_000,
    enabled: id.length > 0,
  });
  const dagQ = useQuery({
    queryKey: ["initiative-dag", id],
    queryFn: ({ signal }) => dashboardApi.initiatives.dag(id, signal),
    refetchInterval: 4_000,
    enabled: id.length > 0,
  });
  const diagnosticsQ = useQuery({
    queryKey: ["diagnostics", "initiative", id],
    queryFn: ({ signal }) =>
      dashboardApi.diagnostics.list({ initiative_id: id, limit: 6 }, signal),
    refetchInterval: 10_000,
    enabled: id.length > 0,
  });

  // Per-task-state counts for the legend. Computed even when the
  // query is pending so hook order stays stable; the early returns
  // below short-circuit before render.
  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const t of q.data?.tasks ?? []) {
      const state = effectiveTaskState(t.state, t.is_active);
      c[state] = (c[state] ?? 0) + 1;
    }
    return c;
  }, [q.data]);

  if (q.isPending) return <PageSpinner />;
  if (q.error) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  const init = q.data;
  const integrationDagNodes = dagQ.data?.nodes ?? [];
  const dagGraphNodes = dagQ.data?.nodes ?? mapTasksToDagNodes(init.tasks);
  const dagEdges = dagQ.data?.edges ?? init.edges;
  const diagnosticFindings = diagnosticsQ.data?.findings ?? [];
  const focusedTask =
    selectedTask && init.tasks.find((t) => t.task_id === selectedTask);
  const activeSet = new Set(activeStatuses);
  const filterActive = activeStatuses.length > 0;
  const taskSearchNeedle = taskSearch.trim().toLowerCase();
  const taskSearchFiltered = taskSearchNeedle
    ? init.tasks.filter((t) =>
        [
          t.task_id,
          t.task_name ?? "",
          t.title,
          t.agent_type,
          t.state,
          effectiveTaskState(t.state, t.is_active),
          t.session_id ?? "",
        ]
          .join(" ")
          .toLowerCase()
          .includes(taskSearchNeedle),
      )
    : init.tasks;

  return (
    <div className="space-y-5">
      <header className="flex items-start gap-4 flex-wrap">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 text-sm text-ink-subtle">
            <Link to="/initiatives" className="hover:text-accent">
              Initiatives
            </Link>
            <span>/</span>
            <Mono className="text-ink-muted">{init.initiative_id}</Mono>
            <CopyButton value={init.initiative_id} />
          </div>
          <h1 className="mt-1 text-xl font-semibold text-ink text-balance">
            {init.display_name}
          </h1>
          <div className="mt-2 flex flex-wrap gap-2 items-center">
            <StateBadge state={init.state} pulse={init.state === "Active"} />
            <span className="text-xs text-ink-muted">
              {plural(init.task_count, "task")} · {init.completed_tasks} done
              {init.failed_tasks > 0 && (
                <span className="text-bad"> · {init.failed_tasks} failed</span>
              )}
            </span>
            <span className="text-xs text-ink-subtle">
              · created {fmtRelative(init.created_at)}
            </span>
            <span className="text-xs text-ink-subtle">
              · updated {fmtRelative(init.updated_at)}
            </span>
          </div>
        </div>

        <div className="card p-3 text-xs space-y-1.5 min-w-[220px]">
          <Row label="Approved by" value={init.approved_by ?? "—"} mono />
          <Row label="Plan SHA" value={shortSha(init.plan_sha256)} mono />
          <Row label="Target ref" value={init.target_ref ?? "—"} mono />
          <Row label="Policy epoch" value={`#${init.policy_epoch}`} />
        </div>
      </header>

      {(isTerminalFailureState(init.state) || init.failure) && (
        <FailureReasonPanel
          reason={init.failure ?? null}
          heading="Initiative failure reason"
        />
      )}

      <InitiativeRunSummaryCard
        summary={init.run_summary}
        open={summaryPanelOpen}
        onToggle={toggleSummaryPanel}
      />

      {diagnosticFindings.length > 0 && (
        <section className="space-y-2">
          <header className="flex items-center justify-between gap-3">
            <button
              type="button"
              onClick={toggleDiagnosisPanel}
              aria-expanded={diagnosisPanelOpen}
              aria-controls="initiative-diagnosis-panel"
              className="group flex min-w-0 flex-1 items-start gap-2 rounded text-left focus:outline-none focus-visible:ring-1 focus-visible:ring-accent"
            >
              <span
                aria-hidden
                className="mt-0.5 text-ink-subtle group-hover:text-ink"
              >
                {diagnosisPanelOpen ? "▾" : "▸"}
              </span>
              <span className="min-w-0">
                <span className="flex items-center gap-2">
                  <h2 className="text-sm font-semibold text-ink">Diagnosis</h2>
                  <span className="badge bg-panel-high border-edge text-ink-subtle">
                    {diagnosticFindings.length}
                  </span>
                </span>
                <span className="block text-xs text-ink-muted">
                  Active root-cause hints for this initiative.
                </span>
              </span>
            </button>
            <div className="flex items-center gap-3 text-xs">
              <button
                type="button"
                onClick={toggleDiagnosisPanel}
                className="text-ink-subtle hover:text-ink"
              >
                {diagnosisPanelOpen ? "Collapse" : "Expand"}
              </button>
              <Link
                to={`/diagnostics?initiative_id=${encodeURIComponent(init.initiative_id)}`}
                className="text-accent hover:underline"
              >
                Open diagnostics →
              </Link>
            </div>
          </header>
          {diagnosisPanelOpen && (
            <div id="initiative-diagnosis-panel">
              <DiagnosticFindingsPanel
                findings={diagnosticFindings.slice(0, 3)}
                compact
              />
            </div>
          )}
        </section>
      )}

      <InitiativeIntegrationState
        initiativeId={init.initiative_id}
        tasks={init.tasks}
        dagNodes={integrationDagNodes}
      />

      {/* Clickable status legend — drives a URL-stored `?status=`
       * filter that dims non-matching rows in the task table and
       * fades non-matching nodes in the DAG. Cmd/Ctrl-click for
       * multi-select. */}
      {init.tasks.length > 0 && (
        <section
          className="card px-4 py-3 flex flex-wrap items-center gap-x-4 gap-y-2"
          aria-label="Task status legend"
        >
          <StatusLegend
            counts={orderedTaskStatusCounts(counts)}
            activeStatuses={activeStatuses}
            onToggle={handleToggle}
            onClear={handleClear}
            itemNoun="task"
          />
          {filterActive && (
            <span className="text-[11px] text-ink-subtle">
              · non-matching rows dimmed · Cmd-click for multi-select
            </span>
          )}
        </section>
      )}

      {filterActive && (
        <StatusFilterPills
          activeStatuses={activeStatuses}
          onRemove={handleRemove}
          onClearAll={handleClear}
        />
      )}

      {/* DAG */}
      <section className="card p-4">
        <header className="flex items-center justify-between mb-2 gap-2 flex-wrap">
          <h2 className="text-sm font-semibold text-ink">Task DAG</h2>
          <div className="flex items-center gap-3 text-[11px] text-ink-subtle">
            <span>Click to focus · double-click to open task</span>
            <Link
              to={`/initiatives/${init.initiative_id}/dag`}
              className="text-accent hover:underline"
            >
              Full DAG view →
            </Link>
          </div>
        </header>
        {init.tasks.length === 0 ? (
          <Empty title="This initiative has no tasks." />
        ) : (
          <DagGraph
            // Prefer the dedicated DAG endpoint when available: it
            // carries per-node witness / integration gate summaries
            // that the initiative task list intentionally omits.
            // Fallback stays on `mapTasksToDagNodes` so the page
            // degrades to the old task-only DAG if that side query
            // fails.
            nodes={dagGraphNodes}
            edges={dagEdges}
            onSelect={setSelectedTask}
            onActivate={(taskId) => navigate(`/tasks/${taskId}`)}
            selected={selectedTask}
            height={Math.min(640, 80 + init.tasks.length * 40)}
            activeStates={activeStatuses}
            hideLegend
          />
        )}
      </section>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
        {/* Task list */}
        <section className="card p-0 overflow-hidden xl:col-span-2">
          <header className="px-4 py-3 border-b border-edge flex items-center justify-between gap-3 flex-wrap">
            <div>
              <h2 className="text-sm font-semibold text-ink">Tasks</h2>
              <span className="text-xs text-ink-subtle">
                {taskSearchNeedle
                  ? `${plural(taskSearchFiltered.length, "match", "matches")} of ${plural(init.tasks.length, "task")}`
                  : plural(init.tasks.length, "task")}
              </span>
            </div>
            <input
              className="input h-8 w-full sm:w-72 text-xs"
              placeholder="Search task name, runtime id, state…"
              value={taskSearch}
              onChange={(e) => setTaskSearch(e.target.value)}
            />
          </header>
          {init.tasks.length === 0 ? (
            <Empty title="No tasks." />
          ) : taskSearchFiltered.length === 0 ? (
            <Empty title="No tasks match your search." />
          ) : (
            <table className="w-full text-sm">
              <thead className="text-xs text-ink-subtle">
                <tr className="border-b border-edge">
                  <th className="text-left px-4 py-2 font-medium">Task</th>
                  <th className="text-left px-4 py-2 font-medium">State</th>
                  <th className="text-left px-4 py-2 font-medium">Session</th>
                  {/* Lifecycle column rendered from
                      `task.latest_annotation` —
                      `INV-DASHBOARD-LIFECYCLE-CAUSALITY-01`. */}
                  <th className="text-left px-4 py-2 font-medium">Lifecycle</th>
                  <th className="text-right px-4 py-2 font-medium">Updated</th>
                </tr>
              </thead>
              <tbody>
                {taskSearchFiltered.map((t) => {
                  const displayState = effectiveTaskState(t.state, t.is_active);
                  const dimmed = filterActive && !activeSet.has(displayState);
                  return (
                  <tr
                    key={t.task_id}
                    tabIndex={0}
                    aria-selected={selectedTask === t.task_id}
                    data-dimmed={dimmed || undefined}
                    className={clsx(
                      "border-b border-edge/40 last:border-b-0 hover:bg-panel-high cursor-pointer",
                      "focus:outline-none focus-visible:ring-1 focus-visible:ring-accent transition-opacity",
                      selectedTask === t.task_id && "bg-panel-high",
                      dimmed && "opacity-40 hover:opacity-90",
                    )}
                    onClick={() => setSelectedTask(t.task_id)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        setSelectedTask(t.task_id);
                      }
                    }}
                  >
                    <td className="px-4 py-2">
                      <Link
                        to={`/tasks/${t.task_id}`}
                        onClick={(e) => e.stopPropagation()}
                        className="text-ink hover:text-accent"
                      >
                        {t.title}
                      </Link>
                      <div className="text-[11px] text-ink-subtle">
                        {t.task_name ? (
                          <>
                            Task name <Mono>{t.task_name}</Mono>
                          </>
                        ) : (
                          <Mono>{taskDisplayId(t.task_id, init.initiative_id)}</Mono>
                        )}
                      </div>
                      {t.task_name && (
                        <div className="mt-0.5 flex items-center gap-1 text-[11px] text-ink-subtle">
                          <span>Runtime ID</span>
                          <Mono>{taskDisplayId(t.task_id, init.initiative_id)}</Mono>
                          <CopyButton value={t.task_id} />
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-2 align-top">
                      <div className="flex flex-col items-start gap-1">
                        {/* `is_active` overrides the literal FSM
                            state for display purposes: the task has
                            an `Active` subtask_activations row, so it
                            IS running right now, even if `state` has
                            flickered to `Admitted` between VM hops.
                            Without this, the polling-resolution gap
                            hides every executor "Running" period
                            from the dashboard index. */}
                        <StateBadge
                          state={displayState}
                          pulse={t.is_active || t.state === "Running"}
                        />
                        {isTerminalFailureState(t.state) && (
                          <FailurePill
                            failed
                            reason={t.failure ?? null}
                            compact
                          />
                        )}
                        <ReviewRetryPill task={t} compact />
                      </div>
                    </td>
                    <td className="px-4 py-2 text-xs">
                      {t.session_id ? (
                        <Link
                          to={`/sessions/${t.session_id}`}
                          onClick={(e) => e.stopPropagation()}
                          className="text-accent hover:underline font-mono"
                        >
                          {t.session_id.slice(0, 12)}…
                        </Link>
                      ) : (
                        <span className="text-ink-subtle">—</span>
                      )}
                    </td>
                    <td className="px-4 py-2 text-xs text-ink-muted">
                      <span className="inline-flex items-center gap-2">
                        <span
                          className={`inline-block w-2 h-2 rounded-full ${lifecycleDotClass(
                            t.latest_annotation ?? null,
                          )}`}
                          aria-hidden="true"
                        />
                        <span>{lifecycleSummary(t.latest_annotation ?? null)}</span>
                      </span>
                    </td>
                    <td className="px-4 py-2 text-right text-xs text-ink-muted">
                      {fmtRelative(t.updated_at)}
                    </td>
                  </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </section>

        {/* Focused task panel */}
        <aside className="card p-4">
          <h2 className="text-sm font-semibold text-ink mb-2">
            {focusedTask ? "Focused task" : "Task detail"}
          </h2>
          {focusedTask ? (
            <>
              <Link
                to={`/tasks/${focusedTask.task_id}`}
                className="text-base font-medium text-ink hover:text-accent"
              >
                {focusedTask.title}
              </Link>
              <div className="text-xs text-ink-subtle mt-0.5 flex items-center gap-1">
                <span>
                  {focusedTask.task_name ? "Runtime ID" : "Task"}
                </span>
                <Mono>
                  {taskDisplayId(focusedTask.task_id, init.initiative_id)}
                </Mono>
                {/* Copy still uses the real task_id so operators
                    can paste a wire-stable id into kernel CLI /
                    audit queries. The task name is the human label. */}
                <CopyButton value={focusedTask.task_id} />
              </div>
              <div className="mt-3 flex items-center gap-2">
                {/* INV-DASHBOARD-RUNNING-STATE-VISIBLE-01 — same
                    `Admitted + is_active → Running` lift the DAG
                    (`DagGraph::effectiveState`), the sibling task
                    table on this page (~line 348), the standalone
                    DAG focus panel (`InitiativeDag.tsx` ~line 272),
                    and `TaskDetail.tsx` (~line 67) already apply.
                    Pre-iter74 this panel rendered the raw FSM
                    state, so a live executor (FSM still `Admitted`
                    because no terminal intent has landed yet)
                    showed "Admitted" in the focused-task card
                    while the sibling list / DAG on the same page
                    showed "Running" — the user-reported
                    source-of-truth split. The pulse predicate is
                    widened to match `TaskDetail.tsx`'s shape so
                    every actively-executing task pulses in this
                    surface too. */}
                <StateBadge
                  state={effectiveTaskState(
                    focusedTask.state,
                    focusedTask.is_active,
                  )}
                  pulse={focusedTask.is_active || focusedTask.state === "Running"}
                />
                <ReviewRetryPill task={focusedTask} />
              </div>
              {(isTerminalFailureState(focusedTask.state) ||
                focusedTask.failure) && (
                <div className="mt-3">
                  <FailureReasonPanel
                    reason={focusedTask.failure ?? null}
                    heading="Task failure reason"
                    collapsible
                  />
                  {focusedTask.blocked_downstream &&
                    focusedTask.blocked_downstream.length > 0 && (
                      <div className="mt-2 text-[11px] text-warn">
                        Blocks {focusedTask.blocked_downstream.length} downstream{" "}
                        {focusedTask.blocked_downstream.length === 1
                          ? "task"
                          : "tasks"}
                      </div>
                    )}
                </div>
              )}
              <dl className="mt-3 space-y-2 text-xs">
                <Row
                  label="Session"
                  value={
                    focusedTask.session_id ? (
                      <Link
                        to={`/sessions/${focusedTask.session_id}`}
                        className="text-accent hover:underline"
                      >
                        <Mono>{focusedTask.session_id}</Mono>
                      </Link>
                    ) : (
                      "—"
                    )
                  }
                />
                <Row
                  label="Reviewer verdicts"
                  value={String(focusedTask.reviewer_verdicts.length)}
                />
                <Row
                  label="Outputs"
                  value={String(focusedTask.structured_outputs.length)}
                />
                <Row
                  label="Path scope"
                  value={
                    <div className="font-mono text-[11px] mt-1 max-h-32 overflow-y-auto overscroll-y-auto scroll-thin">
                      {focusedTask.path_allowlist.length === 0 ? (
                        <span className="text-ink-subtle">—</span>
                      ) : (
                        focusedTask.path_allowlist.map((p) => (
                          <div key={p} className="text-ink-muted truncate">
                            {p}
                          </div>
                        ))
                      )}
                    </div>
                  }
                />
                <Row
                  label="Created"
                  value={fmtAbsolute(focusedTask.created_at)}
                />
                <Row
                  label="Updated"
                  value={fmtAbsolute(focusedTask.updated_at)}
                />
              </dl>
              <Link
                to={`/tasks/${focusedTask.task_id}`}
                className="btn w-full justify-center mt-4"
              >
                Open task page →
              </Link>
            </>
          ) : (
            <p className="text-xs text-ink-subtle">
              Select a task in the DAG or table to view its detail summary.
            </p>
          )}
        </aside>
      </div>

      {/* Plan TOML — collapsible panel surfacing the original
       * submitted plan.toml byte-for-byte. Spec:
       * `INV-DASHBOARD-INITIATIVE-PLAN-VISIBLE-01`. */}
      <section className="card p-0 overflow-hidden">
        <button
          type="button"
          onClick={togglePlanPanel}
          aria-expanded={planPanelOpen}
          aria-controls="plan-toml-panel"
          data-testid="plan-toml-toggle"
          className="w-full flex items-center justify-between px-4 py-3 hover:bg-panel-high transition-colors"
        >
          <div className="flex items-center gap-2">
            <span aria-hidden className="text-ink-subtle">
              {planPanelOpen ? "▾" : "▸"}
            </span>
            <h2 className="text-sm font-semibold text-ink">Plan TOML</h2>
            <span className="text-[11px] text-ink-subtle">
              · {planPanelOpen ? "Hide" : "Show"} the original submitted plan
            </span>
          </div>
          <span className="text-[11px] text-ink-subtle">
            {planPanelOpen ? "click to collapse" : "click to expand"}
          </span>
        </button>
        {planPanelOpen && (
          <div id="plan-toml-panel" className="border-t border-edge p-4">
            <InitiativePlanView initiativeId={init.initiative_id} />
          </div>
        )}
      </section>

      {/* Credentials — collapsible panel surfacing the
       * declared credential files for this initiative. Spec:
       * `INV-DASHBOARD-CREDENTIAL-DEFAULT-MASKED-01`. */}
      <section className="card p-0 overflow-hidden">
        <button
          type="button"
          onClick={toggleCredentialsPanel}
          aria-expanded={credentialsPanelOpen}
          aria-controls="credentials-panel"
          data-testid="credentials-toggle"
          className="w-full flex items-center justify-between px-4 py-3 hover:bg-panel-high transition-colors"
        >
          <div className="flex items-center gap-2">
            <span aria-hidden className="text-ink-subtle">
              {credentialsPanelOpen ? "▾" : "▸"}
            </span>
            <h2 className="text-sm font-semibold text-ink">Credentials</h2>
            <span className="text-[11px] text-ink-subtle">
              · {credentialsPanelOpen ? "Hide" : "Show"} declared credential files (default masked)
            </span>
          </div>
          <span className="text-[11px] text-ink-subtle">
            {credentialsPanelOpen ? "click to collapse" : "click to expand"}
          </span>
        </button>
        {credentialsPanelOpen && (
          <div id="credentials-panel" className="border-t border-edge p-4">
            <CredentialsView
              scope={{ kind: "initiative", initiativeId: init.initiative_id }}
              operatorRoles={operatorRoles}
            />
          </div>
        )}
      </section>
    </div>
  );
}

function ReviewRetryPill({
  task,
  compact = false,
}: {
  task: TaskView;
  compact?: boolean;
}) {
  const verdict = (task.review_verdict ?? "").toLowerCase();
  const rejected =
    verdict === "rejected" || verdict === "reject" || verdict === "atleastonerejected";
  if (!rejected) return null;
  const count = task.review_reject_count ?? 0;
  const max = task.max_review_rejections ?? 0;
  const exhausted = Boolean(task.review_retry_exhausted);
  const label =
    max > 0
      ? `${exhausted ? "Review exhausted" : "Review rejected"} ${count}/${max}`
      : exhausted
        ? "Review exhausted"
        : "Review rejected";
  return (
    <span
      className={clsx(
        "badge border-bad bg-bad-muted/30 text-bad",
        compact && "text-[10px] px-1.5 py-0.5",
      )}
      title={
        exhausted
          ? "Reviewer rejection reached the retry ceiling; no automatic retry remains."
          : "At least one reviewer rejected this artifact; a retry may still be admissible."
      }
    >
      {label}
    </span>
  );
}

function InitiativeRunSummaryCard({
  summary,
  open,
  onToggle,
}: {
  summary: InitiativeRunSummary;
  open: boolean;
  onToggle: () => void;
}) {
  const totalTokens =
    summary.input_tokens +
    summary.output_tokens +
    summary.cache_read_tokens +
    summary.cache_creation_tokens;
  const turnBudget =
    summary.declared_turn_budget != null
      ? `${fmtTokens(summary.llm_turn_count)} / ${fmtTokens(summary.declared_turn_budget)}`
      : fmtTokens(summary.llm_turn_count);
  const wallBudget =
    summary.declared_wallclock_budget_seconds != null
      ? `${fmtDuration(summary.elapsed_seconds)} / ${fmtDuration(summary.declared_wallclock_budget_seconds)}`
      : fmtDuration(summary.elapsed_seconds);
  const pricingNote =
    summary.token_cost_pricing_note ||
    "Token cost pricing source was not recorded by this kernel version.";
  const pricingHint = pricingHintForSource(summary.token_cost_pricing_source);
  return (
    <section className="card p-4">
      <header className="flex items-start justify-between gap-3 flex-wrap">
        <button
          type="button"
          onClick={onToggle}
          aria-expanded={open}
          aria-controls="initiative-resource-summary-panel"
          className="group flex min-w-0 flex-1 items-start gap-2 rounded text-left focus:outline-none focus-visible:ring-1 focus-visible:ring-accent"
        >
          <span
            aria-hidden
            className="mt-0.5 text-ink-subtle group-hover:text-ink"
          >
            {open ? "▾" : "▸"}
          </span>
          <span className="min-w-0">
            <span className="flex flex-wrap items-center gap-2">
              <h2 className="text-sm font-semibold text-ink">
                Resource summary
              </h2>
              <span
                className={clsx(
                  "badge",
                  summary.terminal ? toneClasses("ok") : toneClasses("info"),
                )}
              >
                {summary.terminal ? "final" : "so far"}
              </span>
            </span>
            <span className="mt-1 block text-xs text-ink-muted">
              Kernel ledger for sessions, turns, tokens, budget ceilings, and
              cost.
            </span>
          </span>
        </button>
        <div className="flex items-start gap-4 text-right text-xs text-ink-subtle">
          <div>
            <div>{plural(summary.session_count, "session")}</div>
            <div>
              {fmtTokens(totalTokens)} tokens ·{" "}
              {fmtMicroDollars(summary.token_cost_micros)}
            </div>
          </div>
          {summary.active_session_count > 0 && (
            <div>{summary.active_session_count} still active</div>
          )}
          <button
            type="button"
            onClick={onToggle}
            className="text-ink-subtle hover:text-ink"
          >
            {open ? "Collapse" : "Expand"}
          </button>
        </div>
      </header>

      {open && (
        <div id="initiative-resource-summary-panel">
          <div className="mt-4 grid grid-cols-2 md:grid-cols-4 xl:grid-cols-7 gap-2">
            <SummaryMetric
              label="Turns"
              value={turnBudget}
              hint={
                summary.declared_turn_budget != null
                  ? "used / declared"
                  : "no declared cap"
              }
            />
            <SummaryMetric
              label="Tokens"
              value={fmtTokens(totalTokens)}
              hint={`in ${fmtTokens(summary.input_tokens)} · out ${fmtTokens(summary.output_tokens)}`}
            />
            <SummaryMetric
              label="Cache"
              value={fmtTokens(
                summary.cache_read_tokens + summary.cache_creation_tokens,
              )}
              hint={`read ${fmtTokens(summary.cache_read_tokens)} · write ${fmtTokens(summary.cache_creation_tokens)}`}
            />
            <SummaryMetric
              label="Cost"
              value={fmtMicroDollars(summary.token_cost_micros)}
              hint={pricingHint}
            />
            <SummaryMetric
              label="Elapsed"
              value={wallBudget}
              hint={
                summary.declared_wallclock_budget_seconds != null
                  ? "used / declared"
                  : "no declared cap"
              }
            />
            <SummaryMetric
              label="Admission"
              value={fmtTokens(summary.admission_reserved_units)}
              hint="reserved units"
            />
            <SummaryMetric
              label="Actual"
              value={fmtTokens(summary.actual_cost_units)}
              hint="admission units"
            />
          </div>
          <p className="mt-3 text-[11px] leading-relaxed text-ink-muted">
            Provider reported {fmtTokens(summary.input_tokens)} input /{" "}
            {fmtTokens(summary.output_tokens)} output tokens; {pricingNote}
          </p>
          {(summary.token_cost_breakdown?.length ?? 0) > 0 && (
            <div className="mt-3 overflow-hidden rounded border border-edge">
              <div className="grid grid-cols-[minmax(0,1.2fr)_minmax(0,1.2fr)_minmax(7rem,0.8fr)_minmax(6rem,0.6fr)_minmax(6rem,0.6fr)] gap-2 border-b border-edge bg-panel-muted px-3 py-2 text-[10px] uppercase tracking-wider text-ink-subtle max-lg:hidden">
                <div>Provider</div>
                <div>Model</div>
                <div>Source</div>
                <div className="text-right">Tokens</div>
                <div className="text-right">Cost</div>
              </div>
              <div className="divide-y divide-edge">
                {summary.token_cost_breakdown!.map((row, index) => {
                  const rowTokens =
                    row.input_tokens +
                    row.output_tokens +
                    row.cache_read_tokens +
                    row.cache_creation_tokens;
                  return (
                    <div
                      key={`${row.provider_id}-${row.model_id}-${row.pricing_source}-${index}`}
                      className="grid grid-cols-[minmax(0,1.2fr)_minmax(0,1.2fr)_minmax(7rem,0.8fr)_minmax(6rem,0.6fr)_minmax(6rem,0.6fr)] gap-2 px-3 py-2 text-xs max-lg:grid-cols-1"
                    >
                      <div className="min-w-0">
                        <div className="text-[10px] uppercase tracking-wider text-ink-subtle lg:hidden">
                          Provider
                        </div>
                        <div className="truncate font-mono text-ink">
                          {row.provider_id || "unknown"}
                        </div>
                      </div>
                      <div className="min-w-0">
                        <div className="text-[10px] uppercase tracking-wider text-ink-subtle lg:hidden">
                          Model
                        </div>
                        <div className="truncate font-mono text-ink-muted">
                          {row.model_id || "unknown"}
                        </div>
                      </div>
                      <div className="min-w-0">
                        <div className="text-[10px] uppercase tracking-wider text-ink-subtle lg:hidden">
                          Source
                        </div>
                        <span
                          className={clsx(
                            "badge",
                            pricingSourceTone(row.pricing_source),
                          )}
                        >
                          {pricingLabel(row.pricing_source)}
                        </span>
                        <div className="mt-1 truncate text-[11px] text-ink-muted">
                          {row.pricing_note}
                        </div>
                      </div>
                      <div className="text-right font-mono text-ink max-lg:text-left">
                        <div className="text-[10px] uppercase tracking-wider text-ink-subtle lg:hidden">
                          Tokens
                        </div>
                        {fmtTokens(rowTokens)}
                        <div className="text-[11px] text-ink-muted">
                          in {fmtTokens(row.input_tokens)} · out{" "}
                          {fmtTokens(row.output_tokens)}
                        </div>
                      </div>
                      <div className="text-right font-mono text-ink max-lg:text-left">
                        <div className="text-[10px] uppercase tracking-wider text-ink-subtle lg:hidden">
                          Cost
                        </div>
                        {fmtMicroDollars(row.token_cost_micros)}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}
    </section>
  );
}

function pricingHintForSource(source?: string): string {
  switch (source) {
    case "operator_policy_override":
      return "policy override";
    case "runtime_provider_api":
      return "provider runtime";
    case "bundled_estimate":
    case "estimated":
    case "partly_estimated":
    case "mixed":
      return "estimated";
    case "pricing_source_unknown":
      return "pricing source unknown";
    case "unpriced":
      return "not priced";
    default:
      return "pricing source unknown";
  }
}

function pricingLabel(source?: string): string {
  switch (source) {
    case "operator_policy_override":
      return "policy override";
    case "runtime_provider_api":
      return "provider runtime";
    case "bundled_estimate":
    case "estimated":
    case "partly_estimated":
    case "mixed":
      return "estimate";
    case "unpriced":
      return "not priced";
    default:
      return "unknown";
  }
}

function pricingSourceTone(source?: string): string {
  switch (source) {
    case "operator_policy_override":
    case "runtime_provider_api":
      return toneClasses("ok");
    case "bundled_estimate":
    case "estimated":
    case "partly_estimated":
    case "mixed":
      return toneClasses("warn");
    default:
      return toneClasses("muted");
  }
}

function SummaryMetric({
  label,
  value,
  hint,
}: {
  label: string;
  value: React.ReactNode;
  hint: string;
}) {
  return (
    <div className="rounded border border-edge bg-panel px-3 py-2 min-w-0">
      <div className="text-[10px] uppercase tracking-wider text-ink-subtle">
        {label}
      </div>
      <div className="mt-1 text-sm font-semibold text-ink font-mono truncate">
        {value}
      </div>
      <div className="mt-0.5 text-[11px] text-ink-muted truncate">{hint}</div>
    </div>
  );
}

function fmtDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "—";
  const s = Math.floor(seconds);
  const hours = Math.floor(s / 3600);
  const minutes = Math.floor((s % 3600) / 60);
  const rest = s % 60;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m ${rest}s`;
  return `${rest}s`;
}

function fmtMicroDollars(micros: number): string {
  if (!Number.isFinite(micros) || micros < 0) return "—";
  const dollars = micros / 1_000_000;
  if (dollars === 0) return "$0.00";
  if (dollars < 0.01) return `$${dollars.toFixed(6)}`;
  if (dollars < 1) return `$${dollars.toFixed(4)}`;
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: 2,
  }).format(dollars);
}

function InitiativeIntegrationState({
  initiativeId,
  tasks,
  dagNodes,
}: {
  initiativeId: string;
  tasks: TaskView[];
  dagNodes: DagNode[];
}) {
  const integrationTask = useMemo(
    () => tasks.find((t) => isIntegrationMergeTask(t.task_id, initiativeId)),
    [initiativeId, tasks],
  );
  const integrationNode = useMemo(
    () => dagNodes.find((n) => isIntegrationMergeTask(n.task_id, initiativeId)),
    [dagNodes, initiativeId],
  );
  const q = useQuery({
    queryKey: ["initiative", initiativeId, "integration-merge-snapshots"],
    queryFn: ({ signal }) =>
      dashboardApi.tasks.worktreeSnapshots(
        integrationTask?.task_id ?? "",
        signal,
      ),
    enabled: Boolean(integrationTask),
    refetchInterval:
      integrationTask &&
      integrationTask.state !== "Completed" &&
      !isTerminalFailureState(integrationTask.state)
        ? 6_000
        : false,
  });

  if (!integrationTask) return null;

  const snapshots = q.data ?? [];
  const finalSnapshot =
    snapshots.find((s) => s.trigger === "IntegrationMerge") ??
    snapshots.find((s) => s.trigger === "PreGc") ??
    snapshots[0] ??
    null;
  const gates = integrationNode?.gate_verdict_summary ?? [];
  const pendingGates = gates.filter((gate) => gate.latest_verdict === "Pending");
  const failedGates = gates.filter((gate) => gateTone(gate.latest_verdict) === "bad");
  const displayState = effectiveTaskState(
    integrationTask.state,
    integrationTask.is_active,
  );
  const awaitingGates =
    displayState === "GatesPending" ||
    (gates.length > 0 && pendingGates.length > 0 && !finalSnapshot);

  return (
    <section className="card p-4">
      <header className="flex items-center justify-between gap-3 flex-wrap">
        <div>
          <h2 className="text-sm font-semibold text-ink">
            Integration merge
          </h2>
          <p className="text-xs text-ink-muted">
            Candidate merge, pre-merge gates, target-ref advancement, and final main snapshot.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <StateBadge
            state={displayState}
            pulse={integrationTask.is_active || displayState === "Running"}
          />
          <Link
            to={`/tasks/${integrationTask.task_id}`}
            className="btn text-xs py-1"
          >
            Open merge task
          </Link>
        </div>
      </header>

      <div
        className={clsx(
          "mt-3 rounded border p-3 text-sm",
          awaitingGates
            ? "border-warn/40 bg-warn-muted/10"
            : isTerminalFailureState(displayState) || failedGates.length > 0
              ? "border-bad/40 bg-bad-muted/10"
              : finalSnapshot || displayState === "Completed"
                ? "border-ok/40 bg-ok-muted/10"
                : "border-info/40 bg-info-muted/10",
        )}
      >
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="font-medium text-ink">
              {integrationStatusTitle(displayState, gates.length, pendingGates.length, finalSnapshot !== null)}
            </div>
            <p className="mt-1 text-xs text-ink-muted leading-relaxed">
              {integrationStatusCopy(displayState, gates.length, pendingGates.length, finalSnapshot !== null)}
            </p>
          </div>
          <div className="flex flex-wrap gap-1 text-[11px]">
            <span className="badge bg-panel border-edge text-ink-muted">
              candidate submitted
            </span>
            {gates.length > 0 ? (
              <span
                className={clsx(
                  "badge",
                  pendingGates.length > 0
                    ? toneClasses("warn")
                    : failedGates.length > 0
                      ? toneClasses("bad")
                      : toneClasses("ok"),
                )}
              >
                {pendingGates.length > 0
                  ? `${pendingGates.length}/${gates.length} gates pending`
                  : failedGates.length > 0
                    ? `${failedGates.length}/${gates.length} gates failed`
                    : `${gates.length}/${gates.length} gates passed`}
              </span>
            ) : (
              <span className="badge bg-panel border-edge text-ink-muted">
                no pre-merge gates
              </span>
            )}
            <span
              className={clsx(
                "badge",
                finalSnapshot || displayState === "Completed"
                  ? toneClasses("ok")
                  : toneClasses("muted"),
              )}
            >
              {finalSnapshot ? "snapshot captured" : "snapshot pending"}
            </span>
          </div>
        </div>

        {gates.length > 0 && (
          <div className="mt-3 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-2">
            {gates.map((gate) => (
              <div
                key={`${gate.gate_source}:${gate.gate_hook}:${gate.gate_type}`}
                className="rounded border border-edge bg-panel px-2.5 py-2 text-xs"
              >
                <div className="flex items-center justify-between gap-2">
                  <Mono className="truncate">{gate.gate_type}</Mono>
                  <span className={clsx("badge", toneClasses(gateTone(gate.latest_verdict)))}>
                    {gate.latest_verdict}
                  </span>
                </div>
                <div className="mt-1 flex flex-wrap gap-1 text-[10px] text-ink-subtle">
                  <span>{mergeGateSourceLabel(gate.gate_source)}</span>
                  <span>·</span>
                  <span>{mergeGateHookLabel(gate.gate_hook)}</span>
                  <span>·</span>
                  <span>{fmtRelative(gate.recorded_at)}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {q.isPending && !finalSnapshot ? (
        <div className="mt-3 text-xs text-ink-subtle">
          Checking for final merge snapshot…
        </div>
      ) : q.error ? (
        <div className="mt-3">
          <ErrorBox error={q.error} onRetry={() => q.refetch()} />
        </div>
      ) : finalSnapshot ? (
        <IntegrationSnapshotSummary snapshot={finalSnapshot} />
      ) : awaitingGates ? (
        <div className="mt-3 rounded border border-edge bg-panel px-3 py-2 text-xs text-ink-muted">
          The final main-root snapshot is intentionally absent until the blocking
          integration gates pass and the kernel advances the target ref.
        </div>
      ) : (
        <Empty
          title="No merge snapshot recorded yet."
          hint="The final main-root state appears here once the orchestrator submits IntegrationMerge and the kernel captures the merged worktree."
        />
      )}
    </section>
  );
}

function integrationStatusTitle(
  state: string,
  gateCount: number,
  pendingCount: number,
  hasSnapshot: boolean,
): string {
  if (state === "Completed" || hasSnapshot) return "Merge complete";
  if (isTerminalFailureState(state)) return "Merge failed";
  if (state === "GatesPending" || pendingCount > 0) {
    return gateCount > 0
      ? "Merge submitted; awaiting pre-merge gates"
      : "Merge submitted; gate decision pending";
  }
  if (state === "Running") return "Merge is running";
  if (state === "Admitted") return "Waiting for orchestrator merge submission";
  return "Integration merge is in progress";
}

function integrationStatusCopy(
  state: string,
  gateCount: number,
  pendingCount: number,
  hasSnapshot: boolean,
): string {
  if (state === "Completed" || hasSnapshot) {
    return "The kernel accepted the merge, advanced the target ref, and captured the final main-root snapshot.";
  }
  if (isTerminalFailureState(state)) {
    return "The integration merge path reached a terminal failure. Open the merge task for the failure reason and witness timeline.";
  }
  if (state === "GatesPending" || pendingCount > 0) {
    return gateCount > 0
      ? "The orchestrator submitted IntegrationMerge. The kernel is holding target-ref advancement until the listed blocking gates finish."
      : "The orchestrator submitted IntegrationMerge. The kernel has paused before target-ref advancement while gate state is reconciled.";
  }
  if (state === "Running") {
    return "The kernel is processing the submitted merge candidate and will either spawn gates, advance the target ref, or surface a failure.";
  }
  return "The synthetic integration task is admitted. It will move once the orchestrator submits the final IntegrationMerge intent.";
}

function gateTone(verdict: string): StateBadgeTone {
  switch (verdict) {
    case "Pass":
      return "ok";
    case "Pending":
      return "warn";
    case "Inconclusive":
      return "warn";
    case "Fail":
    case "SpawnFailed":
    case "ProcessFailed":
    case "Timeout":
    case "ConfigInvalid":
    case "BudgetExhausted":
    case "CapExceeded":
      return "bad";
    default:
      return "muted";
  }
}

function mergeGateSourceLabel(source: string | undefined): string {
  switch (source) {
    case "plan_integration_verifier":
      return "Plan gate";
    case "policy_integration_verifier":
      return "Policy gate";
    case "integration_verifier":
      return "Integration gate";
    case "policy_gate":
      return "Policy invariant";
    default:
      return source ?? "Gate";
  }
}

function mergeGateHookLabel(hook: string | undefined): string {
  return hook === "integration_merge" ? "IntegrationMerge" : (hook ?? "Hook");
}

function IntegrationSnapshotSummary({
  snapshot,
}: {
  snapshot: WorktreeSnapshotView;
}) {
  const clean = !snapshot.porcelain_blob_sha256;
  const [activeBlob, setActiveBlob] = useState<
    "diff" | "log" | "porcelain" | null
  >(null);
  return (
    <div className="mt-3 space-y-3">
      <div className="grid min-w-0 max-w-full grid-cols-1 lg:grid-cols-[minmax(0,1fr)_auto] gap-3 items-start">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs">
          <MergeField label="Trigger">
            <span className="badge bg-accent-muted/40 border-accent text-accent">
              {snapshot.trigger}
            </span>
          </MergeField>
          <MergeField label="Range">
            <span className="font-mono text-ink-muted">
              {shortSha(snapshot.base_sha)} to {shortSha(snapshot.head_sha)}
            </span>
          </MergeField>
          <MergeField label="Commits">{snapshot.commit_count}</MergeField>
          <MergeField label="Working tree">
            <span
              className={clsx(
                "badge",
                clean
                  ? "bg-ok-muted/20 border-ok text-ok"
                  : "bg-warn-muted/20 border-warn text-warn",
              )}
            >
              {clean ? "Clean" : "Dirty snapshot"}
            </span>
          </MergeField>
        </div>
        <div className="flex items-center gap-2 text-xs flex-wrap justify-start lg:justify-end">
          {snapshot.diff_blob_sha256 && (
            <button
              type="button"
              className={clsx("btn py-1", activeBlob === "diff" && "active")}
              onClick={() => setActiveBlob(activeBlob === "diff" ? null : "diff")}
            >
              Diff
            </button>
          )}
          {snapshot.log_blob_sha256 && (
            <button
              type="button"
              className={clsx("btn py-1", activeBlob === "log" && "active")}
              onClick={() => setActiveBlob(activeBlob === "log" ? null : "log")}
            >
              Log
            </button>
          )}
          {snapshot.porcelain_blob_sha256 && (
            <button
              type="button"
              className={clsx(
                "btn py-1",
                activeBlob === "porcelain" && "active",
              )}
              onClick={() =>
                setActiveBlob(activeBlob === "porcelain" ? null : "porcelain")
              }
            >
              Status
            </button>
          )}
        </div>
      </div>
      {activeBlob && (
        <SnapshotBlobPanel snapshotId={snapshot.snapshot_id} kind={activeBlob} />
      )}
    </div>
  );
}

function SnapshotBlobPanel({
  snapshotId,
  kind,
}: {
  snapshotId: string;
  kind: "diff" | "log" | "tree" | "porcelain";
}) {
  const q = useQuery({
    queryKey: ["integration-snapshot", snapshotId, "blob", kind],
    queryFn: ({ signal }) =>
      dashboardApi.worktreeSnapshots.fetchBlob(snapshotId, kind, signal),
    staleTime: Infinity,
    gcTime: 5 * 60_000,
  });

  if (q.isPending) {
    return <div className="text-xs text-ink-subtle">Loading {kind}…</div>;
  }
  if (q.error) {
    return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  }
  return (
    <pre className="min-w-0 max-w-full text-[11px] font-mono text-ink-muted overflow-auto overscroll-auto scroll-thin max-h-96 bg-panel border border-edge rounded p-2">
      {q.data}
    </pre>
  );
}

function MergeField({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="min-w-0">
      <div className="text-[10px] uppercase tracking-wider text-ink-subtle">
        {label}
      </div>
      <div className="mt-1 text-ink min-w-0">{children}</div>
    </div>
  );
}

interface RowProps {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
}

function Row({ label, value, mono }: RowProps) {
  return (
    <div className="flex items-start gap-3 text-xs">
      <span className="w-24 text-ink-subtle uppercase tracking-wider text-[10px] mt-0.5 shrink-0">
        {label}
      </span>
      <span
        className={`flex-1 min-w-0 ${mono ? "font-mono text-ink-muted" : "text-ink"}`}
      >
        {typeof value === "string" && mono && value.length > 18 ? (
          <span title={value}>{shortFingerprint(value)}</span>
        ) : (
          value
        )}
      </span>
    </div>
  );
}
