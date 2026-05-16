import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import clsx from "clsx";

import { dashboardApi } from "@/api/client";
import { CopyButton } from "@/components/CopyButton";
import { CredentialsView } from "@/components/CredentialsView";
import { useOperatorRoles } from "@/components/useOperatorRoles";
import { DagGraph } from "@/components/DagGraph";
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
  isTerminalFailureState,
  taskDisplayId,
} from "@/lib/state-color";
import {
  StatusFilterPills,
  StatusLegend,
} from "@/components/StatusLegend";
import {
  fmtAbsolute,
  fmtRelative,
  plural,
  shortFingerprint,
  shortSha,
} from "@/lib/format";
import {
  parseStatusParam,
  serializeStatusParam,
  toggleStatus,
} from "@/lib/status-filter";

export function InitiativeDetailPage() {
  const { id = "" } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [selectedTask, setSelectedTask] = useState<string | null>(null);

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

  // Per-task-state counts for the legend. Computed even when the
  // query is pending so hook order stays stable; the early returns
  // below short-circuit before render.
  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const t of q.data?.tasks ?? []) {
      c[t.state] = (c[t.state] ?? 0) + 1;
    }
    return c;
  }, [q.data]);

  if (q.isPending) return <PageSpinner />;
  if (q.error) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  const init = q.data;
  const focusedTask =
    selectedTask && init.tasks.find((t) => t.task_id === selectedTask);
  const activeSet = new Set(activeStatuses);
  const filterActive = activeStatuses.length > 0;

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
            {init.display_name || init.initiative_id}
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
            counts={counts}
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
            nodes={init.tasks.map((t) => ({
              task_id: t.task_id,
              title: t.title,
              state: t.state,
            }))}
            edges={init.edges}
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
          <header className="px-4 py-3 border-b border-edge flex items-center justify-between">
            <h2 className="text-sm font-semibold text-ink">Tasks</h2>
            <span className="text-xs text-ink-subtle">
              {plural(init.tasks.length, "task")}
            </span>
          </header>
          {init.tasks.length === 0 ? (
            <Empty title="No tasks." />
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
                {init.tasks.map((t) => {
                  const dimmed = filterActive && !activeSet.has(t.state);
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
                        {/* INV-DASHBOARD-INTEGRATION-MERGE-VISIBLE-OR-EXCLUDED-01:
                            render `«integration-merge»` instead of the
                            initiative UUID for the synthetic coordinator
                            row. Routing in the parent `<Link>` keeps using
                            the real `task_id` so deep-links survive. */}
                        <Mono>
                          {taskDisplayId(t.task_id, init.initiative_id)}
                        </Mono>
                      </div>
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
                          state={
                            t.is_active && t.state === "Admitted"
                              ? "Running"
                              : t.state
                          }
                          pulse={t.is_active || t.state === "Running"}
                        />
                        {isTerminalFailureState(t.state) && (
                          <FailurePill
                            failed
                            reason={t.failure ?? null}
                            compact
                          />
                        )}
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
                <Mono>
                  {taskDisplayId(focusedTask.task_id, init.initiative_id)}
                </Mono>
                {/* Copy still uses the real task_id so operators
                    can paste a wire-stable id into kernel CLI /
                    audit queries. The display ribbon is a
                    render-time friendly label only. */}
                <CopyButton value={focusedTask.task_id} />
              </div>
              <div className="mt-3 flex items-center gap-2">
                <StateBadge
                  state={focusedTask.state}
                  pulse={focusedTask.state === "Running"}
                />
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
                    <div className="font-mono text-[11px] mt-1 max-h-32 overflow-y-auto scroll-thin">
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
