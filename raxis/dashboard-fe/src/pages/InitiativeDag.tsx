import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";

import { dashboardApi } from "@/api/client";
import { CopyButton } from "@/components/CopyButton";
import { DagGraph } from "@/components/DagGraph";
import { Empty } from "@/components/Empty";
import { ErrorBox } from "@/components/ErrorBox";
import { Mono } from "@/components/Mono";
import { PageSpinner } from "@/components/Spinner";
import { StateBadge } from "@/components/StateBadge";
import {
  StatusFilterPills,
  StatusLegend,
} from "@/components/StatusLegend";
import {
  parseStatusParam,
  serializeStatusParam,
  toggleStatus,
} from "@/lib/status-filter";
import { taskDisplayId } from "@/lib/state-color";
// `stateTone`/`toneClasses` previously colored static badge chips
// in this view; they now live inside the interactive
// `<StatusLegend>` component above.

/// Dedicated DAG view at `/initiatives/:id/dag`. Backed by the
/// lightweight `GET /api/initiatives/:id/dag` endpoint (nodes +
/// edges + per-node state, no task detail).
///
/// Layout: full-width DAG on the left, status legend +
/// focused-node detail on the right. Single click focuses a
/// node in the side panel; double click (or Enter) opens the
/// task page directly.
///
/// Refreshes every 3 s — operator-facing pages must feel live.
export function InitiativeDagPage() {
  const { id = "" } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [selected, setSelected] = useState<string | null>(null);
  const [rankdir, setRankdir] = useState<"LR" | "TB">("LR");

  // Mirror the InitiativeDetail page's URL-state convention so an
  // operator can swap between the detail and DAG views with the
  // filter intact (Cmd-click to multi-select, click again to
  // clear, `?status=Running,Completed` survives reload).
  const [searchParams, setSearchParams] = useSearchParams();
  const activeStatuses = useMemo(
    () => parseStatusParam(searchParams.get("status")),
    [searchParams],
  );
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

  // Two queries, joined client-side: the DAG endpoint gives us
  // the nodes/edges quickly; the initiative endpoint surfaces
  // the display name + task counts + base ref for the header.
  const dag = useQuery({
    queryKey: ["initiative-dag", id],
    queryFn: ({ signal }) => dashboardApi.initiatives.dag(id, signal),
    refetchInterval: 3_000,
    enabled: id.length > 0,
  });

  const summary = useQuery({
    queryKey: ["initiative", id],
    queryFn: ({ signal }) => dashboardApi.initiatives.get(id, signal),
    refetchInterval: 10_000,
    enabled: id.length > 0,
  });

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const n of dag.data?.nodes ?? []) {
      c[n.state] = (c[n.state] ?? 0) + 1;
    }
    return c;
  }, [dag.data]);

  const focusedNode =
    selected && dag.data
      ? (dag.data.nodes.find((n) => n.task_id === selected) ?? null)
      : null;

  if (dag.isPending) return <PageSpinner />;
  if (dag.error)
    return <ErrorBox error={dag.error} onRetry={() => dag.refetch()} />;

  const nodes = dag.data.nodes;
  const edges = dag.data.edges;

  return (
    <div className="space-y-4">
      <header className="flex items-start justify-between gap-4 flex-wrap">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-sm text-ink-subtle">
            <Link to="/initiatives" className="hover:text-accent">
              Initiatives
            </Link>
            <span>/</span>
            <Link
              to={`/initiatives/${id}`}
              className="hover:text-accent text-ink-muted"
            >
              <Mono>{id}</Mono>
            </Link>
            <CopyButton value={id} />
            <span>/</span>
            <span className="text-ink">DAG</span>
          </div>
          <h1 className="mt-1 text-xl font-semibold text-ink">
            {summary.data?.display_name ||
              summary.data?.initiative_id ||
              "Task DAG"}
          </h1>
          <p className="text-sm text-ink-muted mt-0.5">
            {nodes.length} task{nodes.length === 1 ? "" : "s"} · {edges.length}{" "}
            dependency{edges.length === 1 ? "" : "ies"}
          </p>
        </div>

        {/*
         * Layout-direction buttons. The mapping is pinned by
         * `src/test/dag-layout-buttons.test.tsx` (iter48 QA defect
         * #1: operator screenshots showed the visual layout doing
         * the opposite of the labels). The contract is:
         *
         *   "Left → Right"  →  rankdir="LR"  →  dagre horizontal row
         *   "Top → Bottom"  →  rankdir="TB"  →  dagre vertical column
         *
         * Do NOT swap the `onClick` / `aria-pressed` values without
         * updating that test — the test is the gate against any
         * future "buttons feel inverted" regression.
         */}
        <div className="flex items-center gap-2">
          <div className="text-xs text-ink-subtle mr-1">Layout</div>
          <button
            onClick={() => setRankdir("LR")}
            className={`btn text-xs py-1 ${
              rankdir === "LR" ? "border-accent text-ink" : ""
            }`}
            aria-pressed={rankdir === "LR"}
            title="Lay out tasks as a horizontal pipeline (LR)"
          >
            Left → Right
          </button>
          <button
            onClick={() => setRankdir("TB")}
            className={`btn text-xs py-1 ${
              rankdir === "TB" ? "border-accent text-ink" : ""
            }`}
            aria-pressed={rankdir === "TB"}
            title="Stack tasks as a vertical column (TB)"
          >
            Top → Bottom
          </button>
          <Link
            to={`/initiatives/${id}`}
            className="btn text-xs py-1 ml-2"
            title="Back to the initiative detail page"
          >
            Detail view →
          </Link>
        </div>
      </header>

      {/* Per-state counters — clickable to focus the DAG on a
       * single status (or Cmd-click for multi-select). Non-matching
       * nodes fade rather than disappearing, preserving the
       * operator's mental model of the full dependency graph. */}
      {nodes.length > 0 && (
        <section
          className="card px-4 py-3 flex flex-wrap items-center gap-x-4 gap-y-2"
          aria-label="Task status legend"
        >
          <StatusLegend
            counts={Object.fromEntries(
              Object.entries(counts).sort(([a], [b]) => a.localeCompare(b)),
            )}
            activeStatuses={activeStatuses}
            onToggle={handleToggle}
            onClear={handleClear}
            itemNoun="task"
          />
          {activeStatuses.length > 0 && (
            <span className="text-[11px] text-ink-subtle">
              · non-matching nodes faded · Cmd-click for multi-select
            </span>
          )}
        </section>
      )}

      {activeStatuses.length > 0 && (
        <StatusFilterPills
          activeStatuses={activeStatuses}
          onRemove={handleRemove}
          onClearAll={handleClear}
        />
      )}

      <div className="grid grid-cols-1 xl:grid-cols-[1fr_320px] gap-4">
        {/* Graph */}
        <section className="card p-3">
          {nodes.length === 0 ? (
            <Empty
              title="This initiative has no tasks yet."
              hint={
                <>
                  The plan hasn&apos;t been admitted, or every task has been
                  garbage-collected. Check the{" "}
                  <Link to={`/initiatives/${id}`} className="text-accent">
                    initiative detail
                  </Link>{" "}
                  page or admit a plan with{" "}
                  <code className="font-mono">raxis plan submit</code>.
                </>
              }
            />
          ) : (
            <DagGraph
              nodes={nodes}
              edges={edges}
              onSelect={setSelected}
              onActivate={(taskId) => navigate(`/tasks/${taskId}`)}
              selected={selected}
              rankdir={rankdir}
              activeStates={activeStatuses}
              hideLegend
              // Generous floor: 80 px per row + a 200 px base.
              height={Math.min(900, 240 + nodes.length * 32)}
            />
          )}
        </section>

        {/* Focused-node panel */}
        <aside className="card p-4 self-start">
          <h2 className="text-sm font-semibold text-ink mb-2">
            {focusedNode ? "Focused task" : "Click a task"}
          </h2>
          {focusedNode ? (
            <>
              <Link
                to={`/tasks/${focusedNode.task_id}`}
                className="text-base font-medium text-ink hover:text-accent"
              >
                {focusedNode.title}
              </Link>
              <div className="text-xs text-ink-subtle mt-0.5 flex items-center gap-1">
                {/* INV-DASHBOARD-INTEGRATION-MERGE-VISIBLE-OR-EXCLUDED-01:
                    substitute the stable display id for the
                    synthetic IntegrationMerge coordinator row;
                    copy still emits the wire-stable UUID. */}
                <Mono>{taskDisplayId(focusedNode.task_id, id)}</Mono>
                <CopyButton value={focusedNode.task_id} />
              </div>
              <div className="mt-3 flex items-center gap-2">
                <StateBadge
                  // Lift `Admitted + is_active` to `Running` so the
                  // focus panel matches the chip on the node body
                  // and the row treatment on `InitiativeDetail` /
                  // `TaskDetail`. The raw FSM state is still
                  // available on the node for forensic copy.
                  state={
                    focusedNode.is_active && focusedNode.state === "Admitted"
                      ? "Running"
                      : focusedNode.state
                  }
                  pulse={
                    focusedNode.state === "Running" ||
                    Boolean(focusedNode.is_active)
                  }
                />
              </div>
              <Link
                to={`/tasks/${focusedNode.task_id}`}
                className="btn w-full justify-center mt-4"
              >
                Open task page →
              </Link>
              <p className="text-[11px] text-ink-subtle mt-3">
                Tip: double-click a node, or press Enter when focused, to jump
                straight to the task page.
              </p>
            </>
          ) : (
            <p className="text-xs text-ink-subtle">
              Single-click a node in the graph to focus it here. Double-click
              (or Enter) opens that task&apos;s detail page.
            </p>
          )}
        </aside>
      </div>
    </div>
  );
}
