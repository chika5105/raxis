import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import clsx from "clsx";

import { dashboardApi } from "@/api/client";
import { Empty } from "@/components/Empty";
import { ErrorBox } from "@/components/ErrorBox";
import { Mono } from "@/components/Mono";
import { PageSpinner } from "@/components/Spinner";
import { StateBadge } from "@/components/StateBadge";
import {
  StatusFilterPills,
  StatusLegend,
} from "@/components/StatusLegend";
import { fmtRelative, plural } from "@/lib/format";
import {
  parseStatusParam,
  serializeStatusParam,
  toggleStatus,
} from "@/lib/status-filter";

const STATE_OPTIONS = [
  "All",
  "Pending",
  "Active",
  "Paused",
  "Completed",
  "Closed",
  "Failed",
];

export function InitiativesPage() {
  const navigate = useNavigate();
  // The Overview KPI tile links here with `?state=Active`,
  // and operators expect to share / bookmark filtered URLs.
  // Mirror the filter into the URL so back/forward, copy-link,
  // and refresh all preserve the chosen state.
  const [searchParams, setSearchParams] = useSearchParams();
  const urlState = searchParams.get("state") ?? "All";
  const stateFilter = STATE_OPTIONS.includes(urlState) ? urlState : "All";
  const setStateFilter = (next: string) => {
    const sp = new URLSearchParams(searchParams);
    if (next === "All") sp.delete("state");
    else sp.set("state", next);
    // Changing the server-side state filter invalidates any
    // narrower `?status=` legend selection — drop it so the
    // operator doesn't see "0/0" right after picking a dropdown
    // value that overlaps zero legend chips.
    sp.delete("status");
    setSearchParams(sp, { replace: true });
  };
  // Secondary, FE-side multi-select status legend filter. Stacks
  // on top of the server-side dropdown above: the dropdown drives
  // which initiatives we fetch; the legend dims rows that don't
  // match the operator's narrower per-state focus.
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
  const handleClearStatus = () => writeStatuses([]);
  const handleRemoveStatus = (status: string) =>
    writeStatuses(activeStatuses.filter((s) => s !== status));
  const [search, setSearch] = useState("");

  const q = useQuery({
    queryKey: ["initiatives", { state: stateFilter, limit: 200 }],
    queryFn: ({ signal }) =>
      dashboardApi.initiatives.list(
        {
          limit: 200,
          ...(stateFilter !== "All" ? { state: stateFilter } : {}),
        },
        signal,
      ),
    refetchInterval: 5_000,
  });

  const searchFiltered = useMemo(() => {
    if (!q.data) return [];
    if (search.trim() === "") return q.data;
    const needle = search.trim().toLowerCase();
    return q.data.filter((i) => {
      const taskHaystack = (i.tasks ?? [])
        .flatMap((t) => [
          t.task_id,
          t.task_name ?? "",
          t.title,
          t.agent_type,
          t.state,
        ])
        .join(" ");
      const haystack = [
        i.display_name ?? "",
        i.initiative_id,
        i.state,
        taskHaystack,
      ]
        .join(" ")
        .toLowerCase();
      return haystack.includes(needle);
    });
  }, [q.data, search]);
  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const i of searchFiltered) c[i.state] = (c[i.state] ?? 0) + 1;
    return c;
  }, [searchFiltered]);
  const activeSet = new Set(activeStatuses);
  const filterActive = activeStatuses.length > 0;
  // Rows always render — non-matching ones dim. Matches the
  // user-stated "highlight" intent and lets the operator keep
  // situational awareness of total scope.
  const filtered = searchFiltered;

  return (
    <div className="space-y-4">
      <header className="flex items-end justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-xl font-semibold text-ink">Workspaces</h1>
          <p className="text-sm text-ink-muted">
            Operator-named initiatives, newest first.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <input
            className="input w-56"
            placeholder="Search workspace, task name, or id…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <select
            className="input"
            value={stateFilter}
            onChange={(e) => setStateFilter(e.target.value)}
          >
            {STATE_OPTIONS.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </div>
      </header>

      {Object.keys(counts).length > 0 && (
        <section
          className="card px-4 py-3 flex flex-wrap items-center gap-x-4 gap-y-2"
          aria-label="Initiative status legend"
        >
          <StatusLegend
            counts={counts}
            activeStatuses={activeStatuses}
            onToggle={handleToggle}
            onClear={handleClearStatus}
            itemNoun="initiative"
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
          onRemove={handleRemoveStatus}
          onClearAll={handleClearStatus}
        />
      )}

      {q.isPending ? (
        <PageSpinner />
      ) : q.error ? (
        <ErrorBox error={q.error} onRetry={() => q.refetch()} />
      ) : filtered.length === 0 ? (
        <Empty
          title={
            search
              ? "No initiatives match your search."
              : "No initiatives in this state."
          }
          hint={
            <>
              Try a different filter, or admit a plan with{" "}
              <code className="font-mono">raxis plan submit</code>.
            </>
          }
        />
      ) : (
        <div className="card p-0 overflow-hidden">
          <table className="w-full text-sm">
            <thead className="text-xs text-ink-subtle bg-panel-high">
              <tr>
                <th className="text-left px-4 py-2.5 font-medium">
                  Workspace
                </th>
                <th className="text-left px-4 py-2.5 font-medium">State</th>
                <th className="text-left px-4 py-2.5 font-medium">Tasks</th>
                <th className="text-right px-4 py-2.5 font-medium">Created</th>
                <th className="text-right px-4 py-2.5 font-medium">Updated</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((i) => {
                const href = `/initiatives/${i.initiative_id}`;
                const dimmed = filterActive && !activeSet.has(i.state);
                const previewTasks = (i.tasks ?? [])
                  .filter((t) => t.task_id !== i.initiative_id)
                  .slice(0, 3);
                return (
                  <tr
                    key={i.initiative_id}
                    tabIndex={0}
                    data-dimmed={dimmed || undefined}
                    onClick={() => navigate(href)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        e.preventDefault();
                        navigate(href);
                      }
                    }}
                    className={clsx(
                      "border-t border-edge/40 hover:bg-panel-high cursor-pointer",
                      "focus:outline-none focus-visible:ring-1 focus-visible:ring-accent focus-visible:bg-panel-high transition-opacity",
                      dimmed && "opacity-40 hover:opacity-90",
                    )}
                  >
                    <td className="px-4 py-2.5">
                      <Link
                        to={href}
                        onClick={(e) => e.stopPropagation()}
                        className="text-ink hover:text-accent font-medium"
                      >
                        {i.display_name}
                      </Link>
                      <div className="text-[11px] text-ink-subtle">
                        <Mono>{i.initiative_id}</Mono>
                      </div>
                    </td>
                    <td className="px-4 py-2.5">
                      <StateBadge
                        state={i.state}
                        pulse={i.state === "Active"}
                      />
                    </td>
                    <td className="px-4 py-2.5 text-xs text-ink-muted">
                      {plural(i.task_count, "task")}
                      <div className="text-[11px]">
                        {i.completed_tasks > 0 && (
                          <span className="text-ok">
                            {i.completed_tasks} done
                          </span>
                        )}
                        {i.failed_tasks > 0 && (
                          <span className="text-bad ml-2">
                            {i.failed_tasks} failed
                          </span>
                        )}
                      </div>
                      {previewTasks.length > 0 && (
                        <div className="mt-1 flex flex-wrap gap-1">
                          {previewTasks.map((t) => (
                            <Link
                              key={t.task_id}
                              to={`/tasks/${t.task_id}`}
                              onClick={(e) => e.stopPropagation()}
                              className="badge bg-panel border-edge text-ink-muted hover:text-accent max-w-[14rem] truncate"
                              title={`${t.task_name ?? t.title} · ${t.task_id}`}
                            >
                              {t.task_name ?? compactTaskId(t.task_id)}
                            </Link>
                          ))}
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-2.5 text-right text-xs text-ink-muted tabular">
                      {fmtRelative(i.created_at)}
                    </td>
                    <td className="px-4 py-2.5 text-right text-xs text-ink-muted tabular">
                      {fmtRelative(i.updated_at)}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function compactTaskId(taskId: string): string {
  return taskId.length > 12 ? `${taskId.slice(0, 12)}…` : taskId;
}
