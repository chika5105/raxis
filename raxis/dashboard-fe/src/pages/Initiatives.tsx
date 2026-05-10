import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { dashboardApi } from "@/api/client";
import { Empty } from "@/components/Empty";
import { ErrorBox } from "@/components/ErrorBox";
import { Mono } from "@/components/Mono";
import { PageSpinner } from "@/components/Spinner";
import { StateBadge } from "@/components/StateBadge";
import { fmtRelative, plural } from "@/lib/format";

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
  const [stateFilter, setStateFilter] = useState<string>("All");
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

  const filtered = useMemo(() => {
    if (!q.data) return [];
    if (search.trim() === "") return q.data;
    const needle = search.trim().toLowerCase();
    return q.data.filter(
      (i) =>
        i.display_name.toLowerCase().includes(needle) ||
        i.initiative_id.toLowerCase().includes(needle),
    );
  }, [q.data, search]);

  return (
    <div className="space-y-4">
      <header className="flex items-end justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-xl font-semibold text-ink">Initiatives</h1>
          <p className="text-sm text-ink-muted">
            All operator-approved initiatives, newest first.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <input
            className="input w-56"
            placeholder="Search by id or name…"
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

      {q.isPending ? (
        <PageSpinner />
      ) : q.error ? (
        <ErrorBox error={q.error} onRetry={() => q.refetch()} />
      ) : filtered.length === 0 ? (
        <Empty
          title={search ? "No initiatives match your search." : "No initiatives in this state."}
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
                <th className="text-left px-4 py-2.5 font-medium">Initiative</th>
                <th className="text-left px-4 py-2.5 font-medium">State</th>
                <th className="text-left px-4 py-2.5 font-medium">Tasks</th>
                <th className="text-right px-4 py-2.5 font-medium">Created</th>
                <th className="text-right px-4 py-2.5 font-medium">Updated</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((i) => (
                <tr
                  key={i.initiative_id}
                  className="border-t border-edge/40 hover:bg-panel-high"
                >
                  <td className="px-4 py-2.5">
                    <Link
                      to={`/initiatives/${i.initiative_id}`}
                      className="text-ink hover:text-accent font-medium"
                    >
                      {i.display_name}
                    </Link>
                    <div className="text-[11px] text-ink-subtle">
                      <Mono>{i.initiative_id}</Mono>
                    </div>
                  </td>
                  <td className="px-4 py-2.5">
                    <StateBadge state={i.state} pulse={i.state === "Active"} />
                  </td>
                  <td className="px-4 py-2.5 text-xs text-ink-muted">
                    {plural(i.task_count, "task")}
                    <div className="text-[11px]">
                      {i.completed_tasks > 0 && (
                        <span className="text-ok">{i.completed_tasks} done</span>
                      )}
                      {i.failed_tasks > 0 && (
                        <span className="text-bad ml-2">{i.failed_tasks} failed</span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-2.5 text-right text-xs text-ink-muted tabular">
                    {fmtRelative(i.created_at)}
                  </td>
                  <td className="px-4 py-2.5 text-right text-xs text-ink-muted tabular">
                    {fmtRelative(i.updated_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
