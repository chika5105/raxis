import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { dashboardApi } from "@/api/client";
import { Empty } from "@/components/Empty";
import { ErrorBox } from "@/components/ErrorBox";
import { Mono } from "@/components/Mono";
import { PageSpinner } from "@/components/Spinner";
import { StateBadge } from "@/components/StateBadge";
import { fmtRelative, fmtTokens } from "@/lib/format";

const ROLES = ["All", "Orchestrator", "Executor", "Reviewer"];

export function SessionsPage() {
  const [role, setRole] = useState<string>("All");
  const [search, setSearch] = useState("");

  const q = useQuery({
    queryKey: ["sessions", { limit: 200 }],
    queryFn: ({ signal }) => dashboardApi.sessions.list(200, signal),
    refetchInterval: 3_000,
  });

  const filtered = useMemo(() => {
    if (!q.data) return [];
    return q.data.filter((s) => {
      if (role !== "All" && s.role !== role) return false;
      if (search) {
        const needle = search.toLowerCase();
        const haystack = [s.session_id, s.task_id ?? "", s.initiative_id ?? "", s.model ?? ""]
          .join(" ")
          .toLowerCase();
        if (!haystack.includes(needle)) return false;
      }
      return true;
    });
  }, [q.data, role, search]);

  return (
    <div className="space-y-4">
      <header className="flex items-end justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-xl font-semibold text-ink">Sessions</h1>
          <p className="text-sm text-ink-muted">All planner sessions, newest first.</p>
        </div>
        <div className="flex gap-2">
          <input
            className="input w-56"
            placeholder="Search id / model…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <select className="input" value={role} onChange={(e) => setRole(e.target.value)}>
            {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
        </div>
      </header>

      {q.isPending ? (
        <PageSpinner />
      ) : q.error ? (
        <ErrorBox error={q.error} onRetry={() => q.refetch()} />
      ) : filtered.length === 0 ? (
        <Empty title="No sessions." />
      ) : (
        <div className="card p-0 overflow-hidden">
          <table className="w-full text-sm">
            <thead className="text-xs text-ink-subtle bg-panel-high">
              <tr>
                <th className="text-left px-4 py-2 font-medium">Session</th>
                <th className="text-left px-4 py-2 font-medium">Role</th>
                <th className="text-left px-4 py-2 font-medium">State</th>
                <th className="text-left px-4 py-2 font-medium">Initiative / Task</th>
                <th className="text-left px-4 py-2 font-medium">Model</th>
                <th className="text-right px-4 py-2 font-medium">Tokens</th>
                <th className="text-right px-4 py-2 font-medium">Updated</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((s) => (
                <tr key={s.session_id} className="border-t border-edge/40 hover:bg-panel-high">
                  <td className="px-4 py-2">
                    <Link to={`/sessions/${s.session_id}`} className="text-ink hover:text-accent">
                      <Mono>{s.session_id.slice(0, 16)}…</Mono>
                    </Link>
                  </td>
                  <td className="px-4 py-2 text-ink-muted">{s.role}</td>
                  <td className="px-4 py-2">
                    <StateBadge state={s.state} pulse={s.state === "Running"} />
                  </td>
                  <td className="px-4 py-2 text-xs">
                    {s.initiative_id && (
                      <Link to={`/initiatives/${s.initiative_id}`} className="text-accent hover:underline font-mono">
                        {s.initiative_id}
                      </Link>
                    )}
                    {s.task_id && (
                      <div>
                        <Link to={`/tasks/${s.task_id}`} className="text-ink-muted hover:text-accent font-mono text-[11px]">
                          {s.task_id}
                        </Link>
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-2 text-xs text-ink-muted font-mono">
                    {s.provider ?? "—"}
                    <div className="text-[11px]">{s.model ?? "—"}</div>
                  </td>
                  <td className="px-4 py-2 text-right text-xs text-ink-muted tabular">
                    <span className="text-ink">{fmtTokens(s.input_tokens + s.output_tokens)}</span>
                    <div className="text-[10px]">
                      in {fmtTokens(s.input_tokens)} · out {fmtTokens(s.output_tokens)}
                    </div>
                  </td>
                  <td className="px-4 py-2 text-right text-xs text-ink-muted">
                    {fmtRelative(s.updated_at)}
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
