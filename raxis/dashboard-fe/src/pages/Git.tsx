import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { dashboardApi } from "@/api/client";
import { Empty } from "@/components/Empty";
import { ErrorBox } from "@/components/ErrorBox";
import { Mono } from "@/components/Mono";
import { PageSpinner } from "@/components/Spinner";
import { shortSha } from "@/lib/format";

export function GitPage() {
  const q = useQuery({
    queryKey: ["worktrees"],
    queryFn: ({ signal }) => dashboardApi.git.list(signal),
    refetchInterval: 10_000,
  });

  if (q.isPending) return <PageSpinner />;
  if (q.error) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  const items = q.data;

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold text-ink">Git Worktrees</h1>
        <p className="text-sm text-ink-muted">
          Operator-allowed roots and per-session VM clones.
        </p>
      </header>

      {items.length === 0 ? (
        <Empty title="No worktrees registered." />
      ) : (
        <div className="card p-0 overflow-hidden">
          <table className="w-full text-sm">
            <thead className="text-xs text-ink-subtle bg-panel-high">
              <tr>
                <th className="text-left px-4 py-2 font-medium">Worktree</th>
                <th className="text-left px-4 py-2 font-medium">Kind</th>
                <th className="text-left px-4 py-2 font-medium">Path</th>
                <th className="text-left px-4 py-2 font-medium">Session / Task</th>
                <th className="text-left px-4 py-2 font-medium">Base</th>
              </tr>
            </thead>
            <tbody>
              {items.map((w) => (
                <tr key={w.name} className="border-t border-edge/40 hover:bg-panel-high">
                  <td className="px-4 py-2.5">
                    <Link to={`/git/${encodeURIComponent(w.name)}`} className="text-ink hover:text-accent">
                      {w.label}
                    </Link>
                    <div className="text-[11px] text-ink-subtle">
                      <Mono>{w.name}</Mono>
                    </div>
                  </td>
                  <td className="px-4 py-2.5">
                    <span
                      className={`badge ${
                        w.kind === "Main"
                          ? "bg-info-muted/30 border-info text-info"
                          : "bg-edge/40 border-edge-strong text-ink-muted"
                      }`}
                    >
                      {w.kind}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 font-mono text-[11px] text-ink-muted truncate max-w-[280px]" title={w.path}>
                    {w.path}
                  </td>
                  <td className="px-4 py-2.5 text-xs">
                    {w.session_id ? (
                      <Link to={`/sessions/${w.session_id}`} className="text-accent hover:underline font-mono">
                        {w.session_id.slice(0, 12)}…
                      </Link>
                    ) : (
                      <span className="text-ink-subtle">—</span>
                    )}
                    {w.task_id && (
                      <div>
                        <Link to={`/tasks/${w.task_id}`} className="text-ink-muted hover:text-accent font-mono text-[11px]">
                          {w.task_id}
                        </Link>
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-2.5 font-mono text-[11px] text-ink-muted">
                    {shortSha(w.base_sha)}
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
