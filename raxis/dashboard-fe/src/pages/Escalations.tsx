import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { dashboardApi } from "@/api/client";
import { Empty } from "@/components/Empty";
import { ErrorBox } from "@/components/ErrorBox";
import { Mono } from "@/components/Mono";
import { PageSpinner } from "@/components/Spinner";
import { fmtRelative } from "@/lib/format";

export function EscalationsPage() {
  const q = useQuery({
    queryKey: ["escalations"],
    queryFn: ({ signal }) => dashboardApi.escalations.list(signal),
    refetchInterval: 5_000,
  });

  if (q.isPending) return <PageSpinner />;
  if (q.error) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  const items = q.data;

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold text-ink">Escalations</h1>
        <p className="text-sm text-ink-muted">Pending operator-action items.</p>
      </header>

      {items.length === 0 ? (
        <Empty title="No pending escalations." hint="Operator inbox is clear." />
      ) : (
        <ul className="space-y-3">
          {items.map((e) => (
            <li key={e.escalation_id} className="card p-4">
              <div className="flex items-start justify-between gap-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span
                      className={`badge ${
                        e.severity === "High"
                          ? "bg-bad-muted/30 border-bad text-bad"
                          : e.severity === "Normal"
                          ? "bg-warn-muted/30 border-warn text-warn"
                          : "bg-edge/40 border-edge-strong text-ink-muted"
                      }`}
                    >
                      {e.severity}
                    </span>
                    <Link
                      to={`/initiatives/${e.initiative_id}`}
                      className="text-sm text-accent hover:underline font-mono"
                    >
                      {e.initiative_id}
                    </Link>
                    {e.task_id && (
                      <Link
                        to={`/tasks/${e.task_id}`}
                        className="text-xs text-ink-muted hover:text-accent font-mono"
                      >
                        / {e.task_id}
                      </Link>
                    )}
                  </div>
                  <p className="mt-2 text-sm text-ink whitespace-pre-wrap">{e.reason}</p>
                  <p className="mt-2 text-xs text-ink-muted">
                    <strong className="text-ink">Action required:</strong>{" "}
                    {e.action_required}
                  </p>
                </div>
                <div className="text-right text-xs text-ink-subtle">
                  <Mono>{e.escalation_id.slice(0, 12)}…</Mono>
                  <div>{fmtRelative(e.created_at)}</div>
                </div>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
