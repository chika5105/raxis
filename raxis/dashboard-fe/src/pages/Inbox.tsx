import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";

import { dashboardApi } from "@/api/client";
import { Empty } from "@/components/Empty";
import { ErrorBox } from "@/components/ErrorBox";
import { Mono } from "@/components/Mono";
import { PageSpinner } from "@/components/Spinner";
import { fmtRelative } from "@/lib/format";

export function InboxPage() {
  const navigate = useNavigate();
  const q = useQuery({
    queryKey: ["inbox"],
    queryFn: ({ signal }) => dashboardApi.inbox(signal),
    refetchInterval: 5_000,
  });

  if (q.isPending) return <PageSpinner />;
  if (q.error) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  const items = q.data;

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold text-ink">Operator Inbox</h1>
        <p className="text-sm text-ink-muted">
          Unified queue of escalations, reviews awaiting acknowledgement, and
          initiatives waiting on operator input.
        </p>
      </header>

      {items.length === 0 ? (
        <Empty title="Inbox zero." hint="No pending operator actions." />
      ) : (
        <div className="card p-0 overflow-hidden">
          <ul className="divide-y divide-edge/50">
            {items.map((a) => {
              // Drill-in target: prefer initiative, fall back
              // to task. Some inbox events (e.g.
              // PolicyEpochAdvanced) carry neither — render
              // those as plain non-interactive rows so the
              // hover affordance doesn't lie about
              // clickability.
              const href = a.initiative_id
                ? `/initiatives/${a.initiative_id}`
                : a.task_id
                ? `/tasks/${a.task_id}`
                : null;
              const interactive = href !== null;
              const interactiveProps = interactive
                ? {
                    tabIndex: 0,
                    role: "link",
                    onClick: () => navigate(href!),
                    onKeyDown: (e: React.KeyboardEvent<HTMLLIElement>) => {
                      if (e.key === "Enter") {
                        e.preventDefault();
                        navigate(href!);
                      }
                    },
                  }
                : {};
              return (
              <li
                key={a.event_id}
                {...interactiveProps}
                className={`px-4 py-3 ${
                  interactive
                    ? "hover:bg-panel-high cursor-pointer focus:outline-none focus-visible:ring-1 focus-visible:ring-accent"
                    : ""
                }`}
              >
                <div className="flex items-center gap-3 flex-wrap">
                  <span className="badge bg-warn-muted/30 border-warn text-warn">
                    {a.event_kind}
                  </span>
                  {a.initiative_id && (
                    <Link
                      to={`/initiatives/${a.initiative_id}`}
                      onClick={(e) => e.stopPropagation()}
                      className="text-sm text-accent hover:underline font-mono"
                    >
                      {a.initiative_id}
                    </Link>
                  )}
                  {a.task_id && (
                    <Link
                      to={`/tasks/${a.task_id}`}
                      onClick={(e) => e.stopPropagation()}
                      className="text-xs text-ink-muted hover:text-accent font-mono"
                    >
                      · {a.task_id}
                    </Link>
                  )}
                  <span className="ml-auto text-xs text-ink-subtle">
                    <Mono>#{a.seq}</Mono> · {fmtRelative(a.at)}
                  </span>
                </div>
                <pre className="mt-2 text-[11px] text-ink-muted font-mono overflow-x-auto overscroll-x-auto scroll-thin">
                  {JSON.stringify(a.payload, null, 2)}
                </pre>
              </li>
              );
            })}
          </ul>
        </div>
      )}
    </div>
  );
}
