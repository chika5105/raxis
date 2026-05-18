// `<RecentSessionsPage>` — bounded ring view of the last N
// sessions, regardless of their `revoked` flag.
//
// The Sessions page filters to active sessions only; the
// active-list lookup the kernel currently uses for that view
// drops `revoked = 1` rows the moment the session terminates.
// Operators investigating "what happened to that revoked
// session?" lost the row from their view.
//
// This page consumes `GET /api/recent-sessions` (one row per
// session in the SessionCapture-ring window). Each row shows
// the session's terminal annotation pre-classified by the
// backend's lifecycle module so an operator sees self-exit
// vs operator-revoke at a glance.
//
// `INV-DASHBOARD-RECENT-SESSIONS-RING-01`.

import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";

import { dashboardApi } from "@/api/client";
import { Empty } from "@/components/Empty";
import { ErrorBox } from "@/components/ErrorBox";
import {
  lifecycleDotClass,
  lifecycleSummary,
} from "@/components/lifecycle/LifecycleAnnotation";
import { Mono } from "@/components/Mono";
import { PageSpinner } from "@/components/Spinner";
import { fmtAbsolute, fmtBytes, fmtRelative } from "@/lib/format";

const PAGE_LIMIT = 100;

export function RecentSessionsPage() {
  const navigate = useNavigate();

  const q = useQuery({
    queryKey: ["recent-sessions", { limit: PAGE_LIMIT }],
    queryFn: ({ signal }) =>
      dashboardApi.sessions.recent(PAGE_LIMIT, signal),
    refetchInterval: 8_000,
  });

  return (
    <div className="space-y-4">
      <header className="flex items-end justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-xl font-semibold text-ink">Recent sessions</h1>
          <p className="text-sm text-ink-muted">
            Bounded ring of the most-recent {PAGE_LIMIT} sessions, including
            revoked + expired rows. The active Sessions list drops these — see
            the &quot;Lifecycle&quot; column for why each session ended.
          </p>
        </div>
      </header>

      {q.isPending ? (
        <PageSpinner />
      ) : q.error ? (
        <ErrorBox error={q.error} onRetry={() => q.refetch()} />
      ) : !q.data || q.data.length === 0 ? (
        <Empty
          title="No sessions in the recent ring."
          hint="The capture ring fills as the kernel emits per-session streams."
        />
      ) : (
        <div className="card p-0 overflow-hidden">
          <table
            data-testid="recent-sessions-table"
            className="w-full text-sm"
          >
            <thead className="text-xs text-ink-subtle bg-panel-high">
              <tr>
                <th className="text-left px-4 py-2 font-medium">Session</th>
                <th className="text-left px-4 py-2 font-medium">Agent</th>
                <th className="text-left px-4 py-2 font-medium">Initiative / Task</th>
                <th className="text-left px-4 py-2 font-medium">Lifecycle</th>
                <th className="text-right px-4 py-2 font-medium">Created</th>
                <th className="text-right px-4 py-2 font-medium">Terminated</th>
                <th className="text-right px-4 py-2 font-medium">Capture</th>
              </tr>
            </thead>
            <tbody>
              {q.data.map((s) => {
                const href = `/sessions/${s.session_id}`;
                return (
                  <tr
                    key={s.session_id}
                    tabIndex={0}
                    onClick={() => navigate(href)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        e.preventDefault();
                        navigate(href);
                      }
                    }}
                    className="border-t border-edge/40 hover:bg-panel-high cursor-pointer"
                  >
                    <td className="px-4 py-2">
                      <Link
                        to={href}
                        onClick={(e) => e.stopPropagation()}
                        className="text-ink hover:text-accent"
                      >
                        <Mono>{s.session_id.slice(0, 16)}…</Mono>
                      </Link>
                      {s.terminated_reason && (
                        <div className="text-[11px] text-ink-subtle mt-0.5">
                          {s.terminated_reason}
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-2 text-ink-muted">
                      {s.agent_type || "—"}
                    </td>
                    <td className="px-4 py-2 text-xs">
                      {s.initiative_id && (
                        <Link
                          to={`/initiatives/${s.initiative_id}`}
                          onClick={(e) => e.stopPropagation()}
                          className="text-accent hover:underline font-mono"
                        >
                          {s.initiative_id}
                        </Link>
                      )}
                      {s.task_id && (
                        <div>
                          <Link
                            to={`/tasks/${s.task_id}`}
                            onClick={(e) => e.stopPropagation()}
                            className="text-ink-muted hover:text-accent font-mono text-[11px]"
                          >
                            {s.task_id}
                          </Link>
                        </div>
                      )}
                      {!s.initiative_id && !s.task_id && (
                        <span className="text-ink-subtle">—</span>
                      )}
                    </td>
                    <td className="px-4 py-2 text-xs">
                      <span className="inline-flex items-center gap-2">
                        <span
                          className={`inline-block w-2 h-2 rounded-full ${lifecycleDotClass(
                            s.final_annotation ?? null,
                          )}`}
                          aria-hidden="true"
                        />
                        <span className="text-ink-muted">
                          {lifecycleSummary(s.final_annotation ?? null)}
                        </span>
                      </span>
                    </td>
                    <td className="px-4 py-2 text-right text-xs text-ink-muted">
                      <div>{fmtAbsolute(s.created_at)}</div>
                      <div className="text-[10px]">
                        {fmtRelative(s.created_at)}
                      </div>
                    </td>
                    <td className="px-4 py-2 text-right text-xs text-ink-muted">
                      {s.terminated_at ? (
                        <>
                          <div>{fmtAbsolute(s.terminated_at)}</div>
                          <div className="text-[10px]">
                            {fmtRelative(s.terminated_at)}
                          </div>
                        </>
                      ) : (
                        <span className="text-ink-subtle">—</span>
                      )}
                    </td>
                    <td className="px-4 py-2 text-right text-xs text-ink-muted tabular">
                      {fmtBytes(s.capture_bytes)}
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
