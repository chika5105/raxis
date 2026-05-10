import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { dashboardApi } from "@/api/client";
import { Empty } from "@/components/Empty";
import { ErrorBox } from "@/components/ErrorBox";
import { Mono } from "@/components/Mono";
import { PageSpinner } from "@/components/Spinner";
import { fmtRelative } from "@/lib/format";

export function NotificationsPage() {
  const qc = useQueryClient();
  const [unreadOnly, setUnreadOnly] = useState(false);

  const list = useQuery({
    queryKey: ["notifications", { unreadOnly }],
    queryFn: ({ signal }) =>
      dashboardApi.notifications.list({ unread_only: unreadOnly, limit: 200 }, signal),
    refetchInterval: 5_000,
  });

  const markRead = useMutation({
    mutationFn: (id: string) => dashboardApi.notifications.markRead(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["notifications"] });
      qc.invalidateQueries({ queryKey: ["notifications", "unread-count"] });
    },
  });

  const markAll = useMutation({
    mutationFn: () => dashboardApi.notifications.markAllRead(),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["notifications"] });
      qc.invalidateQueries({ queryKey: ["notifications", "unread-count"] });
    },
  });

  if (list.isPending) return <PageSpinner />;
  if (list.error) return <ErrorBox error={list.error} onRetry={() => list.refetch()} />;
  const items = list.data;

  return (
    <div className="space-y-4">
      <header className="flex items-end justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-xl font-semibold text-ink">Notifications</h1>
          <p className="text-sm text-ink-muted">
            Routed events that matched the active{" "}
            <code className="font-mono">[notifications]</code> policy.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <label className="text-sm text-ink-muted flex items-center gap-1.5">
            <input
              type="checkbox"
              checked={unreadOnly}
              onChange={(e) => setUnreadOnly(e.target.checked)}
              className="accent-accent"
            />
            Unread only
          </label>
          <button
            className="btn"
            disabled={markAll.isPending}
            onClick={() => markAll.mutate()}
          >
            Mark all read
          </button>
        </div>
      </header>

      {items.length === 0 ? (
        <Empty title="No notifications." />
      ) : (
        <ul className="card p-0 overflow-hidden divide-y divide-edge/40">
          {items.map((n) => (
            <li
              key={n.notification_id}
              className={`px-4 py-3 hover:bg-panel-high ${n.read ? "opacity-70" : ""}`}
            >
              <div className="flex items-center gap-2 flex-wrap">
                {!n.read && <span className="w-1.5 h-1.5 rounded-full bg-accent" aria-hidden="true" />}
                <span className="badge bg-info-muted/30 border-info text-info">
                  {n.event_kind}
                </span>
                {n.initiative_id && (
                  <Link
                    to={`/initiatives/${n.initiative_id}`}
                    className="text-sm text-accent hover:underline font-mono"
                  >
                    {n.initiative_id}
                  </Link>
                )}
                {n.task_id && (
                  <Link
                    to={`/tasks/${n.task_id}`}
                    className="text-xs text-ink-muted hover:text-accent font-mono"
                  >
                    · {n.task_id}
                  </Link>
                )}
                <span className="ml-auto flex items-center gap-3 text-xs text-ink-subtle">
                  <span>{fmtRelative(n.created_at)}</span>
                  {!n.read && (
                    <button
                      className="text-accent hover:underline"
                      onClick={() => markRead.mutate(n.notification_id)}
                    >
                      Mark read
                    </button>
                  )}
                </span>
              </div>
              <p className="mt-1.5 text-sm text-ink">{n.summary}</p>
              <Mono className="text-[10px] text-ink-subtle">
                source event {n.source_event_id}
              </Mono>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
