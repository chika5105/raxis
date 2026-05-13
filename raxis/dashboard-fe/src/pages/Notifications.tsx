import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";

import { dashboardApi } from "@/api/client";
import { Empty } from "@/components/Empty";
import { ErrorBox } from "@/components/ErrorBox";
import { Mono } from "@/components/Mono";
import { PageSpinner } from "@/components/Spinner";
import { auditBadgeClasses } from "@/lib/audit-tone";
import { fmtRelative } from "@/lib/format";

export function NotificationsPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [unreadOnly, setUnreadOnly] = useState(false);

  const list = useQuery({
    queryKey: ["notifications", { unreadOnly }],
    queryFn: ({ signal }) =>
      dashboardApi.notifications.list(
        { unread_only: unreadOnly, limit: 200 },
        signal,
      ),
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
  if (list.error)
    return <ErrorBox error={list.error} onRetry={() => list.refetch()} />;
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
            type="button"
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
          {items.map((n) => {
            // Default activation drills into the linked entity
            // (initiative > task) and marks the notification
            // read, mirroring the Slack/Gmail "click row to
            // open" pattern operators expect. Notifications
            // with neither id are non-navigable but still
            // clickable to mark read.
            const href = n.initiative_id
              ? `/initiatives/${n.initiative_id}`
              : n.task_id
                ? `/tasks/${n.task_id}`
                : null;
            const activate = () => {
              if (!n.read) markRead.mutate(n.notification_id);
              if (href) navigate(href);
            };
            return (
              <li
                key={n.notification_id}
                tabIndex={0}
                role={href ? "link" : "button"}
                onClick={activate}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    activate();
                  }
                }}
                className={`px-4 py-3 hover:bg-panel-high cursor-pointer focus:outline-none focus-visible:ring-1 focus-visible:ring-accent ${
                  n.read ? "opacity-70" : ""
                }`}
              >
                <div className="flex items-center gap-2 flex-wrap">
                  {!n.read && (
                    <span
                      className="w-1.5 h-1.5 rounded-full bg-accent"
                      aria-hidden="true"
                    />
                  )}
                  <span className={auditBadgeClasses(n.event_kind)}>
                    {n.event_kind}
                  </span>
                  {n.initiative_id && (
                    <Link
                      to={`/initiatives/${n.initiative_id}`}
                      onClick={(e) => e.stopPropagation()}
                      className="text-sm text-accent hover:underline font-mono"
                    >
                      {n.initiative_id}
                    </Link>
                  )}
                  {n.task_id && (
                    <Link
                      to={`/tasks/${n.task_id}`}
                      onClick={(e) => e.stopPropagation()}
                      className="text-xs text-ink-muted hover:text-accent font-mono"
                    >
                      · {n.task_id}
                    </Link>
                  )}
                  <span className="ml-auto flex items-center gap-3 text-xs text-ink-subtle">
                    <span>{fmtRelative(n.created_at)}</span>
                    {!n.read && (
                      <button
                        type="button"
                        className="text-accent hover:underline focus:outline-none focus-visible:underline"
                        onClick={(e) => {
                          e.stopPropagation();
                          markRead.mutate(n.notification_id);
                        }}
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
            );
          })}
        </ul>
      )}
    </div>
  );
}
