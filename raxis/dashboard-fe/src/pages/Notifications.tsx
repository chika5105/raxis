import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useSearchParams } from "react-router-dom";

import { dashboardApi } from "@/api/client";
import { Empty } from "@/components/Empty";
import { ErrorBox } from "@/components/ErrorBox";
import { Mono } from "@/components/Mono";
import { PageSpinner } from "@/components/Spinner";
import { auditBadgeClasses } from "@/lib/audit-tone";
import { fmtRelative } from "@/lib/format";
import {
  decrementUnreadCount,
  markListAllRead,
  markListRowRead,
  NOTIFICATIONS_LIST_KEY,
  NOTIFICATIONS_PREFIX_KEY,
  rollbackNotificationCaches,
  snapshotNotificationCaches,
  zeroUnreadCount,
} from "@/lib/notification-cache";
import { notificationDisplaySummary } from "@/lib/notification-summary";

export function NotificationsPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [params, setParams] = useSearchParams();
  const initiativeId = params.get("initiative_id") ?? undefined;
  const [unreadOnly, setUnreadOnly] = useState(false);

  const list = useQuery({
    // The list cache lives under a `"list"` discriminator under
    // the shared `["notifications"]` prefix. Keeps the optimistic
    // `setQueriesData` writes in `markRead` / `markAll` from
    // accidentally trying to mutate the sibling
    // `["notifications", "unread-count"]` slice (different
    // payload shape). Coarse `["notifications"]` invalidation
    // still matches both branches.
    queryKey: [...NOTIFICATIONS_LIST_KEY, { unreadOnly, initiativeId }],
    queryFn: ({ signal }) =>
      dashboardApi.notifications.list(
        {
          unread_only: unreadOnly,
          limit: 200,
          ...(initiativeId ? { initiative_id: initiativeId } : {}),
        },
        signal,
      ),
    refetchInterval: 5_000,
  });

  // Mark a single notification as read with an optimistic write
  // against both cache slices that derive notification state:
  //   * `["notifications", "list", …]`  — the page list
  //   * `["notifications", "unread-count"]` — the sidebar badge
  //
  // Reconciliation runs INSIDE `mutationFn` (not `onSettled`)
  // because the row-click handler navigates to the linked
  // initiative / task on the same tick as `mutate()`, which
  // unmounts this component mid-mutation. TanStack Query's
  // `useMutation` deliberately suppresses `onSuccess` /
  // `onError` / `onSettled` callbacks for unmounted observers —
  // so an `onSettled`-based invalidation would silently no-op
  // for every row click, which is the bug operators were
  // reporting (the badge count stayed stale until the next
  // sidebar 10 s refetch tick). The invalidate call from inside
  // the awaited mutation body always runs to completion against
  // the global `QueryClient`, regardless of mount state.
  const markRead = useMutation({
    mutationFn: async (id: string) => {
      const result = await dashboardApi.notifications.markRead(id);
      void qc.invalidateQueries({ queryKey: NOTIFICATIONS_PREFIX_KEY });
      return result;
    },
    onMutate: async (id: string) => {
      // Cancel any in-flight notification refetches so they
      // don't race with the optimistic write and snap the cache
      // back to the pre-mark state.
      await qc.cancelQueries({ queryKey: NOTIFICATIONS_PREFIX_KEY });
      const snap = snapshotNotificationCaches(qc);
      const updatedRows = markListRowRead(qc, id);
      // Decrement by the same number of slices that flipped a
      // row, capped at 1 — the badge counts UNIQUE unread rows,
      // not per-slice flips. (`updatedRows > 0` means at least
      // one cached slice transitioned, so the underlying row
      // was previously unread, so the badge count should drop
      // by exactly 1.)
      decrementUnreadCount(qc, updatedRows > 0 ? 1 : 0);
      return snap;
    },
    onError: (_err, _id, ctx) => {
      if (ctx) rollbackNotificationCaches(qc, ctx);
    },
  });

  // Mark every unread notification as read. Same optimistic +
  // in-mutationFn-reconciliation pattern as `markRead`, except
  // the badge optimistically zeros out and every cached list
  // slice flips its unread rows.
  const markAll = useMutation({
    mutationFn: async () => {
      const result = await dashboardApi.notifications.markAllRead();
      void qc.invalidateQueries({ queryKey: NOTIFICATIONS_PREFIX_KEY });
      return result;
    },
    onMutate: async () => {
      await qc.cancelQueries({ queryKey: NOTIFICATIONS_PREFIX_KEY });
      const snap = snapshotNotificationCaches(qc);
      markListAllRead(qc);
      zeroUnreadCount(qc);
      return snap;
    },
    onError: (_err, _vars, ctx) => {
      if (ctx) rollbackNotificationCaches(qc, ctx);
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

      {initiativeId && (
        <div className="text-xs text-ink-muted">
          Filtered to initiative <Mono pill>{initiativeId}</Mono>{" "}
          <button
            type="button"
            onClick={() => setParams({})}
            className="text-accent hover:underline ml-2"
          >
            clear
          </button>
        </div>
      )}

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
                <p className="mt-1.5 text-sm text-ink">
                  {notificationDisplaySummary(
                    n.summary,
                    n.event_kind,
                    n.payload,
                  )}
                </p>
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
