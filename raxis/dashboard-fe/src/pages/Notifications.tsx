import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useSearchParams } from "react-router-dom";

import { ApiError, dashboardApi } from "@/api/client";
import { Empty } from "@/components/Empty";
import { ErrorBox } from "@/components/ErrorBox";
import { FailurePill } from "@/components/FailureReasonPanel";
import { Mono } from "@/components/Mono";
import { PageSpinner } from "@/components/Spinner";
import { auditBadgeClasses } from "@/lib/audit-tone";
import {
  failureFromAuditEvent,
  isFailureAuditEvent,
} from "@/lib/failure-extract";
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
import {
  applyPriorityFilter,
  compareByPriorityThenTimeDesc,
  PRIORITY_FILTER_VALUES,
  type PriorityFilter,
  priorityAriaLabel,
  priorityGlyph,
  priorityIconClasses,
  readSnoozeLowPriority,
  writeSnoozeLowPriority,
} from "@/lib/notification-priority";
import { notificationDisplaySummary } from "@/lib/notification-summary";

export function NotificationsPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [params, setParams] = useSearchParams();
  const initiativeId = params.get("initiative_id") ?? undefined;
  const [unreadOnly, setUnreadOnly] = useState(false);

  // ── INV-NOTIF-SCOPE-01 surface controls ──────────────────────
  // The priority pill filter is URL-driven (`?priority=Critical`)
  // so operators can deep-link "show me only Criticals" — same
  // pattern as the `?status=` legend filter shipped in `acf09e2`.
  // We coerce any unknown value back to `"All"` so a stale
  // bookmark or a typo can't trap the operator on an empty
  // pseudo-filter.
  const priorityParam = params.get("priority");
  const priorityFilter: PriorityFilter =
    PRIORITY_FILTER_VALUES.includes(priorityParam as PriorityFilter)
      ? (priorityParam as PriorityFilter)
      : "All";
  const setPriorityFilter = (next: PriorityFilter) => {
    const merged = new URLSearchParams(params);
    if (next === "All") {
      merged.delete("priority");
    } else {
      merged.set("priority", next);
    }
    setParams(merged, { replace: true });
  };

  // Snooze toggle persists via localStorage; off by default. We
  // hydrate from storage on mount and never read again — the
  // setter mirrors the change back into storage so multiple
  // tabs converge on next reload.
  const [snoozeLowPriority, setSnoozeLowPriority] = useState<boolean>(() =>
    readSnoozeLowPriority(),
  );
  const toggleSnooze = (next: boolean) => {
    setSnoozeLowPriority(next);
    writeSnoozeLowPriority(next);
  };

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

  // Sort + filter happens client-side: the server returns
  // every row that matches `unread_only` / `initiative_id`, and
  // the priority pill / snooze toggle act as visual lenses on
  // that result. This keeps the SQL hot-path simple (no priority
  // column index) and lets the operator switch pills without
  // burning a refetch.
  //
  // The `useMemo` MUST run before the early returns below so
  // React's rules-of-hooks invariant holds across renders — if
  // the loading branch returns first, then the success branch
  // calls `useMemo`, React sees a different hook count between
  // renders and tears the page down with "Rendered more hooks
  // than during the previous render".
  const items = list.data ?? [];
  const visibleItems = useMemo(() => {
    const filtered = applyPriorityFilter(items, priorityFilter, snoozeLowPriority);
    return [...filtered].sort(compareByPriorityThenTimeDesc);
  }, [items, priorityFilter, snoozeLowPriority]);

  if (list.isPending) return <PageSpinner />;
  if (list.error)
    return <ErrorBox error={list.error} onRetry={() => list.refetch()} />;

  // Empty-state copy is sensitive to which lens hid the rows so
  // the operator never wonders "are there really no
  // notifications, or am I looking through a too-narrow filter?"
  const hadAnyRows = items.length > 0;
  const allFiltersOff =
    priorityFilter === "All" && !snoozeLowPriority && !unreadOnly;

  return (
    <div className="space-y-4">
      <header className="flex items-end justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-xl font-semibold text-ink">Notifications</h1>
          <p className="text-sm text-ink-muted">
            Important events that need operator attention. The full
            audit-grade history of every operator action is in the{" "}
            <Link to="/audit" className="text-accent hover:underline">
              Audit Chain
            </Link>
            .
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
          <label
            className="text-sm text-ink-muted flex items-center gap-1.5"
            title="Hide Low + unclassified rows from the inbox. Stored locally; does not affect the audit chain."
          >
            <input
              type="checkbox"
              checked={snoozeLowPriority}
              onChange={(e) => toggleSnooze(e.target.checked)}
              className="accent-accent"
            />
            Snooze low-priority
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

      {/* INV-DASHBOARD-FAILURE-VISIBILITY-01 — surface
          mark-read / mark-all-read mutation failures inline so
          operators see why an inbox action did not take
          effect. Anchored above the priority pills so the banner
          stays visually attached to the header buttons that
          triggered it. */}
      {markAll.error && (
        <ActionFailureBanner
          label="Mark all read failed"
          error={markAll.error}
          onDismiss={() => markAll.reset()}
        />
      )}
      {markRead.error && (
        <ActionFailureBanner
          label="Mark read failed"
          error={markRead.error}
          onDismiss={() => markRead.reset()}
        />
      )}

      {/* Priority filter pills — Critical / High / Medium / Low / All.
          Mirrors the clickable status legend pattern shipped in
          `acf09e2` so operators can switch lenses without leaving
          the page. URL-driven (`?priority=…`) for deep-linking. */}
      <nav
        aria-label="Filter notifications by priority"
        className="flex items-center gap-1.5 flex-wrap text-xs"
      >
        {PRIORITY_FILTER_VALUES.map((p) => {
          const active = priorityFilter === p;
          return (
            <button
              key={p}
              type="button"
              onClick={() => setPriorityFilter(p)}
              aria-pressed={active}
              className={`rounded-full px-3 py-1 border transition-colors ${
                active
                  ? "bg-accent text-white border-accent"
                  : "bg-panel-low text-ink-muted border-edge hover:bg-panel-high"
              }`}
            >
              {p}
            </button>
          );
        })}
      </nav>

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

      {visibleItems.length === 0 ? (
        // INV-NOTIF-SCOPE-01: when the inbox is empty (either
        // because there really are no important events or the
        // active filters hid them), point the operator at the
        // audit chain so they understand the contract — Operator*
        // history lives there, not here.
        hadAnyRows && !allFiltersOff ? (
          <Empty
            title="No notifications match the active filters."
            hint={
              <span>
                Try selecting{" "}
                <button
                  type="button"
                  onClick={() => setPriorityFilter("All")}
                  className="text-accent hover:underline"
                >
                  All priorities
                </button>{" "}
                or clearing the snooze / unread-only toggles. Operator
                actions you've taken (mark-read, view-diff, …) are in
                the{" "}
                <Link to="/audit" className="text-accent hover:underline">
                  Audit Chain
                </Link>
                .
              </span>
            }
          />
        ) : (
          <Empty
            title="All caught up."
            hint={
              <span>
                Operator-action history is in the{" "}
                <Link to="/audit" className="text-accent hover:underline">
                  Audit Chain →
                </Link>
              </span>
            }
          />
        )
      ) : (
        <ul className="card p-0 overflow-hidden divide-y divide-edge/40">
          {visibleItems.map((n) => {
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
                  {/* Priority icon — Critical = red "!", High =
                      amber triangle, Medium = blue dot, Low =
                      gray dot, unclassified = hollow gray dot.
                      Sourced from server-projected
                      `n.priority` so the FE never re-derives the
                      audit→notification taxonomy. */}
                  <span
                    aria-label={priorityAriaLabel(n.priority)}
                    title={priorityAriaLabel(n.priority)}
                    className={`inline-flex items-center justify-center w-4 h-4 rounded-full text-[10px] font-bold leading-none ${priorityIconClasses(
                      n.priority,
                    )}`}
                  >
                    {priorityGlyph(n.priority)}
                  </span>
                  {!n.read && (
                    <span
                      className="w-1.5 h-1.5 rounded-full bg-accent"
                      aria-label="Unread"
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
                {/* INV-DASHBOARD-FAILURE-VISIBILITY-01 — when a
                    notification is itself a failure event, render
                    a compact `FailurePill` so the operator sees
                    "WHY did this fire?" without having to drill
                    into the audit log. */}
                {isFailureAuditEvent(n.event_kind, n.payload) && (
                  <div className="mt-1.5">
                    <FailurePill
                      failed
                      reason={failureFromAuditEvent(
                        n.event_kind,
                        n.payload,
                        { eventId: n.source_event_id, observedAt: n.created_at },
                      )}
                      compact
                    />
                  </div>
                )}
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

interface ActionFailureBannerProps {
  /// What the operator tried to do (e.g. "Mark all read failed").
  label: string;
  /// React Query mutation error.
  error: unknown;
  /// Clears the mutation error state so the banner auto-hides
  /// once the operator acknowledges it.
  onDismiss: () => void;
}

/// Inline error banner for failed dashboard mutations. Surfaces
/// the API `code` + `detail` (raw kernel error) so the operator
/// can read WHY the action failed without opening devtools.
///
/// Anchors `INV-DASHBOARD-FAILURE-VISIBILITY-01` clause on
/// operator-action rejections — when an Approve / Mark-read /
/// Re-verify fails with `RejectedPermission` / `InternalError`,
/// the operator MUST see the reason inline rather than a generic
/// toast.
function ActionFailureBanner({
  label,
  error,
  onDismiss,
}: ActionFailureBannerProps) {
  const isApi = error instanceof ApiError;
  const code = isApi ? error.code : "ERROR";
  const detail =
    isApi
      ? error.detail
      : error instanceof Error
        ? error.message
        : String(error);
  return (
    <div
      role="alert"
      data-testid="action-failure-banner"
      className="card border-bad/40 bg-bad/5 p-3 text-sm flex items-start gap-3"
    >
      <span aria-hidden="true" className="text-bad font-bold leading-none mt-0.5">
        !
      </span>
      <div className="flex-1 min-w-0">
        <p className="font-medium text-bad">{label}</p>
        <p className="mt-0.5 text-[12.5px] font-mono text-bad/90 break-words">
          {code}
        </p>
        <p className="mt-1 text-ink whitespace-pre-wrap break-words">
          {detail || "(no detail returned by the kernel)"}
        </p>
      </div>
      <button
        type="button"
        className="text-xs text-ink-muted hover:text-accent"
        onClick={onDismiss}
        aria-label="Dismiss"
      >
        Dismiss
      </button>
    </div>
  );
}
