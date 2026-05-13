// Optimistic-update + rollback helpers for the notification
// cache slices in TanStack Query.
//
// Two cache slices are involved:
//   * `["notifications", "list", …]` — every variant of the
//     Notifications page list (unread-only on/off, optional
//     `initiative_id` filter) is its own cache entry under
//     this prefix. There can be multiple live list slices
//     simultaneously (e.g. the operator toggled the filter
//     a few times and TanStack Query is still holding the
//     prior result in `gcTime`).
//   * `["notifications", "unread-count"]` — single slice
//     read by the sidebar badge in `<Shell />`.
//
// The shared `["notifications"]` prefix is what the
// invalidation calls in `Notifications.tsx` use — TanStack
// Query's prefix match invalidates both branches in one go.
//
// The split of the list under a `"list"` discriminator (vs
// the v0 layout, which keyed list slices directly under
// `["notifications", { …filters… }]`) lets the optimistic
// `setQueriesData` writes target the list shape precisely,
// without accidentally invoking the updater on the count
// slice — whose payload is `{ count: number }`, not
// `NotificationView[]`.

import type { QueryClient, QueryKey } from "@tanstack/react-query";

import type { NotificationView, UnreadCountResponse } from "@/types/api";

/// React Query cache key prefix for every "list" slice on the
/// Notifications page. Exported so the page itself, this module,
/// and any future test helpers all reference the same constant.
export const NOTIFICATIONS_LIST_KEY = ["notifications", "list"] as const;

/// React Query cache key for the sidebar unread-count badge.
export const NOTIFICATIONS_UNREAD_COUNT_KEY = [
  "notifications",
  "unread-count",
] as const;

/// Coarse prefix that matches every notification cache slice
/// (list + unread-count). Used for invalidation after a
/// mark-read mutation so both surfaces refetch.
export const NOTIFICATIONS_PREFIX_KEY = ["notifications"] as const;

/// Snapshot returned by `snapshotNotificationCaches`. Captures
/// every list-shape cache slice plus the badge-count slice so
/// an optimistic update can be rolled back atomically on error.
export interface NotificationCacheSnapshot {
  /// `[queryKey, previousData]` tuples for every matching list
  /// slice — the same shape `QueryClient.getQueriesData` returns.
  listSnapshots: Array<[QueryKey, NotificationView[] | undefined]>;
  /// Previous badge-count value, or `undefined` if the badge
  /// query hasn't populated its cache yet (operator is on the
  /// login page, etc.).
  countSnapshot: UnreadCountResponse | undefined;
}

/// Capture the current state of every notification cache slice.
/// Call this from a mutation's `onMutate` before applying the
/// optimistic write — the returned value flows into `onError`
/// as the third argument and is the input to
/// `rollbackNotificationCaches`.
export function snapshotNotificationCaches(
  qc: QueryClient,
): NotificationCacheSnapshot {
  const listSnapshots = qc.getQueriesData<NotificationView[]>({
    queryKey: NOTIFICATIONS_LIST_KEY,
  });
  const countSnapshot = qc.getQueryData<UnreadCountResponse>(
    NOTIFICATIONS_UNREAD_COUNT_KEY,
  );
  return { listSnapshots, countSnapshot };
}

/// Restore every cache slice captured by
/// `snapshotNotificationCaches`. Used on mutation error so the
/// optimistic UI doesn't lie to the operator after a server
/// reject / 5xx.
export function rollbackNotificationCaches(
  qc: QueryClient,
  snap: NotificationCacheSnapshot,
): void {
  for (const [key, value] of snap.listSnapshots) {
    qc.setQueryData(key, value);
  }
  if (snap.countSnapshot !== undefined) {
    qc.setQueryData(NOTIFICATIONS_UNREAD_COUNT_KEY, snap.countSnapshot);
  }
}

/// Optimistically flip `read = true` for `notificationId` in
/// every cached list slice that contains it. Returns the number
/// of list slices that were actually mutated (a row may live in
/// multiple cached filter variants — e.g. "all" + "this
/// initiative" — and we update them all).
///
/// No-op for slices where the row is already read, or where the
/// row isn't present (different filter / pagination cap).
export function markListRowRead(
  qc: QueryClient,
  notificationId: string,
): number {
  let updated = 0;
  qc.setQueriesData<NotificationView[]>(
    { queryKey: NOTIFICATIONS_LIST_KEY },
    (old) => {
      if (!Array.isArray(old)) return old;
      let touched = false;
      const next = old.map((n) => {
        if (n.notification_id === notificationId && !n.read) {
          touched = true;
          return { ...n, read: true };
        }
        return n;
      });
      if (touched) {
        updated++;
        return next;
      }
      return old;
    },
  );
  return updated;
}

/// Optimistically flip `read = true` for every unread row in
/// every cached list slice. Returns the total number of rows
/// flipped across all slices — useful for telemetry / logging
/// but not consumed by the page today.
export function markListAllRead(qc: QueryClient): number {
  let total = 0;
  qc.setQueriesData<NotificationView[]>(
    { queryKey: NOTIFICATIONS_LIST_KEY },
    (old) => {
      if (!Array.isArray(old)) return old;
      let touched = false;
      const next = old.map((n) => {
        if (n.read) return n;
        touched = true;
        total++;
        return { ...n, read: true };
      });
      return touched ? next : old;
    },
  );
  return total;
}

/// Optimistically decrement the badge unread count by `n`,
/// floored at zero. Skips the write if the badge cache hasn't
/// been populated yet (the sidebar query may still be in
/// flight on first load) — the natural refetch will populate
/// it shortly with the correct post-mutation count.
export function decrementUnreadCount(qc: QueryClient, n: number): void {
  if (n <= 0) return;
  const current = qc.getQueryData<UnreadCountResponse>(
    NOTIFICATIONS_UNREAD_COUNT_KEY,
  );
  if (!current) return;
  qc.setQueryData<UnreadCountResponse>(NOTIFICATIONS_UNREAD_COUNT_KEY, {
    count: Math.max(0, current.count - n),
  });
}

/// Optimistically zero out the badge unread count. Used by
/// `markAllRead` so the sidebar drops to nothing IMMEDIATELY
/// on click rather than waiting for the kernel round-trip.
export function zeroUnreadCount(qc: QueryClient): void {
  if (
    qc.getQueryData<UnreadCountResponse>(NOTIFICATIONS_UNREAD_COUNT_KEY) ===
    undefined
  ) {
    return;
  }
  qc.setQueryData<UnreadCountResponse>(NOTIFICATIONS_UNREAD_COUNT_KEY, {
    count: 0,
  });
}
