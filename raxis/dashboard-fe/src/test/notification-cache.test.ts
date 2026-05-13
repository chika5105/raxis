import { QueryClient } from "@tanstack/react-query";
import { describe, expect, it } from "vitest";

import {
  decrementUnreadCount,
  markListAllRead,
  markListRowRead,
  NOTIFICATIONS_LIST_KEY,
  NOTIFICATIONS_PREFIX_KEY,
  NOTIFICATIONS_UNREAD_COUNT_KEY,
  rollbackNotificationCaches,
  snapshotNotificationCaches,
  zeroUnreadCount,
} from "@/lib/notification-cache";
import type { NotificationView, UnreadCountResponse } from "@/types/api";

function notif(
  id: string,
  read: boolean,
  initiative: string | null = null,
): NotificationView {
  return {
    notification_id: id,
    event_kind:      "EscalationPending",
    initiative_id:   initiative,
    task_id:         null,
    session_id:      null,
    summary:         `notif ${id}`,
    payload:         {},
    read,
    source_event_id: `evt-${id}`,
    created_at:      0,
  };
}

function freshClient(): QueryClient {
  // Disable retries in tests so any error path surfaces
  // immediately and predictably.
  return new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
}

describe("notification-cache helpers", () => {
  it("snapshot captures every list slice and the count slice", () => {
    const qc = freshClient();
    qc.setQueryData([...NOTIFICATIONS_LIST_KEY, { unreadOnly: false }], [
      notif("n-1", false),
      notif("n-2", true),
    ]);
    qc.setQueryData(
      [...NOTIFICATIONS_LIST_KEY, { unreadOnly: true }],
      [notif("n-1", false)],
    );
    qc.setQueryData<UnreadCountResponse>(NOTIFICATIONS_UNREAD_COUNT_KEY, {
      count: 1,
    });

    const snap = snapshotNotificationCaches(qc);
    expect(snap.listSnapshots).toHaveLength(2);
    expect(snap.countSnapshot).toEqual({ count: 1 });

    // Mutate caches into a totally different state.
    qc.setQueryData([...NOTIFICATIONS_LIST_KEY, { unreadOnly: false }], []);
    qc.setQueryData([...NOTIFICATIONS_LIST_KEY, { unreadOnly: true }], []);
    qc.setQueryData(NOTIFICATIONS_UNREAD_COUNT_KEY, { count: 999 });

    rollbackNotificationCaches(qc, snap);

    expect(
      qc.getQueryData<NotificationView[]>([
        ...NOTIFICATIONS_LIST_KEY,
        { unreadOnly: false },
      ]),
    ).toEqual([notif("n-1", false), notif("n-2", true)]);
    expect(
      qc.getQueryData<NotificationView[]>([
        ...NOTIFICATIONS_LIST_KEY,
        { unreadOnly: true },
      ]),
    ).toEqual([notif("n-1", false)]);
    expect(
      qc.getQueryData<UnreadCountResponse>(NOTIFICATIONS_UNREAD_COUNT_KEY),
    ).toEqual({ count: 1 });
  });

  it("snapshot is stable when the count slice has never been populated", () => {
    const qc = freshClient();
    qc.setQueryData([...NOTIFICATIONS_LIST_KEY, { unreadOnly: false }], [
      notif("n-1", false),
    ]);
    const snap = snapshotNotificationCaches(qc);
    expect(snap.countSnapshot).toBeUndefined();

    // Rollback after snapshot must not write `undefined` over a
    // count cache that the sidebar query may have populated
    // between snapshot and error.
    qc.setQueryData(NOTIFICATIONS_UNREAD_COUNT_KEY, { count: 7 });
    rollbackNotificationCaches(qc, snap);
    expect(
      qc.getQueryData<UnreadCountResponse>(NOTIFICATIONS_UNREAD_COUNT_KEY),
    ).toEqual({ count: 7 });
  });

  it("markListRowRead flips the matching row across every cached list slice", () => {
    const qc = freshClient();
    qc.setQueryData([...NOTIFICATIONS_LIST_KEY, { unreadOnly: false }], [
      notif("n-1", false),
      notif("n-2", false),
    ]);
    qc.setQueryData(
      [...NOTIFICATIONS_LIST_KEY, { initiativeId: "init-1" }],
      [notif("n-1", false, "init-1")],
    );

    const updated = markListRowRead(qc, "n-1");
    expect(updated).toBe(2);

    const all = qc.getQueryData<NotificationView[]>([
      ...NOTIFICATIONS_LIST_KEY,
      { unreadOnly: false },
    ]);
    expect(all?.find((n) => n.notification_id === "n-1")?.read).toBe(true);
    expect(all?.find((n) => n.notification_id === "n-2")?.read).toBe(false);

    const filtered = qc.getQueryData<NotificationView[]>([
      ...NOTIFICATIONS_LIST_KEY,
      { initiativeId: "init-1" },
    ]);
    expect(filtered?.[0].read).toBe(true);
  });

  it("markListRowRead is a no-op for an unknown id and an already-read row", () => {
    const qc = freshClient();
    qc.setQueryData([...NOTIFICATIONS_LIST_KEY, { unreadOnly: false }], [
      notif("n-1", true),
    ]);
    expect(markListRowRead(qc, "n-1")).toBe(0); // already read
    expect(markListRowRead(qc, "ghost")).toBe(0); // not in cache
    expect(
      qc.getQueryData<NotificationView[]>([
        ...NOTIFICATIONS_LIST_KEY,
        { unreadOnly: false },
      ]),
    ).toEqual([notif("n-1", true)]);
  });

  it("markListAllRead flips every unread row in every cached list slice", () => {
    const qc = freshClient();
    qc.setQueryData([...NOTIFICATIONS_LIST_KEY, { unreadOnly: false }], [
      notif("n-1", false),
      notif("n-2", false),
      notif("n-3", true),
    ]);
    qc.setQueryData([...NOTIFICATIONS_LIST_KEY, { unreadOnly: true }], [
      notif("n-1", false),
      notif("n-2", false),
    ]);

    const total = markListAllRead(qc);
    expect(total).toBe(4); // 2 in slice A + 2 in slice B

    const a = qc.getQueryData<NotificationView[]>([
      ...NOTIFICATIONS_LIST_KEY,
      { unreadOnly: false },
    ]);
    expect(a?.every((n) => n.read)).toBe(true);

    const b = qc.getQueryData<NotificationView[]>([
      ...NOTIFICATIONS_LIST_KEY,
      { unreadOnly: true },
    ]);
    expect(b?.every((n) => n.read)).toBe(true);
  });

  it("decrementUnreadCount decrements the badge count and floors at zero", () => {
    const qc = freshClient();
    qc.setQueryData<UnreadCountResponse>(NOTIFICATIONS_UNREAD_COUNT_KEY, {
      count: 3,
    });
    decrementUnreadCount(qc, 1);
    expect(
      qc.getQueryData<UnreadCountResponse>(NOTIFICATIONS_UNREAD_COUNT_KEY),
    ).toEqual({ count: 2 });

    decrementUnreadCount(qc, 99);
    expect(
      qc.getQueryData<UnreadCountResponse>(NOTIFICATIONS_UNREAD_COUNT_KEY),
    ).toEqual({ count: 0 });
  });

  it("decrementUnreadCount is a no-op when the badge cache hasn't been populated", () => {
    const qc = freshClient();
    decrementUnreadCount(qc, 1);
    expect(
      qc.getQueryData<UnreadCountResponse>(NOTIFICATIONS_UNREAD_COUNT_KEY),
    ).toBeUndefined();
  });

  it("decrementUnreadCount is a no-op for a non-positive delta", () => {
    const qc = freshClient();
    qc.setQueryData<UnreadCountResponse>(NOTIFICATIONS_UNREAD_COUNT_KEY, {
      count: 5,
    });
    decrementUnreadCount(qc, 0);
    decrementUnreadCount(qc, -1);
    expect(
      qc.getQueryData<UnreadCountResponse>(NOTIFICATIONS_UNREAD_COUNT_KEY),
    ).toEqual({ count: 5 });
  });

  it("zeroUnreadCount drops the badge to zero when populated, no-ops otherwise", () => {
    const qc = freshClient();
    zeroUnreadCount(qc);
    expect(
      qc.getQueryData<UnreadCountResponse>(NOTIFICATIONS_UNREAD_COUNT_KEY),
    ).toBeUndefined();

    qc.setQueryData<UnreadCountResponse>(NOTIFICATIONS_UNREAD_COUNT_KEY, {
      count: 7,
    });
    zeroUnreadCount(qc);
    expect(
      qc.getQueryData<UnreadCountResponse>(NOTIFICATIONS_UNREAD_COUNT_KEY),
    ).toEqual({ count: 0 });
  });

  it("the prefix key matches both list and unread-count slices", () => {
    // Sanity check that the prefix used by the page's
    // `invalidateQueries` actually covers both branches.
    const qc = freshClient();
    qc.setQueryData([...NOTIFICATIONS_LIST_KEY, { unreadOnly: false }], [
      notif("n-1", false),
    ]);
    qc.setQueryData<UnreadCountResponse>(NOTIFICATIONS_UNREAD_COUNT_KEY, {
      count: 1,
    });
    const matches = qc
      .getQueryCache()
      .findAll({ queryKey: NOTIFICATIONS_PREFIX_KEY });
    expect(matches).toHaveLength(2);
  });
});
