// `notification-priority.ts` — small frontend helpers around the
// server-projected `NotificationView.priority` field.
//
// Normative reference:
// `specs/v2/dashboard-hardening.md §2`,
// `specs/invariants.md INV-NOTIF-SCOPE-01`.
//
// What lives here
// ───────────────
//   * `priorityRank` for "Critical-first" sort ordering.
//   * `compareByTimeDescThenPriority` for the Notifications
//     inbox's newest-first ordering.
//   * `priorityToneClasses` for the row-icon Tailwind classes
//     (red / amber / blue / gray, AA-contrast vs panel-high).
//   * `priorityIconLabel` ARIA label for the row icon.
//   * `Snooze`-toggle localStorage helpers
//     (`readSnoozeLowPriority` / `writeSnoozeLowPriority`).
//
// What does NOT live here
// ───────────────────────
//   * The audit→notification taxonomy itself. The server projects
//     `event_kind → priority` via
//     `raxis_dashboard_kernel::notification_priority_for_kind_str`
//     and stamps the resulting string onto every row. The
//     frontend reads `n.priority` verbatim — we never re-derive
//     it from `event_kind` here, because that would be the drift
//     vector `INV-NOTIF-SCOPE-01` exists to prevent.

import type { NotificationPriority, NotificationView } from "@/types/api";

/**
 * Rank used for "Critical-first, then time-desc" sort. Lower
 * rank = higher visual priority. Unclassified rows (server
 * returned `priority: null`) sort to the very bottom.
 */
export function priorityRank(p: NotificationPriority | null | undefined): number {
  switch (p) {
    case "Critical":
      return 0;
    case "High":
      return 1;
    case "Medium":
      return 2;
    case "Low":
      return 3;
    default:
      return 4;
  }
}

/**
 * Compose a side-by-side ordering tuple for the inbox: priority
 * bucket first, then time-desc within the bucket. Operators see
 * the most urgent banner at the top, with newest-within-bucket
 * underneath.
 */
export function compareByPriorityThenTimeDesc(
  a: NotificationView,
  b: NotificationView,
): number {
  const ra = priorityRank(a.priority);
  const rb = priorityRank(b.priority);
  if (ra !== rb) return ra - rb;
  return b.created_at - a.created_at;
}

/**
 * Newest-first inbox ordering. Priority is only a tie-breaker so
 * the operator can trust the Notifications page as a timeline.
 */
export function compareByTimeDescThenPriority(
  a: NotificationView,
  b: NotificationView,
): number {
  if (a.created_at !== b.created_at) return b.created_at - a.created_at;
  return priorityRank(a.priority) - priorityRank(b.priority);
}

/**
 * Tailwind classes for the priority dot rendered before each row.
 * Picked to match the spec's `Critical = red exclamation`,
 * `High = amber`, `Medium = blue`, `Low = gray dot` palette and
 * to clear AA contrast on both the panel-high (light) and
 * panel-high (dark) backgrounds in the existing tokens.
 */
export function priorityIconClasses(
  p: NotificationPriority | null | undefined,
): string {
  switch (p) {
    case "Critical":
      // Solid red circle with a white "!" — strongest at-a-
      // glance signal, mirrors macOS/Linux notification-bell red.
      return "bg-red-500 text-white";
    case "High":
      return "bg-amber-500 text-white";
    case "Medium":
      return "bg-blue-500 text-white";
    case "Low":
      return "bg-zinc-400 text-white";
    default:
      // Legacy / unclassified — same gray as Low but hollow so
      // the operator can tell it's a fallback rather than an
      // explicit Low-priority decision.
      return "bg-transparent text-ink-subtle border border-edge";
  }
}

/**
 * The single character rendered inside the priority dot. Picked
 * for at-a-glance differentiation when colour alone is
 * insufficient (colour-blind / monochrome printer). Matches the
 * spec's "red exclamation".
 */
export function priorityGlyph(
  p: NotificationPriority | null | undefined,
): string {
  switch (p) {
    case "Critical":
      return "!";
    case "High":
      return "▲";
    case "Medium":
      return "●";
    case "Low":
      return "·";
    default:
      return "·";
  }
}

/** ARIA label for the row icon. */
export function priorityAriaLabel(
  p: NotificationPriority | null | undefined,
): string {
  switch (p) {
    case "Critical":
      return "Critical priority";
    case "High":
      return "High priority";
    case "Medium":
      return "Medium priority";
    case "Low":
      return "Low priority";
    default:
      return "Unclassified priority";
  }
}

/**
 * The set of priority pills the operator can pick from at the
 * top of the inbox. `"All"` is a synthetic value and not a real
 * priority bucket; render it last in the active pill but first in
 * the row order so the default-on case is left-most.
 */
export const PRIORITY_FILTER_VALUES = [
  "All",
  "Critical",
  "High",
  "Medium",
  "Low",
] as const;
export type PriorityFilter = (typeof PRIORITY_FILTER_VALUES)[number];

/**
 * Apply the priority pill + the optional snooze toggle, in
 * that order. Snooze hides everything below `Medium`
 * (i.e. `Low` and unclassified) UNLESS the operator has
 * explicitly picked `"Low"` as the filter, in which case we
 * defer to the explicit filter — the assumption being that an
 * operator who picks `Low` *does* want to see Low rows even with
 * snooze enabled.
 */
export function applyPriorityFilter(
  rows: readonly NotificationView[],
  filter: PriorityFilter,
  snoozeLowPriority: boolean,
): NotificationView[] {
  const pickFilter = (n: NotificationView) => {
    if (filter === "All") return true;
    return n.priority === filter;
  };
  const pickSnooze = (n: NotificationView) => {
    if (!snoozeLowPriority) return true;
    if (filter === "Low") return true;
    return n.priority === "Critical" || n.priority === "High" ||
      n.priority === "Medium";
  };
  return rows.filter((n) => pickFilter(n) && pickSnooze(n));
}

// ── Snooze-toggle localStorage helpers ─────────────────────────
//
// The snooze toggle is a per-operator UX preference that lives
// entirely in the browser; the server has no concept of "this
// operator wants Low rows hidden right now" because the same
// data is forensically valuable in the audit chain. We persist
// to localStorage so the choice survives page reloads but stays
// device-local.

const SNOOZE_KEY = "raxis.notifications.snoozeLowPriority";

/** Return the current snooze setting (default: `false`). */
export function readSnoozeLowPriority(): boolean {
  // Tests + SSR: localStorage is unavailable. Default to off.
  if (typeof window === "undefined" || !window.localStorage) return false;
  try {
    return window.localStorage.getItem(SNOOZE_KEY) === "1";
  } catch {
    // Some sandbox / private-mode browsers throw on .getItem.
    // Treat that as "off" rather than blowing up the inbox.
    return false;
  }
}

/** Persist the snooze setting. */
export function writeSnoozeLowPriority(snooze: boolean): void {
  if (typeof window === "undefined" || !window.localStorage) return;
  try {
    if (snooze) {
      window.localStorage.setItem(SNOOZE_KEY, "1");
    } else {
      window.localStorage.removeItem(SNOOZE_KEY);
    }
  } catch {
    // Ignore — operator's preference will reset to default on
    // next reload, but the inbox stays usable.
  }
}
