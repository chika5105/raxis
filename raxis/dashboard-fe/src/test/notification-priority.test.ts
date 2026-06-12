import { describe, expect, it } from "vitest";

import {
  applyPriorityFilter,
  compareByPriorityThenTimeDesc,
  compareByTimeDescThenPriority,
  priorityAriaLabel,
  priorityRank,
  type PriorityFilter,
  readSnoozeLowPriority,
  writeSnoozeLowPriority,
} from "@/lib/notification-priority";
import type { NotificationView } from "@/types/api";

function row(
  id: string,
  priority: NotificationView["priority"],
  ts: number,
): NotificationView {
  return {
    notification_id: id,
    event_kind:      "EscalationPending",
    initiative_id:   null,
    task_id:         null,
    session_id:      null,
    summary:         `notif ${id}`,
    payload:         {},
    read:            false,
    source_event_id: `evt-${id}`,
    created_at:      ts,
    priority,
  };
}

describe("priorityRank", () => {
  it("orders Critical < High < Medium < Low < unclassified", () => {
    expect(priorityRank("Critical")).toBeLessThan(priorityRank("High"));
    expect(priorityRank("High")).toBeLessThan(priorityRank("Medium"));
    expect(priorityRank("Medium")).toBeLessThan(priorityRank("Low"));
    expect(priorityRank("Low")).toBeLessThan(priorityRank(null));
    expect(priorityRank(undefined)).toBe(priorityRank(null));
  });
});

describe("compareByPriorityThenTimeDesc", () => {
  it("Critical sorts above High regardless of time", () => {
    const old_critical = row("c", "Critical", 100);
    const new_high = row("h", "High", 9_999);
    expect(compareByPriorityThenTimeDesc(old_critical, new_high))
      .toBeLessThan(0);
  });

  it("within the same bucket, newest first", () => {
    const old_low = row("a", "Low", 100);
    const new_low = row("b", "Low", 200);
    expect(compareByPriorityThenTimeDesc(new_low, old_low)).toBeLessThan(0);
  });

  it("unclassified rows sort to the bottom", () => {
    const new_unclassified = row("u", null, 9_999);
    const old_low = row("l", "Low", 0);
    expect(compareByPriorityThenTimeDesc(old_low, new_unclassified))
      .toBeLessThan(0);
  });

  it("is sort-stable across the canonical example mix", () => {
    const rows = [
      row("low-old",    "Low",        50),
      row("crit-newer", "Critical",   200),
      row("med-mid",    "Medium",     150),
      row("crit-older", "Critical",   100),
      row("high-newest","High",       300),
      row("none-newest", null,        9_999),
    ];
    const sorted = [...rows].sort(compareByPriorityThenTimeDesc);
    expect(sorted.map((r) => r.notification_id)).toEqual([
      "crit-newer",
      "crit-older",
      "high-newest",
      "med-mid",
      "low-old",
      "none-newest",
    ]);
  });
});

describe("compareByTimeDescThenPriority", () => {
  it("sorts newest first globally, even when the newer row has lower priority", () => {
    const old_critical = row("old-critical", "Critical", 100);
    const new_low = row("new-low", "Low", 200);
    expect(compareByTimeDescThenPriority(new_low, old_critical)).toBeLessThan(0);
  });

  it("uses priority as a tie-breaker for identical timestamps", () => {
    const critical = row("critical", "Critical", 100);
    const low = row("low", "Low", 100);
    expect(compareByTimeDescThenPriority(critical, low)).toBeLessThan(0);
  });
});

describe("applyPriorityFilter", () => {
  const rows = [
    row("c", "Critical", 1),
    row("h", "High",     2),
    row("m", "Medium",   3),
    row("l", "Low",      4),
    row("u", null,       5),
  ];

  it("'All' + snooze=false returns every row", () => {
    expect(applyPriorityFilter(rows, "All", false).map((r) => r.notification_id))
      .toEqual(["c", "h", "m", "l", "u"]);
  });

  it("'Critical' returns only Critical rows", () => {
    expect(applyPriorityFilter(rows, "Critical", false).map((r) => r.notification_id))
      .toEqual(["c"]);
  });

  it.each(["All", "Critical", "High", "Medium"] as PriorityFilter[])(
    "snooze=true on filter=%s hides Low + unclassified",
    (filter) => {
      const out = applyPriorityFilter(rows, filter, true)
        .map((r) => r.notification_id);
      expect(out).not.toContain("l");
      expect(out).not.toContain("u");
    },
  );

  it("snooze=true + filter='Low' STILL shows Low rows (explicit filter wins)", () => {
    expect(applyPriorityFilter(rows, "Low", true).map((r) => r.notification_id))
      .toEqual(["l"]);
  });
});

describe("priorityAriaLabel", () => {
  it("emits a non-empty ARIA label for every bucket + unclassified", () => {
    expect(priorityAriaLabel("Critical")).toMatch(/critical/i);
    expect(priorityAriaLabel("High")).toMatch(/high/i);
    expect(priorityAriaLabel("Medium")).toMatch(/medium/i);
    expect(priorityAriaLabel("Low")).toMatch(/low/i);
    expect(priorityAriaLabel(null)).toMatch(/unclassified/i);
  });
});

describe("snooze localStorage helpers", () => {
  it("default is off", () => {
    window.localStorage.removeItem("raxis.notifications.snoozeLowPriority");
    expect(readSnoozeLowPriority()).toBe(false);
  });

  it("write/read round trips", () => {
    writeSnoozeLowPriority(true);
    expect(readSnoozeLowPriority()).toBe(true);
    writeSnoozeLowPriority(false);
    expect(readSnoozeLowPriority()).toBe(false);
  });
});
