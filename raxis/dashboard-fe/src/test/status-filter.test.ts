import { describe, expect, it } from "vitest";

import {
  parseStatusParam,
  serializeStatusParam,
  toggleStatus,
} from "@/lib/status-filter";

describe("parseStatusParam", () => {
  it("returns [] for null / empty input", () => {
    expect(parseStatusParam(null)).toEqual([]);
    expect(parseStatusParam("")).toEqual([]);
    expect(parseStatusParam("   ")).toEqual([]);
  });

  it("splits on comma, trims whitespace, drops empties", () => {
    expect(parseStatusParam("Running")).toEqual(["Running"]);
    expect(parseStatusParam("Running,Completed")).toEqual([
      "Running",
      "Completed",
    ]);
    expect(parseStatusParam(" Running , , Completed ,")).toEqual([
      "Running",
      "Completed",
    ]);
  });

  it("de-duplicates while preserving first-seen order", () => {
    expect(parseStatusParam("Running,Completed,Running")).toEqual([
      "Running",
      "Completed",
    ]);
  });
});

describe("serializeStatusParam", () => {
  it("joins with commas", () => {
    expect(serializeStatusParam([])).toBe("");
    expect(serializeStatusParam(["Running"])).toBe("Running");
    expect(serializeStatusParam(["Running", "Completed"])).toBe(
      "Running,Completed",
    );
  });
});

describe("toggleStatus", () => {
  it("plain click replaces single-status selection", () => {
    // empty -> click adds
    expect(toggleStatus([], "Running", false)).toEqual(["Running"]);
    // single active -> click same clears
    expect(toggleStatus(["Running"], "Running", false)).toEqual([]);
    // single active -> click different replaces
    expect(toggleStatus(["Running"], "Completed", false)).toEqual([
      "Completed",
    ]);
    // multi active -> plain click on one collapses to that one
    expect(toggleStatus(["Running", "Completed"], "Failed", false)).toEqual([
      "Failed",
    ]);
  });

  it("multi-select toggles in/out of the active set", () => {
    expect(toggleStatus([], "Running", true)).toEqual(["Running"]);
    expect(toggleStatus(["Running"], "Completed", true)).toEqual([
      "Running",
      "Completed",
    ]);
    expect(
      toggleStatus(["Running", "Completed"], "Completed", true),
    ).toEqual(["Running"]);
    expect(toggleStatus(["Running"], "Running", true)).toEqual([]);
  });

  it("preserves order on multi-select", () => {
    let s: string[] = [];
    s = toggleStatus(s, "Running", true);
    s = toggleStatus(s, "Completed", true);
    s = toggleStatus(s, "Failed", true);
    expect(s).toEqual(["Running", "Completed", "Failed"]);
    s = toggleStatus(s, "Completed", true);
    expect(s).toEqual(["Running", "Failed"]);
  });
});
