import { describe, expect, it } from "vitest";

import {
  shortStateLabel,
  stateTone,
  toneClasses,
} from "@/lib/state-color";

describe("stateTone", () => {
  it("maps legacy / mock-test state aliases", () => {
    expect(stateTone("Pending")).toBe("muted");
    expect(stateTone("Active")).toBe("info");
    expect(stateTone("Running")).toBe("info");
    expect(stateTone("Completed")).toBe("ok");
    expect(stateTone("Failed")).toBe("bad");
    expect(stateTone("Blocked")).toBe("block");
    expect(stateTone("Reviewing")).toBe("warn");
  });

  it("maps real kernel InitiativeState variants", () => {
    expect(stateTone("Draft")).toBe("muted");
    expect(stateTone("ApprovedPlan")).toBe("warn");
    expect(stateTone("Executing")).toBe("info");
    expect(stateTone("Aborted")).toBe("block");
  });

  it("maps real kernel TaskState variants", () => {
    expect(stateTone("Admitted")).toBe("muted");
    expect(stateTone("GatesPending")).toBe("warn");
    expect(stateTone("Cancelled")).toBe("block");
    expect(stateTone("BlockedRecoveryPending")).toBe("warn");
  });

  it("normalizes case for unknown variants", () => {
    expect(stateTone("ACTIVE")).toBe("info");
    expect(stateTone("running")).toBe("info");
  });

  it("falls through to muted for unrecognized states", () => {
    expect(stateTone("ZZZ_UNKNOWN")).toBe("muted");
    expect(stateTone(null)).toBe("muted");
  });

  it("toneClasses returns AA-contrast Tailwind utility strings", () => {
    // Each tone now bakes in BOTH a light-mode pair (-700 tinted
    // bg + -800/-900 text) AND a dark-mode pair (-500 tinted bg
    // + -200 text). This mirrors the local-component contrast
    // pattern landed by `worker/fe-audit-banner-contrast`
    // (commit 9e8f063, ChainStatusBanner.tsx) — see the
    // file-level comment in `state-color.ts` for the full WCAG
    // ratio table that motivates the move.
    const okClasses = toneClasses("ok");
    expect(okClasses).toContain("bg-emerald-700/10");
    expect(okClasses).toContain("text-emerald-800");
    expect(okClasses).toContain("dark:bg-emerald-500/10");
    expect(okClasses).toContain("dark:text-emerald-200");

    const badClasses = toneClasses("bad");
    expect(badClasses).toContain("text-rose-800");
    expect(badClasses).toContain("dark:text-rose-200");
  });
});

describe("shortStateLabel", () => {
  it("upper-cases short single-segment names verbatim", () => {
    expect(shortStateLabel("Running")).toBe("RUNNING");
    expect(shortStateLabel("Failed")).toBe("FAILED");
    expect(shortStateLabel("Completed")).toBe("COMPLETED");
  });

  it("collapses PascalCase compounds to the leading word", () => {
    // BlockedRecoveryPending (22 chars) overflows the DAG chip;
    // the leading PascalCase token is the most-meaningful glance.
    expect(shortStateLabel("BlockedRecoveryPending")).toBe("BLOCKED");
    expect(shortStateLabel("ApprovedPlan")).toBe("APPROVED");
    expect(shortStateLabel("GatesPending")).toBe("GATES");
  });

  it("clips a long single token at 9 chars + ellipsis", () => {
    // Defensive: a 11+ char single-word state (none today, but
    // guard anyway) gets clipped rather than overflowing the chip.
    expect(shortStateLabel("Verylongstatename")).toBe("VERYLONGS…");
  });

  it("renders an em-dash for null / empty states", () => {
    expect(shortStateLabel(null)).toBe("—");
    expect(shortStateLabel(undefined)).toBe("—");
    expect(shortStateLabel("")).toBe("—");
    expect(shortStateLabel("   ")).toBe("—");
  });
});
