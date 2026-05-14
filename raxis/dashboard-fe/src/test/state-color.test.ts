import { describe, expect, it } from "vitest";

import {
  INTEGRATION_MERGE_DISPLAY_ID,
  KERNEL_INITIATIVE_STATES,
  KERNEL_SESSION_STATES,
  KERNEL_TASK_STATES,
  hasExplicitStateEntry,
  isIntegrationMergeTask,
  shortStateLabel,
  stateTone,
  taskDisplayId,
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

// ── INV-DASHBOARD-TASK-STATE-COMPLETENESS-01 ─────────────────────
//
// Every kernel `TaskState` FSM variant (eight today, as encoded
// by the `tasks.state` SQL CHECK constraint) MUST have a distinct,
// non-fallback renderer entry in `state-color.ts::MAP`. The
// matching kernel-side witness lives in
// `crates/dashboard-kernel/src/lib.rs::
//  inv_dashboard_task_state_completeness_projection_round_trips_every_variant`
// and pins the enum length so a future variant cannot land without
// updating both sides in the same commit.
//
// "Distinct" means: NO two TaskState variants may collide on the
// same tone, otherwise an operator cannot tell them apart at a
// glance — which is exactly the iter53 paper-cut where `Running`
// silently rendered with the same muted styling as `Admitted`.
describe("INV-DASHBOARD-TASK-STATE-COMPLETENESS-01", () => {
  it("registers an explicit (non-fallback) MAP entry for every kernel TaskState", () => {
    for (const state of KERNEL_TASK_STATES) {
      expect(
        hasExplicitStateEntry(state),
        `kernel TaskState '${state}' has no explicit entry in state-color.ts::MAP — ` +
          `it would silently render as the muted fallback and be visually indistinguishable ` +
          `from 'Admitted'. Add a tone mapping for this variant.`,
      ).toBe(true);
    }
  });

  it("assigns distinct tones across the task-state spectrum (Running ≠ Admitted)", () => {
    // Specifically pin the iter53 regression: the `Running` state
    // MUST NOT collapse into the same tone as `Admitted`, otherwise
    // operators can't tell whether a task is queued vs. executing.
    expect(stateTone("Running")).not.toBe(stateTone("Admitted"));
    expect(stateTone("Running")).not.toBe(stateTone("Completed"));
    expect(stateTone("Running")).not.toBe(stateTone("Failed"));
  });

  it("registers an explicit MAP entry for every kernel InitiativeState", () => {
    for (const state of KERNEL_INITIATIVE_STATES) {
      expect(
        hasExplicitStateEntry(state),
        `kernel InitiativeState '${state}' missing from state-color.ts::MAP`,
      ).toBe(true);
    }
  });

  it("registers an explicit MAP entry for every dashboard session-row state", () => {
    for (const state of KERNEL_SESSION_STATES) {
      expect(
        hasExplicitStateEntry(state),
        `dashboard session-row state '${state}' missing from state-color.ts::MAP`,
      ).toBe(true);
    }
  });

  it("pins the kernel TaskState length so a new variant trips this witness", () => {
    // Length drift here means the kernel `TaskState::ALL` array grew
    // without a matching update to `KERNEL_TASK_STATES` in
    // `state-color.ts`. The kernel-side witness
    // (`inv_dashboard_task_state_completeness_projection_round_trips_every_variant`)
    // pins the same length from the Rust side, so the two are
    // forced to move together.
    expect(KERNEL_TASK_STATES).toHaveLength(8);
  });
});

// ── INV-DASHBOARD-INTEGRATION-MERGE-VISIBLE-OR-EXCLUDED-01 ────────
//
// The synthetic IntegrationMerge coordinator row (kernel admits
// it with `task_id == initiative_id` in
// `auto_spawn_orchestrator_session_in_tx`) MUST surface a stable
// display id rather than the raw initiative UUID. The
// dashboard-kernel projection stamps the human title
// (`Integration merge`); the FE substitutes the stable display
// chip (`«integration-merge»`) wherever the task id would
// otherwise render as the same UUID as the parent initiative.
//
// Wire identifiers (routing, copy-to-clipboard, audit queries)
// keep using the real `task_id` so deep-links stay valid — the
// substitution is render-time only.
describe("INV-DASHBOARD-INTEGRATION-MERGE-VISIBLE-OR-EXCLUDED-01", () => {
  const INIT_ID = "019e254f-c2b1-7db2-8733-72753668a5d8";

  it("detects the coordinator row by the task_id == initiative_id predicate", () => {
    expect(isIntegrationMergeTask(INIT_ID, INIT_ID)).toBe(true);
    expect(
      isIntegrationMergeTask("sibling-materialize-records", INIT_ID),
    ).toBe(false);
    expect(isIntegrationMergeTask(null, INIT_ID)).toBe(false);
    expect(isIntegrationMergeTask(INIT_ID, null)).toBe(false);
  });

  it("substitutes the stable display id for the coordinator row", () => {
    expect(taskDisplayId(INIT_ID, INIT_ID)).toBe(INTEGRATION_MERGE_DISPLAY_ID);
    // Spec-pinned constant — see kernel-side comment on
    // `INTEGRATION_MERGE_TITLE` in `crates/dashboard-kernel/src/lib.rs`.
    expect(INTEGRATION_MERGE_DISPLAY_ID).toBe("«integration-merge»");
  });

  it("echoes the operator-authored task id for ordinary sub-tasks", () => {
    expect(taskDisplayId("sibling-materialize-records", INIT_ID)).toBe(
      "sibling-materialize-records",
    );
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
