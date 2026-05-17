import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";

import { GateStatTableRow } from "@/pages/Gates";
import type { GateStatRow } from "@/types/api";

const HEALTHY_ROW: GateStatRow = {
  gate_type: "NoSecretStrings",
  pass_count: 12,
  fail_count: 1,
  inconclusive_count: 0,
  last_seen_at: 1_700_000_000,
  fixup_loop_count: 0,
};

const FLAGGED_ROW: GateStatRow = {
  gate_type: "SchemaValid",
  pass_count: 4,
  fail_count: 2,
  inconclusive_count: 0,
  last_seen_at: 1_700_000_000,
  fixup_loop_count: 3,
};

const NEVER_RUN_ROW: GateStatRow = {
  gate_type: "BudgetUnderCap",
  pass_count: 0,
  fail_count: 0,
  inconclusive_count: 0,
  last_seen_at: null,
  fixup_loop_count: 0,
};

/// Vitest contract for the per-gate row component.
///
/// INV-DASHBOARD-GATE-STATS-PER-GATE-ROLLUP-01 (FE projection):
///   * Raw counts MUST render verbatim — no FE-computed
///     pass-rate / percentage.
///   * The warn-tone flag MUST fire iff `fail_count > 0 AND
///     fixup_loop_count >= fail_count`. A gate with fails but
///     zero fixups is healthy (the operator may have disabled
///     the loop intentionally); a gate that has never run
///     surfaces as healthy.
///   * `last_seen_at = null` MUST render as the "never" string,
///     NOT as the Unix epoch.
describe("<GateStatTableRow>", () => {
  function renderRow(row: GateStatRow) {
    return render(
      <table>
        <tbody>
          <GateStatTableRow row={row} />
        </tbody>
      </table>,
    );
  }

  it("renders raw counts verbatim and a Healthy flag for a passing gate", () => {
    renderRow(HEALTHY_ROW);
    const row = screen.getByTestId("gate-row-NoSecretStrings");
    expect(row.classList.contains("raxis-gate-row-flagged")).toBe(false);
    // Pass / Fail / Inconclusive cells render the raw integers.
    expect(row).toHaveTextContent("12");
    expect(row).toHaveTextContent("1");
    expect(screen.getByText("Healthy")).toBeInTheDocument();
  });

  it("fires the warn-tone flag when every fail spawns a fixup loop", () => {
    renderRow(FLAGGED_ROW);
    const row = screen.getByTestId("gate-row-SchemaValid");
    expect(row.classList.contains("raxis-gate-row-flagged")).toBe(true);
    expect(screen.getByText("Fixup-loop heavy")).toBeInTheDocument();
    // Fixup-loop counter MUST render the raw count even when
    // flagged so the operator can see how deep the loop went.
    expect(row).toHaveTextContent("3");
  });

  it("renders 'never' for a gate that has never run", () => {
    renderRow(NEVER_RUN_ROW);
    const row = screen.getByTestId("gate-row-BudgetUnderCap");
    expect(row).toHaveTextContent("never");
    // A gate that has never run is treated as healthy — the
    // operator just hasn't exercised it yet.
    expect(row.classList.contains("raxis-gate-row-flagged")).toBe(false);
  });
});
