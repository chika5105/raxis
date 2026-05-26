import { describe, expect, it } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { TestMemoryRouter } from "@/test/router";

import {
  GateStatTableRow,
  VerdictPill,
  WitnessTimelineRow,
  witnessKey,
} from "@/pages/Gates";
import type { GateStatRow, WitnessView } from "@/types/api";

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
///   * iter69 — counts MUST be tone-coded (Pass → ok, Fail →
///     bad, Inconclusive/Fixup → warn) ONLY when the count is
///     non-zero, so a "0 fails" row doesn't shout red. The flag
///     pills MUST route through `toneClasses` (i.e. carry the
///     `border-emerald-* / border-amber-* / …` palette classes
///     `<StateBadge>` family uses) rather than the pre-iter69
///     `text-success` / `text-danger` aliases that never
///     resolved against `tailwind.config.js`.
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
    const healthy = screen.getByText("Healthy");
    expect(healthy).toBeInTheDocument();
    // iter69 — Healthy pill MUST carry the `ok` tone classes
    // (emerald palette via `toneClasses("ok")`) so it actually
    // renders green, not as an un-styled grey chip.
    expect(healthy.getAttribute("data-tone")).toBe("ok");
    expect(healthy.className).toMatch(/badge/);
    expect(healthy.className).toMatch(/emerald/);
  });

  it("fires the warn-tone flag when every fail spawns a fixup loop", () => {
    renderRow(FLAGGED_ROW);
    const row = screen.getByTestId("gate-row-SchemaValid");
    expect(row.classList.contains("raxis-gate-row-flagged")).toBe(true);
    const flagPill = screen.getByText("Fixup-loop heavy");
    expect(flagPill).toBeInTheDocument();
    // iter69 — flagged pill MUST carry the `warn` tone classes
    // (amber palette) so the operator's eye is drawn to it.
    expect(flagPill.getAttribute("data-tone")).toBe("warn");
    expect(flagPill.className).toMatch(/amber/);
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

  /// INV-DASHBOARD-WIRE-UNITS-CONSISTENT-01 regression: the
  /// backend emits `last_seen_at` as unix-SECONDS (mirrors
  /// `recorded_at` from `witness_records`), so `fmtRelative`
  /// must consume it verbatim. iter69 caught this surfacing as
  /// "in 56,355 years" because the FE was multiplying by 1000
  /// before handing it to `fmtRelative`. This test pins the
  /// fix: a row with last_seen_at = (now - 5 minutes) MUST
  /// render as a sub-minute / few-minute-old relative label,
  /// never a year-scale one.
  it("renders last_seen_at as a near-now relative time (no ms vs s confusion)", () => {
    const now = Math.floor(Date.now() / 1000);
    const row: GateStatRow = {
      ...HEALTHY_ROW,
      gate_type: "RegressionGate",
      last_seen_at: now - 300,
    };
    renderRow(row);
    const tr = screen.getByTestId("gate-row-RegressionGate");
    expect(tr.textContent ?? "").toMatch(/minutes? ago|just now|seconds? ago/);
    expect(tr.textContent ?? "").not.toMatch(/years/);
  });

  it("tone-codes Pass / Fail / Inconclusive / Fixup counts only when > 0", () => {
    // Mixed row: non-zero in every numeric column → every
    // count MUST carry its tone class.
    const mixed: GateStatRow = {
      gate_type: "MixedGate",
      pass_count: 7,
      fail_count: 3,
      inconclusive_count: 2,
      last_seen_at: 1_700_000_000,
      fixup_loop_count: 1,
    };
    renderRow(mixed);
    const row = screen.getByTestId("gate-row-MixedGate");
    const cells = within(row).getAllByRole("cell");
    // Order from the component: Pass, Fail, Inconclusive,
    // Fixup, Last seen, Health flag. (The leading <th
    // scope="row"> is not a cell.)
    expect(cells[0].className).toMatch(/text-ok/);
    expect(cells[1].className).toMatch(/text-bad/);
    expect(cells[2].className).toMatch(/text-warn/);
    expect(cells[3].className).toMatch(/text-warn/);

    // Zero-count row → every count MUST be muted.
    renderRow(NEVER_RUN_ROW);
    const zeroRow = screen.getByTestId("gate-row-BudgetUnderCap");
    const zeroCells = within(zeroRow).getAllByRole("cell");
    expect(zeroCells[0].className).toMatch(/text-ink-subtle/);
    expect(zeroCells[1].className).toMatch(/text-ink-subtle/);
    expect(zeroCells[2].className).toMatch(/text-ink-subtle/);
    expect(zeroCells[3].className).toMatch(/text-ink-subtle/);
  });

  it("is keyboard-activatable when wired with onClick (operator click-to-filter affordance)", () => {
    let calls = 0;
    render(
      <table>
        <tbody>
          <GateStatTableRow row={HEALTHY_ROW} onClick={() => (calls += 1)} />
        </tbody>
      </table>,
    );
    const row = screen.getByTestId("gate-row-NoSecretStrings");
    expect(row.getAttribute("role")).toBe("button");
    expect(row.getAttribute("tabIndex")).toBe("0");
    row.click();
    expect(calls).toBe(1);
  });
});

describe("<VerdictPill>", () => {
  /// iter69 — the previous incarnation referenced
  /// `bg-success-muted / border-success / text-success`,
  /// classes that don't exist in `tailwind.config.js` (the
  /// real tokens are `ok / bad / warn`). Tailwind silently
  /// dropped them so every verdict rendered grey. This suite
  /// pins the post-fix contract: each verdict MUST resolve to
  /// the matching tone class set the rest of the dashboard
  /// uses.
  it("routes Pass → ok / emerald palette", () => {
    render(<VerdictPill kind="Pass" />);
    const pill = screen.getByText("Pass");
    expect(pill.getAttribute("data-tone")).toBe("ok");
    expect(pill.className).toMatch(/emerald/);
  });

  it("routes Fail → bad / rose palette", () => {
    render(<VerdictPill kind="Fail" />);
    const pill = screen.getByText("Fail");
    expect(pill.getAttribute("data-tone")).toBe("bad");
    expect(pill.className).toMatch(/rose/);
  });

  it("routes Inconclusive → warn / amber palette", () => {
    render(<VerdictPill kind="Inconclusive" />);
    const pill = screen.getByText("Inconclusive");
    expect(pill.getAttribute("data-tone")).toBe("warn");
    expect(pill.className).toMatch(/amber/);
  });

  it("falls back to muted for an unknown verdict (no crash, neutral chip)", () => {
    render(<VerdictPill kind="QuantumSuperposed" />);
    const pill = screen.getByText("QuantumSuperposed");
    expect(pill.getAttribute("data-tone")).toBe("muted");
  });

  it("respects the optional label override", () => {
    render(<VerdictPill kind="Pass" label="42 pass" />);
    expect(screen.getByText("42 pass")).toBeInTheDocument();
  });
});

const SAMPLE_WITNESS: WitnessView = {
  verifier_run_id: "vr-1",
  task_id: "task-aaaa-bbbb-cccc",
  gate_type: "NoSecretStrings",
  result_class: "Pass",
  evaluation_sha: "abcdef0123456789abcdef0123456789",
  blob_sha256: "00112233445566778899aabbccddeeff",
  recorded_at: Math.floor(Date.now() / 1000) - 60,
};

describe("<WitnessTimelineRow>", () => {
  function renderRow(w: WitnessView) {
    return render(
      <TestMemoryRouter>
        <table>
          <tbody>
            <WitnessTimelineRow w={w} />
          </tbody>
        </table>
      </TestMemoryRouter>,
    );
  }

  it("renders the verdict pill, gate, task link and shortened eval sha", () => {
    renderRow(SAMPLE_WITNESS);
    expect(screen.getByText("Pass").getAttribute("data-tone")).toBe("ok");
    expect(screen.getByText("NoSecretStrings")).toBeInTheDocument();
    // Task link target is the canonical task-detail route.
    const link = screen.getByRole("link", {
      name: /task-aaaa-bbbb-cccc/,
    });
    expect(link.getAttribute("href")).toBe("/tasks/task-aaaa-bbbb-cccc");
    // Eval sha is rendered truncated to 12 chars.
    expect(screen.getByText("abcdef012345")).toBeInTheDocument();
  });

  it("renders the recorded_at as a relative time (unix-seconds, not ms)", () => {
    renderRow(SAMPLE_WITNESS);
    expect(document.body.textContent ?? "").toMatch(
      /seconds? ago|just now|minutes? ago/,
    );
    expect(document.body.textContent ?? "").not.toMatch(/years/);
  });
});

describe("witnessKey", () => {
  it("composites the row tuple (verifier_run_id, gate, recorded_at)", () => {
    expect(witnessKey(SAMPLE_WITNESS)).toBe(
      `vr-1-NoSecretStrings-${SAMPLE_WITNESS.recorded_at}`,
    );
  });

  it("differs between two witnesses on the same task at the same instant for different gates", () => {
    const a: WitnessView = { ...SAMPLE_WITNESS, gate_type: "GateA" };
    const b: WitnessView = { ...SAMPLE_WITNESS, gate_type: "GateB" };
    expect(witnessKey(a)).not.toBe(witnessKey(b));
  });
});
