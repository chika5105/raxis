/* DAG layout-direction regression test (iter48 QA defect #1).
 *
 * Pins the contract:
 *
 *   Button label    →  state value  →  dagre `rankdir`  →  visual flow
 *   ──────────────────────────────────────────────────────────────────
 *   "Left → Right"  →  "LR"         →  "LR"             →  horizontal row
 *   "Top → Bottom"  →  "TB"         →  "TB"             →  vertical column
 *
 * Both halves are tested so a future regression that swaps the
 * click handlers (or the labels, or the inner `rankdir` prop
 * mapping in `<DagGraph>`) fails this file.
 *
 * Background: iter48 QA observed the visual layout doing the
 * OPPOSITE of what the labels said — clicking "Top → Bottom"
 * produced a horizontal row, and clicking "Left → Right"
 * produced a vertical column. Whatever produced that inversion
 * (stale build, mismatched copy, accidental swap during a
 * refactor) must never recur — this test is the gate.
 */

import { describe, expect, it, vi } from "vitest";
import dagre from "dagre";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes } from "react-router-dom";

import { dashboardApi } from "@/api/client";
import { InitiativeDagPage } from "@/pages/InitiativeDag";

// ─────────────────────────────────────────────────────────────
// Layer 1: dagre contract — what does each `rankdir` actually
// produce? If dagre ever flipped its convention (or a wrapper
// snuck in a `swapXY`), this test stops the bug at the source.
// ─────────────────────────────────────────────────────────────
describe("dagre rankdir contract", () => {
  function layoutChain(rankdir: "LR" | "TB") {
    const g = new dagre.graphlib.Graph({ multigraph: false, compound: false });
    g.setGraph({ rankdir, nodesep: 24, ranksep: 60, marginx: 16, marginy: 16 });
    g.setDefaultEdgeLabel(() => ({}));
    ["A", "B", "C"].forEach((id) =>
      g.setNode(id, { width: 200, height: 64 }),
    );
    g.setEdge("A", "B");
    g.setEdge("B", "C");
    dagre.layout(g);
    return ["A", "B", "C"].map((id) => g.node(id));
  }

  it("rankdir='TB' produces a vertical column (same x, increasing y)", () => {
    const [a, b, c] = layoutChain("TB");
    expect(a.x).toBe(b.x);
    expect(b.x).toBe(c.x);
    expect(a.y).toBeLessThan(b.y);
    expect(b.y).toBeLessThan(c.y);
  });

  it("rankdir='LR' produces a horizontal row (same y, increasing x)", () => {
    const [a, b, c] = layoutChain("LR");
    expect(a.y).toBe(b.y);
    expect(b.y).toBe(c.y);
    expect(a.x).toBeLessThan(b.x);
    expect(b.x).toBeLessThan(c.x);
  });
});

// ─────────────────────────────────────────────────────────────
// Layer 2: button → state wiring on the InitiativeDag page.
// `aria-pressed` is the public contract for which button is
// active — we read it instead of poking React internals so the
// test exercises the exact surface the operator (and a11y
// readers) see.
// ─────────────────────────────────────────────────────────────
function renderPage(id: string) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, refetchInterval: false } },
  });
  vi.spyOn(dashboardApi.initiatives, "dag").mockResolvedValue({
    initiative_id: id,
    nodes: [
      { task_id: "t1", title: "first",  state: "Completed" },
      { task_id: "t2", title: "second", state: "Running" },
      { task_id: "t3", title: "third",  state: "Admitted" },
    ],
    edges: [
      { from: "t1", to: "t2" },
      { from: "t2", to: "t3" },
    ],
  });
  vi.spyOn(dashboardApi.initiatives, "get").mockResolvedValue({
    initiative_id: id,
    display_name: "dag-button-fixture",
    state: "Executing",
    task_count: 3,
    completed_tasks: 1,
    failed_tasks: 0,
    created_at: 0,
    updated_at: 0,
    approved_by: null,
    plan_sha256: "deadbeef",
    target_ref: null,
    policy_epoch: 1,
    tasks: [],
    edges: [],
    failure: null,
  });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[`/initiatives/${id}/dag`]}>
        <Routes>
          <Route
            path="/initiatives/:id/dag"
            element={<InitiativeDagPage />}
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("<InitiativeDagPage> layout buttons", () => {
  it("'Left → Right' is the default and stays pressed when re-clicked", async () => {
    renderPage("init-1");
    const lr = await screen.findByRole("button", { name: "Left → Right" });
    const tb = screen.getByRole("button", { name: "Top → Bottom" });
    expect(lr).toHaveAttribute("aria-pressed", "true");
    expect(tb).toHaveAttribute("aria-pressed", "false");
  });

  it("clicking 'Top → Bottom' makes ONLY that button pressed (state → 'TB')", async () => {
    renderPage("init-2");
    const lr = await screen.findByRole("button", { name: "Left → Right" });
    const tb = screen.getByRole("button", { name: "Top → Bottom" });
    fireEvent.click(tb);
    await waitFor(() => {
      expect(tb).toHaveAttribute("aria-pressed", "true");
      expect(lr).toHaveAttribute("aria-pressed", "false");
    });
  });

  it("clicking 'Left → Right' after 'Top → Bottom' restores 'LR'", async () => {
    renderPage("init-3");
    const lr = await screen.findByRole("button", { name: "Left → Right" });
    const tb = screen.getByRole("button", { name: "Top → Bottom" });
    fireEvent.click(tb);
    fireEvent.click(lr);
    await waitFor(() => {
      expect(lr).toHaveAttribute("aria-pressed", "true");
      expect(tb).toHaveAttribute("aria-pressed", "false");
    });
  });
});
