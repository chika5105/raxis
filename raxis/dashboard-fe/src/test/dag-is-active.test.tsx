/* DAG `is_active` rendering regression test.
 *
 * Pins the contract:
 *
 *   When the backend ships `is_active: true` on a node whose
 *   FSM state is still `Admitted` (the gap between the row
 *   flipping to Running and the next state-changed audit), the
 *   DAG MUST render that node as Running — same tone, same chip
 *   label, same pulse — as a node whose `state === "Running"`.
 *
 * Background: operators noticed "running tasks show as Admitted
 * in the DAG" while the `Tasks` list (which already consumes
 * `is_active`) correctly showed them Running. The fix plumbed
 * `is_active` through `DagNode` (BE), `DagNode` interface (TS),
 * `DagGraphNode` (the renderer's prop), and the
 * `InitiativeDag` focus-panel `<StateBadge>`. This file is the
 * gate against a regression that re-introduces the divergence.
 */

import { describe, expect, it } from "vitest";
import { render } from "@testing-library/react";

import { DagGraph } from "@/components/DagGraph";

describe("<DagGraph> is_active plumbing", () => {
  it("lifts Admitted + is_active to Running for tone + label + pulse", () => {
    const { container } = render(
      <DagGraph
        nodes={[
          { task_id: "T1", title: "execute-a", state: "Admitted" },
          {
            task_id: "T2",
            title: "execute-b",
            state: "Admitted",
            is_active: true,
          },
          { task_id: "T3", title: "execute-c", state: "Running" },
        ]}
        edges={[]}
      />,
    );

    // The `data-status` attribute mirrors the effective state used
    // for tone / chip / pulse derivation: T1 stays Admitted, T2
    // lifts to Running, T3 stays Running.
    const groups = container.querySelectorAll("g[data-raw-state]");
    const byTask: Record<string, Element> = {};
    groups.forEach((g) => {
      const id = g.getAttribute("aria-label") ?? "";
      if (id.includes("execute-a")) byTask.T1 = g;
      if (id.includes("execute-b")) byTask.T2 = g;
      if (id.includes("execute-c")) byTask.T3 = g;
    });

    expect(byTask.T1.getAttribute("data-status")).toBe("Admitted");
    expect(byTask.T1.getAttribute("data-raw-state")).toBe("Admitted");
    expect(byTask.T1.getAttribute("data-is-active")).toBeNull();

    expect(byTask.T2.getAttribute("data-status")).toBe("Running");
    expect(byTask.T2.getAttribute("data-raw-state")).toBe("Admitted");
    expect(byTask.T2.getAttribute("data-is-active")).toBe("true");

    expect(byTask.T3.getAttribute("data-status")).toBe("Running");
    expect(byTask.T3.getAttribute("data-raw-state")).toBe("Running");

    // The Running pulse is applied via inline animation on the
    // node body rect; T2 + T3 must throb, T1 must not.
    function pulseFor(g: Element): string | null {
      const rect = g.querySelector("rect");
      return rect?.getAttribute("style") ?? null;
    }
    expect(pulseFor(byTask.T1) ?? "").not.toMatch(/raxis-node-pulse/);
    expect(pulseFor(byTask.T2) ?? "").toMatch(/raxis-node-pulse/);
    expect(pulseFor(byTask.T3) ?? "").toMatch(/raxis-node-pulse/);
  });

  it("leaves the FSM row state on data-raw-state so forensics still see Admitted", () => {
    const { container } = render(
      <DagGraph
        nodes={[
          {
            task_id: "T2",
            title: "execute-b",
            state: "Admitted",
            is_active: true,
          },
        ]}
        edges={[]}
      />,
    );
    const group = container.querySelector("g[data-raw-state]")!;
    expect(group.getAttribute("data-raw-state")).toBe("Admitted");
    // The aria-label should narrate the EFFECTIVE state so screen
    // readers don't tell the operator the task is Admitted while
    // the executor is actively burning.
    expect(group.getAttribute("aria-label")).toMatch(/state Running/);
  });

  it("respects the activeStates filter on the lifted Running state", () => {
    const { container } = render(
      <DagGraph
        nodes={[
          { task_id: "T1", title: "a", state: "Admitted" },
          {
            task_id: "T2",
            title: "b",
            state: "Admitted",
            is_active: true,
          },
        ]}
        edges={[]}
        activeStates={["Running"]}
      />,
    );
    // When the operator filters on Running, T1 (pure Admitted)
    // dims; T2 (Admitted + is_active → effective Running) stays
    // fully opaque.
    const groups = Array.from(
      container.querySelectorAll("g[data-raw-state]"),
    );
    const t1 = groups.find((g) =>
      (g.getAttribute("aria-label") ?? "").includes("Task a"),
    )!;
    const t2 = groups.find((g) =>
      (g.getAttribute("aria-label") ?? "").includes("Task b"),
    )!;
    expect(t1.getAttribute("data-dimmed")).toBe("true");
    expect(t2.getAttribute("data-dimmed")).toBeNull();
  });
});
