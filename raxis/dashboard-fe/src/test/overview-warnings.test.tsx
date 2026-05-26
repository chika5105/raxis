import { beforeEach, describe, expect, it } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { TestMemoryRouter } from "@/test/router";

import { OverviewWarnings } from "@/pages/Overview";
import type { LifecycleAnnotation } from "@/types/api";

const GAP_A: Extract<LifecycleAnnotation, { kind: "orchestrator_gap" }> = {
  kind: "orchestrator_gap",
  activation_id: "act_greeter_a",
  task_id: "greeter",
  predecessors_completed_at: [["setup", 1_000_000]],
  wait_seconds: 240,
};

const GAP_B: Extract<LifecycleAnnotation, { kind: "orchestrator_gap" }> = {
  kind: "orchestrator_gap",
  activation_id: "act_greeter_b",
  task_id: "greeter",
  predecessors_completed_at: [["setup", 1_000_000]],
  wait_seconds: 180,
};

function renderWarnings(gaps = [GAP_A, GAP_B]) {
  return render(
    <TestMemoryRouter>
      <OverviewWarnings gaps={gaps} />
    </TestMemoryRouter>,
  );
}

function dismissKey(
  gap: Extract<LifecycleAnnotation, { kind: "orchestrator_gap" }>,
): string {
  return `${gap.kind}:${gap.task_id}:${gap.activation_id}`;
}

describe("<OverviewWarnings>", () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  it("lets an operator dismiss a single warning without removing the other warnings", () => {
    renderWarnings();

    expect(screen.getByText("Warnings (2)")).toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", {
        name: "Dismiss orchestrator gap for greeter on act_greeter_a",
      }),
    );

    expect(screen.getByText("Warnings (1)")).toBeInTheDocument();
    expect(screen.getByText(/1 dismissed/)).toBeInTheDocument();
    expect(screen.getAllByTestId("lifecycle-orchestrator-gap")).toHaveLength(1);
  });

  it("persists dismissed warnings by task and activation id across reloads", () => {
    window.localStorage.setItem(
      "raxis.overview.dismissedOrchestratorGaps.v1",
      JSON.stringify([dismissKey(GAP_A)]),
    );

    renderWarnings();

    expect(screen.getByText("Warnings (1)")).toBeInTheDocument();
    expect(screen.getByText(/1 dismissed/)).toBeInTheDocument();
    expect(screen.queryByText("act_greeter_a")).toBeNull();
    expect(screen.getByText("act_greeter_b")).toBeInTheDocument();
  });

  it("can dismiss and restore all current warnings", () => {
    renderWarnings();

    fireEvent.click(screen.getByRole("button", { name: "Dismiss all" }));

    expect(screen.getByText("Warnings (0)")).toBeInTheDocument();
    expect(screen.getByText(/2 dismissed/)).toBeInTheDocument();
    expect(
      screen.getByText(/All current warnings dismissed/),
    ).toBeInTheDocument();

    fireEvent.click(
      screen.getByRole("button", { name: "Restore dismissed" }),
    );

    expect(screen.getByText("Warnings (2)")).toBeInTheDocument();
    expect(screen.queryByText(/dismissed/)).toBeNull();
    expect(screen.getAllByTestId("lifecycle-orchestrator-gap")).toHaveLength(2);
  });
});
