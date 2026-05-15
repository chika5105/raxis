// Witness coverage for `<OrchestratorGapWarningCard>`.
//
// Pin: warn-orange tint visible to the operator + minute
// rounding for `wait_seconds` (so a 67-min stall reads as
// "stalled 67min" instead of "stalled 4020s").

import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import { OrchestratorGapWarningCard } from "../OrchestratorGapWarningCard";
import type { LifecycleAnnotation } from "@/types/api";

const GAP: Extract<LifecycleAnnotation, { kind: "orchestrator_gap" }> = {
  kind: "orchestrator_gap",
  activation_id: "act_review_lint_defect_rust",
  task_id: "review-lint-defect-rust",
  predecessors_completed_at: [
    ["lint-runner-rust", 1_700_000_000],
    ["lint-defect-rust", 1_700_000_500],
  ],
  wait_seconds: 4020,
};

describe("<OrchestratorGapWarningCard>", () => {
  it("renders the warning badge with rounded-minute label", () => {
    render(
      <MemoryRouter>
        <OrchestratorGapWarningCard a={GAP} />
      </MemoryRouter>,
    );
    expect(screen.getByText("Orchestrator gap")).toBeInTheDocument();
    expect(screen.getByText(/stalled 67min/)).toBeInTheDocument();
  });

  it("uses warn-tinted styling", () => {
    render(
      <MemoryRouter>
        <OrchestratorGapWarningCard a={GAP} />
      </MemoryRouter>,
    );
    const card = screen.getByTestId("lifecycle-orchestrator-gap");
    expect(card.className).toMatch(/border-warn/);
    expect(card.className).toMatch(/bg-warn/);
  });

  it("links the task id and lists every predecessor", () => {
    render(
      <MemoryRouter>
        <OrchestratorGapWarningCard a={GAP} />
      </MemoryRouter>,
    );
    const link = screen.getByRole("link", {
      name: /review-lint-defect-rust/,
    });
    expect(link.getAttribute("href")).toBe("/tasks/review-lint-defect-rust");
    expect(screen.getByText("lint-runner-rust")).toBeInTheDocument();
    expect(screen.getByText("lint-defect-rust")).toBeInTheDocument();
  });

  it("falls back to seconds when wait < 1 minute", () => {
    render(
      <MemoryRouter>
        <OrchestratorGapWarningCard
          a={{
            ...GAP,
            wait_seconds: 45,
          }}
        />
      </MemoryRouter>,
    );
    expect(screen.getByText(/stalled 45s/)).toBeInTheDocument();
  });
});
