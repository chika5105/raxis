// Witness coverage for `<OrchestratorGapWarningCard>`.
//
// Pin: warn-orange tint visible to the operator + minute
// rounding for `wait_seconds` (so a 67-min stall reads as
// "stalled 67min" instead of "stalled 4020s").

import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { TestMemoryRouter } from "@/test/router";

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
      <TestMemoryRouter>
        <OrchestratorGapWarningCard a={GAP} />
      </TestMemoryRouter>,
    );
    expect(screen.getByText("Orchestrator gap")).toBeInTheDocument();
    expect(screen.getByText(/stalled 67min/)).toBeInTheDocument();
  });

  it("uses warn-tinted styling", () => {
    render(
      <TestMemoryRouter>
        <OrchestratorGapWarningCard a={GAP} />
      </TestMemoryRouter>,
    );
    const card = screen.getByTestId("lifecycle-orchestrator-gap");
    expect(card.className).toMatch(/border-warn/);
    expect(card.className).toMatch(/bg-warn/);
  });

  it("links the task id and lists every predecessor", () => {
    render(
      <TestMemoryRouter>
        <OrchestratorGapWarningCard a={GAP} />
      </TestMemoryRouter>,
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
      <TestMemoryRouter>
        <OrchestratorGapWarningCard
          a={{
            ...GAP,
            wait_seconds: 45,
          }}
        />
      </TestMemoryRouter>,
    );
    expect(screen.getByText(/stalled 45s/)).toBeInTheDocument();
  });

  it("wraps long generated ids instead of letting them escape the card", () => {
    const longTask =
      "interpret_reddit_opportunities__20260609T162842Z_daily_reddit_engagement_plan_90207";
    const longPred =
      "discover_reddit_opportunities__20260609T162842Z_daily_reddit_engagement_plan_90207";
    render(
      <TestMemoryRouter>
        <OrchestratorGapWarningCard
          a={{
            ...GAP,
            activation_id: "a9fb8700-2c0e-46ff-a992-bfc5f6765b66",
            task_id: longTask,
            predecessors_completed_at: [[longPred, 1_700_000_000]],
            wait_seconds: 63_000,
          }}
        />
      </TestMemoryRouter>,
    );

    const card = screen.getByTestId("lifecycle-orchestrator-gap");
    expect(card.className).toContain("overflow-hidden");
    const taskLink = screen.getByRole("link", { name: longTask });
    expect(taskLink.className).toContain("break-all");
    expect(screen.getByText(longPred).className).toContain("break-all");
  });
});
