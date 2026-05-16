// Witness coverage for `<LifecycleTimeline>`.
//
// Pin: the timeline preserves the order it was given, and
// dispatches each annotation to the correct kind-specific
// renderer.

import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import { LifecycleTimeline } from "../LifecycleTimeline";
import type { LifecycleAnnotation } from "@/types/api";

const REJECT_AT_T1: LifecycleAnnotation = {
  kind: "retry_review_reject",
  retry_number: 1,
  triggered_by_reviewer_task_id: "rev-1",
  verdict: "Rejected",
  critique: "first reject",
  review_reject_count: 1,
  max_review_rejections: 3,
  crash_retry_count: 0,
  max_crash_retries: 5,
  prior_activation_id: "act_001",
  new_activation_id: "act_002",
  prior_head_sha: null,
  new_head_sha: null,
  ts_unix: 1_000_000_001,
};

const CRASH_AT_T2: LifecycleAnnotation = {
  kind: "retry_crash",
  retry_number: 2,
  exit_code: 137,
  terminal_tool: null,
  max_turns_scaled_from: 32,
  max_turns_scaled_to: 64,
  crash_retry_count: 1,
  max_crash_retries: 5,
  ts_unix: 1_000_000_002,
};

const GAP: LifecycleAnnotation = {
  kind: "orchestrator_gap",
  activation_id: "act_007",
  task_id: "review-lint-defect-rust",
  predecessors_completed_at: [["lint-runner-rust", 1_000_000_000]],
  wait_seconds: 1800,
};

describe("<LifecycleTimeline>", () => {
  it("renders annotations in the order it was given", () => {
    render(
      <MemoryRouter>
        <LifecycleTimeline annotations={[REJECT_AT_T1, CRASH_AT_T2, GAP]} />
      </MemoryRouter>,
    );
    const rows = screen.getAllByTestId("lifecycle-timeline-row");
    expect(rows).toHaveLength(3);
    expect(rows[0].textContent).toContain("review reject");
    expect(rows[1].textContent).toContain("worker crash");
    expect(rows[2].textContent).toContain("Orchestrator gap");
  });

  it("renders nothing when annotations is empty and showEmpty=false", () => {
    const { container } = render(
      <MemoryRouter>
        <LifecycleTimeline annotations={[]} />
      </MemoryRouter>,
    );
    expect(container.firstChild).toBeNull();
  });

  it("renders an empty-state card when showEmpty=true", () => {
    render(
      <MemoryRouter>
        <LifecycleTimeline annotations={[]} showEmpty heading="Lifecycle" />
      </MemoryRouter>,
    );
    expect(screen.getByText(/No lifecycle events recorded yet/)).toBeInTheDocument();
  });
});
