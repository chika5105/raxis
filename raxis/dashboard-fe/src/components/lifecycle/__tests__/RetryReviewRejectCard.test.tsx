// Witness coverage for `<RetryReviewRejectCard>`.
//
// Pin: the iter62-style retry-review-reject card MUST render
// the budget counters, the triggering reviewer link, and a
// collapsible critique block with first 3 lines visible by
// default. `INV-DASHBOARD-LIFECYCLE-CAUSALITY-01`.

import { describe, expect, it } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import { RetryReviewRejectCard } from "../RetryReviewRejectCard";
import type { LifecycleAnnotation } from "@/types/api";

const FIXTURE: Extract<
  LifecycleAnnotation,
  { kind: "retry_review_reject" }
> = {
  kind: "retry_review_reject",
  retry_number: 2,
  triggered_by_reviewer_task_id: "review-lint-defect-rust",
  verdict: "Rejected",
  critique:
    "Line 1: clippy::needless_borrow violations remain.\n" +
    "Line 2: rustfmt diff non-empty.\n" +
    "Line 3: tests still fail under cargo nextest.\n" +
    "Line 4: extra detail that should be hidden by default.\n" +
    "Line 5: even more detail.",
  review_reject_count: 2,
  max_review_rejections: 3,
  crash_retry_count: 0,
  max_crash_retries: 5,
  prior_activation_id: "act_001",
  new_activation_id: "act_002",
  prior_head_sha: "deadbeefcafe",
  new_head_sha: "abcd1234ef56",
  ts_unix: 1714500000,
};

describe("<RetryReviewRejectCard>", () => {
  it("renders budget counters", () => {
    render(
      <MemoryRouter>
        <RetryReviewRejectCard a={FIXTURE} />
      </MemoryRouter>,
    );
    // Reviewer-reject budget visible.
    expect(screen.getByText(/review 2\/3/)).toBeInTheDocument();
    // Crash budget visible.
    expect(screen.getByText(/crash 0\/5/)).toBeInTheDocument();
  });

  it("links to the triggering reviewer task", () => {
    render(
      <MemoryRouter>
        <RetryReviewRejectCard a={FIXTURE} />
      </MemoryRouter>,
    );
    const link = screen.getByRole("link", { name: /review-lint-defect-rust/ });
    expect(link.getAttribute("href")).toBe("/tasks/review-lint-defect-rust");
  });

  it("shows the first 3 critique lines by default and expands on click", () => {
    render(
      <MemoryRouter>
        <RetryReviewRejectCard a={FIXTURE} />
      </MemoryRouter>,
    );
    const critique = screen.getByTestId(
      "lifecycle-retry-review-reject-critique",
    );
    expect(critique.textContent).toContain("clippy::needless_borrow");
    expect(critique.textContent).toContain("rustfmt diff non-empty");
    expect(critique.textContent).toContain("tests still fail");
    expect(critique.textContent).not.toContain("extra detail");
    fireEvent.click(
      screen.getByRole("button", { name: /Expand full critique/i }),
    );
    expect(critique.textContent).toContain("extra detail");
  });

  it("renders prior→new sha pairs", () => {
    render(
      <MemoryRouter>
        <RetryReviewRejectCard a={FIXTURE} />
      </MemoryRouter>,
    );
    // shortSha truncates to 8 chars.
    expect(screen.getByText("deadbeef")).toBeInTheDocument();
    expect(screen.getByText("abcd1234")).toBeInTheDocument();
  });

  it("renders the activation id pair", () => {
    render(
      <MemoryRouter>
        <RetryReviewRejectCard a={FIXTURE} />
      </MemoryRouter>,
    );
    expect(screen.getByText("act_001")).toBeInTheDocument();
    expect(screen.getByText("act_002")).toBeInTheDocument();
  });
});
