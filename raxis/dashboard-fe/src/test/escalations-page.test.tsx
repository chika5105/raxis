import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { dashboardApi } from "@/api/client";
import { EscalationsPage } from "@/pages/Escalations";
import { TestMemoryRouter } from "@/test/router";
import type { EscalationView } from "@/types/api";

function renderPage() {
  const qc = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        refetchInterval: false,
        refetchOnMount: true,
        refetchOnWindowFocus: false,
      },
    },
  });
  return render(
    <QueryClientProvider client={qc}>
      <TestMemoryRouter>
        <EscalationsPage />
      </TestMemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("<EscalationsPage>", () => {
  it("wraps long escalation handles and shows recovery commands", async () => {
    const longTask =
      "interpret_reddit_opportunities__20260611T101235Z_reddit_20260611T101235Z_daily_reddit_engagement_plan_90207";
    const row: EscalationView = {
      escalation_id: "e85d796f-1c80-45fb-8321-9afb35fe0b2c",
      initiative_id: "019eb62b-5ae0-7270-8784-e8b04bb32104",
      task_id: longTask,
      severity: "Low",
      reason:
        "Orchestrator respawn-no-progress ceiling exceeded. Operator approval required to reset the respawn counter and retry, or deny to preserve the Failed terminal state.",
      action_required: "LogicalDeadlock",
      created_at: 1_714_500_000,
    };
    vi.spyOn(dashboardApi.escalations, "list").mockResolvedValue([row]);

    renderPage();

    const taskLink = await screen.findByRole("link", { name: `/ ${longTask}` });
    expect(taskLink.className).toContain("break-all");
    expect(taskLink.className).toContain("[overflow-wrap:anywhere]");

    expect(screen.getByText("Recovery commands")).toBeInTheDocument();
    expect(screen.getByText("Resume")).toBeInTheDocument();
    expect(screen.getByText("Fail")).toBeInTheDocument();
    await waitFor(() => {
      expect(
        screen.getByText(/escalation approve e85d796f-1c80-45fb-8321-9afb35fe0b2c/),
      ).toHaveTextContent("--scope LogicalDeadlock");
    });
    expect(
      screen.getByText(/escalation deny e85d796f-1c80-45fb-8321-9afb35fe0b2c/),
    ).toHaveTextContent("preserve failed state");
  });
});
