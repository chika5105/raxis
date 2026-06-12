import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Route, Routes } from "react-router-dom";

import { dashboardApi } from "@/api/client";
import { InitiativeDetailPage } from "@/pages/InitiativeDetail";
import { TestMemoryRouter } from "@/test/router";

function renderInitiativeDetail(initialEntry = "/initiatives/init-collapse") {
  vi.spyOn(dashboardApi.initiatives, "get").mockResolvedValue({
    initiative_id: "init-collapse",
    display_name: "Collapse fixture",
    state: "Executing",
    task_count: 0,
    completed_tasks: 0,
    failed_tasks: 0,
    created_at: 1_779_211_000,
    updated_at: 1_779_211_400,
    approved_by: null,
    plan_sha256: "1a62fe99",
    target_ref: null,
    policy_epoch: 1,
    tasks: [],
    edges: [],
    run_summary: {
      terminal: false,
      elapsed_seconds: 404,
      session_count: 2,
      active_session_count: 1,
      llm_turn_count: 12,
      input_tokens: 100,
      output_tokens: 50,
      cache_read_tokens: 20,
      cache_creation_tokens: 10,
      token_cost_micros: 1_234_000,
      token_cost_pricing_source: "operator_policy_override",
      token_cost_pricing_note:
        "Provider-reported usage priced with operator policy override rates.",
      admission_reserved_units: 0,
      actual_cost_units: 0,
      declared_turn_budget: 30,
      declared_wallclock_budget_seconds: null,
    },
    failure: null,
  });
  vi.spyOn(dashboardApi.initiatives, "dag").mockResolvedValue({
    initiative_id: "init-collapse",
    display_name: "Collapse fixture",
    nodes: [],
    edges: [],
  });
  vi.spyOn(dashboardApi.diagnostics, "list").mockResolvedValue({
    generated_at: 1_779_211_410,
    findings: [
      {
        finding_id: "diag-network",
        severity: "high",
        status: "active",
        scope: "networking",
        title: "Mediated egress was denied",
        summary:
          "A session tried to reach a host outside its signed allowlist.",
        initiative_id: "init-collapse",
        observed_at: 1_779_211_405,
        evidence: [],
        actions: [],
      },
    ],
    vm: { sessions: [], commands: [] },
  });
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, refetchInterval: false } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <TestMemoryRouter initialEntries={[initialEntry]}>
        <Routes>
          <Route path="/initiatives/:id" element={<InitiativeDetailPage />} />
        </Routes>
      </TestMemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("<InitiativeDetailPage> collapsible summary panels", () => {
  it("collapses resource summary and diagnosis sections without removing their headers", async () => {
    renderInitiativeDetail();

    expect(await screen.findByText("Resource summary")).toBeInTheDocument();
    expect(screen.getByText(/Provider reported/)).toBeInTheDocument();
    expect(screen.getByText("Mediated egress was denied")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /Resource summary/i }));
    await waitFor(() => {
      expect(screen.getByText("Resource summary")).toBeInTheDocument();
      expect(screen.queryByText(/Provider reported/)).toBeNull();
    });

    fireEvent.click(screen.getByRole("button", { name: /Diagnosis/i }));
    await waitFor(() => {
      expect(screen.getByText("Diagnosis")).toBeInTheDocument();
      expect(screen.queryByText("Mediated egress was denied")).toBeNull();
    });
  });

  it("honors URL-backed collapsed state", async () => {
    renderInitiativeDetail(
      "/initiatives/init-collapse?summary=closed&diagnosis=closed",
    );

    expect(await screen.findByText("Resource summary")).toBeInTheDocument();
    expect(screen.getByText("Diagnosis")).toBeInTheDocument();
    expect(screen.queryByText(/Provider reported/)).toBeNull();
    expect(screen.queryByText("Mediated egress was denied")).toBeNull();
  });
});
