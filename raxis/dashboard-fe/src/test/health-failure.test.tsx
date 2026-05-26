/* Subsystem-card rendering under unhealthy + missing-reason
 * conditions. Pinned by INV-DASHBOARD-FAILURE-VISIBILITY-01 §5.4.
 *
 * The `<SubsystemCard>` component is private to `Health.tsx`; we
 * import the page and render only the cards section by feeding
 * fixture data through `dashboardApi.subsystemHealth`. Querying
 * by `data-testid="subsystem-last-error"` (the inline-error band
 * the Health page renders) keeps the test resilient to layout
 * tweaks. */

import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { TestMemoryRouter } from "@/test/router";

import { dashboardApi } from "@/api/client";
import { HealthPage } from "@/pages/Health";

function mockSubsystems(
  cards: Array<{
    id: string;
    label: string;
    status: "ok" | "degraded" | "failing" | "unknown";
    summary: string;
    last_error?: string | null;
    details?: Array<{ label: string; value: string }>;
    grafana_url?: string | null;
    last_observed_at?: number;
  }>,
) {
  vi.spyOn(dashboardApi, "health").mockResolvedValue({
    status: "ok",
    checks: [],
    kernel_booted_at: 0,
    policy_epoch: 1,
    active_initiatives: 0,
    active_sessions: 0,
    pending_escalations: 0,
  });
  vi.spyOn(dashboardApi, "subsystemHealth").mockResolvedValue({
    aggregate_status: cards.some((c) => c.status === "failing")
      ? "failing"
      : cards.some((c) => c.status === "degraded")
        ? "degraded"
        : "ok",
    cards: cards.map((c) => ({
      id: c.id,
      label: c.label,
      status: c.status,
      summary: c.summary,
      details: c.details ?? [],
      grafana_url: c.grafana_url ?? null,
      last_observed_at: c.last_observed_at ?? 0,
      last_error: c.last_error ?? null,
    })),
    generated_at_ms: Date.now(),
  });
}

function renderPage() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, refetchInterval: false } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <TestMemoryRouter>
        <HealthPage />
      </TestMemoryRouter>
    </QueryClientProvider>,
  );
}

describe("<HealthPage> subsystem cards", () => {
  it("renders last_error inline beneath a failing card", async () => {
    mockSubsystems([
      {
        id: "audit-chain",
        label: "Audit chain",
        status: "failing",
        summary: "Chain verification failed",
        last_error: "missing segment 0042 at /var/lib/raxis/audit/0042.segment",
      },
    ]);
    renderPage();
    await waitFor(() =>
      expect(screen.getByText("Audit chain")).toBeInTheDocument(),
    );
    const errBand = await screen.findByTestId("subsystem-last-error");
    expect(errBand).toHaveTextContent(
      "missing segment 0042 at /var/lib/raxis/audit/0042.segment",
    );
  });

  it("renders a calm `(no reason recorded)` affordance when last_error is null on an unhealthy card", async () => {
    mockSubsystems([
      {
        id: "credential-proxy",
        label: "Credential proxies",
        status: "degraded",
        summary: "One or more proxies unhealthy",
        last_error: null,
      },
    ]);
    renderPage();
    const errBand = await screen.findByTestId("subsystem-last-error");
    expect(errBand).toHaveTextContent(/\(no reason recorded\)/);
    expect(errBand).not.toHaveTextContent(/KERNEL BUG/);
    expect(errBand.getAttribute("data-error-missing")).toBe("true");
  });

  it("does not render the inline-error band on healthy cards", async () => {
    mockSubsystems([
      {
        id: "audit-chain",
        label: "Audit chain",
        status: "ok",
        summary: "All segments verified",
        last_error: null,
      },
    ]);
    renderPage();
    await waitFor(() =>
      expect(screen.getByText("Audit chain")).toBeInTheDocument(),
    );
    expect(screen.queryByTestId("subsystem-last-error")).toBeNull();
  });
});
