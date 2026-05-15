/* Witness for `INV-DASHBOARD-HEALTH-REFRESH-CADENCE-01`
 * (`specs/v2/dashboard-hardening.md §1.7`) — the Health page
 * MUST poll `/api/health` on a fixed 5 s cadence and the live
 * refresh signal MUST be visible to operators. This file
 * drives the page with fake timers + a recording mock and
 * asserts:
 *
 *   1. The first render fetches once.
 *   2. After advancing fake timers past the poll interval,
 *      the FE issues another fetch.
 *   3. The visible "Updated Xs ago" pill is rendered (the
 *      operator's witness that the page is alive even when
 *      values do not change).
 *
 * Bug 1 root cause this test pins: pre-fix, the page polled
 * but operators reported "never refreshes" because (a) the
 * kernel responses were cacheable (browser heuristic-caching
 * served the cached body) AND (b) there was no visible
 * freshness signal so identical Healthy-kernel snapshots
 * looked frozen. The backend fix is paired with this
 * front-end witness so the regression cannot land silently.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

import { dashboardApi } from "@/api/client";
import { HealthPage } from "@/pages/Health";

function mockHealthOnce() {
  const healthSpy = vi.spyOn(dashboardApi, "health");
  let callIdx = 0;
  healthSpy.mockImplementation(async () => {
    const n = callIdx++;
    return {
      // Every call returns a slightly-different `policy_epoch`
      // so a state-update bug that uses the same object
      // reference would surface as a stuck displayed value.
      status: "ok",
      checks: [],
      kernel_booted_at: 1_700_000_000,
      policy_epoch: 1 + n,
      active_initiatives: 0,
      active_sessions: 0,
      pending_escalations: 0,
    };
  });
  const subSpy = vi.spyOn(dashboardApi, "subsystemHealth");
  subSpy.mockResolvedValue({
    aggregate_status: "ok",
    cards: [],
    generated_at_ms: Date.now(),
  });
  return { healthSpy, subSpy };
}

function renderPage() {
  // The default options here mirror App.tsx (staleTime 5 s)
  // EXCEPT we keep `refetchOnWindowFocus` false to match prod
  // and we re-enable retries off so a single mocked failure
  // would surface immediately.
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <HealthPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("<HealthPage> polling (INV-DASHBOARD-HEALTH-REFRESH-CADENCE-01)", () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
  });
  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("renders the freshness pill so the operator can see polling is alive", async () => {
    mockHealthOnce();
    renderPage();
    // Initial fetch + first render — the pill is mounted as
    // soon as the query resolves.
    const pill = await screen.findByTestId("health-freshness");
    expect(pill).toBeInTheDocument();
    // Refreshing flash (visible while the initial fetch is
    // still in flight) OR the post-fetch "Updated 0s ago"
    // — both are acceptable witnesses on the first render.
    expect(pill.textContent ?? "").toMatch(/Refreshing|Updated \d+s ago/);
  });

  it("refetches /api/health on the 5s polling interval", async () => {
    const { healthSpy } = mockHealthOnce();
    renderPage();
    // First fetch.
    await waitFor(() => expect(healthSpy).toHaveBeenCalledTimes(1));
    // Advance the fake timers past the 5 s polling cadence.
    // `vi.advanceTimersByTimeAsync` flushes both the
    // setInterval and any pending microtasks the refetch
    // chains.
    await vi.advanceTimersByTimeAsync(5_100);
    await waitFor(() => expect(healthSpy).toHaveBeenCalledTimes(2));
    // Advance another full interval — a third call MUST
    // fire, ruling out a "first refetch only" regression.
    await vi.advanceTimersByTimeAsync(5_100);
    await waitFor(() => expect(healthSpy).toHaveBeenCalledTimes(3));
  });

  it("displays incrementing policy_epoch across polls (no stuck-reference bug)", async () => {
    const { healthSpy } = mockHealthOnce();
    renderPage();
    // After first fetch the displayed epoch is `#1`.
    await waitFor(() => {
      expect(screen.getByText("#1")).toBeInTheDocument();
    });
    await vi.advanceTimersByTimeAsync(5_100);
    // After second fetch the displayed epoch advances to `#2`
    // — this catches a "structural sharing kept the same
    // object reference and React skipped re-render" bug.
    await waitFor(() => {
      expect(screen.getByText("#2")).toBeInTheDocument();
    });
    // The mock was driven by the polling loop, not by an
    // explicit refetch button — assert the recording spy
    // shows ≥2 calls in case the assertion above passes for
    // a reason other than the timer (e.g. focus refetch).
    expect(healthSpy.mock.calls.length).toBeGreaterThanOrEqual(2);
  });
});
