/* SessionDetail-page failure-reason rendering. Pinned by
 * INV-DASHBOARD-FAILURE-VISIBILITY-01 §5.1 + §5.4 + §5.5:
 *   - Failed session with `failure` populated renders the full
 *     `<FailureReasonPanel>` body.
 *   - Failed session with `failure: null` renders the calm
 *     muted `(no reason recorded)` empty-state affordance —
 *     never the loud KERNEL BUG banner.
 *   - Healthy session does NOT render the panel.
 *
 * `SessionStream` is mocked because it opens a real EventSource
 * in jsdom — irrelevant to the failure-panel assertion and
 * noisy in test output. */

import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Route, Routes } from "react-router-dom";
import { TestMemoryRouter } from "@/test/router";

import { dashboardApi } from "@/api/client";
import { SessionDetailPage } from "@/pages/SessionDetail";
import type { FailureInfo, SessionView } from "@/types/api";

vi.mock("@/components/SessionStream", () => ({
  SessionStream: ({
    historical,
    annotations,
  }: {
    historical?: boolean;
    annotations?: unknown[];
  }) => (
    <div
      data-testid="session-stream-mock"
      data-historical={historical ? "true" : "false"}
      data-annotation-count={String(annotations?.length ?? 0)}
    />
  ),
}));

const FAILURE: FailureInfo = {
  kind: "SessionVmFailedFinal",
  message: "VM scaling exhausted retries",
  fields: [
    { label: "failure_class", value: "Isolation" },
    { label: "total_attempts", value: "5" },
  ],
  artifacts: [
    {
      label: "Kernel log",
      href: "/var/log/raxis/kernel.stderr.log",
    },
  ],
  event_id: "evt_abc123",
  seq: 12345,
  observed_at: 1714500000,
};

function mockSession(s: Partial<SessionView>) {
  const session: SessionView = {
    session_id: "sess_abc",
    role: "Executor",
    initiative_id: "init_xyz",
    task_id: "task_xyz",
    state: "Failed",
    provider: "anthropic",
    model: "claude",
    input_tokens: 100,
    output_tokens: 50,
    created_at: 1714500000,
    updated_at: 1714500000,
    failure: null,
    ...s,
  };
  vi.spyOn(dashboardApi.sessions, "get").mockResolvedValue(session);
  vi.spyOn(dashboardApi.git, "list").mockResolvedValue([]);
}

function renderAt(sessionId: string) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, refetchInterval: false } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <TestMemoryRouter initialEntries={[`/sessions/${sessionId}`]}>
        <Routes>
          <Route path="/sessions/:id" element={<SessionDetailPage />} />
        </Routes>
      </TestMemoryRouter>
    </QueryClientProvider>,
  );
}

describe("<SessionDetailPage> failure rendering", () => {
  it("renders the structured failure panel on a Failed session with reason", async () => {
    mockSession({ state: "Failed", failure: FAILURE });
    renderAt("sess_abc");
    expect(await screen.findByTestId("failure-kind")).toHaveTextContent(
      "SessionVmFailedFinal",
    );
    expect(screen.getByTestId("failure-message")).toHaveTextContent(
      "VM scaling exhausted retries",
    );
    expect(screen.getByTestId("failure-fields")).toHaveTextContent(
      "failure_class",
    );
  });

  it("renders a calm `(no reason recorded)` affordance when a Failed session ships failure=null", async () => {
    mockSession({ state: "Failed", failure: null });
    renderAt("sess_abc");
    expect(
      await screen.findByText(/\(no reason recorded\)/),
    ).toBeInTheDocument();
    expect(screen.queryByText(/KERNEL BUG/)).toBeNull();
    expect(screen.queryByTestId("failure-kind")).toBeNull();
  });

  it("renders no failure panel on a Running session", async () => {
    mockSession({ state: "Running", failure: null });
    renderAt("sess_abc");
    expect(await screen.findByTestId("session-stream-mock")).toBeInTheDocument();
    expect(screen.getByTestId("session-detail-provider-badge")).toHaveTextContent(
      "anthropic",
    );
    expect(screen.queryByTestId("failure-kind")).toBeNull();
    expect(screen.queryByText(/\(no reason recorded\)/)).toBeNull();
    expect(screen.queryByText(/KERNEL BUG/)).toBeNull();
  });

  it("keeps a revoked session on the detail page as a historical view", async () => {
    mockSession({ state: "Revoked", failure: null, updated_at: 1714500300 });
    renderAt("sess_abc");
    expect(
      await screen.findByTestId("session-lifecycle-notice"),
    ).toHaveTextContent("Session moved to historical view");
    expect(screen.getByTestId("tab-stream")).toHaveTextContent(
      "Stream capture",
    );
    expect(screen.getByTestId("session-stream-mock")).toHaveAttribute(
      "data-historical",
      "true",
    );
  });
});
