/* Inline action-failure banner rendering on the Notifications
 * page. Pinned by INV-DASHBOARD-FAILURE-VISIBILITY-01 §5.6
 * ("operator-action rejections render inline at the click
 * site"). */

import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { TestMemoryRouter } from "@/test/router";

import { ApiError, dashboardApi } from "@/api/client";
import { NotificationsPage } from "@/pages/Notifications";

function mockEmptyList() {
  vi.spyOn(dashboardApi.notifications, "list").mockResolvedValue([]);
  vi.spyOn(dashboardApi.notifications, "unreadCount").mockResolvedValue({
    count: 0,
  });
}

function renderPage() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, refetchInterval: false } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <TestMemoryRouter>
        <NotificationsPage />
      </TestMemoryRouter>
    </QueryClientProvider>,
  );
}

describe("<NotificationsPage> action-failure banner", () => {
  it("shows the kernel error code + detail when Mark all read rejects", async () => {
    mockEmptyList();
    vi.spyOn(dashboardApi.notifications, "markAllRead").mockRejectedValue(
      new ApiError(
        500,
        "FAIL_DASHBOARD_NOTIFICATIONS_MARK_ALL",
        "sqlite: database is locked",
      ),
    );

    renderPage();
    await waitFor(() =>
      expect(screen.getByText("Notifications")).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("button", { name: /Mark all read/i }));

    const banner = await screen.findByTestId("action-failure-banner");
    expect(banner).toHaveTextContent("Mark all read failed");
    expect(banner).toHaveTextContent("FAIL_DASHBOARD_NOTIFICATIONS_MARK_ALL");
    expect(banner).toHaveTextContent("sqlite: database is locked");

    fireEvent.click(screen.getByRole("button", { name: "Dismiss" }));
    await waitFor(() =>
      expect(screen.queryByTestId("action-failure-banner")).toBeNull(),
    );
  });

  it("falls back to a generic error code on a non-ApiError rejection", async () => {
    mockEmptyList();
    vi.spyOn(dashboardApi.notifications, "markAllRead").mockRejectedValue(
      new Error("xhr aborted"),
    );

    renderPage();
    await waitFor(() =>
      expect(screen.getByText("Notifications")).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("button", { name: /Mark all read/i }));

    const banner = await screen.findByTestId("action-failure-banner");
    expect(banner).toHaveTextContent("ERROR");
    expect(banner).toHaveTextContent("xhr aborted");
  });
});
