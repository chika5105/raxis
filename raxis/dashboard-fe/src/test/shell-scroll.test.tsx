import { describe, expect, it } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { TestMemoryRouter } from "@/test/router";

import { Shell } from "@/components/Shell";
import { CanvasLayout } from "@/components/builder/CanvasLayout";
import { ThemeProvider } from "@/lib/theme";

function renderWithProviders(initialEntries = ["/"]) {
  window.localStorage.clear();
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
      <ThemeProvider>
        <TestMemoryRouter initialEntries={initialEntries}>
          <Shell>
            <div>wide route body</div>
          </Shell>
        </TestMemoryRouter>
      </ThemeProvider>
    </QueryClientProvider>,
  );
}

describe("<Shell> scroll frame", () => {
  it("bounds the dashboard to one viewport so body scroll does not fight route scroll", () => {
    const { container } = renderWithProviders();

    expect(container.firstElementChild).toHaveClass("h-screen");
    expect(container.firstElementChild).toHaveClass("overflow-hidden");
  });

  it("keeps routed dashboard pages scrollable on both axes", () => {
    renderWithProviders();

    expect(screen.getByTestId("dashboard-scroll-viewport")).toHaveClass(
      "overflow-auto",
    );
    expect(screen.getByTestId("dashboard-route-frame")).toHaveClass(
      "min-w-0",
    );
  });

  it("lets canvas pages own internal pane scrolling", () => {
    renderWithProviders(["/policy-builder"]);

    expect(screen.getByTestId("dashboard-scroll-viewport")).toHaveClass(
      "overflow-hidden",
    );
    expect(screen.getByTestId("dashboard-route-frame")).toHaveClass(
      "flex-col",
    );
  });

  it("lets builder side panes delegate scrolling to child-owned panels", () => {
    render(
      <CanvasLayout
        leftPaneTitle="Library"
        leftPaneOwnsScroll
        leftPane={<div data-testid="left-owned-scroll" className="h-full overflow-y-auto">left</div>}
        rightPaneTitle="Actions"
        rightPaneOwnsScroll
        rightPane={<div data-testid="right-owned-scroll" className="h-full overflow-y-auto">right</div>}
      >
        <div>center</div>
      </CanvasLayout>,
    );

    expect(screen.getByTestId("left-owned-scroll").parentElement).toHaveClass(
      "overflow-hidden",
    );
    expect(screen.getByTestId("right-owned-scroll").parentElement).toHaveClass(
      "overflow-hidden",
    );
    expect(screen.getByTestId("left-owned-scroll").parentElement).not.toHaveClass(
      "overflow-y-auto",
    );
  });

  it("resets route viewport scroll when changing pages", async () => {
    renderWithProviders();
    const viewport = screen.getByTestId("dashboard-scroll-viewport");
    viewport.scrollLeft = 480;
    viewport.scrollTop = 320;

    fireEvent.click(screen.getByRole("link", { name: /health/i }));

    await waitFor(() => {
      expect(viewport.scrollLeft).toBe(0);
      expect(viewport.scrollTop).toBe(0);
    });
  });
});
