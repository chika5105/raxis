import { describe, expect, it } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { TestMemoryRouter } from "@/test/router";

import { Shell } from "@/components/Shell";
import { ThemeProvider } from "@/lib/theme";

function renderWithProviders() {
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
        <TestMemoryRouter>
          <Shell>
            <div>wide route body</div>
          </Shell>
        </TestMemoryRouter>
      </ThemeProvider>
    </QueryClientProvider>,
  );
}

describe("<Shell> scroll frame", () => {
  it("keeps routed dashboard pages scrollable on both axes", () => {
    renderWithProviders();

    expect(screen.getByTestId("dashboard-scroll-viewport")).toHaveClass(
      "overflow-auto",
    );
    expect(screen.getByTestId("dashboard-route-frame")).toHaveClass(
      "min-w-0",
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
