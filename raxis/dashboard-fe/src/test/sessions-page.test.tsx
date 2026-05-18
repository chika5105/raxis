import React from "react";
import { describe, expect, it, vi, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

import { dashboardApi } from "@/api/client";
import { SessionsPage } from "@/pages/Sessions";
import type { SessionView } from "@/types/api";

function renderWithProviders(ui: React.ReactElement) {
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
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

function session(over: Partial<SessionView>): SessionView {
  return {
    session_id: "sess-anthropic-1234567890",
    role: "Executor",
    initiative_id: "init-a",
    task_id: "task-a",
    state: "Active",
    provider: "anthropic-prod",
    model: "claude-sonnet-4-5-20250929",
    input_tokens: 10,
    output_tokens: 5,
    created_at: 1714500000,
    updated_at: 1714500000,
    failure: null,
    annotations: [],
    latest_annotation: null,
    ...over,
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("<SessionsPage>", () => {
  it("renders and searches provider alongside model", async () => {
    vi.spyOn(dashboardApi.sessions, "list").mockResolvedValue([
      session({}),
      session({
        session_id: "sess-openai-1234567890",
        provider: "openai-prod",
        model: "gpt-4o",
        task_id: "task-b",
      }),
    ]);

    renderWithProviders(<SessionsPage />);

    expect(await screen.findByText("Provider / Model")).toBeInTheDocument();
    expect(screen.getByText("anthropic-prod")).toBeInTheDocument();
    expect(screen.getByText("openai-prod")).toBeInTheDocument();

    fireEvent.change(
      screen.getByPlaceholderText("Search id / provider / model…"),
      { target: { value: "openai" } },
    );

    await waitFor(() => {
      expect(screen.getByText("openai-prod")).toBeInTheDocument();
      expect(screen.queryByText("anthropic-prod")).toBeNull();
    });
  });
});
