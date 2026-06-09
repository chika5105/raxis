import React from "react";
import { describe, expect, it, vi, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { TestMemoryRouter } from "@/test/router";

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
      <TestMemoryRouter>{ui}</TestMemoryRouter>
    </QueryClientProvider>,
  );
}

function session(over: Partial<SessionView>): SessionView {
  return {
    session_id: "sess-anthropic-1234567890",
    role: "Executor",
    initiative_id: "init-a",
    initiative_display_name: "Alpha pipeline",
    task_id: "task-a",
    task_name: "ship-api",
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
      screen.getByPlaceholderText(
        "Search workspace / task / session / provider...",
      ),
      { target: { value: "openai" } },
    );

    await waitFor(() => {
      expect(screen.getByText("openai-prod")).toBeInTheDocument();
      expect(screen.queryByText("anthropic-prod")).toBeNull();
    });
  });

  it("searches by operator task name as well as runtime task id", async () => {
    vi.spyOn(dashboardApi.sessions, "list").mockResolvedValue([
      session({ task_id: "uuid-build-api", task_name: "build-api" }),
      session({
        session_id: "sess-review-1234567890",
        task_id: "uuid-review-api",
        task_name: "review-api",
      }),
    ]);

    renderWithProviders(<SessionsPage />);

    expect(await screen.findByText("build-api")).toBeInTheDocument();
    expect(screen.getByText("review-api")).toBeInTheDocument();

    fireEvent.change(
      screen.getByPlaceholderText(
        "Search workspace / task / session / provider...",
      ),
      { target: { value: "review-api" } },
    );

    await waitFor(() => {
      expect(screen.queryByText("build-api")).toBeNull();
      expect(screen.getByText("review-api")).toBeInTheDocument();
      expect(screen.getByText("uuid-review-api")).toBeInTheDocument();
    });
  });

  it("filters sessions by workspace name", async () => {
    vi.spyOn(dashboardApi.sessions, "list").mockResolvedValue([
      session({}),
      session({
        session_id: "sess-beta-1234567890",
        initiative_id: "init-b",
        initiative_display_name: "Beta import",
        task_id: "task-beta",
      }),
    ]);

    renderWithProviders(<SessionsPage />);

    expect(await screen.findByText("sess-anthropic-1...")).toBeInTheDocument();
    expect(screen.getByText("sess-beta-123456...")).toBeInTheDocument();

    fireEvent.change(screen.getByDisplayValue("All workspaces"), {
      target: { value: "Beta import" },
    });

    await waitFor(() => {
      expect(screen.queryByText("sess-anthropic-1...")).toBeNull();
      expect(screen.getByText("sess-beta-123456...")).toBeInTheDocument();
    });
  });

  it("keeps past sessions on the main sessions page", async () => {
    vi.spyOn(dashboardApi.sessions, "list").mockResolvedValue([
      session({}),
      session({
        session_id: "sess-revoked-1234567890",
        state: "Revoked",
        provider: "anthropic-prod",
        model: "claude-sonnet-4-5-20250929",
        task_id: "task-ended",
      }),
    ]);

    renderWithProviders(<SessionsPage />);

    expect(await screen.findByText("2 total")).toBeInTheDocument();
    expect(screen.getByText("1 live")).toBeInTheDocument();
    expect(screen.getByText("1 past")).toBeInTheDocument();
    expect(screen.getByText("sess-revoked-123...")).toBeInTheDocument();
    expect(screen.getAllByText("Revoked").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Past").length).toBeGreaterThan(0);
  });
});
