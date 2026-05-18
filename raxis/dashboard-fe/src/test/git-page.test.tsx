import React from "react";
import { describe, expect, it, vi, afterEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

import { dashboardApi } from "@/api/client";
import { GitPage } from "@/pages/Git";
import type { WorktreeListEntry } from "@/types/api";

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

function worktree(over: Partial<WorktreeListEntry>): WorktreeListEntry {
  return {
    name: "session-live",
    label: "Executor:session-live",
    kind: "Session",
    path: "/tmp/raxis/worktrees/session-live",
    session_id: "session-live-1234567890",
    task_id: "task-live",
    session_state: "Active",
    observed_head_sha: null,
    observed_branch: null,
    observed_dirty_paths: null,
    base_sha: "a".repeat(40),
    ...over,
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("<GitPage>", () => {
  it("keeps live and past session worktrees on the same page", async () => {
    vi.spyOn(dashboardApi.git, "list").mockResolvedValue([
      worktree({}),
      worktree({
        name: "session-past",
        label: "Executor:session-past",
        path: "/tmp/raxis/worktrees/session-past",
        session_id: "session-past-1234567890",
        task_id: "task-past",
        session_state: "Revoked",
        base_sha: null,
      }),
    ]);

    renderWithProviders(<GitPage />);

    expect(await screen.findByText("2 total")).toBeInTheDocument();
    expect(screen.getByText("1 live")).toBeInTheDocument();
    expect(screen.getByText("1 past")).toBeInTheDocument();
    expect(screen.getByText("Executor:session-live")).toBeInTheDocument();
    expect(screen.getByText("Executor:session-past")).toBeInTheDocument();
    expect(screen.getByText("Browse only")).toBeInTheDocument();
    expect(screen.getAllByText("Past").length).toBeGreaterThan(0);
  });
});
