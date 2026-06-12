import React from "react";
import { describe, expect, it, vi, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { TestMemoryRouter } from "@/test/router";

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
      <TestMemoryRouter>{ui}</TestMemoryRouter>
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
    initiative_id: "init-a",
    initiative_display_name: "Alpha pipeline",
    agent_type: "Executor",
    session_state: "Active",
    observed_head_sha: null,
    observed_branch: null,
    observed_dirty_paths: null,
    surface: "Worktree",
    repository_id: null,
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

  it("filters worktrees by workspace name", async () => {
    vi.spyOn(dashboardApi.git, "list").mockResolvedValue([
      worktree({}),
      worktree({
        name: "session-beta",
        label: "Executor:session-beta",
        path: "/tmp/raxis/worktrees/session-beta",
        session_id: "session-beta-1234567890",
        initiative_id: "init-b",
        initiative_display_name: "Beta import",
        task_id: "task-beta",
      }),
    ]);

    renderWithProviders(<GitPage />);

    expect(await screen.findByText("Executor:session-live")).toBeInTheDocument();
    expect(screen.getByText("Executor:session-beta")).toBeInTheDocument();

    fireEvent.change(screen.getByDisplayValue("All workspaces"), {
      target: { value: "Beta import" },
    });

    await waitFor(() => {
      expect(screen.queryByText("Executor:session-live")).toBeNull();
      expect(screen.getByText("Executor:session-beta")).toBeInTheDocument();
    });
  });

  it("keeps integration-merge main rows attributable to each workspace", async () => {
    vi.spyOn(dashboardApi.git, "list").mockResolvedValue([
      worktree({
        name: "main-repository",
        label: "main",
        kind: "Main",
        surface: "Repository",
        repository_id: "main",
        path: "/tmp/raxis/repositories/main",
        session_id: null,
        task_id: null,
        initiative_id: null,
        initiative_display_name: null,
        agent_type: null,
        session_state: null,
        observed_head_sha: "c".repeat(40),
        observed_branch: "main",
        observed_dirty_paths: 0,
        base_sha: null,
        comparison_head_sha: null,
      }),
      worktree({
        name: "main-integration-init-a",
        label: "Main:Alpha pipeline",
        kind: "Main",
        surface: "Integration",
        repository_id: "main",
        path: "/tmp/raxis/repositories/main",
        session_id: null,
        task_id: "init-a",
        initiative_id: "init-a",
        initiative_display_name: "Alpha pipeline",
        agent_type: null,
        session_state: null,
        observed_head_sha: "b".repeat(40),
        observed_branch: "main",
        observed_dirty_paths: 0,
        base_sha: "a".repeat(40),
        comparison_head_sha: "b".repeat(40),
      }),
      worktree({
        name: "main-integration-init-b",
        label: "Main:Beta import",
        kind: "Main",
        surface: "Integration",
        repository_id: "main",
        path: "/tmp/raxis/repositories/main",
        session_id: null,
        task_id: "init-b",
        initiative_id: "init-b",
        initiative_display_name: "Beta import",
        agent_type: null,
        session_state: null,
        observed_head_sha: "d".repeat(40),
        observed_branch: "main",
        observed_dirty_paths: 0,
        base_sha: "c".repeat(40),
        comparison_head_sha: "d".repeat(40),
      }),
    ]);

    renderWithProviders(<GitPage />);

    expect((await screen.findAllByText("Repositories")).length).toBeGreaterThan(
      0,
    );
    expect(screen.getByText("Repository: main")).toBeInTheDocument();
    expect(screen.getAllByText("Alpha pipeline").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Beta import").length).toBeGreaterThan(0);
    expect(
      screen.getByText("Integrated result: Alpha pipeline"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Integrated result: Beta import"),
    ).toBeInTheDocument();
    expect(screen.getAllByText("bbbbbbbb").length).toBeGreaterThan(0);
    expect(screen.getAllByText("dddddddd").length).toBeGreaterThan(0);

    fireEvent.change(
      screen.getByPlaceholderText(
        "Search repo / workspace / path / session...",
      ),
      { target: { value: "Beta import" } },
    );

    await waitFor(() => {
      expect(screen.queryByText("Integrated result: Alpha pipeline")).toBeNull();
      expect(
        screen.getByText("Integrated result: Beta import"),
      ).toBeInTheDocument();
    });
  });

  it("shows every managed repository in the repositories tab", async () => {
    vi.spyOn(dashboardApi.git, "list").mockResolvedValue([
      worktree({
        name: "main-repository",
        label: "main",
        kind: "Main",
        surface: "Repository",
        repository_id: "main",
        path: "/tmp/raxis/repositories/main",
        session_id: null,
        task_id: null,
        initiative_id: null,
        initiative_display_name: null,
        agent_type: null,
        session_state: null,
        observed_head_sha: "c".repeat(40),
        observed_branch: "main",
        observed_dirty_paths: 0,
        base_sha: null,
        comparison_head_sha: null,
      }),
      worktree({
        name: "main-repository-raxis-gtm",
        label: "raxis-gtm",
        kind: "Main",
        surface: "Repository",
        repository_id: "raxis-gtm",
        path: "/tmp/raxis/repositories/raxis-gtm",
        session_id: null,
        task_id: null,
        initiative_id: null,
        initiative_display_name: null,
        agent_type: null,
        session_state: null,
        observed_head_sha: "d".repeat(40),
        observed_branch: "main",
        observed_dirty_paths: 0,
        base_sha: null,
        comparison_head_sha: null,
      }),
      worktree({
        name: "main-integration-init-a",
        label: "Main:Alpha pipeline",
        kind: "Main",
        surface: "Integration",
        repository_id: "main",
        path: "/tmp/raxis/repositories/main",
        session_id: null,
        task_id: "init-a",
        initiative_id: "init-a",
        initiative_display_name: "Alpha pipeline",
        agent_type: null,
        session_state: null,
        observed_head_sha: "b".repeat(40),
        observed_branch: "main",
        observed_dirty_paths: 0,
        base_sha: "a".repeat(40),
        comparison_head_sha: "b".repeat(40),
      }),
    ]);

    renderWithProviders(<GitPage />);

    expect(await screen.findByText("Repository: main")).toBeInTheDocument();
    expect(screen.getByText("Repository: raxis-gtm")).toBeInTheDocument();
    expect(
      screen.getByText("Integrated result: Alpha pipeline"),
    ).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Repositories" }));

    await waitFor(() => {
      expect(screen.getByText("Repository: main")).toBeInTheDocument();
      expect(screen.getByText("Repository: raxis-gtm")).toBeInTheDocument();
      expect(screen.queryByText("Integrated result: Alpha pipeline")).toBeNull();
    });
  });
});
