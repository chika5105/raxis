import { describe, expect, it, vi, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Route, Routes } from "react-router-dom";
import { TestMemoryRouter } from "@/test/router";

import { dashboardApi } from "@/api/client";
import { WorktreeDetailPage } from "@/pages/WorktreeDetail";
import type { WorktreeDetail, WorktreeDiff, WorktreeLogEntry } from "@/types/api";

function renderWithProviders() {
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
      <TestMemoryRouter initialEntries={["/git/session-a"]}>
        <Routes>
          <Route path="/git/:name" element={<WorktreeDetailPage />} />
        </Routes>
      </TestMemoryRouter>
    </QueryClientProvider>,
  );
}

const fromSha = "a".repeat(40);
const toSha = "b".repeat(40);

function worktree(): WorktreeDetail {
  return {
    name: "session-a",
    label: "Executor:session-a",
    kind: "Session",
    path: "/tmp/raxis/worktrees/session-a",
    session_id: "session-a",
    task_id: "task-a",
    initiative_id: "initiative-a",
    session_state: "Revoked",
    observed_head_sha: toSha,
    observed_branch: null,
    observed_dirty_paths: 0,
    base_sha: fromSha,
    head_sha: toSha,
    branch: null,
    ahead: 1,
    behind: 0,
    status_lines: [],
  };
}

function emptyDiff(): WorktreeDiff {
  return {
    name: "session-a",
    from_sha: fromSha,
    to_sha: toSha,
    files: [],
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("<WorktreeDetailPage>", () => {
  it("opens an agent commit and renders its parent-to-commit diff", async () => {
    const logEntry: WorktreeLogEntry = {
      sha: toSha,
      parent_sha: fromSha,
      short_sha: toSha.slice(0, 8),
      author: "Raxis Agent <agent@example.test>",
      subject: "materialize records",
      at: 1_779_157_878,
    };
    const commitDiff: WorktreeDiff = {
      name: "session-a",
      from_sha: fromSha,
      to_sha: toSha,
      files: [
        {
          path: "out/postgres/001.json",
          status: "A",
          insertions: 2,
          deletions: 0,
          hunk: "@@ -0,0 +1,2 @@\n+{\"id\":1}\n+{\"id\":2}\n",
        },
      ],
    };

    vi.spyOn(dashboardApi.git, "get").mockResolvedValue(worktree());
    vi.spyOn(dashboardApi.git, "diffDefault").mockResolvedValue(emptyDiff());
    vi.spyOn(dashboardApi.git, "log").mockResolvedValue([logEntry]);
    const diffRange = vi
      .spyOn(dashboardApi.git, "diffRange")
      .mockResolvedValue(commitDiff);

    renderWithProviders();

    fireEvent.click(await screen.findByRole("tab", { name: "Agent commits" }));
    const row = await screen.findByRole("button", {
      name: `Expand commit ${logEntry.short_sha}`,
    });

    fireEvent.click(row);

    await waitFor(() =>
      expect(diffRange).toHaveBeenCalledWith("session-a", fromSha, toSha, expect.any(AbortSignal)),
    );
    expect(await screen.findByText("out/postgres/001.json")).toBeInTheDocument();
    expect(screen.getByText("Hide diff")).toBeInTheDocument();
  });
});
