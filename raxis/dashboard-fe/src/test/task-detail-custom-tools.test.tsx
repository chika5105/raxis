import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Route, Routes } from "react-router-dom";

import { dashboardApi } from "@/api/client";
import { TaskDetailPage } from "@/pages/TaskDetail";
import { TestMemoryRouter } from "@/test/router";
import type { TaskView } from "@/types/api";

function task(overrides: Partial<TaskView> = {}): TaskView {
  return {
    task_id: "tooling-mcp-unity",
    initiative_id: "init-tools",
    initiative_display_name: "Unity Tools",
    agent_type: "Executor",
    title: "tooling-mcp-unity",
    state: "Completed",
    session_id: "session-tools",
    reviewer_verdicts: [],
    structured_outputs: [],
    custom_tool_calls: [
      {
        seq: 199,
        event_id: "event-custom-tool",
        at: 1_779_211_351,
        tool_name: "unity_run_playmode_tests",
        profile_name: "unity_mcp_tools",
        execution_locality: "host_mcp",
        outcome: "Success",
        duration_ms: 83,
        exit_code: 0,
        signal: null,
        timeout_ms: 5000,
        command_argv_sha256:
          "3392b18473e1d9c385d94c9c559cb71ae3859053000427c5ada674d40ac64de1",
        stdin_bytes_total: 2,
        stdin_sha256:
          "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
        stdout_bytes_total: 287,
        stdout_bytes_captured: 287,
        stdout_sha256:
          "6d3866a0fc52da19ccecf2a35d17f4fbf8ef1289e77073a88825e7bca0ba4e23",
        stdout_truncated: false,
        stderr_bytes_total: 0,
        stderr_bytes_captured: 0,
        stderr_sha256:
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        stderr_truncated: false,
        error: null,
      },
    ],
    path_allowlist: ["out/tools/"],
    created_at: 1_779_211_000,
    updated_at: 1_779_211_400,
    failure: null,
    blocked_downstream: [],
    annotations: [],
    latest_annotation: null,
    review_verdict: null,
    last_critique: null,
    reviewer_panel_results: [],
    review_reject_count: 0,
    max_review_rejections: 2,
    review_retry_exhausted: false,
    crash_retry_count: 0,
    max_crash_retries: 3,
    is_active: false,
    ...overrides,
  };
}

function renderTask() {
  vi.spyOn(dashboardApi.tasks, "get").mockResolvedValue(task());
  vi.spyOn(dashboardApi.tasks, "llmTurns").mockResolvedValue([]);
  vi.spyOn(dashboardApi.tasks, "witnesses").mockResolvedValue([]);
  vi.spyOn(dashboardApi.tasks, "worktreeSnapshots").mockResolvedValue([]);
  vi.spyOn(dashboardApi.initiatives, "get").mockResolvedValue({
    initiative_id: "init-tools",
    display_name: "Unity Tools",
    state: "Completed",
    task_count: 1,
    completed_tasks: 1,
    failed_tasks: 0,
    created_at: 1_779_211_000,
    updated_at: 1_779_211_400,
    approved_by: null,
    plan_sha256: null,
    target_ref: null,
    policy_epoch: 1,
    tasks: [],
    edges: [],
    run_summary: {
      terminal: true,
      elapsed_seconds: 400,
      session_count: 1,
      active_session_count: 0,
      llm_turn_count: 0,
      input_tokens: 0,
      output_tokens: 0,
      cache_read_tokens: 0,
      cache_creation_tokens: 0,
      token_cost_micros: 0,
      admission_reserved_units: 0,
      actual_cost_units: 0,
      declared_turn_budget: null,
      declared_wallclock_budget_seconds: null,
    },
    failure: null,
  });
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, refetchInterval: false } },
  });
  return render(
    <QueryClientProvider client={qc}>
      <TestMemoryRouter initialEntries={["/tasks/tooling-mcp-unity"]}>
        <Routes>
          <Route path="/tasks/:id" element={<TaskDetailPage />} />
        </Routes>
      </TestMemoryRouter>
    </QueryClientProvider>,
  );
}

describe("<TaskDetailPage> custom tool calls", () => {
  it("renders CustomToolInvoked audit rows as first-class task evidence", async () => {
    renderTask();

    expect(await screen.findByText("Custom tool calls")).toBeInTheDocument();
    expect(screen.getByText("unity_run_playmode_tests")).toBeInTheDocument();
    expect(screen.getByText("unity_mcp_tools")).toBeInTheDocument();
    expect(screen.getByText("host_mcp")).toBeInTheDocument();
    expect(screen.getByText("Audit #199")).toBeInTheDocument();
    expect(screen.getByText("83 ms")).toBeInTheDocument();
    expect(screen.getByText("287 / 287 B")).toBeInTheDocument();
  });
});
