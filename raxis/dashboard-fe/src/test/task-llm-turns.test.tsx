// Witness coverage for `<TaskLlmTurns>`.
//
// Pin: per-turn cards render with usage + cache-hit ratio
// colour coded by the FE-derived ratio. The empty state
// surfaces a hint pointing operators at the kernel-side tap
// once Worker 1 lands.
//
// `INV-DASHBOARD-LLM-TURN-CAPTURED-01` (paired).

import React from "react";
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { dashboardApi } from "@/api/client";
import { TaskLlmTurns } from "@/components/TaskLlmTurns";
import type { TaskLlmTurnView } from "@/types/api";

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
    <QueryClientProvider client={qc}>{ui}</QueryClientProvider>,
  );
}

function turn(over: Partial<TaskLlmTurnView> = {}): TaskLlmTurnView {
  return {
    turn_number: 1,
    ts_unix: 1714500000,
    model: "claude-3-5-sonnet",
    role: "assistant",
    request: { messages: [{ role: "user", content: "hi" }] },
    response: { content: [{ type: "text", text: "hello" }] },
    input_tokens: 200,
    output_tokens: 80,
    cache_creation_input_tokens: 0,
    cache_read_input_tokens: 800,
    latency_ms: 1234,
    ...over,
  };
}

beforeEach(() => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe("<TaskLlmTurns>", () => {
  it("renders one card per turn with usage + cache-hit badge", async () => {
    vi.spyOn(dashboardApi.tasks, "llmTurns").mockResolvedValue([turn()]);

    renderWithProviders(<TaskLlmTurns taskId="task-x" n={50} />);

    await waitFor(() =>
      expect(screen.getByTestId("task-llm-turns-list")).toBeInTheDocument(),
    );
    expect(screen.getAllByTestId("task-llm-turns-row")).toHaveLength(1);
    expect(screen.getByText("Turn 1")).toBeInTheDocument();
    expect(screen.getByText("claude-3-5-sonnet")).toBeInTheDocument();
    // 800 cache_read / (800 + 0 + 200) = 0.8 → green badge.
    const ratio = screen.getByTestId("task-llm-turns-cache-hit-ratio");
    expect(ratio.className).toMatch(/border-ok/);
    expect(ratio.textContent).toContain("80%");
  });

  it("colour codes a poor cache-hit ratio in red", async () => {
    vi.spyOn(dashboardApi.tasks, "llmTurns").mockResolvedValue([
      turn({
        cache_read_input_tokens: 100,
        cache_creation_input_tokens: 50,
        input_tokens: 850,
      }),
    ]);

    renderWithProviders(<TaskLlmTurns taskId="task-x" />);
    await waitFor(() =>
      expect(screen.getByTestId("task-llm-turns-list")).toBeInTheDocument(),
    );
    const ratio = screen.getByTestId("task-llm-turns-cache-hit-ratio");
    expect(ratio.className).toMatch(/border-bad/);
    expect(ratio.textContent).toContain("10%");
  });

  it("renders a typed empty state pointing operators at the kernel-side tap", async () => {
    vi.spyOn(dashboardApi.tasks, "llmTurns").mockResolvedValue([]);

    renderWithProviders(<TaskLlmTurns taskId="task-empty" />);

    await waitFor(() =>
      expect(
        screen.getByText(/No LLM turns recorded yet/),
      ).toBeInTheDocument(),
    );
    expect(
      screen.getByText(/kernel-side gateway tap/),
    ).toBeInTheDocument();
  });
});
