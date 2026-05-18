// Witness coverage for `<TaskLlmTurns>`.
//
// Pin: per-turn cards render with usage + cache-hit ratio
// colour coded by the FE-derived ratio. The empty state
// surfaces a hint pointing operators at the kernel-side tap.
//
// `INV-DASHBOARD-LLM-TURN-CAPTURED-01` (paired with kernel
// tap), `INV-DASHBOARD-LLM-TURN-PANEL-WIRE-SHAPE-01`
// (wire-shape contract).

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
    model: "claude-sonnet-4-5-20250929",
    provider: "anthropic",
    role: "assistant",
    request: { messages: [{ role: "user", content: "hi" }] },
    response: {
      model: "claude-sonnet-4-5-20250929",
      role: "assistant",
      content: [{ type: "text", text: "hello-from-anthropic" }],
      stop_reason: "end_turn",
    },
    input_tokens: 200,
    output_tokens: 80,
    cache_creation_input_tokens: 0,
    cache_read_input_tokens: 800,
    latency_ms: 1234,
    // iter64 carry-over fields — required on the wire so global
    // "recent LLM activity" cross-task views can merge across
    // tasks. The FE may not render them in this panel today but
    // the type is non-optional.
    task_id: "task-x",
    session_id: "sess-1",
    fetch_id: "fetch-1",
    status_code: 200,
    body_truncated: false,
    original_body_bytes: 770,
    error: null,
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
    expect(
      screen.getByText("claude-sonnet-4-5-20250929"),
    ).toBeInTheDocument();
    expect(screen.getByTestId("task-llm-turns-provider")).toHaveTextContent(
      "anthropic",
    );
    // 800 cache_read / (800 + 0 + 200) = 0.8 → green badge.
    const ratio = screen.getByTestId("task-llm-turns-cache-hit-ratio");
    expect(ratio.className).toMatch(/border-ok/);
    expect(ratio.textContent).toContain("80%");
  });

  /// `INV-DASHBOARD-LLM-TURN-PANEL-WIRE-SHAPE-01`. Pin the post-
  /// iter64 contract end-to-end: with the new wire shape (model
  /// + role + parsed response + per-turn usage flowing through
  /// from the BE) the panel MUST surface every field the
  /// operator needs to debug an LLM round-trip.
  it("surfaces model, parsed response payload, token counts, and cache-hit ratio", async () => {
    vi.spyOn(dashboardApi.tasks, "llmTurns").mockResolvedValue([
      turn({
        input_tokens: 2,
        output_tokens: 1281,
        cache_creation_input_tokens: 5586,
        cache_read_input_tokens: 2596,
      }),
    ]);

    renderWithProviders(<TaskLlmTurns taskId="task-x" />);
    await waitFor(() =>
      expect(screen.getByTestId("task-llm-turns-list")).toBeInTheDocument(),
    );

    // Model name lifted from response.model on the BE.
    expect(
      screen.getByText("claude-sonnet-4-5-20250929"),
    ).toBeInTheDocument();
    // Provider-role marker. iter65 — the literal "role" prefix
    // was dropped in favour of a `title` tooltip ("Upstream LLM
    // speaker (provider role)") so the new dedicated agent-role
    // badge (Orchestrator/Executor/Reviewer) reads cleanly next
    // to it. The visible text is now just the bare value
    // (`assistant`).
    expect(screen.getByText("assistant")).toBeInTheDocument();
    // Parsed response payload renders as JSON in the <pre>; the
    // operator-visible substring of the Anthropic content block
    // tells us the projection landed.
    expect(
      screen.getByText(/hello-from-anthropic/),
    ).toBeInTheDocument();

    // Per-turn token counts. The component renders the four
    // counters under <dl> — assert the formatted token strings
    // are present (fmtTokens is locale-formatted; we assert the
    // digit substring instead of an exact match to keep the
    // witness robust across locale).
    expect(screen.getByText(/1,?281/)).toBeInTheDocument();
    expect(screen.getByText(/5,?586/)).toBeInTheDocument();
    expect(screen.getByText(/2,?596/)).toBeInTheDocument();

    // Cache-hit ratio = 2596 / (2596 + 5586 + 2) = 0.317 → yellow
    // (≥ 0.3, < 0.8 → border-warn). The Math.floor of 31.7 is
    // 31 → "32%" via toFixed(0).
    const ratio = screen.getByTestId("task-llm-turns-cache-hit-ratio");
    expect(ratio.className).toMatch(/border-warn/);
    expect(ratio.textContent).toContain("32%");
  });

  it("renders an upstream-error badge when the kernel captured a transport failure", async () => {
    vi.spyOn(dashboardApi.tasks, "llmTurns").mockResolvedValue([
      turn({
        error: "transport_timeout",
        status_code: null,
      }),
    ]);

    renderWithProviders(<TaskLlmTurns taskId="task-x" />);
    await waitFor(() =>
      expect(screen.getByTestId("task-llm-turns-list")).toBeInTheDocument(),
    );

    const badge = screen.getByTestId("task-llm-turns-error-badge");
    expect(badge.textContent).toContain("transport_timeout");
    expect(badge.className).toMatch(/border-bad/);
  });

  it("appends a truncation suffix on the Response header when body_truncated is true", async () => {
    vi.spyOn(dashboardApi.tasks, "llmTurns").mockResolvedValue([
      turn({
        body_truncated: true,
        original_body_bytes: 45_678,
      }),
    ]);

    renderWithProviders(<TaskLlmTurns taskId="task-x" />);
    await waitFor(() =>
      expect(screen.getByTestId("task-llm-turns-list")).toBeInTheDocument(),
    );

    const truncBadge = screen.getByTestId("task-llm-turns-truncation-badge");
    expect(truncBadge.textContent).toMatch(/truncated/);
    expect(truncBadge.textContent).toMatch(/45,?678/);
  });

  // iter65 — orchestrator-llm-turns: every captured turn carries
  // an `agent_role` (`"Orchestrator"` | `"Executor"` | `"Reviewer"`)
  // so the operator can tell which raxis session issued the call
  // when several roles land in the same coordinator task file.
  // The kernel-side stamp lives in `planner_fetch.rs::agent_role_label`
  // (BE pin) — this is the FE pin on the same wire labels.
  it.each([
    ["Orchestrator", "border-accent"],
    ["Executor", "border-info"],
    ["Reviewer", "border-warn"],
  ])(
    "renders the %s agent-role badge with the role-tone class",
    async (role, expectedToneClass) => {
      vi.spyOn(dashboardApi.tasks, "llmTurns").mockResolvedValue([
        turn({ agent_role: role }),
      ]);

      renderWithProviders(<TaskLlmTurns taskId="task-x" />);
      await waitFor(() =>
        expect(screen.getByTestId("task-llm-turns-list")).toBeInTheDocument(),
      );

      const badge = screen.getByTestId("task-llm-turns-agent-role");
      expect(badge.getAttribute("data-agent-role")).toBe(role);
      expect(badge.textContent).toContain(role);
      expect(badge.className).toContain(expectedToneClass);
    },
  );

  it("hides the agent-role badge when the turn carries no role tag", async () => {
    vi.spyOn(dashboardApi.tasks, "llmTurns").mockResolvedValue([
      turn({ agent_role: null }),
    ]);

    renderWithProviders(<TaskLlmTurns taskId="task-x" />);
    await waitFor(() =>
      expect(screen.getByTestId("task-llm-turns-list")).toBeInTheDocument(),
    );

    expect(
      screen.queryByTestId("task-llm-turns-agent-role"),
    ).not.toBeInTheDocument();
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
