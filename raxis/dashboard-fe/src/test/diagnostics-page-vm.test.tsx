import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { dashboardApi } from "@/api/client";
import { DiagnosticsPage } from "@/pages/Diagnostics";
import { TestMemoryRouter } from "@/test/router";

afterEach(() => {
  vi.restoreAllMocks();
});

function renderDiagnostics() {
  const qc = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        refetchInterval: false,
        refetchOnWindowFocus: false,
      },
    },
  });
  return render(
    <QueryClientProvider client={qc}>
      <TestMemoryRouter initialEntries={["/diagnostics?tab=vm"]}>
        <DiagnosticsPage />
      </TestMemoryRouter>
    </QueryClientProvider>,
  );
}

describe("<DiagnosticsPage> VM tab", () => {
  it("renders VM sessions, command telemetry, and structured command errors", async () => {
    vi.spyOn(dashboardApi.diagnostics, "list").mockResolvedValue({
      generated_at: 1_779_211_500,
      findings: [],
      vm: {
        sessions: [
          {
            session_id: "session-tools",
            role: "Executor",
            state: "Revoked",
            initiative_id: "init-tools",
            initiative_display_name: "Unity Tools",
            task_id: "task-tools",
            task_name: "tooling-mcp-unity",
            provider: "anthropic-realism-e2e",
            model: "claude-haiku-4-5",
            input_tokens: 42,
            output_tokens: 7,
            created_at: 1_779_211_000,
            updated_at: 1_779_211_400,
          },
        ],
        commands: [
          {
            seq: 199,
            event_id: "event-custom-tool",
            at: 1_779_211_351,
            initiative_id: "init-tools",
            initiative_display_name: "Unity Tools",
            task_id: "task-tools",
            task_name: "tooling-mcp-unity",
            session_id: "session-tools",
            tool_name: "unity_run_playmode_tests",
            profile_name: "unity_mcp_tools",
            execution_locality: "host_mcp",
            outcome: "Failed",
            duration_ms: 83,
            exit_code: null,
            signal: null,
            timeout_ms: 5000,
            command_argv_sha256:
              "3392b18473e1d9c385d94c9c559cb71ae3859053000427c5ada674d40ac64de1",
            stdin_bytes_total: 2,
            stdin_sha256:
              "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
            stdout_bytes_total: 512,
            stdout_bytes_captured: 287,
            stdout_sha256:
              "6d3866a0fc52da19ccecf2a35d17f4fbf8ef1289e77073a88825e7bca0ba4e23",
            stdout_truncated: true,
            stderr_bytes_total: 31,
            stderr_bytes_captured: 31,
            stderr_sha256:
              "f2ca1bb6c7e907d06dafe4687e579fceafaa2db39c5a26a9c6d0de33ec2f993d",
            stderr_truncated: false,
            error: "spawn failed: missing rg",
          },
        ],
      },
    });
    vi.spyOn(dashboardApi.sessions, "capture").mockResolvedValue([
      {
        session_id: "session-tools",
        kind: "audit_event",
        ts_unix: 1_779_211_352,
        payload: {
          event_kind: "CustomToolInvoked",
          event_id: "event-custom-tool",
          seq: 199,
          outcome: "Failed",
          error: "spawn failed: missing rg",
        },
      },
    ]);

    renderDiagnostics();

    expect(await screen.findByText("VM sessions")).toBeInTheDocument();
    expect(screen.getAllByText("tooling-mcp-unity")).toHaveLength(2);
    expect(screen.getByText("anthropic-realism-e2e")).toBeInTheDocument();
    expect(screen.getByText("VM command and tool activity")).toBeInTheDocument();
    expect(screen.getByText("unity_run_playmode_tests")).toBeInTheDocument();
    expect(screen.getByText("host_mcp")).toBeInTheDocument();
    expect(screen.getByText("287 B / 512 B truncated")).toBeInTheDocument();
    expect(screen.getByText("spawn failed: missing rg")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Audit #199" })).toHaveAttribute(
      "href",
      "/audit?search=event-custom-tool",
    );

    fireEvent.click(screen.getAllByRole("button", { name: "Open capture" })[1]);

    expect(await screen.findByText("Capture / artifacts")).toBeInTheDocument();
    const dialog = screen.getByRole("dialog", { name: "Capture / artifacts" });
    expect(dialog).toBeInTheDocument();
    expect(screen.getByText("Command evidence")).toBeInTheDocument();
    expect(screen.getByText("Session capture records")).toBeInTheDocument();
    expect(screen.getByText(/Raw stdout and/)).toBeInTheDocument();
    expect(await screen.findByText("CustomToolInvoked")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    expect(dialog).not.toBeInTheDocument();
  });
});
