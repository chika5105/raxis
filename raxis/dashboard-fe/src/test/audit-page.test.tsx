import { describe, expect, it, vi, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { TestMemoryRouter } from "@/test/router";

import { dashboardApi } from "@/api/client";
import { AuditPage } from "@/pages/Audit";
import type { AuditEntryView } from "@/types/api";

function renderAudit(initialEntry: string) {
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
      <TestMemoryRouter
        initialEntries={[initialEntry]}
        future={{
          v7_startTransition: true,
          v7_relativeSplatPath: true,
        }}
      >
        <AuditPage />
      </TestMemoryRouter>
    </QueryClientProvider>,
  );
}

const row = (over: Partial<AuditEntryView> & { seq: number }): AuditEntryView => ({
  seq: over.seq,
  event_id: over.event_id ?? `ev-${over.seq}`,
  event_kind: over.event_kind ?? "KernelEvent",
  initiative_id: over.initiative_id ?? null,
  task_id: over.task_id ?? null,
  session_id: over.session_id ?? null,
  at: over.at ?? 1_700_000_000 + over.seq,
  payload: over.payload ?? {},
  is_highlighted: over.is_highlighted ?? false,
  highlight_reasons: over.highlight_reasons ?? [],
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("<AuditPage>", () => {
  it("keeps the kernel-wide chain while highlighting one initiative", async () => {
    const listSpy = vi
      .spyOn(dashboardApi.audit, "list")
      .mockResolvedValue([
        row({ seq: 2, initiative_id: "init-b" }),
        row({
          seq: 1,
          initiative_id: "init-a",
          is_highlighted: true,
          highlight_reasons: ["audit.initiative_id"],
        }),
      ]);
    vi.spyOn(dashboardApi.audit, "chainStatus").mockResolvedValue({
      status: "ok",
      last_verified_seq: 2,
      total_records: 2,
      segment_count: 1,
      verified_at_ms: 1_700_000_000_000,
      last_error: null,
      fresh: true,
    });
    vi.spyOn(dashboardApi.initiatives, "list").mockResolvedValue([]);

    renderAudit("/audit?highlight_initiative_id=init-a");

    await screen.findByText("init-b");
    expect(screen.getAllByText("init-a").length).toBeGreaterThan(0);
    expect(screen.getByText("match")).toBeInTheDocument();
    expect(screen.getByText(/Kernel chain:/)).toHaveTextContent(
      "2 loaded · 1 highlighted",
    );
    await waitFor(() => {
      expect(listSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          limit: 50,
          highlight_initiative_id: "init-a",
        }),
        expect.anything(),
      );
    });
  });

  it("treats legacy initiative_id URLs as highlight-only", async () => {
    const listSpy = vi
      .spyOn(dashboardApi.audit, "list")
      .mockResolvedValue([row({ seq: 1, initiative_id: "init-a" })]);
    vi.spyOn(dashboardApi.audit, "chainStatus").mockResolvedValue({
      status: "ok",
      last_verified_seq: 1,
      total_records: 1,
      segment_count: 1,
      verified_at_ms: 1_700_000_000_000,
      last_error: null,
      fresh: true,
    });
    vi.spyOn(dashboardApi.initiatives, "list").mockResolvedValue([]);

    renderAudit("/audit?initiative_id=init-a");

    await screen.findByText("Audit chain OK");
    expect(screen.getAllByText("init-a").length).toBeGreaterThan(0);
    expect(listSpy).toHaveBeenCalledWith(
      expect.objectContaining({ highlight_initiative_id: "init-a" }),
      expect.anything(),
    );
  });

  it("filters loaded rows by partial event name and workspace", async () => {
    vi.spyOn(dashboardApi.audit, "list").mockResolvedValue([
      row({
        seq: 2,
        event_kind: "TproxyAdmissionGranted",
        initiative_id: "init-alpha",
      }),
      row({
        seq: 1,
        event_kind: "CredentialProxyStarted",
        initiative_id: "init-beta",
      }),
    ]);
    vi.spyOn(dashboardApi.audit, "chainStatus").mockResolvedValue({
      status: "ok",
      last_verified_seq: 2,
      total_records: 2,
      segment_count: 1,
      verified_at_ms: 1_700_000_000_000,
      last_error: null,
      fresh: true,
    });
    vi.spyOn(dashboardApi.initiatives, "list").mockResolvedValue([
      {
        initiative_id: "init-alpha",
        display_name: "Alpha workspace",
        state: "Completed",
        task_count: 1,
        completed_tasks: 1,
        failed_tasks: 0,
        created_at: 1,
        updated_at: 1,
      },
      {
        initiative_id: "init-beta",
        display_name: "Beta workspace",
        state: "Completed",
        task_count: 1,
        completed_tasks: 1,
        failed_tasks: 0,
        created_at: 1,
        updated_at: 1,
      },
    ]);

    renderAudit("/audit");

    expect(await screen.findByText("TproxyAdmissionGranted")).toBeInTheDocument();
    expect(screen.getByText("CredentialProxyStarted")).toBeInTheDocument();

    fireEvent.change(screen.getByPlaceholderText("Event name, payload text, task..."), {
      target: { value: "tproxy" },
    });
    expect(await screen.findByText("TproxyAdmissionGranted")).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.queryByText("CredentialProxyStarted")).toBeNull();
    });

    fireEvent.change(screen.getByDisplayValue("All workspaces"), {
      target: { value: "Beta workspace" },
    });
    expect(await screen.findByText("No audit rows match these filters.")).toBeInTheDocument();
  });

  it("sends audit search to the backend and avoids matching payload keys as text", async () => {
    const listSpy = vi
      .spyOn(dashboardApi.audit, "list")
      .mockResolvedValue([
        row({
          seq: 2,
          event_kind: "SessionRevoked",
          payload: { terminal_tool: null },
        }),
        row({
          seq: 1,
          event_kind: "CustomToolInvoked",
          task_id: "tooling-mcp-unity",
          payload: { tool_name: "unity_build_player" },
        }),
      ]);
    vi.spyOn(dashboardApi.audit, "chainStatus").mockResolvedValue({
      status: "ok",
      last_verified_seq: 2,
      total_records: 2,
      segment_count: 1,
      verified_at_ms: 1_700_000_000_000,
      last_error: null,
      fresh: true,
    });
    vi.spyOn(dashboardApi.initiatives, "list").mockResolvedValue([]);

    renderAudit("/audit?search=tool");

    expect(await screen.findByText("CustomToolInvoked")).toBeInTheDocument();
    expect(screen.queryByText("SessionRevoked")).toBeNull();
    await waitFor(() => {
      expect(listSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          limit: 50,
          search: "tool",
        }),
        expect.anything(),
      );
    });
  });
});
