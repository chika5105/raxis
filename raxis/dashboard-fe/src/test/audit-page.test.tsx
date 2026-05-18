import { describe, expect, it, vi, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";

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
      <MemoryRouter
        initialEntries={[initialEntry]}
        future={{
          v7_startTransition: true,
          v7_relativeSplatPath: true,
        }}
      >
        <AuditPage />
      </MemoryRouter>
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

    renderAudit("/audit?initiative_id=init-a");

    await screen.findByText("Audit chain OK");
    expect(screen.getAllByText("init-a").length).toBeGreaterThan(0);
    expect(listSpy).toHaveBeenCalledWith(
      expect.objectContaining({ highlight_initiative_id: "init-a" }),
      expect.anything(),
    );
  });
});
