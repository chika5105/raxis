/* `<InitiativePlanView>` — covers all four states required by
 * `INV-DASHBOARD-INITIATIVE-PLAN-VISIBLE-01`: loading, loaded
 * (with copy + download interactions), 404 (initiative unknown),
 * 410 (plan archived). Monaco is mocked to a plain <textarea>
 * so the bundled editor doesn't blow up jsdom on its CSS
 * imports — the tests assert on the body content + button
 * behaviour, not on Monaco's chrome. */

import React from "react";
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { TestMemoryRouter } from "@/test/router";

// Monaco editor mock — jsdom can't load Monaco's bundled CSS / web
// workers, so we replace the editor with a vanilla textarea that
// echoes the `value` and a `data-testid` matching what the SUT
// expects. Tests assert on the textarea's content for the loaded
// state; download tests synthesise the blob from the wire payload.
vi.mock("@monaco-editor/react", () => ({
  __esModule: true,
  default: function MockMonaco({
    value,
    options,
  }: {
    value?: string;
    options?: { readOnly?: boolean };
  }) {
    return (
      <textarea
        data-testid="monaco-mock"
        readOnly={options?.readOnly ?? false}
        value={value ?? ""}
        onChange={() => {
          /* read-only mock */
        }}
      />
    );
  },
}));

import { ApiError, dashboardApi } from "@/api/client";
import { InitiativePlanView } from "@/components/InitiativePlanView";
import { ThemeProvider } from "@/lib/theme";

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
      <ThemeProvider>
        <TestMemoryRouter>{ui}</TestMemoryRouter>
      </ThemeProvider>
    </QueryClientProvider>,
  );
}

const SAMPLE_TOML = `# original\n[plan.initiative]\ntitle = "ship-auth"\n\n[[tasks]]\ntask_name = "implement-auth"\npath_allowlist = ["src/auth/**"]\n`;

beforeEach(() => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe("<InitiativePlanView>", () => {
  it("renders a loading state before the plan resolves", async () => {
    let resolve: ((v: never) => void) | null = null;
    const planSpy = vi
      .spyOn(dashboardApi.initiatives, "plan")
      .mockReturnValueOnce(
        new Promise((r) => {
          // never resolves during this test
          resolve = r as never;
        }),
      );
    renderWithProviders(<InitiativePlanView initiativeId="init-1" />);
    expect(screen.getByLabelText("Loading plan")).toBeInTheDocument();
    expect(planSpy).toHaveBeenCalledWith("init-1", expect.anything());
    // Silence the dangling promise.
    void resolve;
  });

  it("renders the submitted plan TOML byte-for-byte once loaded", async () => {
    vi.spyOn(dashboardApi.initiatives, "plan").mockResolvedValue({
      initiative_id: "init-1",
      plan_sha256: "deadbeef".repeat(8),
      bundle_sha256: "ab".repeat(32),
      submitted_toml: SAMPLE_TOML,
      submitted_toml_bytes: SAMPLE_TOML.length,
      submitted_at_unix: 1_700_000_000,
      submitted_by: "fingerprint-deadbeef",
      approval_status: "approved",
      approved_at_unix: 1_700_000_001,
    });
    renderWithProviders(<InitiativePlanView initiativeId="init-1" />);

    const editor = await screen.findByTestId("monaco-mock");
    expect(editor).toHaveValue(SAMPLE_TOML);
    expect(editor).toHaveAttribute("readOnly");
    expect(screen.getByTestId("plan-loaded")).toHaveAttribute(
      "data-approval-status",
      "approved",
    );
    expect(screen.getByTestId("plan-approval-badge")).toHaveTextContent(
      /approved/i,
    );
  });

  it("copies the TOML to the clipboard and surfaces a Copied! toast", async () => {
    vi.spyOn(dashboardApi.initiatives, "plan").mockResolvedValue({
      initiative_id: "init-1",
      plan_sha256: null,
      bundle_sha256: null,
      submitted_toml: SAMPLE_TOML,
      submitted_toml_bytes: SAMPLE_TOML.length,
      submitted_at_unix: 1_700_000_000,
      submitted_by: null,
      approval_status: "pending",
      approved_at_unix: null,
    });
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(globalThis.navigator, "clipboard", {
      value: { writeText },
      configurable: true,
    });

    renderWithProviders(<InitiativePlanView initiativeId="init-1" />);
    const copyBtn = await screen.findByTestId("plan-copy");
    expect(copyBtn).toHaveTextContent(/copy/i);
    fireEvent.click(copyBtn);
    await waitFor(() => {
      expect(writeText).toHaveBeenCalledWith(SAMPLE_TOML);
    });
    await waitFor(() => {
      expect(copyBtn).toHaveTextContent(/copied/i);
    });
  });

  it("triggers a blob download named after the initiative on click", async () => {
    vi.spyOn(dashboardApi.initiatives, "plan").mockResolvedValue({
      initiative_id: "init-XYZ",
      plan_sha256: null,
      bundle_sha256: null,
      submitted_toml: SAMPLE_TOML,
      submitted_toml_bytes: SAMPLE_TOML.length,
      submitted_at_unix: 1_700_000_000,
      submitted_by: null,
      approval_status: "approved",
      approved_at_unix: 1_700_000_001,
    });

    const createObjectURL = vi.fn().mockReturnValue("blob:fake");
    const revokeObjectURL = vi.fn();
    Object.defineProperty(globalThis.URL, "createObjectURL", {
      value: createObjectURL,
      configurable: true,
    });
    Object.defineProperty(globalThis.URL, "revokeObjectURL", {
      value: revokeObjectURL,
      configurable: true,
    });
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, "click");

    renderWithProviders(<InitiativePlanView initiativeId="init-XYZ" />);
    const dl = await screen.findByTestId("plan-download");
    fireEvent.click(dl);

    expect(createObjectURL).toHaveBeenCalledTimes(1);
    expect(clickSpy).toHaveBeenCalledTimes(1);
    // The synthesised <a> should carry the right filename. The
    // spy's `instances[0]` is `this` at call time, which is the
    // anchor element — cast through unknown so tsc doesn't
    // complain about void↔HTMLAnchorElement.
    const a = clickSpy.mock.instances[0] as unknown as HTMLAnchorElement;
    expect(a.download).toBe("init-XYZ.plan.toml");
  });

  it("renders an inline 'Initiative not found.' message on 404", async () => {
    vi.spyOn(dashboardApi.initiatives, "plan").mockRejectedValue(
      new ApiError(404, "FAIL_DASHBOARD_NOT_FOUND", "not found: initiative"),
    );
    renderWithProviders(<InitiativePlanView initiativeId="missing" />);
    const node = await screen.findByTestId("plan-not-found");
    expect(node).toHaveTextContent(/not found/i);
    expect(screen.queryByTestId("plan-editor")).toBeNull();
  });

  it("renders an inline 'Plan archived.' message on 410 Gone", async () => {
    vi.spyOn(dashboardApi.initiatives, "plan").mockRejectedValue(
      new ApiError(410, "FAIL_DASHBOARD_GONE", "gone: plan"),
    );
    renderWithProviders(<InitiativePlanView initiativeId="init-old" />);
    const node = await screen.findByTestId("plan-archived");
    expect(node).toHaveTextContent(/archived/i);
    expect(screen.queryByTestId("plan-editor")).toBeNull();
  });
});
