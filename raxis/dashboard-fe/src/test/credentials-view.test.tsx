/* `<CredentialsView>` — covers the password-reveal state
 * machine required by `INV-DASHBOARD-CREDENTIAL-*`:
 *
 *   1. masked: row renders metadata only; no plaintext in the
 *      DOM, no listing-side request for bytes.
 *   2. role-gated: a non-admin operator sees the Reveal button
 *      enabled with a tooltip; clicking it round-trips to the
 *      kernel for an audited denial — silent failure is
 *      forbidden by
 *      `INV-DASHBOARD-CREDENTIAL-REVEAL-PLAINTEXT-WORKS-OR-EXPLAINS-01`.
 *   3. confirming: clicking Reveal as an admin pops a modal
 *      naming the credential + the audit class. Anthropic
 *      credentials get Critical-tier copy; system credentials
 *      get High-tier copy; per-initiative credentials get the
 *      default copy.
 *   4. revealing → revealed: confirming the modal POSTs the
 *      reveal endpoint and inserts the plaintext into a
 *      Monaco viewer (mocked to a `<textarea>`).
 *   5. auto-hidden: when wall-clock crosses
 *      `expires_at_unix`, the row re-masks (no operator
 *      action required).
 *   6. hide-now: clicking "Hide now" re-masks immediately.
 *   7. error: the reveal POST 4xx is surfaced inline; the
 *      row goes back to masked on dismiss.
 *
 * Monaco is mocked to a `<textarea>` so jsdom can mount the
 * tree without choking on the bundled CSS / web workers.
 */

import React from "react";
import {
  describe,
  expect,
  it,
  vi,
  beforeEach,
  afterEach,
} from "vitest";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

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
          /* mock is read-only */
        }}
      />
    );
  },
}));

import { ApiError, dashboardApi } from "@/api/client";
import { CredentialsView } from "@/components/CredentialsView";
import { ThemeProvider } from "@/lib/theme";
import type {
  CredentialListResponse,
  CredentialMetadata,
  CredentialReveal,
} from "@/types/api";

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
      <ThemeProvider>{ui}</ThemeProvider>
    </QueryClientProvider>,
  );
}

function meta(over: Partial<CredentialMetadata> = {}): CredentialMetadata {
  return {
    name:                 "test-pg-dev",
    proxy_type:           "postgres",
    mount_as:             "DATABASE_URL",
    format_hint:          "libpq URL (postgresql://user:pass@host:port/db)",
    upstream_host_port:   "127.0.0.1:5432",
    byte_size:            64,
    sha256_prefix:        "deadbeef",
    loaded_from_path:     "/var/raxis/credentials/test-pg-dev.env",
    is_revealable:        true,
    reveal_required_role: "admin",
    ...over,
  };
}

function listOf(...rows: CredentialMetadata[]): CredentialListResponse {
  return { credentials: rows };
}

beforeEach(() => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe("<CredentialsView> — masked baseline", () => {
  it("renders one row per credential with metadata only and never POSTs the reveal endpoint", async () => {
    const listSpy = vi
      .spyOn(dashboardApi.initiatives, "credentials")
      .mockResolvedValue(
        listOf(meta(), meta({ name: "test-redis", proxy_type: "redis" })),
      );
    const revealSpy = vi.spyOn(
      dashboardApi.initiatives,
      "revealCredential",
    );

    renderWithProviders(
      <CredentialsView
        scope={{ kind: "initiative", initiativeId: "init-1" }}
        operatorRoles={["admin"]}
      />,
    );

    expect(await screen.findByTestId("credentials-list")).toBeInTheDocument();
    expect(screen.getByTestId("credential-row-test-pg-dev")).toHaveAttribute(
      "data-state",
      "masked",
    );
    expect(screen.getByTestId("credential-row-test-redis")).toHaveAttribute(
      "data-state",
      "masked",
    );
    // No plaintext in the DOM yet.
    expect(screen.queryByTestId("monaco-mock")).toBeNull();
    expect(screen.queryByTestId("credential-revealed-banner")).toBeNull();
    // The listing call fired exactly once; no reveal POST.
    expect(listSpy).toHaveBeenCalledTimes(1);
    expect(revealSpy).not.toHaveBeenCalled();
  });

  it("renders the empty-state when the kernel returns zero credentials", async () => {
    vi.spyOn(dashboardApi.initiatives, "credentials").mockResolvedValue(
      listOf(),
    );
    renderWithProviders(
      <CredentialsView
        scope={{ kind: "initiative", initiativeId: "init-empty" }}
        operatorRoles={["admin"]}
      />,
    );
    expect(await screen.findByTestId("credentials-empty")).toHaveTextContent(
      /declares no credentials/i,
    );
  });

  it("renders the structured 403 panel when the kernel rejects a non-admin lister", async () => {
    vi.spyOn(dashboardApi.systemCredentials, "list").mockRejectedValue(
      new ApiError(403, "FAIL_DASHBOARD_FORBIDDEN", "admin role required"),
    );
    renderWithProviders(
      <CredentialsView scope={{ kind: "system" }} operatorRoles={["read"]} />,
    );
    expect(
      await screen.findByTestId("credentials-forbidden"),
    ).toHaveTextContent(/permission denied/i);
  });

  it("renders the system-credential listing as a read operator (Anthropic visible)", async () => {
    // INV-DASHBOARD-CREDENTIAL-VIEWER-LISTS-ALL-OPERATOR-VISIBLE-SECRETS-01:
    // a read operator can list every system credential the
    // kernel uses (planner LLM keys, gateway upstreams, …).
    // Plaintext stays masked; reveal stays admin-only.
    vi.spyOn(dashboardApi.systemCredentials, "list").mockResolvedValue(
      listOf(
        meta({
          name: "providers.anthropic-prod",
          proxy_type: "provider",
          mount_as: null,
          format_hint: "Anthropic provider TOML (api_key = \"…\")",
          upstream_host_port: null,
        }),
      ),
    );
    renderWithProviders(
      <CredentialsView scope={{ kind: "system" }} operatorRoles={["read"]} />,
    );
    const row = await screen.findByTestId(
      "credential-row-providers.anthropic-prod",
    );
    expect(row).toBeInTheDocument();
    expect(row).toHaveAttribute("data-anthropic", "true");
    // Header pill calls out the limited role.
    expect(screen.getByTestId("credentials-role-warning")).toHaveTextContent(
      /read-only/i,
    );
  });
});

describe("<CredentialsView> — role gate", () => {
  it("round-trips the reveal click as a read operator and renders the kernel-audited 403 inline", async () => {
    // INV-DASHBOARD-CREDENTIAL-REVEAL-PLAINTEXT-WORKS-OR-EXPLAINS-01:
    // silent failure (button does nothing, no UI feedback, no
    // audit row) is forbidden. A read operator's click MUST
    // round-trip so the kernel can emit a paired
    // `RejectedPermission` audit row, and the FE MUST render
    // the structured 403 inline.
    vi.spyOn(dashboardApi.initiatives, "credentials").mockResolvedValue(
      listOf(meta()),
    );
    const revealSpy = vi
      .spyOn(dashboardApi.initiatives, "revealCredential")
      .mockRejectedValue(
        new ApiError(
          403,
          "FAIL_DASHBOARD_FORBIDDEN",
          'this action requires the "admin" role',
        ),
      );

    renderWithProviders(
      <CredentialsView
        scope={{ kind: "initiative", initiativeId: "init-1" }}
        operatorRoles={["read"]}
      />,
    );

    expect(
      await screen.findByTestId("credentials-role-warning"),
    ).toHaveTextContent(/read-only/i);
    const btn = screen.getByTestId("credential-reveal-test-pg-dev");
    // Button is NOT HTML-disabled — clicks must reach the
    // handler so the kernel can audit the denial.
    expect(btn).not.toBeDisabled();
    expect(btn).toHaveAttribute("data-reveal-eligible", "false");

    fireEvent.click(btn);

    // No modal — the modal exists to gate the plaintext, not
    // the denial. We round-trip directly.
    expect(screen.queryByTestId("credential-confirm-modal")).toBeNull();
    await waitFor(() => {
      expect(revealSpy).toHaveBeenCalledWith("init-1", "test-pg-dev");
    });
    const err = await screen.findByTestId("credential-reveal-error");
    expect(err).toHaveTextContent(/admin/i);
    expect(screen.queryByTestId("credential-revealed-banner")).toBeNull();
    // Plaintext never made it to the DOM.
    expect(screen.queryByTestId("monaco-mock")).toBeNull();
  });

  it("surfaces the local explanation when the credential itself is non-revealable (admin role + is_revealable=false)", async () => {
    vi.spyOn(dashboardApi.initiatives, "credentials").mockResolvedValue(
      listOf(meta({ is_revealable: false })),
    );
    const revealSpy = vi.spyOn(
      dashboardApi.initiatives,
      "revealCredential",
    );

    renderWithProviders(
      <CredentialsView
        scope={{ kind: "initiative", initiativeId: "init-1" }}
        operatorRoles={["admin"]}
      />,
    );
    const btn = await screen.findByTestId("credential-reveal-test-pg-dev");
    expect(btn).toHaveAttribute("data-reveal-eligible", "false");
    fireEvent.click(btn);

    // No POST — the kernel has already told us this credential
    // is non-revealable; the FE explains locally instead of
    // generating a 4xx with no recourse.
    expect(revealSpy).not.toHaveBeenCalled();
    const err = await screen.findByTestId("credential-reveal-error");
    expect(err).toHaveTextContent(/is_revealable=false/);
  });
});

describe("<CredentialsView> — reveal flow", () => {
  it("pops a confirmation modal on Reveal click and POSTs only after the operator confirms", async () => {
    vi.spyOn(dashboardApi.initiatives, "credentials").mockResolvedValue(
      listOf(meta()),
    );
    const revealSpy = vi
      .spyOn(dashboardApi.initiatives, "revealCredential")
      .mockResolvedValue({
        name: "test-pg-dev",
        plaintext: "postgres://user:secret@db:5432/app",
        encoding: "utf8",
        byte_size: 64,
        expires_at_unix: Math.floor(Date.now() / 1000) + 30,
        sha256_prefix: "deadbeef",
      } satisfies CredentialReveal);

    renderWithProviders(
      <CredentialsView
        scope={{ kind: "initiative", initiativeId: "init-1" }}
        operatorRoles={["admin"]}
      />,
    );

    const btn = await screen.findByTestId("credential-reveal-test-pg-dev");
    fireEvent.click(btn);

    // Modal appears; the reveal POST has NOT fired yet.
    expect(screen.getByTestId("credential-confirm-modal")).toHaveTextContent(
      /reveal credential/i,
    );
    expect(revealSpy).not.toHaveBeenCalled();

    fireEvent.click(screen.getByTestId("credential-confirm-yes"));

    await waitFor(() => {
      expect(revealSpy).toHaveBeenCalledWith("init-1", "test-pg-dev");
    });
    const banner = await screen.findByTestId("credential-revealed-banner");
    expect(banner).toHaveTextContent(/plaintext visible/i);
    expect(banner).toHaveTextContent(/sha256=deadbeef/);
    // Plaintext is in the DOM (Monaco mock + sr-only sibling).
    expect(screen.getByTestId("monaco-mock")).toHaveValue(
      "postgres://user:secret@db:5432/app",
    );
  });

  it("renders the Critical-severity Anthropic warning copy", async () => {
    vi.spyOn(dashboardApi.systemCredentials, "list").mockResolvedValue(
      listOf(
        meta({
          name: "providers.anthropic",
          proxy_type: "provider",
          mount_as: null,
          format_hint: "Anthropic provider TOML (api_key = \"…\")",
          upstream_host_port: null,
        }),
      ),
    );

    renderWithProviders(
      <CredentialsView scope={{ kind: "system" }} operatorRoles={["admin"]} />,
    );

    fireEvent.click(
      await screen.findByTestId("credential-reveal-providers.anthropic"),
    );
    const modal = screen.getByTestId("credential-confirm-modal");
    expect(modal).toHaveTextContent(/critical/i);
    expect(modal).toHaveTextContent(/anthropic/i);
    expect(screen.getByTestId("credential-confirm-yes")).toHaveTextContent(
      /reveal anthropic key/i,
    );
    // Row carries the data-anthropic flag for spec-conformance
    // selectors (e.g. e2e harness assertions).
    expect(
      screen.getByTestId("credential-row-providers.anthropic"),
    ).toHaveAttribute("data-anthropic", "true");
  });

  it("re-masks automatically when wall-clock crosses expires_at_unix", async () => {
    const start = 1_700_000_000;
    vi.setSystemTime(start * 1000);
    vi.spyOn(dashboardApi.initiatives, "credentials").mockResolvedValue(
      listOf(meta()),
    );
    vi.spyOn(dashboardApi.initiatives, "revealCredential").mockResolvedValue({
      name: "test-pg-dev",
      plaintext: "postgres://user:s@db/app",
      encoding: "utf8",
      byte_size: 24,
      expires_at_unix: start + 5, // 5-second test window
      sha256_prefix: "deadbeef",
    });

    renderWithProviders(
      <CredentialsView
        scope={{ kind: "initiative", initiativeId: "init-1" }}
        operatorRoles={["admin"]}
      />,
    );
    fireEvent.click(
      await screen.findByTestId("credential-reveal-test-pg-dev"),
    );
    fireEvent.click(screen.getByTestId("credential-confirm-yes"));
    expect(
      await screen.findByTestId("credential-revealed-banner"),
    ).toBeInTheDocument();

    // Walk the wall clock past the deadline and let timers fire.
    // We wrap in act() so the useCountdown / setTimeout-driven
    // re-mask state transitions are flushed under React's batch.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(6_000);
    });

    await waitFor(() => {
      expect(screen.queryByTestId("credential-revealed-banner")).toBeNull();
    });
    expect(screen.getByTestId("credential-row-test-pg-dev")).toHaveAttribute(
      "data-state",
      "masked",
    );
  });

  it("re-masks immediately when the operator clicks Hide now", async () => {
    const start = 1_700_000_000;
    vi.setSystemTime(start * 1000);
    vi.spyOn(dashboardApi.initiatives, "credentials").mockResolvedValue(
      listOf(meta()),
    );
    vi.spyOn(dashboardApi.initiatives, "revealCredential").mockResolvedValue({
      name: "test-pg-dev",
      plaintext: "postgres://user:s@db/app",
      encoding: "utf8",
      byte_size: 24,
      expires_at_unix: start + 30,
      sha256_prefix: "deadbeef",
    });

    renderWithProviders(
      <CredentialsView
        scope={{ kind: "initiative", initiativeId: "init-1" }}
        operatorRoles={["admin"]}
      />,
    );
    fireEvent.click(
      await screen.findByTestId("credential-reveal-test-pg-dev"),
    );
    fireEvent.click(screen.getByTestId("credential-confirm-yes"));
    await screen.findByTestId("credential-revealed-banner");

    fireEvent.click(screen.getAllByTestId("credential-hide-now")[0]);

    await waitFor(() => {
      expect(screen.queryByTestId("credential-revealed-banner")).toBeNull();
    });
  });

  it("surfaces an inline error when the reveal POST returns 429 and lets the operator dismiss it", async () => {
    vi.spyOn(dashboardApi.initiatives, "credentials").mockResolvedValue(
      listOf(meta()),
    );
    vi.spyOn(dashboardApi.initiatives, "revealCredential").mockRejectedValue(
      new ApiError(
        429,
        "FAIL_DASHBOARD_RATE_LIMITED",
        "rate limit: try again in 30s",
      ),
    );

    renderWithProviders(
      <CredentialsView
        scope={{ kind: "initiative", initiativeId: "init-1" }}
        operatorRoles={["admin"]}
      />,
    );
    fireEvent.click(
      await screen.findByTestId("credential-reveal-test-pg-dev"),
    );
    fireEvent.click(screen.getByTestId("credential-confirm-yes"));

    const err = await screen.findByTestId("credential-reveal-error");
    expect(err).toHaveTextContent(/rate limit/i);
    expect(screen.queryByTestId("credential-revealed-banner")).toBeNull();
    fireEvent.click(screen.getByText("Dismiss"));
    await waitFor(() => {
      expect(screen.queryByTestId("credential-reveal-error")).toBeNull();
    });
  });

  it("keeps the modal in the DOM and avoids POSTing when the operator cancels", async () => {
    vi.spyOn(dashboardApi.initiatives, "credentials").mockResolvedValue(
      listOf(meta()),
    );
    const revealSpy = vi.spyOn(
      dashboardApi.initiatives,
      "revealCredential",
    );

    renderWithProviders(
      <CredentialsView
        scope={{ kind: "initiative", initiativeId: "init-1" }}
        operatorRoles={["admin"]}
      />,
    );
    fireEvent.click(
      await screen.findByTestId("credential-reveal-test-pg-dev"),
    );
    expect(screen.getByTestId("credential-confirm-modal")).toBeInTheDocument();
    fireEvent.click(screen.getByTestId("credential-confirm-cancel"));
    await waitFor(() => {
      expect(screen.queryByTestId("credential-confirm-modal")).toBeNull();
    });
    expect(revealSpy).not.toHaveBeenCalled();
  });
});
