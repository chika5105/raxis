import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";

import { DiagnosticFindingsPanel } from "@/components/DiagnosticFindingsPanel";
import type { DiagnosticFinding } from "@/types/api";

describe("DiagnosticFindingsPanel", () => {
  it("renders root-cause summary, evidence, route actions, and command actions", () => {
    const findings: DiagnosticFinding[] = [
      {
        finding_id: "log:gateway-supervisor-no-config",
        severity: "critical",
        status: "active",
        scope: "model_gateway",
        title: "No model providers are configured",
        summary:
          "The gateway supervisor did not start because the active policy has no model provider configuration.",
        initiative_id: "init-123",
        observed_at: 1_700_000_000,
        evidence: [
          {
            label: "Kernel log",
            value: "/opt/homebrew/var/log/raxis/kernel.err.log",
            href: "/opt/homebrew/var/log/raxis/kernel.err.log",
          },
          { label: "Valid values", value: "block_merge, warn_only" },
        ],
        actions: [
          { label: "Open Policy Builder", kind: "route", target: "/policy-builder" },
          {
            label: "Restart Homebrew service",
            kind: "command",
            target: "brew services restart raxis",
          },
        ],
      },
    ];

    render(
      <MemoryRouter>
        <DiagnosticFindingsPanel findings={findings} />
      </MemoryRouter>,
    );

    expect(screen.getByText("No model providers are configured")).toBeInTheDocument();
    expect(screen.getByText("critical")).toBeInTheDocument();
    expect(screen.getByText("model_gateway")).toBeInTheDocument();
    expect(screen.getByText("init-123")).toBeInTheDocument();
    expect(screen.getByText("/opt/homebrew/var/log/raxis/kernel.err.log")).toBeInTheDocument();
    expect(screen.getByText("block_merge, warn_only")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open Policy Builder" })).toHaveAttribute(
      "href",
      "/policy-builder",
    );
    expect(screen.getByText("brew services restart raxis")).toBeInTheDocument();
  });

  it("renders a calm empty state when there are no active diagnostics", () => {
    render(
      <MemoryRouter>
        <DiagnosticFindingsPanel findings={[]} />
      </MemoryRouter>,
    );

    expect(screen.getByText("No active diagnostics.")).toBeInTheDocument();
  });
});
