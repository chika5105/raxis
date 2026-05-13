/* Witness for `INV-DASHBOARD-KERNEL-LIFECYCLE-01`
 * (`raxis/specs/v2/self-healing-supervisor.md §5.4`).
 *
 * Drives the pure presentation `<KernelLifecycleBannerView>`
 * directly with hand-built `KernelLifecycleResponse` fixtures
 * — no React Query, no `vi.spyOn` on `dashboardApi`. We also
 * cover the `bannerTone` / `headlineFor` decision functions in
 * isolation so a refactor of the JSX cannot quietly break the
 * "no banner when supervisor is absent" hide rule.
 *
 * The hide rule (Healthy + supervisor_pid === 0 ⇒ render
 * nothing) is the linchpin of the live-e2e contract — operators
 * who never opt into `RAXIS_SUPERVISOR_AUTO_RESTART=1` MUST see
 * zero supervisor chrome on every dashboard pane. */

import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";

import {
  KernelLifecycleBannerView,
  bannerTone,
  headlineFor,
} from "@/components/KernelLifecycleBanner";
import type { KernelLifecycleResponse } from "@/types/api";

function snap(
  overrides: Partial<KernelLifecycleResponse>,
): KernelLifecycleResponse {
  return {
    status: "Healthy",
    sub_state: null,
    attempt_n: 0,
    max_attempts: 0,
    last_restart_reason: null,
    last_restart_unix_ts: 0,
    attempts_in_window: 0,
    window_secs: 60,
    supervisor_pid: 0,
    kernel_pid: 0,
    updated_at_unix_secs: 0,
    fresh: true,
    ...overrides,
  };
}

describe("bannerTone (INV-DASHBOARD-KERNEL-LIFECYCLE-01)", () => {
  it("hides the banner when no supervisor is in play", () => {
    expect(bannerTone(snap({ status: "Healthy", supervisor_pid: 0 }))).toBe(
      "hidden",
    );
  });

  it("hides the banner when supervisor reports Healthy", () => {
    expect(
      bannerTone(snap({ status: "Healthy", supervisor_pid: 12345 })),
    ).toBe("hidden");
  });

  it("paints amber/warn while restarting", () => {
    expect(
      bannerTone(
        snap({
          status: "Restarting",
          attempt_n: 1,
          max_attempts: 3,
          supervisor_pid: 12345,
        }),
      ),
    ).toBe("warn");
  });

  it("paints rose/stop on every Halted sub_state", () => {
    for (const sub of [
      "CircuitOpen",
      "OperatorStop",
      "OperatorStopForced",
      "SupervisorGone",
    ] as const) {
      expect(
        bannerTone(
          snap({
            status: "Halted",
            sub_state: sub,
            supervisor_pid: 12345,
          }),
        ),
      ).toBe("stop");
    }
  });

  it("falls back to warn for an unknown future status", () => {
    expect(
      bannerTone(
        snap({
          status: "QuiescedForUpgrade",
          supervisor_pid: 12345,
        }),
      ),
    ).toBe("warn");
  });
});

describe("headlineFor (spec wording)", () => {
  it("matches every documented Halted sub_state", () => {
    expect(headlineFor(snap({ status: "Halted", sub_state: "CircuitOpen" })))
      .toBe("Kernel halted — restart circuit OPEN");
    expect(
      headlineFor(snap({ status: "Halted", sub_state: "OperatorStop" })),
    ).toBe("Kernel stopped by operator");
    expect(
      headlineFor(snap({ status: "Halted", sub_state: "OperatorStopForced" })),
    ).toBe("Kernel force-killed by operator (grace exceeded)");
    expect(
      headlineFor(snap({ status: "Halted", sub_state: "SupervisorGone" })),
    ).toBe("Supervisor process gone");
    expect(headlineFor(snap({ status: "Halted", sub_state: null })))
      .toBe("Kernel halted");
  });

  it("uses 'Kernel restarting' for Restarting", () => {
    expect(headlineFor(snap({ status: "Restarting" }))).toBe(
      "Kernel restarting",
    );
  });
});

describe("<KernelLifecycleBannerView>", () => {
  it("renders nothing when the supervisor is absent (no chrome leak)", () => {
    const { container } = render(
      <KernelLifecycleBannerView snapshot={snap({})} />,
    );
    expect(container).toBeEmptyDOMElement();
    expect(
      screen.queryByTestId("kernel-lifecycle-banner"),
    ).not.toBeInTheDocument();
  });

  it("renders nothing when the supervisor is present and Healthy", () => {
    const { container } = render(
      <KernelLifecycleBannerView
        snapshot={snap({ status: "Healthy", supervisor_pid: 12345 })}
      />,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it("renders the restarting banner with attempt N/M + reason", () => {
    render(
      <KernelLifecycleBannerView
        snapshot={snap({
          status: "Restarting",
          attempt_n: 2,
          max_attempts: 3,
          last_restart_reason: "DeadlockDetected",
          supervisor_pid: 12345,
          kernel_pid: 99999,
          updated_at_unix_secs: 1_700_000_000,
        })}
      />,
    );
    const banner = screen.getByTestId("kernel-lifecycle-banner");
    expect(banner).toHaveAttribute("data-kernel-status", "Restarting");
    expect(banner).toHaveTextContent("Kernel restarting");
    expect(banner).toHaveTextContent("DeadlockDetected");
    expect(banner).toHaveTextContent("2/3");
  });

  it("renders the halted/circuit-open banner with attempts + window", () => {
    render(
      <KernelLifecycleBannerView
        snapshot={snap({
          status: "Halted",
          sub_state: "CircuitOpen",
          attempt_n: 4,
          max_attempts: 3,
          attempts_in_window: 4,
          window_secs: 60,
          last_restart_reason: "DeadlockDetected",
          supervisor_pid: 12345,
        })}
      />,
    );
    const banner = screen.getByTestId("kernel-lifecycle-banner");
    expect(banner).toHaveAttribute("data-kernel-status", "Halted");
    expect(banner).toHaveAttribute("data-kernel-substate", "CircuitOpen");
    expect(banner).toHaveTextContent("restart circuit OPEN");
    expect(banner).toHaveTextContent("4 attempts in last 60s window");
  });

  it("renders the operator-stop banner without a reason", () => {
    render(
      <KernelLifecycleBannerView
        snapshot={snap({
          status: "Halted",
          sub_state: "OperatorStop",
          supervisor_pid: 12345,
        })}
      />,
    );
    const banner = screen.getByTestId("kernel-lifecycle-banner");
    expect(banner).toHaveTextContent("Kernel stopped by operator");
  });

  it("renders the operator-stop-forced banner (SIGKILL escalation)", () => {
    render(
      <KernelLifecycleBannerView
        snapshot={snap({
          status: "Halted",
          sub_state: "OperatorStopForced",
          supervisor_pid: 12345,
        })}
      />,
    );
    const banner = screen.getByTestId("kernel-lifecycle-banner");
    expect(banner).toHaveTextContent(
      "Kernel force-killed by operator (grace exceeded)",
    );
  });

  it("appends the stale-data note when fresh=false", () => {
    render(
      <KernelLifecycleBannerView
        snapshot={snap({
          status: "Halted",
          sub_state: "SupervisorGone",
          supervisor_pid: 12345,
          fresh: false,
        })}
      />,
    );
    expect(screen.getByTestId("kernel-lifecycle-stale")).toHaveTextContent(
      "stale (supervisor has not written recently)",
    );
  });

  it("does not render the stale note when fresh=true", () => {
    render(
      <KernelLifecycleBannerView
        snapshot={snap({
          status: "Restarting",
          attempt_n: 1,
          max_attempts: 3,
          supervisor_pid: 12345,
          fresh: true,
        })}
      />,
    );
    expect(
      screen.queryByTestId("kernel-lifecycle-stale"),
    ).not.toBeInTheDocument();
  });
});
