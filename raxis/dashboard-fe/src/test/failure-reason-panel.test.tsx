import { describe, expect, it } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";

import {
  FailurePill,
  FailureReasonPanel,
} from "@/components/FailureReasonPanel";
import type { FailureInfo } from "@/types/api";

const FULL_REASON: FailureInfo = {
  kind: "WorktreeProvisionFailed",
  message: "ENOSPC: no space left on device",
  fields: [
    { label: "exit_code", value: "28" },
    { label: "worktree_path", value: "/var/lib/raxis/wts/abc123" },
    {
      label: "stderr_excerpt",
      value: "fatal: cannot create directory: No space left on device",
    },
  ],
  artifacts: [
    { label: "Kernel stderr log", href: "/var/log/raxis/kernel.stderr.log" },
    { label: "Audit row 12345", href: "/audit/12345" },
    { label: "Worktree home", href: "https://example.com/wts/abc123" },
  ],
  actions: [
    { label: "Open task", kind: "route", target: "/tasks/task-abc" },
    {
      label: "Resume task",
      kind: "command",
      target: "raxis task resume task-abc",
    },
  ],
  event_id: "evt_abc123def456",
  seq: 12345,
  observed_at: 1714500000,
};

describe("<FailureReasonPanel>", () => {
  it("renders the full reason shape", () => {
    render(<FailureReasonPanel reason={FULL_REASON} />);
    // Kind + message are always rendered above the fold.
    expect(screen.getByTestId("failure-kind")).toHaveTextContent(
      "WorktreeProvisionFailed",
    );
    expect(screen.getByTestId("failure-message")).toHaveTextContent(
      "ENOSPC: no space left on device",
    );
    // Every structured field appears as a dt/dd pair.
    const fieldsList = screen.getByTestId("failure-fields");
    expect(fieldsList).toHaveTextContent("exit_code");
    expect(fieldsList).toHaveTextContent("28");
    expect(fieldsList).toHaveTextContent("worktree_path");
    expect(fieldsList).toHaveTextContent("/var/lib/raxis/wts/abc123");
    // Artifacts list every entry; HTTP links open in a new tab,
    // raxis-relative `/audit/…` paths stay in the SPA, kernel
    // log paths render as monospace text (not clickable).
    const artifacts = screen.getByTestId("failure-artifacts");
    const httpsLink = artifacts.querySelector(
      "a[href='https://example.com/wts/abc123']",
    );
    expect(httpsLink).not.toBeNull();
    expect(httpsLink?.getAttribute("target")).toBe("_blank");
    expect(httpsLink?.getAttribute("rel")).toContain("noopener");
    const auditLink = artifacts.querySelector("a[href='/audit/12345']");
    expect(auditLink).not.toBeNull();
    expect(auditLink?.getAttribute("target")).toBeNull();
    expect(artifacts).toHaveTextContent("/var/log/raxis/kernel.stderr.log");
    expect(artifacts.querySelectorAll("a")).toHaveLength(2);
    // Recovery actions are first-class and copyable so the
    // operator can act without spelunking through logs.
    const recovery = screen.getByTestId("failure-recovery-actions");
    expect(recovery).toHaveTextContent("Open task");
    expect(recovery).toHaveTextContent("Resume task");
    expect(recovery).toHaveTextContent("raxis task resume task-abc");
    expect(recovery).toHaveTextContent("Task can be resumed");
    expect(screen.getAllByTestId("failure-recovery-status")[0]).toHaveTextContent(
      "Recoverable",
    );
    expect(
      recovery.querySelector("a[href='/tasks/task-abc']"),
    ).not.toBeNull();
    // Footer surfaces the audit anchors so the operator can deep-link.
    expect(screen.getByText(/audit seq/)).toBeInTheDocument();
    expect(screen.getByText(/event/)).toBeInTheDocument();
  });

  it("renders a calm `(no reason recorded)` card when reason is missing", () => {
    render(<FailureReasonPanel reason={null} />);
    expect(
      screen.getByTestId("failure-no-reason"),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/\(no reason recorded\)/),
    ).toBeInTheDocument();
    expect(screen.queryByText(/KERNEL BUG/)).toBeNull();
    expect(
      screen.queryByText(/INV-FAILURE-REASON-MANDATORY-01/),
    ).toBeNull();
  });

  it("emits absent empty-state when whenMissing=absent", () => {
    const { container } = render(
      <FailureReasonPanel reason={null} whenMissing="absent" />,
    );
    expect(container.firstChild).toBeNull();
  });

  it("emits no-error-reported empty state when whenMissing=no-error-reported", () => {
    render(
      <FailureReasonPanel reason={null} whenMissing="no-error-reported" />,
    );
    expect(screen.getByText(/No error reported/)).toBeInTheDocument();
  });

  it("hides empty optional blocks", () => {
    render(
      <FailureReasonPanel
        reason={{
          kind: "SessionVmExited",
          message: "kernel-mediated terminate",
        }}
      />,
    );
    expect(screen.queryByTestId("failure-fields")).toBeNull();
    expect(screen.queryByTestId("failure-artifacts")).toBeNull();
    expect(screen.queryByTestId("failure-recovery-actions")).toBeNull();
    // No audit anchors → no footer
    expect(screen.queryByText(/audit seq/)).toBeNull();
    expect(screen.queryByText(/observed /)).toBeNull();
  });

  it("labels unrecoverable failures even when there is no command", () => {
    render(
      <FailureReasonPanel
        reason={{
          kind: "ReviewRejectionCeilingExceeded",
          message: "review retry budget exhausted",
          recovery: {
            status: "unrecoverable",
            label: "Review retry budget exhausted",
            detail:
              "This task loop is terminal in place. Start a corrected initiative or amendment.",
          },
        }}
      />,
    );

    const recovery = screen.getByTestId("failure-recovery-actions");
    expect(recovery).toHaveTextContent("Unrecoverable in place");
    expect(recovery).toHaveTextContent("Review retry budget exhausted");
    expect(recovery).toHaveTextContent(
      "No in-place recovery command is available",
    );
  });

  it("prefers parent recovery when an escalation action is present", () => {
    render(
      <FailureReasonPanel
        reason={{
          kind: "TaskFailed",
          message:
            "parent initiative requires recovery: orchestrator no-progress respawn ceiling exceeded",
          recovery: {
            status: "unrecoverable",
            label: "Not recoverable in place",
            detail:
              "This terminal task state is preserved. Use a new run instead.",
          },
          actions: [
            {
              label: "Open recovery escalations",
              kind: "route",
              target: "/escalations",
            },
            {
              label: "Open task",
              kind: "route",
              target: "/tasks/019ebbb5",
            },
          ],
        }}
      />,
    );

    const recovery = screen.getByTestId("failure-recovery-actions");
    expect(screen.getAllByTestId("failure-recovery-status")[0]).toHaveTextContent(
      "Operator action required",
    );
    expect(recovery).toHaveTextContent("Parent initiative recovery available");
    expect(recovery).toHaveTextContent("Open recovery escalations");
    expect(recovery).not.toHaveTextContent("No in-place recovery command");
  });

  it("collapses details when collapsible=true", () => {
    render(<FailureReasonPanel reason={FULL_REASON} collapsible />);
    // Details visible by default.
    expect(screen.getByTestId("failure-fields")).toBeInTheDocument();
    const toggle = screen.getByRole("button", { name: /Hide details/i });
    fireEvent.click(toggle);
    expect(screen.queryByTestId("failure-fields")).toBeNull();
    expect(screen.queryByTestId("failure-artifacts")).toBeNull();
    expect(screen.getByTestId("failure-recovery-actions")).toBeInTheDocument();
    // Headline + message stay rendered.
    expect(screen.getByTestId("failure-kind")).toBeInTheDocument();
    expect(screen.getByTestId("failure-message")).toBeInTheDocument();
    // Re-open.
    fireEvent.click(screen.getByRole("button", { name: /Show details/i }));
    expect(screen.getByTestId("failure-fields")).toBeInTheDocument();
  });

  it("renders the failure kind as the data attribute for E2E selectors", () => {
    const { container } = render(
      <FailureReasonPanel reason={FULL_REASON} />,
    );
    const section = container.querySelector("section");
    expect(section?.getAttribute("data-failure-kind")).toBe(
      "WorktreeProvisionFailed",
    );
  });

  it("falls back to '(no message)' when the kernel sends a blank string", () => {
    render(
      <FailureReasonPanel
        reason={{ kind: "BlankFailure", message: "   " }}
      />,
    );
    expect(screen.getByTestId("failure-message")).toHaveTextContent(
      "(no message)",
    );
  });
});

describe("<FailurePill>", () => {
  it("renders nothing when not failed", () => {
    const { container } = render(
      <FailurePill failed={false} reason={null} />,
    );
    expect(container.firstChild).toBeNull();
  });

  it("renders message inline when present", () => {
    render(<FailurePill failed reason={FULL_REASON} />);
    expect(
      screen.getByText("ENOSPC: no space left on device"),
    ).toBeInTheDocument();
  });

  it("falls back to kind when no message", () => {
    render(
      <FailurePill
        failed
        reason={{ kind: "ReviewerRejected", message: "" }}
      />,
    );
    expect(screen.getByText("ReviewerRejected")).toBeInTheDocument();
  });

  it("falls back to a calm `(no reason recorded)` pill when reason is missing", () => {
    render(<FailurePill failed reason={null} />);
    expect(
      screen.getByText(/\(no reason recorded\)/),
    ).toBeInTheDocument();
    expect(screen.queryByText(/KERNEL BUG/)).toBeNull();
  });
});
