// Witness coverage for `<SessionRevokedSelfExitCard>`. Pin
// the green-tinted rendering for clean self-exits + the
// console-log path surface so the operator can deep-link.

import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";

import { SessionRevokedSelfExitCard } from "../SessionRevokedSelfExitCard";
import type { LifecycleAnnotation } from "@/types/api";

const SELF_EXIT: Extract<
  LifecycleAnnotation,
  { kind: "session_revoked_self_exit" }
> = {
  kind: "session_revoked_self_exit",
  terminal_tool: "execute",
  exit_code: 0,
  console_log_path: "/var/log/raxis/sessions/abc.log",
  ts_unix: 1714500123,
};

describe("<SessionRevokedSelfExitCard>", () => {
  it("renders the ok-tinted self-exit card", () => {
    render(<SessionRevokedSelfExitCard a={SELF_EXIT} />);
    const card = screen.getByTestId("lifecycle-session-revoked-self-exit");
    expect(card.className).toMatch(/border-ok/);
    expect(card.className).toMatch(/bg-ok/);
  });

  it("surfaces the terminal tool and exit code", () => {
    render(<SessionRevokedSelfExitCard a={SELF_EXIT} />);
    expect(screen.getByText("execute")).toBeInTheDocument();
    expect(screen.getByText("0")).toBeInTheDocument();
  });

  it("surfaces the console log path verbatim", () => {
    render(<SessionRevokedSelfExitCard a={SELF_EXIT} />);
    expect(
      screen.getByText("/var/log/raxis/sessions/abc.log"),
    ).toBeInTheDocument();
  });

  it("falls back to 'kernel marker' when no terminal tool", () => {
    render(
      <SessionRevokedSelfExitCard
        a={{
          ...SELF_EXIT,
          terminal_tool: null,
          console_log_path: null,
          exit_code: null,
        }}
      />,
    );
    expect(screen.getByText("via kernel marker")).toBeInTheDocument();
  });
});
