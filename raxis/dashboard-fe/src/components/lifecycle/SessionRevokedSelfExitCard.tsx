// `<SessionRevokedSelfExitCard>` —
// `LifecycleAnnotation::SessionRevokedSelfExit`.
//
// Operator semantics: a session that revoked itself cleanly
// is the GOOD path (the agent completed its work and
// terminated). Render in the `ok`-tinted card so the
// operator's eye treats it as expected.
//
// Populated once Worker 1's C1 marker pattern lands —
// `SessionRevoked.revoked_by` starting with `kernel://`
// classifies as self-exit; everything else is operator-
// revoke.

import { Mono } from "@/components/Mono";
import { fmtAbsolute } from "@/lib/format";
import type { LifecycleAnnotation } from "@/types/api";

type SessionRevokedSelfExit = Extract<
  LifecycleAnnotation,
  { kind: "session_revoked_self_exit" }
>;

interface Props {
  a: SessionRevokedSelfExit;
}

export function SessionRevokedSelfExitCard({ a }: Props) {
  return (
    <div
      data-testid="lifecycle-session-revoked-self-exit"
      className="card border-ok/40 bg-ok/5 p-3"
    >
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-2 min-w-0">
          <span className="badge bg-ok-muted/30 border-ok text-ok">
            Session self-exit
          </span>
          <span className="text-[11px] text-ink-subtle">
            {fmtAbsolute(a.ts_unix)}
          </span>
        </div>
      </div>

      <div className="mt-2 text-xs text-ink-muted">
        {a.terminal_tool ? (
          <>
            via <span className="font-mono">{a.terminal_tool}</span>
          </>
        ) : (
          "via kernel marker"
        )}
        {a.exit_code !== null && a.exit_code !== undefined && (
          <>
            {" · "}exit <Mono>{a.exit_code}</Mono>
          </>
        )}
      </div>

      {a.console_log_path && (
        <div className="mt-1 text-[11px] text-ink-subtle">
          console log:{" "}
          <Mono className="break-all text-ink-muted">
            {a.console_log_path}
          </Mono>
        </div>
      )}
    </div>
  );
}
