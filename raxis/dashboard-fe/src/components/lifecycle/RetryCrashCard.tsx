// `<RetryCrashCard>` — `LifecycleAnnotation::RetryCrash`.
//
// Worker premature-exit retries; warn-orange tint so they
// stand out from the red review-reject card. `max_turns`
// scaling note surfaced inline when the kernel decided to
// extend the budget on respawn.

import { Mono } from "@/components/Mono";
import { fmtAbsolute } from "@/lib/format";
import type { LifecycleAnnotation } from "@/types/api";

type RetryCrash = Extract<LifecycleAnnotation, { kind: "retry_crash" }>;

interface Props {
  a: RetryCrash;
}

export function RetryCrashCard({ a }: Props) {
  const turnsScaled =
    a.max_turns_scaled_from !== null &&
    a.max_turns_scaled_from !== undefined &&
    a.max_turns_scaled_to !== null &&
    a.max_turns_scaled_to !== undefined &&
    a.max_turns_scaled_from !== a.max_turns_scaled_to;
  return (
    <div
      data-testid="lifecycle-retry-crash"
      className="card border-warn/40 bg-warn/5 p-3"
    >
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-2 min-w-0">
          <span className="badge bg-warn-muted/30 border-warn text-warn">
            Retry {a.retry_number} · worker crash
          </span>
          <span className="text-[11px] text-ink-subtle">
            {fmtAbsolute(a.ts_unix)}
          </span>
        </div>
        <span className="text-[11px] text-ink-subtle" title="Crash-retry budget">
          crash {a.crash_retry_count}/{a.max_crash_retries}
        </span>
      </div>

      <div className="mt-2 text-xs text-ink-muted">
        {a.exit_code !== null && a.exit_code !== undefined && (
          <span>
            exit code <Mono>{a.exit_code}</Mono>
          </span>
        )}
        {a.terminal_tool ? (
          <>
            {a.exit_code !== null && a.exit_code !== undefined && " · "}
            terminal tool <span className="font-mono">{a.terminal_tool}</span>
          </>
        ) : null}
      </div>

      {turnsScaled && (
        <div className="mt-1 text-[11px] text-ink-subtle">
          <span className="text-ink-faint">max_turns</span>{" "}
          <Mono>{a.max_turns_scaled_from}</Mono>
          <span className="mx-1">→</span>
          <Mono>{a.max_turns_scaled_to}</Mono>
        </div>
      )}
    </div>
  );
}
