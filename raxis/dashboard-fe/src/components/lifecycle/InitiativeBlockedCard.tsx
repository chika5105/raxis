// `<InitiativeBlockedCard>` —
// `LifecycleAnnotation::InitiativeBlocked`. Bad-tinted
// card; clicking the optional blocking task id deep-links
// to the per-task surface so the operator can debug.

import { Link } from "react-router-dom";

import { Mono } from "@/components/Mono";
import { fmtAbsolute } from "@/lib/format";
import type { LifecycleAnnotation } from "@/types/api";

type InitiativeBlocked = Extract<
  LifecycleAnnotation,
  { kind: "initiative_blocked" }
>;

interface Props {
  a: InitiativeBlocked;
}

export function InitiativeBlockedCard({ a }: Props) {
  return (
    <div
      data-testid="lifecycle-initiative-blocked"
      className="card border-bad/40 bg-bad/5 p-3"
    >
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-2 min-w-0">
          <span className="badge bg-bad-muted/30 border-bad text-bad">
            Initiative blocked
          </span>
          <span className="text-[11px] text-ink-subtle">
            {fmtAbsolute(a.ts_unix)}
          </span>
        </div>
      </div>

      <div className="mt-2 text-xs text-ink-muted">{a.block_reason}</div>

      {a.blocking_task_id && (
        <div className="mt-1 text-[11px]">
          <span className="text-ink-faint">blocking task: </span>
          <Link
            to={`/tasks/${encodeURIComponent(a.blocking_task_id)}`}
            className="text-accent hover:underline"
          >
            <Mono>{a.blocking_task_id}</Mono>
          </Link>
        </div>
      )}
    </div>
  );
}
