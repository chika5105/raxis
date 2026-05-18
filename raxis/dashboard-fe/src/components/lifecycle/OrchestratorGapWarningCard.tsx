// `<OrchestratorGapWarningCard>` —
// `LifecycleAnnotation::OrchestratorGap`.
//
// Warn-orange card. The operator-visible signal that
// something upstream of admission is wedged: a
// `subtask_activations` row stuck in `PendingActivation`
// past the gap threshold (default 120s) AND every
// predecessor task has reached `Completed`. Powers the
// home-view "Warnings" pane and TaskDetail timeline.

import { Link } from "react-router-dom";

import { Mono } from "@/components/Mono";
import type { LifecycleAnnotation } from "@/types/api";

type OrchestratorGap = Extract<
  LifecycleAnnotation,
  { kind: "orchestrator_gap" }
>;

interface Props {
  a: OrchestratorGap;
}

export function OrchestratorGapWarningCard({ a }: Props) {
  // Threshold the unit choice on the raw seconds so a 45s gap
  // never rounds up to "1min" — the operator needs the precise
  // sub-minute reading to discriminate "just stalled" from
  // "long stalled". For ≥ 60s we floor instead of round so a
  // 4020s gap reads as "67min" exactly (rounding would have
  // shown 67 here anyway; floor keeps the contract stable for
  // edge values like 4050s → still 67min, not 68min).
  const waitLabel =
    a.wait_seconds >= 60
      ? `${Math.floor(a.wait_seconds / 60)}min`
      : `${a.wait_seconds}s`;
  return (
    <div
      data-testid="lifecycle-orchestrator-gap"
      className="card border-warn/60 bg-warn/10 p-3"
    >
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-2 min-w-0">
          <span className="badge bg-warn-muted/40 border-warn text-warn">
            Orchestrator gap
          </span>
          <span className="text-[11px] text-warn">
            stalled {waitLabel}
          </span>
        </div>
      </div>

      <div className="mt-2 text-xs text-ink-muted">
        Task{" "}
        <Link
          to={`/tasks/${encodeURIComponent(a.task_id)}`}
          className="text-accent hover:underline"
        >
          <Mono>{a.task_id}</Mono>
        </Link>{" "}
        has been waiting on{" "}
        <Mono>{a.activation_id}</Mono> with all predecessors complete.
      </div>

      {a.predecessors_completed_at.length > 0 && (
        <ul className="mt-2 space-y-1 text-[11px] text-ink-subtle">
          {a.predecessors_completed_at.map(([pred]) => (
            <li key={pred}>
              <Mono>{pred}</Mono> completed
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
