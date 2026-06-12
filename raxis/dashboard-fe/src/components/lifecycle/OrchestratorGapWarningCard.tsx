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
  onDismiss?: () => void;
}

export function OrchestratorGapWarningCard({ a, onDismiss }: Props) {
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
      className="card min-w-0 max-w-full overflow-hidden border-warn/60 bg-warn/10 p-3"
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <span className="badge shrink-0 bg-warn-muted/40 border-warn text-warn">
            Orchestrator gap
          </span>
          <span className="whitespace-nowrap text-[11px] text-warn">
            stalled {waitLabel}
          </span>
        </div>
        {onDismiss && (
          <button
            type="button"
            className="shrink-0 text-[11px] text-ink-muted hover:text-accent"
            onClick={onDismiss}
            aria-label={`Dismiss orchestrator gap for ${a.task_id} on ${a.activation_id}`}
          >
            Dismiss
          </button>
        )}
      </div>

      <div className="mt-2 min-w-0 text-xs leading-relaxed text-ink-muted [overflow-wrap:anywhere]">
        Task{" "}
        <Link
          to={`/tasks/${encodeURIComponent(a.task_id)}`}
          className="break-all text-accent [overflow-wrap:anywhere] hover:underline"
        >
          <Mono className="whitespace-normal break-all [overflow-wrap:anywhere]">
            {a.task_id}
          </Mono>
        </Link>{" "}
        has been waiting on{" "}
        <Mono className="whitespace-normal break-all [overflow-wrap:anywhere]">
          {a.activation_id}
        </Mono>{" "}
        with all predecessors complete.
      </div>

      {a.predecessors_completed_at.length > 0 && (
        <ul className="mt-2 min-w-0 space-y-1 text-[11px] text-ink-subtle">
          {a.predecessors_completed_at.map(([pred]) => (
            <li key={pred} className="min-w-0 [overflow-wrap:anywhere]">
              <Mono className="whitespace-normal break-all [overflow-wrap:anywhere]">
                {pred}
              </Mono>{" "}
              completed
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
