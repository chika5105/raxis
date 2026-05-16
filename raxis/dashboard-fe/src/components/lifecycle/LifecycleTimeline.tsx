// `<LifecycleTimeline>` — vertical timeline of ordered
// annotations.
//
// The timeline is the visible expression of the per-task /
// per-session causality classifier. Annotations arrive
// sorted by `ts_unix` (or `wait_seconds` for OrchestratorGap
// rows, which carry no `ts_unix`); the timeline preserves
// that ordering so the operator reads top-to-bottom in
// kernel-emit order.
//
// Empty input renders nothing — the timeline is invisible
// when there is no causality signal yet.

import { Empty } from "@/components/Empty";
import type { LifecycleAnnotation as LA } from "@/types/api";

import { LifecycleAnnotation } from "./LifecycleAnnotation";

interface Props {
  annotations: LA[];
  /// When true, render an empty-state card instead of
  /// nothing. Used on TaskDetail / SessionDetail where
  /// we always want the section visible to indicate
  /// "no retries / no revokes / no warnings".
  showEmpty?: boolean;
  heading?: string;
}

export function LifecycleTimeline({
  annotations,
  showEmpty = false,
  heading = "Lifecycle timeline",
}: Props) {
  if (annotations.length === 0) {
    if (!showEmpty) return null;
    return (
      <section data-testid="lifecycle-timeline" className="card p-3">
        <h2 className="text-sm font-semibold text-ink mb-2">{heading}</h2>
        <Empty
          title="No lifecycle events recorded yet."
          hint="Retry, revoke, and orchestrator-gap events appear here as the kernel emits them."
        />
      </section>
    );
  }
  return (
    <section data-testid="lifecycle-timeline" className="space-y-3">
      <h2 className="text-sm font-semibold text-ink">{heading}</h2>
      <ol className="space-y-3">
        {annotations.map((a, i) => (
          <li key={`${a.kind}-${i}`} data-testid="lifecycle-timeline-row">
            <LifecycleAnnotation annotation={a} />
          </li>
        ))}
      </ol>
    </section>
  );
}
