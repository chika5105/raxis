// `<RetryValidationRejectCard>` —
// `LifecycleAnnotation::RetryValidationReject`. Surfaces the
// validator reason and structured detail. Wired but
// dormant on the backend until Worker 1's C7 lands.

import { useState } from "react";

import { fmtAbsolute } from "@/lib/format";
import type { LifecycleAnnotation } from "@/types/api";

type RetryValidationReject = Extract<
  LifecycleAnnotation,
  { kind: "retry_validation_reject" }
>;

interface Props {
  a: RetryValidationReject;
}

export function RetryValidationRejectCard({ a }: Props) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div
      data-testid="lifecycle-retry-validation-reject"
      className="card border-bad/40 bg-bad/5 p-3"
    >
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-2 min-w-0">
          <span className="badge bg-bad-muted/30 border-bad text-bad">
            Retry {a.retry_number} · validation reject
          </span>
          <span className="text-[11px] text-ink-subtle">
            {fmtAbsolute(a.ts_unix)}
          </span>
        </div>
        <span className="text-[11px] text-ink-subtle">
          validator {a.validation_reject_count}/{a.max_validation_rejections}
        </span>
      </div>

      <div className="mt-2 text-xs text-ink-muted">
        Reason: <span className="font-mono">{a.validator_reason}</span>
      </div>

      {a.validator_detail !== null && a.validator_detail !== undefined && (
        <div className="mt-2">
          <button
            type="button"
            className="text-[11px] text-accent hover:underline"
            onClick={() => setExpanded((v) => !v)}
          >
            {expanded ? "Collapse" : "Expand validator detail"}
          </button>
          {expanded && (
            <pre className="mt-1 overflow-x-auto text-[11px] text-ink-muted whitespace-pre-wrap">
              {JSON.stringify(a.validator_detail, null, 2)}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}
