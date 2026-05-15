// `<RetryReviewRejectCard>` renders one
// `LifecycleAnnotation::RetryReviewReject` from the kernel-
// side classifier.
//
// Visual contract:
//   * Red-tinted card so the operator's eye is drawn to a
//     reviewer rejection (the historical blind spot —
//     iter62's lint-runner-js retries surfaced as raw audit
//     JSON one-liners with no causal explanation).
//   * Budget counters (`review_reject_count` /
//     `max_review_rejections`, `crash_retry_count` /
//     `max_crash_retries`) so the operator sees how close
//     the task is to an absolute-fail state.
//   * Click-through to the triggering reviewer task so the
//     operator can read the full critique without correlating
//     audit seq numbers by hand.
//
// `INV-DASHBOARD-LIFECYCLE-CAUSALITY-01`.

import { useState } from "react";
import { Link } from "react-router-dom";

import { Mono } from "@/components/Mono";
import { fmtAbsolute, shortSha } from "@/lib/format";
import type { LifecycleAnnotation } from "@/types/api";

type RetryReviewReject = Extract<
  LifecycleAnnotation,
  { kind: "retry_review_reject" }
>;

interface Props {
  a: RetryReviewReject;
}

export function RetryReviewRejectCard({ a }: Props) {
  const [expanded, setExpanded] = useState(false);
  const critique = a.critique ?? "";
  const lines = critique.split("\n");
  const previewLines = lines.slice(0, 3).join("\n");
  const hasMore = lines.length > 3;
  return (
    <div
      data-testid="lifecycle-retry-review-reject"
      className="card border-bad/40 bg-bad/5 p-3"
    >
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-2 min-w-0">
          <span className="badge bg-bad-muted/30 border-bad text-bad">
            Retry {a.retry_number} · review reject
          </span>
          <span className="text-[11px] text-ink-subtle">
            {fmtAbsolute(a.ts_unix)}
          </span>
        </div>
        <div className="flex items-center gap-2 text-[11px] text-ink-subtle">
          <span title="Reviewer-reject budget">
            review {a.review_reject_count}/{a.max_review_rejections}
          </span>
          <span className="text-ink-faint">·</span>
          <span title="Crash-retry budget">
            crash {a.crash_retry_count}/{a.max_crash_retries}
          </span>
        </div>
      </div>

      <div className="mt-2 text-xs text-ink-muted">
        Triggered by reviewer{" "}
        <Link
          to={`/tasks/${encodeURIComponent(a.triggered_by_reviewer_task_id)}`}
          className="text-accent hover:underline"
        >
          <Mono>{a.triggered_by_reviewer_task_id}</Mono>
        </Link>
        {a.verdict ? (
          <>
            {" — verdict "}
            <span className="font-mono text-bad">{a.verdict}</span>
          </>
        ) : null}
      </div>

      {(a.prior_head_sha || a.new_head_sha) && (
        <div className="mt-1 text-[11px] text-ink-subtle">
          <span className="text-ink-faint">prior</span>{" "}
          <Mono>{shortSha(a.prior_head_sha ?? null)}</Mono>{" "}
          <span className="text-ink-faint">→ new</span>{" "}
          <Mono>{shortSha(a.new_head_sha ?? null)}</Mono>
        </div>
      )}

      {critique && (
        <div className="mt-2">
          <pre
            data-testid="lifecycle-retry-review-reject-critique"
            className="text-[12px] whitespace-pre-wrap text-ink leading-relaxed font-sans"
          >
            {expanded ? critique : previewLines}
          </pre>
          {hasMore && (
            <button
              type="button"
              className="mt-1 text-[11px] text-accent hover:underline"
              onClick={() => setExpanded((v) => !v)}
            >
              {expanded ? "Collapse" : "Expand full critique"}
            </button>
          )}
        </div>
      )}

      <div className="mt-2 text-[11px] text-ink-faint">
        <span className="font-mono">{a.prior_activation_id}</span>
        <span className="mx-1">→</span>
        <span className="font-mono">{a.new_activation_id}</span>
      </div>
    </div>
  );
}
