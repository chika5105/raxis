// `<ReviewerVerdictPanel>` — top-of-page panel surfacing
// the executor task's reviewer aggregate verdict.
//
// Renders:
//   * a colour-coded verdict badge
//     (Approved=green, Rejected=red, anything else=neutral),
//   * the aggregated `last_critique` blob as a
//     collapsible markdown-ish block (first 3 lines visible
//     by default + Expand button),
//   * one row per reviewer, parsed from the audit chain's
//     `SubmitReview` / `ReviewAggregationCompleted` events
//     by the backend classifier — verdict, critique
//     excerpt, completed-at timestamp, link to the per-
//     reviewer task page.
//
// `INV-DASHBOARD-LIFECYCLE-CAUSALITY-01`.

import { useState } from "react";
import { Link } from "react-router-dom";

import { Empty } from "@/components/Empty";
import { Mono } from "@/components/Mono";
import { fmtAbsolute } from "@/lib/format";
import type { ReviewerPanelEntry } from "@/types/api";

interface Props {
  verdict: string | null | undefined;
  critique: string | null | undefined;
  entries: ReviewerPanelEntry[];
}

export function ReviewerVerdictPanel({ verdict, critique, entries }: Props) {
  const [expanded, setExpanded] = useState(false);
  const verdictBadge = verdictBadgeClasses(verdict ?? null);
  const critiqueText = critique ?? "";
  const lines = critiqueText.split("\n");
  const previewLines = lines.slice(0, 3).join("\n");
  const hasMore = lines.length > 3;

  return (
    <section
      data-testid="reviewer-verdict-panel"
      className="card p-4 space-y-3"
    >
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <h2 className="text-sm font-semibold text-ink">Reviewer verdict</h2>
        <span
          data-testid="reviewer-verdict-panel-badge"
          className={`badge ${verdictBadge}`}
        >
          {verdict ?? "Pending"}
        </span>
      </div>

      {critiqueText ? (
        <div>
          <pre
            data-testid="reviewer-verdict-panel-critique"
            className="text-[12px] whitespace-pre-wrap text-ink leading-relaxed font-sans"
          >
            {expanded ? critiqueText : previewLines}
          </pre>
          {hasMore && (
            <button
              type="button"
              className="mt-1 text-[11px] text-accent hover:underline"
              onClick={() => setExpanded((v) => !v)}
            >
              {expanded ? "Collapse" : "Expand"}
            </button>
          )}
        </div>
      ) : (
        <p className="text-xs text-ink-subtle">No aggregate critique recorded.</p>
      )}

      <div>
        <h3 className="text-xs uppercase tracking-wide text-ink-subtle mb-2">
          Reviewer panel
        </h3>
        {entries.length === 0 ? (
          <Empty
            title="No reviewer panel results yet."
            hint="Reviewer rows will appear here as they land."
          />
        ) : (
          <ul className="space-y-2">
            {entries.map((e, i) => (
              <li
                key={`${e.reviewer_task_id}-${i}`}
                className="border border-edge rounded p-2"
              >
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <Link
                    to={`/tasks/${encodeURIComponent(e.reviewer_task_id)}`}
                    className="text-accent hover:underline text-xs"
                  >
                    <Mono>{e.reviewer_task_id}</Mono>
                  </Link>
                  <div className="flex items-center gap-2">
                    <span className={`badge ${verdictBadgeClasses(e.verdict)}`}>
                      {e.verdict || "—"}
                    </span>
                    <span className="text-[11px] text-ink-subtle">
                      {fmtAbsolute(e.completed_at)}
                    </span>
                  </div>
                </div>
                {e.critique_excerpt && (
                  <pre className="mt-1 text-[11px] whitespace-pre-wrap text-ink-muted font-sans">
                    {e.critique_excerpt}
                  </pre>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}

function verdictBadgeClasses(verdict: string | null): string {
  const normalized = (verdict ?? "").toLowerCase();
  if (normalized === "approved") {
    return "bg-ok-muted/30 border-ok text-ok";
  }
  if (normalized === "rejected" || normalized === "reject" || normalized === "atleastonerejected") {
    return "bg-bad-muted/30 border-bad text-bad";
  }
  return "bg-edge/20 border-edge text-ink-muted";
}
