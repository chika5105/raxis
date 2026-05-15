// `<LifecycleAnnotation>` — single dispatcher over the
// discriminated-union annotation wire shape.
//
// Each kernel-emitted annotation kind picks one renderer
// component below. A new kernel-side variant ⇒ one new
// `*.tsx` file + a `case` arm here, no other touch points.
//
// `INV-DASHBOARD-LIFECYCLE-CAUSALITY-01`.

import type { LifecycleAnnotation as LA } from "@/types/api";

import { InitiativeBlockedCard } from "./InitiativeBlockedCard";
import { OrchestratorGapWarningCard } from "./OrchestratorGapWarningCard";
import { RetryCrashCard } from "./RetryCrashCard";
import { RetryReviewRejectCard } from "./RetryReviewRejectCard";
import { RetryValidationRejectCard } from "./RetryValidationRejectCard";
import { SessionRevokedOperatorCard } from "./SessionRevokedOperatorCard";
import { SessionRevokedSelfExitCard } from "./SessionRevokedSelfExitCard";

interface Props {
  annotation: LA;
}

export function LifecycleAnnotation({ annotation }: Props) {
  switch (annotation.kind) {
    case "retry_review_reject":
      return <RetryReviewRejectCard a={annotation} />;
    case "retry_crash":
      return <RetryCrashCard a={annotation} />;
    case "retry_validation_reject":
      return <RetryValidationRejectCard a={annotation} />;
    case "session_revoked_operator":
      return <SessionRevokedOperatorCard a={annotation} />;
    case "session_revoked_self_exit":
      return <SessionRevokedSelfExitCard a={annotation} />;
    case "initiative_blocked":
      return <InitiativeBlockedCard a={annotation} />;
    case "orchestrator_gap":
      return <OrchestratorGapWarningCard a={annotation} />;
    default: {
      // Exhaustiveness guard. If the wire grows a new variant
      // and the FE hasn't shipped a renderer yet, this branch
      // surfaces a typed error in dev builds and falls back to
      // a generic JSON dump in prod so the operator still sees
      // *something*.
      const _exhaustive: never = annotation;
      void _exhaustive;
      return (
        <div className="card border-edge p-3 text-xs text-ink-subtle">
          <div className="font-mono text-[10px] uppercase tracking-wide">
            unrecognised lifecycle annotation
          </div>
          <pre className="mt-1 overflow-x-auto whitespace-pre-wrap text-[10px]">
            {JSON.stringify(annotation, null, 2)}
          </pre>
        </div>
      );
    }
  }
}

/// Render a one-line summary suitable for the global Tasks
/// "Lifecycle" column. Skips inline cards entirely; this is
/// the compact path.
export function lifecycleSummary(a: LA | null | undefined): string {
  if (!a) return "—";
  switch (a.kind) {
    case "retry_review_reject":
      return `Retry ${a.retry_number} (review reject ${a.review_reject_count}/${a.max_review_rejections})`;
    case "retry_crash":
      return `Retry ${a.retry_number} (crash ${a.crash_retry_count}/${a.max_crash_retries})`;
    case "retry_validation_reject":
      return `Retry ${a.retry_number} (validator: ${a.validator_reason})`;
    case "session_revoked_operator":
      return `Revoked by ${a.revoked_by_display_name ?? a.revoked_by}`;
    case "session_revoked_self_exit":
      return `Self-exit${a.exit_code !== null && a.exit_code !== undefined ? ` (exit ${a.exit_code})` : ""}`;
    case "initiative_blocked":
      return `Initiative blocked: ${a.block_reason}`;
    case "orchestrator_gap":
      return `Orchestrator gap (${Math.round(a.wait_seconds / 60)}min)`;
    default:
      return "—";
  }
}

/// Map a `kind` to a short colour-coded dot class so the
/// global Tasks index renders a one-glance cue per row.
export function lifecycleDotClass(a: LA | null | undefined): string {
  if (!a) return "bg-edge";
  switch (a.kind) {
    case "retry_review_reject":
    case "retry_validation_reject":
      return "bg-bad";
    case "retry_crash":
      return "bg-warn";
    case "session_revoked_operator":
      return "bg-info";
    case "session_revoked_self_exit":
      return "bg-ok";
    case "initiative_blocked":
      return "bg-bad";
    case "orchestrator_gap":
      return "bg-warn";
    default:
      return "bg-edge";
  }
}
