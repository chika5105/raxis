// `<SessionRevokedOperatorCard>` —
// `LifecycleAnnotation::SessionRevokedOperator`.
//
// An operator-initiated revoke is interesting (someone
// pressed the button) but not necessarily a failure;
// `info`-tinted card to differentiate from review-reject /
// crash retries.

import { fmtAbsolute } from "@/lib/format";
import type { LifecycleAnnotation } from "@/types/api";

type SessionRevokedOperator = Extract<
  LifecycleAnnotation,
  { kind: "session_revoked_operator" }
>;

interface Props {
  a: SessionRevokedOperator;
}

export function SessionRevokedOperatorCard({ a }: Props) {
  return (
    <div
      data-testid="lifecycle-session-revoked-operator"
      className="card border-info/40 bg-info/5 p-3"
    >
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-2 min-w-0">
          <span className="badge bg-info-muted/30 border-info text-info">
            Session revoked
          </span>
          <span className="text-[11px] text-ink-subtle">
            {fmtAbsolute(a.ts_unix)}
          </span>
        </div>
      </div>

      <div className="mt-2 text-xs text-ink-muted">
        by{" "}
        <span className="font-mono">
          {a.revoked_by_display_name ?? a.revoked_by}
        </span>
        {a.intent_kind && (
          <>
            {" · intent "}
            <span className="font-mono">{a.intent_kind}</span>
          </>
        )}
      </div>
    </div>
  );
}
