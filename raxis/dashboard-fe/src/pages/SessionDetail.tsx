import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";

import { ApiError, dashboardApi } from "@/api/client";
import { CopyButton } from "@/components/CopyButton";
import { ErrorBox } from "@/components/ErrorBox";
import { FailureReasonPanel } from "@/components/FailureReasonPanel";
import { Mono } from "@/components/Mono";
import { PageSpinner } from "@/components/Spinner";
import { SessionStream } from "@/components/SessionStream";
import { StateBadge } from "@/components/StateBadge";
import { fmtAbsolute, fmtRelative, fmtTokens } from "@/lib/format";
import { isTerminalFailureState } from "@/lib/state-color";

export function SessionDetailPage() {
  const { id = "" } = useParams<{ id: string }>();

  const q = useQuery({
    queryKey: ["session", id],
    queryFn: ({ signal }) => dashboardApi.sessions.get(id, signal),
    refetchInterval: 3_000,
    enabled: id.length > 0,
    // A terminated (revoked / expired) session that was in the
    // list at click-time may legitimately 404 on detail under
    // older kernels that didn't ship
    // `INV-DASHBOARD-SESSION-DETAIL-FORENSIC-01`. Retrying that
    // wedges the operator on a generic FAIL screen — we surface
    // a typed affordance below instead.
    retry: (count, err) => {
      if (err instanceof ApiError && err.status === 404) return false;
      return count < 2;
    },
  });

  // Cross-correlate worktrees to surface a "View worktree" deep
  // link when the kernel has registered a session-owned clone.
  // Refresh on the same cadence as the worktree list page so a
  // late-attached clone shows up without a manual reload.
  const worktrees = useQuery({
    queryKey: ["worktrees", { for: id }],
    queryFn: ({ signal }) => dashboardApi.git.list(signal),
    refetchInterval: 15_000,
    enabled: id.length > 0,
  });

  const ownedWorktree = useMemo(() => {
    if (!worktrees.data) return null;
    return worktrees.data.find((w) => w.session_id === id) ?? null;
  }, [worktrees.data, id]);

  if (q.isPending) return <PageSpinner />;
  if (q.error) {
    // `INV-DASHBOARD-SESSION-DETAIL-FORENSIC-01`: a session that
    // crossed `expires_at` or was revoked between the list fetch
    // and the detail click currently surfaces as a generic
    // `FAIL_DASHBOARD_NOT_FOUND`. Once the kernel-side fix lands
    // (forensic by_id lookup that includes terminated rows), this
    // path stops firing on those sessions; until then, render a
    // typed affordance so the operator has somewhere to go
    // (audit chain filtered by the session) rather than a dead-
    // end Retry button.
    if (q.error instanceof ApiError && q.error.status === 404) {
      return (
        <SessionNotFound sessionId={id} onRetry={() => q.refetch()} />
      );
    }
    return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  }
  const s = q.data;

  return (
    <div className="space-y-5">
      <header className="flex items-start justify-between gap-3 flex-wrap">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-sm text-ink-subtle">
            <Link to="/sessions" className="hover:text-accent">
              Sessions
            </Link>
            <span>/</span>
            <Mono className="text-ink-muted">{s.session_id}</Mono>
            <CopyButton value={s.session_id} />
          </div>
          <h1 className="mt-1 text-xl font-semibold text-ink">
            {s.role}
            {s.task_id && (
              <span className="text-ink-muted text-base ml-2">
                · task{" "}
                <Link
                  to={`/tasks/${s.task_id}`}
                  className="hover:text-accent font-mono"
                >
                  {s.task_id}
                </Link>
              </span>
            )}
          </h1>
          <div className="mt-2 flex items-center gap-2 flex-wrap text-xs text-ink-muted">
            <StateBadge state={s.state} pulse={s.state === "Running"} />
            <span>created {fmtAbsolute(s.created_at)}</span>
            <span>· updated {fmtRelative(s.updated_at)}</span>
          </div>
        </div>
        <div className="card p-3 text-xs space-y-1.5 min-w-[260px]">
          <Row label="Provider" value={s.provider ?? "—"} mono />
          <Row label="Model" value={s.model ?? "—"} mono />
          <Row
            label="Initiative"
            value={
              s.initiative_id ? (
                <Link
                  to={`/initiatives/${s.initiative_id}`}
                  className="text-accent hover:underline font-mono"
                >
                  {s.initiative_id}
                </Link>
              ) : (
                "—"
              )
            }
          />
          <Row label="Input tokens" value={fmtTokens(s.input_tokens)} mono />
          <Row label="Output tokens" value={fmtTokens(s.output_tokens)} mono />
          <Row
            label="Worktree"
            value={
              ownedWorktree ? (
                <Link
                  to={`/git/${encodeURIComponent(ownedWorktree.name)}`}
                  className="text-accent hover:underline"
                >
                  {ownedWorktree.label} ↗
                </Link>
              ) : (
                <span className="text-ink-subtle">—</span>
              )
            }
          />
        </div>
      </header>

      {(isTerminalFailureState(s.state) || s.failure) && (
        <FailureReasonPanel
          reason={s.failure ?? null}
          heading="Session failure reason"
        />
      )}

      <SessionStream sessionId={s.session_id} />
    </div>
  );
}

function Row({
  label,
  value,
  mono,
}: {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="flex items-start gap-3 text-xs">
      <span className="w-24 text-ink-subtle uppercase tracking-wider text-[10px] mt-0.5 shrink-0">
        {label}
      </span>
      <span
        className={`flex-1 min-w-0 ${mono ? "font-mono text-ink-muted" : "text-ink"}`}
      >
        {value}
      </span>
    </div>
  );
}

/// 404 affordance for the SessionDetail page. The most common
/// cause is a session that terminated (was revoked / expired)
/// after the operator opened the list page but before they
/// clicked the row, so the list cache still showed the row but
/// the kernel's `active_list`-backed lookup no longer matches
/// (`INV-DASHBOARD-SESSION-DETAIL-FORENSIC-01`; the kernel-side
/// fix that surfaces terminated rows via `by_id` is tracked by
/// the sibling backend worker).
///
/// Until that lands we point the operator at the audit chain
/// pre-filtered by the session id so they can still reconstruct
/// what happened — far better than a bare retry on a row that
/// will keep 404'ing on every poll.
function SessionNotFound({
  sessionId,
  onRetry,
}: {
  sessionId: string;
  onRetry: () => void;
}) {
  return (
    <div className="space-y-4" data-testid="session-not-found">
      <header className="flex items-start justify-between gap-3 flex-wrap">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-sm text-ink-subtle">
            <Link to="/sessions" className="hover:text-accent">
              Sessions
            </Link>
            <span>/</span>
            <Mono className="text-ink-muted">{sessionId}</Mono>
            <CopyButton value={sessionId} />
          </div>
          <h1 className="mt-1 text-xl font-semibold text-ink">
            Session not currently retrievable
          </h1>
        </div>
      </header>
      <div className="card border-warn/40 p-4 max-w-prose">
        <p className="text-sm text-ink">
          The kernel returned <Mono pill>FAIL_DASHBOARD_NOT_FOUND</Mono>{" "}
          for this session id. The most common cause is that the session{" "}
          <strong>terminated</strong> (revoked or expired) after the
          Sessions list was loaded but before this detail page was
          opened — the active-session lookup the kernel currently uses
          for detail filters those rows out, even though the list page
          still showed it.
        </p>
        <p className="mt-3 text-sm text-ink-muted">
          The kernel-side fix that surfaces terminated sessions on the
          detail surface is tracked by{" "}
          <Mono>INV-DASHBOARD-SESSION-DETAIL-FORENSIC-01</Mono>. Until
          it lands, the audit chain is the source of truth for what
          happened to this session.
        </p>
        <div className="mt-4 flex flex-wrap items-center gap-2">
          <Link
            to={`/audit?session_id=${encodeURIComponent(sessionId)}`}
            className="btn-primary text-sm"
          >
            Search audit chain for this session →
          </Link>
          <Link to="/sessions" className="btn text-sm">
            Back to sessions list
          </Link>
          <button type="button" className="btn text-sm" onClick={onRetry}>
            Retry detail fetch
          </button>
        </div>
      </div>
    </div>
  );
}
