import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";

import { dashboardApi } from "@/api/client";
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
  if (q.error) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
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
