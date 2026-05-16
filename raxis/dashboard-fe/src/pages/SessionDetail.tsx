import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";

import { ApiError, dashboardApi } from "@/api/client";
import { CopyButton } from "@/components/CopyButton";
import { ErrorBox } from "@/components/ErrorBox";
import { FailureReasonPanel } from "@/components/FailureReasonPanel";
import { LifecycleTimeline } from "@/components/lifecycle/LifecycleTimeline";
import { Mono } from "@/components/Mono";
import { PageSpinner } from "@/components/Spinner";
import { SessionStream } from "@/components/SessionStream";
import { StateBadge } from "@/components/StateBadge";
import { fmtAbsolute, fmtRelative, fmtTokens } from "@/lib/format";
import { isTerminalFailureState } from "@/lib/state-color";
import type { SessionCaptureView } from "@/types/api";

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

      {/* `<LifecycleTimeline>` rendered above the tabs as a
          header band so the operator sees self-exit /
          operator-revoke / initiative-block context before
          drilling into the live stream or post-mortem.
          `INV-DASHBOARD-LIFECYCLE-CAUSALITY-01`. */}
      <LifecycleTimeline annotations={s.annotations ?? []} />

      <SessionDetailTabs sessionId={s.session_id} />
    </div>
  );
}

type DetailTab = "stream" | "postmortem";

/// Tab strip for the bottom of the SessionDetail page. Two
/// tabs:
///   * **Live stream** — the existing `<SessionStream>`
///     subscribes to `/api/sessions/:id/stream` SSE for
///     active sessions. Replays the on-disk ring's tail then
///     attaches live frames.
///   * **Post-mortem** — `<SessionPostmortemPanel>` calls
///     `/api/sessions/:id/capture` to surface FSM transitions
///     + audit-event mirrors + KSB snapshots from the
///     per-session lifecycle ring. Persists after the
///     session terminates (Completed / Failed / Aborted),
///     pinned by
///     `INV-DASHBOARD-SESSION-CAPTURE-PERSIST-AFTER-TERMINATION-01`.
///
/// We default to the live stream — operators land here while
/// the session is running 95 % of the time. Only on a fail /
/// post-mortem dive do they want the capture ring.
function SessionDetailTabs({ sessionId }: { sessionId: string }) {
  const [tab, setTab] = useState<DetailTab>("stream");
  return (
    <section data-testid="session-detail-tabs" className="space-y-3">
      <div
        role="tablist"
        aria-label="Session views"
        className="inline-flex rounded-md border border-edge bg-panel-high p-0.5"
      >
        <TabButton
          active={tab === "stream"}
          onClick={() => setTab("stream")}
          testId="tab-stream"
        >
          Live stream
        </TabButton>
        <TabButton
          active={tab === "postmortem"}
          onClick={() => setTab("postmortem")}
          testId="tab-postmortem"
        >
          Post-mortem
        </TabButton>
      </div>
      {tab === "stream" ? (
        <SessionStream sessionId={sessionId} />
      ) : (
        <SessionPostmortemPanel sessionId={sessionId} />
      )}
    </section>
  );
}

function TabButton({
  active,
  onClick,
  children,
  testId,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
  testId?: string;
}) {
  return (
    <button
      type="button"
      role="tab"
      aria-selected={active}
      data-testid={testId}
      onClick={onClick}
      className={
        "px-3 py-1.5 text-xs rounded-sm transition-colors " +
        (active
          ? "bg-accent/15 text-accent border border-accent/30"
          : "text-ink-muted hover:text-ink hover:bg-panel")
      }
    >
      {children}
    </button>
  );
}

/// Post-mortem capture panel. Reads the per-session lifecycle
/// ring (`raxis-dashboard-kernel::SessionCapture`) and renders
/// it as a tabular timeline. The records persist past session
/// termination — that's the entire point of the surface (the
/// user's "session data gets deleted once the session is done"
/// complaint).
function SessionPostmortemPanel({ sessionId }: { sessionId: string }) {
  const q = useQuery({
    queryKey: ["session-capture", sessionId],
    queryFn: ({ signal }) =>
      dashboardApi.sessions.capture(sessionId, { limit: 200 }, signal),
    refetchInterval: 5_000,
    refetchIntervalInBackground: false,
    staleTime: 1_000,
  });
  if (q.isPending) {
    return (
      <div
        className="card p-4 text-sm text-ink-muted"
        data-testid="session-capture-loading"
      >
        Loading post-mortem capture…
      </div>
    );
  }
  if (q.error) {
    return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  }
  const records = q.data ?? [];
  if (records.length === 0) {
    return (
      <div
        data-testid="session-capture-empty"
        className="card p-4 text-sm text-ink-muted leading-relaxed"
      >
        <p>
          No post-mortem records yet for this session. The kernel
          observer appends FSM transitions, KSB snapshots, and
          audit-event mirrors to a bounded on-disk ring at{" "}
          <Mono pill>{`<data_dir>/session-capture/${sessionId}.ndjson`}</Mono>{" "}
          — records persist after the session terminates
          (Completed / Failed / Aborted) until the ring rolls.
        </p>
        <p className="mt-2 text-xs text-ink-subtle">
          Pinned by{" "}
          <Mono>INV-DASHBOARD-SESSION-CAPTURE-PERSIST-AFTER-TERMINATION-01</Mono>
          .
        </p>
      </div>
    );
  }
  return (
    <div className="card p-0 overflow-hidden" data-testid="session-capture-list">
      <header className="px-4 py-3 border-b border-edge flex items-center justify-between gap-2">
        <h3 className="text-sm font-semibold text-ink">
          Post-mortem capture
          <span className="text-ink-muted ml-2 font-normal">
            ({records.length} record{records.length === 1 ? "" : "s"})
          </span>
        </h3>
        <span className="text-[11px] text-ink-subtle">
          Persists after Completed / Failed / Aborted
        </span>
      </header>
      <ul className="divide-y divide-edge/40">
        {records.map((r, idx) => (
          <CaptureRow key={`${r.ts_unix}-${idx}`} record={r} />
        ))}
      </ul>
    </div>
  );
}

function CaptureRow({ record }: { record: SessionCaptureView }) {
  return (
    <li className="px-4 py-2.5 flex items-start gap-3" data-kind={record.kind}>
      <Mono className="text-[11px] text-ink-subtle w-32 shrink-0 mt-1">
        {fmtAbsolute(record.ts_unix)}
      </Mono>
      <span
        className={
          "badge text-[11px] shrink-0 " +
          (record.kind === "fsm_transition"
            ? "bg-accent/15 border-accent/30 text-accent"
            : record.kind === "audit_event"
              ? "bg-panel border-edge text-ink"
              : "bg-panel-high border-edge text-ink-muted")
        }
      >
        {record.kind}
      </span>
      <pre className="text-[11px] text-ink-muted flex-1 whitespace-pre-wrap break-words leading-snug font-mono">
        {JSON.stringify(record.payload, null, 0)}
      </pre>
    </li>
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
