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
import { TaskLlmTurns } from "@/components/TaskLlmTurns";
import { fmtAbsolute, fmtRelative, fmtTokens } from "@/lib/format";
import { isTerminalFailureState } from "@/lib/state-color";
import type { LifecycleAnnotation, SessionCaptureView } from "@/types/api";

export function SessionDetailPage() {
  const { id = "" } = useParams<{ id: string }>();

  const q = useQuery({
    queryKey: ["session", id],
    queryFn: ({ signal }) => dashboardApi.sessions.get(id, signal),
    refetchInterval: 3_000,
    enabled: id.length > 0,
    placeholderData: (prev) => prev,
    // Unknown sessions should not retry forever. Background
    // refetch failures are handled below without discarding the
    // last successful row, so a session that transitions from
    // active to revoked stays on-screen.
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

  const s = q.data;
  if (!s && q.isPending) return <PageSpinner />;
  if (!s && q.error) {
    if (q.error instanceof ApiError && q.error.status === 404) {
      return (
        <SessionNotFound sessionId={id} onRetry={() => q.refetch()} />
      );
    }
    return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  }
  if (!s) return <PageSpinner />;

  const historical = isHistoricalSessionState(s.state);
  const refreshError = q.error instanceof Error ? q.error : null;

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
            <StateBadge state={s.state} pulse={isLiveSessionState(s.state)} />
            <span>created {fmtAbsolute(s.created_at)}</span>
            <span>· updated {fmtRelative(s.updated_at)}</span>
          </div>
        </div>
        <div className="card p-3 text-xs space-y-1.5 min-w-[260px]">
          <Row label="Provider" value={<ProviderBadge provider={s.provider} />} />
          <Row
            label="Model"
            value={
              <span className="font-mono text-ink-muted break-all">
                {s.model ?? "model pending"}
              </span>
            }
          />
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

      {historical && (
        <SessionLifecycleNotice
          state={s.state}
          updatedAt={s.updated_at}
        />
      )}

      {refreshError && (
        <div
          className="card border-warn/40 bg-warn-muted/10 px-4 py-3 text-sm text-ink-muted"
          data-testid="session-detail-stale-refresh"
        >
          Showing the last successful session snapshot. The most recent refresh
          failed with <Mono pill>{refreshError.message}</Mono>.
        </div>
      )}

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

      <SessionDetailTabs
        sessionId={s.session_id}
        owningTaskId={s.task_id ?? null}
        annotations={s.annotations ?? []}
        historical={historical}
      />
    </div>
  );
}

type DetailTab = "stream" | "llm-turns" | "postmortem";

/// Tab strip for the bottom of the SessionDetail page. Three
/// tabs:
///   * **Live stream** — the existing `<SessionStream>`
///     subscribes to `/api/sessions/:id/stream` SSE for
///     active sessions. Replays the on-disk ring's tail then
///     attaches live frames.
///   * **LLM turns** — `<TaskLlmTurns>` keyed by the session's
///     owning `task_id` (bound at session-mint time per
///     `INV-DASHBOARD-SESSION-OWNS-TASK-AT-MINT-01`). Shows the
///     raw upstream provider request/response envelopes the
///     kernel-side gateway tap captured for whichever task this
///     session is bound to (for Orchestrator sessions the
///     synthetic coordinator task whose `task_id == initiative_id`;
///     for Executor / Reviewer sessions their respective subtask).
///     `INV-DASHBOARD-LLM-TURN-CAPTURED-01` /
///     `INV-DASHBOARD-TASK-LLM-CAPTURE-01`. When the session has
///     no owning task (pre-iter72 fixture, or a synthetic test
///     row), the tab is disabled with a hint.
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
function SessionDetailTabs({
  sessionId,
  owningTaskId,
  annotations,
  historical,
}: {
  sessionId: string;
  owningTaskId: string | null;
  annotations: LifecycleAnnotation[];
  historical: boolean;
}) {
  const [tab, setTab] = useState<DetailTab>("stream");
  const llmTurnsEnabled = !!owningTaskId;
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
          {historical ? "Stream capture" : "Live stream"}
        </TabButton>
        <TabButton
          active={tab === "llm-turns"}
          onClick={() => llmTurnsEnabled && setTab("llm-turns")}
          testId="tab-llm-turns"
          disabled={!llmTurnsEnabled}
          title={
            llmTurnsEnabled
              ? "Raw LLM request/response envelopes for the session's owning task"
              : "No owning task is bound to this session (pre-iter72 fixture)."
          }
        >
          LLM turns
        </TabButton>
        <TabButton
          active={tab === "postmortem"}
          onClick={() => setTab("postmortem")}
          testId="tab-postmortem"
        >
          Post-mortem
        </TabButton>
      </div>
      {tab === "stream" && (
        <SessionStream
          sessionId={sessionId}
          annotations={annotations}
          historical={historical}
        />
      )}
      {tab === "llm-turns" && owningTaskId && (
        <TaskLlmTurns taskId={owningTaskId} />
      )}
      {tab === "postmortem" && <SessionPostmortemPanel sessionId={sessionId} />}
    </section>
  );
}

function isLiveSessionState(state: string): boolean {
  return (
    state === "Active" ||
    state === "Running" ||
    state === "Spawning" ||
    state === "Paused"
  );
}

function isHistoricalSessionState(state: string): boolean {
  return !isLiveSessionState(state);
}

function SessionLifecycleNotice({
  state,
  updatedAt,
}: {
  state: string;
  updatedAt: number;
}) {
  return (
    <div
      className="card border-info/30 bg-info/5 px-4 py-3 flex items-start justify-between gap-4"
      data-testid="session-lifecycle-notice"
    >
      <div className="min-w-0">
        <div className="flex items-center gap-2 text-sm font-medium text-ink">
          <StateBadge state={state} />
          <span>Session moved to historical view</span>
        </div>
        <p className="mt-1 text-xs text-ink-muted leading-relaxed">
          The active VM/session has ended, but this detail page keeps the same
          stream, LLM turns, post-mortem capture, and worktree links in place.
        </p>
      </div>
      <div className="shrink-0 text-right text-[11px] text-ink-subtle">
        <div>transitioned {fmtRelative(updatedAt)}</div>
        <Link to="/sessions/recent" className="text-accent hover:underline">
          also in Recent sessions
        </Link>
      </div>
    </div>
  );
}

function TabButton({
  active,
  onClick,
  children,
  testId,
  disabled,
  title,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
  testId?: string;
  disabled?: boolean;
  title?: string;
}) {
  const stateCls = disabled
    ? "text-ink-faint cursor-not-allowed opacity-60"
    : active
      ? "bg-accent/15 text-accent border border-accent/30"
      : "text-ink-muted hover:text-ink hover:bg-panel";
  return (
    <button
      type="button"
      role="tab"
      aria-selected={active}
      aria-disabled={disabled || undefined}
      data-testid={testId}
      title={title}
      onClick={disabled ? undefined : onClick}
      disabled={disabled}
      className={"px-3 py-1.5 text-xs rounded-sm transition-colors " + stateCls}
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

function ProviderBadge({ provider }: { provider: string | null | undefined }) {
  return (
    <span
      data-testid="session-detail-provider-badge"
      className={
        "badge text-[11px] font-mono " +
        (provider
          ? "bg-accent/10 border-accent/30 text-accent"
          : "bg-panel border-edge text-ink-faint")
      }
      title={provider ? "Observed provider" : "Provider not observed yet"}
    >
      {provider ?? "provider pending"}
    </span>
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
