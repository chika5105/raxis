import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";

import { dashboardApi } from "@/api/client";
import { ErrorBox } from "@/components/ErrorBox";
import { OrchestratorGapWarningCard } from "@/components/lifecycle/OrchestratorGapWarningCard";
import { PageSpinner } from "@/components/Spinner";
import { StateBadge } from "@/components/StateBadge";
import { Mono } from "@/components/Mono";
import { auditBadgeClasses } from "@/lib/audit-tone";
import { fmtRelative, fmtTokens, plural } from "@/lib/format";

// How many operator-relevant rows the "Recent activity" widget
// surfaces. The backend's curated `/api/audit/recent` endpoint
// already filters out read-only page-view audits server-side
// (see `crates/dashboard/src/data.rs::recent_activity_filter`),
// so we ask for exactly the count we want to render.
const RECENT_ACTIVITY_DISPLAY_LIMIT = 10;

/// Operator landing page. Shows kernel health, top-level
/// counters, and a recent-activity feed (newest 10 audit
/// rows). Refreshes on a 5-second cadence per the spec
/// principle "real-time indicators" (§4.4).
export function OverviewPage() {
  const navigate = useNavigate();
  const health = useQuery({
    queryKey: ["health"],
    queryFn: ({ signal }) => dashboardApi.health(signal),
    refetchInterval: 5_000,
  });

  const initiatives = useQuery({
    queryKey: ["initiatives", { limit: 5 }],
    queryFn: ({ signal }) =>
      dashboardApi.initiatives.list({ limit: 5 }, signal),
    refetchInterval: 5_000,
  });

  const sessions = useQuery({
    queryKey: ["sessions", { limit: 8 }],
    queryFn: ({ signal }) => dashboardApi.sessions.list(8, signal),
    refetchInterval: 3_000,
  });

  // The Recent Activity widget hits the backend's curated
  // `/api/audit/recent` endpoint, which the dashboard kernel
  // filters to state-affecting events only (the allow-list
  // lives in `data::recent_activity_filter`). The FE no longer
  // post-filters — once the backend filters, the FE doing it
  // again is dead code (`INV-DASHBOARD-RECENT-ACTIVITY-FILTER-01`
  // moved server-side; see
  // `specs/v2/dashboard-operator-action-audit-coverage.md
  // §signal-vs-noise`).
  const audit = useQuery({
    queryKey: ["audit", "recent", { limit: RECENT_ACTIVITY_DISPLAY_LIMIT }],
    queryFn: ({ signal }) =>
      dashboardApi.audit.recent(
        { limit: RECENT_ACTIVITY_DISPLAY_LIMIT },
        signal,
      ),
    refetchInterval: 5_000,
  });
  const recentActivity = audit.data ?? [];

  // Orchestrator-gap warnings — surfaces every stuck
  // PendingActivation row whose predecessors all completed.
  // Front-and-center on the home view so an operator sees
  // wedged orchestrators immediately.
  // `INV-DASHBOARD-LIFECYCLE-CAUSALITY-01`.
  const gaps = useQuery({
    queryKey: ["orchestrator-gaps"],
    queryFn: ({ signal }) => dashboardApi.orchestratorGaps(signal),
    refetchInterval: 10_000,
  });
  const orchestratorGaps =
    (gaps.data?.gaps ?? []).filter(
      (g): g is Extract<typeof g, { kind: "orchestrator_gap" }> =>
        g.kind === "orchestrator_gap",
    );

  if (health.isPending) return <PageSpinner />;
  if (health.error)
    return <ErrorBox error={health.error} onRetry={() => health.refetch()} />;

  const h = health.data;
  return (
    <div className="space-y-5">
      <header className="flex items-baseline justify-between">
        <div>
          <h1 className="text-xl font-semibold text-ink">Overview</h1>
          <p className="text-sm text-ink-muted">
            Kernel health · {plural(h.active_initiatives, "active initiative")}{" "}
            · {plural(h.active_sessions, "active session")} ·{" "}
            {plural(h.pending_escalations, "pending escalation")}
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs text-ink-subtle">
          <span>Auto-refresh 5s</span>
        </div>
      </header>

      {orchestratorGaps.length > 0 && (
        <section
          data-testid="overview-warnings"
          className="space-y-3"
          aria-label="Orchestrator gaps"
        >
          <header className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-warn">
              Warnings ({orchestratorGaps.length})
            </h2>
            <span className="text-[11px] text-ink-subtle">
              Auto-refresh 10s
            </span>
          </header>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
            {orchestratorGaps.map((g, i) => (
              <OrchestratorGapWarningCard key={`${g.task_id}-${i}`} a={g} />
            ))}
          </div>
        </section>
      )}

      {/* KPI tiles. Each tile is a navigation target — the
          number is the operator's most common drill-in question
          ("which active initiatives?", "what's escalated?"). */}
      <section className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Tile
          title="Kernel"
          value={h.status}
          tone={
            h.status === "ok" ? "ok" : h.status === "degraded" ? "warn" : "bad"
          }
          sub={`Booted ${fmtRelative(h.kernel_booted_at)}`}
          to="/health"
        />
        <Tile
          title="Policy epoch"
          value={`#${h.policy_epoch}`}
          tone="info"
          sub="Active bundle"
          to="/policy"
        />
        <Tile
          title="Active initiatives"
          value={String(h.active_initiatives)}
          tone="info"
          sub="In flight"
          to="/initiatives?state=Active"
        />
        <Tile
          title="Pending escalations"
          value={String(h.pending_escalations)}
          tone={h.pending_escalations > 0 ? "warn" : "muted"}
          sub="Awaiting operator"
          to="/escalations"
        />
      </section>

      {/* Health checks */}
      <section className="card p-4">
        <header className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-ink">Subsystem health</h2>
          <Link to="/health" className="text-xs text-accent hover:underline">
            Full doctor view →
          </Link>
        </header>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
          {h.checks.length === 0 && (
            <div className="text-xs text-ink-subtle col-span-full">
              No checks reported.
            </div>
          )}
          {h.checks.map((c) => (
            <div
              key={c.id}
              className="flex items-center gap-2 px-3 py-2 rounded border border-edge bg-panel"
            >
              <span
                className={
                  c.status === "ok"
                    ? "w-2 h-2 rounded-full bg-ok"
                    : c.status === "degraded"
                      ? "w-2 h-2 rounded-full bg-warn"
                      : "w-2 h-2 rounded-full bg-bad"
                }
                aria-hidden="true"
              />
              <Mono className="text-ink-muted">{c.id}</Mono>
              <span className="text-xs text-ink-subtle truncate ml-auto">
                {c.message}
              </span>
            </div>
          ))}
        </div>
      </section>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-5">
        {/* Recent initiatives */}
        <section className="card p-0 overflow-hidden">
          <header className="px-4 py-3 border-b border-edge flex items-center justify-between">
            <h2 className="text-sm font-semibold text-ink">
              Recent initiatives
            </h2>
            <Link
              to="/initiatives"
              className="text-xs text-accent hover:underline"
            >
              View all →
            </Link>
          </header>
          {initiatives.isPending ? (
            <div className="py-12 text-center text-ink-subtle text-sm">
              Loading…
            </div>
          ) : initiatives.error ? (
            <div className="p-4">
              <ErrorBox error={initiatives.error} />
            </div>
          ) : initiatives.data.length === 0 ? (
            <div className="py-12 text-center text-ink-subtle text-sm">
              No initiatives yet.
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead className="text-xs text-ink-subtle">
                <tr className="border-b border-edge">
                  <th className="text-left px-4 py-2 font-medium">
                    Initiative
                  </th>
                  <th className="text-left px-4 py-2 font-medium">State</th>
                  <th className="text-right px-4 py-2 font-medium">Progress</th>
                  <th className="text-right px-4 py-2 font-medium">Updated</th>
                </tr>
              </thead>
              <tbody>
                {initiatives.data.map((i) => {
                  const href = `/initiatives/${i.initiative_id}`;
                  return (
                    <tr
                      key={i.initiative_id}
                      tabIndex={0}
                      onClick={() => navigate(href)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") {
                          e.preventDefault();
                          navigate(href);
                        }
                      }}
                      className="border-b border-edge/50 last:border-b-0 hover:bg-panel-high cursor-pointer focus:outline-none focus-visible:ring-1 focus-visible:ring-accent focus-visible:bg-panel-high"
                    >
                      <td className="px-4 py-2">
                        <Link
                          to={href}
                          onClick={(e) => e.stopPropagation()}
                          className="text-ink hover:text-accent"
                        >
                          {i.display_name || i.initiative_id}
                        </Link>
                        <div className="text-[11px] text-ink-subtle">
                          <Mono>{i.initiative_id}</Mono>
                        </div>
                      </td>
                      <td className="px-4 py-2">
                        <StateBadge
                          state={i.state}
                          pulse={i.state === "Active"}
                        />
                      </td>
                      <td className="px-4 py-2 text-right">
                        <Progress
                          completed={i.completed_tasks}
                          failed={i.failed_tasks}
                          total={i.task_count}
                        />
                      </td>
                      <td className="px-4 py-2 text-right text-ink-muted text-xs">
                        {fmtRelative(i.updated_at)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </section>

        {/*
         * Recent sessions — newest first, regardless of state.
         * Previously labelled "Active sessions" which lied about
         * the data: the underlying query is `sessions.list(8)`
         * with no state filter, so a one-Completed + seven-Failed
         * page would display under an "Active" banner. Mirroring
         * the "Recent initiatives" sibling is also more useful
         * at-a-glance than a state-filtered list.
         */}
        <section className="card p-0 overflow-hidden">
          <header className="px-4 py-3 border-b border-edge flex items-center justify-between">
            <h2 className="text-sm font-semibold text-ink">Recent sessions</h2>
            <Link
              to="/sessions"
              className="text-xs text-accent hover:underline"
            >
              View all →
            </Link>
          </header>
          {sessions.isPending ? (
            <div className="py-12 text-center text-ink-subtle text-sm">
              Loading…
            </div>
          ) : sessions.error ? (
            <div className="p-4">
              <ErrorBox error={sessions.error} />
            </div>
          ) : sessions.data.length === 0 ? (
            <div className="py-12 text-center text-ink-subtle text-sm">
              No sessions running.
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead className="text-xs text-ink-subtle">
                <tr className="border-b border-edge">
                  <th className="text-left px-4 py-2 font-medium">Session</th>
                  <th className="text-left px-4 py-2 font-medium">Role</th>
                  <th className="text-left px-4 py-2 font-medium">State</th>
                  <th className="text-right px-4 py-2 font-medium">Tokens</th>
                </tr>
              </thead>
              <tbody>
                {sessions.data.map((s) => {
                  const href = `/sessions/${s.session_id}`;
                  return (
                    <tr
                      key={s.session_id}
                      tabIndex={0}
                      onClick={() => navigate(href)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") {
                          e.preventDefault();
                          navigate(href);
                        }
                      }}
                      className="border-b border-edge/50 last:border-b-0 hover:bg-panel-high cursor-pointer focus:outline-none focus-visible:ring-1 focus-visible:ring-accent focus-visible:bg-panel-high"
                    >
                      <td className="px-4 py-2">
                        <Link
                          to={href}
                          onClick={(e) => e.stopPropagation()}
                          className="text-ink hover:text-accent"
                        >
                          <Mono>{s.session_id.slice(0, 12)}…</Mono>
                        </Link>
                        <div className="text-[11px] text-ink-subtle">
                          {s.provider ?? "—"} · {s.model ?? "—"}
                        </div>
                      </td>
                      <td className="px-4 py-2 text-ink-muted">{s.role}</td>
                      <td className="px-4 py-2">
                        <StateBadge
                          state={s.state}
                          pulse={s.state === "Running"}
                        />
                      </td>
                      <td className="px-4 py-2 text-right text-ink-muted text-xs tabular">
                        <span className="text-ink">
                          {fmtTokens(s.input_tokens + s.output_tokens)}
                        </span>
                        <div className="text-[10px]">
                          in {fmtTokens(s.input_tokens)} · out{" "}
                          {fmtTokens(s.output_tokens)}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </section>
      </div>

      {/*
       * Recent activity — operator-relevant subset of the audit
       * chain. The backend's `/api/audit/recent` endpoint filters
       * the chain server-side to state-affecting events only
       * (`OperatorViewed*` / `OperatorOpened*` read-only page-
       * views are no longer persisted; what slips through pre-
       * deprecation is suppressed by the curated filter), so the
       * teaser surfaces meaningful state transitions even on a
       * busy operator session (the iter48 chain hit 1260 events
       * in 17 min, ~90% read-only spam). The full chain remains
       * on `/audit`, which ships its own toggle to show / hide
       * the read-only views
       * (`INV-DASHBOARD-AUDIT-OPERATOR-READ-TOGGLE-01`).
       */}
      <section className="card p-0 overflow-hidden">
        <header className="px-4 py-3 border-b border-edge flex items-center justify-between">
          <h2 className="text-sm font-semibold text-ink">Recent activity</h2>
          <Link to="/audit" className="text-xs text-accent hover:underline">
            Full audit chain →
          </Link>
        </header>
        {audit.isPending ? (
          <div className="py-12 text-center text-ink-subtle text-sm">
            Loading…
          </div>
        ) : audit.error ? (
          <div className="p-4">
            <ErrorBox error={audit.error} />
          </div>
        ) : recentActivity.length === 0 ? (
          <div className="py-12 text-center text-ink-subtle text-sm">
            {audit.data.length === 0
              ? "No audit events."
              : "No operator-relevant events in the recent chain — only page-view audits."}
          </div>
        ) : (
          <ul className="divide-y divide-edge/50">
            {recentActivity.map((a) => (
              <li
                key={a.event_id}
                className="px-4 py-2.5 flex items-center gap-3 text-sm"
              >
                <span className="text-[11px] text-ink-subtle font-mono w-12 text-right">
                  #{a.seq}
                </span>
                <span className={auditBadgeClasses(a.event_kind)}>
                  {a.event_kind}
                </span>
                {a.initiative_id && (
                  <Link
                    to={`/initiatives/${a.initiative_id}`}
                    className="text-xs text-accent hover:underline"
                  >
                    {a.initiative_id}
                  </Link>
                )}
                {a.task_id && (
                  <Link
                    to={`/tasks/${a.task_id}`}
                    className="text-xs text-ink-muted hover:text-accent"
                  >
                    · {a.task_id}
                  </Link>
                )}
                <span className="ml-auto text-xs text-ink-subtle">
                  {fmtRelative(a.at)}
                </span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

interface TileProps {
  title: string;
  value: string;
  tone: "ok" | "warn" | "bad" | "info" | "muted";
  sub: string;
  /// Optional drill-in target. When set, the tile is a real
  /// link (full-tile click + keyboard focus) — the entire card
  /// looks clickable and now actually is.
  to?: string;
}

function Tile({ title, value, tone, sub, to }: TileProps) {
  const toneClass =
    tone === "ok"
      ? "text-ok"
      : tone === "warn"
        ? "text-warn"
        : tone === "bad"
          ? "text-bad"
          : tone === "info"
            ? "text-info"
            : "text-ink-muted";

  const inner = (
    <>
      <div className="text-xs uppercase tracking-wider text-ink-subtle">
        {title}
      </div>
      <div className={`mt-1 text-2xl font-semibold ${toneClass} tabular`}>
        {value}
      </div>
      <div className="text-[11px] text-ink-subtle mt-1">{sub}</div>
    </>
  );

  if (to) {
    return (
      <Link
        to={to}
        className="card p-3 block hover:border-accent/60 hover:bg-panel-high transition-colors focus:outline-none focus-visible:ring-1 focus-visible:ring-accent"
      >
        {inner}
      </Link>
    );
  }
  return <div className="card p-3">{inner}</div>;
}

interface ProgressProps {
  completed: number;
  failed: number;
  total: number;
}

function Progress({ completed, failed, total }: ProgressProps) {
  const pct =
    total === 0 ? 0 : Math.round(((completed + failed) / total) * 100);
  const okPct = total === 0 ? 0 : (completed / total) * 100;
  const failPct = total === 0 ? 0 : (failed / total) * 100;
  return (
    <div className="inline-block w-32 align-middle">
      <div className="flex items-center gap-2 justify-end">
        <div className="text-xs text-ink-muted tabular">{pct}%</div>
        <div className="flex-1 h-1.5 rounded-full bg-edge overflow-hidden flex">
          <div className="bg-ok h-full" style={{ width: `${okPct}%` }} />
          <div className="bg-bad h-full" style={{ width: `${failPct}%` }} />
        </div>
      </div>
      <div className="text-[10px] text-ink-subtle text-right mt-0.5">
        {completed}/{total}
        {failed > 0 && <span className="text-bad"> · {failed} failed</span>}
      </div>
    </div>
  );
}
