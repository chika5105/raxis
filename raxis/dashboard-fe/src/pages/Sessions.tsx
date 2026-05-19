import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import clsx from "clsx";

import { dashboardApi } from "@/api/client";
import { Empty } from "@/components/Empty";
import { ErrorBox } from "@/components/ErrorBox";
import { FailurePill } from "@/components/FailureReasonPanel";
import { Mono } from "@/components/Mono";
import { PageSpinner } from "@/components/Spinner";
import { StateBadge } from "@/components/StateBadge";
import {
  StatusFilterPills,
  StatusLegend,
} from "@/components/StatusLegend";
import { fmtRelative, fmtTokens } from "@/lib/format";
import { isTerminalFailureState } from "@/lib/state-color";
import {
  parseStatusParam,
  serializeStatusParam,
  toggleStatus,
} from "@/lib/status-filter";

const ROLES = ["All", "Orchestrator", "Executor", "Reviewer"];
type LifecycleScope = "all" | "live" | "past";

export function SessionsPage() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const initiativeId = params.get("initiative_id") ?? undefined;
  const workspaceName = params.get("workspace") ?? "All";
  const scope = parseLifecycleScope(params.get("scope"));
  const activeStatuses = useMemo(
    () => parseStatusParam(params.get("status")),
    [params],
  );
  const writeScope = (next: LifecycleScope) => {
    const sp = new URLSearchParams(params);
    if (next === "all") sp.delete("scope");
    else sp.set("scope", next);
    setParams(sp, { replace: true });
  };
  const writeStatuses = (next: string[]) => {
    const sp = new URLSearchParams(params);
    if (next.length === 0) sp.delete("status");
    else sp.set("status", serializeStatusParam(next));
    setParams(sp, { replace: true });
  };
  const writeWorkspaceName = (next: string) => {
    const sp = new URLSearchParams(params);
    if (next === "All") sp.delete("workspace");
    else sp.set("workspace", next);
    setParams(sp, { replace: true });
  };
  const clearInitiativeFilter = () => {
    const sp = new URLSearchParams(params);
    sp.delete("initiative_id");
    setParams(sp, { replace: true });
  };
  const handleToggle = (status: string, multiSelect: boolean) =>
    writeStatuses(toggleStatus(activeStatuses, status, multiSelect));
  const handleClear = () => writeStatuses([]);
  const handleRemove = (status: string) =>
    writeStatuses(activeStatuses.filter((s) => s !== status));
  const [role, setRole] = useState<string>("All");
  const [search, setSearch] = useState("");

  const q = useQuery({
    queryKey: ["sessions", { limit: 200, initiativeId }],
    queryFn: ({ signal }) =>
      dashboardApi.sessions.list(
        {
          limit: 200,
          ...(initiativeId ? { initiative_id: initiativeId } : {}),
        },
        signal,
      ),
    refetchInterval: 3_000,
  });

  // Per-state legend counts are computed from the role/search-
  // narrowed list (excluding the status filter itself) — that way
  // the counts reflect the operator's other filters and don't
  // shrink to "X/X" the moment they click a chip.
  const roleSearchFiltered = useMemo(() => {
    if (!q.data) return [];
    return q.data.filter((s) => {
      if (role !== "All" && s.role !== role) return false;
      if (
        workspaceName !== "All" &&
        (s.initiative_display_name ?? "") !== workspaceName
      ) {
        return false;
      }
      if (search) {
        const needle = search.toLowerCase();
        const haystack = [
          s.session_id,
          s.role,
          s.task_id ?? "",
          s.initiative_id ?? "",
          s.initiative_display_name ?? "",
          s.provider ?? "",
          s.model ?? "",
        ]
          .join(" ")
          .toLowerCase();
        if (!haystack.includes(needle)) return false;
      }
      return true;
    });
  }, [q.data, role, search, workspaceName]);
  const workspaceOptions = useMemo(() => {
    const names = new Set<string>();
    for (const s of q.data ?? []) {
      const name = s.initiative_display_name?.trim();
      if (name) names.add(name);
    }
    return [...names].sort((a, b) => a.localeCompare(b));
  }, [q.data]);
  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const s of roleSearchFiltered.filter((s) =>
      matchesLifecycleScope(s.state, scope),
    )) {
      c[s.state] = (c[s.state] ?? 0) + 1;
    }
    return c;
  }, [roleSearchFiltered, scope]);
  const lifecycleCounts = useMemo(() => {
    let live = 0;
    let past = 0;
    for (const s of roleSearchFiltered) {
      if (isLiveSessionState(s.state)) live += 1;
      else past += 1;
    }
    return { live, past, all: live + past };
  }, [roleSearchFiltered]);
  const activeSet = new Set(activeStatuses);
  const filterActive = activeStatuses.length > 0;
  // Rows always render — when a status filter is active we dim the
  // non-matching ones (highlight semantics) rather than removing
  // them, matching the user's stated "highlight" intent.
  const filtered = roleSearchFiltered.filter((s) =>
    matchesLifecycleScope(s.state, scope),
  );

  return (
    <div className="space-y-4">
      <header className="flex items-end justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-xl font-semibold text-ink">Sessions</h1>
          <p className="text-sm text-ink-muted">
            Live and historical planner sessions, newest first.
          </p>
          <div className="mt-2 flex items-center gap-2 text-xs text-ink-subtle">
            <span className="badge bg-panel-high border-edge text-ink-muted">
              {lifecycleCounts.all} total
            </span>
            <span className="badge bg-ok-muted/20 border-ok text-ok">
              {lifecycleCounts.live} live
            </span>
            <span className="badge bg-panel-high border-edge text-ink-subtle">
              {lifecycleCounts.past} past
            </span>
          </div>
        </div>
        <div className="flex gap-2 flex-wrap justify-end">
          <div className="inline-flex rounded-md border border-edge bg-panel p-0.5 text-xs">
            <ScopeButton
              active={scope === "all"}
              onClick={() => writeScope("all")}
            >
              All
            </ScopeButton>
            <ScopeButton
              active={scope === "live"}
              onClick={() => writeScope("live")}
            >
              Live
            </ScopeButton>
            <ScopeButton
              active={scope === "past"}
              onClick={() => writeScope("past")}
            >
              Past
            </ScopeButton>
          </div>
          <input
            className="input w-56"
            placeholder="Search workspace / session / initiative / provider..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <select
            className="input max-w-[220px]"
            value={workspaceName}
            onChange={(e) => writeWorkspaceName(e.target.value)}
          >
            <option value="All">All workspaces</option>
            {workspaceOptions.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
          <select
            className="input"
            value={role}
            onChange={(e) => setRole(e.target.value)}
          >
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
        </div>
      </header>

      {initiativeId && (
        <div className="text-xs text-ink-muted">
          Filtered to initiative <Mono pill>{initiativeId}</Mono>{" "}
          <button
            type="button"
            onClick={clearInitiativeFilter}
            className="text-accent hover:underline ml-2"
          >
            clear
          </button>
        </div>
      )}

      {workspaceName !== "All" && (
        <div className="text-xs text-ink-muted">
          Filtered to workspace <Mono pill>{workspaceName}</Mono>{" "}
          <button
            type="button"
            onClick={() => writeWorkspaceName("All")}
            className="text-accent hover:underline ml-2"
          >
            clear
          </button>
        </div>
      )}

      {Object.keys(counts).length > 0 && (
        <section
          className="card px-4 py-3 flex flex-wrap items-center gap-x-4 gap-y-2"
          aria-label="Session status legend"
        >
          <StatusLegend
            counts={counts}
            activeStatuses={activeStatuses}
            onToggle={handleToggle}
            onClear={handleClear}
            itemNoun="session"
          />
          {filterActive && (
            <span className="text-[11px] text-ink-subtle">
              · non-matching rows dimmed · Cmd-click for multi-select
            </span>
          )}
        </section>
      )}

      {filterActive && (
        <StatusFilterPills
          activeStatuses={activeStatuses}
          onRemove={handleRemove}
          onClearAll={handleClear}
        />
      )}

      {q.isPending ? (
        <PageSpinner />
      ) : q.error ? (
        <ErrorBox error={q.error} onRetry={() => q.refetch()} />
      ) : filtered.length === 0 ? (
        <Empty title="No sessions." />
      ) : (
        <div className="card p-0 overflow-hidden">
          <table className="w-full text-sm">
            <thead className="text-xs text-ink-subtle bg-panel-high">
              <tr>
                <th className="text-left px-4 py-2 font-medium">Session</th>
                <th className="text-left px-4 py-2 font-medium">Role</th>
                <th className="text-left px-4 py-2 font-medium">Lifecycle</th>
                <th className="text-left px-4 py-2 font-medium">State</th>
                <th className="text-left px-4 py-2 font-medium">
                  Workspace / Task
                </th>
                <th className="text-left px-4 py-2 font-medium">
                  Provider / Model
                </th>
                <th className="text-right px-4 py-2 font-medium">Tokens</th>
                <th className="text-right px-4 py-2 font-medium">Updated</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((s) => {
                const href = `/sessions/${s.session_id}`;
                const dimmed = filterActive && !activeSet.has(s.state);
                return (
                  <tr
                    key={s.session_id}
                    tabIndex={0}
                    data-dimmed={dimmed || undefined}
                    onClick={() => navigate(href)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        e.preventDefault();
                        navigate(href);
                      }
                    }}
                    className={clsx(
                      "border-t border-edge/40 hover:bg-panel-high cursor-pointer",
                      "focus:outline-none focus-visible:ring-1 focus-visible:ring-accent focus-visible:bg-panel-high transition-opacity",
                      dimmed && "opacity-40 hover:opacity-90",
                    )}
                  >
                    <td className="px-4 py-2">
                      <Link
                        to={href}
                        onClick={(e) => e.stopPropagation()}
                        className="text-ink hover:text-accent"
                      >
                        <Mono>{s.session_id.slice(0, 16)}...</Mono>
                      </Link>
                    </td>
                    <td className="px-4 py-2 text-ink-muted">
                      <span className="badge bg-panel border-edge text-ink-muted">
                        {s.role}
                      </span>
                    </td>
                    <td className="px-4 py-2 align-top">
                      <LifecyclePill state={s.state} />
                    </td>
                    <td className="px-4 py-2 align-top">
                      <div className="flex flex-col items-start gap-1">
                        <StateBadge
                          state={s.state}
                          pulse={isLiveSessionState(s.state)}
                        />
                        {isTerminalFailureState(s.state) && (
                          <FailurePill
                            failed
                            reason={s.failure ?? null}
                            compact
                          />
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-2 text-xs">
                      {s.initiative_id && (
                        <Link
                          to={`/initiatives/${s.initiative_id}`}
                          onClick={(e) => e.stopPropagation()}
                          className="text-accent hover:underline"
                          title={s.initiative_id}
                        >
                          {s.initiative_display_name}
                        </Link>
                      )}
                      {s.initiative_id && (
                        <div className="font-mono text-[11px] text-ink-subtle break-all">
                          {s.initiative_id}
                        </div>
                      )}
                      {s.task_id && (
                        <div>
                          <Link
                            to={`/tasks/${s.task_id}`}
                            onClick={(e) => e.stopPropagation()}
                            className="text-ink-muted hover:text-accent font-mono text-[11px]"
                          >
                            {s.task_id}
                          </Link>
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-2 text-xs">
                      <ProviderModelStack
                        provider={s.provider}
                        model={s.model}
                      />
                    </td>
                    <td className="px-4 py-2 text-right text-xs text-ink-muted tabular">
                      <span className="text-ink">
                        {fmtTokens(s.input_tokens + s.output_tokens)}
                      </span>
                      <div className="text-[10px]">
                        in {fmtTokens(s.input_tokens)} · out{" "}
                        {fmtTokens(s.output_tokens)}
                      </div>
                    </td>
                    <td className="px-4 py-2 text-right text-xs text-ink-muted">
                      {fmtRelative(s.updated_at)}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function parseLifecycleScope(raw: string | null): LifecycleScope {
  return raw === "live" || raw === "past" ? raw : "all";
}

function isLiveSessionState(state: string): boolean {
  return (
    state === "Active" ||
    state === "Running" ||
    state === "Spawning" ||
    state === "Paused"
  );
}

function matchesLifecycleScope(state: string, scope: LifecycleScope): boolean {
  if (scope === "all") return true;
  const live = isLiveSessionState(state);
  return scope === "live" ? live : !live;
}

function LifecyclePill({ state }: { state: string }) {
  const live = isLiveSessionState(state);
  return (
    <span
      className={clsx(
        "badge text-[11px]",
        live
          ? "bg-ok-muted/20 border-ok text-ok"
          : "bg-panel-high border-edge text-ink-subtle",
      )}
    >
      {live ? "Live" : "Past"}
    </span>
  );
}

function ScopeButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={clsx(
        "rounded px-2.5 py-1",
        active
          ? "bg-accent text-white"
          : "text-ink-muted hover:bg-panel-high hover:text-ink",
      )}
    >
      {children}
    </button>
  );
}

function ProviderModelStack({
  provider,
  model,
}: {
  provider: string | null | undefined;
  model: string | null | undefined;
}) {
  return (
    <div className="flex flex-col items-start gap-1 min-w-[9rem]">
      <span
        data-testid="session-provider-badge"
        className={clsx(
          "badge text-[11px] font-mono",
          provider
            ? "bg-accent/10 border-accent/30 text-accent"
            : "bg-panel border-edge text-ink-faint",
        )}
        title={provider ? "Observed provider" : "Provider not observed yet"}
      >
        {provider ?? "provider pending"}
      </span>
      <span className="max-w-[18rem] break-all font-mono text-[11px] text-ink-muted">
        {model ?? "model pending"}
      </span>
    </div>
  );
}
