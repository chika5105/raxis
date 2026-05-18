import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import clsx from "clsx";

import { dashboardApi } from "@/api/client";
import { Empty } from "@/components/Empty";
import { ErrorBox } from "@/components/ErrorBox";
import { Mono } from "@/components/Mono";
import { PageSpinner } from "@/components/Spinner";
import { shortSha } from "@/lib/format";
import type { WorktreeListEntry } from "@/types/api";

type WorktreeScope = "all" | "reviewable" | "session" | "main";
type LifecycleScope = "all" | "live" | "past";
const EMPTY_WORKTREES: WorktreeListEntry[] = [];

export function GitPage() {
  const navigate = useNavigate();
  const [search, setSearch] = useState("");
  const [scope, setScope] = useState<WorktreeScope>("all");
  const [lifecycleScope, setLifecycleScope] =
    useState<LifecycleScope>("all");
  const q = useQuery({
    queryKey: ["worktrees"],
    queryFn: ({ signal }) => dashboardApi.git.list(signal),
    refetchInterval: 10_000,
  });

  const items = q.data ?? EMPTY_WORKTREES;
  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return items.filter((w) => {
      if (scope === "reviewable" && !w.base_sha) return false;
      if (scope === "session" && w.kind === "Main") return false;
      if (scope === "main" && w.kind !== "Main") return false;
      if (!matchesLifecycleScope(w, lifecycleScope)) return false;
      if (!needle) return true;
      return [
        w.name,
        w.label,
        w.kind,
        w.path,
        w.session_id ?? "",
        w.task_id ?? "",
        w.session_state ?? "",
        w.base_sha ?? "",
      ]
        .join(" ")
        .toLowerCase()
        .includes(needle);
    });
  }, [items, scope, lifecycleScope, search]);
  const sessionCount = items.filter((w) => w.kind !== "Main").length;
  const liveSessionCount = items.filter(
    (w) => worktreeLifecycle(w) === "live",
  ).length;
  const pastSessionCount = items.filter(
    (w) => worktreeLifecycle(w) === "past",
  ).length;
  const reviewableCount = items.filter((w) => w.base_sha).length;

  if (q.isPending) return <PageSpinner />;
  if (q.error) return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;

  return (
    <div className="space-y-4">
      <header className="flex items-end justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-xl font-semibold text-ink">Git Worktrees</h1>
          <p className="text-sm text-ink-muted">
            Review session changes with file lists and PR-style diffs.
          </p>
          <div className="mt-2 flex items-center gap-2 text-xs text-ink-subtle">
            <span className="badge bg-panel-high border-edge text-ink-muted">
              {items.length} total
            </span>
            <span className="badge bg-info-muted/30 border-info text-info">
              {sessionCount} session
            </span>
            <span className="badge bg-ok-muted/20 border-ok text-ok">
              {liveSessionCount} live
            </span>
            <span className="badge bg-panel-high border-edge text-ink-subtle">
              {pastSessionCount} past
            </span>
            <span className="badge bg-ok-muted/20 border-ok text-ok">
              {reviewableCount} reviewable
            </span>
          </div>
        </div>
        <div className="flex items-center gap-3 flex-wrap justify-end">
          <div className="flex items-center gap-1.5">
            <span className="text-[11px] uppercase tracking-wider text-ink-subtle">
              Type
            </span>
            <div className="inline-flex rounded-md border border-edge bg-panel p-0.5 text-xs">
              <ScopeButton
                active={scope === "all"}
                onClick={() => setScope("all")}
              >
                All
              </ScopeButton>
              <ScopeButton
                active={scope === "reviewable"}
                onClick={() => setScope("reviewable")}
              >
                Reviewable
              </ScopeButton>
              <ScopeButton
                active={scope === "session"}
                onClick={() => setScope("session")}
              >
                Sessions
              </ScopeButton>
              <ScopeButton
                active={scope === "main"}
                onClick={() => setScope("main")}
              >
                Main
              </ScopeButton>
            </div>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-[11px] uppercase tracking-wider text-ink-subtle">
              Lifecycle
            </span>
            <div className="inline-flex rounded-md border border-edge bg-panel p-0.5 text-xs">
              <ScopeButton
                active={lifecycleScope === "all"}
                onClick={() => setLifecycleScope("all")}
              >
                All
              </ScopeButton>
              <ScopeButton
                active={lifecycleScope === "live"}
                onClick={() => setLifecycleScope("live")}
              >
                Live
              </ScopeButton>
              <ScopeButton
                active={lifecycleScope === "past"}
                onClick={() => setLifecycleScope("past")}
              >
                Past
              </ScopeButton>
            </div>
          </div>
          <input
            className="input w-72"
            placeholder="Search path / session / task..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </header>

      {items.length === 0 ? (
        <Empty title="No worktrees registered." />
      ) : filtered.length === 0 ? (
        <Empty
          title="No worktrees match this view."
          hint="Switch the scope filter or search text to inspect browse-only roots and older sessions."
        />
      ) : (
        <div className="card p-0 overflow-hidden">
          <table className="w-full text-sm">
            <thead className="text-xs text-ink-subtle bg-panel-high">
              <tr>
                <th className="text-left px-4 py-2 font-medium">Worktree</th>
                <th className="text-left px-4 py-2 font-medium">Kind</th>
                <th className="text-left px-4 py-2 font-medium">Lifecycle</th>
                <th className="text-left px-4 py-2 font-medium">Repo state</th>
                <th className="text-left px-4 py-2 font-medium">Path</th>
                <th className="text-left px-4 py-2 font-medium">Session / Task</th>
                <th className="text-left px-4 py-2 font-medium">Review range</th>
                <th className="text-right px-4 py-2 font-medium">Review</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((w) => {
                const href = `/git/${encodeURIComponent(w.name)}`;
                return (
                  <tr
                    key={w.name}
                    tabIndex={0}
                    onClick={() => navigate(href)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        e.preventDefault();
                        navigate(href);
                      }
                    }}
                    className="border-t border-edge/40 hover:bg-panel-high cursor-pointer focus:outline-none focus-visible:ring-1 focus-visible:ring-accent focus-visible:bg-panel-high"
                  >
                    <td className="px-4 py-2.5">
                      <Link
                        to={href}
                        onClick={(e) => e.stopPropagation()}
                        className="text-ink hover:text-accent"
                      >
                        {w.label}
                      </Link>
                      <div className="text-[11px] text-ink-subtle">
                        <Mono>{w.name}</Mono>
                      </div>
                    </td>
                    <td className="px-4 py-2.5">
                      <span
                        className={`badge ${
                          w.kind === "Main"
                            ? "bg-info-muted/30 border-info text-info"
                            : "bg-edge/40 border-edge-strong text-ink-muted"
                        }`}
                      >
                        {w.kind}
                      </span>
                    </td>
                    <td className="px-4 py-2.5">
                      <WorktreeLifecyclePill worktree={w} />
                    </td>
                    <td className="px-4 py-2.5">
                      <RepoStateCell worktree={w} />
                    </td>
                    <td
                      className="px-4 py-2.5 font-mono text-[11px] text-ink-muted truncate max-w-[280px]"
                      title={w.path}
                    >
                      {w.path}
                    </td>
                    <td className="px-4 py-2.5 text-xs">
                      {w.session_id ? (
                        <Link
                          to={`/sessions/${w.session_id}`}
                          onClick={(e) => e.stopPropagation()}
                          className="text-accent hover:underline font-mono"
                        >
                          {w.session_id.slice(0, 12)}...
                        </Link>
                      ) : (
                        <span className="text-ink-subtle">-</span>
                      )}
                      {w.task_id && (
                        <div>
                          <Link
                            to={`/tasks/${w.task_id}`}
                            onClick={(e) => e.stopPropagation()}
                            className="text-ink-muted hover:text-accent font-mono text-[11px]"
                          >
                            {w.task_id}
                          </Link>
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-2.5">
                      {w.base_sha ? (
                        <div className="flex items-center gap-2 text-xs">
                          <Mono className="text-ink-muted">
                            {shortSha(w.base_sha)}
                          </Mono>
                          <span className="text-ink-subtle">to</span>
                          <span className="badge bg-ok-muted/20 border-ok text-ok">
                            HEAD
                          </span>
                        </div>
                      ) : (
                        <span className="badge bg-panel-high border-edge text-ink-subtle">
                          Browse only
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-2.5 text-right">
                      <Link
                        to={href}
                        onClick={(e) => e.stopPropagation()}
                        className="btn text-xs py-1"
                      >
                        Review
                      </Link>
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

function worktreeLifecycle(
  worktree: WorktreeListEntry,
): "root" | "live" | "past" | "unknown" {
  if (worktree.kind === "Main") return "root";
  if (!worktree.session_state) return "unknown";
  return isLiveSessionState(worktree.session_state) ? "live" : "past";
}

function isLiveSessionState(state: string): boolean {
  return (
    state === "Active" ||
    state === "Running" ||
    state === "Spawning" ||
    state === "Paused"
  );
}

function matchesLifecycleScope(
  worktree: WorktreeListEntry,
  scope: LifecycleScope,
): boolean {
  if (scope === "all") return true;
  const lifecycle = worktreeLifecycle(worktree);
  if (scope === "live") return lifecycle === "live";
  return lifecycle === "past";
}

function WorktreeLifecyclePill({
  worktree,
}: {
  worktree: WorktreeListEntry;
}) {
  const lifecycle = worktreeLifecycle(worktree);
  const label =
    lifecycle === "root"
      ? "Root"
      : lifecycle === "live"
        ? "Live"
        : lifecycle === "past"
          ? "Past"
          : "Unknown";
  return (
    <span
      className={clsx(
        "badge text-[11px]",
        lifecycle === "live" && "bg-ok-muted/20 border-ok text-ok",
        lifecycle === "past" && "bg-panel-high border-edge text-ink-subtle",
        lifecycle === "root" && "bg-info-muted/30 border-info text-info",
        lifecycle === "unknown" && "bg-warn-muted/20 border-warn text-warn",
      )}
      title={
        lifecycle === "root"
          ? "Operator-allowed repository root"
          : worktree.session_state
            ? `Owning session is ${worktree.session_state}`
            : "Owning session lifecycle was not recorded"
      }
    >
      {label}
    </span>
  );
}

function RepoStateCell({ worktree }: { worktree: WorktreeListEntry }) {
  const dirty = worktree.observed_dirty_paths;
  if (worktree.kind !== "Main") {
    return (
      <span className="text-xs text-ink-subtle">
        Session HEAD resolves on detail
      </span>
    );
  }
  if (!worktree.observed_head_sha) {
    return (
      <span className="badge bg-warn-muted/20 border-warn text-warn">
        Not probed
      </span>
    );
  }
  return (
    <div className="flex flex-col items-start gap-1 text-xs">
      <div className="flex items-center gap-2">
        <Mono className="text-ink-muted">
          {shortSha(worktree.observed_head_sha)}
        </Mono>
        <span
          className={clsx(
            "badge text-[11px]",
            dirty && dirty > 0
              ? "bg-warn-muted/20 border-warn text-warn"
              : "bg-ok-muted/20 border-ok text-ok",
          )}
        >
          {dirty && dirty > 0 ? `${dirty} dirty` : "Clean"}
        </span>
      </div>
      <span className="text-[11px] text-ink-subtle">
        {worktree.observed_branch ?? "(detached)"}
      </span>
    </div>
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
      className={`rounded px-2.5 py-1 ${
        active
          ? "bg-accent text-white"
          : "text-ink-muted hover:bg-panel-high hover:text-ink"
      }`}
    >
      {children}
    </button>
  );
}
