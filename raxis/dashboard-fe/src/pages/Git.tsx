import { Fragment, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import clsx from "clsx";

import { dashboardApi } from "@/api/client";
import { CopyButton } from "@/components/CopyButton";
import { Empty } from "@/components/Empty";
import { ErrorBox } from "@/components/ErrorBox";
import { Mono } from "@/components/Mono";
import { PageSpinner } from "@/components/Spinner";
import { shortSha } from "@/lib/format";
import type { WorktreeListEntry } from "@/types/api";

type WorktreeScope = "all" | "reviewable" | "worktree" | "repository";
type LifecycleScope = "all" | "live" | "past";
type GroupScope = "name" | "id";
const EMPTY_WORKTREES: WorktreeListEntry[] = [];

export function GitPage() {
  const navigate = useNavigate();
  const [search, setSearch] = useState("");
  const [scope, setScope] = useState<WorktreeScope>("all");
  const [lifecycleScope, setLifecycleScope] =
    useState<LifecycleScope>("all");
  const [groupBy, setGroupBy] = useState<GroupScope>("name");
  const [workspaceName, setWorkspaceName] = useState("All");
  const [collapsedGroups, setCollapsedGroups] = useState<
    Record<string, boolean>
  >({});
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
      if (scope === "worktree" && worktreeSurface(w) !== "Worktree") {
        return false;
      }
      if (scope === "repository" && worktreeSurface(w) === "Worktree") {
        return false;
      }
      if (!matchesLifecycleScope(w, lifecycleScope)) return false;
      if (
        workspaceName !== "All" &&
        (w.initiative_display_name ?? "") !== workspaceName
      ) {
        return false;
      }
      if (!needle) return true;
      return [
        w.name,
        w.label,
        w.kind,
        w.surface ?? "",
        w.repository_id ?? "",
        w.path,
        w.session_id ?? "",
        w.task_id ?? "",
        w.initiative_id ?? "",
        w.initiative_display_name ?? "",
        w.agent_type ?? "",
        w.session_state ?? "",
        w.base_sha ?? "",
        w.comparison_head_sha ?? "",
        w.repository_lifecycle_state ?? "",
        w.repository_publish_state ?? "",
        w.repository_source_url ?? "",
        w.repository_tracking_ref ?? "",
        w.repository_last_error ?? "",
      ]
        .join(" ")
        .toLowerCase()
        .includes(needle);
    });
  }, [items, scope, lifecycleScope, search, workspaceName]);
  const workspaceOptions = useMemo(() => {
    const names = new Set<string>();
    for (const w of items) {
      const name = w.initiative_display_name?.trim();
      if (name) names.add(name);
    }
    return [...names].sort((a, b) => a.localeCompare(b));
  }, [items]);
  const grouped = useMemo(
    () => groupWorktrees(filtered, groupBy),
    [filtered, groupBy],
  );
  const repositoryCount = items.filter(
    (w) => worktreeSurface(w) !== "Worktree",
  ).length;
  const worktreeCount = items.filter(
    (w) => worktreeSurface(w) === "Worktree",
  ).length;
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
          <h1 className="text-xl font-semibold text-ink">
            Repositories & Worktrees
          </h1>
          <p className="text-sm text-ink-muted">
            Managed source repositories, session worktrees, and merged review
            ranges in one place.
          </p>
          <div className="mt-2 flex items-center gap-2 text-xs text-ink-subtle">
            <span className="badge bg-panel-high border-edge text-ink-muted">
              {items.length} total
            </span>
            <span className="badge bg-info-muted/30 border-info text-info">
              {repositoryCount} repositories
            </span>
            <span className="badge bg-info-muted/30 border-info text-info">
              {worktreeCount} worktrees
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
                active={scope === "worktree"}
                onClick={() => setScope("worktree")}
              >
                Worktrees
              </ScopeButton>
              <ScopeButton
                active={scope === "repository"}
                onClick={() => setScope("repository")}
              >
                Repositories
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
          <div className="flex items-center gap-1.5">
            <span className="text-[11px] uppercase tracking-wider text-ink-subtle">
              Group
            </span>
            <div className="inline-flex rounded-md border border-edge bg-panel p-0.5 text-xs">
              <ScopeButton
                active={groupBy === "name"}
                onClick={() => setGroupBy("name")}
              >
                Workspace
              </ScopeButton>
              <ScopeButton
                active={groupBy === "id"}
                onClick={() => setGroupBy("id")}
              >
                ID
              </ScopeButton>
            </div>
          </div>
          <select
            className="input max-w-[220px]"
            value={workspaceName}
            onChange={(e) => setWorkspaceName(e.target.value)}
          >
            <option value="All">All workspaces</option>
            {workspaceOptions.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
          <input
            className="input w-72"
            placeholder="Search repo / workspace / path / session..."
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
        <div className="card p-0 overflow-x-auto overscroll-x-auto scroll-thin">
          <table className="min-w-[1280px] w-full text-sm">
            <thead className="text-xs text-ink-subtle bg-panel-high">
              <tr>
                <th className="text-left px-4 py-2 font-medium">
                  Repository / Worktree
                </th>
                <th className="text-left px-4 py-2 font-medium">Surface</th>
                <th className="text-left px-4 py-2 font-medium">Status</th>
                <th className="text-left px-4 py-2 font-medium">Repo state</th>
                <th className="text-left px-4 py-2 font-medium">Path</th>
                <th className="text-left px-4 py-2 font-medium">Workspace</th>
                <th className="text-left px-4 py-2 font-medium">Session / Task</th>
                <th className="text-left px-4 py-2 font-medium">Review range</th>
                <th className="text-right px-4 py-2 font-medium">Review</th>
              </tr>
            </thead>
            <tbody>
              {grouped.map((group) => (
                <Fragment key={group.key}>
                  <tr className="border-t border-edge/60 bg-panel-high/70">
                    <td colSpan={9} className="px-4 py-2">
                      <button
                        type="button"
                        onClick={() =>
                          setCollapsedGroups((prev) => ({
                            ...prev,
                            [group.key]: !prev[group.key],
                          }))
                        }
                        className="w-full flex items-center justify-between gap-3 text-left focus:outline-none focus-visible:ring-1 focus-visible:ring-accent rounded-sm"
                      >
                        <span className="flex items-center gap-2 min-w-0">
                          <span
                            className="text-ink-subtle w-4 text-center"
                            aria-hidden="true"
                          >
                            {collapsedGroups[group.key] ? "▸" : "▾"}
                          </span>
                          <span className="font-medium text-ink truncate">
                            {group.label}
                          </span>
                          {group.initiativeId && groupBy === "name" && (
                            <Mono className="text-[11px] text-ink-subtle truncate">
                              {group.initiativeId}
                            </Mono>
                          )}
                          {group.initiativeName && groupBy === "id" && (
                            <span className="text-[11px] text-ink-subtle truncate">
                              {group.initiativeName}
                            </span>
                          )}
                        </span>
                        <span className="badge bg-panel border-edge text-ink-muted">
                          {group.items.length}{" "}
                          {group.items.length === 1 ? "item" : "items"}
                        </span>
                      </button>
                    </td>
                  </tr>
                  {!collapsedGroups[group.key] &&
                    group.items.map((w) => {
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
                              {displayNameForWorktree(w)}
                            </Link>
                            <div className="text-[11px] text-ink-subtle flex flex-wrap gap-x-2 gap-y-0.5">
                              {w.repository_id && (
                                <span>
                                  repo <Mono>{w.repository_id}</Mono>
                                </span>
                              )}
                              <Mono>{w.name}</Mono>
                            </div>
                          </td>
                          <td className="px-4 py-2.5">
                            <div className="flex flex-col items-start gap-1">
                              <span
                                className={`badge ${
                                  worktreeSurface(w) !== "Worktree"
                                    ? "bg-info-muted/30 border-info text-info"
                                    : "bg-edge/40 border-edge-strong text-ink-muted"
                                }`}
                              >
                                {worktreeSurface(w)}
                              </span>
                              {w.agent_type && (
                                <span className="text-[11px] text-ink-subtle">
                                  {w.agent_type}
                                </span>
                              )}
                            </div>
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
                            {w.initiative_id && w.initiative_display_name ? (
                              <Link
                                to={`/initiatives/${w.initiative_id}`}
                                onClick={(e) => e.stopPropagation()}
                                className="text-accent hover:underline"
                                title={w.initiative_id}
                              >
                                {w.initiative_display_name}
                              </Link>
                            ) : (
                              <span className="text-ink-subtle">-</span>
                            )}
                            {w.initiative_id && (
                              <div className="font-mono text-[11px] text-ink-subtle break-all">
                                {w.initiative_id}
                              </div>
                            )}
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
                            <ReviewRangeCell worktree={w} />
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
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

interface WorktreeGroup {
  key: string;
  label: string;
  initiativeId?: string;
  initiativeName?: string;
  items: WorktreeListEntry[];
}

function groupWorktrees(
  worktrees: WorktreeListEntry[],
  groupBy: GroupScope,
): WorktreeGroup[] {
  const groups = new Map<string, WorktreeGroup>();
  for (const w of worktrees) {
    const initiativeName = w.initiative_display_name?.trim() || undefined;
    const surface = worktreeSurface(w);
    const key =
      surface === "Repository" && !w.initiative_id
        ? "__repositories"
        : w.initiative_id
          ? groupBy === "id"
            ? `initiative-id:${w.initiative_id}`
            : `initiative-name:${initiativeName ?? "__missing-workspace"}`
          : "__unscoped";
    let group = groups.get(key);
    if (!group) {
      group = {
        key,
        label:
          key === "__repositories"
            ? "Repositories"
            : key === "__unscoped"
              ? "Unscoped worktrees"
              : groupBy === "id"
                ? (w.initiative_id ?? "Initiative")
                : (initiativeName ?? "Workspace unavailable"),
        initiativeId: w.initiative_id ?? undefined,
        initiativeName,
        items: [],
      };
      groups.set(key, group);
    }
    group.items.push(w);
  }
  return [...groups.values()].sort((a, b) => {
    if (a.key === "__repositories") return -1;
    if (b.key === "__repositories") return 1;
    if (a.key === "__unscoped") return 1;
    if (b.key === "__unscoped") return -1;
    return a.label.localeCompare(b.label);
  });
}

function worktreeLifecycle(
  worktree: WorktreeListEntry,
): "repository" | "integration" | "live" | "past" | "unknown" {
  const surface = worktreeSurface(worktree);
  if (surface === "Repository") return "repository";
  if (surface === "Integration") return "integration";
  if (!worktree.session_state) return "unknown";
  return isLiveSessionState(worktree.session_state) ? "live" : "past";
}

function worktreeSurface(
  worktree: WorktreeListEntry,
): "Repository" | "Integration" | "Worktree" {
  if (worktree.surface === "Integration") return "Integration";
  if (worktree.surface === "Repository") return "Repository";
  return worktree.kind === "Main" ? "Repository" : "Worktree";
}

function displayNameForWorktree(worktree: WorktreeListEntry): string {
  const surface = worktreeSurface(worktree);
  if (surface === "Repository") {
    return worktree.repository_id
      ? `Repository: ${worktree.repository_id}`
      : worktree.label;
  }
  if (surface === "Integration") {
    return worktree.initiative_display_name
      ? `Integrated result: ${worktree.initiative_display_name}`
      : worktree.label;
  }
  return worktree.label;
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
    lifecycle === "repository"
      ? "Managed"
      : lifecycle === "integration"
        ? "Integrated"
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
        lifecycle === "repository" &&
          "bg-info-muted/30 border-info text-info",
        lifecycle === "integration" && "bg-ok-muted/20 border-ok text-ok",
        lifecycle === "unknown" && "bg-warn-muted/20 border-warn text-warn",
      )}
      title={
        lifecycle === "repository"
          ? "RAXIS-managed source repository"
          : lifecycle === "integration"
            ? "Merged initiative result ready for repository-level review"
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
  const lifecycle = worktree.repository_lifecycle_state;
  const publish = worktree.repository_publish_state;
  const actions = repoActionCommands(worktree);
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
        {lifecycle && (
          <span
            className={clsx(
              "badge text-[11px]",
              lifecycle === "clean" || lifecycle === "local_only"
                ? "bg-ok-muted/20 border-ok text-ok"
                : lifecycle === "ahead"
                  ? "bg-info-muted/30 border-info text-info"
                  : "bg-warn-muted/20 border-warn text-warn",
            )}
            title={worktree.repository_last_error ?? undefined}
          >
            {repoStateLabel(lifecycle)}
          </span>
        )}
        {publish && (
          <span
            className={clsx(
              "badge text-[11px]",
              publish === "published" || publish === "local_only"
                ? "bg-ok-muted/20 border-ok text-ok"
                : publish === "pending"
                  ? "bg-info-muted/30 border-info text-info"
                  : publish === "failed"
                    ? "bg-bad-muted/20 border-bad text-bad"
                    : "bg-panel-high border-edge text-ink-subtle",
            )}
          >
            publish {repoStateLabel(publish)}
          </span>
        )}
      </div>
      <span className="text-[11px] text-ink-subtle">
        {worktree.observed_branch ?? "(detached)"}
      </span>
      {(worktree.repository_ahead_count || worktree.repository_behind_count) && (
        <span className="text-[11px] text-ink-subtle">
          ahead {worktree.repository_ahead_count ?? 0} · behind{" "}
          {worktree.repository_behind_count ?? 0}
        </span>
      )}
      {worktree.repository_tracking_ref && (
        <span
          className="text-[11px] text-ink-subtle max-w-[180px] truncate"
          title={worktree.repository_tracking_ref}
        >
          {worktree.repository_tracking_ref}
        </span>
      )}
      {worktree.repository_last_error && (
        <span
          className="text-[11px] text-bad max-w-[220px] truncate"
          title={worktree.repository_last_error}
        >
          {worktree.repository_last_error}
        </span>
      )}
      {actions.length > 0 && (
        <div
          className="flex flex-wrap items-center gap-1 pt-0.5"
          onClick={(e) => e.stopPropagation()}
        >
          {actions.map((action) => (
            <span
              key={action.label}
              className="inline-flex items-center gap-1 rounded border border-edge bg-panel px-1.5 py-0.5 text-[11px] text-ink-muted"
              title={action.command}
            >
              {action.label}
              <CopyButton
                value={action.command}
                label={`Copy ${action.label} command`}
                className="w-5 h-5"
              />
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function repoStateLabel(value: string): string {
  return value.replace(/_/g, " ");
}

interface RepoActionCommand {
  label: string;
  command: string;
}

function repoActionCommands(worktree: WorktreeListEntry): RepoActionCommand[] {
  if (worktreeSurface(worktree) !== "Repository" || !worktree.repository_id) {
    return [];
  }
  const repo = worktree.repository_id;
  const actions: RepoActionCommand[] = [
    { label: "Status", command: `raxis repo status ${repo} --remote` },
  ];
  const lifecycle = worktree.repository_lifecycle_state;
  const publish = worktree.repository_publish_state;
  if (lifecycle === "behind") {
    actions.push({ label: "Sync", command: `raxis repo sync ${repo}` });
  }
  if (
    lifecycle === "ahead" ||
    publish === "pending" ||
    publish === "failed"
  ) {
    actions.push({ label: "Publish", command: `raxis repo publish ${repo}` });
  }
  if (
    lifecycle === "dirty" ||
    lifecycle === "diverged" ||
    lifecycle === "missing" ||
    lifecycle === "not_a_git_root" ||
    lifecycle === "remote_unreachable"
  ) {
    actions.push({ label: "Repair", command: "raxis repo repair" });
  }
  if (worktree.path) {
    actions.push({ label: "Open", command: `cd ${shellQuote(worktree.path)}` });
  }
  return actions;
}

function shellQuote(value: string): string {
  return "'" + value.replace(/'/g, "'\\''") + "'";
}

function ReviewRangeCell({ worktree }: { worktree: WorktreeListEntry }) {
  if (!worktree.base_sha) {
    return (
      <span className="badge bg-panel-high border-edge text-ink-subtle">
        Browse only
      </span>
    );
  }
  const toSha = worktree.comparison_head_sha ?? worktree.observed_head_sha;
  return (
    <div className="flex items-center gap-2 text-xs">
      <Mono className="text-ink-muted" title={worktree.base_sha}>
        {shortSha(worktree.base_sha)}
      </Mono>
      <span className="text-ink-subtle">to</span>
      {toSha ? (
        <Mono
          className={clsx(
            "badge",
            worktree.comparison_head_sha
              ? "bg-info-muted/30 border-info text-info"
              : "bg-ok-muted/20 border-ok text-ok",
          )}
          title={toSha}
        >
          {shortSha(toSha)}
        </Mono>
      ) : (
        <span className="badge bg-ok-muted/20 border-ok text-ok">HEAD</span>
      )}
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
