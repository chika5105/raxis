import { useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";

import { ApiError, dashboardApi } from "@/api/client";
import { CopyButton } from "@/components/CopyButton";
import { DiffView } from "@/components/DiffView";
import { Empty } from "@/components/Empty";
import { ErrorBox } from "@/components/ErrorBox";
import { Mono } from "@/components/Mono";
import { RepoBrowser } from "@/components/RepoBrowser";
import { RepoFileTree } from "@/components/RepoFileTree";
import { PageSpinner } from "@/components/Spinner";
import { fmtRelative, plural, shortSha } from "@/lib/format";

type Tab = "files" | "browse" | "log" | "diff" | "range";

/// Operator-facing repo viewer for a single worktree.
///
/// Layout:
///   * Header: breadcrumbs, copyable path, HEAD/branch/base
///     summary, and (when applicable) deep links to the owning
///     session and task.
///   * Tabs:
///       - **Files**: a tree-shaped list of files the executor
///         has changed relative to the worktree's base SHA,
///         derived from the same diff payload the Diff tab
///         renders. Clicking a file scrolls the corresponding
///         hunk into view.
///       - **Browse**: full lazy-loaded file-tree browser backed
///         by `GET /api/git/worktrees/:name/tree?path=…` and
///         `GET /api/git/worktrees/:name/file?path=…`. Lets the
///         operator inspect any file in the worktree, not just
///         the ones the executor touched.
///       - **Log**: `git log -n 100` against the worktree.
///       - **Diff vs base**: the same diff the operator sees on
///         the Files tab, but expanded inline.
///       - **Range diff**: arbitrary sha1..sha2 comparison.
export function WorktreeDetailPage() {
  const { name = "" } = useParams<{ name: string }>();
  const [tab, setTab] = useState<Tab>("files");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  // Used by the "Files" tab to scroll the matching FileDiff
  // into view in the inline diff list when the operator picks
  // a file in the tree.
  const [scrollTo, setScrollTo] = useState<string | null>(null);

  const detail = useQuery({
    queryKey: ["worktree", name],
    queryFn: ({ signal }) => dashboardApi.git.get(name, signal),
    refetchInterval: 10_000,
    enabled: name.length > 0,
  });

  const log = useQuery({
    queryKey: ["worktree-log", name],
    queryFn: ({ signal }) => dashboardApi.git.log(name, 100, signal),
    enabled: tab === "log" && name.length > 0,
    refetchInterval: tab === "log" ? 10_000 : false,
  });

  // The diff against the base SHA powers BOTH the Files and the
  // Diff tabs. Loading it eagerly on both means the operator
  // can switch tabs without an extra spinner.
  const defaultDiff = useQuery({
    queryKey: ["worktree-diff-default", name],
    queryFn: ({ signal }) => dashboardApi.git.diffDefault(name, signal),
    enabled: (tab === "files" || tab === "diff") && name.length > 0,
    refetchInterval: tab === "files" || tab === "diff" ? 15_000 : false,
    retry: false,
  });

  const rangeDiff = useQuery({
    queryKey: ["worktree-diff-range", name, from, to],
    queryFn: ({ signal }) => dashboardApi.git.diffRange(name, from, to, signal),
    enabled: tab === "range" && from.length === 40 && to.length === 40,
    retry: false,
  });

  if (detail.isPending) return <PageSpinner />;
  if (detail.error)
    return <ErrorBox error={detail.error} onRetry={() => detail.refetch()} />;
  const w = detail.data;

  return (
    <div className="space-y-5">
      <header className="flex items-start justify-between gap-3 flex-wrap">
        <div>
          <div className="flex items-center gap-2 text-sm text-ink-subtle">
            <Link to="/git" className="hover:text-accent">
              Git Worktrees
            </Link>
            <span>/</span>
            <Mono>{w.name}</Mono>
          </div>
          <h1 className="mt-1 text-xl font-semibold text-ink">{w.label}</h1>
          <div className="mt-2 flex items-center gap-2 flex-wrap text-xs">
            <span className="badge bg-info-muted/30 border-info text-info">
              {w.kind}
            </span>
            <Mono className="text-ink-muted">{w.path}</Mono>
            <CopyButton value={w.path} />
            {w.session_id && (
              <Link
                to={`/sessions/${w.session_id}`}
                className="text-accent hover:underline"
              >
                · session {w.session_id.slice(0, 12)}…
              </Link>
            )}
            {w.task_id && (
              <Link
                to={`/tasks/${w.task_id}`}
                className="text-accent hover:underline"
              >
                · task {w.task_id}
              </Link>
            )}
          </div>
        </div>
        <div className="card p-3 text-xs space-y-1.5 min-w-[260px]">
          <Row
            label="HEAD"
            value={
              <span className="font-mono text-ink-muted flex items-center gap-1">
                {shortSha(w.head_sha)}
                {w.head_sha && <CopyButton value={w.head_sha} />}
              </span>
            }
          />
          <Row label="Branch" value={w.branch ?? "(detached)"} mono />
          <Row
            label="Base"
            value={
              <span className="font-mono text-ink-muted flex items-center gap-1">
                {shortSha(w.base_sha)}
                {w.base_sha && <CopyButton value={w.base_sha} />}
              </span>
            }
          />
          <Row
            label="Ahead / Behind"
            value={
              w.ahead != null && w.behind != null ? (
                <span>
                  <span className="text-ok">+{w.ahead}</span> /{" "}
                  <span className="text-warn">−{w.behind}</span>
                </span>
              ) : (
                "—"
              )
            }
          />
          {w.status_lines.length > 0 && (
            <Row
              label="Status"
              value={
                <pre className="text-[11px] font-mono text-warn whitespace-pre-wrap">
                  {w.status_lines.join("\n")}
                </pre>
              }
            />
          )}
        </div>
      </header>

      {/* Tabs */}
      <div role="tablist" className="flex border-b border-edge text-sm">
        <TabButton active={tab === "files"} onClick={() => setTab("files")}>
          Files
        </TabButton>
        <TabButton active={tab === "browse"} onClick={() => setTab("browse")}>
          Browse
        </TabButton>
        <TabButton active={tab === "log"} onClick={() => setTab("log")}>
          Log
        </TabButton>
        <TabButton active={tab === "diff"} onClick={() => setTab("diff")}>
          Diff vs base
        </TabButton>
        <TabButton active={tab === "range"} onClick={() => setTab("range")}>
          Range diff
        </TabButton>
      </div>

      {tab === "files" && (
        <FilesTab
          isPending={defaultDiff.isPending}
          error={defaultDiff.error}
          data={defaultDiff.data}
          baseSha={w.base_sha}
          scrollTo={scrollTo}
          onSelectFile={setScrollTo}
        />
      )}

      {tab === "browse" && <RepoBrowser worktreeName={w.name} />}

      {tab === "log" && (
        <>
          {log.isPending ? (
            <PageSpinner />
          ) : log.error ? (
            <ErrorBox error={log.error} onRetry={() => log.refetch()} />
          ) : log.data.length === 0 ? (
            <Empty title="No commits in this worktree." />
          ) : (
            <ul className="card p-0 overflow-hidden divide-y divide-edge/40">
              {log.data.map((c) => (
                <li
                  key={c.sha}
                  className="px-4 py-2.5 flex items-center gap-3 hover:bg-panel-high"
                >
                  <Mono className="text-ink-muted w-20 text-right">
                    {c.short_sha}
                  </Mono>
                  <span className="flex-1 text-sm text-ink truncate">
                    {c.subject}
                  </span>
                  <span className="text-xs text-ink-subtle">{c.author}</span>
                  <span className="text-xs text-ink-subtle">
                    {fmtRelative(c.at)}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </>
      )}

      {tab === "diff" && (
        <>
          {defaultDiff.isPending ? (
            <PageSpinner />
          ) : defaultDiff.error ? (
            <DiffErrorOrEmpty error={defaultDiff.error} baseSha={w.base_sha} />
          ) : (
            <DiffView diff={defaultDiff.data} />
          )}
        </>
      )}

      {tab === "range" && (
        <>
          <div className="card p-3 flex items-center gap-2 flex-wrap">
            <input
              className="input font-mono text-xs w-[26rem]"
              placeholder="from sha (40 hex chars)"
              value={from}
              onChange={(e) => setFrom(e.target.value.trim())}
            />
            <span className="text-ink-subtle">→</span>
            <input
              className="input font-mono text-xs w-[26rem]"
              placeholder="to sha (40 hex chars)"
              value={to}
              onChange={(e) => setTo(e.target.value.trim())}
            />
          </div>
          {from.length !== 40 || to.length !== 40 ? (
            <Empty title="Enter 40-char from/to SHAs to compute the diff." />
          ) : rangeDiff.isPending ? (
            <PageSpinner />
          ) : rangeDiff.error ? (
            <ErrorBox error={rangeDiff.error} />
          ) : (
            <DiffView diff={rangeDiff.data} />
          )}
        </>
      )}
    </div>
  );
}

interface FilesTabProps {
  isPending: boolean;
  error: unknown;
  data: WorktreeDiffData | undefined;
  baseSha: string | null;
  scrollTo: string | null;
  onSelectFile: (path: string | null) => void;
}

type WorktreeDiffData = Awaited<
  ReturnType<typeof dashboardApi.git.diffDefault>
>;

function FilesTab({
  isPending,
  error,
  data,
  baseSha,
  scrollTo,
  onSelectFile,
}: FilesTabProps) {
  // When the operator clicks a file in the tree, scroll the
  // matching anchor on the right pane into view.
  const inlineRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!scrollTo) return;
    const el = inlineRef.current?.querySelector<HTMLDivElement>(
      `[data-file-path="${cssEscape(scrollTo)}"]`,
    );
    if (el) {
      el.scrollIntoView({ behavior: "smooth", block: "start" });
      el.classList.add("ring-2", "ring-accent");
      window.setTimeout(() => {
        el.classList.remove("ring-2", "ring-accent");
      }, 1_500);
    }
  }, [scrollTo]);

  if (isPending) return <PageSpinner />;
  if (error) {
    return <DiffErrorOrEmpty error={error} baseSha={baseSha} />;
  }
  if (!data) return <PageSpinner />;
  const diff = data;

  return (
    <div className="space-y-3">
      {diff.files.length === 0 ? (
        <Empty
          title="No files changed against the base SHA."
          hint="The executor hasn't touched any tracked files in this worktree yet, or the base SHA already matches HEAD."
        />
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-[320px_1fr] gap-4">
          <aside className="card p-3 self-start xl:sticky xl:top-2 max-h-[80vh] overflow-y-auto scroll-thin">
            <header className="text-xs text-ink-subtle uppercase tracking-wider mb-2">
              Changed files · {plural(diff.files.length, "file")}
            </header>
            <RepoFileTree diff={diff} onSelect={onSelectFile} />
          </aside>
          <div ref={inlineRef} className="space-y-3">
            <DiffView diff={diff} />
            <p className="text-[11px] text-ink-subtle italic">
              Showing files the executor touched relative to the base SHA. Use
              the <strong>Browse</strong> tab to inspect any file in the
              worktree, including unchanged files.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

/// Single-source-of-truth empty/error renderer for the
/// `diff_default` endpoint, which is allowed to 404 with
/// "default-diff" when the worktree has no recorded base SHA
/// (typically the main operator-allowed root, which has no
/// upstream pin).
function DiffErrorOrEmpty({
  error,
  baseSha,
}: {
  error: unknown;
  baseSha: string | null;
}) {
  const is404 =
    error instanceof ApiError &&
    error.status === 404 &&
    (error.detail.toLowerCase().includes("default-diff") || baseSha == null);
  if (is404) {
    return (
      <Empty
        title="This worktree has no recorded base SHA."
        hint={
          <>
            The main operator-allowed root tracks{" "}
            <code className="font-mono">origin/main</code> directly; only
            session worktrees record a base SHA the executor diffs against. Use
            the <strong>Range diff</strong> tab to compare two arbitrary commits
            in this worktree.
          </>
        }
      />
    );
  }
  return <ErrorBox error={error} />;
}

/// CSS.escape polyfill for older runtimes. The querySelector
/// path argument can contain `/`, `.`, etc., none of which need
/// escaping in CSS attribute-equality selectors — but quoting
/// embedded double-quotes is still required for paths that
/// contain them.
function cssEscape(s: string): string {
  return s.replace(/"/g, '\\"');
}

interface TabButtonProps {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}

function TabButton({ active, onClick, children }: TabButtonProps) {
  return (
    <button
      type="button"
      role="tab"
      aria-selected={active}
      onClick={onClick}
      className={`px-4 py-2 -mb-px border-b-2 focus:outline-none focus-visible:bg-panel-high ${
        active
          ? "text-ink border-accent"
          : "text-ink-muted border-transparent hover:text-ink"
      }`}
    >
      {children}
    </button>
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
    <div className="flex items-start gap-3">
      <span className="w-28 text-ink-subtle uppercase tracking-wider text-[10px] mt-0.5 shrink-0">
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
