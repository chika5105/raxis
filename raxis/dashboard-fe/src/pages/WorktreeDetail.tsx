import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";

import { dashboardApi } from "@/api/client";
import { CopyButton } from "@/components/CopyButton";
import { DiffView } from "@/components/DiffView";
import { Empty } from "@/components/Empty";
import { ErrorBox } from "@/components/ErrorBox";
import { Mono } from "@/components/Mono";
import { PageSpinner } from "@/components/Spinner";
import { fmtRelative, shortSha } from "@/lib/format";

export function WorktreeDetailPage() {
  const { name = "" } = useParams<{ name: string }>();
  const [tab, setTab] = useState<"log" | "diff" | "range">("log");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");

  const detail = useQuery({
    queryKey: ["worktree", name],
    queryFn: ({ signal }) => dashboardApi.git.get(name, signal),
    enabled: name.length > 0,
  });

  const log = useQuery({
    queryKey: ["worktree-log", name],
    queryFn: ({ signal }) => dashboardApi.git.log(name, 100, signal),
    enabled: tab === "log" && name.length > 0,
  });

  const defaultDiff = useQuery({
    queryKey: ["worktree-diff-default", name],
    queryFn: ({ signal }) => dashboardApi.git.diffDefault(name, signal),
    enabled: tab === "diff" && name.length > 0,
    retry: false,
  });

  const rangeDiff = useQuery({
    queryKey: ["worktree-diff-range", name, from, to],
    queryFn: ({ signal }) => dashboardApi.git.diffRange(name, from, to, signal),
    enabled: tab === "range" && from.length === 40 && to.length === 40,
    retry: false,
  });

  if (detail.isPending) return <PageSpinner />;
  if (detail.error) return <ErrorBox error={detail.error} onRetry={() => detail.refetch()} />;
  const w = detail.data;

  return (
    <div className="space-y-5">
      <header className="flex items-start justify-between gap-3 flex-wrap">
        <div>
          <div className="flex items-center gap-2 text-sm text-ink-subtle">
            <Link to="/git" className="hover:text-accent">Git Worktrees</Link>
            <span>/</span>
            <Mono>{w.name}</Mono>
          </div>
          <h1 className="mt-1 text-xl font-semibold text-ink">{w.label}</h1>
          <div className="mt-2 flex items-center gap-2 flex-wrap text-xs">
            <span className="badge bg-info-muted/30 border-info text-info">{w.kind}</span>
            <Mono className="text-ink-muted">{w.path}</Mono>
            <CopyButton value={w.path} />
          </div>
        </div>
        <div className="card p-3 text-xs space-y-1.5 min-w-[260px]">
          <Row label="HEAD" value={
            <span className="font-mono text-ink-muted flex items-center gap-1">
              {shortSha(w.head_sha)}
              {w.head_sha && <CopyButton value={w.head_sha} />}
            </span>
          } />
          <Row label="Branch" value={w.branch ?? "(detached)"} mono />
          <Row label="Base" value={
            <span className="font-mono text-ink-muted flex items-center gap-1">
              {shortSha(w.base_sha)}
              {w.base_sha && <CopyButton value={w.base_sha} />}
            </span>
          } />
          <Row label="Ahead / Behind" value={
            w.ahead != null && w.behind != null
              ? <span><span className="text-ok">+{w.ahead}</span> / <span className="text-warn">−{w.behind}</span></span>
              : "—"
          } />
          {w.status_lines.length > 0 && (
            <Row label="Status" value={
              <pre className="text-[11px] font-mono text-warn whitespace-pre-wrap">
                {w.status_lines.join("\n")}
              </pre>
            } />
          )}
        </div>
      </header>

      {/* Tabs */}
      <div role="tablist" className="flex border-b border-edge text-sm">
        <Tab active={tab === "log"} onClick={() => setTab("log")}>Log</Tab>
        <Tab active={tab === "diff"} onClick={() => setTab("diff")}>Diff vs base</Tab>
        <Tab active={tab === "range"} onClick={() => setTab("range")}>Range diff</Tab>
      </div>

      {tab === "log" && (
        <>
          {log.isPending ? <PageSpinner />
            : log.error ? <ErrorBox error={log.error} onRetry={() => log.refetch()} />
            : log.data.length === 0 ? <Empty title="No commits in this worktree." />
            : (
              <ul className="card p-0 overflow-hidden divide-y divide-edge/40">
                {log.data.map((c) => (
                  <li key={c.sha} className="px-4 py-2.5 flex items-center gap-3 hover:bg-panel-high">
                    <Mono className="text-ink-muted w-20 text-right">{c.short_sha}</Mono>
                    <span className="flex-1 text-sm text-ink truncate">{c.subject}</span>
                    <span className="text-xs text-ink-subtle">{c.author}</span>
                    <span className="text-xs text-ink-subtle">{fmtRelative(c.at)}</span>
                  </li>
                ))}
              </ul>
            )}
        </>
      )}

      {tab === "diff" && (
        <>
          {defaultDiff.isPending ? <PageSpinner />
            : defaultDiff.error ? <ErrorBox error={defaultDiff.error} />
            : <DiffView diff={defaultDiff.data} />}
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
          ) : rangeDiff.isPending ? <PageSpinner />
            : rangeDiff.error ? <ErrorBox error={rangeDiff.error} />
            : <DiffView diff={rangeDiff.data} />}
        </>
      )}
    </div>
  );
}

function Tab({
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

function Row({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-start gap-3">
      <span className="w-28 text-ink-subtle uppercase tracking-wider text-[10px] mt-0.5 shrink-0">
        {label}
      </span>
      <span className={`flex-1 min-w-0 ${mono ? "font-mono text-ink-muted" : "text-ink"}`}>
        {value}
      </span>
    </div>
  );
}
