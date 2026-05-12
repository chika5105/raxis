import { useMemo, useState } from "react";

import type { WorktreeDiff, WorktreeDiffFile } from "@/types/api";

import { Empty } from "@/components/Empty";
import { Mono } from "@/components/Mono";
import { plural, shortSha } from "@/lib/format";

interface DiffViewProps {
  diff: WorktreeDiff;
  /// When true (default), every file body is open. The operator
  /// can collapse individual files via the per-file toggle. A
  /// header-level "Collapse all" / "Expand all" button lets them
  /// reset.
  defaultOpen?: boolean;
}

/// Unified-diff renderer for a `WorktreeDiff` payload from
/// `GET /api/git/worktrees/:name/diff[/:range]`. Each file
/// shows the path header, status, line counts, and a
/// collapsible hunk pane. The hunk text is colored per line:
///
///   * `+` insertion (green)
///   * `-` deletion (red)
///   * `@@` hunk header (info)
///   * everything else (subtle context)
///
/// The kernel-side wrapper truncates per-file hunks at 64 KiB
/// (see `raxis/crates/dashboard-kernel/src/git.rs::
/// MAX_PER_FILE_DIFF_BYTES`), so the operator may see a
/// `[diff truncated by raxis-dashboard]` marker on very large
/// changes. We display that verbatim — surfacing the
/// truncation is more useful than hiding it.
export function DiffView({ diff, defaultOpen = true }: DiffViewProps) {
  const totals = useMemo(() => {
    let ins = 0;
    let del = 0;
    const groups = new Map<string, WorktreeDiffFile[]>();
    for (const f of diff.files) {
      ins += f.insertions;
      del += f.deletions;
      const dir = f.path.includes("/")
        ? f.path.slice(0, f.path.lastIndexOf("/"))
        : "(root)";
      const existing = groups.get(dir);
      if (existing) {
        existing.push(f);
      } else {
        groups.set(dir, [f]);
      }
    }
    return {
      ins,
      del,
      groupedByDir: Array.from(groups.entries()).sort(([a], [b]) =>
        a.localeCompare(b),
      ),
    };
  }, [diff.files]);

  const [open, setOpen] = useState<Record<string, boolean>>(() =>
    Object.fromEntries(diff.files.map((f) => [f.path, defaultOpen])),
  );

  const setAll = (next: boolean) =>
    setOpen(Object.fromEntries(diff.files.map((f) => [f.path, next])));

  return (
    <div className="space-y-4">
      <header className="card p-3 flex items-center gap-3 text-xs flex-wrap">
        <Mono className="text-ink-muted">{shortSha(diff.from_sha)}</Mono>
        <span className="text-ink-subtle">→</span>
        <Mono className="text-ink-muted">{shortSha(diff.to_sha)}</Mono>
        <span className="ml-auto flex items-center gap-3 text-ink-subtle">
          <span>{plural(diff.files.length, "file")}</span>
          <span className="text-ok">+{totals.ins}</span>
          <span className="text-bad">−{totals.del}</span>
          {diff.files.length > 1 && (
            <>
              <button
                className="btn text-[11px] py-0.5"
                onClick={() => setAll(true)}
              >
                Expand all
              </button>
              <button
                className="btn text-[11px] py-0.5"
                onClick={() => setAll(false)}
              >
                Collapse all
              </button>
            </>
          )}
        </span>
      </header>

      {diff.files.length === 0 ? (
        <Empty title="No file-level changes." />
      ) : (
        totals.groupedByDir.map(([dir, files]) => (
          <div key={dir} className="space-y-2">
            {totals.groupedByDir.length > 1 && (
              <div className="flex items-center gap-2 text-[11px] text-ink-subtle uppercase tracking-wider px-1">
                <span className="font-mono text-ink-muted">{dir}/</span>
                <span>· {plural(files.length, "file")}</span>
              </div>
            )}
            {files.map((f) => (
              <FileDiff
                key={f.path}
                file={f}
                isOpen={open[f.path] ?? defaultOpen}
                onToggle={() =>
                  setOpen((prev) => ({
                    ...prev,
                    [f.path]: !(prev[f.path] ?? defaultOpen),
                  }))
                }
              />
            ))}
          </div>
        ))
      )}
    </div>
  );
}

interface FileDiffProps {
  file: WorktreeDiffFile;
  isOpen: boolean;
  onToggle: () => void;
}

function FileDiff({ file, isOpen, onToggle }: FileDiffProps) {
  return (
    <div className="card p-0 overflow-hidden" data-file-path={file.path}>
      <header
        className="px-3 py-2 border-b border-edge bg-panel-high flex items-center gap-3 text-xs cursor-pointer hover:bg-panel"
        onClick={onToggle}
        role="button"
        aria-expanded={isOpen}
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            onToggle();
          }
        }}
      >
        <span
          className="text-ink-subtle font-mono w-4 select-none"
          aria-hidden="true"
        >
          {isOpen ? "▾" : "▸"}
        </span>
        <span
          className={`badge ${
            file.status === "A"
              ? "bg-ok-muted/30 border-ok text-ok"
              : file.status === "D"
                ? "bg-bad-muted/30 border-bad text-bad"
                : file.status === "M"
                  ? "bg-info-muted/30 border-info text-info"
                  : "bg-edge/40 border-edge-strong text-ink-muted"
          }`}
        >
          {file.status}
        </span>
        <Mono className="text-ink truncate flex-1">{file.path}</Mono>
        <span className="text-ok">+{file.insertions}</span>
        <span className="text-bad">−{file.deletions}</span>
      </header>
      {isOpen && (
        <pre className="font-mono text-[11.5px] leading-relaxed overflow-x-auto scroll-thin px-0">
          {file.hunk.length === 0 ? (
            <span className="block px-3 py-2 text-ink-subtle italic">
              (binary or empty diff)
            </span>
          ) : (
            file.hunk.split("\n").map((line, i) => {
              const tone =
                line.startsWith("+++") || line.startsWith("---")
                  ? "text-ink-subtle bg-panel"
                  : line.startsWith("+")
                    ? "text-ok bg-ok-muted/15"
                    : line.startsWith("-")
                      ? "text-bad bg-bad-muted/15"
                      : line.startsWith("@@")
                        ? "text-info bg-info-muted/15 font-semibold"
                        : "text-ink-muted";
              return (
                <span key={i} className={`block px-3 ${tone}`}>
                  {line || " "}
                </span>
              );
            })
          )}
        </pre>
      )}
    </div>
  );
}
