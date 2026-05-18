import { useMemo, useState } from "react";
import clsx from "clsx";

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

type DiffViewMode = "unified" | "split" | "raw";

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
  const [mode, setMode] = useState<DiffViewMode>("unified");
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
        <span className="text-ink-subtle">to</span>
        <Mono className="text-ink-muted">{shortSha(diff.to_sha)}</Mono>
        <div className="inline-flex rounded-md border border-edge bg-panel p-0.5 text-[11px]">
          <DiffModeButton
            active={mode === "unified"}
            onClick={() => setMode("unified")}
          >
            Inline
          </DiffModeButton>
          <DiffModeButton
            active={mode === "split"}
            onClick={() => setMode("split")}
          >
            Side by side
          </DiffModeButton>
          <DiffModeButton
            active={mode === "raw"}
            onClick={() => setMode("raw")}
          >
            Raw
          </DiffModeButton>
        </div>
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
                mode={mode}
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
  mode: DiffViewMode;
  isOpen: boolean;
  onToggle: () => void;
}

function FileDiff({ file, mode, isOpen, onToggle }: FileDiffProps) {
  const rows = useMemo(() => parseUnifiedDiff(file.hunk), [file.hunk]);
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
        <div className="font-mono text-[11.5px] leading-relaxed overflow-x-auto scroll-thin">
          {file.hunk.length === 0 ? (
            <span className="block px-3 py-2 text-ink-subtle italic">
              (binary or empty diff)
            </span>
          ) : mode === "split" ? (
            <SplitDiff rows={rows} />
          ) : mode === "raw" ? (
            <RawDiff hunk={file.hunk} />
          ) : (
            <UnifiedDiff rows={rows} />
          )}
        </div>
      )}
    </div>
  );
}

function UnifiedDiff({ rows }: { rows: DiffRow[] }) {
  return (
    <>
      {rows.map((row, i) => (
        <div
          key={i}
          className={clsx(
            "grid grid-cols-[3.25rem_3.25rem_2rem_minmax(max-content,1fr)] border-l-2",
            rowTone(row.kind),
          )}
        >
          <span className="select-none text-right pr-2 text-ink-subtle/70 border-r border-edge/60">
            {row.oldLine ?? ""}
          </span>
          <span className="select-none text-right pr-2 text-ink-subtle/70 border-r border-edge/60">
            {row.newLine ?? ""}
          </span>
          <span className="select-none text-center text-ink-subtle/80 border-r border-edge/60">
            {rowMarker(row)}
          </span>
          <span className="px-3 whitespace-pre">{row.text || " "}</span>
        </div>
      ))}
    </>
  );
}

function SplitDiff({ rows }: { rows: DiffRow[] }) {
  const splitRows = useMemo(() => toSplitRows(rows), [rows]);
  return (
    <>
      {splitRows.map((row, i) =>
        row.kind === "meta" || row.kind === "hunk" ? (
          <div
            key={i}
            className={clsx(
              "grid grid-cols-[minmax(max-content,1fr)] border-l-2 px-3 py-0.5 whitespace-pre",
              row.kind === "hunk"
                ? "text-info bg-info-muted/15 border-info font-semibold"
                : "text-ink-subtle bg-panel border-edge",
            )}
          >
            {row.text || " "}
          </div>
        ) : (
          <div
            key={i}
            className="grid grid-cols-[3.25rem_2rem_minmax(18rem,1fr)_3.25rem_2rem_minmax(18rem,1fr)]"
          >
            <span className="select-none text-right pr-2 text-ink-subtle/70 border-r border-edge/60 bg-panel">
              {row.oldLine ?? ""}
            </span>
            <span
              className={clsx(
                "select-none text-center border-r border-edge/60",
                row.oldKind === "del"
                  ? "text-bad bg-bad-muted/20"
                  : "text-ink-subtle/70 bg-panel",
              )}
            >
              {row.oldKind === "del" ? "-" : ""}
            </span>
            <span
              className={clsx(
                "px-3 whitespace-pre border-r border-edge/60",
                row.oldKind === "del"
                  ? "text-bad bg-bad-muted/20"
                  : "text-ink-muted bg-panel",
              )}
            >
              {row.oldText || " "}
            </span>
            <span className="select-none text-right pr-2 text-ink-subtle/70 border-r border-edge/60 bg-panel">
              {row.newLine ?? ""}
            </span>
            <span
              className={clsx(
                "select-none text-center border-r border-edge/60",
                row.newKind === "add"
                  ? "text-ok bg-ok-muted/20"
                  : "text-ink-subtle/70 bg-panel",
              )}
            >
              {row.newKind === "add" ? "+" : ""}
            </span>
            <span
              className={clsx(
                "px-3 whitespace-pre",
                row.newKind === "add"
                  ? "text-ok bg-ok-muted/20"
                  : "text-ink-muted bg-panel",
              )}
            >
              {row.newText || " "}
            </span>
          </div>
        ),
      )}
    </>
  );
}

function RawDiff({ hunk }: { hunk: string }) {
  return <TerminalDiffBlock diffText={hunk} />;
}

export function TerminalDiffBlock({ diffText }: { diffText: string }) {
  return (
    <>
      {diffText.split("\n").map((line, i) => {
        const kind = classifyRawLine(line);
        return (
          <div
            key={i}
            className={clsx("px-3 whitespace-pre border-l-2", rowTone(kind))}
          >
            {line || " "}
          </div>
        );
      })}
    </>
  );
}

type DiffRowKind = "meta" | "hunk" | "add" | "del" | "context";

interface DiffRow {
  oldLine: number | null;
  newLine: number | null;
  text: string;
  kind: DiffRowKind;
}

interface SplitRow {
  kind: "meta" | "hunk" | "context" | "change";
  text: string;
  oldLine: number | null;
  newLine: number | null;
  oldText: string;
  newText: string;
  oldKind: DiffRowKind | null;
  newKind: DiffRowKind | null;
}

function parseUnifiedDiff(hunk: string): DiffRow[] {
  let oldLine = 0;
  let newLine = 0;
  return hunk.split("\n").map((text) => {
    const header = /^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(text);
    if (header) {
      oldLine = Number(header[1]);
      newLine = Number(header[2]);
      return { oldLine: null, newLine: null, text, kind: "hunk" };
    }
    if (
      text.startsWith("diff --git") ||
      text.startsWith("index ") ||
      text.startsWith("new file mode ") ||
      text.startsWith("deleted file mode ") ||
      text.startsWith("similarity index ") ||
      text.startsWith("rename from ") ||
      text.startsWith("rename to ") ||
      text.startsWith("+++") ||
      text.startsWith("---")
    ) {
      return { oldLine: null, newLine: null, text, kind: "meta" };
    }
    if (text.startsWith("+")) {
      const row = { oldLine: null, newLine, text, kind: "add" as const };
      newLine += 1;
      return row;
    }
    if (text.startsWith("-")) {
      const row = { oldLine, newLine: null, text, kind: "del" as const };
      oldLine += 1;
      return row;
    }
    const row = {
      oldLine: oldLine || null,
      newLine: newLine || null,
      text,
      kind: "context" as const,
    };
    if (oldLine > 0) oldLine += 1;
    if (newLine > 0) newLine += 1;
    return row;
  });
}

function toSplitRows(rows: DiffRow[]): SplitRow[] {
  const out: SplitRow[] = [];
  let i = 0;
  while (i < rows.length) {
    const row = rows[i];
    if (row.kind === "meta" || row.kind === "hunk") {
      out.push({
        kind: row.kind,
        text: row.text,
        oldLine: null,
        newLine: null,
        oldText: "",
        newText: "",
        oldKind: null,
        newKind: null,
      });
      i += 1;
      continue;
    }
    if (row.kind === "del" || row.kind === "add") {
      const dels: DiffRow[] = [];
      const adds: DiffRow[] = [];
      while (rows[i]?.kind === "del") {
        dels.push(rows[i]);
        i += 1;
      }
      while (rows[i]?.kind === "add") {
        adds.push(rows[i]);
        i += 1;
      }
      const n = Math.max(dels.length, adds.length);
      for (let j = 0; j < n; j += 1) {
        const oldRow = dels[j] ?? null;
        const newRow = adds[j] ?? null;
        out.push({
          kind: "change",
          text: "",
          oldLine: oldRow?.oldLine ?? null,
          newLine: newRow?.newLine ?? null,
          oldText: oldRow ? displayCode(oldRow) : "",
          newText: newRow ? displayCode(newRow) : "",
          oldKind: oldRow?.kind ?? null,
          newKind: newRow?.kind ?? null,
        });
      }
      continue;
    }
    out.push({
      kind: "context",
      text: "",
      oldLine: row.oldLine,
      newLine: row.newLine,
      oldText: displayCode(row),
      newText: displayCode(row),
      oldKind: row.kind,
      newKind: row.kind,
    });
    i += 1;
  }
  return out;
}

function displayCode(row: DiffRow): string {
  if (row.kind === "add" || row.kind === "del") {
    return row.text.slice(1);
  }
  if (row.kind === "context" && row.text.startsWith(" ")) {
    return row.text.slice(1);
  }
  return row.text;
}

function classifyRawLine(line: string): DiffRowKind {
  if (line.startsWith("@@")) return "hunk";
  if (line.startsWith("+") && !line.startsWith("+++")) return "add";
  if (line.startsWith("-") && !line.startsWith("---")) return "del";
  if (
    line.startsWith("diff --git") ||
    line.startsWith("index ") ||
    line.startsWith("new file mode ") ||
    line.startsWith("deleted file mode ") ||
    line.startsWith("+++") ||
    line.startsWith("---")
  ) {
    return "meta";
  }
  return "context";
}

function rowTone(kind: DiffRowKind): string {
  switch (kind) {
    case "meta":
      return "text-ink-subtle bg-panel border-edge";
    case "add":
      return "text-ok bg-ok-muted/20 border-ok";
    case "del":
      return "text-bad bg-bad-muted/20 border-bad";
    case "hunk":
      return "text-info bg-info-muted/15 border-info font-semibold";
    default:
      return "text-ink-muted bg-panel border-transparent";
  }
}

function rowMarker(row: DiffRow): string {
  if (row.kind === "add") return "+";
  if (row.kind === "del") return "-";
  return "";
}

function DiffModeButton({
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
