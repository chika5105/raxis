import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import Editor from "@monaco-editor/react";

import { dashboardApi } from "@/api/client";
import { CopyButton } from "@/components/CopyButton";
import { Empty } from "@/components/Empty";
import { ErrorBox } from "@/components/ErrorBox";
import { Mono } from "@/components/Mono";
import { PageSpinner } from "@/components/Spinner";
import { fmtBytes } from "@/lib/format";
import { detectMonacoLanguage } from "@/lib/monaco-language";
import { useTheme } from "@/lib/theme-context";
import type { WorktreeTree, WorktreeTreeEntry } from "@/types/api";

interface RepoBrowserProps {
  /// Worktree slug — same one the diff/log endpoints use.
  worktreeName: string;
}

/// Operator-facing repo browser backed by the shipped backend
/// endpoints `GET /api/git/worktrees/:name/tree?path=…` and
/// `GET /api/git/worktrees/:name/file?path=…`.
///
/// The tree endpoint is lazy: each directory is fetched on first
/// expansion (rather than walking the whole tree on first paint).
/// The file endpoint returns either UTF-8 text or base64-encoded
/// raw bytes; the renderer chooses an appropriate view.
///
/// Backend safety contract (validated in
/// `crates/dashboard/src/routes/git.rs::validate_relative_path`
/// and the data-layer canonicalization check):
///   * Paths are forward-slash separated and root-relative.
///   * No `..`, `.`, NUL, leading `/`, `.git`, or backslash.
///   * Containment under `policy.allowed_worktree_roots()` is
///     enforced server-side, so a malicious operator cannot
///     escape the worktree even if they bypass the route layer.
export function RepoBrowser({ worktreeName }: RepoBrowserProps) {
  const [selected, setSelected] = useState<string | null>(null);

  return (
    <div className="grid grid-cols-1 xl:grid-cols-[320px_1fr] gap-4">
      <aside className="card p-3 self-start xl:sticky xl:top-2 max-h-[80vh] overflow-y-auto scroll-thin">
        <header className="text-xs text-ink-subtle uppercase tracking-wider mb-2">
          Repository tree
        </header>
        <DirectoryNode
          worktreeName={worktreeName}
          path=""
          name=""
          depth={0}
          initialOpen
          selected={selected}
          onSelect={setSelected}
        />
      </aside>
      <div className="min-w-0">
        {selected ? (
          <FileView worktreeName={worktreeName} path={selected} />
        ) : (
          <Empty
            title="Select a file to view its contents."
            hint="The repo tree on the left lists every file the kernel exposes for this worktree, sandboxed to the operator-allowed roots."
          />
        )}
      </div>
    </div>
  );
}

interface DirectoryNodeProps {
  worktreeName: string;
  /// Forward-slash relative path (`""` ⇒ worktree root).
  path: string;
  /// Display name for this row (`""` for the synthetic root).
  name: string;
  depth: number;
  initialOpen?: boolean;
  selected: string | null;
  onSelect: (path: string) => void;
}

/// Recursive directory node. The synthetic root (`depth === 0`,
/// `path === ""`) is rendered without a header row — we just
/// drop into the listing — so the tree doesn't waste a line on
/// "(root)/".
function DirectoryNode({
  worktreeName,
  path,
  name,
  depth,
  initialOpen = false,
  selected,
  onSelect,
}: DirectoryNodeProps) {
  const isRoot = depth === 0 && path === "";
  const [open, setOpen] = useState(initialOpen);

  const indentPx = depth * 14;

  const tree = useQuery({
    queryKey: ["worktree-tree", worktreeName, path],
    queryFn: ({ signal }) =>
      dashboardApi.git.tree(worktreeName, path || undefined, signal),
    enabled: open,
    staleTime: 5_000,
  });

  const listingProps = {
    worktreeName,
    depth,
    isPending: tree.isPending,
    error: tree.error,
    data: tree.data,
    refetch: () => {
      void tree.refetch();
    },
    selected,
    onSelect,
  };

  // Render the synthetic root inline (no chevron / no row).
  if (isRoot) {
    return <DirectoryListing {...listingProps} />;
  }

  return (
    <div>
      <button
        type="button"
        className="flex items-center gap-1 text-left w-full hover:bg-panel-high rounded px-1 focus:outline-none focus-visible:ring-1 focus-visible:ring-accent"
        style={{ paddingLeft: indentPx }}
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
      >
        <span
          className="text-ink-subtle w-3 inline-block text-center"
          aria-hidden="true"
        >
          {open ? "▾" : "▸"}
        </span>
        <span className="text-ink-muted truncate" title={path}>
          {name}/
        </span>
      </button>
      {open && <DirectoryListing {...listingProps} />}
    </div>
  );
}

interface DirectoryListingProps {
  worktreeName: string;
  depth: number;
  isPending: boolean;
  error: unknown;
  data: WorktreeTree | undefined;
  refetch: () => void;
  selected: string | null;
  onSelect: (path: string) => void;
}

function DirectoryListing({
  worktreeName,
  depth,
  isPending,
  error,
  data,
  refetch,
  selected,
  onSelect,
}: DirectoryListingProps) {
  const indentPx = (depth + 1) * 14;

  if (isPending) {
    return (
      <div
        className="text-[11px] text-ink-subtle italic py-1"
        style={{ paddingLeft: indentPx }}
      >
        loading…
      </div>
    );
  }
  if (error) {
    return (
      <div className="py-1" style={{ paddingLeft: indentPx }}>
        <ErrorBox error={error} onRetry={refetch} />
      </div>
    );
  }
  if (!data) {
    return (
      <div
        className="text-[11px] text-ink-subtle italic py-1"
        style={{ paddingLeft: indentPx }}
      >
        loading…
      </div>
    );
  }
  if (data.entries.length === 0) {
    // `depth === 0` is the synthetic root listing (rendered inline
    // by the `isRoot` branch in `DirectoryNode`). An empty root
    // means the worktree has no files at all — much more
    // operator-relevant than "(empty)" tucked into a sub-folder
    // expansion, so spell it out so the operator does not assume
    // the tree failed to load.
    if (depth === 0) {
      return (
        <div className="text-xs text-ink-muted py-2 px-1 leading-snug">
          <p className="font-medium text-ink-subtle">No tracked files yet.</p>
          <p className="mt-1">
            This worktree has not produced any files. Files appear here once a
            session writes inside it.
          </p>
        </div>
      );
    }
    return (
      <div
        className="text-[11px] text-ink-subtle italic py-1"
        style={{ paddingLeft: indentPx }}
      >
        (empty)
      </div>
    );
  }

  return (
    <ul className="space-y-0.5">
      {data.entries.map((entry) => (
        <li key={entry.path}>
          {entry.kind === "dir" ? (
            <DirectoryNode
              worktreeName={worktreeName}
              path={entry.path}
              name={entry.name}
              depth={depth + 1}
              selected={selected}
              onSelect={onSelect}
            />
          ) : (
            <FileRow
              entry={entry}
              depth={depth + 1}
              selected={selected === entry.path}
              onSelect={onSelect}
            />
          )}
        </li>
      ))}
      {data.truncated && (
        <li
          className="text-[11px] text-warn italic py-1"
          style={{ paddingLeft: indentPx }}
          title="The kernel capped this listing at the per-request entry budget. Drill into a sub-folder to see the rest."
        >
          (listing truncated — drill into a sub-folder)
        </li>
      )}
    </ul>
  );
}

interface FileRowProps {
  entry: WorktreeTreeEntry;
  depth: number;
  selected: boolean;
  onSelect: (path: string) => void;
}

function FileRow({ entry, depth, selected, onSelect }: FileRowProps) {
  const indentPx = depth * 14;
  return (
    <button
      type="button"
      className={`flex items-center gap-1.5 text-left w-full rounded px-1 group focus:outline-none focus-visible:ring-1 focus-visible:ring-accent ${
        selected ? "bg-panel-high text-ink" : "hover:bg-panel-high"
      }`}
      style={{ paddingLeft: indentPx }}
      onClick={() => onSelect(entry.path)}
      title={entry.path}
    >
      <span
        className="text-ink-subtle w-3 inline-block text-center"
        aria-hidden="true"
      >
        {entry.kind === "symlink" ? "↪" : entry.kind === "file" ? " " : "·"}
      </span>
      <Mono className="truncate flex-1 text-ink-muted">{entry.name}</Mono>
      {entry.size != null && (
        <span className="text-[10px] text-ink-subtle tabular">
          {fmtBytes(entry.size)}
        </span>
      )}
    </button>
  );
}

interface FileViewProps {
  worktreeName: string;
  path: string;
}

/// Maximum bytes we'll inline as text. Beyond this we still
/// fetch (the backend already enforces its own per-request
/// budget) but we show a heads-up so the operator understands
/// why scrolling feels heavy.
const LARGE_TEXT_BYTES = 256 * 1024;

function FileView({ worktreeName, path }: FileViewProps) {
  const { theme } = useTheme();
  const monacoTheme = theme === "dark" ? "vs-dark" : "vs";

  const file = useQuery({
    queryKey: ["worktree-file", worktreeName, path],
    queryFn: ({ signal }) => dashboardApi.git.file(worktreeName, path, signal),
    retry: false,
  });

  const decoded = useMemo(() => {
    if (!file.data) return null;
    if (file.data.encoding === "utf8") return file.data.content;
    if (file.data.encoding === "base64") {
      try {
        return atob(file.data.content);
      } catch {
        return null;
      }
    }
    return null;
  }, [file.data]);

  if (file.isPending) return <PageSpinner />;
  if (file.error) {
    return <ErrorBox error={file.error} onRetry={() => file.refetch()} />;
  }
  const f = file.data;

  const language = detectMonacoLanguage(f.path);
  const lineCount =
    f.encoding === "utf8" ? Math.max(1, f.content.split("\n").length) : 1;
  // Cap the inline editor height to ~70 viewport-units; the Monaco
  // editor handles its own scrolling above that. Using a rough
  // 18px/line average matches Monaco's default density.
  const editorPx = Math.min(Math.max(160, lineCount * 18 + 24), 720);

  return (
    <div className="card p-0 overflow-hidden">
      <header className="px-3 py-2 border-b border-edge bg-panel-high flex items-center gap-2 text-xs flex-wrap">
        <Mono className="text-ink truncate flex-1 min-w-[160px]">{f.path}</Mono>
        <CopyButton value={f.path} label="Copy path" />
        <span className="text-ink-subtle tabular">{fmtBytes(f.size)}</span>
        <span className="badge bg-edge/40 border-edge-strong text-ink-muted text-[10px]">
          {f.encoding}
        </span>
        {f.encoding === "utf8" && (
          <span className="badge bg-edge/40 border-edge-strong text-ink-muted text-[10px]">
            {language}
          </span>
        )}
      </header>
      {f.encoding === "utf8" ? (
        <>
          {f.size > LARGE_TEXT_BYTES && (
            <p className="m-3 text-[11px] text-warn">
              Large file ({fmtBytes(f.size)}) — rendering inline; expect some
              scroll lag.
            </p>
          )}
          <div style={{ height: `${editorPx}px` }} data-testid="repo-file-editor">
            <Editor
              height="100%"
              defaultLanguage={language}
              language={language}
              path={f.path}
              theme={monacoTheme}
              value={f.content}
              options={{
                readOnly: true,
                domReadOnly: true,
                fontSize: 12,
                minimap: { enabled: false },
                scrollBeyondLastLine: false,
                automaticLayout: true,
                tabSize: 2,
                wordWrap: "on",
                renderLineHighlight: "none",
              }}
            />
          </div>
        </>
      ) : decoded != null ? (
        <div className="p-3">
          <BinaryView raw={decoded} />
        </div>
      ) : (
        <p className="p-3 text-xs text-ink-subtle italic">
          Unable to decode binary content for inline display.
        </p>
      )}
    </div>
  );
}

/// Hex-dump the first slice of a binary file. Operator-tooling
/// usefulness: confirm magic bytes, sniff a header. Intentionally
/// capped — full hex dumps belong in a real binary viewer, not in
/// the dashboard.
function BinaryView({ raw }: { raw: string }) {
  const HEX_PREVIEW_BYTES = 4096;
  const slice =
    raw.length > HEX_PREVIEW_BYTES ? raw.slice(0, HEX_PREVIEW_BYTES) : raw;
  const lines = useMemo(() => {
    const out: string[] = [];
    for (let i = 0; i < slice.length; i += 16) {
      const chunk = slice.slice(i, i + 16);
      const offset = i.toString(16).padStart(8, "0");
      const hex: string[] = [];
      let ascii = "";
      for (let j = 0; j < chunk.length; j++) {
        const b = chunk.charCodeAt(j) & 0xff;
        hex.push(b.toString(16).padStart(2, "0"));
        ascii += b >= 0x20 && b < 0x7f ? chunk[j] : ".";
      }
      out.push(`${offset}  ${hex.join(" ").padEnd(48)}  |${ascii}|`);
    }
    return out;
  }, [slice]);
  return (
    <>
      <pre className="font-mono text-[11px] leading-relaxed overflow-auto scroll-thin max-h-[70vh] text-ink-muted">
        {lines.join("\n")}
      </pre>
      {raw.length > HEX_PREVIEW_BYTES && (
        <p className="mt-2 text-[11px] text-ink-subtle italic">
          Hex preview truncated to {fmtBytes(HEX_PREVIEW_BYTES)} of{" "}
          {fmtBytes(raw.length)}.
        </p>
      )}
    </>
  );
}

// Re-export so call sites can spread it without a separate import.
export type { WorktreeTreeEntry };
