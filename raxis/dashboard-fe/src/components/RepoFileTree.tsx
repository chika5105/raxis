import { useMemo, useState } from "react";

import type { WorktreeDiff, WorktreeDiffFile } from "@/types/api";

import { Mono } from "@/components/Mono";

interface RepoFileTreeProps {
  diff: WorktreeDiff;
  /// Called when a leaf (file) is clicked. The page typically
  /// scrolls the matching `FileDiff` into view.
  onSelect?: (path: string) => void;
}

/// A nested tree view derived from the changed-files list of a
/// `WorktreeDiff`. Each path segment becomes a directory node;
/// leaves are files. Directories sort before files at every
/// level so the layout reads top-down like `ls -F`.
///
/// **Why a derived tree and not a real `git ls-tree` view.**
/// The dashboard backend at `raxis/crates/dashboard/src/data.rs`
/// surfaces only `list_worktrees`, `get_worktree`, `worktree_log`,
/// `worktree_diff_default`, and `worktree_diff_range`. There is
/// no `tree` / `blob` endpoint yet. The diff already names every
/// file the executor touched relative to the base, so deriving a
/// tree from that gives the operator a glanceable "what's
/// changing" map without a backend round trip.
///
/// A full unchanged-files browser (including content view +
/// syntax highlighting) requires new endpoints — see the
/// backend ask in the worker report for the dashboard-backend
/// sibling worker.
export function RepoFileTree({ diff, onSelect }: RepoFileTreeProps) {
  const root = useMemo(() => buildTree(diff.files), [diff.files]);
  return (
    <div className="font-mono text-[12px] leading-relaxed">
      <TreeNode node={root} depth={0} onSelect={onSelect} initialOpen />
    </div>
  );
}

interface TreeNodeData {
  name: string;
  path: string;
  /// `null` for directories; the file entry for leaves.
  file: WorktreeDiffFile | null;
  children: TreeNodeData[];
}

function buildTree(files: WorktreeDiffFile[]): TreeNodeData {
  const root: TreeNodeData = {
    name: "",
    path: "",
    file: null,
    children: [],
  };
  for (const f of files) {
    const segs = f.path.split("/").filter((s) => s.length > 0);
    let cursor = root;
    for (let i = 0; i < segs.length; i++) {
      const isLast = i === segs.length - 1;
      const segPath = segs.slice(0, i + 1).join("/");
      let child = cursor.children.find((c) => c.name === segs[i]);
      if (!child) {
        child = {
          name: segs[i],
          path: segPath,
          file: isLast ? f : null,
          children: [],
        };
        cursor.children.push(child);
      }
      cursor = child;
    }
  }
  sortRecursive(root);
  return root;
}

function sortRecursive(node: TreeNodeData) {
  node.children.sort((a, b) => {
    // Directories before files; alpha within a kind.
    const aDir = a.file == null;
    const bDir = b.file == null;
    if (aDir !== bDir) return aDir ? -1 : 1;
    return a.name.localeCompare(b.name);
  });
  for (const c of node.children) sortRecursive(c);
}

interface TreeNodeProps {
  node: TreeNodeData;
  depth: number;
  onSelect?: (path: string) => void;
  initialOpen?: boolean;
}

function TreeNode({
  node,
  depth,
  onSelect,
  initialOpen = true,
}: TreeNodeProps) {
  const [open, setOpen] = useState(initialOpen);
  const isDir = node.file == null;
  const indentPx = depth * 14;
  // The synthetic root has no name; render its children
  // straight away.
  if (node.name === "" && depth === 0) {
    return (
      <ul className="space-y-0.5">
        {node.children.map((c) => (
          <li key={c.path}>
            <TreeNode
              node={c}
              depth={depth}
              onSelect={onSelect}
              initialOpen={initialOpen}
            />
          </li>
        ))}
      </ul>
    );
  }

  if (isDir) {
    return (
      <div>
        <button
          className="flex items-center gap-1 text-left w-full hover:bg-panel-high rounded px-1"
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
          <span className="text-ink-muted">{node.name}/</span>
          <span className="text-[10px] text-ink-subtle ml-1">
            {countLeaves(node)} file{countLeaves(node) === 1 ? "" : "s"}
          </span>
        </button>
        {open && (
          <ul className="space-y-0.5">
            {node.children.map((c) => (
              <li key={c.path}>
                <TreeNode
                  node={c}
                  depth={depth + 1}
                  onSelect={onSelect}
                  initialOpen={initialOpen}
                />
              </li>
            ))}
          </ul>
        )}
      </div>
    );
  }

  const f = node.file!;
  return (
    <button
      className="flex items-center gap-1.5 text-left w-full hover:bg-panel-high rounded px-1 group"
      style={{ paddingLeft: indentPx }}
      onClick={() => onSelect?.(f.path)}
      title={f.path}
    >
      <span className="text-ink-subtle w-3 inline-block" aria-hidden="true">
        {" "}
      </span>
      <span
        className={`badge text-[9px] py-0 px-1 ${
          f.status === "A"
            ? "bg-ok-muted/30 border-ok text-ok"
            : f.status === "D"
              ? "bg-bad-muted/30 border-bad text-bad"
              : f.status === "M"
                ? "bg-info-muted/30 border-info text-info"
                : "bg-edge/40 border-edge-strong text-ink-muted"
        }`}
      >
        {f.status}
      </span>
      <Mono className="text-ink truncate flex-1">{node.name}</Mono>
      <span className="text-[10px] text-ok">+{f.insertions}</span>
      <span className="text-[10px] text-bad">−{f.deletions}</span>
    </button>
  );
}

function countLeaves(node: TreeNodeData): number {
  if (node.file != null) return 1;
  let n = 0;
  for (const c of node.children) n += countLeaves(c);
  return n;
}
