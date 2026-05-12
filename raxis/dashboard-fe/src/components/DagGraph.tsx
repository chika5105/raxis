import { useMemo, useRef, useState } from "react";
import dagre from "dagre";

import { stateTone, toneClasses, type StateBadgeTone } from "@/lib/state-color";

export interface DagGraphNode {
  task_id: string;
  title: string;
  state: string;
}

export interface DagGraphEdge {
  from: string;
  to: string;
}

// SVG attributes can't take Tailwind classes; we drive every
// fill/stroke from the same CSS custom properties Tailwind reads
// (`--c-ok-muted`, `--c-info`, …) so the graph re-themes on
// light/dark toggle without a re-render. Going through
// `rgb(var(--c-x))` mirrors the README's "always reach for a
// semantic token" rule for SVG primitives that bypass Tailwind.
const NODE_FILL_VAR: Record<StateBadgeTone, string> = {
  ok:    "rgb(var(--c-ok-muted))",
  info:  "rgb(var(--c-info-muted))",
  warn:  "rgb(var(--c-warn-muted))",
  bad:   "rgb(var(--c-bad-muted))",
  block: "rgb(var(--c-block-muted))",
  muted: "rgb(var(--c-edge))",
};
const NODE_STROKE_VAR: Record<StateBadgeTone, string> = {
  ok:    "rgb(var(--c-ok))",
  info:  "rgb(var(--c-info))",
  warn:  "rgb(var(--c-warn))",
  bad:   "rgb(var(--c-bad))",
  block: "rgb(var(--c-block))",
  muted: "rgb(var(--c-edge-strong))",
};

interface DagGraphProps {
  nodes: DagGraphNode[];
  edges: DagGraphEdge[];
  /// Called when the operator clicks a node. The page is free
  /// to decide whether that means "focus this node in a side
  /// panel" or "navigate to the task detail page".
  onSelect?: (taskId: string) => void;
  /// Called when the operator double-clicks a node — typically
  /// "open the task page" when single-click already focuses.
  onActivate?: (taskId: string) => void;
  /// Currently-highlighted task id.
  selected?: string | null;
  /// Minimum SVG display height in pixels. The graph grows
  /// beyond this if the laid-out content is taller. Defaults to
  /// 360.
  height?: number;
  /// Layout direction. `LR` (default) is best for "executor
  /// pipeline" plans where stages flow left-to-right; `TB` is
  /// preferred for tall fan-out plans. Mirrors the dagre option
  /// vocabulary.
  rankdir?: "LR" | "TB";
}

const NODE_W = 200;
const NODE_H = 56;

/// Static SVG DAG renderer using `dagre` for layered layout.
/// Operator-tooling-grade — no zoom/pan, just a clean readable
/// view that scales with the canvas. ≤ 50 nodes is the target
/// (`v2_extended_gaps.md §4.4` ergonomic budget).
export function DagGraph({
  nodes,
  edges,
  onSelect,
  onActivate,
  selected,
  height = 360,
  rankdir = "LR",
}: DagGraphProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [hover, setHover] = useState<string | null>(null);

  const layout = useMemo(() => {
    const g = new dagre.graphlib.Graph({ multigraph: false, compound: false });
    g.setGraph({ rankdir, nodesep: 24, ranksep: 60, marginx: 16, marginy: 16 });
    g.setDefaultEdgeLabel(() => ({}));

    // Only edges whose endpoints exist in `nodes` get rendered —
    // a stale edge from a deleted task would otherwise blow up
    // `dagre.layout`.
    const nodeIds = new Set(nodes.map((n) => n.task_id));
    nodes.forEach((n) => {
      g.setNode(n.task_id, { width: NODE_W, height: NODE_H, label: n.title });
    });
    const safeEdges = edges.filter(
      (e) => nodeIds.has(e.from) && nodeIds.has(e.to),
    );
    safeEdges.forEach((e) => {
      g.setEdge(e.from, e.to);
    });
    dagre.layout(g);

    const placedNodes = nodes.map((n) => {
      const meta = g.node(n.task_id);
      const cx = meta?.x ?? 0;
      const cy = meta?.y ?? 0;
      return {
        ...n,
        x: cx - NODE_W / 2,
        y: cy - NODE_H / 2,
        w: NODE_W,
        h: NODE_H,
      };
    });

    const placedEdges = safeEdges.map((e) => {
      const edgeData = g.edge({ v: e.from, w: e.to });
      const points = (edgeData?.points ?? []) as Array<{
        x: number;
        y: number;
      }>;
      return { ...e, points };
    });

    const graphInfo = g.graph();
    // Pad the natural extent so the rightmost / bottommost node
    // stroke isn't clipped by the viewBox edge.
    const naturalW = (graphInfo.width ?? 800) + 8;
    const naturalH = (graphInfo.height ?? height) + 8;
    return {
      nodes: placedNodes,
      edges: placedEdges,
      width: naturalW,
      height: naturalH,
    };
  }, [nodes, edges, height, rankdir]);

  // The viewBox MUST match the laid-out extent so dagre's
  // coordinates render at scale; the SVG height is the larger
  // of the natural extent and the caller's minimum. Width is
  // 100% of the container — the container scrolls horizontally
  // if the natural width exceeds it.
  const svgHeight = Math.max(layout.height, height);

  return (
    <div ref={containerRef} className="w-full overflow-auto scroll-thin">
      <svg
        viewBox={`0 0 ${layout.width} ${layout.height}`}
        width={layout.width}
        height={svgHeight}
        preserveAspectRatio="xMinYMin meet"
        style={{ minWidth: "100%" }}
        className="bg-panel rounded grid-overlay border border-edge"
      >
        <defs>
          <marker
            id="arrow"
            viewBox="0 0 10 10"
            refX="9"
            refY="5"
            markerWidth="5"
            markerHeight="5"
            orient="auto-start-reverse"
          >
            <path d="M 0 0 L 10 5 L 0 10 z" fill="rgb(var(--c-ink-subtle))" />
          </marker>
        </defs>

        {/* Edges */}
        {layout.edges.map((e, i) => {
          if (e.points.length < 2) return null;
          const d = e.points
            .map((p, j) => `${j === 0 ? "M" : "L"} ${p.x},${p.y}`)
            .join(" ");
          return (
            <path
              key={`${e.from}-${e.to}-${i}`}
              d={d}
              fill="none"
              stroke="rgb(var(--c-ink-subtle))"
              strokeWidth={1.4}
              markerEnd="url(#arrow)"
              opacity={
                hover && hover !== e.from && hover !== e.to ? 0.25 : 0.85
              }
            />
          );
        })}

        {/* Nodes */}
        {layout.nodes.map((n) => {
          const tone = stateTone(n.state);
          const fill = NODE_FILL_VAR[tone];
          const stroke = NODE_STROKE_VAR[tone];
          const isSelected = selected === n.task_id;
          return (
            <g
              key={n.task_id}
              transform={`translate(${n.x}, ${n.y})`}
              onClick={() => onSelect?.(n.task_id)}
              onDoubleClick={() => onActivate?.(n.task_id)}
              onMouseEnter={() => setHover(n.task_id)}
              onMouseLeave={() => setHover(null)}
              style={{ cursor: "pointer" }}
              role="button"
              tabIndex={0}
              aria-label={`Task ${n.title} (state ${n.state}). Click to focus, double-click to open task page.`}
              onKeyDown={(ev) => {
                if (ev.key === "Enter" || ev.key === " ") {
                  ev.preventDefault();
                  // Enter = activate (open task page) when wired,
                  // else fall back to onSelect so the operator can
                  // still focus the node with the keyboard.
                  if (onActivate) {
                    onActivate(n.task_id);
                  } else if (onSelect) {
                    onSelect(n.task_id);
                  }
                }
              }}
            >
              <rect
                width={n.w}
                height={n.h}
                rx={6}
                fill={fill}
                stroke={isSelected ? "rgb(var(--c-accent))" : stroke}
                strokeWidth={isSelected ? 2 : 1}
                opacity={hover && hover !== n.task_id ? 0.8 : 1}
              />
              <title>
                {n.title}
                {"\n"}
                {n.task_id}
                {"\n"}
                state: {n.state}
              </title>
              <text
                x={10}
                y={22}
                fill="rgb(var(--c-ink))"
                fontSize={12}
                fontWeight={500}
                fontFamily="Inter, system-ui, sans-serif"
              >
                {truncate(n.title, 26)}
              </text>
              <text
                x={10}
                y={40}
                fill="rgb(var(--c-ink-muted))"
                fontSize={10}
                fontFamily="JetBrains Mono, ui-monospace, monospace"
              >
                {n.task_id.length > 20
                  ? `${n.task_id.slice(0, 20)}…`
                  : n.task_id}
              </text>
              <text
                x={n.w - 8}
                y={22}
                textAnchor="end"
                fill={stroke}
                fontSize={9}
                fontWeight={700}
                fontFamily="Inter, system-ui, sans-serif"
              >
                {n.state.toUpperCase()}
              </text>
            </g>
          );
        })}
      </svg>

      {/* Legend */}
      <div className="flex flex-wrap gap-1.5 mt-2 text-[11px]">
        {[
          "Pending",
          "Running",
          "Completed",
          "Failed",
          "Blocked",
          "Reviewing",
        ].map((s) => (
          <span key={s} className={`badge ${toneClasses(stateTone(s))}`}>
            {s}
          </span>
        ))}
      </div>
    </div>
  );
}

function truncate(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}
