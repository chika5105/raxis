import { useMemo, useRef, useState } from "react";
import dagre from "dagre";

import { stateTone, toneClasses } from "@/lib/state-color";

export interface DagGraphNode {
  task_id: string;
  title: string;
  state: string;
}

export interface DagGraphEdge {
  from: string;
  to: string;
}

interface DagGraphProps {
  nodes: DagGraphNode[];
  edges: DagGraphEdge[];
  /// Called when the operator clicks a node.
  onSelect?: (taskId: string) => void;
  /// Currently-highlighted task id.
  selected?: string | null;
  /// Display height in pixels (the SVG fills the parent
  /// width). Defaults to 360.
  height?: number;
}

/// Static SVG DAG renderer using `dagre` for left-to-right
/// layered layout. Operator-tooling-grade — no zoom/pan,
/// just a clean readable view that scales with the canvas.
export function DagGraph({ nodes, edges, onSelect, selected, height = 360 }: DagGraphProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [hover, setHover] = useState<string | null>(null);

  const layout = useMemo(() => {
    const g = new dagre.graphlib.Graph({ multigraph: false, compound: false });
    g.setGraph({ rankdir: "LR", nodesep: 20, ranksep: 50, marginx: 12, marginy: 12 });
    g.setDefaultEdgeLabel(() => ({}));

    const NODE_W = 180;
    const NODE_H = 50;
    nodes.forEach((n) => {
      g.setNode(n.task_id, { width: NODE_W, height: NODE_H, label: n.title });
    });
    edges.forEach((e) => {
      g.setEdge(e.from, e.to);
    });
    dagre.layout(g);

    const placedNodes = nodes.map((n) => {
      const meta = g.node(n.task_id);
      return {
        ...n,
        x: meta.x - NODE_W / 2,
        y: meta.y - NODE_H / 2,
        w: NODE_W,
        h: NODE_H,
      };
    });

    const placedEdges = edges.map((e) => {
      const edgeData = g.edge({ v: e.from, w: e.to });
      const points = (edgeData?.points ?? []) as Array<{ x: number; y: number }>;
      return { ...e, points };
    });

    const graphInfo = g.graph();
    return {
      nodes: placedNodes,
      edges: placedEdges,
      width: graphInfo.width ?? 800,
      height: graphInfo.height ?? height,
    };
  }, [nodes, edges, height]);

  return (
    <div ref={containerRef} className="w-full overflow-auto scroll-thin">
      <svg
        viewBox={`0 0 ${Math.max(layout.width, 600)} ${Math.max(layout.height, height)}`}
        width="100%"
        height={Math.max(layout.height, height)}
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
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#7d8892" />
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
              stroke="#7d8892"
              strokeWidth={1.4}
              markerEnd="url(#arrow)"
              opacity={hover && hover !== e.from && hover !== e.to ? 0.25 : 0.85}
            />
          );
        })}

        {/* Nodes */}
        {layout.nodes.map((n) => {
          const tone = stateTone(n.state);
          const fill =
            tone === "ok"
              ? "#1c5b2c"
              : tone === "info"
              ? "#1f4d80"
              : tone === "warn"
              ? "#6b4d10"
              : tone === "bad"
              ? "#7d1d1d"
              : tone === "block"
              ? "#3a2762"
              : "#222a36";
          const stroke =
            tone === "ok"
              ? "#2ea043"
              : tone === "info"
              ? "#58a6ff"
              : tone === "warn"
              ? "#d29922"
              : tone === "bad"
              ? "#f85149"
              : tone === "block"
              ? "#a371f7"
              : "#2e3849";
          const isSelected = selected === n.task_id;
          return (
            <g
              key={n.task_id}
              transform={`translate(${n.x}, ${n.y})`}
              onClick={() => onSelect?.(n.task_id)}
              onMouseEnter={() => setHover(n.task_id)}
              onMouseLeave={() => setHover(null)}
              style={{ cursor: "pointer" }}
            >
              <rect
                width={n.w}
                height={n.h}
                rx={6}
                fill={fill}
                stroke={isSelected ? "#3a86ff" : stroke}
                strokeWidth={isSelected ? 2 : 1}
                opacity={hover && hover !== n.task_id ? 0.8 : 1}
              />
              <text
                x={10}
                y={20}
                fill="#e6e8eb"
                fontSize={12}
                fontWeight={500}
                fontFamily="Inter, system-ui, sans-serif"
              >
                {truncate(n.title, 24)}
              </text>
              <text
                x={10}
                y={36}
                fill="#a8b1bc"
                fontSize={10}
                fontFamily="JetBrains Mono, ui-monospace, monospace"
              >
                {n.task_id.length > 18 ? `${n.task_id.slice(0, 18)}…` : n.task_id}
              </text>
              <text
                x={n.w - 8}
                y={20}
                textAnchor="end"
                fill={stroke}
                fontSize={9}
                fontWeight={600}
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
        {["Pending", "Running", "Completed", "Failed", "Blocked", "Reviewing"].map((s) => (
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
