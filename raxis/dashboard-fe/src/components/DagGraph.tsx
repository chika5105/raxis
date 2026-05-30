import { useMemo, useRef, useState } from "react";
import dagre from "dagre";

import {
  shortStateLabel,
  stateTone,
  toneClasses,
  type StateBadgeTone,
} from "@/lib/state-color";

export interface DagGraphNode {
  task_id: string;
  title: string;
  agent_type?: string;
  state: string;
  node_kind?: "task" | "gate";
  parent_task_id?: string;
  gate_type?: string;
  gate_source?: string;
  gate_hook?: string;
  latest_verdict?: string;
  /// Backend signals an active subtask activation for this task.
  /// The graph treats `is_active` as Running for tone, chip label
  /// and pulse so mid-execution `Admitted` tasks (between VM hops)
  /// don't visually look stalled. Optional for back-compat.
  is_active?: boolean;
  /// Latest state per mechanical witness gate. The DAG renders
  /// these as dashed gate nodes attached to this task so gates are
  /// part of the graph, not hidden in a tiny decoration.
  gate_verdict_summary?: Array<{
    gate_type: string;
    gate_source?: string;
    gate_hook?: string;
    latest_verdict: string;
    recorded_at: number;
  }>;
  /// Derived reviewer aggregate for executor tasks. The backend
  /// derives this from downstream reviewer rows when the executor
  /// task row itself has no aggregate verdict.
  review_verdict?: string | null;
  review_reject_count?: number;
  max_review_rejections?: number;
  review_retry_exhausted?: boolean;
}

/// Effective state for tone / chip / pulse derivation: an active
/// task with FSM state `Admitted` is rendered as Running because
/// from the operator's perspective an executor IS doing work.
function effectiveState(node: DagGraphNode): string {
  if (node.is_active && node.state === "Admitted") return "Running";
  return node.state;
}

function visualState(node: DagGraphNode): string {
  if (node.node_kind !== "gate" && isRejectedReview(node.review_verdict)) {
    return node.review_retry_exhausted ? "RetryExhausted" : "ReviewRejected";
  }
  return effectiveState(node);
}

function isRejectedReview(verdict: string | null | undefined): boolean {
  const v = (verdict ?? "").toLowerCase();
  return v === "rejected" || v === "reject" || v === "atleastonerejected";
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
  /// When non-empty, nodes whose `state` is NOT in this list are
  /// rendered at low opacity ("dim mode" — the operator keeps
  /// situational awareness of the full graph while a status
  /// filter narrows attention to one or more states). The legend
  /// at the bottom of the graph is suppressed when the caller is
  /// driving a richer external `StatusLegend` upstream.
  activeStates?: string[];
  /// Suppress the small built-in status reference legend at the
  /// bottom of the graph (use when the caller renders a richer
  /// interactive `<StatusLegend>` above the DAG).
  hideLegend?: boolean;
}

const NODE_W = 200;
const NODE_H = 80;
// State chip occupies a fixed slot in the top-right of the
// node. The chip width is sized to fit a 10-char uppercase
// label at fontSize 9 bold — `shortStateLabel` (in
// `lib/state-color.ts`) caps every kernel state name at that
// length by splitting PascalCase tokens on uppercase
// boundaries (so e.g. `BlockedRecoveryPending` reads as
// `BLOCKED`). Title truncation is then derived from the
// remaining horizontal budget so the two text columns can
// never collide horizontally regardless of how long the
// title is.
const STATE_CHIP_W = 70;
const STATE_CHIP_H = 16;
// Title gets the horizontal budget the chip leaves behind:
//   200 (node) - 10 (left pad) - 70 (chip) - 6 (chip right pad)
//   - 8 (visual gap) ≈ 106 px. At fontSize 12 / Inter that's
// ~16 chars before truncation; the helper appends a trailing
// ellipsis when truncation actually fires.
const TITLE_MAX_CHARS = 16;

/// Static SVG DAG renderer using `dagre` for layered layout.
/// Operator-tooling-grade — no zoom/pan, just a clean readable
/// view that scales with the canvas. ≤ 50 nodes is the target
/// ergonomic budget.
export function DagGraph({
  nodes,
  edges,
  onSelect,
  onActivate,
  selected,
  height = 360,
  rankdir = "LR",
  activeStates,
  hideLegend = false,
}: DagGraphProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [hover, setHover] = useState<string | null>(null);

  const activeSet = useMemo(
    () => (activeStates && activeStates.length > 0 ? new Set(activeStates) : null),
    [activeStates],
  );
  const dimNodeFor = (node: DagGraphNode) =>
    activeSet !== null &&
    !activeSet.has(effectiveState(node)) &&
    !activeSet.has(visualState(node));

  const expanded = useMemo(() => expandGateNodes(nodes, edges), [nodes, edges]);

  const layout = useMemo(() => {
    const g = new dagre.graphlib.Graph({ multigraph: false, compound: false });
    g.setGraph({ rankdir, nodesep: 24, ranksep: 60, marginx: 16, marginy: 16 });
    g.setDefaultEdgeLabel(() => ({}));

    // Only edges whose endpoints exist in `nodes` get rendered —
    // a stale edge from a deleted task would otherwise blow up
    // `dagre.layout`.
    const nodeIds = new Set(expanded.nodes.map((n) => n.task_id));
    expanded.nodes.forEach((n) => {
      g.setNode(n.task_id, { width: NODE_W, height: NODE_H, label: n.title });
    });
    const safeEdges = expanded.edges.filter(
      (e) => nodeIds.has(e.from) && nodeIds.has(e.to),
    );
    safeEdges.forEach((e) => {
      g.setEdge(e.from, e.to);
    });
    dagre.layout(g);

    const placedNodes = expanded.nodes.map((n) => {
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
  }, [expanded, height, rankdir]);

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
          // When the operator has activated a status filter, fade
          // edges whose BOTH endpoints are out of the active set —
          // matching nodes still pull their wiring forward. Hover
          // de-emphasis still wins when the operator is mousing
          // over a specific node.
          const fromNode = expanded.nodes.find((n) => n.task_id === e.from);
          const toNode = expanded.nodes.find((n) => n.task_id === e.to);
          const edgeDim =
            activeSet !== null &&
            fromNode !== undefined &&
            toNode !== undefined &&
            !activeSet.has(effectiveState(fromNode)) &&
            !activeSet.has(visualState(fromNode)) &&
            !activeSet.has(effectiveState(toNode)) &&
            !activeSet.has(visualState(toNode));
          const hoverDim =
            hover !== null && hover !== e.from && hover !== e.to;
          const opacity = edgeDim ? 0.15 : hoverDim ? 0.25 : 0.85;
          return (
            <path
              key={`${e.from}-${e.to}-${i}`}
              d={d}
              fill="none"
              stroke="rgb(var(--c-ink-subtle))"
              strokeWidth={1.4}
              strokeDasharray={e.kind === "gate" ? "4 4" : undefined}
              markerEnd="url(#arrow)"
              opacity={opacity}
            />
          );
        })}

        {/* Nodes */}
        {layout.nodes.map((n) => {
          // `effectiveState` lifts `Admitted + is_active` to
          // `Running` so the tone, chip label and pulse all
          // reflect the operator's reality (a live executor) even
          // while the FSM row hasn't flipped state yet.
          const eff = effectiveState(n);
          const visual = visualState(n);
          const tone = stateTone(visual);
          const fill = NODE_FILL_VAR[tone];
          const stroke = NODE_STROKE_VAR[tone];
          const isGate = n.node_kind === "gate";
          const isSelected =
            selected === n.task_id || (isGate && selected === n.parent_task_id);
          const dim = dimNodeFor(n);
          const hoverDim = hover !== null && hover !== n.task_id;
          const showPulse = eff === "Running";
          const selectId = isGate ? n.parent_task_id : n.task_id;
          const chipLabel = isGate
            ? (n.latest_verdict ?? "Pending").toUpperCase()
            : reviewChipLabel(visual);
          const detailLine = reviewLine(n) ?? (n.agent_type ?? "Task");
          // Filter-dim wins over hover-dim because it's the
          // explicit operator intent ("I want to see Running") vs.
          // an incidental mouseover.
          const nodeOpacity = dim ? 0.25 : hoverDim ? 0.8 : 1;
          return (
            <g
              key={n.task_id}
              transform={`translate(${n.x}, ${n.y})`}
              onClick={() => selectId && onSelect?.(selectId)}
              onDoubleClick={() => selectId && onActivate?.(selectId)}
              onMouseEnter={() => setHover(n.task_id)}
              onMouseLeave={() => setHover(null)}
              style={{ cursor: "pointer" }}
              role="button"
              tabIndex={0}
              aria-label={
                isGate
                  ? `Witness gate ${n.gate_type ?? n.title} for task ${n.parent_task_id} (${n.latest_verdict ?? "Pending"}). Click to focus the task, double-click to open task page.`
                  : `Task ${n.title} (state ${eff}${reviewLine(n) ? `, ${reviewLine(n)}` : ""}). Click to focus, double-click to open task page.`
              }
              data-node-kind={n.node_kind ?? "task"}
              data-status={visual}
              data-raw-state={n.state}
              data-review-verdict={n.review_verdict || undefined}
              data-review-exhausted={n.review_retry_exhausted || undefined}
              data-is-active={n.is_active || undefined}
              data-dimmed={dim || undefined}
              onKeyDown={(ev) => {
                if (ev.key === "Enter" || ev.key === " ") {
                  ev.preventDefault();
                  // Enter = activate (open task page) when wired,
                  // else fall back to onSelect so the operator can
                  // still focus the node with the keyboard.
                  if (selectId && onActivate) {
                    onActivate(selectId);
                  } else if (selectId && onSelect) {
                    onSelect(selectId);
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
                strokeDasharray={isGate ? "7 5" : undefined}
                opacity={nodeOpacity}
                // 1.4s ease-in-out infinite-alternate stroke-pulse
                // keeps the running affordance in sync with the
                // state-badge pulse used by `<StateBadge pulse>`
                // on the detail pages, so the DAG and the lists
                // throb in unison.
                style={
                  showPulse
                    ? { animation: "raxis-node-pulse 1.4s ease-in-out infinite alternate" }
                    : undefined
                }
              />
              <title>
                {isGate ? `Witness gate: ${n.gate_type ?? n.title}` : n.title}
                {"\n"}
                {isGate
                  ? `task: ${n.parent_task_id}`
                  : `${n.agent_type ?? "Task"}: ${n.task_id}`}
                {"\n"}
                {isGate
                  ? `source: ${gateSourceLabel(n.gate_source)}\nhook: ${hookLabel(n.gate_hook)}\nverdict: ${n.latest_verdict ?? "Pending"}`
                  : `state: ${eff}`}
                {!isGate && reviewLine(n) ? `\nreview: ${reviewLine(n)}` : ""}
                {n.is_active && n.state !== eff
                  ? `\n(FSM row: ${n.state} · executor active)`
                  : ""}
              </title>
              {/*
               * State label rendered as a discrete chip in the
               * top-right slot — NOT a free-floating right-aligned
               * `<text>`. The previous treatment let the state
               * string (e.g. `COMPLETED`, 9 chars at fontSize 9
               * bold ≈ 55px) extend leftwards into the title's
               * x-range; for any title > ~20 chars the truncated
               * title would visually overlap the state label,
               * making both unreadable. Operators reported this
               * as "overlay of completed on the task description".
               *
               * The chip occupies a fixed `STATE_CHIP_W`-wide slot
               * with its own panel-raised fill (i.e. the card
               * surface, not the muted node body), giving the
               * status text a high-contrast background regardless
               * of the surrounding tone family. Title truncation
               * below is sized so the title can never exceed the
               * chip's left edge.
               */}
              <rect
                x={n.w - STATE_CHIP_W - 6}
                y={6}
                width={STATE_CHIP_W}
                height={STATE_CHIP_H}
                rx={3}
                fill="rgb(var(--c-panel-raised))"
                stroke={stroke}
                strokeWidth={1}
              />
              <text
                x={n.w - 6 - STATE_CHIP_W / 2}
                y={6 + STATE_CHIP_H - 4}
                textAnchor="middle"
                fill={stroke}
                fontSize={9}
                fontWeight={700}
                fontFamily="Inter, system-ui, sans-serif"
              >
                {chipLabel}
              </text>
              <text
                x={10}
                y={26}
                fill="rgb(var(--c-ink))"
                fontSize={12}
                fontWeight={500}
                fontFamily="Inter, system-ui, sans-serif"
              >
                {truncate(
                  isGate
                    ? `${gateSourceLabel(n.gate_source)}: ${n.gate_type ?? n.title}`
                    : n.title,
                  TITLE_MAX_CHARS,
                )}
              </text>
              <text
                x={10}
                y={44}
                fill="rgb(var(--c-ink-muted))"
                fontSize={10}
                fontFamily="JetBrains Mono, ui-monospace, monospace"
              >
                {displayNodeId(n, isGate)}
              </text>
              {!isGate && (
                <text
                  x={10}
                  y={62}
                  fill="rgb(var(--c-ink-subtle))"
                  fontSize={9}
                  fontWeight={600}
                  fontFamily="Inter, system-ui, sans-serif"
                >
                  {detailLine}
                </text>
              )}
            </g>
          );
        })}
      </svg>

      {/* Fallback legend — one chip per kernel TaskState tone
       * family, in lifecycle order: muted (not running yet) →
       * info (running) → warn (gated) → ok (terminal-ok) →
       * bad (terminal-fail) → block (operator-cancelled). The
       * interactive click-to-filter legend lives upstream in
       * `<StatusLegend>` when the caller wires one; we
       * suppress this fallback via `hideLegend` to avoid two
       * side-by-side legends in that case. */}
      {!hideLegend && (
        <div className="flex flex-wrap gap-1.5 mt-2 text-[11px]">
          {[
            "Admitted",
            "Running",
            "GatesPending",
            "Completed",
            "Failed",
            "Cancelled",
          ].map((s) => (
            <span key={s} className={`badge ${toneClasses(stateTone(s))}`}>
              {s}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function truncate(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

function displayNodeId(n: DagGraphNode, isGate: boolean): string {
  if (isGate) {
    const parent = n.parent_task_id ?? "";
    return parent.length > 20 ? `${parent.slice(0, 20)}…` : parent;
  }
  return n.task_id.length > 20 ? `${n.task_id.slice(0, 20)}…` : n.task_id;
}

function reviewChipLabel(state: string): string {
  if (state === "RetryExhausted") return "EXHAUSTED";
  if (state === "ReviewRejected") return "REJECTED";
  return shortStateLabel(state);
}

function reviewLine(node: DagGraphNode): string | null {
  if (!isRejectedReview(node.review_verdict)) return null;
  const count = node.review_reject_count ?? 0;
  const max = node.max_review_rejections ?? 0;
  if (node.review_retry_exhausted) {
    return max > 0 ? `review ${count}/${max} exhausted` : "review exhausted";
  }
  return max > 0 ? `review rejected ${count}/${max}` : "review rejected";
}

interface ExpandedDagEdge extends DagGraphEdge {
  kind?: "task" | "gate";
}

function expandGateNodes(
  nodes: DagGraphNode[],
  edges: DagGraphEdge[],
): { nodes: DagGraphNode[]; edges: ExpandedDagEdge[] } {
  const outNodes: DagGraphNode[] = [];
  const outEdges: ExpandedDagEdge[] = [...edges];
  for (const n of nodes) {
    outNodes.push({ ...n, node_kind: n.node_kind ?? "task" });
    for (const chip of n.gate_verdict_summary ?? []) {
      const gateId = `${n.task_id}::gate::${chip.gate_type}`;
      outNodes.push({
        task_id: gateId,
        title: chip.gate_type,
        agent_type: "Witness",
        state: gateState(chip.latest_verdict),
        node_kind: "gate",
        parent_task_id: n.task_id,
        gate_type: chip.gate_type,
        gate_source: chip.gate_source,
        gate_hook: chip.gate_hook,
        latest_verdict: chip.latest_verdict,
      });
      outEdges.push({ from: n.task_id, to: gateId, kind: "gate" });
    }
  }
  return { nodes: outNodes, edges: outEdges };
}

function gateState(verdict: string): string {
  switch (verdict) {
    case "Pass":
      return "Completed";
    case "Fail":
    case "SpawnFailed":
    case "ProcessFailed":
    case "Timeout":
    case "ConfigInvalid":
    case "BudgetExhausted":
    case "CapExceeded":
      return "Failed";
    case "Pending":
    case "Inconclusive":
      return "GatesPending";
    default:
      return "GatesPending";
  }
}

function gateSourceLabel(source: string | undefined): string {
  switch (source) {
    case "task_verifier":
      return "Task gate";
    case "plan_integration_verifier":
      return "Plan integration gate";
    case "policy_integration_verifier":
      return "Policy integration gate";
    case "integration_verifier":
      return "Integration gate";
    case "policy_gate":
      return "Policy gate";
    default:
      return "Gate";
  }
}

function hookLabel(hook: string | undefined): string {
  switch (hook) {
    case "complete_task":
      return "CompleteTask";
    case "integration_merge":
      return "IntegrationMerge";
    case "intent":
      return "Intent";
    default:
      return hook ?? "unknown";
  }
}
