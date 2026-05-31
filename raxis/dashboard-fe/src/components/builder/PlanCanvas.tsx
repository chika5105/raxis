import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ReactFlow,
  ReactFlowProvider,
  Background,
  BackgroundVariant,
  Controls,
  Panel,
  BaseEdge,
  EdgeLabelRenderer,
  Handle,
  MarkerType,
  Position,
  ConnectionMode,
  ConnectionLineType,
  addEdge,
  applyEdgeChanges,
  applyNodeChanges,
  useReactFlow,
  type Connection,
  type Edge,
  type EdgeChange,
  type EdgeProps,
  type Node,
  type NodeChange,
  type NodeProps,
  type OnConnect,
  type OnEdgesDelete,
} from "@xyflow/react";
import dagre from "dagre";

import { Tooltip } from "@/components/Tooltip";
import type {
  CredentialDraft,
  CredentialProxyType,
  CredentialSetupDraft,
  PlanVerifierDraft,
  PolicyGateRef,
  TaskDraft,
  ToolProfileDraft,
} from "@/pages/PlanBuilder";

const NODE_W = 270;
const NODE_H = 104;
const GATE_NODE_W = 220;
const GATE_NODE_H = 72;
const EDITOR_W = 440;
const EDITOR_H = 690;
// Handles sit outside the card to make edge-dragging forgiving; the edge path
// is pulled back by the same amount so arrows terminate on the visible border.
const HANDLE_VISUAL_OUTSET = 12;
const EDGE_ANCHOR_INSET = 32;
const NODE_PLACEMENT_MARGIN = 48;
const NODE_PLACEMENT_GAP_X = 96;
const NODE_PLACEMENT_GAP_Y = 48;
const NODE_COLLISION_PADDING = 24;
const NODE_REVEAL_MARGIN = 56;

const EDGE_STYLE: React.CSSProperties = {
  stroke: "rgb(var(--c-accent))",
  strokeWidth: 2.25,
};

const EDGE_MARKER = {
  type: MarkerType.ArrowClosed,
  width: 14,
  height: 14,
  color: "rgb(var(--c-accent))",
};

const GATE_EDGE_STYLE: React.CSSProperties = {
  stroke: "rgb(var(--c-ok))",
  strokeWidth: 2,
  strokeDasharray: "7 5",
  strokeLinecap: "round",
};

const GATE_EDGE_MARKER = {
  type: MarkerType.ArrowClosed,
  width: 13,
  height: 13,
  color: "rgb(var(--c-ok))",
};

const credentialProxyTypes: CredentialProxyType[] = [
  "postgres",
  "mysql",
  "mssql",
  "mongodb",
  "redis",
  "smtp",
  "http",
  "aws",
  "gcp",
  "azure",
  "k8s",
];

export interface PlanCanvasProps {
  tasks: TaskDraft[];
  planVerifiers: PlanVerifierDraft[];
  toolProfiles: ToolProfileDraft[];
  credentialSetups: CredentialSetupDraft[];
  policyGateRefs: PolicyGateRef[];
  selectedTaskId: string | null;
  revealTaskId?: string | null;
  revealVersion?: number;
  arrangeVersion: number;
  canRemoveTask: boolean;
  onSelectTask: (taskId: string | null) => void;
  onUpdateTask: (taskId: string, patch: Partial<TaskDraft>) => void;
  onRemoveTask: (taskId: string) => void;
  onUpdatePredecessors: (taskId: string, predecessors: string) => void;
  onAddTask: (type: "Executor" | "Reviewer") => void;
  onOpenToolProfiles: () => void;
  onOpenCredentialSetup: () => void;
}

interface TaskNodeData extends Record<string, unknown> {
  task: TaskDraft;
  toolProfiles: ToolProfileDraft[];
  credentialSetups: CredentialSetupDraft[];
  policyGateRefs: PolicyGateRef[];
  allTaskIds: string[];
  canRemoveTask: boolean;
  isExpanded: boolean;
  onUpdateTask: (taskId: string, patch: Partial<TaskDraft>) => void;
  onRemoveTask: (taskId: string) => void;
  onCollapse: () => void;
  onOpenToolProfiles: () => void;
  onOpenCredentialSetup: () => void;
}

interface GateNodeData extends Record<string, unknown> {
  title: string;
  subtitle: string;
  badge: string;
  tone: "task" | "policy" | "integration";
  parentTaskId?: string;
}

type BuilderNode = Node<TaskNodeData | GateNodeData>;

function splitList(raw: string): string[] {
  return raw
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
}

function defaultMountAs(proxyType: CredentialProxyType) {
  switch (proxyType) {
    case "postgres":
      return "DATABASE_URL";
    case "mysql":
      return "MYSQL_DSN";
    case "mssql":
      return "MSSQL_DSN";
    case "mongodb":
      return "MONGO_URI";
    case "redis":
      return "REDIS_URL";
    case "smtp":
      return "SMTP_URL";
    case "http":
      return "SERVICE_BASE_URL";
    case "aws":
      return "AWS_CONTAINER_CREDENTIALS_FULL_URI";
    case "gcp":
      return "GOOGLE_APPLICATION_CREDENTIALS";
    case "azure":
      return "AZURE_TOKEN_URL";
    case "k8s":
      return "KUBECONFIG";
    default:
      return "CREDENTIAL_PROXY_URL";
  }
}

function makeCredentialDraft(proxyType: CredentialProxyType = "postgres"): CredentialDraft {
  return {
    name: "",
    proxyType,
    mountAs: defaultMountAs(proxyType),
    upstreamUrl: "",
    upstreamHostPort: "",
    authMode: "bearer",
    project: "",
    tenantId: "",
    roleArn: "",
    clientId: "",
  };
}

function isTextEditingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  const tagName = target.tagName.toLowerCase();
  return (
    tagName === "input" ||
    tagName === "textarea" ||
    tagName === "select" ||
    target.isContentEditable
  );
}

function computeLayout(tasks: TaskDraft[]): Map<string, { x: number; y: number }> {
  const g = new dagre.graphlib.Graph();
  g.setGraph({ rankdir: "LR", nodesep: 80, ranksep: 110, marginx: 80, marginy: 80 });
  g.setDefaultEdgeLabel(() => ({}));

  const ids = new Set(tasks.map((task) => task.id));
  tasks.forEach((task) => g.setNode(task.id, { width: NODE_W, height: NODE_H }));
  tasks.forEach((task) => {
    splitList(task.predecessors).forEach((pred) => {
      if (ids.has(pred) && pred !== task.id) g.setEdge(pred, task.id);
    });
  });
  dagre.layout(g);

  const result = new Map<string, { x: number; y: number }>();
  tasks.forEach((task, index) => {
    const meta = g.node(task.id);
    result.set(task.id, {
      x: (meta?.x ?? 90 + index * (NODE_W + 120)) - NODE_W / 2,
      y: (meta?.y ?? 100) - NODE_H / 2,
    });
  });
  return result;
}

function tasksToNodes(
  tasks: TaskDraft[],
  planVerifiers: PlanVerifierDraft[],
  positions: Map<string, { x: number; y: number }>,
  selectedTaskId: string | null,
  handlers: Omit<TaskNodeData, "task">,
): BuilderNode[] {
  const taskNodes = tasks.map((task, index) => ({
    id: task.id,
    type: "task",
    position: positions.get(task.id) ?? { x: 90 + index * (NODE_W + 120), y: 120 },
    data: {
      ...handlers,
      task,
      isExpanded: task.id === selectedTaskId,
    } as TaskNodeData,
    selected: false,
    zIndex: task.id === selectedTaskId ? 30 : 1,
  })) satisfies BuilderNode[];
  return [
    ...taskNodes,
    ...taskVerifierNodes(tasks, positions, handlers.policyGateRefs as PolicyGateRef[]),
    ...integrationVerifierNodes(tasks, planVerifiers, positions),
  ];
}

function tasksToEdges(tasks: TaskDraft[], planVerifiers: PlanVerifierDraft[] = []): Edge[] {
  const ids = new Set(tasks.map((task) => task.id));
  const taskEdges = tasks.flatMap((task) =>
    splitList(task.predecessors)
      .filter((pred) => ids.has(pred) && pred !== task.id)
      .map((pred) => ({
        id: `${pred}=>${task.id}`,
        source: pred,
        target: task.id,
        type: "deletable",
        style: EDGE_STYLE,
        markerEnd: EDGE_MARKER,
      })),
  );
  const taskGateEdges = tasks
    .filter((task) => task.verifierName.trim())
    .map((task) => ({
      id: `${task.id}=>${taskGateNodeId(task)}`,
      source: task.id,
      target: taskGateNodeId(task),
      type: "deletable",
      data: { kind: "gate" },
      selectable: false,
      deletable: false,
      style: GATE_EDGE_STYLE,
      markerEnd: GATE_EDGE_MARKER,
    }));
  const integrationGateEdges = planVerifiers.flatMap((verifier) =>
    integrationVerifierSourceIds(tasks, verifier).map((source) => ({
      id: `${source}=>${integrationVerifierNodeId(verifier)}`,
      source,
      target: integrationVerifierNodeId(verifier),
      type: "deletable",
      data: { kind: "gate" },
      selectable: false,
      deletable: false,
      style: GATE_EDGE_STYLE,
      markerEnd: GATE_EDGE_MARKER,
    })),
  );
  return [...taskEdges, ...taskGateEdges, ...integrationGateEdges];
}

function taskVerifierNodes(
  tasks: TaskDraft[],
  positions: Map<string, { x: number; y: number }>,
  policyGateRefs: PolicyGateRef[],
): BuilderNode[] {
  return tasks
    .filter((task) => task.verifierName.trim())
    .map((task, index) => {
      const position = positions.get(task.id) ?? { x: 90 + index * (NODE_W + 120), y: 120 };
      const gate = policyGateRefs.find((candidate) => candidate.name === task.verifierName);
      return {
        id: taskGateNodeId(task),
        type: "gate",
        position: {
          x: position.x + NODE_W * 0.42,
          y: position.y + NODE_H + 34,
        },
        data: {
          title: task.verifierName.trim(),
          subtitle: gate
            ? `${gate.source} policy gate${gate.claimTypes.length ? ` · ${gate.claimTypes.join(", ")}` : ""}`
            : task.verifierCommand.trim() || "Per-task verifier",
          badge: gate ? "Policy gate" : "Task verifier",
          tone: gate ? "policy" : "task",
          parentTaskId: task.id,
        } satisfies GateNodeData,
        draggable: false,
        selectable: false,
        connectable: false,
        zIndex: 0,
      };
    });
}

function integrationVerifierNodes(
  tasks: TaskDraft[],
  planVerifiers: PlanVerifierDraft[],
  positions: Map<string, { x: number; y: number }>,
): BuilderNode[] {
  if (tasks.length === 0) return [];
  const taskPositions = tasks.map((task, index) => positions.get(task.id) ?? { x: 90 + index * (NODE_W + 120), y: 120 });
  const maxX = Math.max(...taskPositions.map((position) => position.x));
  const minY = Math.min(...taskPositions.map((position) => position.y));
  return planVerifiers
    .filter((verifier) => verifier.name.trim())
    .map((verifier, index) => ({
      id: integrationVerifierNodeId(verifier),
      type: "gate",
      position: {
        x: maxX + NODE_W + 120,
        y: minY + index * (GATE_NODE_H + 28),
      },
      data: {
        title: verifier.name.trim(),
        subtitle:
          verifier.appliesTo === "task_set"
            ? `Integration verifier · ${splitList(verifier.taskSet).length || 0} task scope`
            : `Integration verifier · ${verifier.appliesTo}`,
        badge: verifier.onFailure === "warn_only" ? "Warn only" : "Blocks merge",
        tone: "integration",
      } satisfies GateNodeData,
      draggable: false,
      selectable: false,
      connectable: false,
      zIndex: 0,
    }));
}

function taskGateNodeId(task: TaskDraft) {
  return `gate::task::${task.id}::${task.verifierName.trim()}`;
}

function integrationVerifierNodeId(verifier: PlanVerifierDraft) {
  return `gate::integration::${verifier.name.trim()}`;
}

function integrationVerifierSourceIds(tasks: TaskDraft[], verifier: PlanVerifierDraft): string[] {
  const ids = new Set(tasks.map((task) => task.id));
  if (verifier.appliesTo === "task_set") {
    return splitList(verifier.taskSet).filter((taskId) => ids.has(taskId));
  }
  return terminalTaskIds(tasks);
}

function terminalTaskIds(tasks: TaskDraft[]): string[] {
  const dependedOn = new Set(tasks.flatMap((task) => splitList(task.predecessors)));
  return tasks.map((task) => task.id).filter((taskId) => !dependedOn.has(taskId));
}

const TaskNode = memo(({ data }: NodeProps<Node<TaskNodeData>>) => {
  const task = data.task;
  const expanded = data.isExpanded;
  const isExecutor = task.agentType === "Executor";
  const border = expanded
    ? "rgb(var(--c-accent))"
    : isExecutor
      ? "rgb(var(--c-info) / 0.72)"
      : "rgb(var(--c-ok) / 0.72)";

  return (
    <div
      data-task-node-id={task.id}
      className="plan-builder-node rounded-lg border-2 bg-panel-raised shadow-soft text-ink transition-[border-color,box-shadow] duration-150"
      style={{
        width: expanded ? `clamp(360px, 42vw, ${EDITOR_W}px)` : NODE_W,
        minHeight: expanded ? `min(${EDITOR_H}px, calc(100vh - 160px))` : NODE_H,
        borderColor: border,
        boxShadow: expanded
          ? "0 0 0 3px rgb(var(--c-accent) / 0.18), 0 18px 44px rgb(0 0 0 / 0.18)"
          : "0 1px 5px rgb(0 0 0 / 0.08)",
      }}
    >
      <TaskEdgeHandles />
      {expanded ? (
        <InlineTaskEditor
          task={task}
          toolProfiles={data.toolProfiles}
          credentialSetups={data.credentialSetups}
          policyGateRefs={data.policyGateRefs}
          allTaskIds={data.allTaskIds}
          canRemove={data.canRemoveTask}
          onUpdate={(patch) => data.onUpdateTask(task.id, patch)}
          onRemove={() => data.onRemoveTask(task.id)}
          onCollapse={data.onCollapse}
          onOpenToolProfiles={data.onOpenToolProfiles}
          onOpenCredentialSetup={data.onOpenCredentialSetup}
        />
      ) : (
        <TaskSummary task={task} />
      )}
    </div>
  );
});
TaskNode.displayName = "TaskNode";

function TaskEdgeHandles() {
  return (
    <>
      <Handle
        id="edge-top"
        type="source"
        position={Position.Top}
        className="task-edge-handle task-edge-handle-top"
      />
      <Handle
        id="edge-right"
        type="source"
        position={Position.Right}
        className="task-edge-handle task-edge-handle-right"
      />
      <Handle
        id="edge-bottom"
        type="source"
        position={Position.Bottom}
        className="task-edge-handle task-edge-handle-bottom"
      />
      <Handle
        id="edge-left"
        type="source"
        position={Position.Left}
        className="task-edge-handle task-edge-handle-left"
      />
    </>
  );
}

function TaskSummary({ task }: { task: TaskDraft }) {
  const isExecutor = task.agentType === "Executor";
  return (
    <div className="p-3">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="truncate font-mono text-xs text-ink">{task.id}</div>
          <div className="mt-1 line-clamp-2 text-xs leading-snug text-ink-muted">
            {task.description || "No description"}
          </div>
        </div>
        <span
          className={`badge shrink-0 text-[9px] ${
            isExecutor ? "border-info bg-info-muted text-info" : "border-ok bg-ok-muted text-ok"
          }`}
        >
          {isExecutor ? "Executor" : "Reviewer"}
        </span>
      </div>
      <div className="mt-3 flex flex-wrap gap-1">
        {splitList(task.profiles).map((profile) => (
          <CapabilityBadge key={profile} label={profile} tone="info" />
        ))}
        {task.credentials.map((credential, index) => {
          const name = credential.name.trim();
          return name ? (
            <CapabilityBadge key={`${name}:${index}`} label={name} tone="warn" />
          ) : null;
        })}
        {task.verifierName && <CapabilityBadge label={task.verifierName} tone="gate" />}
      </div>
    </div>
  );
}

function InlineTaskEditor({
  task,
  toolProfiles,
  credentialSetups,
  policyGateRefs,
  allTaskIds,
  canRemove,
  onUpdate,
  onRemove,
  onCollapse,
  onOpenToolProfiles,
  onOpenCredentialSetup,
}: {
  task: TaskDraft;
  toolProfiles: ToolProfileDraft[];
  credentialSetups: CredentialSetupDraft[];
  policyGateRefs: PolicyGateRef[];
  allTaskIds: string[];
  canRemove: boolean;
  onUpdate: (patch: Partial<TaskDraft>) => void;
  onRemove: () => void;
  onCollapse: () => void;
  onOpenToolProfiles: () => void;
  onOpenCredentialSetup: () => void;
}) {
  const isExecutor = task.agentType === "Executor";
  const selectedProfiles = splitList(task.profiles);
  const knownProfileIds = new Set(toolProfiles.map((profile) => profile.id));
  const missingProfiles = selectedProfiles.filter((profile) => !knownProfileIds.has(profile));
  const selectedPolicyGate = policyGateRefs.find((gate) => gate.name === task.verifierName);
  const effectiveTools = selectedProfiles.flatMap((profileId) => {
    const profile = toolProfiles.find((candidate) => candidate.id === profileId);
    if (!profile) return [];
    return profile.tools.map((tool) => ({
      profileId,
      name: tool.name.trim() || "(unnamed)",
      locality: tool.locality,
    }));
  });
  const toggleProfile = (profileId: string) => {
    const next = selectedProfiles.includes(profileId)
      ? selectedProfiles.filter((profile) => profile !== profileId)
      : [...selectedProfiles, profileId];
    onUpdate({ profiles: next.join(", ") });
  };
  const updateCredential = (index: number, patch: Partial<CredentialDraft>) => {
    onUpdate({
      credentials: task.credentials.map((credential, candidateIndex) =>
        candidateIndex === index ? { ...credential, ...patch } : credential,
      ),
    });
  };
  const addCredential = () => {
    onUpdate({
      credentials: [
        ...task.credentials,
        makeCredentialDraft(),
      ],
    });
  };
  const attachCredentialSetup = (setup: CredentialSetupDraft) => {
    onUpdate({
      credentials: [
        ...task.credentials,
        {
          name: setup.name,
          proxyType: setup.proxyType,
          mountAs: setup.mountAs,
          upstreamUrl: setup.upstreamUrl,
          upstreamHostPort: setup.upstreamHostPort,
          authMode: setup.authMode,
          project: setup.project,
          tenantId: setup.tenantId,
          roleArn: setup.roleArn,
          clientId: setup.clientId,
        },
      ],
    });
  };
  const removeCredential = (index: number) => {
    onUpdate({
      credentials: task.credentials.filter((_, candidateIndex) => candidateIndex !== index),
    });
  };
  const removeStartedRef = useRef(false);
  const requestRemove = () => {
    if (!canRemove) return;
    onRemove();
  };
  const handleRemoveMouseDown = (event: React.MouseEvent<HTMLButtonElement>) => {
    event.preventDefault();
    event.stopPropagation();
    removeStartedRef.current = true;
    requestRemove();
  };
  const handleRemoveClick = (event: React.MouseEvent<HTMLButtonElement>) => {
    event.preventDefault();
    event.stopPropagation();
    if (removeStartedRef.current) {
      removeStartedRef.current = false;
      return;
    }
    requestRemove();
  };
  return (
    <div
      className="nowheel flex max-h-[min(78vh,720px)] flex-col overflow-hidden"
      onClick={(event) => event.stopPropagation()}
      onDoubleClick={(event) => event.stopPropagation()}
      onWheel={(event) => {
        event.stopPropagation();
      }}
    >
      <div className="task-card-drag-handle shrink-0 cursor-grab border-b border-edge bg-panel-raised px-4 py-3 active:cursor-grabbing">
        <div className="flex items-center justify-between gap-3">
          <div className="min-w-0">
            <div className="text-[10px] font-semibold uppercase tracking-wider text-ink-subtle">
              Task card
            </div>
            <div className="mt-1 truncate font-mono text-sm text-ink">{task.id}</div>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <span
              className={`badge text-[10px] ${
                isExecutor ? "border-info bg-info-muted text-info" : "border-ok bg-ok-muted text-ok"
              }`}
            >
              {task.agentType || "Role required"}
            </span>
            <Tooltip content={canRemove ? "Delete task card" : "A plan needs at least one task"}>
              <button
                type="button"
                className="nodrag nopan nowheel inline-grid h-7 w-7 place-items-center rounded-md border border-bad/30 bg-panel text-bad transition-colors hover:bg-bad/10 disabled:cursor-not-allowed disabled:border-edge disabled:text-ink-subtle disabled:hover:bg-panel focus:outline-none focus-visible:ring-2 focus-visible:ring-bad"
                aria-label="Delete task card"
                disabled={!canRemove}
                onPointerDown={(event) => event.stopPropagation()}
                onMouseDown={handleRemoveMouseDown}
                onClick={handleRemoveClick}
              >
                <svg
                  className="h-3.5 w-3.5"
                  viewBox="0 0 16 16"
                  fill="none"
                  aria-hidden
                >
                  <path
                    d="M6 2.75h4M3.75 4.75h8.5M5 4.75l.5 8.25h5l.5-8.25M7 7v4M9 7v4"
                    stroke="currentColor"
                    strokeWidth="1.55"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
              </button>
            </Tooltip>
            <Tooltip content="Collapse task card">
              <button
                type="button"
                className="nodrag nopan nowheel inline-grid h-7 w-7 place-items-center rounded-md border border-edge-strong bg-panel text-ink-muted transition-colors hover:border-accent hover:bg-panel-high hover:text-accent focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                aria-label="Collapse task card"
                onPointerDown={(event) => event.stopPropagation()}
                onMouseDown={(event) => event.stopPropagation()}
                onClick={(event) => {
                  event.stopPropagation();
                  onCollapse();
                }}
              >
                <svg
                  className="h-3.5 w-3.5"
                  viewBox="0 0 16 16"
                  fill="none"
                  aria-hidden
                >
                  <path
                    d="M4 8h8"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                  />
                </svg>
              </button>
            </Tooltip>
          </div>
        </div>
      </div>

      <div
        data-task-scroll-region
        className="nodrag nopan nowheel flex-1 overflow-y-auto overscroll-contain scroll-thin p-4 pb-8 space-y-3 [touch-action:pan-y]"
        onPointerDown={(event) => event.stopPropagation()}
      >
        <div className="grid grid-cols-[1fr_8.5rem] gap-2">
          <CardField label="Task id">
            <input
              value={task.id}
              onChange={(e) => onUpdate({ id: e.target.value })}
              className="input w-full font-mono text-xs"
            />
          </CardField>
          <CardField label="Role">
            <select
              value={task.agentType}
              onChange={(e) => onUpdate({ agentType: e.target.value as TaskDraft["agentType"] })}
              className="input w-full text-xs"
            >
              <option value="">Choose role</option>
              <option>Executor</option>
              <option>Reviewer</option>
            </select>
          </CardField>
        </div>

        <CardField label="Description">
          <input
            value={task.description}
            onChange={(e) => onUpdate({ description: e.target.value })}
            className="input w-full text-xs"
          />
        </CardField>

        <CardField label="Predecessors">
          <input
            value={task.predecessors}
            onChange={(e) => onUpdate({ predecessors: e.target.value })}
            className="input w-full font-mono text-xs"
            placeholder="task-a, task-b"
          />
          {task.predecessors && (
            <div className="mt-1 flex flex-wrap gap-1">
              {splitList(task.predecessors).map((pred) => (
                <span
                  key={pred}
                  className={`badge text-[9px] ${
                    allTaskIds.includes(pred)
                      ? "border-ok/40 bg-ok-muted text-ok"
                      : "border-bad/40 bg-bad/10 text-bad"
                  }`}
                >
                  {pred}
                </span>
              ))}
            </div>
          )}
        </CardField>

        <div className="grid grid-cols-[1fr_8.5rem] gap-2">
          <CardField label="Path allowlist">
            <input
              value={task.paths}
              onChange={(e) => onUpdate({ paths: e.target.value })}
              className="input w-full font-mono text-xs"
              placeholder="src/, README.md"
            />
          </CardField>
          <CardField label="Clone strategy">
            <select
              value={task.cloneStrategy}
              onChange={(e) => onUpdate({ cloneStrategy: e.target.value as TaskDraft["cloneStrategy"] })}
              className="input w-full text-xs"
            >
              <option value="">Choose strategy</option>
              <option>blobless</option>
              <option>full</option>
              <option>sparse</option>
            </select>
          </CardField>
        </div>

        {isExecutor && (
          <div className="grid grid-cols-2 gap-2">
            <CardField label="Allowed egress">
              <input
                value={task.allowedEgress}
                onChange={(e) => onUpdate({ allowedEgress: e.target.value })}
                className="input w-full font-mono text-xs"
                placeholder="api.github.com"
              />
            </CardField>
            <CardField label="Path export globs">
              <input
                value={task.pathExports}
                onChange={(e) => onUpdate({ pathExports: e.target.value })}
                className="input w-full font-mono text-xs"
                placeholder="docs/**/*.md"
              />
            </CardField>
          </div>
        )}

        <div className="grid grid-cols-3 gap-2">
          <CardField label="Max turns">
            <input
              value={task.maxTurns}
              onChange={(e) => onUpdate({ maxTurns: e.target.value })}
              className="input w-full font-mono text-xs"
              placeholder="60"
            />
          </CardField>
          <CardField label="Turn step">
            <input
              value={task.maxTurnsStep}
              onChange={(e) => onUpdate({ maxTurnsStep: e.target.value })}
              className="input w-full font-mono text-xs"
              placeholder="30"
            />
          </CardField>
          <CardField label="Wall cap (s)">
            <input
              value={task.cumulativeMaxSeconds}
              onChange={(e) => onUpdate({ cumulativeMaxSeconds: e.target.value })}
              className="input w-full font-mono text-xs"
              placeholder="600"
            />
          </CardField>
        </div>

        {isExecutor && (
          <>
            <div className="grid grid-cols-2 gap-2">
              <CardField label="VM image">
                <input
                  value={task.vmImage}
                  onChange={(e) => onUpdate({ vmImage: e.target.value })}
                  className="input w-full font-mono text-xs"
                  placeholder="raxis-canonical"
                />
              </CardField>
              <CardField label="Tool profiles">
                <div className="rounded border border-edge bg-panel px-2 py-2">
                  {toolProfiles.length === 0 ? (
                    <div className="text-[11px] text-ink-subtle">No shared profiles.</div>
                  ) : (
                    <div className="flex flex-wrap gap-1.5">
                      {toolProfiles.map((profile) => {
                        const selected = selectedProfiles.includes(profile.id);
                        return (
                          <button
                            key={profile.id}
                            type="button"
                            className={`badge max-w-full text-[10px] transition-colors ${
                              selected
                                ? "border-info bg-info-muted text-info"
                                : "border-edge bg-panel text-ink-muted hover:border-info/50 hover:text-info"
                            }`}
                            onClick={(event) => {
                              event.stopPropagation();
                              toggleProfile(profile.id);
                            }}
                          >
                            {profile.id}
                          </button>
                        );
                      })}
                    </div>
                  )}
                  {missingProfiles.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-1">
                      {missingProfiles.map((profile) => (
                        <span
                          key={profile}
                          className="badge border-bad/40 bg-bad/10 text-[10px] text-bad"
                        >
                          {profile} missing
                        </span>
                      ))}
                    </div>
                  )}
                  <div className="mt-2 border-t border-edge/70 pt-2">
                    <div className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-ink-subtle">
                      Effective tools ({effectiveTools.length})
                    </div>
                    {effectiveTools.length === 0 ? (
                      <div className="text-[11px] text-ink-subtle">
                        No custom tools selected for this executor.
                      </div>
                    ) : (
                      <div className="space-y-1">
                        {effectiveTools.slice(0, 6).map((tool, index) => (
                          <div
                            key={`${tool.profileId}:${tool.name}:${index}`}
                            className="flex min-w-0 items-center justify-between gap-2 rounded border border-edge/70 bg-panel-high px-1.5 py-1 text-[10px]"
                          >
                            <span className="truncate font-mono text-ink">{tool.name}</span>
                            <span className="shrink-0 text-ink-subtle">
                              {tool.profileId} / {tool.locality}
                            </span>
                          </div>
                        ))}
                        {effectiveTools.length > 6 && (
                          <div className="text-[10px] text-ink-subtle">
                            +{effectiveTools.length - 6} more from selected profiles
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
                <button
                  type="button"
                  className="mt-1 text-[10px] font-semibold text-accent hover:underline"
                  onClick={(event) => {
                    event.stopPropagation();
                    onOpenToolProfiles();
                  }}
                >
                  Edit shared profiles
                </button>
              </CardField>
            </div>

            <InlineSection
              title={`Credential bindings (${task.credentials.length})`}
              action={
                <div className="flex items-center gap-1.5">
                  <button
                    type="button"
                    className="btn nowheel px-2 py-1 text-[10px]"
                    onClick={(event) => {
                      event.stopPropagation();
                      onOpenCredentialSetup();
                    }}
                  >
                    Setup
                  </button>
                  <button
                    type="button"
                    className="btn nowheel px-2 py-1 text-[10px]"
                    onClick={(event) => {
                      event.stopPropagation();
                      addCredential();
                    }}
                  >
                    Add
                  </button>
                </div>
              }
            >
              {credentialSetups.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {credentialSetups.map((setup) => {
                    const alreadyBound = task.credentials.some(
                      (credential) => credential.name.trim() === setup.name.trim(),
                    );
                    return (
                      <button
                        key={setup.name}
                        type="button"
                        className={`badge max-w-full text-[10px] transition-colors ${
                          alreadyBound
                            ? "border-edge bg-panel text-ink-subtle"
                            : "border-warn/60 bg-warn-muted text-warn hover:border-warn"
                        }`}
                        disabled={alreadyBound}
                        onClick={(event) => {
                          event.stopPropagation();
                          attachCredentialSetup(setup);
                        }}
                      >
                        {alreadyBound ? `${setup.name} attached` : `Attach ${setup.name}`}
                      </button>
                    );
                  })}
                </div>
              )}
              {task.credentials.length === 0 ? (
                <div className="rounded border border-dashed border-edge bg-panel px-2 py-2 text-[11px] text-ink-subtle">
                  No credentials bound to this executor.
                </div>
              ) : (
                <div className="space-y-2">
                  {task.credentials.map((credential, index) => (
                    <div
                      key={index}
                      className="rounded border border-edge bg-panel p-2"
                    >
                      <div className="mb-2 flex items-center justify-between gap-2">
                        <span className="font-mono text-[10px] text-ink-subtle">
                          credential {index + 1}
                        </span>
                        <button
                          type="button"
                          className="text-[10px] font-semibold text-bad hover:underline"
                          onClick={(event) => {
                            event.stopPropagation();
                            removeCredential(index);
                          }}
                        >
                          Remove
                        </button>
                      </div>
                      <div className="grid grid-cols-[1fr_7.5rem] gap-2">
                        <CardField label="Name">
                          <input
                            value={credential.name}
                            onChange={(e) => updateCredential(index, { name: e.target.value })}
                            className="input w-full font-mono text-xs"
                            placeholder="staging-api"
                          />
                        </CardField>
                        <CardField label="Proxy type">
                          <select
                            value={credential.proxyType}
                            onChange={(e) => {
                              const proxyType = e.target.value as CredentialProxyType;
                              updateCredential(index, {
                                proxyType,
                                mountAs:
                                  credential.mountAs === defaultMountAs(credential.proxyType)
                                    ? defaultMountAs(proxyType)
                                    : credential.mountAs,
                              });
                            }}
                            className="input w-full text-xs"
                          >
                            {credentialProxyTypes.map((proxyType) => (
                              <option key={proxyType}>{proxyType}</option>
                            ))}
                          </select>
                        </CardField>
                      </div>
                      <CardField label="Mount env">
                        <input
                          value={credential.mountAs}
                          onChange={(e) => updateCredential(index, { mountAs: e.target.value })}
                          className="input w-full font-mono text-xs"
                          placeholder={defaultMountAs(credential.proxyType)}
                        />
                      </CardField>
                      <CredentialBindingFields
                        credential={credential}
                        onUpdate={(patch) => updateCredential(index, patch)}
                      />
                    </div>
                  ))}
                </div>
              )}
            </InlineSection>
          </>
        )}

        <InlineSection title="Per-task verifier">
          <div className="grid grid-cols-3 gap-2">
            <CardField label="Verifier">
              <div className="space-y-1">
                <input
                  value={task.verifierName}
                  onChange={(e) => onUpdate({ verifierName: e.target.value })}
                  className="input w-full font-mono text-xs"
                  placeholder="no_secret_strings"
                  list={`policy-gates-${task.id}`}
                />
                <datalist id={`policy-gates-${task.id}`}>
                  {policyGateRefs.map((gate) => (
                    <option key={`${gate.source}:${gate.name}`} value={gate.name}>
                      {gate.source} policy gate
                    </option>
                  ))}
                </datalist>
                {selectedPolicyGate && (
                  <p className="text-[10px] leading-snug text-ink-subtle">
                    Policy gate from {selectedPolicyGate.source}
                    {selectedPolicyGate.claimTypes.length
                      ? `; satisfies ${selectedPolicyGate.claimTypes.join(", ")}`
                      : ""}
                    .
                  </p>
                )}
              </div>
            </CardField>
            <CardField label="Image">
              <input
                value={task.verifierImage}
                onChange={(e) => onUpdate({ verifierImage: e.target.value })}
                className="input w-full font-mono text-xs"
                placeholder="raxis-verifier-starter"
              />
            </CardField>
            <CardField label="On failure">
              <select
                value={task.verifierOnFailure}
                onChange={(e) =>
                  onUpdate({
                    verifierOnFailure:
                      e.target.value === "warn_only" ? "warn_only" : "block_review",
                  })
                }
                className="input w-full font-mono text-xs"
              >
                <option value="block_review">block_review</option>
                <option value="warn_only">warn_only</option>
              </select>
            </CardField>
          </div>
          <div className="grid grid-cols-[1fr_8rem] gap-2">
            <CardField label="Command">
              <input
                value={task.verifierCommand}
                onChange={(e) => onUpdate({ verifierCommand: e.target.value })}
                className="input w-full font-mono text-xs"
                placeholder="cargo test --workspace"
              />
            </CardField>
            <CardField label="Timeout">
              <input
                value={task.verifierTimeout}
                onChange={(e) => onUpdate({ verifierTimeout: e.target.value })}
                className="input w-full font-mono text-xs"
                placeholder="30s"
              />
            </CardField>
          </div>
          <div className="grid grid-cols-[1fr_8rem] gap-2">
            <CardField label="Artifact">
              <input
                value={task.verifierArtifact}
                onChange={(e) => onUpdate({ verifierArtifact: e.target.value })}
                className="input w-full font-mono text-xs"
                placeholder="/raxis/verifier-output.json"
              />
            </CardField>
            <CardField label="Max bytes">
              <input
                value={task.verifierArtifactMaxBytes}
                onChange={(e) => onUpdate({ verifierArtifactMaxBytes: e.target.value })}
                className="input w-full font-mono text-xs"
                placeholder="1048576"
              />
            </CardField>
          </div>
        </InlineSection>

        <CardField label="Prompt">
          <textarea
            value={task.prompt}
            onChange={(e) => onUpdate({ prompt: e.target.value })}
            rows={5}
            className="input w-full min-h-[116px] text-xs"
          />
        </CardField>
      </div>

      <div className="shrink-0 border-t border-edge bg-panel-raised px-4 py-3">
        <div className="flex items-center justify-between gap-2">
          <p className="text-[10px] leading-relaxed text-ink-subtle">
            {isExecutor
              ? "Executors do work inside explicit paths, tools, egress, and credentials."
              : "Reviewers inspect predecessor output; executor-only fields are hidden."}
          </p>
          <button
            type="button"
            className="btn nowheel text-xs py-1 text-bad border-bad/30 hover:bg-bad/10"
            disabled={!canRemove}
            onPointerDown={(event) => event.stopPropagation()}
            onMouseDown={handleRemoveMouseDown}
            onClick={handleRemoveClick}
          >
            Delete
          </button>
        </div>
      </div>
    </div>
  );
}

function InlineSection({
  title,
  action,
  children,
}: {
  title: string;
  action?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section className="rounded border border-edge bg-panel-raised p-3 space-y-2">
      <div className="flex items-center justify-between gap-2">
        <div className="text-[10px] font-semibold uppercase tracking-wider text-ink-subtle">
          {title}
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}

function CredentialBindingFields({
  credential,
  onUpdate,
}: {
  credential: CredentialDraft;
  onUpdate: (patch: Partial<CredentialDraft>) => void;
}) {
  if (credential.proxyType === "http") {
    return (
      <div className="grid grid-cols-2 gap-2">
        <CardField label="Upstream URL">
          <input
            value={credential.upstreamUrl}
            onChange={(e) => onUpdate({ upstreamUrl: e.target.value })}
            className="input w-full font-mono text-xs"
            placeholder="https://api.example.com/v1"
          />
        </CardField>
        <CardField label="Auth mode">
          <select
            value={credential.authMode}
            onChange={(e) => onUpdate({ authMode: e.target.value })}
            className="input w-full text-xs"
          >
            <option>bearer</option>
            <option>basic</option>
          </select>
        </CardField>
      </div>
    );
  }
  if (credential.proxyType === "redis" || credential.proxyType === "smtp") {
    return (
      <CardField label="Upstream host:port">
        <input
          value={credential.upstreamHostPort}
          onChange={(e) => onUpdate({ upstreamHostPort: e.target.value })}
          className="input w-full font-mono text-xs"
          placeholder={credential.proxyType === "redis" ? "redis.example.com:6379" : "smtp.example.com:587"}
        />
      </CardField>
    );
  }
  if (credential.proxyType === "gcp") {
    return (
      <CardField label="Project id">
        <input
          value={credential.project}
          onChange={(e) => onUpdate({ project: e.target.value })}
          className="input w-full font-mono text-xs"
          placeholder="my-staging-project"
        />
      </CardField>
    );
  }
  if (credential.proxyType === "azure") {
    return (
      <div className="grid grid-cols-2 gap-2">
        <CardField label="Tenant id">
          <input
            value={credential.tenantId}
            onChange={(e) => onUpdate({ tenantId: e.target.value })}
            className="input w-full font-mono text-xs"
            placeholder="tenant-id"
          />
        </CardField>
        <CardField label="Client id">
          <input
            value={credential.clientId}
            onChange={(e) => onUpdate({ clientId: e.target.value })}
            className="input w-full font-mono text-xs"
            placeholder="optional"
          />
        </CardField>
      </div>
    );
  }
  if (credential.proxyType === "aws") {
    return (
      <CardField label="Role ARN">
        <input
          value={credential.roleArn}
          onChange={(e) => onUpdate({ roleArn: e.target.value })}
          className="input w-full font-mono text-xs"
          placeholder="arn:aws:iam::123456789012:role/raxis-agent"
        />
      </CardField>
    );
  }
  return null;
}

function CardField({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <label className="block text-[10px] font-semibold text-ink-subtle">
      <span>{label}</span>
      <span className="mt-1 block">{children}</span>
    </label>
  );
}

function CapabilityBadge({ label, tone }: { label: string; tone: "info" | "warn" | "gate" }) {
  const cls =
    tone === "info"
      ? "border-info bg-info-muted text-info"
      : tone === "warn"
        ? "border-warn bg-warn-muted text-warn"
        : "border-ok bg-panel text-ok border-dashed";
  return <span className={`badge max-w-full truncate text-[9px] ${cls}`}>{label}</span>;
}

interface NodeRect {
  x: number;
  y: number;
  width: number;
  height: number;
}

type FlowRect = NodeRect;

interface EdgeEndpoint {
  x: number;
  y: number;
  position: Position;
}

interface RoutedEdge {
  source: EdgeEndpoint;
  target: EdgeEndpoint;
}

interface EdgeFallbackGeometry {
  sourceX: number;
  sourceY: number;
  targetX: number;
  targetY: number;
  sourcePosition: Position;
  targetPosition: Position;
}

function getFluidEdgePath(route: RoutedEdge) {
  const sourceVector = positionVector(route.source.position);
  const targetVector = positionVector(route.target.position);
  const dx = route.target.x - route.source.x;
  const dy = route.target.y - route.source.y;
  const distance = Math.hypot(dx, dy);
  const controlOffset = Math.max(Math.min(distance * 0.42, 180), 64);
  const c1x = route.source.x + sourceVector.x * controlOffset;
  const c1y = route.source.y + sourceVector.y * controlOffset;
  const c2x = route.target.x + targetVector.x * controlOffset;
  const c2y = route.target.y + targetVector.y * controlOffset;
  const labelX =
    0.125 * route.source.x +
    0.375 * c1x +
    0.375 * c2x +
    0.125 * route.target.x;
  const labelY =
    0.125 * route.source.y +
    0.375 * c1y +
    0.375 * c2y +
    0.125 * route.target.y;

  return [`M ${route.source.x},${route.source.y} C ${c1x},${c1y} ${c2x},${c2y} ${route.target.x},${route.target.y}`, labelX, labelY] as const;
}

function routeBetweenNodes(source: NodeRect, target: NodeRect): RoutedEdge {
  const sourceCenter = rectCenter(source);
  const targetCenter = rectCenter(target);
  const dx = targetCenter.x - sourceCenter.x;
  const dy = targetCenter.y - sourceCenter.y;
  const horizontalGap = Math.max(target.x - (source.x + source.width), source.x - (target.x + target.width), 0);
  const verticalGap = Math.max(target.y - (source.y + source.height), source.y - (target.y + target.height), 0);

  if (horizontalGap >= verticalGap || Math.abs(dx) >= Math.abs(dy)) {
    if (dx >= 0) {
      return {
        source: sideEndpoint(source, Position.Right, targetCenter),
        target: sideEndpoint(target, Position.Left, sourceCenter),
      };
    }
    return {
      source: sideEndpoint(source, Position.Left, targetCenter),
      target: sideEndpoint(target, Position.Right, sourceCenter),
    };
  }

  if (dy >= 0) {
    return {
      source: sideEndpoint(source, Position.Bottom, targetCenter),
      target: sideEndpoint(target, Position.Top, sourceCenter),
    };
  }
  return {
    source: sideEndpoint(source, Position.Top, targetCenter),
    target: sideEndpoint(target, Position.Bottom, sourceCenter),
  };
}

function fallbackRoute(geometry: EdgeFallbackGeometry): RoutedEdge {
  return {
    source: {
      ...alignEndpointToCard(geometry.sourceX, geometry.sourceY, geometry.sourcePosition),
      position: geometry.sourcePosition,
    },
    target: {
      ...alignEndpointToCard(geometry.targetX, geometry.targetY, geometry.targetPosition),
      position: geometry.targetPosition,
    },
  };
}

function sideEndpoint(rect: NodeRect, position: Position, toward: { x: number; y: number }): EdgeEndpoint {
  switch (position) {
    case Position.Top:
      return {
        x: clamp(toward.x, rect.x + EDGE_ANCHOR_INSET, rect.x + rect.width - EDGE_ANCHOR_INSET),
        y: rect.y,
        position,
      };
    case Position.Right:
      return {
        x: rect.x + rect.width,
        y: clamp(toward.y, rect.y + EDGE_ANCHOR_INSET, rect.y + rect.height - EDGE_ANCHOR_INSET),
        position,
      };
    case Position.Bottom:
      return {
        x: clamp(toward.x, rect.x + EDGE_ANCHOR_INSET, rect.x + rect.width - EDGE_ANCHOR_INSET),
        y: rect.y + rect.height,
        position,
      };
    case Position.Left:
    default:
      return {
        x: rect.x,
        y: clamp(toward.y, rect.y + EDGE_ANCHOR_INSET, rect.y + rect.height - EDGE_ANCHOR_INSET),
        position: Position.Left,
      };
  }
}

function rectCenter(rect: NodeRect) {
  return {
    x: rect.x + rect.width / 2,
    y: rect.y + rect.height / 2,
  };
}

function positionVector(position: Position) {
  switch (position) {
    case Position.Top:
      return { x: 0, y: -1 };
    case Position.Right:
      return { x: 1, y: 0 };
    case Position.Bottom:
      return { x: 0, y: 1 };
    case Position.Left:
    default:
      return { x: -1, y: 0 };
  }
}

function alignEndpointToCard(x: number, y: number, position: Position) {
  switch (position) {
    case Position.Top:
      return { x, y: y + HANDLE_VISUAL_OUTSET };
    case Position.Right:
      return { x: x - HANDLE_VISUAL_OUTSET, y };
    case Position.Bottom:
      return { x, y: y - HANDLE_VISUAL_OUTSET };
    case Position.Left:
      return { x: x + HANDLE_VISUAL_OUTSET, y };
    default:
      return { x, y };
  }
}

function clamp(value: number, min: number, max: number) {
  if (max < min) return (min + max) / 2;
  return Math.min(Math.max(value, min), max);
}

function getVisibleFlowRect(
  pane: HTMLDivElement | null,
  screenToFlowPosition: ReturnType<typeof useReactFlow>["screenToFlowPosition"],
): FlowRect | null {
  if (!pane) return null;
  const rect = pane.getBoundingClientRect();
  if (rect.width <= 0 || rect.height <= 0) return null;
  const topLeft = screenToFlowPosition({ x: rect.left, y: rect.top });
  const bottomRight = screenToFlowPosition({ x: rect.right, y: rect.bottom });
  const x = Math.min(topLeft.x, bottomRight.x);
  const y = Math.min(topLeft.y, bottomRight.y);
  return {
    x,
    y,
    width: Math.abs(bottomRight.x - topLeft.x),
    height: Math.abs(bottomRight.y - topLeft.y),
  };
}

function rectsOverlap(a: NodeRect, b: NodeRect, padding = 0) {
  return !(
    a.x + a.width + padding <= b.x ||
    b.x + b.width + padding <= a.x ||
    a.y + a.height + padding <= b.y ||
    b.y + b.height + padding <= a.y
  );
}

function rectIntersects(a: NodeRect, b: NodeRect) {
  return rectsOverlap(a, b, 0);
}

function nodeRectAt(position: { x: number; y: number }): NodeRect {
  return {
    x: position.x,
    y: position.y,
    width: NODE_W,
    height: NODE_H,
  };
}

function positionFitsVisible(position: { x: number; y: number }, visible: FlowRect) {
  const minX = visible.x + NODE_PLACEMENT_MARGIN;
  const minY = visible.y + NODE_PLACEMENT_MARGIN;
  const maxX = visible.x + visible.width - NODE_PLACEMENT_MARGIN - NODE_W;
  const maxY = visible.y + visible.height - NODE_PLACEMENT_MARGIN - NODE_H;
  return position.x >= minX && position.x <= maxX && position.y >= minY && position.y <= maxY;
}

function positionIsOpen(position: { x: number; y: number }, occupied: NodeRect[]) {
  const candidate = nodeRectAt(position);
  return occupied.every((rect) => !rectsOverlap(candidate, rect, NODE_COLLISION_PADDING));
}

function findOpenNodePosition({
  visible,
  occupied,
  anchor,
}: {
  visible: FlowRect | null;
  occupied: NodeRect[];
  anchor: NodeRect | null;
}) {
  const fallbackAnchor =
    anchor ??
    (visible
      ? {
          x: visible.x + NODE_PLACEMENT_MARGIN,
          y: visible.y + NODE_PLACEMENT_MARGIN,
          width: NODE_W,
          height: NODE_H,
        }
      : occupied.at(-1) ?? { x: 90, y: 120, width: NODE_W, height: NODE_H });
  const preferred = [
    {
      x: fallbackAnchor.x + fallbackAnchor.width + NODE_PLACEMENT_GAP_X,
      y: fallbackAnchor.y,
    },
    {
      x: fallbackAnchor.x,
      y: fallbackAnchor.y + fallbackAnchor.height + NODE_PLACEMENT_GAP_Y,
    },
    {
      x: fallbackAnchor.x,
      y: fallbackAnchor.y - NODE_H - NODE_PLACEMENT_GAP_Y,
    },
  ];

  if (visible) {
    for (const position of preferred) {
      if (positionFitsVisible(position, visible) && positionIsOpen(position, occupied)) {
        return position;
      }
    }

    const minX = visible.x + NODE_PLACEMENT_MARGIN;
    const minY = visible.y + NODE_PLACEMENT_MARGIN;
    const maxX = visible.x + visible.width - NODE_PLACEMENT_MARGIN - NODE_W;
    const maxY = visible.y + visible.height - NODE_PLACEMENT_MARGIN - NODE_H;
    if (maxX >= minX && maxY >= minY) {
      const rowStep = NODE_H + NODE_PLACEMENT_GAP_Y;
      const colStep = NODE_W + NODE_PLACEMENT_GAP_X;
      const rows: number[] = [];
      for (let y = minY; y <= maxY; y += rowStep) rows.push(y);
      rows.sort((a, b) => Math.abs(a - fallbackAnchor.y) - Math.abs(b - fallbackAnchor.y));
      for (const y of rows) {
        for (let x = minX; x <= maxX; x += colStep) {
          const position = { x, y };
          if (positionIsOpen(position, occupied)) return position;
        }
      }
    }
  }

  for (let attempt = 0; attempt < 16; attempt += 1) {
    const position = {
      x: fallbackAnchor.x + fallbackAnchor.width + NODE_PLACEMENT_GAP_X + attempt * (NODE_W + NODE_PLACEMENT_GAP_X),
      y: fallbackAnchor.y + (attempt % 3) * (NODE_H + NODE_PLACEMENT_GAP_Y),
    };
    if (positionIsOpen(position, occupied)) return position;
  }
  return preferred[0];
}

function revealFlowRect(
  rect: NodeRect,
  pane: HTMLDivElement | null,
  flowToScreenPosition: ReturnType<typeof useReactFlow>["flowToScreenPosition"],
  getViewport: ReturnType<typeof useReactFlow>["getViewport"],
  setViewport: ReturnType<typeof useReactFlow>["setViewport"],
) {
  if (!pane) return;
  const paneRect = pane.getBoundingClientRect();
  const topLeft = flowToScreenPosition({ x: rect.x, y: rect.y });
  const bottomRight = flowToScreenPosition({ x: rect.x + rect.width, y: rect.y + rect.height });
  let dx = 0;
  let dy = 0;

  if (bottomRight.x > paneRect.right - NODE_REVEAL_MARGIN) {
    dx = paneRect.right - NODE_REVEAL_MARGIN - bottomRight.x;
  } else if (topLeft.x < paneRect.left + NODE_REVEAL_MARGIN) {
    dx = paneRect.left + NODE_REVEAL_MARGIN - topLeft.x;
  }
  if (bottomRight.y > paneRect.bottom - NODE_REVEAL_MARGIN) {
    dy = paneRect.bottom - NODE_REVEAL_MARGIN - bottomRight.y;
  } else if (topLeft.y < paneRect.top + NODE_REVEAL_MARGIN) {
    dy = paneRect.top + NODE_REVEAL_MARGIN - topLeft.y;
  }

  if (Math.abs(dx) < 1 && Math.abs(dy) < 1) return;
  const viewport = getViewport();
  void setViewport(
    {
      x: viewport.x + dx,
      y: viewport.y + dy,
      zoom: viewport.zoom,
    },
    { duration: 180 },
  );
}

function nodeRect(node: ReturnType<ReturnType<typeof useReactFlow>["getInternalNode"]>): NodeRect | null {
  if (!node) return null;
  const width = node.measured.width ?? node.width ?? NODE_W;
  const height = node.measured.height ?? node.height ?? NODE_H;
  return {
    x: node.internals.positionAbsolute.x,
    y: node.internals.positionAbsolute.y,
    width,
    height,
  };
}

function DeletableEdge({
  id,
  source,
  target,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  style,
  markerEnd,
  selected,
  data,
}: EdgeProps) {
  const reactFlow = useReactFlow();
  const { deleteElements } = reactFlow;
  const isGate = isGateEdgeData(data);
  const sourceRect = nodeRect(reactFlow.getInternalNode(source));
  const targetRect = nodeRect(reactFlow.getInternalNode(target));
  const route = sourceRect && targetRect
    ? routeBetweenNodes(sourceRect, targetRect)
    : fallbackRoute({ sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition });
  const [edgePath, labelX, labelY] = getFluidEdgePath(route);

  return (
    <>
      <BaseEdge
        path={edgePath}
        markerEnd={markerEnd}
        interactionWidth={24}
        style={{
          ...style,
          stroke: isGate
            ? "rgb(var(--c-ok))"
            : selected
              ? "rgb(var(--c-accent))"
              : (style?.stroke as string),
          strokeDasharray: isGate ? "7 5" : style?.strokeDasharray,
          strokeWidth: selected && !isGate ? 3 : ((style?.strokeWidth as number) ?? 2.25),
        }}
      />
      {!isGate && (
        <EdgeLabelRenderer>
          <Tooltip
            content="Remove dependency"
            className="nodrag nopan opacity-0 transition-opacity"
            style={{
              position: "absolute",
              transform: `translate(-50%, -50%) translate(${labelX}px,${labelY}px)`,
              pointerEvents: "all",
            }}
            onMouseEnter={(event) => {
              event.currentTarget.style.opacity = "1";
            }}
            onMouseLeave={(event) => {
              event.currentTarget.style.opacity = "0";
            }}
          >
            <button
              className="flex items-center justify-center rounded-full border border-edge-strong bg-panel-raised text-[9px] font-bold text-ink-muted transition-colors hover:bg-bad/10 hover:text-bad"
              style={{ width: 20, height: 20 }}
              onClick={(event) => {
                event.stopPropagation();
                void deleteElements({ edges: [{ id }] });
              }}
              aria-label="Remove dependency"
              type="button"
            >
              ×
            </button>
          </Tooltip>
        </EdgeLabelRenderer>
      )}
    </>
  );
}

function GateNode({ data }: NodeProps<Node<GateNodeData>>) {
  const toneClass =
    data.tone === "policy"
      ? "border-ok bg-ok-muted text-ok"
      : data.tone === "integration"
        ? "border-warn bg-warn-muted text-warn"
        : "border-info bg-info-muted text-info";
  return (
    <Tooltip
      content={data.parentTaskId ? `${data.badge} for ${data.parentTaskId}` : data.badge}
      side="bottom"
    >
      <div
        className="rounded-lg border border-dashed border-ok/70 bg-panel-raised px-3 py-2 text-ink shadow-soft"
        style={{ width: GATE_NODE_W, minHeight: GATE_NODE_H }}
      >
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0">
            <div className="truncate font-mono text-xs font-semibold">{data.title}</div>
            <div className="mt-1 line-clamp-2 text-[11px] leading-snug text-ink-muted">
              {data.subtitle}
            </div>
          </div>
          <span className={`badge shrink-0 text-[9px] ${toneClass}`}>{data.badge}</span>
        </div>
      </div>
    </Tooltip>
  );
}

function isGateEdgeData(data: unknown): boolean {
  return Boolean(
    data &&
      typeof data === "object" &&
      "kind" in data &&
      (data as { kind?: unknown }).kind === "gate",
  );
}

function isGateEdge(edge: Edge): boolean {
  return isGateEdgeData(edge.data);
}

const NODE_TYPES = { task: TaskNode, gate: GateNode };
const EDGE_TYPES = { deletable: DeletableEdge };

function PlanCanvasInner({
  tasks,
  planVerifiers,
  toolProfiles,
  credentialSetups,
  policyGateRefs,
  selectedTaskId,
  revealTaskId,
  revealVersion = 0,
  arrangeVersion,
  canRemoveTask,
  onSelectTask,
  onUpdateTask,
  onRemoveTask,
  onUpdatePredecessors,
  onAddTask,
  onOpenToolProfiles,
  onOpenCredentialSetup,
}: PlanCanvasProps) {
  const reactFlow = useReactFlow();
  const {
    fitView,
    flowToScreenPosition,
    getInternalNode,
    getViewport,
    screenToFlowPosition,
    setViewport,
  } = reactFlow;
  const canvasRef = useRef<HTMLDivElement>(null);
  const positionsRef = useRef<Map<string, { x: number; y: number }>>(computeLayout(tasks));
  const rfInteractingRef = useRef(false);
  const suppressNodeClickRef = useRef(false);
  const nodePointerDownRef = useRef<{ id: string; x: number; y: number } | null>(null);
  const prevTaskIdsRef = useRef(tasks.map((task) => task.id).join(","));
  const prevPredsRef = useRef(tasks.map((task) => `${task.id}:${task.predecessors}`).join("|"));
  const initialFitDoneRef = useRef(false);

  const handlers = useMemo<Omit<TaskNodeData, "task">>(
    () => ({
      toolProfiles,
      credentialSetups,
      policyGateRefs,
      allTaskIds: tasks.map((task) => task.id),
      canRemoveTask,
      onUpdateTask,
      onRemoveTask,
      onCollapse: () => onSelectTask(null),
      onOpenToolProfiles,
      onOpenCredentialSetup,
    }),
    [canRemoveTask, credentialSetups, onOpenCredentialSetup, onOpenToolProfiles, onRemoveTask, onSelectTask, onUpdateTask, policyGateRefs, tasks, toolProfiles],
  );

  const [rfNodes, setRfNodes] = useState<BuilderNode[]>(() =>
    tasksToNodes(tasks, planVerifiers, positionsRef.current, selectedTaskId, handlers),
  );
  const [rfEdges, setRfEdges] = useState<Edge[]>(() => tasksToEdges(tasks, planVerifiers));

  const refreshNodes = useCallback(
    (positions = positionsRef.current) => {
      setRfNodes(tasksToNodes(tasks, planVerifiers, positions, selectedTaskId, handlers));
      setRfEdges(tasksToEdges(tasks, planVerifiers));
    },
    [handlers, planVerifiers, selectedTaskId, tasks],
  );

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && selectedTaskId) {
        event.preventDefault();
        onSelectTask(null);
        return;
      }

      if (
        (event.key === "Delete" || event.key === "Backspace") &&
        selectedTaskId &&
        canRemoveTask &&
        !isTextEditingTarget(event.target)
      ) {
        event.preventDefault();
        onRemoveTask(selectedTaskId);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [canRemoveTask, onRemoveTask, onSelectTask, selectedTaskId]);

  useEffect(() => {
    if (initialFitDoneRef.current || tasks.length === 0) return;
    initialFitDoneRef.current = true;
    window.setTimeout(() => fitView({ padding: 0.3, maxZoom: 1.1, duration: 0 }), 0);
  }, [fitView, tasks.length]);

  useEffect(() => {
    if (arrangeVersion === 0) return;
    positionsRef.current = computeLayout(tasks);
    refreshNodes(positionsRef.current);
    window.setTimeout(() => fitView({ padding: 0.24, maxZoom: 1.1, duration: 180 }), 0);
  }, [arrangeVersion, fitView, refreshNodes, tasks]);

  useEffect(() => {
    const taskIdsStr = tasks.map((task) => task.id).join(",");
    const predsStr = tasks.map((task) => `${task.id}:${task.predecessors}`).join("|");
    const idsChanged = taskIdsStr !== prevTaskIdsRef.current;
    const predsChanged = predsStr !== prevPredsRef.current;
    const positions = positionsRef.current;

    if (idsChanged) {
      const currentIds = new Set(tasks.map((task) => task.id));
      for (const key of positions.keys()) {
        if (!currentIds.has(key)) positions.delete(key);
      }
      const visible = getVisibleFlowRect(canvasRef.current, screenToFlowPosition);
      const occupied = tasks
        .filter((task) => positions.has(task.id))
        .map((task) => nodeRect(getInternalNode(task.id)) ?? nodeRectAt(positions.get(task.id)!));
      let anchor =
        [...occupied].reverse().find((rect) => (visible ? rectIntersects(rect, visible) : false)) ??
        occupied.at(-1) ??
        null;
      let lastAddedRect: NodeRect | null = null;

      tasks
        .filter((task) => !positions.has(task.id))
        .forEach((task) => {
          const position = findOpenNodePosition({ visible, occupied, anchor });
          positions.set(task.id, position);
          const rect = nodeRectAt(position);
          occupied.push(rect);
          anchor = rect;
          lastAddedRect = rect;
        });

      if (lastAddedRect) {
        window.setTimeout(() => {
          revealFlowRect(
            lastAddedRect!,
            canvasRef.current,
            flowToScreenPosition,
            getViewport,
            setViewport,
          );
        }, 0);
      }
    }

    prevTaskIdsRef.current = taskIdsStr;
    prevPredsRef.current = predsStr;

    if (rfInteractingRef.current) {
      rfInteractingRef.current = false;
      return;
    }
    if (idsChanged || predsChanged) {
      refreshNodes(positions);
    } else {
      setRfNodes((prev) =>
        prev.map((node) => {
          const task = tasks.find((candidate) => candidate.id === node.id);
          return task
            ? {
                ...node,
                data: {
                  ...handlers,
                  task,
                  isExpanded: task.id === selectedTaskId,
                } as TaskNodeData,
                selected: false,
              }
            : node;
        }),
      );
    }
  }, [
    flowToScreenPosition,
    getInternalNode,
    getViewport,
    handlers,
    refreshNodes,
    screenToFlowPosition,
    selectedTaskId,
    setViewport,
    tasks,
  ]);

  useEffect(() => {
    setRfNodes((prev) =>
      prev.map((node) => {
        if (node.type !== "task") {
          return { ...node, zIndex: 0, selected: false };
        }
        return {
          ...node,
          zIndex: node.id === selectedTaskId ? 30 : 1,
          data: {
            ...node.data,
            isExpanded: node.id === selectedTaskId,
          } as TaskNodeData,
          selected: false,
        };
      }),
    );
  }, [selectedTaskId]);

  useEffect(() => {
    if (!revealTaskId || revealVersion === 0) return;
    const timeout = window.setTimeout(() => {
      const position = positionsRef.current.get(revealTaskId);
      if (!position) return;
      const rect = nodeRect(getInternalNode(revealTaskId)) ?? nodeRectAt(position);
      revealFlowRect(rect, canvasRef.current, flowToScreenPosition, getViewport, setViewport);
    }, 40);
    return () => window.clearTimeout(timeout);
  }, [flowToScreenPosition, getInternalNode, getViewport, revealTaskId, revealVersion, setViewport]);

  const onNodesChange = useCallback((changes: NodeChange[]) => {
    setRfNodes((nodes) => applyNodeChanges(changes, nodes) as BuilderNode[]);
    let shouldRefreshGatePositions = false;
    changes.forEach((change) => {
      if (change.type === "position" && change.position && !change.dragging) {
        positionsRef.current.set(change.id, change.position);
        if (!change.id.startsWith("gate::")) shouldRefreshGatePositions = true;
      }
    });
    if (shouldRefreshGatePositions) {
      window.setTimeout(() => refreshNodes(positionsRef.current), 0);
    }
  }, [refreshNodes]);

  const onEdgesChange = useCallback((changes: EdgeChange[]) => {
    setRfEdges((edges) => applyEdgeChanges(changes, edges));
  }, []);

  const handleConnect: OnConnect = useCallback(
    (connection: Connection) => {
      const { source, target } = connection;
      if (!source || !target || source === target) return;
      rfInteractingRef.current = true;
      setRfEdges((edges) =>
        addEdge(
          {
            id: `${source}=>${target}`,
            source,
            target,
            type: "deletable",
            style: EDGE_STYLE,
            markerEnd: EDGE_MARKER,
          },
          edges,
        ),
      );
      const targetTask = tasks.find((task) => task.id === target);
      if (!targetTask) return;
      const merged = Array.from(new Set([...splitList(targetTask.predecessors), source])).join(", ");
      onUpdatePredecessors(target, merged);
    },
    [onUpdatePredecessors, tasks],
  );

  const handleEdgesDelete: OnEdgesDelete = useCallback(
    (deletedEdges) => {
      rfInteractingRef.current = true;
      deletedEdges.forEach((edge) => {
        if (isGateEdge(edge)) return;
        const targetTask = tasks.find((task) => task.id === edge.target);
        if (!targetTask) return;
        const next = splitList(targetTask.predecessors)
          .filter((pred) => pred !== edge.source)
          .join(", ");
        onUpdatePredecessors(edge.target, next);
      });
    },
    [onUpdatePredecessors, tasks],
  );

  return (
    <div
      ref={canvasRef}
      className="plan-builder-canvas h-full w-full"
      style={
        {
          "--xy-background-color-default": "transparent",
          "--xy-background-pattern-color-default": "rgb(var(--c-edge-strong))",
          "--xy-controls-button-background-color-default": "rgb(var(--c-panel-raised))",
          "--xy-controls-button-background-color-hover-default": "rgb(var(--c-panel-high))",
          "--xy-controls-button-border-color-default": "rgb(var(--c-edge-strong))",
          "--xy-controls-button-color-default": "rgb(var(--c-ink-muted))",
          "--xy-controls-box-shadow-default": "none",
          "--xy-selection-background-color-default": "rgb(var(--c-accent) / 0.07)",
          "--xy-selection-border-default": "1px dashed rgb(var(--c-accent))",
          "--xy-connection-path-color-default": "rgb(var(--c-accent))",
        } as React.CSSProperties
      }
    >
      <ReactFlow
        nodes={rfNodes}
        edges={rfEdges}
        nodeTypes={NODE_TYPES}
        edgeTypes={EDGE_TYPES}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={handleConnect}
        onEdgesDelete={handleEdgesDelete}
        onMouseDown={(event) => {
          const target = event.target as HTMLElement | null;
          const nodeEl = target?.closest<HTMLElement>("[data-task-node-id]");
          if (!nodeEl?.dataset.taskNodeId) return;
          nodePointerDownRef.current = {
            id: nodeEl.dataset.taskNodeId,
            x: event.clientX,
            y: event.clientY,
          };
        }}
        onNodeDragStart={() => {
          suppressNodeClickRef.current = true;
        }}
        onNodeDragStop={() => {
          window.setTimeout(() => {
            suppressNodeClickRef.current = false;
          }, 150);
        }}
        onNodeClick={(event, node) => {
          if (node.type === "gate") {
            const parentTaskId = (node.data as GateNodeData).parentTaskId;
            if (parentTaskId) onSelectTask(parentTaskId);
            return;
          }
          const start = nodePointerDownRef.current;
          nodePointerDownRef.current = null;
          const moved =
            start?.id === node.id &&
            Math.hypot(event.clientX - start.x, event.clientY - start.y) > 4;
          if (suppressNodeClickRef.current || moved) return;
          onSelectTask(node.id);
        }}
        onPaneClick={() => onSelectTask(null)}
        deleteKeyCode={null}
        connectionMode={ConnectionMode.Loose}
        connectionLineType={ConnectionLineType.Bezier}
        connectionLineStyle={{
          stroke: "rgb(var(--c-accent))",
          strokeWidth: 2.25,
          strokeDasharray: "8 6",
        }}
        defaultEdgeOptions={{
          type: "deletable",
          style: EDGE_STYLE,
          markerEnd: EDGE_MARKER,
        }}
        minZoom={0.18}
        maxZoom={2.2}
        snapToGrid
        snapGrid={[10, 10]}
        panOnScroll
        noWheelClassName="nowheel"
        noPanClassName="nopan"
        noDragClassName="nodrag"
        selectionOnDrag
        proOptions={{ hideAttribution: true }}
      >
        <Background variant={BackgroundVariant.Dots} gap={24} size={1.25} color="rgb(var(--c-edge-strong))" />
        <Controls
          showInteractive={false}
          style={{
            boxShadow: "none",
            border: "1px solid rgb(var(--c-edge-strong))",
            borderRadius: 6,
            overflow: "hidden",
          }}
        />
        {tasks.length === 0 && (
          <Panel position="top-center" style={{ pointerEvents: "none" }}>
            <div className="rounded border border-edge bg-panel-raised px-4 py-3 text-center shadow-soft">
              <div className="text-sm font-semibold text-ink">No task cards yet</div>
              <div className="mt-1 text-xs text-ink-muted">Add an executor or paste TOML.</div>
            </div>
          </Panel>
        )}
        {!selectedTaskId && (
          <Panel position="bottom-right">
            <div className="flex gap-2 pb-1 pr-1">
              <button
                type="button"
                className="btn text-xs py-1 shadow-soft"
                style={{ background: "rgb(var(--c-panel-raised))" }}
                onClick={() => onAddTask("Executor")}
              >
                Add executor
              </button>
              <button
                type="button"
                className="btn text-xs py-1 shadow-soft"
                style={{ background: "rgb(var(--c-panel-raised))" }}
                onClick={() => onAddTask("Reviewer")}
              >
                Add reviewer
              </button>
            </div>
          </Panel>
        )}
        {tasks.length > 0 && (
          <Panel position="top-center" style={{ pointerEvents: "none" }}>
            <div className="rounded-full border border-edge bg-panel-raised/90 px-3 py-1 text-[10px] text-ink-subtle backdrop-blur">
              Click a card to edit inline · drag edges to connect · Escape collapses
            </div>
          </Panel>
        )}
      </ReactFlow>
    </div>
  );
}

export function PlanCanvas(props: PlanCanvasProps) {
  return (
    <ReactFlowProvider>
      <PlanCanvasInner {...props} />
    </ReactFlowProvider>
  );
}
