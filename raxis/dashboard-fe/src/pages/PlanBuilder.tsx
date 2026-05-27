import { useMemo, useState, type ReactNode } from "react";

import { ApiError, dashboardApi } from "@/api/client";
import { CopyButton } from "@/components/CopyButton";
import {
  DagGraph,
  type DagGraphEdge,
  type DagGraphNode,
} from "@/components/DagGraph";
import { Spinner } from "@/components/Spinner";
import type { BuilderValidationResponse, BuilderValidationSeverity } from "@/types/api";

type AgentType = "Executor" | "Reviewer";
type CloneStrategy = "blobless" | "full" | "sparse";
type PlanFeatureCategory = "Flow" | "Scope" | "Runtime" | "Security" | "Gates" | "Merge";
type PlanFeatureAction =
  | "executor"
  | "reviewer"
  | "review_pair"
  | "fanout"
  | "egress"
  | "turns"
  | "wall_clock"
  | "vm_image"
  | "verifier"
  | "credential"
  | "lockfile";

interface PlanFeature {
  title: string;
  category: PlanFeatureCategory;
  purpose: string;
  fields: string[];
  snippet: string;
  action?: PlanFeatureAction;
}

export interface TaskDraft {
  id: string;
  description: string;
  agentType: AgentType;
  predecessors: string;
  paths: string;
  pathExports: string;
  allowedEgress: string;
  cloneStrategy: CloneStrategy;
  maxTurns: string;
  maxTurnsStep: string;
  cumulativeMaxSeconds: string;
  vmImage: string;
  verifierName: string;
  verifierGateType: string;
  verifierCommand: string;
  credentialName: string;
  credentialKind: string;
  prompt: string;
}

const PLAN_FEATURES: PlanFeature[] = [
  {
    title: "Executor task",
    category: "Flow",
    purpose: "A task that can edit files inside its path allowlist.",
    fields: ["session_agent_type", "path_allowlist", "prompt"],
    action: "executor",
    snippet: `[[tasks]]
task_id            = "implementer"
session_agent_type = "Executor"
clone_strategy     = "blobless"
path_allowlist     = ["src/"]
predecessors       = []
prompt             = """Describe the exact change, verification, and commit."""`,
  },
  {
    title: "Reviewer task",
    category: "Flow",
    purpose: "A read-only review node that depends on executor output.",
    fields: ["Reviewer", "predecessors", "path_allowlist"],
    action: "reviewer",
    snippet: `[[tasks]]
task_id            = "review-implementer"
session_agent_type = "Reviewer"
clone_strategy     = "blobless"
path_allowlist     = ["src/"]
predecessors       = ["implementer"]
prompt             = """Review predecessor output for correctness, safety, and scope."""`,
  },
  {
    title: "Executor plus reviewer",
    category: "Flow",
    purpose: "The default production shape: make a change, then review it.",
    fields: ["Executor", "Reviewer", "DAG edge"],
    action: "review_pair",
    snippet: `# Add one Executor and one Reviewer.
# Reviewer.predecessors points at the Executor task_id.`,
  },
  {
    title: "Fan-out then review",
    category: "Flow",
    purpose: "Run independent slices in parallel, then review the combined output.",
    fields: ["predecessors", "parallel tasks", "DAG"],
    action: "fanout",
    snippet: `# Two Executors:
predecessors = []

# One Reviewer:
predecessors = ["slice-api", "slice-ui"]`,
  },
  {
    title: "Path scope",
    category: "Scope",
    purpose: "Constrain write access to exact files or directory prefixes.",
    fields: ["path_allowlist", "path_export_globs"],
    snippet: `path_allowlist   = ["src/api/", "README.md"]
path_export_globs = ["docs/**/*.md"]`,
  },
  {
    title: "Allowed egress",
    category: "Security",
    purpose: "Permit only the outbound hosts this executor needs.",
    fields: ["allowed_egress", "[egress]", "TransparentProxyDenied"],
    action: "egress",
    snippet: `allowed_egress = [
  "api.github.com",
  "registry.npmjs.org",
]`,
  },
  {
    title: "Turn scaling",
    category: "Runtime",
    purpose: "Give complex tasks more turns and retry headroom.",
    fields: ["max_turns", "max_turns_step"],
    action: "turns",
    snippet: `max_turns      = 90
max_turns_step = 30`,
  },
  {
    title: "Wall-clock cap",
    category: "Runtime",
    purpose: "Fail loud when a task runs longer than it should.",
    fields: ["cumulative_max_seconds"],
    action: "wall_clock",
    snippet: `cumulative_max_seconds = 1800`,
  },
  {
    title: "VM image override",
    category: "Runtime",
    purpose: "Choose a policy-published executor image for one task.",
    fields: ["vm_image", "[[vm_images]]", "default_executor_image"],
    action: "vm_image",
    snippet: `vm_image = "rust-toolchain-2026-05"`,
  },
  {
    title: "Credential proxy",
    category: "Security",
    purpose: "Use a registered credential without exposing secret bytes to the VM.",
    fields: ["[[tasks.credentials]]", "name", "kind"],
    action: "credential",
    snippet: `[[tasks.credentials]]
name        = "staging-api"
kind        = "http"
description = "Use staging API through the credential proxy."`,
  },
  {
    title: "Task verifier",
    category: "Gates",
    purpose: "Run a mechanical verifier and require its witness before merge.",
    fields: ["[[tasks.verifiers]]", "gate_type", "gate_on"],
    action: "verifier",
    snippet: `[[tasks.verifiers]]
name             = "cargo-test"
gate_type        = "TestPass"
command          = "cargo test --workspace"
max_wall_seconds = 600
gate_on          = "Pass"`,
  },
  {
    title: "Cross-cutting artifacts",
    category: "Merge",
    purpose: "Let the kernel-managed Orchestrator own lockfiles and generated files.",
    fields: ["[orchestrator]", "cross_cutting_artifacts"],
    action: "lockfile",
    snippet: `[orchestrator]
cross_cutting_artifacts = ["Cargo.lock", "package-lock.json"]`,
  },
];

const starterTasks: TaskDraft[] = [
  {
    id: "greeter",
    description: "Create HELLO.md and commit it",
    agentType: "Executor",
    predecessors: "",
    paths: "HELLO.md",
    pathExports: "",
    allowedEgress: "",
    cloneStrategy: "blobless",
    maxTurns: "60",
    maxTurnsStep: "",
    cumulativeMaxSeconds: "600",
    vmImage: "",
    verifierName: "",
    verifierGateType: "TestPass",
    verifierCommand: "",
    credentialName: "",
    credentialKind: "http",
    prompt:
      "Write HELLO.md at the repository root with the exact text: hello from alex. Stage and commit it as a single commit with the message: add HELLO.md. Do not modify any other file.",
  },
];

export function PlanBuilderPage() {
  const [initiative, setInitiative] = useState("Create a HELLO.md greeting file.");
  const [workspace, setWorkspace] = useState("Hello world");
  const [lane, setLane] = useState("default");
  const [targetRef, setTargetRef] = useState("refs/heads/main");
  const [repository, setRepository] = useState("hello-world");
  const [crossCuttingArtifacts, setCrossCuttingArtifacts] = useState("");
  const [tasks, setTasks] = useState<TaskDraft[]>(starterTasks);
  const [dagOpen, setDagOpen] = useState(true);
  const [previewTab, setPreviewTab] = useState<"dag" | "toml">("dag");
  const [featureCategory, setFeatureCategory] = useState<PlanFeatureCategory | "All">("All");
  const [kernelValidation, setKernelValidation] = useState<BuilderValidationResponse | null>(null);
  const [kernelBusy, setKernelBusy] = useState(false);
  const [kernelError, setKernelError] = useState<string | null>(null);

  const validation = useMemo(
    () =>
      validatePlan({
        initiative,
        workspace,
        lane,
        targetRef,
        repository,
        crossCuttingArtifacts,
        tasks,
      }),
    [initiative, workspace, lane, targetRef, repository, crossCuttingArtifacts, tasks],
  );
  const toml = useMemo(
    () =>
      renderPlan({
        initiative,
        workspace,
        lane,
        targetRef,
        repository,
        crossCuttingArtifacts,
        tasks,
      }),
    [initiative, workspace, lane, targetRef, repository, crossCuttingArtifacts, tasks],
  );
  const graph = useMemo(() => buildPlanGraph(tasks), [tasks]);
  const visibleFeatures = useMemo(
    () =>
      featureCategory === "All"
        ? PLAN_FEATURES
        : PLAN_FEATURES.filter((feature) => feature.category === featureCategory),
    [featureCategory],
  );

  const updateTask = (index: number, patch: Partial<TaskDraft>) => {
    setTasks((prev) => prev.map((task, i) => (i === index ? { ...task, ...patch } : task)));
    setKernelValidation(null);
  };

  const addTask = (agentType: AgentType) => {
    setTasks((prev) => [...prev, makeTask(agentType, prev)]);
    setKernelValidation(null);
  };

  const addReviewPair = () => {
    setTasks((prev) => {
      const executor = makeTask("Executor", prev);
      const reviewer = makeTask("Reviewer", [...prev, executor]);
      return [
        ...prev,
        {
          ...executor,
          description: "Implement scoped change",
          prompt:
            "Make the requested change inside the allowed paths. Run the smallest meaningful verification command, then commit the result with a concise commit message.",
        },
        {
          ...reviewer,
          id: `review-${executor.id}`,
          description: `Review ${executor.id}`,
          predecessors: executor.id,
          paths: executor.paths,
        },
      ];
    });
    setKernelValidation(null);
  };

  const addFanOut = () => {
    setTasks((prev) => {
      const base = prev.length + 1;
      const taskA = makeTask("Executor", prev);
      const taskB = makeTask("Executor", [...prev, taskA]);
      const review = makeTask("Reviewer", [...prev, taskA, taskB]);
      return [
        ...prev,
        {
          ...taskA,
          id: `slice-${base}-api`,
          description: "Implement API slice",
          predecessors: "",
          paths: "src/api/",
          prompt:
            "Implement the API slice only. Keep changes inside src/api/. Run the relevant API tests and commit the result.",
        },
        {
          ...taskB,
          id: `slice-${base}-ui`,
          description: "Implement UI slice",
          predecessors: "",
          paths: "src/ui/",
          prompt:
            "Implement the UI slice only. Keep changes inside src/ui/. Run the relevant UI tests and commit the result.",
        },
        {
          ...review,
          id: `review-slices-${base}`,
          description: "Review both slices",
          predecessors: `slice-${base}-api, slice-${base}-ui`,
          paths: "src/api/, src/ui/",
        },
      ];
    });
    setKernelValidation(null);
  };

  const applyFeature = (action: PlanFeatureAction) => {
    switch (action) {
      case "executor":
        addTask("Executor");
        return;
      case "reviewer":
        addTask("Reviewer");
        return;
      case "review_pair":
        addReviewPair();
        return;
      case "fanout":
        addFanOut();
        return;
      case "lockfile":
        setCrossCuttingArtifacts((prev) =>
          mergeList(prev, ["Cargo.lock", "package-lock.json"]).join(", "),
        );
        break;
      default:
        setTasks((prev) => applyFeatureToLastExecutor(prev, action));
        break;
    }
    setKernelValidation(null);
  };

  const removeTask = (index: number) => {
    setTasks((prev) => prev.filter((_, i) => i !== index));
    setKernelValidation(null);
  };

  const runKernelValidation = async () => {
    setKernelBusy(true);
    setKernelError(null);
    try {
      setKernelValidation(await dashboardApi.builders.validatePlan(toml));
    } catch (e) {
      if (e instanceof ApiError) setKernelError(`${e.code}: ${e.detail}`);
      else if (e instanceof Error) setKernelError(e.message);
      else setKernelError("validation failed");
    } finally {
      setKernelBusy(false);
    }
  };

  return (
    <div className="space-y-4">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div className="max-w-3xl">
          <h1 className="text-xl font-semibold text-ink">Plan Builder</h1>
          <p className="text-sm text-ink-muted">
            Build a plan.toml from Raxis primitives: managed repo, lane, tasks,
            DAG dependencies, scopes, runtime budgets, credentials, verifiers, and prompts.
            This helper drafts; kernel validation and admission remain authoritative.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button type="button" className="btn" disabled={kernelBusy} onClick={runKernelValidation}>
            {kernelBusy ? <><Spinner className="h-4 w-4" /> Validating</> : "Validate with kernel"}
          </button>
          <CopyButton value={toml} label="Copy generated plan.toml" />
          <button type="button" className="btn-primary" onClick={() => downloadText("plan.toml", toml)}>
            Download plan.toml
          </button>
        </div>
      </header>

      <section className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(360px,0.92fr)]">
        <div className="min-w-0 space-y-4">
          <div className="card p-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <SectionTitle
                title="Plan basics"
                subtitle="These map to [plan.initiative], [workspace], and optional [orchestrator]."
              />
              <span className="badge border-info bg-info-muted text-info">
                Orchestrator is kernel-managed
              </span>
            </div>
            <div className="mt-4 grid gap-3 md:grid-cols-2">
              <Field label="Initiative description" className="md:col-span-2">
                <textarea
                  value={initiative}
                  onChange={(e) => {
                    setInitiative(e.target.value);
                    setKernelValidation(null);
                  }}
                  rows={3}
                  className="input min-h-[84px] w-full"
                />
              </Field>
              <Field label="Workspace">
                <input
                  value={workspace}
                  onChange={(e) => {
                    setWorkspace(e.target.value);
                    setKernelValidation(null);
                  }}
                  className="input w-full"
                />
              </Field>
              <Field label="Repository id">
                <input
                  value={repository}
                  onChange={(e) => {
                    setRepository(e.target.value);
                    setKernelValidation(null);
                  }}
                  className="input w-full font-mono"
                />
                <span className="mt-1 block text-[11px] font-normal leading-relaxed text-ink-muted">
                  Use the actual repo name, for example acme-api. Branches belong in target_ref.
                </span>
              </Field>
              <Field label="Lane">
                <input
                  value={lane}
                  onChange={(e) => {
                    setLane(e.target.value);
                    setKernelValidation(null);
                  }}
                  className="input w-full font-mono"
                />
              </Field>
              <Field label="Target ref">
                <input
                  value={targetRef}
                  onChange={(e) => {
                    setTargetRef(e.target.value);
                    setKernelValidation(null);
                  }}
                  className="input w-full font-mono"
                />
              </Field>
              <Field label="Cross-cutting artifacts" className="md:col-span-2">
                <input
                  value={crossCuttingArtifacts}
                  onChange={(e) => {
                    setCrossCuttingArtifacts(e.target.value);
                    setKernelValidation(null);
                  }}
                  className="input w-full font-mono"
                  placeholder="Cargo.lock, package-lock.json"
                />
              </Field>
            </div>
          </div>

          <div className="card p-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <SectionTitle
                title="Feature library"
                subtitle="Browse the plan features Raxis understands, copy snippets, or apply common patterns."
              />
              <div className="flex flex-wrap gap-1">
                {(["All", "Flow", "Scope", "Runtime", "Security", "Gates", "Merge"] as const).map((cat) => (
                  <button
                    key={cat}
                    type="button"
                    className={
                      featureCategory === cat
                        ? "badge border-accent bg-accent/20 text-accent"
                        : "badge border-edge bg-panel text-ink-muted hover:border-accent"
                    }
                    onClick={() => setFeatureCategory(cat)}
                  >
                    {cat}
                  </button>
                ))}
              </div>
            </div>
            <div className="mt-4 grid gap-3 lg:grid-cols-2 2xl:grid-cols-3">
              {visibleFeatures.map((feature) => (
                <PlanFeatureCard
                  key={feature.title}
                  feature={feature}
                  onApply={feature.action ? () => applyFeature(feature.action!) : undefined}
                />
              ))}
            </div>
          </div>

          <div className="card p-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <SectionTitle
                title="Tasks"
                subtitle="Prompt is the main instruction. Description is the short operator-facing summary."
              />
              <div className="flex gap-2">
                <button type="button" className="btn" onClick={() => addTask("Executor")}>
                  Add executor
                </button>
                <button type="button" className="btn" onClick={() => addTask("Reviewer")}>
                  Add reviewer
                </button>
              </div>
            </div>
            <div className="mt-4 grid gap-3 lg:grid-cols-2">
              {tasks.map((task, index) => (
                <TaskCard
                  key={`${task.id}-${index}`}
                  task={task}
                  index={index}
                  canRemove={tasks.length > 1}
                  updateTask={updateTask}
                  removeTask={removeTask}
                />
              ))}
            </div>
          </div>
        </div>

        <aside className="min-w-0 space-y-4 self-start xl:sticky xl:top-4">
          <ValidationCard
            title="Draft checks"
            subtitle="Fast local checks before asking the kernel."
            issues={validation}
          />

          <KernelValidationCard
            response={kernelValidation}
            error={kernelError}
            busy={kernelBusy}
            onValidate={runKernelValidation}
          />

          <div className="card overflow-hidden p-0">
            <header className="border-b border-edge px-4 py-3">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <SectionTitle title="Preview" subtitle="Confirm the DAG before copying TOML." />
                <div className="inline-flex rounded-md border border-edge bg-panel p-0.5 text-xs">
                  <SegmentButton active={previewTab === "dag"} onClick={() => setPreviewTab("dag")}>
                    DAG
                  </SegmentButton>
                  <SegmentButton active={previewTab === "toml"} onClick={() => setPreviewTab("toml")}>
                    TOML
                  </SegmentButton>
                </div>
              </div>
              {previewTab === "dag" && (
                <button
                  type="button"
                  className="mt-3 text-xs font-medium text-accent hover:underline"
                  onClick={() => setDagOpen((v) => !v)}
                >
                  {dagOpen ? "Collapse DAG" : "Show DAG"}
                </button>
              )}
            </header>
            {previewTab === "dag" ? (
              dagOpen ? (
                <div className="p-3">
                  <DagGraph
                    nodes={graph.nodes}
                    edges={graph.edges}
                    height={320}
                    rankdir={graph.nodes.length > 6 ? "TB" : "LR"}
                    hideLegend
                  />
                </div>
              ) : (
                <div className="px-4 py-8 text-sm text-ink-muted">
                  DAG collapsed. The generated plan still updates as you edit.
                </div>
              )
            ) : (
              <div className="p-3">
                <div className="mb-2 flex items-center justify-end gap-2">
                  <CopyButton value={toml} label="Copy generated plan.toml" />
                  <button type="button" className="btn" onClick={() => downloadText("plan.toml", toml)}>
                    Download
                  </button>
                </div>
                <pre className="max-h-[42rem] overflow-auto rounded-md border border-edge bg-panel p-3 text-xs leading-relaxed text-ink">
                  <code>{toml}</code>
                </pre>
              </div>
            )}
          </div>

          <div className="card p-4">
            <SectionTitle title="Submit next" subtitle="The CLI still performs final validation and signing." />
            <div className="mt-3 space-y-2">
              {planSubmitCommands.map((command) => (
                <CommandRow key={command} command={command} />
              ))}
            </div>
          </div>
        </aside>
      </section>
    </div>
  );
}

function TaskCard({
  task,
  index,
  canRemove,
  updateTask,
  removeTask,
}: {
  task: TaskDraft;
  index: number;
  canRemove: boolean;
  updateTask: (index: number, patch: Partial<TaskDraft>) => void;
  removeTask: (index: number) => void;
}) {
  return (
    <div className="rounded-md border border-edge bg-panel p-3">
      <div className="grid grid-cols-[1fr_8.5rem] gap-3">
        <Field label="Task id">
          <input
            value={task.id}
            onChange={(e) => updateTask(index, { id: e.target.value })}
            className="input w-full font-mono"
          />
        </Field>
        <Field label="Role">
          <select
            value={task.agentType}
            onChange={(e) => updateTask(index, { agentType: e.target.value as AgentType })}
            className="input w-full"
          >
            <option>Executor</option>
            <option>Reviewer</option>
          </select>
        </Field>
      </div>
      <div className="mt-3 grid gap-3 md:grid-cols-2">
        <Field label="Description">
          <input
            value={task.description}
            onChange={(e) => updateTask(index, { description: e.target.value })}
            className="input w-full"
          />
        </Field>
        <Field label="Predecessors">
          <input
            value={task.predecessors}
            onChange={(e) => updateTask(index, { predecessors: e.target.value })}
            className="input w-full font-mono"
            placeholder="task-a, task-b"
          />
        </Field>
      </div>
      <div className="mt-3 grid gap-3 md:grid-cols-[1fr_8rem_7rem_7rem]">
        <Field label="Path allowlist">
          <input
            value={task.paths}
            onChange={(e) => updateTask(index, { paths: e.target.value })}
            className="input w-full font-mono"
            placeholder="src/, README.md"
          />
        </Field>
        <Field label="Clone">
          <select
            value={task.cloneStrategy}
            onChange={(e) => updateTask(index, { cloneStrategy: e.target.value as CloneStrategy })}
            className="input w-full"
          >
            <option>blobless</option>
            <option>full</option>
            <option>sparse</option>
          </select>
        </Field>
        <Field label="Max turns">
          <input
            value={task.maxTurns}
            onChange={(e) => updateTask(index, { maxTurns: e.target.value })}
            className="input w-full font-mono"
            placeholder="60"
          />
        </Field>
        <Field label="Step">
          <input
            value={task.maxTurnsStep}
            onChange={(e) => updateTask(index, { maxTurnsStep: e.target.value })}
            className="input w-full font-mono"
            placeholder="30"
          />
        </Field>
      </div>
      <div className="mt-3">
        <Field label="Prompt">
          <textarea
            value={task.prompt}
            onChange={(e) => updateTask(index, { prompt: e.target.value })}
            rows={5}
            className="input min-h-[112px] w-full"
          />
        </Field>
      </div>
      <details className="mt-3 rounded-md border border-edge bg-panel-raised p-3">
        <summary className="cursor-pointer text-xs font-semibold text-ink">
          Advanced scope, runtime, credentials, and gates
        </summary>
        <div className="mt-3 grid gap-3 md:grid-cols-2">
          <Field label="Allowed egress">
            <input
              value={task.allowedEgress}
              onChange={(e) => updateTask(index, { allowedEgress: e.target.value })}
              className="input w-full font-mono"
              placeholder="api.github.com, registry.npmjs.org"
            />
          </Field>
          <Field label="Path export globs">
            <input
              value={task.pathExports}
              onChange={(e) => updateTask(index, { pathExports: e.target.value })}
              className="input w-full font-mono"
              placeholder="docs/**/*.md"
            />
          </Field>
          <Field label="VM image alias">
            <input
              value={task.vmImage}
              onChange={(e) => updateTask(index, { vmImage: e.target.value })}
              className="input w-full font-mono"
              placeholder="rust-toolchain-2026-05"
            />
          </Field>
          <Field label="Wall-clock cap seconds">
            <input
              value={task.cumulativeMaxSeconds}
              onChange={(e) => updateTask(index, { cumulativeMaxSeconds: e.target.value })}
              className="input w-full font-mono"
              placeholder="1800"
            />
          </Field>
          <Field label="Credential name">
            <input
              value={task.credentialName}
              onChange={(e) => updateTask(index, { credentialName: e.target.value })}
              className="input w-full font-mono"
              placeholder="staging-api"
            />
          </Field>
          <Field label="Credential kind">
            <select
              value={task.credentialKind}
              onChange={(e) => updateTask(index, { credentialKind: e.target.value })}
              className="input w-full"
            >
              <option>http</option>
              <option>postgres</option>
              <option>mysql</option>
              <option>mssql</option>
              <option>mongodb</option>
            </select>
          </Field>
          <Field label="Verifier name">
            <input
              value={task.verifierName}
              onChange={(e) => updateTask(index, { verifierName: e.target.value })}
              className="input w-full font-mono"
              placeholder="cargo-test"
            />
          </Field>
          <Field label="Verifier gate type">
            <input
              value={task.verifierGateType}
              onChange={(e) => updateTask(index, { verifierGateType: e.target.value })}
              className="input w-full font-mono"
              placeholder="TestPass"
            />
          </Field>
          <Field label="Verifier command" className="md:col-span-2">
            <input
              value={task.verifierCommand}
              onChange={(e) => updateTask(index, { verifierCommand: e.target.value })}
              className="input w-full font-mono"
              placeholder="cargo test --workspace"
            />
          </Field>
        </div>
      </details>
      <div className="mt-3 flex justify-between gap-3 text-xs text-ink-subtle">
        <span>
          {task.agentType === "Reviewer"
            ? "Reviewers should depend on an Executor and stay network-free."
            : "Executors should have narrow write paths and explicit egress."}
        </span>
        <button type="button" className="btn" onClick={() => removeTask(index)} disabled={!canRemove}>
          Remove
        </button>
      </div>
    </div>
  );
}

function PlanFeatureCard({
  feature,
  onApply,
}: {
  feature: PlanFeature;
  onApply?: () => void;
}) {
  return (
    <article className="flex min-h-[13rem] flex-col rounded-md border border-edge bg-panel p-3">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold text-ink">{feature.title}</h3>
          <span className="mt-1 inline-flex text-[10px] font-semibold uppercase tracking-wider text-ink-subtle">
            {feature.category}
          </span>
        </div>
        <CopyButton value={feature.snippet} label={`Copy ${feature.title} snippet`} />
      </div>
      <p className="mt-2 text-xs leading-relaxed text-ink-muted">{feature.purpose}</p>
      <div className="mt-3 flex flex-wrap gap-1">
        {feature.fields.map((field) => (
          <code
            key={field}
            className="rounded border border-edge bg-panel-raised px-1.5 py-0.5 font-mono text-[10px] text-ink-muted"
          >
            {field}
          </code>
        ))}
      </div>
      {onApply && (
        <div className="mt-auto pt-3">
          <button type="button" className="btn w-full justify-center" onClick={onApply}>
            Apply pattern
          </button>
        </div>
      )}
    </article>
  );
}

function SectionTitle({ title, subtitle }: { title: string; subtitle?: string }) {
  return (
    <div>
      <h2 className="text-sm font-semibold text-ink">{title}</h2>
      {subtitle && <p className="mt-0.5 text-xs text-ink-muted">{subtitle}</p>}
    </div>
  );
}

function Field({
  label,
  children,
  className,
}: {
  label: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <label className={`block text-xs font-semibold text-ink-subtle ${className ?? ""}`}>
      <span>{label}</span>
      <span className="mt-1 block">{children}</span>
    </label>
  );
}

function SegmentButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      className={active ? "rounded bg-panel-raised px-2 py-1 text-ink" : "px-2 py-1 text-ink-muted"}
      onClick={onClick}
    >
      {children}
    </button>
  );
}

function ValidationCard({
  title,
  subtitle,
  issues,
}: {
  title: string;
  subtitle?: string;
  issues: string[];
}) {
  const ready = issues.length === 1 && issues[0].startsWith("Ready");
  return (
    <div className="card p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <SectionTitle title={title} subtitle={subtitle} />
        <span className={ready ? "badge border-ok bg-ok-muted text-ok" : "badge border-warn bg-warn-muted text-warn"}>
          {ready ? "Ready" : `${issues.length} issue${issues.length === 1 ? "" : "s"}`}
        </span>
      </div>
      <ul className="mt-3 space-y-2 text-xs">
        {issues.map((item) => (
          <li key={item} className="rounded border border-edge bg-panel px-2.5 py-2 text-ink-muted">
            {item}
          </li>
        ))}
      </ul>
    </div>
  );
}

function KernelValidationCard({
  response,
  error,
  busy,
  onValidate,
}: {
  response: BuilderValidationResponse | null;
  error: string | null;
  busy: boolean;
  onValidate: () => void;
}) {
  return (
    <div className="card p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <SectionTitle
          title="Kernel validation"
          subtitle="Read-only check against the active policy; final submit can still reject changed state."
        />
        <button type="button" className="btn" disabled={busy} onClick={onValidate}>
          {busy ? <><Spinner className="h-4 w-4" /> Running</> : "Run"}
        </button>
      </div>
      {error && <div className="mt-3 rounded border border-bad/40 bg-bad/10 p-2 text-xs text-bad">{error}</div>}
      {!response && !error && (
        <p className="mt-3 text-xs text-ink-muted">
          Use this before copying the plan. It catches policy-aware issues such as
          locked target refs, missing lanes, invalid DAGs, and deprecated context fields.
        </p>
      )}
      {response && (
        <div className="mt-3 space-y-3">
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className={response.ok ? "badge border-ok bg-ok-muted text-ok" : "badge border-bad bg-bad/10 text-bad"}>
              {response.ok ? "Kernel check passed" : "Kernel check found errors"}
            </span>
            <span className="text-ink-subtle">policy epoch #{response.policy_epoch}</span>
            {response.resolved_target_ref && (
              <code className="rounded border border-edge bg-panel px-1.5 py-0.5 font-mono text-[11px] text-ink-muted">
                {response.resolved_target_ref}
              </code>
            )}
          </div>
          {response.issues.length === 0 ? (
            <div className="rounded border border-ok/40 bg-ok-muted px-2.5 py-2 text-xs text-ok">
              No issues reported by kernel validation.
            </div>
          ) : (
            <ul className="space-y-2">
              {response.issues.map((issue) => (
                <li
                  key={`${issue.code}-${issue.message}`}
                  className={`rounded border px-2.5 py-2 text-xs ${issueClass(issue.severity)}`}
                >
                  <div className="font-semibold">{issue.message}</div>
                  <div className="mt-1 text-ink-muted">{issue.remediation}</div>
                  <code className="mt-1 inline-block font-mono text-[10px] text-ink-subtle">
                    {issue.code}
                  </code>
                </li>
              ))}
            </ul>
          )}
          <div className="space-y-2">
            {response.next_steps.map((command) => (
              <CommandRow key={command} command={command} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function CommandRow({ command }: { command: string }) {
  return (
    <div className="flex items-center gap-2 rounded border border-edge bg-panel px-2.5 py-2">
      <code className="min-w-0 flex-1 truncate font-mono text-[11px] text-ink-muted">{command}</code>
      <CopyButton value={command} label="Copy command" />
    </div>
  );
}

function issueClass(severity: BuilderValidationSeverity) {
  if (severity === "error") return "border-bad/40 bg-bad/10 text-bad";
  if (severity === "warning") return "border-warn/40 bg-warn-muted text-warn";
  return "border-info/40 bg-info-muted text-info";
}

function makeTask(agentType: AgentType, existing: TaskDraft[]): TaskDraft {
  const suffix = existing.length + 1;
  return {
    id: agentType === "Reviewer" ? `review-${suffix}` : `task-${suffix}`,
    description: agentType === "Reviewer" ? "Review predecessor output" : "Implement task",
    agentType,
    predecessors: existing.at(-1)?.id ?? "",
    paths: agentType === "Reviewer" ? existing.at(-1)?.paths ?? "" : "./",
    pathExports: "",
    allowedEgress: "",
    cloneStrategy: "blobless",
    maxTurns: agentType === "Reviewer" ? "30" : "60",
    maxTurnsStep: "",
    cumulativeMaxSeconds: agentType === "Reviewer" ? "600" : "",
    vmImage: "",
    verifierName: "",
    verifierGateType: "TestPass",
    verifierCommand: "",
    credentialName: "",
    credentialKind: "http",
    prompt:
      agentType === "Reviewer"
        ? "Review the predecessor commit for correctness, safety, and scope. Submit Approve or Reject with concise evidence."
        : "Describe the exact change, verification command, commit message, and files that must remain untouched.",
  };
}

function applyFeatureToLastExecutor(tasks: TaskDraft[], action: PlanFeatureAction): TaskDraft[] {
  const index = findLastExecutorIndex(tasks);
  if (index < 0) return tasks;
  return tasks.map((task, i) => {
    if (i !== index) return task;
    switch (action) {
      case "egress":
        return { ...task, allowedEgress: mergeList(task.allowedEgress, ["api.github.com"]).join(", ") };
      case "turns":
        return { ...task, maxTurns: "90", maxTurnsStep: "30" };
      case "wall_clock":
        return { ...task, cumulativeMaxSeconds: "1800" };
      case "vm_image":
        return { ...task, vmImage: task.vmImage || "rust-toolchain-2026-05" };
      case "verifier":
        return {
          ...task,
          verifierName: task.verifierName || "cargo-test",
          verifierGateType: task.verifierGateType || "TestPass",
          verifierCommand: task.verifierCommand || "cargo test --workspace",
        };
      case "credential":
        return {
          ...task,
          credentialName: task.credentialName || "staging-api",
          credentialKind: task.credentialKind || "http",
          allowedEgress: mergeList(task.allowedEgress, ["localhost"]).join(", "),
        };
      default:
        return task;
    }
  });
}

function findLastExecutorIndex(tasks: TaskDraft[]) {
  for (let i = tasks.length - 1; i >= 0; i -= 1) {
    if (tasks[i].agentType === "Executor") return i;
  }
  return -1;
}

function validatePlan(input: {
  initiative: string;
  workspace: string;
  lane: string;
  targetRef: string;
  repository: string;
  crossCuttingArtifacts: string;
  tasks: TaskDraft[];
}) {
  const issues: string[] = [];
  if (!input.initiative.trim()) issues.push("Add [plan.initiative] description.");
  if (!input.workspace.trim()) issues.push("Add [workspace] name.");
  if (!input.lane.trim()) issues.push("Add [workspace] lane_id.");
  if (!input.targetRef.startsWith("refs/heads/")) {
    issues.push("target_ref must start with refs/heads/.");
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(input.repository.trim())) {
    issues.push("repository must be a path-safe id, for example hello-world, acme-api, api, or web.");
  }
  for (const artifact of splitList(input.crossCuttingArtifacts)) {
    if (artifact.startsWith("/") || artifact.includes("..")) {
      issues.push(`Cross-cutting artifact ${artifact} must be relative and cannot contain ...`);
    }
  }
  const ids = new Set<string>();
  for (const task of input.tasks) {
    const id = task.id.trim();
    if (!id) issues.push("Every task needs task_id.");
    if (id && !/^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(id)) {
      issues.push(`Task ${id} must start with a letter and use only letters, digits, _ or -.`);
    }
    if (ids.has(id)) issues.push(`Duplicate task_id: ${id}.`);
    ids.add(id);
    if (!task.description.trim()) issues.push(`Task ${id || "(blank)"} needs description.`);
    if (!task.prompt.trim()) issues.push(`Task ${id || "(blank)"} needs prompt.`);
    for (const pred of splitList(task.predecessors)) {
      if (!input.tasks.some((candidate) => candidate.id.trim() === pred)) {
        issues.push(`Task ${id || "(blank)"} references unknown predecessor ${pred}.`);
      }
      if (pred === id) issues.push(`Task ${id} cannot depend on itself.`);
    }
    if (task.agentType === "Executor" && splitList(task.paths).length === 0) {
      issues.push(`Executor task ${id || "(blank)"} needs path_allowlist.`);
    }
    if (task.agentType === "Reviewer") {
      if (splitList(task.predecessors).length === 0) {
        issues.push(`Reviewer task ${id || "(blank)"} needs an Executor predecessor.`);
      }
      if (task.vmImage.trim()) issues.push(`Reviewer task ${id || "(blank)"} cannot declare vm_image.`);
      if (splitList(task.allowedEgress).length > 0) {
        issues.push(`Reviewer task ${id || "(blank)"} should not declare allowed_egress.`);
      }
      if (task.credentialName.trim()) {
        issues.push(`Reviewer task ${id || "(blank)"} should not declare credentials.`);
      }
    }
    if (task.credentialName.trim() && !task.credentialKind.trim()) {
      issues.push(`Task ${id || "(blank)"} credential kind is required when credential name is set.`);
    }
    if (task.verifierName.trim() && !task.verifierGateType.trim()) {
      issues.push(`Task ${id || "(blank)"} verifier gate type is required.`);
    }
    for (const [label, raw] of [
      ["max_turns", task.maxTurns],
      ["max_turns_step", task.maxTurnsStep],
      ["cumulative_max_seconds", task.cumulativeMaxSeconds],
    ] as const) {
      if (raw.trim() && !/^[1-9][0-9]*$/.test(raw.trim())) {
        issues.push(`Task ${id || "(blank)"} ${label} must be a positive integer.`);
      }
    }
  }
  return issues.length === 0 ? ["Ready for kernel validation and raxis plan validate."] : issues;
}

function renderPlan(input: {
  initiative: string;
  workspace: string;
  lane: string;
  targetRef: string;
  repository: string;
  crossCuttingArtifacts: string;
  tasks: TaskDraft[];
}) {
  const lines: string[] = [
    "[plan.initiative]",
    `description = ${tomlString(input.initiative.trim())}`,
    "",
    "[workspace]",
    `name       = ${tomlString(input.workspace.trim())}`,
    `lane_id    = ${tomlString(input.lane.trim())}`,
    `target_ref = ${tomlString(input.targetRef.trim())}`,
    `repository = ${tomlString(input.repository.trim())}`,
    "",
  ];
  const artifacts = splitList(input.crossCuttingArtifacts);
  if (artifacts.length > 0) {
    lines.push("[orchestrator]");
    lines.push(`cross_cutting_artifacts = [${artifacts.map(tomlString).join(", ")}]`);
    lines.push("");
  }
  for (const task of input.tasks) {
    const predecessors = splitList(task.predecessors);
    const paths = splitList(task.paths);
    const pathExports = splitList(task.pathExports);
    const allowedEgress = splitList(task.allowedEgress);
    lines.push("[[tasks]]");
    lines.push(`task_id            = ${tomlString(task.id.trim())}`);
    lines.push(`description        = ${tomlString(task.description.trim())}`);
    lines.push(`session_agent_type = ${tomlString(task.agentType)}`);
    lines.push(`clone_strategy     = ${tomlString(task.cloneStrategy)}`);
    if (task.maxTurns.trim()) lines.push(`max_turns          = ${task.maxTurns.trim()}`);
    if (task.maxTurnsStep.trim()) lines.push(`max_turns_step     = ${task.maxTurnsStep.trim()}`);
    if (task.cumulativeMaxSeconds.trim()) {
      lines.push(`cumulative_max_seconds = ${task.cumulativeMaxSeconds.trim()}`);
    }
    if (task.vmImage.trim()) lines.push(`vm_image           = ${tomlString(task.vmImage.trim())}`);
    if (paths.length > 0) lines.push(`path_allowlist     = [${paths.map(tomlString).join(", ")}]`);
    if (pathExports.length > 0) {
      lines.push(`path_export_globs  = [${pathExports.map(tomlString).join(", ")}]`);
    }
    if (allowedEgress.length > 0) {
      lines.push(`allowed_egress     = [${allowedEgress.map(tomlString).join(", ")}]`);
    }
    lines.push(`predecessors       = [${predecessors.map(tomlString).join(", ")}]`);
    lines.push('prompt             = """');
    lines.push(task.prompt.trimEnd());
    lines.push('"""');
    if (task.credentialName.trim()) {
      lines.push("");
      lines.push("[[tasks.credentials]]");
      lines.push(`name = ${tomlString(task.credentialName.trim())}`);
      lines.push(`kind = ${tomlString(task.credentialKind.trim() || "http")}`);
    }
    if (task.verifierName.trim()) {
      lines.push("");
      lines.push("[[tasks.verifiers]]");
      lines.push(`name      = ${tomlString(task.verifierName.trim())}`);
      lines.push(`gate_type = ${tomlString(task.verifierGateType.trim() || "TestPass")}`);
      if (task.verifierCommand.trim()) {
        lines.push(`command   = ${tomlString(task.verifierCommand.trim())}`);
      }
      lines.push('gate_on   = "Pass"');
    }
    lines.push("");
  }
  return lines.join("\n");
}

function buildPlanGraph(tasks: TaskDraft[]): { nodes: DagGraphNode[]; edges: DagGraphEdge[] } {
  const nodes = tasks.map<DagGraphNode>((task) => ({
    task_id: task.id.trim() || "(blank)",
    title: task.description.trim() || task.id.trim() || "Untitled task",
    agent_type: task.agentType,
    state: "Admitted",
  }));
  const nodeIds = new Set(nodes.map((n) => n.task_id));
  const edges = tasks.flatMap<DagGraphEdge>((task) => {
    const to = task.id.trim();
    if (!to || !nodeIds.has(to)) return [];
    return splitList(task.predecessors)
      .filter((from) => nodeIds.has(from) && from !== to)
      .map((from) => ({ from, to }));
  });
  return { nodes, edges };
}

function downloadText(filename: string, text: string) {
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function splitList(raw: string) {
  return raw
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
}

function mergeList(raw: string, values: string[]) {
  const merged = new Set([...splitList(raw), ...values]);
  return Array.from(merged);
}

function tomlString(value: string) {
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

const planSubmitCommands = [
  "raxis plan validate plan.toml",
  "raxis submit plan plan.toml --no-dry-run",
  "raxis plan approve <initiative_id>",
];
