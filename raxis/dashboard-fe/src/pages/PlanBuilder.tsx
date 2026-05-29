import { useMemo, useState, type ReactNode } from "react";
import Editor from "@monaco-editor/react";

import { ApiError, dashboardApi } from "@/api/client";
import { CopyButton } from "@/components/CopyButton";
import { PlanCanvas } from "@/components/builder/PlanCanvas";
import { Spinner } from "@/components/Spinner";
import { ensureTomlLanguage, raxisMonacoTheme } from "@/lib/monaco-toml";
import { useTheme } from "@/lib/theme-context";
import type {
  BuilderValidationResponse,
  BuilderValidationSeverity,
} from "@/types/api";

type AgentType = "Executor" | "Reviewer";
type CloneStrategy = "blobless" | "full" | "sparse";
export type ToolLocality =
  | "guest_subprocess"
  | "host_subprocess"
  | "host_mcp"
  | "remote_mcp";
export type CredentialProxyType =
  | "postgres"
  | "mysql"
  | "mssql"
  | "mongodb"
  | "redis"
  | "smtp"
  | "http"
  | "aws"
  | "gcp"
  | "azure"
  | "k8s";

type PlanStatus = "empty" | "ready" | "warnings" | "needs-fixes";
type ParseStatus =
  | { kind: "empty"; message: string }
  | { kind: "synced"; message: string }
  | { kind: "error"; message: string };
type BuilderDrawer = "plan" | "tools" | "credentials" | null;

interface PlanBasics {
  initiative: string;
  workspace: string;
  lane: string;
  targetRef: string;
  repository: string;
  crossCuttingArtifacts: string;
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
  profiles: string;
  verifierName: string;
  verifierGateType: string;
  verifierCommand: string;
  verifierGateOn: string;
  credentials: CredentialDraft[];
  prompt: string;
}

export interface CredentialDraft {
  name: string;
  proxyType: CredentialProxyType;
  mountAs: string;
  upstreamUrl: string;
  upstreamHostPort: string;
  authMode: string;
  project: string;
  tenantId: string;
  roleArn: string;
  clientId: string;
}

export interface CredentialSetupDraft extends CredentialDraft {
  description: string;
  environment: string;
  expectedShape: string;
}

export interface ToolDraft {
  name: string;
  description: string;
  locality: ToolLocality;
  command: string;
  timeoutSeconds: string;
  stdinMaxBytes: string;
  stdoutMaxBytes: string;
  stderrMaxBytes: string;
  schemaJson: string;
}

export interface ToolProfileDraft {
  id: string;
  description: string;
  tools: ToolDraft[];
}

interface LocalIssue {
  severity: "error" | "warning";
  field: string;
  message: string;
  next: string;
}

const initialPlan: PlanBasics = {
  initiative: "Create a HELLO.md greeting file.",
  workspace: "hello-world",
  lane: "default",
  targetRef: "refs/heads/main",
  repository: "hello-world",
  crossCuttingArtifacts: "",
};

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
    profiles: "repo_tools",
    verifierName: "",
    verifierGateType: "TestPass",
    verifierCommand: "",
    verifierGateOn: "Pass",
    credentials: [],
    prompt:
      "Write HELLO.md at the repository root with the exact text: hello from alex. Stage and commit it as a single commit with the message: add HELLO.md. Do not modify any other file.",
  },
];

const starterToolProfiles: ToolProfileDraft[] = [
  {
    id: "repo_tools",
    description: "Repository inspection tools available to executor tasks.",
    tools: [
      {
        name: "repo_symbol_search",
        description: "Search symbols and file names with ripgrep inside the assigned workspace.",
        locality: "guest_subprocess",
        command: "/usr/bin/rg\n--line-number\n--hidden\n--glob\n!.git/*",
        timeoutSeconds: "30",
        stdinMaxBytes: "4096",
        stdoutMaxBytes: "65536",
        stderrMaxBytes: "8192",
        schemaJson: '{ "query": "string" }',
      },
    ],
  },
];

const starterCredentialSetups: CredentialSetupDraft[] = [];

const toolLocalities: ToolLocality[] = [
  "guest_subprocess",
  "host_subprocess",
  "host_mcp",
  "remote_mcp",
];
export const credentialProxyTypes = [
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
] as const;
const maxEffectiveCustomToolsPerTask = 25;

const emptyPlan: PlanBasics = {
  initiative: "",
  workspace: "",
  lane: "",
  targetRef: "",
  repository: "",
  crossCuttingArtifacts: "",
};

const planSubmitCommands = [
  "raxis plan validate plan.toml",
  "raxis submit plan plan.toml --no-dry-run",
  "raxis plan approve <initiative_id>",
];

export function PlanBuilderPage() {
  const { theme } = useTheme();
  const monacoTheme = raxisMonacoTheme(theme);
  const [planEnabled, setPlanEnabled] = useState(true);
  const [plan, setPlan] = useState<PlanBasics>(initialPlan);
  const [tasks, setTasks] = useState<TaskDraft[]>(starterTasks);
  const [toolProfiles, setToolProfiles] = useState<ToolProfileDraft[]>(starterToolProfiles);
  const [credentialSetups, setCredentialSetups] =
    useState<CredentialSetupDraft[]>(starterCredentialSetups);
  const [selectedTaskId, setSelectedTaskId] = useState<string | null>(null);
  const [drawer, setDrawer] = useState<BuilderDrawer>(null);
  const [sourceOpen, setSourceOpen] = useState(true);
  const [validationOpen, setValidationOpen] = useState(false);
  const [filename, setFilename] = useState("plan.toml");
  const [arrangeVersion, setArrangeVersion] = useState(0);
  const [parseStatus, setParseStatus] = useState<ParseStatus>({
    kind: "synced",
    message: "Canvas and TOML are in sync.",
  });
  const [tomlText, setTomlText] = useState(() =>
    renderPlan({
      plan: initialPlan,
      tasks: starterTasks,
      toolProfiles: starterToolProfiles,
    }),
  );
  const [kernelValidation, setKernelValidation] =
    useState<BuilderValidationResponse | null>(null);
  const [kernelBusy, setKernelBusy] = useState(false);
  const [kernelError, setKernelError] = useState<string | null>(null);

  const localIssues = useMemo(
    () => (planEnabled ? validatePlan({ plan, tasks, toolProfiles, credentialSetups }) : []),
    [planEnabled, plan, tasks, toolProfiles, credentialSetups],
  );
  const status = useMemo<PlanStatus>(() => {
    if (!planEnabled) return "empty";
    if (localIssues.some((i) => i.severity === "error")) return "needs-fixes";
    if (localIssues.some((i) => i.severity === "warning")) return "warnings";
    return "ready";
  }, [localIssues, planEnabled]);

  const syncFromState = (
    nextPlan: PlanBasics,
    nextTasks: TaskDraft[],
    nextToolProfiles = toolProfiles,
  ) => {
    setPlanEnabled(true);
    setPlan(nextPlan);
    setTasks(nextTasks);
    setToolProfiles(nextToolProfiles);
    setTomlText(renderPlan({
      plan: nextPlan,
      tasks: nextTasks,
      toolProfiles: nextToolProfiles,
    }));
    setParseStatus({ kind: "synced", message: "Canvas and TOML are in sync." });
    setKernelValidation(null);
    setKernelError(null);
  };

  const updatePlan = (patch: Partial<PlanBasics>) => {
    syncFromState({ ...plan, ...patch }, tasks);
  };

  const updateTasks = (updater: (prev: TaskDraft[]) => TaskDraft[]) => {
    const next = updater(tasks);
    syncFromState(planEnabled ? plan : initialPlan, next);
  };

  const updateToolProfiles = (
    updater: (prev: ToolProfileDraft[]) => ToolProfileDraft[],
  ) => {
    const next = updater(toolProfiles);
    syncFromState(planEnabled ? plan : initialPlan, tasks, next);
  };

  const updateCredentialSetups = (
    updater: (prev: CredentialSetupDraft[]) => CredentialSetupDraft[],
  ) => {
    setCredentialSetups(updater);
    setKernelValidation(null);
    setKernelError(null);
  };

  const updateTask = (taskId: string, patch: Partial<TaskDraft>) => {
    updateTasks((prev) =>
      prev.map((task) =>
        task.id === taskId ? normalizeTask({ ...task, ...patch }) : task,
      ),
    );
  };

  const updatePredecessors = (taskId: string, predecessors: string) => {
    updateTask(taskId, { predecessors });
  };

  const removeTask = (taskId: string) => {
    updateTasks((prev) => {
      const next = prev
        .filter((task) => task.id !== taskId)
        .map((task) => ({
          ...task,
          predecessors: splitList(task.predecessors)
            .filter((pred) => pred !== taskId)
            .join(", "),
        }));
      if (selectedTaskId === taskId) {
        setSelectedTaskId(null);
      }
      return next;
    });
  };

  const addTask = (agentType: AgentType) => {
    const next = makeTask(agentType, tasks);
    updateTasks((prev) => [...prev, next]);
  };

  const addReviewPair = () => {
    const executor = makeTask("Executor", tasks);
    const reviewer = normalizeTask({
      ...makeTask("Reviewer", [...tasks, executor]),
      id: uniqueTaskId(`review-${executor.id}`, [...tasks, executor]),
      description: `Review ${executor.id}`,
      predecessors: executor.id,
      paths: executor.paths,
    });
    updateTasks((prev) => [...prev, executor, reviewer]);
  };

  const addFanOut = () => {
    const base = tasks.length + 1;
    const first = normalizeTask({
      ...makeTask("Executor", tasks),
      id: uniqueTaskId(`slice-${base}-api`, tasks),
      description: "Implement API slice",
      paths: "src/api/",
      prompt:
        "Implement the API slice only. Keep changes inside src/api/. Run the relevant API tests and commit the result.",
    });
    const second = normalizeTask({
      ...makeTask("Executor", [...tasks, first]),
      id: uniqueTaskId(`slice-${base}-ui`, [...tasks, first]),
      description: "Implement UI slice",
      paths: "src/ui/",
      prompt:
        "Implement the UI slice only. Keep changes inside src/ui/. Run the relevant UI tests and commit the result.",
    });
    const reviewer = normalizeTask({
      ...makeTask("Reviewer", [...tasks, first, second]),
      id: uniqueTaskId(`review-slices-${base}`, [...tasks, first, second]),
      description: "Review both slices",
      predecessors: `${first.id}, ${second.id}`,
      paths: "src/api/, src/ui/",
    });
    updateTasks((prev) => [...prev, first, second, reviewer]);
  };

  const clearToml = () => {
    setPlanEnabled(false);
    setPlan(emptyPlan);
    setTasks([]);
    setToolProfiles([]);
    setCredentialSetups([]);
    setSelectedTaskId(null);
    setDrawer(null);
    setTomlText("");
    setParseStatus({
      kind: "empty",
      message: "TOML is empty. Add a task or paste a plan to start again.",
    });
    setKernelValidation(null);
    setKernelError(null);
  };

  const handleTomlChange = (value: string | undefined) => {
    const next = value ?? "";
    setTomlText(next);
    setKernelValidation(null);
    setKernelError(null);
    if (next.trim() === "") {
      setPlanEnabled(false);
      setPlan(emptyPlan);
      setTasks([]);
      setToolProfiles([]);
      setCredentialSetups([]);
      setSelectedTaskId(null);
      setDrawer(null);
      setParseStatus({
        kind: "empty",
        message: "TOML is empty. Add a task or paste a plan to start again.",
      });
      return;
    }
    try {
      const parsed = parsePlanToml(next);
      setPlanEnabled(true);
      setPlan(parsed.plan);
      setTasks(parsed.tasks);
      setToolProfiles(parsed.toolProfiles);
      setSelectedTaskId((prev) =>
        prev && parsed.tasks.some((t) => t.id === prev) ? prev : null,
      );
      setParseStatus({
        kind: "synced",
        message: "Valid TOML parsed back into the canvas.",
      });
    } catch (error) {
      setParseStatus({
        kind: "error",
        message: error instanceof Error ? error.message : "TOML could not be parsed.",
      });
    }
  };

  const runKernelValidation = async () => {
    setValidationOpen(true);
    setKernelBusy(true);
    setKernelError(null);
    try {
      setKernelValidation(await dashboardApi.builders.validatePlan(tomlText));
    } catch (error) {
      if (error instanceof ApiError) setKernelError(`${error.code}: ${error.detail}`);
      else if (error instanceof Error) setKernelError(error.message);
      else setKernelError("validation failed");
    } finally {
      setKernelBusy(false);
    }
  };

  return (
    <div className="h-full min-h-0 min-w-0 overflow-hidden bg-panel text-ink flex flex-col">
      <header className="shrink-0 border-b border-edge bg-panel-raised px-4 py-3">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="text-lg font-semibold leading-tight">Plan Builder</h1>
              <PlanStatusPill status={status} />
              <ParseStatusPill status={parseStatus} />
            </div>
            <p className="mt-1 text-xs text-ink-muted">
              Draw the governed workflow; Raxis keeps the live plan.toml beside it.
            </p>
          </div>
          <div className="flex shrink-0 flex-wrap items-center justify-end gap-2">
            <button
              type="button"
              className="btn text-xs py-1"
              disabled={!planEnabled}
              onClick={() => setDrawer((open) => (open === "plan" ? null : "plan"))}
            >
              {drawer === "plan" ? "Hide setup" : "Plan setup"}
            </button>
            <button
              type="button"
              className="btn text-xs py-1"
              disabled={!planEnabled}
              onClick={() => setDrawer((open) => (open === "tools" ? null : "tools"))}
            >
              {drawer === "tools" ? "Hide profiles" : "Tool profiles"}
            </button>
            <button
              type="button"
              className="btn text-xs py-1"
              disabled={!planEnabled}
              onClick={() => setDrawer((open) => (open === "credentials" ? null : "credentials"))}
            >
              {drawer === "credentials" ? "Hide credentials" : "Credentials"}
            </button>
            <button
              type="button"
              className="btn-primary text-xs py-1"
              disabled={!planEnabled || kernelBusy}
              onClick={() => void runKernelValidation()}
            >
              {kernelBusy ? (
                <>
                  <Spinner className="h-3.5 w-3.5" /> Validating
                </>
              ) : (
                "Validate"
              )}
            </button>
          </div>
        </div>
      </header>

      <div className="shrink-0 border-b border-edge bg-panel px-4 py-2">
        <div className="flex flex-wrap items-center gap-2">
          <button type="button" className="btn text-xs py-1" onClick={() => addTask("Executor")}>
            Add executor
          </button>
          <button type="button" className="btn text-xs py-1" onClick={() => addTask("Reviewer")}>
            Add reviewer
          </button>
          <button type="button" className="btn text-xs py-1" onClick={addReviewPair}>
            Review pair
          </button>
          <button type="button" className="btn text-xs py-1" onClick={addFanOut}>
            Fan-out
          </button>
          <button
            type="button"
            className="btn text-xs py-1"
            disabled={!planEnabled || tasks.length === 0}
            onClick={() => setArrangeVersion((v) => v + 1)}
          >
            Arrange DAG
          </button>
          <button type="button" className="btn text-xs py-1" onClick={clearToml}>
            Clear
          </button>
          <span className="ml-auto text-[11px] text-ink-subtle">
            Drag from a card edge to another card to create a dependency.
          </span>
        </div>
      </div>

      <div className="flex-1 min-h-0 min-w-0 overflow-hidden flex xl:flex-row max-xl:flex-col">
        {drawer === "plan" && planEnabled && (
          <PlanSetupDrawer
            plan={plan}
            onUpdate={updatePlan}
            commands={planSubmitCommands}
            onClose={() => setDrawer(null)}
          />
        )}
        {drawer === "tools" && planEnabled && (
          <ToolProfilesDrawer
            profiles={toolProfiles}
            onUpdate={updateToolProfiles}
            onClose={() => setDrawer(null)}
          />
        )}
        {drawer === "credentials" && planEnabled && (
          <CredentialSetupDrawer
            credentials={credentialSetups}
            onUpdate={updateCredentialSetups}
            onClose={() => setDrawer(null)}
          />
        )}
        <section className="flex-1 min-w-0 min-h-0 overflow-hidden bg-panel max-xl:min-h-[480px] max-md:min-h-[420px]">
          {planEnabled ? (
            <PlanCanvas
              tasks={tasks}
              toolProfiles={toolProfiles}
              credentialSetups={credentialSetups}
              selectedTaskId={selectedTaskId}
              arrangeVersion={arrangeVersion}
              onSelectTask={setSelectedTaskId}
              onUpdateTask={updateTask}
              onRemoveTask={removeTask}
              onUpdatePredecessors={updatePredecessors}
              onAddTask={addTask}
              onOpenToolProfiles={() => setDrawer("tools")}
              onOpenCredentialSetup={() => setDrawer("credentials")}
              canRemoveTask={tasks.length > 0}
            />
          ) : (
            <EmptyPlanState onAddTask={addTask} />
          )}
        </section>
        {sourceOpen ? (
          <aside
            id="generated-plan-toml-panel"
            className="w-[clamp(360px,34vw,460px)] min-w-[340px] max-w-[46vw] border-l border-edge bg-panel-raised flex flex-col min-h-0 max-xl:h-[38vh] max-xl:w-full max-xl:min-w-0 max-xl:max-w-none max-xl:border-l-0 max-xl:border-t max-md:h-[42vh]"
          >
            <div className="shrink-0 border-b border-edge px-3 py-2">
              <div className="flex items-center gap-2">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      className="inline-grid h-7 w-7 place-items-center rounded-md border border-edge-strong bg-panel text-ink-muted transition-colors hover:border-accent hover:bg-panel-high hover:text-accent focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                      aria-label="Collapse generated plan.toml"
                      aria-expanded={sourceOpen}
                      aria-controls="generated-plan-toml-panel"
                      title="Collapse generated plan.toml"
                      onClick={() => setSourceOpen(false)}
                    >
                      <SourcePanelIcon open />
                    </button>
                    <div className="min-w-0">
                      <div className="text-[10px] font-semibold uppercase tracking-wider text-ink-subtle">
                        Generated plan.toml
                      </div>
                      <div className="mt-0.5 truncate text-[11px] text-ink-subtle">
                        Live source of truth
                      </div>
                    </div>
                  </div>
                  <input
                    value={filename}
                    onChange={(e) => setFilename(e.target.value || "plan.toml")}
                    className="mt-2 input w-full font-mono text-xs"
                    aria-label="Download filename"
                  />
                </div>
                <CopyButton value={tomlText} label="Copy plan.toml" />
                <button
                  type="button"
                  className="btn text-xs py-1"
                  disabled={!tomlText.trim()}
                  onClick={() => downloadText(filename || "plan.toml", tomlText)}
                >
                  Download
                </button>
              </div>
            </div>
            <div className="flex-1 min-h-0">
              <Editor
                value={tomlText}
                language="toml"
                beforeMount={ensureTomlLanguage}
                theme={monacoTheme}
                onChange={handleTomlChange}
                options={{
                  minimap: { enabled: false },
                  fontSize: 12,
                  lineNumbersMinChars: 3,
                  scrollBeyondLastLine: false,
                  wordWrap: "on",
                  wrappingIndent: "same",
                  tabSize: 2,
                  automaticLayout: true,
                }}
              />
            </div>
          </aside>
        ) : (
          <aside className="shrink-0 border-l border-edge bg-panel-raised max-xl:border-l-0 max-xl:border-t">
            <button
              type="button"
              className="flex h-full min-h-[320px] w-12 items-center justify-center gap-2 text-[10px] font-semibold uppercase tracking-wider text-ink-muted transition-colors hover:bg-panel-high hover:text-accent focus:outline-none focus-visible:ring-2 focus-visible:ring-accent max-xl:min-h-0 max-xl:h-11 max-xl:w-full"
              aria-label="Show generated plan.toml"
              aria-expanded={sourceOpen}
              aria-controls="generated-plan-toml-panel"
              title="Show generated plan.toml"
              onClick={() => setSourceOpen(true)}
            >
              <SourcePanelIcon open={false} />
              <span className="hidden xl:block" style={{ writingMode: "vertical-rl" }}>
                plan.toml
              </span>
              <span className="xl:hidden">Show generated plan.toml</span>
            </button>
          </aside>
        )}
      </div>

      {validationOpen && (
        <ValidationPanel
          issues={localIssues}
          kernelValidation={kernelValidation}
          kernelBusy={kernelBusy}
          kernelError={kernelError}
          onClose={() => setValidationOpen(false)}
          onRun={() => void runKernelValidation()}
        />
      )}
    </div>
  );
}

function PlanSetupDrawer({
  plan,
  onUpdate,
  commands,
  onClose,
}: {
  plan: PlanBasics;
  onUpdate: (patch: Partial<PlanBasics>) => void;
  commands: string[];
  onClose: () => void;
}) {
  return (
    <aside className="w-80 shrink-0 border-r border-edge bg-panel-raised min-h-0 overflow-y-auto scroll-thin max-xl:w-full max-xl:max-h-64 max-xl:border-r-0 max-xl:border-b">
      <div className="sticky top-0 z-10 border-b border-edge bg-panel-raised px-4 py-3">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="text-sm font-semibold text-ink">Plan setup</div>
            <p className="mt-1 text-xs text-ink-subtle">
              Initiative and workspace details. Task-specific authority stays on task cards.
            </p>
          </div>
          <DrawerCloseButton label="Collapse plan setup" onClick={onClose} />
        </div>
      </div>
      <div className="space-y-3 p-4">
        <Field label="Initiative description">
          <textarea
            value={plan.initiative}
            onChange={(e) => onUpdate({ initiative: e.target.value })}
            rows={4}
            className="input w-full min-h-[88px] text-xs"
          />
        </Field>
        <Field label="Workspace name">
          <input
            value={plan.workspace}
            onChange={(e) => onUpdate({ workspace: e.target.value })}
            className="input w-full text-xs"
          />
        </Field>
        <Field label="Lane id">
          <input
            value={plan.lane}
            onChange={(e) => onUpdate({ lane: e.target.value })}
            className="input w-full font-mono text-xs"
          />
        </Field>
        <Field label="Target ref">
          <input
            value={plan.targetRef}
            onChange={(e) => onUpdate({ targetRef: e.target.value })}
            className="input w-full font-mono text-xs"
          />
        </Field>
        <Field label="Repository name">
          <input
            value={plan.repository}
            onChange={(e) => onUpdate({ repository: e.target.value })}
            className="input w-full font-mono text-xs"
          />
        </Field>
        <Field label="Cross-cutting artifacts">
          <input
            value={plan.crossCuttingArtifacts}
            onChange={(e) => onUpdate({ crossCuttingArtifacts: e.target.value })}
            className="input w-full font-mono text-xs"
            placeholder="Cargo.lock, package-lock.json"
          />
        </Field>
        <Divider label="Next steps" />
        <div className="space-y-1.5">
          {commands.map((command) => (
            <CommandRow key={command} command={command} />
          ))}
        </div>
      </div>
    </aside>
  );
}

function ToolProfilesDrawer({
  profiles,
  onUpdate,
  onClose,
}: {
  profiles: ToolProfileDraft[];
  onUpdate: (updater: (prev: ToolProfileDraft[]) => ToolProfileDraft[]) => void;
  onClose: () => void;
}) {
  const [selectedId, setSelectedId] = useState(() => profiles[0]?.id ?? "");
  const selected = profiles.find((profile) => profile.id === selectedId) ?? profiles[0];

  const updateProfile = (profileId: string, patch: Partial<ToolProfileDraft>) => {
    onUpdate((prev) =>
      prev.map((profile) =>
        profile.id === profileId ? { ...profile, ...patch } : profile,
      ),
    );
    if (patch.id) setSelectedId(patch.id);
  };

  const updateTool = (
    profileId: string,
    index: number,
    patch: Partial<ToolDraft>,
  ) => {
    onUpdate((prev) =>
      prev.map((profile) =>
        profile.id === profileId
          ? {
              ...profile,
              tools: profile.tools.map((tool, toolIndex) =>
                toolIndex === index ? { ...tool, ...patch } : tool,
              ),
            }
          : profile,
      ),
    );
  };

  const addProfile = () => {
    const next = makeToolProfile(profiles);
    onUpdate((prev) => [...prev, next]);
    setSelectedId(next.id);
  };

  const removeProfile = (profileId: string) => {
    onUpdate((prev) => prev.filter((profile) => profile.id !== profileId));
    setSelectedId("");
  };

  const addTool = (profileId: string) => {
    onUpdate((prev) =>
      prev.map((profile) =>
        profile.id === profileId
          ? {
              ...profile,
              tools: [...profile.tools, makeTool(profile.tools)],
            }
          : profile,
      ),
    );
  };

  const removeTool = (profileId: string, index: number) => {
    onUpdate((prev) =>
      prev.map((profile) =>
        profile.id === profileId
          ? {
              ...profile,
              tools: profile.tools.filter((_, toolIndex) => toolIndex !== index),
            }
          : profile,
      ),
    );
  };

  return (
    <aside className="w-[360px] shrink-0 border-r border-edge bg-panel-raised min-h-0 overflow-y-auto scroll-thin max-xl:w-full max-xl:max-h-[360px] max-xl:border-r-0 max-xl:border-b">
      <div className="sticky top-0 z-10 border-b border-edge bg-panel-raised px-4 py-3">
        <div className="flex items-center justify-between gap-2">
          <div className="min-w-0">
            <div className="text-sm font-semibold text-ink">Tool profiles</div>
            <p className="mt-1 text-xs text-ink-subtle">
              Shared tool bundles. Executor cards can reference multiple profiles.
            </p>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <button type="button" className="btn text-xs py-1" onClick={addProfile}>
              Add
            </button>
            <DrawerCloseButton label="Collapse tool profiles" onClick={onClose} />
          </div>
        </div>
      </div>
      <div className="grid grid-cols-[8.5rem_1fr] gap-0 min-h-full max-md:grid-cols-1">
        <div className="border-r border-edge p-3 space-y-1 max-md:border-r-0 max-md:border-b">
          {profiles.length === 0 ? (
            <div className="rounded border border-dashed border-edge px-2.5 py-3 text-xs text-ink-muted">
              No profiles yet.
            </div>
          ) : (
            profiles.map((profile) => (
              <button
                key={profile.id}
                type="button"
                className={`w-full truncate rounded border px-2.5 py-2 text-left font-mono text-[11px] transition-colors ${
                  selected?.id === profile.id
                    ? "border-accent bg-accent-muted text-accent"
                    : "border-transparent text-ink-muted hover:border-edge hover:bg-panel"
                }`}
                onClick={() => setSelectedId(profile.id)}
              >
                {profile.id || "(blank)"}
              </button>
            ))
          )}
        </div>
        <div className="p-4 space-y-3">
          {!selected ? (
            <div className="rounded border border-edge bg-panel px-3 py-4 text-xs text-ink-muted">
              Add a tool profile to define shared tools for executor tasks.
            </div>
          ) : (
            <>
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <div className="text-[10px] font-semibold uppercase tracking-wider text-ink-subtle">
                    Profile
                  </div>
                  <div className="mt-1 truncate font-mono text-sm text-ink">
                    {selected.id || "(blank)"}
                  </div>
                </div>
                <button
                  type="button"
                  className="btn text-xs py-1 text-bad border-bad/30 hover:bg-bad/10"
                  onClick={() => removeProfile(selected.id)}
                >
                  Remove
                </button>
              </div>
              <Field label="Profile id">
                <input
                  value={selected.id}
                  onChange={(e) => updateProfile(selected.id, { id: e.target.value })}
                  className="input w-full font-mono text-xs"
                  placeholder="repo_tools"
                />
              </Field>
              <Field label="Description">
                <textarea
                  value={selected.description}
                  onChange={(e) => updateProfile(selected.id, { description: e.target.value })}
                  rows={3}
                  className="input w-full min-h-[72px] text-xs"
                  placeholder="Repository inspection tools available to executor tasks."
                />
              </Field>
              <Divider label="Tools" />
              {selected.tools.length === 0 ? (
                <div className="rounded border border-dashed border-edge px-3 py-4 text-xs text-ink-muted">
                  This profile has no tools yet.
                </div>
              ) : (
                <div className="space-y-3">
                  {selected.tools.map((tool, index) => (
                    <section
                      key={`${selected.id}-${index}`}
                      className="rounded border border-edge bg-panel p-3 space-y-2"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <div className="font-mono text-xs text-ink">
                          {tool.name || `tool-${index + 1}`}
                        </div>
                        <button
                          type="button"
                          className="btn text-xs py-1 text-bad border-bad/30 hover:bg-bad/10"
                          onClick={() => removeTool(selected.id, index)}
                        >
                          Remove
                        </button>
                      </div>
                      <div className="grid grid-cols-2 gap-2">
                        <Field label="Operation name">
                          <input
                            value={tool.name}
                            onChange={(e) => updateTool(selected.id, index, { name: e.target.value })}
                            className="input w-full font-mono text-xs"
                            placeholder="repo_symbol_search"
                          />
                        </Field>
                        <Field label="Execution locality">
                          <select
                            value={tool.locality}
                            onChange={(e) =>
                              updateTool(selected.id, index, {
                                locality: e.target.value as ToolLocality,
                              })
                            }
                            className="input w-full text-xs"
                          >
                            {toolLocalities.map((locality) => (
                              <option key={locality} value={locality}>
                                {locality}
                              </option>
                            ))}
                          </select>
                        </Field>
                      </div>
                      <Field label="Description">
                        <input
                          value={tool.description}
                          onChange={(e) => updateTool(selected.id, index, { description: e.target.value })}
                          className="input w-full text-xs"
                          placeholder="Search symbols and file names with rg."
                        />
                      </Field>
                      <Field label="Command argv">
                        <textarea
                          value={tool.command}
                          onChange={(e) => updateTool(selected.id, index, { command: e.target.value })}
                          rows={4}
                          className="input w-full min-h-[86px] font-mono text-xs"
                          placeholder={"/usr/bin/rg\n--line-number\n--hidden"}
                        />
                      </Field>
                      <div className="grid grid-cols-4 gap-2">
                        <Field label="Timeout">
                          <input
                            value={tool.timeoutSeconds}
                            onChange={(e) => updateTool(selected.id, index, { timeoutSeconds: e.target.value })}
                            className="input w-full font-mono text-xs"
                          />
                        </Field>
                        <Field label="Stdin">
                          <input
                            value={tool.stdinMaxBytes}
                            onChange={(e) => updateTool(selected.id, index, { stdinMaxBytes: e.target.value })}
                            className="input w-full font-mono text-xs"
                          />
                        </Field>
                        <Field label="Stdout">
                          <input
                            value={tool.stdoutMaxBytes}
                            onChange={(e) => updateTool(selected.id, index, { stdoutMaxBytes: e.target.value })}
                            className="input w-full font-mono text-xs"
                          />
                        </Field>
                        <Field label="Stderr">
                          <input
                            value={tool.stderrMaxBytes}
                            onChange={(e) => updateTool(selected.id, index, { stderrMaxBytes: e.target.value })}
                            className="input w-full font-mono text-xs"
                          />
                        </Field>
                      </div>
                      <Field label="Tool Schema">
                        <textarea
                          value={tool.schemaJson}
                          onChange={(e) => updateTool(selected.id, index, { schemaJson: e.target.value })}
                          rows={2}
                          className="input w-full min-h-[54px] font-mono text-xs"
                          placeholder='{ "query": "string", "limit?": { "type": "integer" } }'
                        />
                      </Field>
                    </section>
                  ))}
                </div>
              )}
              <button
                type="button"
                className="btn text-xs py-1 w-full justify-center"
                onClick={() => addTool(selected.id)}
              >
                Add tool to profile
              </button>
            </>
          )}
        </div>
      </div>
    </aside>
  );
}

function CredentialSetupDrawer({
  credentials,
  onUpdate,
  onClose,
}: {
  credentials: CredentialSetupDraft[];
  onUpdate: (updater: (prev: CredentialSetupDraft[]) => CredentialSetupDraft[]) => void;
  onClose: () => void;
}) {
  const [selectedName, setSelectedName] = useState(() => credentials[0]?.name ?? "");
  const selected =
    credentials.find((credential) => credential.name === selectedName) ?? credentials[0];
  const renderedToml = renderCredentialSetupToml(credentials);

  const updateCredential = (
    credentialName: string,
    patch: Partial<CredentialSetupDraft>,
  ) => {
    onUpdate((prev) =>
      prev.map((credential) => {
        if (credential.name !== credentialName) return credential;
        const merged = { ...credential, ...patch };
        if (patch.proxyType && !patch.mountAs && credential.mountAs === defaultMountAs(credential.proxyType)) {
          merged.mountAs = defaultMountAs(patch.proxyType);
        }
        if (patch.proxyType && !patch.expectedShape) {
          merged.expectedShape = defaultCredentialShape(patch.proxyType);
        }
        return merged;
      }),
    );
    if (patch.name) setSelectedName(patch.name);
  };

  const addCredential = () => {
    const next = makeCredentialSetup(credentials);
    onUpdate((prev) => [...prev, next]);
    setSelectedName(next.name);
  };

  const removeCredential = (credentialName: string) => {
    onUpdate((prev) => prev.filter((credential) => credential.name !== credentialName));
    setSelectedName("");
  };

  return (
    <aside className="w-[380px] shrink-0 border-r border-edge bg-panel-raised min-h-0 overflow-y-auto scroll-thin max-xl:w-full max-xl:max-h-[380px] max-xl:border-r-0 max-xl:border-b">
      <div className="sticky top-0 z-10 border-b border-edge bg-panel-raised px-4 py-3">
        <div className="flex items-center justify-between gap-2">
          <div className="min-w-0">
            <div className="text-sm font-semibold text-ink">Credential setup</div>
            <p className="mt-1 text-xs text-ink-subtle">
              Name kernel-held credentials and generate attachable plan snippets. Secret values stay out of the plan.
            </p>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <button type="button" className="btn text-xs py-1" onClick={addCredential}>
              Add
            </button>
            <DrawerCloseButton label="Collapse credential setup" onClick={onClose} />
          </div>
        </div>
      </div>
      <div className="grid grid-cols-[9rem_1fr] gap-0 min-h-full max-md:grid-cols-1">
        <div className="border-r border-edge p-3 space-y-1 max-md:border-r-0 max-md:border-b">
          {credentials.length === 0 ? (
            <div className="rounded border border-dashed border-edge px-2.5 py-3 text-xs text-ink-muted">
              No credential templates yet.
            </div>
          ) : (
            credentials.map((credential) => (
              <button
                key={credential.name}
                type="button"
                className={`w-full truncate rounded border px-2.5 py-2 text-left font-mono text-[11px] transition-colors ${
                  selected?.name === credential.name
                    ? "border-accent bg-accent-muted text-accent"
                    : "border-transparent text-ink-muted hover:border-edge hover:bg-panel"
                }`}
                onClick={() => setSelectedName(credential.name)}
              >
                {credential.name || "(blank)"}
              </button>
            ))
          )}
        </div>
        <div className="p-4 space-y-3">
          {!selected ? (
            <div className="rounded border border-edge bg-panel px-3 py-4 text-xs text-ink-muted">
              Add a credential template, then bind it from executor cards.
            </div>
          ) : (
            <>
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <div className="text-[10px] font-semibold uppercase tracking-wider text-ink-subtle">
                    Credential
                  </div>
                  <div className="mt-1 truncate font-mono text-sm text-ink">
                    {selected.name || "(blank)"}
                  </div>
                </div>
                <button
                  type="button"
                  className="btn text-xs py-1 text-bad border-bad/30 hover:bg-bad/10"
                  onClick={() => removeCredential(selected.name)}
                >
                  Remove
                </button>
              </div>
              <div className="grid grid-cols-2 gap-2">
                <Field label="Name">
                  <input
                    value={selected.name}
                    onChange={(e) => updateCredential(selected.name, { name: e.target.value })}
                    className="input w-full font-mono text-xs"
                    placeholder="db_main"
                  />
                </Field>
                <Field label="Proxy type">
                  <select
                    value={selected.proxyType}
                    onChange={(e) =>
                      updateCredential(selected.name, {
                        proxyType: e.target.value as CredentialProxyType,
                      })
                    }
                    className="input w-full text-xs"
                  >
                    {credentialProxyTypes.map((proxyType) => (
                      <option key={proxyType} value={proxyType}>
                        {proxyType}
                      </option>
                    ))}
                  </select>
                </Field>
              </div>
              <div className="grid grid-cols-2 gap-2">
                <Field label="Mount env">
                  <input
                    value={selected.mountAs}
                    onChange={(e) => updateCredential(selected.name, { mountAs: e.target.value })}
                    className="input w-full font-mono text-xs"
                    placeholder={defaultMountAs(selected.proxyType)}
                  />
                </Field>
                <Field label="Environment">
                  <input
                    value={selected.environment}
                    onChange={(e) => updateCredential(selected.name, { environment: e.target.value })}
                    className="input w-full font-mono text-xs"
                    placeholder="staging"
                  />
                </Field>
              </div>
              <Field label="Description">
                <textarea
                  value={selected.description}
                  onChange={(e) => updateCredential(selected.name, { description: e.target.value })}
                  rows={2}
                  className="input w-full min-h-[54px] text-xs"
                  placeholder="Database credential used through the kernel proxy."
                />
              </Field>
              <CredentialProxyFields
                credential={selected}
                onUpdate={(patch) => updateCredential(selected.name, patch)}
              />
              <Field label="Expected secret shape">
                <input
                  value={selected.expectedShape}
                  onChange={(e) => updateCredential(selected.name, { expectedShape: e.target.value })}
                  className="input w-full font-mono text-xs"
                  placeholder={defaultCredentialShape(selected.proxyType)}
                />
              </Field>
              <Divider label="Downloadable setup TOML" />
              <textarea
                readOnly
                value={renderedToml}
                rows={10}
                className="input w-full min-h-[180px] font-mono text-[11px]"
              />
              <div className="flex items-center gap-2">
                <CopyButton value={renderedToml} label="Copy credential setup" />
                <button
                  type="button"
                  className="btn text-xs py-1"
                  disabled={!credentials.length}
                  onClick={() => downloadText("credentials.toml", renderedToml)}
                >
                  Download credentials.toml
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </aside>
  );
}

function CredentialProxyFields({
  credential,
  onUpdate,
}: {
  credential: CredentialSetupDraft | CredentialDraft;
  onUpdate: (patch: Partial<CredentialDraft>) => void;
}) {
  if (credential.proxyType === "http") {
    return (
      <div className="grid grid-cols-2 gap-2">
        <Field label="Upstream URL">
          <input
            value={credential.upstreamUrl}
            onChange={(e) => onUpdate({ upstreamUrl: e.target.value })}
            className="input w-full font-mono text-xs"
            placeholder="https://api.example.com/v1"
          />
        </Field>
        <Field label="Auth mode">
          <select
            value={credential.authMode}
            onChange={(e) => onUpdate({ authMode: e.target.value })}
            className="input w-full text-xs"
          >
            <option>bearer</option>
            <option>basic</option>
          </select>
        </Field>
      </div>
    );
  }
  if (credential.proxyType === "redis" || credential.proxyType === "smtp") {
    return (
      <Field label="Upstream host:port">
        <input
          value={credential.upstreamHostPort}
          onChange={(e) => onUpdate({ upstreamHostPort: e.target.value })}
          className="input w-full font-mono text-xs"
          placeholder={credential.proxyType === "redis" ? "redis.example.com:6379" : "smtp.example.com:587"}
        />
      </Field>
    );
  }
  if (credential.proxyType === "gcp") {
    return (
      <Field label="Project id">
        <input
          value={credential.project}
          onChange={(e) => onUpdate({ project: e.target.value })}
          className="input w-full font-mono text-xs"
          placeholder="my-staging-project"
        />
      </Field>
    );
  }
  if (credential.proxyType === "azure") {
    return (
      <div className="grid grid-cols-2 gap-2">
        <Field label="Tenant id">
          <input
            value={credential.tenantId}
            onChange={(e) => onUpdate({ tenantId: e.target.value })}
            className="input w-full font-mono text-xs"
            placeholder="00000000-0000-0000-0000-000000000000"
          />
        </Field>
        <Field label="Client id">
          <input
            value={credential.clientId}
            onChange={(e) => onUpdate({ clientId: e.target.value })}
            className="input w-full font-mono text-xs"
            placeholder="optional"
          />
        </Field>
      </div>
    );
  }
  if (credential.proxyType === "aws") {
    return (
      <Field label="Role ARN">
        <input
          value={credential.roleArn}
          onChange={(e) => onUpdate({ roleArn: e.target.value })}
          className="input w-full font-mono text-xs"
          placeholder="arn:aws:iam::123456789012:role/raxis-agent"
        />
      </Field>
    );
  }
  return null;
}

function DrawerCloseButton({
  label,
  onClick,
}: {
  label: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      className="inline-grid h-7 w-7 place-items-center rounded-md border border-edge-strong bg-panel text-ink-muted transition-colors hover:border-accent hover:bg-panel-high hover:text-accent focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
      aria-label={label}
      title={label}
      onClick={onClick}
    >
      <svg className="h-3.5 w-3.5" viewBox="0 0 16 16" fill="none" aria-hidden>
        <path
          d="M4 8h8"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
        />
      </svg>
    </button>
  );
}

function SourcePanelIcon({ open }: { open: boolean }) {
  return (
    <svg className="h-3.5 w-3.5 shrink-0" viewBox="0 0 16 16" fill="none" aria-hidden>
      {open ? (
        <path
          d="M6 3.5 10.5 8 6 12.5"
          stroke="currentColor"
          strokeWidth="1.8"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      ) : (
        <path
          d="M10 3.5 5.5 8 10 12.5"
          stroke="currentColor"
          strokeWidth="1.8"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      )}
    </svg>
  );
}

function EmptyPlanState({
  onAddTask,
}: {
  onAddTask: (type: AgentType) => void;
}) {
  return (
    <div className="h-full min-h-0 flex items-center justify-center p-8">
      <div className="max-w-md rounded border border-edge bg-panel-raised p-6 text-center shadow-soft">
        <div className="text-sm font-semibold text-ink">No plan document</div>
        <p className="mt-2 text-xs leading-relaxed text-ink-muted">
          Paste a plan.toml into the source panel or create a task to start a new
          visual plan.
        </p>
        <div className="mt-4 flex justify-center gap-2">
          <button type="button" className="btn-primary text-xs py-1" onClick={() => onAddTask("Executor")}>
            Add executor
          </button>
        </div>
      </div>
    </div>
  );
}

function ValidationPanel({
  issues,
  kernelValidation,
  kernelBusy,
  kernelError,
  onClose,
  onRun,
}: {
  issues: LocalIssue[];
  kernelValidation: BuilderValidationResponse | null;
  kernelBusy: boolean;
  kernelError: string | null;
  onClose: () => void;
  onRun: () => void;
}) {
  return (
    <div className="absolute bottom-4 right-[480px] z-30 w-[440px] max-w-[calc(100vw-520px)] rounded border border-edge bg-panel-raised shadow-soft">
      <div className="flex items-center justify-between gap-2 border-b border-edge px-3 py-2">
        <div>
          <div className="text-sm font-semibold text-ink">Validation</div>
          <div className="text-[11px] text-ink-subtle">
            Draft checks plus kernel validation output.
          </div>
        </div>
        <button type="button" className="btn text-xs py-1" onClick={onClose}>
          Close
        </button>
      </div>
      <div className="max-h-[58vh] overflow-y-auto scroll-thin p-3 space-y-3">
        <section>
          <div className="flex items-center justify-between gap-2">
            <h2 className="text-xs font-semibold text-ink">Draft checks</h2>
            <span className="text-[10px] text-ink-subtle">
              {issues.length === 0 ? "0 issues" : `${issues.length} issue${issues.length === 1 ? "" : "s"}`}
            </span>
          </div>
          {issues.length === 0 ? (
            <div className="mt-2 rounded border border-ok/40 bg-ok-muted px-2.5 py-2 text-xs text-ok">
              Ready for kernel validation.
            </div>
          ) : (
            <ul className="mt-2 space-y-1.5">
              {issues.map((issue) => (
                <li
                  key={`${issue.field}-${issue.message}`}
                  className={`rounded border px-2.5 py-2 text-xs ${
                    issue.severity === "error"
                      ? "border-bad/40 bg-bad/10 text-bad"
                      : "border-warn/40 bg-warn-muted text-warn"
                  }`}
                >
                  <div className="font-semibold">{issue.message}</div>
                  <div className="mt-1 text-ink-muted">{issue.next}</div>
                  <code className="mt-1 inline-block font-mono text-[10px] text-ink-subtle">
                    {issue.field}
                  </code>
                </li>
              ))}
            </ul>
          )}
        </section>
        <Divider label="Kernel" />
        <div className="flex items-center justify-between gap-2">
          <p className="text-xs leading-relaxed text-ink-muted">
            Uses the same backend validation path the dashboard and CLI use.
          </p>
          <button type="button" className="btn text-xs py-1 shrink-0" disabled={kernelBusy} onClick={onRun}>
            {kernelBusy ? (
              <>
                <Spinner className="h-3 w-3" /> Running
              </>
            ) : (
              "Run"
            )}
          </button>
        </div>
        {kernelError && (
          <div className="rounded border border-bad/40 bg-bad/10 px-2.5 py-2 text-xs text-bad">
            {kernelError}
          </div>
        )}
        {kernelValidation && <KernelValidationPanel response={kernelValidation} />}
      </div>
    </div>
  );
}

function KernelValidationPanel({ response }: { response: BuilderValidationResponse }) {
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className={response.ok ? "badge border-ok bg-ok-muted text-ok" : "badge border-bad bg-bad/10 text-bad"}>
          {response.ok ? "Kernel check passed" : "Kernel check found errors"}
        </span>
        <span className="text-ink-subtle">epoch #{response.policy_epoch}</span>
        {response.resolved_target_ref && (
          <code className="rounded border border-edge bg-panel px-1.5 py-0.5 font-mono text-[10px] text-ink-muted">
            {response.resolved_target_ref}
          </code>
        )}
      </div>
      {response.issues.length === 0 ? (
        <div className="rounded border border-ok/40 bg-ok-muted px-2.5 py-2 text-xs text-ok">
          No kernel issues reported.
        </div>
      ) : (
        <ul className="space-y-1.5">
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
      {response.next_steps.length > 0 && (
        <div className="space-y-1.5 pt-1">
          {response.next_steps.map((command) => (
            <CommandRow key={command} command={command} />
          ))}
        </div>
      )}
    </div>
  );
}

function PlanStatusPill({ status }: { status: PlanStatus }) {
  const meta = {
    empty: ["No plan", "border-edge bg-panel text-ink-muted"],
    ready: ["Ready", "border-ok bg-ok-muted text-ok"],
    warnings: ["Warnings", "border-warn bg-warn-muted text-warn"],
    "needs-fixes": ["Needs fixes", "border-bad bg-bad/10 text-bad"],
  } satisfies Record<PlanStatus, [string, string]>;
  return <span className={`badge text-[10px] ${meta[status][1]}`}>{meta[status][0]}</span>;
}

function ParseStatusPill({ status }: { status: ParseStatus }) {
  const tone =
    status.kind === "synced"
      ? "border-info bg-info-muted text-info"
      : status.kind === "error"
        ? "border-bad bg-bad/10 text-bad"
        : "border-edge bg-panel text-ink-muted";
  return (
    <span className={`badge text-[10px] ${tone}`} title={status.message}>
      {status.kind === "synced" ? "Synced" : status.kind === "error" ? "Parse error" : "Empty"}
    </span>
  );
}

function Field({
  label,
  children,
  className = "",
}: {
  label: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <label className={`block text-[10px] font-semibold text-ink-subtle ${className}`}>
      <span>{label}</span>
      <span className="mt-1 block">{children}</span>
    </label>
  );
}

function Divider({ label }: { label: string }) {
  return (
    <div className="flex items-center gap-2 py-1">
      <div className="h-px flex-1 bg-edge" />
      <span className="text-[9px] font-semibold uppercase tracking-wider text-ink-subtle">
        {label}
      </span>
      <div className="h-px flex-1 bg-edge" />
    </div>
  );
}

function CommandRow({ command }: { command: string }) {
  return (
    <div className="flex items-center gap-2 rounded border border-edge bg-panel px-2.5 py-1.5">
      <code className="min-w-0 flex-1 truncate font-mono text-[10px] text-ink-muted">
        {command}
      </code>
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
  const id = uniqueTaskId(agentType === "Reviewer" ? "review" : "task", existing);
  return normalizeTask({
    id,
    description: agentType === "Reviewer" ? "Review predecessor output" : "Implement task",
    agentType,
    predecessors: "",
    paths: agentType === "Reviewer" ? existing.at(-1)?.paths ?? "" : "./",
    pathExports: "",
    allowedEgress: "",
    cloneStrategy: "blobless",
    maxTurns: agentType === "Reviewer" ? "30" : "60",
    maxTurnsStep: "",
    cumulativeMaxSeconds: agentType === "Reviewer" ? "600" : "",
    vmImage: "",
    profiles: "",
    verifierName: "",
    verifierGateType: "TestPass",
    verifierCommand: "",
    verifierGateOn: "Pass",
    credentials: [],
    prompt:
      agentType === "Reviewer"
        ? "Review the predecessor commit for correctness, safety, and scope. Submit Approve or Reject with concise evidence."
        : "Describe the exact change, verification command, commit message, and files that must remain untouched.",
  });
}

function normalizeTask(task: TaskDraft): TaskDraft {
  const normalized = {
    ...task,
    credentials: task.credentials ?? [],
  };
  if (normalized.agentType !== "Reviewer") return normalized;
  return {
    ...normalized,
    allowedEgress: "",
    vmImage: "",
    profiles: "",
    credentials: [],
  };
}

function uniqueTaskId(prefix: string, existing: TaskDraft[]) {
  const used = new Set(existing.map((task) => task.id));
  const safePrefix = slugify(prefix || "task");
  if (!used.has(safePrefix)) return safePrefix;
  for (let i = existing.length + 1; i < existing.length + 200; i += 1) {
    const candidate = `${safePrefix}-${i}`;
    if (!used.has(candidate)) return candidate;
  }
  return `${safePrefix}-${Date.now().toString(36)}`;
}

function makeToolProfile(existing: ToolProfileDraft[]): ToolProfileDraft {
  const id = uniqueProfileId("repo_tools", existing);
  return {
    id,
    description: "Reusable tools available to selected executor tasks.",
    tools: [makeTool([])],
  };
}

function makeTool(existing: ToolDraft[]): ToolDraft {
  return {
    name: uniqueToolName("repo_symbol_search", existing),
    description: "Search symbols and file names with ripgrep inside the assigned workspace.",
    locality: "guest_subprocess",
    command: "/usr/bin/rg\n--line-number\n--hidden\n--glob\n!.git/*",
    timeoutSeconds: "30",
    stdinMaxBytes: "4096",
    stdoutMaxBytes: "65536",
    stderrMaxBytes: "8192",
    schemaJson: '{ "query": "string" }',
  };
}

function makeCredentialSetup(existing: CredentialSetupDraft[]): CredentialSetupDraft {
  const proxyType: CredentialProxyType = "postgres";
  const name = uniqueCredentialName("db_main", existing);
  return {
    ...makeCredentialDraft({ name, proxyType }),
    description: "Kernel-held credential available through a task-scoped proxy.",
    environment: "",
    expectedShape: defaultCredentialShape(proxyType),
  };
}

export function makeCredentialDraft(input: {
  name?: string;
  proxyType?: CredentialProxyType;
  mountAs?: string;
} = {}): CredentialDraft {
  const proxyType = input.proxyType ?? "postgres";
  return {
    name: input.name ?? "",
    proxyType,
    mountAs: input.mountAs ?? defaultMountAs(proxyType),
    upstreamUrl: "",
    upstreamHostPort: "",
    authMode: "bearer",
    project: "",
    tenantId: "",
    roleArn: "",
    clientId: "",
  };
}

function uniqueProfileId(prefix: string, existing: ToolProfileDraft[]) {
  const used = new Set(existing.map((profile) => profile.id));
  const safePrefix = slugify(prefix || "tools");
  if (!used.has(safePrefix)) return safePrefix;
  for (let i = existing.length + 1; i < existing.length + 200; i += 1) {
    const candidate = `${safePrefix}-${i}`;
    if (!used.has(candidate)) return candidate;
  }
  return `${safePrefix}-${Date.now().toString(36)}`;
}

function uniqueToolName(prefix: string, existing: ToolDraft[]) {
  const used = new Set(existing.map((tool) => tool.name));
  const safePrefix = slugifyToolName(prefix || "tool");
  if (!used.has(safePrefix)) return safePrefix;
  for (let i = existing.length + 1; i < existing.length + 200; i += 1) {
    const candidate = `${safePrefix}_${i}`;
    if (!used.has(candidate)) return candidate;
  }
  return `${safePrefix}_${Date.now().toString(36)}`;
}

function uniqueCredentialName(prefix: string, existing: CredentialSetupDraft[]) {
  const used = new Set(existing.map((credential) => credential.name));
  const safePrefix = slugify(prefix || "credential");
  if (!used.has(safePrefix)) return safePrefix;
  for (let i = existing.length + 1; i < existing.length + 200; i += 1) {
    const candidate = `${safePrefix}-${i}`;
    if (!used.has(candidate)) return candidate;
  }
  return `${safePrefix}-${Date.now().toString(36)}`;
}

function validatePlan(input: {
  plan: PlanBasics;
  tasks: TaskDraft[];
  toolProfiles: ToolProfileDraft[];
  credentialSetups: CredentialSetupDraft[];
}) {
  const issues: LocalIssue[] = [];
  const push = (
    severity: LocalIssue["severity"],
    field: string,
    message: string,
    next: string,
  ) => issues.push({ severity, field, message, next });

  if (!input.plan.initiative.trim()) {
    push("error", "[plan.initiative].description", "Initiative description is required.", "Open Plan setup and describe the initiative.");
  }
  if (!input.plan.workspace.trim()) {
    push("error", "[workspace].name", "Workspace name is required.", "Open Plan setup and set a short workspace name.");
  } else if (input.plan.workspace.trim().length > 48) {
    push("error", "[workspace].name", "Workspace name is too long.", "Use 48 characters or fewer so the dashboard can display it cleanly.");
  }
  if (!input.plan.lane.trim()) {
    push("error", "[workspace].lane_id", "Lane id is required.", "Set the policy lane that should execute this plan.");
  }
  if (!input.plan.targetRef.startsWith("refs/heads/")) {
    push("error", "[workspace].target_ref", "Target ref must start with refs/heads/.", "Use a full branch ref such as refs/heads/main.");
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(input.plan.repository.trim())) {
    push("error", "[workspace].repository", "Repository name must be path-safe.", "Use letters, digits, dots, underscores, or dashes.");
  }
  for (const artifact of splitList(input.plan.crossCuttingArtifacts)) {
    if (artifact.startsWith("/") || artifact.includes("..")) {
      push("error", "[orchestrator].cross_cutting_artifacts", `Artifact ${artifact} is not relative.`, "Use repository-relative artifact paths only.");
    }
  }
  if (input.tasks.length === 0) {
    push("error", "[[tasks]]", "At least one task is required.", "Add an executor task or paste a plan containing tasks.");
  }

  const profileIds = new Set<string>();
  const referencedProfiles = new Set(
    input.tasks
      .filter((task) => task.agentType === "Executor")
      .flatMap((task) => splitList(task.profiles))
      .filter(Boolean),
  );
	  for (const profile of input.toolProfiles) {
    const profileId = profile.id.trim();
    if (!profileId) {
      push("error", "[profiles]", "Every tool profile needs an id.", "Open Tool profiles and enter a stable profile id.");
    } else if (!/^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(profileId)) {
      push("error", `[profiles.${profileId}]`, `Tool profile ${profileId} is invalid.`, "Start with a letter and use only letters, digits, underscores, or dashes.");
    }
    if (profileIds.has(profileId)) {
      push("error", `[profiles.${profileId}]`, `Duplicate tool profile ${profileId}.`, "Rename or remove one of the duplicate profiles.");
    }
    profileIds.add(profileId);
    if (!referencedProfiles.has(profileId)) {
      push("warning", `[profiles.${profileId}]`, `Tool profile ${profileId || "(blank)"} is not used by any executor.`, "Select it on an executor card or remove it from the plan.");
    }
    if (!profile.description.trim()) {
      push("warning", `[profiles.${profileId}].description`, `Tool profile ${profileId || "(blank)"} has no description.`, "Describe the kind of tasks this profile supports.");
    }
    if (profile.tools.length === 0) {
      push("warning", `[profiles.${profileId}.custom_tool]`, `Tool profile ${profileId || "(blank)"} has no tools.`, "Add at least one custom tool or remove the empty profile.");
    }
    const toolNames = new Set<string>();
    for (const tool of profile.tools) {
      const toolName = tool.name.trim();
      if (!toolName) {
        push("error", `[profiles.${profileId}.custom_tool].name`, `A tool in ${profileId || "(blank)"} needs a name.`, "Use a stable operation name such as repo_symbol_search.");
      } else if (!/^[a-z][a-z0-9_]{0,47}$/.test(toolName)) {
        push("error", `[profiles.${profileId}.custom_tool.${toolName}]`, `Tool ${toolName} is invalid.`, "Use lowercase snake_case, starting with a letter, up to 48 characters.");
      }
      if (toolNames.has(toolName)) {
        push("error", `[profiles.${profileId}.custom_tool.${toolName}]`, `Duplicate tool ${toolName} in ${profileId}.`, "Each operation in a profile must have a unique name.");
      }
      toolNames.add(toolName);
      if (!tool.description.trim()) {
        push("error", `[profiles.${profileId}.custom_tool.${toolName}].description`, `Tool ${toolName || "(blank)"} needs a description.`, "Describe when the agent should use the tool.");
      }
      const command = splitCommand(tool.command);
      if (command.length === 0) {
        push("error", `[profiles.${profileId}.custom_tool.${toolName}].command`, `Tool ${toolName || "(blank)"} needs a command.`, "Add the executable and arguments, one per line.");
      } else if (!command[0].startsWith("/")) {
        push("error", `[profiles.${profileId}.custom_tool.${toolName}].command`, `Tool ${toolName || "(blank)"} command must start with an absolute path.`, "Use an absolute executable path such as /usr/bin/rg.");
      }
      if (!toolLocalities.includes(tool.locality)) {
        push("error", `[profiles.${profileId}.custom_tool.${toolName}].execution_locality`, `Tool ${toolName || "(blank)"} has an unsupported locality.`, "Choose guest_subprocess, host_subprocess, host_mcp, or remote_mcp.");
      }
      if (tool.schemaJson.trim() && !parseSchemaJson(tool.schemaJson)) {
        push("warning", `[profiles.${profileId}.custom_tool.${toolName}].schema`, `Tool ${toolName || "(blank)"} Tool Schema is not valid JSON.`, "Use full JSON Schema or shorthand such as { \"query\": \"string\" }. Leave it blank for an empty object input.");
      }
      for (const [field, raw] of [
        ["timeout_seconds", tool.timeoutSeconds],
        ["stdin_max_bytes", tool.stdinMaxBytes],
        ["stdout_max_bytes", tool.stdoutMaxBytes],
        ["stderr_max_bytes", tool.stderrMaxBytes],
      ] as const) {
        if (raw.trim() && !/^[1-9][0-9]*$/.test(raw.trim())) {
          push("error", `[profiles.${profileId}.custom_tool.${toolName}].${field}`, `${field} must be a positive integer.`, "Replace it with a whole number greater than zero.");
        }
      }
	    }
	  }

  const setupNames = new Set<string>();
  const referencedCredentials = new Set(
    input.tasks
      .filter((task) => task.agentType === "Executor")
      .flatMap((task) => task.credentials.map((credential) => credential.name.trim()))
      .filter(Boolean),
  );
  for (const credential of input.credentialSetups) {
    const name = credential.name.trim();
    if (!name) {
      push("error", "[credentials]", "Every credential setup needs a name.", "Open Credential setup and enter the kernel credential name.");
    } else if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(name)) {
      push("error", `[credentials.${name}]`, `Credential name ${name} is invalid.`, "Use letters, digits, dots, underscores, or dashes.");
    }
    if (setupNames.has(name)) {
      push("error", `[credentials.${name}]`, `Duplicate credential setup ${name}.`, "Rename or remove one duplicate credential setup.");
    }
    setupNames.add(name);
    if (!referencedCredentials.has(name)) {
      push("warning", `[credentials.${name}]`, `Credential setup ${name || "(blank)"} is not bound to any executor.`, "Attach it from an executor card or remove it from the setup pane.");
    }
    validateCredentialDraft(credential, `[credentials.${name || "blank"}]`, push);
  }

  const ids = new Set<string>();
  for (const task of input.tasks) {
    const id = task.id.trim();
    if (!id) {
      push("error", "[[tasks]].task_id", "Every task needs a task id.", "Open the task card and enter a stable id.");
    } else if (!/^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(id)) {
      push("error", `${id}.task_id`, `Task id ${id} is invalid.`, "Start with a letter and use only letters, digits, underscores, or dashes.");
    }
    if (ids.has(id)) {
      push("error", `${id}.task_id`, `Duplicate task id ${id}.`, "Rename one of the tasks so every id is unique.");
    }
    ids.add(id);
    if (!task.description.trim()) {
      push("error", `${id}.description`, `Task ${id || "(blank)"} needs a description.`, "Describe what this task is meant to do.");
    }
    if (!task.prompt.trim()) {
      push("error", `${id}.prompt`, `Task ${id || "(blank)"} needs a prompt.`, "Give the agent the precise work instructions.");
    }
    for (const pred of splitList(task.predecessors)) {
      if (!input.tasks.some((candidate) => candidate.id.trim() === pred)) {
        push("error", `${id}.predecessors`, `Task ${id || "(blank)"} references unknown predecessor ${pred}.`, "Drag an edge from an existing task or remove the stale predecessor.");
      }
      if (pred === id) {
        push("error", `${id}.predecessors`, `Task ${id} cannot depend on itself.`, "Remove the self-edge.");
      }
    }
    if (task.agentType === "Executor") {
      if (splitList(task.paths).length === 0) {
        push("error", `${id}.path_allowlist`, `Executor ${id || "(blank)"} needs a path allowlist.`, "Add at least one repository-relative file or directory.");
      }
      const taskProfiles = splitList(task.profiles);
      const selectedProfileIds = new Set<string>();
      for (const profile of taskProfiles) {
        if (selectedProfileIds.has(profile)) {
          push("error", `${id}.profiles`, `Executor ${id || "(blank)"} selects profile ${profile} more than once.`, "Keep each profile only once on a task.");
        }
        selectedProfileIds.add(profile);
        if (!profileIds.has(profile)) {
          push("error", `${id}.profiles`, `Executor ${id || "(blank)"} references missing tool profile ${profile}.`, "Create that profile in Tool profiles or select an existing profile.");
        }
      }
      const mergedTools = new Map<string, { profileId: string; signature: string }>();
      for (const profileId of taskProfiles) {
        const profile = input.toolProfiles.find((candidate) => candidate.id.trim() === profileId);
        if (!profile) continue;
        for (const tool of profile.tools) {
          const toolName = tool.name.trim();
          if (!toolName) continue;
          const signature = toolSignature(tool);
          const first = mergedTools.get(toolName);
          if (first) {
            if (first.signature === signature) {
              push("warning", `${id}.profiles`, `Executor ${id || "(blank)"} gets identical tool ${toolName} from both ${first.profileId} and ${profileId}.`, "This is allowed when intentional; RAXIS will expose one tool and keep the first profile attribution.");
            } else {
              push("error", `${id}.profiles`, `Executor ${id || "(blank)"} gets conflicting tool ${toolName} from both ${first.profileId} and ${profileId}.`, "Rename one operation or make the declarations identical; one tool name cannot mean two different commands.");
            }
          } else {
            mergedTools.set(toolName, { profileId, signature });
          }
        }
      }
      if (mergedTools.size > maxEffectiveCustomToolsPerTask) {
        push(
          "error",
          `${id}.profiles`,
          `Executor ${id || "(blank)"} has ${mergedTools.size} effective tools.`,
          `RAXIS allows at most ${maxEffectiveCustomToolsPerTask} merged custom tools per executor; remove profiles or split the task.`,
        );
      }
      const credentialNames = new Set<string>();
      for (const [index, credential] of task.credentials.entries()) {
        const name = credential.name.trim();
        const proxyType = credential.proxyType.trim();
        const mountAs = credential.mountAs.trim();
        if (!name && !proxyType && !mountAs) continue;
        const field = `${id}.credentials[${index + 1}]`;
        if (!name) {
          push("error", `${field}.name`, `Credential binding ${index + 1} needs a name.`, "Name the credential binding the executor is allowed to use.");
        } else if (credentialNames.has(name)) {
          push("warning", `${field}.name`, `Executor ${id || "(blank)"} binds credential ${name} more than once.`, "This is allowed when intentional, but one binding per credential name is usually clearer.");
        }
        if (name) credentialNames.add(name);
        if (name && input.credentialSetups.length > 0 && !setupNames.has(name)) {
          push("warning", `${field}.name`, `Credential ${name} has no setup template in this builder.`, "This can be intentional; add it in Credential setup if you want it downloaded with the plan materials.");
        }
        validateCredentialDraft(credential, field, push);
      }
    } else {
      if (splitList(task.predecessors).length === 0) {
        push("warning", `${id}.predecessors`, `Reviewer ${id || "(blank)"} has no predecessor.`, "Drag an edge from the executor it should inspect.");
      }
    }
    if (task.verifierName.trim() && !task.verifierGateType.trim()) {
      push("error", `${id}.verifiers.gate_type`, `Verifier ${task.verifierName} needs a gate type.`, "Set the mechanical witness type this verifier produces.");
    }
    for (const [field, raw] of [
      ["max_turns", task.maxTurns],
      ["max_turns_step", task.maxTurnsStep],
      ["cumulative_max_seconds", task.cumulativeMaxSeconds],
    ] as const) {
      if (raw.trim() && !/^[1-9][0-9]*$/.test(raw.trim())) {
        push("error", `${id}.${field}`, `${field} must be a positive integer.`, "Replace it with a whole number greater than zero.");
      }
    }
  }
  return issues;
}

function validateCredentialDraft(
  credential: CredentialDraft,
  field: string,
  push: (
    severity: LocalIssue["severity"],
    field: string,
    message: string,
    next: string,
  ) => void,
) {
  const name = credential.name.trim();
  const proxyType = credential.proxyType.trim();
  const mountAs = credential.mountAs.trim();
  const label = name || "credential";
  if (!proxyType) {
    push("error", `${field}.proxy_type`, `Credential ${label} needs a proxy type.`, "Choose postgres, mysql, mssql, mongodb, redis, smtp, http, aws, gcp, azure, or k8s.");
  } else if (!credentialProxyTypes.includes(proxyType as CredentialProxyType)) {
    push("error", `${field}.proxy_type`, `Credential ${label} uses unsupported proxy type ${proxyType}.`, "Choose one of the supported credential proxy types.");
  }
  if (!mountAs) {
    push("error", `${field}.mount_as`, `Credential ${label} needs a mount env.`, "Set the environment variable that will receive the kernel proxy URL.");
  } else if (!/^[A-Z_][A-Z0-9_]{0,63}$/.test(mountAs)) {
    push("warning", `${field}.mount_as`, `Mount env ${mountAs} is unusual.`, "Use an uppercase environment variable name such as DATABASE_URL.");
  }
  if (credential.proxyType === "http" && !credential.upstreamUrl.trim()) {
    push("error", `${field}.upstream_url`, `HTTP credential ${label} needs an upstream URL.`, "Set the pinned upstream URL the proxy may forward to.");
  }
  if (
    (credential.proxyType === "redis" || credential.proxyType === "smtp") &&
    !credential.upstreamHostPort.trim()
  ) {
    push("error", `${field}.upstream_host_port`, `Credential ${label} needs an upstream host:port.`, "Set the single upstream service endpoint the proxy may reach.");
  }
  if (credential.proxyType === "gcp" && !credential.project.trim()) {
    push("error", `${field}.project`, `GCP credential ${label} needs a project id.`, "Set the project id returned by the metadata proxy.");
  }
  if (credential.proxyType === "azure" && !credential.tenantId.trim()) {
    push("error", `${field}.tenant_id`, `Azure credential ${label} needs a tenant id.`, "Set the tenant id used by the IMDS-compatible proxy.");
  }
}

function renderPlan(input: {
  plan: PlanBasics;
  tasks: TaskDraft[];
  toolProfiles: ToolProfileDraft[];
}) {
  const lines: string[] = [
    "[plan.initiative]",
    `description = ${tomlString(input.plan.initiative.trim())}`,
    "",
    "[workspace]",
    `name       = ${tomlString(input.plan.workspace.trim())}`,
    `lane_id    = ${tomlString(input.plan.lane.trim())}`,
    `target_ref = ${tomlString(input.plan.targetRef.trim())}`,
    `repository = ${tomlString(input.plan.repository.trim())}`,
    "",
  ];

  const artifacts = splitList(input.plan.crossCuttingArtifacts);
  if (artifacts.length > 0) {
    lines.push("[orchestrator]");
    lines.push(`cross_cutting_artifacts = [${artifacts.map(tomlString).join(", ")}]`);
    lines.push("");
  }

  for (const profile of input.toolProfiles) {
    if (!profile.id.trim()) continue;
    lines.push(`[profiles.${tomlKey(profile.id.trim())}]`);
    lines.push('inherits_from = "Executor"');
    lines.push(`description = ${tomlString(profile.description.trim() || `Tool profile for ${profile.id.trim()}`)}`);
    lines.push("");
    for (const tool of profile.tools) {
      if (!tool.name.trim()) continue;
      lines.push(`[[profiles.${tomlKey(profile.id.trim())}.custom_tool]]`);
      lines.push(`name               = ${tomlString(tool.name.trim())}`);
      lines.push(`description        = ${tomlString(tool.description.trim())}`);
      lines.push(`execution_locality = ${tomlString(tool.locality)}`);
      lines.push(`command            = [${splitCommand(tool.command).map(tomlString).join(", ")}]`);
      if (tool.timeoutSeconds.trim()) {
        lines.push(`timeout_seconds    = ${tool.timeoutSeconds.trim()}`);
      }
      if (tool.stdinMaxBytes.trim()) {
        lines.push(`stdin_max_bytes    = ${tool.stdinMaxBytes.trim()}`);
      }
      if (tool.stdoutMaxBytes.trim()) {
        lines.push(`stdout_max_bytes   = ${tool.stdoutMaxBytes.trim()}`);
      }
      if (tool.stderrMaxBytes.trim()) {
        lines.push(`stderr_max_bytes   = ${tool.stderrMaxBytes.trim()}`);
      }
      if (tool.schemaJson.trim()) {
        emitToolSchema(lines, profile.id.trim(), tool.schemaJson);
      }
      lines.push("");
    }
  }

  for (const rawTask of input.tasks) {
    const task = normalizeTask(rawTask);
    const predecessors = splitList(task.predecessors);
    const paths = splitList(task.paths);
    const pathExports = splitList(task.pathExports);
    const allowedEgress = splitList(task.allowedEgress);
    lines.push("[[tasks]]");
    lines.push(`task_id            = ${tomlString(task.id.trim())}`);
    lines.push(`description        = ${tomlString(task.description.trim())}`);
    lines.push(`session_agent_type = ${tomlString(task.agentType)}`);
    lines.push(`clone_strategy     = ${tomlString(task.cloneStrategy)}`);
    const taskProfiles = splitList(task.profiles);
    if (task.agentType === "Executor" && taskProfiles.length > 0) {
      lines.push(`profiles           = [${taskProfiles.map(tomlString).join(", ")}]`);
    }
    if (task.maxTurns.trim()) lines.push(`max_turns          = ${task.maxTurns.trim()}`);
    if (task.maxTurnsStep.trim()) lines.push(`max_turns_step     = ${task.maxTurnsStep.trim()}`);
    if (task.cumulativeMaxSeconds.trim()) {
      lines.push(`cumulative_max_seconds = ${task.cumulativeMaxSeconds.trim()}`);
    }
    if (task.agentType === "Executor" && task.vmImage.trim()) {
      lines.push(`vm_image           = ${tomlString(task.vmImage.trim())}`);
    }
    if (paths.length > 0) {
      lines.push(`path_allowlist     = [${paths.map(tomlString).join(", ")}]`);
    }
    if (pathExports.length > 0) {
      lines.push(`path_export_globs  = [${pathExports.map(tomlString).join(", ")}]`);
    }
    if (task.agentType === "Executor" && allowedEgress.length > 0) {
      lines.push(`allowed_egress     = [${allowedEgress.map(tomlString).join(", ")}]`);
    }
    lines.push(`predecessors       = [${predecessors.map(tomlString).join(", ")}]`);
    lines.push('prompt             = """');
    lines.push(task.prompt.trimEnd());
    lines.push('"""');
    if (task.agentType === "Executor") {
      for (const credential of task.credentials) {
        if (!credential.name.trim()) continue;
        lines.push("");
        lines.push("[[tasks.credentials]]");
        emitCredentialPlanBlock(lines, credential);
      }
    }
    if (task.verifierName.trim()) {
      lines.push("");
      lines.push("[[tasks.verifiers]]");
      lines.push(`name      = ${tomlString(task.verifierName.trim())}`);
      lines.push(`gate_type = ${tomlString(task.verifierGateType.trim() || "TestPass")}`);
      if (task.verifierCommand.trim()) {
        lines.push(`command   = ${tomlString(task.verifierCommand.trim())}`);
      }
      lines.push(`gate_on   = ${tomlString(task.verifierGateOn.trim() || "Pass")}`);
    }
    lines.push("");
  }
  return lines.join("\n");
}

function renderCredentialSetupToml(credentials: CredentialSetupDraft[]) {
  const lines: string[] = [
    "# RAXIS credential setup template.",
    "# This file contains names, plan binding shape, and expected secret formats.",
    "# Do not commit real credential values. Seed secret bytes into",
    "# $RAXIS_DATA_DIR/credentials/<name>.env with mode 0600.",
    "",
  ];
  if (credentials.length === 0) {
    lines.push("# No credentials configured yet.");
    return lines.join("\n");
  }
  for (const credential of credentials) {
    const name = credential.name.trim() || "credential-name";
    lines.push("[[permitted_credentials]]");
    lines.push(`name = ${tomlString(name)}`);
    if (credential.environment.trim()) {
      lines.push(`environment = ${tomlString(credential.environment.trim())}`);
    }
    if (credential.description.trim()) {
      lines.push(`description = ${tomlString(credential.description.trim())}`);
    }
    lines.push("");
    lines.push("[[credential_files]]");
    lines.push(`name = ${tomlString(name)}`);
    lines.push(`path = ${tomlString(`$RAXIS_DATA_DIR/credentials/${name}.env`)}`);
    lines.push(`expected_shape = ${tomlString(credential.expectedShape.trim() || defaultCredentialShape(credential.proxyType))}`);
    lines.push("");
    lines.push("# Attach this block inside the executor [[tasks]] entry that may use it:");
    lines.push("[[tasks.credentials]]");
    emitCredentialPlanBlock(lines, credential);
    lines.push("");
  }
  return lines.join("\n");
}

function emitCredentialPlanBlock(lines: string[], credential: CredentialDraft) {
  lines.push(`name       = ${tomlString(credential.name.trim())}`);
  lines.push(`mount_as   = ${tomlString(credential.mountAs.trim() || defaultMountAs(credential.proxyType))}`);
  lines.push(`proxy_type = ${tomlString(credential.proxyType)}`);
  if (credential.proxyType === "http") {
    lines.push(`upstream_url = ${tomlString(credential.upstreamUrl.trim())}`);
    lines.push(`auth_mode    = ${tomlString(credential.authMode.trim() || "bearer")}`);
  }
  if (credential.proxyType === "redis" || credential.proxyType === "smtp") {
    lines.push(`upstream_host_port = ${tomlString(credential.upstreamHostPort.trim())}`);
  }
  if (credential.proxyType === "gcp") {
    lines.push(`project = ${tomlString(credential.project.trim())}`);
  }
  if (credential.proxyType === "azure") {
    lines.push(`tenant_id = ${tomlString(credential.tenantId.trim())}`);
    if (credential.clientId.trim()) {
      lines.push(`client_id = ${tomlString(credential.clientId.trim())}`);
    }
  }
  if (credential.proxyType === "aws" && credential.roleArn.trim()) {
    lines.push(`role_arn = ${tomlString(credential.roleArn.trim())}`);
  }
}

function emitToolSchema(lines: string[], profile: string, schemaJson: string) {
  const prefix = `profiles.${tomlKey(profile)}.custom_tool.schema`;
  const parsed = parseSchemaJson(schemaJson);
  lines.push(`[${prefix}]`);
  if (!parsed || (Object.keys(parsed).length === 0 && parsed.constructor === Object)) {
    lines.push('type = "object"');
    lines.push("additionalProperties = true");
    return;
  }
  if (typeof parsed.type === "string") lines.push(`type = ${tomlString(parsed.type)}`);
  else lines.push('type = "object"');
  if (Array.isArray(parsed.required)) {
    lines.push(`required = [${parsed.required.filter(isString).map(tomlString).join(", ")}]`);
  }
  if (typeof parsed.additionalProperties === "boolean") {
    lines.push(`additionalProperties = ${String(parsed.additionalProperties)}`);
  }
  const properties =
    isRecord(parsed.properties) ? parsed.properties : schemaShorthandToProperties(parsed);
  for (const [name, rawProperty] of Object.entries(properties)) {
    if (!isRecord(rawProperty)) continue;
    lines.push("");
    lines.push(`[${prefix}.properties.${tomlKey(name)}]`);
    if (typeof rawProperty.type === "string") {
      lines.push(`type = ${tomlString(rawProperty.type)}`);
    }
    if (typeof rawProperty.description === "string") {
      lines.push(`description = ${tomlString(rawProperty.description)}`);
    }
    if (typeof rawProperty.default === "string") {
      lines.push(`default = ${tomlString(rawProperty.default)}`);
    } else if (typeof rawProperty.default === "number" || typeof rawProperty.default === "boolean") {
      lines.push(`default = ${String(rawProperty.default)}`);
    }
  }
}

function parsePlanToml(text: string): {
  plan: PlanBasics;
  tasks: TaskDraft[];
  toolProfiles: ToolProfileDraft[];
} {
  const plan: PlanBasics = {
    initiative:
      readSectionString(text, "plan.initiative", "description") ??
      readString(text, "title") ??
      "",
    workspace: readSectionString(text, "workspace", "name") ?? "",
    lane: readSectionString(text, "workspace", "lane_id") ?? "",
    targetRef: readSectionString(text, "workspace", "target_ref") ?? "",
    repository: readSectionString(text, "workspace", "repository") ?? "",
    crossCuttingArtifacts: readArrayFromSection(text, "orchestrator", "cross_cutting_artifacts").join(", "),
  };

  const toolProfiles = parseProfileTools(text);
  const taskBlocks = text
    .split(/^\[\[tasks\]\]\s*$/m)
    .slice(1)
    .map((block) => block.trim())
    .filter(Boolean);

  const tasks = taskBlocks.map((block, index) => {
    const agentType = readString(block, "session_agent_type") === "Reviewer" ? "Reviewer" : "Executor";
    const profiles = readArray(block, "profiles").join(", ");
    const credentials = readNestedBlocks(block, "tasks.credentials").map((credential) => {
      const proxyType =
        ((readString(credential, "proxy_type") ??
          readString(credential, "kind") ??
          "postgres") as CredentialProxyType);
      return {
        ...makeCredentialDraft({
          name: readString(credential, "name") ?? "",
          proxyType,
          mountAs:
            readString(credential, "mount_as") ??
            readString(credential, "path") ??
            defaultMountAs(proxyType),
        }),
        upstreamUrl: readString(credential, "upstream_url") ?? "",
        upstreamHostPort: readString(credential, "upstream_host_port") ?? "",
        authMode: readString(credential, "auth_mode") ?? "bearer",
        project: readString(credential, "project") ?? "",
        tenantId: readString(credential, "tenant_id") ?? "",
        roleArn: readString(credential, "role_arn") ?? "",
        clientId: readString(credential, "client_id") ?? "",
      };
    });
    const verifier = readNestedBlock(block, "tasks.verifiers");
    return normalizeTask({
      id: readString(block, "task_id") ?? `task-${index + 1}`,
      description: readString(block, "description") ?? "",
      agentType,
      predecessors: readArray(block, "predecessors").join(", "),
      paths: readArray(block, "path_allowlist").join(", "),
      pathExports: readArray(block, "path_export_globs").join(", "),
      allowedEgress: readArray(block, "allowed_egress").join(", "),
      cloneStrategy: (readString(block, "clone_strategy") as CloneStrategy | null) ?? "blobless",
      maxTurns: readNumber(block, "max_turns") ?? "",
      maxTurnsStep: readNumber(block, "max_turns_step") ?? "",
      cumulativeMaxSeconds: readNumber(block, "cumulative_max_seconds") ?? "",
      vmImage: readString(block, "vm_image") ?? "",
      profiles,
      verifierName: verifier ? readString(verifier, "name") ?? "" : "",
      verifierGateType: verifier ? readString(verifier, "gate_type") ?? "TestPass" : "TestPass",
      verifierCommand: verifier ? readString(verifier, "command") ?? "" : "",
      verifierGateOn: verifier ? readString(verifier, "gate_on") ?? "Pass" : "Pass",
      credentials,
      prompt: readTriple(block, "prompt") ?? readString(block, "prompt") ?? "",
    });
  });

  if (!text.includes("[[tasks]]")) {
    return { plan, tasks: [], toolProfiles };
  }
  return { plan, tasks, toolProfiles };
}

function parseProfileTools(text: string) {
  const profiles = new Map<string, ToolProfileDraft>();
  const profileRe = /^\[profiles\.(?:"([^"]+)"|([A-Za-z0-9_-]+))\]\s*$/gm;
  let profileMatch: RegExpExecArray | null;
  while ((profileMatch = profileRe.exec(text)) !== null) {
    const id = profileMatch[1] ?? profileMatch[2] ?? "";
    const start = profileMatch.index + profileMatch[0].length;
    const nextMatch = text.slice(start).search(/^\[\[?profiles\.|^\[\[tasks\]\]|^\[[A-Za-z]/m);
    const block = nextMatch >= 0 ? text.slice(start, start + nextMatch) : text.slice(start);
    profiles.set(id, {
      id,
      description: readString(block, "description") ?? "",
      tools: [],
    });
  }

  const re = /^\[\[profiles\.(?:"([^"]+)"|([A-Za-z0-9_-]+))\.custom_tool\]\]\s*$/gm;
  let match: RegExpExecArray | null;
  while ((match = re.exec(text)) !== null) {
    const profileId = match[1] ?? match[2] ?? "";
    const start = match.index + match[0].length;
    const nextMatch = text.slice(start).search(/^\[\[?profiles\.|^\[\[tasks\]\]|^\[[A-Za-z]/m);
    const block = nextMatch >= 0 ? text.slice(start, start + nextMatch) : text.slice(start);
    const existing = profiles.get(profileId) ?? {
      id: profileId,
      description: "",
      tools: [],
    };
    existing.tools.push({
      name: readString(block, "name") ?? "",
      description: readString(block, "description") ?? "",
      locality: (readString(block, "execution_locality") as ToolLocality | null) ?? "guest_subprocess",
      command: readArray(block, "command").join("\n"),
      timeoutSeconds: readNumber(block, "timeout_seconds") ?? "30",
      stdinMaxBytes: readNumber(block, "stdin_max_bytes") ?? "4096",
      stdoutMaxBytes: readNumber(block, "stdout_max_bytes") ?? "65536",
      stderrMaxBytes: readNumber(block, "stderr_max_bytes") ?? "8192",
      schemaJson: readString(block, "schema_json") ?? "",
    });
    profiles.set(profileId, existing);
  }
  return [...profiles.values()];
}

function readSection(text: string, section: string) {
  const escaped = section.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const re = new RegExp(`^\\[${escaped}\\]\\s*$`, "m");
  const match = re.exec(text);
  if (!match) return null;
  const start = match.index + match[0].length;
  const next = text.slice(start).search(/^\[[^\]]+\]\s*$/m);
  return next >= 0 ? text.slice(start, start + next) : text.slice(start);
}

function readSectionString(text: string, section: string, key: string) {
  const block = readSection(text, section);
  return block ? readString(block, key) : null;
}

function readArrayFromSection(text: string, section: string, key: string) {
  const block = readSection(text, section);
  return block ? readArray(block, key) : [];
}

function readNestedBlock(text: string, table: string) {
  return readNestedBlocks(text, table)[0] ?? null;
}

function readNestedBlocks(text: string, table: string) {
  const escaped = table.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const re = new RegExp(`^\\[\\[${escaped}\\]\\]\\s*$`, "gm");
  const blocks: string[] = [];
  let match: RegExpExecArray | null;
  while ((match = re.exec(text)) !== null) {
    const start = match.index + match[0].length;
    const next = text.slice(start).search(/^\[\[[^\]]+\]\]\s*$/m);
    blocks.push(next >= 0 ? text.slice(start, start + next) : text.slice(start));
  }
  return blocks;
}

function readString(text: string, key: string) {
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = new RegExp(`^\\s*${escaped}\\s*=\\s*"((?:\\\\.|[^"])*)"`, "m").exec(text);
  return match ? unescapeToml(match[1]) : null;
}

function readTriple(text: string, key: string) {
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = new RegExp(`^\\s*${escaped}\\s*=\\s*"""\\n?([\\s\\S]*?)\\n?"""`, "m").exec(text);
  return match ? match[1] : null;
}

function readNumber(text: string, key: string) {
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = new RegExp(`^\\s*${escaped}\\s*=\\s*([0-9]+)\\s*$`, "m").exec(text);
  return match?.[1] ?? "";
}

function readArray(text: string, key: string) {
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = new RegExp(`^\\s*${escaped}\\s*=\\s*\\[([\\s\\S]*?)\\]`, "m").exec(text);
  if (!match) return [];
  const values: string[] = [];
  const itemRe = /"((?:\\.|[^"])*)"/g;
  let item: RegExpExecArray | null;
  while ((item = itemRe.exec(match[1])) !== null) {
    values.push(unescapeToml(item[1]));
  }
  return values;
}

function splitList(raw: string) {
  return raw
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
}

export function defaultMountAs(proxyType: CredentialProxyType) {
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

function defaultCredentialShape(proxyType: CredentialProxyType) {
  switch (proxyType) {
    case "postgres":
      return "postgresql://USER:PASSWORD@HOST:5432/DATABASE";
    case "mysql":
      return "mysql://USER:PASSWORD@HOST:3306/DATABASE";
    case "mssql":
      return "sqlserver://USER:PASSWORD@HOST:1433/DATABASE";
    case "mongodb":
      return "mongodb://USER:PASSWORD@HOST:27017/DATABASE";
    case "redis":
      return "redis://:PASSWORD@HOST:6379/0";
    case "smtp":
      return "smtp://USER:PASSWORD@HOST:587";
    case "http":
      return "bearer token or basic auth material for the pinned upstream_url";
    case "aws":
      return "AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY material for backend resolution";
    case "gcp":
      return "GCP service account JSON or backend-specific secret reference";
    case "azure":
      return "Azure client secret or backend-specific managed identity reference";
    case "k8s":
      return "kubeconfig or bearer token material for the Kubernetes API";
    default:
      return "backend-specific credential material";
  }
}

function splitCommand(raw: string) {
  return raw
    .split(/\r?\n/)
    .map((value) => value.trim())
    .filter(Boolean);
}

function toolSignature(tool: ToolDraft) {
  return JSON.stringify({
    name: tool.name.trim(),
    description: tool.description.trim(),
    locality: tool.locality,
    command: splitCommand(tool.command),
    timeoutSeconds: tool.timeoutSeconds.trim() || "60",
    stdinMaxBytes: tool.stdinMaxBytes.trim() || "262144",
    stdoutMaxBytes: tool.stdoutMaxBytes.trim() || "65536",
    stderrMaxBytes: tool.stderrMaxBytes.trim() || "16384",
    schema: parseSchemaJson(tool.schemaJson.trim()) ?? {},
  });
}

function slugify(value: string) {
  const slug = value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return /^[a-z]/.test(slug) ? slug : `task-${slug || "1"}`;
}

function slugifyToolName(value: string) {
  const slug = value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 48);
  return /^[a-z]/.test(slug) ? slug : `tool_${slug || "1"}`;
}

function tomlString(value: string) {
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function tomlKey(value: string) {
  return /^[A-Za-z0-9_-]+$/.test(value) ? value : tomlString(value);
}

function unescapeToml(value: string) {
  return value.replace(/\\"/g, '"').replace(/\\\\/g, "\\");
}

function parseSchemaJson(raw: string): Record<string, unknown> | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  try {
    const parsed = JSON.parse(trimmed) as unknown;
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function schemaShorthandToProperties(raw: Record<string, unknown>) {
  const properties: Record<string, Record<string, unknown>> = {};
  for (const [key, value] of Object.entries(raw)) {
    if (["type", "required", "additionalProperties", "properties"].includes(key)) continue;
    if (typeof value === "string") properties[key] = { type: value };
    else if (isRecord(value)) properties[key] = value;
  }
  return properties;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isString(value: unknown): value is string {
  return typeof value === "string";
}

function downloadText(filename: string, text: string) {
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
}
