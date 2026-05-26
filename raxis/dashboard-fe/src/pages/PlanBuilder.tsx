import { useMemo, useState } from "react";

import { CopyButton } from "@/components/CopyButton";

type AgentType = "Executor" | "Reviewer";

interface TaskDraft {
  id: string;
  description: string;
  agentType: AgentType;
  predecessors: string;
  paths: string;
  prompt: string;
}

const starterTasks: TaskDraft[] = [
  {
    id: "greeter",
    description: "Create HELLO.md and commit it",
    agentType: "Executor",
    predecessors: "",
    paths: "HELLO.md",
    prompt:
      "Write HELLO.md at the repository root with the exact text: hello from alex. Stage and commit it as a single commit with the message: add HELLO.md. Do not modify any other file.",
  },
];

export function PlanBuilderPage() {
  const [initiative, setInitiative] = useState("Create a HELLO.md greeting file.");
  const [workspace, setWorkspace] = useState("Hello world");
  const [lane, setLane] = useState("default");
  const [targetRef, setTargetRef] = useState("refs/heads/main");
  const [repository, setRepository] = useState("main");
  const [tasks, setTasks] = useState<TaskDraft[]>(starterTasks);

  const validation = useMemo(
    () => validatePlan({ initiative, workspace, lane, targetRef, repository, tasks }),
    [initiative, workspace, lane, targetRef, repository, tasks],
  );
  const toml = useMemo(
    () => renderPlan({ initiative, workspace, lane, targetRef, repository, tasks }),
    [initiative, workspace, lane, targetRef, repository, tasks],
  );

  const updateTask = (index: number, patch: Partial<TaskDraft>) => {
    setTasks((prev) => prev.map((task, i) => (i === index ? { ...task, ...patch } : task)));
  };
  const addTask = (agentType: AgentType) => {
    const suffix = tasks.length + 1;
    setTasks((prev) => [
      ...prev,
      {
        id: agentType === "Reviewer" ? `review-${suffix}` : `task-${suffix}`,
        description: agentType === "Reviewer" ? "Review predecessor output" : "Implement task",
        agentType,
        predecessors: prev.at(-1)?.id ?? "",
        paths: agentType === "Reviewer" ? "" : "./",
        prompt:
          agentType === "Reviewer"
            ? "Review the predecessor commit for correctness, safety, and scope. Submit Approve or Reject with concise evidence."
            : "Describe the exact change, verification command, commit message, and files that must remain untouched.",
      },
    ]);
  };
  const removeTask = (index: number) => {
    setTasks((prev) => prev.filter((_, i) => i !== index));
  };

  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-ink">Plan Builder</h1>
          <p className="text-sm text-ink-muted">
            Draft a kernel-valid plan.toml before submitting it from the CLI.
          </p>
        </div>
        <CopyButton value={toml} label="Copy TOML" />
      </header>

      <section className="grid grid-cols-[520px_1fr] gap-4">
        <div className="card p-4 space-y-4">
          <SectionTitle title="Initiative" />
          <Field label="Description">
            <textarea
              value={initiative}
              onChange={(e) => setInitiative(e.target.value)}
              rows={3}
              className="input w-full min-h-[88px]"
            />
          </Field>
          <div className="grid grid-cols-2 gap-3">
            <Field label="Workspace">
              <input
                value={workspace}
                onChange={(e) => setWorkspace(e.target.value)}
                className="input w-full"
              />
            </Field>
            <Field label="Repository">
              <input
                value={repository}
                onChange={(e) => setRepository(e.target.value)}
                className="input w-full font-mono"
              />
            </Field>
            <Field label="Lane">
              <input
                value={lane}
                onChange={(e) => setLane(e.target.value)}
                className="input w-full font-mono"
              />
            </Field>
            <Field label="Target ref">
              <input
                value={targetRef}
                onChange={(e) => setTargetRef(e.target.value)}
                className="input w-full font-mono"
              />
            </Field>
          </div>
          <div className="border-t border-edge pt-4">
            <SectionTitle title="Validation" />
            <ul className="mt-3 space-y-2 text-xs">
              {validation.map((item) => (
                <li
                  key={item}
                  className="rounded border border-edge bg-panel px-2.5 py-2 text-ink-muted"
                >
                  {item}
                </li>
              ))}
            </ul>
          </div>
        </div>

        <div className="card p-4 min-w-0">
          <div className="flex items-center justify-between gap-3">
            <SectionTitle title="Generated TOML" />
            <CopyButton value={toml} label="Copy" />
          </div>
          <pre className="mt-3 max-h-[42rem] overflow-auto rounded-md border border-edge bg-panel p-3 text-xs leading-relaxed text-ink">
            <code>{toml}</code>
          </pre>
        </div>
      </section>

      <section className="card p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <SectionTitle title="Tasks" />
          <div className="flex gap-2">
            <button type="button" className="btn" onClick={() => addTask("Executor")}>
              Add executor
            </button>
            <button type="button" className="btn" onClick={() => addTask("Reviewer")}>
              Add reviewer
            </button>
          </div>
        </div>
        <div className="mt-4 grid grid-cols-2 gap-4">
          {tasks.map((task, index) => (
            <div key={`${task.id}-${index}`} className="rounded-md border border-edge bg-panel p-3">
              <div className="grid grid-cols-[1fr_8rem] gap-3">
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
                    onChange={(e) =>
                      updateTask(index, { agentType: e.target.value as AgentType })
                    }
                    className="input w-full"
                  >
                    <option>Executor</option>
                    <option>Reviewer</option>
                  </select>
                </Field>
              </div>
              <div className="mt-3 grid grid-cols-2 gap-3">
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
              <div className="mt-3">
                <Field label="Path allowlist">
                  <input
                    value={task.paths}
                    onChange={(e) => updateTask(index, { paths: e.target.value })}
                    className="input w-full font-mono"
                    placeholder="src/, README.md"
                  />
                </Field>
              </div>
              <div className="mt-3">
                <Field label="Prompt">
                  <textarea
                    value={task.prompt}
                    onChange={(e) => updateTask(index, { prompt: e.target.value })}
                    rows={5}
                    className="input w-full min-h-[120px]"
                  />
                </Field>
              </div>
              <div className="mt-3 flex justify-end">
                <button
                  type="button"
                  className="btn"
                  onClick={() => removeTask(index)}
                  disabled={tasks.length === 1}
                >
                  Remove
                </button>
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

function SectionTitle({ title }: { title: string }) {
  return <h2 className="text-sm font-semibold text-ink">{title}</h2>;
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block text-xs font-semibold text-ink-subtle">
      <span>{label}</span>
      <span className="mt-1 block">{children}</span>
    </label>
  );
}

function validatePlan(input: {
  initiative: string;
  workspace: string;
  lane: string;
  targetRef: string;
  repository: string;
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
    issues.push("repository must be a path-safe id, for example main or api.");
  }
  const ids = new Set<string>();
  for (const task of input.tasks) {
    const id = task.id.trim();
    if (!id) issues.push("Every task needs task_id.");
    if (ids.has(id)) issues.push(`Duplicate task_id: ${id}.`);
    ids.add(id);
    if (!task.description.trim()) issues.push(`Task ${id || "(blank)"} needs description.`);
    if (!task.prompt.trim()) issues.push(`Task ${id || "(blank)"} needs prompt.`);
    for (const pred of splitList(task.predecessors)) {
      if (!input.tasks.some((candidate) => candidate.id.trim() === pred)) {
        issues.push(`Task ${id || "(blank)"} references unknown predecessor ${pred}.`);
      }
    }
    if (task.agentType === "Executor" && splitList(task.paths).length === 0) {
      issues.push(`Executor task ${id || "(blank)"} needs path_allowlist.`);
    }
  }
  return issues.length === 0 ? ["Ready for raxis plan validate."] : issues;
}

function renderPlan(input: {
  initiative: string;
  workspace: string;
  lane: string;
  targetRef: string;
  repository: string;
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
    `repository = ${tomlString(input.repository.trim() || "main")}`,
    "",
  ];
  for (const task of input.tasks) {
    const predecessors = splitList(task.predecessors);
    const paths = splitList(task.paths);
    lines.push("[[tasks]]");
    lines.push(`task_id            = ${tomlString(task.id.trim())}`);
    lines.push(`description        = ${tomlString(task.description.trim())}`);
    lines.push(`session_agent_type = ${tomlString(task.agentType)}`);
    lines.push('clone_strategy     = "blobless"');
    if (paths.length > 0) lines.push(`path_allowlist     = [${paths.map(tomlString).join(", ")}]`);
    lines.push(`predecessors       = [${predecessors.map(tomlString).join(", ")}]`);
    lines.push('prompt             = """');
    lines.push(task.prompt.trimEnd());
    lines.push('"""');
    lines.push("");
  }
  return lines.join("\n");
}

function splitList(raw: string) {
  return raw
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
}

function tomlString(value: string) {
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}
