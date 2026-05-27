"use client";

import type { ReactNode } from "react";
import { useMemo, useState } from "react";

type AgentType = "Executor" | "Reviewer";

type TaskDraft = {
  id: string;
  title: string;
  agentType: AgentType;
  predecessors: string;
  paths: string;
  prompt: string;
};

const starterTasks: TaskDraft[] = [
  {
    id: "greeter",
    title: "Create greeting file",
    agentType: "Executor",
    predecessors: "",
    paths: "HELLO.md",
    prompt:
      "Write HELLO.md at the repository root with the exact text: hello from alex. Commit it with the message: add HELLO.md. Do not modify any other file.",
  },
];

export default function PlanBuilderPage() {
  const [initiative, setInitiative] = useState("Create a HELLO.md greeting file.");
  const [workspace, setWorkspace] = useState("Hello world");
  const [lane, setLane] = useState("default");
  const [targetRef, setTargetRef] = useState("refs/heads/main");
  const [repository, setRepository] = useState("hello-world");
  const [tasks, setTasks] = useState<TaskDraft[]>(starterTasks);
  const [copied, setCopied] = useState(false);

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
        title: agentType === "Reviewer" ? "Review changes" : "Implement task",
        agentType,
        predecessors: prev.at(-1)?.id ?? "",
        paths: agentType === "Reviewer" ? "" : "./",
        prompt:
          agentType === "Reviewer"
            ? "Review the predecessor's commit for correctness, safety, and scope. Submit Approve or Reject with concise evidence."
            : "Describe the exact code change the executor should make, how to verify it, and what not to touch.",
      },
    ]);
  };
  const removeTask = (index: number) => {
    setTasks((prev) => prev.filter((_, i) => i !== index));
  };
  const copyToml = async () => {
    await navigator.clipboard.writeText(toml);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1600);
  };

  return (
    <div className="mx-auto max-w-6xl px-4 py-12 sm:px-6 sm:py-16">
      <div className="grid gap-8 lg:grid-cols-[0.9fr_1.1fr] lg:items-start">
        <section>
          <p className="eyebrow">Plan builder</p>
          <h1 className="h-section mt-4">Sketch the work. Generate the plan.</h1>
          <p className="mt-5 max-w-2xl leading-relaxed text-[var(--muted)]">
            Use this as the safe front door for `plan.toml`: define the
            initiative, managed repository, tasks, prompts, dependencies, and
            write scopes. The builder checks the common mistakes before you
            copy the TOML into `raxis plan validate`.
          </p>

          <div className="mt-8 space-y-5">
            <LabeledInput label="Initiative description">
              <textarea
                value={initiative}
                onChange={(e) => setInitiative(e.target.value)}
                rows={3}
                className="field min-h-24"
              />
            </LabeledInput>
            <div className="grid gap-4 sm:grid-cols-2">
              <LabeledInput label="Workspace name">
                <input
                  value={workspace}
                  onChange={(e) => setWorkspace(e.target.value)}
                  className="field"
                />
              </LabeledInput>
              <LabeledInput label="Managed repository">
                <input
                  value={repository}
                  onChange={(e) => setRepository(e.target.value)}
                  className="field"
                />
                <span className="mt-1 block text-xs font-normal leading-relaxed text-[var(--muted)]">
                  Use the actual repository name. Keep branch names in target ref.
                </span>
              </LabeledInput>
              <LabeledInput label="Lane">
                <input value={lane} onChange={(e) => setLane(e.target.value)} className="field" />
              </LabeledInput>
              <LabeledInput label="Target ref">
                <input
                  value={targetRef}
                  onChange={(e) => setTargetRef(e.target.value)}
                  className="field font-mono"
                />
              </LabeledInput>
            </div>
          </div>
        </section>

        <section className="rounded-lg border border-[var(--rule)] bg-[var(--surface)] p-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 className="text-lg font-semibold text-[var(--fg)]">Task canvas</h2>
              <p className="mt-1 text-sm text-[var(--muted)]">
                Executors edit. Reviewers judge. The Orchestrator is created by the kernel.
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              <button type="button" className="btn btn-ghost" onClick={() => addTask("Executor")}>
                Add executor
              </button>
              <button type="button" className="btn btn-ghost" onClick={() => addTask("Reviewer")}>
                Add reviewer
              </button>
            </div>
          </div>
          <div className="mt-5 space-y-4">
            {tasks.map((task, index) => (
              <div key={`${task.id}-${index}`} className="rounded-lg border border-[var(--rule)] bg-[var(--bg)] p-4">
                <div className="grid gap-3 sm:grid-cols-[1fr_10rem]">
                  <LabeledInput label="Task id">
                    <input
                      value={task.id}
                      onChange={(e) => updateTask(index, { id: e.target.value })}
                      className="field font-mono"
                    />
                  </LabeledInput>
                  <LabeledInput label="Role">
                    <select
                      value={task.agentType}
                      onChange={(e) => updateTask(index, { agentType: e.target.value as AgentType })}
                      className="field"
                    >
                      <option>Executor</option>
                      <option>Reviewer</option>
                    </select>
                  </LabeledInput>
                </div>
                <div className="mt-3 grid gap-3 sm:grid-cols-2">
                  <LabeledInput label="Description">
                    <input
                      value={task.title}
                      onChange={(e) => updateTask(index, { title: e.target.value })}
                      className="field"
                    />
                  </LabeledInput>
                  <LabeledInput label="Predecessors">
                    <input
                      value={task.predecessors}
                      onChange={(e) => updateTask(index, { predecessors: e.target.value })}
                      className="field font-mono"
                      placeholder="task-a, task-b"
                    />
                  </LabeledInput>
                </div>
                <div className="mt-3">
                  <LabeledInput label="Path allowlist">
                    <input
                      value={task.paths}
                      onChange={(e) => updateTask(index, { paths: e.target.value })}
                      className="field font-mono"
                      placeholder="src/, README.md"
                    />
                  </LabeledInput>
                </div>
                <div className="mt-3">
                  <LabeledInput label="Prompt">
                    <textarea
                      value={task.prompt}
                      onChange={(e) => updateTask(index, { prompt: e.target.value })}
                      rows={4}
                      className="field min-h-28"
                    />
                  </LabeledInput>
                </div>
                <div className="mt-3 flex justify-end">
                  <button
                    type="button"
                    className="text-sm font-semibold text-[var(--muted)] hover:text-[var(--fg)]"
                    onClick={() => removeTask(index)}
                  >
                    Remove
                  </button>
                </div>
              </div>
            ))}
          </div>
        </section>
      </div>

      <section className="mt-8 grid gap-6 lg:grid-cols-[0.85fr_1.15fr]">
        <div className="rounded-lg border border-[var(--rule)] bg-[var(--surface)] p-5">
          <h2 className="text-lg font-semibold text-[var(--fg)]">Validation</h2>
          <ul className="mt-4 space-y-2 text-sm">
            {validation.map((item) => (
              <li key={item} className="rounded border border-[var(--rule)] bg-[var(--bg)] px-3 py-2 text-[var(--muted)]">
                {item}
              </li>
            ))}
          </ul>
        </div>
        <div className="min-w-0 rounded-lg border border-[var(--rule)] bg-[var(--surface)] p-5">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <h2 className="text-lg font-semibold text-[var(--fg)]">Generated plan.toml</h2>
            <button type="button" className="btn btn-primary" onClick={copyToml}>
              {copied ? "Copied" : "Copy TOML"}
            </button>
          </div>
          <pre className="mt-4 max-h-[40rem] min-w-0 overflow-auto rounded-lg border border-[var(--rule)] bg-[var(--code-bg)] p-4 text-sm leading-relaxed">
            <code>{toml}</code>
          </pre>
        </div>
      </section>
    </div>
  );
}

function LabeledInput({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block text-sm font-semibold text-[var(--fg)]">
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
  if (!input.initiative.trim()) issues.push("Add an initiative description.");
  if (!input.workspace.trim()) issues.push("Add a workspace name.");
  if (!input.lane.trim()) issues.push("Add a lane id.");
  if (!input.targetRef.startsWith("refs/heads/")) issues.push("Target ref should start with refs/heads/.");
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(input.repository.trim())) {
    issues.push("Repository id should start with a letter or number and use only letters, numbers, dot, dash, or underscore.");
  }
  const ids = new Set<string>();
  for (const task of input.tasks) {
    if (!task.id.trim()) issues.push("Every task needs a task_id.");
    if (ids.has(task.id)) issues.push(`Duplicate task_id: ${task.id}.`);
    ids.add(task.id);
    if (!task.title.trim()) issues.push(`Task ${task.id || "(blank)"} needs a description.`);
    if (!task.prompt.trim()) issues.push(`Task ${task.id || "(blank)"} needs a prompt.`);
    for (const pred of splitList(task.predecessors)) {
      if (!ids.has(pred) && !input.tasks.some((t) => t.id === pred)) {
        issues.push(`Task ${task.id} references unknown predecessor ${pred}.`);
      }
    }
    if (task.agentType === "Executor" && splitList(task.paths).length === 0) {
      issues.push(`Executor task ${task.id} needs at least one path_allowlist entry.`);
    }
  }
  return issues.length === 0 ? ["Ready to copy. Next: raxis plan validate plan.toml"] : issues;
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
    `description = ${tomlString(input.initiative)}`,
    "",
    "[workspace]",
    `name       = ${tomlString(input.workspace)}`,
    `lane_id    = ${tomlString(input.lane)}`,
    `target_ref = ${tomlString(input.targetRef)}`,
    `repository = ${tomlString(input.repository)}`,
    "",
  ];
  for (const task of input.tasks) {
    const predecessors = splitList(task.predecessors);
    const paths = splitList(task.paths);
    lines.push("[[tasks]]");
    lines.push(`task_id            = ${tomlString(task.id)}`);
    lines.push(`description        = ${tomlString(task.title)}`);
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
    .map((v) => v.trim())
    .filter(Boolean);
}

function tomlString(value: string) {
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}
