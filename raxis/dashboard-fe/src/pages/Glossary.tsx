import { useMemo, useState } from "react";
import { Link } from "react-router-dom";

type GlossaryCategory =
  | "Setup"
  | "Authority"
  | "Runtime"
  | "Work"
  | "Builders"
  | "Security";

interface GlossaryTerm {
  term: string;
  category: GlossaryCategory;
  summary: string;
  detail: string;
  related?: string[];
}

const TERMS: GlossaryTerm[] = [
  {
    term: "Install dir",
    category: "Setup",
    summary: "The immutable Homebrew runtime bundle.",
    detail:
      "Homebrew installs binaries, dashboard assets, VM images, examples, and helper scripts under $(brew --prefix raxis)/share/raxis. Export it as RAXIS_INSTALL_DIR so the CLI, kernel, and dashboard all resolve the same shipped assets.",
    related: ["RAXIS_INSTALL_DIR", "Homebrew bottle"],
  },
  {
    term: "Data dir",
    category: "Setup",
    summary: "The writable state root for one kernel.",
    detail:
      "The data dir holds policy, keys, provider credentials, kernel.db, audit segments, sockets, worktrees, managed repositories, and runtime status. The Homebrew service default is $(brew --prefix)/var/lib/raxis.",
    related: ["RAXIS_DATA_DIR", "kernel.db"],
  },
  {
    term: "Operator key",
    category: "Authority",
    summary: "Your local Ed25519 signing key.",
    detail:
      "The operator private key signs plans, approvals, dashboard login challenges, and other operator requests. Keep RAXIS_OPERATOR_KEY exported for convenience; otherwise pass the key path on each signed CLI command.",
    related: ["RAXIS_OPERATOR_KEY", "operator certificate"],
  },
  {
    term: "Genesis",
    category: "Authority",
    summary: "The one-time bootstrap ceremony.",
    detail:
      "Genesis creates the first policy, authority keys, operator certificate, kernel database, key directories, provider directory, and the first audit segment. It runs once per data dir.",
    related: ["policy.toml", "audit chain"],
  },
  {
    term: "Policy",
    category: "Authority",
    summary: "The signed rulebook the kernel enforces.",
    detail:
      "Policy declares operators, permitted operations, lanes, providers, egress, gates, dashboard settings, budgets, environments, repositories, and runtime defaults. The kernel is the authority on whether a draft policy can advance.",
    related: ["Policy Builder", "epoch"],
  },
  {
    term: "Epoch",
    category: "Authority",
    summary: "A numbered policy version.",
    detail:
      "Each accepted policy advances the policy epoch. Running sessions and operator permissions are evaluated against the active epoch so stale authority can be rejected cleanly.",
    related: ["RotateEpoch", "policy signature"],
  },
  {
    term: "Provider",
    category: "Runtime",
    summary: "A model backend plus private credential file.",
    detail:
      "The policy names providers, while private API keys live under providers/*.toml in the data dir with mode 0600. Agents never read those files directly; the gateway mediates model calls.",
    related: ["raxis-gateway", "credential file"],
  },
  {
    term: "Kernel",
    category: "Runtime",
    summary: "The authority process.",
    detail:
      "raxis-kernel admits plans, spawns isolated agents, enforces policy, supervises egress and credentials, merges accepted work, writes audit events, and serves the operator dashboard.",
    related: ["raxis-kernel", "audit chain"],
  },
  {
    term: "Supervisor",
    category: "Runtime",
    summary: "The service wrapper around the kernel.",
    detail:
      "raxis-supervisor starts the kernel, reports lifecycle state, handles restart policy, raises file descriptor limits, and avoids tight crash loops when the data dir is not initialized.",
    related: ["brew services", "raxis-supervisor status"],
  },
  {
    term: "Dashboard",
    category: "Runtime",
    summary: "The local operator UI.",
    detail:
      "The dashboard is served by the kernel on loopback by default. It shows health, initiatives, sessions, diffs, audit events, gates, policy, credentials, Plan Builder, Policy Builder, and recovery guidance.",
    related: ["http://127.0.0.1:9820"],
  },
  {
    term: "Managed repository",
    category: "Work",
    summary: "A repository Raxis owns for governed work.",
    detail:
      "A managed repository is cloned or adopted into the data dir so the kernel can create task worktrees, perform integration merge, and update the target ref under policy. Raxis 0.2.x supports named repositories.",
    related: ["repositories/main", "target_ref"],
  },
  {
    term: "Plan",
    category: "Work",
    summary: "The signed TOML bundle for one initiative.",
    detail:
      "A plan declares the workspace, repository, target ref, tasks, prompts, dependencies, reviewers, verifiers, credentials, and path scopes. It is validated before admission and then treated as immutable signed input.",
    related: ["Plan Builder", "plan.toml"],
  },
  {
    term: "Initiative",
    category: "Work",
    summary: "One admitted plan moving through the kernel.",
    detail:
      "An initiative is the runtime instance created from a plan. It moves from admission through task execution, review, gate evaluation, integration merge, completion, abort, or quarantine.",
    related: ["DAG", "audit log"],
  },
  {
    term: "Task",
    category: "Work",
    summary: "One node in the initiative DAG.",
    detail:
      "A task has a stable task_id, agent type, prompt, path allowlist, predecessors, optional gates, and runtime limits. description is the short label; prompt is the main instruction sent to the agent.",
    related: ["Executor", "Reviewer"],
  },
  {
    term: "Orchestrator",
    category: "Work",
    summary: "The kernel-managed initiative coordinator.",
    detail:
      "The orchestrator activates ready tasks, respects predecessor edges, handles retry windows, assembles task bundles, and drives integration. You do not declare it as a plan task.",
    related: ["DAG", "integration merge"],
  },
  {
    term: "Executor",
    category: "Work",
    summary: "The agent role that changes files.",
    detail:
      "Executors receive the task prompt and the allowed worktree scope. They produce commits for the kernel to review, gate, and merge.",
    related: ["path_allowlist", "commit_sha"],
  },
  {
    term: "Reviewer",
    category: "Work",
    summary: "The agent role that reviews predecessor work.",
    detail:
      "Reviewers inspect task output and emit approve or reject verdicts without making product code changes. They are useful for high-risk or multi-step plans.",
    related: ["review gate", "verdict"],
  },
  {
    term: "Plan Builder",
    category: "Builders",
    summary: "A helper for drafting plan.toml.",
    detail:
      "Plan Builder exposes the feature library, task graph, live DAG preview, TOML output, copy/download actions, and kernel validation. It is a drafting tool; admitted plans still go through kernel validation and signed submission.",
    related: ["prompt", "DAG"],
  },
  {
    term: "Policy Builder",
    category: "Builders",
    summary: "A helper for editing policy.toml.",
    detail:
      "Policy Builder exposes policy features, known-good snippets, TOML editing, draft hashing, kernel validation, and next-step commands. Epoch advance still requires signed policy authority.",
    related: ["RotateEpoch", "OperatorCertInstall"],
  },
  {
    term: "DAG",
    category: "Work",
    summary: "The dependency graph for tasks.",
    detail:
      "The DAG is derived from task predecessors. The kernel admits only acyclic graphs where each predecessor exists, and the dashboard uses the same shape to show execution flow.",
    related: ["predecessors", "task graph"],
  },
  {
    term: "Lane",
    category: "Security",
    summary: "A policy-controlled execution queue.",
    detail:
      "A lane bounds concurrency, cost, retry behavior, and scheduling priority. Plans reference a lane_id, and policy decides whether that lane is allowed.",
    related: ["max_concurrent_tasks", "budgets"],
  },
  {
    term: "Environment",
    category: "Security",
    summary: "A label for credential and deployment separation.",
    detail:
      "Raxis supports multiple environments in policy, but production operators should prefer separate kernels and data dirs for staging/prod when human error would be costly. The Homebrew service defaults to the default environment.",
    related: ["RAXIS_ENV", "providers"],
  },
  {
    term: "Credential proxy",
    category: "Security",
    summary: "Kernel-mediated access to private systems.",
    detail:
      "Credential proxies let a task use approved services without exposing raw secrets to the agent VM. Policy declares allowed credentials and environment bindings.",
    related: ["permitted_credentials", "egress"],
  },
  {
    term: "Gate",
    category: "Security",
    summary: "A verifier-backed merge requirement.",
    detail:
      "A gate runs a verifier against a task output or integration candidate. The kernel binds verifier results to the exact evaluation SHA so stale evidence cannot satisfy new work.",
    related: ["witness", "verifier"],
  },
  {
    term: "Witness",
    category: "Security",
    summary: "The durable evidence from a verifier run.",
    detail:
      "Witness records connect a verifier result to task id, gate type, evaluation SHA, and evidence blob. They live under the data dir and are reflected in the audit chain.",
    related: ["evaluation_sha", "audit chain"],
  },
  {
    term: "Audit chain",
    category: "Security",
    summary: "The append-only record of kernel decisions.",
    detail:
      "Every admission, denial, approval, verifier result, session event, policy advance, and merge decision is written into hash-chained JSONL segments for later verification.",
    related: ["raxis verify-chain", "segment-000.jsonl"],
  },
];

const CATEGORIES: Array<GlossaryCategory | "All"> = [
  "All",
  "Setup",
  "Authority",
  "Runtime",
  "Work",
  "Builders",
  "Security",
];

export function GlossaryPage() {
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState<GlossaryCategory | "All">("All");

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return TERMS.filter((term) => {
      const matchesCategory = category === "All" || term.category === category;
      if (!matchesCategory) return false;
      if (!needle) return true;
      return [
        term.term,
        term.summary,
        term.detail,
        term.category,
        ...(term.related ?? []),
      ]
        .join(" ")
        .toLowerCase()
        .includes(needle);
    });
  }, [category, query]);

  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-ink">Glossary</h1>
          <p className="mt-1 max-w-3xl text-sm text-ink-muted">
            The operator vocabulary in one place. Use it while reading
            plans, policy, health checks, and dashboard alerts.
          </p>
        </div>
        <Link to="/plan-builder" className="btn">
          Open Plan Builder
        </Link>
      </header>

      <section className="card p-4">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-center">
          <label className="flex min-w-0 flex-1 flex-col gap-1 text-xs font-semibold text-ink-subtle">
            Search terms
            <input
              className="input w-full"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="operator key, policy, DAG, provider..."
            />
          </label>
          <div className="flex flex-wrap gap-1">
            {CATEGORIES.map((cat) => (
              <button
                key={cat}
                type="button"
                className={
                  category === cat
                    ? "badge border-accent bg-accent/20 text-accent"
                    : "badge border-edge bg-panel text-ink-muted hover:border-accent"
                }
                onClick={() => setCategory(cat)}
              >
                {cat}
              </button>
            ))}
          </div>
        </div>
      </section>

      <section className="grid gap-3 lg:grid-cols-2">
        {filtered.map((term) => (
          <article key={term.term} className="card p-4">
            <div className="flex flex-wrap items-start justify-between gap-2">
              <div>
                <h2 className="text-sm font-semibold text-ink">{term.term}</h2>
                <p className="mt-1 text-xs font-medium text-accent">
                  {term.category}
                </p>
              </div>
              {term.related && (
                <div className="flex max-w-md flex-wrap justify-end gap-1">
                  {term.related.map((item) => (
                    <code
                      key={item}
                      className="rounded border border-edge bg-panel px-1.5 py-0.5 font-mono text-[10px] text-ink-muted"
                    >
                      {item}
                    </code>
                  ))}
                </div>
              )}
            </div>
            <p className="mt-3 text-sm font-medium text-ink">{term.summary}</p>
            <p className="mt-2 text-sm leading-relaxed text-ink-muted">
              {term.detail}
            </p>
          </article>
        ))}
        {filtered.length === 0 && (
          <div className="card col-span-full p-8 text-center text-sm text-ink-muted">
            No glossary terms match this filter.
          </div>
        )}
      </section>
    </div>
  );
}
