import type { Metadata } from "next";
import Link from "next/link";
import { Section } from "@/components/Section";
import { Card } from "@/components/Card";

export const metadata: Metadata = {
  title: "Reference implementation",
  description:
    "A complete reference implementation of RAXIS in the hardest agent domain we could pick: autonomous software engineering. Agents that read code, write code, run tests, and integrate changes into a real git repository.",
};

export default function ReferencePage() {
  return (
    <>
      <header className="border-b border-[var(--rule)] py-16 sm:py-20 bg-[var(--card)]">
        <div className="mx-auto max-w-6xl px-4 sm:px-6">
          <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">
            Reference implementation
          </p>
          <h1 className="mt-4 max-w-3xl text-4xl sm:text-5xl font-semibold tracking-[-0.02em] leading-[1.05]">
            Autonomous software engineering, end to end.
          </h1>
          <p className="mt-6 max-w-3xl text-lg text-[var(--muted)] leading-relaxed">
            A paradigm without a working implementation is a manifesto. RAXIS ships with a complete reference
            implementation in the hardest domain we could pick — agents that read code, write code, run tests, and
            integrate changes into a real git repository. Written in Rust. Open source under SSPL.
          </p>
        </div>
      </header>

      <Section
        eyebrow="Why this domain"
        title="Three reasons software engineering is the right proving ground."
      >
        <div className="grid gap-4 md:grid-cols-3">
          <Card>
            <h3 className="font-semibold tracking-tight">The highest-stakes agent domain.</h3>
            <p className="mt-3 text-sm leading-relaxed text-[var(--muted)]">
              Coding agents — Cursor, Claude Code, Codex, Devin — are the most-deployed, most-capability-rich agent class
              in production today. They touch source code, hold cloud credentials, push to production. If RAXIS can
              constrain a coding agent without breaking it, every other domain is downhill from there.
            </p>
          </Card>
          <Card>
            <h3 className="font-semibold tracking-tight">Perfect ground truth.</h3>
            <p className="mt-3 text-sm leading-relaxed text-[var(--muted)]">
              When the agent claims "I implemented the change," the kernel verifies mechanically: it runs git diff
              itself; it spawns a verifier subprocess that runs the actual tests; it binds the witness blob to the
              commit SHA. Software engineering is the one domain where claim and reality reconcile mechanically.
            </p>
          </Card>
          <Card>
            <h3 className="font-semibold tracking-tight">Every invariant, under load.</h3>
            <p className="mt-3 text-sm leading-relaxed text-[var(--muted)]">
              The reference implementation runs the full 12-invariant gauntlet on real engineering work — and surfaces
              the operational details (worktree concurrency, cross-session path safety, lockfile contention) that only
              show up when you actually ship the abstraction.
            </p>
          </Card>
        </div>
      </Section>

      <Section
        bleed
        eyebrow="Architecture"
        title="A small cluster of processes. Each with a clear role and trust level."
        lead="RAXIS is not a single application. It is a separation pattern — the same one used by OpenSSH, Chrome, and OpenBSD pledge — applied to LLM output."
      >
        <div className="grid gap-4 md:grid-cols-2">
          {[
            {
              role: "The Kernel",
              tag: "Authority core",
              body: "A long-lived local Rust daemon. Owns sessions, capabilities, the work queue, budgets, escalation state, and the audit log. Never reads agent message text when making policy decisions — it evaluates only structured envelope fields it set itself at session creation, which the model cannot overwrite.",
            },
            {
              role: "The Planner",
              tag: "Untrusted proposer",
              body: "The agent loop. Calls the AI model, translates responses into typed intent packets, submits them to the kernel over a local socket. Holds no API keys. Has no HTTP client in its dependency closure. Runs inside a microVM with no virtual NIC.",
            },
            {
              role: "The Provider Gateway",
              tag: "Mediated I/O",
              body: "Every external AI model call goes through here. The kernel checks the budget, assembles the final prompt (injecting the static policy portion the planner cannot modify), and hands the call to the gateway. The gateway holds the API keys; the planner never does.",
            },
            {
              role: "The Verifier Runner",
              tag: "Independent evidence",
              body: "An ephemeral subprocess the kernel spawns when a task is ready for promotion. Compiles code, runs tests, checks architecture rules. Writes results back to the kernel — not to a file the planner can read — keyed by commit SHA, task ID, and a kernel-issued run ID.",
            },
          ].map((p) => (
            <div key={p.role} className="rounded-xl border border-[var(--card-rule)] bg-[var(--bg)] p-5">
              <div className="flex items-baseline justify-between">
                <h3 className="text-lg font-semibold tracking-tight">{p.role}</h3>
                <span className="font-mono text-[10px] uppercase tracking-wider text-accent">{p.tag}</span>
              </div>
              <p className="mt-3 text-sm leading-relaxed text-[var(--muted)]">{p.body}</p>
            </div>
          ))}
        </div>
      </Section>

      <Section
        eyebrow="Five storage layers"
        title="State, separated by trust level — outside the workspace."
        lead="Five stores hold the system's state. Each has a different trust level. The four trusted stores live outside the repository, under ~/.raxis/, where agents operating inside the workspace cannot reach them."
      >
        <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
          {[
            ["Kernel State Store", "SQLite WAL. Sessions, delegations, task DAGs, lane queues, budget positions, escalation states. Only the kernel reads or writes."],
            ["Policy Store", "Signed policy artifacts. The SQLite index is a derived cache; the signed files are ground truth."],
            ["Audit Log", "Append-only JSONL, hash-chained across segments so tampering is detectable without a database."],
            ["Witness Store", "Content-addressed blobs. Test results, static analysis outputs, gate verdicts — keyed by commit SHA and verifier run ID."],
            ["Planner Working Cache", "Throwaway. Context packs, candidate plans, temporary summaries. Aggressively TTL'd; wiping it has no effect on system correctness."],
          ].map(([title, body]) => (
            <Card key={title}>
              <h4 className="font-semibold tracking-tight">{title}</h4>
              <p className="mt-2 text-sm leading-relaxed text-[var(--muted)]">{body}</p>
            </Card>
          ))}
        </div>
      </Section>

      <Section
        bleed
        eyebrow="Eight intent kinds"
        title="The only ways an agent can act."
        lead="There is no side channel. No shared filesystem write to a 'command' directory. No HTTP callback. No kill -USR1. Every agent action is one of eight typed intents over the kernel IPC socket."
      >
        <div className="overflow-x-auto rounded-xl border border-[var(--rule)] bg-[var(--bg)]">
          <table className="w-full text-sm">
            <thead className="bg-[var(--card)] text-left">
              <tr>
                <th className="px-4 py-3 font-medium">Intent kind</th>
                <th className="px-4 py-3 font-medium">Allowed agents</th>
                <th className="px-4 py-3 font-medium">Purpose</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--rule)]">
              {[
                ["SingleCommit", "Executor", "One non-merge commit on top of the base SHA"],
                ["IntegrationMerge", "Orchestrator", "Merge commit that integrates Executors' branches into the target ref"],
                ["CompleteTask", "Executor / Reviewer", "Assert task is done — triggers gate-closure check"],
                ["ReportFailure", "Any role", "Self-report inability to complete with a justification"],
                ["ActivateSubTask", "Orchestrator only", "Spawn a sub-task (Executor or Reviewer)"],
                ["RetrySubTask", "Orchestrator only", "Re-activate a previously failed sub-task"],
                ["SubmitReview", "Reviewer only", "Approve or reject a peer Executor's commits"],
                ["StructuredOutput", "Executor / Orchestrator", "Mid-session typed output (non-terminal — task stays Running)"],
              ].map(([k, a, p]) => (
                <tr key={k}>
                  <td className="px-4 py-3 font-mono text-xs align-top text-accent">{k}</td>
                  <td className="px-4 py-3 align-top text-[var(--muted)]">{a}</td>
                  <td className="px-4 py-3 align-top text-[var(--muted)]">{p}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-6 text-sm text-[var(--muted)]">
          The pair (intent kind, agent role) is checked against a compile-time dispatch matrix. Adding a new IntentKind
          variant breaks compilation until a row is added — the static type system enforces exhaustive role checking.
        </p>
      </Section>

      <Section
        eyebrow="Mediated I/O in production"
        title="Ten protocol-aware credential proxies."
        lead="The agent connects to localhost:PORT and speaks a normal protocol. The proxy parses every request, applies the operator's allowlist, audits each one, and forwards to the real upstream with credentials the agent never sees."
      >
        <div className="grid gap-3 md:grid-cols-2">
          {[
            ["postgres", "PostgreSQL wire protocol", "allowed_operations · allowed_tables · max_rows"],
            ["mysql", "MySQL wire protocol", "allowed_operations · allowed_tables"],
            ["mssql", "TDS / SQL Server", "allowed_operations · allowed_tables"],
            ["mongodb", "MongoDB wire protocol", "allowed_operations · allowed_collections"],
            ["redis", "RESP", "allowed_commands · blocked_commands"],
            ["http", "HTTP/1.1 reverse proxy", "allowed_methods · allowed_paths · path globs"],
            ["smtp", "SMTP relay", "allowed_recipients · max_recipients · max_message_size"],
            ["aws", "AWS IMDS-compatible", "allowed_services · allowed_regions · role ARN"],
            ["gcp", "GCP metadata-compatible", "allowed_scopes · project ID"],
            ["azure", "Azure IMDS-compatible", "allowed_scopes · subscription restrictions"],
          ].map(([name, proto, restr]) => (
            <div
              key={name}
              className="rounded-xl border border-[var(--card-rule)] bg-[var(--card)] p-4 flex flex-col sm:flex-row sm:items-baseline gap-2 sm:gap-4"
            >
              <span className="font-mono text-xs text-accent w-20 shrink-0">{name}</span>
              <span className="text-sm font-medium w-44 shrink-0">{proto}</span>
              <span className="text-xs text-[var(--muted)] font-mono">{restr}</span>
            </div>
          ))}
        </div>
      </Section>

      <Section
        bleed
        eyebrow="Reproducible end-to-end"
        title="Fifty documented scenarios."
        lead='From "hello world" (one Executor, one file) to a full feature shipment (parallel decomposition, panel review, mechanical witnesses, operator-approved integration merge). Every scenario reproducible end-to-end against a live kernel.'
      >
        <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
          {[
            ["01 · Hello World", "One Executor writes one file. The minimal valid plan."],
            ["02 · Single Executor + Reviewer", "The canonical pattern for verified work."],
            ["07 · Panel Review", "Three Reviewers debate quality; majority decides."],
            ["13 · Monorepo Frontend + Backend", "Parallel Executors with non-overlapping path scopes."],
            ["29 · pytest Verifier", "Mechanical witnesses for Python projects."],
            ["35 · HTTP Egress Allowlist", "Outbound network restricted to declared domains."],
            ["36 · Postgres Credential Proxy", "Agent queries Postgres without ever seeing the password."],
            ["41 · Audit Chain Replay", "Reproduce every kernel decision from the log alone."],
            ["44 · Session Revocation", "Operator kills an in-flight session; clean teardown."],
            ["47 · Crash Recovery Mid-Merge", "Kernel restart during IntegrationMerge; state survives."],
            ["50 · End-to-End Feature Shipment", "The capstone: parallel decomp + panel review + witnesses + merge."],
          ].map(([title, body]) => (
            <Card key={title}>
              <h4 className="font-mono text-xs text-accent">{title.split(" · ")[0]}</h4>
              <h5 className="mt-1 font-semibold tracking-tight">{title.split(" · ")[1]}</h5>
              <p className="mt-2 text-sm leading-relaxed text-[var(--muted)]">{body}</p>
            </Card>
          ))}
        </div>
        <p className="mt-8 text-sm text-[var(--muted)]">
          Each scenario in <code className="px-1 rounded bg-[var(--code-bg)] font-mono text-xs">guides/scenarios/</code>{" "}
          ships with a runnable plan.toml, expected outputs, and a tear-down step.{" "}
          <Link href="/docs" className="text-accent underline underline-offset-4 hover:no-underline">
            Browse all scenarios →
          </Link>
        </p>
      </Section>

      <section className="border-t border-[var(--rule)] py-16 sm:py-20 bg-[var(--card)]">
        <div className="mx-auto max-w-3xl px-4 sm:px-6 text-center">
          <h2 className="text-2xl sm:text-3xl font-semibold tracking-tight">
            The reference implementation is the proof. The paradigm is the contribution.
          </h2>
          <p className="mt-4 text-[var(--muted)]">
            Read the spec. Run a scenario. File an issue. The point of writing the 12 invariants down is to give
            serious people something specific to break.
          </p>
          <div className="mt-6 flex flex-wrap items-center justify-center gap-3">
            <Link
              href="/docs"
              className="inline-flex h-10 items-center justify-center rounded-md bg-accent px-5 text-sm font-medium text-white hover:bg-accent-strong transition"
            >
              Browse the documentation
            </Link>
            <a
              href="https://github.com/"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex h-10 items-center justify-center rounded-md border border-[var(--rule)] px-5 text-sm font-medium text-[var(--fg)] hover:border-[var(--fg)] transition"
            >
              Source on GitHub
            </a>
          </div>
        </div>
      </section>
    </>
  );
}
