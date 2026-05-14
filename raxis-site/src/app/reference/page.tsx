import type { Metadata } from "next";
import Link from "next/link";
import { Section } from "@/components/Section";
import { PageHeader } from "@/components/PageHeader";

export const metadata: Metadata = {
  title: "Reference implementation",
  description:
    "A working implementation of Raxis in autonomous software engineering. Agents that read code, write code, run tests, and integrate changes into a real git repository.",
};

export default function ReferencePage() {
  return (
    <>
      <PageHeader
        eyebrow="Reference implementation"
        title="Autonomous software engineering, end to end"
        lead={
          <>
            A complete reference implementation in the hardest agent domain we
            could pick: agents that read code, write code, run tests, and
            integrate changes into a real git repository. Written in Rust,
            released under SSPL.
          </>
        }
      />
      <Why />
      <Architecture />
      <Stores />
      <Intents />
      <Proxies />
      <Scenarios />
      <CTA />
    </>
  );
}

function Why() {
  const items = [
    {
      h: "The highest-stakes agent domain",
      b: "Coding agents are the most-deployed, most-capability-rich agent class in production. They touch source code, hold cloud credentials, push to production. If Raxis can constrain a coding agent without breaking it, every other domain is downhill from there.",
    },
    {
      h: "Perfect ground truth",
      b: "When the agent claims it implemented the change, the kernel verifies mechanically: it runs git diff itself, spawns a verifier subprocess that runs the actual tests, and binds the witness blob to the commit SHA. Software engineering is the one domain where claim and reality reconcile mechanically.",
    },
    {
      h: "Every invariant under load",
      b: "The reference implementation runs the full twelve-invariant gauntlet on real engineering work and surfaces the operational details (worktree concurrency, cross-session path safety, lockfile contention) that only show up when you ship the abstraction.",
    },
  ];
  return (
    <Section title="Why this domain" divider={false} className="pt-20">
      <dl className="grid gap-12 md:grid-cols-3">
        {items.map((it) => (
          <div key={it.h}>
            <dt className="h-sub">{it.h}</dt>
            <dd className="mt-3 text-[var(--muted)] leading-relaxed">{it.b}</dd>
          </div>
        ))}
      </dl>
    </Section>
  );
}

function Architecture() {
  const procs = [
    [
      "Kernel",
      "Authority core",
      "A long-lived local Rust daemon. Owns sessions, capabilities, the work queue, budgets, escalation state, and the audit log. Never reads agent message text when making policy decisions; it evaluates only structured envelope fields it set itself at session creation.",
    ],
    [
      "Planner",
      "Untrusted proposer",
      "The agent loop. Calls the AI model, translates responses into typed intent packets, submits them to the kernel over a local socket. Holds no API keys. Has no HTTP client in its dependency closure. Runs inside a microVM with no virtual NIC.",
    ],
    [
      "Provider gateway",
      "Mediated I/O",
      "Every external AI model call goes through here. The kernel checks the budget, assembles the final prompt (injecting the static policy portion the planner cannot modify), and hands the call to the gateway. The gateway holds the API keys.",
    ],
    [
      "Verifier runner",
      "Independent evidence",
      "An ephemeral subprocess the kernel spawns when a task is ready for promotion. Compiles code, runs tests, checks architecture rules. Writes results back to the kernel keyed by commit SHA, task ID, and a kernel-issued run ID.",
    ],
  ];
  return (
    <Section
      bleed
      title="Architecture"
      lead="A small cluster of processes, each with a clear role and trust level. Not novel: privilege separation as used by OpenSSH, Chrome, and OpenBSD pledge, applied to LLM output."
    >
      <dl className="grid gap-x-12 gap-y-10 md:grid-cols-2">
        {procs.map(([role, tag, body]) => (
          <div key={role}>
            <div className="flex items-baseline justify-between gap-3">
              <dt className="h-sub">{role}</dt>
              <span className="text-xs uppercase tracking-wider text-[var(--soft)]">
                {tag}
              </span>
            </div>
            <dd className="mt-3 text-[var(--muted)] leading-relaxed">{body}</dd>
          </div>
        ))}
      </dl>
    </Section>
  );
}

function Stores() {
  const rows: Array<[string, string]> = [
    [
      "Kernel state store",
      "SQLite WAL. Sessions, delegations, task DAGs, lane queues, budget positions, escalation states. Only the kernel reads or writes.",
    ],
    [
      "Policy store",
      "Signed policy artifacts. The SQLite index is a derived cache; the signed files are ground truth.",
    ],
    [
      "Audit log",
      "Append-only JSONL, hash-chained across segments so tampering is detectable without a database.",
    ],
    [
      "Witness store",
      "Content-addressed blobs. Test results, static analysis outputs, gate verdicts, keyed by commit SHA and verifier run ID.",
    ],
    [
      "Planner working cache",
      "Throwaway. Context packs, candidate plans, temporary summaries. Aggressively TTL'd; wiping it has no effect on correctness.",
    ],
  ];
  return (
    <Section
      title="Five storage layers"
      lead="State separated by trust level, outside the workspace. Four trusted stores live under ~/.raxis/, where agents operating inside the workspace cannot reach them."
    >
      <div className="border-y border-[var(--rule)]">
        {rows.map(([title, body], i) => (
          <div
            key={title}
            className={
              "grid grid-cols-1 sm:grid-cols-[16rem_minmax(0,1fr)] gap-2 sm:gap-10 py-6 " +
              (i > 0 ? "border-t border-[var(--rule)]" : "")
            }
          >
            <div className="text-[1.125rem] font-semibold tracking-[-0.01em] text-[var(--fg)]">
              {title}
            </div>
            <div className="text-[var(--muted)] leading-relaxed">{body}</div>
          </div>
        ))}
      </div>
    </Section>
  );
}

function Intents() {
  const rows: Array<[string, string, string]> = [
    [
      "SingleCommit",
      "Executor",
      "One non-merge commit on top of the base SHA",
    ],
    [
      "IntegrationMerge",
      "Orchestrator",
      "Merge commit integrating Executors' branches into the target ref",
    ],
    [
      "CompleteTask",
      "Executor / Reviewer",
      "Assert task is done; triggers gate-closure check",
    ],
    [
      "ReportFailure",
      "Any role",
      "Self-report inability to complete with a justification",
    ],
    [
      "ActivateSubTask",
      "Orchestrator",
      "Spawn a sub-task (Executor or Reviewer)",
    ],
    [
      "RetrySubTask",
      "Orchestrator",
      "Re-activate a previously failed sub-task",
    ],
    [
      "SubmitReview",
      "Reviewer",
      "Approve or reject a peer Executor's commits",
    ],
    [
      "StructuredOutput",
      "Executor / Orchestrator",
      "Mid-session typed output, non-terminal",
    ],
  ];
  return (
    <Section
      bleed
      title="Eight intent kinds"
      lead="The only ways an agent can act. No side channel. No shared filesystem write to a 'command' directory. No HTTP callback. Every action is one of eight typed intents over the kernel IPC socket."
    >
      <div className="overflow-x-auto">
        <table className="w-full text-[0.95rem]">
          <thead>
            <tr className="border-y border-[var(--rule)]">
              <th className="py-3 pr-6 text-left text-sm font-medium text-[var(--soft)]">
                Intent kind
              </th>
              <th className="py-3 pr-6 text-left text-sm font-medium text-[var(--soft)]">
                Allowed roles
              </th>
              <th className="py-3 text-left text-sm font-medium text-[var(--soft)]">
                Purpose
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.map(([k, a, p]) => (
              <tr key={k} className="border-b border-[var(--rule)]">
                <td className="py-3 pr-6 align-top font-mono text-[0.85rem] text-accent">
                  {k}
                </td>
                <td className="py-3 pr-6 align-top text-[var(--muted)]">{a}</td>
                <td className="py-3 align-top text-[var(--muted)]">{p}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="mt-8 text-base text-[var(--muted)] max-w-3xl">
        The pair (intent kind, agent role) is checked against a compile-time
        dispatch matrix. Adding a new IntentKind variant breaks compilation
        until a row is added; the static type system enforces exhaustive role
        checking.
      </p>
    </Section>
  );
}

function Proxies() {
  const rows: Array<[string, string, string]> = [
    [
      "postgres",
      "PostgreSQL wire protocol",
      "allowed_operations · allowed_tables · max_rows",
    ],
    ["mysql", "MySQL wire protocol", "allowed_operations · allowed_tables"],
    ["mssql", "TDS / SQL Server", "allowed_operations · allowed_tables"],
    [
      "mongodb",
      "MongoDB wire protocol",
      "allowed_operations · allowed_collections",
    ],
    ["redis", "RESP", "allowed_commands · blocked_commands"],
    [
      "http",
      "HTTP/1.1 reverse proxy",
      "allowed_methods · allowed_paths · path globs",
    ],
    [
      "smtp",
      "SMTP relay",
      "allowed_recipients · max_recipients · max_message_size",
    ],
    [
      "aws",
      "AWS IMDS-compatible",
      "allowed_services · allowed_regions · role ARN",
    ],
    ["gcp", "GCP metadata-compatible", "allowed_scopes · project ID"],
    [
      "azure",
      "Azure IMDS-compatible",
      "allowed_scopes · subscription restrictions",
    ],
  ];
  return (
    <Section
      title="Ten credential proxies"
      lead="The agent connects to localhost on a port and speaks a normal protocol. The proxy parses every request, applies the operator's allowlist, audits each one, and forwards to the real upstream with credentials the agent never sees."
    >
      <div className="border-y border-[var(--rule)]">
        {rows.map(([name, proto, restr], i) => (
          <div
            key={name}
            className={
              "grid grid-cols-[6rem_minmax(0,1fr)] sm:grid-cols-[7rem_16rem_minmax(0,1fr)] gap-4 sm:gap-6 py-4 items-baseline " +
              (i > 0 ? "border-t border-[var(--rule)]" : "")
            }
          >
            <div className="font-mono text-[0.85rem] text-accent">{name}</div>
            <div className="text-[var(--fg)]">{proto}</div>
            <div className="text-[0.85rem] font-mono text-[var(--muted)]">
              {restr}
            </div>
          </div>
        ))}
      </div>
    </Section>
  );
}

function Scenarios() {
  const items: Array<[string, string]> = [
    ["01 Hello World", "One Executor writes one file. The minimal valid plan."],
    ["02 Single Executor + Reviewer", "The canonical pattern for verified work."],
    ["07 Panel Review", "Three Reviewers debate quality; majority decides."],
    [
      "13 Monorepo Frontend + Backend",
      "Parallel Executors with non-overlapping path scopes.",
    ],
    ["29 pytest Verifier", "Mechanical witnesses for Python projects."],
    [
      "35 HTTP Egress Allowlist",
      "Outbound network restricted to declared domains.",
    ],
    [
      "36 Postgres Credential Proxy",
      "Agent queries Postgres without ever seeing the password.",
    ],
    [
      "41 Audit Chain Replay",
      "Reproduce every kernel decision from the log alone.",
    ],
    [
      "50 End-to-End Feature Shipment",
      "Parallel decomposition, panel review, witnesses, merge.",
    ],
  ];
  return (
    <Section
      bleed
      title="Fifty reproducible scenarios"
      lead="From a one-file hello world to a full feature shipment. Every scenario reproducible end-to-end against a live kernel, with a runnable plan.toml, expected outputs, and a tear-down step."
    >
      <ul className="grid gap-x-10 gap-y-7 sm:grid-cols-2 lg:grid-cols-3">
        {items.map(([title, body]) => (
          <li key={title}>
            <div className="text-[1.0625rem] font-semibold tracking-[-0.01em] text-[var(--fg)]">
              {title}
            </div>
            <p className="mt-2 text-[var(--muted)] leading-relaxed text-[0.95rem]">
              {body}
            </p>
          </li>
        ))}
      </ul>
      <p className="mt-12 text-base text-[var(--muted)]">
        <Link
          href="/docs"
          className="text-accent hover:underline underline-offset-4"
        >
          Browse all scenarios →
        </Link>
      </p>
    </Section>
  );
}

function CTA() {
  return (
    <section className="border-t border-[var(--rule)] py-20 sm:py-24">
      <div className="mx-auto max-w-5xl px-4 sm:px-6">
        <h2 className="h-section max-w-3xl">
          The implementation is the proof, the paradigm is the contribution
        </h2>
        <p className="lead mt-4 max-w-2xl">
          Twelve invariants, written down so they can be argued with. A
          working implementation, so the paradigm is buildable. Both are open.
        </p>
        <div className="mt-10 flex flex-wrap items-center gap-4">
          <Link href="/docs" className="btn btn-primary">
            Browse documentation
          </Link>
          <a
            href="https://github.com/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-base text-[var(--fg)] hover:text-accent underline underline-offset-4 decoration-[var(--rule)] hover:decoration-accent transition"
          >
            Source on GitHub
          </a>
        </div>
      </div>
    </section>
  );
}
