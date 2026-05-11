const STEPS: Array<{
  num: string;
  title: string;
  body: string;
  by: "Operator" | "Agent" | "Kernel";
}> = [
  {
    num: "01",
    title: "A human submits a goal.",
    body: "A document, a spec, a set of requirements. The kernel does nothing autonomously yet.",
    by: "Operator",
  },
  {
    num: "02",
    title: "An agent proposes a structured plan.",
    body: "Task DAG, capability requirements per task, budget estimates, machine-checkable success criteria. The plan is a structured artifact, not prose.",
    by: "Agent",
  },
  {
    num: "03",
    title: "The operator reviews the plan and signs it.",
    body: "Ed25519 signature over the plan bytes. The kernel transitions the initiative from Draft to ApprovedPlan. No agent action has happened yet.",
    by: "Operator",
  },
  {
    num: "04",
    title: "Agents work under bounded capability.",
    body: "Each agent runs in a microVM with the narrowest capability set needed for its task — no API keys, no direct network, no storage beyond its worktree mount.",
    by: "Agent",
  },
  {
    num: "05",
    title: "Every action is admitted or rejected at the front.",
    body: "The agent sends a typed intent. The kernel runs git diff itself to derive what files were touched — never trusting the agent's claim — and checks against the signed allowlist. Witness subprocesses produce evidence the kernel binds to the commit SHA. The agent cannot self-certify.",
    by: "Kernel",
  },
  {
    num: "06",
    title: "Authority widens only through human approval.",
    body: "When work needs more capability than the plan grants, the agent submits a typed EscalationRequest. The operator signs an ApprovalToken with their offline key — through a CLI the agent cannot reach. The token is bound to a single nonce, a single epoch, and a narrowed scope.",
    by: "Operator",
  },
  {
    num: "07",
    title: "Every decision is recorded on the chain at the back.",
    body: "Admit, deny, escalate, error — each writes one line to a hash-chained JSONL audit log. An independent verifier holding only the log and the operator's public keys can reproduce every decision and detect any single-byte modification.",
    by: "Kernel",
  },
];

const BY_COLOR: Record<"Operator" | "Agent" | "Kernel", string> = {
  Operator: "text-amber-600 dark:text-amber-400",
  Agent: "text-sky-600 dark:text-sky-400",
  Kernel: "text-accent",
};

export function FlowDiagram() {
  return (
    <ol className="relative">
      {/* Vertical rule */}
      <div
        aria-hidden
        className="absolute left-[14px] sm:left-[18px] top-2 bottom-2 w-px bg-[var(--rule)]"
      />
      {STEPS.map((s) => (
        <li key={s.num} className="relative pl-12 sm:pl-16 pb-8 last:pb-0">
          <div
            aria-hidden
            className="absolute left-0 top-0 inline-flex h-7 w-7 sm:h-9 sm:w-9 items-center justify-center rounded-full border border-[var(--rule)] bg-[var(--bg)] font-mono text-[10px] sm:text-xs font-semibold text-[var(--fg)]"
          >
            {s.num}
          </div>
          <div className="flex items-baseline gap-2 flex-wrap">
            <h3 className="text-base sm:text-lg font-semibold tracking-tight">{s.title}</h3>
            <span className={`font-mono text-[10px] uppercase tracking-wider ${BY_COLOR[s.by]}`}>
              {s.by}
            </span>
          </div>
          <p className="mt-2 max-w-2xl text-sm leading-relaxed text-[var(--muted)]">{s.body}</p>
        </li>
      ))}
    </ol>
  );
}
