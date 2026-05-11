export function StackDiagram() {
  const layers = [
    {
      title: "Agent Frameworks",
      examples: "LangChain · AutoGen · OpenAI Agents SDK · Claude Agent SDK · CrewAI · MetaGPT",
      concern: "How do I build an agent that gets work done?",
      tone: "muted" as const,
    },
    {
      title: "RAXIS",
      examples: "Policy authority · capability gating · audit chain · credential isolation · budget enforcement · escalation",
      concern: "How do I run that agent in production with cryptographic accountability?",
      tone: "accent" as const,
    },
    {
      title: "Isolation & Runtime Substrates",
      examples: "Firecracker · Apple Virtualization.framework · gVisor · Docker · LXC · WebAssembly",
      concern: "How do I isolate untrusted code?",
      tone: "muted" as const,
    },
  ];
  return (
    <div className="mx-auto max-w-3xl">
      {layers.map((l, i) => (
        <div key={l.title}>
          <div
            className={
              "rounded-xl border p-5 sm:p-6 " +
              (l.tone === "accent"
                ? "border-accent/40 bg-accent-soft"
                : "border-[var(--rule)] bg-[var(--card)]")
            }
          >
            <div className="flex items-baseline justify-between gap-3 flex-wrap">
              <h3
                className={
                  "font-semibold tracking-tight " +
                  (l.tone === "accent" ? "text-accent text-xl" : "text-[var(--fg)]")
                }
              >
                {l.title}
              </h3>
              {l.tone === "accent" && (
                <span className="font-mono text-[10px] uppercase tracking-[0.18em] text-accent">
                  this layer
                </span>
              )}
            </div>
            <p className="mt-2 text-xs text-[var(--muted)] font-mono leading-relaxed">{l.examples}</p>
            <p className="mt-3 text-sm leading-relaxed text-[var(--fg)]">
              <span className="text-[var(--muted)]">Concern: </span>
              {l.concern}
            </p>
          </div>
          {i < layers.length - 1 && (
            <div aria-hidden className="flex justify-center py-2">
              <div className="flex flex-col items-center gap-0.5 text-[var(--muted)]">
                <div className="h-3 w-px bg-[var(--rule)]" />
                <span className="text-xs">
                  {i === 0 ? "submits work to" : "enforces policy on"}
                </span>
                <div className="h-3 w-px bg-[var(--rule)]" />
                <svg width="10" height="10" viewBox="0 0 10 10" fill="currentColor">
                  <path d="M5 8 L1 3 L9 3 Z" />
                </svg>
              </div>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
