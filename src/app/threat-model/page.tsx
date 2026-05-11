import type { Metadata } from "next";
import Link from "next/link";
import { Section } from "@/components/Section";
import { Card } from "@/components/Card";

export const metadata: Metadata = {
  title: "Threat model",
  description:
    "RAXIS makes one assumption stack and refuses to make any other. Agents are adversarial. Operators may make mistakes. The kernel binary and host OS are trusted. The 12 invariants are the structural consequences.",
};

export default function ThreatModelPage() {
  return (
    <>
      <header className="border-b border-[var(--rule)] py-16 sm:py-20 bg-[var(--card)]">
        <div className="mx-auto max-w-6xl px-4 sm:px-6">
          <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">
            Threat model
          </p>
          <h1 className="mt-4 max-w-3xl text-4xl sm:text-5xl font-semibold tracking-[-0.02em] leading-[1.05]">
            One assumption stack. No others.
          </h1>
          <p className="mt-6 max-w-2xl text-lg text-[var(--muted)] leading-relaxed">
            RAXIS makes a small set of assumptions and refuses to make any other. Everything in the architecture follows
            from this triad. Get the threat model right and the 12 invariants are the only sensible response.
          </p>
        </div>
      </header>

      <Section
        eyebrow="The triad"
        title="Three assumptions that hold the whole architecture up."
      >
        <div className="grid gap-4 lg:grid-cols-3">
          <Card>
            <div className="font-mono text-xs uppercase tracking-wider text-red-500/90">
              Assumption #1 — Adversarial
            </div>
            <h3 className="mt-3 text-xl font-semibold tracking-tight">Agents are adversarial.</h3>
            <p className="mt-3 text-sm leading-relaxed text-[var(--muted)]">
              Not because every model is malicious — but because we cannot tell the difference at runtime. An LLM may
              hallucinate, be prompt-injected by a file it reads, be silently swapped for an adversarial fine-tune, or
              simply be confidently wrong in a way that looks correct on review.
            </p>
            <p className="mt-3 text-sm leading-relaxed text-[var(--muted)]">
              RAXIS's safety properties hold whether or not any of this is true. A correct agent gets faster delegation
              with less friction. A compromised agent is contained by the same mechanisms.
            </p>
          </Card>
          <Card>
            <div className="font-mono text-xs uppercase tracking-wider text-amber-500/90">
              Assumption #2 — Fallible
            </div>
            <h3 className="mt-3 text-xl font-semibold tracking-tight">Operators may make mistakes.</h3>
            <p className="mt-3 text-sm leading-relaxed text-[var(--muted)]">
              A misnamed credential. A glob that matches more than intended. A plan signed under pressure that grants
              more than it should. Security failures in production systems most often originate at the human and
              configuration layer.
            </p>
            <p className="mt-3 text-sm leading-relaxed text-[var(--muted)]">
              RAXIS narrows the blast radius with bounded capabilities, fail-closed defaults, hierarchical authority
              that can only narrow — and an audit chain that makes mistakes recoverable rather than catastrophic.
            </p>
          </Card>
          <Card>
            <div className="font-mono text-xs uppercase tracking-wider text-accent">
              Assumption #3 — Trusted
            </div>
            <h3 className="mt-3 text-xl font-semibold tracking-tight">The kernel binary and host OS are trusted.</h3>
            <p className="mt-3 text-sm leading-relaxed text-[var(--muted)]">
              RAXIS is honest about its trust root. The kernel is a single Rust binary; the host OS is whatever you
              boot. Compromise of either invalidates the model.
            </p>
            <p className="mt-3 text-sm leading-relaxed text-[var(--muted)]">
              Hardware roots of trust, signed builds, and confidential computing belong in your stack — but they belong
              alongside RAXIS, not where RAXIS pretends to substitute for them. The paradigm is explicit about what it
              does not solve.
            </p>
          </Card>
        </div>
      </Section>

      <Section
        bleed
        eyebrow='What "compromised agent" actually means'
        title="Four distinct compromise modes. Layered enforcement against each."
        lead='"Compromise" is not one thing. RAXIS distinguishes four modes and assumes each layer can fail — no single layer is trusted to be the last line of defense.'
      >
        <div className="grid gap-4 md:grid-cols-2">
          {[
            {
              title: "LLM jailbreak",
              body: "The model produces adversarial output — ignoring its system prompt, fabricating tool calls, or producing content designed to manipulate another agent.",
            },
            {
              title: "Prompt injection",
              body: "Malicious content in a file the agent reads causes the LLM to produce adversarial output it otherwise wouldn't.",
            },
            {
              title: "VM process compromise",
              body: "The process inside the microVM is itself compromised (malware, exploited dependency) and tries to act outside the intent system entirely.",
            },
            {
              title: "Colluding agents",
              body: "Two or more agents in the same initiative are simultaneously compromised and coordinate to evade individual-agent defenses.",
            },
          ].map((m) => (
            <div key={m.title} className="rounded-xl border border-[var(--card-rule)] bg-[var(--bg)] p-5">
              <h4 className="font-semibold tracking-tight">{m.title}</h4>
              <p className="mt-2 text-sm leading-relaxed text-[var(--muted)]">{m.body}</p>
            </div>
          ))}
        </div>
      </Section>

      <Section
        eyebrow="Layered enforcement"
        title="Ten mechanisms. Each assumes the others can fail."
        lead="RAXIS does not try to prove a single layer is unbreakable. It composes ten independent layers so that a breach of any one is bounded by the others."
      >
        <div className="overflow-x-auto rounded-xl border border-[var(--rule)]">
          <table className="w-full text-sm">
            <thead className="bg-[var(--card)] text-left">
              <tr>
                <th className="px-4 py-3 font-medium">Layer</th>
                <th className="px-4 py-3 font-medium">Mechanism</th>
                <th className="px-4 py-3 font-medium">What it stops</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--rule)]">
              {[
                ["Path allowlist", "Kernel diffs every commit; rejects out-of-scope paths", "Writing outside signed scope regardless of agent state"],
                ["Dispatch matrix", "Session type checked at every intent", "Forbidden intent types per role (e.g., Reviewer can't commit)"],
                ["VM network isolation", "No virtual NIC in agent VM config", "Exfiltration, C2 callbacks, unauthorized pushes"],
                ["VirtioFS boundary", "Kernel controls mount points", "Cross-VM filesystem access"],
                ["Session token isolation", "Kernel-signed, per-VM tokens", "Impersonating other sessions"],
                ["VSock CID binding", "Hypervisor-enforced CID → session binding", "CID spoofing"],
                ["DAG dependency gates", "Kernel state machine on task edges", "Skipping the Reviewer or any other gate"],
                ["Shared lane ceiling", "Budget aggregated across all sessions", "Budget exhaustion as a denial-of-service vector"],
                ["Audit chain", "Every intent recorded with SHA attribution", "Untraceable post-hoc attacks"],
                ["Reviewer gate", "Independent Reviewer VM evaluates before merge", "Compromised Implementer reaching main branch alone"],
              ].map(([layer, mech, stops]) => (
                <tr key={layer}>
                  <td className="px-4 py-3 font-medium align-top">{layer}</td>
                  <td className="px-4 py-3 align-top text-[var(--muted)]">{mech}</td>
                  <td className="px-4 py-3 align-top text-[var(--muted)]">{stops}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>

      <Section
        bleed
        eyebrow="Honest about residual risk"
        title="What RAXIS does not prevent."
      >
        <div className="reading space-y-4 text-[var(--fg)] leading-relaxed">
          <p>
            <strong>Two simultaneously compromised, coordinating agents</strong> in the same initiative — say, an
            Implementer that writes malicious code and a Reviewer that approves it — represent the residual risk of any
            multi-agent system. RAXIS bounds the blast radius (path allowlist confines damage to declared scope) and
            requires two independent VM-level compromises with coordinated timing. Adding a second independent
            Reviewer with different criteria (Panel Review pattern) reduces the risk further. The audit chain is complete
            either way: the breach is fully attributable post-incident.
          </p>
          <p>
            <strong>Compromise of the host OS or the kernel binary itself</strong> invalidates the model. RAXIS is not a
            substitute for measured boot, signed builds, hardware roots of trust, or confidential computing. Those
            primitives belong alongside RAXIS in a serious deployment.
          </p>
          <p>
            <strong>Semantic correctness of the agent's output</strong> is outside RAXIS's scope. The kernel verifies
            authority and evidence of mechanical checks (tests pass, code compiles); it does not verify that the change
            implements what the human meant. That is what tests, code review, and operator approval gates exist for.
          </p>
          <p className="text-[var(--muted)]">
            The point of writing the threat model down — including the residual risk — is to make it specific enough
            for serious people to argue with.{" "}
            <Link href="/paradigm" className="text-accent underline underline-offset-4 hover:no-underline">
              Read the 12 invariants →
            </Link>
          </p>
        </div>
      </Section>
    </>
  );
}
