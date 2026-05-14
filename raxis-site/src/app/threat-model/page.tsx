import type { Metadata } from "next";
import Link from "next/link";
import { Section } from "@/components/Section";
import { PageHeader } from "@/components/PageHeader";

export const metadata: Metadata = {
  title: "Threat model",
  description:
    "Raxis makes one assumption stack and refuses to make any other. Agents are adversarial. Operators may make mistakes. The kernel and host OS are trusted.",
};

export default function ThreatModelPage() {
  return (
    <>
      <PageHeader
        eyebrow="Threat model"
        title="One assumption stack, no others"
        lead={
          <>
            Raxis makes a small set of assumptions and refuses to make any
            other. Everything in the architecture follows from this triad.
            Get the threat model right and the twelve invariants are the only
            sensible response.
          </>
        }
      />
      <Triad />
      <CompromiseModes />
      <Layers />
      <Residual />
    </>
  );
}

function Triad() {
  const items = [
    {
      title: "Agents are adversarial",
      body: "Not because every model is malicious, but because we cannot tell the difference at runtime. An LLM may hallucinate, be prompt-injected by a file it reads, be silently swapped for an adversarial fine-tune, or simply be confidently wrong in a way that looks correct on review. Safety properties hold whether or not any of this is true. A correct agent gets faster delegation. A compromised one is contained by the same mechanisms.",
    },
    {
      title: "Operators may make mistakes",
      body: "A misnamed credential, a glob that matches more than intended, a plan signed under pressure that grants more than it should. Security failures in production systems most often originate at the human and configuration layer. Bounded capabilities, fail closed defaults, and hierarchical authority that can only narrow keep mistakes recoverable rather than catastrophic.",
    },
    {
      title: "The kernel and host OS are trusted",
      body: "The kernel is one Rust binary, the host OS is whatever you boot. Compromise of either invalidates the model. Hardware roots of trust, signed builds, and confidential computing belong alongside Raxis, not where Raxis pretends to substitute for them. The paradigm is explicit about what it does not solve.",
    },
  ];
  return (
    <Section title="The triad" divider={false} className="pt-20">
      <dl className="grid gap-12 md:grid-cols-3">
        {items.map((it) => (
          <div key={it.title}>
            <dt className="h-sub">{it.title}</dt>
            <dd className="mt-3 text-[var(--muted)] leading-relaxed">
              {it.body}
            </dd>
          </div>
        ))}
      </dl>
    </Section>
  );
}

function CompromiseModes() {
  const modes = [
    [
      "LLM jailbreak",
      "The model produces adversarial output. Ignores its system prompt, fabricates tool calls, or produces content designed to manipulate another agent.",
    ],
    [
      "Prompt injection",
      "Malicious content in a file the agent reads causes the LLM to produce adversarial output it otherwise would not.",
    ],
    [
      "VM process compromise",
      "The process inside the microVM is itself compromised, by malware or an exploited dependency, and tries to act outside the intent system entirely.",
    ],
    [
      "Colluding agents",
      "Two or more agents in the same initiative are simultaneously compromised and coordinate to evade individual-agent defenses.",
    ],
  ];
  return (
    <Section
      bleed
      title="What compromised actually means"
      lead="Compromise is not one thing. Raxis distinguishes four modes and assumes each layer can fail; no single layer is trusted to be the last line of defense."
    >
      <dl className="grid gap-x-12 gap-y-10 sm:grid-cols-2">
        {modes.map(([title, body]) => (
          <div key={title}>
            <dt className="h-sub">{title}</dt>
            <dd className="mt-3 text-[var(--muted)] leading-relaxed">{body}</dd>
          </div>
        ))}
      </dl>
    </Section>
  );
}

function Layers() {
  const rows: Array<[string, string, string]> = [
    [
      "Path allowlist",
      "Kernel diffs every commit, rejects out-of-scope paths",
      "Writing outside signed scope regardless of agent state",
    ],
    [
      "Dispatch matrix",
      "Session type checked at every intent",
      "Forbidden intent types per role (Reviewer cannot commit)",
    ],
    [
      "VM network isolation",
      "No virtual NIC in agent VM config",
      "Exfiltration, C2 callbacks, unauthorized pushes",
    ],
    ["VirtioFS boundary", "Kernel controls mount points", "Cross-VM filesystem access"],
    [
      "Session token isolation",
      "Kernel-signed, per-VM tokens",
      "Impersonating other sessions",
    ],
    [
      "VSock CID binding",
      "Hypervisor-enforced CID to session binding",
      "CID spoofing",
    ],
    [
      "DAG dependency gates",
      "Kernel state machine on task edges",
      "Skipping the Reviewer or any other gate",
    ],
    [
      "Shared lane ceiling",
      "Budget aggregated across all sessions",
      "Budget exhaustion as a denial-of-service vector",
    ],
    [
      "Audit chain",
      "Every intent recorded with attribution",
      "Untraceable post-hoc attacks",
    ],
    [
      "Reviewer gate",
      "Independent Reviewer VM evaluates before merge",
      "Compromised Implementer reaching main alone",
    ],
  ];
  return (
    <Section
      title="Ten layers, each assumes the others can fail"
      lead="Raxis does not try to prove a single layer is unbreakable. It composes ten independent layers so a breach of any one is bounded by the others."
    >
      <div className="overflow-x-auto">
        <table className="w-full text-[0.95rem]">
          <thead>
            <tr className="border-y border-[var(--rule)]">
              <th className="py-3 pr-6 text-left text-sm font-medium text-[var(--soft)]">
                Layer
              </th>
              <th className="py-3 pr-6 text-left text-sm font-medium text-[var(--soft)]">
                Mechanism
              </th>
              <th className="py-3 text-left text-sm font-medium text-[var(--soft)]">
                What it stops
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.map(([layer, mech, stops]) => (
              <tr key={layer} className="border-b border-[var(--rule)]">
                <td className="py-3 pr-6 align-top font-semibold text-[var(--fg)]">
                  {layer}
                </td>
                <td className="py-3 pr-6 align-top text-[var(--muted)]">{mech}</td>
                <td className="py-3 align-top text-[var(--muted)]">{stops}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Section>
  );
}

function Residual() {
  return (
    <Section title="What it does not prevent">
      <div className="reading space-y-6 leading-relaxed text-[var(--fg)]">
        <p>
          Two simultaneously compromised, coordinating agents in the same
          initiative (an Implementer that writes malicious code and a Reviewer
          that approves it) represent the residual risk of any multi-agent
          system. Raxis bounds the blast radius (path allowlists confine
          damage to declared scope) and requires two independent VM-level
          compromises with coordinated timing. One containment channel that
          holds regardless of colluding agents is operator-configured
          mechanical witnesses: verifier subprocesses the kernel spins up
          independently after each action to validate correctness:
          compilation, test execution, diff bounds, using criteria the
          agents cannot influence. A colluding Implementer and Reviewer cannot
          suppress a witness result without defeating a separate kernel-level
          control. Adding a second independent Reviewer with different
          criteria reduces the risk further. The audit chain is complete
          either way: the breach is fully attributable post-incident.
        </p>
        <p>
          Compromise of the host OS or the kernel binary itself invalidates
          the model. Raxis is not a substitute for measured boot, signed
          builds, hardware roots of trust, or confidential computing. Those
          primitives belong alongside Raxis in a serious deployment.
        </p>
        <p>
          Semantic correctness of the agent&rsquo;s output is outside
          Raxis&rsquo;s scope. The kernel verifies authority and evidence of
          mechanical checks (tests pass, code compiles); it does not verify
          that the change implements what the human meant. That is what
          tests, code review, and operator approval gates exist for.
        </p>
      </div>
      <p className="mt-12 text-base text-[var(--muted)]">
        <Link
          href="/paradigm"
          className="text-accent hover:underline underline-offset-4"
        >
          Read the twelve invariants →
        </Link>
      </p>
    </Section>
  );
}
