import Link from "next/link";
import { Section } from "@/components/Section";

export default function HomePage() {
  return (
    <>
      <Hero />
      <WhatItDoes />
      <ThreatModel />
      <Invariants />
      <ReferenceImpl />
      <Conformance />
      <FAQ />
      <CTA />
    </>
  );
}

function Hero() {
  return (
    <section className="border-b border-[var(--rule)]">
      <div className="mx-auto max-w-5xl px-4 sm:px-6 pt-24 sm:pt-36 pb-24 sm:pb-32">
        <p className="eyebrow">A paradigm for autonomous-system safety</p>
        <h1 className="h-hero mt-6 max-w-4xl">
          AI agents: authorized actions only,{" "}
          <span className="text-accent">fully audited</span>
        </h1>
        <p className="lead mt-14 sm:mt-16 max-w-3xl">
          <strong>Runtime Attestation eXchange for Intelligent Systems</strong>{" "}
          (Raxis) is a structural enforcement layer that sits between AI agents
          and the systems they act on. Twelve invariants extending Lampson&rsquo;s
          1974 Protection model into the era of probabilistic, autonomous
          intelligence working at scale. Proven in a working reference implementation for
          autonomous software engineering.
        </p>
        <div className="mt-12 flex flex-wrap items-center gap-4">
          <Link href="/paradigm" className="btn btn-primary">
            Read the paradigm
          </Link>
          <Link
            href="/docs"
            className="text-base text-[var(--fg)] hover:text-accent underline underline-offset-4 decoration-[var(--rule)] hover:decoration-accent transition"
          >
            Browse documentation
          </Link>
          <a
            href="https://github.com/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-base text-[var(--muted)] hover:text-[var(--fg)] underline underline-offset-4 decoration-[var(--rule)] hover:decoration-[var(--rule-strong)] transition"
          >
            Source code available
          </a>
        </div>
      </div>
    </section>
  );
}

function WhatItDoes() {
  const items = [
    {
      verb: "Admit",
      body: "Every agent action goes through a typed intent. The kernel checks it against a signed policy and admits or denies before any side effect lands.",
    },
    {
      verb: "Bind",
      body: "Credentials, networks, and storage are mediated by protocol-aware proxies. The agent connects to localhost; the kernel forwards with credentials it never sees.",
    },
    {
      verb: "Audit",
      body: "Deploying agents at scale only works if you can prove, weeks after the fact, exactly what each one did. Every action appends one entry to a SHA-256 hash-chained, append-only log. A single-byte mutation breaks the chain and is detected without a database. An independent verifier holding only the log and the operator's public keys can replay every action byte-for-byte and prove cryptographically that nothing was altered.",
    },
    {
      verb: "Escalate",
      body: "When work needs more than the plan grants, the agent asks. The operator approves through a CLI signed offline, in a channel the model cannot reach.",
    },
  ];
  return (
    <Section title="What it does">
      <div className="grid gap-x-12 gap-y-10 sm:grid-cols-2">
        {items.map((it) => (
          <div key={it.verb}>
            <h3 className="h-sub">{it.verb}</h3>
            <p className="mt-3 text-[var(--muted)] leading-relaxed">{it.body}</p>
          </div>
        ))}
      </div>
    </Section>
  );
}

function ThreatModel() {
  return (
    <Section
      title="Threat model"
      lead="The architecture follows from a small set of assumptions and refuses to make any other."
    >
      <dl className="grid gap-10 sm:grid-cols-3">
        <div>
          <dt className="h-sub">Agents are adversarial</dt>
          <dd className="mt-3 text-[var(--muted)] leading-relaxed">
            Not because every model is malicious, but because we cannot tell
            the difference at runtime. Hallucination, prompt injection, a
            silent fine-tune swap. Safety properties hold whether or not any
            of this is true.
          </dd>
        </div>
        <div>
          <dt className="h-sub">Operators may make mistakes</dt>
          <dd className="mt-3 text-[var(--muted)] leading-relaxed">
            A misnamed credential, a glob that matches more than intended, a
            plan signed under pressure. Bounded capabilities and fail closed
            defaults keep the blast radius small and the audit trail complete.
          </dd>
        </div>
        <div>
          <dt className="h-sub">The kernel is trusted</dt>
          <dd className="mt-3 text-[var(--muted)] leading-relaxed">
            Raxis is honest about its trust root. The kernel is one Rust
            binary, the host OS is whatever you boot. Hardware roots of trust
            and confidential computing belong alongside, not as substitutes.
          </dd>
        </div>
      </dl>
      <p className="mt-12 text-base text-[var(--muted)]">
        <Link
          href="/threat-model"
          className="text-accent hover:underline underline-offset-4"
        >
          Read the full threat model →
        </Link>
      </p>
    </Section>
  );
}

function Invariants() {
  const groups = [
    {
      n: "01",
      title: "Structural separation",
      ids: ["R-1", "R-2"],
      body: "Intelligence and authority run in separate execution domains. All credential, network, and storage access goes through typed intents.",
    },
    {
      n: "02",
      title: "Authority model",
      ids: ["R-3", "R-4", "R-5", "R-6"],
      body: "Capabilities are signed, derived only by narrowing, bounded by explicit numbers, and fail closed when anything is missing or ambiguous.",
    },
    {
      n: "03",
      title: "Accountability",
      ids: ["R-7", "R-8", "R-9", "R-10"],
      body: "The audit chain is cryptographic, decisions reproduce from recorded inputs, every intent traces to a verified identity, rejections do not leak rule structure.",
    },
    {
      n: "04",
      title: "Coordination & recovery",
      ids: ["R-11", "R-12"],
      body: "Multi-agent communication passes through authority. Authority widens only through a human channel the model cannot reach.",
    },
  ];
  return (
    <Section
      bleed
      title="Twelve invariants"
      lead="A system claiming to be Raxis satisfies all twelve. Drop one and you have something else, possibly useful, but no longer Raxis."
    >
      <div className="grid gap-10 sm:grid-cols-2">
        {groups.map((g) => (
          <div key={g.n} className="border-t border-[var(--rule)] pt-6">
            <div className="flex items-baseline gap-3">
              <span className="text-sm text-[var(--soft)] tabular-nums">
                {g.n}
              </span>
              <h3 className="h-sub">{g.title}</h3>
              <span className="ml-auto text-xs text-[var(--soft)] tabular-nums">
                {g.ids.join(" · ")}
              </span>
            </div>
            <p className="mt-3 text-[var(--muted)] leading-relaxed">{g.body}</p>
          </div>
        ))}
      </div>
      <p className="mt-12 text-base text-[var(--muted)]">
        <Link
          href="/paradigm"
          className="text-accent hover:underline underline-offset-4"
        >
          See each invariant with rationale and verification →
        </Link>
      </p>
    </Section>
  );
}

function ReferenceImpl() {
  return (
    <Section title="Reference implementation">
      <div className="grid gap-12 lg:grid-cols-[1.1fr_1fr]">
        <div className="space-y-5 leading-relaxed text-[var(--fg)]">
          <p>
            A paradigm without a working implementation is a manifesto. Raxis
            ships with a complete reference implementation in autonomous
            software engineering: agents that read code, write code, run
            tests, and integrate changes into a real git repository.
          </p>
          <p className="text-[var(--muted)]">
            Software engineering is the right proving ground because it has
            perfect ground truth. When the agent claims it implemented the
            change, the kernel can verify mechanically: it runs{" "}
            <code className="px-1 rounded bg-[var(--code-bg)] font-mono text-[0.88em]">
              git diff
            </code>{" "}
            itself, spawns a verifier subprocess that runs the actual tests,
            and binds the witness blob to the commit SHA. The agent cannot
            self-certify.
          </p>
          <p className="text-[var(--muted)]">
            Every agent runs in a microVM (Firecracker on Linux, Apple
            Virtualization on macOS). Every commit is path-checked. Every
            credential lives behind a protocol-aware proxy. Every escalation
            needs a signature from a key the agent has no path to.
          </p>
        </div>
        <dl className="space-y-5">
          <Stat label="Intent kinds" value="8" hint="every action is one of these" />
          <Stat
            label="Credential proxies"
            value="10"
            hint="postgres, mysql, mongodb, redis, http, smtp, aws, gcp, azure, mssql"
          />
          <Stat
            label="Reproducible scenarios"
            value="50+"
            hint="hello-world to a full feature shipment"
          />
          <Stat label="Language" value="Rust" hint="released under SSPL" />
          <p className="text-base pt-2">
            <Link
              href="/reference"
              className="text-accent hover:underline underline-offset-4"
            >
              Read the architecture →
            </Link>
          </p>
        </dl>
      </div>
    </Section>
  );
}

function Stat({
  label,
  value,
  hint,
}: {
  label: string;
  value: string;
  hint: string;
}) {
  return (
    <div className="flex justify-between gap-6 border-b border-[var(--rule)] pb-4">
      <dt className="text-[var(--muted)]">{label}</dt>
      <dd className="text-right">
        <span className="font-semibold tabular-nums text-[1.25rem] tracking-[-0.01em] text-[var(--fg)]">
          {value}
        </span>
        <span className="block text-sm text-[var(--soft)] mt-0.5">{hint}</span>
      </dd>
    </div>
  );
}

function Conformance() {
  const tiers = [
    {
      tier: "1",
      name: "Aligned",
      verification: "Self-attested",
      use: "Early-stage implementations and prototypes",
    },
    {
      tier: "2",
      name: "Tested",
      verification: "Self-tested against the canonical conformance suite",
      use: "Production-bound implementations seeking demonstrable conformance",
    },
    {
      tier: "3",
      name: "Verified",
      verification: "Independent third-party audit; annual re-audit",
      use: "Regulated deployments and contractual conformance commitments",
    },
  ];
  return (
    <Section
      title="Conformance"
      lead="Three tiers of evidence, modeled on FIPS 140 and Common Criteria. The unqualified phrase 'Raxis-Verified' is reserved for tier 3."
    >
      <div className="border-y border-[var(--rule)]">
        {tiers.map((t, i) => (
          <div
            key={t.tier}
            className={
              "grid grid-cols-[3rem_minmax(0,1fr)] sm:grid-cols-[3rem_8rem_minmax(0,1fr)_minmax(0,1fr)] gap-4 sm:gap-6 py-6 " +
              (i > 0 ? "border-t border-[var(--rule)]" : "")
            }
          >
            <div className="text-sm tabular-nums text-[var(--soft)]">
              Tier {t.tier}
            </div>
            <div className="text-[1.125rem] font-semibold tracking-[-0.01em] text-[var(--fg)]">
              {t.name}
            </div>
            <div className="text-[var(--muted)] leading-snug">
              {t.verification}
            </div>
            <div className="text-[var(--muted)] leading-snug">{t.use}</div>
          </div>
        ))}
      </div>
      <p className="mt-8 text-base text-[var(--muted)]">
        Status of the reference implementation: tier 1 and tier 2 current,
        tier 3 not currently claimed.{" "}
        <Link
          href="/conformance"
          className="text-accent hover:underline underline-offset-4"
        >
          Read more →
        </Link>
      </p>
    </Section>
  );
}

function FAQ() {
  const qs = [
    {
      q: "Is Raxis an agent framework?",
      a: "No. Frameworks like LangChain, AutoGen, or the OpenAI Agents SDK help you build an agent. Raxis is the layer below that, controlling what the agent is allowed to do and producing the audit trail. Use both.",
    },
    {
      q: "Is Raxis a sandbox?",
      a: "Sandboxing is one of twelve invariants. A sandbox contains the process; Raxis also gates per-action authorization, mediates credentials, enforces budgets, and produces a tamper-evident log. Sandboxing alone satisfies one of the twelve.",
    },
    {
      q: "How is this different from a policy engine like OPA?",
      a: "OPA evaluates rules. Raxis makes the rules a cryptographic contract whose enforcement on every action is auditable, and binds them to identity, hierarchy, budgets, and an out-of-band escalation channel. OPA can be a building block inside a Raxis kernel.",
    },
    {
      q: "Does this only work for coding agents?",
      a: "The reference implementation is for coding agents because that is the hardest domain we could pick: highest stakes, strongest ground truth, every invariant under load. The paradigm is independent of domain. Other implementations could exist. We hope to see Raxis in healthcare (agents authorising diagnostic actions and treatment plans), financial trading systems (agents placing orders within cryptographically bounded mandates), legal discovery (agents retrieving and summarising documents under strict privilege controls), and critical infrastructure (agents issuing configuration changes to power, water, or network systems). Any domain where an autonomous system takes consequential actions on behalf of a human principal is a candidate.",
    },
    {
      q: "What does it not do?",
      a: "It does not verify the semantic correctness of the agent's output. Tests, code review, and operator approval gates exist for that. It does not substitute for measured boot, signed builds, or hardware roots of trust. Those belong alongside it.",
    },
  ];
  return (
    <Section bleed title="Common questions">
      <div className="divide-y divide-[var(--rule)] border-y border-[var(--rule)]">
        {qs.map((it) => (
          <div
            key={it.q}
            className="py-7 grid gap-4 sm:grid-cols-[16rem_minmax(0,1fr)] sm:gap-12"
          >
            <h3 className="text-[1.1875rem] font-semibold text-[var(--fg)] tracking-[-0.01em]">
              {it.q}
            </h3>
            <p className="text-[var(--muted)] leading-relaxed">{it.a}</p>
          </div>
        ))}
      </div>
    </Section>
  );
}

function CTA() {
  return (
    <section className="border-t border-[var(--rule)] py-20 sm:py-24">
      <div className="mx-auto max-w-5xl px-4 sm:px-6">
        <h2 className="h-section max-w-3xl">
          Read the spec, run a scenario, file an issue
        </h2>
        <p className="lead mt-4 max-w-2xl">
          Twelve invariants written down so they can be argued with. A working
          implementation so the paradigm is buildable. Both are open.
        </p>
        <div className="mt-10 flex flex-wrap items-center gap-4">
          <Link href="/paradigm" className="btn btn-primary">
            Read the paradigm
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
