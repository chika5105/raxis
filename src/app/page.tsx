import Link from "next/link";
import { Section } from "@/components/Section";
import { Card } from "@/components/Card";
import { InvariantsGrid } from "@/components/InvariantsGrid";
import { StackDiagram } from "@/components/StackDiagram";
import { FlowDiagram } from "@/components/FlowDiagram";
import { ConformanceTable } from "@/components/ConformanceTable";

export default function HomePage() {
  return (
    <>
      <Hero />
      <ThreatTriad />
      <Section
        eyebrow="The 12 invariants"
        title="A paradigm in twelve structural requirements."
        lead="Every RAXIS implementation, in every domain, on any tech stack, satisfies these. Drop one and you have something else — possibly useful, but no longer RAXIS."
      >
        <InvariantsGrid compact />
        <div className="mt-10 text-center">
          <Link
            href="/paradigm"
            className="inline-flex items-center gap-1.5 text-sm font-medium text-accent hover:underline underline-offset-4"
          >
            Read the full statements with rationale and verification
            <span aria-hidden>→</span>
          </Link>
        </div>
      </Section>
      <Section
        bleed
        eyebrow="In practice"
        title="How a piece of work flows through RAXIS."
        lead="The kernel is the constraint enforcer at every step. The agent is the proposer. The operator is the only authority that can widen what is allowed."
      >
        <FlowDiagram />
      </Section>
      <Section
        eyebrow="Where it sits"
        title="The missing layer between agent frameworks and isolation runtimes."
        lead="Frameworks orchestrate intelligence; they do not enforce authority. Isolation runtimes contain a process; they do not gate per-action authorization or produce non-repudiable audit. RAXIS is the layer in between."
      >
        <StackDiagram />
        <div className="mt-12 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {[
            ["Not alignment", "Alignment improves the model's intent. RAXIS governs the model's actions. Use both."],
            ["Not a sandbox", "Sandboxes contain a process. RAXIS contains the authority surface. Sandboxing alone satisfies 1 of 12 invariants."],
            ["Not a framework", "Frameworks help you build an agent. RAXIS lets you deploy one without losing sleep."],
            ["Not a policy engine", "OPA evaluates rules. RAXIS makes the rules a cryptographic contract whose enforcement on every action is auditable."],
          ].map(([title, body]) => (
            <Card key={title} className="text-sm">
              <h4 className="font-semibold tracking-tight">{title}.</h4>
              <p className="mt-2 text-[var(--muted)] leading-relaxed">{body}</p>
            </Card>
          ))}
        </div>
      </Section>
      <ReferencePitch />
      <Section
        bleed
        eyebrow="What conformance means"
        title="Three tiers of evidence. Modeled on FIPS 140 and Common Criteria."
        lead='Most "AI safety" claims have no evidentiary requirement. RAXIS does. The unqualified phrase "RAXIS-Verified" is reserved for Tier 3.'
      >
        <ConformanceTable />
        <p className="mt-8 max-w-3xl text-sm text-[var(--muted)] leading-relaxed">
          <span className="font-medium text-[var(--fg)]">Status of the current reference implementation:</span>{" "}
          Tier 1 — Aligned. Architectural mechanisms for all twelve invariants are present and documented. Partial Tier 2 —
          extensive invariant test coverage in this codebase, with the canonical conformance suite as v3 GA scope. Tier 3 is
          not currently claimed.
        </p>
      </Section>
      <CTA />
    </>
  );
}

function Hero() {
  return (
    <section className="relative isolate overflow-hidden">
      <div aria-hidden className="pointer-events-none absolute inset-0 bg-grid" />
      <div className="relative mx-auto max-w-6xl px-4 sm:px-6 pt-20 sm:pt-28 pb-20 sm:pb-24">
        <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent animate-fade-in-up">
          Runtime Attestation eXchange for Intelligent Systems
        </p>
        <h1 className="mt-4 text-4xl sm:text-6xl font-semibold tracking-[-0.02em] leading-[1.05] max-w-4xl animate-fade-in-up">
          AI agents:{" "}
          <span className="text-[var(--fg)]">authorized actions only,</span>{" "}
          <span className="text-accent">fully audited.</span>
        </h1>
        <p className="mt-6 max-w-2xl text-lg sm:text-xl text-[var(--muted)] leading-relaxed animate-fade-in-up">
          RAXIS is the structural enforcement layer between AI intelligence and authority — the OS kernel
          for autonomous agents. A 12-invariant paradigm extending Lampson's 1974 capability-based protection model
          into the era of probabilistic, adversarial intelligence. Proven in a working reference implementation
          for autonomous software engineering.
        </p>
        <div className="mt-6 max-w-2xl space-y-2 text-[var(--muted)] animate-fade-in-up">
          <p className="text-base">
            Agents propose. The kernel admits. Every action signed at the front; every decision hash-chained at the back.
          </p>
          <p className="text-base">
            Built so you can delegate to AI agents the way you delegate to people — with a chain of authority you can
            defend in front of a regulator, a board, or a court.
          </p>
        </div>
        <div className="mt-10 flex flex-wrap items-center gap-3 animate-fade-in-up">
          <Link
            href="/paradigm"
            className="inline-flex h-11 items-center justify-center rounded-md bg-accent px-5 text-sm font-medium text-white hover:bg-accent-strong transition shadow-sm"
          >
            Read the 12 invariants
          </Link>
          <Link
            href="/reference"
            className="inline-flex h-11 items-center justify-center rounded-md border border-[var(--rule)] px-5 text-sm font-medium text-[var(--fg)] hover:border-[var(--fg)] transition"
          >
            See the reference implementation
          </Link>
          <Link
            href="/docs"
            className="inline-flex h-11 items-center justify-center px-2 text-sm text-[var(--muted)] hover:text-[var(--fg)]"
          >
            Browse the spec →
          </Link>
        </div>

        {/* The four pillar metrics under the hero */}
        <dl className="mt-16 grid grid-cols-2 gap-px bg-[var(--rule)] border border-[var(--rule)] rounded-xl overflow-hidden md:grid-cols-4 animate-fade-in-up">
          {[
            { k: "12", v: "Paradigm invariants", s: "Structural, independent, non-negotiable." },
            { k: "8", v: "Intent kinds", s: "Every agent action is one of these. No side channels." },
            { k: "10", v: "Credential proxies", s: "Postgres, MySQL, MSSQL, Mongo, Redis, HTTP, SMTP, AWS, GCP, Azure." },
            { k: "50+", v: "Reproducible scenarios", s: "From hello-world to a full feature shipment." },
          ].map((it) => (
            <div key={it.v} className="bg-[var(--bg)] p-5">
              <dt className="font-mono text-3xl font-semibold tracking-tight text-[var(--fg)]">{it.k}</dt>
              <dd className="mt-1 text-sm font-medium text-[var(--fg)]">{it.v}</dd>
              <dd className="mt-0.5 text-xs text-[var(--muted)] leading-relaxed">{it.s}</dd>
            </div>
          ))}
        </dl>
      </div>
    </section>
  );
}

function ThreatTriad() {
  return (
    <Section
      eyebrow="The threat model"
      title="One assumption stack. No others."
      lead="RAXIS makes one set of assumptions and refuses to make any other. Everything in the architecture follows from this triad."
    >
      <div className="grid gap-4 lg:grid-cols-3">
        <Card hoverable className="bg-gradient-to-br from-[var(--card)] to-[var(--card)]">
          <div className="font-mono text-xs uppercase tracking-wider text-red-500/90">Adversarial</div>
          <h3 className="mt-3 text-xl font-semibold tracking-tight">Agents are adversarial.</h3>
          <p className="mt-3 text-sm leading-relaxed text-[var(--muted)]">
            Not because every model is malicious — but because we cannot tell the difference at runtime. An LLM may
            hallucinate, be prompt-injected by a file it reads, be silently swapped for an adversarial fine-tune, or simply
            be confidently wrong in a way that looks correct on review. RAXIS's safety properties hold whether or not any
            of this is true.
          </p>
        </Card>
        <Card hoverable>
          <div className="font-mono text-xs uppercase tracking-wider text-amber-500/90">Fallible</div>
          <h3 className="mt-3 text-xl font-semibold tracking-tight">Operators may make mistakes.</h3>
          <p className="mt-3 text-sm leading-relaxed text-[var(--muted)]">
            A misnamed credential. A glob that matches more than intended. A plan signed under pressure that grants
            more than it should. RAXIS narrows the blast radius of operator error with bounded capabilities, fail-closed
            defaults, hierarchical authority that can only narrow — and an audit chain that makes mistakes recoverable
            rather than catastrophic.
          </p>
        </Card>
        <Card hoverable>
          <div className="font-mono text-xs uppercase tracking-wider text-accent">Trusted</div>
          <h3 className="mt-3 text-xl font-semibold tracking-tight">The kernel binary and host OS are trusted.</h3>
          <p className="mt-3 text-sm leading-relaxed text-[var(--muted)]">
            RAXIS is honest about its trust root. The kernel is a single Rust binary; the host OS is whatever you
            boot. Compromise of either invalidates the model — and that is where hardware roots of trust, signed
            builds, and confidential computing belong in your stack, not where RAXIS pretends to substitute for them.
          </p>
        </Card>
      </div>
      <div className="mt-10 max-w-3xl">
        <p className="text-[var(--muted)]">
          Everything in the architecture follows from that triad. The 12 invariants are the structural consequences.{" "}
          <Link href="/threat-model" className="text-accent underline underline-offset-4 hover:no-underline">
            Read the full threat model →
          </Link>
        </p>
      </div>
    </Section>
  );
}

function ReferencePitch() {
  return (
    <Section
      eyebrow="Reference implementation"
      title={<>A paradigm without a working implementation is a manifesto.</>}
      lead="RAXIS ships with a complete reference implementation in the hardest domain we could pick: autonomous software engineering. Agents that read code, write code, run tests, and integrate changes into a real git repository."
    >
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <h3 className="font-semibold tracking-tight">The highest-stakes agent domain</h3>
          <p className="mt-3 text-sm leading-relaxed text-[var(--muted)]">
            Coding agents (Cursor, Claude Code, Codex, Devin) are the most-deployed, most-capability-rich agent class in
            production. They touch source code, hold cloud credentials, push to production. If RAXIS can constrain a
            coding agent without breaking it, every other domain is downhill from there.
          </p>
        </Card>
        <Card>
          <h3 className="font-semibold tracking-tight">Perfect ground truth</h3>
          <p className="mt-3 text-sm leading-relaxed text-[var(--muted)]">
            When the agent claims "I implemented the change," the kernel can verify mechanically: it runs{" "}
            <code className="px-1 rounded bg-[var(--code-bg)] font-mono text-xs">git diff</code> itself; spawns a verifier
            subprocess that runs the actual tests; binds the witness blob to the commit SHA. The agent cannot self-certify.
          </p>
        </Card>
        <Card>
          <h3 className="font-semibold tracking-tight">Every invariant under load</h3>
          <p className="mt-3 text-sm leading-relaxed text-[var(--muted)]">
            Every agent runs in a Firecracker (Linux) or Apple Virtualization.framework (macOS) microVM. Every commit is
            path-checked. Every credential lives behind a protocol-aware proxy. Every escalation needs an Ed25519 signature
            from a key the agent has no path to.
          </p>
        </Card>
      </div>
      <div className="mt-12 grid gap-4 lg:grid-cols-2">
        <Card>
          <div className="font-mono text-xs uppercase tracking-wider text-accent">Mediated I/O in production</div>
          <h3 className="mt-2 text-lg font-semibold tracking-tight">
            Protocol-aware credential proxies for ten backends.
          </h3>
          <p className="mt-3 text-sm leading-relaxed text-[var(--muted)]">
            Postgres, MySQL, MSSQL, MongoDB, Redis, HTTP, SMTP, AWS IMDS, GCP metadata, Azure IMDS. The agent connects to
            <code className="mx-1 px-1 rounded bg-[var(--code-bg)] font-mono text-xs">localhost:PORT</code>; the kernel
            inspects every query against an allowlist (<em>SELECT</em> only, only on tables{" "}
            <em>users</em> and <em>orders</em>, max 1000 rows), audits each one, and forwards to the real upstream with
            credentials the agent never sees.
          </p>
        </Card>
        <Card>
          <div className="font-mono text-xs uppercase tracking-wider text-accent">Reproducible at every scale</div>
          <h3 className="mt-2 text-lg font-semibold tracking-tight">
            Fifty documented scenarios — from hello-world to a full feature shipment.
          </h3>
          <p className="mt-3 text-sm leading-relaxed text-[var(--muted)]">
            One Executor writing one file; parallel decomposition with three Reviewers debating quality; mechanical
            witnesses (cargo build, cargo test, clippy, curl-against-dev-server); operator-approved integration merge.
            Each scenario is reproducible end-to-end against a live kernel.
          </p>
        </Card>
      </div>
      <div className="mt-10">
        <Link
          href="/reference"
          className="inline-flex items-center gap-1.5 text-sm font-medium text-accent hover:underline underline-offset-4"
        >
          Read the reference architecture <span aria-hidden>→</span>
        </Link>
      </div>
    </Section>
  );
}

function CTA() {
  return (
    <section className="border-t border-[var(--rule)] py-20 sm:py-24">
      <div className="mx-auto max-w-4xl px-4 sm:px-6 text-center">
        <h2 className="text-3xl sm:text-4xl font-semibold tracking-tight">
          Authority is what makes delegation real.
        </h2>
        <p className="mt-4 max-w-2xl mx-auto text-lg text-[var(--muted)]">
          The point of writing the 12 invariants down is to give serious people something specific to break. The point of
          shipping a reference implementation is to prove the paradigm is buildable. Read the spec, run a scenario, file
          an issue.
        </p>
        <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
          <Link
            href="/paradigm"
            className="inline-flex h-11 items-center justify-center rounded-md bg-accent px-5 text-sm font-medium text-white hover:bg-accent-strong transition"
          >
            Read the paradigm
          </Link>
          <Link
            href="/docs"
            className="inline-flex h-11 items-center justify-center rounded-md border border-[var(--rule)] px-5 text-sm font-medium text-[var(--fg)] hover:border-[var(--fg)] transition"
          >
            Browse the documentation
          </Link>
          <a
            href="https://github.com/"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex h-11 items-center justify-center rounded-md border border-[var(--rule)] px-5 text-sm font-medium text-[var(--fg)] hover:border-[var(--fg)] transition"
          >
            Source on GitHub
          </a>
        </div>
      </div>
    </section>
  );
}
