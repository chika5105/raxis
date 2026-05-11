import type { Metadata } from "next";
import Link from "next/link";
import { Section } from "@/components/Section";
import { InvariantsGrid } from "@/components/InvariantsGrid";
import { ConformanceTable } from "@/components/ConformanceTable";

export const metadata: Metadata = {
  title: "The Paradigm — 12 invariants",
  description:
    "RAXIS is a paradigm for autonomous-system safety, defined by twelve structural invariants. A deliberate extension of Lampson's 1974 protection model into the era of intelligent subjects.",
};

export default function ParadigmPage() {
  return (
    <>
      <header className="border-b border-[var(--rule)] py-16 sm:py-20 bg-[var(--card)]">
        <div className="mx-auto max-w-6xl px-4 sm:px-6">
          <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">
            The Paradigm
          </p>
          <h1 className="mt-4 max-w-3xl text-4xl sm:text-5xl font-semibold tracking-[-0.02em] leading-[1.05]">
            RAXIS is a paradigm. The codebase is one implementation of it.
          </h1>
          <p className="mt-6 max-w-2xl text-lg text-[var(--muted)] leading-relaxed">
            The paradigm is twelve structural invariants any RAXIS implementation must satisfy. The current Rust workspace
            is one reference implementation, applied to autonomous software engineering. Other implementations could
            exist; all RAXIS implementations satisfy the same twelve.
          </p>
        </div>
      </header>

      <Section
        eyebrow="Lineage"
        title="A 52-year line of thought."
        lead="Lampson set the foundations. RAXIS extends them for the era of intelligent subjects."
      >
        <div className="reading space-y-5 text-[var(--fg)] leading-relaxed">
          <p>
            In 1974, Butler Lampson published <em>“Protection”</em> in ACM SIGOPS{" "}
            <em>Operating Systems Review</em> (Vol. 8, No. 1) — one of the founding papers of computer security. It
            introduced the access control matrix, capabilities, ACLs, and the principle that protection is what a{" "}
            <em>reference monitor</em> enforces when it mediates every access between subjects and objects. Every modern
            OS security primitive — POSIX permissions, Linux capabilities, seL4, Capsicum, EROS, even the iOS sandbox —
            is a descendant of that paper.
          </p>
          <p>
            Lampson's model assumed one thing implicitly:{" "}
            <strong>subjects are deterministic programs</strong>. A process either has the capability or it does not. Its
            behavior is bounded by the code humans wrote into it. That assumption held for fifty years.
          </p>
          <p>
            It does not hold for AI agents. The subject is now probabilistic, emergent, possibly adversarial, and changes
            behavior based on inputs nobody can fully anticipate. Lampson's reference monitor is no longer enough — not
            because the monitor is wrong, but because the <em>subject it mediates</em> is a different category of thing.
          </p>
          <p>
            <strong>RAXIS is a deliberate extension of Lampson's protection model into the era of intelligent subjects.</strong>{" "}
            It keeps everything Lampson's model gave us — the matrix, the capabilities, the reference monitor — and adds
            five new requirements that the original model did not need:
          </p>
        </div>

        <div className="mt-8 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {[
            ["Hypervisor-grade subject isolation", "R-1", "The subject can no longer be trusted to respect process boundaries when its behavior is emergent."],
            ["Cryptographic capability signing", "R-3", "Policy must be defensible to a third party who does not trust the host filesystem."],
            ["Tamper-evident audit chained across decisions", "R-7", "Retrospective verification is now a load-bearing safety property, not just an operational nicety."],
            ["Opaque rejection codes", "R-10", "An adversarial subject can converge on the boundary of permitted behavior in a way a deterministic subject cannot."],
            ["Out-of-band escalation", "R-12", "Static authority is unworkable for emergent work, but every channel the subject can read is a channel it can manipulate."],
            ["Mediated coordination between subjects", "R-11", "Multi-agent flows preserve the audit chain only if every cross-agent message also passes through authority."],
          ].map(([title, id, body]) => (
            <div key={id} className="rounded-xl border border-[var(--card-rule)] bg-[var(--card)] p-5">
              <div className="flex items-center justify-between">
                <h4 className="text-sm font-semibold tracking-tight">{title}</h4>
                <span className="font-mono text-[11px] text-accent">{id}</span>
              </div>
              <p className="mt-2 text-sm leading-relaxed text-[var(--muted)]">{body}</p>
            </div>
          ))}
        </div>

        <p className="mt-10 reading text-[var(--muted)] leading-relaxed">
          The other seven invariants are Lampson's contribution — made explicit and enforceable for the new threat model.{" "}
          <strong className="text-[var(--fg)]">RAXIS is what protection looks like when the subject is intelligent.</strong>
        </p>
      </Section>

      <Section
        bleed
        eyebrow="The 12 invariants in full"
        title="Statements, rationale, and how the reference impl enforces each."
        lead="A system claiming to be RAXIS satisfies all twelve. Anything less is not RAXIS — it may be useful, well-engineered, even safer than alternatives, but the paradigm is the conjunction of all twelve."
      >
        <InvariantsGrid />
      </Section>

      <Section
        eyebrow="Conformance"
        title='What "RAXIS-Verified" actually means.'
        lead="Three tiers of evidence, modeled on FIPS 140 cryptographic module validation labs and Common Criteria. The unqualified phrase is reserved for Tier 3."
      >
        <ConformanceTable />
        <div className="mt-10 reading text-sm text-[var(--muted)] leading-relaxed space-y-3">
          <p>
            <span className="font-medium text-[var(--fg)]">Qualified verifiers</span> must satisfy independence (no
            financial relationship beyond the audit fee), methodology transparency (published audit methodology open to
            community review), reproducibility (findings reproducible by a second independent verifier), conflict
            disclosure, and certification by the RAXIS specification body.
          </p>
          <p>
            <span className="font-medium text-[var(--fg)]">Status of the current reference implementation:</span> Tier 1 —
            Aligned. Architectural mechanisms for all twelve invariants are present and documented. Partial Tier 2 —
            extensive invariant test coverage in this codebase, with the canonical conformance suite as v3 GA scope. Tier
            3 is not currently claimed.
          </p>
        </div>
      </Section>

      <section className="border-t border-[var(--rule)] py-16 sm:py-20 bg-[var(--card)]">
        <div className="mx-auto max-w-3xl px-4 sm:px-6 text-center">
          <h2 className="text-2xl sm:text-3xl font-semibold tracking-tight">
            See the reference implementation
          </h2>
          <p className="mt-4 text-[var(--muted)]">
            A working Rust workspace that enforces every invariant on real autonomous software engineering work — agents
            that read code, write code, run tests, and integrate changes into real git repositories.
          </p>
          <div className="mt-6 flex flex-wrap items-center justify-center gap-3">
            <Link
              href="/reference"
              className="inline-flex h-10 items-center justify-center rounded-md bg-accent px-5 text-sm font-medium text-white hover:bg-accent-strong transition"
            >
              Read the architecture
            </Link>
            <Link
              href="/docs"
              className="inline-flex h-10 items-center justify-center rounded-md border border-[var(--rule)] px-5 text-sm font-medium text-[var(--fg)] hover:border-[var(--fg)] transition"
            >
              Browse the spec
            </Link>
          </div>
        </div>
      </section>
    </>
  );
}
