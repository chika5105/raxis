import type { Metadata } from "next";
import Link from "next/link";
import { Section } from "@/components/Section";
import { Card } from "@/components/Card";
import { ConformanceTable } from "@/components/ConformanceTable";

export const metadata: Metadata = {
  title: "Conformance",
  description:
    "Three tiers of evidence for RAXIS conformance. Modeled on FIPS 140 cryptographic module validation labs and Common Criteria. The unqualified phrase 'RAXIS-Verified' is reserved for Tier 3.",
};

export default function ConformancePage() {
  return (
    <>
      <header className="border-b border-[var(--rule)] py-16 sm:py-20 bg-[var(--card)]">
        <div className="mx-auto max-w-6xl px-4 sm:px-6">
          <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">
            Conformance
          </p>
          <h1 className="mt-4 max-w-3xl text-4xl sm:text-5xl font-semibold tracking-[-0.02em] leading-[1.05]">
            Three tiers of evidence. Modeled on FIPS 140 and Common Criteria.
          </h1>
          <p className="mt-6 max-w-3xl text-lg text-[var(--muted)] leading-relaxed">
            Most "AI safety" claims have no evidentiary requirement. RAXIS does. The paradigm spec defines three
            conformance tiers with progressively stronger evidence — modeled on the same structure used by FIPS 140
            cryptographic module validation labs and Common Criteria evaluation labs.
          </p>
          <p className="mt-4 max-w-3xl text-[var(--muted)] leading-relaxed">
            The unqualified phrase <strong className="text-[var(--fg)]">"RAXIS-Verified" is reserved for Tier 3 only</strong>.
            Lower tiers must be qualified ("RAXIS-Aligned" or "RAXIS-Tested").
          </p>
        </div>
      </header>

      <Section eyebrow="The tiers" title="Each tier requires the previous tier's evidence plus its own.">
        <ConformanceTable />
      </Section>

      <Section
        bleed
        eyebrow="What gets tested at Tier 2"
        title="The conformance test suite — eleven categories, every invariant."
        lead="The canonical RAXIS conformance test suite exercises each of the 12 invariants with both positive cases (action correctly admitted) and adversarial cases (action correctly denied despite attempted bypass). It is maintained as an independent repository so test updates are decoupled from any single implementation's release cycle."
      >
        <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
          {[
            ["Separation tests", "Verify intelligence cannot read authority memory, cannot bypass IPC, cannot reach storage directly. Includes adversarial fuzzing of the IPC protocol."],
            ["Capability tests", "Verify undeclared capabilities are denied. Includes adversarial intent submissions claiming undeclared capabilities."],
            ["Hierarchy tests", "Verify sub-artifacts cannot exceed parent authority. Includes attempted plan-widening."],
            ["Bounds tests", "Verify every capability hits its bound. Includes deliberate overage attempts at every bound type."],
            ["Fail-closed tests", "Verify denial under fault injection — missing policy, IPC timeout, audit failure, etc."],
            ["Audit chain tests", "Verify single-byte tampering is detected. Includes random mutation of audit segments."],
            ["Reproducibility tests", "Verify the audit replay tool reproduces recorded decisions byte-for-byte."],
            ["Identity tests", "Verify unauthenticated intents are rejected before any admission logic executes."],
            ["Opacity tests", "Verify rejection codes do not leak rule structure. Includes timing-based information leak tests."],
            ["Coordination tests", "Verify no inter-agent IPC primitive exists outside authority mediation."],
            ["Escalation tests", "Verify escalation channel cannot be reached or forged by intelligence."],
          ].map(([title, body]) => (
            <Card key={title}>
              <h4 className="font-semibold tracking-tight">{title}</h4>
              <p className="mt-2 text-sm leading-relaxed text-[var(--muted)]">{body}</p>
            </Card>
          ))}
        </div>
      </Section>

      <Section
        eyebrow="Qualified verifiers"
        title="Five requirements. Patterned on existing standards bodies."
        lead="To prevent the verification ecosystem from collapsing into a self-certifying cartel, qualified verifiers must satisfy five criteria — the same model used by FIPS 140 validation labs, Common Criteria evaluation labs, and SOC 2 auditors."
      >
        <div className="grid gap-3 md:grid-cols-2">
          {[
            ["Independence", "The verifier MUST NOT have a financial relationship with the implementation under audit other than the audit fee itself."],
            ["Methodology transparency", "The verifier MUST publish its audit methodology — which conformance test cases are included beyond the canonical suite, what penetration tests are performed, how each invariant is evaluated. Open to community review."],
            ["Reproducibility", "Audit findings MUST be reproducible by a second independent verifier given the same source tree and methodology."],
            ["Conflict disclosure", "The verifier MUST disclose any prior or ongoing engagements with the implementation team or its dependencies."],
            ["Certification", "Verifiers MUST themselves be certified by the RAXIS specification body (initially the maintainers; later a neutral standards body)."],
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
        eyebrow="Status"
        title="Where the current reference implementation stands."
      >
        <div className="reading space-y-4 text-[var(--fg)] leading-relaxed">
          <p>
            <span className="font-mono text-xs px-2 py-0.5 rounded-full bg-accent-soft text-accent border border-accent/30">
              Tier 1 — Aligned
            </span>{" "}
            <span className="ml-2 text-[var(--muted)]">
              Architectural mechanisms for all twelve invariants are present and documented across the spec tree. The
              mapping from R-invariants to implementation mechanisms is published.
            </span>
          </p>
          <p>
            <span className="font-mono text-xs px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-700 dark:text-amber-400 border border-amber-500/30">
              Tier 2 — Partial
            </span>{" "}
            <span className="ml-2 text-[var(--muted)]">
              Extensive INV-* test coverage exists in this codebase, but the canonical paradigm conformance test suite is
              v3 GA scope. Adapting the canonical suite is concrete work that has not yet shipped.
            </span>
          </p>
          <p>
            <span className="font-mono text-xs px-2 py-0.5 rounded-full bg-[var(--code-bg)] text-[var(--muted)] border border-[var(--rule)]">
              Tier 3 — Not claimed
            </span>{" "}
            <span className="ml-2 text-[var(--muted)]">
              Independent third-party audit has not been performed. Tier 3 requires both the canonical conformance suite
              to be adopted (Tier 2) and a qualified verifier engagement.
            </span>
          </p>
          <p>
            The current reference implementation also has acknowledged paradigm gaps that limit its ceiling even at Tier
            3 — no model identity attestation, no hardware root of trust, retrospective rather than prospective
            attestation. These do not violate any invariant as stated; they represent open research problems that would
            strengthen the paradigm itself in a future revision.
          </p>
        </div>
      </Section>
    </>
  );
}
