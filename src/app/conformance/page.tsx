import type { Metadata } from "next";
import Link from "next/link";
import { Section } from "@/components/Section";
import { PageHeader } from "@/components/PageHeader";

export const metadata: Metadata = {
  title: "Conformance",
  description:
    "Three tiers of evidence for Raxis conformance, modeled on FIPS 140 and Common Criteria. The unqualified phrase 'Raxis-Verified' is reserved for tier 3.",
};

export default function ConformancePage() {
  return (
    <>
      <PageHeader
        eyebrow="Conformance"
        title="Three tiers of evidence"
        lead={
          <>
            Most claims about AI safety carry no evidentiary requirement.
            Raxis does. The paradigm spec defines three conformance tiers
            with progressively stronger evidence, modeled on the same
            structure used by FIPS 140 cryptographic module validation labs
            and Common Criteria evaluation labs. The unqualified phrase
            &ldquo;Raxis-Verified&rdquo; is reserved for tier 3 only.
          </>
        }
      />
      <Tiers />
      <Tests />
      <Verifiers />
      <Status />
    </>
  );
}

function Tiers() {
  const tiers = [
    {
      tier: "1",
      name: "Aligned",
      verification: "Self-attested",
      evidence:
        "Public conformance statement mapping each of the twelve invariants to its enforcement mechanism, plus an architectural diagram of the intelligence/authority boundary.",
      use: "Early-stage implementations, research prototypes, Raxis adapted to a new domain.",
    },
    {
      tier: "2",
      name: "Tested",
      verification: "Self-tested with an open conformance suite",
      evidence:
        "Tier 1 plus the canonical Raxis conformance test suite passes (positive and adversarial cases for every invariant).",
      use: "Production-bound implementations seeking engineered, demonstrable conformance.",
    },
    {
      tier: "3",
      name: "Verified",
      verification: "Independent third-party audit, annual re-audit",
      evidence:
        "Tier 2 plus independent third-party audit by a qualified verifier covering source-code audit of the authority layer, isolation soundness review, audit-format conformance, credential-isolation pen-test, and policy artifact format conformance.",
      use: "Regulated deployments, customer-facing claims, contractual conformance commitments.",
    },
  ];
  return (
    <Section title="The tiers" divider={false} className="pt-20">
      <div className="space-y-14">
        {tiers.map((t) => (
          <article
            key={t.tier}
            className="grid gap-6 md:grid-cols-[12rem_minmax(0,1fr)]"
          >
            <div>
              <div className="text-sm tabular-nums text-[var(--soft)]">
                Tier {t.tier}
              </div>
              <h3 className="mt-1 h-sub">{t.name}</h3>
              <div className="mt-2 text-sm text-[var(--muted)]">
                {t.verification}
              </div>
            </div>
            <div className="space-y-3 leading-relaxed text-[var(--muted)]">
              <p>
                <span className="text-[var(--fg)] font-semibold">
                  Evidence.{" "}
                </span>
                {t.evidence}
              </p>
              <p>
                <span className="text-[var(--fg)] font-semibold">
                  Use case.{" "}
                </span>
                {t.use}
              </p>
            </div>
          </article>
        ))}
      </div>
    </Section>
  );
}

function Tests() {
  const cats = [
    [
      "Separation",
      "Verify intelligence cannot read authority memory, cannot bypass IPC, cannot reach storage directly.",
    ],
    [
      "Capability",
      "Verify undeclared capabilities are denied; adversarial intent submissions claiming undeclared capabilities.",
    ],
    [
      "Hierarchy",
      "Verify sub-artifacts cannot exceed parent authority; attempted plan-widening.",
    ],
    [
      "Bounds",
      "Verify every capability hits its bound; deliberate overage attempts.",
    ],
    [
      "Fail-closed",
      "Verify denial under fault injection: missing policy, IPC timeout, audit failure.",
    ],
    [
      "Audit chain",
      "Verify single-byte tampering is detected; random mutation of audit segments.",
    ],
    [
      "Reproducibility",
      "Verify the audit replay tool reproduces recorded decisions byte-for-byte.",
    ],
    [
      "Identity",
      "Verify unauthenticated intents are rejected before any admission logic runs.",
    ],
    [
      "Opacity",
      "Verify rejection codes do not leak rule structure; timing-based information leak tests.",
    ],
    [
      "Coordination",
      "Verify no inter-agent IPC primitive exists outside authority mediation.",
    ],
    [
      "Escalation",
      "Verify the escalation channel cannot be reached or forged by intelligence.",
    ],
  ];
  return (
    <Section
      bleed
      title="What gets tested at tier 2"
      lead="Eleven test categories exercise every invariant with both positive cases (action correctly admitted) and adversarial cases (action correctly denied despite attempted bypass). The suite is maintained as an independent repository so updates are decoupled from any single implementation's release cycle."
    >
      <dl className="grid gap-x-10 gap-y-9 sm:grid-cols-2 lg:grid-cols-3">
        {cats.map(([h, b]) => (
          <div key={h}>
            <dt className="text-[1.0625rem] font-semibold tracking-[-0.01em] text-[var(--fg)]">
              {h}
            </dt>
            <dd className="mt-2 text-[var(--muted)] leading-relaxed text-[0.95rem]">
              {b}
            </dd>
          </div>
        ))}
      </dl>
    </Section>
  );
}

function Verifiers() {
  const items = [
    [
      "Independence",
      "No financial relationship with the implementation under audit other than the audit fee.",
    ],
    [
      "Methodology transparency",
      "Published audit methodology open to community review: which test cases beyond the canonical suite, what penetration tests, how each invariant is evaluated.",
    ],
    [
      "Reproducibility",
      "Findings reproducible by a second independent verifier given the same source tree and methodology.",
    ],
    [
      "Conflict disclosure",
      "Disclosure of prior or ongoing engagements with the implementation team or its dependencies.",
    ],
    [
      "Certification",
      "Verifiers themselves certified by the Raxis specification body (initially the maintainers, later a neutral standards body).",
    ],
  ];
  return (
    <Section
      title="Qualified verifiers"
      lead="To prevent the verification ecosystem from collapsing into a self-certifying cartel, qualified verifiers satisfy five criteria, the same model used by FIPS 140 validation labs, Common Criteria evaluation labs, and SOC 2 auditors."
    >
      <dl className="space-y-0">
        {items.map(([h, b]) => (
          <div
            key={h}
            className="grid gap-2 sm:grid-cols-[16rem_minmax(0,1fr)] sm:gap-10 border-b border-[var(--rule)] py-6"
          >
            <dt className="text-[1.0625rem] font-semibold tracking-[-0.01em] text-[var(--fg)]">
              {h}
            </dt>
            <dd className="text-[var(--muted)] leading-relaxed">{b}</dd>
          </div>
        ))}
      </dl>
    </Section>
  );
}

function Status() {
  return (
    <Section bleed title="Status of the reference implementation">
      <dl className="grid gap-10 md:grid-cols-3">
        <div>
          <dt className="text-sm tabular-nums text-accent uppercase tracking-wider">
            Tier 1, current
          </dt>
          <dd className="mt-3 text-[var(--muted)] leading-relaxed">
            Architectural mechanisms for all twelve invariants are present
            and documented. The mapping from R-invariants to implementation
            mechanisms is published.
          </dd>
        </div>
        <div>
          <dt className="text-sm tabular-nums text-amber-500 uppercase tracking-wider">
            Tier 2, partial
          </dt>
          <dd className="mt-3 text-[var(--muted)] leading-relaxed">
            Extensive INV-* test coverage exists in this codebase, but the
            canonical paradigm conformance test suite is v3 GA scope.
            Adapting the canonical suite is concrete work that has not yet
            shipped.
          </dd>
        </div>
        <div>
          <dt className="text-sm tabular-nums text-[var(--soft)] uppercase tracking-wider">
            Tier 3, not claimed
          </dt>
          <dd className="mt-3 text-[var(--muted)] leading-relaxed">
            Independent third-party audit has not been performed. Tier 3
            requires both the canonical conformance suite to be adopted and
            a qualified verifier engagement.
          </dd>
        </div>
      </dl>
      <p className="mt-12 text-base text-[var(--muted)]">
        <Link
          href="/about"
          className="text-accent hover:underline underline-offset-4"
        >
          Read about the open paradigm gaps →
        </Link>
      </p>
    </Section>
  );
}
