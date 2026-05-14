import type { Metadata } from "next";
import Link from "next/link";
import { Section } from "@/components/Section";
import { PageHeader } from "@/components/PageHeader";
import { InvariantsGrid } from "@/components/InvariantsGrid";

export const metadata: Metadata = {
  title: "The paradigm",
  description:
    "Raxis is a paradigm for autonomous-system safety, defined by twelve structural invariants. A deliberate extension of Lampson's 1974 protection model into the era of intelligent subjects.",
};

export default function ParadigmPage() {
  return (
    <>
      <PageHeader
        eyebrow="The paradigm"
        title="Raxis is a paradigm. The codebase is one implementation of it."
        lead={
          <>
            The paradigm is twelve structural invariants any Raxis
            implementation must satisfy. The current Rust workspace is one
            reference implementation, applied to autonomous software
            engineering. Other implementations could exist; all Raxis
            implementations satisfy the same twelve.
          </>
        }
      />
      <Lineage />
      <FullList />
      <CTA />
    </>
  );
}

function Lineage() {
  return (
    <Section title="A 52-year line of thought" divider={false} className="pt-20">
      <div className="reading space-y-6 leading-relaxed text-[var(--fg)]">
        <p>
          In 1974, Butler Lampson published &ldquo;Protection&rdquo; in ACM
          SIGOPS <em>Operating Systems Review</em>. It introduced the access
          control matrix, capabilities, ACLs, and the principle that
          protection is what a <em>reference monitor</em> enforces when it
          mediates every access between subjects and objects. Every modern OS
          security primitive, POSIX permissions, Linux capabilities, seL4,
          Capsicum, the iOS sandbox, is a descendant of that paper.
        </p>
        <p>
          Lampson&rsquo;s model assumed one thing implicitly: subjects are
          deterministic programs. A process either has the capability or it
          does not. Its behavior is bounded by the code humans wrote into it.
          That assumption held for fifty years. It does not hold for AI
          agents. The subject is now probabilistic, emergent, possibly
          adversarial, and changes behavior based on inputs nobody can fully
          anticipate.
        </p>
        <p>
          Raxis is a deliberate extension of Lampson&rsquo;s protection model
          into the era of intelligent subjects. It keeps everything
          Lampson&rsquo;s model gave us and adds what the original did not
          need: hypervisor-grade isolation because the subject can no longer
          be trusted to respect process boundaries; cryptographic capability
          signing because policy must be defensible to a third party who does
          not trust the host filesystem; tamper-evident audit chained across
          decisions because retrospective verification is now load-bearing;
          opaque rejection because an adversarial subject can converge on the
          boundary of permitted behavior; out-of-band escalation because
          static authority is unworkable for emergent work but every channel
          the subject can read is a channel it can manipulate; and mediated
          coordination because multi-agent flows preserve the audit chain only
          when every cross-agent message also passes through authority.
        </p>
        <p>
          The other seven invariants are Lampson&rsquo;s contribution, made
          explicit and enforceable for the new threat model. Raxis is what
          protection looks like when the subject is intelligent.
        </p>
      </div>
    </Section>
  );
}

function FullList() {
  return (
    <Section
      title="The twelve in full"
      lead="A system claiming to be Raxis satisfies all twelve. Each statement, the rationale for it, and how the reference implementation enforces it."
    >
      <InvariantsGrid />
    </Section>
  );
}

function CTA() {
  return (
    <section className="border-t border-[var(--rule)] py-20 sm:py-24">
      <div className="mx-auto max-w-5xl px-4 sm:px-6">
        <h2 className="h-section max-w-3xl">
          See the implementation, or read the threat model
        </h2>
        <p className="lead mt-4 max-w-2xl">
          A working Rust workspace enforces every invariant on real autonomous
          software engineering work. The threat model explains the assumption
          stack the twelve are derived from.
        </p>
        <div className="mt-10 flex flex-wrap items-center gap-4">
          <Link href="/reference" className="btn btn-primary">
            Reference implementation
          </Link>
          <Link
            href="/threat-model"
            className="text-base text-[var(--fg)] hover:text-accent underline underline-offset-4 decoration-[var(--rule)] hover:decoration-accent transition"
          >
            Threat model
          </Link>
        </div>
      </div>
    </section>
  );
}
