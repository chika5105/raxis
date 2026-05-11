import type { Metadata } from "next";
import Link from "next/link";
import { Section } from "@/components/Section";
import { PageHeader } from "@/components/PageHeader";

export const metadata: Metadata = {
  title: "About",
  description:
    "Raxis was developed by Chika Jinanwa as a sibling project to Aegis. The origin, the rename from CJBrain, and an open invitation to break the paradigm.",
};

export default function AboutPage() {
  return (
    <>
      <PageHeader
        eyebrow="About"
        title="Where Raxis comes from"
        lead={
          <>
            Raxis was developed by{" "}
            <span className="text-[var(--fg)] font-semibold">
              Chika Jinanwa
            </span>
            . The architecture emerged while building{" "}
            <a
              href="https://tryaegis.io"
              target="_blank"
              rel="noopener noreferrer"
              className="text-accent hover:underline underline-offset-4"
            >
              Aegis
            </a>
            , reliability software for ML infrastructure. That is where the
            connection ends; the paradigm stands on its own.
          </>
        }
      />
      <Origin />
      <Lineage />
      <Gaps />
      <CTA />
    </>
  );
}

function Origin() {
  return (
    <Section
      title="The architecture earned the term"
      divider={false}
      className="pt-20"
    >
      <div className="reading space-y-6 leading-relaxed text-[var(--fg)]">
        <p>
          The system was first sketched as <em>CJBrain</em> while building
          Aegis and trying to use coding agents at the speed Aegis required.
          The agents were almost right often enough to be dangerous: changes
          that compiled and looked fine on review but missed edge cases,
          agents that wandered outside task scope, agents that claimed tests
          passed when they had not run.
        </p>
        <p>
          None of that was the model&rsquo;s fault. The architecture had no
          enforcement layer. The agent was simultaneously the worker, the
          authority, and the verifier. That is a shared-delusion loop. It
          cannot be fixed with better prompting.
        </p>
        <p>
          The fix was structural. Privilege-separated processes, applied to
          LLM output the same way OpenSSH applies them to network bytes.
          Operator-signed plans. Independent verifier subprocesses.
          Append-only, hash-chained audit. Worst-case budgets reserved at
          intent time, not hoped for at runtime.
        </p>
        <p>
          When the spec hardened, a pattern surfaced that had not been
          labeled at the start: every engineering decision lined up with what
          is now called{" "}
          <em>Runtime Attestation eXchange for Intelligent Systems</em>.
          Before side effects land in a shared environment, an intelligent
          system has to exchange cryptographically checkable attestations at
          runtime, and a verifier outside the proposer&rsquo;s trust boundary
          gets a vote. CJBrain became Raxis.
        </p>
      </div>
    </Section>
  );
}

function Lineage() {
  return (
    <Section
      bleed
      title="From OpenSSH and Chrome to AI agents"
      lead="The process architecture is not a novel idea. It is a deliberate application of privilege separation, a security principle with a long track record in systems software."
    >
      <dl className="space-y-0">
        <div className="border-b border-[var(--rule)] py-6">
          <dt className="h-sub">OpenSSH</dt>
          <dd className="mt-3 text-[var(--muted)] leading-relaxed">
            Splits into a privileged monitor and an unprivileged child. The
            monitor holds the private keys; the child does the parsing and
            I/O. Compromise of the child cannot yield the keys because they
            are never in its address space.
          </dd>
        </div>
        <div className="border-b border-[var(--rule)] py-6">
          <dt className="h-sub">Google Chrome</dt>
          <dd className="mt-3 text-[var(--muted)] leading-relaxed">
            Runs each tab in a sandboxed renderer with no direct OS access.
            The browser kernel mediates all privileged operations. A
            compromised renderer cannot escalate without defeating the kernel
            layer.
          </dd>
        </div>
        <div className="border-b border-[var(--rule)] py-6">
          <dt className="h-sub">OpenBSD pledge / unveil</dt>
          <dd className="mt-3 text-[var(--muted)] leading-relaxed">
            Lets processes declare the minimal capability set they need at
            startup. The kernel enforces that ceiling for the rest of the
            process lifetime.
          </dd>
        </div>
      </dl>
      <p className="mt-10 max-w-3xl text-[var(--muted)] leading-relaxed">
        The common structure: an unprivileged worker handles untrusted input,
        a privileged supervisor makes authority decisions, the two
        communicate through a narrow typed channel. Raxis applies it
        exactly. The &ldquo;untrusted input&rdquo; is LLM output.
      </p>
    </Section>
  );
}

function Gaps() {
  const items = [
    [
      "No hardware root of trust",
      "The kernel binary is assumed honest. A serious deployment eventually wants TPM, enclave, or FIDO-class anchors.",
    ],
    [
      "No model identity attestation",
      "The planner holds a session, not a cryptographic identity. Swap weights or providers behind the same API and the kernel cannot tell.",
    ],
    [
      "Retrospective, not prospective attestation",
      "v1 is largely commit-then-verify. A tighter protocol would pre-authorize compute before it runs.",
    ],
    [
      "No interoperability standard yet",
      "The schema is internal: not W3C Verifiable Credentials, not RATS (RFC 9334), not DICE.",
    ],
    [
      "Semantic effect verification is out of scope",
      "Raxis bounds what the agent did; it does not prove the change matches what the English meant.",
    ],
  ];
  return (
    <Section
      title="A roadmap, not a finished product"
      lead="A complete Raxis story wants things one repository cannot deliver by itself. The current reference implementation has known gaps that a future paradigm revision will close."
    >
      <dl className="space-y-0">
        {items.map(([h, b]) => (
          <div
            key={h}
            className="grid gap-2 sm:grid-cols-[20rem_minmax(0,1fr)] sm:gap-10 border-b border-[var(--rule)] py-6"
          >
            <dt className="text-[1.0625rem] font-semibold tracking-[-0.01em] text-[var(--fg)]">
              {h}
            </dt>
            <dd className="text-[var(--muted)] leading-relaxed">{b}</dd>
          </div>
        ))}
      </dl>
      <p className="mt-10 max-w-3xl text-[var(--muted)] leading-relaxed">
        These gaps are stated openly so the conversation about the next
        paradigm revision can start from facts.
      </p>
    </Section>
  );
}

function CTA() {
  return (
    <section className="border-t border-[var(--rule)] py-20 sm:py-24">
      <div className="mx-auto max-w-5xl px-4 sm:px-6">
        <h2 className="h-section max-w-3xl">Critique is welcome</h2>
        <p className="lead mt-4 max-w-2xl">
          The paradigm spec, the conformance test suite, and the reference
          implementation are all open. The steel-man critique against Raxis
          lives in the repo too, alongside the structured response.
        </p>
        <div className="mt-10 flex flex-wrap items-center gap-4">
          <Link href="/docs" className="btn btn-primary">
            Read the spec
          </Link>
          <a
            href="https://github.com/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-base text-[var(--fg)] hover:text-accent underline underline-offset-4 decoration-[var(--rule)] hover:decoration-accent transition"
          >
            File an issue on GitHub
          </a>
          <a
            href="https://tryaegis.io"
            target="_blank"
            rel="noopener noreferrer"
            className="text-base text-[var(--fg)] hover:text-accent underline underline-offset-4 decoration-[var(--rule)] hover:decoration-accent transition"
          >
            Visit Aegis
          </a>
        </div>
      </div>
    </section>
  );
}
