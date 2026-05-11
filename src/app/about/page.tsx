import type { Metadata } from "next";
import Link from "next/link";
import { Section } from "@/components/Section";

export const metadata: Metadata = {
  title: "About",
  description:
    "RAXIS was developed by Chika Jinanwa as a sibling project to Aegis. The origin, the rename from CJBrain, and an open invitation to break the paradigm.",
};

export default function AboutPage() {
  return (
    <>
      <header className="border-b border-[var(--rule)] py-16 sm:py-20 bg-[var(--card)]">
        <div className="mx-auto max-w-6xl px-4 sm:px-6">
          <p className="font-mono text-xs uppercase tracking-[0.18em] text-accent">
            About
          </p>
          <h1 className="mt-4 max-w-3xl text-4xl sm:text-5xl font-semibold tracking-[-0.02em] leading-[1.05]">
            Where RAXIS comes from.
          </h1>
          <p className="mt-6 max-w-2xl text-lg text-[var(--muted)] leading-relaxed">
            RAXIS was developed by <strong className="text-[var(--fg)]">Chika Jinanwa</strong>. It is a sibling project
            to <a className="text-accent underline underline-offset-4" href="https://tryaegis.io" target="_blank" rel="noopener noreferrer">Aegis</a> —
            Chika's earlier work on EDR for AI workloads, where the same design instinct (separation of concerns,
            structural enforcement, evidence over assertion) first showed up in production form.
          </p>
        </div>
      </header>

      <Section eyebrow="Origin" title="The architecture earned the term.">
        <div className="reading space-y-5 text-[var(--fg)] leading-relaxed">
          <p>
            The name has a history. The system was first sketched as <strong>CJBrain</strong> while Chika was building
            Aegis and trying to use coding agents at the speed Aegis required. The agents were <em>almost</em> right
            often enough to be dangerous: changes that compiled and looked fine on review but missed edge cases, agents
            that wandered outside task scope, agents that claimed tests passed when they hadn't run.
          </p>
          <p>
            None of that was the model's fault. The architecture had no enforcement layer. The agent was simultaneously
            the worker, the authority, and the verifier. That is a shared-delusion loop, and it cannot be fixed with
            better prompting.
          </p>
          <p>
            The fix was structural. <strong>Privilege-separated processes</strong> — a worker that handles untrusted
            input, a supervisor that decides what is allowed — applied to LLM output the same way OpenSSH applies it to
            network bytes. Operator-signed plans (Ed25519). Independent verifier subprocesses. Append-only, hash-chained
            audit. Worst-case budgets reserved at intent time, not hoped for at runtime.
          </p>
          <p>
            When the spec hardened, a pattern surfaced that had not been labeled at the start: every engineering
            decision lined up with what is now called <strong>Runtime Attestation eXchange for Intelligent Systems</strong>.
            Before side effects land in a shared environment, an intelligent system has to exchange cryptographically
            checkable attestations at runtime — and a verifier outside the proposer's trust boundary gets a vote.
          </p>
          <p>
            CJBrain became RAXIS. Partly because the architecture had earned the term. Partly because the term is a
            claim you can argue with.
          </p>
        </div>
      </Section>

      <Section
        bleed
        eyebrow="Lineage"
        title="From OpenSSH and Chrome to AI agents."
      >
        <div className="reading space-y-4 text-[var(--fg)] leading-relaxed">
          <p>
            RAXIS's process architecture is not a novel idea. It is a deliberate application of <strong>privilege
            separation</strong> — a security principle with a long track record in systems software:
          </p>
          <ul className="space-y-2 text-[var(--muted)] pl-5 list-disc marker:text-[var(--muted)]">
            <li>
              <strong className="text-[var(--fg)]">OpenSSH</strong> splits into a privileged monitor and an unprivileged
              child. The monitor holds the private keys; the child does the parsing and I/O. Compromise of the child
              cannot yield the keys because they are never in its address space.
            </li>
            <li>
              <strong className="text-[var(--fg)]">Google Chrome</strong> runs each tab in a sandboxed renderer with no
              direct OS access. The browser kernel mediates all privileged operations. A compromised renderer cannot
              escalate to OS-level capabilities without defeating the kernel layer.
            </li>
            <li>
              <strong className="text-[var(--fg)]">OpenBSD's pledge(2) / unveil(2)</strong> let processes declare the
              minimal capability set they need at startup. The kernel enforces that ceiling for the rest of the process
              lifetime.
            </li>
          </ul>
          <p>
            The common structure: an unprivileged worker handles untrusted input, a privileged supervisor makes authority
            decisions, the two communicate through a narrow typed channel. RAXIS applies it exactly — except the
            "untrusted input" is LLM output. Treating it with the same discipline that systems engineers apply to network
            input is not paranoia. It is a model that has proven correct in practice for decades.
          </p>
        </div>
      </Section>

      <Section
        eyebrow="Honest about gaps"
        title="A roadmap, not a finished product."
      >
        <div className="reading space-y-4 text-[var(--fg)] leading-relaxed">
          <p>
            A complete RAXIS story wants things one repository cannot deliver by itself. The current reference
            implementation has known gaps that a future paradigm revision will close:
          </p>
          <ul className="space-y-2 text-[var(--muted)] pl-5 list-disc marker:text-[var(--muted)]">
            <li>
              <strong className="text-[var(--fg)]">No hardware root of trust.</strong> The kernel binary is assumed
              honest. A serious deployment eventually wants TPM, enclave, or FIDO-class anchors.
            </li>
            <li>
              <strong className="text-[var(--fg)]">No model identity attestation.</strong> The planner holds a session,
              not a cryptographic identity. Swap weights or providers behind the same API and the kernel cannot tell.
            </li>
            <li>
              <strong className="text-[var(--fg)]">Retrospective, not prospective attestation.</strong> v1 is largely
              commit-then-verify. A tighter protocol would pre-authorize compute before it runs.
            </li>
            <li>
              <strong className="text-[var(--fg)]">No interoperability standard yet.</strong> The schema is internal —
              not W3C Verifiable Credentials, not RATS (RFC 9334), not DICE.
            </li>
            <li>
              <strong className="text-[var(--fg)]">Semantic effect verification is out of scope.</strong> RAXIS bounds
              what the agent <em>did</em>; it does not prove the change matches what the English meant.
            </li>
          </ul>
          <p>
            These gaps are not excuses. They are the messy middle of AI governance for the next decade — and they are
            stated openly so the conversation about the next paradigm revision can start from facts.
          </p>
        </div>
      </Section>

      <Section
        bleed
        eyebrow="Open invitation"
        title="The point of writing it down is to give serious people something specific to break."
      >
        <div className="reading text-[var(--fg)] leading-relaxed">
          <p>
            The paradigm spec, the conformance test suite, and the reference implementation are all open. Critique is
            welcome. If you work on protocols, formal methods, cryptography, or distributed systems, the project wants
            the criticism. The code is Rust; the contracts live under{" "}
            <code className="px-1 rounded bg-[var(--code-bg)] font-mono text-xs">specs/</code>. The steel-man critique
            against RAXIS lives in the repo too — under{" "}
            <code className="px-1 rounded bg-[var(--code-bg)] font-mono text-xs">perspectives/case-against-raxis.md</code>{" "}
            — alongside the structured response.
          </p>
          <p className="mt-4">
            The goal is simple to say and hard to reach: agents whose actions are <em>checkable by someone who is not
            the agent</em>, with a log that survives storytelling.
          </p>
          <div className="mt-8 flex flex-wrap items-center gap-3">
            <Link
              href="/docs"
              className="inline-flex h-10 items-center justify-center rounded-md bg-accent px-5 text-sm font-medium text-white hover:bg-accent-strong transition"
            >
              Read the spec
            </Link>
            <a
              href="https://github.com/"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex h-10 items-center justify-center rounded-md border border-[var(--rule)] px-5 text-sm font-medium text-[var(--fg)] hover:border-[var(--fg)] transition"
            >
              File an issue on GitHub
            </a>
            <a
              href="https://tryaegis.io"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex h-10 items-center justify-center rounded-md border border-[var(--rule)] px-5 text-sm font-medium text-[var(--fg)] hover:border-[var(--fg)] transition"
            >
              Visit Aegis
            </a>
          </div>
        </div>
      </Section>
    </>
  );
}
