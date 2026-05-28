import Link from "next/link";
import Image from "next/image";
import { DemoPlayer } from "@/components/DemoPlayer";
import { Section } from "@/components/Section";
import { LinkedInBadge } from "@/components/LinkedInBadge";
import {
  ASK_GOOGLE_RAXIS_HREF,
  RAXIS_COFFEE_HREF,
  RAXIS_SOURCE_HREF,
} from "@/lib/site-links";

export default function HomePage() {
  return (
    <>
      <Hero />
      <FastStart />
      <DemoVideo />
      <EnterpriseBlocker />
      <WhatItDoes />
      <Paradigm />
      <AuditTrail />
      <WhoItIsFor />
      <ExploreMore />
      <FAQ />
      <CreatorSection />
      <CTA />
    </>
  );
}

function Hero() {
  return (
    <section className="border-b border-[var(--rule)]">
      <div className="mx-auto grid max-w-5xl gap-12 px-4 pb-16 pt-16 sm:px-6 sm:pb-24 sm:pt-24 lg:grid-cols-[minmax(0,1.05fr)_minmax(320px,0.95fr)] lg:items-center">
        <div className="min-w-0">
          <p className="eyebrow">RAXIS</p>
          <p className="mt-3 max-w-full break-words font-mono text-sm leading-relaxed text-[var(--muted)]">
            Runtime Attestation eXchange for Intelligent Systems
          </p>
          <h1 className="h-hero mt-6 max-w-4xl break-words">
            Let agents work.{" "}
            <span className="block text-accent sm:inline">
              Do not give them the keys.
            </span>
          </h1>
          <p className="lead mt-8 max-w-3xl break-words">
            RAXIS is the Runtime Attestation eXchange for Intelligent Systems:
            a governed runtime for autonomous agents. Agents can write code,
            run commands, query services, and coordinate work, while every
            privileged action is checked against a user-signed plan, enforced
            by a host-side kernel, and recorded in a tamper-evident audit
            chain.
          </p>
          <div className="mt-8 flex flex-wrap items-center gap-3 text-sm text-[var(--muted)]">
            <span className="rounded-full border border-[var(--rule)] bg-[var(--surface)] px-3 py-1">
              No raw credentials reach the agent
            </span>
            <span className="rounded-full border border-[var(--rule)] bg-[var(--surface)] px-3 py-1">
              No direct network path
            </span>
            <span className="rounded-full border border-[var(--rule)] bg-[var(--surface)] px-3 py-1">
              Human-signed plans
            </span>
          </div>
          <div className="mt-10 grid gap-3 sm:flex sm:flex-wrap sm:items-center sm:gap-4">
            <Link href="/get-started" className="btn btn-primary w-full sm:w-auto">
              Get started
            </Link>
            <Link href="/#demo" className="btn btn-ghost w-full sm:w-auto">
              Watch the demo
            </Link>
          </div>
          <div className="mt-5 flex max-w-2xl flex-wrap items-center gap-x-4 gap-y-2 text-sm font-medium text-[var(--muted)]">
            <span>Prefer to explore first?</span>
            <a
              href={ASK_GOOGLE_RAXIS_HREF}
              target="_blank"
              rel="noopener noreferrer"
              className="text-[var(--fg)] underline decoration-[var(--rule)] underline-offset-4 transition hover:text-accent hover:decoration-accent"
            >
              Ask Google about RAXIS
            </a>
            <Link
              href="/paradigm"
              className="text-[var(--fg)] underline decoration-[var(--rule)] underline-offset-4 transition hover:text-accent hover:decoration-accent"
            >
              Read the paradigm
            </Link>
            <a
              href={RAXIS_SOURCE_HREF}
              target="_blank"
              rel="noopener noreferrer"
              className="text-[var(--fg)] underline decoration-[var(--rule)] underline-offset-4 transition hover:text-accent hover:decoration-accent"
            >
              View source
            </a>
          </div>
        </div>
        <RuntimeDiagram />
      </div>
    </section>
  );
}

function FastStart() {
  const paths = [
    {
      eyebrow: "Ask it",
      title: "Use Google as a guide",
      body: "Open a source-grounded Google AI query scoped to raxis.io and the public repo.",
      href: ASK_GOOGLE_RAXIS_HREF,
      cta: "Ask Google",
      external: true,
    },
    {
      eyebrow: "See it",
      title: "Watch a live agent run",
      body: "See isolation, signed authority, mediated access, and the dashboard audit trail in one pass.",
      href: "/#demo",
      cta: "Watch demo",
    },
    {
      eyebrow: "Understand it",
      title: "Learn the paradigm",
      body: "Read the twelve invariants behind governed execution for intelligent systems.",
      href: "/paradigm",
      cta: "Read invariants",
    },
    {
      eyebrow: "Run it",
      title: "Start with Homebrew",
      body: "Install the bottle, run guided setup, and launch the smallest governed initiative.",
      href: "/get-started",
      cta: "Open guided path",
    },
  ];

  return (
    <section id="get-started" className="border-b border-[var(--rule)] bg-[var(--surface)]">
      <div className="mx-auto max-w-5xl px-4 py-12 sm:px-6 sm:py-14">
        <div className="min-w-0">
          <p className="eyebrow">Choose your path</p>
          <h2 className="h-section mt-4">Find the fastest route into RAXIS.</h2>
          <p className="mt-5 max-w-2xl leading-relaxed text-[var(--muted)]">
            New visitors should not have to decode the whole spec tree. Start
            with the path that matches what you need right now.
          </p>
        </div>
        <div className="mt-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {paths.map((path) => (
            <PathCard key={path.title} {...path} />
          ))}
        </div>
      </div>
    </section>
  );
}

function PathCard({
  eyebrow,
  title,
  body,
  href,
  cta,
  external = false,
}: {
  eyebrow: string;
  title: string;
  body: string;
  href: string;
  cta: string;
  external?: boolean;
}) {
  const className =
    "group flex min-h-56 flex-col rounded-xl border border-[var(--rule)] bg-[var(--bg)] p-5 transition hover:border-[var(--accent)] hover:shadow-[var(--shadow-soft)]";
  const content = (
    <>
      <p className="text-xs font-semibold uppercase tracking-[0.12em] text-[var(--accent)]">
        {eyebrow}
      </p>
      <h3 className="mt-4 text-[1.12rem] font-semibold leading-tight tracking-[-0.01em] text-[var(--fg)]">
        {title}
      </h3>
      <p className="mt-3 text-sm leading-relaxed text-[var(--muted)]">{body}</p>
      <span className="mt-auto pt-6 text-sm font-semibold text-[var(--fg)] transition group-hover:text-accent">
        {cta} →
      </span>
    </>
  );

  if (external) {
    return (
      <a href={href} target="_blank" rel="noopener noreferrer" className={className}>
        {content}
      </a>
    );
  }

  return (
    <Link href={href} className={className}>
      {content}
    </Link>
  );
}

function DemoVideo() {
  return (
    <section id="demo" className="border-b border-[var(--rule)]">
      <div className="mx-auto grid max-w-5xl gap-8 px-4 py-14 sm:px-6 sm:py-16 lg:grid-cols-[0.9fr_1.1fr] lg:items-center">
        <div>
          <p className="eyebrow mb-4">Demo video</p>
          <h2 className="h-section">Watch RAXIS govern a live agent run.</h2>
          <p className="mt-5 leading-relaxed text-[var(--muted)]">
            See the Runtime Attestation eXchange for Intelligent Systems
            isolate an agent, enforce user-signed authority, mediate access,
            and leave behind a tamper-evident record an operator can inspect.
          </p>
          <div className="mt-6 flex flex-wrap items-center gap-4">
            <a
              href="https://www.loom.com/share/a9e5673f410542bcb09b8ce7813e240c"
              target="_blank"
              rel="noopener noreferrer"
              className="btn btn-primary"
            >
              Open on Loom
            </a>
            <Link
              href="/reference"
              className="text-base text-[var(--muted)] underline decoration-[var(--rule)] underline-offset-4 transition hover:text-[var(--fg)] hover:decoration-[var(--rule-strong)]"
            >
              Read the architecture
            </Link>
          </div>
        </div>
        <div className="min-w-0">
          <DemoPlayer />
        </div>
      </div>
    </section>
  );
}

function RuntimeDiagram() {
  const systems = ["Files", "Databases", "Cloud APIs", "Network"];
  return (
    <div
      className="min-w-0 overflow-hidden rounded-2xl border border-[var(--rule)] bg-[var(--surface)] p-4 shadow-[var(--shadow-soft)]"
      aria-label="RAXIS runtime flow"
    >
      <div className="rounded-xl border border-[var(--rule)] bg-[var(--bg)] p-4">
        <div className="grid gap-3">
          <FlowBox
            label="Agent VM"
            detail="Untrusted intelligence"
            tone="muted"
          />
          <div className="mx-auto h-8 w-px bg-[var(--rule-strong)]" />
          <FlowBox
            label="RAXIS Kernel"
            detail="Enforce, mediate, audit"
            tone="accent"
          />
          <div className="mx-auto h-8 w-px bg-[var(--rule-strong)]" />
          <div className="grid grid-cols-2 gap-3">
            {systems.map((s) => (
              <div
                key={s}
                className="min-w-0 rounded-lg border border-[var(--rule)] bg-[var(--surface)] px-3 py-3 text-center text-sm font-semibold text-[var(--fg)]"
              >
                {s}
              </div>
            ))}
          </div>
        </div>
      </div>
      <div className="mt-4 grid gap-3 text-sm sm:grid-cols-3">
        <MiniProof label="Signed plan" body="Who allowed this?" />
        <MiniProof label="Admission gate" body="Should it happen now?" />
        <MiniProof label="Audit chain" body="Can we prove it later?" />
      </div>
    </div>
  );
}

function FlowBox({
  label,
  detail,
  tone,
}: {
  label: string;
  detail: string;
  tone: "accent" | "muted";
}) {
  return (
    <div
      className={
        tone === "accent"
          ? "min-w-0 rounded-xl border-2 border-[var(--accent)] bg-[var(--accent-soft)] px-4 py-5 text-center"
          : "min-w-0 rounded-xl border border-[var(--rule)] bg-[var(--surface)] px-4 py-5 text-center"
      }
    >
      <p className="text-lg font-semibold tracking-[-0.01em] text-[var(--fg)]">
        {label}
      </p>
      <p className="mt-1 text-sm text-[var(--muted)]">{detail}</p>
    </div>
  );
}

function MiniProof({ label, body }: { label: string; body: string }) {
  return (
    <div className="rounded-lg border border-[var(--rule)] px-3 py-3">
      <p className="text-sm font-semibold text-[var(--fg)]">{label}</p>
      <p className="mt-1 text-xs leading-snug text-[var(--soft)]">{body}</p>
    </div>
  );
}

function EnterpriseBlocker() {
  return (
    <section className="border-b border-[var(--rule)] bg-[var(--accent-soft)]">
      <div className="mx-auto max-w-5xl px-4 py-12 sm:px-6 sm:py-14">
        <p className="eyebrow mb-4">The blocker is governance</p>
        <div className="grid gap-8 lg:grid-cols-[0.95fr_1.05fr] lg:items-start">
          <h2 className="h-section max-w-xl">
            Enterprises do not need weaker agents. They need safer authority.
          </h2>
          <p className="text-[1.125rem] leading-relaxed text-[var(--muted)]">
            Teams want agents to ship code, operate services, and handle
            repetitive production-adjacent work. Security teams cannot approve
            that if the agent inherits developer credentials, direct network
            access, and the power to self-certify. RAXIS gives both sides what
            they need: capable agents for builders, user-signed authority
            enforced by the kernel, and evidence for operators.
          </p>
        </div>
      </div>
    </section>
  );
}

function WhatItDoes() {
  const items = [
    {
      verb: "Enforce",
      body: "Every privileged action is a typed intent. The user signs the authority boundary; the kernel enforces it before side effects land.",
    },
    {
      verb: "Isolate",
      body: "Agents run in microVMs with no raw credentials and no direct network path. Compromise stays inside the boundary.",
    },
    {
      verb: "Mediate",
      body: "Databases, cloud APIs, HTTP, SMTP, and egress flow through kernel-owned proxies. The agent uses normal tools; RAXIS holds the enforcement point.",
    },
    {
      verb: "Prove",
      body: "Every admission, denial, witness, retry, escalation, and merge is linked into a cryptographic audit chain that can be independently verified.",
    },
  ];
  return (
    <Section
      title="What RAXIS does"
      lead="The agent proposes work. The user defines what is allowed. RAXIS enforces that boundary, carries the credentials, and preserves the evidence."
    >
      <div className="grid gap-x-12 gap-y-10 sm:grid-cols-2">
        {items.map((it) => (
          <div key={it.verb} className="border-t-2 border-[var(--accent)] pt-5">
            <h3 className="h-sub">{it.verb}</h3>
            <p className="mt-3 leading-relaxed text-[var(--muted)]">{it.body}</p>
          </div>
        ))}
      </div>
    </Section>
  );
}

function Paradigm() {
  const groups = [
    {
      n: "01",
      slug: "structural-separation",
      title: "Structural separation",
      ids: ["R-1", "R-2"],
      body: "Intelligence and authority run in different execution domains. The model cannot reach secrets, networks, or privileged state directly.",
    },
    {
      n: "02",
      slug: "authority-model",
      title: "Bounded authority",
      ids: ["R-3", "R-4", "R-5", "R-6"],
      body: "Capabilities are signed, narrowed, budgeted, and fail closed. Missing or ambiguous authority means no action.",
    },
    {
      n: "03",
      slug: "accountability",
      title: "Replayable accountability",
      ids: ["R-7", "R-8", "R-9", "R-10"],
      body: "Decisions reproduce from recorded inputs. Audit entries bind intent, identity, plan, evidence, and outcome.",
    },
    {
      n: "04",
      slug: "coordination-recovery",
      title: "Mediated coordination",
      ids: ["R-11", "R-12"],
      body: "Multi-agent work and authority changes pass through the kernel. Humans widen authority through channels the model cannot reach.",
    },
  ];
  return (
    <Section
      bleed
      title="The RAXIS paradigm"
      lead="RAXIS is not just a product. It is a reference-monitor model for intelligent subjects: agents can reason and act, but authority lives outside them."
    >
      <div className="grid gap-10 sm:grid-cols-2">
        {groups.map((g) => (
          <div key={g.n} className="border-t border-[var(--rule-strong)] pt-6">
            <div className="mb-2 flex items-baseline gap-3">
              <Link
                href={`/paradigm#${g.slug}`}
                className="text-xs font-semibold uppercase tracking-widest text-[var(--accent)] transition hover:text-[var(--accent-strong)]"
              >
                Category {g.n}
              </Link>
              <span className="ml-auto flex items-center gap-1 text-xs text-[var(--soft)] tabular-nums">
                {g.ids.map((id, i) => (
                  <span key={id}>
                    {i > 0 && <span className="opacity-40"> · </span>}
                    <Link
                      href={`/paradigm#${id.toLowerCase()}`}
                      className="transition hover:text-[var(--accent)]"
                    >
                      {id}
                    </Link>
                  </span>
                ))}
              </span>
            </div>
            <h3 className="h-sub">{g.title}</h3>
            <p className="mt-3 leading-relaxed text-[var(--muted)]">{g.body}</p>
          </div>
        ))}
      </div>
      <p className="mt-10 text-base text-[var(--muted)]">
        The full paradigm defines twelve invariants. Drop one and you may still
        have a useful tool, but you no longer have RAXIS.{" "}
        <Link
          href="/paradigm"
          className="text-accent underline-offset-4 hover:underline"
        >
          Read the invariants →
        </Link>
      </p>
    </Section>
  );
}

function AuditTrail() {
  const questions = [
    "What did the agent try to do?",
    "Was it allowed, denied, retried, or escalated?",
    "Which signed plan authorized it?",
    "Which files, credentials, APIs, and network destinations were involved?",
    "What diff was actually produced?",
    "Which witness, reviewer, or human approved the next step?",
  ];
  return (
    <Section
      title="Audit that answers real questions"
      lead="The audit chain is tamper-evident, not just a log viewer. Each event is linked to the previous one, so rewriting history breaks verification."
    >
      <div className="grid gap-8 lg:grid-cols-[0.95fr_1.05fr]">
        <div className="space-y-5 leading-relaxed text-[var(--muted)]">
          <p>
            Enterprises need evidence before they can trust autonomous work.
            RAXIS records the admission decision, the policy epoch, the
            session, the task, the initiative, and the payload for every
            consequential transition.
          </p>
          <p>
            An auditor can replay the chain and see whether the record was
            altered. An operator can debug a failed task without asking the
            model to explain itself. A customer can see why a change was
            allowed to merge.
          </p>
        </div>
        <ul className="grid gap-3">
          {questions.map((q) => (
            <li
              key={q}
              className="rounded-lg border border-[var(--rule)] bg-[var(--surface)] px-4 py-3 text-[0.98rem] font-medium text-[var(--fg)]"
            >
              {q}
            </li>
          ))}
        </ul>
      </div>
    </Section>
  );
}

function WhoItIsFor() {
  return (
    <Section
      bleed
      title="Built for security teams. Useful to everyone using agents."
    >
      <div className="grid gap-8 md:grid-cols-2">
        <AudienceCard
          title="For enterprises"
          body="Approve agents for real engineering and infrastructure workflows with signed plans, scoped authority, credential isolation, evidence retention, and recovery paths when work stalls or fails."
          cta="Read the threat model"
          href="/threat-model"
        />
        <AudienceCard
          title="For builders"
          body="Use powerful coding agents without handing them your whole machine. Keep normal tools, get safer defaults, and see exactly what happened when an agent changes code."
          cta="Browse the docs"
          href="/docs"
        />
      </div>
    </Section>
  );
}

function AudienceCard({
  title,
  body,
  cta,
  href,
}: {
  title: string;
  body: string;
  cta: string;
  href: string;
}) {
  return (
    <div className="rounded-2xl border border-[var(--rule)] bg-[var(--bg)] p-6">
      <h3 className="h-sub">{title}</h3>
      <p className="mt-4 leading-relaxed text-[var(--muted)]">{body}</p>
      <Link
        href={href}
        className="mt-6 inline-flex text-base font-semibold text-accent underline-offset-4 hover:underline"
      >
        {cta} →
      </Link>
    </div>
  );
}

function ExploreMore() {
  const items = [
    {
      title: "Architecture",
      body: "How the kernel, gateways, VM isolation, credential proxies, witnesses, and dashboard fit together.",
      href: "/reference",
      cta: "Read the reference",
    },
    {
      title: "Threat model",
      body: "The assumptions RAXIS makes about agents, operators, kernels, credentials, networks, and audit evidence.",
      href: "/threat-model",
      cta: "Review the model",
    },
    {
      title: "Conformance",
      body: "The tiers and evidence used to describe whether an implementation satisfies the RAXIS invariants.",
      href: "/conformance",
      cta: "See the tiers",
    },
  ];

  return (
    <Section
      title="Go deeper when you are ready"
      lead="The homepage gives the shape of the system. These pages carry the detailed proof for operators, security reviewers, and implementation teams."
    >
      <div className="grid gap-5 md:grid-cols-3">
        {items.map((item) => (
          <Link
            key={item.title}
            href={item.href}
            className="group rounded-xl border border-[var(--rule)] bg-[var(--surface)] p-5 transition hover:border-[var(--accent)] hover:shadow-[var(--shadow-soft)]"
          >
            <h3 className="h-sub">{item.title}</h3>
            <p className="mt-3 text-sm leading-relaxed text-[var(--muted)]">
              {item.body}
            </p>
            <span className="mt-6 inline-flex text-sm font-semibold text-[var(--fg)] transition group-hover:text-accent">
              {item.cta} →
            </span>
          </Link>
        ))}
      </div>
    </Section>
  );
}

function FAQ() {
  const qs = [
    {
      q: "Is RAXIS an agent framework?",
      a: "No. Agent frameworks manage context, prompts, tools, and iteration. RAXIS is the layer below them: it controls what the agent is allowed to do and preserves the evidence. Use both.",
    },
    {
      q: "Is RAXIS just a sandbox?",
      a: "No. Sandboxing contains a process. RAXIS also enforces user-signed per-action authority, mediates credentials and egress, enforces budgets, runs witnesses, handles escalation, and produces a tamper-evident audit chain.",
    },
    {
      q: "Why does the paradigm matter?",
      a: "Because agents will move across tools, models, clouds, and industries. The durable part is the set of invariants: separate intelligence from authority, mediate every privileged action, bind decisions to signed plans, and make the record verifiable.",
    },
    {
      q: "Does this only work for coding agents?",
      a: "The reference implementation starts with software engineering because it has strong ground truth: diffs, tests, reviewers, and merge gates. The paradigm applies anywhere autonomous systems take consequential actions on behalf of people.",
    },
    {
      q: "Can normal developers use it?",
      a: "Yes. The first local workflow is for developers who want to use powerful agents without giving them an unbounded path to their machine, secrets, or network. Enterprise controls come from the same architecture.",
    },
    {
      q: "What does RAXIS not do?",
      a: "It does not make the model correct. It makes the model bounded. Correctness still comes from tests, reviews, witnesses, policies, and human approval. RAXIS makes those gates structural and auditable.",
    },
  ];
  return (
    <Section bleed title="Common questions">
      <div className="divide-y divide-[var(--rule)] border-y border-[var(--rule)]">
        {qs.map((it) => (
          <div
            key={it.q}
            className="grid gap-4 py-7 sm:grid-cols-[16rem_minmax(0,1fr)] sm:gap-12"
          >
            <h3 className="text-[1.1875rem] font-semibold tracking-[-0.01em] text-[var(--fg)]">
              {it.q}
            </h3>
            <p className="leading-relaxed text-[var(--muted)]">{it.a}</p>
          </div>
        ))}
      </div>
    </Section>
  );
}

function CreatorSection() {
  return (
    <section className="border-t border-[var(--rule)] bg-[var(--accent-soft)]">
      <div className="mx-auto max-w-5xl px-4 py-16 sm:px-6 sm:py-20">
        <div className="grid items-center gap-10 lg:grid-cols-[280px_minmax(0,1fr)]">
          <div className="flex flex-col items-center gap-4 lg:items-start">
            <div className="relative h-52 w-52 overflow-hidden rounded-2xl border border-[var(--rule)] shadow-lg sm:h-64 sm:w-64">
              <Image
                src="/images/chika-jinanwa.png"
                alt="Chika Jinanwa, creator of RAXIS"
                fill
                className="object-cover object-top"
                sizes="(max-width: 640px) 208px, 256px"
              />
            </div>
            <LinkedInBadge />
          </div>
          <div>
            <p className="eyebrow mb-4">The person behind RAXIS</p>
            <h2 className="h-section max-w-2xl">Chika Jinanwa created RAXIS</h2>
            <p className="mt-5 max-w-xl leading-relaxed text-[var(--muted)]">
              RAXIS grew out of using coding agents intensely while building{" "}
              <a
                href="https://tryaegis.io"
                target="_blank"
                rel="noopener noreferrer"
                className="text-accent underline-offset-4 hover:underline"
              >
                Aegis
              </a>
              . The agents were capable, but authority had to move outside the
              model. The architecture became a paradigm, the paradigm became a
              spec, and the spec became a working reference implementation.
            </p>
            <div className="mt-8 flex flex-wrap items-center gap-4">
              <a
                href="https://www.linkedin.com/in/chika-jinanwa/"
                target="_blank"
                rel="noopener noreferrer"
                className="btn btn-primary"
              >
                Connect on LinkedIn
              </a>
              <Link
                href="/about"
                className="text-base text-[var(--fg)] underline decoration-[var(--rule)] underline-offset-4 transition hover:text-accent hover:decoration-accent"
              >
                Learn more
              </Link>
            </div>
            <div className="mt-6 flex flex-wrap items-center gap-6 text-sm">
              <a
                href={RAXIS_COFFEE_HREF}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-2 font-medium text-[var(--muted)] transition hover:text-accent"
              >
                Buy me a coffee
              </a>
              <Link
                href="/investors"
                className="inline-flex items-center gap-1.5 font-medium text-[var(--muted)] transition hover:text-accent"
              >
                Investor overview
              </Link>
              <a
                href="mailto:chikajinanwa@raxis.io"
                className="inline-flex items-center gap-1.5 font-medium text-[var(--muted)] transition hover:text-accent"
              >
                chikajinanwa@raxis.io
              </a>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

function CTA() {
  return (
    <section className="border-t border-[var(--rule)] py-20 sm:py-24">
      <div className="mx-auto max-w-5xl px-4 sm:px-6">
        <p className="eyebrow mb-4">Start with the source</p>
        <h2 className="h-section max-w-3xl">
          Inspect the code, argue with the paradigm, run the reference
          implementation.
        </h2>
        <p className="lead mt-5 max-w-2xl">
          RAXIS is public because governed agent execution needs trust,
          criticism, and shared language. The goal is simple: make agents
          useful enough to work and constrained enough to approve.
        </p>
        <div className="mt-10 flex flex-wrap items-center gap-4">
          <a
            href={RAXIS_SOURCE_HREF}
            target="_blank"
            rel="noopener noreferrer"
            className="btn btn-primary"
          >
            View Source Code
          </a>
          <Link href="/paradigm" className="btn btn-ghost">
            Read the paradigm
          </Link>
          <a
            href={ASK_GOOGLE_RAXIS_HREF}
            target="_blank"
            rel="noopener noreferrer"
            className="btn btn-ghost"
          >
            Ask Google about RAXIS
          </a>
        </div>
      </div>
    </section>
  );
}
