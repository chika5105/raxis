import Link from "next/link";
import Image from "next/image";
import { DemoPlayer } from "@/components/DemoPlayer";
import { Section } from "@/components/Section";
import { LinkedInBadge } from "@/components/LinkedInBadge";

export default function HomePage() {
  return (
    <>
      <Hero />
      <FastStart />
      <TrustBar />
      <DemoVideo />
      <EnterpriseBlocker />
      <WhatItDoes />
      <Paradigm />
      <AuditTrail />
      <WhoItIsFor />
      <ReferenceImpl />
      <ThreatModel />
      <Conformance />
      <FAQ />
      <CreatorSection />
      <CTA />
    </>
  );
}

function Hero() {
  return (
    <section className="border-b border-[var(--rule)]">
      <div className="mx-auto grid max-w-5xl gap-12 px-4 pb-20 pt-20 sm:px-6 sm:pb-28 sm:pt-28 lg:grid-cols-[minmax(0,1.05fr)_minmax(320px,0.95fr)] lg:items-center">
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
            run commands, query services, and coordinate work, but every
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
            <a
              href="https://github.com/chika5105/raxis"
              target="_blank"
              rel="noopener noreferrer"
              className="btn btn-ghost w-full sm:w-auto"
            >
              View Source Code
            </a>
            <Link href="/paradigm" className="btn btn-ghost w-full sm:w-auto">
              Read the paradigm
            </Link>
            <Link
              href="/docs/guides/getting-started/02-first-initiative"
              className="justify-self-center text-base text-[var(--muted)] underline decoration-[var(--rule)] underline-offset-4 transition hover:text-[var(--fg)] hover:decoration-[var(--rule-strong)] sm:justify-self-auto"
            >
              First initiative
            </Link>
          </div>
          <p className="mt-4 text-sm font-medium text-[var(--muted)]">
            Fast path: Homebrew install -&gt; genesis -&gt; first initiative.
          </p>
        </div>
        <RuntimeDiagram />
      </div>
    </section>
  );
}

function FastStart() {
  const steps = [
    {
      title: "Install",
      body: "Install the Homebrew bottle and run the guided setup script.",
      href: "/docs/guides/getting-started/01-prereqs",
    },
    {
      title: "Bootstrap",
      body: "Let the script create genesis state, provider config, and the daemon.",
      href: "/docs/guides/getting-started/02-first-initiative",
    },
    {
      title: "Run",
      body: "Adopt or seed a managed repo and submit the first hello-world initiative.",
      href: "/docs/guides/scenarios/01-hello-world",
    },
  ];

  return (
    <section id="get-started" className="border-b border-[var(--rule)] bg-[var(--surface)]">
      <div className="mx-auto grid max-w-5xl gap-8 px-4 py-10 sm:px-6 lg:grid-cols-[0.95fr_1.05fr] lg:items-start">
        <div>
          <p className="eyebrow">Start here</p>
          <h2 className="h-section mt-4">From Homebrew to first initiative.</h2>
          <p className="mt-5 max-w-2xl leading-relaxed text-[var(--muted)]">
            New users should not start in the spec tree. Install the bottle,
            run the guided setup once, then run the smallest governed
            workflow.
          </p>
          <div className="mt-7 flex flex-wrap gap-3">
            <Link href="/get-started" className="btn btn-primary">
              Open the guided path
            </Link>
            <Link href="/plan-builder" className="btn btn-ghost">
              Open the plan builder
            </Link>
            <Link href="/docs/guides/getting-started/02-first-initiative" className="btn btn-ghost">
              Jump to first initiative
            </Link>
          </div>
        </div>

        <div className="grid min-w-0 gap-4">
          <pre className="min-w-0 overflow-x-auto rounded-lg border border-[var(--rule)] bg-[var(--code-bg)] p-4 text-sm leading-relaxed">
            <code>{`brew update
brew tap chika5105/raxis
brew install raxis

"$(brew --prefix raxis)/share/raxis/install.sh"

export RAXIS_INSTALL_DIR="$(brew --prefix raxis)/share/raxis"
export RAXIS_DATA_DIR="$(brew --prefix)/var/lib/raxis"
export RAXIS_OPERATOR_KEY="$HOME/raxis-keys/operator_private.pem"`}</code>
          </pre>
          <div className="grid gap-3 sm:grid-cols-3">
            {steps.map((step, index) => (
              <Link
                key={step.title}
                href={step.href}
                className="rounded-lg border border-[var(--rule)] bg-[var(--bg)] p-4 transition hover:border-[var(--rule-strong)] hover:shadow-[var(--shadow-soft)]"
              >
                <span className="font-mono text-xs text-[var(--accent)]">
                  0{index + 1}
                </span>
                <h3 className="mt-2 text-base font-semibold leading-tight text-[var(--fg)]">
                  {step.title}
                </h3>
                <p className="mt-2 text-sm leading-relaxed text-[var(--muted)]">
                  {step.body}
                </p>
              </Link>
            ))}
          </div>
        </div>
      </div>
    </section>
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
        <DemoPlayer />
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

function TrustBar() {
  const points = [
    "Isolated microVMs",
    "Credential proxies",
    "Mediated egress",
    "Signed approvals",
    "Mechanical witnesses",
    "Hash-chained audit",
  ];
  return (
    <section className="border-b border-[var(--rule)] bg-[var(--surface)]">
      <div className="mx-auto flex max-w-5xl flex-wrap gap-x-8 gap-y-3 px-4 py-5 text-sm font-medium text-[var(--muted)] sm:px-6">
        {points.map((p) => (
          <span key={p}>{p}</span>
        ))}
      </div>
    </section>
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

function ReferenceImpl() {
  return (
    <Section title="Working reference implementation">
      <div className="grid gap-12 lg:grid-cols-[1.05fr_0.95fr]">
        <div className="space-y-5 leading-relaxed text-[var(--fg)]">
          <p>
            A paradigm has to run. RAXIS ships a source-available Rust
            implementation for autonomous software engineering: agents that
            read code, write code, run tools, call services, pass gates, and
            integrate changes through a controlled merge path.
          </p>
          <p className="text-[var(--muted)]">
            Software engineering is the first proving ground because it has
            ground truth. RAXIS can inspect the actual Git diff, run mechanical
            witnesses, bind verdicts to commit SHAs, and show the operator what
            happened in the dashboard.
          </p>
          <p className="text-[var(--muted)]">
            Source availability is part of the strategy. Security buyers can
            inspect the design before they trust it, and the public specs give
            the industry a shared vocabulary for governed agent execution.
          </p>
        </div>
        <dl className="space-y-5">
          <Stat
            label="Runtime"
            value="Rust"
            hint="kernel, CLI, gateways, proxies, verifier"
          />
          <Stat
            label="Isolation"
            value="VMs"
            hint="Apple Virtualization.framework and Firecracker/KVM"
          />
          <Stat
            label="Credential proxies"
            value="11"
            hint="databases, HTTP, SMTP, AWS, GCP, Azure"
          />
          <Stat
            label="Audit"
            value="SHA-256"
            hint="hash-chained JSONL with replayable evidence"
          />
          <p className="pt-2 text-base">
            <Link
              href="/reference"
              className="text-accent underline-offset-4 hover:underline"
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
        <span className="text-[1.25rem] font-semibold tabular-nums tracking-[-0.01em] text-[var(--fg)]">
          {value}
        </span>
        <span className="mt-0.5 block text-sm text-[var(--soft)]">{hint}</span>
      </dd>
    </div>
  );
}

function ThreatModel() {
  return (
    <Section
      title="Threat model"
      lead="The architecture starts from uncomfortable assumptions and makes them explicit."
    >
      <dl className="grid gap-10 sm:grid-cols-3">
        <Threat
          title="Agents are untrusted"
          body="Not because every model is malicious, but because hallucination, prompt injection, and model changes are normal operating conditions."
        />
        <Threat
          title="Operators make mistakes"
          body="A bad glob, stale credential, or rushed approval should have a bounded blast radius and a complete audit trail."
        />
        <Threat
          title="The kernel is the root"
          body="RAXIS is honest about the trust boundary: a small host-side kernel mediates access, records evidence, and fails closed."
        />
      </dl>
      <p className="mt-10 text-base text-[var(--muted)]">
        <Link
          href="/threat-model"
          className="text-accent underline-offset-4 hover:underline"
        >
          Read the full threat model →
        </Link>
      </p>
    </Section>
  );
}

function Threat({ title, body }: { title: string; body: string }) {
  return (
    <div>
      <dt className="h-sub">{title}</dt>
      <dd className="mt-3 leading-relaxed text-[var(--muted)]">{body}</dd>
    </div>
  );
}

function Conformance() {
  const tiers = [
    {
      tier: "1",
      name: "Aligned",
      verification: "Self-attested",
      use: "Designs, prototypes, and early implementations",
    },
    {
      tier: "2",
      name: "Tested",
      verification: "Canonical conformance suite",
      use: "Production-bound implementations seeking evidence",
    },
    {
      tier: "3",
      name: "Verified",
      verification: "Independent third-party audit",
      use: "Regulated deployments and contractual commitments",
    },
  ];
  return (
    <Section
      title="Conformance"
      lead="RAXIS is designed to become a category, not a black box. Conformance gives teams a way to prove which guarantees an implementation actually satisfies."
    >
      <div className="border-y border-[var(--rule)]">
        {tiers.map((t, i) => (
          <div
            key={t.tier}
            className={
              "grid gap-3 py-6 sm:grid-cols-[4rem_minmax(0,1fr)] sm:gap-x-6 sm:gap-y-4 md:grid-cols-[4rem_9rem_minmax(0,1fr)_minmax(0,1fr)] " +
              (i > 0 ? "border-t border-[var(--rule)]" : "")
            }
          >
            <div className="text-sm tabular-nums text-[var(--soft)]">
              Tier {t.tier}
            </div>
            <div className="text-[1.125rem] font-semibold tracking-[-0.01em] text-[var(--fg)]">
              {t.name}
            </div>
            <div className="leading-snug text-[var(--muted)]">
              {t.verification}
            </div>
            <div className="leading-snug text-[var(--muted)]">{t.use}</div>
          </div>
        ))}
      </div>
      <p className="mt-8 text-base text-[var(--muted)]">
        The reference implementation currently claims tier 1 and tier 2. Tier 3
        requires independent review.{" "}
        <Link
          href="/conformance"
          className="text-accent underline-offset-4 hover:underline"
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
                href="https://paypal.me/chikajinanwa"
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
            href="https://github.com/chika5105/raxis"
            target="_blank"
            rel="noopener noreferrer"
            className="btn btn-primary"
          >
            View Source Code
          </a>
          <Link href="/paradigm" className="btn btn-ghost">
            Read the paradigm
          </Link>
        </div>
      </div>
    </section>
  );
}
