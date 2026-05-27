import type { Metadata } from "next";
import type { ReactNode } from "react";
import Image from "next/image";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Get Started",
  description:
    "The shortest path from Homebrew install to a first governed Raxis initiative.",
};

const firstInitiativeHref = "/docs/guides/getting-started/02-first-initiative";
const installVerifyHref = "/docs/guides/getting-started/01-prereqs";
const dashboardTourHref = "/docs/guides/getting-started/03-dashboard-tour";
const sourceSetupHref = "/docs/guides/setup";

export default function GetStartedPage() {
  return (
    <>
      <section className="border-b border-[var(--rule)]">
        <div className="mx-auto max-w-5xl px-4 pb-14 pt-16 sm:px-6 sm:pb-20 sm:pt-24">
          <p className="eyebrow">Get started</p>
          <h1 className="h-hero mt-4 max-w-4xl">
            Install Raxis, bootstrap one operator, run the first initiative.
          </h1>
          <p className="lead mt-8 max-w-3xl">
            This is the fastest route for a new Homebrew user. Run the guided
            setup once; it installs the bottle, creates the operator key,
            initializes the service data dir, writes the provider credential,
            signs policy, and starts the daemon.
          </p>
          <div className="mt-9 flex flex-wrap gap-3">
            <a href="#fast-path" className="btn btn-primary">
              Start the terminal flow
            </a>
            <Link href={installVerifyHref} className="btn btn-ghost">
              Install and verify details
            </Link>
            <Link href={firstInitiativeHref} className="btn btn-ghost">
              Open full first initiative guide
            </Link>
          </div>
        </div>
      </section>

      <section className="border-b border-[var(--rule)] bg-[var(--surface)]">
        <div className="mx-auto max-w-5xl px-4 py-12 sm:px-6">
          <p className="eyebrow">First-run glossary</p>
          <h2 className="h-section mt-4">Know the pieces before you run commands.</h2>
          <p className="mt-5 max-w-3xl leading-relaxed text-[var(--muted)]">
            You do not need the full architecture to start. These are the
            names that appear in the setup flow and dashboard.
          </p>
          <div className="mt-8 grid gap-3 md:grid-cols-2">
            {glossaryTerms.map((term) => (
              <GlossaryTerm
                key={term.term}
                term={term.term}
                body={term.body}
              />
            ))}
          </div>
        </div>
      </section>

      <section className="border-b border-[var(--rule)] bg-[var(--surface)]">
        <div className="mx-auto grid max-w-5xl gap-6 px-4 py-10 sm:px-6 lg:grid-cols-3">
          <Audience
            title="New Homebrew users"
            body="Start here. You only need the bottle, an operator key, a provider credential, and the first initiative guide."
          />
          <Audience
            title="Security evaluators"
            body="Run the same flow first, then read the threat model and audit-chain docs once you have local evidence."
          />
          <Audience
            title="Source contributors"
            body="Use the source setup docs when you need local Rust builds, dashboard development, or release work."
          />
        </div>
      </section>

      <section className="border-b border-[var(--rule)]">
        <div className="mx-auto max-w-5xl px-4 py-12 sm:px-6">
          <p className="eyebrow">Related setup pages</p>
          <h2 className="h-section mt-4">Use the right entry point.</h2>
          <div className="mt-8 grid gap-4 md:grid-cols-3">
            <RelatedDoc
              href="/get-started"
              title="Get started"
              body="The shortest guided path for Homebrew users. Start here when you want to run Raxis now."
            />
            <RelatedDoc
              href={installVerifyHref}
              title="01 · Install and Verify"
              body="The detailed Homebrew install, host requirements, and verification checklist behind this page."
            />
            <RelatedDoc
              href={sourceSetupHref}
              title="Source setup"
              body="Developer and maintainer setup for local builds, dashboard builds, image baking, and codesigning."
            />
          </div>
        </div>
      </section>

      <section id="fast-path" className="py-16 sm:py-20">
        <div className="mx-auto grid max-w-5xl gap-10 px-4 sm:px-6 lg:grid-cols-[0.8fr_1.2fr]">
          <div>
            <p className="eyebrow">Fast path</p>
            <h2 className="h-section mt-4">Do this first.</h2>
            <p className="mt-5 leading-relaxed text-[var(--muted)]">
              These commands install the bottle, create your operator key, run
              genesis, write the provider file, sign policy, and start the
              Homebrew daemon. After that, continue in the first initiative
              guide with a real managed repository and a hello-world plan.
            </p>
          </div>

          <div className="min-w-0 space-y-6">
            <Step number="01" title="Run guided setup">
              <CommandBlock>{`brew update
brew tap chika5105/raxis
brew install raxis

"$(brew --prefix raxis)/share/raxis/install.sh"`}</CommandBlock>
              <p className="mt-3 text-sm leading-relaxed text-[var(--muted)]">
                The script uses the same data dir as{" "}
                <code className="rounded bg-[var(--code-bg)] px-1 font-mono">brew services</code>,
                prompts for the Anthropic key without echoing it, and creates
                an admin-capable bootstrap operator by default. Need host
                requirements or manual verification commands? Use{" "}
                <Link href={installVerifyHref} className="font-semibold text-accent underline-offset-4 hover:underline">
                  01 · Install and Verify
                </Link>
                .
              </p>
            </Step>

            <Step number="02" title="Keep these exports">
              <CommandBlock>{`install -d -m 700 "$HOME/raxis-keys"
openssl genpkey -algorithm ED25519 -out "$HOME/raxis-keys/operator_private.pem"
chmod 600 "$HOME/raxis-keys/operator_private.pem"

export RAXIS_INSTALL_DIR="$(brew --prefix raxis)/share/raxis"
export RAXIS_DATA_DIR="$(brew --prefix)/var/lib/raxis"
export RAXIS_ENV="default"
export RAXIS_OPERATOR_KEY="$HOME/raxis-keys/operator_private.pem"`}</CommandBlock>
              <p className="mt-3 text-sm leading-relaxed text-[var(--muted)]">
                The guided setup prints these at the end. Keep{" "}
                <code className="rounded bg-[var(--code-bg)] px-1 font-mono">RAXIS_OPERATOR_KEY</code>{" "}
                exported for convenience; otherwise every signed request needs
                the key path passed explicitly.
              </p>
            </Step>

            <Step number="03" title="Verify the daemon">
              <CommandBlock>{`raxis --version
brew services list | awk 'NR==1 || $1=="raxis"'
raxis-supervisor status --data-dir "$RAXIS_DATA_DIR"
raxis doctor`}</CommandBlock>
              <p className="mt-3 text-sm leading-relaxed text-[var(--muted)]">
                Expected: the service is started, supervisor status is healthy,
                and <code className="rounded bg-[var(--code-bg)] px-1 font-mono">doctor</code>{" "}
                has no FAIL rows.
              </p>
            </Step>

            <Step number="04" title="Run hello world">
              <p className="mt-3 text-sm leading-relaxed text-[var(--muted)]">
                Continue to the first initiative guide at the section that
                seeds the demo repository and submits the hello-world plan.
              </p>
              <Link href={firstInitiativeHref} className="mt-4 inline-flex font-semibold text-accent underline-offset-4 hover:underline">
                Open the first initiative guide →
              </Link>
            </Step>
          </div>
        </div>
      </section>

      <section className="border-t border-[var(--rule)] bg-[var(--surface)] py-16 sm:py-20">
        <div className="mx-auto max-w-5xl px-4 sm:px-6">
          <p className="eyebrow">Operator dashboard</p>
          <h2 className="h-section mt-4">
            Use the dashboard for the parts that are easier to see than type.
          </h2>
          <p className="mt-5 max-w-3xl leading-relaxed text-[var(--muted)]">
            The terminal flow is the fastest bootstrap. After the daemon is
            healthy, open <code className="rounded bg-[var(--code-bg)] px-1 font-mono">http://127.0.0.1:9820</code>
            {" "}to inspect health, draft plans, validate policy changes, and
            watch the first initiative run.
          </p>
          <div className="mt-8 grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <DashboardFeature
              title="Glossary"
              body="Search the operator vocabulary without leaving the dashboard."
            />
            <DashboardFeature
              title="Plan Builder"
              body="Add tasks, browse plan features, confirm the DAG, validate with the kernel, then copy or download plan.toml."
            />
            <DashboardFeature
              title="Policy Builder"
              body="Discover policy features, validate drafts through the kernel loader, and see the exact sign/advance commands."
            />
            <DashboardFeature
              title="Recovery hints"
              body="When health is degraded, the dashboard points you at raxis doctor, supervisor status, and the right logs."
            />
          </div>
          <div className="mt-8 space-y-6">
            <DashboardShot
              src="/images/dashboard-plan-builder.png"
              alt="Raxis dashboard Plan Builder with feature library and DAG preview"
              title="Plan Builder"
            />
            <DashboardShot
              src="/images/dashboard-policy-builder.png"
              alt="Raxis dashboard Policy Builder with environment recommendation and feature library"
              title="Policy Builder"
            />
            <DashboardShot
              src="/images/dashboard-glossary.png"
              alt="Raxis dashboard glossary with searchable operator concepts"
              title="Dashboard glossary"
            />
          </div>
          <div className="mt-7 flex flex-wrap gap-3">
            <Link href={dashboardTourHref} className="btn btn-primary">
              Open dashboard tour
            </Link>
            <Link href="/plan-builder" className="btn btn-ghost">
              Try the website plan builder
            </Link>
          </div>
        </div>
      </section>

      <section className="border-t border-[var(--rule)] bg-[var(--surface)] py-16 sm:py-20">
        <div className="mx-auto max-w-5xl px-4 sm:px-6">
          <h2 className="h-section">Next useful stops</h2>
          <div className="mt-8 grid gap-4 md:grid-cols-3">
            <NextLink href={installVerifyHref} title="Install and verify" />
            <NextLink href="/plan-builder" title="Plan builder" />
            <NextLink href={dashboardTourHref} title="Dashboard tour" />
          </div>
        </div>
      </section>
    </>
  );
}

const glossaryTerms = [
  {
    term: "Data dir",
    body: "The writable runtime home for state: policy, keys, kernel.db, audit logs, providers, sockets, worktrees, and managed repositories.",
  },
  {
    term: "Install dir",
    body: "The immutable Homebrew bundle with the shipped binaries, dashboard assets, VM images, and guest kernel.",
  },
  {
    term: "Operator key",
    body: "Your local Ed25519 signing key. It proves CLI approvals and plan submissions came from you.",
  },
  {
    term: "Genesis",
    body: "The one-time bootstrap that creates the first policy, kernel keys, operator certificate, database, and audit chain anchor.",
  },
  {
    term: "Policy",
    body: "The signed rules Raxis enforces: operators, providers, dashboard settings, budgets, repositories, and permissions.",
  },
  {
    term: "Provider",
    body: "An LLM backend configuration, such as Anthropic. Credentials stay in private files under the data dir.",
  },
  {
    term: "Environment",
    body: "A policy label such as default, staging, or prod. Raxis supports many labels, but separate data dirs/kernels are safer for production boundaries.",
  },
  {
    term: "Kernel",
    body: "The authority process. It admits plans, spawns isolated agents, enforces policy, merges results, and writes the audit log.",
  },
  {
    term: "Supervisor",
    body: "The Homebrew-run process that starts the kernel, watches its lifecycle, and reports health.",
  },
  {
    term: "Dashboard",
    body: "The local browser UI for watching initiatives, tasks, logs, diffs, policy state, and approvals.",
  },
  {
    term: "Managed repo",
    body: "A Git repository Raxis owns for governed work. Name it after the actual repo, such as hello-world, acme-api, api, or web. The branch lives in target_ref.",
  },
  {
    term: "Plan",
    body: "The signed TOML file that describes one unit of governed work: repository, target ref, tasks, prompts, dependencies, and gates.",
  },
  {
    term: "Initiative",
    body: "One admitted plan running through the kernel from approval to completion, abort, or quarantine.",
  },
  {
    term: "Task",
    body: "One executable node inside an initiative. Tasks declare role, write scope, dependencies, and the instruction to run.",
  },
  {
    term: "Orchestrator",
    body: "The kernel-managed coordinator for an initiative. It activates ready tasks and drives integration; users do not declare it as a task.",
  },
  {
    term: "Executor",
    body: "The agent role that changes files and commits work inside its allowed paths.",
  },
  {
    term: "Reviewer",
    body: "The agent role that reviews predecessor work and submits a verdict without writing code.",
  },
  {
    term: "Plan Builder",
    body: "Dashboard helper for drafting plan.toml, rendering the DAG, validating with the kernel, and copying/downloading the result.",
  },
  {
    term: "Policy Builder",
    body: "Dashboard helper for discovering policy features, validating drafts, and preparing the signed epoch-advance path.",
  },
];

function GlossaryTerm({ term, body }: { term: string; body: string }) {
  return (
    <div className="rounded-lg border border-[var(--rule)] bg-[var(--bg)] p-4">
      <h3 className="text-sm font-semibold leading-tight text-[var(--fg)]">
        {term}
      </h3>
      <p className="mt-2 text-sm leading-relaxed text-[var(--muted)]">
        {body}
      </p>
    </div>
  );
}

function RelatedDoc({
  href,
  title,
  body,
}: {
  href: string;
  title: string;
  body: string;
}) {
  return (
    <Link
      href={href}
      className="rounded-lg border border-[var(--rule)] bg-[var(--surface)] p-5 transition hover:border-[var(--rule-strong)] hover:shadow-[var(--shadow-soft)]"
    >
      <h3 className="text-base font-semibold leading-tight text-[var(--fg)]">
        {title}
      </h3>
      <p className="mt-3 text-sm leading-relaxed text-[var(--muted)]">{body}</p>
    </Link>
  );
}

function Audience({ title, body }: { title: string; body: string }) {
  return (
    <div className="rounded-lg border border-[var(--rule)] bg-[var(--bg)] p-5">
      <h2 className="text-base font-semibold leading-tight text-[var(--fg)]">
        {title}
      </h2>
      <p className="mt-3 text-sm leading-relaxed text-[var(--muted)]">{body}</p>
    </div>
  );
}

function DashboardFeature({ title, body }: { title: string; body: string }) {
  return (
    <div className="rounded-lg border border-[var(--rule)] bg-[var(--bg)] p-5">
      <h3 className="text-base font-semibold leading-tight text-[var(--fg)]">
        {title}
      </h3>
      <p className="mt-3 text-sm leading-relaxed text-[var(--muted)]">{body}</p>
    </div>
  );
}

function DashboardShot({
  src,
  alt,
  title,
}: {
  src: string;
  alt: string;
  title: string;
}) {
  return (
    <figure className="overflow-hidden rounded-lg border border-[var(--rule)] bg-[var(--bg)] shadow-[var(--shadow-soft)]">
      <a href={src} target="_blank" rel="noreferrer" className="block">
        <Image
          src={src}
          alt={alt}
          width={2880}
          height={2000}
          sizes="(min-width: 1024px) 960px, calc(100vw - 2rem)"
          unoptimized
          className="h-auto w-full"
        />
      </a>
      <figcaption className="flex flex-wrap items-center justify-between gap-2 border-t border-[var(--rule)] px-4 py-3 text-sm font-semibold text-[var(--fg)]">
        <span>{title}</span>
        <a
          href={src}
          target="_blank"
          rel="noreferrer"
          className="text-[var(--accent)] hover:text-[var(--fg)]"
        >
          Open full-size
        </a>
      </figcaption>
    </figure>
  );
}

function Step({
  number,
  title,
  children,
}: {
  number: string;
  title: string;
  children: ReactNode;
}) {
  return (
    <section className="min-w-0 rounded-lg border border-[var(--rule)] bg-[var(--surface)] p-5">
      <div className="mb-4 flex items-baseline gap-3">
        <span className="font-mono text-xs text-[var(--accent)]">{number}</span>
        <h3 className="text-base font-semibold leading-tight text-[var(--fg)]">
          {title}
        </h3>
      </div>
      {children}
    </section>
  );
}

function CommandBlock({ children }: { children: string }) {
  return (
    <pre className="min-w-0 max-w-full overflow-x-auto rounded-lg border border-[var(--rule)] bg-[var(--code-bg)] p-4 text-sm leading-relaxed">
      <code>{children}</code>
    </pre>
  );
}

function NextLink({ href, title }: { href: string; title: string }) {
  return (
    <Link
      href={href}
      className="rounded-lg border border-[var(--rule)] bg-[var(--bg)] p-4 text-base font-semibold text-[var(--fg)] transition hover:border-[var(--rule-strong)] hover:text-accent"
    >
      {title} →
    </Link>
  );
}
