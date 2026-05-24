import type { Metadata } from "next";
import type { ReactNode } from "react";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Get Started",
  description:
    "The shortest path from Homebrew install to a first governed Raxis initiative.",
};

const firstInitiativeHref = "/docs/guides/getting-started/02-first-initiative";
const installVerifyHref = "/docs/guides/getting-started/01-prereqs";
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
            This is the fastest route for a new Homebrew user. It gets the
            kernel running with one operator and sends you straight to the
            hello-world workflow.
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
              These commands establish the installed runtime path, create your
              operator key, and run genesis. After that, continue in the first
              initiative guide for provider setup, kernel startup, dashboard
              login, and the hello-world plan.
            </p>
          </div>

          <div className="min-w-0 space-y-6">
            <Step number="01" title="Install the bottle">
              <CommandBlock>{`brew update
brew tap chika5105/raxis
brew install raxis
raxis --version

export RAXIS_INSTALL_DIR="$(brew --prefix raxis)/share/raxis"
export RAXIS_DATA_DIR="$(brew --prefix)/var/lib/raxis"`}</CommandBlock>
              <p className="mt-3 text-sm leading-relaxed text-[var(--muted)]">
                Need host requirements or verification commands? Use{" "}
                <Link href={installVerifyHref} className="font-semibold text-accent underline-offset-4 hover:underline">
                  01 · Install and Verify
                </Link>
                .
              </p>
            </Step>

            <Step number="02" title="Create an operator key">
              <CommandBlock>{`install -d -m 700 "$HOME/raxis-keys"
openssl genpkey -algorithm ED25519 -out "$HOME/raxis-keys/operator_private.pem"
chmod 600 "$HOME/raxis-keys/operator_private.pem"

export RAXIS_OPERATOR_KEY="$HOME/raxis-keys/operator_private.pem"`}</CommandBlock>
              <p className="mt-3 text-sm leading-relaxed text-[var(--muted)]">
                Keep <code className="rounded bg-[var(--code-bg)] px-1 font-mono">RAXIS_OPERATOR_KEY</code>{" "}
                exported for convenience; otherwise every signed request needs
                the key path passed explicitly.
              </p>
            </Step>

            <Step number="03" title="Bootstrap Raxis">
              <CommandBlock>{`raxis genesis \\
  --operator-key "$RAXIS_OPERATOR_KEY" \\
  --operator-name "$USER"`}</CommandBlock>
              <p className="mt-3 text-sm leading-relaxed text-[var(--muted)]">
                This uses the same data dir that{" "}
                <code className="rounded bg-[var(--code-bg)] px-1 font-mono">brew services start raxis</code>{" "}
                will use later. After the first initiative guide adds your
                provider and signs policy, start Raxis as a daemon with
                Homebrew.
              </p>
            </Step>

            <Step number="04" title="Start the Homebrew daemon">
              <CommandBlock>{`brew services start raxis
brew services list | awk 'NR==1 || $1=="raxis"'
raxis-supervisor status
raxis doctor`}</CommandBlock>
              <p className="mt-3 text-sm leading-relaxed text-[var(--muted)]">
                Run this when the first initiative guide reaches kernel
                startup. It starts a user LaunchAgent, not a privileged system
                daemon.
              </p>
            </Step>

            <div className="rounded-lg border border-[var(--rule)] bg-[var(--accent-soft)] p-5">
              <h3 className="text-base font-semibold text-[var(--fg)]">
                Continue to the first initiative
              </h3>
              <p className="mt-2 text-sm leading-relaxed text-[var(--muted)]">
                The full guide finishes provider setup, signs the policy with
                the authority key, starts the kernel, opens the dashboard, and
                runs the hello-world workflow.
              </p>
              <Link href={firstInitiativeHref} className="mt-4 inline-flex font-semibold text-accent underline-offset-4 hover:underline">
                Run the first initiative →
              </Link>
            </div>
          </div>
        </div>
      </section>

      <section className="border-t border-[var(--rule)] bg-[var(--surface)] py-16 sm:py-20">
        <div className="mx-auto max-w-5xl px-4 sm:px-6">
          <h2 className="h-section">Next useful stops</h2>
          <div className="mt-8 grid gap-4 md:grid-cols-3">
            <NextLink href={installVerifyHref} title="Install and verify" />
            <NextLink href="/docs/guides/getting-started/03-dashboard-tour" title="Dashboard tour" />
            <NextLink href={sourceSetupHref} title="Source setup" />
          </div>
        </div>
      </section>
    </>
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
