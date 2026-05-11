import Link from "next/link";
import { Wordmark } from "./Wordmark";

export function SiteFooter() {
  return (
    <footer className="border-t border-[var(--rule)] mt-24">
      <div className="mx-auto max-w-6xl px-4 sm:px-6 py-12 grid gap-8 md:grid-cols-4">
        <div className="md:col-span-2">
          <Wordmark />
          <p className="mt-3 max-w-md text-sm text-[var(--muted)]">
            The structural enforcement layer between AI intelligence and authority.
            Twelve paradigm invariants. Cryptographic admission on every action.
            Tamper-evident audit on every decision.
          </p>
          <p className="mt-3 text-xs text-[var(--muted)]">
            Created by{" "}
            <a
              className="underline decoration-1 underline-offset-2 hover:text-[var(--fg)]"
              href="https://www.linkedin.com/"
              target="_blank"
              rel="noopener noreferrer"
            >
              Chika Jinanwa
            </a>
            . A sibling project to{" "}
            <a
              className="underline decoration-1 underline-offset-2 hover:text-[var(--fg)]"
              href="https://tryaegis.io"
              target="_blank"
              rel="noopener noreferrer"
            >
              Aegis
            </a>
            .
          </p>
        </div>
        <div>
          <h4 className="text-xs font-semibold uppercase tracking-wider text-[var(--muted)]">
            Paradigm
          </h4>
          <ul className="mt-3 space-y-2 text-sm">
            <li><Link href="/paradigm" className="hover:text-[var(--fg)] text-[var(--muted)]">The 12 invariants</Link></li>
            <li><Link href="/threat-model" className="hover:text-[var(--fg)] text-[var(--muted)]">Threat model</Link></li>
            <li><Link href="/conformance" className="hover:text-[var(--fg)] text-[var(--muted)]">Conformance tiers</Link></li>
            <li><Link href="/about" className="hover:text-[var(--fg)] text-[var(--muted)]">About & lineage</Link></li>
          </ul>
        </div>
        <div>
          <h4 className="text-xs font-semibold uppercase tracking-wider text-[var(--muted)]">
            Implementation
          </h4>
          <ul className="mt-3 space-y-2 text-sm">
            <li><Link href="/reference" className="hover:text-[var(--fg)] text-[var(--muted)]">Reference impl</Link></li>
            <li><Link href="/docs" className="hover:text-[var(--fg)] text-[var(--muted)]">Documentation</Link></li>
            <li><Link href="/docs/search" className="hover:text-[var(--fg)] text-[var(--muted)]">Search docs</Link></li>
            <li>
              <a
                href="https://github.com/"
                className="hover:text-[var(--fg)] text-[var(--muted)]"
                target="_blank"
                rel="noopener noreferrer"
              >
                GitHub
              </a>
            </li>
          </ul>
        </div>
      </div>
      <div className="border-t border-[var(--rule)]">
        <div className="mx-auto max-w-6xl px-4 sm:px-6 py-5 flex flex-col sm:flex-row gap-2 items-start sm:items-center justify-between text-xs text-[var(--muted)]">
          <span>© {new Date().getFullYear()} RAXIS. Reference implementation released under SSPL.</span>
          <span className="font-mono">runtime · attestation · exchange · for intelligent systems</span>
        </div>
      </div>
    </footer>
  );
}
