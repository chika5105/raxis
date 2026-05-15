import Link from "next/link";
import { Wordmark } from "./Wordmark";

export function SiteFooter() {
  return (
    <footer className="border-t border-[var(--rule)] mt-24">
      <div className="mx-auto max-w-5xl px-4 sm:px-6 py-12 grid gap-10 md:grid-cols-4">
        <div className="md:col-span-2">
          <Wordmark />
          <p className="mt-3 max-w-md text-sm text-[var(--muted)] leading-relaxed">
          A paradigm for autonomous-system safety: twelve structural invariants,
            and a reference implementation in autonomous software engineering.
          </p>
          <p className="mt-3 max-w-md text-sm text-[var(--muted)] leading-relaxed">
            Source open under SSPL. For enterprise licensing, evaluations, or
            partnerships, reach{" "}
            <a
              href="mailto:chikajinanwa@raxis.io"
              className="text-[var(--fg)] hover:text-accent transition"
            >
              chikajinanwa@raxis.io
            </a>
            .
          </p>
          <p className="mt-3 text-sm text-[var(--muted)]">
            Created by{" "}
            <a
              className="text-[var(--fg)] hover:text-accent transition"
              href="https://www.linkedin.com/in/chika-jinanwa/"
              target="_blank"
              rel="noopener noreferrer"
            >
              Chika Jinanwa
            </a>
            . Sibling project of{" "}
            <a
              className="text-[var(--fg)] hover:text-accent transition"
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
          <h4 className="text-sm font-semibold text-[var(--fg)]">Paradigm</h4>
          <ul className="mt-3 space-y-2 text-sm">
            <li><Link href="/" className="text-[var(--muted)] hover:text-[var(--fg)]">Home</Link></li>
            <li><Link href="/paradigm" className="text-[var(--muted)] hover:text-[var(--fg)]">The twelve invariants</Link></li>
            <li><Link href="/threat-model" className="text-[var(--muted)] hover:text-[var(--fg)]">Threat model</Link></li>
            <li><Link href="/conformance" className="text-[var(--muted)] hover:text-[var(--fg)]">Conformance</Link></li>
            <li><Link href="/about" className="text-[var(--muted)] hover:text-[var(--fg)]">About</Link></li>
            <li><Link href="/investors" className="text-[var(--muted)] hover:text-[var(--fg)]">Investors</Link></li>
          </ul>
        </div>
        <div>
          <h4 className="text-sm font-semibold text-[var(--fg)]">Implementation</h4>
          <ul className="mt-3 space-y-2 text-sm">
            <li><Link href="/reference" className="text-[var(--muted)] hover:text-[var(--fg)]">Reference</Link></li>
            <li><Link href="/docs" className="text-[var(--muted)] hover:text-[var(--fg)]">Documentation</Link></li>
            <li><Link href="/docs/search" className="text-[var(--muted)] hover:text-[var(--fg)]">Search</Link></li>
            <li>
              <a
                href="https://github.com/"
                className="text-[var(--muted)] hover:text-[var(--fg)]"
                target="_blank"
                rel="noopener noreferrer"
              >
                GitHub
              </a>
            </li>
            <li>
            <a
                href="mailto:chikajinanwa@raxis.io"
                className="text-[var(--muted)] hover:text-[var(--fg)]"
              >
                chikajinanwa@raxis.io
              </a>
            </li>
          </ul>
        </div>
      </div>
      <div className="border-t border-[var(--rule)]">
        <div className="mx-auto max-w-5xl px-4 sm:px-6 py-5 flex flex-col sm:flex-row gap-2 items-start sm:items-center justify-between text-xs text-[var(--muted)]">
          <span>© {new Date().getFullYear()} Raxis. All rights reserved.</span>
          <span>
            <a href="mailto:chikajinanwa@raxis.io" className="hover:text-[var(--fg)]">
              chikajinanwa@raxis.io
            </a>
          </span>
        </div>
      </div>
    </footer>
  );
}
