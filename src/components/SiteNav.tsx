import Link from "next/link";
import { ThemeToggle } from "./ThemeToggle";
import { Wordmark } from "./Wordmark";

const NAV_LINKS: Array<{ href: string; label: string }> = [
  { href: "/", label: "Home" },
  { href: "/paradigm", label: "Paradigm" },
  { href: "/threat-model", label: "Threat model" },
  { href: "/reference", label: "Reference" },
  { href: "/conformance", label: "Conformance" },
  { href: "/docs", label: "Docs" },
  { href: "/about", label: "About" },
];

export function SiteNav() {
  return (
    <header className="sticky top-0 z-40 border-b border-[var(--rule)] bg-[var(--bg)]/85 backdrop-blur supports-[backdrop-filter]:bg-[var(--bg)]/70">
      <div className="mx-auto flex h-14 max-w-5xl items-center justify-between px-4 sm:px-6">
        <Link href="/" aria-label="Raxis home" className="flex items-center gap-2">
          <Wordmark />
        </Link>
        <nav aria-label="Primary" className="hidden md:block">
          <ul className="flex items-center gap-5">
            {NAV_LINKS.map((l) => (
              <li key={l.href}>
                <Link
                  href={l.href}
                  className="text-sm text-[var(--muted)] hover:text-[var(--fg)] transition"
                >
                  {l.label}
                </Link>
              </li>
            ))}
          </ul>
        </nav>
        <div className="flex items-center gap-4">
          <a
            href="mailto:hello@raxis.io"
            className="hidden sm:inline-flex items-center text-sm text-[var(--muted)] hover:text-[var(--fg)] transition"
          >
            Contact
          </a>
          <a
            href="https://github.com/"
            target="_blank"
            rel="noopener noreferrer"
            className="hidden sm:inline-flex items-center text-xs text-[var(--muted)] hover:text-[var(--fg)] transition"
          >
            GitHub
          </a>
          <ThemeToggle />
        </div>
      </div>
      {/* Mobile nav */}
      <div className="md:hidden border-t border-[var(--rule)]">
        <ul className="mx-auto flex max-w-5xl gap-5 overflow-x-auto px-4 py-2 text-sm">
          {NAV_LINKS.map((l) => (
            <li key={l.href} className="shrink-0">
              <Link
                href={l.href}
                className="text-[var(--muted)] hover:text-[var(--fg)]"
              >
                {l.label}
              </Link>
            </li>
          ))}
          <li className="shrink-0">
            <a
              href="mailto:hello@raxis.io"
              className="text-[var(--muted)] hover:text-[var(--fg)]"
            >
              Contact
            </a>
          </li>
        </ul>
      </div>
    </header>
  );
}
