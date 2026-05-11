import Link from "next/link";
import { ThemeToggle } from "./ThemeToggle";
import { Wordmark } from "./Wordmark";

const NAV_LINKS: Array<{ href: string; label: string }> = [
  { href: "/paradigm", label: "Paradigm" },
  { href: "/threat-model", label: "Threat model" },
  { href: "/reference", label: "Reference impl" },
  { href: "/conformance", label: "Conformance" },
  { href: "/docs", label: "Docs" },
  { href: "/about", label: "About" },
];

export function SiteNav() {
  return (
    <header className="sticky top-0 z-40 border-b border-[var(--rule)] bg-[var(--bg)]/85 backdrop-blur supports-[backdrop-filter]:bg-[var(--bg)]/70">
      <div className="mx-auto flex h-14 max-w-6xl items-center justify-between px-4 sm:px-6">
        <Link href="/" aria-label="RAXIS home" className="flex items-center gap-2">
          <Wordmark />
        </Link>
        <nav aria-label="Primary" className="hidden md:block">
          <ul className="flex items-center gap-1">
            {NAV_LINKS.map((l) => (
              <li key={l.href}>
                <Link
                  href={l.href}
                  className="rounded-md px-3 py-1.5 text-sm text-[var(--muted)] hover:text-[var(--fg)] hover:bg-[var(--card)] transition"
                >
                  {l.label}
                </Link>
              </li>
            ))}
          </ul>
        </nav>
        <div className="flex items-center gap-2">
          <a
            href="https://github.com/"
            target="_blank"
            rel="noopener noreferrer"
            className="hidden sm:inline-flex h-8 items-center justify-center rounded-md border border-[var(--rule)] px-3 text-xs font-medium text-[var(--muted)] hover:text-[var(--fg)] hover:border-[var(--fg)] transition"
          >
            GitHub
          </a>
          <ThemeToggle />
        </div>
      </div>
      {/* Mobile nav */}
      <div className="md:hidden border-t border-[var(--rule)] bg-[var(--bg)]">
        <ul className="mx-auto flex max-w-6xl gap-1 overflow-x-auto px-3 py-2 text-sm">
          {NAV_LINKS.map((l) => (
            <li key={l.href} className="shrink-0">
              <Link
                href={l.href}
                className="rounded-md px-3 py-1.5 text-[var(--muted)] hover:text-[var(--fg)] hover:bg-[var(--card)]"
              >
                {l.label}
              </Link>
            </li>
          ))}
        </ul>
      </div>
    </header>
  );
}
