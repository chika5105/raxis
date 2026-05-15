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
  { href: "/investors", label: "Investors" },
];

export function SiteNav() {
  return (
    <header className="sticky top-0 z-40 border-b border-[var(--rule)] bg-[var(--bg)]/85 backdrop-blur supports-[backdrop-filter]:bg-[var(--bg)]/70">
      <div className="mx-auto flex h-14 w-full max-w-[1600px] items-center justify-between px-6 xl:px-12">
        <Link href="/" aria-label="Raxis home" className="flex items-center gap-2">
          <Wordmark />
        </Link>
        <nav aria-label="Primary" className="hidden md:block">
          <ul className="flex items-center gap-4 whitespace-nowrap">
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
          href="https://docs.google.com/forms/d/e/1FAIpQLScnVmQUI-PEX-eykhXFdmcLPgxjfqGsKai4N6BRmSnozr--Vw/viewform?usp=publish-editor"
            target="_blank"
            rel="noopener noreferrer"
            className="hidden sm:inline-flex items-center text-sm text-[var(--muted)] hover:text-[var(--fg)] transition"
          >
            Contact
          </a>
          <a
            href="https://github.com/chika5105/raxis"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="GitHub"
            className="hidden sm:inline-flex items-center text-[var(--muted)] hover:text-[var(--fg)] transition"
          >
            <svg
              viewBox="0 0 16 16"
              width="18"
              height="18"
              fill="currentColor"
              aria-hidden="true"
            >
              <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" />
            </svg>
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
              href="https://docs.google.com/forms/d/e/1FAIpQLScnVmQUI-PEX-eykhXFdmcLPgxjfqGsKai4N6BRmSnozr--Vw/viewform?usp=publish-editor"
              target="_blank"
              rel="noopener noreferrer"
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
