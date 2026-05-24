import Link from "next/link";
import { ThemeToggle } from "./ThemeToggle";
import { Wordmark } from "./Wordmark";

type NavLink = {
  href: string;
  label: string;
  external?: boolean;
  emphasis?: boolean;
};

const GET_STARTED_HREF = "/get-started";

const NAV_LINKS: NavLink[] = [
  { href: "/", label: "Home" },
  { href: GET_STARTED_HREF, label: "Get started", emphasis: true },
  { href: "/docs", label: "Docs" },
  { href: "/investors", label: "Investors" },
  { href: "/#demo", label: "Demo" },
  { href: "/paradigm", label: "Paradigm" },
  { href: "/reference", label: "Reference" },
  { href: "/threat-model", label: "Threat model" },
  { href: "/conformance", label: "Conformance" },
  { href: "/about", label: "About" },
  {
    href: "https://paypal.me/chikajinanwa",
    label: "Buy me a coffee",
    external: true,
  },
];

function NavItem({ link, className }: { link: NavLink; className: string }) {
  if (link.external) {
    return (
      <a
        href={link.href}
        target="_blank"
        rel="noopener noreferrer"
        className={className}
      >
        {link.label}
      </a>
    );
  }

  return (
    <Link href={link.href} className={className}>
      {link.label}
    </Link>
  );
}

export function SiteNav() {
  return (
    <header className="sticky top-0 z-40 border-b border-[var(--rule)] bg-[var(--bg)]/85 backdrop-blur supports-[backdrop-filter]:bg-[var(--bg)]/70">
      <div className="mx-auto flex h-14 w-full max-w-[1600px] items-center justify-between px-6 xl:px-12">
        <Link href="/" aria-label="Raxis home" className="flex items-center gap-2">
          <Wordmark />
        </Link>
        <nav aria-label="Primary" className="hidden xl:block">
          <ul className="flex items-center gap-4 whitespace-nowrap">
            {NAV_LINKS.map((l) => (
              <li key={l.href}>
                <NavItem
                  link={l}
                  className={
                    l.emphasis
                      ? "text-sm font-semibold text-accent transition hover:text-[var(--accent-strong)]"
                      : "text-sm text-[var(--muted)] transition hover:text-[var(--fg)]"
                  }
                />
              </li>
            ))}
          </ul>
        </nav>
        <div className="flex items-center gap-4">
          <Link
            href={GET_STARTED_HREF}
            className="hidden md:inline-flex items-center rounded-[var(--radius-md)] bg-[var(--accent)] px-4 py-2 text-sm font-semibold leading-none text-white transition hover:bg-[var(--accent-strong)] dark:text-[#06141a]"
          >
            Get started
          </Link>
          <a
            href="https://docs.google.com/forms/d/e/1FAIpQLScnVmQUI-PEX-eykhXFdmcLPgxjfqGsKai4N6BRmSnozr--Vw/viewform?usp=publish-editor"
            target="_blank"
            rel="noopener noreferrer"
            className="hidden sm:inline-flex items-center text-sm text-[var(--muted)] hover:text-[var(--fg)] transition"
          >
            Contact
          </a>
          <a
            href="https://www.reddit.com/r/raxis/"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="Reddit community"
            className="hidden sm:inline-flex items-center text-[var(--muted)] hover:text-[var(--fg)] transition"
          >
            <svg viewBox="0 0 20 20" width="18" height="18" fill="currentColor" aria-hidden="true">
              <path d="M20 10a10 10 0 1 0-10 10A10 10 0 0 0 20 10zm-2 0a2 2 0 0 1-.77 1.58 4.54 4.54 0 0 1 .05.65c0 2.69-3.25 4.87-7.28 4.87s-7.28-2.18-7.28-4.87a4.54 4.54 0 0 1 .05-.65A2 2 0 1 1 5.37 8.4a9.16 9.16 0 0 1 4.68-1.39l.86-3.76a.34.34 0 0 1 .4-.25l2.71.58a1.38 1.38 0 1 1-.24.88l-2.39-.51-.75 3.3a9.13 9.13 0 0 1 4.63 1.38A2 2 0 0 1 18 10zm-10.87 1a1.38 1.38 0 1 0 1.38-1.38A1.38 1.38 0 0 0 7.13 11zm6.64 2.43a3.65 3.65 0 0 1-3.77 0 .34.34 0 0 0-.41.54 4.32 4.32 0 0 0 4.59 0 .34.34 0 1 0-.41-.54zm-.41-1.05a1.38 1.38 0 1 0-1.38-1.38 1.38 1.38 0 0 0 1.38 1.38z"/>
            </svg>
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
      {/* Compact nav */}
      <div className="xl:hidden border-t border-[var(--rule)]">
        <ul className="mx-auto flex max-w-5xl gap-5 overflow-x-auto px-4 py-2 text-sm">
          {NAV_LINKS.map((l) => (
            <li key={l.href} className="shrink-0">
              <NavItem
                link={l}
                className={
                  l.emphasis
                    ? "font-semibold text-accent hover:text-[var(--accent-strong)]"
                    : "text-[var(--muted)] hover:text-[var(--fg)]"
                }
              />
            </li>
          ))}
          <li className="shrink-0">
            <a
              href="https://www.reddit.com/r/raxis/"
              target="_blank"
              rel="noopener noreferrer"
              className="text-[var(--muted)] hover:text-[var(--fg)]"
            >
              Community
            </a>
          </li>
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
