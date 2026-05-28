import Link from "next/link";
import { ThemeToggle } from "./ThemeToggle";
import { Wordmark } from "./Wordmark";
import {
  ASK_GOOGLE_RAXIS_HREF,
  RAXIS_COFFEE_HREF,
  RAXIS_COMMUNITY_HREF,
  RAXIS_CONTACT_HREF,
  RAXIS_SOURCE_HREF,
} from "@/lib/site-links";

type NavLink = {
  href: string;
  label: string;
  external?: boolean;
  emphasis?: boolean;
};

const GET_STARTED_HREF = "/get-started";

const PRIMARY_LINKS: NavLink[] = [
  { href: "/", label: "Home" },
  { href: GET_STARTED_HREF, label: "Get started", emphasis: true },
  { href: "/docs", label: "Docs" },
  { href: "/investors", label: "Investors" },
  { href: "/#demo", label: "Demo" },
];

const NAV_GROUPS: { label: string; links: NavLink[] }[] = [
  {
    label: "Learn",
    links: [
      { href: "/plan-builder", label: "Plan builder" },
      { href: ASK_GOOGLE_RAXIS_HREF, label: "Ask Google about RAXIS", external: true },
      { href: "/paradigm", label: "Paradigm" },
      { href: "/threat-model", label: "Threat model" },
      { href: "/conformance", label: "Conformance" },
      { href: "/reference", label: "Reference implementation" },
    ],
  },
  {
    label: "Company",
    links: [
      { href: "/about", label: "About" },
      { href: RAXIS_CONTACT_HREF, label: "Contact", external: true },
    ],
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

function DesktopNavGroup({ label, links }: { label: string; links: NavLink[] }) {
  return (
    <li className="group relative">
      <button
        type="button"
        className="inline-flex items-center gap-1 text-sm text-[var(--muted)] transition hover:text-[var(--fg)] focus:outline-none focus-visible:rounded focus-visible:ring-2 focus-visible:ring-[var(--accent)]"
        aria-haspopup="true"
      >
        {label}
        <span
          aria-hidden="true"
          className="mt-[-2px] h-1.5 w-1.5 rotate-45 border-b border-r border-current opacity-70 transition group-hover:translate-y-0.5 group-hover:opacity-100 group-focus-within:translate-y-0.5 group-focus-within:opacity-100"
        />
      </button>
      <div className="invisible absolute left-1/2 top-full z-50 min-w-56 -translate-x-1/2 pt-3 opacity-0 transition group-hover:visible group-hover:opacity-100 group-focus-within:visible group-focus-within:opacity-100">
        <div className="max-h-[min(70vh,26rem)] overflow-y-auto rounded-[var(--radius-md)] border border-[var(--rule)] bg-[var(--bg)] p-2 shadow-lg">
          <ul className="space-y-1">
            {links.map((link) => (
              <li key={link.href}>
                <NavItem
                  link={link}
                  className="block rounded-[var(--radius-sm)] px-3 py-2 text-sm text-[var(--muted)] transition hover:bg-[var(--surface)] hover:text-[var(--fg)] focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]"
                />
              </li>
            ))}
          </ul>
        </div>
      </div>
    </li>
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
            {PRIMARY_LINKS.map((l) => (
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
            {NAV_GROUPS.map((group) => (
              <DesktopNavGroup key={group.label} label={group.label} links={group.links} />
            ))}
          </ul>
        </nav>
        <div className="flex items-center gap-4">
          <a
            href={RAXIS_SOURCE_HREF}
            target="_blank"
            rel="noopener noreferrer"
            className="hidden md:inline-flex items-center rounded-[var(--radius-md)] border border-[var(--rule)] px-4 py-2 text-sm font-semibold leading-none text-[var(--fg)] transition hover:border-[var(--accent)] hover:text-accent"
          >
            View Source Code
          </a>
          <a
            href={RAXIS_COFFEE_HREF}
            target="_blank"
            rel="noopener noreferrer"
            className="hidden lg:inline-flex items-center text-sm text-[var(--muted)] hover:text-[var(--fg)] transition"
          >
            Buy me a coffee
          </a>
          <a
            href={RAXIS_COMMUNITY_HREF}
            target="_blank"
            rel="noopener noreferrer"
            aria-label="Reddit community"
            className="hidden sm:inline-flex items-center text-[var(--muted)] hover:text-[var(--fg)] transition"
          >
            <svg viewBox="0 0 20 20" width="18" height="18" fill="currentColor" aria-hidden="true">
              <path d="M20 10a10 10 0 1 0-10 10A10 10 0 0 0 20 10zm-2 0a2 2 0 0 1-.77 1.58 4.54 4.54 0 0 1 .05.65c0 2.69-3.25 4.87-7.28 4.87s-7.28-2.18-7.28-4.87a4.54 4.54 0 0 1 .05-.65A2 2 0 1 1 5.37 8.4a9.16 9.16 0 0 1 4.68-1.39l.86-3.76a.34.34 0 0 1 .4-.25l2.71.58a1.38 1.38 0 1 1-.24.88l-2.39-.51-.75 3.3a9.13 9.13 0 0 1 4.63 1.38A2 2 0 0 1 18 10zm-10.87 1a1.38 1.38 0 1 0 1.38-1.38A1.38 1.38 0 0 0 7.13 11zm6.64 2.43a3.65 3.65 0 0 1-3.77 0 .34.34 0 0 0-.41.54 4.32 4.32 0 0 0 4.59 0 .34.34 0 1 0-.41-.54zm-.41-1.05a1.38 1.38 0 1 0-1.38-1.38 1.38 1.38 0 0 0 1.38 1.38z"/>
            </svg>
          </a>
          <ThemeToggle />
        </div>
      </div>
      {/* Compact nav */}
      <div className="xl:hidden border-t border-[var(--rule)]">
        <div className="mx-auto max-w-5xl px-4 py-2">
          <ul className="flex gap-5 overflow-x-auto text-sm">
            {PRIMARY_LINKS.map((l) => (
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
              <NavItem
                link={{ href: RAXIS_SOURCE_HREF, label: "Source", external: true }}
                className="text-[var(--muted)] hover:text-[var(--fg)]"
              />
            </li>
          </ul>
          <details className="mt-2 border-t border-[var(--rule)] pt-2 text-sm">
            <summary className="cursor-pointer list-none text-[var(--muted)] transition hover:text-[var(--fg)] [&::-webkit-details-marker]:hidden">
              More links
            </summary>
            <div className="grid gap-4 py-3 sm:grid-cols-3">
              {NAV_GROUPS.map((group) => (
                <div key={group.label}>
                  <p className="mb-2 text-xs font-semibold uppercase tracking-[0.12em] text-[var(--muted)]">
                    {group.label}
                  </p>
                  <ul className="space-y-2">
                    {group.links.map((link) => (
                      <li key={link.href}>
                        <NavItem
                          link={link}
                          className="text-[var(--fg)] hover:text-accent"
                        />
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
              <div>
                <p className="mb-2 text-xs font-semibold uppercase tracking-[0.12em] text-[var(--muted)]">
                  Community
                </p>
                <ul className="space-y-2">
                  <li>
                    <NavItem
                      link={{ href: ASK_GOOGLE_RAXIS_HREF, label: "Ask Google about RAXIS", external: true }}
                      className="text-[var(--fg)] hover:text-accent"
                    />
                  </li>
                  <li>
                    <NavItem
                      link={{ href: RAXIS_COMMUNITY_HREF, label: "Reddit community", external: true }}
                      className="text-[var(--fg)] hover:text-accent"
                    />
                  </li>
                  <li>
                    <NavItem
                      link={{ href: RAXIS_COFFEE_HREF, label: "Buy me a coffee", external: true }}
                      className="text-[var(--fg)] hover:text-accent"
                    />
                  </li>
                </ul>
              </div>
            </div>
          </details>
        </div>
      </div>
    </header>
  );
}
