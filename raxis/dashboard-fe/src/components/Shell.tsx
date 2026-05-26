import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Link, NavLink, useLocation, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";

import { authApi, dashboardApi } from "@/api/client";
import {
  CommandPalette,
  type PaletteCommand,
} from "@/components/CommandPalette";
import { KernelLifecycleBanner } from "@/components/KernelLifecycleBanner";
import { clearStoredToken, getStoredProfile, getStoredToken } from "@/lib/auth-store";
import { shortFingerprint } from "@/lib/format";
import { ThemeToggle } from "@/components/ThemeToggle";

interface NavSection {
  label: string;
  items: NavItem[];
}

interface NavItem {
  to: string;
  label: string;
  /// Optional role gate — only shown when the operator's roles
  /// include any of these. `undefined` ⇒ visible to every role.
  rolesAny?: string[];
  /// Single-letter glyph for the dense sidebar.
  glyph: string;
}

const NAV: NavSection[] = [
  {
    label: "Overview",
    items: [
      { to: "/", label: "Home", glyph: "H" },
      { to: "/health", label: "Health", glyph: "+" },
      { to: "/inbox", label: "Inbox", glyph: "I" },
      { to: "/notifications", label: "Notifications", glyph: "N" },
    ],
  },
  {
    label: "Work",
    items: [
      { to: "/initiatives", label: "Initiatives", glyph: "•" },
      { to: "/plan-builder", label: "Plan Builder", glyph: "B" },
      { to: "/sessions", label: "Sessions", glyph: "S" },
      { to: "/escalations", label: "Escalations", glyph: "!" },
    ],
  },
  {
    label: "Code",
    items: [
      { to: "/git", label: "Git Worktrees", glyph: "G" },
      { to: "/audit", label: "Audit Chain", glyph: "A" },
      // iter69 — Gates absorbed the standalone /witnesses page;
      // per-gate rollup + cross-task verdict timeline now live
      // on one surface with click-to-filter coupling.
      { to: "/gates", label: "Gates", glyph: "T" },
    ],
  },
  {
    label: "System",
    items: [
      { to: "/policy", label: "Policy", glyph: "P" },
      // Visible to every authenticated operator (read or higher) —
      // `INV-DASHBOARD-CREDENTIAL-VIEWER-LISTS-ALL-OPERATOR-VISIBLE-SECRETS-01`
      // requires that the system-credential viewer surfaces every
      // credential the kernel uses (planner LLM keys, gateway
      // upstreams, …) so the operator can audit the surface area.
      // The listing wire is metadata-only; the reveal endpoint
      // stays admin-only and emits a paired audit row on the
      // deny path.
      {
        to: "/system/credentials",
        label: "Credentials",
        glyph: "K",
      },
    ],
  },
];

interface ShellProps {
  children: ReactNode;
}

export function Shell({ children }: ShellProps) {
  const navigate = useNavigate();
  const location = useLocation();
  const routeViewportRef = useRef<HTMLDivElement | null>(null);
  const [profile, setProfile] = useState(() => getStoredProfile());
  const [paletteOpen, setPaletteOpen] = useState(false);

  // Re-read the profile when storage changes (logout in
  // another tab — clear local state to match).
  useEffect(() => {
    function onStorage() {
      setProfile(getStoredProfile());
    }
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);

  // Cmd/Ctrl-K opens the quick-nav palette. The header pill
  // already advertises this shortcut; this commit makes it real.
  // We mount the listener globally (window) so it works from
  // any keyboard focus inside the dashboard, and we explicitly
  // skip when an `<input>` / `<textarea>` / contenteditable is
  // focused so operators editing policy TOML / search filters
  // can still type a literal "k" with Cmd held (rare but
  // possible on layout switches).
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && (e.key === "k" || e.key === "K")) {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  // The route viewport owns both dashboard axes so forensic
  // tables can be inspected without clipping. Reset only on a
  // path change; query-only changes such as table filters should
  // keep the operator's local scroll context.
  useEffect(() => {
    const el = routeViewportRef.current;
    if (!el) return;
    el.scrollTop = 0;
    el.scrollLeft = 0;
  }, [location.pathname]);

  // Lightweight badge counts for the nav. Refresh every 10s
  // so the operator sees inbox / escalation drops without
  // having to navigate to those pages.
  const unread = useQuery({
    queryKey: ["notifications", "unread-count"],
    queryFn: ({ signal }) => dashboardApi.notifications.unreadCount(signal),
    refetchInterval: 10_000,
    enabled: !!profile,
  });
  const escalations = useQuery({
    queryKey: ["escalations"],
    queryFn: ({ signal }) => dashboardApi.escalations.list(signal),
    refetchInterval: 10_000,
    enabled: !!profile,
  });

  const badges: Record<string, number> = {
    "/notifications": unread.data?.count ?? 0,
    "/escalations": escalations.data?.length ?? 0,
  };

  const onLogout = async () => {
    const tok = getStoredToken();
    if (tok) {
      try {
        await authApi.logout(tok);
      } catch {
        // Ignore — logout is best-effort. The local
        // localStorage clear below always runs.
      }
    }
    clearStoredToken();
    setProfile(null);
    navigate("/login");
  };

  // Build the palette command list from the same NAV config
  // the sidebar uses. Adds a couple of action-style commands
  // (Logout, Refresh page) so the palette is genuinely faster
  // than clicking through the chrome.
  const paletteCommands: PaletteCommand[] = useMemo(() => {
    const navCommands: PaletteCommand[] = NAV.flatMap((section) =>
      section.items
        .filter(
          (i) =>
            !i.rolesAny ||
            i.rolesAny.some((r) => profile?.roles.includes(r)),
        )
        .map<PaletteCommand>((i) => ({
          label: i.label,
          glyph: i.glyph,
          hint: i.to,
          keywords: section.label,
          to: i.to,
        })),
    );
    const actions: PaletteCommand[] = [
      {
        label: "Logout",
        keywords: "sign out exit",
        hint: "action",
        run: () => {
          void onLogout();
        },
      },
    ];
    return [...navCommands, ...actions];
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [profile]);

  return (
    <div className="min-h-screen flex bg-panel">
      {/* Sidebar */}
      <aside className="w-56 shrink-0 border-r border-edge bg-panel-raised flex flex-col">
        <div className="p-4 border-b border-edge flex items-center gap-2">
          <img src="/raxis-logo.svg" alt="Raxis" className="w-7 h-7 rounded" />
          <div>
            <div className="text-sm font-semibold text-ink leading-tight">
              Raxis
            </div>
            <div className="text-xs text-ink-subtle leading-tight">
              Operator Dashboard
            </div>
          </div>
        </div>
        <nav className="flex-1 overflow-y-auto scroll-thin py-3">
          {NAV.map((section) => (
            <div key={section.label} className="mb-4">
              <div className="px-4 py-1 text-[10px] uppercase tracking-wider text-ink-subtle font-semibold">
                {section.label}
              </div>
              {section.items
                .filter(
                  (i) =>
                    !i.rolesAny ||
                    i.rolesAny.some((r) => profile?.roles.includes(r)),
                )
                .map((item) => {
                  const badge = badges[item.to] ?? 0;
                  return (
                    <NavLink
                      key={item.to}
                      to={item.to}
                      end={item.to === "/"}
                      className={({ isActive }) =>
                        clsx(
                          "flex items-center gap-2.5 px-4 py-1.5 text-sm border-l-2 transition-colors",
                          "focus:outline-none focus-visible:bg-panel-high focus-visible:text-ink",
                          isActive
                            ? "border-accent text-ink bg-panel-high"
                            : "border-transparent text-ink-muted hover:text-ink hover:bg-panel-high/50",
                        )
                      }
                    >
                      <span className="font-mono text-ink-subtle text-[11px] w-3 text-center">
                        {item.glyph}
                      </span>
                      <span className="flex-1">{item.label}</span>
                      {badge > 0 && (
                        <span className="badge bg-accent/30 border-accent text-accent text-[10px] px-1.5">
                          {badge}
                        </span>
                      )}
                    </NavLink>
                  );
                })}
            </div>
          ))}
        </nav>
        <div className="border-t border-edge p-3">
          {profile ? (
            <div className="text-xs">
              <div className="text-ink font-medium truncate">
                {profile.display_name}
              </div>
              <div className="text-ink-subtle font-mono truncate">
                {shortFingerprint(profile.operator_id)}
              </div>
              <div className="mt-1 flex flex-wrap gap-1">
                {profile.roles.map((r) => (
                  <span
                    key={r}
                    className="badge bg-panel-high text-ink-muted border-edge-strong"
                  >
                    {r}
                  </span>
                ))}
              </div>
              <button
                type="button"
                className="btn w-full mt-3 justify-center"
                onClick={onLogout}
              >
                Logout
              </button>
            </div>
          ) : (
            <button
              type="button"
              className="btn-primary w-full justify-center"
              onClick={() => navigate("/login")}
            >
              Login
            </button>
          )}
        </div>
      </aside>

      {/* Main column */}
      <main className="flex-1 min-w-0 min-h-0 flex flex-col overflow-hidden">
        <header className="h-12 border-b border-edge bg-panel-raised flex items-center px-5 shrink-0">
          <Breadcrumb />
          <div className="ml-auto flex items-center gap-3">
            <button
              type="button"
              onClick={() => setPaletteOpen(true)}
              aria-label="Open quick navigation"
              title="Quick navigation (⌘K)"
              className="flex items-center gap-2 text-xs text-ink-subtle hover:text-ink focus:outline-none focus-visible:ring-1 focus-visible:ring-accent rounded px-1.5 py-1 transition-colors"
            >
              <span className="kbd" aria-hidden="true">⌘K</span>
              <span>quick nav</span>
            </button>
            <ThemeToggle />
          </div>
        </header>
        <div
          ref={routeViewportRef}
          className="flex-1 min-h-0 min-w-0 overflow-auto scroll-thin"
          data-testid="dashboard-scroll-viewport"
        >
          <div
            className="px-5 py-5 min-w-[1600px] max-w-[1600px] mx-auto w-full space-y-3"
            data-testid="dashboard-route-frame"
          >
            {/*
              Supervisor lifecycle banner. Mounted globally so an
              operator-noticed restart-in-flight or halted state
              follows them across navigation. Renders nothing
              until the supervisor reports a non-Healthy state OR
              `supervisor_pid !== 0`. See
              `INV-DASHBOARD-KERNEL-LIFECYCLE-01`.
            */}
            {profile && <KernelLifecycleBanner />}
            {children}
          </div>
        </div>
      </main>
      <CommandPalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        commands={paletteCommands}
      />
    </div>
  );
}

// Friendly labels for top-level route segments. Anything not
// in this map is rendered as-is (e.g. raw IDs / hashes).
const SEGMENT_LABELS: Record<string, string> = {
  health: "Health",
  inbox: "Inbox",
  notifications: "Notifications",
  initiatives: "Initiatives",
  "plan-builder": "Plan Builder",
  tasks: "Tasks",
  sessions: "Sessions",
  escalations: "Escalations",
  audit: "Audit",
  gates: "Gates",
  git: "Git Worktrees",
  policy: "Policy",
  system: "System",
  credentials: "Credentials",
};

function Breadcrumb() {
  // useLocation makes the breadcrumb update on every SPA
  // navigation. The previous implementation read
  // `window.location.pathname` directly, which is correct on
  // the first render but only re-runs because Shell happens
  // to re-render on route change — fragile, and broke entirely
  // when the parent didn't re-render (e.g. nav inside a tab).
  const location = useLocation();
  const segments = location.pathname.split("/").filter(Boolean);

  if (segments.length === 0) {
    return (
      <nav aria-label="Breadcrumb" className="text-sm text-ink-muted">
        <span className="text-ink">Home</span>
      </nav>
    );
  }

  return (
    <nav aria-label="Breadcrumb" className="text-sm text-ink-muted">
      <Link to="/" className="hover:text-accent">
        Home
      </Link>
      {segments.map((seg, i) => {
        // Truncate long IDs / hashes so the chrome doesn't
        // overflow when the operator drills into something
        // like `/sessions/01HXYZ…64hex`. Keep `Mono`-ish
        // styling for raw IDs (no friendly label match).
        const isLast = i === segments.length - 1;
        const friendly = SEGMENT_LABELS[seg];
        const decoded = (() => {
          try {
            return decodeURIComponent(seg);
          } catch {
            return seg;
          }
        })();
        const display = friendly
          ? friendly
          : decoded.length > 18
          ? `${decoded.slice(0, 8)}…${decoded.slice(-4)}`
          : decoded;
        const path = "/" + segments.slice(0, i + 1).join("/");
        return (
          <span key={`${seg}-${i}`}>
            <span className="mx-1.5 text-ink-subtle">/</span>
            {isLast ? (
              <span
                className={
                  friendly
                    ? "text-ink"
                    : "text-ink font-mono text-[0.78rem]"
                }
                title={decoded}
              >
                {display}
              </span>
            ) : (
              <Link
                to={path}
                className={clsx(
                  "hover:text-accent",
                  !friendly && "font-mono text-[0.78rem]",
                )}
                title={decoded}
              >
                {display}
              </Link>
            )}
          </span>
        );
      })}
    </nav>
  );
}
