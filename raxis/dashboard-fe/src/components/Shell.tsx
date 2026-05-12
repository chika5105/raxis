import { useEffect, useState, type ReactNode } from "react";
import { NavLink, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";

import { authApi, dashboardApi } from "@/api/client";
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
      { to: "/sessions", label: "Sessions", glyph: "S" },
      { to: "/escalations", label: "Escalations", glyph: "!" },
    ],
  },
  {
    label: "Code",
    items: [
      { to: "/git", label: "Git Worktrees", glyph: "G" },
      { to: "/audit", label: "Audit Chain", glyph: "A" },
    ],
  },
  {
    label: "System",
    items: [
      { to: "/policy", label: "Policy", glyph: "P" },
    ],
  },
];

interface ShellProps {
  children: ReactNode;
}

export function Shell({ children }: ShellProps) {
  const navigate = useNavigate();
  const [profile, setProfile] = useState(() => getStoredProfile());

  // Re-read the profile when storage changes (logout in
  // another tab — clear local state to match).
  useEffect(() => {
    function onStorage() {
      setProfile(getStoredProfile());
    }
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);

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
                className="btn w-full mt-3 justify-center"
                onClick={onLogout}
              >
                Logout
              </button>
            </div>
          ) : (
            <button
              className="btn-primary w-full justify-center"
              onClick={() => navigate("/login")}
            >
              Login
            </button>
          )}
        </div>
      </aside>

      {/* Main column */}
      <main className="flex-1 min-w-0 flex flex-col">
        <header className="h-12 border-b border-edge bg-panel-raised flex items-center px-5 shrink-0">
          <Breadcrumb />
          <div className="ml-auto flex items-center gap-3 text-xs text-ink-subtle">
            <div className="flex items-center gap-2">
              <span className="kbd">⌘K</span>
              <span>quick nav</span>
            </div>
            <ThemeToggle />
          </div>
        </header>
        <div className="flex-1 overflow-y-auto scroll-thin">
          <div className="px-5 py-5 max-w-[1600px] mx-auto w-full">
            {children}
          </div>
        </div>
      </main>
    </div>
  );
}

function Breadcrumb() {
  const segments =
    typeof window !== "undefined"
      ? window.location.pathname.split("/").filter(Boolean)
      : [];
  if (segments.length === 0) {
    return (
      <span className="text-sm text-ink-muted">
        <span className="text-ink">Home</span>
      </span>
    );
  }
  return (
    <span className="text-sm text-ink-muted">
      {segments.map((s, i) => (
        <span key={i}>
          {i > 0 && <span className="mx-1.5 text-ink-subtle">/</span>}
          <span className={i === segments.length - 1 ? "text-ink" : ""}>
            {s}
          </span>
        </span>
      ))}
    </span>
  );
}
