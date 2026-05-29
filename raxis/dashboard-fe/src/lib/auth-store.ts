// Browser-side persistence for the JWT minted by
// `POST /api/auth/verify`. Spec §4.2 — JWT lives in
// `localStorage` so it survives reloads but is namespaced
// under `raxis.dashboard.*` to avoid collisions with other
// tools served from the same origin.

const STORAGE_KEY = "raxis.dashboard.token.v1";
const PROFILE_KEY = "raxis.dashboard.profile.v1";
const DEV_BYPASS_OPERATOR_ID = "dev-auth-bypass";

export interface OperatorProfile {
  operator_id: string;
  display_name: string;
  roles: string[];
  expires_at: number;
}

const isBrowser = (): boolean =>
  typeof window !== "undefined" && typeof window.localStorage !== "undefined";

export function getStoredToken(): string | null {
  if (!isBrowser()) return null;
  return window.localStorage.getItem(STORAGE_KEY);
}

export function setStoredToken(token: string): void {
  if (!isBrowser()) return;
  window.localStorage.setItem(STORAGE_KEY, token);
}

export function clearStoredToken(): void {
  if (!isBrowser()) return;
  window.localStorage.removeItem(STORAGE_KEY);
  window.localStorage.removeItem(PROFILE_KEY);
}

export function getStoredProfile(): OperatorProfile | null {
  if (!isBrowser()) return null;
  const raw = window.localStorage.getItem(PROFILE_KEY);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as OperatorProfile;
    if (typeof parsed.operator_id !== "string") return null;
    return parsed;
  } catch {
    return null;
  }
}

export function getDevAuthBypassProfile(): OperatorProfile | null {
  if (!isBrowser()) return null;
  if (!import.meta.env.DEV) return null;
  if (import.meta.env.VITE_RAXIS_DASHBOARD_AUTH_BYPASS !== "1") return null;
  if (!isLoopbackHost(window.location.hostname)) return null;
  return {
    operator_id: DEV_BYPASS_OPERATOR_ID,
    display_name: "dev-auth-bypass",
    roles: ["read", "write_policy", "admin"],
    expires_at: Math.floor(Date.now() / 1000) + 24 * 60 * 60,
  };
}

export function getDashboardProfile(): OperatorProfile | null {
  return getStoredProfile() ?? getDevAuthBypassProfile();
}

export function setStoredProfile(profile: OperatorProfile): void {
  if (!isBrowser()) return;
  window.localStorage.setItem(PROFILE_KEY, JSON.stringify(profile));
}

/// `true` when the stored JWT is still within its TTL window.
/// Returns `false` for an expired or missing token; callers
/// should redirect to `/login` in that case.
export function isTokenLive(profile: OperatorProfile | null): boolean {
  if (!profile) return false;
  const now = Math.floor(Date.now() / 1000);
  // Subtract a 30-second buffer so a request mid-flight does
  // not race the expiry boundary.
  return profile.expires_at - 30 > now;
}

function isLoopbackHost(hostname: string): boolean {
  return (
    hostname === "localhost" ||
    hostname === "127.0.0.1" ||
    hostname === "::1" ||
    hostname === "[::1]"
  );
}
