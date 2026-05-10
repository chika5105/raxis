// Browser-side persistence for the JWT minted by
// `POST /api/auth/verify`. Spec §4.2 — JWT lives in
// `localStorage` so it survives reloads but is namespaced
// under `raxis.dashboard.*` to avoid collisions with other
// tools served from the same origin.

const STORAGE_KEY = "raxis.dashboard.token.v1";
const PROFILE_KEY = "raxis.dashboard.profile.v1";

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
