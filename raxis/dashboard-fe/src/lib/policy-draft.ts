export const POLICY_DRAFT_STORAGE_KEY = "raxis.dashboard.policyDraft.v1";

export function readPolicyDraft(): string | null {
  if (typeof window === "undefined" || !window.localStorage) return null;
  try {
    return window.localStorage.getItem(POLICY_DRAFT_STORAGE_KEY);
  } catch {
    return null;
  }
}

export function writePolicyDraft(toml: string | null) {
  if (typeof window === "undefined" || !window.localStorage) return;
  try {
    if (toml === null) window.localStorage.removeItem(POLICY_DRAFT_STORAGE_KEY);
    else window.localStorage.setItem(POLICY_DRAFT_STORAGE_KEY, toml);
  } catch {
    // Local draft persistence is a UI convenience only. The signed
    // policy epoch in the kernel remains the source of truth.
  }
}
