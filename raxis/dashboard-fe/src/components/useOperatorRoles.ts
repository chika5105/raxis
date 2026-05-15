// Convenience hook — surfaces the operator's roles to component
// trees that need to gate UI on RBAC.
//
// Split out from `CredentialsView.tsx` so the component file
// only exports React components, keeping
// `react-refresh/only-export-components` happy without forcing
// every caller to thread `operatorRoles` themselves.

import { useMemo } from "react";

import { getStoredProfile } from "@/lib/auth-store";

export function useOperatorRoles(): string[] {
  return useMemo(() => {
    const p = getStoredProfile();
    return p?.roles ?? [];
  }, []);
}
