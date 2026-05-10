import type { ReactNode } from "react";
import { Navigate, useLocation } from "react-router-dom";

import { getStoredProfile, isTokenLive } from "@/lib/auth-store";

interface RequireAuthProps {
  children: ReactNode;
  /// Optional list of roles; the operator must hold AT LEAST
  /// ONE to enter. Empty / undefined ⇒ any authenticated
  /// operator may enter.
  rolesAny?: string[];
}

/// Route guard. Redirects unauthenticated visitors to /login,
/// preserving the original destination as `?next=…`. When
/// `rolesAny` is specified, an authenticated operator without
/// the required role is sent to a soft "forbidden" placeholder.
export function RequireAuth({ children, rolesAny }: RequireAuthProps) {
  const location = useLocation();
  const profile = getStoredProfile();

  if (!profile || !isTokenLive(profile)) {
    const next = encodeURIComponent(location.pathname + location.search);
    return <Navigate to={`/login?next=${next}`} replace />;
  }

  if (rolesAny && rolesAny.length > 0) {
    const ok = rolesAny.some((r) => profile.roles.includes(r));
    if (!ok) {
      return (
        <div className="card p-6 m-5 text-center">
          <h2 className="text-lg font-semibold text-ink">Forbidden</h2>
          <p className="mt-2 text-sm text-ink-muted">
            Your operator account is missing one of the required roles:{" "}
            <code className="font-mono text-ink">{rolesAny.join(", ")}</code>.
            Contact the policy authority to be granted the appropriate
            certificate scope.
          </p>
        </div>
      );
    }
  }

  return <>{children}</>;
}
