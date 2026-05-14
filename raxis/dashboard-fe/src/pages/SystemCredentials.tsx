/* `<SystemCredentialsPage>` — top-level page for system-wide
 * credentials (Anthropic API key, other provider keys, etc.).
 *
 * Listing surface: visible to every authenticated operator
 * (`read` or higher) per
 * `INV-DASHBOARD-CREDENTIAL-VIEWER-LISTS-ALL-OPERATOR-VISIBLE-SECRETS-01`
 * — every credential the kernel uses MUST appear here so the
 * operator can audit the surface area. The wire shape is
 * metadata-only; plaintext never leaves the kernel on the
 * listing path.
 *
 * Reveal surface: admin-only per
 * `INV-DASHBOARD-CREDENTIAL-REVEAL-ROLE-GATED-01`. Non-admin
 * reveal attempts return a structured 403 with a paired
 * `RejectedPermission` audit row so the denied attempt is
 * forensically visible.
 *
 * Spec: `INV-DASHBOARD-ANTHROPIC-CREDENTIAL-SEVERITY-01` —
 * the page renders an explicit warning banner above the
 * credential list reminding the operator that reveals here
 * are Critical-severity audit events.
 */

import {
  CredentialsView,
  useOperatorRoles,
} from "@/components/CredentialsView";

export function SystemCredentialsPage() {
  const operatorRoles = useOperatorRoles();
  const isAdmin = operatorRoles.includes("admin");

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold text-ink">System credentials</h1>
        <p className="mt-1 text-sm text-ink-muted max-w-2xl">
          Provider-bound credentials the kernel uses to reach the planner /
          reviewer model substrate, gateways, and other shared upstream
          services. These never reach an agent VM — only the kernel reads
          them. Reveals from this surface emit{" "}
          <strong className="text-warn">High-severity</strong> audit rows
          (Anthropic-bound credentials emit{" "}
          <strong className="text-bad">Critical-severity</strong> rows and
          fire an operator notification).
        </p>
      </header>
      <div
        className="card border-bad/40 bg-bad/5 px-4 py-3 text-xs text-ink-muted"
        role="note"
        data-testid="system-credentials-warning"
      >
        <strong className="text-bad uppercase tracking-wider text-[10px]">
          Critical-severity surface ·{" "}
        </strong>
        Every reveal from this page is recorded against your operator
        fingerprint, surfaces in the kernel's notifications inbox at the
        configured priority, and is rate-limited per operator. Treat the
        plaintext as live secrets — copy/paste only into the systems you
        intend to update; close the page when you're done.
      </div>
      {!isAdmin && (
        <div
          className="card border-warn/40 bg-warn/10 px-4 py-3 text-xs text-warn"
          role="note"
          data-testid="system-credentials-no-admin"
        >
          Your operator token carries roles{" "}
          <strong>{operatorRoles.join(", ") || "(none)"}</strong>. Listing
          credentials is allowed for the <strong>read</strong> role; the{" "}
          <strong>Reveal plaintext</strong> action is gated on{" "}
          <strong>admin</strong> and a non-admin attempt will return a
          structured 403 with a paired audit row.
        </div>
      )}
      <CredentialsView scope={{ kind: "system" }} operatorRoles={operatorRoles} />
    </div>
  );
}
