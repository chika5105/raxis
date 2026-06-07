/* `<SystemCredentialsPage>` — top-level page for registered
 * credentials (provider API keys, workload credentials, gateway
 * upstream keys, etc.).
 *
 * Listing surface: visible to every authenticated operator
 * (`read` or higher) per
 * `INV-DASHBOARD-CREDENTIAL-VIEWER-LISTS-ALL-OPERATOR-VISIBLE-SECRETS-01`
 * — every registered credential MUST appear here so the operator
 * can audit the surface area. The wire shape is metadata-only;
 * plaintext never leaves the kernel on the listing path.
 *
 * Reveal surface: admin-only per
 * `INV-DASHBOARD-CREDENTIAL-REVEAL-ROLE-GATED-01`. A `read`
 * operator who clicks "Reveal plaintext" round-trips to the
 * kernel, which emits a paired `RejectedPermission` audit row
 * and returns a structured 403; the FE renders the deny inline
 * (`INV-DASHBOARD-CREDENTIAL-REVEAL-PLAINTEXT-WORKS-OR-EXPLAINS-01`
 * — silent failure forbidden).
 *
 * Spec: `INV-DASHBOARD-SYSTEM-CREDENTIAL-SEVERITY-01` —
 * the page renders an explicit warning banner above the
 * credential list reminding the operator that reveals here
 * are Critical-severity audit events.
 */

import { CredentialsView } from "@/components/CredentialsView";
import { useOperatorRoles } from "@/components/useOperatorRoles";

export function SystemCredentialsPage() {
  const operatorRoles = useOperatorRoles();
  const isAdmin = operatorRoles.includes("admin");

  return (
    <div className="space-y-4">
      <header>
        <h1 className="text-xl font-semibold text-ink">System credentials</h1>
        <p className="mt-1 text-sm text-ink-muted max-w-2xl">
          Registered credentials the kernel can use for model providers,
          gateway upstreams, and task-scoped credential proxies. Secret bytes
          never reach an agent VM — agents receive only mediated handles such
          as mounted env names or local proxy endpoints. Every reveal from
          this surface emits a{" "}
          <strong className="text-bad">Critical-severity</strong> audit row
          and fires an operator notification.
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
        fingerprint, surfaces in the kernel&apos;s notifications inbox at the
        configured priority, and is rate-limited per operator. Treat the
        plaintext as live secrets — copy/paste only into the systems you
        intend to update; close the page when you&apos;re done.
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
          <strong>admin</strong>. Clicking Reveal will round-trip to the
          kernel, which records a denied-attempt audit row and surfaces an
          inline error.
        </div>
      )}
      <CredentialsView scope={{ kind: "system" }} operatorRoles={operatorRoles} />
    </div>
  );
}
