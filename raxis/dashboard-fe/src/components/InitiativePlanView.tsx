import { useCallback, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import Editor from "@monaco-editor/react";
import clsx from "clsx";

import { ApiError, dashboardApi } from "@/api/client";
import { Empty } from "@/components/Empty";
import { ErrorBox } from "@/components/ErrorBox";
import { Mono } from "@/components/Mono";
import { Spinner } from "@/components/Spinner";
import {
  fmtAbsolute,
  fmtBytes,
  fmtRelative,
  shortFingerprint,
  shortSha,
} from "@/lib/format";
import { useTheme } from "@/lib/theme";
import type { ApprovalStatus, InitiativePlanView as PlanWire } from "@/types/api";

interface InitiativePlanViewProps {
  initiativeId: string;
}

/// React Query stale time for `GET /api/initiatives/:id/plan`.
///
/// Mirrors the backend's `Cache-Control: private, max-age=60`
/// header for **approved** plans (which are immutable past
/// approval — see `INV-DASHBOARD-INITIATIVE-PLAN-VISIBLE-01`).
/// Pending plans are revalidated more aggressively below by
/// switching `staleTime` based on `data.approval_status`.
export const PLAN_STALE_MS_APPROVED = 60_000;

/// Plan-view tab body for `<InitiativeDetail>`.
///
/// Renders the original submitted `plan.toml` for an initiative
/// in a read-only Monaco editor. Theme follows the dashboard's
/// `<ThemeProvider>` (light → `vs`; dark → `vs-dark`); the editor
/// is bounded to `60vh` so a multi-thousand-line plan does not
/// blow up the page layout.
export function InitiativePlanView({ initiativeId }: InitiativePlanViewProps) {
  const { theme } = useTheme();
  const monacoTheme = theme === "dark" ? "vs-dark" : "vs";

  const q = useQuery({
    queryKey: ["initiative-plan", initiativeId],
    queryFn: ({ signal }) => dashboardApi.initiatives.plan(initiativeId, signal),
    // Pre-approval the plan can change; post-approval it is
    // immutable. `placeholderData` keeps the existing TOML on
    // screen during background refetches so the operator does
    // not see the editor flicker between tab switches.
    staleTime: PLAN_STALE_MS_APPROVED,
    enabled: initiativeId.length > 0,
    // Surface the structured 404 / 410 path explicitly: those
    // states render inline copy, not a generic error toast,
    // so we MUST NOT auto-retry them. Other errors (network
    // glitches, transient 500s) get React Query's default
    // 3-attempt retry.
    retry: (failureCount, err) => {
      if (err instanceof ApiError && (err.status === 404 || err.status === 410)) {
        return false;
      }
      return failureCount < 3;
    },
  });

  if (q.isPending) {
    return (
      <section
        className="card p-6 flex items-center justify-center min-h-[180px]"
        aria-busy="true"
        aria-label="Loading plan"
      >
        <Spinner className="w-5 h-5" />
        <span className="ml-3 text-sm text-ink-muted">Loading plan…</span>
      </section>
    );
  }

  if (q.error) {
    if (q.error instanceof ApiError && q.error.status === 404) {
      return (
        <section className="card p-4" data-testid="plan-not-found">
          <Empty
            title="Initiative not found."
            hint="The initiative id in the URL did not match any kernel record. Try the initiatives list."
          />
        </section>
      );
    }
    if (q.error instanceof ApiError && q.error.status === 410) {
      return (
        <section className="card p-4" data-testid="plan-archived">
          <Empty
            title="Plan archived."
            hint="The kernel retained the initiative row but the plan artifact has been purged from the store. This is normal for very old initiatives; the plan TOML is no longer recoverable from the dashboard."
          />
        </section>
      );
    }
    return <ErrorBox error={q.error} onRetry={() => q.refetch()} />;
  }

  const plan = q.data;
  return <PlanLoadedBody plan={plan} monacoTheme={monacoTheme} />;
}

// -------------------------------------------------------------------
// Loaded body (separated for clarity + so vitest can mount it
// directly with synthetic data without hitting the API).
// -------------------------------------------------------------------

interface PlanLoadedBodyProps {
  plan: PlanWire;
  monacoTheme: "vs" | "vs-dark";
}

export function PlanLoadedBody({ plan, monacoTheme }: PlanLoadedBodyProps) {
  const [copied, setCopied] = useState(false);

  const onCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(plan.submitted_toml);
    } catch {
      // Fallback for older browsers / non-secure contexts.
      const ta = document.createElement("textarea");
      ta.value = plan.submitted_toml;
      ta.style.position = "absolute";
      ta.style.left = "-9999px";
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
    }
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1200);
  }, [plan.submitted_toml]);

  const onDownload = useCallback(() => {
    const blob = new Blob([plan.submitted_toml], { type: "application/toml" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${plan.initiative_id}.plan.toml`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    // Defer revoke so Safari has time to actually trigger the
    // download — synchronous revoke can race the navigate.
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }, [plan.initiative_id, plan.submitted_toml]);

  return (
    <section
      className="card p-0 overflow-hidden"
      data-testid="plan-loaded"
      data-approval-status={plan.approval_status}
    >
      <header className="px-4 py-3 border-b border-edge flex flex-wrap items-start justify-between gap-3">
        <div className="text-xs space-y-0.5 min-w-0 flex-1">
          <div className="flex items-center gap-2 text-ink-muted">
            <span className="text-[10px] uppercase tracking-wider text-ink-subtle">
              plan.toml
            </span>
            <ApprovalBadge status={plan.approval_status} />
          </div>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 mt-1 text-ink-subtle">
            <MetaItem label="Submitted by">
              {plan.submitted_by ? (
                <span title={plan.submitted_by}>
                  <Mono pill>{shortFingerprint(plan.submitted_by)}</Mono>
                </span>
              ) : (
                <span className="text-ink-subtle">—</span>
              )}
            </MetaItem>
            <MetaItem label="Submitted">
              <span title={fmtAbsolute(plan.submitted_at_unix)}>
                {fmtRelative(plan.submitted_at_unix)}
              </span>
            </MetaItem>
            {plan.approved_at_unix !== null && (
              <MetaItem label="Approved">
                <span title={fmtAbsolute(plan.approved_at_unix)}>
                  {fmtRelative(plan.approved_at_unix)}
                </span>
              </MetaItem>
            )}
            <MetaItem label="Bytes">{fmtBytes(plan.submitted_toml_bytes)}</MetaItem>
            {plan.bundle_sha256 && (
              <MetaItem label="Bundle">
                <span title={plan.bundle_sha256}>
                  <Mono pill>{shortSha(plan.bundle_sha256)}</Mono>
                </span>
              </MetaItem>
            )}
            {plan.plan_sha256 && (
              <MetaItem label="Plan SHA">
                <span title={plan.plan_sha256}>
                  <Mono pill>{shortSha(plan.plan_sha256)}</Mono>
                </span>
              </MetaItem>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            className="btn"
            onClick={onCopy}
            aria-label="Copy plan TOML"
            data-testid="plan-copy"
            aria-live="polite"
          >
            {copied ? "Copied!" : "Copy"}
          </button>
          <button
            type="button"
            className="btn"
            onClick={onDownload}
            aria-label="Download plan TOML"
            data-testid="plan-download"
          >
            Download
          </button>
        </div>
      </header>
      <div
        className={clsx(
          "h-[60vh] min-h-[280px] max-h-[60vh] overflow-hidden",
        )}
        data-testid="plan-editor"
      >
        <Editor
          height="100%"
          // Monaco's bundled languages include `ini` but not
          // `toml`; the policy editor uses `"toml"` and the
          // Monaco loader resolves it via `monaco-textmate`-
          // style fallback. Same string here keeps the two
          // editors visually aligned.
          defaultLanguage="toml"
          theme={monacoTheme}
          value={plan.submitted_toml}
          options={{
            readOnly: true,
            // Forensic display: a read-only editor MUST NOT
            // suggest the operator can mutate the bytes.
            domReadOnly: true,
            fontSize: 13,
            minimap: { enabled: false },
            scrollBeyondLastLine: false,
            automaticLayout: true,
            tabSize: 2,
            // No horizontal overflow per spec. We still allow
            // scrolling vertically inside the bounded container.
            wordWrap: "on",
            // Make the editor look read-only at a glance:
            // hide the right-side gutter glyphs that suggest
            // commit-style edits.
            renderLineHighlight: "none",
          }}
        />
      </div>
    </section>
  );
}

interface MetaItemProps {
  label: string;
  children: React.ReactNode;
}

function MetaItem({ label, children }: MetaItemProps) {
  return (
    <span className="inline-flex items-baseline gap-1 text-[11px]">
      <span className="text-[10px] uppercase tracking-wider text-ink-subtle">
        {label}
      </span>
      <span className="text-ink-muted">{children}</span>
    </span>
  );
}

interface ApprovalBadgeProps {
  status: ApprovalStatus;
}

function ApprovalBadge({ status }: ApprovalBadgeProps) {
  // WCAG-AA: every approval-status colour pairs with its label
  // (kept on the same pill so screen readers + colour-blind
  // operators get the verdict from the text, not just the hue).
  const tone =
    status === "approved"
      ? "bg-ok/15 text-ok border-ok/30"
      : status === "rejected"
        ? "bg-bad/15 text-bad border-bad/30"
        : "bg-warn/15 text-warn border-warn/30";
  return (
    <span
      className={clsx(
        "inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[10px] font-medium uppercase tracking-wider",
        tone,
      )}
      data-testid="plan-approval-badge"
    >
      {status}
    </span>
  );
}
