import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import clsx from "clsx";

import { ApiError, dashboardApi } from "@/api/client";
import { fmtAbsolute } from "@/lib/format";
import type { ChainStatusResponse } from "@/types/api";

// Surfaces the kernel's own audit-chain integrity verdict to the
// operator UI. The verdict comes from
// `raxis_audit_tools::verify_chain_from` via the
// `GET /api/audit/chain-status` endpoint — the FE never
// re-implements verification (`INV-AUDIT-DASHBOARD-01`).
//
// Three states:
//   * "ok"      — green banner, mirrors kernel `cargo audit verify`.
//   * "broken"  — red banner with `last_error` reason and the seq
//                 the break was observed at.
//   * "unknown" — soft amber while the data layer is still
//                 producing its first verdict (boot window or
//                 audit directory absent).
//
// The "Re-verify chain" button calls the same endpoint with
// `?reverify=true`, which forces the kernel to bypass its cache
// and walk the chain end-to-end one more time. The data layer
// still rate-limits to ~once per 30 s so a chatty button cannot
// pin a worker thread.
export function ChainStatusBanner() {
  const queryClient = useQueryClient();
  const q = useQuery({
    queryKey: ["audit", "chain-status"],
    queryFn: ({ signal }) => dashboardApi.audit.chainStatus({}, signal),
    // Refresh on a slow cadence — the cache TTL is 30s on the
    // backend and the chain only breaks under truly exceptional
    // conditions, so a chatty refetch would just waste cycles.
    refetchInterval: 30_000,
    staleTime: 15_000,
  });

  const [reverifyError, setReverifyError] = useState<unknown>(null);
  const [reverifying, setReverifying] = useState(false);
  const onReverify = async () => {
    setReverifyError(null);
    setReverifying(true);
    try {
      const fresh = await dashboardApi.audit.chainStatus({ reverify: true });
      queryClient.setQueryData<ChainStatusResponse>(
        ["audit", "chain-status"],
        fresh,
      );
    } catch (err) {
      // Surface the audit-tools error message inline rather than
      // silently no-oping (`INV-DASHBOARD-FAILURE-VISIBILITY-01`).
      // The button rests right beneath this banner, so a sibling
      // inline error frames it as a direct response to the click.
      setReverifyError(err);
    } finally {
      setReverifying(false);
    }
  };

  if (q.isPending) {
    return (
      <div className="rounded-md border border-edge/60 bg-panel px-3 py-2 text-xs text-ink-muted">
        Verifying audit chain…
      </div>
    );
  }
  if (q.error || !q.data) {
    // The chain-status endpoint itself failed (network / 5xx /
    // auth). Render as soft warn rather than red — the underlying
    // chain may still be intact; we just couldn't reach the
    // verdict. The hard-red treatment is reserved for the
    // backend reporting `status: "broken"`.
    //
    // Light mode uses the deeper amber-700/900 ramp; dark mode
    // keeps the original amber-500/200 pairing. Both pairs land
    // above WCAG AA (≥4.5:1) on their own canvas.
    return (
      <div className="rounded-md border border-amber-700/40 bg-amber-700/10 px-3 py-2 text-xs text-amber-900 flex items-center justify-between gap-3 dark:border-amber-500/40 dark:bg-amber-500/10 dark:text-amber-200">
        <span>
          Audit chain status unavailable.{" "}
          <span className="text-amber-800/80 dark:text-amber-300/70">
            {q.error instanceof Error ? q.error.message : "Unknown error."}
          </span>
        </span>
        <button
          type="button"
          className="btn text-[11px] px-2 py-1"
          onClick={() => q.refetch()}
        >
          Retry
        </button>
      </div>
    );
  }

  const s = q.data;
  const tone =
    s.status === "ok"
      ? "ok"
      : s.status === "broken"
        ? "broken"
        : "unknown";
  return (
    <div
      role="status"
      aria-live="polite"
      data-chain-status={s.status}
      className={clsx(
        "rounded-md border px-3 py-2 text-xs flex flex-wrap items-center gap-3 justify-between",
        // Each tone carries a light-mode pair (-700 tint + -800/-900
        // text) AND a dark-mode pair (-500 tint + -200 text). The
        // light-mode pairs deepen the ramp to clear WCAG AA against
        // the warm off-white panel; previously the dashboard reused
        // the dark-mode-only -500/-200 pairing in both themes and
        // landed around 1.1:1 in light mode (effectively invisible).
        tone === "ok" &&
          "border-emerald-700/40 bg-emerald-700/10 text-emerald-800 dark:border-emerald-500/40 dark:bg-emerald-500/10 dark:text-emerald-200",
        tone === "broken" &&
          "border-rose-700/50 bg-rose-700/10 text-rose-800 dark:border-rose-500/50 dark:bg-rose-500/10 dark:text-rose-200",
        tone === "unknown" &&
          "border-amber-700/40 bg-amber-700/10 text-amber-900 dark:border-amber-500/40 dark:bg-amber-500/10 dark:text-amber-200",
      )}
    >
      <div className="flex items-center gap-2">
        <ChainStatusIcon status={s.status} />
        <span className="font-medium">
          {s.status === "ok" && "Audit chain OK"}
          {s.status === "broken" && "Audit chain BROKEN"}
          {s.status === "unknown" && "Audit chain status unknown"}
        </span>
        {s.status === "ok" && (
          <span className="text-ink-muted">
            · {s.total_records.toLocaleString()} records · last seq{" "}
            <span className="font-mono">#{s.last_verified_seq}</span> ·{" "}
            {s.segment_count} segments
          </span>
        )}
        {s.status === "broken" && s.last_error && (
          <span className="text-rose-800/85 dark:text-rose-300/90 truncate max-w-[60ch]">
            · {s.last_error}
            {s.last_verified_seq > 0 && (
              <>
                {" "}
                at seq <span className="font-mono">#{s.last_verified_seq}</span>
              </>
            )}
          </span>
        )}
      </div>
      <div className="flex items-center gap-3">
        {s.verified_at_ms > 0 && (
          <span className="text-ink-subtle">
            {s.fresh ? "Verified" : "Cached"}{" "}
            {fmtAbsolute(Math.floor(s.verified_at_ms / 1000))}
          </span>
        )}
        <button
          type="button"
          className="btn text-[11px] px-2 py-1"
          onClick={onReverify}
          aria-label="Re-verify audit chain"
          disabled={reverifying}
        >
          {reverifying ? "Re-verifying…" : "Re-verify"}
        </button>
      </div>
      {reverifyError !== null && (
        <ReverifyFailureRow
          error={reverifyError}
          onDismiss={() => setReverifyError(null)}
        />
      )}
    </div>
  );
}

// Inline error sibling for the "Re-verify chain" button. Renders
// in the same banner so the operator sees the audit-tools error
// (`FAIL_DASHBOARD_AUDIT_VERIFY` / etc.) where they clicked,
// not in a transient toast. `INV-DASHBOARD-FAILURE-VISIBILITY-01`.
function ReverifyFailureRow({
  error,
  onDismiss,
}: {
  error: unknown;
  onDismiss: () => void;
}) {
  const isApi = error instanceof ApiError;
  const code = isApi ? error.code : "ERROR";
  const detail = isApi
    ? error.detail
    : error instanceof Error
      ? error.message
      : String(error);
  return (
    <div
      role="alert"
      data-testid="reverify-failure"
      className="w-full mt-2 rounded border border-rose-700/50 bg-rose-700/10 px-2 py-1.5 text-[12px] text-rose-900 dark:border-rose-500/50 dark:bg-rose-500/10 dark:text-rose-200 flex items-start gap-2"
    >
      <span aria-hidden="true" className="font-bold">!</span>
      <div className="flex-1 min-w-0">
        <span className="font-mono">{code}</span>{" "}
        <span className="break-words">{detail || "(no detail)"}</span>
      </div>
      <button
        type="button"
        className="text-[11px] hover:underline"
        onClick={onDismiss}
        aria-label="Dismiss"
      >
        Dismiss
      </button>
    </div>
  );
}

// Tiny per-row glyph variant used by the audit-entry list. Same
// color tone, no border / background — meant to fit inside an
// existing row rather than draw its own banner. Light/dark uses
// the same per-tone split as the banner above so the glyph stays
// legible on either canvas.
export function ChainStatusIcon({
  status,
}: {
  status: "ok" | "broken" | "unknown";
}) {
  const cls =
    status === "ok"
      ? "text-emerald-700 dark:text-emerald-400"
      : status === "broken"
        ? "text-rose-700 dark:text-rose-400"
        : "text-amber-700 dark:text-amber-400";
  const glyph = status === "ok" ? "✓" : status === "broken" ? "✗" : "?";
  return (
    <span
      aria-hidden="true"
      className={clsx(
        "inline-flex h-4 w-4 items-center justify-center rounded-full text-[10px] font-bold leading-none",
        cls,
      )}
    >
      {glyph}
    </span>
  );
}
