import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";

import { dashboardApi } from "@/api/client";
import { fmtAbsolute } from "@/lib/format";
import type { KernelLifecycleResponse } from "@/types/api";

// Surfaces the supervisor's view of the kernel lifecycle.
//
// Spec: `raxis/specs/v2/self-healing-supervisor.md §5.4` /
//       `INV-DASHBOARD-KERNEL-LIFECYCLE-01`.
//
// Visibility contract:
//   * `Healthy` + sentinel absent OR `supervisor_pid === 0` ⇒
//     render NOTHING. Operators who never opted into the
//     `RAXIS_SUPERVISOR_AUTO_RESTART=1` workflow should not
//     see banner chrome on every dashboard pane.
//   * `Restarting`     ⇒ amber banner with attempt N/M + reason.
//   * `Halted` + sub_state ⇒ rose banner (supervisor stopped
//     attempting; operator action required).
//   * `fresh === false` ⇒ append a "stale data" note to whichever
//     banner is rendered so the operator knows the supervisor's
//     last writeup is suspect.
//
// The banner is mounted in `<Shell>`; it polls every 5 s while
// the operator is on any dashboard page. The kernel handler is
// best-effort and never throws — every failure mode collapses to
// a `Halted{SupervisorGone}` view, which in turn renders here as
// a "supervisor process gone" rose banner.
export function KernelLifecycleBanner() {
  const q = useQuery({
    queryKey: ["health", "kernel-lifecycle"],
    queryFn: ({ signal }) => dashboardApi.kernelLifecycle(signal),
    // 5-second polling cadence matches the spec
    // (`self-healing-supervisor.md §5.4`). Fast enough that an
    // operator clicking around catches a restart-in-flight
    // banner; slow enough not to flood the audit log with
    // OperatorHealthQueried rows.
    refetchInterval: 5_000,
    staleTime: 2_000,
    // Quiet failure modes: a transient network error MUST NOT
    // bury the banner under a red toast. The kernel handler
    // never errors when the sentinel is missing, so the only
    // real failure modes here are 401/403 (handled by the
    // global redirect) and 5xx during a kernel restart (which
    // is exactly what the banner is supposed to surface). When
    // the query is genuinely failing, render nothing — the
    // dashboard ChainStatusBanner (always mounted alongside)
    // already screams when the kernel is unreachable.
    retry: false,
  });

  // No data yet OR query errored — render nothing. The
  // ChainStatusBanner already covers "kernel unreachable".
  if (!q.data) return null;
  return <KernelLifecycleBannerView snapshot={q.data} />;
}

/// Pure-presentation variant. Exported so vitest can drive
/// rendering without spinning up the React Query stack.
export function KernelLifecycleBannerView({
  snapshot,
}: {
  snapshot: KernelLifecycleResponse;
}) {
  const tone = bannerTone(snapshot);
  if (tone === "hidden") return null;
  const { status, sub_state } = snapshot;
  const glyph =
    tone === "warn" ? "↻" : tone === "stop" ? "■" : "?";
  return (
    <div
      role="status"
      aria-live="polite"
      data-testid="kernel-lifecycle-banner"
      data-kernel-status={status}
      data-kernel-substate={sub_state ?? ""}
      data-kernel-fresh={snapshot.fresh ? "true" : "false"}
      className={clsx(
        "rounded-md border px-3 py-2 text-xs flex flex-wrap items-center gap-3 justify-between",
        // Light + dark mode tone pairs follow ChainStatusBanner.
        tone === "warn" &&
          "border-amber-700/40 bg-amber-700/10 text-amber-900 dark:border-amber-500/40 dark:bg-amber-500/10 dark:text-amber-200",
        tone === "stop" &&
          "border-rose-700/50 bg-rose-700/10 text-rose-800 dark:border-rose-500/50 dark:bg-rose-500/10 dark:text-rose-200",
      )}
    >
      <div className="flex items-center gap-2 min-w-0">
        <span
          aria-hidden="true"
          className={clsx(
            "inline-flex h-4 w-4 items-center justify-center rounded-full text-[10px] font-bold leading-none",
            tone === "warn"
              ? "text-amber-700 dark:text-amber-400"
              : "text-rose-700 dark:text-rose-400",
          )}
        >
          {glyph}
        </span>
        <span className="font-medium">{headlineFor(snapshot)}</span>
        {snapshot.last_restart_reason && (
          <span className="text-ink-muted truncate max-w-[60ch]">
            · reason{" "}
            <span className="font-mono">{snapshot.last_restart_reason}</span>
          </span>
        )}
        {status === "Restarting" && snapshot.max_attempts > 0 && (
          <span className="text-ink-muted">
            · attempt{" "}
            <span className="font-mono">
              {snapshot.attempt_n}/{snapshot.max_attempts}
            </span>
          </span>
        )}
        {status === "Halted" &&
          sub_state === "CircuitOpen" &&
          snapshot.window_secs > 0 && (
            <span className="text-ink-muted">
              · {snapshot.attempts_in_window} attempts in last{" "}
              {snapshot.window_secs}s window
            </span>
          )}
      </div>
      <div className="flex items-center gap-3">
        {!snapshot.fresh && (
          <span
            data-testid="kernel-lifecycle-stale"
            className="text-ink-subtle"
          >
            stale (supervisor has not written recently)
          </span>
        )}
        {snapshot.updated_at_unix_secs > 0 && (
          <span className="text-ink-subtle">
            updated {fmtAbsolute(snapshot.updated_at_unix_secs)}
          </span>
        )}
      </div>
    </div>
  );
}

type BannerTone = "hidden" | "warn" | "stop";

/// Computes the banner tone from the snapshot. Pure function so
/// tests can drive every branch without a React tree.
export function bannerTone(s: KernelLifecycleResponse): BannerTone {
  // No supervisor in play (default-off opt-in) ⇒ never paint.
  // The kernel handler returns `Healthy { fresh: true,
  // supervisor_pid: 0 }` in this case; we want zero chrome.
  if (s.status === "Healthy" && s.supervisor_pid === 0) return "hidden";
  // Healthy + supervisor running ⇒ also no banner. The
  // operator opted in but everything is fine; chrome would be
  // noise.
  if (s.status === "Healthy") return "hidden";
  if (s.status === "Restarting") return "warn";
  if (s.status === "Halted") return "stop";
  // Unknown / future status ⇒ render as warn so we don't
  // silently swallow a state the FE doesn't know about yet.
  return "warn";
}

/// Headline string lookup. Pure for the same testability reason
/// as `bannerTone` above. Mirrors the wording in
/// `self-healing-supervisor.md §5.4`.
export function headlineFor(s: KernelLifecycleResponse): string {
  if (s.status === "Restarting") return "Kernel restarting";
  if (s.status === "Halted") {
    switch (s.sub_state) {
      case "CircuitOpen":
        return "Kernel halted — restart circuit OPEN";
      case "OperatorStop":
        return "Kernel stopped by operator";
      case "OperatorStopForced":
        return "Kernel force-killed by operator (grace exceeded)";
      case "SupervisorGone":
        return "Supervisor process gone";
      default:
        return "Kernel halted";
    }
  }
  // Unknown status — surface verbatim so the operator at least
  // sees what the supervisor reported.
  return `Kernel status: ${s.status}`;
}
