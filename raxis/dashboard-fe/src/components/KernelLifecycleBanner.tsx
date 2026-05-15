import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";

import { dashboardApi } from "@/api/client";
import { fmtAbsolute } from "@/lib/format";
import type { KernelLifecycleResponse } from "@/types/api";

import { bannerTone, headlineFor } from "./KernelLifecycleBanner.helpers";

// Surfaces the supervisor's view of the kernel lifecycle.
//
// Spec: `raxis/specs/v2/self-healing-supervisor.md §5.4` +
//       `§3.5` (auto-resume) /
//       `INV-DASHBOARD-KERNEL-LIFECYCLE-01` +
//       `INV-SUPERVISOR-AUTO-RESUME-ON-CLEAN-RESTART-01`.
//
// Visibility contract:
//   * `Healthy` + sentinel absent OR `supervisor_pid === 0` AND
//     no recent `auto_resume` summary ⇒ render NOTHING.
//     Operators who never opted into the
//     `RAXIS_SUPERVISOR_AUTO_RESTART=1` workflow should not
//     see banner chrome on every dashboard pane.
//   * `Restarting`     ⇒ amber banner with attempt N/M + reason.
//   * `Halted` + sub_state ⇒ rose banner (supervisor stopped
//     attempting; operator action required).
//   * `Healthy` + recent `auto_resume` summary present ⇒
//     green pill (full auto-resume — every BRP swept by the
//     restart was re-admitted) or amber pill (partial — at
//     least one task stayed paused because of operator
//     quarantine, pre-existing block, or transition failure).
//     The pill is transient — the kernel handler suppresses
//     the field after the 5-minute visibility window
//     (`AUTO_RESUME_VISIBILITY_WINDOW_SECS`).
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
    tone === "warn"
      ? "↻"
      : tone === "stop"
        ? "■"
        : tone === "ok"
          ? "✓"
          : "?";
  return (
    <div
      role="status"
      aria-live="polite"
      data-testid="kernel-lifecycle-banner"
      data-kernel-status={status}
      data-kernel-substate={sub_state ?? ""}
      data-kernel-fresh={snapshot.fresh ? "true" : "false"}
      data-kernel-tone={tone}
      className={clsx(
        "rounded-md border px-3 py-2 text-xs flex flex-wrap items-center gap-3 justify-between",
        // Light + dark mode tone pairs follow ChainStatusBanner.
        tone === "warn" &&
          "border-amber-700/40 bg-amber-700/10 text-amber-900 dark:border-amber-500/40 dark:bg-amber-500/10 dark:text-amber-200",
        tone === "stop" &&
          "border-rose-700/50 bg-rose-700/10 text-rose-800 dark:border-rose-500/50 dark:bg-rose-500/10 dark:text-rose-200",
        tone === "ok" &&
          "border-emerald-700/40 bg-emerald-700/10 text-emerald-900 dark:border-emerald-500/40 dark:bg-emerald-500/10 dark:text-emerald-200",
      )}
    >
      <div className="flex items-center gap-2 min-w-0">
        <span
          aria-hidden="true"
          className={clsx(
            "inline-flex h-4 w-4 items-center justify-center rounded-full text-[10px] font-bold leading-none",
            tone === "warn"
              ? "text-amber-700 dark:text-amber-400"
              : tone === "stop"
                ? "text-rose-700 dark:text-rose-400"
                : "text-emerald-700 dark:text-emerald-400",
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
        {snapshot.auto_resume && (
          <AutoResumeDetail summary={snapshot.auto_resume} />
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

/// Per-restart auto-resume breakdown that rides inside the main
/// banner row. Spec: `self-healing-supervisor.md §3.5` /
/// `INV-SUPERVISOR-AUTO-RESUME-ON-CLEAN-RESTART-01`.
function AutoResumeDetail({
  summary,
}: {
  summary: NonNullable<KernelLifecycleResponse["auto_resume"]>;
}) {
  // Full auto-resume ⇒ a single, dense pill. The amber-cases
  // (skipped + transition_failed counts) are conditionally
  // appended only when non-zero so the green-path stays as a
  // one-glance reassurance line.
  const hasSkipsOrFailures =
    summary.skipped_quarantined > 0 ||
    summary.skipped_pre_existing_block > 0 ||
    summary.transition_failed > 0;
  return (
    <span
      data-testid="kernel-lifecycle-auto-resume"
      className="text-ink-muted truncate max-w-[80ch]"
    >
      · auto-resumed{" "}
      <span className="font-mono">{summary.resumed}</span> task
      {summary.resumed === 1 ? "" : "s"}
      {hasSkipsOrFailures && (
        <>
          {summary.skipped_quarantined > 0 && (
            <>
              {" "}
              · skipped{" "}
              <span className="font-mono">
                {summary.skipped_quarantined}
              </span>{" "}
              quarantined
            </>
          )}
          {summary.skipped_pre_existing_block > 0 && (
            <>
              {" "}
              · preserved{" "}
              <span className="font-mono">
                {summary.skipped_pre_existing_block}
              </span>{" "}
              pre-existing
            </>
          )}
          {summary.transition_failed > 0 && (
            <>
              {" "}
              · failed{" "}
              <span className="font-mono">
                {summary.transition_failed}
              </span>
            </>
          )}
        </>
      )}
    </span>
  );
}

