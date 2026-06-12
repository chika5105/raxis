// Pure helpers for `<KernelLifecycleBanner>`.
//
// Split out from `KernelLifecycleBanner.tsx` so the component file
// only exports React components — keeps the
// `react-refresh/only-export-components` rule happy and gives the
// unit tests a non-tsx entry point.
//
// Spec: `raxis/specs/v2/self-healing-supervisor.md §5.4` +
//       `INV-DASHBOARD-KERNEL-LIFECYCLE-01` +
//       `INV-SUPERVISOR-AUTO-RESUME-ON-CLEAN-RESTART-01`.

import type { KernelLifecycleResponse } from "@/types/api";

export type BannerTone = "hidden" | "ok" | "warn" | "stop";

function hasHostRestartRecovery(s: KernelLifecycleResponse): boolean {
  return (s.host_restart_recovery?.tasks.length ?? 0) > 0;
}

/// Computes the banner tone from the snapshot. Pure function so
/// tests can drive every branch without a React tree.
export function bannerTone(s: KernelLifecycleResponse): BannerTone {
  // Restart in flight or halt always wins over the auto-resume
  // pill — those are the operator's primary signals.
  if (s.status === "Restarting") return "warn";
  if (s.status === "Halted") return "stop";
  // V2.5 §3.5 auto-resume: when the kernel handler surfaced a
  // recent auto-resume episode, paint a transient pill in
  // place of the otherwise-hidden Healthy banner.
  //
  //   * Full auto-resume (no skips, no failures) → green pill.
  //   * Partial (any skipped or transition-failed) → amber.
  //
  // There is no "auto-resume disabled" state because the
  // supervisor opt-out (`RAXIS_SUPERVISOR_AUTO_RESTART=0`) is
  // also the auto-resume opt-out — see
  // `INV-SUPERVISOR-AUTO-RESUME-ON-CLEAN-RESTART-01`. With the
  // supervisor disabled there IS no auto-resume episode to
  // surface, so no pill renders.
  if (s.auto_resume) {
    const partial =
      s.auto_resume.skipped_quarantined > 0 ||
      s.auto_resume.skipped_pre_existing_block > 0 ||
      s.auto_resume.transition_failed > 0;
    return partial ? "warn" : "ok";
  }
  if (hasHostRestartRecovery(s)) return "warn";
  // No supervisor in play (default-off opt-in) ⇒ never paint.
  // The kernel handler returns `Healthy { fresh: true,
  // supervisor_pid: 0 }` in this case; we want zero chrome.
  if (s.status === "Healthy" && s.supervisor_pid === 0) return "hidden";
  // Healthy + supervisor running ⇒ also no banner. The
  // operator opted in but everything is fine; chrome would be
  // noise.
  if (s.status === "Healthy") return "hidden";
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
  if (s.status === "Healthy" && s.auto_resume) {
    const partial =
      s.auto_resume.skipped_quarantined > 0 ||
      s.auto_resume.skipped_pre_existing_block > 0 ||
      s.auto_resume.transition_failed > 0;
    return partial
      ? "Kernel restored — partial auto-resume"
      : "Kernel restored — work auto-resumed";
  }
  if (s.status === "Healthy" && hasHostRestartRecovery(s)) {
    return "Recovery after host restart";
  }
  // Unknown status — surface verbatim so the operator at least
  // sees what the supervisor reported.
  return `Kernel status: ${s.status}`;
}
