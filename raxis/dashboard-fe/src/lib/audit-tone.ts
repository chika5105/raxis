// Map an audit-event kind name to a semantic tone the chrome can
// color a badge with. The mapping is intentionally suffix-driven
// rather than an exhaustive enum so it survives every new kernel
// event variant the spec lands without a dashboard touch — when
// the live-e2e or V3 worker adds a new `*Failed` / `*Approved` /
// `*Detected` event, the audit timeline picks up the right tone
// automatically. Unknown kinds fall back to `default` (neutral
// chrome) so an unrecognised payload never renders as alarming.
//
// Tone palette aligns with the existing semantic CSS variables
// (`ok`, `warn`, `bad`, `info`, `block`, `accent`) so the badge
// re-skins itself across dark / light without bespoke CSS.

export type AuditTone = "default" | "ok" | "warn" | "bad" | "info" | "block";

// Suffix-based classifier. The first matching rule wins; ordering
// reflects severity (bad > warn > ok > info > block) so a kind
// like `EscalationRateLimitExceeded` reads as `bad` (operator
// surface), not `block` (operational throttle). Endings are
// matched as whole words so `KernelStarted` does not collide with
// `BreakglassActivated`'s `*ed` suffix.
const SUFFIX_RULES: ReadonlyArray<readonly [RegExp, AuditTone]> = [
  // Hard failures, security trips, and revoked credentials.
  // `Detected` is bucketed here because every kernel kind carrying
  // that suffix today is a security / liveness alarm
  // (`SecurityViolationDetected`, `SessionEgressStallDetected`,
  // …) — none of them are neutral observations.
  [
    /(Failed|FailedFinal|FailFinal|Crashed|Denied|Rejected|Refused|Revoked|Quarantined|Aborted|Violation|ViolationDetected|StallDetected|Unverifiable|Inconsistent|Bypass|Bypassed|RateLimitExceeded|HaltEntered|TimedOut|ProcessFailed)$/,
    "bad",
  ],
  // Recoverable warnings the operator should glance at.
  [
    /(Attempted|Deferred|MarkedStale|ExpiringSoon|InGracePeriod|Stopped|Backpressure|Throttled)$/,
    "warn",
  ],
  // Successful state transitions.
  [
    /(Completed|Approved|Accepted|Verified|Healed|Repaired|Connected|Acknowledged|Consumed|Delivered|Relayed|Activated)$/,
    "ok",
  ],
  // Throttle / admission control — useful to spot but not alarms.
  [
    /(Backoff|Throttle|StateChanged|QueueFull|Reservation|Sweep|Swept|Gap)$/,
    "block",
  ],
  // Lifecycle creates / starts / spawns / advances. Catch-all for
  // the high-volume "kernel ticked" events.
  [
    /(Created|Started|Spawned|Submitted|Installed|Registered|Updated|Advanced|Selected|Admitted|Enqueued|Granted|Rotated|Emitted|Pushed|Scaled|Served|Used|Executed|Read|Accessed|Forwarded|Refreshed|Hit)$/,
    "info",
  ],
];

// Special-case kinds whose name doesn't end in a recognisable verb
// suffix but still carry a clear tone. Add sparingly — every
// addition is a maintenance liability.
const KIND_OVERRIDES: Record<string, AuditTone> = {
  GenesisRecord: "info",
  KernelStarted: "info",
  KernelStopped: "warn",
  EmergencyOperatorUsed: "bad",
  ReplayRejected: "bad",
  ReconciliationGap: "warn",
  IntegrationMergeCompleted: "ok",
  PolicyEpochAdvanced: "info",
  PolicyUpdatedViaDashboard: "info",
};

export function auditTone(eventKind: string): AuditTone {
  if (KIND_OVERRIDES[eventKind] !== undefined) {
    return KIND_OVERRIDES[eventKind];
  }
  for (const [pattern, tone] of SUFFIX_RULES) {
    if (pattern.test(eventKind)) {
      return tone;
    }
  }
  return "default";
}

// Tailwind class string for a `<span class="badge …">` rendered
// next to an audit row. Uses the existing `--c-{ok,warn,bad,info,
// block}` semantic variables (set in `styles/global.css` for both
// dark + light themes) so the colours track theme automatically.
//
// `default` keeps the prior look-and-feel so unfamiliar kinds do
// not visually shout.
export function auditBadgeClasses(eventKind: string): string {
  const tone = auditTone(eventKind);
  switch (tone) {
    case "ok":
      return "badge bg-ok-muted/30 border-ok/40 text-ok";
    case "warn":
      return "badge bg-warn-muted/30 border-warn/40 text-warn";
    case "bad":
      return "badge bg-bad-muted/30 border-bad/40 text-bad";
    case "info":
      return "badge bg-info-muted/30 border-info/40 text-info";
    case "block":
      return "badge bg-block-muted/30 border-block/40 text-block";
    case "default":
    default:
      return "badge bg-panel-high text-ink-muted border-edge-strong";
  }
}
