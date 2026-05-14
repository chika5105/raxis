// Audit-event importance classifier shared by:
//   * The "Recent activity" widget on the Home page — filters the
//     newest-N teaser to operator-relevant events ONLY (so the
//     widget is not buried by `OperatorViewed*` read-only spam).
//   * The "/audit" Audit Chain page — drives the
//     "Hide read-only operator views" toggle so the full chain can
//     be hidden / shown without re-querying the backend.
//
// Anchors:
//   * `INV-DASHBOARD-RECENT-ACTIVITY-FILTER-01` — Overview teaser
//     MUST exclude `OperatorViewed*` and surface operator-relevant
//     state transitions (`*Started/*Completed/*Failed`, witness
//     assertions, planner-fetch responses, escalations, security
//     events, kernel lifecycle, integration merges, …).
//   * `INV-DASHBOARD-AUDIT-OPERATOR-READ-TOGGLE-01` — `/audit`
//     ships a default-ON filter that hides `OperatorViewed*` from
//     display; the underlying chain is unchanged.
//
// Design choice: a SUFFIX-driven matcher (the same approach
// `audit-tone.ts` uses) rather than an exhaustive event-kind
// allowlist. A literal allowlist drifts the moment a kernel sibling
// worker lands a new event kind; suffix rules keep the filter
// useful across iterations without a dashboard-side touch each
// time. The single fixed prefix we DO match exactly is the
// `OperatorViewed*` family, which is the user-specified spam
// signal we are squelching.

/// Returns `true` when `eventKind` is a pure read-only operator
/// page-view event — `OperatorViewedInitiativeList`,
/// `OperatorViewedSessionList`, `OperatorViewedAuditChain`,
/// `OperatorViewedEscalationList`, `OperatorViewedSession`,
/// `OperatorViewedInitiative`, `OperatorOpenedSessionStream`,
/// `OperatorViewedTask`, etc. These events are emitted whenever
/// the operator clicks around the dashboard and have no
/// state-transition semantics — they are forensic-only and MUST
/// be filtered from the home-page teaser (and toggled off by
/// default on the Audit page).
///
/// Note: `OperatorViewed*` is the exact dashboard naming
/// convention; the broader `Operator*` namespace includes
/// state-changing variants (e.g. `OperatorRevealedCredential`,
/// `OperatorApprovedRespawnEscalation`,
/// `OperatorDeniedRespawnEscalation`,
/// `OperatorPolicyUpdated`, `OperatorCertInstalled`) which are
/// **NOT** filtered — those are first-class operator-relevant
/// actions.
export function isOperatorReadOnlyView(eventKind: string): boolean {
  // Anchored prefix match. The pure-read namespace is exactly
  // `OperatorViewed*` (and the analogous `OperatorOpened*` for
  // long-poll / SSE attachments, which are also read-only side
  // effects of the operator browsing). Anything outside these
  // two prefixes is treated as a write-or-decision event.
  if (eventKind.startsWith("OperatorViewed")) return true;
  if (eventKind.startsWith("OperatorOpened")) return true;
  return false;
}

/// Returns `true` when `eventKind` represents an
/// operator-relevant event — i.e. one that belongs in the
/// home-page "Recent activity" teaser. The current heuristic:
///
///   * Exclude every `OperatorViewed*` / `OperatorOpened*`
///     pure-read event (see [`isOperatorReadOnlyView`]).
///   * Include EVERYTHING ELSE.
///
/// Inverting the test (allowlist) was the original spec sketch,
/// but the kernel ships ≥ 80 event variants today and grows on
/// every iter. A denylist of the well-known pure-read prefixes
/// keeps the teaser useful out-of-the-box for any new event the
/// kernel lands — a new `*Started`/`*Completed`/`*Crashed` kind
/// shows up in the teaser immediately without a dashboard PR.
///
/// `INV-DASHBOARD-RECENT-ACTIVITY-FILTER-01` pins the contract:
/// the teaser is the operator-relevant subset; the full chain
/// is on `/audit` (and can be filtered there too via the
/// "Hide read-only operator views" toggle).
export function isOperatorRelevantEvent(eventKind: string): boolean {
  return !isOperatorReadOnlyView(eventKind);
}
