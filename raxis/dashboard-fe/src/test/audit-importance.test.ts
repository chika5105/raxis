/* Audit-event importance classifier — pinned by:
 *
 *   * `INV-DASHBOARD-RECENT-ACTIVITY-FILTER-01` — Home-page
 *     "Recent activity" teaser MUST surface only operator-relevant
 *     events.
 *   * `INV-DASHBOARD-AUDIT-OPERATOR-READ-TOGGLE-01` — `/audit` ships
 *     a default-ON filter that hides `OperatorViewed*` /
 *     `OperatorOpened*` rows from display.
 *
 * The matching FE bug (iter48 QA defect #3): the Recent Activity
 * widget showed 10 entries, all `OperatorViewedInitiativeList /
 * OperatorViewedSessionList / OperatorViewedAuditChain /
 * OperatorViewedEscalationList` — meaningful events (state
 * transitions, witness assertions, planner-fetch responses,
 * escalations) were completely buried. */

import { describe, expect, it } from "vitest";

import {
  isOperatorReadOnlyView,
  isOperatorRelevantEvent,
} from "@/lib/audit-importance";

describe("isOperatorReadOnlyView", () => {
  it("flags every OperatorViewed* page-view kind", () => {
    // The exact kinds the iter48 QA screenshot listed.
    const READ_ONLY = [
      "OperatorViewedInitiativeList",
      "OperatorViewedSessionList",
      "OperatorViewedAuditChain",
      "OperatorViewedEscalationList",
      "OperatorViewedSession",
      "OperatorViewedInitiative",
      "OperatorViewedTask",
    ];
    for (const k of READ_ONLY) {
      expect(isOperatorReadOnlyView(k)).toBe(true);
    }
  });

  it("flags OperatorOpened* attachments (SSE stream attach, etc.)", () => {
    // Long-poll / SSE attach events are pure read-side effects of
    // the operator browsing — they don't represent a state
    // transition the teaser should highlight.
    expect(isOperatorReadOnlyView("OperatorOpenedSessionStream")).toBe(true);
  });

  it("does NOT flag operator decision events", () => {
    // These are first-class operator actions (state-changing,
    // policy-approving, credential-revealing). They are NOT
    // filtered — they belong on the home-page teaser AND on the
    // audit page even with the default-ON toggle.
    const DECISIONS = [
      "OperatorRevealedCredential",
      "OperatorApprovedRespawnEscalation",
      "OperatorDeniedRespawnEscalation",
      "OperatorPolicyUpdated",
      "OperatorCertInstalled",
      "OperatorRotatedEpoch",
    ];
    for (const k of DECISIONS) {
      expect(isOperatorReadOnlyView(k)).toBe(false);
    }
  });

  it("does NOT flag kernel / planner / witness / escalation events", () => {
    const KEEP = [
      "InitiativeApproved",
      "InitiativeCompleted",
      "InitiativeFailed",
      "TaskAdmitted",
      "TaskCompleted",
      "TaskFailed",
      "WitnessAsserted",
      "WitnessRejected",
      "ReviewSubmitted",
      "IntegrationMergeCompleted",
      "KernelStopped",
      "KernelCrashed",
      "KernelRestarted",
      "SecurityViolationDetected",
      "EscalationCreated",
      "EscalationResolved",
      "PlannerFetchCompleted",
    ];
    for (const k of KEEP) {
      expect(isOperatorReadOnlyView(k)).toBe(false);
    }
  });
});

describe("isOperatorRelevantEvent (Recent-Activity widget filter)", () => {
  it("includes meaningful state transitions and witness/escalation/planner events", () => {
    const RELEVANT = [
      "InitiativeApproved",
      "TaskAdmitted",
      "TaskCompleted",
      "WitnessAsserted",
      "ReviewSubmitted",
      "IntegrationMergeCompleted",
      "KernelStopped",
      "SecurityViolationDetected",
      "EscalationCreated",
      "OperatorRevealedCredential",
      "OperatorApprovedRespawnEscalation",
    ];
    for (const k of RELEVANT) {
      expect(isOperatorRelevantEvent(k)).toBe(true);
    }
  });

  it("excludes every OperatorViewed* / OperatorOpened* row", () => {
    const SUPPRESSED = [
      "OperatorViewedInitiativeList",
      "OperatorViewedSessionList",
      "OperatorViewedAuditChain",
      "OperatorViewedEscalationList",
      "OperatorViewedSession",
      "OperatorViewedInitiative",
      "OperatorOpenedSessionStream",
    ];
    for (const k of SUPPRESSED) {
      expect(isOperatorRelevantEvent(k)).toBe(false);
    }
  });

  // The iter48 chain used as the headline evidence: 1260 events,
  // ~90% page-view spam. After filtering, the teaser MUST contain
  // ONLY the operator-relevant rows (with default ordering
  // preserved). This walks a representative slice in canonical
  // order.
  it("a fixture chain with mixed spam + relevant events filters down to the meaningful subset", () => {
    const chain = [
      { kind: "OperatorViewedInitiativeList",    relevant: false },
      { kind: "InitiativeApproved",              relevant: true  },
      { kind: "OperatorViewedSessionList",       relevant: false },
      { kind: "TaskAdmitted",                    relevant: true  },
      { kind: "OperatorViewedAuditChain",        relevant: false },
      { kind: "OperatorViewedEscalationList",    relevant: false },
      { kind: "WitnessAsserted",                 relevant: true  },
      { kind: "OperatorOpenedSessionStream",     relevant: false },
      { kind: "ReviewSubmitted",                 relevant: true  },
      { kind: "IntegrationMergeCompleted",       relevant: true  },
      { kind: "OperatorViewedSession",           relevant: false },
      { kind: "OperatorRevealedCredential",      relevant: true  },
      { kind: "OperatorApprovedRespawnEscalation", relevant: true },
      { kind: "OperatorDeniedRespawnEscalation", relevant: true  },
    ];
    const kept = chain
      .filter((e) => isOperatorRelevantEvent(e.kind))
      .map((e) => e.kind);
    const expected = chain.filter((e) => e.relevant).map((e) => e.kind);
    expect(kept).toEqual(expected);
    // Spot-check: the page-view spam is fully gone.
    expect(kept.some((k) => k.startsWith("OperatorViewed"))).toBe(false);
    expect(kept.some((k) => k.startsWith("OperatorOpened"))).toBe(false);
  });
});
