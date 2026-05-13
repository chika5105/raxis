import { describe, expect, it } from "vitest";

import {
  failureFromAuditEvent,
  isFailureAuditEvent,
  isFailureAuditKind,
} from "@/lib/failure-extract";

describe("isFailureAuditKind", () => {
  it("returns true for known failure kinds", () => {
    expect(isFailureAuditKind("SessionVmFailedFinal")).toBe(true);
    expect(isFailureAuditKind("ReviewerRejected")).toBe(true);
    expect(isFailureAuditKind("SessionEgressStallDetected")).toBe(true);
    expect(isFailureAuditKind("WorktreeProvisionFailed")).toBe(true);
    expect(isFailureAuditKind("OperatorApprovalDenied")).toBe(true);
    expect(isFailureAuditKind("NotificationDeliveryFailed")).toBe(true);
  });

  it("uses suffix fallback for unseen kinds", () => {
    expect(isFailureAuditKind("FutureFooFailed")).toBe(true);
    expect(isFailureAuditKind("SomethingRejected")).toBe(true);
    expect(isFailureAuditKind("ReplayRejected")).toBe(true);
  });

  it("returns false for non-failure kinds", () => {
    expect(isFailureAuditKind("KernelStarted")).toBe(false);
    expect(isFailureAuditKind("SessionCreated")).toBe(false);
    expect(isFailureAuditKind("PolicyEpochAdvanced")).toBe(false);
    expect(isFailureAuditKind("CredentialProxySubstituted")).toBe(false);
  });
});

describe("isFailureAuditEvent (payload-aware)", () => {
  it("inherits the shape-only classifier verdict", () => {
    expect(isFailureAuditEvent("SessionVmFailedFinal", {})).toBe(true);
    expect(isFailureAuditEvent("KernelStarted", {})).toBe(false);
  });

  it("treats Operator* events with a non-Accepted outcome as failures", () => {
    expect(
      isFailureAuditEvent("OperatorApproveRequested", {
        outcome: "RejectedPermission",
      }),
    ).toBe(true);
    expect(
      isFailureAuditEvent("OperatorMarkAllReadRequested", {
        outcome: "InternalError",
      }),
    ).toBe(true);
  });

  it("treats Operator* events with Accepted outcome as non-failures", () => {
    expect(
      isFailureAuditEvent("OperatorApproveRequested", { outcome: "Accepted" }),
    ).toBe(false);
  });

  it("returns false for Operator* events with no outcome field", () => {
    expect(isFailureAuditEvent("OperatorApproveRequested", {})).toBe(false);
  });
});

describe("failureFromAuditEvent", () => {
  it("returns null for non-failure kinds", () => {
    expect(
      failureFromAuditEvent("KernelStarted", { booted_at: 1 }),
    ).toBeNull();
  });

  it("extracts the canonical fields for SessionVmFailedFinal", () => {
    const f = failureFromAuditEvent("SessionVmFailedFinal", {
      session_id: "sess_abc",
      task_id: "task_xyz",
      failure_class: "Isolation",
      total_attempts: 5,
      final_reason: "exhausted VM scaling retries",
      last_attempt_backend: "firecracker",
    });
    expect(f).not.toBeNull();
    expect(f?.kind).toBe("SessionVmFailedFinal");
    expect(f?.message).toBe("exhausted VM scaling retries");
    const labels = (f?.fields ?? []).map((x) => x.label);
    expect(labels).toContain("failure_class");
    expect(labels).toContain("total_attempts");
    expect(labels).toContain("session_id");
    expect(labels).toContain("task_id");
    expect(labels).toContain("last_attempt_backend");
  });

  it("extracts reason + chokepoint for SessionEgressStallDetected", () => {
    const f = failureFromAuditEvent("SessionEgressStallDetected", {
      reason: "host outside allowlist",
      source: "tproxy",
      block_count_in_window: 7,
      window_seconds: 60,
      session_id: "sess_abc",
      host_or_sni: "evil.example.com",
      port: 443,
    });
    expect(f?.message).toBe("host outside allowlist");
    const f2 = f?.fields ?? [];
    expect(f2.find((x) => x.label === "block_count_in_window")?.value).toBe("7");
    expect(f2.find((x) => x.label === "port")?.value).toBe("443");
    expect(f2.find((x) => x.label === "host_or_sni")?.value).toBe(
      "evil.example.com",
    );
  });

  it("handles ReviewerRejected with a free-form reason", () => {
    const f = failureFromAuditEvent("ReviewerRejected", {
      reviewer_session_id: "sess_rev",
      verdict: "RequestChanges",
      reason: "test coverage regression in foo_bar.rs",
      task_id: "task_xyz",
    });
    expect(f?.message).toBe("test coverage regression in foo_bar.rs");
    expect((f?.fields ?? []).find((x) => x.label === "verdict")?.value).toBe(
      "RequestChanges",
    );
  });

  it("falls through to operator-action outcome path for Operator* events", () => {
    const f = failureFromAuditEvent("OperatorApproveRequested", {
      outcome: "RejectedPermission",
      operator_id: "operator_a",
      action: "approve_plan",
      reason: "missing dashboard:approve role",
    });
    expect(f?.message).toBe("missing dashboard:approve role");
    const labels = (f?.fields ?? []).map((x) => x.label);
    expect(labels).toContain("outcome");
    expect(labels).toContain("operator_id");
    expect(labels).toContain("action");
  });

  it("passes audit meta into the result", () => {
    const f = failureFromAuditEvent(
      "WorktreeProvisionFailed",
      { reason: "ENOSPC", task_id: "task_a" },
      { seq: 99, eventId: "evt_abc", observedAt: 1714500000 },
    );
    expect(f?.seq).toBe(99);
    expect(f?.event_id).toBe("evt_abc");
    expect(f?.observed_at).toBe(1714500000);
  });

  it("returns a FailureInfo for an unenumerated *Failed kind via the fallback", () => {
    const f = failureFromAuditEvent("FutureFooFailed", {
      reason: "something broke",
      task_id: "task_foo",
    });
    expect(f).not.toBeNull();
    expect(f?.kind).toBe("FutureFooFailed");
    expect(f?.message).toBe("something broke");
    expect((f?.fields ?? []).find((x) => x.label === "task_id")?.value).toBe(
      "task_foo",
    );
  });

  it("returns an empty message rather than throwing when the payload is missing fields", () => {
    const f = failureFromAuditEvent("InitiativeAborted", {});
    expect(f?.kind).toBe("InitiativeAborted");
    expect(f?.message).toBe("Initiative aborted by operator/kernel");
  });
});
