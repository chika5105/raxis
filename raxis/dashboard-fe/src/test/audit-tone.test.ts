import { describe, expect, it } from "vitest";

import { auditBadgeClasses, auditTone } from "@/lib/audit-tone";

describe("auditTone", () => {
  it("classifies hard failures as bad", () => {
    expect(auditTone("PlanRejected")).toBe("bad");
    expect(auditTone("PushFailed")).toBe("bad");
    expect(auditTone("GatewayCrashed")).toBe("bad");
    expect(auditTone("CredentialProxyUpstreamFailed")).toBe("bad");
    expect(auditTone("OperatorCertRevoked")).toBe("bad");
    expect(auditTone("InitiativeQuarantined")).toBe("bad");
    expect(auditTone("InitiativeAborted")).toBe("bad");
    expect(auditTone("SessionVmFailedFinal")).toBe("bad");
    expect(auditTone("SecurityViolationDetected")).toBe("bad");
    expect(auditTone("EscalationRateLimitExceeded")).toBe("bad");
    expect(auditTone("DiskFullHaltEntered")).toBe("bad");
    expect(auditTone("VerifierProcessFailed")).toBe("bad");
    expect(auditTone("EmergencyOperatorUsed")).toBe("bad");
    expect(auditTone("ReplayRejected")).toBe("bad");
    expect(auditTone("DelegationSignatureUnverifiable")).toBe("bad");
    expect(auditTone("CloudCredentialForwardingDenied")).toBe("bad");
  });

  it("classifies recoverable signals as warn", () => {
    expect(auditTone("PushAttempted")).toBe("warn");
    expect(auditTone("OperatorCertExpiringSoon")).toBe("warn");
    expect(auditTone("DelegationMarkedStale")).toBe("warn");
    expect(auditTone("KernelStopped")).toBe("warn");
    expect(auditTone("SessionVmScaleDeferred")).toBe("warn");
    expect(auditTone("ReconciliationGap")).toBe("warn");
  });

  it("classifies success transitions as ok", () => {
    expect(auditTone("PlanApproved")).toBe("ok");
    expect(auditTone("DatabaseQueryCompleted")).toBe("ok");
    expect(auditTone("CredentialProxyUpstreamConnected")).toBe("ok");
    expect(auditTone("CredentialVerified")).toBe("ok");
    expect(auditTone("WitnessAccepted")).toBe("ok");
    expect(auditTone("IntentAccepted")).toBe("ok");
    expect(auditTone("GitConsistencyRepaired")).toBe("ok");
    expect(auditTone("IntegrationMergeCompleted")).toBe("ok");
  });

  it("classifies lifecycle / informational events as info", () => {
    expect(auditTone("InitiativeCreated")).toBe("info");
    expect(auditTone("KernelStarted")).toBe("info");
    expect(auditTone("GenesisRecord")).toBe("info");
    expect(auditTone("SessionVmSpawned")).toBe("info");
    expect(auditTone("OperatorCertInstalled")).toBe("info");
    expect(auditTone("CloudCredentialForwarded")).toBe("info");
    expect(auditTone("PolicyEpochAdvanced")).toBe("info");
    expect(auditTone("AwsCredentialServed")).toBe("info");
    expect(auditTone("DatabaseQueryExecuted")).toBe("info");
  });

  it("classifies throttle / admission events as block", () => {
    expect(auditTone("AdmissionQueueFull")).toBe("block");
    expect(auditTone("CircuitBreakerStateChanged")).toBe("block");
    expect(auditTone("OperatorQuarantineSwept")).toBe("block");
  });

  it("falls through to default for unfamiliar kinds", () => {
    expect(auditTone("ZzzUnknownVariant")).toBe("default");
    expect(auditTone("")).toBe("default");
  });

  it("auditBadgeClasses returns the right tailwind tone", () => {
    expect(auditBadgeClasses("PlanApproved")).toContain("text-ok");
    expect(auditBadgeClasses("PlanRejected")).toContain("text-bad");
    expect(auditBadgeClasses("PushAttempted")).toContain("text-warn");
    expect(auditBadgeClasses("InitiativeCreated")).toContain("text-info");
    expect(auditBadgeClasses("CircuitBreakerStateChanged")).toContain(
      "text-block",
    );
    expect(auditBadgeClasses("ZzzUnknown")).toContain("text-ink-muted");
  });
});
