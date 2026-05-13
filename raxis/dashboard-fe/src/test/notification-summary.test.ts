import { describe, expect, it } from "vitest";

import {
  isPlaceholderSummary,
  notificationDisplaySummary,
  summarizeNotificationPayload,
} from "@/lib/notification-summary";

describe("isPlaceholderSummary", () => {
  it("recognises the kernel's `<EventKind> (no summary)` placeholder", () => {
    expect(isPlaceholderSummary("MongoCommandExecuted (no summary)")).toBe(
      true,
    );
    expect(isPlaceholderSummary("CredentialAccessed (no summary)  ")).toBe(
      true,
    );
    expect(isPlaceholderSummary("")).toBe(true);
    expect(isPlaceholderSummary(null)).toBe(true);
    expect(isPlaceholderSummary(undefined)).toBe(true);
  });

  it("does not flag a real kernel-rendered summary", () => {
    expect(
      isPlaceholderSummary("Escalation 019e1f05 APPROVED by alice@raxis.dev"),
    ).toBe(false);
    expect(isPlaceholderSummary("Policy advanced to epoch 12 by alice")).toBe(
      false,
    );
  });
});

describe("summarizeNotificationPayload", () => {
  it("derives a credential-proxy connect line", () => {
    const summary = summarizeNotificationPayload(
      "CredentialProxyUpstreamConnected",
      {
        credential_name: "test-pg-dev",
        handshake_ms: 54,
        proxy_type: "postgres",
        tls: false,
        upstream_host: "127.0.0.1",
        upstream_port: 54399,
      },
    );
    expect(summary).toBe(
      'postgres proxy "test-pg-dev" connected to 127.0.0.1:54399 in 54 ms',
    );
  });

  it("derives a CredentialProxySubstituted line", () => {
    expect(
      summarizeNotificationPayload("CredentialProxySubstituted", {
        credential_name: "test-pg-dev",
        proxy_type: "postgres",
        real_resolved: true,
        session_id: "3258b2d3-629d-4706-81cf-ac424df163b1",
        substitution_shape: "scram-sha-256",
      }),
    ).toBe(
      'postgres proxy "test-pg-dev" substituted real credential (shape=scram-sha-256)',
    );
    expect(
      summarizeNotificationPayload("CredentialProxySubstituted", {
        credential_name: "synthetic-pg",
        proxy_type: "postgres",
        real_resolved: false,
        substitution_shape: "scram-sha-256",
      }),
    ).toBe(
      'postgres proxy "synthetic-pg" substituted real credential (shape=scram-sha-256, real-resolved=false)',
    );
  });

  it("derives a TLS-up connect line when tls=true", () => {
    const summary = summarizeNotificationPayload(
      "CredentialProxyUpstreamConnected",
      {
        credential_name: "prod-pg",
        handshake_ms: 12,
        proxy_type: "postgres",
        tls: true,
        upstream_host: "db.internal",
        upstream_port: 5432,
      },
    );
    expect(summary).toBe(
      'postgres proxy "prod-pg" connected to db.internal:5432 over TLS in 12 ms',
    );
  });

  it("derives a query-completed line with rows + bytes + duration", () => {
    const summary = summarizeNotificationPayload("DatabaseQueryCompleted", {
      bytes_returned: 2776,
      credential_name: "test-pg-dev",
      duration_ms: 3,
      proxy_type: "postgres",
      rows_returned: 25,
      sql_sha256:
        "32286b827a2c72fe5f76406597b2821756adf412753213207118bfc9c74fb6a7",
      upstream_error: null,
    });
    expect(summary).toBe(
      'postgres "test-pg-dev" returned 25 rows, 2.7 KiB in 3 ms',
    );
  });

  it("surfaces the upstream error on a failed query", () => {
    const summary = summarizeNotificationPayload("DatabaseQueryCompleted", {
      bytes_returned: 0,
      credential_name: "test-pg-dev",
      duration_ms: 12,
      proxy_type: "postgres",
      rows_returned: 0,
      sql_sha256: null,
      upstream_error: "connection reset by peer",
    });
    expect(summary).toBe(
      'postgres "test-pg-dev" query FAILED: connection reset by peer',
    );
  });

  it("derives a CredentialAccessed line with consumer + backend", () => {
    const summary = summarizeNotificationPayload("CredentialAccessed", {
      backend_kind: "file",
      consumer_id: "3258b2d3-629d-4706-81cf-ac424df163b1",
      consumer_kind: "session",
      name: "test-mongo-dev",
      success: true,
    });
    expect(summary).toBe(
      'session 3258b2d3 accessed credential "test-mongo-dev" (file backend)',
    );
  });

  it("flips CredentialAccessed verb when success=false", () => {
    const summary = summarizeNotificationPayload("CredentialAccessed", {
      backend_kind: "file",
      consumer_id: "3258b2d3-629d-4706-81cf-ac424df163b1",
      consumer_kind: "session",
      name: "secret-x",
      success: false,
    });
    expect(summary).toBe(
      'session 3258b2d3 denied access to credential "secret-x" (file backend)',
    );
  });

  it("derives a MongoCommandExecuted line", () => {
    expect(
      summarizeNotificationPayload("MongoCommandExecuted", {
        blocked: false,
        command: "isMaster",
        credential_name: "test-mongo-dev",
      }),
    ).toBe('mongodb "test-mongo-dev" ran isMaster');

    expect(
      summarizeNotificationPayload("MongoCommandExecuted", {
        blocked: true,
        command: "shutdown",
        credential_name: "prod-mongo",
      }),
    ).toBe('mongodb "prod-mongo" ran shutdown — BLOCKED');
  });

  it("derives a SessionVmSpawned line with task + backend + tier", () => {
    const summary = summarizeNotificationPayload("SessionVmSpawned", {
      admission_loopback: "127.0.0.1:53891",
      backend_id: "apple-vz-14.x",
      credential_proxies: 2,
      egress_tier: "Tier1Tproxy",
      initiative_id: "019e1f05-0146-77a3-b455-2dd3e8fdf4b9",
      session_id: "3258b2d3-629d-4706-81cf-ac424df163b1",
      task_id: "materialize-records",
    });
    expect(summary).toBe(
      "Session 3258b2d3 VM spawned for materialize-records (backend=apple-vz-14.x, egress=Tier1Tproxy, 2 cred proxies)",
    );
  });

  it("pluralises cred proxy correctly when count=1", () => {
    const summary = summarizeNotificationPayload("SessionVmSpawned", {
      backend_id: "apple-vz-14.x",
      credential_proxies: 1,
      egress_tier: "Tier1Tproxy",
      session_id: "3258b2d3-629d-4706-81cf-ac424df163b1",
      task_id: "materialize-records",
    });
    expect(summary).toBe(
      "Session 3258b2d3 VM spawned for materialize-records (backend=apple-vz-14.x, egress=Tier1Tproxy, 1 cred proxy)",
    );
  });

  it("derives a SessionCreated line", () => {
    expect(
      summarizeNotificationPayload("SessionCreated", {
        initiative_id: "019e1f05-0146-77a3-b455-2dd3e8fdf4b9",
        role: "executor",
        session_id: "3258b2d3-629d-4706-81cf-ac424df163b1",
      }),
    ).toBe("Session 3258b2d3 created (executor) for initiative 019e1f05");
  });

  it("derives a PlanApproved line", () => {
    expect(
      summarizeNotificationPayload("PlanApproved", {
        initiative_id: "019e1f05-0146-77a3-b455-2dd3e8fdf4b9",
        task_count: 9,
      }),
    ).toBe("Plan approved for 019e1f05 (9 tasks)");
  });

  it("derives an InitiativeCreated line", () => {
    expect(
      summarizeNotificationPayload("InitiativeCreated", {
        initiative_id: "019e1f05-0146-77a3-b455-2dd3e8fdf4b9",
        plan_hash:
          "2dd2aa3a666bd61c0f50c69ff1592da545628744b2563a5613388fa639d1b490",
        signed_at: 1778636882,
        signed_by: "f8dda84490292405",
      }),
    ).toBe("Initiative 019e1f05 created (plan 2dd2aa3a), signed by f8dda844");
  });

  it("derives V3 cloud-credential lines", () => {
    expect(
      summarizeNotificationPayload("CloudCredentialForwarded", {
        credential_name: "aws-prod",
        provider: "aws",
        session_id: "3258b2d3-629d-4706-81cf-ac424df163b1",
      }),
    ).toBe('aws credential "aws-prod" forwarded to session 3258b2d3');

    expect(
      summarizeNotificationPayload("CloudCredentialCacheHit", {
        credential_name: "gcp-readonly",
        provider: "gcp",
        session_id: "3258b2d3-629d-4706-81cf-ac424df163b1",
      }),
    ).toBe('gcp credential "gcp-readonly" cache hit to session 3258b2d3');
  });

  it("derives a SessionEgressStallDetected line", () => {
    expect(
      summarizeNotificationPayload("SessionEgressStallDetected", {
        chokepoint: "AdmissionLoopback",
        session_id: "3258b2d3-629d-4706-81cf-ac424df163b1",
        stall_ms: 4500,
      }),
    ).toBe(
      "Egress STALLED on session 3258b2d3 (chokepoint=AdmissionLoopback, 4500 ms)",
    );
  });

  it("returns null for a payload with the wrong shape", () => {
    expect(
      summarizeNotificationPayload("CredentialProxyUpstreamConnected", {
        unrelated: 1,
      }),
    ).toBeNull();
    expect(
      summarizeNotificationPayload("MongoCommandExecuted", null),
    ).toBeNull();
    expect(
      summarizeNotificationPayload("MongoCommandExecuted", "string"),
    ).toBeNull();
  });

  it("returns null for an unknown event kind", () => {
    expect(
      summarizeNotificationPayload("ZzzUnknownVariant", {
        anything: 1,
      }),
    ).toBeNull();
  });
});

describe("notificationDisplaySummary", () => {
  it("keeps a real kernel summary verbatim", () => {
    const got = notificationDisplaySummary(
      "Escalation E1 APPROVED by alice@raxis.dev",
      "EscalationApproved",
      {},
    );
    expect(got).toBe("Escalation E1 APPROVED by alice@raxis.dev");
  });

  it("substitutes the FE-derived summary when the backend placeholder is set", () => {
    const got = notificationDisplaySummary(
      "MongoCommandExecuted (no summary)",
      "MongoCommandExecuted",
      {
        blocked: false,
        command: "isMaster",
        credential_name: "test-mongo-dev",
      },
    );
    expect(got).toBe('mongodb "test-mongo-dev" ran isMaster');
  });

  it("falls all the way back to the placeholder when nothing else works", () => {
    const got = notificationDisplaySummary(
      "ZzzUnknownVariant (no summary)",
      "ZzzUnknownVariant",
      { whatever: true },
    );
    expect(got).toBe("ZzzUnknownVariant (no summary)");
  });

  it("uses the event kind itself when both summary + derivation are empty", () => {
    const got = notificationDisplaySummary("", "ZzzUnknownVariant", undefined);
    expect(got).toBe("ZzzUnknownVariant");
  });
});
