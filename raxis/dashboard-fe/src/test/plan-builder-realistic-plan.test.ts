import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { __planBuilderTest } from "@/pages/PlanBuilder";

const primaryPlan = readFileSync(
  "../live-e2e/examples/plan_primary.toml",
  "utf8",
);

describe("Plan Builder realistic e2e plan round-trip", () => {
  it("preserves tool profile descriptions from the primary live-e2e plan", () => {
    const parsed = __planBuilderTest.parsePlanToml(primaryPlan);
    const profile = parsed.toolProfiles.find(
      (candidate) => candidate.id === "unity_mcp_tools",
    );

    expect(profile?.description).toContain("Unity MCP adapter tools");
    expect(
      __planBuilderTest
        .validatePlan({ ...parsed, credentialSetups: [] })
        .find((issue) => issue.field === "[profiles.unity_mcp_tools].description"),
    ).toBeUndefined();
  });

  it("renders multiline initiative descriptions as valid multiline TOML", () => {
    const parsed = __planBuilderTest.parsePlanToml(primaryPlan);
    const rendered = __planBuilderTest.renderPlan(parsed);

    expect(rendered).toContain('description = """\nExtended e2e realistic scenario');
    expect(rendered).not.toContain(
      'description = "Extended e2e realistic scenario per raxis/specs/v2/e2e-extended-scenario.md\n',
    );

    const reparsed = __planBuilderTest.parsePlanToml(rendered);
    expect(reparsed.plan.initiative).toContain(
      "Extended e2e realistic scenario",
    );
    expect(reparsed.plan.initiative).toContain(
      "Cloud connections (S3 / GCP / Azure) are explicitly out of scope.",
    );
  });

  it("does not warn when a credential binding matches a registered credential", () => {
    const parsed = __planBuilderTest.parsePlanToml(primaryPlan);
    const tasks = parsed.tasks.map((task, index) =>
      index === 0
        ? {
            ...task,
            credentials: [
              {
                name: "postgres-staging",
                proxyType: "postgres" as const,
                mountAs: "DATABASE_URL",
                upstreamUrl: "",
                upstreamHostPort: "",
                authMode: "",
                project: "",
                tenantId: "",
                roleArn: "",
                clientId: "",
              },
            ],
          }
        : task,
    );

    const issues = __planBuilderTest.validatePlan({
      ...parsed,
      tasks,
      credentialSetups: [
        {
          name: "redis-staging",
          proxyType: "redis",
          mountAs: "REDIS_URL",
          upstreamUrl: "",
          upstreamHostPort: "127.0.0.1:6379",
          authMode: "",
          project: "",
          tenantId: "",
          roleArn: "",
          clientId: "",
          description: "Unrelated Redis credential.",
          environment: "staging",
          expectedShape: "redis://:PASSWORD@HOST:6379/0",
        },
      ],
      registeredCredentials: [
        {
          name: "postgres-staging",
          proxy_type: "postgres",
          environment: "staging",
          environment_source: "credential.metadata",
          backend_kind: "file",
          provider_kind: null,
          mount_as: null,
          format_hint: "Postgres staging URL",
          upstream_host_port: null,
          byte_size: 32,
          sha256_prefix: "deadbeef",
          loaded_from_path: "/var/raxis/credentials/postgres-staging.env",
          modified_unix: 1_700_000_000,
          mode_octal: "0600",
          owner_uid: 501,
          is_revealable: true,
          reveal_required_role: "admin",
        },
      ],
    });

    expect(
      issues.find((issue) =>
        issue.message.includes("postgres-staging has no setup template"),
      ),
    ).toBeUndefined();
  });

  it("maps generated TOML sections back to builder surfaces", () => {
    const parsed = __planBuilderTest.parsePlanToml(primaryPlan);
    const rendered = __planBuilderTest.renderPlan(parsed);
    const taskLine = __planBuilderTest.findPlanTomlLine(rendered, {
      kind: "task",
      taskId: "materialize-records",
    });
    const profileLine = __planBuilderTest.findPlanTomlLine(rendered, {
      kind: "tools",
      profileId: "unity_mcp_tools",
    });
    const renderedWithModel = __planBuilderTest.renderPlan({
      ...parsed,
      modelRoutes: [
        {
          alias: "executor",
          scope: "executor",
          description: "Executor provider fallback chain.",
          fallbackBehavior: "attempt_in_order",
          sessionAffinity: false,
          rotateExecutorPrimary: true,
          chain: [
            {
              providerKind: "anthropic",
              providerId: "anthropic",
              model: "claude-haiku",
            },
          ],
        },
      ],
    });
    const modelLine = __planBuilderTest.findPlanTomlLine(renderedWithModel, {
      kind: "models",
      alias: "executor",
    });

    expect(taskLine).toBeGreaterThan(0);
    expect(profileLine).toBeGreaterThan(0);
    expect(modelLine).toBeGreaterThan(0);
    expect(
      __planBuilderTest.inferPlanTomlTargetFromLine(rendered, taskLine! + 3),
    ).toEqual({ kind: "task", taskId: "materialize-records" });
    expect(
      __planBuilderTest.inferPlanTomlTargetFromLine(rendered, profileLine! + 1),
    ).toEqual({ kind: "tools", profileId: "unity_mcp_tools" });
    expect(
      __planBuilderTest.inferPlanTomlTargetFromLine(renderedWithModel, modelLine! + 1),
    ).toEqual({ kind: "models", alias: "executor" });
  });
});
