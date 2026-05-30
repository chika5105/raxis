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
});
