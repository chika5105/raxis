import { useMemo, useState, type ReactNode } from "react";

import { ApiError, dashboardApi } from "@/api/client";
import { CopyButton } from "@/components/CopyButton";
import { Spinner } from "@/components/Spinner";
import type { BuilderValidationResponse, BuilderValidationSeverity } from "@/types/api";

type ToolTemplate =
  | "script"
  | "stdioMcp"
  | "http"
  | "vendorMcp"
  | "unity"
  | "blender"
  | "smoke";

interface ToolDraft {
  name: string;
  description: string;
  commandText: string;
  timeoutSeconds: string;
  schemaToml: string;
}

const TEMPLATE_LABELS: Record<ToolTemplate, string> = {
  script: "Existing script",
  stdioMcp: "Stdio MCP method",
  http: "Local HTTP service",
  vendorMcp: "Commercial MCP bridge",
  unity: "Unity MCP adapter",
  blender: "Blender MCP adapter",
  smoke: "Smoke test tool",
};

const TEMPLATE_DESCRIPTIONS: Record<ToolTemplate, string> = {
  script: "Turn a repo or studio script into one schema-bound Executor tool.",
  stdioMcp: "Call one method on an existing stdio MCP server through a thin bridge.",
  http: "Wrap one local service endpoint without exposing an open network client.",
  vendorMcp: "Use a vendor MCP or CLI integration through one approved operation.",
  unity: "Wrap selected Unity Editor MCP methods as bounded Executor tools.",
  blender: "Wrap Blender automation commands without exposing a generic tool bridge.",
  smoke: "A tiny validation tool for checking wrapper plumbing before a real run.",
};

const TEMPLATE_TOOLS: Record<ToolTemplate, ToolDraft[]> = {
  script: [
    {
      name: "repo_codegen_check",
      description: "Run the repository code-generation check wrapper.",
      commandText: "/usr/local/bin/raxis-repo-codegen-check",
      timeoutSeconds: "20",
      schemaToml: `type = "object"
additionalProperties = false

[properties.scope]
type = "string"
maxLength = 120`,
    },
  ],
  stdioMcp: [
    {
      name: "docs_search",
      description: "Search one configured stdio MCP documentation server.",
      commandText: "/usr/local/bin/raxis-mcp-stdio-bridge\n/opt/raxis-tools/docs-mcp\nsearch",
      timeoutSeconds: "15",
      schemaToml: `type = "object"
required = ["query"]
additionalProperties = false

[properties.query]
type = "string"
maxLength = 240

[properties.limit]
type = "integer"
minimum = 1
maximum = 10`,
    },
  ],
  http: [
    {
      name: "render_preview",
      description: "Ask one approved local preview service endpoint for a render.",
      commandText: "/usr/local/bin/raxis-http-tool\nPOST\nhttp://127.0.0.1:8877/render-preview",
      timeoutSeconds: "20",
      schemaToml: `type = "object"
required = ["asset_path"]
additionalProperties = false

[properties.asset_path]
type = "string"
maxLength = 240

[properties.quality]
type = "string"
enum = ["draft", "final"]`,
    },
  ],
  vendorMcp: [
    {
      name: "vendor_lookup_ticket",
      description: "Read one work item from a configured vendor MCP bridge.",
      commandText: "/usr/local/bin/raxis-vendor-mcp-bridge\nissues\nlookup",
      timeoutSeconds: "15",
      schemaToml: `type = "object"
required = ["ticket_id"]
additionalProperties = false

[properties.ticket_id]
type = "string"
maxLength = 80`,
    },
  ],
  unity: [
    {
      name: "unity_list_scenes",
      description: "List scenes known to the local Unity Editor MCP adapter.",
      commandText: "/usr/local/bin/raxis-tool-mcp\nunity\nlist-scenes",
      timeoutSeconds: "5",
      schemaToml: `type = "object"
additionalProperties = false

[properties.include_disabled]
type = "boolean"`,
    },
    {
      name: "unity_run_playmode_tests",
      description: "Run bounded Unity playmode tests through the local MCP adapter.",
      commandText: "/usr/local/bin/raxis-tool-mcp\nunity\nrun-playmode-tests",
      timeoutSeconds: "30",
      schemaToml: `type = "object"
additionalProperties = false

[properties.filter]
type = "string"
maxLength = 80`,
    },
    {
      name: "unity_build_player",
      description: "Build one Unity player target through the local MCP adapter.",
      commandText: "/usr/local/bin/raxis-tool-mcp\nunity\nbuild-player",
      timeoutSeconds: "60",
      schemaToml: `type = "object"
required = ["target", "scene"]
additionalProperties = false

[properties.target]
type = "string"
enum = ["ios", "android"]

[properties.scene]
type = "string"
maxLength = 240`,
    },
  ],
  blender: [
    {
      name: "blender_export_asset",
      description: "Export one Blender asset through a local wrapper.",
      commandText: "/usr/local/bin/raxis-tool-mcp\nblender\nexport-asset",
      timeoutSeconds: "45",
      schemaToml: `type = "object"
required = ["blend_file", "asset_name", "format"]
additionalProperties = false

[properties.blend_file]
type = "string"
maxLength = 240

[properties.asset_name]
type = "string"
maxLength = 120

[properties.format]
type = "string"
enum = ["fbx", "glb", "obj"]`,
    },
  ],
  smoke: [
    {
      name: "local_tool_smoke",
      description: "Confirm the executor can invoke a local custom-tool wrapper.",
      commandText: "/usr/local/bin/raxis-tool-smoke",
      timeoutSeconds: "5",
      schemaToml: `type = "object"
additionalProperties = false`,
    },
  ],
};

const severityClasses: Record<BuilderValidationSeverity, string> = {
  error: "border-bad/40 bg-bad-muted text-bad",
  warning: "border-warn/40 bg-warn-muted text-warn",
  info: "border-accent/30 bg-accent/10 text-accent",
};

export function ToolBuilderPage() {
  const [profileName, setProfileName] = useState("unity_mobile");
  const [tools, setTools] = useState<ToolDraft[]>(() =>
    TEMPLATE_TOOLS.unity.map((tool) => ({ ...tool })),
  );
  const [validation, setValidation] =
    useState<BuilderValidationResponse | null>(null);
  const [validating, setValidating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const generatedToml = useMemo(
    () => generateToolToml(profileName, tools),
    [profileName, tools],
  );
  const taskSnippet = `# Add this to each Executor task that should receive the tools.
profile = "${profileName}"`;

  const applyTemplate = (template: ToolTemplate) => {
    setValidation(null);
    setError(null);
    if (template === "script") setProfileName("repo_tools");
    if (template === "stdioMcp") setProfileName("docs_tools");
    if (template === "http") setProfileName("preview_tools");
    if (template === "vendorMcp") setProfileName("vendor_tools");
    if (template === "unity") setProfileName("unity_mobile");
    if (template === "blender") setProfileName("blender_assets");
    if (template === "smoke") setProfileName("tool_smoke");
    setTools(TEMPLATE_TOOLS[template].map((tool) => ({ ...tool })));
  };

  const updateTool = (idx: number, patch: Partial<ToolDraft>) => {
    setTools((current) =>
      current.map((tool, i) => (i === idx ? { ...tool, ...patch } : tool)),
    );
    setValidation(null);
  };

  const addTool = () => {
    setTools((current) => [
      ...current,
      {
        name: "custom_tool",
        description: "Describe the bounded operation this wrapper performs.",
        commandText: "/usr/local/bin/your-wrapper",
        timeoutSeconds: "30",
        schemaToml: `type = "object"
additionalProperties = false`,
      },
    ]);
  };

  const removeTool = (idx: number) => {
    setTools((current) => current.filter((_, i) => i !== idx));
    setValidation(null);
  };

  const validate = async () => {
    setValidating(true);
    setError(null);
    try {
      setValidation(await dashboardApi.builders.validateTools(generatedToml));
    } catch (e) {
      setError(e instanceof ApiError ? e.detail : String(e));
    } finally {
      setValidating(false);
    }
  };

  const download = () => {
    const blob = new Blob([generatedToml], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${profileName}-tools.toml`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6 max-w-7xl">
      <header className="space-y-2">
        <p className="text-xs uppercase tracking-wider text-accent font-semibold">
          Executor capabilities
        </p>
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-semibold text-ink">Tool Builder</h1>
            <p className="text-sm text-ink-muted max-w-3xl">
              Draft profile-scoped custom tools for existing scripts, MCP
              adapters, local services, vendor bridges, Unity, Blender, and
              other operator tooling. The kernel still validates the final
              plan; this page keeps the wrapper surface small before you copy
              it into plan.toml.
            </p>
          </div>
          <div className="flex gap-2">
            <button className="btn" type="button" onClick={download}>
              Download
            </button>
            <button
              className="btn btn-primary"
              type="button"
              onClick={() => void validate()}
              disabled={validating}
            >
              {validating ? <Spinner className="w-3.5 h-3.5" /> : null}
              Validate
            </button>
          </div>
        </div>
      </header>

      <section className="grid xl:grid-cols-[minmax(280px,360px)_1fr] gap-5">
        <div className="space-y-4">
          <Panel title="Feature Library">
            <div className="grid gap-2">
              {(Object.keys(TEMPLATE_LABELS) as ToolTemplate[]).map((template) => (
                <button
                  key={template}
                  type="button"
                  onClick={() => applyTemplate(template)}
                  className="text-left rounded border border-edge bg-panel hover:bg-panel-high p-3 transition-colors"
                >
                  <div className="text-sm font-semibold text-ink">
                    {TEMPLATE_LABELS[template]}
                  </div>
                  <div className="text-xs text-ink-muted mt-1">
                    {TEMPLATE_DESCRIPTIONS[template]}
                  </div>
                </button>
              ))}
            </div>
          </Panel>

          <Panel title="Bounded Capability Rules">
            <ul className="text-sm text-ink-muted space-y-2">
              <li>Tools live under an Executor-rooted profile.</li>
              <li>Each tool wraps one operation, not an open-ended bridge.</li>
              <li>Commands use absolute wrapper paths inside the executor image.</li>
              <li>Timeouts should be short; the hard cap is 300 seconds.</li>
              <li>Reviewer and Orchestrator sessions never receive these tools.</li>
            </ul>
          </Panel>

          <Panel title="Plug-In Path">
            <ol className="text-sm text-ink-muted space-y-2 list-decimal list-inside">
              <li>Keep your existing script, MCP server, or vendor tool.</li>
              <li>Add a thin wrapper that reads JSON stdin and writes JSON stdout.</li>
              <li>Expose only the exact operation an Executor needs.</li>
            </ol>
          </Panel>

          <Panel title="Next CLI Step">
            <pre className="rounded border border-edge bg-panel p-3 font-mono whitespace-pre-wrap text-xs text-ink">
              {taskSnippet}
            </pre>
          </Panel>
        </div>

        <div className="space-y-5 min-w-0">
          <Panel title="Profile">
            <label className="block">
              <span className="text-xs text-ink-subtle">Profile name</span>
              <input
                value={profileName}
                onChange={(e) => {
                  setProfileName(e.target.value);
                  setValidation(null);
                }}
                className="input mt-1 w-full"
              />
            </label>
          </Panel>

          <div className="space-y-4">
            {tools.map((tool, idx) => (
              <Panel
                key={`${idx}-${tool.name}`}
                title={`Tool ${idx + 1}`}
                action={
                  tools.length > 1 ? (
                    <button
                      className="text-xs text-bad hover:underline"
                      type="button"
                      onClick={() => removeTool(idx)}
                    >
                      Remove
                    </button>
                  ) : null
                }
              >
                <div className="grid lg:grid-cols-2 gap-3">
                  <label className="block">
                    <span className="text-xs text-ink-subtle">Name</span>
                    <input
                      value={tool.name}
                      onChange={(e) => updateTool(idx, { name: e.target.value })}
                      className="input mt-1 w-full"
                    />
                  </label>
                  <label className="block">
                    <span className="text-xs text-ink-subtle">
                      Timeout seconds
                    </span>
                    <input
                      value={tool.timeoutSeconds}
                      onChange={(e) =>
                        updateTool(idx, { timeoutSeconds: e.target.value })
                      }
                      className="input mt-1 w-full"
                    />
                  </label>
                </div>
                <label className="block mt-3">
                  <span className="text-xs text-ink-subtle">Description</span>
                  <input
                    value={tool.description}
                    onChange={(e) =>
                      updateTool(idx, { description: e.target.value })
                    }
                    className="input mt-1 w-full"
                  />
                </label>
                <div className="grid lg:grid-cols-2 gap-3 mt-3">
                  <label className="block">
                    <span className="text-xs text-ink-subtle">
                      Command argv, one entry per line
                    </span>
                    <textarea
                      value={tool.commandText}
                      onChange={(e) =>
                        updateTool(idx, { commandText: e.target.value })
                      }
                      className="input mt-1 min-h-[9rem] w-full font-mono text-xs"
                    />
                  </label>
                  <label className="block">
                    <span className="text-xs text-ink-subtle">
                      JSON schema as TOML
                    </span>
                    <textarea
                      value={tool.schemaToml}
                      onChange={(e) =>
                        updateTool(idx, { schemaToml: e.target.value })
                      }
                      className="input mt-1 min-h-[9rem] w-full font-mono text-xs"
                    />
                  </label>
                </div>
              </Panel>
            ))}
            <button className="btn" type="button" onClick={addTool}>
              Add Tool
            </button>
          </div>

          <Panel
            title="Generated Profile TOML"
            action={<CopyButton value={generatedToml} label="Copy tool profile TOML" />}
          >
            <pre className="rounded border border-edge bg-panel p-3 font-mono text-xs text-ink overflow-x-auto">
              {generatedToml}
            </pre>
          </Panel>

          <ValidationPanel validation={validation} error={error} />
        </div>
      </section>
    </div>
  );
}

function Panel({
  title,
  action,
  children,
}: {
  title: string;
  action?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="rounded border border-edge bg-panel-raised p-4">
      <div className="flex items-center justify-between gap-3 mb-3">
        <h2 className="text-sm font-semibold text-ink">{title}</h2>
        {action}
      </div>
      {children}
    </section>
  );
}

function ValidationPanel({
  validation,
  error,
}: {
  validation: BuilderValidationResponse | null;
  error: string | null;
}) {
  if (error) {
    return (
      <Panel title="Validation">
      <div className="rounded border border-bad/40 bg-bad-muted p-3 text-sm text-bad">
          {error}
        </div>
      </Panel>
    );
  }
  if (!validation) return null;
  return (
    <Panel title="Kernel Validation">
      <div className="flex items-center gap-2 text-sm">
        <span
          className={
            validation.ok
              ? "badge border-ok/40 bg-ok-muted text-ok"
              : "badge border-bad/40 bg-bad-muted text-bad"
          }
        >
          {validation.ok ? "OK" : "Needs repair"}
        </span>
        <span className="text-ink-muted">
          policy epoch {validation.policy_epoch}
        </span>
      </div>
      <div className="mt-3 space-y-2">
        {validation.issues.length === 0 ? (
          <p className="text-sm text-ink-muted">
            No issues found. The final plan still goes through authoritative
            plan validation before admission.
          </p>
        ) : (
          validation.issues.map((issue) => (
            <div
              key={`${issue.code}-${issue.message}`}
              className={`rounded border p-3 ${severityClasses[issue.severity]}`}
            >
              <div className="text-xs font-mono">{issue.code}</div>
              <div className="text-sm font-semibold mt-1">{issue.message}</div>
              <div className="text-sm opacity-90 mt-1">{issue.remediation}</div>
            </div>
          ))
        )}
      </div>
      {validation.next_steps.length > 0 && (
        <div className="mt-4">
          <div className="text-xs uppercase tracking-wider text-ink-subtle font-semibold mb-2">
            Next steps
          </div>
          <pre className="rounded border border-edge bg-panel p-3 font-mono text-xs text-ink whitespace-pre-wrap">
            {validation.next_steps.join("\n")}
          </pre>
        </div>
      )}
    </Panel>
  );
}

function generateToolToml(profileName: string, tools: ToolDraft[]): string {
  const safeProfile = profileName.trim() || "executor_tools";
  const lines = [`[profiles.${safeProfile}]`, `inherits_from = "Executor"`, ""];
  for (const tool of tools) {
    lines.push(`[[profiles.${safeProfile}.custom_tool]]`);
    lines.push(`name = ${tomlString(tool.name.trim())}`);
    lines.push(`description = ${tomlString(tool.description.trim())}`);
    lines.push(`command = [${commandEntries(tool.commandText).map(tomlString).join(", ")}]`);
    lines.push(`timeout_seconds = ${timeoutValue(tool.timeoutSeconds)}`);
    lines.push("");
    lines.push(`[profiles.${safeProfile}.custom_tool.schema]`);
    lines.push(scopeSchemaToml(safeProfile, tool.schemaToml));
    lines.push("");
  }
  return lines.join("\n").trimEnd() + "\n";
}

function commandEntries(value: string): string[] {
  return value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}

function timeoutValue(value: string): string {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? String(parsed) : "30";
}

function tomlString(value: string): string {
  return JSON.stringify(value);
}

function scopeSchemaToml(profileName: string, schema: string): string {
  return schema
    .split(/\r?\n/)
    .map((line) => {
      const trimmed = line.trim();
      if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
        const inner = trimmed.slice(1, -1).trim();
        return `[profiles.${profileName}.custom_tool.schema.${inner}]`;
      }
      return line.trimEnd();
    })
    .join("\n");
}
