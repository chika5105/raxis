# Bring Your Own Tools and MCP Adapters

> **Audience.** Operators who already have local scripts, Unity/Blender
> automation, or MCP servers and want Executors to use them safely.

RAXIS does not make MCP a first-class authority channel. Instead, keep
your existing setup and wrap specific operations as Executor custom
tools. That makes the migration feel close to plug-and-play while
preserving bounded capabilities, auditability, and timeout limits.

The pattern is always the same:

1. Keep the existing script, CLI, MCP server, or commercial tool.
2. Add a tiny adapter executable that reads JSON from stdin and writes a
   `ToolOutput` JSON object to stdout.
3. Declare one operation per custom tool in `plan.toml`.
4. Attach the profile, or a small set of profiles, only to Executor
   tasks that need those operations.

The agent never gets the broad tool substrate. It sees only the
operation-specific tool name and schema. MCP discovery, server URLs,
credentials, host sockets, and vendor account routing stay in the
operator-controlled adapter.

The shipped runtime supports four localities:

- `guest_subprocess`: run the tool inside the Executor VM.
- `host_subprocess`: run one host-owned adapter from the kernel.
- `host_mcp`: run one host-owned adapter that talks to a local MCP server.
- `remote_mcp`: run one host-owned adapter that talks to a remote MCP
  service.

For the host-owned localities, the Executor VM still receives only the
tool name and JSON input. The kernel looks up the signed declaration,
runs the adapter, audits the invocation, and returns the bounded result.

## Rules

- Declare tools under `[[profiles.<name>.custom_tool]]` in `plan.toml`.
- Assign one or more profiles to Executor tasks with
  `profiles = ["repo_tools", "db_tools"]`.
- Use one operation per tool, such as `unity_build_player`, not a
  generic `mcp_call`.
- Use an absolute command path. For `guest_subprocess`, the path is
  inside the executor image. For host-owned localities, the path is on
  the kernel host.
- Pass model input as JSON on stdin and return a `ToolOutput` JSON
  envelope on stdout.
- Keep `timeout_seconds` small. The hard cap is 300 seconds.
- Set `stdin_max_bytes`, `stdout_max_bytes`, and `stderr_max_bytes`
  when a tool can produce large payloads. RAXIS also enforces hard
  upper bounds so a tool cannot become a memory-pressure path.
- Do not attach custom tools to Reviewer or Orchestrator profiles.
- Avoid generic bridge tools such as `mcp_call`, `run_any_script`, or
  `browser_click_anywhere`. Make the operation name specific enough to
  review in a plan.
- Every invocation is audited as `CustomToolInvoked` by default. No
  extra notification route or dashboard setting is required.

Host-owned adapters run with a cleared environment. RAXIS sets only
non-secret context variables such as `RAXIS_CUSTOM_TOOL_NAME`,
`RAXIS_CUSTOM_TOOL_LOCALITY`, `RAXIS_SESSION_ID`, `RAXIS_TASK_ID`, and
`RAXIS_INITIATIVE_ID`. Keep tokens and vendor credentials in host-owned
config, OS keychain, or your adapter's secure store, not in the guest
environment.

## Existing script

Use this when you already have a repository script, studio script, or
CI helper. The wrapper can be as small as a shell or Python program, as
long as it reads JSON stdin and writes a bounded response.

```toml
[profiles.repo_tools]
inherits_from = "Executor"

[[profiles.repo_tools.custom_tool]]
name = "repo_codegen_check"
description = "Run the repository code-generation check wrapper."
command = ["/usr/local/bin/raxis-repo-codegen-check"]
timeout_seconds = 20

[profiles.repo_tools.custom_tool.schema]
type = "object"
additionalProperties = false

[profiles.repo_tools.custom_tool.schema.properties.scope]
type = "string"
maxLength = 120
```

## Stdio MCP method

Use this when the existing tool is a local stdio MCP server. The RAXIS
custom tool is not the MCP server itself; it is a narrow bridge to one
approved MCP method.

```toml
[profiles.docs_tools]
inherits_from = "Executor"

[[profiles.docs_tools.custom_tool]]
name = "docs_search"
description = "Search one configured stdio MCP documentation server."
command = [
  "/usr/local/bin/raxis-mcp-stdio-bridge",
  "/opt/raxis-tools/docs-mcp",
  "search",
]
execution_locality = "host_mcp"
timeout_seconds = 15

[profiles.docs_tools.custom_tool.schema]
type = "object"
required = ["query"]
additionalProperties = false

[profiles.docs_tools.custom_tool.schema.properties.query]
type = "string"
maxLength = 240

[profiles.docs_tools.custom_tool.schema.properties.limit]
type = "integer"
minimum = 1
maximum = 10
```

## Local HTTP service

Use this when an existing local service already exposes one safe
operation. The wrapper should call only the pinned endpoint and should
not expose arbitrary URLs to the Executor. If the service must remain on
the host or behind a vendor network, keep that connection in the adapter
and return only the bounded operation result to RAXIS.

```toml
[profiles.preview_tools]
inherits_from = "Executor"

[[profiles.preview_tools.custom_tool]]
name = "render_preview"
description = "Ask one approved local preview service endpoint for a render."
command = [
  "/usr/local/bin/raxis-http-tool",
  "POST",
  "http://127.0.0.1:8877/render-preview",
]
execution_locality = "host_subprocess"
timeout_seconds = 20

[profiles.preview_tools.custom_tool.schema]
type = "object"
required = ["asset_path"]
additionalProperties = false

[profiles.preview_tools.custom_tool.schema.properties.asset_path]
type = "string"
maxLength = 240

[profiles.preview_tools.custom_tool.schema.properties.quality]
type = "string"
enum = ["draft", "final"]
```

## Commercial MCP or CLI tool

Use the same bridge pattern for vendor tools. Keep the vendor token,
account routing, and MCP server configuration outside the plan, then
expose one readable operation to the Executor.

```toml
[profiles.vendor_tools]
inherits_from = "Executor"

[[profiles.vendor_tools.custom_tool]]
name = "vendor_lookup_ticket"
description = "Read one work item from a configured vendor MCP bridge."
command = ["/usr/local/bin/raxis-vendor-mcp-bridge", "issues", "lookup"]
execution_locality = "remote_mcp"
timeout_seconds = 15

[profiles.vendor_tools.custom_tool.schema]
type = "object"
required = ["ticket_id"]
additionalProperties = false

[profiles.vendor_tools.custom_tool.schema.properties.ticket_id]
type = "string"
maxLength = 80
```

## Unity-like MCP wrapper

```toml
[profiles.unity_mobile]
inherits_from = "Executor"

[[profiles.unity_mobile.custom_tool]]
name = "unity_list_scenes"
description = "List scenes known to the local Unity Editor MCP adapter."
command = ["/usr/local/bin/raxis-tool-mcp", "unity", "list-scenes"]
execution_locality = "host_mcp"
timeout_seconds = 5

[profiles.unity_mobile.custom_tool.schema]
type = "object"
additionalProperties = false

[[profiles.unity_mobile.custom_tool]]
name = "unity_build_player"
description = "Build one Unity player target through the local MCP adapter."
command = ["/usr/local/bin/raxis-tool-mcp", "unity", "build-player"]
execution_locality = "host_mcp"
timeout_seconds = 60

[profiles.unity_mobile.custom_tool.schema]
type = "object"
required = ["target", "scene"]
additionalProperties = false

[profiles.unity_mobile.custom_tool.schema.properties.target]
type = "string"
enum = ["ios", "android"]

[profiles.unity_mobile.custom_tool.schema.properties.scene]
type = "string"
maxLength = 240
```

Assign it to an Executor:

```toml
[[tasks]]
task_name = "build-mobile-demo"
description = "Build the mobile demo artifact."
session_agent_type = "Executor"
profiles          = ["unity_mobile"]
clone_strategy = "blobless"
path_allowlist = ["Assets/", "ProjectSettings/"]
predecessors = []
prompt = """
Use unity_list_scenes to inspect available scenes, then use
unity_build_player for the iOS target. Commit only the generated build
manifest or project files requested by the task.
"""
```

## Wrapper contract

The wrapper receives JSON stdin:

```json
{"target":"ios","scene":"Assets/Scenes/Main.unity"}
```

It should write a `ToolOutput`-shaped JSON object to stdout:

```json
{"content":"Build artifact: Builds/iOS/RaxisDemo.ipa"}
```

For recoverable tool errors, return `is_error: true`:

```json
{"content":"Unity editor is not reachable on socket /tmp/unity.sock","is_error":true}
```

## Validate

Use the dashboard **Plan Builder** to draft and validate profiles, or use
the CLI when you are already editing `plan.toml`:

```bash
raxis tools add \
  --plan plan.toml \
  --profile repo_tools \
  --name repo_symbol_search \
  --description "Search repository symbols with ripgrep." \
  --command /usr/bin/rg \
  --command-arg --json \
  --tool-schema '{"query":"string","limit?":{"type":"integer","minimum":1,"maximum":20}}'

raxis tools attach --plan plan.toml --task build-mobile-demo --profile repo_tools
raxis tools validate plan.toml
raxis tools test --plan plan.toml --profile repo_tools --tool repo_symbol_search --input-json '{"query":"Raxis"}'
raxis plan validate plan.toml
raxis submit plan plan.toml --no-dry-run
```

`--tool-schema` is RAXIS' normalized model-facing schema. It accepts a
full JSON Schema object or a small shorthand object where each property
maps to a type string or property object. RAXIS then renders the
provider-safe TOML schema that the kernel stamps into the Executor's
tool bundle. The adapter can be written in any language; the translation
layer is just the executable in `command`.

The kernel remains the authority. Admission rejects task-level custom
tools, Reviewer/Orchestrator tools, inherited name collisions, malformed
commands, invalid names, zero byte caps, and timeouts above the policy
cap. At runtime the wrapper rejects schema mismatches and oversized
payloads before the tool runs, records the invocation in the audit chain,
then forwards the bounded tool result back to the agent.
