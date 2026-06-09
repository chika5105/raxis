# RAXIS V2 — Operator-Defined Custom Tools

> **Status:** V2 Specified
>
> **Scope:** This spec is the canonical reference for **operator-defined
> custom tools** — a declarative, plan-bound mechanism for extending the
> agent's tool surface beyond the kernel-provided base tools (`read_file`,
> `bash`, `grep_search`, …) without an SDK, without runtime discovery
> (MCP-style), and without breaking determinism. Custom tools are
> declared inline in `plan.toml`, translated by the planner harness into
> JSON-Schema function definitions, and presented to the LLM on equal
> footing with base tools. Their behavior is implemented by an operator
> command line or kernel-owned adapter that reads JSON from stdin and
> writes a result to stdout.
>
> **Cross-references (canonical homes for adjacent material):**
>
> - [`planner-harness.md`](planner-harness.md) — the harness's overall tool-surface model;
>   custom tools are a third tool category alongside base tools and
>   kernel-mediated intents (§3 of that file).
> - [`policy-plan-authority.md`](policy-plan-authority.md) — admission-time validation, warning and
>   failure catalog (§3, §3b), `policy.toml` hard caps.
> - [`kernel-mechanics-prompt.md`](kernel-mechanics-prompt.md) — KSB and NNSP rendering. Custom tools
>   are appended to the JSON `tools` array in the LLM API call alongside
>   base tools and are indistinguishable to the LLM at the protocol
>   level.
> - [`vm-network-isolation.md`](vm-network-isolation.md), [`credential-proxy.md`](credential-proxy.md) — custom-tool
>   subprocesses share the agent VM's network namespace and are subject
>   to the unified two-tier egress model. No new authority surface.
> - [`verifier-processes.md`](verifier-processes.md) — the *other* mechanism for running operator
>   code; verifiers are kernel-invoked preflight gates with structured
>   witness output. Custom tools are LLM-invoked utilities. §11 of this
>   spec contrasts the two.
> - `invariants.md` — `INV-PLANNER-HARNESS-04` (Reviewer Custom Tool
>   Prohibition) is mirrored from this spec into the consolidated
>   invariants index.

---

## §1 — Why a Standalone Spec

Three of the structural decisions consolidated in [`planner-harness.md`](planner-harness.md)
created a gap operators will hit immediately:

1. **Reviewer was hardened to pure-static** (`INV-PLANNER-HARNESS-01`)
   — no shell, no LSP, no code execution.
2. **Reviewer image was made kernel-canonical**
   (`INV-PLANNER-HARNESS-02`) — operator cannot ship a custom Reviewer
   image with extra tooling.
3. **MCP was rejected** as an authority bypass (no runtime tool
   discovery; tool authority must be plan-bound at admission).

Together these eliminate every ad-hoc path operators historically used
to extend an agent's capabilities. For Executors specifically, this
is too restrictive: real engineering teams need custom utilities
(telemetry analyzers, schema introspectors, internal status APIs,
proprietary linters) that the agent can call structurally rather than
fumbling through `bash` with hand-crafted invocation strings.

**The constraint is explicit:** any extension mechanism must satisfy:

- **Plan-bound and signed.** Tool definitions are part of the plan
  bundle, hashed and signed at submit-time. No runtime discovery.
- **No SDK coupling.** Operators write zero RAXIS-specific code. The
  contract is a one-page JSON-in / output-out shell process.
- **JSON-Schema-shaped.** Custom tools must reach the LLM via the same
  native function-calling protocol as base tools (`read_file`,
  `grep_search`, etc.). Anything weaker (system-prompt-documented
  `bash` invocations) destroys the model's training distribution and
  inflates hallucination rates.
- **Bounded by declared execution locality.** A `guest_subprocess` is
  just another in-VM process. `host_subprocess`, `host_mcp`, and
  `remote_mcp` are kernel-executed from the signed plan declaration,
  so the guest never controls host paths, MCP endpoints, or
  credentials. No runtime discovery.
- **Reviewer cannot use them.** Custom tools are arbitrary code
  execution. The Reviewer's pure-static guarantee
  (`INV-PLANNER-HARNESS-01`) must hold structurally; custom tools are
  banned for the Reviewer role.

This spec specifies the mechanism that satisfies all five constraints.

---

## §2 — Scope and Non-Scope

### In scope

- The `[[profiles.<name>.custom_tool]]` declaration schema in
  `plan.toml` (§3).
- The RAXIS Tool Schema authoring model and Draft-07 JSON Schema subset
  accepted for tool input definitions (§4).
- The reserved-name list and collision rules (§5).
- The stdin / stdout / stderr wire protocol between the harness and
  the operator command (§6).
- Process containment via cgroup v2, timeout enforcement via
  `cgroup.kill` (§7).
- Profile inheritance and merge semantics (§8).
- Token-budget projection at admission plus per-profile and per-task count caps
  (§9).
- Reviewer-role prohibition (`INV-PLANNER-HARNESS-04`) (§10).
- Custom tools vs. verifiers — when to use which (§11).
- Audit emission — the `CustomToolInvoked` event schema (§12).
- Cross-spec impacts and the implementation checklist (§13, §14).
- Invariants introduced by this spec (§15).

### Out of scope (explicit)

- **Streaming tool output.** Custom tools return one stdout blob at
  process exit. The LLM's native tool-call protocol does not natively
  support streaming tool results in V2; revisit in V3 if model APIs
  warrant it.
- **Bidirectional tool I/O.** The script reads stdin once, writes
  stdout once, exits. No mid-run callbacks, no stdin re-prompting.
- **Tool composition / chaining inside the harness.** The LLM composes
  tool calls; the harness does not pre-pipe one custom tool into
  another.
- **Generic host script runners and generic MCP clients.** V2 supports
  host-side and MCP adapter localities, but only as one named operation
  per signed custom tool. It does not expose arbitrary `run_script`,
  `mcp_call`, URL, method-name, or discovery surfaces to the agent.
- **Plan-bundle script inlining.** Operators still provide the script or
  adapter as an installed executable. Inlining script bytes into
  `plan.toml` is deferred to a future release.
- **Side-effecting state shared across invocations beyond what the
  filesystem provides.** The harness does not maintain per-tool
  caches, sessions, or persistent connections. Each invocation forks
  fresh.

---

## §3 — Plan Declaration Schema

Custom tools are declared on a **profile**, not on a task. The reasoning
is operational: a profile defines the archetype's capability surface
("Frontend Engineer has `npm`, `lint`, `query_telemetry`") and tasks
are tickets assigned to that archetype. You do not teach an engineer a
new tool per Jira ticket; you give them their toolbox once.

### 3.1 Minimum example

```toml
# plan.toml

[profiles.frontend_dev]
inherits_from = "Executor"

[[profiles.frontend_dev.custom_tool]]
name        = "query_telemetry"
description = "Query the internal telemetry service for a target. Returns the raw JSON record."
command     = ["/usr/bin/python3", "/usr/local/bin/query_telemetry.py"]

  # JSON Schema (Draft-07 subset) for the LLM-facing input shape.
  [profiles.frontend_dev.custom_tool.schema]
  type = "object"
  required = ["target_id"]
  additionalProperties = false

  [profiles.frontend_dev.custom_tool.schema.properties.target_id]
  type        = "integer"
  description = "Numeric ID of the target to query."

[profiles.frontend_dev.custom_tool.schema.properties.include_raw]
  type        = "boolean"
  description = "Include raw event payload in the response."
  default     = false
```

Attach profiles to Executor tasks with `profiles = [...]`:

```toml
[[tasks]]
task_name            = "implement_api"
session_agent_type = "Executor"
profiles           = ["repo_tools", "db_tools"]
path_allowlist     = ["src/api/"]
predecessors       = []
prompt             = "Implement the API change and commit the result."
```

`profiles` is deliberately plural. Operators can compose small,
reviewable capability bundles (`repo_tools`, `db_tools`,
`cloud_status_tools`) instead of creating one large toolbox profile for
every possible task.

### 3.2 Field reference

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `name` | string | yes | — | LLM-visible function name. Must match `^[a-z][a-z0-9_]{0,47}$`. Reserved-name and uniqueness rules per §5. |
| `description` | string | yes | — | LLM-visible function description. Must be 8–800 characters; counts toward the token-budget projection (§9). |
| `command` | array of strings | yes | — | Argv to invoke when the LLM calls the tool. The first element is an absolute path inside the VM filesystem for `guest_subprocess`, and an absolute path on the kernel host for host-owned localities. All elements must be non-empty. The runtime invokes directly; **no shell interpolation**. |
| `execution_locality` | string | no | `"guest_subprocess"` | One of `"guest_subprocess"`, `"host_subprocess"`, `"host_mcp"`, or `"remote_mcp"`. The agent never chooses this value at runtime; the kernel stamps it from the signed plan bundle. |
| `schema` | object | yes | — | JSON Schema (Draft-07 subset per §4) describing the input object the LLM constructs. The harness sends exactly this object to the script's stdin. |
| `timeout_seconds` | integer | no | `60` | Per-invocation wall-clock cap. Hard-capped by `policy.toml` `max_custom_tool_timeout_seconds` (default 300). |
| `stdin_max_bytes` | integer | no | `262_144` (256 KiB) | Maximum bytes of JSON the harness will send to the script. Hard-capped at 1 MiB. The LLM's tool input is rejected at the harness boundary if it exceeds this; the LLM receives a `tool_result` error and may retry with a smaller input. |
| `stdout_max_bytes` | integer | no | `65_536` (64 KiB) | Maximum stdout bytes retained for model/audit output. Hard-capped at 1 MiB. Excess is truncated and the truncation flagged in the `tool_result` (per §6.4). |
| `stderr_max_bytes` | integer | no | `16_384` (16 KiB) | Maximum stderr bytes retained for model/audit output. Hard-capped at 256 KiB. Excess is truncated; truncation flagged in `CustomToolInvoked`. |
| `expose_stderr` | bool | no | `false` | If `true`, the script's stderr is appended to the LLM-facing `tool_result` (after stdout, separated by a sentinel). Stderr is **always** captured in the audit event regardless. |

### 3.3 Authoring from CLI or UI

Operators can write the TOML directly, use the dashboard Plan Builder, or
use the CLI. All three produce the same profile-scoped declaration.

```bash
raxis tools add \
  --plan plan.toml \
  --profile repo_tools \
  --name repo_symbol_search \
  --description "Search repository symbols with ripgrep." \
  --command /usr/bin/rg \
  --command-arg --json \
  --tool-schema '{"query":"string","limit?":{"type":"integer","minimum":1,"maximum":20}}'

raxis tools attach --plan plan.toml --task implement_api --profile repo_tools
raxis tools validate plan.toml
raxis tools test --plan plan.toml --profile repo_tools --tool repo_symbol_search --input-json '{"query":"CustomToolInvoked"}'
```

The CLI is an authoring helper only. It does not grant authority,
discover tools at runtime, or bypass plan signing. `tools test` is a
local dry-run for the declared adapter contract; the kernel remains the
runtime authority after submission.

### 3.4 Execution locality

The LLM-visible contract is independent of where the operation runs. A
custom tool is always a narrow `(name, schema, result)` capability; the
execution locality is host/kernel-owned metadata, not something the agent
chooses or discovers.

Current implementation:

- `guest_subprocess` — executor VM runs a fixed argv with JSON on stdin
  and reports bounded metadata to the kernel before the result is shown
  to the model.
- `host_subprocess` — the kernel runs an operator-declared host
  executable with JSON on stdin. The executable runs with a cleared
  environment plus non-secret RAXIS context variables
  (`RAXIS_SESSION_ID`, `RAXIS_TASK_ID`, etc.).
- `host_mcp` — the kernel runs an operator-declared host adapter for one
  local MCP operation. The adapter may speak stdio or local HTTP MCP to
  an existing server, but the agent sees only the narrow RAXIS tool.
- `remote_mcp` — the kernel runs an operator-declared host adapter for
  one remote MCP operation. Remote credentials and account routing stay
  in host-owned config, OS keychain, or the adapter's own secure store;
  they are not placed in the guest environment or the plan.

In all cases the agent sees only the operation-specific tool. It does not
see MCP discovery, server URLs, credentials, broad method namespaces, or a
generic script runner.

> **Executable supply-chain verification.** V2 deliberately omits
> per-tool hash verification of the binary at `command[0]`. The kernel
> does not bundle, stage, or inspect script/adapter bytes; it executes
> the operator-installed path from the signed plan. For
> `guest_subprocess`, operators who need supply-chain integrity pin the
> **entire VM image** by OCI digest:
>
> ```toml
> # policy.toml
> [[vm_images]]
> name             = "my-team/executor"
> oci_digest       = "sha256:abcd1234..."   # pinned image digest
> role_restriction = ["Executor"]
> ```
>
> Image-digest pinning is mathematically equivalent to verifying
> *every* byte of the executor filesystem — script, interpreter,
> shared libraries, libc, and all transitive dependencies — in one
> shot. Per-script hashing covers a strict subset of this surface and
> creates a false sense of security (a tampered Python interpreter can
> subvert a hash-pinned `analyze.py` regardless). For host-owned
> localities, the equivalent operator responsibility is host package
> management, file permissions, and release signing for the adapter
> executable. RAXIS binds *which* adapter may run and records every
> invocation; it does not claim to make an arbitrary host binary
> trustworthy.

### 3.5 Profile-level fields

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `inherits_from` | string | no | — | Parent profile name. Inherited custom tools merge per §8. |
| `custom_tool` | array-of-tables | no | `[]` | Zero or more `[[profiles.<name>.custom_tool]]` blocks. |

A profile MAY declare zero custom tools; this is the common case for
profiles inheriting from `Executor` without extension.

### 3.6 Task profile assignment

Executor tasks MAY reference zero or more profile names with:

```toml
profiles = ["repo_tools", "db_tools"]
```

The kernel resolves each profile, including inheritance, in the order
declared on the task. It then merges the effective custom-tool arrays
into the kernel-stamped Executor bundle. Tool names must remain unique
across the merged set. If two selected profiles contribute byte-identical
tool declarations with the same name, the kernel deduplicates them and
keeps the first profile's attribution; the dashboard surfaces this as a
warning because the overlap may be intentional. If the duplicate names
resolve to different command/schema/limit semantics, admission fails
closed rather than treating either declaration as an override. The
kernel stamps each effective tool with the profile that contributed it,
and that `profile_name` is recorded in `CustomToolInvoked` audit events.

Reviewer and Orchestrator tasks cannot receive custom-tool profiles.
Reviewers retain the static review surface, and Orchestrators remain
kernel-managed.

The deprecated singular spelling is rejected:

```toml
profile = "repo_tools" # invalid; use profiles = ["repo_tools"]
```

### 3.7 Per-task overrides — explicitly disallowed

`plan.toml` does NOT permit custom-tool declarations under
`[plan.tasks.<id>]`. Custom tools live exclusively at the profile
level. Attempts to declare `[[plan.tasks.<id>.custom_tool]]` are
rejected at admission with `FAIL_CUSTOM_TOOL_TASK_LEVEL_NOT_ALLOWED`.

The reasoning: a task is a unit of work assigned to an archetype, not
a unit of capability definition. Per-task tool overrides would make
the LLM-visible tool surface non-uniform across sibling tasks running
the same profile, breaking caching, audit comparison, and operator
mental model.

---

## §4 — Tool Schema Validation

RAXIS uses a normalized **Tool Schema** for model-facing custom-tool
inputs. Operators can author it as full JSON Schema or as shorthand:

```json
{"query":"string","limit?":{"type":"integer","minimum":1,"maximum":20}}
```

The authoring core expands that into an object-root schema with
`properties`, `required`, and `additionalProperties = false`. Custom
models and vendor-specific tool formats plug in through adapters, but
the signed plan stores the normalized RAXIS Tool Schema so the kernel,
dashboard, CLI, audit chain, and planner all speak one stable contract.

Custom-tool input schemas are validated against a **deterministic
provider-safe subset**. The subset is chosen for two properties:

1. **All accepted schemas round-trip through both Anthropic's and
   OpenAI's tool-schema validators without modification.** The harness
   forwards the schema verbatim into the model API request. If we
   accept a schema feature one provider rejects, we ship plans that
   pass admission but crash on first inference.
2. **All accepted schemas are fully resolvable at admission time
   without network access.** No `$ref` to remote URLs, no `$id`-based
   resolution, no dynamic schema fetching. This preserves determinism
   and keeps the kernel's network surface unchanged.

### 4.1 Accepted keywords

The accepted vocabulary is the intersection of Anthropic's and
OpenAI's tool-schema acceptance, restricted further to Draft-07 core:

- **Type:** `type` (must be one of `"object"`, `"string"`, `"integer"`,
  `"number"`, `"boolean"`, `"array"`).
- **Object structure:** `properties`, `required`, `additionalProperties`
  (`false` at the root is the default produced by CLI/UI shorthand).
- **Array structure:** `items` (single schema only — tuple-typed
  `items: [...]` is rejected as `FAIL_CUSTOM_TOOL_SCHEMA_UNSUPPORTED_FEATURE`).
- **String constraints:** `minLength`, `maxLength`, `enum`.
- **Numeric constraints:** `minimum`, `maximum`.
- **Documentation:** `description`, `default`
  (all advisory; counted into token-budget projection §9).
- **Conditional and polymorphic constructs:** `enum` only.
  `oneOf` / `anyOf` / `allOf` / `not` / `if` / `then` / `else` are
  rejected as `FAIL_CUSTOM_TOOL_SCHEMA_UNSUPPORTED_FEATURE`. The
  reasoning: model providers handle these inconsistently, and operator
  schemas expressing real polymorphism are rare enough to defer to a
  V3 expansion.

### 4.2 Rejected keywords (always)

| Keyword | Why rejected |
|---|---|
| `$ref`, `$id`, `definitions`, `$defs` | Allows reference resolution, including remote — destroys determinism and contradicts plan-bundle inlining. |
| `oneOf`, `anyOf`, `allOf`, `not` | Provider-inconsistent semantics; rare in practice. |
| `if`, `then`, `else` | Provider-inconsistent semantics; rare in practice. |
| `patternProperties` | Allows unbounded property names; bypasses `additionalProperties: false`. |
| `dependencies`, `dependentRequired`, `dependentSchemas` | Provider-inconsistent semantics. |
| `propertyNames` | Same reasoning as `patternProperties`. |
| `contains` | Provider-inconsistent. |
| `format` other than the four listed in §4.1 | Provider-inconsistent format vocabulary. |

### 4.3 Schema-level admission failures

| Code | Trigger |
|---|---|
| `FAIL_CUSTOM_TOOL_SCHEMA_INVALID` | Schema is not valid JSON / not a valid Draft-07 schema (parser error). |
| `FAIL_CUSTOM_TOOL_SCHEMA_UNSUPPORTED_FEATURE` | Schema uses a keyword listed in §4.2. The error message names the keyword and the reason. |
| `FAIL_CUSTOM_TOOL_SCHEMA_NOT_OBJECT_ROOT` | Top-level `type` is not `"object"`. The LLM's tool-call protocol passes inputs as a single object; non-object root schemas are unrepresentable. |
| `FAIL_CUSTOM_TOOL_SCHEMA_ADDITIONALPROPERTIES_TRUE` | Top-level `additionalProperties` is `true` or omitted. V2 requires `false` for input-shape determinism. |

All failures emit a remediation message naming the offending profile,
tool, and (where applicable) JSON pointer into the schema.

---

## §5 — Reserved Names and Uniqueness

### 5.1 Reserved names

Custom tools MAY NOT use any name reserved by base tools or by the
kernel-mediated intent surface. The reserved list is deterministic and
versioned with the kernel binary:

```text
read_file, write_file, edit_file, glob_search, grep_search,
bash, TodoWrite, SubmitReview,
ActivateSubTask, CompleteTask, SingleCommit, IntegrationMerge,
EscalationRequest, InferenceRequest, InitiativeCompleted,
ResolveSubEscalation, ApprovePlan, ApprovePolicy, ApproveWarning,
WebFetch, WebSearch, StructuredOutput, Sleep
```

The full list is exported by the kernel as
`raxis admin reserved-tool-names` for operator inspection.

Violation → `FAIL_CUSTOM_TOOL_NAME_RESERVED { name, profile }`.

### 5.2 Profile-internal uniqueness

Within a single profile (after inheritance merge per §8), custom-tool
`name` values must be unique. Duplicates are rejected with
`FAIL_CUSTOM_TOOL_NAME_COLLISION { name, conflicting_profiles: [...] }`.

### 5.3 Naming convention

The admission check enforces `^[a-z][a-z0-9_]{0,47}$` (lowercase ASCII,
underscore-separated, 1–48 chars). This matches conventions both
Anthropic and OpenAI accept, and rules out names that risk collision
with future base tools (which use snake_case for in-VM tools and
PascalCase for kernel intents — neither overlaps with the enforced
pattern's intersection except by deliberate operator mistake).

---

## §6 — Stdin / Stdout / Stderr Wire Protocol

### 6.1 Invocation

When the LLM emits a `tool_use` block whose `name` matches a custom
tool, the harness:

1. Validates the LLM-supplied `input` object against the declared
   schema. On failure → returns a `tool_result` with `is_error: true`
   and a structured error message; does not invoke the script/adapter.
2. Dispatches by `execution_locality`:
   - `guest_subprocess`: the Executor harness forks `command[0]`
     inside the VM.
   - `host_subprocess`, `host_mcp`, `remote_mcp`: the Executor sends
     `CustomToolExecution { tool_name, input }` to the kernel. The
     kernel looks up `command` from the signed plan bundle and forks
     it on the host.
3. Writes the canonical UTF-8 JSON serialization of the LLM's input
   object to the script's stdin and closes the write end. Encoding is
   minified JSON with sorted object keys.
4. Reads stdout and stderr concurrently into bounded buffers
   (`stdout_max_bytes`, `stderr_max_bytes`).
5. Awaits process exit, subject to `timeout_seconds`.
6. Emits the `CustomToolInvoked` audit event (§12).
7. Constructs the LLM-facing `tool_result` (§6.4).

### 6.2 Stdin contract

- **Encoding:** UTF-8.
- **Format:** a single minified JSON value (typically an object) with
  no trailing newline.
- **Closure:** the harness closes stdin after writing. Scripts that
  hang waiting for additional input will hit `timeout_seconds`.
- **Size cap:** `stdin_max_bytes`. The cap applies to the *serialized
  input bytes*, not the LLM-visible token count. The LLM's input
  object is admission-validated against the schema first; a
  schema-valid but oversize input is rare but possible (e.g., a
  pathologically long string field). Such an input is rejected at the
  harness boundary with a `tool_result` error
  `CustomToolInputTooLarge`; the LLM may retry with smaller input.

### 6.3 Stdout convention — accept arbitrary bytes; wrap

Per the design discussion: **the harness does NOT require stdout to be
valid JSON.** It accepts arbitrary UTF-8 bytes (lossy decoding for
non-UTF-8) and wraps them in the `tool_result` content as a string.

Two reasons:

1. The model API tool-result content is ultimately a string; wrapping
   `Hello world\n` as `"Hello world\n"` is exactly what the model
   sees regardless.
2. Forcing valid JSON breaks 90% of trivial scripts (`echo "$result"`,
   `print(value)`). Operator ergonomics matter more than a structural
   guarantee whose only consumer is the LLM's free-form context.

If the operator wants structured JSON in the LLM's view, the script
emits JSON and the LLM is informed (via `description`) that it can
parse it. The harness does not validate.

### 6.4 Stdout cap and truncation

If the script's stdout exceeds `stdout_max_bytes`, the harness keeps
the first `stdout_max_bytes - 256` bytes plus the *last* 256 bytes
(the tail often contains the most informative output — error messages,
final result lines), separated by a clearly-marked truncation sentinel:

```text
…[CUSTOM_TOOL_STDOUT_TRUNCATED: original=N_bytes, kept_head=M, kept_tail=256]…
```

The `tool_result` content reflects the truncated stdout. The
`CustomToolInvoked` audit event records the original size and a
SHA-256 of the *full* stdout (which the kernel persists separately if
the operator opts in to full-payload archival; default is digest-only).

### 6.5 Stderr handling

Stderr is **always captured** for the audit log up to
`stderr_max_bytes`. By default it is **NOT exposed to the LLM**
(stderr is notorious for polluting context with progress bars,
deprecation warnings, ANSI color codes, and irrelevant noise that
defeats the LLM's reasoning).

If the operator sets `expose_stderr = true` on a tool declaration,
the harness appends stderr to the LLM-facing `tool_result` content
after stdout, separated by a sentinel:

```text
{stdout content}
…[CUSTOM_TOOL_STDERR_BEGIN]…
{stderr content (truncated to stderr_max_bytes if needed)}
…[CUSTOM_TOOL_STDERR_END]…
```

The audit log always records both.

### 6.6 Environment variables

`guest_subprocess` inherits the executor VM's deliberately sparse runtime
environment. `host_subprocess`, `host_mcp`, and `remote_mcp` are run by
the kernel with a cleared environment and only a small, non-secret
RAXIS context set:

| Variable | Source | Purpose |
|---|---|---|
| `PATH` | Kernel-defined system path | Standard executable search path for host adapters; `command[0]` is still required to be absolute. |
| `RAXIS_CUSTOM_TOOL_NAME` | Tool's `name` field | Lets the script identify which tool it's serving (useful for shared scripts). |
| `RAXIS_CUSTOM_TOOL_LOCALITY` | Tool's `execution_locality` field | Lets shared adapters branch between host subprocess / host MCP / remote MCP modes. |
| `RAXIS_CUSTOM_TOOL_REQUEST_ID` | Per-invocation UUID | Matches the audit event correlation id. |
| `RAXIS_SESSION_ID` | Current session ID | For audit correlation in operator-side logs. |
| `RAXIS_TASK_ID` | Current task ID | For audit correlation in operator-side logs. |
| `RAXIS_INITIATIVE_ID` | Current initiative ID | For audit correlation in operator-side logs. |

There is intentionally no plan-level `env` table in the shipped V2
runtime. Host adapters that need credentials must load them from
host-owned config, OS keychain, or a RAXIS credential proxy path the
operator configured outside the agent environment. This keeps the
planner's environment free of bearer secrets and makes session envs
safe to display in the operator dashboard.

### 6.7 Exit code semantics

| Exit code | LLM-facing outcome | Audit `outcome` |
|---|---|---|
| `0` | `tool_result` with `is_error: false`, content = stdout (truncated per §6.4) | `Success` |
| `1`–`255` | `tool_result` with `is_error: true`, content = stdout + brief footer naming the exit code | `NonZeroExit { code }` |
| Killed by timeout (cgroup.kill) | `tool_result` with `is_error: true`, content = `[CUSTOM_TOOL_TIMEOUT after Ns]` + stdout-so-far | `Timeout` |
| Killed by session teardown | (no result returned to LLM; the LLM session is being torn down) | `KilledOnTeardown` |
| Queued but `max_queue_wait_ms` elapsed before a concurrency slot freed (per §7.3) | `tool_result` with `is_error: true`, content = `[CUSTOM_TOOL_QUEUE_TIMEOUT after Nms; concurrency limit was busy for the entire wait window]`. The LLM-facing failure reason is **`CustomToolQueueTimeout`** — distinct from `Timeout` (which means the script ran but exceeded `timeout_seconds`) and from `CustomToolConcurrencyExhausted` (which means the queue itself was full at admission and the request was never queued). | `QueueTimeout { queued_for_ms }` |
| Stdin too large at admission | `tool_result` with `is_error: true`, structured error | `StdinTooLarge` |
| Stdout truncated at cap | `tool_result` reflects truncated stdout; `is_error` matches exit code | `Success` or `NonZeroExit` with `stdout_truncated: true` flag |

The LLM is expected to handle `is_error: true` by re-planning, just as
it does for any tool failure. Operators are advised to print
human-readable error messages to stdout (which the LLM sees) rather
than relying on stderr (which is hidden by default).

---

## §7 — Process Containment

### 7.1 cgroup substrate (`INV-PLANNER-HARNESS-03`)

Every custom-tool invocation is placed in a transient cgroup
`/sys/fs/cgroup/raxis/customtool-<invocation_seq>/` for the duration
of the call. The cgroup is created before fork, the subprocess is
written to `cgroup.procs` immediately after fork, and the cgroup is
destroyed after the subprocess and all descendants exit.

This reuses the same substrate as backgrounded shells
([`planner-harness.md §5.3`](planner-harness.md)). Linux 5.14+ guest kernel is required
(`INV-PLANNER-HARNESS-03`); the guest-kernel requirement is verified
by `raxis doctor vm-images` per [`system-requirements.md §11`](system-requirements.md).

### 7.2 Termination via `cgroup.kill`

On timeout, session teardown, or explicit cancellation, termination is
performed by writing `1` to the cgroup's `cgroup.kill` file. This is
atomic and race-free against POSIX double-fork daemonization patterns.
The harness verifies `cgroup.events` shows `populated 0` before
returning to the LLM.

`cgroup.kill` semantics are identical to the backgrounded-shell
substrate; this spec does not duplicate the rationale, see
[`planner-harness.md §5.3`](planner-harness.md).

### 7.3 CPU and memory limits

By default, custom-tool subprocesses inherit CPU weight and memory
limits from the planner VM's root cgroup. Operators MAY declare
per-tool limits in a future V2.x extension; V2.0 ships without
per-tool resource caps.

`policy.toml` MAY declare a global `max_concurrent_custom_tool_invocations`
across a single VM (default `4`). Excess concurrent invocations queue
in the harness; queue depth is bounded by `max_queued_custom_tool_invocations`
(default `8`). Queue overflow → the LLM receives a `tool_result` error
`CustomToolConcurrencyExhausted` and may retry.

#### Queue-wait deadline (`max_queue_wait_ms`)

Queueing without a wait cap is a denial-of-service waiting to
happen: a long-running tool A holding the only concurrency slot
can starve any subsequent invocation indefinitely, but the LLM
sees nothing — its `tool_use` block hangs until `timeout_seconds`
or the session is torn down.  Worse, when the tool finally runs,
the run-time deadline (`timeout_seconds`) starts ticking from
*dequeue*, so the LLM has effectively waited `queue_wait +
timeout_seconds` for an outcome.

`policy.toml` declares a global queue-wait deadline:

```toml
[custom_tools]
# Maximum wall-clock time an invocation may sit in the harness
# concurrency queue before the harness gives up and surfaces a
# distinct error to the LLM.  Default: 30_000 ms (30 s).  Hard
# floor: 1_000 ms (anything tighter than 1 s is operationally
# indistinguishable from immediate rejection — use
# max_queued_custom_tool_invocations = 0 if that is the goal).
# Hard ceiling: max_custom_tool_timeout_seconds * 1000 (a queue
# wait longer than the longest legal execution is always wrong).
max_queue_wait_ms = 30000
```

Per-tool override is **not** supported: the queue is a global
harness resource; allowing one tool to declare a 5-minute queue
wait while another declares 1 s would let a noisy tool starve a
quiet one. The deadline applies uniformly to every queued
invocation in a single VM.

**Mechanism.**

1. When the harness receives an invocation request and the
   concurrency limit is hit, it stamps `queued_at_ms = now_ms()`
   on the queue entry.
2. A single dedicated `tokio::time::sleep_until(queued_at_ms +
   max_queue_wait_ms)` task races the entry's
   `concurrency_slot_available` notify channel.
3. If the timer fires first: the harness removes the entry from
   the queue, emits a `CustomToolInvoked` audit event with
   `outcome = QueueTimeout { queued_for_ms }`, and returns to the
   LLM a `tool_result` with `is_error: true`, content =
   `[CUSTOM_TOOL_QUEUE_TIMEOUT after Nms; concurrency limit was
   busy for the entire wait window]`. The LLM-facing failure
   reason is **`CustomToolQueueTimeout`** (distinct from
   `CustomToolTimeout` and from `CustomToolConcurrencyExhausted`
   — see §6.7).
4. If the slot becomes available first: the timer is cancelled,
   the entry is dequeued, and the harness invokes the tool
   normally. `timeout_seconds` is timed from dequeue, NOT from
   `queued_at_ms`. This is intentional: queue-wait time is the
   harness's responsibility and is bounded by `max_queue_wait_ms`;
   execution-time is the script's responsibility and is bounded
   by `timeout_seconds`. Conflating them would mean a tool that
   was queued for 25 s with a 60 s timeout has only 35 s left to
   actually run — surprising and operationally confusing.

**Distinction from `CustomToolConcurrencyExhausted`.**
`CustomToolConcurrencyExhausted` fires at *admission* — the queue
is full when the request arrives, so the request is never
queued. `CustomToolQueueTimeout` fires for a request that was
*successfully queued* but waited too long for a concurrency
slot. Both surface as distinct LLM-facing errors so the LLM (and
the audit consumer) can disambiguate "this VM is too busy to
even queue my call" from "this VM accepted my call but never
freed up a slot."

**Audit guarantees.** A queued-and-timed-out invocation produces
exactly one `CustomToolInvoked` audit row with `outcome =
QueueTimeout { queued_for_ms }`. A queued-and-eventually-run
invocation produces exactly one row with `outcome = Success` /
`NonZeroExit` / `Timeout` (the queue-wait time is recorded in a
separate `queued_for_ms` field on the row, distinct from the
execution `duration_ms`, so operators can trace queue pressure
without reading every audit row).

### 7.4 Filesystem mounts

Custom-tool subprocesses run with the planner VM's mount table
unchanged. They have read-write access to `/workspace` (per the
agent's role; an Executor's `/workspace` is RW, an Orchestrator's is
RO per [`planner-harness.md §3`](planner-harness.md)). They can read `/raxis/` (plan-bundle
artifacts, KSB-staged data, credentials per [`credential-proxy.md`](credential-proxy.md)).

The harness does NOT mount any per-invocation tmpfs. Scripts that
need scratch space use `/tmp` inside the VM (typically a tmpfs in the
operator's image).

---

## §8 — Profile Inheritance and Merge Semantics

### 8.1 Inheritance graph

A profile MAY declare `inherits_from = "<parent>"`. In V2 the
permitted built-in role roots are **`"Executor"`** and **`"Reviewer"`**
(operator-declared Reviewer profiles are permitted but have a tool
surface fixed by `INV-PLANNER-HARNESS-01` — they cannot declare custom
tools, see §10). Profiles attempting `inherits_from = "Orchestrator"`
are rejected at admission with `FAIL_PROFILE_ROLE_NOT_CONFIGURABLE`
because the **Orchestrator** is kernel-managed invisible infrastructure
per `INV-PLANNER-HARNESS-06` ([`planner-harness.md §4.8`](planner-harness.md)) — operators
do not declare Orchestrator profiles at all; the kernel auto-creates
the Orchestrator session per initiative.

Inheritance chains are acyclic; cycles are rejected at admission with
`FAIL_PLAN_PROFILE_INHERITANCE_CYCLE`.

### 8.2 Merge rule for `custom_tool` arrays

Custom tools are merged **additively** through the inheritance chain.
The effective custom-tool set for profile `P` is:

```text
effective(P) =
    union(custom_tools_declared_directly_on(P),
          effective(parent_of(P)))
```

### 8.3 Name collision is an error

If a child profile declares a custom tool with the same `name` as an
ancestor (or sibling-via-shared-ancestor), the merged set has a
collision and admission fails with `FAIL_CUSTOM_TOOL_NAME_COLLISION
{ name, declaring_profiles: [...] }`.

This rule is intentional: silent override is a configuration footgun.
The expert design discussion converged on **error, not override**:
"If the child needs a different tool, it should name it
`lint_frontend`."

### 8.4 Inheriting from `Reviewer` or `Orchestrator`

Reviewer and Orchestrator have asymmetric treatment under inheritance:

- **`inherits_from = "Reviewer"`** is **permitted** at the inheritance
  graph level (operators can declare `[profiles.<name>]` with this
  parent), but profiles in the resulting Reviewer-rooted subtree MAY
  NOT declare any `custom_tool` blocks. This is enforced at admission
  per `INV-PLANNER-HARNESS-04` (§10) on the *effective role* of the
  profile (the role at the root of the inheritance chain). The check
  surfaces as `FAIL_REVIEWER_CUSTOM_TOOL_NOT_ALLOWED` when violated.

- **`inherits_from = "Orchestrator"`** is **rejected outright** at
  admission with `FAIL_PROFILE_ROLE_NOT_CONFIGURABLE`. The
  Orchestrator is kernel-managed invisible infrastructure per
  `INV-PLANNER-HARNESS-06` ([`planner-harness.md §4.8`](planner-harness.md)); there is no
  operator-declared Orchestrator profile concept in V2 to inherit
  from. The custom-tool prohibition is therefore structural — there
  is no Orchestrator-rooted profile that could declare custom tools
  to begin with.

The asymmetry reflects the underlying invariants: Reviewer is a
*configurable role with a fixed tool surface*; Orchestrator is a
*non-configurable role*.

---

## §9 — Token Budget Projection and Count Cap

### 9.1 Per-profile and per-task count cap

Each profile may declare at most **25** custom tools (after
inheritance merge). Each executor task's merged `profiles = [...]`
bundle may also expose at most **25** effective custom tools. The cap
is hard-coded in V2; future versions may make it configurable.
Violation → `FAIL_CUSTOM_TOOL_COUNT_EXCEEDED { scope, count, limit: 25 }`.

The cap exists to push operators toward composing capability across
multiple tasks rather than building one mega-agent with 100 tools
(which both bloats system prompt and degrades the LLM's ability to
choose the right tool). Multiple profiles improve reuse and operator
ergonomics; they do not widen the per-task tool surface beyond the
same fail-closed cap.

### 9.2 Token-budget projection at admission

Custom tools occupy real space in the model's tool-list payload, which
counts against context window. The harness performs a deterministic
token-cost projection at admission:

- Serialize each effective custom tool in the format used in the
  Anthropic / OpenAI tool-list payload (canonical JSON, sorted keys).
- Tokenize using the model-family tokenizer declared in the plan's
  `[provider_aliases.<alias>]` for the profile (per
  [`provider-failure-handling.md`](provider-failure-handling.md)).
- Sum across all custom tools.
- Compute `custom_tool_share = sum / context_window_size` for the
  smallest context window across the profile's alias chain.

### 9.3 Threshold gates

| Threshold | Action |
|---|---|
| `< 10%` | Silent. |
| `≥ 10%` AND `< 25%` | `WARN_CUSTOM_TOOL_SCHEMA_BUDGET_HIGH { profile, share, total_tokens }` (per [`policy-plan-authority.md §3`](policy-plan-authority.md)). |
| `≥ 25%` | `FAIL_CUSTOM_TOOL_SCHEMA_BUDGET_EXCEEDED { profile, share, total_tokens, limit_share: 0.25 }` (per [`policy-plan-authority.md §3b`](policy-plan-authority.md)). |

The 10% / 25% thresholds are V2 defaults. `policy.toml` MAY tighten
(but not loosen) via:

```toml
[custom_tool_limits]
schema_budget_warn_share  = 0.05    # operator wants tighter warning
schema_budget_fail_share  = 0.15    # operator wants tighter rejection
```

Setting either share above the V2 default has no effect — the kernel
takes the more restrictive of (default, policy).

### 9.4 Tokenizer pinning

Token projection uses the tokenizer for the **specific model that
will receive the request**, not a generic estimate. This requires
the kernel to ship the relevant tokenizer tables (Anthropic's BPE
variant, OpenAI's `cl100k_base` / `o200k_base`, etc.) or to call into
the gateway's tokenizer subsystem. V2 implements this via the gateway
(per [`provider-failure-handling.md`](provider-failure-handling.md)); the gateway exposes a
`tokenize(model, text) -> u32` admin interface used at admission.

---

## §10 — Reviewer Role Prohibition (`INV-PLANNER-HARNESS-04`)

### 10.1 The invariant

> **`INV-PLANNER-HARNESS-04` — Reviewer Custom Tool Prohibition.** A
> profile whose effective role is `Reviewer` MUST NOT declare any
> `[[profiles.<name>.custom_tool]]` blocks (directly or via
> inheritance). Plan-admission rejects with
> `FAIL_REVIEWER_CUSTOM_TOOL_NOT_ALLOWED { profile, declaring_profiles:
> [...] }`. The check is structural: the admission stage walks the
> inheritance chain, computes the effective custom-tool set, and
> rejects if the effective role is `Reviewer` AND the set is non-empty.

### 10.2 Why this is structural, not optional

A custom tool is arbitrary code execution — a forked subprocess
running operator-defined argv with operator-defined input. It is the
exact attack surface that `INV-PLANNER-HARNESS-01` (Reviewer Code
Execution Prohibition) was designed to eliminate.

The kernel-bundled `raxis-reviewer-core` image
(`INV-PLANNER-HARNESS-02`) does not contain `python3`, `node`,
`bash`, or any shell — so most operator-declared custom-tool commands
would fail at runtime even if admission permitted them. But relying
on "fails at runtime" is wrong defense-in-depth: it produces partial
audit records, surfaces failure to the LLM mid-session, and leaks the
fact that the operator *attempted* to grant code execution to the
Reviewer.

The structural ban catches the misconfiguration at admission, with a
clear remediation message, before any session is created.

### 10.3 Composition with prior invariants

`INV-PLANNER-HARNESS-04` composes with:

- `INV-PLANNER-HARNESS-01` (no Reviewer code execution) — custom tools
  WOULD be code execution; banned at admission.
- `INV-PLANNER-HARNESS-02` (kernel-canonical Reviewer image) — even if
  admission missed a custom tool declaration, the Reviewer image lacks
  the runtimes to execute it. Defense-in-depth.
- `INV-VERIFIER-01..11` (verifier subsystem) — operators who need
  code-running checks for review-time decisions use verifiers, which
  produce structured witness records that flow through the audit
  chain into the Reviewer's KSB. Verifiers are the supported answer
  to "I want operator code to influence Reviewer judgment."

### 10.4 What Reviewer profiles CAN declare

A Reviewer profile MAY still declare:

- `inherits_from = "Reviewer"` (the only legal parent for a Reviewer
  profile).
- Profile-level metadata fields shared with all roles (description,
  budgets, etc.).
- Plan-level review parameters (`symbol_index = "not_needed"`, etc.,
  per [`policy-plan-authority.md`](policy-plan-authority.md)).

It MAY NOT declare:

- `[[profiles.<name>.custom_tool]]` (this invariant).
- `vm_image` or any image override (`INV-PLANNER-HARNESS-02`).
- Bash or LSP capability flags (`INV-PLANNER-HARNESS-01` — these are
  not even in the harness binary's Reviewer build target).

### 10.5 Orchestrator: structural impossibility (`INV-PLANNER-HARNESS-06`)

The Orchestrator role's prohibition on custom tools is *structural*,
not declarative: in V2, `plan.toml` cannot contain an
`[profiles.<name>]` whose effective role is `Orchestrator`, and cannot
contain `[plan.tasks.<id>] role = "Orchestrator"`, per
`INV-PLANNER-HARNESS-06` ([`planner-harness.md §4.8`](planner-harness.md)). Since there is
no operator-declared Orchestrator profile, there is no surface on
which an operator could attach a `[[profiles.<name>.custom_tool]]`
block targeting the Orchestrator.

Operators who attempt to express "give the Orchestrator a custom tool"
will encounter the rejection at the *profile/task declaration* stage,
not at the custom-tool stage:

- `[profiles.coordinator] role = "Orchestrator"` →
  `FAIL_ORCHESTRATOR_PROFILE_NOT_ALLOWED`.
- `[profiles.coordinator] inherits_from = "Orchestrator"` →
  `FAIL_PROFILE_ROLE_NOT_CONFIGURABLE`.
- `[plan.tasks.merge_things] role = "Orchestrator"` →
  `FAIL_ORCHESTRATOR_TASK_NOT_ALLOWED`.

Each rejection includes a remediation message pointing at
[`planner-harness.md §4.8`](planner-harness.md) and noting that the Orchestrator is
kernel-managed.

**Why the Orchestrator's custom-tool ban is structural, not declarative
(unlike the Reviewer's).** The Reviewer is an operator-configurable
role with a *fixed tool surface* — operators DO declare Reviewer
profiles (with prompt overrides, budgets, etc.), and the custom-tool
ban is an explicit `INV-PLANNER-HARNESS-04` admission check. The
Orchestrator is *not operator-configurable at all* — `plan.toml`
literally has no syntactic surface for an Orchestrator profile, so the
custom-tool question never reaches an admission check; it is rejected
one layer up at the profile-declaration layer. The result is the same
(no custom tools for the Orchestrator), but the failure point
(profile-declaration vs custom-tool-declaration) and the failure code
differ.

---

## §11 — Custom Tools vs. Verifiers (When to Use Which)

This is the operator-facing decision tree the spec must answer
unambiguously, because verifiers and custom tools occupy adjacent
semantic territory and confusion is predictable.

| Concern | Verifier ([`verifier-processes.md`](verifier-processes.md)) | Custom Tool (this spec) |
|---|---|---|
| **Invoked by** | Kernel (preflight, on `CompleteTask`) | LLM (on-demand during a session) |
| **VM / locality** | Dedicated isolated verifier VM | `guest_subprocess` in the agent VM, or kernel-owned host/MCP adapter locality |
| **Output reaches** | Audit chain (`witness_records`) → Reviewer KSB | LLM context as `tool_result` |
| **Affects review gate?** | Yes — `block_review` failures fail the task; `warn_only` failures surface as KSB witnesses | No — informational to the LLM only |
| **Image / binary source** | Operator-published, OCI-pinned, `role_restriction` includes `Verifier` | Executor image for `guest_subprocess`; host-installed adapter for host-owned localities (custom tools are Executor-only in V2 — Reviewer per `INV-PLANNER-HARNESS-04`, Orchestrator per `INV-PLANNER-HARNESS-06`) |
| **Invocation cardinality** | Exactly once per `CompleteTask` per declared verifier | Zero, one, or many times per session at LLM discretion |
| **Network** | Air-gapped by default; explicit `allowed_egress` opt-in | Guest locality gets the agent VM's mediated egress; host/MCP localities use the operator-declared host adapter, never a generic agent-controlled network client |
| **Auditability** | `WitnessSubmission` + `VerifierTimedOut` etc. | `CustomToolInvoked` (this spec §12) |
| **Use it for** | Lint, type-check, unit-test, symbol-index — anything that should gate Reviewer judgment | LLM-callable utilities (telemetry lookup, schema introspection, internal status APIs) — anything informational to the LLM's reasoning loop |

**The crisp rule:** if the operator's intent is *"this code-running
check should gate whether the Reviewer is even allowed to look at the
work"*, it's a verifier. If the intent is *"the agent should be able
to ask this on demand while working"*, it's a custom tool.

A future task may be both: the operator declares both a verifier (for
the gate) and a custom tool (for the agent's interactive use during
work). They are not mutually exclusive.

---

## §12 — Audit Event: `CustomToolInvoked`

### 12.1 Schema

Every custom-tool invocation emits exactly one `CustomToolInvoked`
audit event after the subprocess exits (or is killed). The event
hashes into the audit chain per `INV-04`.

```rust
pub enum AuditEventKind {
    // … existing variants …

    CustomToolInvoked {
        tool_name:               String,
        profile_name:            String,
        execution_locality:      String, // guest_subprocess | host_subprocess | host_mcp | remote_mcp
        outcome:                 String,
        duration_ms:             u64,
        exit_code:               Option<i32>,
        signal:                  Option<i32>,
        timeout_ms:              u64,
        command_argv_sha256:     String,
        stdin_bytes_total:       u64,
        stdin_sha256:            String,
        stdout_bytes_total:      u64,
        stdout_bytes_captured:   u64,
        stdout_sha256:           String,
        stdout_truncated:        bool,
        stderr_bytes_total:      u64,
        stderr_bytes_captured:   u64,
        stderr_sha256:           String,
        stderr_truncated:        bool,
        error:                   Option<String>,
    },
}

pub enum CustomToolOutcome {
    Success,
    ToolError,
    SchemaRejected,
    InputTooLarge,
    SpawnFailed,
    StdinWriteFailed,
    WaitFailed,
    Timeout,
    NonZeroExit,
    StdoutReadFailed,
    StderrReadFailed,
    AuditReportFailed,
    // Reserved / not yet implemented:
    /// Queued but `max_queue_wait_ms` elapsed before a concurrency
    /// slot freed (§7.3). `queued_for_ms` on the parent event
    /// equals `max_queue_wait_ms` at the boundary.
    QueueTimeout { queued_for_ms: u64 },
    KilledOnTeardown,
    /// Queue full at admission — request was never queued.
    /// Distinct from `QueueTimeout`, which fires for a request
    /// that *was* queued but waited too long. See §6.7 / §7.3.
    ConcurrencyExhausted,
    SubprocessSpawnFailed { errno: i32 },
}
```

> **Note on integrity attestation.** V2 deliberately does NOT include
> a per-invocation hash of `command[0]` in this event. The script's
> bytes are part of the operator's VM image, whose OCI digest is
> already pinned at policy load (`INV-VM-CAP-03`) and audited via
> `SessionCreated { vm_image_digest }`. The image digest covers every
> byte the script depends on (interpreter, libc, shared libraries,
> the script itself); a per-invocation script hash would be a strict
> subset of that coverage and create the misleading impression that
> the kernel had verified script integrity end-to-end. The supply
> chain is bound at image-pull time, not at tool-call time.

### 12.2 Optional full-payload archival

By default, the kernel persists only the SHA-256 digests of stdin /
stdout / stderr; the full bytes are discarded after the audit event
emits. Operators who require full payload retention for compliance
can opt in via `policy.toml`:

```toml
[audit.custom_tools]
archive_full_payloads        = false   # default
archive_payload_max_bytes    = 1_048_576   # 1 MiB cap when archival is on
```

When `archive_full_payloads = true`, the kernel writes the full
stdin / stdout / stderr bytes to a content-addressed payload store
(`store/audit-payloads/<sha256>.bin`), keyed by the digests in the
audit event. Payloads above `archive_payload_max_bytes` are truncated
with the truncation flagged in a separate `CustomToolPayloadTruncated`
audit event.

This payload archival follows the same lifecycle as
`audit-retention.md` (V3); V2 retains payloads indefinitely.

### 12.3 Operator-facing log surface

The `raxis log` CLI gains a custom-tool view:

```bash
$ raxis log --filter kind=CustomToolInvoked --task <id>

T+12.4s  query_telemetry  ok  92ms  in=63B out=1.2KiB
T+15.8s  query_telemetry  ok  78ms  in=63B out=1.1KiB
T+18.1s  internal_status  err 215ms in=12B out=234B (exit 1)
```

With `--full`, each line expands to show input/output digests,
truncation state, and the resolved command line.

---

## §13 — Cross-Spec Impacts

### 13.1 Already specified (or being specified in this PR)

| Spec | Change |
|---|---|
| [`planner-harness.md`](planner-harness.md) | Add Custom Tools as a third tool category alongside base tools and kernel-mediated intents (extension to §3); list `INV-PLANNER-HARNESS-04` in §13 invariants index. |
| [`policy-plan-authority.md`](policy-plan-authority.md) | New `WARN_CUSTOM_TOOL_SCHEMA_BUDGET_HIGH` (§3); new `FAIL_CUSTOM_TOOL_*` codes (§3b); admission check ordering update (§5); `policy.toml` `[custom_tool_limits]` and `[audit.custom_tools]` schema (§4). |
| [`kernel-mechanics-prompt.md`](kernel-mechanics-prompt.md) | Note that custom tools are appended verbatim to the JSON `tools` array alongside base tools and indistinguishable to the LLM at the protocol level (§3.1, §3.2). Reviewer NNSP confirms no custom tools surface (§3.3). |
| [`vm-network-isolation.md`](vm-network-isolation.md) | Cross-reference: custom-tool subprocesses share the agent VM's network namespace and are subject to tproxy + credential proxy enforcement; no new authority surface. |
| `invariants.md` | Add `INV-PLANNER-HARNESS-04` (§10); update count in TOC and preamble; new composition row. |

### 13.2 Future amendments (V2.x or V3)

| Spec | Change | Driver |
|---|---|---|
| `audit-retention.md` (V3) | Custom-tool payload archival lifecycle, retention windows, GC. | `[audit.custom_tools]` policy fields above. |
| [`host-capacity.md`](host-capacity.md) | Custom-tool concurrent-invocation limits as a host-aggregate budget category. | If operators report CPU-saturation incidents from runaway concurrent custom tools. |
| [`custom-tools.md`](custom-tools.md) (this file) | Per-tool CPU / memory cgroup limits. | V2.x extension; ships when concrete operator demand exists. |

---

## §14 — Implementation Checklist

- [x] Plan parser accepts `[[profiles.<name>.custom_tool]]` array-of-tables under each profile, with the field schema in §3.2.
- [x] Task parser accepts plural `profiles = [...]`, rejects singular `profile = "..."`, resolves profiles in declared order, deduplicates identical overlapping tool declarations, and rejects conflicting duplicate effective tool names across selected profiles.
- [x] Plan parser rejects `[[plan.tasks.<id>.custom_tool]]` and `[[tasks]].custom_tool` with `FAIL_CUSTOM_TOOL_TASK_LEVEL_NOT_ALLOWED` (§3.5).
- [ ] Vendored Draft-07 schema validator implementing the accepted-keyword set in §4.1 and rejecting all keywords in §4.2.
- [ ] Reserved-name list mirrored from kernel binary; `raxis admin reserved-tool-names` CLI exposes it.
- [x] Inheritance walker computes effective custom-tool set; rejects cycles, name collisions, Reviewer-role + non-empty set, Orchestrator-rooted profiles, and per-task merged bundles above 25 tools.
- [ ] Admission emits all `FAIL_*` and `WARN_*` codes per §3, §4.3, §5, §9.3, §10.1. Current implementation emits the structural `FAIL_*` family for profile shape, name, command, timeout, inheritance, and role violations; token-budget and schema-budget warnings remain outstanding.
- [ ] Token-budget projector pulls tokenizer from `raxis-gateway`'s `tokenize(model, text)` admin interface; computes `custom_tool_share` per §9.2.
- [x] Harness side: loads kernel-stamped custom-tool bundles only for Executor sessions, rejects malformed bundles fail-closed, and constructs JSON stdin for guest subprocess wrappers or kernel-owned execution requests.
- [x] Kernel side: implements `host_subprocess`, `host_mcp`, and `remote_mcp` as signed-plan-resolved host adapter executions. The planner supplies only `tool_name` and JSON input; command argv, locality, and adapter placement are resolved by the kernel.
- [x] Harness/kernel side: enforces per-tool timeout by killing the subprocess and returning a structured `tool_result.is_error`.
- [x] Harness/kernel side: schema-validates the shipped Draft-07 subset before script invocation and enforces stdin/stdout/stderr byte caps. Per-invocation cgroups and `cgroup.kill` remain outstanding.
- [x] Harness side: builds bounded `tool_result` output and applies stderr exposure rules (`expose_stderr` defaults false).
- [ ] Harness side: implements the queue-wait deadline per §7.3 (`max_queue_wait_ms`). Each queued invocation stamps `queued_at_ms`; a `tokio::time::sleep_until` task races the `concurrency_slot_available` notify channel; on timeout, surfaces `CustomToolQueueTimeout` distinct from `Timeout` and `CustomToolConcurrencyExhausted`.
- [ ] Policy admission validates `max_queue_wait_ms ∈ [1_000, max_custom_tool_timeout_seconds * 1000]`; out-of-range emits `FAIL_POLICY_CUSTOM_TOOL_QUEUE_WAIT_EXCEEDS_TIMEOUT` / `FAIL_POLICY_CUSTOM_TOOL_QUEUE_WAIT_TOO_SMALL`.
- [x] Audit event `CustomToolInvoked` per §12.1; emits regardless of outcome for `guest_subprocess`, `host_subprocess`, `host_mcp`, and `remote_mcp` execution attempts once the request resolves to a signed tool. Guest-subprocess audit reports are accepted only when tool name, profile name, locality, argv digest, and timeout match the signed effective task bundle.
- [ ] Optional full-payload archival per §12.2 (gated on `[audit.custom_tools] archive_full_payloads`).
- [ ] `raxis log` CLI gains the custom-tool view per §12.3.
- [ ] `raxis-gateway` exposes `tokenize` admin interface (cross-spec dependency).
- [x] Dashboard Tool Builder validates draft custom-tool profile TOML through a kernel-facing read-only endpoint and surfaces next-step CLI commands.
- [x] Live e2e includes a Unity-like MCP fixture proving the supported BYO/MCP migration path: one bounded Executor custom tool per MCP method, no generic MCP discovery bridge.
- [ ] Tests:
      - Plan with valid custom tool → admitted; LLM sees the tool in `tools` array. (unit coverage exists for bundle resolution; full admission/runtime e2e added via `tooling-mcp-unity` slice)
      - Executor task with multiple profiles → admitted; effective tools merge in declared task order.
      - Executor task selecting two profiles with an identical effective tool declaration → admitted with one LLM-visible tool and first-profile attribution.
      - Executor task selecting two profiles with the same effective tool name but different semantics → `FAIL_CUSTOM_TOOL_NAME_COLLISION`.
      - Plan with reserved-name custom tool → `FAIL_CUSTOM_TOOL_NAME_RESERVED`.
      - Plan with name collision across inherited profile → `FAIL_CUSTOM_TOOL_NAME_COLLISION`.
      - Reviewer profile with custom tool → `FAIL_REVIEWER_CUSTOM_TOOL_NOT_ALLOWED`.
      - Schema with `$ref` → `FAIL_CUSTOM_TOOL_SCHEMA_UNSUPPORTED_FEATURE`.
      - Schema with `oneOf` → `FAIL_CUSTOM_TOOL_SCHEMA_UNSUPPORTED_FEATURE`.
      - Schema with `additionalProperties: true` at root → `FAIL_CUSTOM_TOOL_SCHEMA_ADDITIONALPROPERTIES_TRUE`.
      - 26 custom tools on a profile → `FAIL_CUSTOM_TOOL_COUNT_EXCEEDED`.
      - Custom-tool schemas summing to 26% of context window → `FAIL_CUSTOM_TOOL_SCHEMA_BUDGET_EXCEEDED`.
      - Custom-tool schemas summing to 12% of context window → `WARN_CUSTOM_TOOL_SCHEMA_BUDGET_HIGH` (or admission failure under `--strict`).
      - Custom tool returning non-JSON stdout → `tool_result` content = stdout as-is.
      - Custom tool exceeding `stdout_max_bytes` → truncation sentinel present; full SHA-256 in audit.
      - Custom tool exceeding `timeout_seconds` → cgroup.kill atomic teardown; outcome `Timeout`.
      - Custom tool exiting non-zero → `tool_result.is_error = true`; outcome `NonZeroExit`.
      - Custom tool with `expose_stderr = false` (default) → LLM sees stdout only; audit captures stderr.
      - Custom tool with `expose_stderr = true` → LLM sees stdout + sentinel-bracketed stderr.
      - Custom tool double-fork daemonization → cgroup.kill catches both processes on timeout.
      - Host-owned custom tool tries to spoof command/locality from the guest request → kernel ignores the guest and resolves from the signed task bundle.
      - Profile inheritance cycle → `FAIL_PLAN_PROFILE_INHERITANCE_CYCLE`.
      - 5 concurrent invocations against `max_concurrent_custom_tool_invocations = 4` → 5th gets `CustomToolConcurrencyExhausted`. (Queue still has slots, but the 5th *also* exceeds queue depth — `max_queued_custom_tool_invocations = 0`.)
      - 5 concurrent invocations against `max_concurrent_custom_tool_invocations = 4`, `max_queued_custom_tool_invocations = 4`, `max_queue_wait_ms = 200` with the running tools holding their slots for 30 s → 5th invocation queues, waits 200 ms, surfaces `CustomToolQueueTimeout` (NOT `CustomToolConcurrencyExhausted`); audit row records `outcome = QueueTimeout { queued_for_ms: 200 }` and `duration_ms = 0`.
      - Same setup but the running tool finishes after 100 ms → 5th invocation dequeues at 100 ms, runs to completion; audit row records `queued_for_ms = 100`, `duration_ms` = actual execution time, `outcome = Success`. Verifies queue-wait time does NOT consume `timeout_seconds`.
      - `max_queue_wait_ms` set above `max_custom_tool_timeout_seconds * 1000` → policy admission rejects (`FAIL_POLICY_CUSTOM_TOOL_QUEUE_WAIT_EXCEEDS_TIMEOUT`).
      - Custom tool inside Executor performing HTTP via `urllib` → blocked by tproxy SNI allowlist exactly as bash-invoked HTTP would be.

---

## §15 — Invariants Index

Invariants introduced by this spec:

| Invariant | Statement (one-line) | Section |
|---|---|---|
| `INV-PLANNER-HARNESS-04` | Reviewer Custom Tool Prohibition: profiles with effective role `Reviewer` MUST NOT declare any `[[profiles.<name>.custom_tool]]` blocks (directly or transitively). Plan-admission rejects with `FAIL_REVIEWER_CUSTOM_TOOL_NOT_ALLOWED`. | §10 |

This composes with the existing `INV-PLANNER-HARNESS-*` family:

- **`INV-PLANNER-HARNESS-01`** (no Reviewer code execution) — custom
  tools WOULD be code execution; this invariant catches the
  declaration at admission, before any session is created.
- **`INV-PLANNER-HARNESS-02`** (kernel-canonical Reviewer image) — even
  if admission were bypassed, the canonical image lacks the runtimes
  to execute most operator-declared scripts. Defense-in-depth.
- **`INV-PLANNER-HARNESS-03`** (cgroup v2 process containment) — when
  custom tools DO run (Executor profiles only in V2), they are
  contained in per-invocation cgroups and atomically terminable via
  `cgroup.kill`.
- **`INV-PLANNER-HARNESS-05`** (kernel-canonical Orchestrator image) —
  the Orchestrator image is the kernel's responsibility, parallel to
  the Reviewer image; the operator has no surface on which to attach
  custom tools to it.
- **`INV-PLANNER-HARNESS-06`** (Orchestrator not operator-configurable)
  — there is no operator-declared Orchestrator profile in V2; custom
  tools for the Orchestrator are structurally impossible. This is why
  this spec is an *Executor-only* feature in V2.

And with verifier-side invariants:

- **`INV-VERIFIER-01..11`** — verifiers are the supported answer to
  "I want operator code to influence Reviewer judgment." Custom tools
  serve a different purpose (LLM-on-demand utilities) and explicitly
  do NOT participate in review gating.

---

*Spec complete. Per the standing rule for `INV-PLANNER-HARNESS-*`:
when this file is wrong (i.e., when an implementation choice
contradicts a statement here), the implementation MUST be amended to
conform OR a follow-up amendment to this spec MUST land in the same
PR. Silent divergence between code and this spec is a process
failure.*
