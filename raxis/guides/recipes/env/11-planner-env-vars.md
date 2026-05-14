# Planner env vars (`RAXIS_PLANNER_*` & friends)

> **Topic:** Environment variables | **Time to read:** ~3 min | **Complexity:** ⭐⭐⭐ Advanced

When the kernel spawns a planner VM (Orchestrator, Executor, or
Reviewer), it stamps a fixed set of `RAXIS_PLANNER_*` env vars into
the VM's environment. The in-VM dispatch loop reads them to
configure the LLM provider, the per-session token caps, the kernel
IPC transport, and the seed prompt for "live mode". This recipe is
the reference.

---

## Read by

- The planner binaries inside agent VMs:
  - `raxis-planner-orchestrator`
  - `raxis-planner-executor`
  - `raxis-planner-reviewer`
- All three share the same `planner-core` driver, which reads these
  vars uniformly.

---

## The kernel-IPC vars

These tell the planner how to reach the kernel from inside its VM.

| Variable | Required | Effect |
|---|---|---|
| `RAXIS_KERNEL_PLANNER_SOCKET` | yes (UDS path) | Unix-domain socket for planner ↔ kernel IPC. The kernel stamps this when the VM uses a UDS-mounted transport. |
| `RAXIS_KERNEL_VSOCK_CID` | yes (number) | When using virtio-vsock transport (KVM), the host CID the planner should connect to. |
| `RAXIS_KERNEL_VSOCK_PORT` | yes (port) | The vsock port the kernel listens on. |
| `RAXIS_PLANNER_KSB` | yes (JSON object) | "Kernel session bootstrap" — a JSON blob containing the session_id, task_id, agent_type, allowlist, etc. The planner reads this on startup. Constant: `raxis_ksb::PLANNER_KSB_ENV`. |

The planner picks transport at runtime:

```text
1. RAXIS_KERNEL_PLANNER_SOCKET set + non-empty → use UDS.
2. RAXIS_KERNEL_VSOCK_CID + RAXIS_KERNEL_VSOCK_PORT set → use vsock.
3. Otherwise → KernelTransportConfig::None (parking mode).
```

---

## The "live mode" toggle

| Variable | Required | Effect |
|---|---|---|
| `RAXIS_PLANNER_TASK_PROMPT` | yes for "live mode" | Seed user message for the dispatch loop. **Empty / unset = the planner stays parked** (V1 default; planner spawns and waits for an external signal). The kernel stamps this for V2 spawns; not for legacy V1 spawns. |

When `RAXIS_PLANNER_TASK_PROMPT` is unset OR empty, the planner:

- Connects to the kernel socket.
- Identifies itself.
- Parks: waits for the kernel to send a control message
  (`SpawnReady`, `Begin`, etc.) before doing anything else.

When set, the planner enters "live mode": treats the value as the
seed user message and runs the dispatch loop without waiting for an
external signal.

---

## The LLM-provider vars

| Variable | Required | Default | Effect |
|---|---|---|---|
| `RAXIS_PLANNER_BASE_URL` | optional | `https://api.anthropic.com` | Override the model API base URL. Used by tests to point at a local mock. The kernel stamps this from the active gateway provider. |
| `RAXIS_PLANNER_MAX_TURNS` | optional | `100` | Hard turn ceiling per session. Beyond this the planner stops the loop and submits whatever it has. Default raised from `20` to `50` after Live-e2e iter25 showed the `credential-substitution-canary` task reproducibly exhausted a 20-turn budget on natural tool-error retry cycles, then raised again from `50` to `100` after Live-e2e iter31 reproduced `MaxTurnsExceeded` at turn 50 on the realistic `materialize-records` Executor (25 postgres rows + 25 mongo docs + per-row write + commit + complete — a strictly larger fanout than the canary). The token-cap ceiling (`RAXIS_PLANNER_MAX_TOKENS_INPUT_TOTAL` / `…_OUTPUT_TOTAL`) remains the cost-side bound. Resolution is per-task (V2.7 — see "Resolving `RAXIS_PLANNER_MAX_TURNS`" below). |
| `RAXIS_PLANNER_MAX_TOKENS` | optional | `4096` | Per-request `max_tokens` value sent to the model API. |

`RAXIS_PLANNER_BASE_URL` must parse as an `http` or `https` URL.
Anything else triggers
`RAXIS_PLANNER_BASE_URL must be a valid http(s) URL`.

---

## Resolving `RAXIS_PLANNER_MAX_TURNS` (V2.7, `INV-PLANNER-MAX-TURNS-PRECEDENCE-01`)

The kernel computes the value stamped into `RAXIS_PLANNER_MAX_TURNS`
at session-spawn time via this precedence chain — the **first**
matching arm wins:

| Arm | Source | Wins when | Resulting `source` log label |
|---|---|---|---|
| 1 | `[[tasks]] max_turns = N` in the plan TOML | the activating task declares `max_turns` | `task` |
| 2 | `[gateway].planner_max_turns_default = N` in `policy.toml` | per-task is omitted, policy default is set | `policy` |
| 3 | compiled-in `DEFAULT_PLANNER_MAX_TURNS = 100` | both per-task and policy default are omitted | `compiled-default` |

Each spawn emits a structured `PlannerMaxTurnsResolved` log line on
the kernel's stderr with shape:

```text
PlannerMaxTurnsResolved {
  source        = "task" | "policy" | "compiled-default",
  resolved      = N,
  task_id       = "<task_id>",        // "<orchestrator>" for orchestrator spawns
  session_id    = "sess-…",
  initiative_id = "init-…",
}
```

so an operator can `rg PlannerMaxTurnsResolved <data-dir>/runtime/`
to confirm what budget every spawned VM received.

**Validation.** `[[tasks]] max_turns = 0` is rejected at admission
with `LifecycleError::PlanInvalid` — a 0-turn budget would terminate
the dispatch loop before the first model call and is never useful.
Negative values are rejected by the existing TOML shape check.

**Per-task vs. policy default — when to use which:**

- **Per-task `max_turns`** is the right knob for plans with mixed
  fanout — e.g. one Executor that materializes 25 records (needs
  ≥150) plus three Reviewers that judge a single diff (need ≤5).
  Put the per-task value on each `[[tasks]]` entry that needs to
  diverge from the default.
- **Policy `[gateway].planner_max_turns_default`** is the right knob
  for org-wide ceiling adjustments (e.g. CI plans with `= 5` for
  fail-fast smoke runs). Per-task overrides still win.
- **Compiled `100`** is the safe blanket default — calibrated
  against the realistic-scenario `materialize-records` Executor
  observed in iter25 / iter31.

**KSB visibility (`INV-KSB-MAX-TURNS-VISIBILITY-01`).** The same
resolved value is also projected into the per-session
`SessionCapabilityView::planner_max_turns` field on the KSB
`capabilities=` block, rendered as
`role=<role> session=<id> planner_max_turns=N`. This lets the
in-VM agent self-track its turn budget against the kernel's view
without an extra IPC round-trip.

---

## Progressive scaling on crash retry (V3, `INV-PLANNER-MAX-TURNS-PROGRESSIVE-ON-RETRY-01`)

The V2.7 precedence chain resolves a SINGLE `max_turns` value that
every attempt of the task shares. V3 adds a `step` knob that
**grows** the per-attempt budget on every crash retry, computed
at spawn time as:

    effective = min(base + (attempt - 1) * step, hard_ceiling)

where:

* `attempt` = `subtask_activations.crash_retry_count + 1` for the
  task being spawned (1 on first spawn; 2 after the first crash
  retry; etc.). Orchestrator spawns pass `attempt = 1`
  unconditionally — progressive scaling is a no-op for the
  orchestrator session.
* `base` = the V2.7-resolved per-task → per-policy → compiled
  `max_turns`.
* `step` precedence (mirrors the `base` chain):
  1. `[[tasks]].max_turns_step = N` in the plan TOML.
  2. `[gateway].planner_max_turns_step_default = N` in `policy.toml`.
  3. Derived default: `max(round_up_to_5(base / 2), 10)` (e.g.
     `base = 30` ⇒ derived step `15`; `base = 100` ⇒ derived step
     `50`; `base = 5` ⇒ derived step `10` (floor)).
* `hard_ceiling` = the `RAXIS_PLANNER_MAX_TURNS_HARD_CEILING` env
  var (best-effort u32 parse) or the compiled default `240`.

**Canonical witness table** (`base = 30, step = 30`):

| Attempt | crash_retry_count | scaled | effective (clamped at 240) |
|---|---|---|---|
| 1 | 0 |  30 |  30 |
| 2 | 1 |  60 |  60 |
| 3 | 2 |  90 |  90 |
| 8 | 7 | 240 | 240 |
| 9 | 8 | 270 | 240 (clamped) |

**Validation.** `[[tasks]].max_turns_step = 0` is rejected at
admission (a zero step degenerates the resolver back to a
constant budget and masks the cold-start retry tax this knob
exists to absorb). Omitting the field is admissible — the
resolver falls through to the policy default → derived default
precedence chain.

**Operator override — `RAXIS_PLANNER_MAX_TURNS_HARD_CEILING`.**
Set this env var on the kernel process to clamp the
progressively-scaled budget at a value other than the compiled
default `240`. The kernel reads it once at boot:

```sh
export RAXIS_PLANNER_MAX_TURNS_HARD_CEILING=180   # tighten
export RAXIS_PLANNER_MAX_TURNS_HARD_CEILING=400   # loosen
```

Unparseable / non-positive values silently degrade to the
compiled default — operator typos do not fail-close the spawn.
The resolved ceiling is surfaced on the orchestrator + executor
KSB envelopes as `max_turns_hard_ceiling=N` so the in-VM agent
sees the clamp value.

**Audit visibility.** When `attempt > 1` the kernel emits a
`PlannerMaxTurnsProgressivelyScaled` audit event with the
(`base`, `step`, `attempt`, `effective`, `hard_ceiling`) tuple —
visible in the dashboard's audit timeline. The companion
`PlannerMaxTurnsResolved` stderr structured-log line carries the
same numeric fields on every spawn so operators grepping the
kernel log have parity with the audit chain.

**KSB visibility.** The orchestrator + executor capabilities
envelopes carry a `max_turns_scaling` view rendered as

```text
  max_turns_attempt=N base=B step=S hard_ceiling=H
```

so the in-VM agent can reason about retry economics. The reviewer
envelope omits this line per the role-scoping rule — the
reviewer's verdict must be on the artifact, not on the
executor's budget pressure.

---

## The token cap vars (V2 §2.5)

These come from `[budget.token_caps]` in `policy.toml`. The kernel
stamps them into the planner-VM env at spawn time; the in-VM
dispatch loop enforces them.

| Variable | Stamped from | Effect |
|---|---|---|
| `RAXIS_PLANNER_MAX_TOKENS_INPUT_TOTAL` | `[budget.token_caps] max_input_tokens_per_session` | Cumulative input-token cap across the session. |
| `RAXIS_PLANNER_MAX_TOKENS_OUTPUT_TOTAL` | `[budget.token_caps] max_output_tokens_per_session` | Cumulative output-token cap. |
| `RAXIS_PLANNER_MAX_TOKENS_TOTAL` | `[budget.token_caps] max_total_tokens_per_session` | Combined input+output cap. |

Absent vars ⇒ uncapped on that axis. Reaching a cap fails the
next dispatch turn with `FAIL_TOKEN_CAP_EXCEEDED`.

---

## The workspace var

| Variable | Required | Effect |
|---|---|---|
| `RAXIS_WORKSPACE_PATH` | yes | Absolute path to the worktree provisioned for this session. The planner `cd`s here before running tools. |

---

## What an agent VM's env looks like at spawn

A representative spawn env:

```bash
RAXIS_KERNEL_PLANNER_SOCKET=/run/raxis/sockets/planner-c4f1e8.sock
RAXIS_PLANNER_KSB={"session_id":"c4f1e8...","task_id":"implementer",...}
RAXIS_PLANNER_TASK_PROMPT="Implement IP-based rate limiting on POST /auth/login. ..."
RAXIS_PLANNER_BASE_URL=https://api.anthropic.com
RAXIS_PLANNER_MAX_TURNS=100
RAXIS_PLANNER_MAX_TOKENS=4096
RAXIS_PLANNER_MAX_TOKENS_INPUT_TOTAL=200000
RAXIS_PLANNER_MAX_TOKENS_OUTPUT_TOTAL=100000
RAXIS_PLANNER_MAX_TOKENS_TOTAL=250000
RAXIS_WORKSPACE_PATH=/tmp/raxis-worktrees/c4f1e8-implementer
RAXIS_CREDENTIAL_PROD_POSTGRES_PORT=51234
RAXIS_CREDENTIAL_PROD_POSTGRES_HOST=127.0.0.1
RAXIS_CREDENTIAL_PROD_POSTGRES_USER=app
PATH=/usr/local/bin:/usr/bin:/bin
HOME=/root
```

---

## Common failure modes (planner-side)

| Symptom | Fix |
|---|---|
| Planner exits with `KernelTransport::None` | None of the transport vars are set. The kernel didn't stamp them; check `<data-dir>/runtime/spawn-<session>.log` for the spawn-side error. |
| `RAXIS_PLANNER_BASE_URL must be valid http(s) URL` | The provider's base URL in policy is malformed. Fix it; re-sign policy. |
| `FAIL_TOKEN_CAP_EXCEEDED` in the audit chain | Session hit a `[budget.token_caps]` cap. Either raise the cap (and re-spawn) or shorten the agent's runtime. |
| `RAXIS_PLANNER_KSB malformed` | The kernel's KSB-builder dropped a required field. Indicates a bug; file an issue with the spawn log. |

---

## Reference: relevant kernel-internal state

| Surface | Purpose |
|---|---|
| `kernel/src/initiatives/ksb_assembly.rs` | Builds the `RAXIS_PLANNER_KSB` JSON. |
| `crates/ksb/src/lib.rs::PLANNER_KSB_ENV` | The constant `"RAXIS_PLANNER_KSB"`. |
| `crates/planner-core/src/driver.rs` | Reads every `RAXIS_PLANNER_*` var. |
| `crates/planner-core/src/transport.rs` | Picks UDS / vsock / None at startup. |
| `<data-dir>/runtime/spawn-<session>.log` | Per-session spawn-side log. |

---

## Variations

- **Local mock provider.** Set `RAXIS_PLANNER_BASE_URL` (in the
  policy provider entry, which propagates) to a local mock; useful
  for offline tests.
- **Tight turn cap.** Set `[gateway].planner_max_turns_default = 5`
  in policy (a kernel-side override) to keep agents from running
  away in dev. The env var stamping happens automatically.
- **Don't stamp manually.** Operators never set these env vars by
  hand — the kernel stamps them at spawn time. Setting them in
  the parent shell does NOT propagate into the VM.
