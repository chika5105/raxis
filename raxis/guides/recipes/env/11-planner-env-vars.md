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
| `RAXIS_PLANNER_MAX_TURNS` | optional | `100` | Hard turn ceiling per session. Beyond this the planner stops the loop and submits whatever it has. Default raised from `20` to `50` after Live-e2e iter25 showed the `credential-substitution-canary` task reproducibly exhausted a 20-turn budget on natural tool-error retry cycles, then raised again from `50` to `100` after Live-e2e iter31 reproduced `MaxTurnsExceeded` at turn 50 on the realistic `materialize-records` Executor (25 postgres rows + 25 mongo docs + per-row write + commit + complete — a strictly larger fanout than the canary). The token-cap ceiling (`RAXIS_PLANNER_MAX_TOKENS_INPUT_TOTAL` / `…_OUTPUT_TOTAL`) remains the cost-side bound. Operators can still pin lower (`= 5`) in policy via `[gateway].planner_max_turns_default` for CI / known-easy scenarios. |
| `RAXIS_PLANNER_MAX_TOKENS` | optional | `4096` | Per-request `max_tokens` value sent to the model API. |

`RAXIS_PLANNER_BASE_URL` must parse as an `http` or `https` URL.
Anything else triggers
`RAXIS_PLANNER_BASE_URL must be a valid http(s) URL`.

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
